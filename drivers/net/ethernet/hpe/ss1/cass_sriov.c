// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019, 2024-2026 Hewlett Packard Enterprise Development LP */

/* Cassini SRIOV and VFs handler
 *
 * AF_VSOCK sockets are used to pass messages and responses from the VF to the
 * PF, both when the VF is attached to a guest (using the appropriate hypervisor
 * vsock transport), and when the VF is attached to the host (using the
 * vsock_loopback module).
 *
 * One shared listener serves all PFs with SR-IOV enabled. The PF and local
 * VF index of an incoming connection are identified by hardware: each
 * PF opens a scratch EQ SW state page to each VF through the SRIOV table, and
 * the VF writes a nonce to all of them through its own BAR. Only the write to
 * the page bound to the VF's PCIe requester ID is accepted, which both
 * identifies and authenticates the VF.
 * After this initial handshake, communication is always initiated by the VF,
 * and an acknowledgment from the PF is always expected. Messages are prefixed
 * with an integer result code (only used by the response from the PF) and
 * message length.
 */

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/jiffies.h>
#include <linux/kmod.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/kvm_host.h>
#include <linux/math64.h>
#include <linux/net.h>
#include <linux/version.h>
#include <linux/vfio.h>
#include <linux/vm_sockets.h>
#include <net/sock.h>
#include <linux/vmalloc.h>

#include "cass_core.h"

/* kernel_bind/connect use sockaddr_unsized since v6.15 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
#define CXI_SOCKADDR(a) ((struct sockaddr_unsized *)(a))
#else
#define CXI_SOCKADDR(a) ((struct sockaddr *)(a))
#endif
#include "cass_vf_notif.h"
#include "cxi_core.h"

MODULE_SOFTDEP("pre: vsock vsock_loopback");

/* Rate limits for the VF vsock message channel. */
#define VF_MSG_RATE_LIMIT_DFLT 0
#define VF_MSG_RATE_BURST_DFLT 50

/* Default port for SR-IOV communication over vsock */
#define CXI_SRIOV_VSOCK_PORT_DFLT 0x17db

unsigned int vf_msg_rate_limit = VF_MSG_RATE_LIMIT_DFLT;
module_param(vf_msg_rate_limit, uint, 0644);
MODULE_PARM_DESC(vf_msg_rate_limit,
		 "Max sustained message rate (msgs/sec) accepted over a VF message channel, 0 to disable");

unsigned int vf_msg_rate_burst = VF_MSG_RATE_BURST_DFLT;
module_param(vf_msg_rate_burst, uint, 0644);
MODULE_PARM_DESC(vf_msg_rate_burst,
		 "Max burst (messages) allowed above the sustained VF message rate");

static unsigned int sriov_vsock_port = CXI_SRIOV_VSOCK_PORT_DFLT;
module_param(sriov_vsock_port, uint, 0644);
MODULE_PARM_DESC(sriov_vsock_port,
		 "Port number used for SR-IOV vsock communication between PF and VF");

#if defined(CXI_DISABLE_SRIOV)
#warning "SR-IOV support is disabled."

int cass_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	return -EOPNOTSUPP;
}

int cass_vf_init(struct cass_dev *hw)
{
	return -EOPNOTSUPP;
}

void cass_vf_fini(struct cass_dev *hw)
{
}

int cxi_send_msg_to_pf(struct cxi_dev *cdev, const void *req,
		       size_t req_len, void *rsp, size_t *rsp_len)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(cxi_send_msg_to_pf);

int cxi_send_async_msg_to_pf(struct cxi_dev *cdev, const void *req,
			     size_t req_len)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(cxi_send_async_msg_to_pf);

int cxi_send_msg_to_vf(struct cxi_dev *cdev, int vf_num, const void *req,
		       size_t req_len, void *rsp, size_t *rsp_len)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(cxi_send_msg_to_vf);

int cxi_send_async_msg_to_vf(struct cxi_dev *cdev, int vf_num, const void *req,
			     size_t req_len)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(cxi_send_async_msg_to_vf);

int cxi_register_msg_relay(struct cxi_dev *cdev, cxi_msg_relay_t msg_relay,
			   void *msg_relay_data)
{
	return 0;
}
EXPORT_SYMBOL(cxi_register_msg_relay);

int cxi_unregister_msg_relay(struct cxi_dev *cdev)
{
	return 0;
}
EXPORT_SYMBOL(cxi_unregister_msg_relay);

int cass_vf_get_token(struct cxi_dev *hw, int vf_idx, unsigned int *token)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(cass_vf_get_token);

int cxi_notify_vf_async_event(struct cxi_dev *cdev, int vf_idx,
			      enum cxi_async_event event)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(cxi_notify_vf_async_event);

int cxi_notify_vfs_async_event(struct cxi_dev *cdev, enum cxi_async_event event)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(cxi_notify_vfs_async_event);

#else /* CXI_DISABLE_SRIOV */

/* Size of pre-allocated VF message buffers; messages larger than this will have
 * buffers dynamically allocated on the heap.
 */
#define SMALL_VFMSG_SIZE 256

/* Handshake commands sent from PF to VF */
#define CXI_SRIOV_CMD_DONE  0x17db0003  /* Handshake complete */
#define CXI_SRIOV_CMD_PROVE 0x17db0004  /* Write value to listed EQ SW state pages */

/* Handshake responses sent from VF to PF */
#define CXI_SRIOV_RSP_PROVED 0x17db8004 /* PROVE writes were issued and flushed */

/* EQ SW state bits ignored by the NIC on a disabled EQ: RD_PTR and SPARE */
#define PROVE_VAL_LO GENMASK_ULL(25, 0)
#define PROVE_VAL_HI GENMASK_ULL(47, 44)
#define PROVE_NONCE_BITS 30

struct cxi_sriov_prove_cmd {
	u32 cmd;
	u32 num_eqs;
	u64 val;
	u32 eqn[C_NUM_VFS];
};

/* Timeout for the PF's listener sockets. Should be kept relatively short to
 * allow thread to progress through its periodic cleanup.
 */
#define CXI_SRIOV_LISTENER_TIMEOUT (HZ / 16)

/* VF- and PF-side vsock timeouts */
#define CXI_SRIOV_VSOCK_TIMEOUT (HZ * 10)
#define CXI_SRIOV_PF_TIMEOUT (CXI_SRIOV_VSOCK_TIMEOUT)
#define CXI_SRIOV_VF_TIMEOUT (CXI_SRIOV_VSOCK_TIMEOUT)

#define CXI_SRIOV_THREADPARK_TIME (HZ / 16)

/* PF-side wait for the VF's PROVE write to land after PROVED is received */
#define CXI_SRIOV_PROVE_TIMEOUT msecs_to_jiffies(10)

/* sriov_listener_lock controls startup and shutdown of listener thread */
static DEFINE_MUTEX(sriov_listener_lock);
static unsigned int sriov_pf_count;
static struct task_struct *sriov_listener;
static struct socket *sriov_listen_req_sock;
static struct socket *sriov_listen_notif_sock;

/* List of cass_dev instances that have SR-IOV enabled, locked by sriov_pf_lock */
static LIST_HEAD(sriov_pfs);
static DEFINE_MUTEX(sriov_pf_lock);

/* Rate-limiting for VF requests and notifications, using the GCRA leaky-bucket
 * algorithm. bucket_ts is the time at which the bucket is next empty, given no
 * further arrivals. Charges one message against the bucket, then sleeps as
 * needed to conform to the given rate (messages/sec) and burst count, in short
 * slices so a kthread throttled here still reacts promptly to kthread_stop().
 */
static void msg_ratelimit(ktime_t *bucket_ts, unsigned int rate, unsigned int burst)
{
	const s64 slice_ns = 100LL * NSEC_PER_MSEC;
	ktime_t now = ktime_get();
	ktime_t interval;
	ktime_t max_backlog;
	ktime_t new_ts;
	s64 delay_ns;

	if (!rate)
		return;

	interval = ns_to_ktime(NSEC_PER_SEC / rate);
	max_backlog = ns_to_ktime(div_u64((u64)burst * NSEC_PER_SEC, rate));

	if (ktime_before(*bucket_ts, now))
		*bucket_ts = now;

	new_ts = ktime_add(*bucket_ts, interval);
	delay_ns = ktime_to_ns(ktime_sub(new_ts, ktime_add(now, max_backlog)));

	if (delay_ns > 0)
		new_ts = ktime_add(now, max_backlog);
	else
		delay_ns = 0;

	*bucket_ts = new_ts;

	while (delay_ns > 0 && !kthread_should_stop()) {
		s64 slice = min(delay_ns, slice_ns);

		schedule_timeout_interruptible(nsecs_to_jiffies(slice));
		delay_ns -= slice;
	}
}

static int write_message_to_vsock(struct socket *sock, const void *msg,
				  size_t msg_len, int msg_rc, int seq,
				  unsigned int flags)
{
	struct vf_pf_msg_hdr hdr = {
		.len = msg_len,
		.rc = msg_rc,
		.uid = __kuid_val(current_euid()),
		.gid = __kgid_val(current_egid()),
		.netns = CURRENT_NETNS_ID(),
		.seq = seq,
		.flags = flags,
	};
	struct msghdr msghdr = {};
	struct kvec vec[] = {
		{
			.iov_base = &hdr,
			.iov_len = sizeof(hdr),
		},
		{
			.iov_base = (void *)msg,
			.iov_len = msg_len
		}
	};

	return kernel_sendmsg(sock, &msghdr, vec, 2, sizeof(hdr) + msg_len);
}

static int read_vsock_header(struct socket *sock, struct vf_pf_msg_hdr *hdr)
{
	struct msghdr msghdr = {};
	struct kvec hdrvec = {
		.iov_base = hdr,
		.iov_len = sizeof(*hdr),
	};
	int rc;

	rc = kernel_recvmsg(sock, &msghdr, &hdrvec, 1, sizeof(*hdr), 0);
	if (rc > 0 && rc < sizeof(*hdr)) {
		pr_err("Not enough data received for header (%u < %lu)",
		       rc, sizeof(*hdr));
		return -EINVAL;
	}
	return rc;
}

static int read_vsock_payload(struct socket *sock, struct vf_pf_msg_hdr *hdr,
			      void *msg, size_t *msg_len)
{
	struct msghdr msghdr = {};
	struct kvec msgvec = {
		.iov_base = msg,
		.iov_len = *msg_len,
	};
	int rc;

	if (hdr->len > *msg_len)
		return -ENOSPC;

	rc = kernel_recvmsg(sock, &msghdr, &msgvec, 1, hdr->len, 0);
	if (rc >= 0 && rc < hdr->len) {
		pr_err("Not enough data received for message body (%u < %u)",
		       rc, hdr->len);
		return -EINVAL;
	}
	return rc;
}

/* Read a message from a vsock connection into a preallocated buffer. If buffer
 * is too small, return -ENOSPC and set *msg_len to the required size.
 */
static int read_message_from_vsock(struct socket *sock, void *msg,
				   size_t *msg_len, int *msg_rc,
				   uid_t *uid, gid_t *gid, unsigned int *netns,
				   int *seq, unsigned int *flags)
{
	struct vf_pf_msg_hdr hdr;
	int rc;

	rc = read_vsock_header(sock, &hdr);
	if (rc <= 0)
		return rc;
	else if (rc == 0) {
		/* Connection closed by the other end */
		return 0;
	} else if (rc < sizeof(hdr)) {
		/* Not enough data received for header */
		pr_err("Not enough data received for header (%u < %lu)",
		       rc, sizeof(hdr));
		return -EINVAL;
	}

	if (msg_rc)
		*msg_rc = hdr.rc;
	if (uid)
		*uid = hdr.uid;
	if (gid)
		*gid = hdr.gid;
	if (netns)
		*netns = hdr.netns;
	if (seq)
		*seq = hdr.seq;
	if (flags)
		*flags = hdr.flags;
	if (msg_len) {
		rc = read_vsock_payload(sock, &hdr, msg, msg_len);
		*msg_len = hdr.len;
	}

	return rc;
}

/* Like read_message_from_vsock(), but allows arbitrarily large messages. If the
 * incoming message is larger *msg_len, a new buffer of the required size will
 * be allocated with kvmalloc and returned in *msg_out. The caller is
 * responsible for checking if a buffer was allocated, and freeing this buffer
 * with kvfree() when done. In either case, *msg_len will be set to the actual
 * size of the message payload.
 *
 * Returns a positive value on success, 0 if the connection was closed, or a
 * negative error code.
 */
static int read_message_from_vsock_large(struct socket *sock, void **msg_out,
					 size_t *msg_len, int *msg_rc,
					 uid_t *uid, gid_t *gid,
					 unsigned int *netns, int *seq,
					 unsigned int *flags)
{
	struct vf_pf_msg_hdr hdr;
	size_t len;
	void *buf;
	int rc;

	rc = read_vsock_header(sock, &hdr);
	if (rc <= 0)
		return rc;

	if (msg_rc)
		*msg_rc = hdr.rc;
	if (uid)
		*uid = hdr.uid;
	if (gid)
		*gid = hdr.gid;
	if (netns)
		*netns = hdr.netns;
	if (seq)
		*seq = hdr.seq;
	if (flags)
		*flags = hdr.flags;

	rc = 0;
	if (hdr.len > 0) {
		len = hdr.len;
		if (len > MAX_VFMSG_SIZE) {
			pr_err("Message length %lu exceeds maximum allowed (%u)",
			       len, MAX_VFMSG_SIZE);
			return -EINVAL;
		}

		if (!*msg_out || *msg_len < len) {
			buf = kvmalloc(len, GFP_KERNEL);
			if (!buf)
				return -ENOMEM;
		} else {
			buf = *msg_out;
		}

		rc = read_vsock_payload(sock, &hdr, buf, &len);
		if (rc < 0) {
			if (*msg_out != buf)
				kvfree(buf);
			return rc;
		}
	} else {
		len = 0;
		buf = NULL;
	}

	*msg_out = buf;
	if (msg_len)
		*msg_len = len;
	return rc;
}

/* Handler thread for incoming messages from the VF driver to the PF. 1 instance
 * per active VF.
 */
static int pf_vf_msghandler(void *data)
{
	struct cass_vf *vf = (struct cass_vf *)data;
	struct cass_dev *hw = vf->hw;
	int rc, msg_rc;
	u8 *const request_buf = kmalloc(SMALL_VFMSG_SIZE, GFP_KERNEL);
	u8 *const reply_buf = kmalloc(SMALL_VFMSG_SIZE, GFP_KERNEL);
	void *request = request_buf;
	void *reply = reply_buf;
	size_t request_len, reply_len;
	uid_t uid;
	gid_t gid;
	unsigned int netns;
	int seq;
	unsigned int msg_flags;

	if (!request_buf || !reply_buf) {
		rc = -ENOMEM;
		goto err;
	}

	vf->req_sock->sk->sk_rcvtimeo = CXI_SRIOV_PF_TIMEOUT;

	cxidev_dbg(&hw->cdev, "vf %d: started message handler", vf->vf_idx);

	while (!kthread_should_stop()) {
		memset(request_buf, 0, SMALL_VFMSG_SIZE);
		request = request_buf;
		request_len = SMALL_VFMSG_SIZE;
		memset(reply_buf, 0, SMALL_VFMSG_SIZE);
		reply = reply_buf;
		reply_len = 0;

		rc = read_message_from_vsock_large(vf->req_sock, &request,
						   &request_len, NULL,
						   &uid, &gid, &netns, &seq,
						   &msg_flags);
		if (rc == -EAGAIN) {
			continue;
		} else if (rc == -EINTR) {
			/* Expected when thread is asked to terminate */
			continue;
		} else if (rc == -ECONNRESET) {
			/* Expected when VF shuts down */
			cxidev_info(&hw->cdev, "vf %d: disconnected",
				    vf->vf_idx);
			break;
		} else if (rc < 0) {
			cxidev_err(&hw->cdev, "vf %d: error reading request: %d",
				   vf->vf_idx, rc);
			break;
		} else if (rc == 0) {
			cxidev_info(&hw->cdev, "vf %d: connection closed by VF",
				    vf->vf_idx);
			break;
		}

		cxidev_dbg(&hw->cdev, "vf %d: got %ld byte message", vf->vf_idx,
			   request_len);

		/* Potentially sleep here to enforce message rate limit */
		msg_ratelimit(&vf->req_bucket_ts,
			      READ_ONCE(hw->vf_cfg[vf->vf_idx].msg_rate_limit),
			      READ_ONCE(hw->vf_cfg[vf->vf_idx].msg_rate_burst));

		/* Use the uid/gid that arrived with the VF message directly,
		 * for both host-bound and VM-bound VFs. Isolation between
		 * VFs/VMs is enforced structurally on the PF: each VF's
		 * services are children of the admin-assigned parent service
		 * and are named through a per-VF id space, so a VF can never
		 * reach another VF's resources regardless of the forwarded
		 * credentials. The forwarded uid/gid are only used for
		 * per-user access control within the VF's own domain, and the
		 * PF impersonation in msg_relay() strips capabilities so a VF
		 * is never treated as privileged.
		 */

		reply_len = SMALL_VFMSG_SIZE;
		mutex_lock(&hw->msg_relay_lock);
		if (hw->msg_relay)
			msg_rc = hw->msg_relay(hw->msg_relay_data, vf->vf_idx,
					       request, request_len, uid, gid,
					       netns, &reply, reply_len,
					       &reply_len);
		else
			msg_rc = -ENODEV;
		mutex_unlock(&hw->msg_relay_lock);
		if (msg_rc < 0)
			reply_len = 0;
		if (request != request_buf)
			kvfree(request);

		if (!(msg_flags & VF_PF_MSG_F_NO_REPLY)) {
			cxidev_dbg(&hw->cdev, "vf %d: responding with %ld bytes, rc=%d",
				   vf->vf_idx, reply_len, msg_rc);
			rc = write_message_to_vsock(vf->req_sock, reply, reply_len,
						    msg_rc, seq, 0);
			if (reply != reply_buf)
				kvfree(reply);

			if (rc <= 0) {
				cxidev_err(&hw->cdev, "vf %d: error sending response: %d",
					   vf->vf_idx, rc);
				break;
			}
		} else {
			if (reply != reply_buf)
				kvfree(reply);
		}
	}

	/* Send a NULL request message to indicate that this VF disconnected */
	mutex_lock(&hw->msg_relay_lock);
	if (hw->msg_relay)
		hw->msg_relay(hw->msg_relay_data, vf->vf_idx, NULL, 0, 0, 0, 0,
			      NULL, 0, &reply_len);
	mutex_unlock(&hw->msg_relay_lock);

	if (rc > 0)
		rc = 0;

err:
	cxidev_dbg(&hw->cdev, "vf %d: handler exiting, rc=%d", vf->vf_idx, rc);

	kernel_sock_shutdown(vf->req_sock, SHUT_RDWR);
	sock_release(vf->req_sock);

	mutex_lock(&vf->notif_lock);
	if (vf->notif_sock) {
		kernel_sock_shutdown(vf->notif_sock, SHUT_RDWR);
		sock_release(vf->notif_sock);
		vf->notif_sock = NULL;
	}
	WRITE_ONCE(vf->req_sock, NULL);
	mutex_unlock(&vf->notif_lock);

	cass_ac_phys_free(hw, vf->phys_ac);
	vf->phys_ac = 0;

	kfree(request_buf);
	kfree(reply_buf);

	while (!kthread_should_stop())
		schedule_timeout_interruptible(CXI_SRIOV_THREADPARK_TIME);

	return rc;
}

static int handshake_send_cmd(struct cass_dev *hw, struct socket *sock,
			      unsigned int cmd)
{
	int rc;

	rc = write_message_to_vsock(sock, &cmd, sizeof(cmd), 0, 0, 0);
	if (rc >= 0 && rc != sizeof(struct vf_pf_msg_hdr) + sizeof(cmd))
		rc = -EIO;
	if (rc < 0)
		cxidev_err(&hw->cdev, "VF handshake: could not send cmd %x: %d",
			   cmd, rc);
	return rc;
}

static int handshake_read_rsp(struct cass_dev *hw, struct socket *sock)
{
	int rc;
	int rsp;
	size_t msg_len = sizeof(rsp);

	do {
		rc = read_message_from_vsock(sock, &rsp, &msg_len, NULL,
					     NULL, NULL, NULL, NULL, NULL);
		if (rc == -EINTR)
			schedule();
	} while (rc == -EINTR);

	if (rc == 0) {
		cxidev_err(&hw->cdev, "VF handshake: connection closed by VF");
		return -ECONNRESET;
	} else if (rc < 0) {
		cxidev_err(&hw->cdev, "VF handshake: error reading response: %d",
			   rc);
		return rc;
	} else if (msg_len != sizeof(rsp)) {
		cxidev_err(&hw->cdev, "VF handshake: expected response of size %zu, got %zu",
			   sizeof(rsp), msg_len);
		return -EPROTO;
	}

	return rsp;
}

/* VF probing induces a number of hardware errors, mask them temporarily:
 *  - eq_dsabld_sw_state_wr: Write to software state of disabled EQ
 *  - pri_rarb_xlat_rtrgt_vf_en_error, pri_rarb_xlat_rtrgt_vf_en_num_error: VF
 *    attempted write to EQ not enabled for it
 */
static void pf_handshake_mask_err(struct cass_dev *hw)
{
	union err_flags f = {};

	f.ee.eq_dsabld_sw_state_wr = 1;
	cxi_disable_hw_errors(hw, C_EE_IRQA_MSIX_INT, false, f.mask);

	memset(&f, 0, sizeof(f));
	f.pi_ext.pri_rarb_xlat_rtrgt_vf_en_error = 1;
	f.pi_ext.pri_rarb_xlat_rtrgt_vf_en_num_error = 1;
	cxi_disable_hw_errors(hw, C_PI_IRQA_MSIX_INT, true, f.mask);
}

static void pf_handshake_unmask_err(struct cass_dev *hw, bool expect_err)
{
	unsigned long deadline = jiffies + CXI_SRIOV_PROVE_TIMEOUT;
	union c_ee_err_flg flg_ee;
	union c_pi_ext_err_flg flg_pi_ext;
	union err_flags f = {};

	/* The flag is raised asynchronously by the EE after the write lands */
	while (expect_err) {
		cass_read(hw, C_EE_ERR_FLG, &flg_ee, sizeof(flg_ee));
		cass_read(hw, C_PI_EXT_ERR_FLG, &flg_pi_ext, sizeof(flg_pi_ext));
		if (flg_ee.eq_dsabld_sw_state_wr ||
		    flg_pi_ext.pri_rarb_xlat_rtrgt_vf_en_error ||
		    flg_pi_ext.pri_rarb_xlat_rtrgt_vf_en_num_error ||
		    !time_before(jiffies, deadline))
			break;
		usleep_range(50, 100);
	}

	/* Clear the latched flag so unmasking does not raise it */
	f.ee.eq_dsabld_sw_state_wr = 1;
	cass_write(hw, C_EE_ERR_CLR, &f.ee, sizeof(f.ee));
	cxi_enable_hw_errors(hw, C_EE_IRQA_MSIX_INT, false, f.mask);

	memset(&f, 0, sizeof(f));
	f.pi_ext.pri_rarb_xlat_rtrgt_vf_en_error = 1;
	f.pi_ext.pri_rarb_xlat_rtrgt_vf_en_num_error = 1;
	cass_write(hw, C_PI_EXT_ERR_CLR, &f.pi_ext, sizeof(f.pi_ext));
	cxi_enable_hw_errors(hw, C_PI_IRQA_MSIX_INT, true, f.mask);
}

/* PF side of PF-VF handshake: identify which VF an incoming connection belongs
 * to. Scratch EQ i is opened to VF i only, and the peer writes a nonce to all
 * of them through its own BAR. Hardware drops writes whose PCIe requester ID
 * does not match the SRIOVT entry, so exactly one EQ receives the nonce and the
 * peer cannot claim another VF's identity.
 */
static int pf_vf_prove(struct cass_dev *hw, struct socket *sock)
__must_hold(sriov_pf_lock)
{
	struct cass_dev *hw_tmp;
	struct cxi_sriov_prove_cmd *prove;
	union c_ee_cfg_eq_sw_state sw_state = {};
	unsigned int num = hw->num_vfs;
	unsigned int allocated;
	unsigned int i;
	int vf_idx = -1;
	bool seen = false;
	u32 nonce;
	int rsp;
	int rc;

	prove = kzalloc(sizeof(*prove), GFP_KERNEL);
	if (!prove)
		return -ENOMEM;

	for (allocated = 0; allocated < num; allocated++) {
		rc = ida_alloc_range(&hw->eq_index_table, 1, C_NUM_EQS - 1,
				     GFP_KERNEL);
		if (rc < 0) {
			cxidev_err(&hw->cdev, "VF handshake: no free EQ: %d", rc);
			goto free_eqs;
		}
		prove->eqn[allocated] = rc;
	}

	do {
		nonce = get_random_u32() & GENMASK(PROVE_NONCE_BITS - 1, 0);
	} while (!nonce);

	prove->cmd = CXI_SRIOV_CMD_PROVE;
	prove->num_eqs = num;
	prove->val = FIELD_PREP(PROVE_VAL_LO, nonce) |
		     FIELD_PREP(PROVE_VAL_HI, nonce >> 26);

	list_for_each_entry(hw_tmp, &sriov_pfs, sriov_pf_node)
		pf_handshake_mask_err(hw_tmp);

	for (i = 0; i < num; i++) {
		cass_write(hw, C_EE_CFG_EQ_SW_STATE(prove->eqn[i]), &sw_state,
			   sizeof(sw_state));
		cass_config_sriovt(hw, true, i, 4096 + prove->eqn[i]);
	}
	cass_flush_pci(hw);

	rc = write_message_to_vsock(sock, prove, sizeof(*prove), 0, 0, 0);
	if (rc >= 0 && rc != sizeof(struct vf_pf_msg_hdr) + sizeof(*prove))
		rc = -EIO;
	if (rc < 0) {
		cxidev_err(&hw->cdev, "VF handshake: could not send PROVE: %d",
			   rc);
	} else {
		rsp = handshake_read_rsp(hw, sock);
		if (rsp < 0) {
			rc = rsp;
		} else if (rsp != CXI_SRIOV_RSP_PROVED) {
			cxidev_err(&hw->cdev, "VF handshake: expected PROVED, got %x",
				   rsp);
			rc = -EPROTO;
		} else {
			rc = 0;
		}
	}

	/* The VF's posted writes may still be in flight; wait before revoking */
	if (rc == 0) {
		unsigned long deadline = jiffies + CXI_SRIOV_PROVE_TIMEOUT;

		do {
			for (i = 0; i < num && !seen; i++) {
				cass_read(hw, C_EE_CFG_EQ_SW_STATE(prove->eqn[i]),
					  &sw_state, sizeof(sw_state));
				seen = (sw_state.qw & (PROVE_VAL_LO | PROVE_VAL_HI)) ==
				       prove->val;
			}
			if (!seen)
				usleep_range(50, 100);
		} while (!seen && time_before(jiffies, deadline));
	}

	/* Revoke VF access before the EQ numbers can be reused */
	for (i = 0; i < num; i++)
		cass_config_sriovt(hw, false, 0, 4096 + prove->eqn[i]);
	cass_flush_pci(hw);

	list_for_each_entry(hw_tmp, &sriov_pfs, sriov_pf_node)
		pf_handshake_unmask_err(hw_tmp, hw == hw_tmp && seen);


	if (rc)
		goto free_eqs;

	for (i = 0; i < num; i++) {
		cass_read(hw, C_EE_CFG_EQ_SW_STATE(prove->eqn[i]), &sw_state,
			  sizeof(sw_state));
		if ((sw_state.qw & (PROVE_VAL_LO | PROVE_VAL_HI)) != prove->val)
			continue;
		if (vf_idx >= 0) {
			cxidev_err(&hw->cdev, "VF handshake: nonce seen on vf %d and %u",
				   vf_idx, i);
			rc = -EACCES;
			goto free_eqs;
		}
		vf_idx = i;
	}

	/* No match is normal when the peer belongs to another registered PF. */
	rc = vf_idx < 0 ? -ENOENT : vf_idx;

free_eqs:
	memset(&sw_state, 0, sizeof(sw_state));
	for (i = 0; i < allocated; i++)
		cass_write(hw, C_EE_CFG_EQ_SW_STATE(prove->eqn[i]), &sw_state,
			   sizeof(sw_state));
	cass_flush_pci(hw);
	while (allocated--)
		ida_free(&hw->eq_index_table, prove->eqn[allocated]);
	kfree(prove);

	return rc;
}

/* Challenge each PF in turn using temporary EQ mappings. Each round revokes
 * its mappings and releases its EQs before the next PF is challenged.
 */
static int pf_vf_handshake(struct socket *sock, struct cass_dev **matched_hw,
			   int *vf_idx)
__must_hold(sriov_pf_lock)
{
	struct cass_dev *hw;
	int rc;

	list_for_each_entry(hw, &sriov_pfs, sriov_pf_node) {
		rc = pf_vf_prove(hw, sock);
		if (rc == -ENOENT)
			continue;
		if (rc < 0)
			return rc;
		*matched_hw = hw;
		*vf_idx = rc;
		return 0;
	}

	return -EACCES;
}

static bool vf_token_in_use(unsigned int token)
__must_hold(sriov_pf_lock)
{
	struct cass_dev *hw;
	int i;

	list_for_each_entry(hw, &sriov_pfs, sriov_pf_node)
		for (i = 0; i < hw->num_vfs; i++)
			if (hw->vfs[i].token == token)
				return true;
	return false;
}

/* Handle an incoming request connection from a VF */
static void handle_vf_req_conn(struct socket *incoming)
{
	struct sockaddr_vm peeraddr;
	struct cass_dev *hw;
	struct cass_vf *vf;
	unsigned int token;
	int rc, vf_idx;

	incoming->sk->sk_rcvtimeo = CXI_SRIOV_PF_TIMEOUT;
	incoming->sk->sk_sndtimeo = CXI_SRIOV_PF_TIMEOUT;
	rc = kernel_getpeername(incoming, (struct sockaddr *)&peeraddr);
	if (rc < 0)
		goto close_sock;

	mutex_lock(&sriov_pf_lock);
	rc = pf_vf_handshake(incoming, &hw, &vf_idx);
	if (rc < 0) {
		pr_err("vf handshake from cid %u failed: %d\n",
		       peeraddr.svm_cid, rc);
		goto unlock;
	}

	vf = &hw->vfs[vf_idx];
	/* A reconnect replaces only the authenticated VF. Wait for its relay
	 * disconnect callback and resource cleanup before admitting requests.
	 * Do not reinitialize notif_lock: notification users may still hold it.
	 */
	if (vf->task) {
		kthread_stop(vf->task);
		vf->task = NULL;
	}

	do {
		token = get_random_u32();
	} while (vf_token_in_use(token));

	vf->vf_idx = vf_idx;
	vf->hw = hw;
	vf->req_sock = incoming;
	vf->req_bucket_ts = ktime_get();
	vf->token = token;

	rc = cass_ac_phys_alloc(hw, true, vf_idx);
	if (rc <= 0) {
		vf->req_sock = NULL;
		goto unlock;
	}
	vf->phys_ac = rc;

	/* DONE is only sent after an overall successful hardware proof and
	 * after the previous session's resources have been released.
	 */
	rc = handshake_send_cmd(hw, incoming, CXI_SRIOV_CMD_DONE);
	if (rc < 0)
		goto free_ac;

	vf->task = kthread_run(pf_vf_msghandler, vf, "cxi_vf_%d", vf_idx);
	if (IS_ERR(vf->task)) {
		vf->task = NULL;
		goto free_ac;
	}
	mutex_unlock(&sriov_pf_lock);
	return;

free_ac:
	cass_ac_phys_free(hw, vf->phys_ac);
	vf->phys_ac = 0;
	vf->req_sock = NULL;
unlock:
	mutex_unlock(&sriov_pf_lock);
close_sock:
	kernel_sock_shutdown(incoming, SHUT_RDWR);
	sock_release(incoming);
}

/* Handle an incoming notification connection from a VF */
static void handle_vf_notif_conn(struct socket *incoming)
{
	struct cass_dev *hw;
	struct cass_vf *vf = NULL;
	struct cass_vf_notif_ping ping = {
		.op = CASS_VF_NOTIF_OP_PING,
	};
	unsigned int token;
	size_t msg_len = sizeof(token);
	int rc, i;

	incoming->sk->sk_rcvtimeo = CXI_SRIOV_PF_TIMEOUT;
	incoming->sk->sk_sndtimeo = CXI_SRIOV_PF_TIMEOUT;
	rc = read_message_from_vsock(incoming, &token, &msg_len, NULL,
				     NULL, NULL, NULL, NULL, NULL);
	if (rc <= 0 || msg_len != sizeof(token))
		goto close_sock;

	mutex_lock(&sriov_pf_lock);
	list_for_each_entry(hw, &sriov_pfs, sriov_pf_node) {
		for (i = 0; i < hw->num_vfs; i++) {
			if (!hw->vfs[i].task || hw->vfs[i].token != token)
				continue;
			/* Reject tokens matching more than one session. */
			if (vf)
				goto unlock;
			vf = &hw->vfs[i];
		}
	}
	if (!vf)
		goto unlock;

	mutex_lock(&vf->notif_lock);
	if (!vf->req_sock || vf->notif_sock) {
		mutex_unlock(&vf->notif_lock);
		goto unlock;
	}
	vf->notif_seq = 0;
	vf->notif_sock = incoming;
	mutex_unlock(&vf->notif_lock);

	/* Send test notification; the handler may concurrently disconnect. */
	rc = cxi_send_msg_to_vf(&vf->hw->cdev, vf->vf_idx, &ping,
				sizeof(ping), NULL, NULL);
	if (rc < 0) {
		mutex_lock(&vf->notif_lock);
		if (vf->notif_sock == incoming) {
			vf->notif_sock = NULL;
			mutex_unlock(&vf->notif_lock);
			goto unlock;
		}
		mutex_unlock(&vf->notif_lock);
	}
	/* If the handler took the socket down, it already released it. */
	mutex_unlock(&sriov_pf_lock);
	return;

unlock:
	mutex_unlock(&sriov_pf_lock);
close_sock:
	kernel_sock_shutdown(incoming, SHUT_RDWR);
	sock_release(incoming);
}

static int vsock_create_listen(struct socket **sock, unsigned int port,
			       int timeout, int backlog)
{
	int rc;
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_port = port,
		.svm_cid = VMADDR_CID_ANY
	};

	rc = sock_create_kern(&init_net, PF_VSOCK, SOCK_STREAM, 0, sock);
	if (rc < 0)
		return rc;

	rc = kernel_bind(*sock, CXI_SOCKADDR(&addr), sizeof(addr));
	if (rc < 0)
		goto release_sock;

	(*sock)->sk->sk_rcvtimeo = timeout;
	rc = kernel_listen(*sock, backlog);
	if (rc < 0)
		goto release_sock;

	return 0;
release_sock:
	sock_release(*sock);
	*sock = NULL;
	return rc;
}

/* Listener thread for incoming connections from VFs of all registered PFs.
 * Handles both request and notification sockets. 1 instance only, used by all
 * PFs.
 */
static int pf_vf_listener(void *data)
{
	struct cass_dev *hw;
	int rc = 0;
	int vf_idx;

	pr_debug("started vf listener\n");

	while (!kthread_should_stop()) {
		struct socket *incoming;

		rc = kernel_accept(sriov_listen_req_sock, &incoming, 0);
		if (rc == 0) {
			handle_vf_req_conn(incoming);
			continue;
		} else if (rc != -EAGAIN && rc != -EINTR) {
			pr_err("vf request listener socket accept error: %d\n", rc);
			break;
		}

		rc = kernel_accept(sriov_listen_notif_sock, &incoming, 0);
		if (rc == 0) {
			handle_vf_notif_conn(incoming);
			continue;
		} else if (rc != -EAGAIN && rc != -EINTR) {
			pr_err("vf notification listener socket accept error: %d\n",
			       rc);
			break;
		}

		/* Periodically clean up old handler threads that have
		 * relinquished their request sockets
		 */
		mutex_lock(&sriov_pf_lock);
		list_for_each_entry(hw, &sriov_pfs, sriov_pf_node) {
			for (vf_idx = 0; vf_idx < hw->num_vfs; vf_idx++) {
				if (!READ_ONCE(hw->vfs[vf_idx].req_sock) &&
				    hw->vfs[vf_idx].task) {
					kthread_stop(hw->vfs[vf_idx].task);
					hw->vfs[vf_idx].task = NULL;
				}
			}
		}
		mutex_unlock(&sriov_pf_lock);
	}

	pr_debug("vf listener exiting\n");

	while (!kthread_should_stop())
		schedule_timeout_interruptible(CXI_SRIOV_PF_TIMEOUT);

	return rc;
}

/* Stop all VF handler threads of a PF and release their resources. The PF
 * must already be removed from sriov_pfs.
 */
static void pf_vf_teardown(struct cass_dev *hw)
{
	int vf_idx;

	for (vf_idx = 0; vf_idx < hw->num_vfs; vf_idx++) {
		if (hw->vfs[vf_idx].task) {
			kthread_stop(hw->vfs[vf_idx].task);
			hw->vfs[vf_idx].task = NULL;
		}
		if (hw->vfs[vf_idx].req_sock) {
			kernel_sock_shutdown(hw->vfs[vf_idx].req_sock, SHUT_RDWR);
			sock_release(hw->vfs[vf_idx].req_sock);
			hw->vfs[vf_idx].req_sock = NULL;
		}
		if (hw->vfs[vf_idx].notif_sock) {
			kernel_sock_shutdown(hw->vfs[vf_idx].notif_sock, SHUT_RDWR);
			sock_release(hw->vfs[vf_idx].notif_sock);
			hw->vfs[vf_idx].notif_sock = NULL;
		}
		if (hw->vfs[vf_idx].phys_ac) {
			cass_ac_phys_free(hw, hw->vfs[vf_idx].phys_ac);
			hw->vfs[vf_idx].phys_ac = 0;
		}
	}
}

static void sriov_listener_stop(void)
__must_hold(sriov_listener_lock)
{
	if (sriov_listener) {
		kthread_stop(sriov_listener);
		sriov_listener = NULL;
	}

	if (sriov_listen_notif_sock) {
		kernel_sock_shutdown(sriov_listen_notif_sock, SHUT_RDWR);
		sock_release(sriov_listen_notif_sock);
		sriov_listen_notif_sock = NULL;
	}

	if (sriov_listen_req_sock) {
		kernel_sock_shutdown(sriov_listen_req_sock, SHUT_RDWR);
		sock_release(sriov_listen_req_sock);
		sriov_listen_req_sock = NULL;
	}
}

static int sriov_listener_start(void)
__must_hold(sriov_listener_lock)
{
	int rc;

	rc = vsock_create_listen(&sriov_listen_req_sock, sriov_vsock_port,
				 CXI_SRIOV_LISTENER_TIMEOUT, C_NUM_VFS);
	if (rc < 0) {
		pr_err("could not create vf request listener socket: %d\n", rc);
		return rc;
	}

	rc = vsock_create_listen(&sriov_listen_notif_sock,
				 sriov_vsock_port + 1,
				 CXI_SRIOV_LISTENER_TIMEOUT, C_NUM_VFS);
	if (rc < 0) {
		pr_err("could not create vf notification listener socket: %d\n",
		       rc);
		goto err_stop;
	}

	sriov_listener = kthread_run(pf_vf_listener, NULL, "cxi_vf_listener");
	if (IS_ERR(sriov_listener)) {
		pr_err("could not start vf listener thread\n");
		rc = PTR_ERR(sriov_listener);
		sriov_listener = NULL;
		goto err_stop;
	}

	return 0;

err_stop:
	sriov_listener_stop();
	return rc;
}

/* Add a PF to the set served by the shared listener, starting it if needed */
static int sriov_pf_register(struct cass_dev *hw)
{
	int rc = 0;

	cxidev_dbg(&hw->cdev, "registering for SR-IOV\n");
	mutex_lock(&sriov_listener_lock);

	if (!sriov_pf_count) {
		rc = sriov_listener_start();
		if (rc)
			goto unlock;
	}
	sriov_pf_count++;

	mutex_lock(&sriov_pf_lock);
	list_add_tail(&hw->sriov_pf_node, &sriov_pfs);
	mutex_unlock(&sriov_pf_lock);

unlock:
	mutex_unlock(&sriov_listener_lock);
	return rc;
}

/* Remove a PF from the shared listener's registry, waiting out any proof in
 * progress. Existing VF sessions stay up. Returns whether the PF was
 * registered.
 */
static bool sriov_pf_quiesce(struct cass_dev *hw)
{
	bool registered;

	cxidev_dbg(&hw->cdev, "quiescing SR-IOV\n");
	mutex_lock(&sriov_listener_lock);

	registered = !list_empty(&hw->sriov_pf_node);
	if (registered) {
		mutex_lock(&sriov_pf_lock);
		list_del_init(&hw->sriov_pf_node);
		mutex_unlock(&sriov_pf_lock);
	}

	mutex_unlock(&sriov_listener_lock);
	return registered;
}

/* Stop a quiesced PF's VF sessions, and the listener if this was the last PF */
static void sriov_pf_teardown(struct cass_dev *hw)
{
	cxidev_dbg(&hw->cdev, "tearing down SR-IOV sessions\n");
	mutex_lock(&sriov_listener_lock);

	pf_vf_teardown(hw);

	if (!--sriov_pf_count)
		sriov_listener_stop();

	mutex_unlock(&sriov_listener_lock);
}

static void disable_sriov(struct pci_dev *pdev)
{
	struct cass_dev *hw = pci_get_drvdata(pdev);
	union err_flags f = {
		.pi_ipd_ext.msix_disabled_error = 1,
	};
	bool registered;

	/* Wait out proofs, but keep sessions up: VF removal needs them. */
	registered = sriov_pf_quiesce(hw);

	/* Hardware raises a spurious pi_ipd_ext.msix_disabled_error when
	 * disabling VFs. Temporarily disable this interrupt during teardown
	 */
	cxi_disable_hw_errors(hw, C_PI_IPD_IRQA_MSIX_INT, true, f.mask);
	pci_disable_sriov(pdev);
	cxi_enable_hw_errors(hw, C_PI_IPD_IRQA_MSIX_INT, true, f.mask);

	if (registered)
		sriov_pf_teardown(hw);

	cass_eth_mc_sw_sriov_configure(hw, 0);

	cass_rmu_eth_sriov_disable(hw);

	hw->num_vfs = 0;
}

static int enable_sriov(struct pci_dev *pdev, int num_vfs)
{
	int rc;
	int i;
	int sriov;
	u16 offset;
	u16 stride;
	union c_pi_cfg_pri_sriov pri_sriov = {};
	struct cass_dev *hw = pci_get_drvdata(pdev);

	/* Refuse if any of the requested VFs has no valid service assigned */
	mutex_lock(&hw->svc_lock);
	for (i = 0; i < num_vfs; i++) {
		if (!hw->vf_cfg[i].svc_id ||
		    !idr_find(&hw->svc_ids, hw->vf_cfg[i].svc_id)) {
			cxidev_err(&hw->cdev,
				   "vf %d has an invalid service assigned; set valid svc_id before enabling SR-IOV",
				   i);
			mutex_unlock(&hw->svc_lock);
			return -EINVAL;
		}
	}
	mutex_unlock(&hw->svc_lock);

	cass_vf_eth_cfg_reset(hw);

	rc = request_module("vsock");
	if (rc) {
		cxidev_err(&hw->cdev, "could not load vsock module");
		goto err_novf;
	}

	rc = request_module("vsock_loopback");
	if (rc) {
		cxidev_err(&hw->cdev, "could not load vsock_loopback module");
		goto err_novf;
	}

	hw->num_vfs = num_vfs;

	/* The VF Offset and Stride need to match the SR-IOV configuration. */
	sriov = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!sriov) {
		cxidev_err(&hw->cdev, "No extended capabilities found\n");
		rc = -ENODEV;
		goto err_novf;
	}

	pci_read_config_word(pdev, sriov + PCI_SRIOV_VF_OFFSET, &offset);
	pci_read_config_word(pdev, sriov + PCI_SRIOV_VF_STRIDE, &stride);

	pri_sriov.vf_offset = offset;
	pri_sriov.vf_stride = stride;

	cass_write(hw, C_PI_CFG_PRI_SRIOV, &pri_sriov,
		   sizeof(union c_pi_cfg_pri_sriov));

	/* Carve the VF share of the RMU set_list before the VFs can appear. */
	rc = cass_rmu_eth_sriov_enable(hw, num_vfs);
	if (rc)
		goto err_novf;

	/* Publish only after PF setup, but before PCI can probe any VFs. */
	rc = sriov_pf_register(hw);
	if (rc)
		goto err_rmu_disable;

	rc = pci_enable_sriov(pdev, num_vfs);
	if (rc) {
		cxidev_err(&hw->cdev, "SRIOV enable failed %d\n", rc);
		goto err_unregister_pf;
	}

	rc = cass_eth_mc_sw_sriov_configure(hw, num_vfs);
	if (rc) {
		cxidev_err(&hw->cdev,
			   "mc-switch dispatcher init failed: %d\n", rc);
		goto err_disable_sriov;
	}

	return num_vfs;

err_disable_sriov:
	sriov_pf_quiesce(hw);
	pci_disable_sriov(pdev);
	sriov_pf_teardown(hw);
	goto err_rmu_disable;
err_unregister_pf:
	sriov_pf_quiesce(hw);
	sriov_pf_teardown(hw);
err_rmu_disable:
	cass_rmu_eth_sriov_disable(hw);
err_novf:
	hw->num_vfs = 0;
	return rc;
}

int cass_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs < 0)
		return -EINVAL;

	if (num_vfs == 0) {
		disable_sriov(pdev);
		return 0;
	}

	return enable_sriov(pdev, num_vfs);
}

/* VF-side handler thread for receiving notifications from PF */
static int vf_notif_handler(void *data)
{
	struct cass_dev *hw = (struct cass_dev *)data;
	int rc = 0;

	u8 *const msg_buf = kmalloc(SMALL_VFMSG_SIZE, GFP_KERNEL);
	u8 *const rsp_buf = kmalloc(SMALL_VFMSG_SIZE, GFP_KERNEL);
	void *msg = NULL;
	void *rsp = NULL;
	size_t msg_len, rsp_len;
	unsigned int msg_flags;
	unsigned int seq;

	if (!msg_buf || !rsp_buf) {
		rc = -ENOMEM;
		goto err;
	}

	cxidev_dbg(&hw->cdev, "started notification handler");

	while (!kthread_should_stop()) {
		memset(msg_buf, 0, SMALL_VFMSG_SIZE);
		msg = msg_buf;
		msg_len = SMALL_VFMSG_SIZE;
		memset(rsp_buf, 0, SMALL_VFMSG_SIZE);
		rsp = rsp_buf;
		rsp_len = 0;

		rc = read_message_from_vsock_large(hw->vf_notif_sock, &msg,
						   &msg_len, NULL,
						   NULL, NULL, NULL, &seq,
						   &msg_flags);
		if (rc == -EAGAIN) {
			continue;
		} else if (rc == -EINTR) {
			/* Expected when thread is asked to terminate */
			continue;
		} else if (rc < 0) {
			cxidev_err(&hw->cdev, "error reading notification from PF: %d", rc);
			break;
		} else if (rc == 0) {
			cxidev_dbg(&hw->cdev, "notification connection closed by PF");
			break;
		}

		cxidev_dbg(&hw->cdev, "received %ld byte notification from PF", msg_len);

		/* Potentially sleep here to enforce message rate limit */
		msg_ratelimit(&hw->notif_bucket_ts, vf_msg_rate_limit, vf_msg_rate_burst);

		rc = dispatch_vf_notif(hw, msg, msg_len, &rsp, &rsp_len);
		if (msg != msg_buf)
			kvfree(msg);
		if (rc < 0) {
			cxidev_err(&hw->cdev, "error handling notification from PF: %d", rc);
			rsp_len = 0;
		}

		if (!(msg_flags & VF_PF_MSG_F_NO_REPLY)) {
			rc = write_message_to_vsock(hw->vf_notif_sock, rsp, rsp_len, rc, seq, 0);
			if (rsp != rsp_buf)
				kvfree(rsp);

			if (rc <= 0) {
				cxidev_err(&hw->cdev, "failed to send notification response: %d", rc);
				break;
			} else if (rc < rsp_len) {
				cxidev_err(&hw->cdev, "partial write of notification response: %d < %zu",
					   rc, rsp_len);
				rc = -EIO;
				break;
			}
		} else {
			if (rsp != rsp_buf)
				kvfree(rsp);
		}
	}

	cxidev_dbg(&hw->cdev, "notification handler exiting");

err:
	kfree(msg_buf);
	kfree(rsp_buf);
	/* Wait for kthread_stop() before returning, to avoid use-after-free if the
	 * thread exits before cass_vf_fini() calls kthread_stop().
	 */
	while (!kthread_should_stop())
		schedule_timeout_interruptible(CXI_SRIOV_THREADPARK_TIME);
	return rc;
}

/* VF side of PROVE: write the PF's value to every listed EQ SW state page in
 * our BAR. SRIOVT drops all writes except the one to the page bound to us.
 */
static int vf_prove(struct cass_dev *hw, const struct cxi_sriov_prove_cmd *prove)
{
	void __iomem *page;
	unsigned int i;

	if (prove->num_eqs == 0 || prove->num_eqs > C_NUM_VFS ||
	    prove->val & ~(PROVE_VAL_LO | PROVE_VAL_HI))
		return -EINVAL;

	for (i = 0; i < prove->num_eqs; i++) {
		if (prove->eqn[i] == 0 || prove->eqn[i] >= C_NUM_EQS)
			return -EINVAL;

		page = ioremap(hw->regs_base + C_MEMORG_EE +
			       prove->eqn[i] * C_EE_SW_STATE_PAGE_SIZE,
			       PAGE_SIZE);
		if (!page)
			return -ENOMEM;

		writeq(prove->val, page);
		iounmap(page);
	}

	return 0;
}

static int vf_read_cmd(struct cass_dev *hw, void *msg, size_t *msg_len)
{
	int rc;

	do {
		rc = read_message_from_vsock(hw->vf_req_sock, msg, msg_len,
					     NULL, NULL, NULL, NULL, NULL, NULL);
		if (rc == -EINTR)
			schedule();
	} while (rc == -EINTR);

	if (rc == 0) {
		cxidev_err(&hw->cdev, "VF handshake: PF closed connection");
		return -ENOTCONN;
	} else if (rc < 0) {
		cxidev_err(&hw->cdev, "VF handshake: error reading cmd: %d", rc);
	}

	return rc;
}

/* VF side of VF-PF handshake: answer each PF's PROVE until DONE. */
static int vf_handshake(struct cass_dev *hw)
{
	struct cxi_sriov_prove_cmd *prove;
	unsigned int rsp = CXI_SRIOV_RSP_PROVED;
	bool proved = false;
	size_t msg_len;
	int rc;

	prove = kzalloc(sizeof(*prove), GFP_KERNEL);
	if (!prove)
		return -ENOMEM;

	for (;;) {
		msg_len = sizeof(*prove);
		rc = vf_read_cmd(hw, prove, &msg_len);
		if (rc < 0)
			break;
		if (msg_len == sizeof(prove->cmd) &&
		    prove->cmd == CXI_SRIOV_CMD_DONE && proved) {
			rc = 0;
			break;
		}
		if (msg_len != sizeof(*prove) ||
		    prove->cmd != CXI_SRIOV_CMD_PROVE) {
			rc = -EPROTO;
			break;
		}
		rc = vf_prove(hw, prove);
		if (rc < 0)
			break;
		proved = true;
		rc = write_message_to_vsock(hw->vf_req_sock, &rsp, sizeof(rsp),
					    0, 0, 0);
		if (rc >= 0 && rc != sizeof(struct vf_pf_msg_hdr) + sizeof(rsp))
			rc = -EIO;
		if (rc < 0)
			break;
	}
	kfree(prove);
	return rc;
}

int cass_vf_init(struct cass_dev *hw)
{
	int rc;
	const struct cxi_vf_get_token_cmd token_cmd = {
		.op = CXI_OP_VF_GET_TOKEN,
	};
	struct cxi_vf_get_token_resp token_resp;
	const struct cxi_query_version_cmd version_cmd = {
		.op = CXI_OP_QUERY_VERSION,
		.version = CXI_API_VERSION
	};
	struct cxi_query_version_resp version_resp;
	size_t resp_len = sizeof(token_resp);
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_port = sriov_vsock_port,
		.svm_cid = VMADDR_CID_HOST,
	};

	if (!hw->with_vf_support)
		return 0;

	mutex_init(&hw->vf_cmd_lock);

	rc = request_module("vsock");
	if (rc) {
		cxidev_err(&hw->cdev, "could not load vsock module");
		return rc;
	}

	rc = sock_create_kern(&init_net, PF_VSOCK, SOCK_STREAM, 0, &hw->vf_req_sock);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf socket create failed: %d", rc);
		return rc;
	}

	hw->vf_req_sock->sk->sk_rcvtimeo = CXI_SRIOV_VF_TIMEOUT;
	hw->vf_req_sock->sk->sk_sndtimeo = CXI_SRIOV_VF_TIMEOUT;
	hw->vf_cmd_seq = 0;

	rc = kernel_connect(hw->vf_req_sock, CXI_SOCKADDR(&addr),
			    sizeof(addr), 0);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf socket connect failed: %d", rc);
		goto release_vf_sock;
	}

	rc = vf_handshake(hw);
	if (rc < 0)
		goto shutdown_vf_sock;

	/* Check version compatibility against PF. PF can reject VF client by
	 * returning -EINVAL
	 */
	rc = cxi_send_msg_to_pf(&hw->cdev, &version_cmd, sizeof(version_cmd),
				&version_resp, &resp_len);
	if (rc == -EINVAL) {
		cxidev_err(&hw->cdev, "PF does not support this VF client version");
		goto shutdown_vf_sock;
	}
	if (rc < 0) {
		cxidev_err(&hw->cdev, "failed to query PF version: %d", rc);
		goto shutdown_vf_sock;
	}
	if (version_resp.version < CXI_SRIOV_SERVER_MIN) {
		cxidev_err(&hw->cdev, "PF API version 0x%x is too old (0x%x or newer required)",
			   version_resp.version, CXI_SRIOV_SERVER_MIN);
		goto shutdown_vf_sock;
	}

	/* Handshake successful, now retrieve token and connect notification socket */
	rc = cxi_send_msg_to_pf(&hw->cdev, &token_cmd, sizeof(token_cmd),
				&token_resp, &resp_len);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "failed to get token from PF: %d", rc);
		goto shutdown_vf_sock;
	}

	rc = sock_create_kern(&init_net, PF_VSOCK, SOCK_STREAM, 0,
			      &hw->vf_notif_sock);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf notif socket create failed: %d", rc);
		goto shutdown_vf_sock;
	}

	hw->vf_notif_sock->sk->sk_rcvtimeo = CXI_SRIOV_VF_TIMEOUT;
	hw->vf_notif_sock->sk->sk_sndtimeo = CXI_SRIOV_VF_TIMEOUT;

	addr.svm_port = sriov_vsock_port + 1;
	rc = kernel_connect(hw->vf_notif_sock, CXI_SOCKADDR(&addr),
			    sizeof(addr), 0);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf notif socket connect failed: %d", rc);
		goto release_notif_sock;
	}

	/* Send token to identify this VF */
	rc = write_message_to_vsock(hw->vf_notif_sock, &token_resp.token,
				    sizeof(token_resp.token), 0, 0, 0);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "failed to send token to PF: %d", rc);
		goto shutdown_notif_sock;
	}

	/* Start notification handler thread */
	init_completion(&hw->vf_notif_ready);
	hw->notif_bucket_ts = ktime_get();
	hw->vf_notif_handler = kthread_run(vf_notif_handler, hw, "cxi_vf_notif");
	if (IS_ERR(hw->vf_notif_handler)) {
		cxidev_err(&hw->cdev, "failed to start notification handler");
		rc = PTR_ERR(hw->vf_notif_handler);
		hw->vf_notif_handler = NULL;
		goto shutdown_notif_sock;
	}

	/* Block until the PF's PING is received, which guarantees vf->notif_sock
	 * is set on the PF before cass_vf_init() so that we make sure that we
	 * do not miss any notification event */
	rc = wait_for_completion_timeout(&hw->vf_notif_ready,
					 CXI_SRIOV_VF_TIMEOUT);
	if (!rc) {
		cxidev_err(&hw->cdev,
			   "timed out waiting for notification channel PING from PF");
		kernel_sock_shutdown(hw->vf_notif_sock, SHUT_RDWR);
		kthread_stop(hw->vf_notif_handler);
		hw->vf_notif_handler = NULL;
		rc = -ETIMEDOUT;
		goto release_notif_sock;
	}

	return 0;

shutdown_notif_sock:
	kernel_sock_shutdown(hw->vf_notif_sock, SHUT_RDWR);
release_notif_sock:
	sock_release(hw->vf_notif_sock);
	hw->vf_notif_sock = NULL;
shutdown_vf_sock:
	kernel_sock_shutdown(hw->vf_req_sock, SHUT_RDWR);
release_vf_sock:
	sock_release(hw->vf_req_sock);
	hw->vf_req_sock = NULL;
	return rc;
}

void cass_vf_fini(struct cass_dev *hw)
{
	if (!hw->with_vf_support)
		return;

	/* Shut down the notification socket before stopping the handler thread
	 * so that any blocked recv in vf_notif_handler returns immediately rather
	 * than waiting up to CXI_SRIOV_VF_TIMEOUT for a timeout.
	 */
	if (hw->vf_notif_sock)
		kernel_sock_shutdown(hw->vf_notif_sock, SHUT_RDWR);

	if (hw->vf_notif_handler) {
		kthread_stop(hw->vf_notif_handler);
		hw->vf_notif_handler = NULL;
	}

	if (hw->vf_req_sock) {
		kernel_sock_shutdown(hw->vf_req_sock, SHUT_RDWR);
		sock_release(hw->vf_req_sock);
		hw->vf_req_sock = NULL;
	}

	if (hw->vf_notif_sock) {
		sock_release(hw->vf_notif_sock);
		hw->vf_notif_sock = NULL;
	}
}

/**
 * cxi_vsock_async_send() - Send a vsock message without waiting for a reply
 *
 * @cdev: the device
 * @sock: connected vsock socket
 * @req: message data
 * @req_len: length of message
 */
static int cxi_vsock_async_send(struct cxi_dev *cdev, struct socket *sock,
				const void *req, size_t req_len)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;

	if (!sock)
		return -ENOTCONN;

	rc = write_message_to_vsock(sock, req, req_len, 0, 0, VF_PF_MSG_F_NO_REPLY);
	if (rc <= 0) {
		cxidev_err(&hw->cdev, "error sending async vsock message: %d", rc);
		return rc < 0 ? rc : -EPROTO;
	}

	return 0;
}

/**
 * cxi_vsock_send() - Send a vsock message using a provided socket
 *
 * @cdev: the device
 * @sock: connected vsock socket
 * @req: message data
 * @req_len: length of message
 * @rsp: buffer for response (may be NULL to discard the response payload)
 * @rsp_len: length of response buffer (updated to reflect response length)
 * @seq: sequence number to include in message header and expect in response
 */

static int cxi_vsock_send(struct cxi_dev *cdev, struct socket *sock, const void *req,
			  size_t req_len, void *rsp, size_t *rsp_len, int seq)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;
	int msg_rc;
	int rsp_seq;

	if (!sock)
		return -ENOTCONN;

	rc = write_message_to_vsock(sock, req, req_len, 0, seq, 0);
	if (rc <= 0) {
		cxidev_err(&hw->cdev, "error sending vsock message: %d", rc);
		return rc < 0 ? rc : -EPROTO;
	}

	do {
		rc = read_message_from_vsock(sock, rsp, rsp_len, &msg_rc,
					     NULL, NULL, NULL, &rsp_seq, NULL);
		if (rc == -EINTR)
			schedule();
	} while (rc == -EINTR);
	if (rc == -EAGAIN) {
		cxidev_err(&hw->cdev, "vsock response timed out\n");
		return -ETIMEDOUT;
	} else if (rc < 0) {
		cxidev_err(&hw->cdev, "error reading vsock response: %d", rc);
		return -EPROTO;
	}

	if (rsp_seq != seq) {
		cxidev_err(&hw->cdev, "expected response seq %d but got %d",
			   seq, rsp_seq);
		return -EPROTO;
	}

	return msg_rc;
}

/**
 * cxi_send_msg_to_pf() - Send a message from VF to PF
 *
 * @cdev: the device
 * @req: message data
 * @req_len: length of message
 * @rsp: buffer for response from PF
 * @rsp_len: length of response buffer (updated to reflect response length)
 */
int cxi_send_msg_to_pf(struct cxi_dev *cdev, const void *req,
		       size_t req_len, void *rsp, size_t *rsp_len)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;

	if (cdev->is_physfn)
		return -EINVAL;

	cxidev_dbg(&hw->cdev, "Sending %ld bytes to PF", req_len);

	mutex_lock(&hw->vf_cmd_lock);
	rc = cxi_vsock_send(cdev, hw->vf_req_sock, req, req_len, rsp, rsp_len,
			    hw->vf_cmd_seq++);
	mutex_unlock(&hw->vf_cmd_lock);

	cxidev_dbg(&hw->cdev, "Got %ld byte reply from PF, rc=%d",
		   rsp_len ? *rsp_len : 0, rc);

	return rc;
}
EXPORT_SYMBOL(cxi_send_msg_to_pf);

/**
 * cxi_send_async_msg_to_pf() - Send a VF->PF message without waiting for a reply
 *
 * @cdev: the VF device
 * @req: message data
 * @req_len: length of message
 *
 * Fire-and-forget variant of cxi_send_msg_to_pf() for datapath relays (e.g. BUM
 * TX forwarding) where the PF reply is not needed. The PF handler processes the
 * message but skips the response (VF_PF_MSG_F_NO_REPLY).
 *
 * Return: 0 on success, negative errno on error.
 */
int cxi_send_async_msg_to_pf(struct cxi_dev *cdev, const void *req,
			     size_t req_len)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;

	if (cdev->is_physfn)
		return -EINVAL;

	mutex_lock(&hw->vf_cmd_lock);
	rc = cxi_vsock_async_send(cdev, hw->vf_req_sock, req, req_len);
	mutex_unlock(&hw->vf_cmd_lock);

	return rc;
}
EXPORT_SYMBOL(cxi_send_async_msg_to_pf);

/**
 * cxi_send_msg_to_vf() - Send a message from PF to a specific VF
 *
 * @cdev: the device
 * @vf_num: VF index to send the message to
 * @req: message data
 * @req_len: length of message
 * @rsp: buffer for response from VF
 * @rsp_len: length of response buffer (updated to reflect response length)
 */
int cxi_send_msg_to_vf(struct cxi_dev *cdev, int vf_num, const void *req,
		       size_t req_len, void *rsp, size_t *rsp_len)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;

	if (!cdev->is_physfn)
		return -EINVAL;

	if (vf_num < 0 || vf_num >= hw->num_vfs)
		return -EINVAL;

	cxidev_dbg(&hw->cdev, "Sending %ld bytes to VF %d", req_len, vf_num);

	mutex_lock(&hw->vfs[vf_num].notif_lock);
	rc = cxi_vsock_send(cdev, hw->vfs[vf_num].notif_sock,
			    req, req_len, rsp, rsp_len,
			    hw->vfs[vf_num].notif_seq++);
	mutex_unlock(&hw->vfs[vf_num].notif_lock);

	cxidev_dbg(&hw->cdev, "Got %ld byte reply from VF %d, rc=%d",
		   rsp_len ? *rsp_len : 0, vf_num, rc);

	return rc;
}
EXPORT_SYMBOL(cxi_send_msg_to_vf);

/**
 * cxi_send_async_msg_to_vf() - Send a PF->VF message without waiting for a reply
 *
 * @cdev: the PF device
 * @vf_num: VF index to send the message to
 * @req: message data
 * @req_len: length of message
 *
 * Fire-and-forget variant of cxi_send_msg_to_vf() for datapath fan-out (e.g. MC
 * software-switch RX fan-out) where the VF reply is not needed. The VF notif
 * handler processes the message but skips the response (VF_PF_MSG_F_NO_REPLY),
 * so a slow or stuck VF cannot stall delivery to the other VFs.
 *
 * Return: 0 on success, negative errno on error.
 */
int cxi_send_async_msg_to_vf(struct cxi_dev *cdev, int vf_num, const void *req,
			     size_t req_len)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc = 0;

	if (!cdev->is_physfn)
		return -EINVAL;

	if (vf_num < 0 || vf_num >= hw->num_vfs)
		return -EINVAL;

	mutex_lock(&hw->vfs[vf_num].notif_lock);
	if (hw->vfs[vf_num].notif_sock)
		rc = cxi_vsock_async_send(cdev, hw->vfs[vf_num].notif_sock,
					  req, req_len);
	else
		rc = -ENOTCONN;
	mutex_unlock(&hw->vfs[vf_num].notif_lock);

	return rc;
}
EXPORT_SYMBOL(cxi_send_async_msg_to_vf);

/**
 * cxi_notify_vf_async_event() - Forward an async event to a single VF
 *
 * @cdev: the PF device
 * @vf_idx: VF index (0-based)
 * @event: the event to forward
 */
int cxi_notify_vf_async_event(struct cxi_dev *cdev, int vf_idx,
			      enum cxi_async_event event)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	const struct cass_vf_notif_async_event notif = {
		.op    = CASS_VF_NOTIF_OP_ASYNC_EVENT,
		.event = event,
	};
	int rc = 0;

	mutex_lock(&hw->vfs[vf_idx].notif_lock);
	if (hw->vfs[vf_idx].notif_sock) {
		rc = cxi_vsock_async_send(cdev, hw->vfs[vf_idx].notif_sock,
					  &notif, sizeof(notif));
		if (rc)
			cxidev_dbg(cdev, "vf %d: async event send failed: %d\n",
				   vf_idx, rc);
	}
	mutex_unlock(&hw->vfs[vf_idx].notif_lock);

	return rc;
}
EXPORT_SYMBOL(cxi_notify_vf_async_event);

/**
 * cxi_notify_vfs_async_event() - Forward an async event to all connected VFs
 *
 * @cdev: the PF device
 * @event: the event to forward
 *
 * Sends @event to every VF that has an active notification socket, with no
 * per-VF filtering.  Callers that need per-VF policy (e.g. link-state
 * override) should use a dedicated helper instead.
 */
int cxi_notify_vfs_async_event(struct cxi_dev *cdev, enum cxi_async_event event)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int i;
	int rc;
	int first_error = 0;

	if (!cdev->is_physfn)
		return -EINVAL;

	for (i = 0; i < hw->num_vfs; i++) {
		rc = cxi_notify_vf_async_event(cdev, i, event);
		if (rc && !first_error)
			first_error = rc;
	}

	return first_error;
}
EXPORT_SYMBOL(cxi_notify_vfs_async_event);

/**
 * cxi_register_msg_relay() - Register a VF to PF message handler
 *
 * The user driver, when inserting a new PF device, is registering a
 * callback to receive messages from VFs.
 *
 * @cdev: the device
 * @msg_relay: the message handler
 * @msg_relay_data: opaque pointer to give when caller the handler
 */
int cxi_register_msg_relay(struct cxi_dev *cdev, cxi_msg_relay_t msg_relay,
			   void *msg_relay_data)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;

	if (!cdev->is_physfn)
		return -EINVAL;

	mutex_lock(&hw->msg_relay_lock);

	if (hw->msg_relay) {
		rc = -EINVAL;
	} else {
		hw->msg_relay = msg_relay;
		hw->msg_relay_data = msg_relay_data;
		rc = 0;
	}

	mutex_unlock(&hw->msg_relay_lock);

	return rc;
}
EXPORT_SYMBOL(cxi_register_msg_relay);

int cxi_unregister_msg_relay(struct cxi_dev *cdev)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;

	mutex_lock(&hw->msg_relay_lock);

	if (!hw->msg_relay) {
		rc = -EINVAL;
	} else {
		hw->msg_relay = NULL;
		hw->msg_relay_data = NULL;
		rc = 0;
	}

	mutex_unlock(&hw->msg_relay_lock);

	return rc;
}
EXPORT_SYMBOL(cxi_unregister_msg_relay);

int cass_vf_get_token(struct cxi_dev *cdev, int vf_idx, unsigned int *token)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);

	if (!cdev->is_physfn)
		return -EOPNOTSUPP;

	if (vf_idx < 0 || vf_idx >= hw->num_vfs)
		return -EINVAL;

	*token = hw->vfs[vf_idx].token;
	return 0;
}
EXPORT_SYMBOL(cass_vf_get_token);

#endif /* CXI_DISABLE_SRIOV */
