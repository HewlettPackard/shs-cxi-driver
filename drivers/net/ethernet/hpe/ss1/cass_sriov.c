// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019, 2024-2026 Hewlett Packard Enterprise Development LP */

/* Cassini SRIOV and VFs handler
 *
 * AF_VSOCK sockets are used to pass messages and responses from the VF to the
 * PF, both when the VF is attached to a guest (using the appropriate hypervisor
 * vsock transport), and when the VF is attached to the host (using the
 * vsock_loopback module).
 *
 * The VF index of an incoming vsock connection is identified by probing the
 * PF-to-VF interrupt of each unaccounted-for VF and waiting for a response.
 * After this initial handshake, communication is always initiated by the VF,
 * and an acknowledgment from the PF is always expected. Messages are prefixed
 * with an integer result code (only used by the response from the PF) and
 * message length.
 */

#include <linux/pci.h>
#include <linux/types.h>
#include <linux/kmod.h>
#include <linux/kthread.h>
#include <linux/kvm_host.h>
#include <linux/net.h>
#include <linux/vfio.h>
#include <linux/vm_sockets.h>
#include <net/sock.h>

#include "cass_core.h"
#include "cass_vf_notif.h"
#include "cxi_core.h"

MODULE_SOFTDEP("pre: vsock vsock_loopback");

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

int cxi_send_msg_to_vf(struct cxi_dev *cdev, int vf_num, const void *req,
		       size_t req_len, void *rsp, size_t *rsp_len)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(cxi_send_msg_to_vf);

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

#else /* CXI_DISABLE_SRIOV */

/* TODO: make port configurable? (0x17db is arbitrary, taken from C1 PCI vendor ID) */
#define CXI_SRIOV_VSOCK_PORT 0x17db
#define CXI_SRIOV_VSOCK_NOTIF_PORT (CXI_SRIOV_VSOCK_PORT + 1)

/* Handshake commands sent from PF to VF */
#define CXI_SRIOV_CMD_RESET 0x17db0001  /* Prepare for IRQ probe. Respond with READY */
#define CXI_SRIOV_CMD_CHECK 0x17db0002  /* Report HIT or MISS whether IRQ was received */
#define CXI_SRIOV_CMD_DONE  0x17db0003  /* Handshake complete */

/* Handshake responses sent from VF to PF */
#define CXI_SRIOV_RSP_READY 0x17db8001  /* Ready for IRQ probe */
#define CXI_SRIOV_RSP_HIT   0x17db8002  /* IRQ was received */
#define CXI_SRIOV_RSP_MISS  0x17db8003  /* IRQ was not received */

/* PF-side timeout for vsock. Kept short so that listener-thread loop still runs. */
#define CXI_SRIOV_PF_TIMEOUT (HZ / 4)

/* VF-side timeout - longer than PF timeout, to allow time for PF to respond to requests */
#define CXI_SRIOV_VF_TIMEOUT (HZ * 10)

/* VF-side timeout for waiting for an IRQ during handshake. Must be shorter than
 * CXI_SRIOV_PF_TIMEOUT to ensure VF responds before PF's read times out.
 */
#define CXI_SRIOV_IRQ_TIMEOUT (CXI_SRIOV_PF_TIMEOUT / 4)

static int write_message_to_vsock(struct socket *sock, const void *msg,
				  size_t msg_len, int msg_rc, int seq)
{
	struct vf_pf_msg_hdr hdr = {
		.len = msg_len,
		.rc = msg_rc,
		.uid = __kuid_val(current_euid()),
		.gid = __kgid_val(current_egid()),
		.seq = seq,
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

static int read_message_from_vsock(struct socket *sock, void *msg,
				   size_t *msg_len, int *msg_rc,
				   uid_t *uid, gid_t *gid, int *seq)
{
	struct vf_pf_msg_hdr hdr;
	struct msghdr msghdr = {};
	struct kvec hdrvec = {
		.iov_base = &hdr,
		.iov_len = sizeof(hdr),
	};
	struct kvec msgvec = {
		.iov_base = msg,
	};
	int rc;

	rc = kernel_recvmsg(sock, &msghdr, &hdrvec, 1, sizeof(hdr), 0);
	if (rc < 0)
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

	if (hdr.len > MAX_VFMSG_SIZE) {
		pr_err("Bad message size (%u > %zu)", hdr.len, MAX_VFMSG_SIZE);
		return -EINVAL;
	}

	if ((!msg_len && hdr.len > 0) || (msg_len && *msg_len < hdr.len)) {
		pr_err("Message buffer too small (%u > %zu)", hdr.len, msg_len ? *msg_len : 0);
		return -EINVAL;
	}

	if (msg_len) {
		*msg_len = hdr.len;
		msgvec.iov_len = hdr.len;
	}
	if (msg_rc)
		*msg_rc = hdr.rc;
	if (uid)
		*uid = hdr.uid;
	if (gid)
		*gid = hdr.gid;
	if (seq)
		*seq = hdr.seq;

	if (msg_len && msg) {
		rc = kernel_recvmsg(sock, &msghdr, &msgvec, 1, hdr.len, 0);
		if (rc >= 0 && rc < hdr.len) {
			pr_err("Not enough data received for response (%u < %u)",
			       rc, hdr.len);
			return -EINVAL;
		}
	}

	return rc;
}

/* Given a PF's pci_dev struct, find the pci_dev of one of its VFs */
static struct pci_dev *get_vf_pdev(struct pci_dev *pdev, int vf_idx)
{
	int devfn = pci_iov_virtfn_devfn(pdev, vf_idx);

	if (devfn < 0)
		return ERR_PTR(devfn);
	return pci_get_slot(pdev->bus, devfn);
}

/* Identify the KVM task associated with a VF that is bound to a guest VM. */
static struct task_struct *pf_get_kvm_task(struct cass_vf *vf)
{
	struct cass_dev *hw = vf->hw;
	struct pci_dev *vf_pdev = NULL;
	struct vfio_device *vfio_dev = NULL;
	struct task_struct *task = NULL;

	vf_pdev = get_vf_pdev(hw->cdev.pdev, vf->vf_idx);
	if (IS_ERR(vf_pdev)) {
		cxidev_err(&hw->cdev, "vf %d: could not get device", vf->vf_idx);
		return ERR_PTR(PTR_ERR(vf_pdev));
	}

	cxidev_dbg(&hw->cdev, "vf %d: device at %s", vf->vf_idx, pci_name(vf_pdev));

	if (!vf_pdev->driver) {
		task = ERR_PTR(-ENODEV);
	} else if (!strncmp(vf_pdev->driver->name, "vfio-pci", strlen("vfio-pci"))) {
		/* VF is under control of VFIO driver, look for KVM task. */
		vfio_dev = pci_get_drvdata(vf_pdev);
		if (vfio_dev->kvm) {
			task = get_pid_task(find_get_pid(vfio_dev->kvm->userspace_pid),
					    PIDTYPE_PID);
		} else {
			task = ERR_PTR(-ESRCH);
		}
	} else if (!strncmp(vf_pdev->driver->name, KBUILD_MODNAME,
			    strlen(KBUILD_MODNAME))) {
		/* VF is under control of our driver, KVM task is not applicable */
		task = NULL;
	} else {
		task = ERR_PTR(-EPERM);
	}
	pci_dev_put(vf_pdev);
	return task;
}

/* Handler thread for incoming messages from the VF driver to the PF. 1 instance
 * per active VF.
 */
static int pf_vf_msghandler(void *data)
{
	struct cass_vf *vf = (struct cass_vf *)data;
	struct cass_dev *hw = vf->hw;
	struct task_struct *kvm_task;
	int rc, msg_rc;
	size_t request_len, reply_len;
	uid_t uid;
	gid_t gid;
	int seq;

	vf->req_sock->sk->sk_rcvtimeo = CXI_SRIOV_PF_TIMEOUT;

	cxidev_dbg(&hw->cdev, "vf %d: started message handler", vf->vf_idx);

	kvm_task = pf_get_kvm_task(vf);
	if (IS_ERR(kvm_task)) {
		rc = PTR_ERR(kvm_task);
		goto err;
	}
	vf->kvm_task = kvm_task;

	while (!kthread_should_stop()) {
		request_len = MAX_VFMSG_SIZE;
		rc = read_message_from_vsock(vf->req_sock, vf->request,
					     &request_len, NULL, &uid, &gid, &seq);
		if (rc == -EAGAIN) {
			continue;
		} else if (rc == -EINTR) {
			/* Expected when thread is asked to terminate */
			continue;
		} else if (rc < 0) {
			cxidev_err(&hw->cdev, "vf %d: error reading request: %d",
				   vf->vf_idx, rc);
			break;
		} else if (rc == 0) {
			cxidev_err(&hw->cdev, "vf %d: connection closed by VF",
				   vf->vf_idx);
			break;
		}

		cxidev_dbg(&hw->cdev, "vf %d: got %ld byte message", vf->vf_idx,
			   request_len);

		if (vf->kvm_task) {
			/* VFs associated with a guest virtual machine must use the
			 * credentials of the VM's process on the host, rather than the
			 * guest's user creds that come over the vsock.
			 */
			const struct cred *cred;

			rcu_read_lock();
			cred = rcu_dereference(vf->kvm_task->cred);
			uid = __kuid_val(cred->uid);
			gid = __kgid_val(cred->gid);
			rcu_read_unlock();
		}

		mutex_lock(&hw->msg_relay_lock);
		if (hw->msg_relay) {
			reply_len = MAX_VFMSG_SIZE;
			msg_rc = hw->msg_relay(hw->msg_relay_data, vf->vf_idx,
					       vf->request, request_len, uid, gid,
					       vf->reply, &reply_len);
		} else {
			reply_len = 0;
			msg_rc = -ENODEV;
		}
		mutex_unlock(&hw->msg_relay_lock);

		if (reply_len > MAX_VFMSG_SIZE) {
			reply_len = 0;
			msg_rc = -E2BIG;
		}

		cxidev_dbg(&hw->cdev, "vf %d: responding with %ld bytes, rc=%d",
			   vf->vf_idx, reply_len, msg_rc);
		rc = write_message_to_vsock(vf->req_sock, vf->reply, reply_len,
					    msg_rc, seq);
		if (rc < 0) {
			cxidev_err(&hw->cdev, "vf %d: error sending response: %d",
				   vf->vf_idx, rc);
			break;
		}
	}

	/* Send a NULL request message to indicate that this VF disconnected */
	mutex_lock(&hw->msg_relay_lock);
	if (hw->msg_relay)
		hw->msg_relay(hw->msg_relay_data, vf->vf_idx, NULL, 0, 0, 0, NULL,
			      &reply_len);
	mutex_unlock(&hw->msg_relay_lock);

	if (rc > 0)
		rc = 0;

err:
	cxidev_dbg(&hw->cdev, "vf %d: handler exiting, rc=%d", vf->vf_idx, rc);

	if (vf->kvm_task)
		put_task_struct(vf->kvm_task);
	vf->kvm_task = NULL;

	kernel_sock_shutdown(vf->req_sock, SHUT_RDWR);
	sock_release(vf->req_sock);
	vf->req_sock = NULL;

	if (vf->notif_sock) {
		kernel_sock_shutdown(vf->notif_sock, SHUT_RDWR);
		sock_release(vf->notif_sock);
		vf->notif_sock = NULL;
	}

	cass_ac_phys_free(hw, vf->phys_ac);
	vf->phys_ac = 0;

	while (!kthread_should_stop())
		schedule_timeout_interruptible(CXI_SRIOV_PF_TIMEOUT);

	return rc;
}

static int handshake_send_cmd(struct cass_dev *hw, struct socket *sock,
			      unsigned int cmd)
{
	int rc;

	rc = write_message_to_vsock(sock, &cmd, sizeof(cmd), 0, 0);
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
					     NULL, NULL, NULL);
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

/* Probe a range of VFs by firing IRQs for VFs in [range_min, range_max], and
 * asking the VF whether it got an IRQ. Returns 1 if hit, 0 if miss, negative on
 * error.
 */
static int pf_probe_vf_range(struct cass_dev *hw, struct socket *sock,
			     int range_min, int range_max)
{
	int i, rc, rsp;
	union c_pi_ipd_cfg_pf_vf_irq irqs = {
		.irq = 0,
	};

	cxidev_dbg(&hw->cdev, "probing for VF in range [%d, %d]", range_min, range_max);

	/* Only probe VFs that are not already connected */
	for (i = range_min; i <= range_max; i++)
		if (!hw->vfs[i].req_sock)
			irqs.irq |= 1ULL << i;
	if (!irqs.irq)
		return 0;

	/* 1: Tell VF to reinit completion and wait for READY */
	rc = handshake_send_cmd(hw, sock, CXI_SRIOV_CMD_RESET);
	if (rc < 0)
		return rc;

	rsp = handshake_read_rsp(hw, sock);
	if (rsp < 0)
		return rsp;
	if (rsp != CXI_SRIOV_RSP_READY) {
		cxidev_err(&hw->cdev, "VF handshake: expected READY, got %x", rsp);
		return -EPROTO;
	}

	/* 2: Fire IRQs for the range */
	cass_write(hw, C_PI_IPD_CFG_PF_VF_IRQ, &irqs,
		   sizeof(union c_pi_ipd_cfg_pf_vf_irq));

	/* 3: Ask VF to check for IRQ */
	rc = handshake_send_cmd(hw, sock, CXI_SRIOV_CMD_CHECK);
	if (rc < 0)
		return rc;

	rsp = handshake_read_rsp(hw, sock);
	if (rsp < 0)
		return rsp;

	if (rsp == CXI_SRIOV_RSP_HIT)
		return 1;
	else if (rsp == CXI_SRIOV_RSP_MISS)
		return 0;

	cxidev_err(&hw->cdev, "VF handshake: expected HIT/MISS, got %x", rsp);
	return -EPROTO;
}

/* PF side of PF-VF handshake: Identify which VF an incoming connection belongs
 * to, by binary-searching with PF-to-VF interrupts. The PF drives the protocol;
 * the VF only responds.
 */
static int pf_vf_handshake(struct cass_dev *hw, struct socket *sock)
{
	int lo = 0;
	int hi = hw->num_vfs - 1;
	int mid;
	int rc;

	while (lo < hi) {
		mid = lo + (hi - lo) / 2;

		rc = pf_probe_vf_range(hw, sock, lo, mid);
		if (rc < 0)
			return rc;
		if (rc == 1) {
			hi = mid;
			continue;
		}

		rc = pf_probe_vf_range(hw, sock, mid + 1, hi);
		if (rc < 0)
			return rc;
		if (rc == 1) {
			lo = mid + 1;
			continue;
		}

		cxidev_err(&hw->cdev, "VF handshake: VF not found");
		return -ENOENT;
	}

	/* If only one VF is present, the binary search above is a no-op, but
	 * we still want to verify the presence of the VF.
	 */
	if (hw->num_vfs == 1) {
		rc = pf_probe_vf_range(hw, sock, lo, lo);
		if (rc < 0) {
			return rc;
		} else if (rc == 0) {
			cxidev_err(&hw->cdev, "VF handshake: VF not found");
			return -ENOENT;
		}
	}

	/* Tell VF the handshake is complete */
	rc = handshake_send_cmd(hw, sock, CXI_SRIOV_CMD_DONE);
	if (rc < 0)
		return rc;

	return lo;
}

/* Handle an incoming request connection from a VF */
static void handle_vf_req_conn(struct cass_dev *hw,
			       struct socket *incoming)
{
	struct sockaddr_vm peeraddr;
	struct cass_vf *vf;
	int rc, vf_idx;

	rc = kernel_getpeername(incoming, (struct sockaddr *)&peeraddr);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "could not get peer addr for vf: %d", rc);
		goto close_sock;
	}

	vf_idx = pf_vf_handshake(hw, incoming);
	if (vf_idx < 0) {
		cxidev_err(&hw->cdev, "vf handshake from cid %d failed: %d",
			   peeraddr.svm_cid, vf_idx);
		goto close_sock;
	}

	cxidev_dbg(&hw->cdev, "pf got request connection from cid %d, vf %d",
		   peeraddr.svm_cid, vf_idx);

	vf = &hw->vfs[vf_idx];
	if (vf->req_sock) {
		cxidev_err(&hw->cdev, "vf %d already in use", vf_idx);
		goto close_sock;
	}

	/* The listener loop periodically cleans up stale VF message handler
	 * threads but we should check here too, in case a new connection comes
	 * in before the listener loop has a chance to clean up the old one.
	 */
	if (vf->task) {
		kthread_stop(vf->task);
		vf->task = NULL;
	}

	mutex_init(&vf->notif_lock);

	vf->vf_idx = vf_idx;
	vf->hw = hw;
	vf->req_sock = incoming;
	get_random_bytes(&vf->token, sizeof(vf->token));

	rc = cass_ac_phys_alloc(hw, true, vf_idx);
	if (rc <= 0) {
		cxidev_err(&hw->cdev, "could not allocate ac for vf %d: %d",
			   vf_idx, rc);
		vf->req_sock = NULL;
		goto close_sock;
	}
	vf->phys_ac = rc;
	cxidev_dbg(&hw->cdev, "allocated acid %d for vf %d", vf->phys_ac, vf_idx);

	vf->task = kthread_run(pf_vf_msghandler, vf, "cxi_vf_%d", vf_idx);
	if (IS_ERR(vf->task)) {
		cxidev_err(&hw->cdev, "failed to start handler for vf %d", vf_idx);
		cass_ac_phys_free(hw, vf->phys_ac);
		vf->phys_ac = 0;
		vf->req_sock = NULL;
		vf->task = NULL;
		goto close_sock;
	}
	return;

close_sock:
	kernel_sock_shutdown(incoming, SHUT_RDWR);
	sock_release(incoming);
}

/* Handle an incoming notification connection from a VF */
static void handle_vf_notif_conn(struct cass_dev *hw,
				 struct socket *incoming)
{
	struct sockaddr_vm peeraddr;
	struct cass_vf *vf;
	int rc, vf_idx, i;
	unsigned int token;
	struct cass_vf_notif_ping ping = {
		.op = CASS_VF_NOTIF_OP_PING,
	};
	size_t msg_len;

	rc = kernel_getpeername(incoming, (struct sockaddr *)&peeraddr);
	if (rc < 0) {
		cxidev_err(&hw->cdev,
			   "could not get peer addr for notification connection: %d", rc);
		goto close_sock;
	}

	/* Read token to identify which VF this is */
	msg_len = sizeof(token);
	do {
		rc = read_message_from_vsock(incoming, &token, &msg_len, NULL, NULL, NULL, NULL);
		if (rc == -EINTR)
			schedule();
	} while (rc == -EINTR);
	if (rc < 0) {
		cxidev_err(&hw->cdev,
			   "could not read token from notification connection: %d", rc);
		goto close_sock;
	}

	if (msg_len != sizeof(token)) {
		cxidev_err(&hw->cdev, "invalid token size: %zu", msg_len);
		goto close_sock;
	}

	/* Find VF by matching token */
	vf_idx = -1;
	for (i = 0; i < hw->num_vfs; i++) {
		if (hw->vfs[i].req_sock && hw->vfs[i].token == token) {
			vf_idx = i;
			break;
		}
	}

	if (vf_idx < 0) {
		cxidev_err(&hw->cdev, "notification connection with unknown token %u",
			   token);
		goto close_sock;
	}

	cxidev_dbg(&hw->cdev, "pf got notification connection from cid %d, vf %d",
		   peeraddr.svm_cid, vf_idx);

	vf = &hw->vfs[vf_idx];
	if (vf->notif_sock) {
		cxidev_err(&hw->cdev, "vf %d notification socket already in use", vf_idx);
		goto close_sock;
	}

	vf->notif_seq = 0;
	vf->notif_sock = incoming;
	cxidev_dbg(&hw->cdev, "vf %d: notification socket connected", vf_idx);

	/* Send test notification */
	msg_len = sizeof(ping);
	rc = cxi_send_msg_to_vf(&hw->cdev, vf_idx, &ping, msg_len,
				NULL, NULL);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf %d: could not send test notification: %d",
			   vf_idx, rc);
		vf->notif_sock = NULL;
		goto close_sock;
	}

	return;

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

	rc = kernel_bind(*sock, (struct sockaddr *)&addr, sizeof(addr));
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

/* Combined listener thread for incoming connections from VFs to the PF.
 * Handles both request and notification sockets. 1 instance only.
 */
static int pf_vf_listener(void *data)
{
	int rc, vf_idx;
	struct cass_dev *hw = (struct cass_dev *)data;

	cxidev_dbg(&hw->cdev, "started vf listener");

	rc = vsock_create_listen(&hw->vf_req_sock, CXI_SRIOV_VSOCK_PORT,
				 CXI_SRIOV_PF_TIMEOUT, hw->num_vfs);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "could not create vf request listener socket: %d", rc);
		return rc;
	}

	rc = vsock_create_listen(&hw->vf_notif_sock, CXI_SRIOV_VSOCK_NOTIF_PORT,
				 CXI_SRIOV_PF_TIMEOUT, hw->num_vfs);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "could not create vf notification listener socket: %d", rc);
		goto shutdown_req;
	}

	while (!kthread_should_stop()) {
		struct socket *incoming;

		rc = kernel_accept(hw->vf_req_sock, &incoming, 0);
		if (rc == 0) {
			handle_vf_req_conn(hw, incoming);
			continue;
		} else if (rc != -EAGAIN && rc != -EINTR) {
			cxidev_err(&hw->cdev, "vf request listener socket accept error: %d", rc);
			break;
		}

		rc = kernel_accept(hw->vf_notif_sock, &incoming, 0);
		if (rc == 0) {
			handle_vf_notif_conn(hw, incoming);
			continue;
		} else if (rc != -EAGAIN && rc != -EINTR) {
			cxidev_err(&hw->cdev, "vf notification listener socket accept error: %d",
				   rc);
			break;
		}

		/* Periodically clean up old handler threads that have
		 * relinquished their request sockets
		 */
		for (vf_idx = 0; vf_idx < hw->num_vfs; vf_idx++) {
			if (!hw->vfs[vf_idx].req_sock && hw->vfs[vf_idx].task) {
				kthread_stop(hw->vfs[vf_idx].task);
				hw->vfs[vf_idx].task = NULL;
			}
		}
	}

	cxidev_dbg(&hw->cdev, "vf listener exiting");

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

	kernel_sock_shutdown(hw->vf_notif_sock, SHUT_RDWR);
	sock_release(hw->vf_notif_sock);
	hw->vf_notif_sock = NULL;

shutdown_req:
	kernel_sock_shutdown(hw->vf_req_sock, SHUT_RDWR);
	sock_release(hw->vf_req_sock);
	hw->vf_req_sock = NULL;

	return rc;
}

static void disable_sriov(struct pci_dev *pdev)
{
	struct cass_dev *hw = pci_get_drvdata(pdev);

	pci_disable_sriov(pdev);

	if (hw->vf_listener) {
		kthread_stop(hw->vf_listener);
		hw->vf_listener = NULL;
	}

	hw->num_vfs = 0;
}

static int enable_sriov(struct pci_dev *pdev, int num_vfs)
{
	int rc;
	int sriov;
	u16 offset;
	u16 stride;
	union c_pi_cfg_pri_sriov pri_sriov = {};
	struct cass_dev *hw = pci_get_drvdata(pdev);

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

	if (!hw->vf_listener)
		hw->vf_listener = kthread_run(pf_vf_listener, hw, "cxi_vf_listener");
	if (IS_ERR(hw->vf_listener)) {
		cxidev_err(&hw->cdev, "could not start vf listener thread");
		rc = PTR_ERR(hw->vf_listener);
		hw->vf_listener = NULL;
		goto err_novf;
	}

	/* The VF Offset and Stride need to match the SR-IOV configuration. */
	sriov = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!sriov) {
		cxidev_err(&hw->cdev, "No extended capabilities found\n");
		rc = -ENODEV;
		goto err_kill_listener;
	}

	pci_read_config_word(pdev, sriov + PCI_SRIOV_VF_OFFSET, &offset);
	pci_read_config_word(pdev, sriov + PCI_SRIOV_VF_STRIDE, &stride);

	pri_sriov.vf_offset = offset;
	pri_sriov.vf_stride = stride;

	cass_write(hw, C_PI_CFG_PRI_SRIOV, &pri_sriov,
		   sizeof(union c_pi_cfg_pri_sriov));

	rc = pci_enable_sriov(pdev, num_vfs);
	if (rc) {
		cxidev_err(&hw->cdev, "SRIOV enable failed %d\n", rc);
		goto err_kill_listener;
	}

	return num_vfs;

err_kill_listener:
	kthread_stop(hw->vf_listener);
	hw->vf_listener = NULL;
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

static irqreturn_t pf_to_vf_int_cb(int irq, void *context)
{
	struct cass_dev *hw = context;

	complete(&hw->pf_to_vf_comp);
	return IRQ_HANDLED;
}

/* VF-side handler thread for receiving notifications from PF */
static int vf_notif_handler(void *data)
{
	struct cass_dev *hw = (struct cass_dev *)data;
	int rc;
	size_t msg_len, rsp_len;

	cxidev_dbg(&hw->cdev, "started notification handler");

	while (!kthread_should_stop()) {
		msg_len = MAX_VFMSG_SIZE;
		rc = read_message_from_vsock(hw->vf_notif_sock, hw->vf_notif_buf,
					     &msg_len, NULL, NULL, NULL, NULL);
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

		rsp_len = 0;
		rc = dispatch_vf_notif(hw, hw->vf_notif_buf, msg_len,
				       hw->vf_notif_rsp_buf, &rsp_len);
		rc = write_message_to_vsock(hw->vf_notif_sock, hw->vf_notif_rsp_buf,
					    rsp_len, rc, 0);
		if (rc < 0) {
			cxidev_err(&hw->cdev, "failed to send notification response: %d", rc);
			break;
		}
	}

	cxidev_dbg(&hw->cdev, "notification handler exiting");

	return 0;
}

/* VF side of VF-PF handshake: respond to commands from PF.
 * Returns 0 on success, negative on error.
 */
static int vf_handshake(struct cass_dev *hw)
{
	int rc;
	unsigned int cmd;
	unsigned int rsp;
	size_t msg_len;

	while (true) {
		msg_len = sizeof(cmd);
		do {
			rc = read_message_from_vsock(hw->vf_req_sock, &cmd,
						     &msg_len, NULL,
						     NULL, NULL, NULL);
			if (rc == -EINTR)
				schedule();
		} while (rc == -EINTR);
		if (rc < 0) {
			cxidev_err(&hw->cdev, "VF handshake: error reading cmd: %d",
				   rc);
			return rc;
		} else if (rc == 0) {
			cxidev_err(&hw->cdev, "handshake: PF closed connection");
			return -ENOTCONN;
		} else if (msg_len != sizeof(cmd)) {
			cxidev_err(&hw->cdev, "VF handshake: expected cmd of size %zu, got %zu",
				   sizeof(cmd), msg_len);
			return -EPROTO;
		}

		switch (cmd) {
		case CXI_SRIOV_CMD_RESET:
			cxidev_dbg(&hw->cdev, "handshake: got RESET command from PF");
			reinit_completion(&hw->pf_to_vf_comp);
			rsp = CXI_SRIOV_RSP_READY;
			rc = write_message_to_vsock(hw->vf_req_sock, &rsp,
						    sizeof(rsp), 0, 0);
			if (rc < 0) {
				cxidev_err(&hw->cdev,
					   "VF handshake: error sending READY: %d",
					   rc);
				return rc;
			}
			break;

		case CXI_SRIOV_CMD_CHECK:
			cxidev_dbg(&hw->cdev, "handshake: got CHECK command from PF");

			rc = wait_for_completion_timeout(&hw->pf_to_vf_comp,
							 CXI_SRIOV_IRQ_TIMEOUT);
			rsp = rc ? CXI_SRIOV_RSP_HIT : CXI_SRIOV_RSP_MISS;
			rc = write_message_to_vsock(hw->vf_req_sock, &rsp,
						    sizeof(rsp), 0, 0);
			if (rc < 0) {
				cxidev_err(&hw->cdev,
					   "VF handshake: error sending HIT/MISS: %d",
					   rc);
				return rc;
			}
			break;

		case CXI_SRIOV_CMD_DONE:
			cxidev_dbg(&hw->cdev, "handshake: got DONE command from PF, handshake complete");
			return 0;

		default:
			cxidev_err(&hw->cdev,
				   "VF handshake: unexpected cmd from PF: %x",
				   cmd);
			return -EPROTO;
		}
	}
}

int cass_vf_init(struct cass_dev *hw)
{
	int rc;
	const struct cxi_vf_get_token_cmd token_cmd = {
		.op = CXI_OP_VF_GET_TOKEN,
	};
	struct cxi_vf_get_token_resp token_resp;
	size_t resp_len = sizeof(token_resp);
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_port = CXI_SRIOV_VSOCK_PORT,
		.svm_cid = VMADDR_CID_HOST,
	};

	if (!hw->with_vf_support)
		return 0;

	init_completion(&hw->pf_to_vf_comp);

	mutex_init(&hw->vf_cmd_lock);

	scnprintf(hw->pf_vf_int_name, sizeof(hw->pf_vf_int_name),
		  "%s_from_pf", hw->cdev.name);
	hw->pf_vf_vec = pci_irq_vector(hw->cdev.pdev, 0);
	rc = request_irq(hw->pf_vf_vec, pf_to_vf_int_cb, 0, hw->pf_vf_int_name, hw);
	if (rc)
		return rc;

	rc = request_module("vsock");
	if (rc) {
		cxidev_err(&hw->cdev, "could not load vsock module");
		goto free_irq;
	}

	rc = sock_create_kern(&init_net, PF_VSOCK, SOCK_STREAM, 0, &hw->vf_req_sock);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf socket create failed: %d", rc);
		goto free_irq;
	}

	hw->vf_req_sock->sk->sk_rcvtimeo = CXI_SRIOV_VF_TIMEOUT;
	hw->vf_cmd_seq = 0;

	rc = kernel_connect(hw->vf_req_sock, (struct sockaddr *)&addr,
			    sizeof(addr), 0);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf socket connect failed: %d", rc);
		goto release_vf_sock;
	}

	rc = vf_handshake(hw);
	if (rc < 0)
		goto shutdown_vf_sock;

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

	addr.svm_port = CXI_SRIOV_VSOCK_NOTIF_PORT;
	rc = kernel_connect(hw->vf_notif_sock, (struct sockaddr *)&addr,
			    sizeof(addr), 0);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf notif socket connect failed: %d", rc);
		goto release_notif_sock;
	}

	/* Send token to identify this VF */
	rc = write_message_to_vsock(hw->vf_notif_sock, &token_resp.token,
				    sizeof(token_resp.token), 0, 0);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "failed to send token to PF: %d", rc);
		goto shutdown_notif_sock;
	}

	/* Start notification handler thread */
	hw->vf_notif_handler = kthread_run(vf_notif_handler, hw, "cxi_vf_notif");
	if (IS_ERR(hw->vf_notif_handler)) {
		cxidev_err(&hw->cdev, "failed to start notification handler");
		rc = PTR_ERR(hw->vf_notif_handler);
		hw->vf_notif_handler = NULL;
		goto shutdown_notif_sock;
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
free_irq:
	free_irq(hw->pf_vf_vec, hw);
	return rc;
}

void cass_vf_fini(struct cass_dev *hw)
{
	if (!hw->with_vf_support)
		return;

	free_irq(hw->pf_vf_vec, hw);

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
		kernel_sock_shutdown(hw->vf_notif_sock, SHUT_RDWR);
		sock_release(hw->vf_notif_sock);
		hw->vf_notif_sock = NULL;
	}
}

/**
 * cxi_vsock_send() - Send a vsock message using a provided socket
 *
 * @cdev: the device
 * @sock: connected vsock socket
 * @req: message data
 * @req_len: length of message
 * @rsp: buffer for response
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

	if (req_len > MAX_VFMSG_SIZE)
		return -EINVAL;

	if (!sock)
		return -ENOTCONN;

	rc = write_message_to_vsock(sock, req, req_len, 0, seq);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "error sending vsock message: %d", rc);
		return -EPROTO;
	}
	do {
		rc = read_message_from_vsock(sock, rsp, rsp_len, &msg_rc,
					     NULL, NULL, &rsp_seq);
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
