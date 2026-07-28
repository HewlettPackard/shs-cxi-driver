// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

/* Ethernet multicast software-switch core ops.
 *
 * Core (cxi-ss1) side of the core <-> Ethernet software-switch contract:
 * the VF-notification RX dispatch handler, the RX-mode filter sync entry
 * point, and the registration hooks the Ethernet driver uses to install its
 * ops table. See cass_eth_mc_sw_ops.h for the contract.
 */

#include <linux/hpe/cxi/cxi.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/xarray.h>
#include <linux/idr.h>
#include <linux/rcupdate.h>

#include "cass_core.h"
#include "cxi_core.h"
#include "cxi_internal.h"
#include "cass_vf_notif.h"
#include "cass_eth_mc_sw_ops.h"
#include "cxi_eth.h"

/* Per-device PF software-switch registration state.
 *
 * eth_mc_sw ops / cxi_eth: two reader classes share one invariant.
 *  - Data-path readers (rxfanout / txfwd handlers) are LOCKLESS:
 *    rcu_read_lock() + smp_load_acquire(ops) then READ_ONCE(cxi_eth). They
 *    load ops BEFORE ctx to pair with the release store in reg_ops().
 *  - Control slow-paths (VF-relay reconcile, cleanup_vf, sriov_configure)
 *    read both under sync_lock, which excludes reg/unreg.
 * Publish (reg_ops): set cxi_eth, then smp_store_release(ops).
 * Teardown (unreg_ops): clear both under the mutex, then synchronize_rcu()
 * to drain in-flight lockless readers before cxi_eth is freed.
 */
struct cass_eth_mc_sw {
	const struct cass_eth_mc_sw_ops *ops;
	struct cxi_eth *cxi_eth;
	/* Serializes ops (un)registration, the VF-relay reconcile, cleanup_vf
	 * and sriov_configure. The PF's own reconcile is instead serialized by
	 * the mc_switch mc_filters xa_lock.
	 */
	struct mutex sync_lock;
};

/* Allocate and initialise the per-device switch registration state. */
int cass_eth_mc_sw_alloc(struct cass_dev *hw)
{
	struct cass_eth_mc_sw *sw;

	sw = kzalloc(sizeof(*sw), GFP_KERNEL);
	if (!sw)
		return -ENOMEM;

	mutex_init(&sw->sync_lock);
	hw->eth_mc_sw = sw;

	return 0;
}

/* Free the per-device switch registration state. NULL-safe and idempotent. */
void cass_eth_mc_sw_free(struct cass_dev *hw)
{
	struct cass_eth_mc_sw *sw = hw->eth_mc_sw;

	if (!sw)
		return;

	hw->eth_mc_sw = NULL;
	mutex_destroy(&sw->sync_lock);
	kfree(sw);
}

/* Return the registered PF Ethernet context, or NULL if unregistered. */
struct cxi_eth *cass_eth_mc_sw_ctx(const struct cass_dev *hw)
{
	struct cass_eth_mc_sw *sw = hw->eth_mc_sw;

	return sw ? READ_ONCE(sw->cxi_eth) : NULL;
}
EXPORT_SYMBOL(cass_eth_mc_sw_ctx);

int cass_eth_mc_sw_vf_notif_rxfanout_hdlr(struct cass_dev *hw,
					  const void *cmd_in,
					  void **resp,
					  size_t *resp_len)
{
	struct cass_eth_mc_sw *sw = hw->eth_mc_sw;
	const struct cass_eth_mc_sw_ops *ops;
	struct cxi_eth *ctx;
	const struct cass_vf_notif_mc_sw_rx_fanout_pkt *pkt = cmd_in;
	int rc;
	(void)resp;
	(void)resp_len;

	if (!sw)
		return -EOPNOTSUPP;

	rcu_read_lock();

	/* Acquire the ops table published by cass_eth_mc_sw_reg_ops() so that
	 * cxi_eth is observed fully initialised before it is used.
	 */
	ops = smp_load_acquire(&sw->ops);
	ctx = READ_ONCE(sw->cxi_eth);
	if (!ops || !ctx || !ops->vf_recv_rxfout_pkt) {
		rcu_read_unlock();
		return -EOPNOTSUPP;
	}

	rc = ops->vf_recv_rxfout_pkt(ctx, pkt->frame, pkt->frame_len,
				     pkt->csum_state, pkt->csum);
	rcu_read_unlock();

	return rc;
}

/**
 * cass_eth_mc_sw_sync_rx_mode_vf() - Sync MC list and RX mode flags for VF
 * @cdev: VF CXI device
 * @mc_mac_addrs: Array of multicast MAC addresses
 * @mc_count: Number of multicast MAC addresses in array
 * @ndev_flags: Netdev flags (IFF_ALLMULTI, IFF_BROADCAST, etc)
 *
 * VF version: Sends the request to the PF via vsock.
 * PF performs hardware programming and software state reconciliation.
 *
 * Return: 0 on success, negative errno on error
 */
static int cass_eth_mc_sw_sync_rx_mode_vf(struct cxi_dev *cdev,
					  const u64 *mc_mac_addrs, u16 mc_count,
					  u16 ndev_flags)
{
	struct cxi_eth_sync_rx_mode_cmd *cmd;
	size_t req_len;
	size_t resp_len = 0;
	int rc;

	req_len = struct_size(cmd, mac_addrs, mc_count);
	cmd = kmalloc(req_len, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->op = CXI_OP_ETH_SYNC_RX_MODE_CMD;
	cmd->resp = NULL;
	cmd->mc_count = mc_count;
	cmd->ndev_flags = ndev_flags;

	if (mc_count && mc_mac_addrs)
		memcpy(cmd->mac_addrs, mc_mac_addrs,
		       mc_count * sizeof(*mc_mac_addrs));

	rc = cxi_send_msg_to_pf(cdev, cmd, req_len, NULL, &resp_len);
	kfree(cmd);

	return rc;
}

/**
 * cass_eth_mc_sw_sync_rx_mode() - Sync MC list and RX mode flags
 * @cdev: CXI device owning the Ethernet instance
 * @mc_mac_addrs: Array of multicast MAC addresses
 * @mc_count: Number of multicast MAC addresses in array
 * @ndev_flags: Netdev flags (IFF_ALLMULTI, IFF_BROADCAST, etc)
 * @is_vf: true if @vf_index identifies a VF, false for the PF
 * @vf_index: VF index (valid only when @is_vf)
 *
 * Exported mc_sw API used by the Ethernet driver and the VF->PF relay path.
 *
 * Return: 0 on success, negative errno on error
 */
int cass_eth_mc_sw_sync_rx_mode(struct cxi_dev *cdev,
				const u64 *mc_mac_addrs, u16 mc_count,
				u16 ndev_flags, bool is_vf, u8 vf_index)
{
	const struct cass_eth_mc_sw_ops *ops;
	struct cxi_eth *ctx;
	struct cass_dev *hw;
	struct cass_eth_mc_sw *sw;
	int rc;

	if (!cdev)
		return -EINVAL;

	hw = container_of(cdev, struct cass_dev, cdev);

	if (!cdev->is_physfn)
		return cass_eth_mc_sw_sync_rx_mode_vf(cdev,
						      mc_mac_addrs, mc_count,
						      ndev_flags);

	if (is_vf && vf_index >= C_NUM_VFS)
		return -EINVAL;

	if (mc_count && !mc_mac_addrs)
		return -EINVAL;

	sw = hw->eth_mc_sw;
	mutex_lock(&sw->sync_lock);
	ops = sw->ops;
	ctx = sw->cxi_eth;
	if (!ops || !ctx) {
		mutex_unlock(&sw->sync_lock);
		return -ENODEV;
	}

	rc = ops->sync_rx_mode_filters_pf(ctx, mc_mac_addrs, mc_count,
					  ndev_flags, is_vf, vf_index);
	mutex_unlock(&sw->sync_lock);

	return rc;
}
EXPORT_SYMBOL(cass_eth_mc_sw_sync_rx_mode);

/* Register/unregister the PF-side software-switch operations. The filter
 * implementation registers its ops table at init and clears it at teardown;
 * the core RX-mode sync/teardown paths invoke it through hw->eth_mc_sw->ops.
 */
void cass_eth_mc_sw_reg_ops(struct cxi_dev *cdev,
			    const struct cass_eth_mc_sw_ops *ops,
			    void *ctx)
{
	struct cass_dev *hw = cxi_to_cass_dev(cdev);
	struct cass_eth_mc_sw *sw = hw->eth_mc_sw;

	mutex_lock(&sw->sync_lock);
	WRITE_ONCE(sw->cxi_eth, ctx);
	/* Publish the ops table only after cxi_eth is set; pairs with the
	 * smp_load_acquire() in the ops readers.
	 */
	smp_store_release(&sw->ops, ops);
	mutex_unlock(&sw->sync_lock);
}
EXPORT_SYMBOL(cass_eth_mc_sw_reg_ops);

void cass_eth_mc_sw_unreg_ops(struct cxi_dev *cdev)
{
	struct cass_dev *hw = cxi_to_cass_dev(cdev);
	struct cass_eth_mc_sw *sw = hw->eth_mc_sw;

	mutex_lock(&sw->sync_lock);
	WRITE_ONCE(sw->ops, NULL);
	WRITE_ONCE(sw->cxi_eth, NULL);
	mutex_unlock(&sw->sync_lock);

	synchronize_rcu();
}
EXPORT_SYMBOL(cass_eth_mc_sw_unreg_ops);

/**
 * cass_eth_mc_sw_cleanup_vf() - Release the software-switch state owned by a VF
 * @cdev: PF CXI device owning the Ethernet instance
 * @vf_num: VF index whose software-switch state is being released
 *
 * Invoked from the PF-side VF client teardown path (VF unregister or
 * disconnect) to drop the departing VF's multicast subscriptions and its
 * RX-mode flag contribution.
 */
void cass_eth_mc_sw_cleanup_vf(struct cxi_dev *cdev, unsigned int vf_num)
{
	struct cass_dev *hw;
	struct cass_eth_mc_sw *sw;

	if (!cdev)
		return;

	hw = container_of(cdev, struct cass_dev, cdev);
	sw = hw->eth_mc_sw;
	if (!sw)
		return;

	mutex_lock(&sw->sync_lock);
	if (sw->ops && sw->cxi_eth && sw->ops->cleanup_vf)
		sw->ops->cleanup_vf(sw->cxi_eth, vf_num);
	mutex_unlock(&sw->sync_lock);
}
EXPORT_SYMBOL(cass_eth_mc_sw_cleanup_vf);

int cass_eth_mc_sw_sriov_configure(struct cass_dev *hw, int num_vfs)
{
	struct cass_eth_mc_sw *sw = hw->eth_mc_sw;
	int rc = 0;

	if (!sw)
		return 0;

	mutex_lock(&sw->sync_lock);
	if (sw->ops && sw->cxi_eth && sw->ops->sriov_configure)
		rc = sw->ops->sriov_configure(sw->cxi_eth, num_vfs);
	mutex_unlock(&sw->sync_lock);

	return rc;
}

/* PF-side entry for a VF-forwarded BUM frame */
int cass_eth_mc_sw_pf_recv_txfwd_from_vf(struct cxi_dev *cdev,
					 const u8 *frame, u16 frame_len,
					 bool is_vf, u8 vf_index)
{
	const struct cass_eth_mc_sw_ops *ops;
	struct cxi_eth *ctx;
	struct cass_dev *hw;
	struct cass_eth_mc_sw *sw;
	int rc;

	if (!cdev || !frame)
		return -EINVAL;

	hw = container_of(cdev, struct cass_dev, cdev);
	sw = hw->eth_mc_sw;
	if (!sw)
		return -EOPNOTSUPP;

	rcu_read_lock();

	/* Acquire the ops table published by cass_eth_mc_sw_reg_ops() so that
	 * cxi_eth is observed fully initialised before it is used.
	 */
	ops = smp_load_acquire(&sw->ops);
	ctx = READ_ONCE(sw->cxi_eth);
	if (!ops || !ctx || !ops->pf_recv_vf_bum_tx_pkt) {
		rcu_read_unlock();
		return -EOPNOTSUPP;
	}

	rc = ops->pf_recv_vf_bum_tx_pkt(ctx,
					frame, frame_len,
					is_vf, vf_index);
	rcu_read_unlock();

	return rc;
}
EXPORT_SYMBOL(cass_eth_mc_sw_pf_recv_txfwd_from_vf);
