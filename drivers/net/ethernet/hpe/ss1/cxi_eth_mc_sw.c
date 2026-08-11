// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

/* Ethernet multicast software switch.
 *
 * Tracks the PF-side multicast subscription tables and the per-function RX-mode
 * flag shadow, and runs the dispatcher that fans PF-received
 * multicast/broadcast/promiscuous frames out to subscribed VFs. HW filter
 * programming lives in cxi_eth_ops.c; the switch only tracks subscriptions and
 * calls back into it.
 *
 * All switch state is owned by the PF Ethernet netdev (struct cxi_eth), reached
 * from a struct cass_dev via mc_sw_pf_filters().
 */

#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/moduleparam.h>
#include <linux/bitmap.h>
#include <linux/idr.h>
#include <linux/xarray.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/sched.h>

#include "cass_core.h"
#include "cass_vf_notif.h"
#include "cxi_eth.h"
#include "cxi_eth_mc_sw.h"

#define CXI_ETH_MC_SW_FILTER_MAX_FRAME_SIZE (CXI_ETH_MAX_MTU + VLAN_ETH_HLEN + ETH_FCS_LEN)
#define CXI_MC_SW_DISP_Q_MAX_SIZE 1024

/* Enable sw switch fanout for MC & BC ingress frames PF->VFs
 * when SRIOV is active.
 */
static bool mc_sw_rxfanout_mod_parm = true;
module_param(mc_sw_rxfanout_mod_parm, bool, 0444);
MODULE_PARM_DESC(mc_sw_rxfanout_mod_parm,
		 "Enable mc switch fanout for MC & BC ingress frames PF->VFs (def: true)");

/* Enable sw switch forward for MC & BC egress frames VFs->PF
 * when SRIOV & rxfanout (mc_sw_rxfanout_mod_parm) are active.
 */
static bool mc_sw_txfwd_mod_parm = true;
module_param(mc_sw_txfwd_mod_parm, bool, 0644);
MODULE_PARM_DESC(mc_sw_txfwd_mod_parm,
		 "Enable mc switch forward for MC & BC egress frames VF->PF (def: true)");

/* --- MC SW Filter --- */
struct mc_sw_filter_entry {
	struct rcu_head rcu;
	u64 mac;
	bool pf_subscribed;
	DECLARE_BITMAP(vf_bitmap, C_NUM_VFS);
};

struct mc_sw_filter {
	/* Shared multicast subscription table mc_sw_filter_entry */
	struct xarray mc_filters;

	/* PF/VF netdev flags */
	u16 pf_ndev_flags;
	u16 vf_ndev_flags[C_NUM_VFS];
};

/* --- MC SW Dispatcher --- */
struct mc_sw_work_item {
	struct sk_buff *skb;
	bool is_vf;
	u8 vf_index;
};

struct mc_sw_work_slot {
	unsigned int seq;
	struct mc_sw_work_item *item;
};

struct mc_sw_worker_state {
	wait_queue_head_t wq;
	struct mc_sw_work_slot *ring;
	unsigned int ring_mask;
	unsigned int enq_pos;
	unsigned int deq_pos;
	struct task_struct *task;
	u8 *scratch;
	atomic64_t rx_fanout_drop;
	atomic64_t tx_fwd_drop;
};

/* --- MC SW --- */
struct cxi_mc_sw {
	/* The mc_filters xarray's built-in xa_lock serializes every subscription
	 * table update (PF reconcile, VF relay and VF cleanup); no separate lock
	 * is needed. The PF's ndo_set_rx_mode path holds it directly.
	 */
	struct mc_sw_filter filters;
	struct mc_sw_worker_state *rxfout_state;
	bool rxfout_sysfs_created;
	struct mc_sw_worker_state *txfwd_state;
	bool txfwd_sysfs_created;
};

/* The PF-owned subscription/flag tables. */
static struct mc_sw_filter *mc_sw_pf_filters(const struct cass_dev *hw)
{
	return &cass_eth_mc_sw_ctx(hw)->mc_switch->filters;
}

/* Return true if @mac_addr is present in the @mac_addrs array of @count entries. */
static bool mc_sw_filter_list_contains_mac(const u64 *mac_addrs, u16 count, u64 mac_addr)
{
	u16 i;

	for (i = 0; i < count; i++) {
		if (mac_addrs[i] == mac_addr)
			return true;
	}

	return false;
}

/* Aggregate (OR) the PF and all VF RX-mode flag contributions. */
static u16 mc_sw_filter_aggregate_flags(const struct cass_dev *hw)
{
	const struct mc_sw_filter *disp = mc_sw_pf_filters(hw);
	u16 flags = READ_ONCE(disp->pf_ndev_flags);
	unsigned int i;

	/* VF IFF_ALLMULTI/IFF_BROADCAST fold into the PF's HW flags so
	 * fanned-out VFs receive the traffic;
	 */
	for (i = 0; i < hw->num_vfs; i++)
		flags |= READ_ONCE(disp->vf_ndev_flags[i]);

	return flags;
}

/* Record @ndev_flags as the RX-mode flag contribution of the PF (@is_vf false)
 * or of a specific VF (@vf_index, valid only when @is_vf).
 */
static void mc_sw_filter_set_ndev_flags(struct cass_dev *hw, u16 ndev_flags,
					bool is_vf, u8 vf_index)
{
	struct mc_sw_filter *disp = mc_sw_pf_filters(hw);

	if (is_vf)
		WRITE_ONCE(disp->vf_ndev_flags[vf_index], ndev_flags & ~IFF_PROMISC);
	else
		WRITE_ONCE(disp->pf_ndev_flags, ndev_flags);
}

static int mc_sw_filter_init(struct cxi_eth *dev)
{
	struct mc_sw_filter *disp;

	dev->mc_switch = kzalloc(sizeof(*dev->mc_switch), GFP_KERNEL);
	if (!dev->mc_switch)
		return -ENOMEM;

	disp = &dev->mc_switch->filters;

	xa_init_flags(&disp->mc_filters, XA_FLAGS_ALLOC);
	disp->pf_ndev_flags = 0;
	memset(disp->vf_ndev_flags, 0, sizeof(disp->vf_ndev_flags));

	return 0;
}

static void mc_sw_filter_fini(struct cxi_eth *dev)
{
	struct mc_sw_filter_entry *entry;
	unsigned long index;

	if (!dev->mc_switch)
		return;

	xa_for_each(&dev->mc_switch->filters.mc_filters, index, entry)
		kfree(entry);
	xa_destroy(&dev->mc_switch->filters.mc_filters);
	kfree(dev->mc_switch);
	dev->mc_switch = NULL;
}

/* Remove all multicast subscriptions owned by @vf_num from the shared
 * device-wide subscription table. Hardware filters are removed only when the
 * unsubscribed VF was the last subscriber of that MAC.
 * Caller must hold the mc_filters xa_lock.
 */
static void mc_sw_eth_cleanup_vf_mc_subs(struct cxi_eth *dev, unsigned int vf_num)
{
	struct cass_dev *hw = cxi_to_cass_dev(dev->cxi_dev);
	struct mc_sw_filter_entry *mc_entry;
	unsigned long index;

	xa_for_each(&mc_sw_pf_filters(hw)->mc_filters, index, mc_entry) {
		if (!test_bit(vf_num, mc_entry->vf_bitmap))
			continue;

		clear_bit(vf_num, mc_entry->vf_bitmap);

		if (!mc_entry->pf_subscribed &&
		    bitmap_empty(mc_entry->vf_bitmap, C_NUM_VFS)) {
			u64 mac = mc_entry->mac;

			__xa_erase(&mc_sw_pf_filters(hw)->mc_filters, mac);
			kfree_rcu(mc_entry, rcu);

			cxi_eth_del_mc_filter(dev, mac);
		}
	}
}

/* Drop @vf_num's RX-mode flag contribution and reprogram the aggregated
 * promisc/bcast/all-multicast HW filters from the remaining subscribers, so a
 * VF that goes away while it had them enabled does not leave them programmed.
 * Caller must hold the mc_filters xa_lock.
 */
static void mc_sw_eth_cleanup_vf_flags(struct cxi_eth *dev, unsigned int vf_num)
{
	struct cass_dev *hw;

	hw = cxi_to_cass_dev(dev->cxi_dev);

	if (!READ_ONCE(mc_sw_pf_filters(hw)->vf_ndev_flags[vf_num]))
		return;

	mc_sw_filter_set_ndev_flags(hw, 0, true, vf_num);

	cxi_eth_set_flag_filters(dev, mc_sw_filter_aggregate_flags(hw));
}

/* Release a departing VF's switch state: its multicast subscriptions and its
 * RX-mode flag contribution.
 */
static void mc_sw_eth_cleanup_vf_sw_state(void *ctx, unsigned int vf_num)
{
	struct cxi_eth *dev = ctx;

	if (!dev || !dev->mc_switch)
		return;

	xa_lock(&dev->mc_switch->filters.mc_filters);
	mc_sw_eth_cleanup_vf_mc_subs(dev, vf_num);
	mc_sw_eth_cleanup_vf_flags(dev, vf_num);
	xa_unlock(&dev->mc_switch->filters.mc_filters);
}

/**
 * mc_sw_eth_del_mc_mac_filter() - Remove MC MAC address filter
 * @dev: PF Ethernet device owning the mc_sw subscription state
 * @mac_addr: MAC address to match (48-bit)
 * @is_vf: true if @vf_index identifies a VF, false for the PF
 * @vf_index: VF index (valid only when @is_vf)
 *
 * Caller must hold the mc_filters xa_lock.
 */
static void mc_sw_eth_del_mc_mac_filter(struct cxi_eth *dev, u64 mac_addr,
					bool is_vf, u8 vf_index)
{
	struct mc_sw_filter *filters = &dev->mc_switch->filters;
	struct mc_sw_filter_entry *mc_entry;

	mc_entry = xa_load(&filters->mc_filters, mac_addr);
	if (!mc_entry)
		return;

	if (is_vf)
		clear_bit(vf_index, mc_entry->vf_bitmap);
	else
		mc_entry->pf_subscribed = false;

	if (!mc_entry->pf_subscribed && bitmap_empty(mc_entry->vf_bitmap, C_NUM_VFS)) {
		__xa_erase(&filters->mc_filters, mac_addr);
		kfree_rcu(mc_entry, rcu);
		cxi_eth_del_mc_filter(dev, mac_addr);
	}
}

/**
 * mc_sw_eth_add_mc_mac_filter() - Add MC MAC address filter
 * @dev: PF Ethernet device owning the mc_sw subscription state
 * @mac_addr: MAC address to match (48-bit)
 * @is_vf: true if @vf_index identifies a VF, false for the PF
 * @vf_index: VF index (valid only when @is_vf)
 *
 * Caller must hold the mc_filters xa_lock.
 *
 * Return: 0 on success, negative errno on error
 */
static int mc_sw_eth_add_mc_mac_filter(struct cxi_eth *dev, u64 mac_addr,
				       bool is_vf, u8 vf_index)
{
	struct mc_sw_filter *filters = &dev->mc_switch->filters;
	struct mc_sw_filter_entry *mc_entry;
	struct mc_sw_filter_entry *new_entry = NULL;
	int rc;

	/* SW MC Filter Logic */
	mc_entry = xa_load(&filters->mc_filters, mac_addr);
	if (!mc_entry) {
		/* GFP_ATOMIC: the mc_filters xa_lock is held. */
		new_entry = kzalloc(sizeof(*new_entry), GFP_ATOMIC);
		if (!new_entry)
			return -ENOMEM;

		mc_entry = new_entry;
		bitmap_zero(mc_entry->vf_bitmap, C_NUM_VFS);
		mc_entry->pf_subscribed = false;
		mc_entry->mac = mac_addr;
	}

	if (is_vf)
		set_bit(vf_index, mc_entry->vf_bitmap);
	else
		mc_entry->pf_subscribed = true;

	rc = xa_err(__xa_store(&filters->mc_filters, mac_addr, mc_entry,
			       GFP_NOWAIT));
	if (rc) {
		if (is_vf)
			clear_bit(vf_index, mc_entry->vf_bitmap);
		else
			mc_entry->pf_subscribed = false;
		/* new_entry (if any) was never stored; free it directly. */
		kfree(new_entry);
		return rc;
	}

	rc = cxi_eth_add_mc_filter(dev, mac_addr);
	if (rc < 0) {
		u8 mac_bytes[ETH_ALEN];

		if (is_vf)
			clear_bit(vf_index, mc_entry->vf_bitmap);
		else
			mc_entry->pf_subscribed = false;

		if (!mc_entry->pf_subscribed &&
		    bitmap_empty(mc_entry->vf_bitmap, C_NUM_VFS)) {
			__xa_erase(&filters->mc_filters, mac_addr);
			kfree_rcu(mc_entry, rcu);
		}

		u64_to_ether_addr(mac_addr, mac_bytes);
		cxidev_err(dev->cxi_dev,
			   "Failed to program MC filter for %pM: %d\n",
			   mac_bytes, rc);
		return rc;
	}

	return 0;
}

/* Record the caller's RX-mode flags in the shared shadow, then program the
 * OR-aggregate of the PF + all VF flags onto the PF's HW flag filters.
 *
 * Caller must hold the mc_filters xa_lock.
 */
static int mc_sw_eth_reconcile_flags(struct cxi_eth *dev, u16 ndev_flags,
				     bool is_vf, u8 vf_index)
{
	struct cass_dev *hw;
	int rc;

	hw = cxi_to_cass_dev(dev->cxi_dev);
	mc_sw_filter_set_ndev_flags(hw, ndev_flags, is_vf, vf_index);
	rc = cxi_eth_set_flag_filters(dev, mc_sw_filter_aggregate_flags(hw));

	return rc;
}

/* Reconcile the caller's multicast subscriptions: add the requested MACs and
 * remove the caller's stale ones, in a single pass under the held mc_filters
 * xa_lock. Erasing the current entry mid-iteration is safe with xa_for_each.
 *
 * Caller must hold the mc_filters xa_lock.
 *
 * Return: 0 on success, negative errno on the first error encountered.
 */
static int mc_sw_eth_reconcile_mc(struct cxi_eth *dev,
				  const u64 *mc_mac_addrs, u16 mc_count,
				  bool is_vf, u8 vf_index)
{
	struct mc_sw_filter *filters = &dev->mc_switch->filters;
	struct mc_sw_filter_entry *mc_entry;
	unsigned long index;
	unsigned int i;
	int rc;
	int first_rc = 0;

	for (i = 0; i < mc_count; i++) {
		rc = mc_sw_eth_add_mc_mac_filter(dev, mc_mac_addrs[i], is_vf, vf_index);
		if (rc && !first_rc)
			first_rc = rc;
	}

	/* Drop this function's subscriptions no longer present in the new set. */
	xa_for_each(&filters->mc_filters, index, mc_entry) {
		if (is_vf) {
			if (!test_bit(vf_index, mc_entry->vf_bitmap))
				continue;
		} else if (!mc_entry->pf_subscribed) {
			continue;
		}

		if (mc_sw_filter_list_contains_mac(mc_mac_addrs, mc_count,
						   mc_entry->mac))
			continue;

		mc_sw_eth_del_mc_mac_filter(dev, mc_entry->mac, is_vf, vf_index);
	}

	return first_rc;
}

/* Reconcile flags then multicast subscriptions under the mc_filters xa_lock,
 * which serializes the PF's ndo_set_rx_mode path (a direct caller) against the
 * VF relay path and VF cleanup. Holding the lock across the flag update, the
 * table updates and the HW programming keeps software and hardware state
 * consistent. Unicast is not bridged.
 *
 * Return: 0 on success, negative errno on the first error encountered.
 */
int cxi_eth_mc_sw_reconcile(struct cxi_eth *dev,
			    const u64 *mc_mac_addrs, u16 mc_count,
			    u16 ndev_flags, bool is_vf, u8 vf_index)
{
	struct xarray *mc_filters;
	int rc;
	int first_rc = 0;

	if (!dev->mc_switch)
		return -ENODEV;

	mc_filters = &dev->mc_switch->filters.mc_filters;

	xa_lock(mc_filters);

	rc = mc_sw_eth_reconcile_flags(dev, ndev_flags, is_vf, vf_index);
	if (rc && !first_rc)
		first_rc = rc;

	rc = mc_sw_eth_reconcile_mc(dev, mc_mac_addrs, mc_count, is_vf, vf_index);
	if (rc && !first_rc)
		first_rc = rc;

	xa_unlock(mc_filters);

	return first_rc;
}

/* PF-side ops callback for the VF->PF relay path (process context). The VF's
 * RX-mode update, forwarded over VSOCK, is reconciled into the shared switch
 * tables here.
 *
 * Return: 0 on success, negative errno on the first error encountered.
 */
static int mc_sw_sync_rx_mode_filters_pf(void *ctx,
					 const u64 *mc_mac_addrs, u16 mc_count,
					 u16 ndev_flags, bool is_vf,
					 u8 vf_index)
{
	struct cxi_eth *dev = ctx;

	if (!dev)
		return -ENODEV;

	return cxi_eth_mc_sw_reconcile(dev, mc_mac_addrs, mc_count,
				       ndev_flags, is_vf, vf_index);
}

/* VF-side receive callback: inject a PF-forwarded frame into the VF netdev.
 * Invoked by core (cass_eth_mc_sw_vf_notif_rxfanout_hdlr) when a software-switch
 * dispatch packet arrives from the PF.
 *
 * Return: 0 on success, negative errno on error.
 */
static int mc_sw_vf_recv_rxfout_pkt(void *ctx,
				    const u8 *frame, u16 frame_len,
				    u8 csum_state, u32 csum)
{
	struct cxi_eth *dev = ctx;
	struct mc_sw_worker_state *state;
	struct sk_buff *skb;
	int rc;

	if (!dev || !dev->ndev)
		return -ENODEV;

	state = dev->mc_switch ? dev->mc_switch->txfwd_state : NULL;

	if (frame_len < ETH_HLEN) {
		rc = -EINVAL;
		goto drop;
	}

	if (frame_len > CXI_ETH_MC_SW_FILTER_MAX_FRAME_SIZE) {
		rc = -E2BIG;
		goto drop;
	}

	if (!netif_running(dev->ndev)) {
		rc = 0;
		goto drop;
	}

	skb = netdev_alloc_skb(dev->ndev, frame_len + NET_IP_ALIGN);
	if (unlikely(!skb)) {
		rc = -ENOMEM;
		goto drop;
	}

	skb_reserve(skb, NET_IP_ALIGN);
	skb_put_data(skb, frame, frame_len);
	skb->protocol = eth_type_trans(skb, dev->ndev);

	skb->ip_summed = csum_state;
	if (csum_state == CHECKSUM_COMPLETE)
		skb->csum = (__force __wsum)csum;

	dev->ndev->stats.rx_packets++;
	dev->ndev->stats.rx_bytes += frame_len;

	netif_rx(skb);

	return 0;

drop:
	if (state)
		atomic64_inc(&state->tx_fwd_drop);
	return rc;
}

static int mc_sw_rxfout_init(struct cxi_eth *dev);
static void mc_sw_rxfout_fini(struct cxi_eth *dev);
static int mc_sw_rxfout_sysfs_create(struct cxi_eth *dev);
static void mc_sw_rxfout_sysfs_remove(struct cxi_eth *dev);
static int mc_sw_pf_recv_vf_bum_tx_pkt(void *ctx, const u8 *frame, u16 frame_len,
				       bool is_vf, u8 vf_index);

static int mc_sw_sriov_configure(void *ctx, int num_vfs)
{
	struct cxi_eth *dev = ctx;
	int rc = 0;

	if (!dev)
		return -ENODEV;

	if (num_vfs < 0) {
		return -EINVAL;
	} else if (num_vfs > 0) {
		rc = mc_sw_rxfout_init(dev);
		if (rc)
			return rc;

		rc = mc_sw_rxfout_sysfs_create(dev);
		if (rc)
			mc_sw_rxfout_fini(dev);
	} else {
		mc_sw_rxfout_sysfs_remove(dev);
		mc_sw_rxfout_fini(dev);
	}

	return rc;
}

/* PF-side switch operations, exposed to core through a registered hook. */
static const struct cass_eth_mc_sw_ops eth_mc_sw_ops_impl = {
	.sync_rx_mode_filters_pf = mc_sw_sync_rx_mode_filters_pf,
	.cleanup_vf = mc_sw_eth_cleanup_vf_sw_state,
	.vf_recv_rxfout_pkt = mc_sw_vf_recv_rxfout_pkt,
	.sriov_configure = mc_sw_sriov_configure,
	.pf_recv_vf_bum_tx_pkt = mc_sw_pf_recv_vf_bum_tx_pkt,
};

static const struct cass_eth_mc_sw_ops *cxi_sw_filter_state_ops(void)
{
	return &eth_mc_sw_ops_impl;
}

/* Software dispatcher: fans PF-received multicast/broadcast/promiscuous
 * frames out to subscribed VFs.
 */
static bool mc_sw_worker_q_has_data(struct mc_sw_worker_state *state)
{
	if (!state)
		return false;

	return READ_ONCE(state->deq_pos) !=
		READ_ONCE(state->enq_pos);
}

static int mc_sw_worker_q_enqueue(struct mc_sw_worker_state *state,
				  struct mc_sw_work_item *item)
{
	struct mc_sw_work_slot *slot;
	unsigned int pos;
	unsigned int seq;
	int dif;

	if (!state || !state->ring)
		return -EINVAL;

	pos = READ_ONCE(state->enq_pos);
	for (;;) {
		slot = &state->ring[pos & state->ring_mask];
		seq = READ_ONCE(slot->seq);
		dif = (int)seq - (int)pos;

		if (dif == 0) {
			if (cmpxchg(&state->enq_pos, pos, pos + 1) == pos)
				break;
		} else if (dif < 0) {
			return -ENOSPC;
		}

		pos = READ_ONCE(state->enq_pos);
		cpu_relax();
	}

	WRITE_ONCE(slot->item, item);

	/* Publish the slot->item store above before advancing slot->seq; pairs
	 * with the smp_load_acquire() in mc_sw_worker_q_dequeue().
	 */
	smp_store_release(&slot->seq, pos + 1);

	return 0;
}

static struct mc_sw_work_item *mc_sw_worker_q_dequeue(struct mc_sw_worker_state *state)
{
	struct mc_sw_work_slot *slot;
	struct mc_sw_work_item *item;
	unsigned int pos;
	unsigned int seq;
	int dif;

	if (!state || !state->ring)
		return NULL;

	pos = READ_ONCE(state->deq_pos);
	slot = &state->ring[pos & state->ring_mask];

	/* Acquire the producer's slot->seq so the slot->item read below observes
	 * the enqueued item; pairs with the smp_store_release() in
	 * mc_sw_worker_q_enqueue().
	 */
	seq = smp_load_acquire(&slot->seq);
	dif = (int)seq - (int)(pos + 1);
	if (dif < 0)
		return NULL;
	if (unlikely(dif > 0))
		return NULL;

	item = READ_ONCE(slot->item);
	WRITE_ONCE(slot->item, NULL);
	WRITE_ONCE(state->deq_pos, pos + 1);

	/* Release the slot back to producers only after slot->item is consumed;
	 * pairs with the READ_ONCE(slot->seq) in mc_sw_worker_q_enqueue().
	 */
	smp_store_release(&slot->seq, pos + state->ring_mask + 1);

	return item;
}

static int mc_sw_rxfout_thread(void *data)
{
	struct cxi_eth *dev = data;
	struct mc_sw_worker_state *state = dev->mc_switch->rxfout_state;
	struct mc_sw_filter *disp = &dev->mc_switch->filters;
	struct cass_dev *hw = cxi_to_cass_dev(dev->cxi_dev);

	while (!kthread_should_stop()) {
		struct mc_sw_work_item *item;

		wait_event_interruptible(state->wq,
					 kthread_should_stop() ||
					 mc_sw_worker_q_has_data(state));

		if (kthread_should_stop())
			break;

		while ((item = mc_sw_worker_q_dequeue(state))) {
			struct sk_buff *skb = item->skb;
			struct cass_vf_notif_mc_sw_rx_fanout_pkt *fanout_pkt;
			struct mc_sw_filter_entry *group_entry;
			unsigned long vf_subscribed[BITS_TO_LONGS(C_NUM_VFS)];
			const u8 *mac_hdr;
			unsigned int l2_len;
			size_t fanout_pkt_len;
			u16 frame_len;
			u64 dest_mac;
			bool is_bcast;
			int vf;

			if (!skb) {
				atomic64_inc(&state->rx_fanout_drop);
				goto free_item;
			}

			if (unlikely(!pskb_may_pull(skb, ETH_HLEN)) ||
			    !skb_mac_header_was_set(skb)) {
				atomic64_inc(&state->rx_fanout_drop);
				goto free_item;
			}

			mac_hdr = skb_mac_header(skb);
			if (unlikely(mac_hdr > skb->data)) {
				atomic64_inc(&state->rx_fanout_drop);
				goto free_item;
			}

			l2_len = skb->data - mac_hdr;

			if ((size_t)skb->len + l2_len < ETH_HLEN ||
			    (size_t)skb->len + l2_len >
				    CXI_ETH_MC_SW_FILTER_MAX_FRAME_SIZE) {
				atomic64_inc(&state->rx_fanout_drop);
				goto free_item;
			}

			frame_len = skb->len + l2_len;

			dest_mac = ether_addr_to_u64(eth_hdr(skb)->h_dest);
			is_bcast = is_broadcast_ether_addr(eth_hdr(skb)->h_dest);
			bitmap_zero(vf_subscribed, C_NUM_VFS);

			if (!is_bcast) {
				rcu_read_lock();
				group_entry = xa_load(&disp->mc_filters, dest_mac);
				if (group_entry)
					bitmap_copy(vf_subscribed, group_entry->vf_bitmap,
						    C_NUM_VFS);
				rcu_read_unlock();
			}

			/* Build the fan-out packet once into the reused scratch
			 * buffer; the send is synchronous, so it is free to reuse
			 * for each subscribed VF.
			 */
			fanout_pkt_len =
				offsetof(struct cass_vf_notif_mc_sw_rx_fanout_pkt,
					 frame) + frame_len;
			fanout_pkt = (void *)state->scratch;

			fanout_pkt->op = CASS_VF_NOTIF_OP_MC_SW_RX_FANOUT_PKT;
			fanout_pkt->frame_len = frame_len;
			fanout_pkt->csum_state = skb->ip_summed;
			fanout_pkt->csum = (__force u32)skb->csum;
			/* Preserve CHECKSUM_COMPLETE only when the L2 header was
			 * already pulled at capture (l2_len == ETH_HLEN); otherwise
			 * its base won't match the VF's post-eth_type_trans view.
			 * Force CHECKSUM_NONE for any other state.
			 */
			if (fanout_pkt->csum_state == CHECKSUM_COMPLETE &&
			    l2_len != ETH_HLEN) {
				fanout_pkt->csum_state = CHECKSUM_NONE;
				fanout_pkt->csum = 0;
			} else if (fanout_pkt->csum_state != CHECKSUM_COMPLETE &&
				   fanout_pkt->csum_state != CHECKSUM_UNNECESSARY) {
				fanout_pkt->csum_state = CHECKSUM_NONE;
				fanout_pkt->csum = 0;
			}

			memcpy(fanout_pkt->frame, mac_hdr, l2_len);
			if (skb_copy_bits(skb, 0, fanout_pkt->frame + l2_len,
					  skb->len)) {
				atomic64_inc(&state->rx_fanout_drop);
				goto free_item;
			}

			for (vf = 0; vf < hw->num_vfs; vf++) {
				u16 vf_flags = READ_ONCE(disp->vf_ndev_flags[vf]);
				bool vf_deliver;
				int rc;

				/* Never echo a VF-forwarded frame back to its source. */
				if (item->is_vf && vf == item->vf_index)
					continue;

				if (is_bcast)
					vf_deliver = !!(vf_flags & IFF_BROADCAST);
				else
					vf_deliver = !!(vf_flags & IFF_ALLMULTI) ||
						(!!(vf_flags & IFF_MULTICAST) &&
						 test_bit(vf, vf_subscribed));

				if (!vf_deliver)
					continue;

				/* Fire-and-forget: an async send avoids blocking
				 * on a slow/stuck VF.
				 */
				rc = cxi_send_async_msg_to_vf(dev->cxi_dev, vf,
							      fanout_pkt,
							      fanout_pkt_len);
				if (rc) {
					netdev_dbg(dev->ndev,
						   "sw_switch dispatcher send failed vf=%u rc=%d len=%u\n",
						   vf, rc, frame_len);
					atomic64_inc(&state->rx_fanout_drop);
				}
			}

free_item:
			kfree_skb(skb);
			kfree(item);
		}
	}

	return 0;
}

static ssize_t rx_fanout_drop_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct cxi_eth *eth = netdev_priv(ndev);
	u64 val = 0;

	if (eth->mc_switch && eth->mc_switch->rxfout_state)
		val = atomic64_read(&eth->mc_switch->rxfout_state->rx_fanout_drop);

	return sysfs_emit(buf, "%llu\n", val);
}
static DEVICE_ATTR_RO(rx_fanout_drop);

static struct attribute *mc_sw_rxfout_attrs[] = {
	&dev_attr_rx_fanout_drop.attr,
	NULL,
};

static const struct attribute_group mc_sw_rxfout_group = {
	.name = "mc_sw_rxfout",
	.attrs = mc_sw_rxfout_attrs,
};

static int mc_sw_rxfout_sysfs_create(struct cxi_eth *dev)
{
	int rc;

	if (!dev || !dev->ndev || !dev->mc_switch)
		return -EINVAL;

	if (dev->mc_switch->rxfout_sysfs_created)
		return 0;

	rc = sysfs_create_group(&dev->ndev->dev.kobj, &mc_sw_rxfout_group);
	if (!rc)
		dev->mc_switch->rxfout_sysfs_created = true;

	return rc;
}

static void mc_sw_rxfout_sysfs_remove(struct cxi_eth *dev)
{
	if (!dev || !dev->ndev || !dev->mc_switch)
		return;

	if (!dev->mc_switch->rxfout_sysfs_created)
		return;

	sysfs_remove_group(&dev->ndev->dev.kobj, &mc_sw_rxfout_group);
	dev->mc_switch->rxfout_sysfs_created = false;
}

static ssize_t tx_fwd_drop_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct cxi_eth *eth = netdev_priv(ndev);
	u64 val = 0;

	if (eth->mc_switch && eth->mc_switch->txfwd_state)
		val = atomic64_read(&eth->mc_switch->txfwd_state->tx_fwd_drop);

	return sysfs_emit(buf, "%llu\n", val);
}
static DEVICE_ATTR_RO(tx_fwd_drop);

static struct attribute *mc_sw_txfwd_attrs[] = {
	&dev_attr_tx_fwd_drop.attr,
	NULL,
};

static const struct attribute_group mc_sw_txfwd_group = {
	.name = "mc_sw_txfwd",
	.attrs = mc_sw_txfwd_attrs,
};

/* Exposed per-VF (each VF has its own netdev/kobj), unlike mc_sw_rxfout which is
 * PF-only and driven by sriov_configure.
 */
static int mc_sw_txfwd_sysfs_create(struct cxi_eth *dev)
{
	int rc;

	if (!dev || !dev->ndev || !dev->mc_switch)
		return -EINVAL;

	if (dev->mc_switch->txfwd_sysfs_created)
		return 0;

	rc = sysfs_create_group(&dev->ndev->dev.kobj, &mc_sw_txfwd_group);
	if (!rc)
		dev->mc_switch->txfwd_sysfs_created = true;

	return rc;
}

static void mc_sw_txfwd_sysfs_remove(struct cxi_eth *dev)
{
	if (!dev || !dev->ndev || !dev->mc_switch)
		return;

	if (!dev->mc_switch->txfwd_sysfs_created)
		return;

	sysfs_remove_group(&dev->ndev->dev.kobj, &mc_sw_txfwd_group);
	dev->mc_switch->txfwd_sysfs_created = false;
}

static int mc_sw_worker_start(struct mc_sw_worker_state **slot, struct cxi_eth *dev,
			      int (*threadfn)(void *), const char *tag)
{
	struct mc_sw_worker_state *state;
	size_t scratch_len;
	unsigned int i;
	int rc;

	BUILD_BUG_ON(!is_power_of_2(CXI_MC_SW_DISP_Q_MAX_SIZE));
	if (*slot)
		return 0;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	init_waitqueue_head(&state->wq);
	state->ring_mask = CXI_MC_SW_DISP_Q_MAX_SIZE - 1;
	state->ring = kcalloc(CXI_MC_SW_DISP_Q_MAX_SIZE,
			      sizeof(*state->ring),
			      GFP_KERNEL);
	if (!state->ring) {
		rc = -ENOMEM;
		goto err_free_state;
	}

	for (i = 0; i < CXI_MC_SW_DISP_Q_MAX_SIZE; i++)
		state->ring[i].seq = i;

	scratch_len = max(sizeof(struct cass_vf_notif_mc_sw_rx_fanout_pkt),
			  sizeof(struct cxi_eth_mc_sw_txfwd_cmd)) +
		      CXI_ETH_MC_SW_FILTER_MAX_FRAME_SIZE;
	state->scratch = kzalloc(scratch_len, GFP_KERNEL);
	if (!state->scratch) {
		rc = -ENOMEM;
		goto err_free_ring;
	}

	*slot = state;

	state->task = kthread_run(threadfn, dev, "%s-%s",
				  dev->cxi_dev->name, tag);
	if (IS_ERR(state->task)) {
		rc = PTR_ERR(state->task);
		state->task = NULL;
		*slot = NULL;
		goto err_free_scratch;
	}

	return 0;

err_free_scratch:
	kfree(state->scratch);
err_free_ring:
	kfree(state->ring);
err_free_state:
	kfree(state);
	return rc;
}

/* Stop the worker, drain the ring and free the state pointed to by *slot. */
static void mc_sw_worker_stop(struct mc_sw_worker_state **slot)
{
	struct mc_sw_worker_state *state = *slot;
	struct mc_sw_work_item *item;

	if (!state)
		return;

	if (state->task) {
		kthread_stop(state->task);
		state->task = NULL;
	}

	while ((item = mc_sw_worker_q_dequeue(state))) {
		kfree_skb(item->skb);
		kfree(item);
	}

	kfree(state->scratch);
	kfree(state->ring);
	*slot = NULL;
	kfree(state);
}

static int mc_sw_rxfout_init(struct cxi_eth *dev)
{
	return mc_sw_worker_start(&dev->mc_switch->rxfout_state, dev,
				  mc_sw_rxfout_thread, "sw_switch-dispatcher");
}

static void mc_sw_rxfout_fini(struct cxi_eth *dev)
{
	if (!dev || !dev->mc_switch)
		return;

	mc_sw_worker_stop(&dev->mc_switch->rxfout_state);
}

static int mc_sw_worker_submit(struct mc_sw_worker_state *state,
			       struct sk_buff *skb_owned, bool is_vf, u8 vf_index)
{
	struct mc_sw_work_item *item;
	int rc;

	if (!state || !state->task) {
		kfree_skb(skb_owned);
		return -EINVAL;
	}

	item = kmalloc(sizeof(*item), GFP_ATOMIC);
	if (!item) {
		kfree_skb(skb_owned);
		return -ENOMEM;
	}

	item->skb = skb_owned;
	item->is_vf = is_vf;
	item->vf_index = vf_index;

	rc = mc_sw_worker_q_enqueue(state, item);
	if (rc) {
		kfree(item);
		kfree_skb(skb_owned);
		return rc;
	}

	wake_up_interruptible(&state->wq);

	return 0;
}

/* Hand @skb to the PF dispatcher. When @is_vf, @vf_index is the originating VF
 * to skip on fan-out; otherwise the frame is hardware-received.
 *
 * @own_skb: if true the caller donates @skb (submitted directly; this function
 * consumes it on every path); if false @skb is borrowed and a clone is submitted
 * instead, leaving the caller's reference untouched.
 */
static int mc_sw_rxfout_enqueue(struct cxi_eth *dev,
				struct sk_buff *skb,
				bool is_vf, u8 vf_index, bool own_skb)
{
	struct sk_buff *skb_owned;

	if (!dev->mc_switch->rxfout_state) {
		if (own_skb)
			kfree_skb(skb);
		return -EINVAL;
	}

	if (own_skb) {
		skb_owned = skb;
	} else {
		skb_owned = skb_clone(skb, GFP_ATOMIC);
		if (!skb_owned)
			return -ENOMEM;
	}

	return mc_sw_worker_submit(dev->mc_switch->rxfout_state, skb_owned, is_vf, vf_index);
}

/* Route a BUM frame like a hardware-received one: fan it out to subscribed VFs
 * (when @is_vf, skipping the originating @vf_index). Returns true if the PF
 * should keep a copy.
 *
 * Caller must guarantee @skb is linear with a valid multicast/broadcast
 * eth_hdr()->h_dest, and must itself honor mc_sw_rxfanout_mod_parm.
 *
 * @own_skb: if true the caller donates @skb and this function consumes it on
 * every path (handed to the dispatcher, or freed when no VF needs it); if false
 * @skb is borrowed and cloned before being handed to the dispatcher.
 */
static bool mc_sw_route(struct cxi_eth *dev, struct sk_buff *skb,
			bool is_vf, u8 vf_index, bool own_skb)
{
	struct cass_dev *hw = cxi_to_cass_dev(dev->cxi_dev);
	struct mc_sw_filter *disp = &dev->mc_switch->filters;
	struct mc_sw_filter_entry *group_entry;
	unsigned long vf_subscribed[BITS_TO_LONGS(C_NUM_VFS)];
	u64 dest_mac = ether_addr_to_u64(eth_hdr(skb)->h_dest);
	u16 pf_flags = READ_ONCE(disp->pf_ndev_flags);
	bool is_bcast = is_broadcast_ether_addr(eth_hdr(skb)->h_dest);
	bool pf_deliver;
	bool pf_subscribed = false;
	bool vf_needs_sw_switch = false;
	u8 dmac[ETH_ALEN];
	int vf;
	int rc;

	bitmap_zero(vf_subscribed, C_NUM_VFS);

	if (!is_bcast) {
		rcu_read_lock();
		group_entry = xa_load(&disp->mc_filters, dest_mac);
		if (group_entry) {
			pf_subscribed = READ_ONCE(group_entry->pf_subscribed);
			bitmap_copy(vf_subscribed, group_entry->vf_bitmap, C_NUM_VFS);
		}
		rcu_read_unlock();
	}

	if (pf_flags & IFF_PROMISC)
		pf_deliver = true;
	else if (is_bcast)
		pf_deliver = !!(pf_flags & IFF_BROADCAST);
	else
		pf_deliver = !!(pf_flags & IFF_ALLMULTI) ||
			(!!(pf_flags & IFF_MULTICAST) && pf_subscribed);

	for (vf = 0; vf < hw->num_vfs; vf++) {
		u16 vf_flags = READ_ONCE(disp->vf_ndev_flags[vf]);

		if (is_bcast) {
			if (vf_flags & IFF_BROADCAST) {
				vf_needs_sw_switch = true;
				break;
			}
			continue;
		}

		if ((vf_flags & IFF_ALLMULTI) ||
		    ((vf_flags & IFF_MULTICAST) && test_bit(vf, vf_subscribed))) {
			vf_needs_sw_switch = true;
			break;
		}
	}

	if (!vf_needs_sw_switch) {
		if (own_skb)
			kfree_skb(skb);
		return pf_deliver;
	}

	/* Snapshot the destination MAC before enqueue: when @own_skb the skb is
	 * consumed (and freed on failure) by the dispatcher, so it must not be
	 * dereferenced afterwards.
	 */
	ether_addr_copy(dmac, eth_hdr(skb)->h_dest);

	rc = mc_sw_rxfout_enqueue(dev, skb, is_vf, vf_index, own_skb);
	if (rc) {
		netdev_dbg(dev->ndev,
			   "sw_switch dispatcher enqueue failed mac=%pM rc=%d\n",
			   dmac, rc);
		if (dev->mc_switch->rxfout_state)
			atomic64_inc(&dev->mc_switch->rxfout_state->rx_fanout_drop);
	}

	return pf_deliver;
}

/* Entry point for hardware-received frames: validate/linearize the skb and
 * filter out unicast frames before handing off to mc_sw_route().
 */
bool cxi_eth_mc_sw_rxfout_route(struct rx_queue *rx, struct sk_buff *skb)
{
	struct cxi_eth *dev = rx->dev;
	struct cass_dev *hw = cxi_to_cass_dev(dev->cxi_dev);

	if (!mc_sw_rxfanout_mod_parm)
		return false;

	if (!hw->num_vfs)
		return false;

	if (skb_is_nonlinear(skb))
		skb_reset_mac_header(skb);

	if (unlikely(!pskb_may_pull(skb, ETH_HLEN))) {
		netdev_dbg(dev->ndev, "sw_switch dispatcher pskb_may_pull failed len=%u\n",
			   skb->len);
		if (dev->mc_switch->rxfout_state)
			atomic64_inc(&dev->mc_switch->rxfout_state->rx_fanout_drop);
		return false;
	}

	if (!is_multicast_ether_addr(eth_hdr(skb)->h_dest))
		return false;

	return !mc_sw_route(dev, skb, false, 0, false);
}

/* PF-side ingest of a VF-forwarded BUM frame: rebuild an skb and route it like
 * a hardware-received frame (skipping the source VF to avoid an echo).
 */
static int mc_sw_pf_recv_vf_bum_tx_pkt(void *ctx, const u8 *frame, u16 frame_len,
				       bool is_vf, u8 vf_index)
{
	struct cxi_eth *dev = ctx;
	struct mc_sw_worker_state *state;
	struct sk_buff *skb;
	int rc;

	if (!dev || !dev->ndev)
		return -ENODEV;

	if (!mc_sw_rxfanout_mod_parm)
		return 0;

	state = dev->mc_switch ? dev->mc_switch->rxfout_state : NULL;

	if (frame_len < ETH_HLEN ||
	    frame_len > CXI_ETH_MC_SW_FILTER_MAX_FRAME_SIZE) {
		rc = -EINVAL;
		goto drop;
	}

	if (!is_multicast_ether_addr(frame)) {
		rc = -EINVAL;
		goto drop;
	}

	if (!netif_running(dev->ndev)) {
		rc = -ENETDOWN;
		goto drop;
	}

	skb = netdev_alloc_skb(dev->ndev, frame_len + NET_IP_ALIGN);
	if (unlikely(!skb)) {
		rc = -ENOMEM;
		goto drop;
	}

	skb_reserve(skb, NET_IP_ALIGN);
	skb_put_data(skb, frame, frame_len);

	skb_reset_mac_header(skb);

	/* The PF has not verified the checksum from the VF.
	 * So, force CHECKSUM_NONE to let the receiving stack validate it.
	 */
	skb->ip_summed = CHECKSUM_NONE;

	if (mc_sw_route(dev, skb, is_vf, vf_index, false)) {
		skb->protocol = eth_type_trans(skb, dev->ndev);
		dev->ndev->stats.rx_packets++;
		dev->ndev->stats.rx_bytes += frame_len;
		netif_rx(skb);
	} else {
		kfree_skb(skb);
	}

	return 0;

drop:
	if (state)
		atomic64_inc(&state->rx_fanout_drop);
	return rc;
}

/* VF BUM TX-forward worker: drain captured egress frames and relay each to the
 * PF. Mirrors mc_sw_rxfout_thread().
 */
static int mc_sw_txfwd_thread(void *data)
{
	struct cxi_eth *dev = data;
	struct mc_sw_worker_state *state = dev->mc_switch->txfwd_state;

	while (!kthread_should_stop()) {
		struct mc_sw_work_item *item;

		wait_event_interruptible(state->wq,
					 kthread_should_stop() ||
					 mc_sw_worker_q_has_data(state));

		if (kthread_should_stop())
			break;

		while ((item = mc_sw_worker_q_dequeue(state))) {
			struct sk_buff *skb = item->skb;
			struct cxi_eth_mc_sw_txfwd_cmd *cmd;
			size_t cmd_len;
			u16 frame_len;
			int rc;

			if (!skb) {
				atomic64_inc(&state->tx_fwd_drop);
				goto free_item;
			}

			/* Bound skb->len at full width before narrowing to the u16
			 * frame_len, so an oversized skb cannot wrap past the check.
			 */
			if (skb->len < ETH_HLEN ||
			    skb->len > CXI_ETH_MC_SW_FILTER_MAX_FRAME_SIZE) {
				atomic64_inc(&state->tx_fwd_drop);
				goto free_item;
			}

			frame_len = skb->len;

			/* Reusing the scratch buffer */
			cmd_len = offsetof(struct cxi_eth_mc_sw_txfwd_cmd, frame) +
				  frame_len;
			cmd = (void *)state->scratch;

			cmd->op = CXI_OP_ETH_MC_SW_TX_FWD_PKT;
			cmd->resp = NULL;
			cmd->frame_len = frame_len;

			if (skb_copy_bits(skb, 0, cmd->frame, frame_len)) {
				atomic64_inc(&state->tx_fwd_drop);
				goto free_item;
			}

			/* Fire-and-forget: the PF reply is not needed for BUM relay. */
			rc = cxi_send_async_msg_to_pf(dev->cxi_dev, cmd, cmd_len);
			if (rc) {
				netdev_dbg(dev->ndev,
					   "bum txfwd relay failed rc=%d len=%u\n",
					   rc, frame_len);
				atomic64_inc(&state->tx_fwd_drop);
			}
free_item:
			kfree_skb(skb);
			kfree(item);
		}
	}

	return 0;
}

/* Capture a locally-transmitted BUM frame for software fan-out, whichever role
 * @dev is:
 *  - VF: relay it to the PF asynchronously via the txfwd worker, which
 *    forwards it over cxi_send_async_msg_to_pf() (see mc_sw_txfwd_thread()).
 *  - PF: fan it out synchronously to subscribed VFs by feeding it through
 *    mc_sw_route(), the same dispatcher used for hardware-received frames.
 * Only one of dev->mc_switch->txfwd_state/rxfout_state is ever populated for
 * a given @dev, so exactly one path below can ever do real work.
 *
 * The caller (cxi_eth_start_xmit) already guaranteed @skb is multicast/broadcast.
 * dev->mc_switch may still be NULL in the window between register_netdev() and
 * cxi_eth_mc_sw_init(), so it is checked below before use.
 */
void cxi_eth_mc_sw_txfwd_capture(struct cxi_eth *dev, struct sk_buff *skb)
{
	struct sk_buff *copy;
	int rc;

	if (!mc_sw_rxfanout_mod_parm || !mc_sw_txfwd_mod_parm)
		return;

	if (!dev->mc_switch)
		return;

	if (!dev->cxi_dev->is_physfn) {
		if (!dev->mc_switch->txfwd_state)
			return;

		copy = skb_copy(skb, GFP_ATOMIC);
		if (!copy) {
			atomic64_inc(&dev->mc_switch->txfwd_state->tx_fwd_drop);
			return;
		}

		rc = mc_sw_worker_submit(dev->mc_switch->txfwd_state, copy, false, 0);
		if (rc) {
			netdev_dbg(dev->ndev,
				   "bum txfwd enqueue failed rc=%d\n", rc);
			atomic64_inc(&dev->mc_switch->txfwd_state->tx_fwd_drop);
		}
		return;
	}

	if (!cxi_to_cass_dev(dev->cxi_dev)->num_vfs)
		return;

	if (!dev->mc_switch->rxfout_state)
		return;

	copy = skb_clone(skb, GFP_ATOMIC);
	if (!copy) {
		netdev_dbg(dev->ndev, "bum rxfout capture skb_clone failed\n");
		atomic64_inc(&dev->mc_switch->rxfout_state->rx_fanout_drop);
		return;
	}

	skb_reset_mac_header(copy);

	/* Donate @copy to the dispatcher: mc_sw_route() consumes it (fans it out
	 * or frees it), so it is neither cloned again nor freed here.
	 */
	mc_sw_route(dev, copy, false, 0, true);
}

static int mc_sw_txfwd_init(struct cxi_eth *dev)
{
	bool allocated = false;
	int rc;

	if (!dev->mc_switch) {
		dev->mc_switch = kzalloc(sizeof(*dev->mc_switch), GFP_KERNEL);
		if (!dev->mc_switch)
			return -ENOMEM;

		xa_init_flags(&dev->mc_switch->filters.mc_filters, XA_FLAGS_ALLOC);
		allocated = true;
	}

	rc = mc_sw_worker_start(&dev->mc_switch->txfwd_state, dev,
				mc_sw_txfwd_thread, "bum-txfwd");
	if (rc && allocated) {
		kfree(dev->mc_switch);
		dev->mc_switch = NULL;
	}

	return rc;
}

int cxi_eth_mc_sw_init(struct cxi_eth *dev)
{
	int rc;

	if (!dev->cxi_dev->is_physfn) {
		cass_eth_mc_sw_reg_ops(dev->cxi_dev,
				       cxi_sw_filter_state_ops(),
				       dev);

		rc = mc_sw_txfwd_init(dev);
		if (rc) {
			cass_eth_mc_sw_unreg_ops(dev->cxi_dev);
			return rc;
		}

		rc = mc_sw_txfwd_sysfs_create(dev);
		if (rc) {
			mc_sw_worker_stop(&dev->mc_switch->txfwd_state);
			cass_eth_mc_sw_unreg_ops(dev->cxi_dev);
			kfree(dev->mc_switch);
			dev->mc_switch = NULL;
			return rc;
		}

		return 0;
	}

	rc = mc_sw_filter_init(dev);
	if (rc)
		return rc;

	cass_eth_mc_sw_reg_ops(dev->cxi_dev, cxi_sw_filter_state_ops(), dev);

	return 0;
}

/* Remove the mc-switch sysfs group for either role; must run before unregister_netdev(). */
void cxi_eth_mc_sw_sysfs_remove(struct cxi_eth *dev)
{
	if (!dev || !dev->mc_switch)
		return;

	if (!dev->cxi_dev->is_physfn)
		mc_sw_txfwd_sysfs_remove(dev);
	else
		mc_sw_rxfout_sysfs_remove(dev);
}

/* Stop the mc-switch worker threads and free dev->mc_switch.
 * This must be called AFTER unregister_netdev()
 */
void cxi_eth_mc_sw_fini(struct cxi_eth *dev)
{
	if (!dev->cxi_dev->is_physfn) {
		mc_sw_worker_stop(&dev->mc_switch->txfwd_state);
		cass_eth_mc_sw_unreg_ops(dev->cxi_dev);
		xa_destroy(&dev->mc_switch->filters.mc_filters);
		kfree(dev->mc_switch);
		dev->mc_switch = NULL;
		return;
	}

	mc_sw_rxfout_fini(dev);
	cass_eth_mc_sw_unreg_ops(dev->cxi_dev);
	mc_sw_filter_fini(dev);
}
