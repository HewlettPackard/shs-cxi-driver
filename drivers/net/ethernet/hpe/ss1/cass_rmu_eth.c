// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

/* RMU Ethernet Resource Management */

#include <linux/hpe/cxi/cxi.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/xarray.h>
#include <linux/idr.h>

#include "cass_core.h"
#include "cxi_internal.h"

_Static_assert(CXI_ETH_MAX_INDIR_ENTRIES <=
	       C_RMU_CFG_PORTAL_INDEX_INDIR_TABLE_ENTRIES,
	       "CXI_ETH_MAX_INDIR_ENTRIES exceeds NIC table size");

/* set_list entries (lowest match priority, bottom of the table) reserved
 * exclusively for the in-kernel PF Ethernet driver.  Anchoring it at the
 * bottom keeps its promiscuous catch-all from shadowing VF or userspace PF
 * filters, regardless of client start order.  All other clients share the
 * remaining entries on demand.
 */
static unsigned int rmu_pf_eth_filters = 20;
static int param_set_rmu_pf_eth_filters(const char *val,
					const struct kernel_param *kp)
{
	unsigned int tmp;
	int rc;

	rc = kstrtouint(val, 0, &tmp);
	if (rc)
		return rc;

	if (tmp > C_RMU_CFG_PTLTE_SET_LIST_ENTRIES - 2)
		return -EINVAL;

	*(unsigned int *)kp->arg = tmp;

	return 0;
}

static const struct kernel_param_ops param_ops_rmu_pf_eth_filters = {
	.set = param_set_rmu_pf_eth_filters,
	.get = param_get_uint,
};

module_param_cb(rmu_pf_eth_filters, &param_ops_rmu_pf_eth_filters,
		&rmu_pf_eth_filters, 0444);
MODULE_PARM_DESC(rmu_pf_eth_filters,
		 "set_list entries reserved for the kernel PF Ethernet driver");

/* Indirection table allocation
 * - PF Ethernet gets a fixed reservation: rmu_pf_client_max_rss_indir_size
 *   (default 64, module parameter).
 * - All other clients share the remaining pool.
 */
static unsigned int rmu_pf_client_max_rss_indir_size = 64;
static int param_set_rmu_pf_client_max_rss_indir_size(const char *val,
						      const struct kernel_param *kp)
{
	unsigned int tmp;
	int rc;

	rc = kstrtouint(val, 0, &tmp);
	if (rc)
		return rc;

	if (tmp > CXI_ETH_MAX_INDIR_ENTRIES)
		return -EINVAL;

	*(unsigned int *)kp->arg = tmp;

	return 0;
}

static const struct kernel_param_ops param_ops_rmu_pf_client_max_rss_indir_size = {
	.set = param_set_rmu_pf_client_max_rss_indir_size,
	.get = param_get_uint,
};

module_param_cb(rmu_pf_client_max_rss_indir_size,
		&param_ops_rmu_pf_client_max_rss_indir_size,
		&rmu_pf_client_max_rss_indir_size, 0444);
MODULE_PARM_DESC(rmu_pf_client_max_rss_indir_size,
		 "Maximum size of RSS indirection table for each PF client");

/**
 * validate_mac_vf() - Check that a MAC address is a valid unicast address
 * @mac_addr: MAC address to validate (48-bit, host-endian)
 *
 * Return: 0 if valid, -EINVAL if multicast, broadcast, or all-zero
 */
static int validate_mac_vf(u64 mac_addr)
{
	u8 addr[ETH_ALEN];

	u64_to_ether_addr(mac_addr, addr);
	if (!is_valid_ether_addr(addr))
		return -EINVAL;

	return 0;
}

/**
 * check_vf_mac_policy() - Enforce PF-admin MAC policy for a VF
 * @hw:      Cassini device (PF)
 * @vf_num:  VF index
 * @mac_addr: Proposed MAC address (48-bit, host-endian)
 *
 * Validates the MAC format and checks it against the PF-admin assigned MAC
 * unless the VF is trusted.  Caller must NOT hold rmu_eth_lock.
 *
 * Return: 0 if allowed, -EINVAL for bad format, -EPERM if denied by policy
 */
static int check_vf_mac_policy(struct cass_dev *hw, unsigned int vf_num,
			       u64 mac_addr)
{
	u8 mac_bytes[ETH_ALEN];
	u64 assigned_mac;
	bool trusted;
	int rc;

	u64_to_ether_addr(mac_addr, mac_bytes);

	rc = validate_mac_vf(mac_addr);
	if (rc) {
		cxidev_err(&hw->cdev, "VF%u MAC %pM has invalid format\n",
			   vf_num, mac_bytes);
		return rc;
	}

	mutex_lock(&hw->rmu_eth_lock);
	trusted = hw->vf_eth_cfg[vf_num].trusted;
	assigned_mac = hw->vf_eth_cfg[vf_num].own_mac;
	mutex_unlock(&hw->rmu_eth_lock);

	if (trusted)
		return 0;

	if (!assigned_mac) {
		cxidev_err(&hw->cdev, "VF%u has no MAC assigned by PF admin\n",
			   vf_num);
		return -EPERM;
	}

	if (mac_addr != assigned_mac) {
		u8 allowed[ETH_ALEN];

		u64_to_ether_addr(assigned_mac, allowed);
		cxidev_err(&hw->cdev,
			   "VF%u MAC %pM not allowed (assigned: %pM)\n",
			   vf_num, mac_bytes, allowed);
		return -EPERM;
	}

	return 0;
}

/**
 * cxi_rmu_eth_alloc_vf() - Allocate Ethernet packet matching resources for VF
 * @cdev: CXI device
 * @opts: Requested filter and RSS indirection entries
 *
 * VF version: Sends allocation request to PF via vsock. The PF will allocate
 * the actual hardware resources and track them. The VF maintains a minimal
 * private structure for sending future commands to the PF.
 *
 * Return: Pointer to cxi_rmu_eth or ERR_PTR on error
 */
static struct cxi_rmu_eth *
cxi_rmu_eth_alloc_vf(struct cxi_dev *cdev,
		     const struct cxi_rmu_eth_alloc_opts *opts)
{
	struct cxi_rmu_eth_priv *priv;
	struct cxi_rmu_eth_alloc_resp resp;
	const struct cxi_rmu_eth_alloc_cmd cmd = {
		.op = CXI_OP_RMU_ETH_ALLOC,
		.resp = &resp,
		.filter_entries = opts->filter_entries,
		.rss_indir_entries = opts->rss_indir_entries,
	};
	size_t resp_len = sizeof(resp);
	int rc;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return ERR_PTR(-ENOMEM);

	/* Send allocation request to PF */
	rc = cxi_send_msg_to_pf(cdev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc) {
		kfree(priv);
		return ERR_PTR(rc);
	}
	if (resp_len != sizeof(resp)) {
		kfree(priv);
		return ERR_PTR(-EPROTO);
	}

	priv->dev = cdev;
	priv->rmu_eth.id = resp.rmu_eth;
	priv->rmu_eth.max_filters = resp.max_filters;
	priv->rmu_eth.max_indir_entries = resp.max_indir_entries;

	return &priv->rmu_eth;
}

/**
 * rmu_set_list_slot_alloc() - Grab any free set_list entry from the pool
 * @hw: Cassini device
 * @kernel_eth: Select the reserved PF Ethernet range
 *
 * Caller holds rmu_eth_lock. Kernel PF Ethernet uses its reserved range;
 * all other clients share the range below it.
 *
 * Return: hw index on success, -ENOSPC if the pool is exhausted
 */
static int rmu_set_list_slot_alloc(struct cass_dev *hw, bool kernel_eth)
{
	unsigned int pf_eth_first = C_RMU_CFG_PTLTE_SET_LIST_ENTRIES - 2 -
				    rmu_pf_eth_filters;
	unsigned int first = kernel_eth ? pf_eth_first : 0;
	unsigned int end = kernel_eth ? RMU_ETH_ALL_MCAST_HW_IDX : pf_eth_first;
	unsigned int hw_idx;

	hw_idx = find_next_zero_bit(hw->rmu_set_list_map, end, first);
	if (hw_idx >= end)
		return -ENOSPC;

	set_bit(hw_idx, hw->rmu_set_list_map);

	return hw_idx;
}

static void rmu_indir_alloc(struct cass_dev *hw, unsigned int want,
			    unsigned int lo, unsigned int hi,
			    unsigned int *base_out, unsigned int *size_out)
{
	unsigned int size;

	*base_out = 0;
	*size_out = 0;
	if (!want)
		return;

	for (size = rounddown_pow_of_two(want); size; size >>= 1) {
		unsigned int start;

		if (size > hi - lo)
			continue;

		start = round_down(hi - size, size);
		for (;;) {
			if (start < lo)
				break;
			if (find_next_bit(hw->rmu_indir_map, start + size,
					  start) == start + size) {
				bitmap_set(hw->rmu_indir_map, start, size);
				*base_out = start;
				*size_out = size;
				return;
			}
			if (start < size)
				break;
			start -= size;
		}
	}
}

/**
 * cxi_rmu_eth_alloc_internal() - Allocate Ethernet packet matching resources
 * @cdev: CXI device
 * @vf_en: Whether this is a VF allocation
 * @vf_num: VF number if vf_en is true
 * @opts: Requested filter and RSS indirection entries
 * @role: PF client role (generic vs in-kernel Ethernet)
 *
 * Reserves set_list entries and an RSS indirection range:
 *   - kernel Ethernet: fixed quota of rmu_pf_eth_filters;
 *   - generic PF client: requested filter count;
 *   - VF: its equal share of the set_list pool, computed at SR-IOV enable
 *     time.
 * set_list entries need not be contiguous, but every granted client-relative
 * filter index has a reserved hardware entry for the allocation's lifetime.
 *
 * Return: Pointer to cxi_rmu_eth or ERR_PTR on error
 */
struct cxi_rmu_eth *cxi_rmu_eth_alloc_internal(struct cxi_dev *cdev, bool vf_en,
					       u8 vf_num,
					       const struct cxi_rmu_eth_alloc_opts *opts,
					       enum cxi_rmu_eth_role role)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	unsigned int max_filters;
	unsigned int indir_base = 0;
	unsigned int indir_size = 0;
	struct cxi_rmu_eth *rmu_eth;
	struct cxi_rmu_eth_priv *priv;
	int id;
	int i;
	int hw_idx;
	int rc;

	if (!opts || opts->rss_indir_entries > CXI_ETH_MAX_INDIR_ENTRIES)
		return ERR_PTR(-EINVAL);

	if (vf_en && hw->num_vfs == 0)
		return ERR_PTR(-EINVAL);

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return ERR_PTR(-ENOMEM);

	priv->dev = cdev;
	priv->is_vf = vf_en;
	priv->vf_num = vf_num;
	priv->kernel_eth = role == CXI_RMU_ETH_ROLE_KERNEL_ETH;
	priv->requested_filters = opts->filter_entries;
	priv->requested_indir = opts->rss_indir_entries;
	spin_lock_init(&priv->slot_lock);
	rmu_eth = &priv->rmu_eth;

	mutex_lock(&hw->rmu_eth_lock);

	/* Grant a filter count quota and reserve the corresponding set_list
	 * entries for this allocation for its entire lifetime.
	 */
	if (vf_en) {
		unsigned int vf_indir_base;

		if (!opts->filter_entries || !hw->rmu_vf_set_list_quota) {
			rc = -ENOSPC;
			goto err_unlock;
		}
		if (hw->rmu_vf_set_list_used[vf_num] >=
		    hw->rmu_vf_set_list_quota) {
			rc = -ENOSPC;
			goto err_unlock;
		}
		max_filters = min(opts->filter_entries,
				  hw->rmu_vf_set_list_quota -
				  hw->rmu_vf_set_list_used[vf_num]);

		vf_indir_base = hw->rmu_vf_indir_base +
				vf_num * hw->rmu_vf_indir_quota;
		rmu_indir_alloc(hw, opts->rss_indir_entries,
				vf_indir_base,
				vf_indir_base + hw->rmu_vf_indir_quota,
				&indir_base, &indir_size);
		if (opts->rss_indir_entries && !indir_size) {
			rc = -ENOSPC;
			goto err_unlock;
		}
	} else if (role == CXI_RMU_ETH_ROLE_KERNEL_ETH) {
		if (rmu_pf_eth_filters == 0) {
			rc = -ENOSPC;
			goto err_unlock;
		}
		max_filters = rmu_pf_eth_filters;
		indir_base = 0;
		indir_size = min(opts->rss_indir_entries,
				 rmu_pf_client_max_rss_indir_size);
		if (indir_size)
			indir_size = rounddown_pow_of_two(indir_size);
		if (find_next_bit(hw->rmu_indir_map, indir_size, 0) != indir_size) {
			rc = -EBUSY;
			goto err_unlock;
		}
		bitmap_set(hw->rmu_indir_map, 0, indir_size);
	} else {
		if (!opts->filter_entries) {
			rc = -EINVAL;
			goto err_unlock;
		}
		max_filters = min_t(unsigned int, opts->filter_entries,
				    C_RMU_CFG_PTLTE_SET_LIST_ENTRIES);
		rmu_indir_alloc(hw, opts->rss_indir_entries,
				max(hw->rmu_vf_indir_end,
				    rmu_pf_client_max_rss_indir_size),
				C_RMU_CFG_PORTAL_INDEX_INDIR_TABLE_ENTRIES,
				&indir_base, &indir_size);
		if (opts->rss_indir_entries && !indir_size) {
			rc = -ENOSPC;
			goto err_unlock;
		}
	}

	id = idr_alloc(&hw->rmu_eth_idr, rmu_eth, 0, 0, GFP_KERNEL);
	if (id < 0) {
		rc = id;
		goto err_free_indir;
	}

	rmu_eth->id = id;
	priv->indir_base = indir_base;
	priv->indir_size = indir_size;
	rmu_eth->max_indir_entries = indir_size;

	priv->slots = kcalloc(max_filters, sizeof(*priv->slots), GFP_KERNEL);
	if (!priv->slots) {
		rc = -ENOMEM;
		goto err_idr;
	}
	for (i = 0; i < max_filters; i++) {
		hw_idx = rmu_set_list_slot_alloc(hw, priv->kernel_eth);
		if (hw_idx < 0)
			break;
		priv->slots[i].hw_idx = hw_idx;
	}

	if (!i) {
		rc = -ENOSPC;
		goto err_free_slots;
	}
	priv->max_filters = i;
	rmu_eth->max_filters = i;
	if (vf_en)
		hw->rmu_vf_set_list_used[vf_num] += i;

	/* Default RSS configuration (disabled initially) */
	priv->rss_queues = 0;
	priv->hash_types = 0;
	priv->indir_entries = 0;

	mutex_unlock(&hw->rmu_eth_lock);

	return &priv->rmu_eth;

err_free_slots:
	while (i--)
		clear_bit(priv->slots[i].hw_idx, hw->rmu_set_list_map);
	kfree(priv->slots);
err_idr:
	idr_remove(&hw->rmu_eth_idr, id);
err_free_indir:
	bitmap_clear(hw->rmu_indir_map, indir_base, indir_size);
err_unlock:
	mutex_unlock(&hw->rmu_eth_lock);
	kfree(priv);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL(cxi_rmu_eth_alloc_internal);

struct cxi_rmu_eth *
cxi_rmu_eth_alloc(struct cxi_dev *cdev,
		  const struct cxi_rmu_eth_alloc_opts *opts)
{
	return cdev->is_physfn ?
		cxi_rmu_eth_alloc_internal(cdev, false, 0, opts,
					   CXI_RMU_ETH_ROLE_GENERIC) :
		cxi_rmu_eth_alloc_vf(cdev, opts);
}
EXPORT_SYMBOL(cxi_rmu_eth_alloc);

/**
 * cass_rmu_eth_sriov_enable() - Compute the per-VF filter count quota
 * @hw: Cassini device (PF)
 * @num_vfs: Number of VFs being enabled
 *
 * Divides the currently-free set_list pool equally among the VFs. This is
 * only a count quota, not a reserved hw range: each VF allocation reserves
 * its granted entries from the shared pool for its lifetime. Must run before
 * the VFs can allocate their own resources.
 *
 * Return: 0 on success, -ENOSPC if fewer than one entry per VF is free.
 */
int cass_rmu_eth_sriov_enable(struct cass_dev *hw, int num_vfs)
{
	unsigned int free_bits;
	unsigned int per_vf;
	unsigned int indir_first_used;
	unsigned int indir_free;
	int rc = 0;

	mutex_lock(&hw->rmu_eth_lock);

	free_bits = C_RMU_CFG_PTLTE_SET_LIST_ENTRIES -
		    bitmap_weight(hw->rmu_set_list_map,
				  C_RMU_CFG_PTLTE_SET_LIST_ENTRIES);
	per_vf = free_bits / num_vfs;
	if (per_vf == 0) {
		cxidev_err(&hw->cdev,
			   "Cannot enable %d VFs: only %u free RMU set_list entries\n",
			   num_vfs, free_bits);
		rc = -ENOSPC;
		goto out;
	}

	indir_first_used = find_next_bit(hw->rmu_indir_map,
					 C_RMU_CFG_PORTAL_INDEX_INDIR_TABLE_ENTRIES,
					 rmu_pf_client_max_rss_indir_size);
	indir_free = indir_first_used - rmu_pf_client_max_rss_indir_size;

	hw->rmu_vf_set_list_quota = per_vf;
	memset(hw->rmu_vf_set_list_used, 0, sizeof(hw->rmu_vf_set_list_used));
	hw->rmu_vf_indir_base = rmu_pf_client_max_rss_indir_size;
	hw->rmu_vf_indir_quota = indir_free / num_vfs;
	hw->rmu_vf_indir_end = hw->rmu_vf_indir_base +
				hw->rmu_vf_indir_quota * num_vfs;

out:
	mutex_unlock(&hw->rmu_eth_lock);
	return rc;
}

/**
 * cass_rmu_eth_sriov_disable() - Release the VF set_list/indirection quotas
 * @hw: Cassini device (PF)
 */
void cass_rmu_eth_sriov_disable(struct cass_dev *hw)
{
	mutex_lock(&hw->rmu_eth_lock);
	hw->rmu_vf_set_list_quota = 0;
	memset(hw->rmu_vf_set_list_used, 0, sizeof(hw->rmu_vf_set_list_used));
	hw->rmu_vf_indir_base = rmu_pf_client_max_rss_indir_size;
	hw->rmu_vf_indir_end = rmu_pf_client_max_rss_indir_size;
	hw->rmu_vf_indir_quota = 0;
	mutex_unlock(&hw->rmu_eth_lock);
}

/**
 * cxi_rmu_eth_free_vf() - Free Ethernet resources (VF version)
 * @rmu_eth: Resource handle
 *
 * VF version: Sends free request to PF via vsock.
 */
static void cxi_rmu_eth_free_vf(struct cxi_rmu_eth *rmu_eth)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	const struct cxi_rmu_eth_free_cmd cmd = {
		.op = CXI_OP_RMU_ETH_FREE,
		.resp = NULL,
		.rmu_eth = rmu_eth->id,
	};
	size_t resp_len = 0;
	int rc;

	rc = cxi_send_msg_to_pf(priv->dev, &cmd, sizeof(cmd), NULL, &resp_len);
	if (rc)
		cxidev_err(priv->dev, "Failed to free RMU Ethernet resources on PF: %d\n", rc);

	kfree(priv);
}

/**
 * cxi_rmu_eth_free() - Free Ethernet resources
 * @rmu_eth: Resource handle
 *
 * Automatically invalidates all set_list entries, clears indirection table,
 * and releases all resources.
 */
void cxi_rmu_eth_free(struct cxi_rmu_eth *rmu_eth)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);
	int i;

	if (!priv->dev->is_physfn) {
		cxi_rmu_eth_free_vf(rmu_eth);
		return;
	}

	mutex_lock(&hw->rmu_eth_lock);

	/* Invalidate active filters and return every reserved hw entry. */
	for (i = 0; i < priv->max_filters; i++) {
		struct cxi_rmu_eth_slot *slot = &priv->slots[i];

		if (slot->mode != CXI_RMU_ETH_FILTER_NONE) {
			cxidev_dbg(priv->dev,
				   "Removing RMU filter at idx=%d (hw_idx=%u)\n",
				   i, slot->hw_idx);

			spin_lock(&hw->rmu_lock);
			cass_invalidate_set_list(hw, slot->hw_idx);
			spin_unlock(&hw->rmu_lock);
		}

		clear_bit(slot->hw_idx, hw->rmu_set_list_map);
	}

	if (priv->all_mcast.active) {
		spin_lock(&hw->rmu_lock);
		cass_invalidate_set_list(hw, RMU_ETH_ALL_MCAST_HW_IDX);
		spin_unlock(&hw->rmu_lock);
	}

	if (priv->promisc.active) {
		spin_lock(&hw->rmu_lock);
		cass_invalidate_set_list(hw, RMU_ETH_PROMISC_HW_IDX);
		spin_unlock(&hw->rmu_lock);
	}

	if (priv->is_vf)
		hw->rmu_vf_set_list_used[priv->vf_num] -= priv->max_filters;

	kfree(priv->slots);
	bitmap_clear(hw->rmu_indir_map, priv->indir_base, priv->indir_size);

	idr_remove(&hw->rmu_eth_idr, rmu_eth->id);

	mutex_unlock(&hw->rmu_eth_lock);

	kfree(priv);
}
EXPORT_SYMBOL(cxi_rmu_eth_free);

/**
 * program_rmu_set_list_filter() - Program one RMU set-list filter
 * @priv: Private resource structure
 * @hw_idx: Hardware set_list index
 * @pte: PTE pointer
 * @use_rss: Whether traffic participates in RSS
 * @set_list: Prepared set_list entry with match criteria
 * @set_list_mask: Prepared mask for set_list
 *
 * @mode: Storage for the programmed filter mode
 * @pte_id: Storage for the programmed PTE identifier
 *
 * Return: 0 on success, negative errno on error
 */
static int program_rmu_set_list_filter(struct cxi_rmu_eth_priv *priv,
				       unsigned int hw_idx,
				       struct cxi_pte *pte, bool use_rss,
				       const union c_rmu_cfg_ptlte_set_list *set_list,
				       const union c_rmu_cfg_ptlte_set_list *set_list_mask,
				       u8 *mode, u32 *pte_id)
{
	struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);
	unsigned int portal_idx;
	struct c_rmu_cfg_ptlte_set_ctrl_table_entry set_ctrl = {};

	portal_idx = pte->id;

	cxidev_dbg(priv->dev,
		   "Programming RMU filter hw_idx=%u use_rss=%d pte=%u\n",
		   hw_idx, use_rss, portal_idx);

	spin_lock(&hw->rmu_lock);

	/* Program set_list */
	cass_config_set_list(hw, hw_idx, portal_idx,
			     set_list, set_list_mask);

	/* Program set_ctrl for RSS or direct portal */
	if (use_rss && priv->rss_queues > 1 && priv->indir_entries > 0) {
		/* Use RSS */
		set_ctrl.portal_index_indir_base = priv->indir_base;
		set_ctrl.hash_bits = ilog2(priv->indir_entries);
		set_ctrl.hash_types_enabled = priv->hash_types;
	} else {
		/* Direct portal (RSS disabled) - point to fallback entry */
		set_ctrl.portal_index_indir_base = 2048 + hw_idx;
		set_ctrl.hash_bits = 0;
		set_ctrl.hash_types_enabled = 0;
	}

	/* Program set_ctrl */
	cass_config_set_ctrl(hw, hw_idx, &set_ctrl);

	/* Program default portal at indir_table[2048 + set_list_idx] */
	cass_config_indir_entry(hw, 2048 + hw_idx, portal_idx);

	spin_unlock(&hw->rmu_lock);

	if (mode)
		*mode = use_rss ? CXI_RMU_ETH_FILTER_RSS : CXI_RMU_ETH_FILTER_DIRECT;
	if (pte_id)
		*pte_id = portal_idx;

	return 0;
}

static int add_rmu_set_list_filter(struct cxi_rmu_eth_priv *priv,
				   unsigned int idx, struct cxi_pte *pte,
				   bool use_rss,
				   const union c_rmu_cfg_ptlte_set_list *set_list,
				   const union c_rmu_cfg_ptlte_set_list *set_list_mask)
{
	struct cxi_rmu_eth_slot *slot;

	if (idx >= priv->max_filters)
		return -EINVAL;

	slot = &priv->slots[idx];

	return program_rmu_set_list_filter(priv, slot->hw_idx, pte, use_rss,
					   set_list, set_list_mask,
					   &slot->mode, NULL);
}

/**
 * cxi_rmu_eth_add_mac_filter_vf() - Add MAC address filter (VF version)
 * @rmu_eth: Resource handle
 * @mac_addr: MAC address to match (48-bit)
 * @pte: PTE pointer
 * @use_rss: Whether this MAC participates in RSS distribution
 *
 * VF version: Sends add_mac request to PF via vsock.
 *
 * Return: 0 on success, negative errno on error
 */
static int cxi_rmu_eth_add_mac_filter_vf(struct cxi_rmu_eth *rmu_eth,
					 u64 mac_addr, struct cxi_pte *pte,
					 bool use_rss)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	const struct cxi_rmu_eth_add_mac_filter_cmd cmd = {
		.op = CXI_OP_RMU_ETH_ADD_MAC_FILTER,
		.rmu_eth = rmu_eth->id,
		.mac_addr = mac_addr,
		.pte = pte->id,
		.use_rss = use_rss,
	};
	size_t resp_len = 0;
	int rc;

	rc = cxi_send_msg_to_pf(priv->dev, &cmd, sizeof(cmd), NULL, &resp_len);
	if (rc)
		return rc;

	return 0;
}

/**
 * cxi_rmu_eth_add_all_mcast_filter_vf() - Add all-multicast filter (VF version)
 * @rmu_eth: Resource handle
 * @pte: PTE pointer
 * @use_rss: Whether this filter participates in RSS distribution
 *
 * VF version: Sends add-all-multicast request to PF via vsock.
 *
 * Return: 0 on success, negative errno on error
 */
static int cxi_rmu_eth_add_all_mcast_filter_vf(struct cxi_rmu_eth *rmu_eth,
					       struct cxi_pte *pte, bool use_rss)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	const struct cxi_rmu_eth_add_all_mcast_filter_cmd cmd = {
		.op = CXI_OP_RMU_ETH_ADD_ALL_MCAST_FILTER,
		.rmu_eth = rmu_eth->id,
		.pte = pte->id,
		.use_rss = use_rss,
	};
	size_t resp_len = 0;
	int rc;

	rc = cxi_send_msg_to_pf(priv->dev, &cmd, sizeof(cmd), NULL, &resp_len);
	if (rc)
		return rc;

	return 0;
}

/**
 * cxi_rmu_eth_add_mac_filter() - Add MAC address filter with portal and RSS control
 * @rmu_eth: Resource handle
 * @mac_addr: MAC address to match (48-bit)
 * @pte: PTE pointer (provides portal index via pte->portal_index)
 * @use_rss: Whether this MAC participates in RSS distribution
 *
 * The manager selects the hardware slot for the MAC address.
 *
 * Return: 0 on success, negative errno on error
 */
int cxi_rmu_eth_add_mac_filter(struct cxi_rmu_eth *rmu_eth, u64 mac_addr,
			       struct cxi_pte *pte, bool use_rss)
{
	struct cxi_rmu_eth_priv *priv;
	union c_rmu_cfg_ptlte_set_list set_list = {};
	union c_rmu_cfg_ptlte_set_list set_list_mask = {};
	u8 mac_bytes[ETH_ALEN];
	bool trusted = true;
	int idx;
	int rc;

	if (!rmu_eth || !pte)
		return -EINVAL;

	priv = container_of(rmu_eth, struct cxi_rmu_eth_priv, rmu_eth);

	if (!priv->dev->is_physfn)
		return cxi_rmu_eth_add_mac_filter_vf(rmu_eth, mac_addr, pte, use_rss);

	if (priv->is_vf) {
		struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);

		mutex_lock(&hw->rmu_eth_lock);
		trusted = hw->vf_eth_cfg[priv->vf_num].trusted;
		mutex_unlock(&hw->rmu_eth_lock);

		rc = check_vf_mac_policy(hw, priv->vf_num, mac_addr);
		if (rc)
			return rc;
	}

	/* Prepare set_list entry for MAC match */
	set_list.frame_type = C_RMU_ENET_802_3;
	set_list.dmac = mac_addr;

	/* Accept only that MAC */
	set_list_mask.qw[0] = ~set_list.qw[0];
	set_list_mask.qw[1] = ~set_list.qw[1];
	set_list_mask.qw[2] = ~set_list.qw[2];
	set_list_mask.qw[3] = ~set_list.qw[3];

	/* Ignore VLAN/PCP/DEI bits */
	set_list_mask.vlan_present = 0;
	set_list_mask.pcp = 0;
	set_list_mask.dei = 0;
	set_list_mask.vid = 0;
	set_list_mask.lossless = 0;

	/* Serialise slot search */
	spin_lock(&priv->slot_lock);

	for (idx = 0; idx < priv->max_filters; idx++) {
		struct cxi_rmu_eth_slot *slot = &priv->slots[idx];

		if (slot->mode != CXI_RMU_ETH_FILTER_NONE &&
		    slot->mac_addr == mac_addr)
			break;
	}
	if (idx >= priv->max_filters) {
		for (idx = 0; idx < priv->max_filters; idx++) {
			if (priv->slots[idx].mode == CXI_RMU_ETH_FILTER_NONE)
				break;
		}
		if (idx >= priv->max_filters) {
			rc = -ENOSPC;
			goto unlock;
		}
	}

	if (priv->is_vf && !trusted && idx != 0) {
		rc = -EPERM;
		goto unlock;
	}

	u64_to_ether_addr(mac_addr, mac_bytes);
	cxidev_dbg(priv->dev, "Adding MAC RMU filter %pM at idx=%d use_rss=%d pte id %u\n",
		   mac_bytes, idx, use_rss, pte->id);

	priv->slots[idx].mac_addr = mac_addr;

	rc = add_rmu_set_list_filter(priv, idx, pte, use_rss, &set_list,
				     &set_list_mask);

unlock:
	spin_unlock(&priv->slot_lock);
	return rc;
}
EXPORT_SYMBOL(cxi_rmu_eth_add_mac_filter);

/**
 * cxi_rmu_eth_check_mac_policy() - Validate a MAC address against PF-admin policy
 * @cdev:    PF CXI device
 * @vf_num:  VF index (0-based)
 * @mac_addr: Proposed MAC address (48-bit, host-endian)
 *
 * Checks that @mac_addr passes format validation and is permitted by the
 * PF-admin assignment for @vf_num.  Trusted VFs always pass.
 *
 * Return: 0 if allowed, -EINVAL for bad format, -EPERM if denied
 */
int cxi_rmu_eth_check_mac_policy(struct cxi_dev *cdev, unsigned int vf_num,
				 u64 mac_addr)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;

	if (vf_num >= C_NUM_VFS)
		return -EINVAL;

	rc = check_vf_mac_policy(hw, vf_num, mac_addr);
	if (rc)
		return rc;

	return 0;
}
EXPORT_SYMBOL(cxi_rmu_eth_check_mac_policy);

/**
 * cxi_rmu_eth_add_all_mcast_filter() - Add all-multicast filter with portal and RSS control
 * @rmu_eth: Resource handle
 * @pte: PTE pointer (provides portal index via pte->portal_index)
 * @use_rss: Whether this filter participates in RSS distribution
 *
 * Programs a filter that accepts all multicast Ethernet packets by matching
 * only frame type and destination MAC multicast bit semantics.
 *
 * Return: 0 on success, negative errno on error
 */
int cxi_rmu_eth_add_all_mcast_filter(struct cxi_rmu_eth *rmu_eth,
				     struct cxi_pte *pte, bool use_rss)
{
	struct cxi_rmu_eth_priv *priv;
	const union c_rmu_cfg_ptlte_set_list set_list = {
		.frame_type = C_RMU_ENET_802_3,
		.dmac = 0x010000000000ULL,
	};
	const union c_rmu_cfg_ptlte_set_list set_list_mask = {
		.qw = {
			[2] = ~set_list.qw[2],
			[3] = ~set_list.qw[3],
		}
	};
	if (!rmu_eth || !pte)
		return -EINVAL;

	priv = container_of(rmu_eth, struct cxi_rmu_eth_priv, rmu_eth);

	if (!priv->dev->is_physfn)
		return cxi_rmu_eth_add_all_mcast_filter_vf(rmu_eth, pte, use_rss);

	if (priv->is_vf || !priv->kernel_eth)
		return -EPERM;

	cxidev_dbg(priv->dev,
		   "Adding all-multicast RMU filter at hw_idx=%u use_rss=%d pte id %u\n",
		   RMU_ETH_ALL_MCAST_HW_IDX, use_rss, pte->id);

	if (program_rmu_set_list_filter(priv, RMU_ETH_ALL_MCAST_HW_IDX, pte,
					use_rss, &set_list, &set_list_mask,
					&priv->all_mcast.mode, NULL))
		return -EINVAL;

	priv->all_mcast.active = true;

	return 0;
}
EXPORT_SYMBOL(cxi_rmu_eth_add_all_mcast_filter);

/**
 * cxi_rmu_eth_remove_mac_filter_vf() - Remove MAC filter (VF version)
 * @rmu_eth: Resource handle
 * @mac_addr: MAC address to remove
 *
 * VF version: Sends remove_filter request to PF via vsock.
 *
 * Return: 0 on success, negative errno on error
 */
static int cxi_rmu_eth_remove_mac_filter_vf(struct cxi_rmu_eth *rmu_eth, u64 mac_addr)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	const struct cxi_rmu_eth_remove_filter_cmd cmd = {
		.op = CXI_OP_RMU_ETH_REMOVE_FILTER,
		.rmu_eth = rmu_eth->id,
		.mac_addr = mac_addr,
	};
	size_t resp_len = 0;
	int rc;

	rc = cxi_send_msg_to_pf(priv->dev, &cmd, sizeof(cmd), NULL, &resp_len);
	if (rc)
		return rc;

	return 0;
}

int cxi_rmu_eth_remove_mac_filter(struct cxi_rmu_eth *rmu_eth, u64 mac_addr)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);
	unsigned int i;
	int rc = -ENOENT;

	if (!priv->dev->is_physfn)
		return cxi_rmu_eth_remove_mac_filter_vf(rmu_eth, mac_addr);

	spin_lock(&priv->slot_lock);

	for (i = 0; i < priv->max_filters; i++) {
		struct cxi_rmu_eth_slot *slot = &priv->slots[i];

		if (slot->mode != CXI_RMU_ETH_FILTER_NONE &&
		    slot->mac_addr == mac_addr) {
			spin_lock(&hw->rmu_lock);
			cass_invalidate_set_list(hw, slot->hw_idx);
			spin_unlock(&hw->rmu_lock);
			slot->mode = CXI_RMU_ETH_FILTER_NONE;
			slot->mac_addr = 0;
			rc = 0;
			break;
		}
	}

	spin_unlock(&priv->slot_lock);

	return rc;
}
EXPORT_SYMBOL(cxi_rmu_eth_remove_mac_filter);

int cxi_rmu_eth_remove_all_mcast_filter(struct cxi_rmu_eth *rmu_eth)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);

	if (!priv->all_mcast.active)
		return -ENOENT;

	spin_lock(&hw->rmu_lock);
	cass_invalidate_set_list(hw, RMU_ETH_ALL_MCAST_HW_IDX);
	spin_unlock(&hw->rmu_lock);
	priv->all_mcast.active = false;

	return 0;
}
EXPORT_SYMBOL(cxi_rmu_eth_remove_all_mcast_filter);

int cxi_rmu_eth_remove_promiscuous_filter(struct cxi_rmu_eth *rmu_eth)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);

	if (!priv->promisc.active)
		return -ENOENT;

	spin_lock(&hw->rmu_lock);
	cass_invalidate_set_list(hw, RMU_ETH_PROMISC_HW_IDX);
	spin_unlock(&hw->rmu_lock);

	priv->promisc.active = false;

	return 0;
}
EXPORT_SYMBOL(cxi_rmu_eth_remove_promiscuous_filter);

/**
 * cxi_rmu_eth_add_promiscuous_filter() - Enable promiscuous mode filter
 * @rmu_eth: Resource handle
 * @pte: PTE pointer
 * @use_rss: Whether promiscuous traffic participates in RSS
 *
 * Return: 0 on success, negative errno on error
 */
int cxi_rmu_eth_add_promiscuous_filter(struct cxi_rmu_eth *rmu_eth,
				       struct cxi_pte *pte, bool use_rss)
{
	struct cxi_rmu_eth_priv *priv;
	const union c_rmu_cfg_ptlte_set_list set_list = {
		.frame_type = C_RMU_ENET_802_3,
	};
	const union c_rmu_cfg_ptlte_set_list set_list_mask = {
		.qw = {
			[2] = ~set_list.qw[2],
			[3] = ~set_list.qw[3],
		}
	};
	if (!rmu_eth || !pte)
		return -EINVAL;

	priv = container_of(rmu_eth, struct cxi_rmu_eth_priv, rmu_eth);

	if (priv->is_vf || !priv->kernel_eth)
		return -EPERM;

	cxidev_dbg(priv->dev,
		   "Adding promiscuous RMU filter at hw_idx=%u use_rss=%d\n",
		   RMU_ETH_PROMISC_HW_IDX, use_rss);
	if (program_rmu_set_list_filter(priv, RMU_ETH_PROMISC_HW_IDX, pte,
					use_rss, &set_list, &set_list_mask,
					&priv->promisc.mode, NULL))
		return -EIO;

	priv->promisc.active = true;

	return 0;
}
EXPORT_SYMBOL(cxi_rmu_eth_add_promiscuous_filter);

/**
 * update_rss_filters() - Update set_ctrl for all RSS-enabled filters
 * @priv: Private resource structure
 * @enable: If true, enable RSS; if false, disable RSS
 *
 * Helper function to update set_ctrl entries for all filters that use RSS.
 * This is called when changing RSS configuration or indirection table.
 */
static void update_rss_filters(struct cxi_rmu_eth_priv *priv, bool enable)
{
	struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);
	unsigned int i;
	struct c_rmu_cfg_ptlte_set_ctrl_table_entry set_ctrl = {};

	if (enable && priv->rss_queues > 1 && priv->indir_entries > 0) {
		/* RSS enabled - configure indirection table */
		set_ctrl.portal_index_indir_base = priv->indir_base;
		set_ctrl.hash_bits = ilog2(priv->indir_entries);
		set_ctrl.hash_types_enabled = priv->hash_types;
	}
	/* else: set_ctrl stays zero (direct portal mode); portal_index_indir_base
	 * is set per-filter below */

	/* Update MAC filters that use RSS */
	for (i = 0; i < priv->max_filters; i++) {
		if (priv->slots[i].mode == CXI_RMU_ETH_FILTER_RSS) {
			unsigned int hw_idx = priv->slots[i].hw_idx;

			if (!enable || priv->rss_queues <= 1) {
				/* Use direct portal */
				set_ctrl.portal_index_indir_base = 2048 + hw_idx;
			}

			cass_config_set_ctrl(hw, hw_idx, &set_ctrl);
		}
	}

	/* Update all multicast filter if this uses RSS */
	if (priv->all_mcast.active &&
	    priv->all_mcast.mode == CXI_RMU_ETH_FILTER_RSS) {
		struct c_rmu_cfg_ptlte_set_ctrl_table_entry special_ctrl = set_ctrl;
		unsigned int hw_idx = RMU_ETH_ALL_MCAST_HW_IDX;

		if (!enable || priv->rss_queues <= 1)
			special_ctrl.portal_index_indir_base = 2048 + hw_idx;
		cass_config_set_ctrl(hw, hw_idx, &special_ctrl);
	}

	/* Update promiscuous filter if this uses RSS */
	if (priv->promisc.active &&
	    priv->promisc.mode == CXI_RMU_ETH_FILTER_RSS) {
		struct c_rmu_cfg_ptlte_set_ctrl_table_entry special_ctrl = set_ctrl;
		unsigned int hw_idx = RMU_ETH_PROMISC_HW_IDX;

		if (!enable || priv->rss_queues <= 1)
			special_ctrl.portal_index_indir_base = 2048 + hw_idx;
		cass_config_set_ctrl(hw, hw_idx, &special_ctrl);
	}
}

/**
 * cxi_rmu_eth_set_rss_queues_vf() - Configure RSS queues (VF version)
 * @rmu_eth: Resource handle
 * @num_queues: Number of RSS queues
 * @ptes: Array of PTE pointers
 * @hash_types: Hash types to enable
 *
 * VF version: Sends set_rss_queues request to PF via vsock.
 *
 * Return: 0 on success, negative errno on error
 */
static int cxi_rmu_eth_set_rss_queues_vf(struct cxi_rmu_eth *rmu_eth,
					 unsigned int num_queues,
					 struct cxi_pte **ptes,
					 u32 hash_types)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	struct cxi_rmu_eth_set_rss_queues_cmd cmd = {
		.op = CXI_OP_RMU_ETH_SET_RSS_QUEUES,
		.rmu_eth = rmu_eth->id,
		.num_queues = num_queues,
		.hash_types = hash_types,
	};
	size_t resp_len = 0;
	unsigned int i;

	if (num_queues > CXI_ETH_MAX_RSS_QUEUES)
		return -EINVAL;

	/* Copy PTE numbers into command */
	for (i = 0; i < num_queues; i++)
		cmd.ptes[i] = ptes[i]->id;

	return cxi_send_msg_to_pf(priv->dev, &cmd, sizeof(cmd), NULL, &resp_len);
}

/**
 * cxi_rmu_eth_set_rss_queues() - Configure RSS queues and hash types
 * @rmu_eth: Resource handle
 * @num_queues: Number of RSS queues (0-64, where 0 disables RSS)
 * @ptes: Array of PTE pointers for RSS queues
 * @hash_types: Hash types to enable
 *
 * Return: 0 on success, negative errno on error
 */
int cxi_rmu_eth_set_rss_queues(struct cxi_rmu_eth *rmu_eth,
			       unsigned int num_queues,
			       struct cxi_pte **ptes,
			       u32 hash_types)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);
	unsigned int i;

	if (!priv->dev->is_physfn)
		return cxi_rmu_eth_set_rss_queues_vf(rmu_eth, num_queues, ptes,
						     hash_types);
	if (num_queues > 1 && num_queues > priv->indir_size)
		return -ENOSPC;

	/* RSS requires at least 2 queues and non-zero hash types */
	if (num_queues == 0 || num_queues == 1 || hash_types == 0) {
		/* Disable RSS */
		num_queues = 0;
		hash_types = 0;
	} else {
		/* Validate RSS queue count */
		if (num_queues > CXI_ETH_MAX_RSS_QUEUES)
			return -EINVAL;

		/* Store PTE pointers for RSS queues */
		for (i = 0; i < num_queues; i++)
			priv->ptes[i] = ptes[i];
	}

	/* Update default RSS configuration */
	priv->rss_queues = num_queues;
	priv->hash_types = hash_types;
	priv->indir_entries = (num_queues > 1) ? priv->indir_size : 0;

	/* Program indirection table with default round-robin */
	spin_lock(&hw->rmu_lock);

	/* Disable RSS filters before modifying indirection table */
	update_rss_filters(priv, false);

	if (num_queues > 1) {
		for (i = 0; i < priv->indir_entries; i++) {
			unsigned int queue_idx = ethtool_rxfh_indir_default(i, num_queues);
			unsigned int portal_idx = ptes[queue_idx]->id;

			cass_config_indir_entry(hw, priv->indir_base + i, portal_idx);
		}

		/* Re-enable RSS filters with new configuration */
		update_rss_filters(priv, true);
	}

	spin_unlock(&hw->rmu_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_rmu_eth_set_rss_queues);

/**
 * cxi_rmu_eth_set_indir_table_vf() - Set custom traffic distribution (VF version)
 * @rmu_eth: Resource handle
 * @indir_table: Custom indirection table, or NULL for default
 * @indir_size: Size of indirection table
 *
 * VF version: Sends set_indir_table request to PF via vsock.
 *
 * Return: 0 on success, negative errno on error
 */
static int cxi_rmu_eth_set_indir_table_vf(struct cxi_rmu_eth *rmu_eth,
					  const u8 *indir_table,
					  unsigned int indir_size)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	struct cxi_rmu_eth_set_indir_table_cmd *cmd;
	size_t resp_len = 0;
	int ret;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->op = CXI_OP_RMU_ETH_SET_INDIR_TABLE;
	cmd->rmu_eth = rmu_eth->id;
	cmd->indir_size = indir_size;

	/* Copy indirection table if provided, NULL means use default (all zeros) */
	if (indir_table && indir_size <= CXI_ETH_MAX_INDIR_ENTRIES)
		memcpy(cmd->indir_table, indir_table, indir_size);

	ret = cxi_send_msg_to_pf(priv->dev, cmd, sizeof(*cmd), NULL, &resp_len);
	kfree(cmd);
	return ret;
}

/**
 * cxi_rmu_eth_set_indir_table() - Set custom traffic distribution weights
 * @rmu_eth: Resource handle
 * @indir_table: Custom indirection table, or NULL for default
 * @indir_size: Size of indirection table (must be power of 2)
 *
 * Return: 0 on success, negative errno on error
 */
int cxi_rmu_eth_set_indir_table(struct cxi_rmu_eth *rmu_eth,
				const u8 *indir_table, unsigned int indir_size)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);
	unsigned int i;

	if (!priv->dev->is_physfn)
		return cxi_rmu_eth_set_indir_table_vf(rmu_eth, indir_table, indir_size);

	if (indir_size == 0 || !is_power_of_2(indir_size)) {
		cxidev_err(priv->dev, "Invalid indirection table size %u (must be power of 2)\n",
			   indir_size);
		return -EINVAL;
	}

	if (priv->rss_queues == 0) {
		cxidev_dbg(priv->dev,
			   "Ignoring indirection table update while RSS is disabled (indir_size=%u)\n",
			   indir_size);
		return 0;
	}

	cxidev_dbg(priv->dev, "Setting up RSS indirection table: indir_size=%u\n", indir_size);

	if (indir_size > priv->indir_size) {
		cxidev_err(priv->dev, "Indirection table size %u exceeds allocated size %u\n",
			   indir_size, priv->indir_size);
		return -EINVAL;
	}

	/* Validate all queue indices before modifying hardware */
	if (indir_table) {
		for (i = 0; i < indir_size; i++) {
			if (indir_table[i] >= priv->rss_queues) {
				cxidev_err(priv->dev, "Invalid queue index %u in indirection table (max %u)\n",
					   indir_table[i], priv->rss_queues - 1);
				return -EINVAL;
			}
		}
	}

	/* Update active indirection table size */
	priv->indir_entries = indir_size;

	spin_lock(&hw->rmu_lock);

	/* Disable hashing on all active filters before modifying indirection table */
	update_rss_filters(priv, false);

	/* Program the requested entries (custom or default) */
	for (i = 0; i < indir_size; i++) {
		unsigned int queue_idx;
		unsigned int portal_idx;

		if (!indir_table) {
			/* Default round-robin */
			queue_idx = ethtool_rxfh_indir_default(i, priv->rss_queues);
		} else {
			/* Custom table - already validated above */
			queue_idx = indir_table[i];
		}

		portal_idx = priv->ptes[queue_idx]->id;
		cass_config_indir_entry(hw, priv->indir_base + i, portal_idx);
	}

	/* Fill remaining entries with default round-robin to avoid stale values although
	 * the HW would not be using them once we update the hash_bits */
	for (i = indir_size; i < priv->indir_size; i++) {
		unsigned int queue_idx = ethtool_rxfh_indir_default(i, priv->rss_queues);
		unsigned int portal_idx = priv->ptes[queue_idx]->id;

		cass_config_indir_entry(hw, priv->indir_base + i, portal_idx);
	}

	/* Re-enable hashing on all active filters */
	update_rss_filters(priv, true);

	spin_unlock(&hw->rmu_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_rmu_eth_set_indir_table);

static void cxi_rmu_eth_get_hash_key_vf(struct cxi_dev *cdev, u8 *key)
{
	const struct cxi_rmu_eth_hash_key_get_cmd cmd = {
		.op = CXI_OP_RMU_ETH_HASH_KEY_GET,
	};
	struct cxi_rmu_eth_get_hash_key_resp resp = {};
	size_t resp_len = sizeof(resp);
	int rc;

	BUILD_BUG_ON(sizeof(resp.key) != CXI_ETH_HASH_KEY_SIZE);

	rc = cxi_send_msg_to_pf(cdev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc) {
		/* On error, zero out the key */
		memset(key, 0, CXI_ETH_HASH_KEY_SIZE);
		return;
	}

	memcpy(key, resp.key, CXI_ETH_HASH_KEY_SIZE);
}

/**
 * cxi_rmu_eth_get_hash_key() - Retrieve the RSS hash key
 *
 * @cdev: CXI device
 * @key: A sufficiently large (CXI_ETH_HASH_KEY_SIZE) array to store the key.
 */
void cxi_rmu_eth_get_hash_key(struct cxi_dev *cdev, u8 *key)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	union c_rmu_cfg_hash_key hash_key;

	if (!cdev->is_physfn) {
		cxi_rmu_eth_get_hash_key_vf(cdev, key);
		return;
	}

	spin_lock(&hw->rmu_lock);
	cass_read(hw, C_RMU_CFG_HASH_KEY, &hash_key, sizeof(hash_key));
	spin_unlock(&hw->rmu_lock);

	memcpy(key, hash_key.qw, CXI_ETH_HASH_KEY_SIZE);
}
EXPORT_SYMBOL(cxi_rmu_eth_get_hash_key);
