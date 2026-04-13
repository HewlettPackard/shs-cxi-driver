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

/* Maximum number of concurrent clients allowed in PF */
static unsigned int rmu_pf_max_clients = 2;
module_param(rmu_pf_max_clients, uint, 0444);
MODULE_PARM_DESC(rmu_pf_max_clients, "Maximum number of concurrent RMU Ethernet clients in PF");

/* Total MAC filter allocation (set_list entries)
 * - PF gets fixed quota: rmu_pf_client_max_filters (default 20, module parameter)
 * - VFs split remaining pool equally.
 */
static unsigned int rmu_pf_client_max_filters = 20;
module_param(rmu_pf_client_max_filters, uint, 0444);
MODULE_PARM_DESC(rmu_pf_client_max_filters,
		 "Maximum number of MAC filters allocated to a PF client");

/* Indirection table allocation
 * - PF gets fixed quota: rmu_pf_client_max_rss_indir_size (default 64, module parameter)
 * - VFs split remaining pool equally.
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
 * validate_mac_vf() - Validate MAC address for VF use
 * @mac_addr: MAC address to validate
 *
 * VFs can only use valid unicast MAC addresses (not multicast, broadcast, or zero).
 * This also includes the reserved MAC addresses for PTP and multicast base,
 * which should not be used by VFs.
 *
 * Return: 0 if valid, -EINVAL if invalid
 */
static int validate_mac_vf(u64 mac_addr)
{
	u8 addr[ETH_ALEN];

	u64_to_ether_addr(mac_addr, addr);

	return is_valid_ether_addr(addr) ? 0 : -EINVAL;
}

/**
 * cxi_rmu_eth_alloc_vf() - Allocate Ethernet packet matching resources for VF
 * @cdev: CXI device
 *
 * VF version: Sends allocation request to PF via vsock. The PF will allocate
 * the actual hardware resources and track them. The VF maintains a minimal
 * private structure for sending future commands to the PF.
 *
 * Return: Pointer to cxi_rmu_eth or ERR_PTR on error
 */
static struct cxi_rmu_eth *cxi_rmu_eth_alloc_vf(struct cxi_dev *cdev)
{
	struct cxi_rmu_eth_priv *priv;
	struct cxi_rmu_eth_alloc_resp resp;
	const struct cxi_rmu_eth_alloc_cmd cmd = {
		.op = CXI_OP_RMU_ETH_ALLOC,
		.resp = &resp,
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

	priv->dev = cdev;
	priv->rmu_eth.id = resp.rmu_eth;

	return &priv->rmu_eth;
}

/**
 * cxi_rmu_eth_alloc_internal() - Allocate Ethernet packet matching resources
 * @cdev: CXI device
 * @vf_en: Whether this is a VF allocation
 * @vf_num: VF number if vf_en is true
 *
 * PF supports up to CXI_RMU_ETH_PF_MAX_CLIENTS concurrent allocations.
 * VFs support single client per function.
 * Returns -EBUSY if no slots available.
 *
 * Automatically allocates FULL per-function quota based on num_vfs.
 *
 * Return: Pointer to cxi_rmu_eth or ERR_PTR on error
 */
struct cxi_rmu_eth *cxi_rmu_eth_alloc_internal(struct cxi_dev *cdev, bool vf_en, u8 vf_num)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	struct cxi_rmu_eth *rmu_eth = NULL;
	struct cxi_rmu_eth_priv *priv;
	unsigned int indir_quota;
	unsigned int set_list_quota;
	int id;
	int i;

	if (vf_en && hw->num_vfs == 0)
		return ERR_PTR(-EINVAL);

	mutex_lock(&hw->rmu_eth_lock);

	/* Allocate private structure */
	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		mutex_unlock(&hw->rmu_eth_lock);
		return ERR_PTR(-ENOMEM);
	}

	/* Initialize structure */
	priv->dev = cdev;
	priv->is_vf = vf_en;
	priv->vf_num = vf_num;
	priv->admin = vf_en ? false : true; /* Only PF client has admin privileges */

	/* Store allocation in device structure (needed before ID allocation) */
	rmu_eth = &priv->rmu_eth;

	/* Get unique ID for this allocation. PF and VFs have separate ID spaces.
	 * PF clients: IDs 0 to (rmu_pf_max_clients - 1)
	 * VF clients: IDs starting from rmu_pf_max_clients
	 */
	id = idr_alloc(&hw->rmu_eth_idr, rmu_eth,
		       vf_en ? rmu_pf_max_clients + vf_num : 0,
		       vf_en ? rmu_pf_max_clients + vf_num + 1 : rmu_pf_max_clients,
		       GFP_KERNEL);

	if (id < 0) {
		kfree(priv);
		mutex_unlock(&hw->rmu_eth_lock);
		return ERR_PTR(id);
	}

	rmu_eth->id = id;

	/* Calculate per-client quotas and base indices
	 * - indirection table layout remains unchanged (PF first, then VFs).
	 * - set_list places PF clients at the end to avoid PF catch-all filters
	 *   taking early slots.
	 */
	if (vf_en) {
		/* VF gets equal share of remaining indirection and set_list pools */
		indir_quota = (C_RMU_CFG_PORTAL_INDEX_INDIR_TABLE_ENTRIES -
			      (rmu_pf_client_max_rss_indir_size * rmu_pf_max_clients)) / hw->num_vfs;
		set_list_quota = (C_RMU_CFG_PTLTE_SET_LIST_ENTRIES -
				 (rmu_pf_client_max_filters * rmu_pf_max_clients)) / hw->num_vfs;

		priv->indir_base = (rmu_pf_client_max_rss_indir_size * rmu_pf_max_clients) +
				   (vf_num * indir_quota);
		priv->set_list_base = vf_num * set_list_quota;
	} else {
		/* PF client keeps original indirection layout and gets tail set_list */
		indir_quota = rmu_pf_client_max_rss_indir_size;
		set_list_quota = rmu_pf_client_max_filters;

		priv->indir_base = id * indir_quota;
		priv->set_list_base = C_RMU_CFG_PTLTE_SET_LIST_ENTRIES -
				     (rmu_pf_max_clients * set_list_quota) +
				     (id * set_list_quota);
	}

	priv->indir_size = indir_quota;
	priv->set_list_quota = set_list_quota;

	/* Allocate MAC filter slot tracking array */
	priv->mac_filter_slots = kcalloc(set_list_quota, sizeof(u8), GFP_KERNEL);
	if (!priv->mac_filter_slots) {
		idr_remove(&hw->rmu_eth_idr, id);
		kfree(priv);
		mutex_unlock(&hw->rmu_eth_lock);
		return ERR_PTR(-ENOMEM);
	}

	/* Invalidate all set_list entries in our quota to ensure clean state */
	spin_lock(&hw->rmu_lock);
	for (i = 0; i < set_list_quota; i++)
		cass_invalidate_set_list(hw, priv->set_list_base + i);
	spin_unlock(&hw->rmu_lock);

	/* Default RSS configuration (disabled initially) */
	priv->rss_queues = 0;
	priv->hash_types = 0;
	priv->indir_entries = 0;  /* Active indirection table size */

	mutex_unlock(&hw->rmu_eth_lock);

	return &priv->rmu_eth;
}
EXPORT_SYMBOL(cxi_rmu_eth_alloc_internal);

struct cxi_rmu_eth *cxi_rmu_eth_alloc(struct cxi_dev *cdev)
{
	return cdev->is_physfn ? cxi_rmu_eth_alloc_internal(cdev, false, 0) :
				 cxi_rmu_eth_alloc_vf(cdev);
}
EXPORT_SYMBOL(cxi_rmu_eth_alloc);

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

	/* Invalidate all set_list entries in our quota range */
	spin_lock(&hw->rmu_lock);

	for (i = 0; i < priv->set_list_quota; i++) {
		unsigned int hw_idx = priv->set_list_base + i;

		/* Debug log for entries that were actually programmed */
		if (priv->mac_filter_slots[i]) {
			cxidev_dbg(priv->dev, "Removing RMU filter at idx=%d (hw_idx=%u)\n",
				   i, hw_idx);
		}

		cass_invalidate_set_list(hw, hw_idx);
	}

	spin_unlock(&hw->rmu_lock);

	/* Free slot tracking array */
	kfree(priv->mac_filter_slots);

	/* Remove from IDR */
	idr_remove(&hw->rmu_eth_idr, rmu_eth->id);

	mutex_unlock(&hw->rmu_eth_lock);

	kfree(priv);
}
EXPORT_SYMBOL(cxi_rmu_eth_free);

/**
 * add_rmu_set_list_filter() - Common hardware programming logic for filter installation
 * @priv: Private resource structure
 * @idx: Relative index within client's quota
 * @pte: PTE pointer
 * @use_rss: Whether traffic participates in RSS
 * @set_list: Prepared set_list entry with match criteria
 * @set_list_mask: Prepared mask for set_list
 *
 * Handles index validation, translation, and hardware programming for both
 * MAC filters and promiscuous mode filters.
 *
 * Return: 0 on success, negative errno on error
 */
static int add_rmu_set_list_filter(struct cxi_rmu_eth_priv *priv, unsigned int idx,
				   struct cxi_pte *pte, bool use_rss,
				   const union c_rmu_cfg_ptlte_set_list *set_list,
				   const union c_rmu_cfg_ptlte_set_list *set_list_mask)
{
	struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);
	unsigned int set_list_idx;
	unsigned int portal_idx;
	struct c_rmu_cfg_ptlte_set_ctrl_table_entry set_ctrl = {};

	/* Validate index range */
	if (idx >= priv->set_list_quota) {
		cxidev_err(priv->dev, "Index %d out of range [0..%u]\n",
			   idx, priv->set_list_quota - 1);
		return -EINVAL;
	}

	/* Extract portal index from PTE */
	portal_idx = pte->id;

	/* Translate relative index to hardware index */
	set_list_idx = priv->set_list_base + idx;

	spin_lock(&hw->rmu_lock);

	/* Program set_list */
	cass_config_set_list(hw, set_list_idx, portal_idx,
			     set_list, set_list_mask);

	/* Program set_ctrl for RSS or direct portal */
	if (use_rss && priv->rss_queues > 1) {
		/* Use RSS */
		set_ctrl.portal_index_indir_base = priv->indir_base;
		set_ctrl.hash_bits = ilog2(priv->indir_entries);
		set_ctrl.hash_types_enabled = priv->hash_types;
	} else {
		/* Direct portal (RSS disabled) - point to fallback entry */
		set_ctrl.portal_index_indir_base = 2048 + set_list_idx;
		set_ctrl.hash_bits = 0;
		set_ctrl.hash_types_enabled = 0;
	}

	/* Program set_ctrl */
	cass_config_set_ctrl(hw, set_list_idx, &set_ctrl);

	/* Program default portal at indir_table[2048 + set_list_idx] */
	cass_config_indir_entry(hw, 2048 + set_list_idx, portal_idx);

	spin_unlock(&hw->rmu_lock);

	/* Mark slot as used */
	priv->mac_filter_slots[idx] = use_rss ? CXI_RMU_ETH_FILTER_RSS :
					      CXI_RMU_ETH_FILTER_DIRECT;

	return 0;
}

/**
 * cxi_rmu_eth_add_mac_filter_vf() - Add MAC address filter (VF version)
 * @rmu_eth: Resource handle
 * @idx: Relative index (0-based) within client's quota
 * @mac_addr: MAC address to match (48-bit)
 * @pte: PTE pointer
 * @use_rss: Whether this MAC participates in RSS distribution
 *
 * VF version: Sends add_mac request to PF via vsock.
 *
 * Return: 0 on success, negative errno on error
 */
static int cxi_rmu_eth_add_mac_filter_vf(struct cxi_rmu_eth *rmu_eth,
					 unsigned int idx, u64 mac_addr,
					 struct cxi_pte *pte, bool use_rss)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	const struct cxi_rmu_eth_add_mac_filter_cmd cmd = {
		.op = CXI_OP_RMU_ETH_ADD_MAC_FILTER,
		.rmu_eth = rmu_eth->id,
		.idx = idx,
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
 * @idx: Relative index (0-based) within client's quota
 * @pte: PTE pointer
 * @use_rss: Whether this filter participates in RSS distribution
 *
 * VF version: Sends add-all-multicast request to PF via vsock.
 *
 * Return: 0 on success, negative errno on error
 */
static int cxi_rmu_eth_add_all_mcast_filter_vf(struct cxi_rmu_eth *rmu_eth, unsigned int idx,
					       struct cxi_pte *pte, bool use_rss)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	const struct cxi_rmu_eth_add_all_mcast_filter_cmd cmd = {
		.op = CXI_OP_RMU_ETH_ADD_ALL_MCAST_FILTER,
		.rmu_eth = rmu_eth->id,
		.idx = idx,
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
 * @idx: Relative index (0-based) within client's quota
 * @mac_addr: MAC address to match (48-bit)
 * @pte: PTE pointer (provides portal index via pte->portal_index)
 * @use_rss: Whether this MAC participates in RSS distribution
 *
 * Client provides relative index [0..quota-1], kernel translates to hardware index.
 * Reserved indices (0-3) can only be used by PF.
 *
 * Return: 0 on success, negative errno on error
 */
int cxi_rmu_eth_add_mac_filter(struct cxi_rmu_eth *rmu_eth, unsigned int idx, u64 mac_addr,
			       struct cxi_pte *pte, bool use_rss)
{
	struct cxi_rmu_eth_priv *priv;
	union c_rmu_cfg_ptlte_set_list set_list = {};
	union c_rmu_cfg_ptlte_set_list set_list_mask = {};
	u8 mac_bytes[ETH_ALEN];
	int rc;

	if (!rmu_eth || !pte)
		return -EINVAL;

	priv = container_of(rmu_eth, struct cxi_rmu_eth_priv, rmu_eth);

	if (!priv->dev->is_physfn)
		return cxi_rmu_eth_add_mac_filter_vf(rmu_eth, idx, mac_addr, pte, use_rss);

	u64_to_ether_addr(mac_addr, mac_bytes);
	cxidev_dbg(priv->dev, "Adding MAC RMU filter %pM at idx=%d (hw_idx=%u) use_rss=%d pte id %u\n",
		   mac_bytes, idx, priv->set_list_base + idx, use_rss, pte->id);

	/* VFs must use valid unicast MACs only */
	if (!priv->admin) {
		rc = validate_mac_vf(mac_addr);
		if (rc) {
			cxidev_err(priv->dev, "VF cannot use MAC %pM\n", mac_bytes);
			return rc;
		}
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

	/* Program hardware set_list filter */
	return add_rmu_set_list_filter(priv, idx, pte, use_rss, &set_list, &set_list_mask);
}
EXPORT_SYMBOL(cxi_rmu_eth_add_mac_filter);

/**
 * cxi_rmu_eth_add_all_mcast_filter() - Add all-multicast filter with portal and RSS control
 * @rmu_eth: Resource handle
 * @idx: Relative index (0-based) within client's quota
 * @pte: PTE pointer (provides portal index via pte->portal_index)
 * @use_rss: Whether this filter participates in RSS distribution
 *
 * Programs a filter that accepts all multicast Ethernet packets by matching
 * only frame type and destination MAC multicast bit semantics.
 *
 * Return: 0 on success, negative errno on error
 */
int cxi_rmu_eth_add_all_mcast_filter(struct cxi_rmu_eth *rmu_eth, unsigned int idx,
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
		return cxi_rmu_eth_add_all_mcast_filter_vf(rmu_eth, idx, pte, use_rss);

	cxidev_dbg(priv->dev,
		   "Adding all-multicast RMU filter at idx=%d (hw_idx=%u) use_rss=%d pte id %u\n",
		   idx, priv->set_list_base + idx, use_rss, pte->id);

	return add_rmu_set_list_filter(priv, idx, pte, use_rss, &set_list, &set_list_mask);
}
EXPORT_SYMBOL(cxi_rmu_eth_add_all_mcast_filter);

/**
 * cxi_rmu_eth_remove_filter_vf() - Remove filter (VF version)
 * @rmu_eth: Resource handle
 * @idx: Relative index of filter to remove
 *
 * VF version: Sends remove_filter request to PF via vsock.
 *
 * Return: 0 on success, negative errno on error
 */
static int cxi_rmu_eth_remove_filter_vf(struct cxi_rmu_eth *rmu_eth, unsigned int idx)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	const struct cxi_rmu_eth_remove_filter_cmd cmd = {
		.op = CXI_OP_RMU_ETH_REMOVE_FILTER,
		.rmu_eth = rmu_eth->id,
		.idx = idx,
	};
	size_t resp_len = 0;
	int rc;

	rc = cxi_send_msg_to_pf(priv->dev, &cmd, sizeof(cmd), NULL, &resp_len);
	if (rc)
		return rc;

	return 0;
}

/**
 * cxi_rmu_eth_remove_filter() - Remove filter by index
 * @rmu_eth: Resource handle
 * @idx: Relative index of filter to remove
 *
 * Works for both MAC address filters and promiscuous mode filters.
 * MAC filters use slot tracking and return -ENOENT if slot is empty.
 * Promiscuous filters don't use slot tracking.
 *
 * Return: 0 on success, -ENOENT if MAC slot is empty, -EINVAL for invalid index
 */
int cxi_rmu_eth_remove_filter(struct cxi_rmu_eth *rmu_eth, unsigned int idx)
{
	struct cxi_rmu_eth_priv *priv = container_of(rmu_eth,
						     struct cxi_rmu_eth_priv,
						     rmu_eth);
	struct cass_dev *hw = container_of(priv->dev, struct cass_dev, cdev);
	unsigned int set_list_idx;

	if (!priv->dev->is_physfn)
		return cxi_rmu_eth_remove_filter_vf(rmu_eth, idx);

	/* Validate index range */
	if (idx >= priv->set_list_quota) {
		cxidev_err(priv->dev, "Index %d out of range [0..%u]\n",
			   idx, priv->set_list_quota - 1);
		return -EINVAL;
	}

	/* Check if slot is occupied (both MAC and promiscuous filters use slot tracking) */
	if (!priv->mac_filter_slots[idx]) {
		cxidev_dbg(priv->dev, "Remove filter at idx=%d (hw_idx=%u) but slot is empty\n",
			   idx, priv->set_list_base + idx);
		return -ENOENT;
	}

	cxidev_dbg(priv->dev, "Remove filter at idx=%d (hw_idx=%u)\n",
		   idx, priv->set_list_base + idx);
	/* Translate to hardware index */
	set_list_idx = priv->set_list_base + idx;

	/* Invalidate hardware entry */
	spin_lock(&hw->rmu_lock);
	cass_invalidate_set_list(hw, set_list_idx);
	spin_unlock(&hw->rmu_lock);

	/* Clear slot (all filters use slot tracking now) */
	priv->mac_filter_slots[idx] = CXI_RMU_ETH_FILTER_NONE;

	return 0;
}
EXPORT_SYMBOL(cxi_rmu_eth_remove_filter);

/**
 * cxi_rmu_eth_add_promiscuous_filter() - Enable promiscuous mode filter
 * @rmu_eth: Resource handle
 * @idx: Relative index within client's quota for this filter
 * @pte: PTE pointer
 * @use_rss: Whether promiscuous traffic participates in RSS
 *
 * Return: 0 on success, negative errno on error
 */
int cxi_rmu_eth_add_promiscuous_filter(struct cxi_rmu_eth *rmu_eth, unsigned int idx,
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

	/* VF cannot enable promiscuous mode */
	if (!priv->admin)
		return -EPERM;

	cxidev_dbg(priv->dev, "Add promiscuous RMU filter at idx=%u (hw_idx=%u) use_rss=%d\n",
		   idx, priv->set_list_base + idx, use_rss);

	/* Program hardware set_list filter */
	return add_rmu_set_list_filter(priv, idx, pte, use_rss, &set_list, &set_list_mask);
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

	if (enable && priv->rss_queues > 1) {
		/* RSS enabled - configure indirection table */
		set_ctrl.portal_index_indir_base = priv->indir_base;
		set_ctrl.hash_bits = ilog2(priv->indir_entries);
		set_ctrl.hash_types_enabled = priv->hash_types;
	}
	/* else: set_ctrl stays zero (direct portal mode); portal_index_indir_base
	 * is set per-filter below */

	/* Update all filters that use RSS */
	for (i = 0; i < priv->set_list_quota; i++) {
		if (priv->mac_filter_slots[i] == CXI_RMU_ETH_FILTER_RSS) {
			unsigned int hw_idx = priv->set_list_base + i;

			if (!enable || priv->rss_queues <= 1) {
				/* Use direct portal */
				set_ctrl.portal_index_indir_base = 2048 + hw_idx;
			}

			cass_config_set_ctrl(hw, hw_idx, &set_ctrl);
		}
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
