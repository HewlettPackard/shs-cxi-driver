// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020, 2024-2026 Hewlett Packard Enterprise Development LP */

/* Service Management */

#include <linux/cred.h>

#include "cass_core.h"
#include "cxi_rxtx_profile.h"
#include "cxi_rxtx_profile_list.h"
#include "cass_ss1_debugfs.h"
#include "cxi_vf_cmd.h"

static bool disable_default_svc = true;
module_param(disable_default_svc, bool, 0444);
MODULE_PARM_DESC(disable_default_svc, "Disable the default service.");

static bool default_svc_test_mode;
module_param(default_svc_test_mode, bool, 0444);
MODULE_PARM_DESC(default_svc_test_mode,
		 "Remove all safety rails for default service.");

static int default_svc_num_tles = 512;
module_param(default_svc_num_tles, int, 0644);
MODULE_PARM_DESC(default_svc_num_tles,
		 "Number of reserved TLEs for default service");

static unsigned int default_vnis[CXI_SVC_MAX_VNIS] = {1, 10, 0, 0};
module_param_array(default_vnis, uint, NULL, 0444);
MODULE_PARM_DESC(default_vnis,
		 "Default VNIS. Should be consistent at the fabric level");

static bool enable_rgid_sharing = true;
module_param(enable_rgid_sharing, bool, 0644);
MODULE_PARM_DESC(enable_rgid_sharing,
		 "Allow future CXI service allocations to use RGID sharing.");

static int default_lnis_per_rgid = CXI_DEFAULT_LNIS_PER_RGID;
module_param(default_lnis_per_rgid, int, 0644);
MODULE_PARM_DESC(default_lnis_per_rgid, "Number of LNIs per RGID");

static void svc_destroy(struct cass_dev *hw, struct cxi_svc_priv *svc_priv);

static enum cxi_resource_type stype_to_rtype(enum cxi_rsrc_type type, int pe)
{
	switch (type) {
	case CXI_RSRC_TYPE_PTE:
		return CXI_RESOURCE_PTLTE;
	case CXI_RSRC_TYPE_TXQ:
		return CXI_RESOURCE_TXQ;
	case CXI_RSRC_TYPE_TGQ:
		return CXI_RESOURCE_TGQ;
	case CXI_RSRC_TYPE_EQ:
		return CXI_RESOURCE_EQ;
	case CXI_RSRC_TYPE_CT:
		return CXI_RESOURCE_CT;
	case CXI_RSRC_TYPE_LE:
		return CXI_RESOURCE_PE0_LE + pe;
	case CXI_RSRC_TYPE_TLE:
		return CXI_RESOURCE_TLE;
	case CXI_RSRC_TYPE_AC:
		return CXI_RESOURCE_AC;
	default:
		return CXI_RESOURCE_MAX;
	}
}

static void copy_rsrc_use(struct cxi_dev *dev, struct cxi_rsrc_use *rsrcs,
			  struct cxi_rgroup *rgroup)
{
	int rc;
	int type;
	enum cxi_resource_type rtype;
	struct cxi_resource_entry *entry;
	struct cxi_resource_entry local_entry = {};

	for (type = 0; type < CXI_RSRC_TYPE_MAX; type++) {
		rtype = stype_to_rtype(type, 0);

		/* rsrcs->in_use[type] = U16_MAX; indicates that "in use"
		 * is not valid and any consumer should treat it as
		 * NOT APPLICABLE.
		 */
		if (type == CXI_RSRC_TYPE_TLE) {
			if (!cass_get_tle_in_use(rgroup, &local_entry)) {
				rsrcs->in_use[type] = local_entry.limits.in_use;
				rsrcs->tle_pool_id = cxi_rgroup_tle_pool_id(rgroup);
			} else {
				rsrcs->in_use[type] = U16_MAX;
				rsrcs->tle_pool_id = DEFAULT_TLE_POOL_ID;
			}
		} else if (type == CXI_RSRC_TYPE_LE) {
			if (!cass_get_le_in_use(rgroup, &local_entry)) {
				rsrcs->in_use[type] = local_entry.limits.in_use;
			} else {
				rsrcs->in_use[type] = U16_MAX;
			}
		} else {
			rc = cxi_rgroup_get_resource_entry(rgroup,
							   rtype, &entry);
			if (rc) {
				rsrcs->in_use[type] = 0;
				continue;
			}

			rsrcs->in_use[type] = entry->limits.in_use;
		}
	}
}

void cass_cfg_tle_pool(struct cass_dev *hw, int pool_id,
		       const struct cxi_limits *tles, bool release)
{
	union c_cq_cfg_tle_pool tle_pool;

	if (release) {
		tle_pool.max_alloc = 0;
		tle_pool.num_reserved = 0;
	} else {
		tle_pool.max_alloc = tles->max;
		tle_pool.num_reserved = tles->res;
	}
	cass_write(hw, C_CQ_CFG_TLE_POOL(pool_id), &tle_pool,
			   sizeof(tle_pool));
}

void cass_tle_init(struct cass_dev *hw)
{
	int i;
	union c_cq_cfg_sts_tle_shared tle_shared;
	union c_cq_cfg_tle_pool tle_pool_cfg = {
		.max_alloc = 0,
		.num_reserved = 0,
	};

	/* Ensure there is no shared space for TLEs */
	tle_shared.num_shared = 0;
	cass_write(hw, C_CQ_CFG_STS_TLE_SHARED, &tle_shared,
		   sizeof(tle_shared));

	/* Disable all pools */
	for (i = 0; i < C_CQ_CFG_TLE_POOL_ENTRIES; i++)
		cass_write(hw, C_CQ_CFG_TLE_POOL(i), &tle_pool_cfg,
			   sizeof(tle_pool_cfg));
}

static void default_rsrc_limits(struct cxi_rsrc_limits *limits)
{
	memset(limits, 0, sizeof(*limits));

	limits->type[CXI_RSRC_TYPE_PTE].max = C_NUM_PTLTES;
	limits->type[CXI_RSRC_TYPE_TXQ].max = C_NUM_TRANSMIT_CQS;
	limits->type[CXI_RSRC_TYPE_TGQ].max = C_NUM_TARGET_CQS;
	limits->type[CXI_RSRC_TYPE_EQ].max = EQS_AVAIL;
	limits->type[CXI_RSRC_TYPE_CT].max = CTS_AVAIL;
	limits->type[CXI_RSRC_TYPE_LE].max = pe_total_les;
	limits->type[CXI_RSRC_TYPE_TLE].max = C_NUM_TLES;
	limits->type[CXI_RSRC_TYPE_AC].max = ACS_AVAIL;
}

int cass_svc_init(struct cass_dev *hw)
{
	static struct cxi_svc_desc svc_desc = {
		.resource_limits = true,
	};
	int i, svc_id;
	struct cxi_svc_priv *svc_priv;
	struct cxi_rsrc_limits limits;

	mutex_init(&hw->svc_lock);
	idr_init(&hw->svc_ids);
	INIT_LIST_HEAD(&hw->svc_list);
	hw->svc_count = 0;

	if (!hw->cdev.is_physfn)
		return 0;

	default_rsrc_limits(&hw->cdev.prop.rsrcs);

	for (i = 0; i < CXI_RSRC_TYPE_MAX; i++) {
		/* Set up resource limits for default service */
		if (i == CXI_RSRC_TYPE_TLE) {
			limits.type[i].res = max(CASS_MIN_POOL_TLES,
						 default_svc_num_tles);
			limits.type[i].max = limits.type[i].res;
			continue;
		}

		limits.type[i].max = hw->cdev.prop.rsrcs.type[i].max;

		/* Budget for VF ethernet children; must cover C_NUM_VFS *
		 * hw_setup() per-VF res without exceeding global pool sizes.
		 * PTE: C_NUM_VFS * CXI_ETH_SVC_PTE_RES = 512 << C_NUM_PTLTES=2048.
		 * LE:  half the per-PE pool leaves room for PF ethernet.
		 * For more than ~8 VFs needing full LE allocation, use a
		 * dedicated parent service via sysfs vf/N/svc_id.
		 */
		switch (i) {
		case CXI_RSRC_TYPE_PTE:
			limits.type[i].res = C_NUM_VFS * CXI_ETH_SVC_PTE_RES;
			break;
		case CXI_RSRC_TYPE_TXQ:
		case CXI_RSRC_TYPE_TGQ:
		case CXI_RSRC_TYPE_EQ:
		case CXI_RSRC_TYPE_AC:
			limits.type[i].res = C_NUM_VFS;
			break;
		case CXI_RSRC_TYPE_LE:
			/* Half the per-PE pool; leaves room for PF ethernet */
			limits.type[i].res = limits.type[i].max / 2;
			break;
		default:
			limits.type[i].res = 0;
			break;
		}
	}
	svc_desc.limits = limits;

	for (i = CXI_TC_DEDICATED_ACCESS; i <= CXI_TC_BEST_EFFORT; ++i)
		svc_desc.tcs[i] = true;

	if (!default_svc_test_mode) {
		svc_desc.restricted_vnis = true;
		svc_desc.num_vld_vnis = 0;

		for (i = 0; i < CXI_SVC_MAX_VNIS; i++) {
			if (!is_vni_valid(default_vnis[i]))
				break;
			svc_desc.num_vld_vnis++;
			svc_desc.vnis[i] = default_vnis[i];
		}

		if (!svc_desc.num_vld_vnis)
			return -EINVAL;
	}

	/* Create default service. It will get the default ID of
	 * CXI_DEFAULT_SVC_ID
	 */
	svc_id = cxi_svc_alloc(&hw->cdev, &svc_desc, NULL, "default");
	if (svc_id < 0)
		return svc_id;

	mutex_lock(&hw->svc_lock);
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	mutex_unlock(&hw->svc_lock);

	cxi_rgroup_set_lnis_per_rgid_compat(svc_priv->rgroup, 1);

	svc_service_debugfs_create(hw);

	return 0;
}

/* Check if a there are enough unused instances of a particular resource */
static bool rsrc_available(struct cass_dev *hw,
			   struct cxi_rsrc_limits *limits,
			   enum cxi_rsrc_type type, int pe,
			   struct cxi_svc_fail_info *fail_info)
{
	u16 shared_avail;
	enum cxi_resource_type rtype;

	rtype = stype_to_rtype(type, pe);
	if (rtype >= CXI_RESOURCE_MAX)
		return false;

	shared_avail = hw->resource_use[rtype].shared;

	/* Always fill out fail_info if a resource was requested so it
	 * accurately reflects how many of resource X was available.
	 * If all resources are in fact available, it won't be sent
	 * back to the user.
	 */
	if (fail_info)
		fail_info->rsrc_avail[type] = shared_avail;

	if (limits->type[type].res > shared_avail)
		return false;

	return true;
}

/* Check if a child service can fit within the parent's remaining budget.
 * Caller must hold hw->svc_lock.
 */
static bool rsrc_available_child(const struct cxi_svc_priv *parent,
				 const struct cxi_rsrc_limits *limits,
				 enum cxi_rsrc_type type,
				 struct cxi_svc_fail_info *fail_info)
{
	/* Use res as the parent budget.  res is what the parent
	 * actually withdrew from the global shared pool; that is the only
	 * hard quota children can draw from.
	 */
	u16 remaining = parent->svc_desc.limits.type[type].res -
			parent->child_reserved[type];

	if (fail_info)
		fail_info->rsrc_avail[type] = remaining;

	return limits->type[type].res <= remaining;
}

/* Look up the parent service assigned to a VF.
 * Caller must hold hw->svc_lock.
 */
static struct cxi_svc_priv *find_parent_for_vf(struct cass_dev *hw, u8 vf_num)
{
	return idr_find(&hw->svc_ids, hw->vf_cfg[vf_num].svc_id);
}

/* Validate that all VNIs in child_desc are acceptable given the parent's
 * VNI policy:
 *  - restricted_vnis=1: each child VNI must appear in parent's vnis[] list.
 *  - restricted_vnis=0: the parent has a VNI range; each child VNI must fall
 *    within that range.  Returns -EPERM if the parent has no range set yet.
 */
static int validate_child_vnis(struct cxi_dev *dev,
			       const struct cxi_svc_priv *parent,
			       const struct cxi_svc_desc *child_desc)
	__must_hold(&hw->svc_lock)
{
	int i;
	int j;

	if (!parent->svc_desc.restricted_vnis) {
		struct cxi_tx_attr parent_tx_attr;
		unsigned int parent_min, parent_max;
		int rc;

		if (!parent->tx_profile[0]) {
			pr_debug("%s: parent has no VNI range set\n", __func__);
			return -EPERM;
		}

		rc = cxi_tx_profile_get_info(dev, parent->tx_profile[0],
					     &parent_tx_attr, NULL);
		if (rc)
			return rc;

		parent_min = parent_tx_attr.vni_attr.match;
		parent_max = parent_tx_attr.vni_attr.match +
			     parent_tx_attr.vni_attr.ignore;

		for (i = 0; i < child_desc->num_vld_vnis; i++) {
			if (child_desc->vnis[i] < parent_min ||
			    child_desc->vnis[i] > parent_max) {
				pr_debug("%s: child VNI %u outside parent range [%u, %u]\n",
					 __func__, child_desc->vnis[i],
					 parent_min, parent_max);
				return -EINVAL;
			}
		}
		return 0;
	}

	for (i = 0; i < child_desc->num_vld_vnis; i++) {
		bool found = false;

		for (j = 0; j < parent->svc_desc.num_vld_vnis; j++) {
			if (child_desc->vnis[i] == parent->svc_desc.vnis[j]) {
				found = true;
				break;
			}
		}

		if (!found) {
			pr_debug("%s: child VNI %u not in parent's VNI list\n",
				 __func__, child_desc->vnis[i]);
			return -EINVAL;
		}
	}
	return 0;
}

/* Return resource reservations upon destruction of a service
 * Caller must hold hw->svc_lock.
 */
static void free_rsrc(struct cxi_svc_priv *svc_priv,
		      enum cxi_rsrc_type type)
{
	int rc;
	int pe;
	enum cxi_resource_type rtype = stype_to_rtype(type, 0);

	if (type == CXI_RSRC_TYPE_LE) {
		for (pe = 0; pe < C_PE_COUNT; pe++) {
			rc = cxi_rgroup_delete_resource(svc_priv->rgroup,
							rtype + pe);
			if (rc)
				pr_debug("delete resource %s failed %d\n",
					 cxi_resource_type_to_str(type + pe),
					 rc);
		}

		return;
	}

	rc = cxi_rgroup_delete_resource(svc_priv->rgroup, rtype);
	if (rc)
		pr_debug("delete resource %s failed %d\n",
			 cxi_rsrc_type_to_str(type), rc);
}

static void free_rsrcs(struct cxi_svc_priv *svc_priv)
{
	int i;

	for (i = 0; i < CXI_RSRC_TYPE_MAX; i++)
		free_rsrc(svc_priv, i);
}

static int add_resource(struct cxi_rgroup *rgroup, enum cxi_rsrc_type type,
			struct cxi_resource_limits *limits)
{
	int rc;
	int pe;

	if (type == CXI_RSRC_TYPE_LE) {
		for (pe = 0; pe < C_PE_COUNT; pe++) {
			rc = cxi_rgroup_add_resource(rgroup,
						     stype_to_rtype(type, pe),
						     limits);
			if (rc) {
				pr_debug("add resource %s PE %d failed\n",
					 cxi_rsrc_type_to_str(type), pe);
				return rc;
			}
		}

		return rc;
	}

	rc = cxi_rgroup_add_resource(rgroup,
				     stype_to_rtype(type, 0), limits);
	if (rc)
		pr_debug("add resource %s failed\n",
			 cxi_rsrc_type_to_str(type));

	return rc;
}

/* For each resource requested, check if enough of that resource is available.
 * If they are all available, update the reserved values in the device.
 * Caller must hold hw->svc_lock.
 */
static int reserve_rsrcs(struct cass_dev *hw,
			 struct cxi_svc_priv *svc_priv,
			 struct cxi_svc_fail_info *fail_info)
{
	int i;
	int pe;
	int rc = 0;
	struct cxi_rgroup *rgroup = svc_priv->rgroup;
	struct cxi_rsrc_limits *limits = &svc_priv->svc_desc.limits;
	struct cxi_svc_priv *parent = svc_priv->parent;

	/* Default pool for default svc or when there are no LE limits */
	if (!svc_priv->svc_desc.resource_limits)
		default_rsrc_limits(limits);

	for (i = CXI_RSRC_TYPE_PTE; i < CXI_RSRC_TYPE_MAX; i++) {
		if (!limits->type[i].res && !limits->type[i].max)
			continue;

		if (i == CXI_RSRC_TYPE_TLE) {
			if (parent) {
				/* Child services inherit the parent's TLE pool.
				 * Clear any TLE request so no new pool is
				 * allocated; pool IDs are copied after
				 * reserve_rsrcs() returns.
				 */
				limits->type[i].res = 0;
				limits->type[i].max = 0;
				continue;
			}
			if (svc_priv->svc_desc.svc_id != CXI_DEFAULT_SVC_ID) {
				/* Ensure TLE max/res are at least CASS_MIN_POOL_TLES */
				if (limits->type[i].res < CASS_MIN_POOL_TLES)
					limits->type[i].res = CASS_MIN_POOL_TLES;
				/* Force TLE max/res to be equal */
				limits->type[i].max = limits->type[i].res;
			}
		} else if (parent) {
			/* Child service: check against parent's remaining budget. */
			if (!rsrc_available_child(parent, limits, i, fail_info)) {
				pr_debug("resource %s exceeds parent budget\n",
					 cxi_rsrc_type_to_str(i));
				rc = -ENOSPC;
				goto nospace;
			}
		} else if (i == CXI_RSRC_TYPE_LE) {
			for (pe = 0; pe < C_PE_COUNT; pe++) {
				if (!rsrc_available(hw, limits, i, pe,
						    fail_info)) {
					pr_debug("resource %s PE %d unavailable\n",
						 cxi_rsrc_type_to_str(i), pe);
					rc = -ENOSPC;
					goto nospace;
				}
			}
		} else if (!rsrc_available(hw, limits, i, 0, fail_info)) {
			pr_debug("resource %s unavailable\n",
				 cxi_rsrc_type_to_str(i));
			rc = -ENOSPC;
			goto nospace;
		}
	}

nospace:
	if (rc)
		return rc;

	/* For child services, populate parent_entry[] before calling
	 * add_resource() so that cass_rgroup_add_resource() can adjust
	 * the parent rgroup's per-entry reserved counter under rgrp_lock.
	 */
	if (parent) {
		for (i = CXI_RSRC_TYPE_PTE; i < CXI_RSRC_TYPE_MAX; i++) {
			enum cxi_resource_type rtype = stype_to_rtype(i, 0);

			if (rtype >= CXI_RESOURCE_MAX)
				continue;

			cxi_rgroup_get_resource_entry(parent->rgroup, rtype,
						      &rgroup->parent_entry[rtype]);
			/* For LE, fill all PE entries */
			if (i == CXI_RSRC_TYPE_LE) {
				int pe2;

				for (pe2 = 1; pe2 < C_PE_COUNT; pe2++) {
					rtype = stype_to_rtype(i, pe2);
					cxi_rgroup_get_resource_entry(
						parent->rgroup, rtype,
						&rgroup->parent_entry[rtype]);
				}
			}
		}
		rgroup->is_child = true;
	}

	/* Now reserve resources since needed ones are available */
	for (i = CXI_RSRC_TYPE_PTE; i < CXI_RSRC_TYPE_MAX; i++) {
		struct cxi_resource_limits lim = {
			.reserved = limits->type[i].res,
			.max = limits->type[i].max
		};

		if (!lim.reserved && !lim.max)
			continue;

		/* Do not reserve an LE pool if reserved is 0 */
		if (!lim.reserved && i == CXI_RSRC_TYPE_LE)
			continue;

		rc = add_resource(rgroup, i, &lim);
		if (rc) {
			pr_debug("resource %s add_resource failed %d\n",
				 cxi_rsrc_type_to_str(i), rc);

			if (rc == -EBADR) {
				if (i == CXI_RSRC_TYPE_TLE)
					fail_info->no_tle_pools = true;

				if (i == CXI_RSRC_TYPE_LE)
					fail_info->no_le_pools = true;
				rc = -ENOSPC;
			}

			goto err;
		}
	}

	return 0;

err:
	/* Remove any resources we already allocated */
	for (--i; i >= CXI_RSRC_TYPE_PTE; i--) {
		if (!limits->type[i].res)
			continue;

		free_rsrc(svc_priv, i);
	}

	return rc;
}

/* Basic sanity checks for user provided service descriptor */
static int validate_descriptor(struct cass_dev *hw,
			       const struct cxi_svc_desc *svc_desc)
{
	int i;

	if (svc_desc->restricted_vnis) {
		if (svc_desc->num_vld_vnis > CXI_SVC_MAX_VNIS) {
			pr_debug("%s: too many VNIs: %u > %u\n", __func__,
				 svc_desc->num_vld_vnis, CXI_SVC_MAX_VNIS);
			return -EINVAL;
		}
		for (i = 0; i < svc_desc->num_vld_vnis; i++) {
			if (!is_vni_valid(svc_desc->vnis[i])) {
				pr_debug("%s: invalid VNI[%d]=%u\n", __func__,
					 i, svc_desc->vnis[i]);
				return -EINVAL;
			}
		}
	}

	if (svc_desc->restricted_members) {
		for (i = 0; i < CXI_SVC_MAX_MEMBERS; i++) {
			if (svc_desc->members[i].type < 0 ||
			    svc_desc->members[i].type >= CXI_SVC_MEMBER_MAX) {
				pr_debug("%s: invalid member[%d].type=%d\n",
					 __func__, i, svc_desc->members[i].type);
				return -EINVAL;
			}
		}
	}

	if (svc_desc->resource_limits) {
		for (i = 0; i < CXI_RSRC_TYPE_MAX; i++) {
			if (svc_desc->limits.type[i].max <
			    svc_desc->limits.type[i].res) {
				pr_debug("%s: rsrc[%d] max(%u) < res(%u)\n",
					 __func__, i,
					 svc_desc->limits.type[i].max,
					 svc_desc->limits.type[i].res);
				return -EINVAL;
			}
			if (svc_desc->limits.type[i].max >
			    hw->cdev.prop.rsrcs.type[i].max) {
				pr_debug("%s: rsrc[%d] max(%u) > dev_max(%u)\n",
					 __func__, i,
					 svc_desc->limits.type[i].max,
					 hw->cdev.prop.rsrcs.type[i].max);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static enum cxi_ac_type svc_mbr_to_ac_type(enum cxi_svc_member_type type,
					   bool restricted_members)
{
	if (!restricted_members)
		return CXI_AC_OPEN;

	switch (type) {
	case CXI_SVC_MEMBER_UID:
		return CXI_AC_UID;
	case CXI_SVC_MEMBER_GID:
		return CXI_AC_GID;
	case CXI_SVC_MEMBER_NET_NS:
		return CXI_AC_NETNS;
	case CXI_SVC_MEMBER_IGNORE:
		fallthrough;
	default:
		return 0;
	}
}

static void set_tcs(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv)
{
	int i, j;
	struct cxi_tx_profile *tx_profile;
	struct cxi_svc_desc *svc_desc = &svc_priv->svc_desc;

	for (i = 0; i < svc_priv->svc_desc.num_vld_vnis; i++) {
		tx_profile = svc_priv->tx_profile[i];

		for (j = 0; j < CXI_TC_MAX; j++)
			if (!svc_desc->restricted_tcs || svc_desc->tcs[j])
				cxi_tx_profile_set_tc(tx_profile, j, true);
	}
}

static int alloc_rgroup_ac_entries(struct cxi_dev *dev,
				   struct cxi_svc_priv *svc_priv)
{
	int i;
	int rc;
	enum cxi_ac_type type;
	unsigned int ac_entry_id;
	union cxi_ac_data ac_data = {};
	struct cxi_svc_desc *svc_desc = &svc_priv->svc_desc;

	if (!svc_desc->restricted_members)
		return cxi_rgroup_add_ac_entry(svc_priv->rgroup, CXI_AC_OPEN,
					       &ac_data, &ac_entry_id);

	for (i = 0; i < CXI_SVC_MAX_MEMBERS; i++) {
		/* No AC entry for member[].type of CXI_SVC_MEMBER_IGNORE */
		type = svc_mbr_to_ac_type(svc_desc->members[i].type,
					  svc_desc->restricted_members);
		if (!type)
			continue;

		if (type == CXI_AC_UID)
			ac_data.uid = svc_desc->members[i].svc_member.uid;
		else if (type == CXI_AC_GID)
			ac_data.gid = svc_desc->members[i].svc_member.gid;

		rc = cxi_rgroup_add_ac_entry(svc_priv->rgroup, type, &ac_data,
					     &ac_entry_id);
		if (rc)
			goto cleanup;
	}

	return 0;

cleanup:
	cxi_ac_entry_list_destroy(&svc_priv->rgroup->ac_entry_list);

	return rc;
}

static void remove_profile_ac_entries(struct cxi_dev *dev,
				      struct cxi_svc_priv *svc_priv)
{
	int i;
	struct cxi_svc_desc *svc_desc = &svc_priv->svc_desc;

	for (i = 0; i < svc_desc->num_vld_vnis; i++) {
		cxi_tx_profile_remove_ac_entries(svc_priv->tx_profile[i]);
		cxi_rx_profile_remove_ac_entries(svc_priv->rx_profile[i]);
	}
}

/* No AC entry will be allocated for a member[].type of
 * CXI_SVC_MEMBER_IGNORE.
 */
static int alloc_profile_ac_entries(struct cxi_dev *dev,
				    struct cxi_svc_priv *svc_priv)
{
	int i;
	int j;
	int rc;
	enum cxi_ac_type type;
	unsigned int ac_entry_id;
	struct cxi_svc_desc *svc_desc = &svc_priv->svc_desc;

	if (!svc_desc->restricted_members) {
		for (j = 0; j < svc_priv->svc_desc.num_vld_vnis; j++) {
			rc = cxi_rx_profile_add_ac_entry(svc_priv->rx_profile[j],
							 CXI_AC_OPEN, 0, 0, 0,
							 &ac_entry_id);
			if (rc)
				goto cleanup;

			rc = cxi_tx_profile_add_ac_entry(svc_priv->tx_profile[j],
							 CXI_AC_OPEN, 0, 0, 0,
							 &ac_entry_id);
			if (rc)
				goto cleanup;
		}

		return 0;
	}

	for (j = 0; j < svc_priv->svc_desc.num_vld_vnis; j++) {
		for (i = 0; i < CXI_SVC_MAX_MEMBERS; i++) {
			type = svc_mbr_to_ac_type(svc_desc->members[i].type,
						  svc_desc->restricted_members);
			if (!type)
				continue;

			rc = cxi_rx_profile_add_ac_entry(
					svc_priv->rx_profile[j], type,
					svc_desc->members[i].svc_member.uid,
					svc_desc->members[i].svc_member.gid,
					0,
					&ac_entry_id);
			if (rc)
				goto cleanup;

			rc = cxi_tx_profile_add_ac_entry(
					svc_priv->tx_profile[j], type,
					svc_desc->members[i].svc_member.uid,
					svc_desc->members[i].svc_member.gid,
					0,
					&ac_entry_id);
			if (rc)
				goto cleanup;
		}
	}

	return 0;

cleanup:
	remove_profile_ac_entries(dev, svc_priv);

	return rc;
}

static void release_rxtx_profiles(struct cxi_dev *dev,
				  struct cxi_svc_priv *svc_priv)
{
	int i;

	/* Child services borrow the parent's profiles; never free them. */
	if (svc_priv->parent)
		return;

	remove_profile_ac_entries(dev, svc_priv);

	for (i = 0; i < svc_priv->svc_desc.num_vld_vnis; i++) {
		cxi_rx_profile_dec_refcount(dev, svc_priv->rx_profile[i]);
		cxi_tx_profile_dec_refcount(dev, svc_priv->tx_profile[i],
					    true);
	}
}

/* Update the Netns in RX/TX profile */
static int update_profile_netns_entries(struct cxi_dev *dev,
					struct cxi_svc_priv *svc_priv, unsigned int netns)
{
	int j;
	int rc = 0;
	union cxi_ac_data data = {};
	unsigned int ac_entry_id;

	for (j = 0; j < svc_priv->svc_desc.num_vld_vnis; j++) {
		if (!svc_priv->rx_profile[j] || !svc_priv->tx_profile[j])
			return -ENODATA;

		data.netns = netns;
		rc = cxi_rxtx_profile_add_ac_entry(&svc_priv->rx_profile[j]->profile_common,
						   CXI_AC_NETNS, &data, &ac_entry_id);
		if (rc)
			goto cleanup;

		rc = cxi_rxtx_profile_add_ac_entry(&svc_priv->tx_profile[j]->profile_common,
						   CXI_AC_NETNS, &data, &ac_entry_id);
		if (rc)
			goto cleanup;
	}

	return 0;

cleanup:
	remove_profile_ac_entries(dev, svc_priv);
	return rc;
}

/* Setup up to 4 RX/TX Profiles if restricted_vnis = 1
 * Otherwise set up a single RX/TX profile for a requested VNI range
 */
static int alloc_rxtx_profiles(struct cxi_dev *dev,
			       struct cxi_svc_priv *svc_priv,
			       const struct cxi_rxtx_vni_attr *vni_range_attr)
{
	int i;
	int rc;
	const struct cxi_rxtx_vni_attr *vni_attr;
	struct cxi_svc_desc *svc_desc = &svc_priv->svc_desc;

	if (!svc_desc->restricted_vnis) {
		if (!vni_range_attr) {
			cxidev_err(dev, "vni_range_attr NULL for vni_range\n");
			return -EINVAL;
		}
		svc_priv->svc_desc.num_vld_vnis = 1;
	}

	for (i = 0; i < svc_priv->svc_desc.num_vld_vnis; i++) {
		struct cxi_tx_attr tx_attr = {};
		struct cxi_rx_attr rx_attr = {};
		struct cxi_rxtx_vni_attr restricted_vni_attr = {
			.ignore = 0,
			.match = svc_desc->vnis[i],
			.name = "",
		};

		vni_attr = &restricted_vni_attr;
		if (!svc_desc->restricted_vnis)
			vni_attr = vni_range_attr;

		tx_attr.vni_attr = *vni_attr;
		rx_attr.vni_attr = *vni_attr;

		svc_priv->tx_profile[i] = cxi_dev_alloc_tx_profile(dev,
								   &tx_attr);
		if (IS_ERR(svc_priv->tx_profile[i])) {
			rc = PTR_ERR(svc_priv->tx_profile[i]);
			svc_priv->tx_profile[i] = NULL;
			goto release_profiles;
		}

		svc_priv->rx_profile[i] = cxi_dev_alloc_rx_profile(dev,
								   &rx_attr);
		if (IS_ERR(svc_priv->rx_profile[i])) {
			rc = PTR_ERR(svc_priv->rx_profile[i]);
			svc_priv->rx_profile[i] = NULL;
			goto release_profiles;
		}
	}

	rc = alloc_profile_ac_entries(dev, svc_priv);
	if (rc)
		goto release_profiles;

	set_tcs(dev, svc_priv);

	return 0;

release_profiles:
	release_rxtx_profiles(dev, svc_priv);
	return rc;
}

static int svc_enable(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv,
		      bool enable)
	__must_hold(&hw->svc_lock)
{
	int i;
	int rc = 0;

	if (enable) {
		cxi_rgroup_enable(svc_priv->rgroup);
		svc_priv->svc_desc.enable = 1;

		/* Child services borrow the parent's profiles which are already
		 * enabled; skip profile enable/disable to avoid double-toggling.
		 */
		if (!svc_priv->parent) {
			for (i = 0; i < svc_priv->svc_desc.num_vld_vnis; i++) {
				rc = cxi_tx_profile_enable(dev,
							   svc_priv->tx_profile[i]);
				if (rc)
					goto disable;

				rc = cxi_rx_profile_enable(dev,
							   svc_priv->rx_profile[i]);
				if (rc)
					goto disable;
			}
		}

		return 0;
	}

disable:
	cxi_rgroup_disable(svc_priv->rgroup);
	svc_priv->svc_desc.enable = 0;

	if (!svc_priv->parent) {
		for (i = 0; i < svc_priv->svc_desc.num_vld_vnis; i++) {
			cxi_tx_profile_disable(dev, svc_priv->tx_profile[i]);
			cxi_rx_profile_disable(dev, svc_priv->rx_profile[i]);
		}
	}

	return rc;
}

/**
 * cxi_svc_alloc_internal() - Allocate a service
 *
 * @dev: Cassini Device
 * @svc_desc: A service descriptor that contains requests for various resources,
 *            and optionally identifies member processes, tcs, vnis, etc. see
 *            cxi_svc_desc.
 * @fail_info: extra information when a failure occurs
 * @name: name for service
 * @is_vf: whether the service is being allocated for a VF
 * @vf_num: VF number if is_vf is true
 *
 * Return: Service ID on success. Else, negative errno value.
 */
int cxi_svc_alloc_internal(struct cxi_dev *dev,
			   const struct cxi_svc_desc *svc_desc,
			   struct cxi_svc_fail_info *fail_info,
			   char *name, bool is_vf, u8 vf_num)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rc;
	struct cxi_rgroup *rgroup;
	struct cxi_rgroup_attr attr = {
		.cntr_pool_id = svc_desc->cntr_pool_id,
		.system_service = svc_desc->is_system_svc,
		.lnis_per_rgid = default_lnis_per_rgid,
	};
	int i;

	rc = validate_descriptor(hw, svc_desc);
	if (rc)
		return rc;

	svc_priv = kzalloc(sizeof(*svc_priv), GFP_KERNEL);
	if (!svc_priv)
		return -ENOMEM;
	svc_priv->svc_desc = *svc_desc;
	svc_priv->is_vf  = is_vf;
	svc_priv->vf_num = vf_num;

	rgroup = cxi_dev_alloc_rgroup(dev, &attr);
	if (IS_ERR(rgroup)) {
		rc = PTR_ERR(rgroup);
		goto free_svc;
	}

	svc_priv->rgroup = rgroup;
	svc_priv->svc_desc.svc_id = cxi_rgroup_id(rgroup);

	rc = idr_alloc(&hw->svc_ids, svc_priv, cxi_rgroup_id(rgroup),
		       cxi_rgroup_id(rgroup) + 1,
		       GFP_NOWAIT);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "%s Service idr could not be obtained for rgroup ID %d rc:%d\n",
			   hw->cdev.name, cxi_rgroup_id(rgroup), rc);
		goto release_rgroup;
	}

	cxi_rgroup_set_name(rgroup, name);

	if (svc_desc->is_system_svc)
		cxi_rgroup_set_lnis_per_rgid(svc_priv->rgroup, 1);

	rc = alloc_rgroup_ac_entries(dev, svc_priv);
	if (rc)
		goto remove_idr;

	/* If restricted_vnis is set setup profiles now. Otherwise they will
	 * be set up later when a vni range is requested.
	 * VF child services borrow the parent's profiles instead of
	 * allocating their own (parent profiles already cover these VNIs).
	 */
	if (svc_desc->restricted_vnis && !is_vf) {
		rc = alloc_rxtx_profiles(dev, svc_priv, NULL);
		if (rc)
			goto remove_rgrp_ac_entries;
	}

	mutex_lock(&hw->svc_lock);

	if (is_vf) {
		svc_priv->parent = find_parent_for_vf(hw, vf_num);
		if (!svc_priv->parent) {
			rc = -EPERM;
			goto unlock;
		}

		/* VNIs requested by VF must be a subset of parent's VNIs */
		if (svc_desc->restricted_vnis) {
			rc = validate_child_vnis(dev, svc_priv->parent, svc_desc);
			if (rc)
				goto unlock;

			/* Borrow parent's existing profiles for the matching VNIs.
			 * The parent's profiles are already in the global list and
			 * cover these VNIs; no new allocation is needed.
			 *
			 * When the parent uses a VNI range (restricted_vnis=0),
			 * its single range profile covers all VNIs in the range;
			 * borrow it for every child VNI.
			 */
			if (!svc_priv->parent->svc_desc.restricted_vnis) {
				for (i = 0; i < svc_desc->num_vld_vnis; i++) {
					svc_priv->tx_profile[i] = svc_priv->parent->tx_profile[0];
					svc_priv->rx_profile[i] = svc_priv->parent->rx_profile[0];
				}
			} else {
				struct cxi_svc_priv *par = svc_priv->parent;

				for (i = 0; i < svc_desc->num_vld_vnis; i++) {
					int pi;

					for (pi = 0; pi < par->svc_desc.num_vld_vnis; pi++) {
						if (par->svc_desc.vnis[pi] != svc_desc->vnis[i])
							continue;
						svc_priv->tx_profile[i] = par->tx_profile[pi];
						svc_priv->rx_profile[i] = par->rx_profile[pi];
						break;
					}
				}
			}
		}
	}

	rc = reserve_rsrcs(hw, svc_priv, fail_info);
	if (rc)
		goto unlock;

	/* Track child reservation in parent after resources are committed. */
	if (svc_priv->parent) {
		int pe;
		struct cxi_rgroup *parent_rgroup = svc_priv->parent->rgroup;

		for (i = 0; i < CXI_RSRC_TYPE_MAX; i++)
			svc_priv->parent->child_reserved[i] +=
				svc_desc->limits.type[i].res;

		/* Inherit hardware LE/TLE pool IDs from the parent so this
		 * child service uses the same hardware pools as the parent
		 * rather than the default shared pools.
		 */
		for (pe = 0; pe < C_PE_COUNT; pe++)
			rgroup->pools.le_pool_id[pe] =
				parent_rgroup->pools.le_pool_id[pe];
		rgroup->pools.tle_pool_id = parent_rgroup->pools.tle_pool_id;
	}

	/* SVC is enabled by default for backwards compatibility.
	 * If disable_default_svc is true, the default service
	 * will be disabled.
	 * Setting restricted_vnis = 0 now indicates that a
	 * VNI range will be set up after the service is enabled.
	 * Do not enable the svc/rgroup/profiles until then.
	 */
	if (((cxi_rgroup_id(rgroup) == CXI_DEFAULT_SVC_ID) &&
	     disable_default_svc) ||
	    !svc_desc->restricted_vnis) {
		svc_priv->svc_desc.enable = 0;
	} else {
		rc = svc_enable(dev, svc_priv, true);
		if (rc)
			goto free_resources;
	}

	list_add_tail(&svc_priv->list, &hw->svc_list);
	hw->svc_count++;
	mutex_unlock(&hw->svc_lock);
	refcount_inc(&hw->refcount);

	if (is_vf)
		cxidev_info(&hw->cdev, "VF %u created service %u (parent svc %u)\n",
			    vf_num, cxi_rgroup_id(rgroup),
			    svc_priv->parent ? svc_priv->parent->svc_desc.svc_id : 0);

	return cxi_rgroup_id(rgroup);

free_resources:
	if (svc_priv->parent) {
		for (i = 0; i < CXI_RSRC_TYPE_MAX; i++)
			svc_priv->parent->child_reserved[i] -=
				svc_desc->limits.type[i].res;
	}
	free_rsrcs(svc_priv);
unlock:
	mutex_unlock(&hw->svc_lock);
	if (svc_desc->restricted_vnis)
		release_rxtx_profiles(dev, svc_priv);
remove_rgrp_ac_entries:
	cxi_ac_entry_list_destroy(&svc_priv->rgroup->ac_entry_list);
remove_idr:
	idr_remove(&hw->svc_ids, cxi_rgroup_id(rgroup));
release_rgroup:
	cxi_rgroup_dec_refcount(rgroup);
	return rc;
free_svc:
	kfree(svc_priv);

	return rc;
}
EXPORT_SYMBOL(cxi_svc_alloc_internal);

static int cxi_svc_alloc_vf(struct cxi_dev *dev,
			    const struct cxi_svc_desc *svc_desc,
			    struct cxi_svc_fail_info *fail_info,
			    char *name)
{
	struct cxi_svc_alloc_cmd_vf cmd = {
		.base.op       = CXI_OP_SVC_ALLOC,
		.base.svc_desc = *svc_desc,
	};
	struct cxi_svc_alloc_resp resp = {};
	size_t resp_len = sizeof(resp);
	int rc;

	if (name)
		strscpy(cmd.name, name, sizeof(cmd.name));

	rc = cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc < 0) {
		if (fail_info)
			*fail_info = resp.fail_info;
		return rc;
	}
	return resp.svc_id;
}

int cxi_svc_alloc(struct cxi_dev *dev, const struct cxi_svc_desc *svc_desc,
		  struct cxi_svc_fail_info *fail_info, char *name)
{
	if (!dev->is_physfn)
		return cxi_svc_alloc_vf(dev, svc_desc, fail_info, name);

	return cxi_svc_alloc_internal(dev, svc_desc, fail_info, name, false, 0);
}
EXPORT_SYMBOL(cxi_svc_alloc);

static void svc_destroy(struct cass_dev *hw, struct cxi_svc_priv *svc_priv)
{
	int i;
	int rc;
	int svc_id = cxi_rgroup_id(svc_priv->rgroup);

	/* Restore parent's child_reserved[] before tearing down resources.
	 * The rgroup's parent_entry[] restoration happens automatically inside
	 * cass_rgroup_remove_resource() under rgrp_lock when is_child is set.
	 */
	if (svc_priv->parent) {
		for (i = 0; i < CXI_RSRC_TYPE_MAX; i++)
			svc_priv->parent->child_reserved[i] -=
				svc_priv->svc_desc.limits.type[i].res;
	}

	free_rsrcs(svc_priv);

	release_rxtx_profiles(&hw->cdev, svc_priv);

	rc = cxi_rgroup_dec_refcount(svc_priv->rgroup);
	if (rc)
		pr_err("cxi_dev_release_rgroup_by_id failed %d\n", rc);

	idr_remove(&hw->svc_ids, svc_id);
	list_del(&svc_priv->list);
	hw->svc_count--;

	refcount_dec(&hw->refcount);
	kfree(svc_priv);
}

/**
 * cxi_svc_destroy_vf() - Destroy a service on a VF
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to be destroyed.
 *
 * Return: 0 on success. Else a negative errno value.
 */
static int cxi_svc_destroy_vf(struct cxi_dev *dev, u32 svc_id)
{
	const struct cxi_svc_destroy_cmd cmd = {
		.op     = CXI_OP_SVC_DESTROY,
		.svc_id = svc_id,
	};
	size_t resp_len = 0;

	return cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), NULL, &resp_len);
}

/**
 * cxi_svc_destroy() - Destroy a service
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to be destroyed.
 *
 * Return: 0 on success. Else a negative errno value.
 */
int cxi_svc_destroy(struct cxi_dev *dev, u32 svc_id)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int i;

	if (!dev->is_physfn)
		return cxi_svc_destroy_vf(dev, svc_id);

	/* Don't destroy default svc */
	if (svc_id == CXI_DEFAULT_SVC_ID)
		return -EINVAL;

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Don't delete if an LNI is still using this SVC */
	if (cxi_rgroup_refcount(svc_priv->rgroup) > 1) {
		mutex_unlock(&hw->svc_lock);
		return -EBUSY;
	}

	/* Don't delete a service that is still assigned to a VF.
	 * The admin must disable SR-IOV and clear each VF's svc_id
	 * (echo 0 > /sys/class/cxi/cxiN/vf/<n>/svc_id) first.
	 */
	for (i = 0; i < C_NUM_VFS; i++) {
		if (hw->vf_cfg[i].svc_id == svc_id) {
			mutex_unlock(&hw->svc_lock);
			return -EBUSY;
		}
	}

	svc_destroy(hw, svc_priv);

	mutex_unlock(&hw->svc_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_destroy);

/**
 * cxi_vf_set_svc_id() - Assign a parent service to a VF
 * @hw:     Cassini device (PF)
 * @vf_num: VF index (0-based, must be < C_NUM_VFS)
 * @svc_id: Service ID of the parent service; 0 clears the assignment,
 *          preventing the VF from allocating any services
 *
 * Sets the parent service for @vf_num.  This service acts as the resource
 * budget ceiling for any nested services the VF creates via cxi_svc_alloc().
 *
 * Return: 0 on success, -EINVAL if vf_num is out of range or svc_id does not
 *         exist, -EBUSY if the VF still has live child services
 */
int cxi_vf_set_svc_id(struct cass_dev *hw, unsigned int vf_num, int svc_id)
{
	struct cxi_svc_priv *svc_priv;
	int rc = 0;

	if (vf_num >= C_NUM_VFS)
		return -EINVAL;

	mutex_lock(&hw->svc_lock);

	/* svc_id == 0 clears the assignment (always succeeds);
	 * any other value must refer to an existing service.
	 */
	if (svc_id && !idr_find(&hw->svc_ids, svc_id)) {
		rc = -EINVAL;
		goto unlock;
	}

	/* Refuse if this specific VF has any live child services */
	list_for_each_entry(svc_priv, &hw->svc_list, list) {
		if (svc_priv->is_vf && svc_priv->vf_num == vf_num) {
			rc = -EBUSY;
			goto unlock;
		}
	}

	hw->vf_cfg[vf_num].svc_id = svc_id;
unlock:
	mutex_unlock(&hw->svc_lock);
	return rc;
}
EXPORT_SYMBOL(cxi_vf_set_svc_id);

static int cxi_svc_rsrc_list_get_vf(struct cxi_dev *dev, int count,
				    struct cxi_rsrc_use *rsrc_list)
{
	const struct cxi_svc_rsrc_list_get_cmd cmd = {
		.op = CXI_OP_SVC_RSRC_LIST_GET,
		.count = count,
	};
	struct cxi_svc_rsrc_list_get_resp_vf *resp;
	size_t resp_len = sizeof(struct cxi_svc_rsrc_list_get_resp_vf) +
			  count * sizeof(struct cxi_rsrc_use);
	int rc;

	resp = kzalloc(resp_len, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	rc = cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), resp, &resp_len);
	if (rc)
		goto free_buf;

	if (count >= resp->base.count)
		memcpy(rsrc_list, resp->rsrc_list,
		       resp->base.count * sizeof(struct cxi_rsrc_use));
	rc = resp->base.count;
free_buf:
	kfree(resp);
	return rc;
}

/**
 * cxi_svc_rsrc_list_get_internal - Get per-service resource usage.
 *
 * @dev: Cassini Device
 * @count: number of cxi_rsrc_use slots in @rsrc_list (0 to query count)
 * @rsrc_list: destination buffer
 * @vf_en: if true, return only services owned by @vf_num
 * @vf_num: VF number to filter on when @vf_en is true
 *
 * Return: number of service descriptors, or negative errno.
 */
int cxi_svc_rsrc_list_get_internal(struct cxi_dev *dev, int count,
				   struct cxi_rsrc_use *rsrc_list, bool vf_en, u8 vf_num)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	unsigned int rgroup_count;
	unsigned long index;
	struct cxi_rgroup *rgroup;
	int n = 0;

	if (vf_en) {
		mutex_lock(&hw->svc_lock);
		list_for_each_entry(svc_priv, &hw->svc_list, list) {
			if (!svc_priv->is_vf || svc_priv->vf_num != vf_num)
				continue;
			if (rsrc_list && n < count) {
				copy_rsrc_use(dev, &rsrc_list[n], svc_priv->rgroup);
				rsrc_list[n].svc_id = svc_priv->svc_desc.svc_id;
			}
			n++;
		}
		mutex_unlock(&hw->svc_lock);
		return n;
	}

	mutex_lock(&hw->svc_lock);
	cxi_dev_lock_rgroup_list(hw);

	rgroup_count = cxi_dev_get_rgroup_count(dev);
	if (count < rgroup_count) {
		cxi_dev_unlock_rgroup_list(hw);
		mutex_unlock(&hw->svc_lock);
		return rgroup_count;
	}

	for_each_rgroup(index, rgroup) {
		if (n >= rgroup_count) {
			pr_debug("Found more rgroups than expected: %u\n",
				 rgroup_count);
			break;
		}
		copy_rsrc_use(dev, &rsrc_list[n], rgroup);
		rsrc_list[n].svc_id = rgroup->id;
		n++;
	}

	cxi_dev_unlock_rgroup_list(hw);
	mutex_unlock(&hw->svc_lock);
	return n;
}
EXPORT_SYMBOL(cxi_svc_rsrc_list_get_internal);

/*
 * cxi_svc_rsrc_list_get - Get per service information on resource usage.
 *
 * @dev: Cassini Device
 * @count: number of services descriptors for which space
 *         has been allocated. 0 initially, to determine count.
 * @rsrc_list: destination to land service descriptors
 *
 * Return: number of service descriptors
 * If the specified count is equal to (or greater than) the number of
 * active service descriptors, they are copied to the provided user
 * buffer.
 */
int cxi_svc_rsrc_list_get(struct cxi_dev *dev, int count,
			  struct cxi_rsrc_use *rsrc_list)
{
	if (!dev->is_physfn)
		return cxi_svc_rsrc_list_get_vf(dev, count, rsrc_list);

	return cxi_svc_rsrc_list_get_internal(dev, count, rsrc_list, false, 0);
}
EXPORT_SYMBOL(cxi_svc_rsrc_list_get);

static int cxi_svc_rsrc_get_vf(struct cxi_dev *dev, unsigned int svc_id,
			       struct cxi_rsrc_use *rsrc_use)
{
	const struct cxi_svc_rsrc_get_cmd cmd = {
		.op = CXI_OP_SVC_RSRC_GET,
		.svc_id = svc_id,
	};
	struct cxi_svc_rsrc_get_resp resp = {};
	size_t resp_len = sizeof(resp);
	int rc;

	rc = cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc)
		return rc;

	*rsrc_use = resp.rsrcs;

	return 0;
}

/*
 * cxi_svc_rsrc_get - Get rsrc_use from svc_id
 *
 * @dev: Cassini Device
 * @svc_id: svc_id of the descriptor to find which is equivalent to the
 *          rgroup ID.
 * @rsrc_use: destination to land resource usage
 *
 * Return: 0 on success or a negative errno
 */
int cxi_svc_rsrc_get(struct cxi_dev *dev, unsigned int svc_id,
		     struct cxi_rsrc_use *rsrc_use)
{
	int rc;
	struct cxi_rgroup *rgroup;

	if (!dev->is_physfn)
		return cxi_svc_rsrc_get_vf(dev, svc_id, rsrc_use);

	rc = cxi_dev_find_rgroup_inc_refcount(dev, svc_id, &rgroup);
	if (rc)
		return -EINVAL;

	copy_rsrc_use(dev, rsrc_use, rgroup);
	cxi_rgroup_dec_refcount(rgroup);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_rsrc_get);

static enum cxi_svc_member_type ac_type_to_svc_mbr(enum cxi_ac_type type)
{
	switch (type) {
	case CXI_AC_UID:
		return CXI_SVC_MEMBER_UID;
	case CXI_AC_GID:
		return CXI_SVC_MEMBER_GID;
	default:
		return CXI_SVC_MEMBER_IGNORE;
	}
}

static void add_rgroup_ac_entry_to_svc(struct cxi_svc_desc *desc,
				       struct cxi_rgroup *rgroup)
{
	int i;
	int rc;
	size_t num_ids;
	size_t max_ids;
	unsigned int *ac_entry_ids = NULL;
	enum cxi_ac_type ac_type;
	union cxi_ac_data ac_data;

	desc->restricted_members = false;

	rc = cxi_rgroup_get_ac_entry_ids(rgroup, 0, ac_entry_ids, &num_ids);
	if (rc && rc != -ENOSPC)
		return;

	if (!num_ids)
		return;

	ac_entry_ids = kmalloc_array(num_ids, sizeof(*ac_entry_ids),
				     GFP_ATOMIC);
	if (!ac_entry_ids)
		return;

	rc = cxi_rgroup_get_ac_entry_ids(rgroup, num_ids, ac_entry_ids,
					 &max_ids);
	if (rc)
		goto freemem;

	for (i = 0; i < num_ids; i++) {
		rc = cxi_rgroup_get_ac_entry_data(rgroup, ac_entry_ids[i],
						  &ac_type, &ac_data);
		if (rc || ac_type == CXI_AC_OPEN)
			goto freemem;
	}

	desc->restricted_members = true;
	for (i = 0; i < num_ids && i < CXI_SVC_MAX_MEMBERS; i++) {
		rc = cxi_rgroup_get_ac_entry_data(rgroup, ac_entry_ids[i],
						  &ac_type, &ac_data);
		if (rc)
			continue;

		desc->members[i].type = ac_type_to_svc_mbr(ac_type);
		desc->members[i].svc_member.uid = ac_data.uid;
	}

freemem:
	kfree(ac_entry_ids);
}

static int cxi_svc_list_get_vf(struct cxi_dev *dev, int count,
			       struct cxi_svc_desc *svc_list)
{
	const struct cxi_svc_list_get_cmd cmd = {
		.op = CXI_OP_SVC_LIST_GET,
		.count = count,
	};
	struct cxi_svc_list_get_resp_vf *resp;
	size_t resp_len = sizeof(struct cxi_svc_list_get_resp_vf) +
			  count * sizeof(struct cxi_svc_desc);
	int rc;

	resp = kzalloc(resp_len, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	rc = cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), resp, &resp_len);
	if (rc)
		goto free_buf;

	if (count >= resp->base.count)
		memcpy(svc_list, resp->svc_list,
		       resp->base.count * sizeof(struct cxi_svc_desc));

	rc = resp->base.count;
free_buf:
	kfree(resp);
	return rc;
}

/**
 * cxi_svc_list_get_internal - Assemble list of active service descriptors.
 *
 * @dev: Cassini Device
 * @count: number of cxi_svc_desc slots in @svc_list (0 to query count)
 * @svc_list: destination buffer
 * @vf_en: if true, return only services owned by @vf_num
 * @vf_num: VF number to filter on when @vf_en is true
 *
 * Return: number of service descriptors, or negative errno.
 */
int cxi_svc_list_get_internal(struct cxi_dev *dev, int count,
			      struct cxi_svc_desc *svc_list, bool vf_en, u8 vf_num)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int ret;
	enum cxi_resource_type rt;
	enum cxi_rsrc_type svc_rt;
	unsigned int rgroup_count;
	struct cxi_svc_desc rgroup_svc_desc;
	unsigned long index;
	struct cxi_rgroup *rgroup;
	struct cxi_resource_entry *entry;
	int n = 0;

	if (vf_en) {
		mutex_lock(&hw->svc_lock);
		list_for_each_entry(svc_priv, &hw->svc_list, list) {
			if (!svc_priv->is_vf || svc_priv->vf_num != vf_num)
				continue;
			if (svc_list && n < count)
				svc_list[n] = svc_priv->svc_desc;
			n++;
		}
		mutex_unlock(&hw->svc_lock);
		return n;
	}

	mutex_lock(&hw->svc_lock);
	cxi_dev_lock_rgroup_list(hw);

	rgroup_count = cxi_dev_get_rgroup_count(dev);
	if (count < rgroup_count) {
		cxi_dev_unlock_rgroup_list(hw);
		mutex_unlock(&hw->svc_lock);
		return rgroup_count;
	}

	for_each_rgroup(index, rgroup) {
		svc_priv = idr_find(&hw->svc_ids, cxi_rgroup_id(rgroup));
		if (svc_priv) {
			svc_list[n++] = svc_priv->svc_desc;
			continue;
		}

		memset(&rgroup_svc_desc, 0, sizeof(rgroup_svc_desc));
		rgroup_svc_desc.svc_id = rgroup->id;
		rgroup_svc_desc.enable = rgroup->state.enabled;
		rgroup_svc_desc.resource_limits = true;
		rgroup_svc_desc.is_system_svc =
					cxi_rgroup_system_service(rgroup);
		add_rgroup_ac_entry_to_svc(&rgroup_svc_desc, rgroup);

		for (rt = 1, svc_rt = 0; rt < CXI_RESOURCE_MAX; rt++) {
			ret = cxi_rgroup_get_resource_entry(rgroup, rt,
							    &entry);
			if (!ret) {
				if (svc_rt == CXI_RSRC_TYPE_MAX)
					break;

				if (rt == CXI_RESOURCE_PE1_LE ||
				    rt == CXI_RESOURCE_PE2_LE ||
				    rt == CXI_RESOURCE_PE3_LE)
					continue;

				rgroup_svc_desc.limits.type[svc_rt].max =
							entry->limits.max;
				rgroup_svc_desc.limits.type[svc_rt].res =
							entry->limits.reserved;
			}
			svc_rt++;
		}
		svc_list[n++] = rgroup_svc_desc;
	}

	cxi_dev_unlock_rgroup_list(hw);
	mutex_unlock(&hw->svc_lock);
	return n;
}
EXPORT_SYMBOL(cxi_svc_list_get_internal);

/*
 * cxi_svc_list_get - Assemble list of active services descriptors
 *
 * @dev: Cassini Device
 * @count: number of services descriptors for which space
 *         has been allocated. 0 initially, to determine count.
 * @svc_list: destination to land service descriptors
 *
 * Return: number of service descriptors
 * If the specified count is equal to (or greater than) the number of
 * active service descriptors, they are copied to the provided user
 * buffer.
 */
int cxi_svc_list_get(struct cxi_dev *dev, int count,
		     struct cxi_svc_desc *svc_list)
{
	if (!dev->is_physfn)
		return cxi_svc_list_get_vf(dev, count, svc_list);

	return cxi_svc_list_get_internal(dev, count, svc_list, false, 0);
}
EXPORT_SYMBOL(cxi_svc_list_get);

/* cxi_svc_get_vf - Get svc_desc from svc_id for a VF
 *
 * @dev: Cassini Device
 * @svc_id: svc_id of the descriptor to find which is equivalent to the
 *          rgroup ID.
 * @svc_desc: destination to land service descriptor
 *
 * Return: 0 on success or a negative errno
 */
static int cxi_svc_get_vf(struct cxi_dev *dev, unsigned int svc_id,
			  struct cxi_svc_desc *svc_desc)
{
	const struct cxi_svc_get_cmd cmd = {
		.op = CXI_OP_SVC_GET,
		.svc_id = svc_id,
	};
	struct cxi_svc_get_resp resp;
	size_t resp_len = sizeof(resp);
	int rc;

	rc = cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc)
		return rc;

	*svc_desc = resp.svc_desc;

	return 0;
}

/*
 * cxi_svc_get_internal - Get svc_desc from svc_id with optional VF ownership
 * check.  When vf_en is true the service is only returned if it was allocated
 * on behalf of vf_num; any other service ID causes -EINVAL.
 *
 * @dev: Cassini Device (must be a PF)
 * @svc_id: svc_id to look up
 * @svc_desc: destination for the descriptor
 * @vf_en: when true, enforce VF ownership
 * @vf_num: VF number filter (only meaningful when vf_en is true)
 *
 * Return: 0 on success, -EINVAL if not found or not owned by the VF.
 */
int cxi_svc_get_internal(struct cxi_dev *dev, unsigned int svc_id,
			 struct cxi_svc_desc *svc_desc, bool vf_en, u8 vf_num)
{
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	*svc_desc = svc_priv->svc_desc;
	mutex_unlock(&hw->svc_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_get_internal);

/*
 * cxi_svc_get - Get svc_desc from svc_id
 *
 * @dev: Cassini Device
 * @svc_id: svc_id of the descriptor to find which is equivalent to the
 *          rgroup ID.
 * @svc_desc: destination to land service descriptor
 *
 * Return: 0 on success or a negative errno
 */
int cxi_svc_get(struct cxi_dev *dev, unsigned int svc_id,
		struct cxi_svc_desc *svc_desc)
{
	if (!dev->is_physfn)
		return cxi_svc_get_vf(dev, svc_id, svc_desc);

	return cxi_svc_get_internal(dev, svc_id, svc_desc, false, 0);
}
EXPORT_SYMBOL(cxi_svc_get);

void cxi_free_resource(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv,
		      enum cxi_rsrc_type type)
{
	return cxi_rgroup_free_resource(svc_priv->rgroup,
					stype_to_rtype(type, 0));
}

/* used to allocate ACs, etc. */
int cxi_alloc_resource(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv,
		       enum cxi_rsrc_type type)
{
	return cxi_rgroup_alloc_resource(svc_priv->rgroup,
					 stype_to_rtype(type, 0));
}

/**
 * cxi_svc_enable_vf() - Enable or Disable a service on a VF
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of the service to be enabled.
 * @enable: Boolean value indicating whether to enable or disable the service.
 *
 * Return: 0 on success or negative errno value.
 */
static int cxi_svc_enable_vf(struct cxi_dev *dev, unsigned int svc_id,
			     bool enable)
{
	const struct cxi_svc_enable_cmd cmd = {
		.op     = CXI_OP_SVC_ENABLE,
		.svc_id = svc_id,
		.enable = enable,
	};
	size_t resp_len = 0;

	return cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), NULL, &resp_len);
}

/**
 * cxi_svc_enable() - Enable or Disable a service.
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of the service to be enabled.
 * @enable: Boolean value indicating whether to enable or disable the service.
 *
 * Return: 0 on success or negative errno value.
 */
int cxi_svc_enable(struct cxi_dev *dev, unsigned int svc_id, bool enable)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rc = 0;

	if (!dev->is_physfn)
		return cxi_svc_enable_vf(dev, svc_id, enable);

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		rc = -EINVAL;
		cxidev_err(dev, "Invalid service ID: %u\n", svc_id);
		goto unlock;
	}

	/* Service must be unused for it to be enabled/disabled. */
	if (refcount_read(&svc_priv->rgroup->state.refcount) > 1) {
		rc = -EBUSY;
		goto unlock;
	}

	rc = svc_enable(dev, svc_priv, enable);
unlock:
	mutex_unlock(&hw->svc_lock);
	return rc;
}
EXPORT_SYMBOL(cxi_svc_enable);

static int cxi_svc_update_vf(struct cxi_dev *dev, const struct cxi_svc_desc *svc_desc)
{
	const struct cxi_svc_update_cmd cmd = {
		.op       = CXI_OP_SVC_UPDATE,
		.svc_desc = *svc_desc,
	};
	struct cxi_svc_update_resp resp = {};
	size_t resp_len = sizeof(resp);

	return cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), &resp, &resp_len);
}

/**
 * cxi_svc_update() - Modify an existing service.
 *
 * @dev: Cassini Device
 * @svc_desc: A service descriptor that contains requests for various resources,
 *            and optionally identifies member processes, tcs, vnis, etc. see
 *            cxi_svc_desc.
 *
 * Currently does not honor changes to resource limits in a svc_desc.
 *
 * Return: 0 on success. Else, negative errno value.
 */
int cxi_svc_update(struct cxi_dev *dev, const struct cxi_svc_desc *svc_desc)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rc;

	if (!dev->is_physfn)
		return cxi_svc_update_vf(dev, svc_desc);

	rc = validate_descriptor(hw, svc_desc);
	if (rc)
		return rc;

	mutex_lock(&hw->svc_lock);

	/* Find priv descriptor */
	svc_priv = idr_find(&hw->svc_ids, svc_desc->svc_id);
	if (!svc_priv) {
		rc = -EINVAL;
		goto error;
	}

	/* Service must be unused for it to be updated. */
	if (refcount_read(&svc_priv->rgroup->state.refcount) > 1) {
		rc = -EBUSY;
		goto error;
	}

	/* TODO Handle Resource Reservation Changes */
	if (svc_priv->svc_desc.resource_limits != svc_desc->resource_limits) {
		rc = -EINVAL;
		goto error;
	}

	rc = svc_enable(dev, svc_priv, svc_desc->enable);
	if (rc)
		goto error;

	/* Update TCs, VNIs, Members */
	svc_priv->svc_desc.restricted_members = svc_desc->restricted_members;
	svc_priv->svc_desc.restricted_vnis = svc_desc->restricted_vnis;
	svc_priv->svc_desc.num_vld_vnis = svc_desc->num_vld_vnis;
	svc_priv->svc_desc.restricted_tcs = svc_desc->restricted_tcs;
	svc_priv->svc_desc.cntr_pool_id = svc_desc->cntr_pool_id;
	svc_priv->svc_desc.enable = svc_desc->enable;

	memcpy(svc_priv->svc_desc.tcs, svc_desc->tcs, sizeof(svc_desc->tcs));
	memcpy(svc_priv->svc_desc.vnis, svc_desc->vnis, sizeof(svc_desc->vnis));
	memcpy(svc_priv->svc_desc.members, svc_desc->members, sizeof(svc_desc->members));
	// TODO: update TX profile?
error:
	mutex_unlock(&hw->svc_lock);
	return rc;
}
EXPORT_SYMBOL(cxi_svc_update);

static int cxi_svc_set_lpr_vf(struct cxi_dev *dev, unsigned int svc_id,
			      unsigned int lnis_per_rgid)
{
	const struct cxi_svc_lpr_cmd cmd = {
		.op            = CXI_OP_SVC_SET_LPR,
		.svc_id        = svc_id,
		.lnis_per_rgid = lnis_per_rgid,
	};
	size_t resp_len = 0;

	return cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), NULL, &resp_len);
}

/**
 * cxi_svc_set_lpr() - Update an existing service to set the LNIs per RGID
 *
 * For backwards compatibility, check if service is in use instead of
 * checking if rgroup is enabled.
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to be updated.
 * @lnis_per_rgid: New value of lnis_per_rgid
 *
 * Return: 0 on success or negative errno value.
 */
int cxi_svc_set_lpr(struct cxi_dev *dev, unsigned int svc_id,
		    unsigned int lnis_per_rgid)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;

	if (!dev->is_physfn)
		return cxi_svc_set_lpr_vf(dev, svc_id, lnis_per_rgid);

	if (lnis_per_rgid > C_NUM_LACS)
		return -EINVAL;

	if (!enable_rgid_sharing) {
		cxidev_warn(dev, "RGID sharing is disabled\n");
		return 0;
	}

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Service must be unused for it to be updated. */
	if (cxi_rgroup_refcount(svc_priv->rgroup) > 1) {
		mutex_unlock(&hw->svc_lock);
		return -EBUSY;
	}

	cxi_rgroup_set_lnis_per_rgid_compat(svc_priv->rgroup, lnis_per_rgid);

	mutex_unlock(&hw->svc_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_set_lpr);

static int cxi_svc_get_lpr_vf(struct cxi_dev *dev, unsigned int svc_id)
{
	const struct cxi_svc_lpr_cmd cmd = {
		.op = CXI_OP_SVC_GET_LPR,
		.svc_id = svc_id,
	};
	struct cxi_svc_get_value_resp resp = {};
	size_t resp_len = sizeof(resp);
	int rc;

	rc = cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc)
		return rc;

	return resp.value;
}

/**
 * cxi_svc_get_lpr() - Get the LNIs per RGID of the indicated service
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to be updated.
 *
 * Return: lnis_per_rgid on success or negative errno value.
 */
int cxi_svc_get_lpr(struct cxi_dev *dev, unsigned int svc_id)
{
	struct cxi_rgroup *rgroup;
	int ret;

	if (!dev->is_physfn)
		return cxi_svc_get_lpr_vf(dev, svc_id);

	ret = cxi_dev_find_rgroup_inc_refcount(dev, svc_id, &rgroup);
	if (ret)
		return -EINVAL;

	ret = cxi_rgroup_lnis_per_rgid(rgroup);
	cxi_rgroup_dec_refcount(rgroup);

	return ret;
}
EXPORT_SYMBOL(cxi_svc_get_lpr);

static int cxi_svc_set_exclusive_cp_vf(struct cxi_dev *dev, unsigned int svc_id,
				       bool exclusive_cp)
{
	const struct cxi_svc_set_exclusive_cp_cmd cmd = {
		.op           = CXI_OP_SVC_SET_EXCLUSIVE_CP,
		.svc_id       = svc_id,
		.exclusive_cp = exclusive_cp,
	};
	size_t resp_len = 0;

	return cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), NULL, &resp_len);
}

/**
 * cxi_svc_set_exclusive_cp() - Set the exclusive_cp bit for a service
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to be updated.
 * @exclusive_cp: New value for exclusive_cp (true or false)
 *
 * Return: 0 on success or negative errno value.
 */
int cxi_svc_set_exclusive_cp(struct cxi_dev *dev, unsigned int svc_id,
			     bool exclusive_cp)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rc;

	if (!dev->is_physfn)
		return cxi_svc_set_exclusive_cp_vf(dev, svc_id, exclusive_cp);

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		rc = -EINVAL;
		goto unlock;
	}

	if (svc_priv->svc_desc.restricted_vnis) {
		cxidev_err(dev, "Exclusive CP not allowed with restricted VNIs\n");
		rc = -EINVAL;
		goto unlock;
	}

	/* One VNI Range will be allowed, tied to tx_profile 0.
	 * This call will fail if the svc/tx_profile is already enabled
	 */
	if (!svc_priv->tx_profile[0]) {
		cxidev_err(dev, "tx_profile[0] not initialized for svc_id: %d\n",
			   svc_id);
		rc = -EINVAL;
		goto unlock;
	}

	rc = cxi_tx_profile_set_exclusive_cp(svc_priv->tx_profile[0],
					     exclusive_cp);
	if (rc)
		cxidev_err(dev, "Failed to set exclusive CP for svc_id: %d rc:%d\n",
			   svc_id, rc);

unlock:
	mutex_unlock(&hw->svc_lock);
	return rc;
}
EXPORT_SYMBOL(cxi_svc_set_exclusive_cp);

static int cxi_svc_get_exclusive_cp_vf(struct cxi_dev *dev, unsigned int svc_id)
{
	const struct cxi_svc_get_exclusive_cp_cmd cmd = {
		.op = CXI_OP_SVC_GET_EXCLUSIVE_CP,
		.svc_id = svc_id,
	};
	struct cxi_svc_get_exclusive_cp_resp resp = {};
	size_t resp_len = sizeof(resp);
	int rc;

	rc = cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc)
		return rc;

	return resp.exclusive_cp ? 1 : 0;
}

/**
 * cxi_svc_get_exclusive_cp() - Get the exclusive_cp bit for a service
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to query.
 *
 * Return: 1 if exclusive_cp is set, 0 if not, or negative errno value.
 */
int cxi_svc_get_exclusive_cp(struct cxi_dev *dev, unsigned int svc_id)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rc;

	if (!dev->is_physfn)
		return cxi_svc_get_exclusive_cp_vf(dev, svc_id);

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		rc = -EINVAL;
		goto unlock;
	}

	if (!svc_priv->tx_profile[0]) {
		rc = -ENOENT;
		goto unlock;
	}

	/* Grab the first TX Profile and report its exclusive_cp value */
	rc = cxi_tx_profile_exclusive_cp(svc_priv->tx_profile[0]);
unlock:
	mutex_unlock(&hw->svc_lock);

	return rc;
}
EXPORT_SYMBOL(cxi_svc_get_exclusive_cp);

static int cxi_svc_set_vni_range_vf(struct cxi_dev *dev, unsigned int svc_id,
				    unsigned int vni_min, unsigned int vni_max)
{
	const struct cxi_svc_vni_range_cmd cmd = {
		.op     = CXI_OP_SVC_SET_VNI_RANGE,
		.svc_id = svc_id,
		.vni_min = vni_min,
		.vni_max = vni_max,
	};
	size_t resp_len = 0;

	return cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), NULL, &resp_len);
}

/**
 * cxi_svc_set_vni_range() - Add TX/RX profiles for a contiguous range of VNIs to a service
 *
 * The provided range must be exactly representable as a mask/match pair.
 * Requirements:
 *   - The number of values in the range must be a power of two (1, 2, 4, 8, 16, ...).
 *   - The first value in the range (vni_min) must be a multiple of the range size.
 *   - The svc must not have the restricted_vnis bit set.
 *
 * For example:
 *   64–127: 64 values, starting value (64) is a multiple of the
 *           range size (64), so the range is valid.
 *   32–95 : 64 values, starting value (32) is not a multiple of the
 *           range size (64), so the range is invalid.
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to be updated.
 * @vni_min: Minimum VNI value (inclusive)
 * @vni_max: Maximum VNI value (inclusive)
 *
 * Return: 0 on success, or negative errno value on failure.
 */
int cxi_svc_set_vni_range(struct cxi_dev *dev, unsigned int svc_id,
			  unsigned int vni_min, unsigned int vni_max)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	struct cxi_rxtx_vni_attr vni_attr = {
		.name = "",
	};
	unsigned int range;
	int rc = 0;

	if (!dev->is_physfn)
		return cxi_svc_set_vni_range_vf(dev, svc_id, vni_min, vni_max);

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		rc = -EINVAL;
		goto unlock_return;
	}

	/* VNI range is incompatible with distinct VNIs */
	if (svc_priv->svc_desc.restricted_vnis) {
		cxidev_err(dev, "Cannot specify distinct VNIs and a VNI range");
		rc = -EINVAL;
		goto unlock_return;
	}
	if (!is_vni_valid(vni_min)) {
		cxidev_err(dev, "vni_min %u invalid", vni_min);
		rc = -EINVAL;
		goto unlock_return;
	}
	if (!is_vni_valid(vni_max)) {
		cxidev_err(dev, "vni_max %u invalid", vni_max);
		rc = -EINVAL;
		goto unlock_return;
	}
	if (vni_max < vni_min) {
		cxidev_err(dev, "vni_max %u is less than vni_min %u",
			   vni_max, vni_min);
		rc = -EINVAL;
		goto unlock_return;
	}

	range = vni_max - vni_min + 1;

	if (!is_power_of_2(range)) {
		cxidev_err(dev, "VNI range [%u, %u] is not a power-of-two size",
			   vni_min, vni_max);
		rc = -EINVAL;
		goto unlock_return;
	}
	/* Validate the range is aligned */
	if (vni_min & (range - 1)) {
		cxidev_err(dev, "VNI range [%u, %u] is not aligned. min (%u) must be a multiple of range size (%u)",
			   vni_min, vni_max, vni_min, range);
		rc = -EINVAL;
		goto unlock_return;
	}

	vni_attr.match = vni_min;
	vni_attr.ignore = range - 1;

	/* For child services (VF-allocated) whose parent uses a VNI range,
	 * the requested range must be a subset of the parent's range.
	 *
	 * A hardware TX/RX profile covers a contiguous power-of-2 aligned
	 * range; the overlap check in cxi_dev_alloc_tx_profile() prevents
	 * two profiles whose ranges overlap from coexisting.  Since the
	 * parent already holds a profile for its range, allocating a new
	 * profile for any overlapping subset would fail with -EEXIST.  The
	 * child therefore borrows the parent's profile directly, which
	 * means the child's effective VNI scope is the parent's full range
	 * regardless of the requested subset.
	 */
	if (svc_priv->parent && !svc_priv->parent->svc_desc.restricted_vnis) {
		struct cxi_tx_attr parent_tx_attr;
		unsigned int parent_min, parent_max;

		if (!svc_priv->parent->tx_profile[0]) {
			cxidev_err(dev,
				   "svc_id %u: parent has no VNI range set yet",
				   svc_id);
			rc = -EPERM;
			goto unlock_return;
		}

		rc = cxi_tx_profile_get_info(dev, svc_priv->parent->tx_profile[0],
					     &parent_tx_attr, NULL);
		if (rc)
			goto unlock_return;

		parent_min = parent_tx_attr.vni_attr.match;
		parent_max = parent_tx_attr.vni_attr.match +
			     parent_tx_attr.vni_attr.ignore;

		if (vni_min < parent_min || vni_max > parent_max) {
			cxidev_err(dev,
				   "VNI range [%u, %u] is not a subset of parent range [%u, %u]",
				   vni_min, vni_max, parent_min, parent_max);
			rc = -EINVAL;
			goto unlock_return;
		}

		/* Range validated as a subset of the parent's range.  Borrow
		 * the parent's TX/RX profile rather than allocating a new one:
		 * the parent profile already covers the superset, and creating
		 * any overlapping profile would fail with -EEXIST.  Record the
		 * caller's requested subrange so cxi_svc_get_vni_range() can
		 * report it instead of the borrowed profile's wider range.
		 * release_rxtx_profiles() skips freeing borrowed profiles.
		 */
		svc_priv->svc_desc.num_vld_vnis = 1;
		svc_priv->tx_profile[0] = svc_priv->parent->tx_profile[0];
		svc_priv->rx_profile[0] = svc_priv->parent->rx_profile[0];
		svc_priv->has_vni_range  = true;
		svc_priv->vni_range_min  = vni_min;
		svc_priv->vni_range_max  = vni_max;
		goto unlock_return;
	}

	rc = alloc_rxtx_profiles(dev, svc_priv, &vni_attr);

unlock_return:
	mutex_unlock(&hw->svc_lock);
	return rc;
}
EXPORT_SYMBOL(cxi_svc_set_vni_range);

static int cxi_svc_get_vni_range_vf(struct cxi_dev *dev, unsigned int svc_id,
				    unsigned int *vni_min, unsigned int *vni_max)
{
	const struct cxi_svc_vni_range_cmd cmd = {
		.op = CXI_OP_SVC_GET_VNI_RANGE,
		.svc_id = svc_id,
	};
	struct cxi_svc_get_vni_range_resp resp = {};
	size_t resp_len = sizeof(resp);
	int rc;

	rc = cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc)
		return rc;

	*vni_min = resp.vni_min;
	*vni_max = resp.vni_max;

	return 0;
}

/**
 * cxi_svc_get_vni_range() - Get the VNI range associated with a service
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to query.
 * @vni_min: Pointer to store minimum VNI value (inclusive)
 * @vni_max: Pointer to store maximum VNI value (inclusive)
 *
 * Return: 0 on success, or negative errno value.
 */
int cxi_svc_get_vni_range(struct cxi_dev *dev, unsigned int svc_id,
			  unsigned int *vni_min, unsigned int *vni_max)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	struct cxi_tx_attr tx_attr;
	int rc = 0;
	struct cxi_rgroup *rgroup;

	if (!dev->is_physfn)
		return cxi_svc_get_vni_range_vf(dev, svc_id, vni_min, vni_max);

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		rc = cxi_dev_find_rgroup_inc_refcount(dev, svc_id, &rgroup);
		if (!rc) {
			/* We don't support getting a VNI range for rgroups */
			cxi_rgroup_dec_refcount(rgroup);
			cxidev_dbg(dev, "svc_id %u is a rgroup", svc_id);
			rc = -EOPNOTSUPP;
			goto unlock_return;
		}

		cxidev_err(dev, "svc_id %u not found", svc_id);
		rc = -EINVAL;
		goto unlock_return;
	}
	if (svc_priv->svc_desc.restricted_vnis) {
		cxidev_err(dev, "svc_id %u does not have a vni range", svc_id);
		rc = -EINVAL;
		goto unlock_return;
	}
	if (!svc_priv->svc_desc.num_vld_vnis) {
		cxidev_err(dev, "svc_id %u has no valid TX/RX profiles", svc_id);
		rc = -EINVAL;
		goto unlock_return;
	}

	if (!svc_priv->tx_profile[0]) {
		rc = -ENOENT;
		goto unlock_return;
	}

	/* For VNI-range child services the TX profile covers the parent's full
	 * range, but the caller configured a subset; return that stored range.
	 */
	if (svc_priv->has_vni_range) {
		*vni_min = svc_priv->vni_range_min;
		*vni_max = svc_priv->vni_range_max;
		goto unlock_return;
	}

	rc = cxi_tx_profile_get_info(dev, svc_priv->tx_profile[0], &tx_attr,
				     NULL);
	if (rc) {
		cxidev_err(dev, "Failed to get TX profile info for svc_id %u",
			   svc_id);
		goto unlock_return;
	}

	*vni_min = tx_attr.vni_attr.match;
	*vni_max = tx_attr.vni_attr.match + tx_attr.vni_attr.ignore;

unlock_return:
	mutex_unlock(&hw->svc_lock);
	return rc;
}
EXPORT_SYMBOL(cxi_svc_get_vni_range);

static int cxi_svc_set_netns_vf(struct cxi_dev *dev, unsigned int svc_id,
				unsigned int netns)
{
	const struct cxi_svc_set_netns_cmd cmd = {
		.op     = CXI_OP_SVC_SET_NETNS,
		.svc_id = svc_id,
		.netns  = netns,
	};
	size_t resp_len = 0;

	return cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), NULL, &resp_len);
}

/**
 * cxi_svc_set_netns() - Set netns Access control to existing service
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to be set.
 * @netns: The Namespace id
 * * Return:
 * * 0       - success
 * * -EEXIST - The service was originally created with a UID or GID,
 * *           so netns access control cannot be applied
 * * -EINVAL - The specified service does not exist
 */
int cxi_svc_set_netns(struct cxi_dev *dev, unsigned int svc_id, unsigned int netns)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	unsigned int ac_entry_id;
	union cxi_ac_data ac_data = {};
	struct cxi_ac_entry_list list = {};
	int rc;

	if (!dev->is_physfn)
		return cxi_svc_set_netns_vf(dev, svc_id, netns);

	mutex_lock(&hw->svc_lock);
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		rc = -EINVAL;
		goto unlock_return;
	}

	/* Make sure that the ac list is empty.	 */
	list = svc_priv->rgroup->ac_entry_list;
	if (!xa_empty(&list.uid.xarray) || !xa_empty(&list.gid.xarray) || list.open_entry) {
		cxidev_dbg(dev,
			   "Failed to add netns for svc_id: %u (netns is not supported with uid/gid/open)",
			   svc_id);
		rc = -EEXIST;
		goto unlock_return;
	}

	ac_data.netns = netns;

	rc = cxi_rgroup_update_ac_entry(svc_priv->rgroup, CXI_AC_NETNS, &ac_data,
					&ac_entry_id);
	if (rc)
		goto unlock_return;

	rc = update_profile_netns_entries(dev, svc_priv, netns);
	if (rc)
		goto unlock_return;
unlock_return:
	mutex_unlock(&hw->svc_lock);
	return rc;
}
EXPORT_SYMBOL(cxi_svc_set_netns);

static int cxi_svc_get_netns_vf(struct cxi_dev *dev, unsigned int svc_id,
				unsigned int *netns)
{
	const struct cxi_svc_get_netns_cmd cmd = {
		.op = CXI_OP_SVC_GET_NETNS,
		.svc_id = svc_id,
	};
	struct cxi_svc_get_value_resp resp = {};
	size_t resp_len = sizeof(resp);
	int rc;

	rc = cxi_send_msg_to_pf(dev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc)
		return rc;

	*netns = resp.value;

	return 0;
}

/**
 * cxi_svc_get_netns() - Get the network namespace associated with a service
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to query.
 * @netns: Pointer to store namespace ID
 *
 * Return: 0 on success, or negative errno value.
 */
int cxi_svc_get_netns(struct cxi_dev *dev, unsigned int svc_id,
		      unsigned int *netns)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	union cxi_ac_data ac_data = {};
	int rc;

	if (!dev->is_physfn)
		return cxi_svc_get_netns_vf(dev, svc_id, netns);

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		cxidev_dbg(dev, "svc_id %u not found", svc_id);
		rc = -EINVAL;
		goto unlock_return;
	}
	rc = cxi_ac_entry_list_retrieve_netns(&svc_priv->rgroup->ac_entry_list, &ac_data);
	if (rc)
		goto unlock_return;

	*netns = ac_data.netns;

unlock_return:
	mutex_unlock(&hw->svc_lock);
	return rc;
}
EXPORT_SYMBOL(cxi_svc_get_netns);

void cass_svc_fini(struct cass_dev *hw)
{
	struct cxi_svc_priv *svc_priv;
	struct cxi_svc_priv *tmp;

	if (!hw->cdev.is_physfn) {
		idr_destroy(&hw->svc_ids);
		return;
	}

	debugfs_remove(hw->svc_debug);
	list_for_each_entry_safe(svc_priv, tmp, &hw->svc_list, list)
		svc_destroy(hw, svc_priv);

	idr_destroy(&hw->svc_ids);
}
