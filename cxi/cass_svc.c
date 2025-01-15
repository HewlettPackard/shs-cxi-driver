// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020 Hewlett Packard Enterprise Development LP */

/* Service Management */

#include <linux/debugfs.h>
#include <linux/cred.h>

#include "cass_core.h"

#define DEFAULT_LE_POOL_ID 0
#define DEFAULT_TLE_POOL_ID 0

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

/* Check if a service allows a particular VNI to be used */
bool valid_svc_vni(const struct cxi_svc_priv *svc_priv, unsigned int vni)
{
	int i;

	if (!svc_priv->svc_desc.restricted_vnis)
		return true;

	for (i = 0; (i < svc_priv->svc_desc.num_vld_vnis &&
		     i < CXI_SVC_MAX_VNIS); i++) {
		if (svc_priv->svc_desc.vnis[i] == vni)
			return true;
	}
	return false;
}

/* Check if a service allows a particular TC to be used */
bool valid_svc_tc(const struct cxi_svc_priv *svc_priv, unsigned int tc)
{
	if (!svc_priv->svc_desc.restricted_tcs)
		return true;

	if (svc_priv->svc_desc.tcs[tc])
		return true;

	return false;
}

bool valid_svc_user(const struct cxi_svc_priv *svc_priv)
{
	int i;
	kuid_t svc_euid;
	kgid_t svc_egid;
	kuid_t cur_euid = current_euid();

	/* Service might not have any restrictions */
	if (!svc_priv->svc_desc.restricted_members)
		return true;

	/* Ensure caller is authorized to allocate this resource */
	for (i = 0; i < CXI_SVC_MAX_MEMBERS; i++) {
		if (svc_priv->svc_desc.members[i].type == CXI_SVC_MEMBER_UID) {
			svc_euid.val = svc_priv->svc_desc.members[i].svc_member.uid;
			if (uid_eq(svc_euid, cur_euid))
				return true;
		} else if (svc_priv->svc_desc.members[i].type == CXI_SVC_MEMBER_GID) {
			svc_egid.val = svc_priv->svc_desc.members[i].svc_member.gid;
			if (in_egroup_p(svc_egid))
				return true;
		}
	}

	return false;
}

static void copy_rsrc_use(struct cxi_dev *dev, struct cxi_rsrc_use *rsrcs,
			  struct cxi_svc_priv *svc_priv)
{
	int rc;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	union c_cq_sts_tle_in_use tle_in_use;
	int type;
	enum cxi_resource_type rtype;
	struct cxi_resource_entry *entry;

	for (type = 0; type < CXI_RSRC_TYPE_MAX; type++) {
		rtype = stype_to_rtype(type, 0);
		if (type == CXI_RSRC_TYPE_TLE) {
			if (svc_priv->rgroup->pools.tle_pool_id == -1)
				continue;

			cass_read(hw,
				  C_CQ_STS_TLE_IN_USE(svc_priv->rgroup->pools.tle_pool_id),
				  &tle_in_use, sizeof(tle_in_use));
			rsrcs->in_use[type] = tle_in_use.count;
			rsrcs->tle_pool_id = svc_priv->rgroup->pools.tle_pool_id;
		} else {
			rc = cxi_rgroup_get_resource_entry(svc_priv->rgroup,
							   rtype, &entry);
			if (rc) {
				rsrcs->in_use[type] = 0;
				continue;
			}

			rsrcs->in_use[type] = entry->limits.in_use;
		}
	}
}

int rsrc_dump_order[] = {
	CXI_RESOURCE_AC,
	CXI_RESOURCE_CT,
	CXI_RESOURCE_EQ,
	CXI_RESOURCE_PTLTE,
	CXI_RESOURCE_TGQ,
	CXI_RESOURCE_TXQ,
	CXI_RESOURCE_PE0_LE,
	CXI_RESOURCE_PE1_LE,
	CXI_RESOURCE_PE2_LE,
	CXI_RESOURCE_PE3_LE,
	CXI_RESOURCE_TLE
};

static int dump_services(struct seq_file *s, void *unused)
{
	int i;
	int rc;
	ulong index;
	ulong value;
	struct cxi_rgroup *rgroup;
	struct cxi_resource_entry *entry;
	struct cass_dev *hw = s->private;
	struct cxi_resource_use *rsrc_use = hw->resource_use;

	mutex_lock(&hw->svc_lock);

	seq_puts(s, "Resources\n");
	seq_puts(s, "           ACs     CTs     EQs    PTEs    TGQs    TXQs    LE0s    LE1s    LE2s    LE3s    TLEs\n");

	seq_puts(s, "  Max ");
	for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++)
		seq_printf(s, "  %6lu", rsrc_use[rsrc_dump_order[i]].max);
	seq_puts(s, "\n");

	seq_puts(s, "  Res ");
	for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++)
		seq_printf(s, "  %6lu", rsrc_use[rsrc_dump_order[i]].reserved);
	seq_puts(s, "\n");

	seq_puts(s, "Avail ");
	for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++) {
		value = rsrc_use[rsrc_dump_order[i]].shared -
			rsrc_use[rsrc_dump_order[i]].shared_use;
		seq_printf(s, "  %6lu", value);
	}
	seq_puts(s, "\n\n");

	for_each_rgroup(index, rgroup) {
		seq_printf(s, "ID: %u%s\n", rgroup->id,
			(rgroup->id == CXI_DEFAULT_SVC_ID) ? " (default)" : "");

		seq_printf(s, "  LE pool IDs: %d %d %d %d  TLE pool ID: %d\n",
			rgroup->pools.le_pool_id[0],
			rgroup->pools.le_pool_id[1],
			rgroup->pools.le_pool_id[2],
			rgroup->pools.le_pool_id[3],
			rgroup->pools.tle_pool_id);

		seq_puts(s, "           ACs     CTs     EQs    PTEs    TGQs    TXQs    LE0s    LE1s    LE2s    LE3s    TLEs\n");
		seq_puts(s, "  Max   ");
		for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++) {
			rc = cxi_rgroup_get_resource_entry(rgroup,
							   rsrc_dump_order[i],
							   &entry);
			seq_printf(s, "%6lu  ", rc ? 0 : entry->limits.max);
		}
		seq_puts(s, "\n");

		seq_puts(s, "  Res   ");
		for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++) {
			rc = cxi_rgroup_get_resource_entry(rgroup,
							   rsrc_dump_order[i],
							   &entry);
			seq_printf(s, "%6lu  ", rc ? 0 : entry->limits.reserved);
		}
		seq_puts(s, "\n");

		seq_puts(s, "Alloc   ");
		for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++) {
			rc = cxi_rgroup_get_resource_entry(rgroup,
							   rsrc_dump_order[i],
							   &entry);
			seq_printf(s, "%6lu  ", rc ? 0 : entry->limits.in_use);
		}
		seq_puts(s, "\n\n");
	}

	mutex_unlock(&hw->svc_lock);

	return 0;
}

static int debug_dev_open(struct inode *inode, struct file *file)
{
	return single_open(file, dump_services, inode->i_private);
}

static const struct file_operations svc_debug_fops = {
	.owner = THIS_MODULE,
	.open = debug_dev_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

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
	int i, svc_id, rc;
	struct cxi_svc_priv *svc_priv;
	struct cxi_rsrc_limits limits;

	/* TODO differentiate PF/VF */
	if (!hw->cdev.is_physfn)
		return 0;

	default_rsrc_limits(&hw->cdev.prop.rsrcs);

	for (i = 0; i < CXI_RSRC_TYPE_MAX; i++) {
		/* Set up resource limits for default service */
		if (i != CXI_RSRC_TYPE_TLE) {
			limits.type[i].max = hw->cdev.prop.rsrcs.type[i].max;
			limits.type[i].res = 0;
		} else {
			limits.type[i].res = max(CASS_MIN_POOL_TLES,
						 default_svc_num_tles);
			limits.type[i].max = limits.type[i].res;
		}
	}
	svc_desc.limits = limits;

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

	mutex_init(&hw->svc_lock);
	idr_init(&hw->svc_ids);
	INIT_LIST_HEAD(&hw->svc_list);
	hw->svc_count = 0;

	/* Create default service. It will get the default ID of
	 * CXI_DEFAULT_SVC_ID */
	svc_id = cxi_svc_alloc(&hw->cdev, &svc_desc, NULL);

	if (svc_id < 0)
		return svc_id;

	if (svc_id != CXI_DEFAULT_SVC_ID) {
		cxidev_err(&hw->cdev, "Got incorrect default service ID: %u\n",
			   svc_id);
		rc = -EINVAL;
		goto destroy;
	}

	mutex_lock(&hw->svc_lock);
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	mutex_unlock(&hw->svc_lock);

	/* Ensure we got correct default Pool IDs */
	if (svc_priv->rgroup->pools.tle_pool_id != DEFAULT_TLE_POOL_ID) {
		cxidev_err(&hw->cdev, "Got incorrect TLE_POOL_ID: %d\n",
			   svc_priv->rgroup->pools.tle_pool_id);
		rc = -EINVAL;
		goto destroy;
	}
	if (svc_priv->rgroup->pools.le_pool_id[0] != DEFAULT_LE_POOL_ID) {
		cxidev_err(&hw->cdev, "Got incorrect LE_POOL_ID:  %d\n",
			   svc_priv->rgroup->pools.le_pool_id[0]);
		rc = -EINVAL;
		goto destroy;
	}

	if (disable_default_svc) {
		mutex_lock(&hw->svc_lock);
		svc_priv->svc_desc.enable = 0;
		mutex_unlock(&hw->svc_lock);
		cxi_rgroup_disable(svc_priv->rgroup);
	}

	hw->svc_debug = debugfs_create_file("services", 0444, hw->debug_dir,
					    hw, &svc_debug_fops);

	return 0;
destroy:
	cxi_svc_destroy(&hw->cdev, svc_id);
	return rc;
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

	/* Default pool for default svc or when there are no LE limits */
	if (!svc_priv->svc_desc.resource_limits)
		default_rsrc_limits(limits);

	for (i = CXI_RSRC_TYPE_PTE; i < CXI_RSRC_TYPE_MAX; i++) {
		if (!limits->type[i].res && !limits->type[i].max)
			continue;

		if (i == CXI_RSRC_TYPE_TLE) {
			if (svc_priv->svc_desc.svc_id != CXI_DEFAULT_SVC_ID) {
				/* Ensure TLE max/res are at least CASS_MIN_POOL_TLES */
				if (limits->type[i].res < CASS_MIN_POOL_TLES)
					limits->type[i].res = CASS_MIN_POOL_TLES;
				/* Force TLE max/res to be equal */
				limits->type[i].max = limits->type[i].res;
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

	/* Now reserve resources since needed ones are available */
	for (i = CXI_RSRC_TYPE_PTE; i < CXI_RSRC_TYPE_MAX; i++) {
		struct cxi_resource_limits lim = {
			.reserved = limits->type[i].res,
			.max = limits->type[i].max
		};

		if (!lim.reserved && !lim.max)
			continue;

		rc = add_resource(rgroup, i, &lim);
		if (rc) {
			pr_debug("resource %s add_resource failed %d\n",
				 cxi_rsrc_type_to_str(i), rc);

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
		if (!svc_desc->num_vld_vnis)
			return -EINVAL;
		if (svc_desc->num_vld_vnis > CXI_SVC_MAX_VNIS)
			return -EINVAL;
		for (i = 0; i < svc_desc->num_vld_vnis; i++) {
			if (!is_vni_valid(svc_desc->vnis[i]))
				return -EINVAL;
		}
	}

	if (svc_desc->restricted_members) {
		for (i = 0; i < CXI_SVC_MAX_MEMBERS; i++) {
			if (svc_desc->members[i].type < 0 ||
			    svc_desc->members[i].type >= CXI_SVC_MEMBER_MAX)
				return -EINVAL;
		}
	}

	if (svc_desc->resource_limits) {
		for (i = 0; i < CXI_RSRC_TYPE_MAX; i++) {
			if (svc_desc->limits.type[i].max <
			    svc_desc->limits.type[i].res)
				return -EINVAL;
			if (svc_desc->limits.type[i].max >
			    hw->cdev.prop.rsrcs.type[i].max)
				return -EINVAL;
		}
	}

	return 0;
}

/**
 * cxi_svc_alloc() - Allocate a service
 *
 * @dev: Cassini Device
 * @svc_desc: A service descriptor that contains requests for various resources,
 *            and optionally identifies member processes, tcs, vnis, etc. see
 *            cxi_svc_desc.
 * @fail_info: extra information when a failure occurs
 *
 * Return: Service ID on success. Else, negative errno value.
 */
int cxi_svc_alloc(struct cxi_dev *dev, const struct cxi_svc_desc *svc_desc,
		  struct cxi_svc_fail_info *fail_info)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rc;
	unsigned int rgroup_id;
	struct cxi_rgroup *rgroup;
	struct cxi_rgroup_attr attr = {
		.cntr_pool_id = svc_desc->cntr_pool_id,
		.system_service = svc_desc->is_system_svc,
		.lnis_per_rgid = CXI_DEFAULT_LNIS_PER_RGID,
	};

	rc = validate_descriptor(hw, svc_desc);
	if (rc)
		return rc;

	svc_priv = kzalloc(sizeof(*svc_priv), GFP_KERNEL);
	if (!svc_priv)
		return -ENOMEM;
	svc_priv->svc_desc = *svc_desc;

	refcount_set(&svc_priv->refcount, 1);

	rc = cxi_dev_alloc_rgroup(dev, &attr, &rgroup_id);
	if (rc)
		goto free_svc;

	rc = cxi_dev_find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (rc)
		goto release_rgroup;

	mutex_lock(&hw->svc_lock);
	idr_preload(GFP_KERNEL);
	rc = idr_alloc(&hw->svc_ids, svc_priv, 1, -1, GFP_NOWAIT);
	idr_preload_end();
	mutex_unlock(&hw->svc_lock);

	if (rc < 0) {
		cxidev_dbg(&hw->cdev, "%s service IDs exhausted\n", hw->cdev.name);
		goto rgroup_dec_refcount;
	}

	svc_priv->svc_desc.svc_id = rc;
	svc_priv->rgroup = rgroup;

	/* Check if requested reserved resources are available */
	mutex_lock(&hw->svc_lock);
	rc = reserve_rsrcs(hw, svc_priv, fail_info);
	if (rc)
		goto free_id;

	rc = cxi_rgroup_enable(rgroup);
	if (rc)
		goto free_id;

	svc_priv->svc_desc.enable = 1;
	list_add_tail(&svc_priv->list, &hw->svc_list);
	hw->svc_count++;
	mutex_unlock(&hw->svc_lock);

	refcount_inc(&hw->refcount);

	return svc_priv->svc_desc.svc_id;

free_id:
	idr_remove(&hw->svc_ids, svc_priv->svc_desc.svc_id);
	mutex_unlock(&hw->svc_lock);
rgroup_dec_refcount:
	cxi_rgroup_dec_refcount(rgroup);
	/* The rgroup pointer is no longer usable. */
release_rgroup:
	cxi_dev_rgroup_release(dev, rgroup_id);
free_svc:
	kfree(svc_priv);

	return rc;
}
EXPORT_SYMBOL(cxi_svc_alloc);

static void svc_destroy(struct cass_dev *hw, struct cxi_svc_priv *svc_priv)
{
	refcount_dec(&hw->refcount);
	kfree(svc_priv);
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
	int rc;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rgroup_id;

	/* Don't destroy default svc */
	if (svc_id == CXI_DEFAULT_SVC_ID)
		return -EINVAL;

	mutex_lock(&hw->svc_lock);

	/* Look up svc */
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Don't delete if an LNI is still using this SVC */
	if (refcount_read(&svc_priv->refcount) == 1) {
		free_rsrcs(svc_priv);
		idr_remove(&hw->svc_ids, svc_id);
	} else {
		mutex_unlock(&hw->svc_lock);
		return -EBUSY;
	}

	rgroup_id = svc_priv->rgroup->id;
	cxi_rgroup_dec_refcount(svc_priv->rgroup);
	rc = cxi_dev_rgroup_release(dev, rgroup_id);
	if (rc)
		pr_debug("cxi_dev_release_rgroup_by_id failed %d\n", rc);

	list_del(&svc_priv->list);
	hw->svc_count--;
	mutex_unlock(&hw->svc_lock);

	svc_destroy(hw, svc_priv);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_destroy);

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

	int i = 0;
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	mutex_lock(&hw->svc_lock);

	if (count < hw->svc_count) {
		mutex_unlock(&hw->svc_lock);
		return hw->svc_count;
	}

	list_for_each_entry(svc_priv, &hw->svc_list, list) {
		copy_rsrc_use(dev, &rsrc_list[i], svc_priv);
		rsrc_list[i].svc_id = svc_priv->svc_desc.svc_id;
		i++;
	}

	mutex_unlock(&hw->svc_lock);

	return i;
}
EXPORT_SYMBOL(cxi_svc_rsrc_list_get);

/*
 * cxi_svc_rsrc_get - Get rsrc_use from svc_id
 *
 * @dev: Cassini Device
 * @svc_id: svc_id of the descriptor to find
 * @rsrc_use: destination to land resource usage
 *
 * Return: 0 on success or a negative errno
 */
int cxi_svc_rsrc_get(struct cxi_dev *dev, unsigned int svc_id,
		     struct cxi_rsrc_use *rsrc_use)
{
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	mutex_lock(&hw->svc_lock);

	/* Find priv descriptor */
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	copy_rsrc_use(dev, rsrc_use, svc_priv);
	mutex_unlock(&hw->svc_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_rsrc_get);

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

	int i = 0;
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	mutex_lock(&hw->svc_lock);

	if (count < hw->svc_count) {
		mutex_unlock(&hw->svc_lock);
		return hw->svc_count;
	}

	list_for_each_entry(svc_priv, &hw->svc_list, list) {
		svc_list[i] = svc_priv->svc_desc;
		i++;
	}
	mutex_unlock(&hw->svc_lock);

	return i;
}
EXPORT_SYMBOL(cxi_svc_list_get);

/*
 * cxi_svc_get - Get svc_desc from svc_id
 *
 * @dev: Cassini Device
 * @svc_id: svc_id of the descriptor to find
 * @svc_desc: destination to land service descriptor
 *
 * Return: 0 on success or a negative errno
 */
int cxi_svc_get(struct cxi_dev *dev, unsigned int svc_id,
		struct cxi_svc_desc *svc_desc)
{
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	mutex_lock(&hw->svc_lock);

	/* Find priv descriptor */
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	*svc_desc = svc_priv->svc_desc;
	mutex_unlock(&hw->svc_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_get);

void cxi_free_resource(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv,
		      enum cxi_rsrc_type type)
{
	int rc;
	enum cxi_resource_type rtype;
	struct cxi_resource_use *r_use;
	struct cxi_resource_entry *entry;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	rtype = stype_to_rtype(type, 0);
	r_use = &hw->resource_use[rtype];

	mutex_lock(&hw->svc_lock);

	rc = cxi_rgroup_get_resource_entry(svc_priv->rgroup, rtype, &entry);
	if (rc) {
		pr_warn("cxi_rgroup_get_resource_entry failed:%d\n", rc);
		goto unlock;
	}

	/* Free from shared space if applicable */
	if (entry->limits.in_use > entry->limits.reserved)
		r_use->shared_use--;

	r_use->in_use--;
	entry->limits.in_use--;
unlock:
	mutex_unlock(&hw->svc_lock);
}

/* used to allocate ACs, etc. */
int cxi_alloc_resource(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv,
		       enum cxi_rsrc_type type)
{
	int rc;
	size_t available;
	enum cxi_resource_type rtype;
	struct cxi_resource_use *r_use;
	struct cxi_resource_entry *entry;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	if (!svc_priv->rgroup->state.enabled)
		return -EKEYREVOKED;

	rtype = stype_to_rtype(type, 0);
	r_use = &hw->resource_use[rtype];

	mutex_lock(&hw->svc_lock);

	rc = cxi_rgroup_get_resource_entry(svc_priv->rgroup, rtype, &entry);
	if (rc) {
		pr_debug("cxi_rgroup_get_resource_entry failed:%d\n", rc);
		goto unlock;
	}

	available = r_use->max - r_use->shared_use;

	if (entry->limits.in_use < entry->limits.reserved) {
		r_use->in_use++;
		entry->limits.in_use++;
	} else if (entry->limits.in_use < entry->limits.max && available) {
		entry->limits.in_use++;
		r_use->in_use++;
		r_use->shared_use++;
	} else {
		pr_debug("rgroup_id:%d %s unavailable use:%ld reserved:%ld max:%ld shared_use:%ld\n",
			 svc_priv->rgroup->id,
			 cxi_resource_type_to_str(rtype),
			 entry->limits.in_use, entry->limits.reserved,
			 entry->limits.max, r_use->shared_use);
		rc = -ENOSPC;
	}

unlock:
	mutex_unlock(&hw->svc_lock);
	return rc;
}

/**
 * cxi_svc_update() - Modify an existing service.
 *
 * @dev: Cassini Device
 * @svc_desc: A service descriptor that contains requests for various resources,
 *            and optionally identifies member processes, tcs, vnis, etc. see
 *            cxi_svc_desc.
 * @fail_info: extra information when a failure occurs
 *
 * Currently does not honor changes to resource limits in a svc_desc.
 *
 * Return: 0 on success. Else, negative errno value.
 */
int cxi_svc_update(struct cxi_dev *dev, const struct cxi_svc_desc *svc_desc,
		   struct cxi_svc_fail_info *fail_info)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rc;

	rc = validate_descriptor(hw, svc_desc);
	if (rc)
		return rc;

	mutex_lock(&hw->svc_lock);

	/* Find priv descriptor */
	svc_priv = idr_find(&hw->svc_ids, svc_desc->svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Service must be unused for it to be updated. */
	if (refcount_read(&svc_priv->refcount) != 1) {
		mutex_unlock(&hw->svc_lock);
		return -EBUSY;
	}

	/* TODO Handle Resource Reservation Changes */
	if (svc_priv->svc_desc.resource_limits != svc_desc->resource_limits) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	if (svc_priv->svc_desc.enable != svc_desc->enable) {
		if (svc_desc->enable)
			cxi_rgroup_enable(svc_priv->rgroup);
		else
			cxi_rgroup_disable(svc_priv->rgroup);
	}

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

	mutex_unlock(&hw->svc_lock);
	return 0;
}
EXPORT_SYMBOL(cxi_svc_update);

/**
 * cxi_svc_set_lpr() - Update an existing service to set the LNIs per RGID
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

	if (lnis_per_rgid > C_NUM_LACS)
		return -EINVAL;

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Service must be unused for it to be updated. */
	if (refcount_read(&svc_priv->refcount) != 1) {
		mutex_unlock(&hw->svc_lock);
		return -EBUSY;
	}

	svc_priv->rgroup->attr.lnis_per_rgid = lnis_per_rgid;

	mutex_unlock(&hw->svc_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_set_lpr);

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
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	mutex_unlock(&hw->svc_lock);

	return svc_priv->rgroup->attr.lnis_per_rgid;
}
EXPORT_SYMBOL(cxi_svc_get_lpr);

void cass_svc_fini(struct cass_dev *hw)
{
	struct cxi_svc_priv *svc_priv;
	int svc_id;

	debugfs_remove(hw->svc_debug);

	idr_for_each_entry(&hw->svc_ids, svc_priv, svc_id)
		svc_destroy(hw, svc_priv);
	idr_destroy(&hw->svc_ids);
}
