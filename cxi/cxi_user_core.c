// SPDX-License-Identifier: GPL-2.0
/* Copyright 2018,2024 Hewlett Packard Enterprise Development LP */

/* Userspace communication. */

#include <linux/cxi.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mman.h>
#include <linux/version.h>

#include "cxi_user.h"
#include "cxi_prov_hw.h"
#include "cxi_core.h"

static int free_cq_obj(int id, void *obj_, void *data);
static int free_md_obj(int id, void *obj_, void *data);
static int free_eq_obj(int id, void *obj_, void *data);
static int free_pte_obj(int id, void *obj_, void *data);
static int free_pte_map(int id, void *obj_, void *data);
static int free_wait_obj(int id, void *obj_, void *data);
static int free_ct_obj(int id, void *obj_, void *data);
static int free_cp_obj(int id, void *obj_, void *data);

#ifdef CONFIG_ARM64
/* Provide a workaround for avoiding writecombine on platforms where it is broken
 * and for which the Linux kernel does not already provide a workaround, such as the
 * Ampere Altra, used in the RL300.
 */
DEFINE_STATIC_KEY_FALSE(avoid_writecombine);
#endif

/* /dev entries. Allow for up to 256 devices, which includes SRVIO
 * devices.
 */
static dev_t ucxi_dev;
#define ucxi_num_devices 256
static DECLARE_BITMAP(minors, ucxi_num_devices);
static DEFINE_SPINLOCK(minors_lock);

static void mminfo_pre_mmap(struct user_client *client,
			    struct cxi_mmap_info *mminfo,
			    size_t mminfo_len)
{
	int i;

	spin_lock_bh(&client->pending_lock);
	for (i = 0 ; i < mminfo_len ; ++i) {
		list_add_tail(&mminfo[i].pending_mmaps,
			      &client->pending_mmaps);
	}
	spin_unlock_bh(&client->pending_lock);
}

static void mminfo_unmap(struct user_client *client,
			 struct cxi_mmap_info *mminfo,
			 size_t mminfo_len)
{
	int i;

	/*
	 * looping through mminfo[] twice to minimize time holding the
	 * pending_lock
	 */

	spin_lock_bh(&client->pending_lock);
	for (i = 0 ; i < mminfo_len ; ++i)
		if (!list_empty(&mminfo[i].pending_mmaps))
			list_del_init(&mminfo[i].pending_mmaps);
	spin_unlock_bh(&client->pending_lock);

	for (i = 0 ; i < mminfo_len ; ++i)
		if (mminfo[i].vm_start != 0) {
			WARN_ON(mminfo[i].vm_end == 0);
			vm_munmap(mminfo[i].vm_start, mminfo[i].vm_end
				  - mminfo[i].vm_start);
			mminfo[i].vm_start = 0;
			mminfo[i].vm_end = 0;
		}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) || defined(RHEL8_9_PLUS) || defined(RHEL9_3_PLUS)
static char *devnode(const struct device *dev, umode_t *mode)
#else
static char *devnode(struct device *dev, umode_t *mode)
#endif
{
	if (mode)
		*mode = 0666;
	return NULL;
}

/* /sys/class/cxi_user entry */
static struct class ucxi_class = {
	.name = "cxi_user",
	.devnode = devnode,
};

/* List of devices registered with this client */
static LIST_HEAD(dev_list);
static DEFINE_MUTEX(dev_list_mutex);

/* Allocate an object, and room for its dependencies. For instance a
 * CP has no dependencies, while a PT depends on a domain and an
 * EQ.
 */
static struct ucxi_obj *alloc_obj(unsigned int n_deps)
{
	struct ucxi_obj *ucxi_obj;

	ucxi_obj = kzalloc(sizeof(struct ucxi_obj) +
			   n_deps * sizeof(struct ucxi_obj *), GFP_KERNEL);

	if (ucxi_obj == NULL)
		return NULL;

	atomic_set(&ucxi_obj->refs, 0);
	atomic_set(&ucxi_obj->mappings, 0);

	return ucxi_obj;
}

/* Release the dependencies of an object, and free it. */
static void free_obj(struct ucxi_obj *obj)
{
	const unsigned int num_deps = obj->num_deps;
	int i;

	/* Release dependencies */
	for (i = 0; i < num_deps; i++)
		if (obj->deps[i])
			atomic_dec(&obj->deps[i]->refs);

	kfree(obj);
}

/* Copy the response to a command, either to userspace, or in the
 * buffer provided to the VF.
 *
 * Returns 0 on success, -EFAULT on failures.
 */
static int copy_response(struct user_client *client, const void *resp,
			 size_t resp_size, void *resp_out,
			 size_t *resp_out_size)
{
	int rc;

	if (client->is_vf) {
		memcpy(resp_out, resp, resp_size);
		*resp_out_size = resp_size;
		rc = 0;
	} else {
		rc = copy_to_user(resp_out, resp, resp_size);
		if (rc)
			rc = -EFAULT;
	}

	return rc;
}

/* Allocate an LNI. Return an index. */
static int cxi_user_lni_alloc(struct user_client *client,
			      const void *cmd_in,
			      void *resp_out, size_t *resp_out_len)
{
	struct cxi_lni *lni;
	const struct cxi_lni_alloc_cmd *cmd = cmd_in;
	struct cxi_lni_alloc_resp resp = {};
	int rc;
	struct ucxi_obj *obj;

	lni = cxi_lni_alloc(client->ucxi->dev, cmd->svc_id);
	if (IS_ERR(lni))
		return PTR_ERR(lni);

	obj = alloc_obj(0);
	if (obj == NULL) {
		rc = -ENOMEM;
		goto free_lni;
	}

	obj->lni = lni;

	/* Allocate an id to return to userspace */
	idr_preload(GFP_KERNEL);
	write_lock(&client->res_lock);

	rc = idr_alloc(&client->lni_idr, obj, lni->id, lni->id + 1,
		       GFP_NOWAIT);

	write_unlock(&client->res_lock);
	idr_preload_end();

	if (rc < 0)
		goto free_obj;

	resp.lni = rc;

	rc = copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len);
	if (rc)
		goto release_lni_idr;

	return 0;

release_lni_idr:
	write_lock(&client->res_lock);
	idr_remove(&client->lni_idr, resp.lni);
	write_unlock(&client->res_lock);
free_obj:
	free_obj(obj);
free_lni:
	cxi_lni_free(lni);

	return rc;
}

static int cxi_user_lni_free(struct user_client *client,
			     const void *cmd_in,
			     void *resp_out, size_t *resp_out_len)
{
	const struct cxi_lni_free_cmd *cmd = cmd_in;
	struct ucxi_obj *obj;

	write_lock(&client->res_lock);

	obj = idr_find(&client->lni_idr, cmd->lni);
	if (obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	if (atomic_read(&obj->refs) != 0) {
		write_unlock(&client->res_lock);
		return -EBUSY;
	}

	idr_remove(&client->lni_idr, cmd->lni);

	write_unlock(&client->res_lock);

	cxi_lni_free(obj->lni);
	free_obj(obj);

	return 0;
}

static int cxi_user_dev_alloc_rgroup(struct user_client *client,
				     const void *cmd_in,
				     void *resp_out, size_t *resp_out_len)
{
	const struct cxi_dev_alloc_rgroup_cmd   *cmd = cmd_in;
	struct cxi_dev_alloc_rgroup_resp        resp;
	struct cxi_rgroup_attr                  attr;
	int    ret;

	attr.cntr_pool_id   = cmd->attr.cntr_pool_id;
	attr.system_service = cmd->attr.system_service;
	strscpy(attr.name, cmd->attr.name, ARRAY_SIZE(attr.name));

	ret = cxi_dev_alloc_rgroup(client->ucxi->dev, &attr, &resp.rgroup_id);
	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int cxi_user_rgroup_release(struct user_client *client,
				   const void *cmd_in,
				   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_release_cmd   *cmd = cmd_in;

	return cxi_dev_rgroup_release(client->ucxi->dev,
				      cmd->rgroup_id);
}

static int cxi_user_rgroup_enable(struct user_client *client,
				  const void *cmd_in,
				  void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_enable_cmd   *cmd = cmd_in;

	return cxi_dev_rgroup_enable(client->ucxi->dev,
					   cmd->rgroup_id);
}

static int cxi_user_rgroup_disable(struct user_client *client,
				   const void *cmd_in,
				   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_disable_cmd   *cmd = cmd_in;

	return cxi_dev_rgroup_disable(client->ucxi->dev,
				      cmd->rgroup_id);
}

static int cxi_user_dev_get_rgroup_ids(struct user_client *client,
				       const void *cmd_in,
				       void *resp_out, size_t *resp_out_len)
{
	const struct cxi_dev_get_rgroup_ids_cmd   *cmd = cmd_in;
	struct cxi_dev_get_rgroup_ids_resp        resp;
	unsigned int       *rgroup_ids;
	size_t             bytes;
	int                ret, ret2;

	if (cmd->max_ids && !cmd->rgroup_ids)
		return -EINVAL;

	rgroup_ids = kcalloc(cmd->max_ids, sizeof(*rgroup_ids), GFP_KERNEL);
	if (cmd->max_ids && !rgroup_ids)
		return -ENOMEM;

	ret = cxi_dev_get_rgroup_ids(client->ucxi->dev,
				     cmd->max_ids,
				     rgroup_ids,
				     &resp.num_ids);

	if (ret)
		kfree(rgroup_ids);

	switch (ret) {
	case -ENOSPC:
		goto copy_response;
	case 0:
		break;
	default:
		return ret;
	}

	ret = copy_response(client, rgroup_ids, resp.num_ids * sizeof(*rgroup_ids),
			    cmd->rgroup_ids, &bytes);

	kfree(rgroup_ids);
	if (ret)
		return ret;

copy_response:
	ret2 = copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);

	return (ret2) ? ret2 : ret;
}

static int cxi_user_rgroup_get_info(struct user_client *client,
				    const void *cmd_in,
				    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_get_info_cmd  *cmd = cmd_in;
	struct cxi_rgroup_get_info_resp       resp;
	struct cxi_rgroup_attr                attr;
	struct cxi_rgroup_state               state;
	int    ret;

	ret = cxi_dev_rgroup_get_info(client->ucxi->dev,
				      cmd->rgroup_id,
				      &attr, &state);
	if (ret)
		return ret;

	resp.attr.cntr_pool_id   = attr.cntr_pool_id;
	resp.attr.system_service = attr.system_service;
	strscpy(resp.attr.name, attr.name, ARRAY_SIZE(resp.attr.name));

	resp.state.enabled  = state.enabled;
	resp.state.released = state.released;
	resp.state.refcount = refcount_read(&state.refcount);

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int cxi_user_rgroup_add_resource(struct user_client *client,
					const void *cmd_in,
					void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_add_resource_cmd  *cmd = cmd_in;
	struct cxi_resource_limits                limits;

	limits.reserved = cmd->limits.reserved;
	limits.max      = cmd->limits.max;

	return cxi_dev_rgroup_add_resource(client->ucxi->dev,
					   cmd->rgroup_id,
					   cmd->resource_type,
					   &limits);
}

static int cxi_user_rgroup_delete_resource(struct user_client *client,
					   const void *cmd_in,
					   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_delete_resource_cmd  *cmd = cmd_in;

	return cxi_dev_rgroup_delete_resource(client->ucxi->dev,
					      cmd->rgroup_id,
					      cmd->resource_type);
}

static int cxi_user_rgroup_get_resource(struct user_client *client,
					const void *cmd_in,
					void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_get_resource_cmd   *cmd = cmd_in;
	struct cxi_rgroup_get_resource_resp        resp;
	struct cxi_resource_limits                 limits;
	int    ret;

	ret = cxi_dev_rgroup_get_resource(client->ucxi->dev, cmd->rgroup_id,
					  cmd->resource_type, &limits);

	if (ret)
		return ret;

	resp.limits.reserved = limits.reserved;
	resp.limits.max      = limits.max;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int cxi_user_rgroup_get_resource_types(struct user_client *client,
					      const void *cmd_in,
					      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_get_resource_types_cmd  *cmd = cmd_in;
	struct cxi_rgroup_get_resource_types_resp       resp;
	enum cxi_resource_type                          *types;
	unsigned int  *bounce;
	size_t        i, bytes;
	int           ret, ret2;

	if (cmd->max_types && !cmd->resource_types)
		return -EINVAL;

	types = kcalloc(cmd->max_types, sizeof(*types), GFP_KERNEL);
	if (cmd->max_types && !types)
		return -ENOMEM;

	ret = cxi_dev_rgroup_get_resource_types(client->ucxi->dev,
						cmd->rgroup_id,
						cmd->max_types,
						types,
						&resp.num_types);

	if (ret)
		kfree(types);

	switch (ret) {
	case -ENOSPC:
		goto copy_response;
	case 0:
		break;
	default:
		return ret;
	}

	/* enum cxi_resource_type may not be the same size as unsigned int
	 * so use 'bounce' to do implicit type conversion.
	 */
	bounce = kcalloc(resp.num_types, sizeof(*bounce), GFP_KERNEL);
	if (!bounce) {
		kfree(types);
		return -ENOMEM;
	}

	for (i = 0; i < resp.num_types; i++)
		bounce[i] = types[i];

	kfree(types);

	ret = copy_response(client, bounce, resp.num_types * sizeof(*bounce),
			    cmd->resource_types, &bytes);

	kfree(bounce);
	if (ret)
		return ret;

copy_response:

	ret2 = copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);

	return (ret2) ? ret2 : ret;
}

static int cxi_user_rgroup_add_ac_entry(struct user_client *client,
					const void *cmd_in,
					void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_add_ac_entry_cmd  *cmd = cmd_in;
	struct cxi_rgroup_add_ac_entry_resp       resp;
	union cxi_ac_data                         data;
	int    ret;

	switch (cmd->ac_type) {
	case CXI_AC_UID:
		data.uid = cmd->uid;
		break;
	case CXI_AC_GID:
		data.gid = cmd->gid;
		break;
	case CXI_AC_OPEN:
		memset(&data, 0, sizeof(data));
		break;
	default:
		return -EINVAL;
	}

	ret = cxi_dev_rgroup_add_ac_entry(client->ucxi->dev,
					  cmd->rgroup_id,
					  cmd->ac_type,
					  &data,
					  &resp.ac_entry_id);

	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int cxi_user_rgroup_delete_ac_entry(struct user_client *client,
					   const void *cmd_in,
					   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_delete_ac_entry_cmd  *cmd = cmd_in;

	return cxi_dev_rgroup_delete_ac_entry(client->ucxi->dev,
					      cmd->rgroup_id,
					      cmd->ac_entry_id);
}

static int cxi_user_rgroup_get_ac_entry_ids(struct user_client *client,
					    const void *cmd_in,
					    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rgroup_get_ac_entry_ids_cmd  *cmd = cmd_in;
	struct cxi_rgroup_get_ac_entry_ids_resp       resp;
	unsigned int  *ids;
	size_t        bytes;
	int           ret, ret2;

	if (cmd->max_ids && !cmd->ids)
		return -EINVAL;

	ids = kcalloc(cmd->max_ids, sizeof(*ids), GFP_KERNEL);
	if (cmd->max_ids && !ids)
		return -ENOMEM;

	ret = cxi_dev_rgroup_get_ac_entry_ids(client->ucxi->dev,
					      cmd->rgroup_id,
					      cmd->max_ids,
					      ids,
					      &resp.num_ids);

	if (ret)
		kfree(ids);

	switch (ret) {
	case 0:
		break;
	case -ENOSPC:
		goto copy_response;
	default:
		return ret;
	}

	ret = copy_response(client, ids, resp.num_ids * sizeof(*ids),
			    cmd->ids, &bytes);

	kfree(ids);

	if (ret)
		return ret;

copy_response:
	ret2 = copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);

	return (ret2) ? ret2 : ret;
}

static int
cxi_user_rgroup_get_ac_entry_data_by_id(struct user_client *client,
					const void *cmd_in,
					void *resp_out,
					size_t *resp_out_len)
{
	const struct cxi_rgroup_get_ac_entry_data_by_id_cmd  *cmd = cmd_in;
	struct cxi_rgroup_get_ac_entry_data_by_id_resp       resp;
	enum cxi_ac_type    ac_type;
	union cxi_ac_data   ac_data;
	int    ret;

	ret = cxi_dev_rgroup_get_ac_entry_data(client->ucxi->dev,
					       cmd->rgroup_id,
					       cmd->ac_entry_id,
					       &ac_type,
					       &ac_data);
	if (ret)
		return ret;

	resp.ac_type = ac_type;

	switch (ac_type) {
	case CXI_AC_UID:
		resp.uid = ac_data.uid;
		break;
	case CXI_AC_GID:
		resp.gid = ac_data.gid;
		break;
	case CXI_AC_OPEN:
		break;
	default:
		return -EIO;
	}

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int
cxi_user_rgroup_get_ac_entry_id_by_data(struct user_client *client,
					const void *cmd_in,
					void *resp_out,
					size_t *resp_out_len)
{
	const struct cxi_rgroup_get_ac_entry_id_by_data_cmd   *cmd = cmd_in;
	struct cxi_rgroup_get_ac_entry_id_by_data_resp        resp;
	enum cxi_ac_type     ac_type;
	union cxi_ac_data    ac_data;
	int    ret;

	ac_type = cmd->ac_type;
	switch (ac_type) {
	case CXI_AC_OPEN:
		break;
	case CXI_AC_UID:
		ac_data.uid = cmd->uid;
		break;
	case CXI_AC_GID:
		ac_data.gid = cmd->gid;
		break;
	default:
		return -EBADR;
	}

	ret = cxi_dev_rgroup_get_ac_entry_id_by_data(client->ucxi->dev,
						     cmd->rgroup_id, ac_type,
						     &ac_data, &resp.ac_entry_id);

	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int
cxi_user_rgroup_get_ac_entry_id_by_user(struct user_client *client,
					const void *cmd_in,
					void *resp_out,
					size_t *resp_out_len)
{
	const struct cxi_rgroup_get_ac_entry_id_by_user_cmd   *cmd = cmd_in;
	struct cxi_rgroup_get_ac_entry_id_by_user_resp        resp;
	int    ret;

	ret = cxi_dev_rgroup_get_ac_entry_id_by_user(client->ucxi->dev,
						     cmd->rgroup_id,
						     cmd->uid, cmd->gid,
						     cmd->desired_types,
						     &resp.ac_entry_id);
	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int cxi_user_svc_get(struct user_client *client,
			    const void *cmd_in,
			    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_svc_get_cmd *cmd = cmd_in;
	struct cxi_svc_get_resp resp = {};
	int rc;

	rc = cxi_svc_get(client->ucxi->dev, cmd->svc_id, &resp.svc_desc);
	if (rc)
		return rc;

	if (copy_to_user(cmd->resp, &resp, sizeof(resp)))
		return -EFAULT;

	return 0;
}

/* Passes size of service list back to user. Copies list of services into user
 * memory if user has allocated enough space.
 */
static int cxi_user_svc_list_get(struct user_client *client,
				 const void *cmd_in,
				 void *resp_out, size_t *resp_out_len)
{
	const struct cxi_svc_list_get_cmd *cmd = cmd_in;
	struct cxi_svc_list_get_resp resp = {};
	struct cxi_svc_desc *svc_list;
	int rc;

	/* Call first to check svc count in kernel. */
	rc = cxi_svc_list_get(client->ucxi->dev, 0, NULL);
	resp.count = rc;

	/* User didn't allocate enough memory. Don't copy list. */
	if (cmd->count < resp.count) {
		/* Pass svc count back to user */
		if (copy_to_user(cmd->resp, &resp, sizeof(resp)))
			return -EFAULT;
		return 0;
	}

	/* User allocated enough memory. Allocate bounce buffer. */
	svc_list = kcalloc(cmd->count, sizeof(*svc_list), GFP_KERNEL);
	if (!svc_list)
		return -ENOMEM;

	/*  Call second time to copy into bounce buffer */
	rc = cxi_svc_list_get(client->ucxi->dev, cmd->count,
			      svc_list);

	/* Pass latest svc count back to user. */
	resp.count = rc;
	if (copy_to_user(cmd->resp, &resp, sizeof(resp))) {
		rc = -EFAULT;
		goto err;
	}
	/* Size of kernel service list stayed the same between calls.
	 * Copy list into user memory.
	 */
	if (rc <= cmd->count) {
		if (copy_to_user(cmd->svc_list, svc_list,
				 sizeof(struct cxi_svc_desc) * rc)) {
			rc = -EFAULT;
			goto err;
		}
	}

	rc = 0;
err:
	kfree(svc_list);
	return rc;
}

static int cxi_user_svc_rsrc_get(struct user_client *client,
				 const void *cmd_in,
				 void *resp_out, size_t *resp_out_len)
{
	const struct cxi_svc_rsrc_get_cmd *cmd = cmd_in;
	struct cxi_svc_rsrc_get_resp resp = {};
	int rc;

	rc = cxi_svc_rsrc_get(client->ucxi->dev, cmd->svc_id, &resp.rsrcs);
	if (rc)
		return rc;

	if (copy_to_user(cmd->resp, &resp, sizeof(resp)))
		return -EFAULT;

	return 0;
}

/* Passes size of service list back to user. Copies list of services into user
 * memory if user has allocated enough space.
 */
static int cxi_user_svc_rsrc_list_get(struct user_client *client,
				      const void *cmd_in,
				      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_svc_rsrc_list_get_cmd *cmd = cmd_in;
	struct cxi_svc_rsrc_list_get_resp resp = {};
	struct cxi_rsrc_use *rsrc_list;
	int rc;

	/* Call first to check svc count in kernel. */
	rc = cxi_svc_rsrc_list_get(client->ucxi->dev, 0, NULL);
	resp.count = rc;

	/* User didn't allocate enough memory. Don't copy list. */
	if (cmd->count < resp.count) {
		/* Pass svc count back to user */
		if (copy_to_user(cmd->resp, &resp, sizeof(resp)))
			return -EFAULT;
		return 0;
	}

	/* User allocated enough memory. Allocate bounce buffer. */
	rsrc_list = kcalloc(cmd->count, sizeof(*rsrc_list), GFP_KERNEL);
	if (!rsrc_list)
		return -ENOMEM;

	/*  Call second time to copy into bounce buffer */
	rc = cxi_svc_rsrc_list_get(client->ucxi->dev, cmd->count,
				   rsrc_list);

	/* Pass latest svc count back to user. */
	resp.count = rc;
	if (copy_to_user(cmd->resp, &resp, sizeof(resp))) {
		rc = -EFAULT;
		goto err;
	}
	/* Size of kernel service list stayed the same between calls.
	 * Copy list into user memory.
	 */
	if (rc <= cmd->count) {
		if (copy_to_user(cmd->rsrc_list, rsrc_list,
				 sizeof(struct cxi_rsrc_use) * rc)) {
			rc = -EFAULT;
			goto err;
		}
	}

	rc = 0;
err:
	kfree(rsrc_list);
	return rc;
}

static int cxi_user_svc_alloc(struct user_client *client,
			      const void *cmd_in,
			      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_svc_alloc_cmd *cmd = cmd_in;
	struct cxi_svc_fail_info fail_info = {};
	struct cxi_svc_alloc_resp resp = {};
	int ret = 0;
	int rc;

	rc = cxi_svc_alloc(client->ucxi->dev, &cmd->svc_desc, &fail_info);
	if (rc < 0) {
		resp.fail_info = fail_info;
		ret = rc;
	} else {
		resp.svc_id = rc;
	}

	if (copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len))
		return -EFAULT;

	return ret;
}

static int cxi_user_svc_destroy(struct user_client *client,
				const void *cmd_in,
				void *resp_out, size_t *resp_out_len)
{
	const struct cxi_svc_destroy_cmd *cmd = cmd_in;
	int rc;

	rc = cxi_svc_destroy(client->ucxi->dev, cmd->svc_id);

	return rc;
}

static int cxi_user_svc_update(struct user_client *client,
			       const void *cmd_in,
			       void *resp_out, size_t *resp_out_len)
{
	const struct cxi_svc_update_cmd *cmd = cmd_in;
	struct cxi_svc_fail_info fail_info = {};
	struct cxi_svc_update_resp resp = {};
	int rc;

	rc = cxi_svc_update(client->ucxi->dev, &cmd->svc_desc, &fail_info);
	if (rc < 0) {
		resp.fail_info = fail_info;
	}

	/* fail_info is not currently filled out */
	if (copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len))
		return -EFAULT;
	return rc;
}

static int cxi_user_svc_set_lpr(struct user_client *client,
				const void *cmd_in,
				void *resp_out, size_t *resp_out_len)
{
	const struct cxi_svc_lpr_cmd *cmd = cmd_in;

	return cxi_svc_set_lpr(client->ucxi->dev, cmd->svc_id,
			       cmd->lnis_per_rgid);
}

static int cxi_user_svc_get_lpr(struct user_client *client,
				const void *cmd_in,
				void *resp_out, size_t *resp_out_len)
{
	const struct cxi_svc_lpr_cmd *cmd = cmd_in;
	struct cxi_svc_get_value_resp resp = {};

	resp.value = cxi_svc_get_lpr(client->ucxi->dev, cmd->svc_id);
	if (resp.value < 0)
		return resp.value;

	if (copy_to_user(cmd->resp, &resp, sizeof(resp)))
		return -EFAULT;

	return 0;
}

static int cxi_user_cp_alloc(struct user_client *client,
			     const void *cmd_in,
			     void *resp_out, size_t *resp_out_len)
{
	struct ucxi_obj *lni;
	struct ucxi_obj *cp_obj;
	const struct cxi_cp_alloc_cmd *cmd = cmd_in;
	struct cxi_cp_alloc_resp resp = {};
	struct cxi_cp *cp;
	int rc;

	cp_obj = alloc_obj(1);
	if (!cp_obj)
		return -ENOMEM;

	/* Locate the LNI object. */
	read_lock(&client->res_lock);

	lni = idr_find(&client->lni_idr, cmd->lni);
	if (!lni) {
		read_unlock(&client->res_lock);
		rc = -EINVAL;
		goto free_obj;
	}

	atomic_inc(&lni->refs);
	cp_obj->deps[0] = lni;
	cp_obj->num_deps = 1;

	read_unlock(&client->res_lock);

	/* Allocate the communication profile and handle for the user. */
	cp = cxi_cp_alloc(lni->lni, cmd->vni, cmd->tc, cmd->tc_type);
	if (IS_ERR(cp)) {
		rc = PTR_ERR(cp);
		goto free_obj;
	}
	cp_obj->cp = cp;

	idr_preload(GFP_KERNEL);
	write_lock(&client->res_lock);

	rc = idr_alloc(&client->cp_idr, cp_obj, 0, -1, GFP_NOWAIT);

	write_unlock(&client->res_lock);
	idr_preload_end();

	if (rc < 0)
		goto free_cp;

	/* Return communication profile information to the user. */
	resp.cp_hndl = rc;
	resp.lcid = cp->lcid;

	rc = copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len);
	if (rc)
		goto release_cp_idr;

	return 0;

release_cp_idr:
	write_lock(&client->res_lock);
	idr_remove(&client->cp_idr, resp.cp_hndl);
	write_unlock(&client->res_lock);
free_cp:
	cxi_cp_free(cp);
free_obj:
	free_obj(cp_obj);

	return rc;
}

static int cxi_user_cp_free(struct user_client *client,
			    const void *cmd_in,
			    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_cp_free_cmd *cmd = cmd_in;
	struct ucxi_obj *cp_obj;

	write_lock(&client->res_lock);

	cp_obj = idr_find(&client->cp_idr, cmd->cp_hndl);
	if (!cp_obj) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	if (atomic_read(&cp_obj->refs) != 0) {
		write_unlock(&client->res_lock);
		return -EBUSY;
	}

	idr_remove(&client->cp_idr, cmd->cp_hndl);

	write_unlock(&client->res_lock);

	free_cp_obj(0, cp_obj, client);

	return 0;
}

/* Atomically reserve a contiguous range of VNI PIDs. */
static int cxi_user_domain_reserve(struct user_client *client,
				   const void *cmd_in,
				   void *resp_out, size_t *resp_out_len)
{
	struct ucxi_obj *lni;
	const struct cxi_domain_reserve_cmd *cmd = cmd_in;
	struct cxi_domain_reserve_resp resp = {};
	int rc;

	read_lock(&client->res_lock);

	lni = idr_find(&client->lni_idr, cmd->lni);
	if (lni == NULL) {
		read_unlock(&client->res_lock);
		return -EINVAL;
	}

	atomic_inc(&lni->refs);

	read_unlock(&client->res_lock);

	rc = cxi_domain_reserve(lni->lni, cmd->vni, cmd->pid, cmd->count);
	if (rc >= 0) {
		resp.pid = rc;
		rc = copy_response(client, &resp, sizeof(resp), resp_out,
				   resp_out_len);

		/* Reservations will be cleaned up when the LNI is freed. */
	}

	atomic_dec(&lni->refs);

	return rc;
}

/* Allocate a domain, and return an index. */
static int cxi_user_domain_alloc(struct user_client *client,
				 const void *cmd_in,
				 void *resp_out, size_t *resp_out_len)
{
	struct cxi_domain *domain;
	struct ucxi_obj *lni;
	const struct cxi_domain_alloc_cmd *cmd = cmd_in;
	struct cxi_domain_alloc_resp resp = {};
	int rc;
	struct ucxi_obj *obj;

	obj = alloc_obj(1);
	if (obj == NULL)
		return -ENOMEM;

	read_lock(&client->res_lock);

	lni = idr_find(&client->lni_idr, cmd->lni);
	if (lni == NULL) {
		read_unlock(&client->res_lock);
		rc = -EINVAL;
		goto free_obj;
	}

	atomic_inc(&lni->refs);

	read_unlock(&client->res_lock);

	obj->deps[0] = lni;
	obj->num_deps = 1;

	domain = cxi_domain_alloc(lni->lni, cmd->vni, cmd->pid);
	if (IS_ERR(domain)) {
		rc = PTR_ERR(domain);
		goto free_obj;
	}

	obj->domain = domain;

	idr_preload(GFP_KERNEL);
	write_lock(&client->res_lock);

	rc = idr_alloc(&client->domain_idr, obj,
		       domain->id, domain->id + 1, GFP_NOWAIT);

	write_unlock(&client->res_lock);
	idr_preload_end();

	if (rc < 0)
		goto free_domain;

	resp.domain = rc;
	resp.vni = domain->vni;
	resp.pid = domain->pid;

	rc = copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len);
	if (rc)
		goto release_domain_idr;

	return 0;

release_domain_idr:
	write_lock(&client->res_lock);
	idr_remove(&client->domain_idr, resp.domain);
	write_unlock(&client->res_lock);
free_domain:
	cxi_domain_free(domain);
free_obj:
	free_obj(obj);

	return rc;
}

static int cxi_user_domain_free(struct user_client *client,
				const void *cmd_in,
				void *resp_out, size_t *resp_out_len)
{
	const struct cxi_domain_free_cmd *cmd = cmd_in;
	struct ucxi_obj *obj;

	write_lock(&client->res_lock);

	obj = idr_find(&client->domain_idr, cmd->domain);
	if (obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	if (atomic_read(&obj->refs) != 0) {
		write_unlock(&client->res_lock);
		return -EBUSY;
	}

	idr_remove(&client->domain_idr, cmd->domain);

	write_unlock(&client->res_lock);

	cxi_domain_free(obj->domain);
	free_obj(obj);

	return 0;
}

/* Allocate a Command Queue, and return an index plus some memory mappings. */
static int cxi_user_cq_alloc(struct user_client *client,
			     const void *cmd_in,
			     void *resp_out, size_t *resp_out_len)
{
	int rc;
	phys_addr_t csr_addr;
	size_t csr_size;
	size_t queue_size;
	struct cxi_cq *cq;
	const struct cxi_cq_alloc_cmd *cmd = cmd_in;
	struct cxi_cq_alloc_resp resp = {};
	struct cxi_cq_alloc_opts opts = cmd->opts;
	struct cxi_mmap_info *mminfo;  /* CSR and queue mappings */
	struct page *queue_pages;
	struct ucxi_obj *lni;
	struct ucxi_obj *obj;
	struct ucxi_obj *eq_obj;

	obj = alloc_obj(2);
	if (obj == NULL)
		return -ENOMEM;

	read_lock(&client->res_lock);

	lni = idr_find(&client->lni_idr, cmd->lni);
	if (lni == NULL) {
		read_unlock(&client->res_lock);
		rc = -EINVAL;
		goto free_obj;
	}

	atomic_inc(&lni->refs);
	obj->deps[0] = lni;
	obj->num_deps = 1;

	if (cmd->eq == C_EQ_NONE) {
		eq_obj = NULL;
	} else {
		eq_obj = idr_find(&client->eq_idr, cmd->eq);
		if (eq_obj == NULL) {
			read_unlock(&client->res_lock);
			rc = -EINVAL;
			goto free_obj;
		}

		atomic_inc(&eq_obj->refs);
		obj->deps[1] = eq_obj;
		obj->num_deps++;
	}

	read_unlock(&client->res_lock);

	opts.flags |= CXI_CQ_USER;
	cq = cxi_cq_alloc(lni->lni, eq_obj ? eq_obj->eq : NULL, &opts,
			  numa_node_id());
	if (IS_ERR(cq)) {
		rc = PTR_ERR(cq);
		goto free_obj;
	}

	obj->cq = cq;

	idr_preload(GFP_KERNEL);
	write_lock(&client->res_lock);

	rc = idr_alloc(&client->cq_idr, obj, cq->idx, cq->idx + 1,
		       GFP_NOWAIT);

	write_unlock(&client->res_lock);
	idr_preload_end();

	if (rc < 0)
		goto free_cq;

	resp.cq = rc;

	cxi_cq_user_info(cq, &queue_size, &queue_pages, &csr_addr, &csr_size);

	mminfo = kcalloc(2, sizeof(*mminfo), GFP_KERNEL);
	if (!mminfo)
		goto release_cq_idr;

	//TODO: none of that in the PF if VF CQ
	fill_mmap_info(client, &mminfo[0], (uintptr_t)queue_pages, queue_size,
		       MMAP_LOGICAL);
	resp.cmds = mminfo[0].mminfo;
	mminfo[0].obj = obj;

	fill_mmap_info(client, &mminfo[1], csr_addr, csr_size, MMAP_PHYSICAL);
	resp.wp_addr = mminfo[1].mminfo;
	mminfo[1].obj = obj;
	mminfo[1].wc = true;

	resp.count = cq->size;

	rc = copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len);
	if (rc)
		goto del_mminfo;

	obj->mminfo = mminfo;

	mminfo_pre_mmap(client, mminfo, 2);

	return 0;

del_mminfo:
	kfree(mminfo);
release_cq_idr:
	write_lock(&client->res_lock);
	idr_remove(&client->cq_idr, resp.cq);
	write_unlock(&client->res_lock);
free_cq:
	cxi_cq_free(cq);
free_obj:
	free_obj(obj);

	return rc;
}

static int cxi_user_cq_free(struct user_client *client,
			    const void *cmd_in,
			    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_cq_free_cmd *cmd = cmd_in;
	struct ucxi_obj *obj;

	write_lock(&client->res_lock);

	obj = idr_find(&client->cq_idr, cmd->cq);

	if (obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	if (atomic_read(&obj->refs) != 0 ||
	    atomic_read(&obj->mappings) != 0) {
		write_unlock(&client->res_lock);
		return -EBUSY;
	}

	idr_remove(&client->cq_idr, cmd->cq);

	write_unlock(&client->res_lock);

	free_cq_obj(0, obj, client);

	return 0;
}

static int cxi_user_cq_ack_counter(struct user_client *client,
				   const void *cmd_in,
				   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_cq_ack_counter_cmd *cmd = cmd_in;
	struct cxi_cq_ack_counter_resp resp = {};
	struct ucxi_obj *cq;
	int rc;

	read_lock(&client->res_lock);

	cq = idr_find(&client->cq_idr, cmd->cq);
	if (!cq) {
		read_unlock(&client->res_lock);
		return -EINVAL;
	}

	resp.ack_counter = cxi_cq_ack_counter(cq->cq);

	read_unlock(&client->res_lock);

	rc = copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len);
	if (rc)
		return -EFAULT;

	return 0;
}

static int cxi_user_ct_alloc(struct user_client *client,
			     const void *cmd_in,
			     void *resp_out, size_t *resp_out_len)
{
	int rc;
	const struct cxi_ct_alloc_cmd *cmd = cmd_in;
	struct cxi_ct_alloc_resp resp = {};
	struct ucxi_obj *ct_obj;
	struct ucxi_obj *lni;
	struct cxi_ct *ct;
	struct cxi_mmap_info *mminfo;
	phys_addr_t doorbell_addr;
	size_t doorbell_size;

	ct_obj = alloc_obj(1);
	if (!ct_obj)
		return -ENOMEM;

	/* Locate the LNI object. */
	read_lock(&client->res_lock);

	lni = idr_find(&client->lni_idr, cmd->lni);
	if (!lni) {
		read_unlock(&client->res_lock);
		rc = -EINVAL;
		goto free_obj;
	}

	atomic_inc(&lni->refs);
	ct_obj->deps[0] = lni;
	ct_obj->num_deps = 1;

	read_unlock(&client->res_lock);

	/* Allocating userspace counting event. */
	ct = cxi_ct_alloc(lni->lni, cmd->wb, true);
	if (IS_ERR(ct)) {
		rc = PTR_ERR(ct);
		goto free_obj;
	}
	ct_obj->ct = ct;

	idr_preload(GFP_KERNEL);
	write_lock(&client->res_lock);

	rc = idr_alloc(&client->ct_idr, ct_obj, ct->ctn, ct->ctn + 1,
		       GFP_NOWAIT);

	write_unlock(&client->res_lock);
	idr_preload_end();

	if (rc < 0)
		goto free_ct;

	/* Prepare the doorbell for userspace. */
	rc = cxi_ct_user_info(ct, &doorbell_addr, &doorbell_size);
	if (rc)
		goto release_ct_idr;

	mminfo = kzalloc(sizeof(*mminfo), GFP_KERNEL);
	if (!mminfo) {
		rc = -ENOMEM;
		goto release_ct_idr;
	}

	fill_mmap_info(client, mminfo, doorbell_addr, doorbell_size,
		       MMAP_PHYSICAL);
	mminfo->obj = ct_obj;

	/* Prepare response for user. */
	resp.ctn = ct->ctn;
	resp.doorbell = mminfo->mminfo;

	rc = copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len);
	if (rc)
		goto free_ct_mmap;

	ct_obj->mminfo = mminfo;

	mminfo_pre_mmap(client, mminfo, 1);

	return 0;

free_ct_mmap:
	kfree(mminfo);
release_ct_idr:
	write_lock(&client->res_lock);
	idr_remove(&client->ct_idr, resp.ctn);
	write_unlock(&client->res_lock);
free_ct:
	cxi_ct_free(ct);
free_obj:
	free_obj(ct_obj);

	return rc;
}

static int cxi_user_ct_wb_update(struct user_client *client,
				 const void *cmd_in,
				 void *resp_out, size_t *resp_out_len)
{
	int rc;
	const struct cxi_ct_wb_update_cmd *cmd = cmd_in;
	struct ucxi_obj *ct_obj;

	read_lock(&client->res_lock);

	ct_obj = idr_find(&client->ct_idr, cmd->ctn);
	if (!ct_obj) {
		read_unlock(&client->res_lock);
		return -EINVAL;
	}

	atomic_inc(&ct_obj->refs);

	read_unlock(&client->res_lock);

	rc = cxi_ct_wb_update(ct_obj->ct, cmd->wb);

	atomic_dec(&ct_obj->refs);

	return rc;
}

static int cxi_user_ct_free(struct user_client *client,
			    const void *cmd_in,
			    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_ct_free_cmd *cmd = cmd_in;
	struct ucxi_obj *ct_obj;

	write_lock(&client->res_lock);

	ct_obj = idr_find(&client->ct_idr, cmd->ctn);
	if (!ct_obj) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	if (atomic_read(&ct_obj->refs) != 0 ||
	    atomic_read(&ct_obj->mappings) != 0) {
		write_unlock(&client->res_lock);
		return -EBUSY;
	}

	idr_remove(&client->ct_idr, cmd->ctn);

	write_unlock(&client->res_lock);

	free_ct_obj(0, ct_obj, client);

	return 0;
}

static int cxi_user_atu_map(struct user_client *client,
			    const void *cmd_in,
			    void *resp_out, size_t *resp_out_len)
{
	int rc;
	struct ucxi_obj *lni_obj;
	struct ucxi_obj *md_obj;
	const struct cxi_atu_map_cmd *cmd = cmd_in;
	struct cxi_atu_map_resp resp = {};
	struct cxi_md *md;
	struct cxi_md_hints hints = {};

	/* Allocate Memory Descriptor Object */
	md_obj = alloc_obj(1);
	if (md_obj == NULL)
		return -ENOMEM;

	read_lock(&client->res_lock);

	lni_obj = idr_find(&client->lni_idr, cmd->lni);
	if (lni_obj == NULL) {
		read_unlock(&client->res_lock);
		rc = -EINVAL;
		goto free_obj;
	}

	/* Non-privileged users can only set the huge_shift and
	 * DMA-buf fields.
	 */
	if (capable(CAP_SYS_ADMIN)) {
		hints = cmd->hints;
	} else {
		hints.dmabuf_fd = cmd->hints.dmabuf_fd;
		hints.dmabuf_offset = cmd->hints.dmabuf_offset;
		hints.dmabuf_valid = cmd->hints.dmabuf_valid;
		hints.huge_shift = cmd->hints.huge_shift;
	}

	atomic_inc(&lni_obj->refs);
	md_obj->deps[0] = lni_obj;
	md_obj->num_deps = 1;

	read_unlock(&client->res_lock);

	md = cxi_map(lni_obj->lni, cmd->va, cmd->len,
		     cmd->flags | CXI_MAP_USER_ADDR, &hints);
	if (IS_ERR(md)) {
		rc = PTR_ERR(md);
		goto free_obj;
	}
	md_obj->md = md;

	idr_preload(GFP_KERNEL);
	write_lock(&client->res_lock);
	rc = idr_alloc(&client->md_idr, md_obj, md->id, md->id + 1, GFP_NOWAIT);
	write_unlock(&client->res_lock);
	idr_preload_end();

	if (rc < 0)
		goto idr_full;

	resp.id = rc;
	resp.md = *md;

	rc = copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len);
	if (rc)
		goto copy_failed;

	return 0;

copy_failed:
	write_lock(&client->res_lock);
	idr_remove(&client->md_idr, resp.id);
	write_unlock(&client->res_lock);
idr_full:
	rc = cxi_unmap(md_obj->md);
	if (rc < 0)
		pr_err("cxi_unmap failed %d\n", rc);
free_obj:
	free_obj(md_obj);

	return rc;
}

static int cxi_user_atu_unmap(struct user_client *client,
			      const void *cmd_in,
			      void *resp_out, size_t *resp_out_len)
{
	struct ucxi_obj *md_obj;
	const struct cxi_atu_unmap_cmd *cmd = cmd_in;

	write_lock(&client->res_lock);

	md_obj = idr_find(&client->md_idr, cmd->id);
	if (md_obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	/* Ensure no other objects refer to this MD */
	if (atomic_read(&md_obj->refs) != 0) {
		write_unlock(&client->res_lock);
		return -EBUSY;
	}

	/* Remove the MD from the reference list */
	idr_remove(&client->md_idr, cmd->id);

	write_unlock(&client->res_lock);

	free_md_obj(0, md_obj, client);

	return 0;
}

static int cxi_user_update_md(struct user_client *client,
				const void *cmd_in,
				void *resp_out, size_t *resp_out_len)
{
	int rc;
	struct ucxi_obj *md_obj;
	const struct cxi_atu_update_md_cmd *cmd = cmd_in;

	write_lock(&client->res_lock);

	md_obj = idr_find(&client->md_idr, cmd->id);
	if (md_obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	rc = cxi_update_md(md_obj->md, cmd->va, cmd->len, cmd->flags);

	write_unlock(&client->res_lock);

	return rc;
}

static int cxi_user_map_csrs(struct user_client *client,
			     const void *cmd_in,
			     void *resp_out, size_t *resp_out_len)
{
	int rc;
	const struct cxi_map_csrs_cmd *cmd = cmd_in;
	struct cxi_map_csrs_resp resp = {};
	struct cxi_mmap_info *mminfo;
	phys_addr_t base;
	size_t len;

	if (client->csrs_mminfo)
		return -EALREADY;

	/* Allocate mmap info */
	mminfo = kzalloc(sizeof(*mminfo), GFP_KERNEL);
	if (!mminfo)
		return -ENOMEM;

	/* Create mmap entry for the CSRs */
	cxi_get_csrs_range(client->ucxi->dev, &base, &len);
	fill_mmap_info(client, mminfo, (uintptr_t)base, len, MMAP_PHYSICAL);
	client->csrs_mminfo = mminfo;
	mminfo_pre_mmap(client, mminfo, 1);
	resp.csr = mminfo->mminfo;

	/* Return the response to user space */
	if (copy_to_user(cmd->resp, &resp, sizeof(resp))) {
		rc = -EFAULT;
		goto free_mminfo;
	}

	return 0;

free_mminfo:
	client->csrs_mminfo = NULL;
	mminfo_unmap(client, mminfo, 1);
	kfree(mminfo);

	return rc;
}

/* Contains no useful information. The purpose is to notify the owner
 * that an interrupt has arrived, through its poll() operation.
 */
static ssize_t ucxi_wait_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	buf[0] = '\n';
	buf[1] = 0;

	return 1;
}

#define ATTR(_name, _mode)					\
	struct attribute ucxi_##_name##_attr = {		\
		.name = __stringify(_name), .mode = _mode,	\
	}

static ATTR(intr, 0444);

static struct attribute *ucxi_wait_attrs[] = {
	&ucxi_intr_attr,
	NULL,
};
ATTRIBUTE_GROUPS(ucxi_wait);

static const struct sysfs_ops ucxi_sysfs_ops = {
	.show   = ucxi_wait_show,
};

static struct kobj_type ktype_wait_attrs = {
	.sysfs_ops      = &ucxi_sysfs_ops,
	.default_groups = ucxi_wait_groups,
};

/* Wait object callback */
static void wait_callback(void *data)
{
	struct kernfs_node *dirent = data;

	sysfs_notify_dirent(dirent);
}

enum {
	CXI_USER_EQ_DEP_LNI = 0,
	CXI_USER_EQ_DEP_MD,
	CXI_USER_EQ_DEP_EVENT_WAIT,
	CXI_USER_EQ_DEP_STATUS_WAIT,
	CXI_USER_EQ_DEP_RESIZE_MD,
	CXI_USER_EQ_DEP_MAX,
};

static int cxi_user_eq_alloc(struct user_client *client,
			     const void *cmd_in,
			     void *resp_out, size_t *resp_out_len)
{
	int rc;
	struct cxi_eq *eq;
	const struct cxi_eq_alloc_cmd *cmd = cmd_in;
	struct cxi_eq_alloc_resp resp = {};
	struct ucxi_obj *lni_obj;
	struct ucxi_obj *eq_obj;
	struct ucxi_obj *md_obj;
	struct ucxi_obj *wait_obj;
	struct ucxi_wait *event_wait;
	struct ucxi_wait *status_wait;
	struct cxi_eq_attr attr = {};
	struct cxi_mmap_info *mminfo;
	phys_addr_t csr_addr;
	size_t csr_size;

	/* Allocate EQ Object with dependencies on LNI, optional MD and
	 * optional Wait Object.
	 */
	eq_obj = alloc_obj(CXI_USER_EQ_DEP_MAX);
	if (eq_obj == NULL)
		return -ENOMEM;
	eq_obj->num_deps = CXI_USER_EQ_DEP_MAX;

	read_lock(&client->res_lock);

	/* Get Logical Network Interface reference */
	lni_obj = idr_find(&client->lni_idr, cmd->lni);
	if (lni_obj == NULL) {
		read_unlock(&client->res_lock);
		rc = -EINVAL;
		goto free_eq_obj;
	}

	/* Increment the LNI ref count for the event queue */
	atomic_inc(&lni_obj->refs);
	eq_obj->deps[CXI_USER_EQ_DEP_LNI] = lni_obj;

	if (!(cmd->attr.flags & CXI_EQ_PASSTHROUGH)) {
		/* Get MD reference */
		md_obj = idr_find(&client->md_idr, cmd->queue_md);
		if (md_obj == NULL) {
			read_unlock(&client->res_lock);
			rc = -EINVAL;
			goto free_eq_obj;
		}

		atomic_inc(&md_obj->refs);
		eq_obj->deps[CXI_USER_EQ_DEP_MD] = md_obj;
	} else {
		md_obj = NULL;
	}

	/* Get (optional) event wait object reference */
	if (cmd->event_wait) {
		wait_obj = idr_find(&client->wait_idr, cmd->event_wait);
		if (wait_obj == NULL || wait_obj->wait->going_away) {
			read_unlock(&client->res_lock);
			rc = -EINVAL;
			goto free_eq_obj;
		}

		atomic_inc(&wait_obj->refs);
		eq_obj->deps[CXI_USER_EQ_DEP_EVENT_WAIT] = wait_obj;
		event_wait = wait_obj->wait;
	} else {
		event_wait = NULL;
	}

	/* Get (optional) status wait object reference */
	if (cmd->status_wait) {
		wait_obj = idr_find(&client->wait_idr, cmd->status_wait);
		if (wait_obj == NULL || wait_obj->wait->going_away) {
			read_unlock(&client->res_lock);
			rc = -EINVAL;
			goto free_eq_obj;
		}

		atomic_inc(&wait_obj->refs);
		eq_obj->deps[CXI_USER_EQ_DEP_STATUS_WAIT] = wait_obj;
		status_wait = wait_obj->wait;
	} else {
		status_wait = NULL;
	}

	read_unlock(&client->res_lock);

	attr = cmd->attr;
	attr.flags |= CXI_EQ_USER;

	/* Allocate the event queue */
	eq = cxi_eq_alloc(lni_obj->lni,
			  md_obj ? md_obj->md : NULL,
			  &attr,
			  event_wait ? wait_callback : NULL,
			  event_wait ? event_wait->dirent : NULL,
			  status_wait ? wait_callback : NULL,
			  status_wait ? status_wait->dirent : NULL);
	if (IS_ERR(eq)) {
		rc = PTR_ERR(eq);
		goto free_eq_obj;
	}

	/* Associate the event queue with the allocated object */
	eq_obj->eq = eq;

	/* Create a reference to the allocated object */
	idr_preload(GFP_KERNEL);
	write_lock(&client->res_lock);
	rc = idr_alloc(&client->eq_idr, eq_obj,
		       eq->eqn, eq->eqn + 1, GFP_NOWAIT);
	write_unlock(&client->res_lock);
	idr_preload_end();
	if (rc < 0)
		goto free_eq;
	resp.eq = rc;

	rc = cxi_eq_user_info(eq, &csr_addr, &csr_size);
	if (rc)
		goto free_eq_idr;

	/* Allocate mmap info */
	mminfo = kcalloc(1, sizeof(*mminfo), GFP_KERNEL);
	if (!mminfo)
		goto free_eq_idr;

	/* Create mmap entry for the csrs */
	fill_mmap_info(client, &mminfo[0], (uintptr_t)csr_addr,
		       csr_size, MMAP_PHYSICAL);
	mminfo[0].obj = eq_obj;

	/* Build the event queue Object response for user space */
	resp.csr = mminfo[0].mminfo;

	/* Return the response to user space */
	rc = copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len);
	if (rc)
		goto free_eq_mmap;

	eq_obj->mminfo = mminfo;

	mminfo_pre_mmap(client, mminfo, 1);

	return 0;

free_eq_mmap:
	kfree(mminfo);
free_eq_idr:
	write_lock(&client->res_lock);
	idr_remove(&client->eq_idr, resp.eq);
	write_unlock(&client->res_lock);
free_eq:
	cxi_eq_free(eq);
free_eq_obj:
	free_obj(eq_obj);

	return rc;
}

static int cxi_user_eq_free(struct user_client *client,
			    const void *cmd_in,
			    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_eq_free_cmd *cmd = cmd_in;
	struct ucxi_obj *eq_obj;

	write_lock(&client->res_lock);

	/* Get event queue object */
	eq_obj = idr_find(&client->eq_idr, cmd->eq);
	if (eq_obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	/* Ensure no other objects refer to this event queue */
	if (atomic_read(&eq_obj->refs) != 0 ||
	    atomic_read(&eq_obj->mappings) != 0) {
		write_unlock(&client->res_lock);
		return -EBUSY;
	}

	/* Remove the event queue from the reference list */
	idr_remove(&client->eq_idr, cmd->eq);

	write_unlock(&client->res_lock);

	/* Free the event queue object */
	free_eq_obj(0, eq_obj, client);

	return 0;
}

static int cxi_user_eq_resize(struct user_client *client,
			      const void *cmd_in,
			      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_eq_resize_cmd *cmd = cmd_in;
	struct ucxi_obj *eq_obj;
	struct ucxi_obj *md_obj;
	int rc;

	read_lock(&client->res_lock);

	/* Get EQ reference */
	eq_obj = idr_find(&client->eq_idr, cmd->eq_hndl);
	if (eq_obj == NULL) {
		read_unlock(&client->res_lock);
		return -EINVAL;
	}

	/* Get (optional) MD reference */
	md_obj = idr_find(&client->md_idr, cmd->queue_md);
	if (md_obj)
		atomic_inc(&md_obj->refs);

	atomic_inc(&eq_obj->refs);

	read_unlock(&client->res_lock);

	/* Serialize all client resize()/resize_complete() calls and updates to
	 * EQ dependencies.
	 */
	mutex_lock(&client->eq_resize_mutex);

	rc = cxi_eq_resize(eq_obj->eq, cmd->queue, cmd->queue_len,
			   md_obj ? md_obj->md : NULL);
	if (rc) {
		pr_debug("EQ resize failed: %d\n", rc);

		if (md_obj)
			atomic_dec(&md_obj->refs);
	} else {
		eq_obj->deps[CXI_USER_EQ_DEP_RESIZE_MD] = md_obj;
	}

	mutex_unlock(&client->eq_resize_mutex);

	atomic_dec(&eq_obj->refs);

	return rc;
}

static int cxi_user_eq_resize_complete(struct user_client *client,
				       const void *cmd_in,
				       void *resp_out, size_t *resp_out_len)
{
	const struct cxi_eq_resize_complete_cmd *cmd = cmd_in;
	struct ucxi_obj *eq_obj;
	int rc;

	read_lock(&client->res_lock);

	/* Get event queue object */
	eq_obj = idr_find(&client->eq_idr, cmd->eq_hndl);
	if (eq_obj == NULL) {
		read_unlock(&client->res_lock);
		return -EINVAL;
	}

	atomic_inc(&eq_obj->refs);

	read_unlock(&client->res_lock);

	/* Serialize all client resize()/resize_complete() calls and updates to
	 * EQ dependencies.
	 */
	mutex_lock(&client->eq_resize_mutex);

	rc = cxi_eq_resize_complete(eq_obj->eq);
	if (rc) {
		pr_debug("EQ resize completion failed: %d\n", rc);
	} else {
		/* After resize, the original MD is no longer used. */
		if (eq_obj->deps[CXI_USER_EQ_DEP_MD])
			atomic_dec(&eq_obj->deps[CXI_USER_EQ_DEP_MD]->refs);

		/* Replace the original MD with the resize MD. */
		eq_obj->deps[CXI_USER_EQ_DEP_MD] =
				eq_obj->deps[CXI_USER_EQ_DEP_RESIZE_MD];
		eq_obj->deps[CXI_USER_EQ_DEP_RESIZE_MD] = NULL;
	}

	mutex_unlock(&client->eq_resize_mutex);

	atomic_dec(&eq_obj->refs);

	return rc;
}

static int cxi_user_pte_alloc(struct user_client *client,
			      const void *cmd_in,
			      void *resp_out, size_t *resp_out_len)
{
	// TODO: revisit issue of validating enough "reserved" slots in EQ
	const struct cxi_pte_alloc_cmd *cmd = cmd_in;
	struct cxi_pte_alloc_resp resp = {};
	struct ucxi_obj *pte_obj;
	struct ucxi_obj *lni_obj;
	struct cxi_eq *evtq;
	struct cxi_pte *pte;
	int rc;

	/* Zeroed space for LNI and (optional) EQ */
	pte_obj = alloc_obj(2);
	if (pte_obj == NULL)
		return -ENOMEM;

	/* Find LNI and EVTQ by their handles */
	read_lock(&client->res_lock);

	lni_obj = idr_find(&client->lni_idr, cmd->lni_hndl);
	if (lni_obj == NULL) {
		read_unlock(&client->res_lock);
		rc = -EINVAL;
		goto free_obj;
	}
	/* Keep track of LNI, and increment refs */
	pte_obj->deps[pte_obj->num_deps++] = lni_obj;
	atomic_inc(&lni_obj->refs);

	evtq = NULL;
	if (cmd->evtq_hndl != C_EQ_NONE) {
		struct ucxi_obj *eq_obj;

		eq_obj = idr_find(&client->eq_idr, cmd->evtq_hndl);
		if (eq_obj == NULL) {
			read_unlock(&client->res_lock);
			rc = -EINVAL;
			goto free_obj;
		}
		/* Keep track of EQ, and increment refs */
		pte_obj->deps[pte_obj->num_deps++] = eq_obj;
		atomic_inc(&eq_obj->refs);
		evtq = eq_obj->eq;
	}

	read_unlock(&client->res_lock);

	/* Call the core function */
	pte = cxi_pte_alloc(lni_obj->lni, evtq, &cmd->opts);
	if (IS_ERR(pte)) {
		rc = PTR_ERR(pte);
		goto free_obj;
	}
	pte_obj->pte = pte;

	/* Force the pte_idr to use pte_number for the index */
	idr_preload(GFP_KERNEL);
	write_lock(&client->res_lock);

	rc = idr_alloc(&client->pte_idr, pte_obj, pte->id, pte->id + 1,
		       GFP_NOWAIT);

	write_unlock(&client->res_lock);
	idr_preload_end();

	if (rc < 0)
		goto free_pte;

	/* Return PTE handle and the PtlTE index number */
	resp.pte_number = pte->id;

	rc = copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len);
	if (rc)
		goto release_idr;

	return 0;

release_idr:
	write_lock(&client->res_lock);
	idr_remove(&client->pte_idr, resp.pte_number);
	write_unlock(&client->res_lock);
free_pte:
	cxi_pte_free(pte);
free_obj:
	free_obj(pte_obj);

	return rc;
}

static int cxi_user_pte_free(struct user_client *client,
			     const void *cmd_in,
			     void *resp_out, size_t *resp_out_len)
{
	const struct cxi_pte_free_cmd *cmd = cmd_in;
	struct ucxi_obj *pte_obj;

	/* Find the PTE by handle, and remove */
	write_lock(&client->res_lock);

	pte_obj = idr_find(&client->pte_idr, cmd->pte_number);
	if (pte_obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	/* If this object is in use, we cannot destroy it */
	if (atomic_read(&pte_obj->refs) != 0) {
		write_unlock(&client->res_lock);
		return -EBUSY;
	}

	/* Destroy the handle */
	idr_remove(&client->pte_idr, cmd->pte_number);

	write_unlock(&client->res_lock);

	/* Destroy the PTE, the object, and clear reference counts */
	free_pte_obj(0, pte_obj, client);

	return 0;
}

static int cxi_user_pte_map(struct user_client *client,
			    const void *cmd_in,
			    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_pte_map_cmd *cmd = cmd_in;
	struct cxi_pte_map_resp resp = {};
	struct ucxi_obj *pte_obj;
	struct ucxi_obj *dom_obj;
	struct ucxi_obj *map_obj;
	unsigned int pte_index;
	int rc;

	/* Zeroed space for PTE and DOMAIN */
	map_obj = alloc_obj(2);
	if (map_obj == NULL)
		return -ENOMEM;

	/* Find PTE and domain by handle */
	read_lock(&client->res_lock);

	/* Warning: order dependent -- pte, domain */
	pte_obj = idr_find(&client->pte_idr, cmd->pte_number);
	if (pte_obj == NULL) {
		read_unlock(&client->res_lock);
		rc = -EINVAL;
		goto free_obj;
	}
	map_obj->deps[map_obj->num_deps++] = pte_obj;
	atomic_inc(&pte_obj->refs);

	dom_obj = idr_find(&client->domain_idr, cmd->domain_hndl);
	if (dom_obj == NULL) {
		read_unlock(&client->res_lock);
		rc = -EINVAL;
		goto free_obj;
	}
	map_obj->deps[map_obj->num_deps++] = dom_obj;
	atomic_inc(&dom_obj->refs);

	read_unlock(&client->res_lock);

	/* Call the core function */
	rc = cxi_pte_map(pte_obj->pte, dom_obj->domain,
			 cmd->pid_offset, cmd->is_multicast,
			 &pte_index);
	if (rc < 0)
		goto free_obj;

	/* Record the pte_index value in the object */
	map_obj->pte_index = pte_index;

	/* Force the pte_map_idr to use pte_index for the index */
	idr_preload(GFP_KERNEL);
	write_lock(&client->res_lock);

	rc = idr_alloc(&client->pte_map_idr, map_obj, pte_index, pte_index+1,
		       GFP_NOWAIT);

	write_unlock(&client->res_lock);
	idr_preload_end();

	if (rc < 0)
		goto free_mapping;

	/* Return the map index in the response structure */
	resp.pte_index = pte_index;

	rc = copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len);
	if (rc)
		goto release_idr;

	return 0;

release_idr:
	write_lock(&client->res_lock);
	idr_remove(&client->pte_map_idr, resp.pte_index);
	write_unlock(&client->res_lock);
free_mapping:
	cxi_pte_unmap(pte_obj->pte, dom_obj->domain, pte_index);
free_obj:
	free_obj(map_obj);

	return rc;
}

static int cxi_user_pte_unmap(struct user_client *client,
			      const void *cmd_in,
			      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_pte_unmap_cmd *cmd = cmd_in;
	struct ucxi_obj *map_obj;

	/* Find PTE and domain by handle */
	write_lock(&client->res_lock);

	map_obj = idr_find(&client->pte_map_idr, cmd->pte_index);
	if (map_obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	/* If this object is in use, we cannot destroy it */
	if (atomic_read(&map_obj->refs) != 0) {
		write_unlock(&client->res_lock);
		return -EBUSY;
	}

	/* Destroy the handle */
	idr_remove(&client->pte_map_idr, cmd->pte_index);

	write_unlock(&client->res_lock);

	/* Destroy the map object */
	free_pte_map(0, map_obj, client);

	return 0;
}

static int cxi_user_pte_le_invalidate(struct user_client *client,
				      const void *cmd_in,
				      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_pte_le_invalidate_cmd *cmd = cmd_in;
	struct ucxi_obj *pte_obj;

	/* Take reference to prevent PtlTE from disappearing during cleanup. */
	write_lock(&client->res_lock);
	pte_obj = idr_find(&client->pte_idr, cmd->pte_index);
	if (pte_obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}
	atomic_inc(&pte_obj->refs);
	write_unlock(&client->res_lock);

	cxi_pte_le_invalidate(pte_obj->pte, cmd->buffer_id, cmd->list);

	atomic_dec(&pte_obj->refs);

	return 0;
}

static int cxi_user_pte_status(struct user_client *client,
			       const void *cmd_in,
			       void *resp_out, size_t *resp_out_len)
{
	const struct cxi_pte_status_cmd *cmd = cmd_in;
	struct cxi_pte_status_resp resp = {};
	struct cxi_pte_status status = {};
	struct ucxi_obj *pte_obj;
	int rc;

	/* Take reference to prevent PtlTE from disappearing during cleanup. */
	write_lock(&client->res_lock);
	pte_obj = idr_find(&client->pte_idr, cmd->pte_index);
	if (pte_obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}
	atomic_inc(&pte_obj->refs);
	write_unlock(&client->res_lock);

	/* Response fields are also used for input */
	if (copy_from_user(&status, cmd->resp, sizeof(resp)))
		return -EFAULT;

	rc = cxi_pte_status(pte_obj->pte, &status);

	atomic_dec(&pte_obj->refs);

	if (rc)
		return rc;

	resp.status = status;

	if (copy_to_user(cmd->resp, &resp, sizeof(resp)))
		return -EFAULT;

	return 0;
}

static int cxi_user_pte_transition_sm(struct user_client *client,
				      const void *cmd_in,
				      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_pte_transition_sm_cmd *cmd = cmd_in;
	struct ucxi_obj *pte_obj;
	int rc;

	/* Take reference to prevent PtlTE from disappearing during cleanup. */
	write_lock(&client->res_lock);
	pte_obj = idr_find(&client->pte_idr, cmd->pte_index);
	if (pte_obj == NULL) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}
	atomic_inc(&pte_obj->refs);
	write_unlock(&client->res_lock);

	rc = cxi_pte_transition_sm(pte_obj->pte, cmd->drop_count);

	atomic_dec(&pte_obj->refs);

	return rc;
}

static int cxi_user_wait_alloc(struct user_client *client,
			       const void *cmd_in,
			       void *resp_out, size_t *resp_out_len)
{
	int rc;
	const struct cxi_wait_alloc_cmd *cmd = cmd_in;
	struct cxi_wait_alloc_resp resp = {};
	struct ucxi_obj *lni_obj;
	struct ucxi_obj *wait_obj;
	struct ucxi_wait *wait;

	/* Allocate event queue Object */
	wait_obj = alloc_obj(1);
	if (wait_obj == NULL)
		return -ENOMEM;

	wait = kzalloc(sizeof(*wait), GFP_KERNEL);
	if (!wait) {
		rc = -ENOMEM;
		goto free_obj;
	}

	read_lock(&client->res_lock);

	/* Get Logical Network Interface reference */
	lni_obj = idr_find(&client->lni_idr, cmd->lni);
	if (lni_obj == NULL) {
		read_unlock(&client->res_lock);
		rc = -EINVAL;
		goto free_obj;
	}

	atomic_inc(&lni_obj->refs);
	wait_obj->deps[0] = lni_obj;
	wait_obj->num_deps = 1;

	read_unlock(&client->res_lock);

	wait_obj->wait = wait;

	/* Allocate an id to return to userspace */
	idr_preload(GFP_KERNEL);
	write_lock(&client->res_lock);

	rc = idr_alloc(&client->wait_idr, wait_obj, 1, 0, GFP_NOWAIT);

	write_unlock(&client->res_lock);
	idr_preload_end();

	if (rc < 0)
		goto free_obj;

	resp.client_id = client->id;
	resp.wait = rc;

	/* Create the sysfs notification file */
	rc = kobject_init_and_add(&wait->kobj, &ktype_wait_attrs,
				  client->wait_objs_kobj, "%d", resp.wait);
	if (rc < 0)
		goto release_idr;

	wait->dirent = sysfs_get_dirent(wait->kobj.sd, "intr");
	if (!wait->dirent) {
		rc = -ENODEV;
		goto release_idr;
	}

	if (copy_to_user(cmd->resp, &resp, sizeof(resp))) {
		rc = -EFAULT;
		goto free_dirent;
	}

	return 0;

free_dirent:
	sysfs_put(wait->dirent);

release_idr:
	kobject_put(&wait->kobj);
	write_lock(&client->res_lock);
	idr_remove(&client->wait_idr, resp.wait);
	write_unlock(&client->res_lock);

free_obj:
	kfree(wait);
	free_obj(wait_obj);

	return rc;
}

static int cxi_user_wait_free(struct user_client *client,
			      const void *cmd_in,
			      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_wait_free_cmd *cmd = cmd_in;
	struct ucxi_obj *wait_obj;

	write_lock(&client->res_lock);

	wait_obj = idr_find(&client->wait_idr, cmd->wait);
	if (wait_obj == NULL || wait_obj->wait->going_away) {
		write_unlock(&client->res_lock);
		return -EINVAL;
	}

	if (atomic_read(&wait_obj->refs) != 0) {
		write_unlock(&client->res_lock);
		return -EBUSY;
	}

	/* going_away protects that object from being used again. This
	 * protects against a race, where we need to remove the sysfs
	 * entry before the IDR, which can't be done under lock.
	 */
	wait_obj->wait->going_away = true;

	write_unlock(&client->res_lock);

	free_wait_obj(0, wait_obj, client);

	write_lock(&client->res_lock);
	idr_remove(&client->wait_idr, cmd->wait);
	write_unlock(&client->res_lock);

	return 0;
}

static int cxi_user_sbus_op_reset(struct user_client *client,
				  const void *cmd_in,
				  void *resp_out, size_t *resp_out_len)
{
	return cxi_sbus_op_reset(client->ucxi->dev);
}

static int cxi_user_sbus_op(struct user_client *client, const void *cmd_in,
			    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_sbus_op_cmd *cmd = cmd_in;
	struct cxi_sbus_op_resp resp;
	int rc;

	rc = cxi_sbus_op(client->ucxi->dev, &cmd->params,
			 &resp.rsp_data, &resp.result_code, &resp.overrun);

	if (rc == 0 &&
	    copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len))
		rc = -EFAULT;

	return rc;
}

static int cxi_user_serdes_op(struct user_client *client, const void *cmd_in,
			      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_serdes_op_cmd *cmd = cmd_in;
	struct cxi_serdes_op_resp resp = {};
	int rc;

	rc = cxi_serdes_op(client->ucxi->dev, cmd->serdes_sel,
			   cmd->serdes_op, cmd->data, cmd->timeout,
			   cmd->flags, &resp.result);

	if (rc == 0 &&
	    copy_response(client, &resp, sizeof(resp), resp_out, resp_out_len))
		rc = -EFAULT;

	return rc;
}

static int cxi_get_dev_properties(struct user_client *client,
				  const void *cmd_in,
				  void *resp_out, size_t *resp_out_len)
{
	const struct cxi_properties_info *info = &client->ucxi->dev->prop;

	return copy_response(client, info, sizeof(*info),
			     resp_out, resp_out_len);
}

static int cxi_user_eq_adjust_reserved_fc(struct user_client *client,
					  const void *cmd_in, void *resp_out,
					  size_t *resp_out_len)
{
	const struct cxi_eq_adjust_reserved_fc_cmd *cmd = cmd_in;
	struct cxi_eq_adjust_reserved_fc_resp resp = {};
	struct ucxi_obj *eq_obj;
	int rc;

	read_lock(&client->res_lock);

	eq_obj = idr_find(&client->eq_idr, cmd->eq_hndl);
	if (!eq_obj) {
		read_unlock(&client->res_lock);
		return -EINVAL;
	}

	atomic_inc(&eq_obj->refs);
	read_unlock(&client->res_lock);

	rc = cxi_eq_adjust_reserved_fc(eq_obj->eq, cmd->value);
	if (rc >= 0) {
		resp.reserved_fc = rc;
		if (copy_to_user(cmd->resp, &resp, sizeof(resp)))
			rc = -EFAULT;
		else
			rc = 0;
	}

	atomic_dec(&eq_obj->refs);

	return rc;
}

static int cxi_user_inbound_wait(struct user_client *client,
				 const void *cmd_in,
				 void *resp_out,
				 size_t *resp_out_len)
{
	return cxi_inbound_wait(client->ucxi->dev);
}

static int cxi_user_dev_info_get(struct user_client *client,
				 const void *cmd_in,
				 void *resp_out, size_t *resp_out_len)
{
	const struct cxi_dev_info_get_cmd *cmd = cmd_in;
	struct cxi_dev_info_get_resp resp = {};
	int rc;

	rc = cxi_dev_info_get(client->ucxi->dev, &resp.devinfo);

	if (rc)
		return rc;

	if (copy_to_user(cmd->resp, &resp, sizeof(resp)))
		return -EFAULT;

	return 0;
}

static int cxi_user_dev_alloc_rx_profile(struct user_client *client,
					 const void *cmd_in,
					 void *resp_out, size_t *resp_out_len)
{
	const struct cxi_dev_alloc_rx_profile_cmd  *cmd = cmd_in;
	struct cxi_dev_alloc_rx_profile_resp       resp;
	struct cxi_rx_attr   rx_attr;
	int                  ret;

	rx_attr.vni_attr.match    = cmd->vni_attr.match;
	rx_attr.vni_attr.ignore   = cmd->vni_attr.ignore;
	strncpy(rx_attr.vni_attr.name, cmd->vni_attr.name,
		ARRAY_SIZE(rx_attr.vni_attr.name));

	/* TODO: other rx attributes for creation */

	ret = cxi_dev_alloc_rx_profile(client->ucxi->dev, &rx_attr, &resp.id);
	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int cxi_user_dev_get_rx_profile_ids(struct user_client *client,
					   const void *cmd_in,
					   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_dev_get_rx_profile_ids_cmd   *cmd = cmd_in;
	struct cxi_dev_get_rx_profile_ids_resp        resp;
	unsigned int   *ids;
	size_t         bytes;
	int            ret, ret2;

	if (cmd->max_ids && !cmd->ids)
		return -EINVAL;

	/* allocate bounce buffer */

	ids = kcalloc(cmd->max_ids, sizeof(*ids), GFP_KERNEL);
	if (cmd->max_ids && !ids)
		return -ENOMEM;

	/* retrieve the ids */

	ret = cxi_dev_get_rx_profile_ids(client->ucxi->dev,
					 cmd->max_ids,
					 ids,
					 &resp.num_ids);

	if (ret)
		kfree(ids);

	switch (ret) {
	case 0:
		break;
	case -ENOSPC:
		goto copy_response;
	default:
		return ret;
	}

	ret = copy_response(client, ids, resp.num_ids * sizeof(*ids),
			    cmd->ids, &bytes);
	kfree(ids);
	if (ret)
		return ret;

copy_response:
	ret2 = copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);

	return (ret2) ? ret2 : ret;
}

static int cxi_user_rx_profile_get_info(struct user_client *client,
					const void *cmd_in,
					void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rx_profile_get_info_cmd  *cmd = cmd_in;
	struct cxi_rx_profile_get_info_resp       resp;
	struct cxi_rx_attr              rx_attr;
	struct cxi_rxtx_profile_state   state;
	int   ret;

	ret = cxi_rx_profile_get_info(client->ucxi->dev, cmd->id,
				      &rx_attr, &state);

	if (ret)
		return ret;

	resp.vni_attr.match    = rx_attr.vni_attr.match;
	resp.vni_attr.ignore   = rx_attr.vni_attr.ignore;
	strncpy(resp.vni_attr.name, rx_attr.vni_attr.name,
		ARRAY_SIZE(resp.vni_attr.name));

	/* TODO: other rx attributes */

	resp.state.released  = atomic_read(&state.released);
	resp.state.revoked   = state.revoked;
	resp.state.refcount  = refcount_read(&state.refcount);

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int cxi_user_rx_profile_release(struct user_client *client,
				       const void *cmd_in,
				       void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rx_profile_release_cmd   *cmd = cmd_in;

	return cxi_rx_profile_release(client->ucxi->dev, cmd->id);
}

static int cxi_user_rx_profile_revoke(struct user_client *client,
				      const void *cmd_in,
				      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rx_profile_revoke_cmd   *cmd = cmd_in;

	return cxi_rx_profile_revoke(client->ucxi->dev, cmd->id);
}

static int
cxi_user_rx_profile_add_ac_entry(struct user_client *client,
				 const void *cmd_in,
				 void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rx_profile_add_ac_entry_cmd  *cmd = cmd_in;
	struct cxi_rx_profile_add_ac_entry_resp       resp;
	struct cxi_dev        *dev = client->ucxi->dev;
	struct cxi_rx_profile *rx_profile;
	union cxi_ac_data     data;
	int    ret;

	switch (cmd->type) {
	case CXI_AC_UID:
		data.uid = cmd->uid;
		break;
	case CXI_AC_GID:
		data.gid = cmd->gid;
		break;
	case CXI_AC_OPEN:
		break;
	default:
		return -EDOM;
	}

	ret = cxi_rx_profile_find_inc_refcount(dev,
					       cmd->rx_profile_id,
					       &rx_profile);

	if (ret)
		return ret;

	ret = cxi_rx_profile_add_ac_entry(rx_profile, cmd->type,
					  &data, &resp.ac_entry_id);
	cxi_rx_profile_dec_refcount(dev, rx_profile);

	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int
cxi_user_rx_profile_remove_ac_entry(struct user_client *client,
				   const void *cmd_in,
				   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rx_profile_remove_ac_entry_cmd  *cmd = cmd_in;
	struct cxi_dev        *dev = client->ucxi->dev;
	struct cxi_rx_profile  *rx_profile;
	int    ret;

	ret = cxi_rx_profile_find_inc_refcount(dev,
					      cmd->rx_profile_id,
					      &rx_profile);

	if (ret)
		return ret;

	ret = cxi_rx_profile_remove_ac_entry(rx_profile,
					    cmd->ac_entry_id);
	cxi_rx_profile_dec_refcount(dev, rx_profile);

	return ret;
}

static int
cxi_user_rx_profile_get_ac_entry_ids(struct user_client *client,
				    const void *cmd_in,
				    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rx_profile_get_ac_entry_ids_cmd  *cmd = cmd_in;
	struct cxi_rx_profile_get_ac_entry_ids_resp       resp;
	struct cxi_dev         *dev = client->ucxi->dev;
	struct cxi_rx_profile  *rx_profile;
	int    ret;

	ret = cxi_rx_profile_find_inc_refcount(dev,
					      cmd->rx_profile_id,
					      &rx_profile);
	if (ret)
		return ret;

	ret = cxi_rx_profile_get_ac_entry_ids(rx_profile, cmd->max_ids,
					     cmd->ac_entry_ids, &resp.num_ids);

	cxi_rx_profile_dec_refcount(dev, rx_profile);

	switch (ret) {
	case 0:
		return copy_response(client, &resp, sizeof(resp),
				     resp_out, resp_out_len);
	case -ENOSPC:
		ret = copy_response(client, &resp, sizeof(resp),
				     resp_out, resp_out_len);
		return (ret) ? ret : -ENOSPC;
	default:
		return ret;
	}
}

static int
cxi_user_rx_profile_get_ac_entry_data_by_id(struct user_client *client,
					   const void *cmd_in,
					   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rx_profile_get_ac_entry_data_by_id_cmd   *cmd = cmd_in;
	struct cxi_rx_profile_get_ac_entry_data_by_id_resp        resp;
	struct cxi_dev         *dev = client->ucxi->dev;
	struct cxi_rx_profile   *rx_profile;
	enum cxi_ac_type       ac_type;
	union cxi_ac_data      ac_data;
	int    ret;

	ret = cxi_rx_profile_find_inc_refcount(dev,
					      cmd->rx_profile_id,
					      &rx_profile);
	if (ret)
		return ret;

	ret = cxi_rx_profile_get_ac_entry_data(rx_profile, cmd->ac_entry_id,
					       &ac_type, &ac_data);

	cxi_rx_profile_dec_refcount(dev, rx_profile);
	if (ret)
		return ret;

	resp.type = ac_type;

	switch (ac_type) {
	case CXI_AC_UID:
		resp.uid = ac_data.uid;
		break;
	case CXI_AC_GID:
		resp.gid = ac_data.gid;
		break;
	default:
		break;
	}

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int
cxi_user_rx_profile_get_ac_entry_id_by_data(struct user_client *client,
					   const void *cmd_in,
					   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rx_profile_get_ac_entry_id_by_data_cmd   *cmd = cmd_in;
	struct cxi_rx_profile_get_ac_entry_id_by_data_resp        resp;
	struct cxi_dev        *dev = client->ucxi->dev;
	struct cxi_rx_profile  *rx_profile;
	union cxi_ac_data     data;
	int    ret;

	switch (cmd->type) {
	case CXI_AC_UID:
		data.uid = cmd->uid;
		break;
	case CXI_AC_GID:
		data.gid = cmd->gid;
		break;
	case CXI_AC_OPEN:
		break;
	default:
		return -EDOM;
	}

	ret = cxi_rx_profile_find_inc_refcount(dev,
					      cmd->rx_profile_id,
					      &rx_profile);

	if (ret)
		return ret;

	ret = cxi_rx_profile_get_ac_entry_id_by_data(rx_profile, cmd->type,
						    &data, &resp.ac_entry_id);

	cxi_rx_profile_dec_refcount(dev, rx_profile);
	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}


static int
cxi_user_rx_profile_get_ac_entry_id_by_user(struct user_client *client,
					   const void *cmd_in,
					   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_rx_profile_get_ac_entry_id_by_user_cmd   *cmd = cmd_in;
	struct cxi_rx_profile_get_ac_entry_id_by_user_resp        resp;
	struct cxi_dev         *dev = client->ucxi->dev;
	struct cxi_rx_profile  *rx_profile;
	int    ret;

	ret = cxi_rx_profile_find_inc_refcount(dev,
					      cmd->rx_profile_id,
					      &rx_profile);

	if (ret)
		return ret;

	ret = cxi_rx_profile_get_ac_entry_id_by_user(rx_profile, cmd->uid,
						     cmd->gid,
						     cmd->desired_types,
						     &resp.ac_entry_id);

	cxi_rx_profile_dec_refcount(dev, rx_profile);
	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int cxi_user_dev_alloc_tx_profile(struct user_client *client,
					 const void *cmd_in,
					 void *resp_out, size_t *resp_out_len)
{
	const struct cxi_dev_alloc_tx_profile_cmd  *cmd = cmd_in;
	struct cxi_dev_alloc_tx_profile_resp       resp;
	struct cxi_tx_attr   tx_attr;
	int                  ret;

	tx_attr.vni_attr.match    = cmd->vni_attr.match;
	tx_attr.vni_attr.ignore   = cmd->vni_attr.ignore;
	strncpy(tx_attr.vni_attr.name, cmd->vni_attr.name,
		ARRAY_SIZE(tx_attr.vni_attr.name));

	/* TODO: other TX attributes for creation */

	ret = cxi_dev_alloc_tx_profile(client->ucxi->dev, &tx_attr, &resp.id);
	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int cxi_user_dev_get_tx_profile_ids(struct user_client *client,
					   const void *cmd_in,
					   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_dev_get_tx_profile_ids_cmd   *cmd = cmd_in;
	struct cxi_dev_get_tx_profile_ids_resp        resp;
	unsigned int   *ids;
	size_t         bytes;
	int            ret, ret2;

	if (cmd->max_ids && !cmd->ids)
		return -EINVAL;

	/* allocate bounce buffer */

	ids = kcalloc(cmd->max_ids, sizeof(*ids), GFP_KERNEL);
	if (cmd->max_ids && !ids)
		return -ENOMEM;

	/* retrieve the ids */

	ret = cxi_dev_get_tx_profile_ids(client->ucxi->dev,
					 cmd->max_ids,
					 ids,
					 &resp.num_ids);

	if (ret)
		kfree(ids);

	switch (ret) {
	case 0:
		break;
	case -ENOSPC:
		goto copy_response;
	default:
		return ret;
	}

	ret = copy_response(client, ids, resp.num_ids * sizeof(*ids),
			    cmd->ids, &bytes);
	kfree(ids);
	if (ret)
		return ret;

copy_response:
	ret2 = copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);

	return (ret2) ? ret2 : ret;
}

static int cxi_user_tx_profile_get_info(struct user_client *client,
					const void *cmd_in,
					void *resp_out, size_t *resp_out_len)
{
	const struct cxi_tx_profile_get_info_cmd  *cmd = cmd_in;
	struct cxi_tx_profile_get_info_resp       resp;
	struct cxi_tx_attr              tx_attr;
	struct cxi_rxtx_profile_state   state;
	int   ret;

	ret = cxi_tx_profile_get_info(client->ucxi->dev, cmd->id,
				      &tx_attr, &state);

	if (ret)
		return ret;

	resp.vni_attr.match    = tx_attr.vni_attr.match;
	resp.vni_attr.ignore   = tx_attr.vni_attr.ignore;
	strncpy(resp.vni_attr.name, tx_attr.vni_attr.name,
		ARRAY_SIZE(resp.vni_attr.name));

	/* TODO: other TX attributes */

	resp.state.released  = atomic_read(&state.released);
	resp.state.revoked   = state.revoked;
	resp.state.refcount  = refcount_read(&state.refcount);

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int cxi_user_tx_profile_release(struct user_client *client,
				       const void *cmd_in,
				       void *resp_out, size_t *resp_out_len)
{
	const struct cxi_tx_profile_release_cmd   *cmd = cmd_in;

	return cxi_tx_profile_release(client->ucxi->dev, cmd->id);
}

static int cxi_user_tx_profile_revoke(struct user_client *client,
				      const void *cmd_in,
				      void *resp_out, size_t *resp_out_len)
{
	const struct cxi_tx_profile_revoke_cmd   *cmd = cmd_in;

	return cxi_tx_profile_revoke(client->ucxi->dev, cmd->id);
}

static int
cxi_user_tx_profile_add_ac_entry(struct user_client *client,
				 const void *cmd_in,
				 void *resp_out, size_t *resp_out_len)
{
	const struct cxi_tx_profile_add_ac_entry_cmd  *cmd = cmd_in;
	struct cxi_tx_profile_add_ac_entry_resp       resp;
	struct cxi_dev        *dev = client->ucxi->dev;
	struct cxi_tx_profile *tx_profile;
	union cxi_ac_data     data;
	int    ret;

	switch (cmd->type) {
	case CXI_AC_UID:
		data.uid = cmd->uid;
		break;
	case CXI_AC_GID:
		data.gid = cmd->gid;
		break;
	case CXI_AC_OPEN:
		break;
	default:
		return -EDOM;
	}

	ret = cxi_tx_profile_find_inc_refcount(dev,
					       cmd->tx_profile_id,
					       &tx_profile);

	if (ret)
		return ret;

	ret = cxi_tx_profile_add_ac_entry(tx_profile, cmd->type,
					  &data, &resp.ac_entry_id);
	cxi_tx_profile_dec_refcount(dev, tx_profile);

	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int
cxi_user_tx_profile_remove_ac_entry(struct user_client *client,
				   const void *cmd_in,
				   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_tx_profile_remove_ac_entry_cmd  *cmd = cmd_in;
	struct cxi_dev         *dev = client->ucxi->dev;
	struct cxi_tx_profile  *tx_profile;
	int    ret;

	ret = cxi_tx_profile_find_inc_refcount(dev,
					      cmd->tx_profile_id,
					      &tx_profile);

	if (ret)
		return ret;

	ret = cxi_tx_profile_remove_ac_entry(tx_profile,
					     cmd->ac_entry_id);
	cxi_tx_profile_dec_refcount(dev, tx_profile);

	return ret;
}

static int
cxi_user_tx_profile_get_ac_entry_ids(struct user_client *client,
				    const void *cmd_in,
				    void *resp_out, size_t *resp_out_len)
{
	const struct cxi_tx_profile_get_ac_entry_ids_cmd  *cmd = cmd_in;
	struct cxi_tx_profile_get_ac_entry_ids_resp       resp;
	struct cxi_dev         *dev = client->ucxi->dev;
	struct cxi_tx_profile  *tx_profile;
	int    ret;

	ret = cxi_tx_profile_find_inc_refcount(dev,
					      cmd->tx_profile_id,
					      &tx_profile);
	if (ret)
		return ret;

	ret = cxi_tx_profile_get_ac_entry_ids(tx_profile, cmd->max_ids,
					     cmd->ac_entry_ids, &resp.num_ids);

	cxi_tx_profile_dec_refcount(dev, tx_profile);

	switch (ret) {
	case 0:
		return copy_response(client, &resp, sizeof(resp),
				     resp_out, resp_out_len);
	case -ENOSPC:
		ret = copy_response(client, &resp, sizeof(resp),
				     resp_out, resp_out_len);
		return (ret) ? ret : -ENOSPC;
	default:
		return ret;
	}
}

static int
cxi_user_tx_profile_get_ac_entry_data_by_id(struct user_client *client,
					   const void *cmd_in,
					   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_tx_profile_get_ac_entry_data_by_id_cmd   *cmd = cmd_in;
	struct cxi_tx_profile_get_ac_entry_data_by_id_resp        resp;
	struct cxi_dev         *dev = client->ucxi->dev;
	struct cxi_tx_profile   *tx_profile;
	enum cxi_ac_type       ac_type;
	union cxi_ac_data      ac_data;
	int    ret;

	ret = cxi_tx_profile_find_inc_refcount(dev,
					      cmd->tx_profile_id,
					      &tx_profile);
	if (ret)
		return ret;

	ret = cxi_tx_profile_get_ac_entry_data(tx_profile, cmd->ac_entry_id,
					       &ac_type, &ac_data);

	cxi_tx_profile_dec_refcount(dev, tx_profile);
	if (ret)
		return ret;

	resp.type = ac_type;

	switch (ac_type) {
	case CXI_AC_UID:
		resp.uid = ac_data.uid;
		break;
	case CXI_AC_GID:
		resp.gid = ac_data.gid;
		break;
	default:
		break;
	}

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static int
cxi_user_tx_profile_get_ac_entry_id_by_data(struct user_client *client,
					   const void *cmd_in,
					   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_tx_profile_get_ac_entry_id_by_data_cmd   *cmd = cmd_in;
	struct cxi_tx_profile_get_ac_entry_id_by_data_resp        resp;
	struct cxi_dev        *dev = client->ucxi->dev;
	struct cxi_tx_profile  *tx_profile;
	union cxi_ac_data     data;
	int    ret;

	switch (cmd->type) {
	case CXI_AC_UID:
		data.uid = cmd->uid;
		break;
	case CXI_AC_GID:
		data.gid = cmd->gid;
		break;
	case CXI_AC_OPEN:
		break;
	default:
		return -EDOM;
	}

	ret = cxi_tx_profile_find_inc_refcount(dev,
					      cmd->tx_profile_id,
					      &tx_profile);

	if (ret)
		return ret;

	ret = cxi_tx_profile_get_ac_entry_id_by_data(tx_profile, cmd->type,
						    &data, &resp.ac_entry_id);

	cxi_tx_profile_dec_refcount(dev, tx_profile);
	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}


static int
cxi_user_tx_profile_get_ac_entry_id_by_user(struct user_client *client,
					   const void *cmd_in,
					   void *resp_out, size_t *resp_out_len)
{
	const struct cxi_tx_profile_get_ac_entry_id_by_user_cmd   *cmd = cmd_in;
	struct cxi_tx_profile_get_ac_entry_id_by_user_resp        resp;
	struct cxi_dev         *dev = client->ucxi->dev;
	struct cxi_tx_profile  *tx_profile;
	int    ret;

	ret = cxi_tx_profile_find_inc_refcount(dev,
					      cmd->tx_profile_id,
					      &tx_profile);

	if (ret)
		return ret;

	ret = cxi_tx_profile_get_ac_entry_id_by_user(tx_profile, cmd->uid,
						     cmd->gid,
						     cmd->desired_types,
						     &resp.ac_entry_id);

	cxi_tx_profile_dec_refcount(dev, tx_profile);
	if (ret)
		return ret;

	return copy_response(client, &resp, sizeof(resp),
			     resp_out, resp_out_len);
}

static const struct cmd_info cmds_info[CXI_OP_MAX] = {
	[CXI_OP_LNI_ALLOC] = {
		.req_size   = sizeof(struct cxi_lni_alloc_cmd),
		.name       = "LNI_ALLOC",
		.handler    = cxi_user_lni_alloc, },
	[CXI_OP_LNI_FREE] = {
		.req_size   = sizeof(struct cxi_lni_free_cmd),
		.name       = "LNI_FREE",
		.handler    = cxi_user_lni_free, },
	[CXI_OP_DOMAIN_RESERVE] = {
		.req_size   = sizeof(struct cxi_domain_reserve_cmd),
		.name       = "DOMAIN_RESERVE",
		.handler    = cxi_user_domain_reserve, },
	[CXI_OP_DOMAIN_ALLOC] = {
		.req_size   = sizeof(struct cxi_domain_alloc_cmd),
		.name       = "DOMAIN_ALLOC",
		.handler    = cxi_user_domain_alloc, },
	[CXI_OP_DOMAIN_FREE] = {
		.req_size   = sizeof(struct cxi_domain_free_cmd),
		.name       = "DOMAIN_FREE",
		.handler    = cxi_user_domain_free, },
	[CXI_OP_CP_ALLOC] = {
		.req_size   = sizeof(struct cxi_cp_alloc_cmd),
		.name       = "CP_ALLOC",
		.handler    = cxi_user_cp_alloc, },
	[CXI_OP_CP_FREE] = {
		.req_size   = sizeof(struct cxi_cp_free_cmd),
		.name       = "CP_FREE",
		.handler    = cxi_user_cp_free, },
	[CXI_OP_CQ_ALLOC] = {
		.req_size   = sizeof(struct cxi_cq_alloc_cmd),
		.name       = "CQ_ALLOC",
		.handler    = cxi_user_cq_alloc, },
	[CXI_OP_CQ_FREE] = {
		.req_size   = sizeof(struct cxi_cq_free_cmd),
		.name       = "CQ_FREE",
		.handler    = cxi_user_cq_free, },
	[CXI_OP_CQ_ACK_COUNTER] = {
		.req_size   = sizeof(struct cxi_cq_ack_counter_cmd),
		.name       = "CQ_ACK_COUNTER",
		.handler    = cxi_user_cq_ack_counter, },
	[CXI_OP_ATU_MAP] = {
		.req_size   = sizeof(struct cxi_atu_map_cmd),
		.name       = "ATU_MAP",
		.handler    = cxi_user_atu_map, },
	[CXI_OP_ATU_UNMAP] = {
		.req_size   = sizeof(struct cxi_atu_unmap_cmd),
		.name       = "ATU_UNMAP",
		.handler    = cxi_user_atu_unmap, },
	[CXI_OP_ATU_UPDATE_MD] = {
		.req_size   = sizeof(struct cxi_atu_update_md_cmd),
		.name       = "ATU_UPDATE_MD",
		.handler    = cxi_user_update_md, },
	[CXI_OP_EQ_ALLOC] = {
		.req_size   = sizeof(struct cxi_eq_alloc_cmd),
		.name       = "EQ_ALLOC",
		.handler    = cxi_user_eq_alloc, },
	[CXI_OP_EQ_FREE] = {
		.req_size   = sizeof(struct cxi_eq_free_cmd),
		.name       = "EQ_FREE",
		.handler    = cxi_user_eq_free, },
	[CXI_OP_EQ_RESIZE] = {
		.req_size   = sizeof(struct cxi_eq_resize_cmd),
		.name       = "EQ_RESIZE",
		.handler    = cxi_user_eq_resize, },
	[CXI_OP_EQ_RESIZE_COMPLETE] = {
		.req_size   = sizeof(struct cxi_eq_resize_complete_cmd),
		.name       = "EQ_RESIZE_COMPLETE",
		.handler    = cxi_user_eq_resize_complete, },
	[CXI_OP_PTE_ALLOC] = {
		.req_size   = sizeof(struct cxi_pte_alloc_cmd),
		.name       = "PTE_ALLOC",
		.handler    = cxi_user_pte_alloc, },
	[CXI_OP_PTE_FREE] = {
		.req_size   = sizeof(struct cxi_pte_free_cmd),
		.name       = "PTE_FREE",
		.handler    = cxi_user_pte_free, },
	[CXI_OP_PTE_MAP] = {
		.req_size   = sizeof(struct cxi_pte_map_cmd),
		.name       = "PTE_MAP",
		.handler    = cxi_user_pte_map, },
	[CXI_OP_PTE_UNMAP] = {
		.req_size   = sizeof(struct cxi_pte_unmap_cmd),
		.name       = "PTE_UNMAP",
		.handler    = cxi_user_pte_unmap, },
	[CXI_OP_PTE_LE_INVALIDATE] = {
		.req_size   = sizeof(struct cxi_pte_le_invalidate_cmd),
		.name       = "PTE_LE_INVALIDATE",
		.handler    = cxi_user_pte_le_invalidate, },
	[CXI_OP_PTE_STATUS] = {
		.req_size   = sizeof(struct cxi_pte_status_cmd),
		.name       = "PTE_STATUS",
		.handler    = cxi_user_pte_status, },
	[CXI_OP_PTE_TRANSITION_SM] = {
		.req_size   = sizeof(struct cxi_pte_transition_sm_cmd),
		.name       = "PTE_TRANSITION_SM",
		.handler    = cxi_user_pte_transition_sm, },
	[CXI_OP_WAIT_ALLOC] = {
		.req_size   = sizeof(struct cxi_wait_alloc_cmd),
		.name       = "WAIT_ALLOC",
		.handler    = cxi_user_wait_alloc, },
	[CXI_OP_WAIT_FREE] = {
		.req_size   = sizeof(struct cxi_wait_free_cmd),
		.name       = "WAIT_FREE",
		.handler    = cxi_user_wait_free, },
	[CXI_OP_CT_ALLOC] = {
		.req_size   = sizeof(struct cxi_ct_alloc_cmd),
		.name       = "CT_ALLOC",
		.handler    = cxi_user_ct_alloc, },
	[CXI_OP_CT_WB_UPDATE] = {
		.req_size   = sizeof(struct cxi_ct_wb_update_cmd),
		.name       = "CT_WB_UPDATE",
		.handler    = cxi_user_ct_wb_update, },
	[CXI_OP_CT_FREE] = {
		.req_size   = sizeof(struct cxi_ct_free_cmd),
		.name       = "CT_FREE",
		.handler    = cxi_user_ct_free, },
	[CXI_OP_MAP_CSRS] = {
		.req_size   = sizeof(struct cxi_map_csrs_cmd),
		.name       = "MAP_CSRS",
		.handler    = cxi_user_map_csrs,
		.admin_only = true, },
	[CXI_OP_SVC_GET] = {
		.req_size   = sizeof(struct cxi_svc_get_cmd),
		.name       = "SVC_GET",
		.handler    = cxi_user_svc_get, },
	[CXI_OP_SVC_LIST_GET] = {
		.req_size   = sizeof(struct cxi_svc_list_get_cmd),
		.name       = "SVC_LIST_GET",
		.handler    = cxi_user_svc_list_get, },
	[CXI_OP_SVC_RSRC_LIST_GET] = {
		.req_size   = sizeof(struct cxi_svc_rsrc_list_get_cmd),
		.name       = "SVC_RSRC_LIST_GET",
		.handler    = cxi_user_svc_rsrc_list_get, },
	[CXI_OP_SVC_RSRC_GET] = {
		.req_size   = sizeof(struct cxi_svc_rsrc_get_cmd),
		.name       = "SVC_RSRC_GET",
		.handler    = cxi_user_svc_rsrc_get, },
	[CXI_OP_SVC_ALLOC] = {
		.req_size   = sizeof(struct cxi_svc_alloc_cmd),
		.name       = "SVC_ALLOC",
		.handler    = cxi_user_svc_alloc,
		.admin_only = true, },
	[CXI_OP_SVC_DESTROY] = {
		.req_size   = sizeof(struct cxi_svc_destroy_cmd),
		.name       = "SVC_DESTROY",
		.handler    = cxi_user_svc_destroy,
		.admin_only = true, },
	[CXI_OP_SVC_UPDATE] =  {
		.req_size   = sizeof(struct cxi_svc_update_cmd),
		.name       = "SVC_UPDATE",
		.handler    = cxi_user_svc_update,
		.admin_only = true, },
	[CXI_OP_SBUS_OP_RESET] = {
		.req_size   = sizeof(struct cxi_sbus_op_reset_cmd),
		.name       = "SBUS_OP_RESET",
		.handler    = cxi_user_sbus_op_reset,
		.admin_only = true, },
	[CXI_OP_SBUS_OP] = {
		.req_size   = sizeof(struct cxi_sbus_op_cmd),
		.name       = "SBUS_OP",
		.handler    = cxi_user_sbus_op,
		.admin_only = true, },
	[CXI_OP_SERDES_OP] = {
		.req_size   = sizeof(struct cxi_serdes_op_cmd),
		.name       = "SERDES_OP",
		.handler    = cxi_user_serdes_op,
		.admin_only = true, },
	[CXI_OP_GET_DEV_PROPERTIES] = {
		.req_size   = sizeof(struct cxi_get_dev_properties_cmd),
		.name       = "GET_DEV_PROPERTIES",
		.handler    = cxi_get_dev_properties, },
	[CXI_OP_EQ_ADJUST_RESERVED_FC] = {
		.req_size   = sizeof(struct cxi_eq_adjust_reserved_fc_cmd),
		.name       = "EQ_ADJUST_RESERVED_FC",
		.handler    = cxi_user_eq_adjust_reserved_fc, },
	[CXI_OP_INBOUND_WAIT] = {
		.req_size   = sizeof(struct cxi_inbound_wait_cmd),
		.name       = "INBOUND_WAIT",
		.handler    = cxi_user_inbound_wait, },
	[CXI_OP_DEV_INFO_GET] = {
		.req_size   = sizeof(struct cxi_dev_info_get_cmd),
		.name       = "DEV_INFO_GET",
		.handler    = cxi_user_dev_info_get, },
	[CXI_OP_DEV_ALLOC_RGROUP] = {
		.req_size   = sizeof(struct cxi_dev_alloc_rgroup_cmd),
		.name       = "DEV_ALLOC_RGROUP",
		.handler    = cxi_user_dev_alloc_rgroup,
		.admin_only = true, },
	[CXI_OP_DEV_GET_RGROUP_IDS] = {
		.req_size   = sizeof(struct cxi_dev_get_rgroup_ids_cmd),
		.name       = "DEV_GET_RGROUP_IDS",
		.handler    = cxi_user_dev_get_rgroup_ids,
		.admin_only = true, },
	[CXI_OP_RGROUP_RELEASE] = {
		.req_size   = sizeof(struct cxi_rgroup_release_cmd),
		.name       = "RGROUP_RELEASE",
		.handler    = cxi_user_rgroup_release,
		.admin_only = true, },
	[CXI_OP_RGROUP_ENABLE] = {
		.req_size   = sizeof(struct cxi_rgroup_enable_cmd),
		.name       = "RGROUP_ENABLE",
		.handler    = cxi_user_rgroup_enable,
		.admin_only = true, },
	[CXI_OP_RGROUP_DISABLE] = {
		.req_size   = sizeof(struct cxi_rgroup_disable_cmd),
		.name       = "RGROUP_DISABLE",
		.handler    = cxi_user_rgroup_disable,
		.admin_only = true, },
	[CXI_OP_RGROUP_GET_INFO] = {
		.req_size   = sizeof(struct cxi_rgroup_get_info_cmd),
		.name       = "RGROUP_GET_INFO",
		.handler    = cxi_user_rgroup_get_info,
		.admin_only = true, },
	[CXI_OP_RGROUP_ADD_RESOURCE] = {
		.req_size   = sizeof(struct cxi_rgroup_add_resource_cmd),
		.name       = "RGROUP_ADD_RESOURSE",
		.handler    = cxi_user_rgroup_add_resource,
		.admin_only = true, },
	[CXI_OP_RGROUP_DELETE_RESOURCE] = {
		.req_size   = sizeof(struct cxi_rgroup_delete_resource_cmd),
		.name       = "RGROUP_DELETE_RESOURSE",
		.handler    = cxi_user_rgroup_delete_resource,
		.admin_only = true, },
	[CXI_OP_RGROUP_GET_RESOURCE] = {
		.req_size   = sizeof(struct cxi_rgroup_get_resource_cmd),
		.name       = "RGROUP_GET_RESOURSE",
		.handler    = cxi_user_rgroup_get_resource,
		.admin_only = true, },
	[CXI_OP_RGROUP_GET_RESOURCE_TYPES] = {
		.req_size   = sizeof(struct cxi_rgroup_get_resource_types_cmd),
		.name       = "RGROUP_GET_RESOURSE_TYPES",
		.handler    = cxi_user_rgroup_get_resource_types,
		.admin_only = true, },
	[CXI_OP_RGROUP_ADD_AC_ENTRY] = {
		.req_size   = sizeof(struct cxi_rgroup_add_ac_entry_cmd),
		.name       = "RGROUP_ADD_AC_ENTRY",
		.handler    = cxi_user_rgroup_add_ac_entry,
		.admin_only = true, },
	[CXI_OP_RGROUP_DELETE_AC_ENTRY] = {
		.req_size   = sizeof(struct cxi_rgroup_delete_ac_entry_cmd),
		.name       = "RGROUP_DELETE_AC_ENTRY",
		.handler    = cxi_user_rgroup_delete_ac_entry,
		.admin_only = true, },
	[CXI_OP_RGROUP_GET_AC_ENTRY_IDS] = {
		.req_size   = sizeof(struct cxi_rgroup_get_ac_entry_ids_cmd),
		.name       = "RGROUP_GET_AC_ENTRY_IDS",
		.handler    = cxi_user_rgroup_get_ac_entry_ids,
		.admin_only = true, },
	[CXI_OP_RGROUP_GET_AC_ENTRY_DATA_BY_ID] = {
		.req_size   = sizeof(struct cxi_rgroup_get_ac_entry_data_by_id_cmd),
		.name       = "RGROUP_GET_AC_ENTRY_DATA_BY_ID",
		.handler    = cxi_user_rgroup_get_ac_entry_data_by_id,
		.admin_only = true, },
	[CXI_OP_RGROUP_GET_AC_ENTRY_ID_BY_DATA] = {
		.req_size   = sizeof(struct cxi_rgroup_get_ac_entry_id_by_data_cmd),
		.name       = "RGROUP_GET_AC_ENTRY_ID_BY_DATA",
		.handler    = cxi_user_rgroup_get_ac_entry_id_by_data,
		.admin_only = true, },
	[CXI_OP_RGROUP_GET_AC_ENTRY_ID_BY_USER] = {
		.req_size   = sizeof(struct cxi_rgroup_get_ac_entry_id_by_user_cmd),
		.name       = "RGROUP_GET_AC_ENTRY_ID_BY_USER",
		.handler    = cxi_user_rgroup_get_ac_entry_id_by_user,
		.admin_only = true, },
	[CXI_OP_SVC_SET_LPR] =  {
		.req_size   = sizeof(struct cxi_svc_lpr_cmd),
		.name       = "SVC_SET_LPR",
		.handler    = cxi_user_svc_set_lpr,
		.admin_only = true, },
	[CXI_OP_SVC_GET_LPR] =  {
		.req_size   = sizeof(struct cxi_svc_lpr_cmd),
		.name       = "SVC_GET_LPR",
		.handler    = cxi_user_svc_get_lpr, },
	[CXI_OP_DEV_ALLOC_RX_PROFILE] = {
		.req_size   = sizeof(struct cxi_dev_alloc_rx_profile_cmd),
		.name       = "DEV_ALLOC_RX_PROFILE",
		.handler    = cxi_user_dev_alloc_rx_profile,
		.admin_only = true, },
	[CXI_OP_DEV_GET_RX_PROFILE_IDS] = {
		.req_size   = sizeof(struct cxi_dev_get_rx_profile_ids_cmd),
		.name       = "DEV_GET_RX_PROFILES",
		.handler    = cxi_user_dev_get_rx_profile_ids,
		.admin_only = true, },
	[CXI_OP_RX_PROFILE_RELEASE] = {
		.req_size   = sizeof(struct cxi_rx_profile_release_cmd),
		.name       = "RX_PROFILE_RELEASE",
		.handler    = cxi_user_rx_profile_release,
		.admin_only = true, },
	[CXI_OP_RX_PROFILE_REVOKE] = {
		.req_size   = sizeof(struct cxi_rx_profile_revoke_cmd),
		.name       = "RX_PROFILE_REVOKE",
		.handler    = cxi_user_rx_profile_revoke,
		.admin_only = true, },
	[CXI_OP_RX_PROFILE_GET_INFO] = {
		.req_size   = sizeof(struct cxi_rx_profile_get_info_cmd),
		.name       = "RX_PROFILE_GET_INFO",
		.handler    = cxi_user_rx_profile_get_info,
		.admin_only = true, },
	[CXI_OP_RX_PROFILE_ADD_AC_ENTRY] = {
		.req_size   = sizeof(struct cxi_rx_profile_add_ac_entry_cmd),
		.name       = "RX_PROFILE_ADD_AC_ENTRY",
		.handler    = cxi_user_rx_profile_add_ac_entry,
		.admin_only = true, },
	[CXI_OP_RX_PROFILE_REMOVE_AC_ENTRY] = {
		.req_size   = sizeof(struct cxi_rx_profile_remove_ac_entry_cmd),
		.name       = "RX_PROFILE_REMOVE_AC_ENTRY",
		.handler    = cxi_user_rx_profile_remove_ac_entry,
		.admin_only = true, },
	[CXI_OP_RX_PROFILE_GET_AC_ENTRY_IDS] = {
		.req_size   = sizeof(struct cxi_rx_profile_get_ac_entry_ids_cmd),
		.name       = "RX_PROFILE_GET_AC_ENTRY_IDS",
		.handler    = cxi_user_rx_profile_get_ac_entry_ids,
		.admin_only = true, },
	[CXI_OP_RX_PROFILE_GET_AC_ENTRY_DATA_BY_ID] = {
		.req_size   = sizeof(struct cxi_rx_profile_get_ac_entry_data_by_id_cmd),
		.name       = "RX_PROFILE_GET_AC_ENTRY_DATA_BY_ID",
		.handler    = cxi_user_rx_profile_get_ac_entry_data_by_id,
		.admin_only = true, },
	[CXI_OP_RX_PROFILE_GET_AC_ENTRY_ID_BY_DATA] = {
		.req_size   = sizeof(struct cxi_rx_profile_get_ac_entry_id_by_data_cmd),
		.name       = "RX_PROFILE_GET_AC_ENTRY_ID_BY_DATA",
		.handler    = cxi_user_rx_profile_get_ac_entry_id_by_data,
		.admin_only = true, },
	[CXI_OP_RX_PROFILE_GET_AC_ENTRY_ID_BY_USER] = {
		.req_size   = sizeof(struct cxi_rx_profile_get_ac_entry_id_by_user_cmd),
		.name       = "RX_PROFILE_GET_AC_ENTRY_ID_BY_USER",
		.handler    = cxi_user_rx_profile_get_ac_entry_id_by_user,
		.admin_only = true, },
	[CXI_OP_DEV_ALLOC_TX_PROFILE] = {
		.req_size   = sizeof(struct cxi_dev_alloc_tx_profile_cmd),
		.name       = "DEV_ALLOC_TX_PROFILE",
		.handler    = cxi_user_dev_alloc_tx_profile,
		.admin_only = true, },
	[CXI_OP_DEV_GET_TX_PROFILE_IDS] = {
		.req_size   = sizeof(struct cxi_dev_get_tx_profile_ids_cmd),
		.name       = "DEV_GET_TX_PROFILES",
		.handler    = cxi_user_dev_get_tx_profile_ids,
		.admin_only = true, },
	[CXI_OP_TX_PROFILE_RELEASE] = {
		.req_size   = sizeof(struct cxi_tx_profile_release_cmd),
		.name       = "TX_PROFILE_RELEASE",
		.handler    = cxi_user_tx_profile_release,
		.admin_only = true, },
	[CXI_OP_TX_PROFILE_REVOKE] = {
		.req_size   = sizeof(struct cxi_tx_profile_revoke_cmd),
		.name       = "TX_PROFILE_REVOKE",
		.handler    = cxi_user_tx_profile_revoke,
		.admin_only = true, },
	[CXI_OP_TX_PROFILE_GET_INFO] = {
		.req_size   = sizeof(struct cxi_tx_profile_get_info_cmd),
		.name       = "TX_PROFILE_GET_INFO",
		.handler    = cxi_user_tx_profile_get_info,
		.admin_only = true, },
	[CXI_OP_TX_PROFILE_ADD_AC_ENTRY] = {
		.req_size   = sizeof(struct cxi_tx_profile_add_ac_entry_cmd),
		.name       = "TX_PROFILE_ADD_AC_ENTRY",
		.handler    = cxi_user_tx_profile_add_ac_entry,
		.admin_only = true, },
	[CXI_OP_TX_PROFILE_REMOVE_AC_ENTRY] = {
		.req_size   = sizeof(struct cxi_tx_profile_remove_ac_entry_cmd),
		.name       = "TX_PROFILE_REMOVE_AC_ENTRY",
		.handler    = cxi_user_tx_profile_remove_ac_entry,
		.admin_only = true, },
	[CXI_OP_TX_PROFILE_GET_AC_ENTRY_IDS] = {
		.req_size   = sizeof(struct cxi_tx_profile_get_ac_entry_ids_cmd),
		.name       = "TX_PROFILE_GET_AC_ENTRY_IDS",
		.handler    = cxi_user_tx_profile_get_ac_entry_ids,
		.admin_only = true, },
	[CXI_OP_TX_PROFILE_GET_AC_ENTRY_DATA_BY_ID] = {
		.req_size   = sizeof(struct cxi_tx_profile_get_ac_entry_data_by_id_cmd),
		.name       = "TX_PROFILE_GET_AC_ENTRY_DATA_BY_ID",
		.handler    = cxi_user_tx_profile_get_ac_entry_data_by_id,
		.admin_only = true, },
	[CXI_OP_TX_PROFILE_GET_AC_ENTRY_ID_BY_DATA] = {
		.req_size   = sizeof(struct cxi_tx_profile_get_ac_entry_id_by_data_cmd),
		.name       = "TX_PROFILE_GET_AC_ENTRY_ID_BY_DATA",
		.handler    = cxi_user_tx_profile_get_ac_entry_id_by_data,
		.admin_only = true, },
	[CXI_OP_TX_PROFILE_GET_AC_ENTRY_ID_BY_USER] = {
		.req_size   = sizeof(struct cxi_tx_profile_get_ac_entry_id_by_user_cmd),
		.name       = "TX_PROFILE_GET_AC_ENTRY_ID_BY_USER",
		.handler    = cxi_user_tx_profile_get_ac_entry_id_by_user,
		.admin_only = true, },
};

/* Read and process a command from userspace or from a Virtual
 * Function.
 * The response will be be copied out by the handler.
 */
static int dispatch(struct user_client *client,
		    const void *cmd_in, size_t cmd_in_len,
		    void *resp_out, size_t *resp_out_len)
{
	struct ucxi *ucxi = client->ucxi;
	struct cxi_dev *cdev;
	int rc;
	int idx;
	u8 tmp_req[MAX_REQ_SIZE];
	const struct cxi_common_cmd *req;
	const struct cmd_info *info;

	if (cmd_in_len > MAX_REQ_SIZE)
		return -EINVAL;

	if (client->is_vf) {
		req = cmd_in;
	} else {
		req = (const struct cxi_common_cmd *)tmp_req;
		if (copy_from_user(tmp_req, cmd_in, cmd_in_len))
			return -EFAULT;
	}

	if (req->op <= CXI_OP_INVALID || req->op >= CXI_OP_MAX)
		return -EINVAL;

	info = &cmds_info[req->op];

	if (client->is_vf)
		dev_dbg(ucxi->udev, "Got command %s from VF %d, len %zu\n",
			info->name, client->vf_num, cmd_in_len);
	else
		dev_dbg(ucxi->udev, "Got command %s from user, len %zu\n",
			info->name, cmd_in_len);

	if (info->handler == NULL)
		return -EOPNOTSUPP;

	if (cmd_in_len != info->req_size)
		return -EINVAL;

	if (info->admin_only && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* Process the command only if the device still
	 * exist. Otherwise return an EIO error.
	 */
	idx = srcu_read_lock(&ucxi->srcu);

	cdev = srcu_dereference(ucxi->dev, &ucxi->srcu);

	if (cdev == NULL)
		rc = -EIO;
	else if (client->is_vf)
		rc = info->handler(client, req, resp_out, resp_out_len);
	else
		rc = info->handler(client, req, req->resp, NULL);

	srcu_read_unlock(&ucxi->srcu, idx);

	BUG_ON(rc > 0);

	return rc;
}

/* Read and process a command from userspace. */
static ssize_t ucxi_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *f_pos)
{
	struct user_client *client = filp->private_data;
	int rc;

	rc = dispatch(client, buf, count, NULL, NULL);

	return rc < 0 ? rc : count;
}

static struct user_client *alloc_client(struct ucxi *ucxi)
{
	struct cxi_dev *cdev;
	struct user_client *client;
	int idx;
	int rc;
	char name[24];

	idx = srcu_read_lock(&ucxi->srcu);

	cdev = srcu_dereference(ucxi->dev, &ucxi->srcu);
	if (cdev == NULL) {
		srcu_read_unlock(&ucxi->srcu, idx);
		return ERR_PTR(-EIO);
	}

	kobject_get(&ucxi->kobj);

	srcu_read_unlock(&ucxi->srcu, idx);

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (client == NULL) {
		rc = -ENOMEM;
		goto put_kobj;
	}

	/* Allocate a client id */
	idr_preload(GFP_KERNEL);
	spin_lock(&ucxi->lock);

	rc = idr_alloc(&ucxi->client_idr, client, 1, 0, GFP_NOWAIT);

	spin_unlock(&ucxi->lock);
	idr_preload_end();

	if (rc < 0)
		goto free_client;

	client->ucxi = ucxi;
	client->id = rc;

	sprintf(name, "%d", client->id);
	client->kobj = kobject_create_and_add(name, ucxi->clients_kobj);
	if (!client->kobj) {
		rc = -ENOMEM;
		goto free_idr;
	}

	client->wait_objs_kobj = kobject_create_and_add("wait", client->kobj);
	if (!client->wait_objs_kobj) {
		rc = -ENOMEM;
		goto put_client_kobj;
	}

	spin_lock_init(&client->mmap_offset_lock);
	spin_lock_init(&client->pending_lock);
	INIT_LIST_HEAD(&client->pending_mmaps);
	mutex_init(&client->eq_resize_mutex);
	rwlock_init(&client->res_lock);
	idr_init(&client->lni_idr);
	idr_init(&client->domain_idr);
	idr_init(&client->cq_idr);
	idr_init(&client->eq_idr);
	idr_init(&client->md_idr);
	idr_init(&client->pte_idr);
	idr_init(&client->pte_map_idr);
	idr_init(&client->wait_idr);
	idr_init(&client->ct_idr);
	idr_init(&client->cp_idr);

	client->cntr_pool_id = 0;

	return client;

put_client_kobj:
	kobject_put(client->kobj);

free_idr:
	spin_lock(&ucxi->lock);
	idr_remove(&ucxi->client_idr, client->id);
	spin_unlock(&ucxi->lock);

free_client:
	kfree(client);

put_kobj:
	kobject_put(&ucxi->kobj);

	return ERR_PTR(rc);
}

/* A userspace client is opening the device that owns that /dev
 * entry.
 */
static int ucxi_open(struct inode *inode, struct file *filp)
{
	struct ucxi *ucxi = container_of(inode->i_cdev, struct ucxi, cdev);
	struct user_client *client;

	client = alloc_client(ucxi);
	if (IS_ERR(client))
		return PTR_ERR(client);

	filp->private_data = client;
	client->fileptr = filp;

	return 0;
}

/* Used to free all remaining objects when a user closes the device
 * file.
 */
static int free_lni_obj(int id, void *obj_, void *data)
{
	struct user_client *client = data;
	struct ucxi_obj *lni = obj_;

	if (client->ucxi)
		cxi_lni_free(lni->lni);
	free_obj(lni);

	return 0;
}

static int free_cp_obj(int id, void *obj_, void *data)
{
	struct ucxi_obj *cp = obj_;
	struct user_client *client = data;

	if (client->ucxi)
		cxi_cp_free(cp->cp);
	free_obj(cp);

	return 0;
}

static int free_ct_obj(int id, void *obj_, void *data)
{
	struct ucxi_obj *ct = obj_;
	struct cxi_mmap_info *mminfo = ct->mminfo;
	struct user_client *client = data;

	mminfo_unmap(client, mminfo, 1);
	kfree(mminfo);

	if (client->ucxi)
		cxi_ct_free(ct->ct);

	free_obj(ct);

	return 0;
}

static int free_domain_obj(int id, void *obj_, void *data)
{
	struct user_client *client = data;
	struct ucxi_obj *domain = obj_;

	if (client->ucxi)
		cxi_domain_free(domain->domain);
	free_obj(domain);

	return 0;
}

static int free_cq_obj(int id, void *obj_, void *data)
{
	struct ucxi_obj *cq = obj_;
	struct cxi_mmap_info *mminfo = cq->mminfo;
	struct user_client *client = data;

	mminfo_unmap(client, mminfo, 2);
	kfree(mminfo);
	if (client->ucxi)
		cxi_cq_free(cq->cq);
	free_obj(cq);

	return 0;
}

static int free_md_obj(int id, void *obj_, void *data)
{
	struct ucxi_obj *md = obj_;
	struct user_client *client = data;

	if (client->ucxi)
		cxi_unmap(md->md);
	free_obj(md);
	return 0;
}

static int free_eq_obj(int id, void *obj_, void *data)
{
	struct ucxi_obj *eq = obj_;
	struct cxi_mmap_info *mminfo = eq->mminfo;
	struct user_client *client = data;

	mminfo_unmap(client, mminfo, 1);
	kfree(mminfo);
	if (client->ucxi)
		cxi_eq_free(eq->eq);
	free_obj(eq);
	return 0;
}

static int free_pte_obj(int id, void *obj_, void *data)
{
	struct user_client *client = data;
	struct ucxi_obj *pte_obj = obj_;

	if (client->ucxi)
		cxi_pte_free(pte_obj->pte);
	free_obj(pte_obj);

	return 0;
}

static int free_pte_map(int id, void *obj_, void *data)
{
	struct user_client *client = data;
	struct ucxi_obj *map_obj = obj_;
	struct ucxi_obj *pte_obj = map_obj->deps[0];
	struct ucxi_obj *dom_obj = map_obj->deps[1];

	if (client->ucxi)
		cxi_pte_unmap(pte_obj->pte, dom_obj->domain,
			      map_obj->pte_index);
	free_obj(map_obj);

	return 0;
}

static int free_wait_obj(int id, void *obj_, void *data)
{
	struct ucxi_obj *wait_obj = obj_;
	struct ucxi_wait *wait = wait_obj->wait;

	sysfs_put(wait->dirent);
	kobject_put(&wait->kobj);
	kfree(wait);

	free_obj(obj_);

	return 0;
}

static void free_client(struct user_client *client)
{
	struct ucxi *ucxi = client->ucxi;
	int idx;

	idx = srcu_read_lock(&ucxi->srcu);

	if (!srcu_dereference(ucxi->dev, &ucxi->srcu)) {
		/* Device has been removed. The driver still need to
		 * release local resources in the free_X_X
		 * functions.
		 */
		client->ucxi = NULL;
	}

	/* Free existing resources that userspace didn't release. This
	 * must be done in reverse order of dependencies.
	 */
	idr_for_each(&client->pte_map_idr, free_pte_map, client);
	idr_destroy(&client->pte_map_idr);

	idr_for_each(&client->pte_idr, free_pte_obj, client);
	idr_destroy(&client->pte_idr);

	idr_for_each(&client->cq_idr, free_cq_obj, client);
	idr_destroy(&client->cq_idr);

	idr_for_each(&client->eq_idr, free_eq_obj, client);
	idr_destroy(&client->eq_idr);

	idr_for_each(&client->md_idr, free_md_obj, client);
	idr_destroy(&client->md_idr);

	idr_for_each(&client->wait_idr, free_wait_obj, client);
	idr_destroy(&client->wait_idr);

	idr_for_each(&client->domain_idr, free_domain_obj, client);
	idr_destroy(&client->domain_idr);

	idr_for_each(&client->ct_idr, free_ct_obj, client);
	idr_destroy(&client->ct_idr);

	idr_for_each(&client->cp_idr, free_cp_obj, client);
	idr_destroy(&client->cp_idr);

	idr_for_each(&client->lni_idr, free_lni_obj, client);
	idr_destroy(&client->lni_idr);

	kobject_put(client->wait_objs_kobj);
	kobject_put(client->kobj);

	spin_lock(&ucxi->lock);
	idr_remove(&ucxi->client_idr, client->id);
	spin_unlock(&ucxi->lock);

	kobject_put(&ucxi->kobj);

	if (client->csrs_mminfo) {
		mminfo_unmap(client, client->csrs_mminfo, 1);
		kfree(client->csrs_mminfo);
	}

	/* Sanity check. At this point the mmapping list must be empty. */
	WARN_ON_ONCE(!list_empty(&client->pending_mmaps));

	srcu_read_unlock(&ucxi->srcu, idx);

	kfree(client);
}

/* Called by Linux when the /dev file is closed. Release every
 * resources allocated.
 */
static int ucxi_release(struct inode *inode, struct file *filp)
{
	struct user_client *client = filp->private_data;

	free_client(client);

	return 0;
}

/* Read a message from a VF. */
static int msg_relay(void *data, unsigned int vf_num,
		     const void *req, size_t req_len,
		     void *rsp, size_t *rsp_len)
{
	struct ucxi *ucxi = data;
	struct user_client *client;
	int rc;

	pr_debug("Got message %u from VF %d, len %zu\n",
		((const struct cxi_common_cmd *) req)->op, vf_num, req_len);

	client = ucxi->vf_clients[vf_num];
	if (client == NULL) {
		client = alloc_client(ucxi);

		if (IS_ERR(client))
			return PTR_ERR(client);

		ucxi->vf_clients[vf_num] = client;

		client->is_vf = true;
		client->vf_num = vf_num;
	}

	*rsp_len = 0;
	rc = dispatch(client, req, req_len, rsp, rsp_len);

	return -rc;
}

/* The /dev/cxiX file operations. */
static const struct file_operations ucxi_fops = {
	.open =      ucxi_open,
	.write =     ucxi_write,
	.release =   ucxi_release,
	.mmap = ucxi_mmap,
};

static void release_dev(struct kobject *kobj)
{
	struct ucxi *ucxi =
		container_of(kobj, struct ucxi, kobj);

	cleanup_srcu_struct(&ucxi->srcu);

	kfree(ucxi);
}

static struct kobj_type dev_ktype = {
	.release = release_dev,
};

/* Core is adding a new device */
static int add_device(struct cxi_dev *dev)
{
	struct ucxi *ucxi;
	int rc;
	unsigned int minor;
	dev_t dev_id;

	ucxi = kzalloc(sizeof(*ucxi), GFP_KERNEL);
	if (ucxi == NULL)
		return -ENOMEM;

	spin_lock(&minors_lock);
	minor = find_first_zero_bit(minors, ucxi_num_devices);
	if (minor < ucxi_num_devices)
		set_bit(minor, minors);
	spin_unlock(&minors_lock);

	if (minor == ucxi_num_devices) {
		rc = -ENODEV;
		goto free_ucxi;
	}
	ucxi->minor = minor;
	dev_id = MKDEV(MAJOR(ucxi_dev), minor);

	rcu_assign_pointer(ucxi->dev, dev);
	init_srcu_struct(&ucxi->srcu);

	cdev_init(&ucxi->cdev, &ucxi_fops);
	ucxi->cdev.owner = THIS_MODULE;
	rc = cdev_add(&ucxi->cdev, dev_id, 1);
	if (rc)
		goto free_minor;

	ucxi->udev = device_create(&ucxi_class, &dev->pdev->dev,
				   dev_id, NULL, "%s", dev->name);
	if (IS_ERR(ucxi->udev)) {
		rc = PTR_ERR(ucxi->udev);
		goto free_cdev;
	}

	dev_set_drvdata(ucxi->udev, ucxi);

	kobject_init(&ucxi->kobj, &dev_ktype);
	idr_init(&ucxi->client_idr);
	spin_lock_init(&ucxi->lock);

	mutex_lock(&dev_list_mutex);
	list_add_tail(&ucxi->dev_list, &dev_list);
	mutex_unlock(&dev_list_mutex);

	if (dev->is_physfn) {
		rc = cxi_register_msg_relay(dev, msg_relay, ucxi);
		if (rc) {
			pr_err("msg_relay registration failed\n");
			goto rem_dev;
		}
	}

	ucxi->clients_kobj = kobject_create_and_add("clients",
						    &ucxi->udev->kobj);
	if (!ucxi->clients_kobj)
		goto rem_relay;

	pr_info("Added user device for %s\n", dev->name);

	return 0;

rem_relay:
	if (dev->is_physfn)
		cxi_unregister_msg_relay(dev);

rem_dev:
	mutex_lock(&dev_list_mutex);
	list_del(&ucxi->dev_list);
	mutex_unlock(&dev_list_mutex);

	device_unregister(ucxi->udev);

free_cdev:
	cdev_del(&ucxi->cdev);

free_minor:
	cleanup_srcu_struct(&ucxi->srcu);
	spin_lock(&minors_lock);
	clear_bit(minor, minors);
	spin_unlock(&minors_lock);

free_ucxi:
	kfree(ucxi);

	return rc;
}

static void remove_device(struct cxi_dev *dev)
{
	struct ucxi *ucxi;
	struct ucxi *next;
	bool found = false;
	int i;

	/* Find the device in the list */
	mutex_lock(&dev_list_mutex);
	list_for_each_entry_safe(ucxi, next, &dev_list, dev_list) {
		if (ucxi->dev == dev) {
			list_del(&ucxi->dev_list);
			found = true;
			break;
		}
	}
	mutex_unlock(&dev_list_mutex);

	if (!found)
		return;

	rcu_assign_pointer(ucxi->dev, NULL);
	synchronize_srcu(&ucxi->srcu);

	if (dev->is_physfn)
		cxi_unregister_msg_relay(dev);

	for (i = 0; i < C_NUM_VFS; i++) {
		struct user_client *client = ucxi->vf_clients[i];

		if (client) {
			free_client(client);
			ucxi->vf_clients[i] = NULL;
		}
	}

	kobject_put(ucxi->clients_kobj);

	device_unregister(ucxi->udev);

	cdev_del(&ucxi->cdev);

	spin_lock(&minors_lock);
	clear_bit(ucxi->minor, minors);
	spin_unlock(&minors_lock);

	pr_info("Removed user device for %s\n", dev->name);

	kobject_put(&ucxi->kobj);
}

static struct cxi_client ucxi_client = {
	.add = add_device,
	.remove = remove_device,
};

static int __init init(void)
{
	int rc;
	int i;
	int max_req_size = 0;

	/* Sanity check. Ensure commands didn't grow too big */
	for (i = 0; i < CXI_OP_MAX; i++) {
		const struct cmd_info *info = &cmds_info[i];

		if (info->req_size > max_req_size)
			max_req_size = info->req_size;
	}
	if (max_req_size > MAX_REQ_SIZE) {
		pr_err("MAX_REQ_SIZE is too small. Needs to be %u\n",
		       max_req_size);
		rc = -EINVAL;
		goto out;
	}

	rc = alloc_chrdev_region(&ucxi_dev, 0, ucxi_num_devices, "ucxi");
	if (rc) {
		pr_err("alloc_chrdev_region failed\n");
		goto out;
	}

	rc = class_register(&ucxi_class);
	if (rc) {
		pr_err("Couldn't create Cray eXascale Interconnect user class\n");
		goto unreg_chr;
	}

	rc = cxi_register_client(&ucxi_client);
	if (rc) {
		pr_err("Couldn't register client\n");
		goto cl_unreg;
	}

#ifdef CONFIG_ARM64
	if (pci_get_device(PCI_VENDOR_ID_AMPERE, 0xe100, NULL))
		static_branch_enable(&avoid_writecombine);
#endif

	return 0;

cl_unreg:
	class_unregister(&ucxi_class);

unreg_chr:
	unregister_chrdev_region(ucxi_dev, ucxi_num_devices);

out:
	return rc;
}

static void __exit cleanup(void)
{
	cxi_unregister_client(&ucxi_client);
	class_unregister(&ucxi_class);
	unregister_chrdev_region(ucxi_dev, ucxi_num_devices);
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Cray eXascale Interconnect (CXI) user API driver");
MODULE_AUTHOR("Cray Inc.");
