// SPDX-License-Identifier: GPL-2.0
/* Copyright 2018-2020,2024 Hewlett Packard Enterprise Development LP */

/* User space test common functions */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>

#include "test_ucxi_common.h"

static int write_device(struct cass_dev *dev,
			const void *addr,
			size_t len)
{
	if (!dev)
		return -EINVAL;
	if (len && !addr)
		return -EINVAL;

	ssize_t  nwritten = write(dev->fd, addr, len);

	if (nwritten == len)  /* full write */
		return 0;     /* good */
	if (nwritten >= 0)    /* partial write */
		return -1;    /* not supported */
	return -errno;        /* error during write */
}

struct cass_dev *open_device(const char *name)
{
	struct cass_dev *dev;

	if (strlen(name) > 4)
		return NULL;

	dev = calloc(1, sizeof(*dev));
	if (dev == NULL)
		return NULL;

	strcpy(dev->name, name);
	sprintf(dev->devname, "/dev/%s", name);

	dev->fd = open(dev->devname, O_RDWR | O_CLOEXEC);
	if (dev->fd == -1) {
		free(dev);
		dev = NULL;
	}

	return dev;
}

void close_device(struct cass_dev *dev)
{
	if (dev == NULL)
		return;

	if (dev->mapped_csrs)
		munmap(dev->mapped_csrs,
		       dev->mapped_csrs_size);

	close(dev->fd);
	dev->fd = -1;
}

int map_csr(struct cass_dev *dev)
{
	struct cxi_map_csrs_resp resp;
	struct cxi_map_csrs_cmd cmd = {
		.op = CXI_OP_MAP_CSRS,
		.resp = &resp,
	};
	void *csr;
	int rc;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		return -1;

	/* mmaps the event queue SW state descriptor */
	csr = mmap(NULL, resp.csr.size,
		   PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd,
		   resp.csr.offset);

	if (csr == MAP_FAILED)
		return -1;

	dev->mapped_csrs = csr;
	dev->mapped_csrs_size = resp.csr.size;

	return 0;
}

static bool valid_csr(const struct cass_dev *dev,
		      unsigned int csr, size_t csr_len)
{
	return dev->mapped_csrs && (csr_len % sizeof(uint64_t) == 0) &&
		csr < dev->mapped_csrs_size &&
		csr + csr_len <= dev->mapped_csrs_size;
}

int read_csr(struct cass_dev *dev, unsigned int csr,
	     void *value, size_t csr_len)
{
	const uint64_t *src;
	uint64_t *dst;
	size_t i;

	if (!valid_csr(dev, csr, csr_len))
		return -EINVAL;

	src = (uint64_t *)((char *)dev->mapped_csrs + csr);
	dst = value;

	csr_len /= sizeof(uint64_t);

	for (i = 0; i < csr_len; i++)
		*dst++ = *src++;

	return 0;
}

struct ucxi_cp *alloc_cp(struct cass_dev *dev, unsigned int lni,
			 unsigned int vni, enum cxi_traffic_class tc)
{
	struct cxi_cp_alloc_cmd cmd = {};
	struct cxi_cp_alloc_resp resp = {};
	int rc;
	struct ucxi_cp *cp;

	cp = calloc(1, sizeof(*cp));
	assert(cp != NULL);

	cmd.op = CXI_OP_CP_ALLOC;
	cmd.resp = &resp;
	cmd.lni = lni;
	cmd.vni = vni;
	cmd.tc = tc;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		free(cp);
		perror("alloc cp");
		return NULL;
	}

	cp->cp_hndl = resp.cp_hndl;
	cp->lcid = resp.lcid;

	return cp;
}

void destroy_cp(struct cass_dev *dev, struct ucxi_cp *cp)
{
	struct cxi_cp_free_cmd cmd = {
		.op = CXI_OP_CP_FREE,
		.cp_hndl = cp->cp_hndl,
	};
	int rc;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		perror("free cp");

	free(cp);
}

struct ucxi_cq *create_cq(struct cass_dev *dev, unsigned int lni,
			  bool is_transmit, unsigned int lcid)
{
	struct cxi_cq_alloc_cmd cmd = {};
	struct cxi_cq_alloc_resp resp;
	int rc;
	struct ucxi_cq *cq;

	cq = calloc(1, sizeof(*cq));
	assert(cq != NULL);

	/* Get a cq */
	cmd.op = CXI_OP_CQ_ALLOC;
	cmd.resp = &resp;
	cmd.lni = lni;
	cmd.eq = C_EQ_NONE;
	cmd.opts.count = 80;
	cmd.opts.flags = is_transmit ? CXI_CQ_IS_TX : 0;
	cmd.opts.lcid = lcid;
	cmd.opts.policy = CXI_CQ_UPDATE_ALWAYS;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		perror("alloc cq");
		return NULL;
	}
	cq->cq = resp.cq;
	cq->cmds_len = resp.cmds.size;
	cq->wp_addr_len = resp.wp_addr.size;

	/* mmaping queue */
	cq->cmds = mmap(NULL, resp.cmds.size,
			PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd,
			resp.cmds.offset);

	/* mmaping csr block */
	cq->wp_addr = mmap(NULL, resp.wp_addr.size,
			   PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd,
			   resp.wp_addr.offset);

	cxi_cq_init(&cq->cmdq, cq->cmds, resp.count, cq->wp_addr,
		    cq->cq);

	return cq;
}

int cq_get_ack_counter(struct cass_dev *dev, struct ucxi_cq *cq,
		       unsigned int *ack_counter)
{
	struct cxi_cq_ack_counter_resp resp = {};
	struct cxi_cq_ack_counter_cmd cmd = {
		.op = CXI_OP_CQ_ACK_COUNTER,
		.resp = &resp,
		.cq = cq->cq,
	};
	int rc;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		return -errno;

	*ack_counter = resp.ack_counter;

	return 0;
}

void destroy_cq(struct cass_dev *dev, struct ucxi_cq *cq)
{
	struct cxi_cq_free_cmd cmd = {
		.op = CXI_OP_CQ_FREE,
		.cq = cq->cq,
	};
	int rc;

	munmap(cq->wp_addr, cq->wp_addr_len);
	munmap(cq->cmds, cq->cmds_len);

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		perror("free cq");

	free(cq);
}

int alloc_rgroup(struct cass_dev *dev,
		 const struct ucxi_rgroup_attr *attr,
		 unsigned int *rgroup_id)
{
	int rc;
	struct cxi_dev_alloc_rgroup_resp resp = {};
	struct cxi_dev_alloc_rgroup_cmd cmd = {
		.common.op   = CXI_OP_DEV_ALLOC_RGROUP,
		.common.resp = &resp,
	};

	if (!attr)
		return -EINVAL;

	cmd.attr.cntr_pool_id   = attr->cntr_pool_id;
	cmd.attr.system_service = attr->system_service;
	strncpy(cmd.attr.name, attr->name, sizeof(cmd.attr.name));

	rc = write_device(dev, &cmd, sizeof(cmd));
	if (rc)
		return rc;

	if (!rgroup_id)
		return -EINVAL;

	*rgroup_id = resp.rgroup_id;
	return 0;
}

int release_rgroup(struct cass_dev *dev,
		   unsigned int rgroup_id)
{
	const struct cxi_rgroup_release_cmd   cmd = {
		.common.op   = CXI_OP_RGROUP_RELEASE,
		.common.resp = NULL,
		.rgroup_id   = rgroup_id,
	};

	return write_device(dev, &cmd, sizeof(cmd));
}

int enable_rgroup(struct cass_dev *dev,
		  unsigned int rgroup_id)
{
	const struct cxi_rgroup_enable_cmd   cmd = {
		.common.op   = CXI_OP_RGROUP_ENABLE,
		.common.resp = NULL,
		.rgroup_id   = rgroup_id,
	};

	return write_device(dev, &cmd, sizeof(cmd));
}

int disable_rgroup(struct cass_dev *dev,
		   unsigned int rgroup_id)
{
	const struct cxi_rgroup_disable_cmd   cmd = {
		.common.op   = CXI_OP_RGROUP_DISABLE,
		.common.resp = NULL,
		.rgroup_id   = rgroup_id,
	};

	return write_device(dev, &cmd, sizeof(cmd));
}

int get_rgroup_ids(struct cass_dev *dev,
		   size_t max_ids,
		   unsigned int *rgroup_ids,
		   size_t *num_ids)
{
	struct cxi_dev_get_rgroup_ids_resp   resp;
	struct cxi_dev_get_rgroup_ids_cmd    cmd = {
		.common.op   = CXI_OP_DEV_GET_RGROUP_IDS,
		.common.resp = &resp,
		.max_ids     = max_ids,
		.rgroup_ids  = rgroup_ids,
	};

	int   ret = write_device(dev, &cmd, sizeof(cmd));

	if (!num_ids)
		return -EINVAL;

	switch (ret) {
	case 0:
	case -ENOSPC:
		*num_ids = resp.num_ids;
		break;
	default:
		break;
	}

	return ret;
}

int get_rgroup_info(struct cass_dev *dev,
		    unsigned int rgroup_id,
		    struct ucxi_rgroup_attr *attr,
		    struct ucxi_rgroup_state *state)
{
	struct cxi_rgroup_get_info_resp   resp;
	struct cxi_rgroup_get_info_cmd    cmd = {
		.common.op   = CXI_OP_RGROUP_GET_INFO,
		.common.resp = &resp,
		.rgroup_id   = rgroup_id,
	};

	int ret = write_device(dev, &cmd, sizeof(cmd));

	if (ret)
		return ret;

	if (!attr || !state)
		return -EINVAL;

	attr->cntr_pool_id = resp.attr.cntr_pool_id;
	attr->system_service = resp.attr.system_service;
	strncpy(attr->name, resp.attr.name, ARRAY_SIZE(attr->name));

	state->enabled  = resp.state.enabled;
	state->released = resp.state.released;
	state->refcount = resp.state.refcount;

	return 0;
}

int rgroup_add_resource(struct cass_dev *dev,
			unsigned int rgroup_id,
			enum ucxi_resource_type resource_type,
			const struct ucxi_resource_limits *limits)
{
	struct cxi_rgroup_add_resource_cmd cmd = {
		.common.op     = CXI_OP_RGROUP_ADD_RESOURCE,
		.common.resp   = NULL,
		.rgroup_id     = rgroup_id,
		.resource_type = resource_type,
	};

	if (!limits)
		return -EINVAL;

	cmd.limits.reserved = limits->reserved;
	cmd.limits.max      = limits->max;

	return write_device(dev, &cmd, sizeof(cmd));
}

int rgroup_delete_resource(struct cass_dev *dev,
			   unsigned int rgroup_id,
			   enum ucxi_resource_type resource_type)
{
	struct cxi_rgroup_delete_resource_cmd cmd = {
		.common.op     = CXI_OP_RGROUP_DELETE_RESOURCE,
		.common.resp   = NULL,
		.rgroup_id     = rgroup_id,
		.resource_type = resource_type,
	};


	return write_device(dev, &cmd, sizeof(cmd));
}

int rgroup_get_resource_types(struct cass_dev *dev,
			      unsigned int rgroup_id,
			      size_t max_types,
			      enum ucxi_resource_type *resource_types,
			      size_t *num_types)
{
	struct cxi_rgroup_get_resource_types_resp  resp;
	struct cxi_rgroup_get_resource_types_cmd   cmd = {
		.common.op   = CXI_OP_RGROUP_GET_RESOURCE_TYPES,
		.common.resp = &resp,
		.rgroup_id   = rgroup_id,
		.max_types   = max_types,
	};

	unsigned int   *types = (max_types) ? calloc(max_types, sizeof(*types)) : NULL;

	cmd.resource_types = types;

	int   ret = write_device(dev, &cmd, sizeof(cmd));

	*num_types = resp.num_types;

	if (!ret) {
		for (size_t i = 0; i < *num_types; i++)
			resource_types[i] = types[i];
	}
	free(types);

	return ret;
}

int rgroup_get_resource(struct cass_dev *dev,
			unsigned int rgroup_id,
			enum ucxi_resource_type resource_type,
			struct ucxi_resource_limits *limits)
{
	struct cxi_rgroup_get_resource_resp  resp;
	struct cxi_rgroup_get_resource_cmd   cmd = {
		.common.op     = CXI_OP_RGROUP_GET_RESOURCE,
		.common.resp   = &resp,
		.rgroup_id     = rgroup_id,
		.resource_type = resource_type,
	};

	int ret = write_device(dev, &cmd, sizeof(cmd));

	if (ret)
		return ret;

	limits->reserved = resp.limits.reserved;
	limits->max      = resp.limits.max;

	return 0;
}

int rgroup_add_ac_entry(struct cass_dev *dev,
			unsigned int rgroup_id,
			enum ucxi_ac_type ac_type,
			const union ucxi_ac_data *data,
			unsigned int *id)
{
	struct cxi_rgroup_add_ac_entry_resp  resp;
	struct cxi_rgroup_add_ac_entry_cmd   cmd = {
		.common.op   = CXI_OP_RGROUP_ADD_AC_ENTRY,
		.common.resp = &resp,
		.rgroup_id   = rgroup_id,
		.ac_type     = ac_type,
	};

	if (!data)
		return -EINVAL;

	switch (ac_type) {
	case UCXI_AC_UID:
		cmd.uid = data->uid;
		break;
	case UCXI_AC_GID:
		cmd.gid = data->gid;
		break;
	default:
		break;
	}

	int ret = write_device(dev, &cmd, sizeof(cmd));

	if (ret)
		return ret;

	if (!id)
		return -EINVAL;

	*id = resp.ac_entry_id;
	return 0;
}

int rgroup_delete_ac_entry(struct cass_dev *dev,
			   unsigned int rgroup_id,
			   unsigned int ac_entry_id)
{
	struct cxi_rgroup_delete_ac_entry_cmd   cmd = {
		.common.op   = CXI_OP_RGROUP_DELETE_AC_ENTRY,
		.common.resp = NULL,
		.rgroup_id   = rgroup_id,
		.ac_entry_id = ac_entry_id,
	};

	return write_device(dev, &cmd, sizeof(cmd));
}

int rgroup_get_ac_entry_ids(struct cass_dev *dev,
			    unsigned int rgroup_id,
			    size_t max_ids,
			    unsigned int *ids,
			    size_t *num_ids)
{
	struct cxi_rgroup_get_ac_entry_ids_resp  resp;
	struct cxi_rgroup_get_ac_entry_ids_cmd   cmd = {
		.common.op   = CXI_OP_RGROUP_GET_AC_ENTRY_IDS,
		.common.resp = &resp,
		.rgroup_id   = rgroup_id,
		.max_ids     = max_ids,
		.ids         = ids,
	};

	int ret = write_device(dev, &cmd, sizeof(cmd));

	if (!num_ids)
		return -EINVAL;

	switch (ret) {
	case 0:
	case -ENOSPC:
		*num_ids = resp.num_ids;
		break;
	default:
		break;
	}
	return ret;
}

int rgroup_get_ac_entry_by_id(struct cass_dev *dev,
			      unsigned int rgroup_id,
			      unsigned int ac_entry_id,
			      enum ucxi_ac_type *type,
			      union ucxi_ac_data *data)
{
	struct cxi_rgroup_get_ac_entry_data_by_id_resp  resp;
	struct cxi_rgroup_get_ac_entry_data_by_id_cmd   cmd = {
		.common.op   = CXI_OP_RGROUP_GET_AC_ENTRY_DATA_BY_ID,
		.common.resp = &resp,
		.rgroup_id   = rgroup_id,
		.ac_entry_id = ac_entry_id,
	};

	int ret = write_device(dev, &cmd, sizeof(cmd));

	if (ret)
		return ret;

	if (!type || !data)
		return -EINVAL;

	switch (resp.ac_type) {
	case UCXI_AC_UID:
		data->uid = resp.uid;
		break;
	case UCXI_AC_GID:
		data->gid = resp.gid;
		break;
	case UCXI_AC_OPEN:
		break;
	default:
		return -EFAULT;
	}

	*type = resp.ac_type;
	return 0;
}

int rgroup_get_ac_entry_id_by_data(struct cass_dev *dev,
				   unsigned int rgroup_id,
				   enum ucxi_ac_type type,
				   const union ucxi_ac_data *data,
				   unsigned int *id)
{
	struct cxi_rgroup_get_ac_entry_id_by_data_resp   resp = {};
	struct cxi_rgroup_get_ac_entry_id_by_data_cmd    cmd = {
		.common.op   = CXI_OP_RGROUP_GET_AC_ENTRY_ID_BY_DATA,
		.common.resp = &resp,
		.rgroup_id   = rgroup_id,
		.ac_type     = type,
	};

	switch (type) {
	case UCXI_AC_UID:
		if (!data)
			return -EINVAL;
		cmd.uid = data->uid;
		break;
	case UCXI_AC_GID:
		if (!data)
			return -EINVAL;
		cmd.gid = data->gid;
		break;
	case UCXI_AC_OPEN:
		break;
	default:
		return -EINVAL;
	}

	int  ret = write_device(dev, &cmd, sizeof(cmd));

	if (ret)
		return ret;

	if (!id)
		return -EINVAL;

	*id = resp.ac_entry_id;
	return 0;
}

int rgroup_get_ac_entry_id_by_user(struct cass_dev *dev,
				   unsigned int rgroup_id,
				   uid_t uid,
				   gid_t gid,
				   unsigned int *id)
{
	struct cxi_rgroup_get_ac_entry_id_by_user_resp   resp = {};
	struct cxi_rgroup_get_ac_entry_id_by_user_cmd    cmd = {
		.common.op     = CXI_OP_RGROUP_GET_AC_ENTRY_ID_BY_USER,
		.common.resp   = &resp,
		.rgroup_id     = rgroup_id,
		.uid           = uid,
		.gid           = gid,
		.desired_types = UCXI_AC_ANY,
	};

	int  ret = write_device(dev, &cmd, sizeof(cmd));

	if (ret)
		return ret;

	if (!id)
		return -EINVAL;

	*id = resp.ac_entry_id;
	return 0;
}

int svc_alloc(struct cass_dev *dev, struct cxi_svc_desc *svc_desc)
{
	int rc;
	struct cxi_svc_alloc_resp resp = {};
	struct cxi_svc_alloc_cmd cmd = {
		.op = CXI_OP_SVC_ALLOC,
		.resp = &resp,
		.svc_desc = *svc_desc,
	};

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		return -1;

	return resp.svc_id;
}

void svc_destroy(struct cass_dev *dev, unsigned int svc_id)
{
	int rc;
	struct cxi_svc_destroy_cmd cmd = {
		.op = CXI_OP_SVC_DESTROY,
		.svc_id = svc_id,
	};

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		perror("free svc");

}
int alloc_lni(struct cass_dev *dev, unsigned int svc_id)
{
	struct cxi_lni_alloc_cmd cmd = {};
	struct cxi_lni_alloc_resp resp;
	int rc;

	cmd.op = CXI_OP_LNI_ALLOC;
	cmd.svc_id = svc_id;
	cmd.resp = &resp;
	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		return -1;

	return resp.lni;
}

void destroy_lni(struct cass_dev *dev, unsigned int lni)
{
	struct cxi_lni_free_cmd cmd = {
		.op = CXI_OP_LNI_FREE,
		.lni = lni,
	};
	int rc;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		perror("free lni");
}

struct ucxi_ct *alloc_ct(struct cass_dev *dev, unsigned int lni)
{
	struct cxi_ct_alloc_cmd cmd = {};
	struct cxi_ct_alloc_resp resp;
	struct ucxi_ct *ct;
	int rc;

	ct = calloc(1, sizeof(*ct));
	if (!ct)
		return NULL;

	cmd.op = CXI_OP_CT_ALLOC;
	cmd.resp = &resp;
	cmd.lni = lni;
	cmd.wb = &ct->wb;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		free(ct);
		perror("failed to allocate counting event");
		return NULL;
	}
	ct->ctn = resp.ctn;

	return ct;
}

void free_ct(struct cass_dev *dev, struct ucxi_ct *ct)
{
	struct cxi_ct_free_cmd cmd = {};
	int rc;

	cmd.op = CXI_OP_CT_FREE;
	cmd.ctn = ct->ctn;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		perror("failed to free counting event");

	free(ct);
}

/* Allocate a domain */
int alloc_domain(struct cass_dev *dev, unsigned int lni,
		 unsigned int vni, unsigned int pid,
		 unsigned int pid_granule)
{
	struct cxi_domain_alloc_cmd cmd = {};
	struct cxi_domain_alloc_resp resp;
	int rc;

	cmd.op = CXI_OP_DOMAIN_ALLOC;
	cmd.resp = &resp;
	cmd.lni = lni;
	cmd.vni = vni;
	cmd.pid = pid;
	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		return -1;

	return resp.domain;
}

void destroy_domain(struct cass_dev *dev, unsigned int domain)
{
	struct cxi_domain_free_cmd cmd = {
		.op = CXI_OP_DOMAIN_FREE,
		.domain = domain,
	};
	int rc;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		perror("free domain");
}

int atu_map(struct cass_dev *dev, unsigned int lni, void *va,
	    size_t len, uint32_t flags, unsigned int *md_hndl,
	    struct cxi_md *md)
{
	int rc;
	struct cxi_atu_map_cmd cmd = {};
	struct cxi_atu_map_resp resp;

	cmd.op = CXI_OP_ATU_MAP;
	cmd.resp = &resp;
	cmd.lni = lni;
	cmd.va = (uint64_t)va;
	cmd.len = len;
	cmd.flags = flags;
	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		printf("%s:write failed rc:%d\n", __func__, rc);
		return -1;
	}

	*md_hndl = resp.id;
	*md = resp.md;

	return 0;
}

int atu_unmap(struct cass_dev *dev, unsigned int md_hndl)
{
	int rc;
	struct cxi_atu_unmap_cmd cmd;

	cmd.op = CXI_OP_ATU_UNMAP;
	cmd.id = md_hndl;
	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		printf("%s:write failed rc:%d\n", __func__, rc);
		return -1;
	}

	return 0;
}

void write_pattern(int *to, int length)
{
	int i;

	for (i = 0; i < length / sizeof(int); i++)
		to[i] = i;
}

struct ucxi_wait *create_wait_obj(struct cass_dev *dev, unsigned int lni,
				  void (*callback)(void *data))
{
	struct cxi_wait_alloc_cmd cmd = {};
	struct cxi_wait_alloc_resp resp;
	int rc;
	struct ucxi_wait *wait;
	char *int_fname;
	char buf[4];

	wait = calloc(1, sizeof(*wait));
	assert(wait != NULL);

	cmd.op = CXI_OP_WAIT_ALLOC;
	cmd.resp = &resp;
	cmd.lni = lni;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		perror("alloc wait");
		return NULL;
	}

	wait->wait = resp.wait;

	/* Connect to interrupt notifier */
	rc = asprintf(&int_fname, "/sys/class/cxi_user/%s/clients/%u/wait/%u/intr",
		      dev->name, resp.client_id, resp.wait);
	if (rc == -1) {
		perror("path alloc failed");
		return NULL;
	}

	wait->fd = open(int_fname, O_RDONLY);
	free(int_fname);
	if (wait->fd == -1) {
		perror("open EQ int notification");
		return NULL;
	}

	/* dummy read to clear the creation event */
	rc = read(wait->fd, buf, sizeof(buf));
	if (rc <= 0) {
		fprintf(stderr, "read on int notification file failed: %d\n",
			rc);
		return NULL;
	}

	return wait;
}

void destroy_wait_obj(struct cass_dev *dev, struct ucxi_wait *wait)
{
	struct cxi_wait_free_cmd cmd = {
		.op = CXI_OP_WAIT_FREE,
		.wait = wait->wait,
	};
	int rc;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		perror("free wait");

	free(wait);
}

int adjust_eq_reserved_fq(struct cass_dev *dev, struct ucxi_eq *eq, int value)
{
	struct cxi_eq_adjust_reserved_fc_resp resp = {};
	struct cxi_eq_adjust_reserved_fc_cmd cmd = {
		.op = CXI_OP_EQ_ADJUST_RESERVED_FC,
		.eq_hndl = eq->eq,
		.value = value,
		.resp = &resp,
	};
	int rc;

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc < 0)
		return -errno;
	else if (rc != sizeof(cmd))
		return -EINVAL;
	return resp.reserved_fc;
}

struct ucxi_eq *create_eq(struct cass_dev *dev, unsigned int lni,
			  struct ucxi_wait *wait, unsigned int reserved_slots)
{
	struct cxi_eq_alloc_cmd cmd = {};
	struct cxi_eq_alloc_resp resp;
	int rc;
	struct ucxi_eq *eq;
	void *eq_buf;
	size_t eq_buf_sz = sysconf(_SC_PAGESIZE);
	uint32_t atu_flags = CXI_MAP_WRITE | CXI_MAP_READ | CXI_MAP_PIN;
	struct cxi_md eq_md;

	eq = calloc(1, sizeof(*eq));
	assert(eq != NULL);

	eq_buf = valloc(eq_buf_sz);
	assert(eq_buf);
	memset(eq_buf, 0, eq_buf_sz);

	rc = atu_map(dev, lni, eq_buf, eq_buf_sz, atu_flags, &eq->eq_md_hndl,
		     &eq_md);
	assert(!rc);

	/* Get a eq */
	cmd.op = CXI_OP_EQ_ALLOC;
	cmd.resp = &resp;
	cmd.lni = lni;
	cmd.queue_md = eq->eq_md_hndl;
	cmd.event_wait = wait ? wait->wait : 0;
	cmd.attr.queue_len = eq_buf_sz;
	cmd.attr.queue = eq_buf;
	cmd.attr.flags = 0;
	cmd.attr.reserved_slots = reserved_slots;
	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		perror("alloc eq");
		atu_unmap(dev, eq->eq_md_hndl);
		return NULL;
	}
	eq->eq = resp.eq;

	eq->evts = eq_buf;
	eq->evts_len = eq_buf_sz;

	/* mmaping csr block */
	eq->csr_len = resp.csr.size;
	eq->csr = mmap(NULL, resp.csr.size,
		       PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd,
		       resp.csr.offset);

	cxi_eq_init(&eq->hw, eq_buf, eq_buf_sz, resp.eq, eq->csr);

	return eq;
}

void destroy_eq(struct cass_dev *dev, struct ucxi_eq *eq)
{
	struct cxi_eq_free_cmd cmd = {
		.op = CXI_OP_EQ_FREE,
		.eq = eq->eq,
	};
	int rc;

	munmap(eq->csr, eq->csr_len);

	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		perror("free eq");

	atu_unmap(dev, eq->eq_md_hndl);

	free(eq->eq_buf);

	free(eq);
}

int create_pte(struct cass_dev *dev, unsigned int lni, unsigned int eq)
{
	struct cxi_pte_alloc_resp resp;
	struct cxi_pte_alloc_cmd cmd = {
		.op = CXI_OP_PTE_ALLOC,
		.resp = &resp,
		.lni_hndl = lni,
		.evtq_hndl = eq,
		.opts = {}
	};
	int rc;

	/* Get a pte */
	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		perror("alloc pte");
		return -1;
	}
	return resp.pte_number;
}

void destroy_pte(struct cass_dev *dev, unsigned int pte_number)
{
	struct cxi_pte_free_cmd cmd = {
		.op = CXI_OP_PTE_FREE,
		.pte_number = pte_number,
	};
	int rc;

	/* free the pte */
	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		perror("free pte");
}

int map_pte(struct cass_dev *dev, unsigned int lni, unsigned int pte,
	    unsigned int domain)
{
	struct cxi_pte_map_resp resp;
	struct cxi_pte_map_cmd cmd = {
		.op = CXI_OP_PTE_MAP,
		.resp = &resp,
		.pte_number = pte,
		.domain_hndl = domain,
		.pid_offset = 0,
		.is_multicast = 0,
	};
	int rc;

	/* Get a pte */
	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		perror("map pte");
		return -1;
	}
	return resp.pte_index;
}

int multicast_map_pte(struct cass_dev *dev, unsigned int lni,
		      unsigned int pte, unsigned int domain,
		      unsigned int mcast_id, unsigned int mcast_idx)
{
	union cxi_pte_map_offset offset;
	struct cxi_pte_map_resp resp;

	offset.mcast_id = mcast_id;
	offset.mcast_pte_index = mcast_idx;
	struct cxi_pte_map_cmd cmd = {
		.op = CXI_OP_PTE_MAP,
		.resp = &resp,
		.pte_number = pte,
		.domain_hndl = domain,
		.pid_offset = offset.uintval,
		.is_multicast = 1,
	};
	int rc;

	/* Get a pte */
	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd)) {
		perror("multicast map pte");
		return -1;
	}
	return resp.pte_index;
}

void unmap_pte(struct cass_dev *dev, unsigned int pte_index)
{
	struct cxi_pte_unmap_cmd cmd = {
		.op = CXI_OP_PTE_UNMAP,
		.pte_index = pte_index,
	};
	int rc;

	/* free the pte */
	rc = write(dev->fd, &cmd, sizeof(cmd));
	if (rc != sizeof(cmd))
		perror("unmap pte");
}

/* If the code is known, returns the name as a string.
 * If unknown, returns a string containing the numeric value.
 * Preserves the sign, in either case.
 * Uses a list of 16 static buffers, so that more than one value
 * can be referred to at a time, as in:
 * printf("Error %s is not %s.\n", errstr(-EBUSY), errstr(-EIO));
 */

const char *errstr(int error_code)
{
#define CTS(_x)    { _x, #_x }
	static struct {
		int           value;
		const char    *str;
	} code_to_str[] = {
		CTS(EADDRINUSE),
		CTS(EAGAIN),
		CTS(EBADRQC),
		CTS(EBADE),
		CTS(EBADR),
		CTS(EBUSY),
		CTS(ECANCELED),
		CTS(EDOM),
		CTS(EEXIST),
		CTS(EFAULT),
		CTS(EHOSTDOWN),
		CTS(EINPROGRESS),
		CTS(EINTR),
		CTS(EINVAL),
		CTS(EIO),
		CTS(EKEYREVOKED),
		CTS(EMEDIUMTYPE),
		CTS(ENODATA),
		CTS(ENODEV),
		CTS(ENOENT),
		CTS(ENOLINK),
		CTS(ENOMEDIUM),
		CTS(ENOMEM),
		CTS(ENOSPC),
		/* CTS(ENOTSUP), */
		/* CTS(ENOTSUPP), */
		CTS(EOPNOTSUPP),
		CTS(EOVERFLOW),
		CTS(EPERM),
		/* CTS(ERESTARTSYS), */
		CTS(ESTALE),
		CTS(ETIMEDOUT),
		CTS(EUCLEAN),
		CTS(E2BIG),
	};
#undef CTS

	static char   buf[16][64];
	static int    buf_num;
	bool          negative = (error_code < 0);
	int           code     = (negative) ? -error_code : error_code;

	if (buf_num >= ARRAY_SIZE(buf))
		buf_num = 0;

	for (size_t i = 0; i < ARRAY_SIZE(code_to_str); i++) {
		if (code_to_str[i].value == code) {
			sprintf(buf[buf_num], "%s%s",
				(negative) ? "-" : "",
				code_to_str[i].str);
			return buf[buf_num++];
		}
	}

	sprintf(buf[buf_num], "%i", error_code);
	return buf[buf_num++];
}
