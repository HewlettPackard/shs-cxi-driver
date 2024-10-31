/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2018,2024 Hewlett Packard Enterprise Development LP */

#ifndef __TEST_UCXI_COMMON_H__
#define __TEST_UCXI_COMMON_H__

#include "cxi_prov_hw.h"
#include "uapi/misc/cxi.h"

/*
 * We don't have ARRAY_SIZE in user-space.  But
 * checkpatch.pl insists we do, and that we should use it.
 * So to define ARRAY_SIZE, and fool checkpatch.pl, we
 * add extra parens.
 */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(_a)   ((sizeof(_a))/(sizeof(_a[0])))
#endif

struct cass_dev {
	int fd;
	char name[5];
	char devname[20];
	void *mapped_csrs;
	size_t mapped_csrs_size;
};

struct ucxi_cp {
	unsigned int lcid;
	unsigned int cp_hndl;
};

struct ucxi_cq {
	int cq;
	struct cxi_cmd64 *cmds;
	size_t cmds_len;
	void *wp_addr;
	size_t wp_addr_len;
	struct cxi_cq cmdq;
};

struct ucxi_eq {
	int eq;
	void *evts;
	size_t evts_len;
	int int_fd;
	void *csr;
	size_t csr_len;
	struct cxi_eq hw;
	void *eq_buf;
	unsigned int eq_md_hndl;
};

struct ucxi_wait {
	/* Handle */
	unsigned int wait;

	/* File descriptor to poll() on. */
	unsigned int fd;
};

struct ucxi_ct {
	int ctn;
	struct c_ct_writeback wb;
};

int svc_alloc(struct cass_dev *dev, struct cxi_svc_desc *svc_desc);
void svc_destroy(struct cass_dev *dev, unsigned int svc_id);

enum ucxi_resource_type {
	UCXI_RESOURCE_PTLTE = 1,
	UCXI_RESOURCE_TXQ,
	UCXI_RESOURCE_TGQ,
	UCXI_RESOURCE_EQ,
	UCXI_RESOURCE_CT,
	UCXI_RESOURCE_PE0_LE,
	UCXI_RESOURCE_PE1_LE,
	UCXI_RESOURCE_PE2_LE,
	UCXI_RESOURCE_PE3_LE,
	UCXI_RESOURCE_TLE,
	UCXI_RESOURCE_AC,
};

struct ucxi_resource_limits {
	size_t     reserved;
	size_t     max;
};

struct ucxi_rgroup_attr {
	unsigned int    cntr_pool_id;
	bool            system_service;
	char            name[50];
};

struct ucxi_rgroup_state {
	bool            enabled;
	bool            released;
	int             refcount;
};

union ucxi_ac_data {
	uid_t    uid;
	gid_t    gid;
};

int alloc_rgroup(struct cass_dev *dev,
		 const struct ucxi_rgroup_attr *attr,
		 unsigned int *rgroup_id);
int release_rgroup(struct cass_dev *dev,
		  unsigned int rgroup_id);
int enable_rgroup(struct cass_dev *dev,
		  unsigned int rgroup_id);
int disable_rgroup(struct cass_dev *dev,
		   unsigned int rgroup_id);

int get_rgroup_ids(struct cass_dev *dev,
		   size_t max_ids,
		   unsigned int *rgroup_ids,
		   size_t *num_ids);

int get_rgroup_info(struct cass_dev *dev,
		    unsigned int rgroup_id,
		    struct ucxi_rgroup_attr *attr,
		    struct ucxi_rgroup_state *state);

int rgroup_add_resource(struct cass_dev *dev,
			unsigned int rgroup_id,
			enum ucxi_resource_type resource_type,
			const struct ucxi_resource_limits *limits);

int rgroup_delete_resource(struct cass_dev *dev,
			   unsigned int rgroup_id,
			   enum ucxi_resource_type resource_type);

int rgroup_get_resource_types(struct cass_dev *dev,
			      unsigned int rgroup_id,
			      size_t max_types,
			      enum ucxi_resource_type *resource_types,
			      size_t *num_types);

int rgroup_get_resource(struct cass_dev *dev,
			unsigned int rgroup_id,
			enum ucxi_resource_type resource_type,
			struct ucxi_resource_limits *limits);

int rgroup_add_ac_entry(struct cass_dev *dev,
			unsigned int rgroup_id,
			enum ucxi_ac_type ac_type,
			const union ucxi_ac_data *data,
			unsigned int *id);

int rgroup_delete_ac_entry(struct cass_dev *dev,
			   unsigned int rgroup_id,
			   unsigned int id);

int rgroup_get_ac_entry_ids(struct cass_dev *dev,
			    unsigned int rgroup_id,
			    size_t max_ids,
			    unsigned int *ids,
			    size_t *num_ids);

int rgroup_get_ac_entry_by_id(struct cass_dev *dev,
			      unsigned int rgroup_id,
			      unsigned int id,
			      enum ucxi_ac_type *type,
			      union ucxi_ac_data *data);

int rgroup_get_ac_entry_id_by_data(struct cass_dev *dev,
				   unsigned int rgroup_id,
				   enum ucxi_ac_type type,
				   const union ucxi_ac_data *data,
				   unsigned int *ac_entry_id);

int rgroup_get_ac_entry_id_by_user(struct cass_dev *dev,
				   unsigned int rgroup_id,
				   uid_t uid,
				   gid_t gid,
				   unsigned int *ac_entry_id);

int tc_cfg(struct cass_dev *dev, enum cxi_traffic_class tc,
	   unsigned int rdscp, unsigned int udscp,
	   unsigned int ocu_set_idx, unsigned int *tc_id);
int tc_clear(struct cass_dev *dev, unsigned int tc_id);

extern struct ucxi_cp *alloc_cp(struct cass_dev *dev, unsigned int lni,
				unsigned int vni, enum cxi_traffic_class tc);
extern void destroy_cp(struct cass_dev *dev, struct ucxi_cp *cp);

extern void free_ct(struct cass_dev *dev, struct ucxi_ct *ct);
extern struct ucxi_ct *alloc_ct(struct cass_dev *dev, unsigned int lni);

extern struct cass_dev *open_device(const char *name);

extern void close_device(struct cass_dev *dev);
int map_csr(struct cass_dev *dev);
int read_csr(struct cass_dev *dev, unsigned int csr,
	     void *value, size_t csr_len);
extern struct ucxi_cq *create_cq(struct cass_dev *dev, unsigned int lni,
				 bool is_transmit, unsigned int lcid);

extern void destroy_cq(struct cass_dev *dev, struct ucxi_cq *cq);

extern int cq_get_ack_counter(struct cass_dev *dev, struct ucxi_cq *cq,
			      unsigned int *ack_counter);

extern int alloc_lni(struct cass_dev *dev, unsigned int svc_id);

extern void destroy_lni(struct cass_dev *dev, unsigned int lni);

/* Allocate a domain */
extern int alloc_domain(struct cass_dev *dev, unsigned int lni,
			unsigned int vni, unsigned int pid,
			unsigned int pid_granule);

extern void destroy_domain(struct cass_dev *dev, unsigned int domain);

extern int atu_map(struct cass_dev *dev, unsigned int lni, void *va,
		   size_t len, uint32_t flags, unsigned int *md_hndl,
		   struct cxi_md *md);
extern int atu_unmap(struct cass_dev *dev, unsigned int md_hndl);

extern void write_pattern(int *to, int length);

extern int adjust_eq_reserved_fq(struct cass_dev *dev, struct ucxi_eq *eq,
				 int value);
extern struct ucxi_eq *create_eq(struct cass_dev *dev, unsigned int lni,
				 struct ucxi_wait *wait,
				 unsigned int reserved_slots);

extern void destroy_eq(struct cass_dev *dev, struct ucxi_eq *eq);

extern int create_pte(struct cass_dev *dev, unsigned int lni,
		      unsigned int eq);

extern void destroy_pte(struct cass_dev *dev, unsigned int pte_number);

extern int map_pte(struct cass_dev *dev, unsigned int lni, unsigned int pte,
		   unsigned int domain);

extern int multicast_map_pte(struct cass_dev *dev, unsigned int lni,
			     unsigned int pte, unsigned int domain,
			     unsigned int mcast_id, unsigned int mcast_idx);

extern void unmap_pte(struct cass_dev *dev, unsigned int pte_index);

struct ucxi_wait *create_wait_obj(struct cass_dev *dev, unsigned int lni,
				  void (*acllback)(void *data));
void destroy_wait_obj(struct cass_dev *dev, struct ucxi_wait *wait);

const char *errstr(int error_code);

#endif /* __TEST_UCXI_COMMON_H__ */
