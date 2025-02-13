/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021,2022,2024 Hewlett Packard Enterprise Development LP */

/* Public definitions for the CXI subsystem */

#ifndef _LINUX_CXI_H
#define _LINUX_CXI_H

#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/uio.h>
#include <linux/firmware.h>
#include <uapi/linux/ethtool.h>
#include <uapi/linux/if.h>
#include <uapi/linux/net_tstamp.h>

#include "cxi_prov_hw.h"
#include "uapi/misc/cxi.h"

#define TRANSACTION_TYPE 0xF

/**
 * struct cxi_dev - A CXI device
 *
 * This represents a CXI PCI device, which can either be the physical
 * device (PF), or a virtual device (VF). Such a device is needed to
 * use most CXI APIs.
 */
struct cxi_dev {
	/* Device name. eg cxi0. */
	char name[30];

	/* Device number */
	unsigned int cxi_num;

	/* Main Ethernet device linked to this device. Used for
	 * logging.
	 */
	char eth_name[IFNAMSIZ];

	/* MAC address assigned to the device */
	u8 mac_addr[ETH_ALEN];

	/* PCP to be used for untagged Ethernet frames. */
	u8 untagged_eth_pcp;

	/* Link to the core's device list */
	struct list_head dev_list;

	/* Whether this device is a PF or a passthrough PF, or a VF. */
	bool is_physfn;

	struct pci_dev *pdev;

	struct cxi_properties_info prop;

	/* System info (mix or homogeneous) */
	enum system_type_identifier system_type_identifier;
};

struct cxi_lni {
	unsigned int id;
	unsigned int rgid;
};

struct cxi_md;

struct cxi_pte {
	/* Portal index */
	unsigned int id;
};

struct cxi_domain {
	unsigned int id;
	unsigned int vni;
	unsigned int pid;
};

struct cxi_ac {
	int acid;
	int lac;
};

enum cxi_async_event {
	CXI_EVENT_CABLE_INSERTED = 1,
	CXI_EVENT_CABLE_REMOVED,
	CXI_EVENT_LINK_UP,
	CXI_EVENT_LINK_DOWN,

	/* The MAC address of the device has being set or
	 * updated. This changes the NID, which some users care
	 * about. When getting this event they can retrieve the new
	 * NID.
	 */
	CXI_EVENT_NID_CHANGED,
};

/* Maximum possible number of RSS queues (must be a power of 2.) */
#define CXI_ETH_MAX_RSS_QUEUES 64

/* Maximum possible number of entries in the indirection table */
#define CXI_ETH_MAX_INDIR_ENTRIES 2048

/* Size of RSS key in bytes, rounded up from 351 bits */
#define CXI_ETH_HASH_KEY_SIZE 44

/* Resources used by an Ethernet device. */
struct cxi_eth_res {
	/* Track which Set List entries are used by this Ethernet
	 * device. The size matches C_RMU_CFG_PTLTE_SET_LIST_ENTRIES.
	 */
	unsigned long sl[BITS_TO_LONGS(128)];

	/* The default catch-all portal table entry. If a packet
	 * doesn't hash, or no hash are defined, this is where it will
	 * go to.
	 */
	unsigned int ptn_def;

	/* Portal for ptp */
	unsigned int ptn_ptp;

	/* Number of RSS queues */
	unsigned int rss_queues;

	/* Number of entries in the indirection table */
	unsigned int rss_indir_size;

	/* Hashing function(s) used. The same hash is used for all Set
	 * List entries for that device.
	 */
	unsigned int portal_index_indir_base;
	u32 hash_types_enabled; /* or'ed C_RSS_HASH_TYPES_ENABLED_T */
	unsigned int ptn_rss[CXI_ETH_MAX_RSS_QUEUES];
	u32 indir_table[CXI_ETH_MAX_INDIR_ENTRIES];
};

#define PTP_L2_MAC 0x011B19000000ULL
#define PTP_L2_ETHERTYPE 0x88f7

struct cxi_ct *cxi_ct_alloc(struct cxi_lni *lni, struct c_ct_writeback *wb,
			    bool is_user);
int cxi_ct_wb_update(struct cxi_ct *ct, struct c_ct_writeback *wb);
void cxi_ct_free(struct cxi_ct *ct);
int cxi_ct_user_info(struct cxi_ct *ct, phys_addr_t *csr_addr,
		     size_t *csr_size);

struct cxi_lni *cxi_lni_alloc(struct cxi_dev *dev, unsigned int svc_id);
int cxi_lni_free(struct cxi_lni *lni);

struct cxi_cp *cxi_cp_alloc(struct cxi_lni *lni, unsigned int vni,
			    unsigned int tc,
			    enum cxi_traffic_class_type tc_type);
void cxi_cp_free(struct cxi_cp *cp);

int cxi_domain_reserve(struct cxi_lni *lni, unsigned int vni, unsigned int pid,
		       unsigned int count);
struct cxi_domain *cxi_domain_alloc(struct cxi_lni *lni, unsigned int vni,
				    unsigned int pid);
void cxi_domain_free(struct cxi_domain *domain);

struct cxi_md *cxi_map(struct cxi_lni *lni, uintptr_t va, size_t len,
		       u32 flags, const struct cxi_md_hints *hints);
struct cxi_md *cxi_map_iov(struct cxi_lni *lni, const struct iov_iter *iter,
			   u32 flags);
struct cxi_md *cxi_map_sgtable(struct cxi_lni *lni, struct sg_table *sgt,
			       u32 flags);
int cxi_update_sgtable(struct cxi_md *md, struct sg_table *sgt);
int cxi_unmap(struct cxi_md *md);
int cxi_update_md(struct cxi_md *md, uintptr_t va, size_t len, u32 flags);
int cxi_phys_lac_alloc(struct cxi_lni *lni);
void cxi_phys_lac_free(struct cxi_lni *lni, int lac);
int cxi_clear_md(struct cxi_md *md);
int cxi_update_iov(struct cxi_md *md, const struct iov_iter *iter);

struct cxi_eq *cxi_eq_alloc(struct cxi_lni *lni, const struct cxi_md *md,
			    const struct cxi_eq_attr *attr,
			    void (*event_cb)(void *cb_data),
			    void *event_cb_data,
			    void (*status_cb)(void *cb_data),
			    void *status_cb_data);
int cxi_eq_adjust_reserved_fc(struct cxi_eq *eq, int value);
int cxi_eq_user_info(struct cxi_eq *evtq,
		     phys_addr_t *csr_addr, size_t *csr_size);
int cxi_eq_free(struct cxi_eq *evtq);

int cxi_eq_resize(struct cxi_eq *evtq, void *queue, size_t queue_len,
		  struct cxi_md *queue_md);
int cxi_eq_resize_complete(struct cxi_eq *evtq);
struct cxi_cq *cxi_cq_alloc(struct cxi_lni *lni, struct cxi_eq *evtq,
			    const struct cxi_cq_alloc_opts *opts,
			    int numa_node);
int cxi_cq_user_info(struct cxi_cq *cmdq,
		     size_t *cmds_size, struct page **cmds_pages,
		     phys_addr_t *wp_addr, size_t *wp_addr_size);
void cxi_cq_free(struct cxi_cq *cmdq);
unsigned int cxi_cq_ack_counter(struct cxi_cq *cq);

struct cxi_pte *cxi_pte_alloc(struct cxi_lni *lni, struct cxi_eq *evtq,
			      const struct cxi_pt_alloc_opts *opts);
void cxi_pte_free(struct cxi_pte *pt);
int cxi_pte_map(struct cxi_pte *pt, struct cxi_domain *domain,
		unsigned int pid_offset, bool is_multicast,
		unsigned int *pt_index);
int cxi_pte_unmap(struct cxi_pte *pt, struct cxi_domain *domain, int pt_index);
void cxi_pte_le_invalidate(struct cxi_pte *pt, unsigned int buffer_id,
			   enum c_ptl_list list);
int cxi_pte_status(struct cxi_pte *pte, struct cxi_pte_status *status);
int cxi_pte_transition_sm(struct cxi_pte *pt, unsigned int drop_count);
int cxi_inbound_wait(struct cxi_dev *cdev);

int cxi_svc_alloc(struct cxi_dev *dev, const struct cxi_svc_desc *svc,
		  struct cxi_svc_fail_info *fail_info);
int cxi_svc_destroy(struct cxi_dev *dev, unsigned int svc_id);
int cxi_svc_list_get(struct cxi_dev *dev, int count,
		     struct cxi_svc_desc *svc_list);
int cxi_svc_update(struct cxi_dev *dev, const struct cxi_svc_desc *svc);
int cxi_svc_set_lpr(struct cxi_dev *dev, unsigned int svc_id,
		    unsigned int lnis_per_rgid);
int cxi_svc_get_lpr(struct cxi_dev *dev, unsigned int svc_id);
int cxi_svc_get(struct cxi_dev *dev, unsigned int svc_id,
		struct cxi_svc_desc *svc_desc);
int cxi_svc_rsrc_list_get(struct cxi_dev *dev, int count,
			  struct cxi_rsrc_use *rsrc_list);
int cxi_svc_rsrc_get(struct cxi_dev *dev, unsigned int svc_id,
		     struct cxi_rsrc_use *rsrc_use);
int cxi_get_tc_req_pcp(struct cxi_dev *dev, unsigned int tc);
int cxi_dev_info_get(struct cxi_dev *dev,
		     struct cxi_dev_info_use *devinfo);

/* Access Control Entries */
typedef unsigned int __bitwise cxi_ac_typeset_t;
enum cxi_ac_type {
	CXI_AC_UID  = (__force cxi_ac_typeset_t)BIT(0),
	CXI_AC_GID  = (__force cxi_ac_typeset_t)BIT(1),
	CXI_AC_OPEN = (__force cxi_ac_typeset_t)BIT(2),
};

/* Parameter for use with the 'by_user' retrieve functions */
#define CXI_AC_ANY (CXI_AC_UID | CXI_AC_GID | CXI_AC_OPEN)

union cxi_ac_data {
	uid_t     uid;
	gid_t     gid;
};

struct cxi_ac_entry;

struct cxi_ac_entry_list {
	struct cxi_ac_entry *open_entry;
	struct {
		struct xarray       xarray;
	} uid;
	struct {
		struct xarray       xarray;
	} gid;
	struct {
		struct xarray       xarray;
	} id;
};

void cxi_ac_entry_list_init(struct cxi_ac_entry_list *list);

void cxi_ac_entry_list_purge(struct cxi_ac_entry_list *list);

void cxi_ac_entry_list_destroy(struct cxi_ac_entry_list *list);

bool cxi_ac_entry_list_empty(struct cxi_ac_entry_list *list);

int cxi_ac_entry_list_insert(struct cxi_ac_entry_list *list,
			     enum cxi_ac_type ac_type,
			     const union cxi_ac_data *ac_data,
			     unsigned int *id);

int cxi_ac_entry_list_delete(struct cxi_ac_entry_list *list,
			     unsigned int id);

int cxi_ac_entry_list_retrieve_by_id(struct cxi_ac_entry_list *list,
				     unsigned int id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *data);

int cxi_ac_entry_list_retrieve_by_data(struct cxi_ac_entry_list *list,
				       enum cxi_ac_type ac_type,
				       const union cxi_ac_data *ac_data,
				       unsigned int *id);

int cxi_ac_entry_list_retrieve_by_user(struct cxi_ac_entry_list *list,
				       uid_t uid,
				       gid_t gid,
				       cxi_ac_typeset_t desired_types,
				       unsigned int *id);

int cxi_ac_entry_list_get_ids(struct cxi_ac_entry_list *list,
			      size_t max_ids,
			      unsigned int *ids,
			      size_t *num_ids);

/* Common list for RX and TX Profiles */
struct cxi_rxtx_profile_list {
	struct xarray    xarray;
	struct xa_limit  *limits;
	gfp_t            flags;
	gfp_t            gfp_opts;
};

/* Common parts of RX and TX Profiles */
#define CXI_VNI_NAME_LEN    64

struct cxi_rxtx_vni_attr {
	uint16_t         match;
	uint16_t         ignore;
	char             name[CXI_VNI_NAME_LEN];
};

struct cxi_rxtx_profile_state {
	atomic_t         released;
	bool             revoked;
	refcount_t       refcount;
};

struct cxi_rxtx_profile {
	unsigned int                   id;
	struct cxi_rxtx_vni_attr       vni_attr;
	struct cxi_rxtx_profile_state  state;
	struct cxi_ac_entry_list       ac_entry_list;
};

/* RX Profile */

/* Struct to hold HW configuration */
struct cxi_rx_config {
	int              rmu_index;
};

/* Struct for creation and listing */
struct cxi_rx_attr {
	struct cxi_rxtx_vni_attr        vni_attr;
	/* TODO: other RX specific attributes */
};

struct cxi_rx_profile {
	struct cxi_rxtx_profile         profile_common;
	struct cxi_rx_config            config;
	/* TODO: other RX parameters */
};

/* TX Profile */

struct cxi_tx_config {
	int              cp_id;  /* this is a guess */
};

/* Struct for creation and listing */
struct cxi_tx_attr {
	struct cxi_rxtx_vni_attr        vni_attr;
	/* TODO: other TX specific attributes */
};

struct cxi_tx_profile {
	struct cxi_rxtx_profile         profile_common;
	struct cxi_tx_config            config;
};

int tx_profile_find_inc_refcount(struct cxi_dev *dev,
				 unsigned int tx_profile_id,
				 struct cxi_tx_profile **tx_profile);
int rx_profile_find_inc_refcount(struct cxi_dev *dev,
				 unsigned int rx_profile_id,
				 struct cxi_rx_profile **rx_profile);

int cxi_dev_alloc_rx_profile(struct cxi_dev *dev,
			     const struct cxi_rx_attr *rx_attr,
			     unsigned int *rx_profile_id);
int cxi_dev_get_rx_profile_ids(struct cxi_dev *dev,
			       size_t max_entries,
			       unsigned int *rx_profile_ids,
			       size_t *num_entries);
int cxi_dev_rx_profile_add_ac_entry(struct cxi_dev *dev, enum cxi_ac_type type,
				    uid_t uid, gid_t gid,
				    unsigned int rx_profile_id,
				    unsigned int *ac_entry_id);
int cxi_dev_rx_profile_remove_ac_entries(struct cxi_dev *dev,
					 unsigned int rx_profile_id);

int cxi_rx_profile_find_inc_refcount(struct cxi_dev *dev,
				     unsigned int vni_entry_id,
				     struct cxi_rx_profile **rx_profile);
int cxi_rx_profile_dec_refcount(struct cxi_dev *dev,
				struct cxi_rx_profile *rx_profile);

int cxi_rx_profile_release(struct cxi_dev *dev,
			   unsigned int rx_profile_id);
int cxi_rx_profile_revoke(struct cxi_dev *dev,
			  unsigned int rx_profile_id);

int cxi_rx_profile_get_info(struct cxi_dev *dev,
			    unsigned int rx_profile_id,
			    struct cxi_rx_attr *rx_attr,
			    struct cxi_rxtx_profile_state *state);

int cxi_rx_profile_add_ac_entry(struct cxi_rx_profile *rx_profile,
				enum cxi_ac_type ac_type,
				union cxi_ac_data *ac_data,
				unsigned int *ac_entry_id);
int cxi_rx_profile_remove_ac_entry(struct cxi_rx_profile *rx_profile,
				   unsigned int ac_entry_id);
int cxi_rx_profile_get_ac_entry_ids(struct cxi_rx_profile *rx_profile,
				    size_t max_ids,
				    unsigned int *ac_entry_ids,
				    size_t *num_ids);

int cxi_rx_profile_get_ac_entry_data(struct cxi_rx_profile *rx_profile,
				     unsigned int ac_entry_id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *ac_data);
int cxi_rx_profile_get_ac_entry_id_by_data(struct cxi_rx_profile *rx_profile,
					   enum cxi_ac_type ac_type,
					   const union cxi_ac_data *ac_data,
					   unsigned int *ac_entry_id);
int cxi_rx_profile_get_ac_entry_id_by_user(struct cxi_rx_profile *rx_profile,
					   uid_t uid,
					   gid_t gid,
					   cxi_ac_typeset_t desired_types,
					   unsigned int *ac_entry_id);

int cxi_dev_alloc_tx_profile(struct cxi_dev *dev,
			     const struct cxi_tx_attr *tx_attr,
			     unsigned int *tx_profile_id);
int cxi_dev_get_tx_profile_ids(struct cxi_dev *dev,
			       size_t max_entries,
			       unsigned int *tx_profile_ids,
			       size_t *num_entries);
int cxi_dev_tx_profile_add_ac_entry(struct cxi_dev *dev, enum cxi_ac_type type,
				    uid_t uid, gid_t gid,
				    unsigned int tx_profile_id,
				    unsigned int *ac_entry_id);
int cxi_dev_tx_profile_remove_ac_entries(struct cxi_dev *dev,
					 unsigned int tx_profile_id);

int cxi_tx_profile_release(struct cxi_dev *dev,
			   unsigned int tx_profile_id);
int cxi_tx_profile_revoke(struct cxi_dev *dev,
			  unsigned int tx_profile_id);

int cxi_tx_profile_get_info(struct cxi_dev *dev,
			    unsigned int tx_profile_id,
			    struct cxi_tx_attr *tx_attr,
			    struct cxi_rxtx_profile_state *state);

int cxi_tx_profile_find_inc_refcount(struct cxi_dev *dev,
				     unsigned int vni_entry_id,
				     struct cxi_tx_profile **tx_profile);
int cxi_tx_profile_dec_refcount(struct cxi_dev *dev,
				struct cxi_tx_profile *tx_profile);

int cxi_tx_profile_add_ac_entry(struct cxi_tx_profile *tx_profile,
				enum cxi_ac_type ac_type,
				union cxi_ac_data *ac_data,
				unsigned int *ac_entry_id);
int cxi_tx_profile_remove_ac_entry(struct cxi_tx_profile *tx_profile,
				   unsigned int ac_entry_id);
int cxi_tx_profile_get_ac_entry_ids(struct cxi_tx_profile *tx_profile,
				    size_t max_ids,
				    unsigned int *ac_entry_ids,
				    size_t *num_ids);

int cxi_tx_profile_get_ac_entry_data(struct cxi_tx_profile *tx_profile,
				     unsigned int ac_entry_id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *ac_data);
int cxi_tx_profile_get_ac_entry_id_by_data(struct cxi_tx_profile *tx_profile,
					   enum cxi_ac_type ac_type,
					   const union cxi_ac_data *ac_data,
					   unsigned int *ac_entry_id);
int cxi_tx_profile_get_ac_entry_id_by_user(struct cxi_tx_profile *tx_profile,
					   uid_t uid,
					   gid_t gid,
					   cxi_ac_typeset_t desired_types,
					   unsigned int *ac_entry_id);

/* Resource Group Entries */

struct cxi_rgroup;

enum cxi_resource_type {
	CXI_RESOURCE_PTLTE  = 1,
	CXI_RESOURCE_TXQ,
	CXI_RESOURCE_TGQ,
	CXI_RESOURCE_EQ,
	CXI_RESOURCE_CT,
	CXI_RESOURCE_PE0_LE,
	CXI_RESOURCE_PE1_LE,
	CXI_RESOURCE_PE2_LE,
	CXI_RESOURCE_PE3_LE,
	CXI_RESOURCE_TLE,
	CXI_RESOURCE_AC,
	CXI_RESOURCE_MAX,
};

static const char * const cxi_resource_type_strs[] = {
	[CXI_RESOURCE_PTLTE] = "PTLTE",
	[CXI_RESOURCE_TXQ] = "TXQ",
	[CXI_RESOURCE_TGQ] = "TGQ",
	[CXI_RESOURCE_EQ] = "EQ",
	[CXI_RESOURCE_CT] = "CT",
	[CXI_RESOURCE_PE0_LE] = "PE0_LE",
	[CXI_RESOURCE_PE1_LE] = "PE1_LE",
	[CXI_RESOURCE_PE2_LE] = "PE2_LE",
	[CXI_RESOURCE_PE3_LE] = "PE3_LE",
	[CXI_RESOURCE_TLE] = "TLE",
	[CXI_RESOURCE_AC] = "AC",
};

static inline
const char *cxi_resource_type_to_str(enum cxi_resource_type type)
{
	if (type >= CXI_RESOURCE_PTLTE && type < CXI_RESOURCE_MAX)
		return cxi_resource_type_strs[type];

	return "(invalid)";
}

struct cxi_resource_limits {
	size_t     reserved;
	size_t     max;
	size_t     in_use;
};

struct cxi_resource_use {
	size_t     reserved;
	size_t     shared;
	size_t     shared_use;
	size_t     in_use;
	size_t     max;
};

struct cxi_resource_entry {
	struct cxi_rgroup          *rgroup;
	enum cxi_resource_type     type;
	struct cxi_resource_limits limits;
};

struct cxi_resource_entry_list {
	struct cxi_rgroup   *rgroup;
	struct xarray       xarray;
};

struct cxi_rgroup_pools {
	int            le_pool_id[C_PE_COUNT];
	int            tle_pool_id;
};

/* Resource Group */

struct cxi_rgroup_attr {
	unsigned int   cntr_pool_id;
	bool           system_service;
	char           name[50];
	unsigned int   lnis_per_rgid;
};

struct cxi_rgroup_state {
	bool           enabled;
	bool           released;
	refcount_t     refcount;
};

struct cxi_rgroup {
	unsigned int                   id;
	struct cass_dev                *hw;
	struct cxi_rgroup_attr         attr;
	struct cxi_rgroup_state        state;
	struct cxi_resource_entry_list resource_entry_list;
	struct cxi_ac_entry_list       ac_entry_list;
	struct cxi_rgroup_pools        pools;
	struct cxi_svc_priv *svc_priv;
};

int cxi_rgroup_enable(struct cxi_rgroup *rgroup);

void cxi_rgroup_disable(struct cxi_rgroup *rgroup);

void cxi_rgroup_get_info(struct cxi_rgroup *rgroup,
			struct cxi_rgroup_attr *attr,
			struct cxi_rgroup_state *state);

int cxi_rgroup_add_resource(struct cxi_rgroup *rgroup,
			    enum cxi_resource_type resource_type,
			    const struct cxi_resource_limits *limits);

int cxi_rgroup_delete_resource(struct cxi_rgroup *rgroup,
			       enum cxi_resource_type resource_type);

int cxi_rgroup_get_resource(struct cxi_rgroup *rgroup,
			    enum cxi_resource_type resource_type,
			    struct cxi_resource_limits *limits);

int cxi_rgroup_get_resource_entry(struct cxi_rgroup *rgroup,
				  enum cxi_resource_type type,
				  struct cxi_resource_entry **entry);

int cxi_rgroup_get_resource_types(struct cxi_rgroup *rgroup,
				  size_t max_resources,
				  enum cxi_resource_type *resource_types,
				  size_t *num_resources);

int cxi_rgroup_add_ac_entry(struct cxi_rgroup *rgroup,
			    enum cxi_ac_type type,
			    const union cxi_ac_data *data,
			    unsigned int *ac_entry_id);

int cxi_rgroup_delete_ac_entry(struct cxi_rgroup *rgroup,
			       unsigned int ac_entry_id);

int cxi_rgroup_get_ac_entry_ids(struct cxi_rgroup *rgroup,
				size_t max_ids,
				unsigned int *ids,
				size_t *num_ids);

int cxi_rgroup_get_ac_entry_data(struct cxi_rgroup *rgroup,
				 unsigned int ac_entry_id,
				 enum cxi_ac_type *type,
				 union cxi_ac_data *ac_data);

int cxi_rgroup_get_ac_entry_id_by_data(struct cxi_rgroup *rgroup,
				       enum cxi_ac_type type,
				       const union cxi_ac_data *ac_data,
				       unsigned int *ac_entry_id);

int cxi_rgroup_get_ac_entry_by_user(struct cxi_rgroup *rgroup,
				    uid_t uid,
				    gid_t gid,
				    cxi_ac_typeset_t desired_types,
				    unsigned int *ac_entry_id);

int cxi_rgroup_dec_refcount(struct cxi_rgroup *rgroup);

int cxi_dev_alloc_rgroup(struct cxi_dev *dev,
			 const struct cxi_rgroup_attr *attr,
			 unsigned int *rgroup_id);

int cxi_dev_find_rgroup_inc_refcount(struct cxi_dev *dev,
				     unsigned int id,
				     struct cxi_rgroup **rgroup);

int cxi_dev_get_rgroup_ids(struct cxi_dev *dev,
			   size_t max_ids,
			   unsigned int *rgroup_ids,
			   size_t *num_ids);

int cxi_dev_rgroup_release(struct cxi_dev *dev,
			   unsigned int rgroup_id);

int cxi_dev_rgroup_enable(struct cxi_dev *dev,
			  unsigned int rgroup_id);

int cxi_dev_rgroup_disable(struct cxi_dev *dev,
			   unsigned int rgroup_id);

int cxi_dev_rgroup_get_info(struct cxi_dev *dev,
			    unsigned int rgroup_id,
			    struct cxi_rgroup_attr *attr,
			    struct cxi_rgroup_state *state);

int cxi_dev_rgroup_add_resource(struct cxi_dev *dev,
				unsigned int rgroup_id,
				enum cxi_resource_type resource_type,
				struct cxi_resource_limits *limits);

int cxi_dev_rgroup_delete_resource(struct cxi_dev *dev,
				   unsigned int rgroup_id,
				   enum cxi_resource_type resource_type);

int cxi_dev_rgroup_get_resource(struct cxi_dev *dev,
				unsigned int rgroup_id,
				enum cxi_resource_type resource_type,
				struct cxi_resource_limits *limits);

int cxi_dev_rgroup_get_resource_types(struct cxi_dev *dev,
				      unsigned int rgroup_id,
				      size_t max_types,
				      enum cxi_resource_type *resource_types,
				      size_t *num_types);

int cxi_dev_rgroup_add_ac_entry(struct cxi_dev *dev,
				unsigned int rgroup_id,
				enum cxi_ac_type ac_type,
				union cxi_ac_data *ac_data,
				unsigned int *ac_entry_id);

int cxi_dev_rgroup_delete_ac_entry(struct cxi_dev *dev,
				   unsigned int rgroup_id,
				   unsigned int ac_entry_id);

int cxi_dev_rgroup_get_ac_entry_ids(struct cxi_dev *dev,
				    unsigned int rgroup_id,
				    size_t max_ids,
				    unsigned int *ac_entry_ids,
				    size_t *num_ids);

int cxi_dev_rgroup_get_ac_entry_data(struct cxi_dev *dev,
				     unsigned int rgroup_id,
				     unsigned int ac_entry_id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *ac_data);

int cxi_dev_rgroup_get_ac_entry_id_by_data(struct cxi_dev *dev,
					   unsigned int rgroup_id,
					   enum cxi_ac_type ac_type,
					   union cxi_ac_data *ac_data,
					   unsigned int *ac_entry_id);

int cxi_dev_rgroup_get_ac_entry_id_by_user(struct cxi_dev *dev,
					   unsigned int rgroup_id,
					   uid_t uid,
					   gid_t gid,
					   cxi_ac_typeset_t desired_types,
					   unsigned int *ac_entry_id);

struct cxi_client {
	/* Add and remove devices callback */
	int (*add)(struct cxi_dev *dev);
	void (*remove)(struct cxi_dev *dev);

	/* Asynchronous events handler */
	void (*async_event)(struct cxi_dev *cxi_dev,
			    enum cxi_async_event event);

	/* For the core */
	struct list_head list;
};
int cxi_register_client(struct cxi_client *client);
void cxi_unregister_client(struct cxi_client *client);
void cxi_set_nid(struct cxi_dev *dev, const u8 *mac_addr);

typedef int (*cxi_msg_relay_t)(void *data, unsigned int vf_num,
			       const void *req, size_t req_len,
			       void *rsp, size_t *rsp_len);
int cxi_register_msg_relay(struct cxi_dev *cdev, cxi_msg_relay_t msg_relay,
			   void *msg_relay_data);
int cxi_unregister_msg_relay(struct cxi_dev *cdev);
int cxi_send_msg_to_pf(struct cxi_dev *cdev, const void *req, size_t req_len,
		       void *rsp, size_t *rsp_len);

int cxi_set_max_eth_rxsize(struct cxi_dev *cdev, unsigned int max_std_size);
int cxi_eth_add_mac(struct cxi_dev *cdev, struct cxi_eth_res *res,
		    u64 mac_addr, bool is_ptp);
int cxi_eth_set_promiscuous(struct cxi_dev *cdev, struct cxi_eth_res *res);
int cxi_eth_set_all_multi(struct cxi_dev *cdev, struct cxi_eth_res *res);
void cxi_eth_set_list_invalidate_all(struct cxi_dev *cdev,
				     struct cxi_eth_res *res);
void cxi_eth_set_indir_table(struct cxi_dev *cdev, struct cxi_eth_res *res);
void cxi_eth_clear_indir_table(struct cxi_dev *cdev, struct cxi_eth_res *res);
void cxi_eth_get_hash_key(struct cxi_dev *cdev, u8 *key);
void cxi_eth_get_pause(struct cxi_dev *cdev, struct ethtool_pauseparam *pause);
void cxi_eth_set_pause(struct cxi_dev *cdev, const struct ethtool_pauseparam *pause);
int cxi_eth_cfg_timestamp(struct cxi_dev *cdev,
			  struct hwtstamp_config *config);
int cxi_eth_get_tx_timestamp(struct cxi_dev *cdev,
			     struct skb_shared_hwtstamps *tstamps);
void cxi_set_ethernet_threshold(struct cxi_dev *cdev, unsigned int threshold);
void cxi_set_roce_rcv_seg(struct cxi_dev *cdev, bool enable);
void cxi_set_eth_name(struct cxi_dev *cdev, const char *name);

void cxi_get_csrs_range(struct cxi_dev *cdev, phys_addr_t *base, size_t *len);

struct cxi_eth_info {
	/* The size at which an Ethernet packet is segmented. Each
	 * segment of the packet will be this size.
	 */
	unsigned int max_segment_size;

	/* The device's min_free_shift setting */
	unsigned int min_free_shift;

	/* Default MAC address, as programmed in the uC */
	u8 default_mac_addr[ETH_ALEN];

	/* Current copy of the QSFP eeprom, with its length. If length
	 * is 0, the data is not valid.
	 */
	u8 qsfp_eeprom[ETH_MODULE_SFF_8436_LEN];
	unsigned int qsfp_eeprom_len;

	/* Firmware version, as returned by the uC for FW_QSPI_BLOB. */
	char fw_version[16];

	/* Expansion ROM version, as returned by the uC for FW_OPROM. */
	char erom_version[16];

	int ptp_clock_index;
};
void cxi_eth_devinfo(struct cxi_dev *cdev, struct cxi_eth_info *eth_info);
int cxi_get_qsfp_data(struct cxi_dev *cdev, u32 offset, u32 len, u32 page, u8 *data);

int cxi_program_firmware(struct cxi_dev *cdev, const struct firmware *fw);

int cxi_sbus_op(struct cxi_dev *cdev, const struct cxi_sbus_op_params *params,
		u32 *rsp_data, u8 *result_code, u8 *overrun);
int cxi_sbus_op_reset(struct cxi_dev *cdev);
int cxi_serdes_op(struct cxi_dev *cdev, u64 serdes_sel, u64 op, u64 data,
		  int timeout, unsigned int flags, u16 *result);

bool cxi_is_link_up(struct cxi_dev *cdev);
void cxi_sbl_disable_pml_recovery(struct cxi_dev *cdev, bool disable);

int cxi_dmac_desc_set_alloc(struct cxi_dev *cdev, u16 num_descs,
			    const char *name);
int cxi_dmac_desc_set_reserve(struct cxi_dev *cdev, u16 num_descs,
			      u16 desc_idx, const char *name);
int cxi_dmac_desc_set_free(struct cxi_dev *cdev, int set_id);
int cxi_dmac_desc_set_reset(struct cxi_dev *cdev, int set_id);
int cxi_dmac_desc_set_add(struct cxi_dev *cdev, int set_id, dma_addr_t dst,
			  u32 src, size_t len);
int cxi_dmac_xfer(struct cxi_dev *cdev, int set_id);

int cxi_telem_get_selected(struct cxi_dev *cdev, const unsigned int *items,
			   u64 *data, unsigned int count);

bool cxi_retry_handler_running(struct cxi_dev *cdev);

void cxi_set_led_beacon(struct cxi_dev *cdev, bool state);

int cxi_get_lpe_append_credits(unsigned int lpe_cdt_thresh_id);

#endif	/* _LINUX_CXI_H */
