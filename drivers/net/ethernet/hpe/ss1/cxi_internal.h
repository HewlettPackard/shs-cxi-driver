/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

#ifndef _CXI_INTERNAL_H
#define _CXI_INTERNAL_H

#include <linux/hpe/cxi/cxi.h>

struct cxi_ct *cxi_ct_alloc_internal(struct cxi_lni *lni,
				     struct c_ct_writeback *wb, bool is_user,
				     dma_addr_t wb_dma_addr);
int cxi_ct_wb_update_internal(struct cxi_ct *ct, struct c_ct_writeback *wb,
			      dma_addr_t wb_dma_addr);

struct cxi_lni *cxi_lni_alloc_internal(struct cxi_dev *dev, unsigned int svc_id,
				       bool vf_en, u8 vf_num);

struct cxi_eq *cxi_eq_alloc_internal(struct cxi_lni *lni, const struct cxi_md *md,
				     const struct cxi_eq_attr *attr,
				     void (*event_cb)(void *cb_data),
				     void *event_cb_data,
				     void (*status_cb)(void *cb_data),
				     void *status_cb_data, dma_addr_t dma_addr,
				     int event_irq_idx, int status_irq_idx);
int cxi_eq_resize_internal(struct cxi_eq *evtq, void *queue,
			   size_t queue_len, struct cxi_md *queue_md,
			   dma_addr_t dma_addr);

struct cxi_cq *cxi_cq_alloc_buf_internal(struct cxi_lni *lni, struct cxi_eq *evtq,
					 const struct cxi_cq_alloc_opts_buf *opts_b,
					 int numa_node, dma_addr_t cmds_dma_addr,
					 size_t cmds_len);

struct cxi_rmu_eth *cxi_rmu_eth_alloc_internal(struct cxi_dev *cdev, bool vf_en,
					       u8 vf_num);

#endif /* _CXI_INTERNAL_H */
