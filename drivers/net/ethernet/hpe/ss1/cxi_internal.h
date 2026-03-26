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

#endif /* _CXI_INTERNAL_H */
