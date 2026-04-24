/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

#ifndef _CXI_VF_CMD_H
#define _CXI_VF_CMD_H

#include <linux/hpe/cxi/cxi.h>

struct cxi_lni_alloc_resp_vf {
	struct cxi_lni_alloc_resp base;
	unsigned int rgid;
};

struct cxi_svc_list_get_resp_vf {
	struct cxi_svc_list_get_resp base;
	struct cxi_svc_desc svc_list[];
};

struct cxi_svc_rsrc_list_get_resp_vf {
	struct cxi_svc_rsrc_list_get_resp base;
	struct cxi_rsrc_use rsrc_list[];
};

struct cxi_ct_alloc_cmd_vf {
	struct cxi_ct_alloc_cmd base;
	u64 wb_dma_addr;
};

struct cxi_ct_wb_update_cmd_vf {
	struct cxi_ct_wb_update_cmd base;
	u64 wb_dma_addr;
};

struct cxi_cq_alloc_buf_cmd_vf {
	struct cxi_cq_alloc_buf_cmd base;
	u64 dma_addr;
	size_t cmds_len;
};

struct cxi_eq_alloc_cmd_vf {
	struct cxi_eq_alloc_cmd base;
	u64 dma_addr;
	int event_irq_idx;
	int status_irq_idx;
};

struct cxi_eq_resize_cmd_vf {
	struct cxi_eq_resize_cmd base;
	u64 dma_addr;
};

struct cxi_pte_status_cmd_vf {
	struct cxi_pte_status_cmd base;
	struct cxi_pte_status status;
};

#endif /* _CXI_VF_CMD_H */
