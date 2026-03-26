// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025-2026 Hewlett Packard Enterprise Development LP */

#ifndef _CASS_VF_H
#define _CASS_VF_H

/* VF private structures */
struct cxi_lni_priv_vf {
	/* Matching fields in cxi_lni_priv */
	struct cxi_dev *dev;
	struct cxi_lni lni;
	/* VF only fields */
	int phys_lac; /* Physical LAC associated with this LNI */
};

struct cxi_domain_priv_vf {
	/* Matching fields in cxi_domain_priv */
	struct cxi_domain domain;
	struct cxi_lni_priv *lni_priv;
};

struct cxi_cp_priv_vf {
	/* Matching fields in cxi_cp_priv */
	struct cxi_dev *dev;
	struct cxi_cp cp;
	/* VF only fields */
	unsigned int cp_hndl;
};

struct cxi_cq_priv_vf {
	/* Matching fields in cxi_cq_priv */
	struct cxi_lni_priv *lni_priv;
	struct cxi_cq cass_cq;
	size_t cmds_len;
	size_t cmds_order;
	struct page **pages;
	struct page *cmds_pages;
	void *cmds;
	dma_addr_t cmds_dma_addr;
	void __iomem *cq_mmio;
	u32 flags;
	struct cxi_md_priv *md_priv;
};

struct cxi_md_priv_vf {
	/* Matching fields in cxi_md_priv */
	struct cxi_lni_priv *lni_priv;
	struct device *device;
	struct cxi_md md;
	struct sg_table *sgt;        /* Scatter-gather table for DMA mapping */
	struct page **pages;         /* Array of pinned pages */
	u32 flags;                   /* Mapping flags */
	/* VF only fields */
	int npages;                  /* Number of pinned pages */
};

int cass_vf_get_token(struct cxi_dev *cdev, int vf_idx, unsigned int *token);

#endif /* CASS_VF_H */
