// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

#include <linux/hpe/cxi/cxi.h>
#include <linux/dma-mapping.h>
#include "cass_core.h"
#include "cxi_user.h"
#include "cass_vf.h"

/* Compile-time assertions to ensure VF structures can be safely cast to their
 * corresponding PF structures and vice versa.
 * These verify that the common fields are at the same offsets in both structures.
 */

/* Ensure cxi_lni_priv_vf can be cast to cxi_lni_priv */
static_assert(offsetof(struct cxi_lni_priv_vf, dev) ==
	      offsetof(struct cxi_lni_priv, dev));
static_assert(offsetof(struct cxi_lni_priv_vf, lni) ==
	      offsetof(struct cxi_lni_priv, lni));

/* Ensure cxi_domain_priv_vf can be cast to cxi_domain_priv */
static_assert(offsetof(struct cxi_domain_priv_vf, domain) ==
	      offsetof(struct cxi_domain_priv, domain));
static_assert(offsetof(struct cxi_domain_priv_vf, lni_priv) ==
	      offsetof(struct cxi_domain_priv, lni_priv));

/* Ensure cxi_cp_priv_vf can be cast to cxi_cp_priv */
static_assert(offsetof(struct cxi_cp_priv_vf, dev) ==
	      offsetof(struct cxi_cp_priv, dev));
static_assert(offsetof(struct cxi_cp_priv_vf, cp) ==
	      offsetof(struct cxi_cp_priv, cp));

/* Ensure cxi_cq_priv_vf can be cast to cxi_cq_priv */
static_assert(offsetof(struct cxi_cq_priv_vf, lni_priv) ==
	      offsetof(struct cxi_cq_priv, lni_priv));
static_assert(offsetof(struct cxi_cq_priv_vf, cass_cq) ==
	      offsetof(struct cxi_cq_priv, cass_cq));
static_assert(offsetof(struct cxi_cq_priv_vf, pages) ==
	      offsetof(struct cxi_cq_priv, pages));
static_assert(offsetof(struct cxi_cq_priv_vf, cq_mmio) ==
	      offsetof(struct cxi_cq_priv, cq_mmio));
static_assert(offsetof(struct cxi_cq_priv_vf, flags) ==
	      offsetof(struct cxi_cq_priv, flags));

/* Ensure cxi_md_priv_vf can be cast to cxi_md_priv */
static_assert(offsetof(struct cxi_md_priv_vf, lni_priv) ==
	      offsetof(struct cxi_md_priv, lni_priv));
static_assert(offsetof(struct cxi_md_priv_vf, device) ==
	      offsetof(struct cxi_md_priv, device));
static_assert(offsetof(struct cxi_md_priv_vf, md) ==
	      offsetof(struct cxi_md_priv, md));
static_assert(offsetof(struct cxi_md_priv_vf, sgt) ==
	      offsetof(struct cxi_md_priv, sgt));
static_assert(offsetof(struct cxi_md_priv_vf, pages) ==
	      offsetof(struct cxi_md_priv, pages));
static_assert(offsetof(struct cxi_md_priv_vf, flags) ==
	      offsetof(struct cxi_md_priv, flags));
static_assert(offsetof(struct cxi_md_priv_vf, olen) ==
	      offsetof(struct cxi_md_priv, olen));
