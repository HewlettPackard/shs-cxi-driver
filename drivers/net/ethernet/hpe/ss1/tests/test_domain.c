// SPDX-License-Identifier: GPL-2.0
/* Copyright 2018 Cray Inc. All rights reserved */

/* Test driver for the domain functionality. Allocate and destroy
 * domains.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cxi/cxi.h>
#include <linux/delay.h>

#include "cass_core.h"

static struct cxi_domain *domains[C_RMU_CFG_VNI_LIST_ENTRIES];
static struct cxi_domain *dom2[512];

/* Core is adding a new device */
static int add_device(struct cxi_dev *dev)
{
	struct cxi_domain *domain;
	int i;
	int rc;
	int ac_entry_id;
	int ndom_alloc;
	int ndom2_alloc;
	struct cxi_lni *lni;
	struct cxi_ct *ct;
	struct c_ct_writeback *wb;
	int timeout_count;
	u64 inc_success_value = 5;
	u64 inc_failure_value = 1;
	struct cxi_rx_profile *rx_profile;
	struct cxi_rx_attr rx_attr = {
		.vni_attr = {
			.match = 256,
			.ignore = 255,
		}
	};
	int vni = rx_attr.vni_attr.match;
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	pr_err("TEST-START: DOMAIN\n");

	svc_priv = idr_find(&hw->svc_ids, CXI_DEFAULT_SVC_ID);
	if (!svc_priv) {
		pr_err("TEST-ERROR: cannot get default svc_priv\n");
		return 0;
	}

	if (svc_priv->svc_desc.num_vld_vnis >= CXI_SVC_MAX_VNIS) {
		pr_err("TEST-ERROR: no room for RX profile\n");
		return 0;
	}

	pr_info("Create RX profile with 256 VNIs to create many domains\n");

	rx_profile = cxi_dev_alloc_rx_profile(dev, &rx_attr);
	if (IS_ERR(rx_profile)) {
		pr_err("TEST-ERROR: cannot create RX profile\n");
		return 0;
	}

	pr_info("Created RX profile id %d\n", rx_profile->profile_common.id);

	rc = cxi_rx_profile_enable(dev, rx_profile);
	if (rc) {
		pr_err("TEST-ERROR: cannot enable RX profile\n");
		goto release_profile;
	}

	svc_priv->rx_profile[svc_priv->svc_desc.num_vld_vnis] = rx_profile;
	svc_priv->svc_desc.num_vld_vnis++;

	lni = cxi_lni_alloc(dev, CXI_DEFAULT_SVC_ID);
	if (IS_ERR(lni)) {
		pr_err("TEST-ERROR: cannot create lni\n");
		goto remove_profile;
	}

	pr_info("TEST: alloc should fail without an ac entry\n");
	domain = cxi_domain_alloc(lni, vni, 0);
	if (!IS_ERR(domain))
		pr_err("TEST-ERROR: domain is allocated\n");

	rc = cxi_rx_profile_add_ac_entry(rx_profile, CXI_AC_UID,
					 __kuid_val(current_euid()), 0,
					 &ac_entry_id);

	/* Allocate 256 different VNI */
	pr_info("Create %d different domains\n", C_RMU_CFG_VNI_LIST_ENTRIES);

	for (i = 0, ndom_alloc = 0; i < C_RMU_CFG_VNI_LIST_ENTRIES;
	     i++, ndom_alloc++) {
		domains[i] = cxi_domain_alloc(lni, vni + i, i);
		if (IS_ERR(domains[i])) {
			pr_err("TEST-ERROR: domain %u is not allocated: %ld\n",
			       i, PTR_ERR(domains[i]));
			goto free_dom1;
		}
	}

	/* Allocating one more VNI must fail */
	pr_info("TEST: alloc must fail\n");
	domain = cxi_domain_alloc(lni, C_RMU_CFG_VNI_LIST_ENTRIES + 1, 0);
	if (!IS_ERR(domain))
		pr_err("TEST-ERROR: domains %u is allocated\n", i);

	pr_info("TEST: allocate different PIDs with same VNI\n");
	for (i = 1, ndom2_alloc = 1; i < dev->prop.pid_count;
	     i++, ndom2_alloc++) {
		dom2[i] = cxi_domain_alloc(lni, 10, i);
		if (IS_ERR(dom2[i])) {
			pr_err("TEST-ERROR: domain VNI=10 pid=%u is not allocated: %ld\n",
			       i, PTR_ERR(dom2[i]));
			goto free_dom2;
		}
	}

	/* Test kernel counting events. */
	wb = kzalloc(sizeof(*wb), GFP_KERNEL);
	if (!wb) {
		pr_err("TEST-ERROR: Failed to allocate writeback buffer\n");
		goto free_dom2;
	}

	ct = cxi_ct_alloc(lni, wb, false);
	if (IS_ERR(ct)) {
		kfree(wb);
		pr_err("TEST-ERROR: Failed to allocate counting event: %ld\n",
		       PTR_ERR(ct));
		goto free_wb;
	}

	/* Counting event inc failure should trigger writeback. */
	pr_info("TEST: counting event writeback test\n");

	cxi_ct_inc_success(ct, inc_success_value);
	cxi_ct_inc_failure(ct, inc_failure_value);

	timeout_count = 10;
	while (timeout_count) {
		msleep(200);
		if (ct->wb->ct_success == inc_success_value &&
		    ct->wb->ct_failure == inc_failure_value)
			goto wb_match;
		timeout_count--;
	}

	if (timeout_count == 0)
		pr_err("TEST-ERROR: counting event writeback failed\n");

wb_match:
	cxi_ct_free(ct);
free_wb:
	kfree(wb);

free_dom2:
	for (i = 1; i < ndom2_alloc; i++)
		cxi_domain_free(dom2[i]);

free_dom1:
	pr_info("TEST: free all %u entries\n", C_RMU_CFG_VNI_LIST_ENTRIES);
	for (i = 0; i < ndom_alloc; i++)
		cxi_domain_free(domains[i]);

	pr_err("TEST-END: DOMAIN\n");

	cxi_lni_free(lni);

remove_profile:
	svc_priv->svc_desc.num_vld_vnis--;
	svc_priv->rx_profile[svc_priv->svc_desc.num_vld_vnis] = NULL;
release_profile:
	cxi_rx_profile_dec_refcount(dev, rx_profile);

	return 0;
}

static void remove_device(struct cxi_dev *dev)
{
}

static struct cxi_client cxiu_client = {
	.add = add_device,
	.remove = remove_device,
};

static int __init init(void)
{
	int ret;

	ret = cxi_register_client(&cxiu_client);
	if (ret) {
		pr_err("Couldn't register client\n");
		goto out;
	}

	return 0;

out:
	return ret;
}

static void __exit cleanup(void)
{
	cxi_unregister_client(&cxiu_client);
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Domain test driver");
MODULE_AUTHOR("Cray Inc.");
