// SPDX-License-Identifier: GPL-2.0
/* Copyright 2022 Hewlett Packard Enterprise Development LP */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cxi/cxi.h>

#define VNI 8U
#define TLE_COUNT 10U
#define TIMEOUT 2U

static bool test_pass = true;

#define test_err(fmt, ...) pr_err("%s:%d " fmt, __func__, __LINE__, \
	##__VA_ARGS__)

static int test_service_tle_in_use(struct cxi_dev *dev)
{
	int rc;
	struct cxi_svc_desc desc = {
		.enable = 1,
		.is_system_svc = 1,
		.num_vld_vnis = 1,
		.resource_limits = 1,
		.vnis[0] = VNI,
		.limits.type[CXI_RSRC_TYPE_PTE].max = 100,
		.limits.type[CXI_RSRC_TYPE_PTE].res = 100,
		.limits.type[CXI_RSRC_TYPE_TXQ].max = 100,
		.limits.type[CXI_RSRC_TYPE_TXQ].res = 100,
		.limits.type[CXI_RSRC_TYPE_TGQ].max = 100,
		.limits.type[CXI_RSRC_TYPE_TGQ].res = 100,
		.limits.type[CXI_RSRC_TYPE_EQ].max = 100,
		.limits.type[CXI_RSRC_TYPE_EQ].res = 100,
		.limits.type[CXI_RSRC_TYPE_CT].max = 100,
		.limits.type[CXI_RSRC_TYPE_CT].res = 100,
		.limits.type[CXI_RSRC_TYPE_LE].max = 100,
		.limits.type[CXI_RSRC_TYPE_LE].res = 100,
		.limits.type[CXI_RSRC_TYPE_TLE].max = 100,
		.limits.type[CXI_RSRC_TYPE_TLE].res = 100,
		.limits.type[CXI_RSRC_TYPE_AC].max = 4,
		.limits.type[CXI_RSRC_TYPE_AC].res = 4,
		.tcs[CXI_TC_BEST_EFFORT] = true,
	};
	struct cxi_svc_fail_info info;
	struct cxi_lni *lni;
	struct cxi_ct *ct;
	struct c_ct_writeback *wb;
	struct cxi_cp *cp;
	struct cxi_cq *trig_cq;
	struct cxi_cq_alloc_opts cq_opts = {};
	struct cxi_rsrc_use in_use;
	struct c_ct_cmd ct_cmd = {};
	int i;
	ktime_t timeout;

	rc = cxi_svc_alloc(dev, &desc, &info);
	if (rc < 0) {
		test_err("cxi_svc_alloc failed: %d\n", rc);
		goto err;
	}

	desc.svc_id = rc;

	lni = cxi_lni_alloc(dev, desc.svc_id);
	if (IS_ERR(lni)) {
		rc = PTR_ERR(lni);
		test_err("cxi_lni_alloc failed: %d\n", rc);
		goto err_free_svc;
	}

	wb = kzalloc(sizeof(*wb), GFP_KERNEL);
	if (!wb) {
		pr_err("TEST-ERROR: Failed to allocate writeback buffer\n");
		goto err_free_lni;
	}

	ct = cxi_ct_alloc(lni, wb, false);
	if (IS_ERR(ct)) {
		rc = PTR_ERR(ct);
		test_err("cxi_ct_alloc failed: %d\n", rc);
		goto err_free_wb;
	}

	cp = cxi_cp_alloc(lni, VNI, CXI_TC_BEST_EFFORT, CXI_TC_TYPE_DEFAULT);
	if (IS_ERR(cp)) {
		rc = PTR_ERR(cp);
		test_err("cxi_cp_alloc failed: %d\n", rc);
		goto err_free_ct;
	}

	cq_opts.count = 4096;
	cq_opts.lcid = cp->lcid;
	cq_opts.flags = CXI_CQ_IS_TX | CXI_CQ_TX_WITH_TRIG_CMDS;

	trig_cq = cxi_cq_alloc(lni, NULL, &cq_opts, 0);
	if (IS_ERR(trig_cq)) {
		rc = PTR_ERR(trig_cq);
		test_err("cxi_cq_alloc failed: %d\n", rc);
		goto err_free_cp;
	}

	rc = cxi_svc_rsrc_get(dev, desc.svc_id, &in_use);
	if (rc) {
		test_err("cxi_svc_rsrc_get failed: %d\n", rc);
		goto err_free_cq;
	}

	if (in_use.in_use[CXI_RSRC_TYPE_TLE] != 0) {
		rc = -EINVAL;
		test_err("Incorrect TLE in use: expected=0 got=%d\n",
			 in_use.in_use[CXI_RSRC_TYPE_TLE]);
		goto err_free_cq;
	}

	ct_cmd.trig_ct = ct->ctn;
	ct_cmd.ct = ct->ctn;
	ct_cmd.ct_success = 1;
	ct_cmd.set_ct_success = 1;

	for (i = 0; i < TLE_COUNT; i++) {
		ct_cmd.threshold = i + 1;

		rc = cxi_cq_emit_ct(trig_cq, C_CMD_CT_TRIG_INC, &ct_cmd);
		if (rc) {
			test_err("cxi_cq_emit_ct failed: %d\n", rc);
			goto err_free_cq;
		}

		cxi_cq_ring(trig_cq);
	}

	rc = cxi_svc_rsrc_get(dev, desc.svc_id, &in_use);
	if (rc) {
		test_err("cxi_svc_rsrc_get failed: %d\n", rc);
		goto err_free_cq;
	}

	if (in_use.in_use[CXI_RSRC_TYPE_TLE] != TLE_COUNT) {
		rc = -EINVAL;
		test_err("Incorrect TLE in use: expected=%u got=%d\n",
			 TLE_COUNT, in_use.in_use[CXI_RSRC_TYPE_TLE]);
		goto err_free_cq;
	}

	rc = cxi_cq_emit_ct(trig_cq, C_CMD_CT_INC, &ct_cmd);
	if (rc) {
		test_err("cxi_cq_emit_ct failed: %d\n", rc);
		goto err_free_cq;
	}

	cxi_cq_ring(trig_cq);

	timeout = ktime_add(ktime_get(), ktime_set(TIMEOUT, 0));

	do {
		rc = cxi_svc_rsrc_get(dev, desc.svc_id, &in_use);
		if (rc) {
			test_err("cxi_svc_rsrc_get failed: %d\n", rc);
			goto err_free_cq;
		}

		if (ktime_compare(ktime_get(), timeout) > 1) {
			rc = -ETIMEDOUT;
			test_err("timeout reaching TLE count\n");
			goto err_free_cq;
		}
	} while (in_use.in_use[CXI_RSRC_TYPE_TLE] != 0);

	rc = 0;

err_free_cq:
	cxi_cq_free(trig_cq);
err_free_cp:
	cxi_cp_free(cp);
err_free_ct:
	cxi_ct_free(ct);
err_free_wb:
	kfree(wb);
err_free_lni:
	cxi_lni_free(lni);
err_free_svc:
	cxi_svc_destroy(dev, desc.svc_id);
err:
	return rc;
}

static int test_service_modify(struct cxi_dev *dev)
{
	int i, rc;
	struct cxi_svc_desc desc = {
		.enable = 1,
		.is_system_svc = 1,
		.num_vld_vnis = 1,
		.vnis[0] = VNI,
		.limits.type[CXI_RSRC_TYPE_PTE].max = 100,
		.limits.type[CXI_RSRC_TYPE_PTE].res = 100,
		.limits.type[CXI_RSRC_TYPE_TXQ].max = 100,
		.limits.type[CXI_RSRC_TYPE_TXQ].res = 100,
		.limits.type[CXI_RSRC_TYPE_TGQ].max = 100,
		.limits.type[CXI_RSRC_TYPE_TGQ].res = 100,
		.limits.type[CXI_RSRC_TYPE_EQ].max = 100,
		.limits.type[CXI_RSRC_TYPE_EQ].res = 100,
		.limits.type[CXI_RSRC_TYPE_CT].max = 100,
		.limits.type[CXI_RSRC_TYPE_CT].res = 100,
		.limits.type[CXI_RSRC_TYPE_LE].max = 100,
		.limits.type[CXI_RSRC_TYPE_LE].res = 100,
		.limits.type[CXI_RSRC_TYPE_TLE].max = 100,
		.limits.type[CXI_RSRC_TYPE_TLE].res = 100,
		.limits.type[CXI_RSRC_TYPE_AC].max = 4,
		.limits.type[CXI_RSRC_TYPE_AC].res = 4,
	};
	struct cxi_svc_desc comp;
	struct cxi_svc_fail_info info;
	struct cxi_lni *lni;

	rc = cxi_svc_alloc(dev, &desc, &info);
	if (rc < 0) {
		test_err("cxi_svc_alloc failed: %d\n", rc);
		goto err;
	}

	desc.svc_id = rc;

	/* Modify portions of descriptor */
	desc.restricted_tcs = 1;
	desc.tcs[0] = true;
	desc.tcs[1] = true;

	lni = cxi_lni_alloc(dev, desc.svc_id);
	if (IS_ERR(lni)) {
		rc = PTR_ERR(lni);
		test_err("cxi_lni_alloc failed: %d\n", rc);
		goto err_free_svc;
	}

	/* Should not be able to modify service while it is being used. */
	rc = cxi_svc_update(dev, &desc);
	if (rc != -EBUSY) {
		rc = -EINVAL;
		test_err("cxi_svc_update did not returned -EBUSY\n");
		goto err_free_lni;
	}

	cxi_lni_free(lni);

	/* Should be able to modify service since it is not being used. */
	rc = cxi_svc_update(dev, &desc);
	if (rc) {
		test_err("cxi_svc_update failed: %d\n", rc);
		goto err_free_svc;
	}

	/* Get the updated descriptor back from the kernel */
	rc = cxi_svc_get(dev, desc.svc_id, &comp);
	if (rc) {
		test_err("cxi_svc_get failed: %d\n", rc);
		goto err_free_svc;
	}

	if (comp.restricted_members != desc.restricted_members) {
		test_err("Inconsistent result. desc.restricted_members:%d comp.restricted_members:%d",
			 desc.restricted_members, comp.restricted_members);
		rc = -EINVAL;
		goto err_free_svc;
	}

	if (comp.restricted_tcs != desc.restricted_tcs) {
		test_err("Inconsistent result. desc.restricted_tcs:%d comp.restricted_tcs:%d",
			 desc.restricted_tcs, comp.restricted_tcs);
		rc = -EINVAL;
		goto err_free_svc;
	}

	/* Compare TCs */
	for (i = 0; i < CXI_TC_MAX - 1; i++) {
		if (comp.tcs[i] != desc.tcs[i]) {
			test_err("Inconsistent result. desc.tcs[%d]:%d comp.tcs[%d]:%d",
				 i, desc.tcs[i], i, comp.tcs[i]);
			rc = -EINVAL;
			goto err_free_svc;
		}
	}

	cxi_svc_destroy(dev, desc.svc_id);

	return 0;

err_free_lni:
	cxi_lni_free(lni);
err_free_svc:
	cxi_svc_destroy(dev, desc.svc_id);
err:
	return rc;
}

static int test_disabled_service(struct cxi_dev *dev)
{
	int rc;
	struct cxi_svc_desc desc = {
		.enable = 0,
		.is_system_svc = 1,
		.num_vld_vnis = 1,
		.vnis[0] = VNI,
		.limits.type[CXI_RSRC_TYPE_PTE].max = 100,
		.limits.type[CXI_RSRC_TYPE_PTE].res = 100,
		.limits.type[CXI_RSRC_TYPE_TXQ].max = 100,
		.limits.type[CXI_RSRC_TYPE_TXQ].res = 100,
		.limits.type[CXI_RSRC_TYPE_TGQ].max = 100,
		.limits.type[CXI_RSRC_TYPE_TGQ].res = 100,
		.limits.type[CXI_RSRC_TYPE_EQ].max = 100,
		.limits.type[CXI_RSRC_TYPE_EQ].res = 100,
		.limits.type[CXI_RSRC_TYPE_CT].max = 100,
		.limits.type[CXI_RSRC_TYPE_CT].res = 100,
		.limits.type[CXI_RSRC_TYPE_LE].max = 100,
		.limits.type[CXI_RSRC_TYPE_LE].res = 100,
		.limits.type[CXI_RSRC_TYPE_TLE].max = 100,
		.limits.type[CXI_RSRC_TYPE_TLE].res = 100,
		.limits.type[CXI_RSRC_TYPE_AC].max = 4,
		.limits.type[CXI_RSRC_TYPE_AC].res = 4,
	};
	struct cxi_svc_fail_info info;
	struct cxi_lni *lni;

	rc = cxi_svc_alloc(dev, &desc, &info);
	if (rc < 0) {
		test_err("cxi_svc_alloc failed: %d\n", rc);
		goto err;
	}

	desc.svc_id = rc;

	rc = cxi_svc_update(dev, &desc);
	if (rc) {
		test_err("cxi_svc_update failed: %d\n", rc);
		goto err_free_svc;
	}

	lni = cxi_lni_alloc(dev, desc.svc_id);
	if (PTR_ERR(lni) != -EKEYREVOKED) {
		rc = -EINVAL;
		test_err("cxi_lni_alloc did not return -EKEYREVOKED: %ld\n",
			 PTR_ERR(lni));
		cxi_lni_free(lni);
		goto err_free_svc;
	}

	rc = 0;

err_free_svc:
	cxi_svc_destroy(dev, desc.svc_id);
err:
	return rc;
}

static int test_default_service(struct cxi_dev *dev)
{
	int rc = 0;
	struct cxi_cp *cp;
	struct cxi_lni *lni;
	struct cxi_svc_desc desc;

	/* Get the updated descriptor back from the kernel */
	rc = cxi_svc_get(dev, CXI_DEFAULT_SVC_ID, &desc);
	if (rc) {
		test_err("cxi_svc_get failed: %d\n", rc);
		goto err;
	}

	/* Enable Default Service */
	desc.enable = true;
	rc = cxi_svc_update(dev, &desc);
	if (rc) {
		test_err("cxi_svc_update failed: %d\n", rc);
		goto err;
	}

	/* Allocate LNI against default service */
	lni = cxi_lni_alloc(dev, CXI_DEFAULT_SVC_ID);
	if (IS_ERR(lni)) {
		rc = PTR_ERR(lni);
		test_err("Couldn't allocate LNI with default service: %d\n",
			 rc);
		goto err;
	}

	/* Try to use non-default VNI. Should fail */
	cp = cxi_cp_alloc(lni, 500, CXI_TC_BEST_EFFORT,
			  CXI_TC_TYPE_DEFAULT);

	if (!IS_ERR(cp)) {
		test_err("Allocated CP with non-default VNI using default service\n");
		cxi_cp_free(cp);
		/* TODO cause failure when tx_profile is not allocated
		 * when no profile with vni is found.
		 */
		// rc = -EINVAL;
	}

	cxi_lni_free(lni);
err:
	return rc;
}

static int test_service_busy(struct cxi_dev *dev)
{
	int rc;
	struct cxi_lni *lni;
	struct cxi_svc_fail_info info;
	struct cxi_svc_desc desc = {
		.enable = 1,
		.is_system_svc = 1,
		.num_vld_vnis = 1,
		.vnis[0] = VNI,
		.limits.type[CXI_RSRC_TYPE_AC].max = 4,
		.limits.type[CXI_RSRC_TYPE_AC].res = 4,
	};

	rc = cxi_svc_alloc(dev, &desc, &info);
	if (rc < 0) {
		test_err("cxi_svc_alloc failed: %d\n", rc);
		goto err;
	}

	desc.svc_id = rc;

	lni = cxi_lni_alloc(dev, desc.svc_id);
	if (IS_ERR(lni)) {
		rc = PTR_ERR(lni);
		test_err("cxi_lni_alloc failed: %d\n", rc);
		goto err_free_svc;
	}

	/* should be busy */
	rc = cxi_svc_destroy(dev, desc.svc_id);
	if (rc != -EBUSY) {
		test_err("cxi_svc_destroy should fail\n");
		rc = -1;
		goto err_free_lni;
	}

	/* should still be busy */
	rc = cxi_svc_destroy(dev, desc.svc_id);
	if (rc != -EBUSY) {
		test_err("cxi_svc_destroy should be busy rc:%d\n", rc);
		rc = -1;
		goto err_free_lni;
	}

	cxi_lni_free(lni);

	/* should not be busy any longer */
	rc = cxi_svc_destroy(dev, desc.svc_id);
	if (rc) {
		test_err("cxi_svc_destroy failed: %d\n", rc);
		goto err;
	}

	return 0;

err_free_lni:
	cxi_lni_free(lni);
err_free_svc:
	rc = cxi_svc_destroy(dev, desc.svc_id);
err:
	return rc;
}

static int add_device(struct cxi_dev *dev)
{
	int rc;

	rc = test_service_busy(dev);
	if (rc) {
		test_pass = false;
		test_err("test_service_busy failed: %d\n", rc);
	}

	rc = test_service_tle_in_use(dev);
	if (rc) {
		test_pass = false;
		test_err("test_service_tle_in_use failed: %d\n", rc);
	}

	rc = test_service_modify(dev);
	if (rc) {
		test_pass = false;
		test_err("test_service_modify failed: %d\n", rc);
	}

	rc = test_disabled_service(dev);
	if (rc) {
		test_pass = false;
		test_err("test_service_tle_in_use failed: %d\n", rc);
	}

	rc = test_default_service(dev);
	if (rc) {
		test_pass = false;
		test_err("test_default_service failed: %d\n", rc);
	}

	return rc;
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
	int rc;

	rc = cxi_register_client(&cxiu_client);
	if (rc)
		test_err("cxi_register_client failed: %d\n", rc);

	if (!test_pass)
		rc = -EIO;

	return rc;
}

static void __exit cleanup(void)
{
	cxi_unregister_client(&cxiu_client);
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("CXI service test suite");
MODULE_AUTHOR("HPE");
