// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025-2026 Hewlett Packard Enterprise Development LP */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/hpe/cxi/cxi.h>
#include "cxi_core.h"
#include "cass_core.h"

static bool test_pass;

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ":%s:%d " fmt, __func__, __LINE__

static struct cxi_dev *dev;

static struct cxi_rx_profile *rx_profile;
static struct cxi_tx_profile *tx_profile;

static struct cxi_client cxiu_client;
struct cxi_resource_use r_save[CXI_RESOURCE_MAX];

static int test_rx_profiles(struct cxi_dev *dev)
{
	int rc;
	int match = 0x20;
	int ignore = 0x11;
	struct cxi_rx_attr rx_attr = {};
	struct cxi_rx_attr rx_attr_ret = {};

	rx_attr.vni_attr.match = 2;
	rx_attr.vni_attr.ignore = 2;
	rx_profile = cxi_dev_alloc_rx_profile(dev, &rx_attr);
	if (!IS_ERR(rx_profile)) {
		rc = PTR_ERR(rx_profile);
		pr_info("Allocate RX profile should have failed");
		return rc;
	}

	rx_attr.vni_attr.match = 0;
	rx_attr.vni_attr.ignore = 0;
	rx_profile = cxi_dev_alloc_rx_profile(dev, &rx_attr);
	if (IS_ERR(rx_profile)) {
		rc = PTR_ERR(rx_profile);
		pr_info("Allocate RX profile failed rc:%d", rc);
		return rc;
	}

	rc = cxi_rx_profile_enable(dev, rx_profile);
	if (!rc) {
		pr_info("Enable RX profile should fail rc:%d", rc);
		rc = -1;
		goto remove_rx_profile;
	}

	/* Should be ok to disable even if it is disabled */
	cxi_rx_profile_disable(dev, rx_profile);

	rx_attr.vni_attr.match = match;
	rx_attr.vni_attr.ignore = ignore;
	rc = cxi_dev_set_rx_profile_attr(dev, rx_profile, &rx_attr);
	if (rc) {
		pr_info("Failed to set rx profile attributes rc:%d", rc);
		goto remove_rx_profile;
	}

	rc = cxi_dev_set_rx_profile_attr(dev, rx_profile, &rx_attr);
	if (!rc) {
		pr_info("Should fail to set rx profile attributes again rc:%d",
			rc);
		goto remove_rx_profile;
	}

	rc = cxi_rx_profile_get_info(dev, rx_profile, &rx_attr_ret, NULL);
	if (rc) {
		pr_info("Failed to get rx profile attributes rc:%d", rc);
		goto remove_rx_profile;
	}

	if (rx_attr.vni_attr.match != rx_attr_ret.vni_attr.match ||
	    rx_attr.vni_attr.ignore != rx_attr_ret.vni_attr.ignore) {
		pr_info("Rx profile attributes not equal");
		rc = -1;
		goto remove_rx_profile;
	}

	rc = cxi_rx_profile_enable(dev, rx_profile);
	if (rc) {
		pr_info("Failed enabling RX profile rc:%d", rc);
		goto remove_rx_profile;
	}

	/* Should be ok to disable before the dec_refcount */
	cxi_rx_profile_disable(dev, rx_profile);

remove_rx_profile:
	cxi_rx_profile_dec_refcount(dev, rx_profile);

	return rc;
}

static int test_tx_profiles(struct cxi_dev *dev)
{
	int rc;
	int match = 0x40;
	int ignore = 0x11;
	struct cxi_tx_attr tx_attr = {};
	struct cxi_tx_attr tx_attr_ret = {};

	tx_attr.vni_attr.match = 1;
	tx_attr.vni_attr.ignore = 1;
	tx_profile = cxi_dev_alloc_tx_profile(dev, &tx_attr);
	if (!IS_ERR(tx_profile)) {
		rc = PTR_ERR(tx_profile);
		pr_info("Allocate TX profile should have failed");
		return rc;
	}

	tx_attr.vni_attr.match = 0;
	tx_attr.vni_attr.ignore = 0;
	tx_profile = cxi_dev_alloc_tx_profile(dev, &tx_attr);
	if (IS_ERR(tx_profile)) {
		rc = PTR_ERR(tx_profile);
		pr_info("Allocate TX profile failed rc:%d", rc);
		return rc;
	}

	rc = cxi_tx_profile_enable(dev, tx_profile);
	if (!rc) {
		pr_info("Allocate TX profile should fail rc:%d", rc);
		rc = -1;
		goto remove_tx_profile;
	}

	tx_attr.vni_attr.match = match;
	tx_attr.vni_attr.ignore = ignore;
	rc = cxi_dev_set_tx_profile_attr(dev, tx_profile, &tx_attr);
	if (rc) {
		pr_info("Failed to set tx profile attributes rc:%d", rc);
		goto remove_tx_profile;
	}

	rc = cxi_dev_set_tx_profile_attr(dev, tx_profile, &tx_attr);
	if (!rc) {
		pr_info("Should fail to set tx profile attributes again rc:%d",
			rc);
		goto remove_tx_profile;
	}

	rc = cxi_tx_profile_get_info(dev, tx_profile, &tx_attr_ret, NULL);
	if (rc) {
		pr_info("Failed to get tx profile attributes rc:%d", rc);
		goto remove_tx_profile;
	}

	if (tx_attr.vni_attr.match != tx_attr_ret.vni_attr.match ||
	    tx_attr.vni_attr.ignore != tx_attr_ret.vni_attr.ignore) {
		pr_info("Tx profile attributes not equal");
		goto remove_tx_profile;
	}

remove_tx_profile:
	cxi_tx_profile_dec_refcount(dev, tx_profile, true);

	return rc;
}

static int expect_domain_error(struct cxi_lni *lni, unsigned int vni,
			       unsigned int pid, int expected)
{
	struct cxi_domain *domain = cxi_domain_alloc(lni, vni, pid);

	if (IS_ERR(domain) && PTR_ERR(domain) == expected)
		return 0;
	if (!IS_ERR(domain))
		cxi_domain_free(domain);
	pr_err("PID %u did not fail with %d\n", pid, expected);
	return -EIO;
}

struct rx_profile_worker {
	struct completion *start;
	struct completion done;
	struct cxi_dev *dev;
	struct cxi_rx_profile *profile;
	struct cxi_lni *lni;
	struct cxi_domain *domain;
	unsigned int netns;
	int rc;
};

static int rx_profile_worker(void *arg)
{
	struct rx_profile_worker *worker = arg;
	unsigned int vni = worker->profile->profile_common.vni_attr.match;

	wait_for_completion(worker->start);
	cass_set_netns_override(worker->netns);
	worker->rc = cxi_rx_profile_enable(worker->dev, worker->profile);
	if (!worker->rc) {
		worker->domain = cxi_domain_alloc(worker->lni, vni, C_PID_ANY);
		if (IS_ERR(worker->domain)) {
			worker->rc = PTR_ERR(worker->domain);
			worker->domain = NULL;
		}
	}
	cass_clear_netns_override();
	complete(&worker->done);
	return 0;
}

static int race_rx_profiles(struct cxi_dev *dev,
			    struct cxi_rx_profile **profiles,
			    struct cxi_lni **lnis, unsigned int netns)
{
	DECLARE_COMPLETION_ONSTACK(start);
	struct rx_profile_worker workers[2] = {};
	struct task_struct *tasks[2] = {};
	int i, rc = 0;

	for (i = 0; i < 2; i++) {
		workers[i].start = &start;
		init_completion(&workers[i].done);
		workers[i].dev = dev;
		workers[i].profile = profiles[i];
		workers[i].lni = lnis[i];
		workers[i].netns = netns + i;
		tasks[i] = kthread_run(rx_profile_worker, &workers[i],
				       "cxi-rx-test-%d", i);
		if (IS_ERR(tasks[i])) {
			rc = PTR_ERR(tasks[i]);
			tasks[i] = NULL;
			break;
		}
		get_task_struct(tasks[i]);
	}
	complete_all(&start);
	for (i = 0; i < 2; i++) {
		if (!tasks[i])
			continue;
		wait_for_completion(&workers[i].done);
		kthread_stop(tasks[i]);
		put_task_struct(tasks[i]);
		if (workers[i].rc)
			rc = workers[i].rc;
	}
	if (!rc && workers[0].domain->pid == workers[1].domain->pid)
		rc = -EIO;
	for (i = 0; i < 2; i++)
		if (workers[i].domain)
			cxi_domain_free(workers[i].domain);
	return rc;
}

static int test_shared_rx_profiles(struct cxi_dev *dev, bool reverse)
{
	struct cxi_rx_profile *profiles[2] = {};
	struct cxi_domain *domains[2] = {};
	struct cxi_lni *lnis[2] = {};
	struct cxi_rx_attr attr = { .vni_attr.match = 0x7f01 };
	struct cass_dev *hw = cxi_to_cass_dev(dev);
	union c_rmu_cfg_vni_list entry;
	unsigned int netns = CURRENT_NETNS_ID() + 0x1000;
	unsigned int ac_id;
	int index = -1;
	int i, rc = -EIO;

	for (i = 0; i < 2; i++) {
		profiles[i] = cxi_dev_alloc_rx_profile(dev, &attr);
		if (IS_ERR(profiles[i])) {
			rc = PTR_ERR(profiles[i]);
			profiles[i] = NULL;
			goto out;
		}
		rc = cxi_rx_profile_add_ac_entry(profiles[i], CXI_AC_NETNS,
						 0, 0, netns + i, &ac_id);
		if (rc)
			goto out;
		lnis[i] = cxi_lni_alloc(dev, CXI_DEFAULT_SVC_ID);
		if (IS_ERR(lnis[i])) {
			rc = PTR_ERR(lnis[i]);
			lnis[i] = NULL;
			goto out;
		}
	}

	/* Race initial attachment, then exercise deterministic enable orders. */
	if (reverse) {
		rc = race_rx_profiles(dev, profiles, lnis, netns);
		if (rc)
			goto out;
		cxi_rx_profile_disable(dev, profiles[0]);
		cxi_rx_profile_disable(dev, profiles[1]);
	}
	rc = cxi_rx_profile_enable(dev, profiles[reverse]);
	if (rc)
		goto out;
	rc = cxi_rx_profile_enable(dev, profiles[!reverse]);
	if (rc)
		goto out;
	index = profiles[0]->config.rmu_index;
	rc = -EIO;
	if (index != profiles[1]->config.rmu_index)
		goto out;

	for (i = 0; i < 2; i++) {
		cass_set_netns_override(netns + i);
		domains[i] = cxi_domain_alloc(lnis[i], attr.vni_attr.match,
					      C_PID_ANY);
		if (IS_ERR(domains[i])) {
			rc = PTR_ERR(domains[i]);
			domains[i] = NULL;
			goto out;
		}
	}
	rc = -EIO;
	if (domains[0]->pid == domains[1]->pid)
		goto out;
	rc = expect_domain_error(lnis[1], attr.vni_attr.match,
				 domains[0]->pid, -EEXIST);
	if (rc)
		goto out;

	/* A disabled profile with live domains still owns its PIDs. */
	cxi_rx_profile_disable(dev, profiles[0]);
	cass_read(hw, C_RMU_CFG_VNI_LIST_X(index), &entry, sizeof(entry));
	rc = -EIO;
	if (!entry.valid ||
	    cxi_dev_set_rx_profile_attr(dev, profiles[0], &attr) != -EBUSY)
		goto out;
	rc = expect_domain_error(lnis[1], attr.vni_attr.match,
				 domains[0]->pid, -EEXIST);
	if (rc)
		goto out;
	rc = cxi_rx_profile_enable(dev, profiles[0]);
	if (rc)
		goto out;
	rc = -EIO;
	if (profiles[0]->config.rmu_index != index)
		goto out;

	for (i = 0; i < 2; i++) {
		cxi_domain_free(domains[i]);
		domains[i] = NULL;
	}
	cass_set_netns_override(netns + 2);
	rc = expect_domain_error(lnis[1], attr.vni_attr.match, 8, -EPERM);
	if (rc)
		goto out;

	cass_set_netns_override(netns);
	rc = cxi_domain_reserve(lnis[0], attr.vni_attr.match, 8, 3);
	if (rc != 8) {
		rc = -EIO;
		goto out;
	}
	cass_set_netns_override(netns + 1);
	rc = -EIO;
	if (cxi_domain_reserve(lnis[1], attr.vni_attr.match, 8, 3) != -EEXIST)
		goto out;
	rc = expect_domain_error(lnis[1], attr.vni_attr.match, 9, -EEXIST);
	if (rc)
		goto out;

	/* Consume a reservation after lookup selects the other profile. */
	domains[0] = cxi_domain_alloc(lnis[0], attr.vni_attr.match, 9);
	if (IS_ERR(domains[0])) {
		rc = PTR_ERR(domains[0]);
		domains[0] = NULL;
		goto out;
	}
	cxi_domain_free(domains[0]);
	domains[0] = NULL;
	domains[1] = cxi_domain_alloc(lnis[1], attr.vni_attr.match, 9);
	if (IS_ERR(domains[1])) {
		rc = PTR_ERR(domains[1]);
		domains[1] = NULL;
		goto out;
	}
	cxi_domain_free(domains[1]);
	domains[1] = NULL;

	cxi_lni_free(lnis[0]);
	lnis[0] = NULL;
	/* LNI teardown releases the unconsumed reservation, too. */
	domains[1] = cxi_domain_alloc(lnis[1], attr.vni_attr.match, 10);
	if (IS_ERR(domains[1])) {
		rc = PTR_ERR(domains[1]);
		domains[1] = NULL;
		goto out;
	}
	cxi_domain_free(domains[1]);
	domains[1] = NULL;

	cxi_rx_profile_disable(dev, profiles[0]);
	cxi_rx_profile_dec_refcount(dev, profiles[0]);
	profiles[0] = NULL;
	cass_read(hw, C_RMU_CFG_VNI_LIST_X(index), &entry, sizeof(entry));
	rc = -EIO;
	if (!entry.valid)
		goto out;
	cxi_rx_profile_disable(dev, profiles[1]);
	cass_read(hw, C_RMU_CFG_VNI_LIST_X(index), &entry, sizeof(entry));
	if (entry.valid)
		goto out;
	rc = cxi_rx_profile_enable(dev, profiles[1]);
	if (!rc && profiles[1]->config.rmu_index != index)
		rc = -EIO;
out:
	cass_clear_netns_override();
	for (i = 0; i < 2; i++) {
		if (domains[i])
			cxi_domain_free(domains[i]);
		if (lnis[i])
			cxi_lni_free(lnis[i]);
		if (profiles[i])
			cxi_rx_profile_dec_refcount(dev, profiles[i]);
	}
	if (index >= 0) {
		cass_read(hw, C_RMU_CFG_VNI_LIST_X(index), &entry, sizeof(entry));
		if (entry.valid)
			rc = -EIO;
	}
	if (rc)
		pr_err("Shared RX profile test (reverse=%u) failed: %d\n",
		       reverse, rc);
	return rc;
}

static int run_tests(struct cxi_dev *dev)
{
	int rc;
	struct cass_dev *hw = cxi_to_cass_dev(dev);
	int refcount_final;
	int refcount = refcount_read(&hw->refcount);

	rc = test_rx_profiles(dev);
	if (rc) {
		test_pass = false;
		pr_err("test_rx_profiles failed: %d\n", rc);
		goto done;
	}

	rc = test_tx_profiles(dev);
	if (rc) {
		test_pass = false;
		pr_err("test_tx_profiles failed: %d\n", rc);
		goto done;
	}

	rc = test_shared_rx_profiles(dev, false);
	if (!rc)
		rc = test_shared_rx_profiles(dev, true);
	if (rc) {
		test_pass = false;
		goto done;
	}

	refcount_final = refcount_read(&hw->refcount);

	if (refcount != refcount_final) {
		pr_err("hw refcount %s was:%d now:%d\n",
		       refcount < refcount_final ? "leak" : "missing",
		       refcount, refcount_final);
		test_pass = false;
		rc = -EIO;
	}

	pr_info("All tests pass\n");

done:
	return rc;
}

static int add_device(struct cxi_dev *cdev)
{
	dev = cdev;
	return 0;

}

static void remove_device(struct cxi_dev *cdev)
{
	dev = NULL;
}

static struct cxi_client cxiu_client = {
	.add = add_device,
	.remove = remove_device,
};

static int __init init(void)
{
	int rc;

	test_pass = true;

	rc = cxi_register_client(&cxiu_client);
	if (rc) {
		pr_err("cxi_register_client failed: %d\n", rc);
		return rc;
	}

	rc = run_tests(dev);
	if (rc)
		pr_err("Failed:%d\n", rc);

	if (!test_pass) {
		cxi_unregister_client(&cxiu_client);
		rc = -EIO;
	}

	return rc;
}

static void __exit cleanup(void)
{
	pr_info("unregistering client\n");
	cxi_unregister_client(&cxiu_client);
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("CXI profile test suite");
MODULE_AUTHOR("HPE");
