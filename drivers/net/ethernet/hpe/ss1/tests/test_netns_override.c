// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

/* Unit test for the per-task network namespace override used when the PF
 * relays a VF command. The relay kthread cannot adopt the VF caller's
 * namespace, so it records the forwarded netns id and permission checks read
 * it back through CURRENT_NETNS_ID(). See cass_set_netns_override() in
 * cass_core.c.
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "cass_core.h"
#include "cxi_internal.h"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ":%s:%d " fmt, __func__, __LINE__

/* Offset added to the real netns id to obtain a distinct test value. */
#define FAKE_NETNS_OFFSET 0x1000u

static int run_tests(void)
{
	unsigned int real_netns;
	unsigned int fake_netns;

	/* No override should be active for a fresh task. */
	if (cass_get_netns_override() != 0) {
		pr_err("expected no override initially\n");
		return -EIO;
	}

	/* Without an override, CURRENT_NETNS_ID() reports the task's netns. */
	real_netns = CURRENT_NETNS_ID();
	if (real_netns == 0) {
		pr_err("current netns id is unexpectedly 0\n");
		return -EIO;
	}

	fake_netns = real_netns + FAKE_NETNS_OFFSET;

	/* With an override, both the accessor and CURRENT_NETNS_ID() must
	 * report the forwarded value rather than the task's own netns.
	 */
	cass_set_netns_override(fake_netns);
	if (cass_get_netns_override() != fake_netns) {
		pr_err("override not reported: got %u want %u\n",
		       cass_get_netns_override(), fake_netns);
		cass_clear_netns_override();
		return -EIO;
	}
	if (CURRENT_NETNS_ID() != fake_netns) {
		pr_err("CURRENT_NETNS_ID ignored override: got %u want %u\n",
		       CURRENT_NETNS_ID(), fake_netns);
		cass_clear_netns_override();
		return -EIO;
	}

	/* Clearing the override restores the task's real netns. */
	cass_clear_netns_override();
	if (cass_get_netns_override() != 0) {
		pr_err("override not cleared\n");
		return -EIO;
	}
	if (CURRENT_NETNS_ID() != real_netns) {
		pr_err("netns not restored: got %u want %u\n",
		       CURRENT_NETNS_ID(), real_netns);
		return -EIO;
	}

	pr_info("All tests pass\n");
	return 0;
}

static int __init init(void)
{
	int rc = run_tests();

	if (rc)
		pr_err("Failed: %d\n", rc);

	return rc;
}

static void __exit cleanup(void)
{
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("CXI netns override unit test");
MODULE_AUTHOR("HPE");
