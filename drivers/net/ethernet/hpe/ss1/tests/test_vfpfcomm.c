// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019, 2024-2026 Cray Inc. All rights reserved */

/* Test the PF/VF communication. The requirement for this test is that
 * the VF is also accessible in the host. ie. the VF is not given to a
 * virtual machine.
 *
 * This test could be split into 2 drivers at some point. One to
 * handle the PF part, and the other for the VFs.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <uapi/ethernet/cxi-abi.h>
#include <linux/hpe/cxi/cxi.h>
#include <linux/vmalloc.h>

#include <cxi_prov_hw.h>

#include "cxi_core.h"

/* List of devices registered with this client */
static LIST_HEAD(dev_list);
static DEFINE_MUTEX(dev_list_mutex);

/* Request and reply. Must be odd length for now. The NUL character
 * will make the message of even length.
 */
static const char *request_msg = "hello there";
static const char *reply_msg =   "what's up buddy";

/* Keep track of known devices. Protected by dev_list_mutex. */
struct tdev {
	struct list_head dev_list;
	struct cxi_dev *dev;

	struct delayed_work test_work;
};

/* Read a message from a VF. This would be in cxi-user. */
static int msg_relay(void *data, unsigned int vf_num,
		     const void *req, size_t req_len, uid_t uid, gid_t gid,
		     void **rsp, size_t rsp_buf_size, size_t *rsp_len)
{
	pr_debug("Got message from VF %d, len %zu\n", vf_num, req_len);

	BUG_ON(data == NULL);

	/* Process the request */
	if (req_len != strlen(request_msg) + 1)
		pr_err("BAD: Unexpected request length\n");
	else if (memcmp(request_msg, req, req_len))
		pr_err("BAD: Request has unexpected data\n");
	else
		pr_debug("Request is valid\n");

	/* Prepare the reply. Reply will get freed by the VF message handler. */
	*rsp_len = strlen(reply_msg) + 1;
	*rsp = kvzalloc(*rsp_len, GFP_KERNEL);
	if (!*rsp)
		return -ENOMEM;
	strcpy(*rsp, reply_msg);

	return 0;
}

/* Number of requests sent beyond the burst allowance, to make the resulting
 * throttling delay clearly measurable above scheduling noise.
 */
#define RATE_LIMIT_TEST_OVER_COUNT 200

/* These mirror the VF_REQ_RATE_BURST_DFLT / VF_REQ_RATE_LIMIT_DFLT defaults in
 * cass_sriov.c. If those defaults change, or vf_req_rate_burst/vf_req_rate_limit
 * module params are overridden, this test's expected timing will be off.
 */
#define RATE_LIMIT_TEST_BURST_ASSUMED 50
#define RATE_LIMIT_TEST_RATE_ASSUMED  200

/* Flood the VF->PF request channel past its leaky-bucket burst allowance and
 * verify the PF throttles it rather than processing the flood immediately.
 */
static bool test_rate_limit(struct cxi_dev *dev)
{
	unsigned int total = RATE_LIMIT_TEST_BURST_ASSUMED + RATE_LIMIT_TEST_OVER_COUNT;
	char reply[100];
	size_t reply_len;
	ktime_t start, end;
	s64 elapsed_ms, expected_min_ms;
	unsigned int i;
	int rc;

	pr_info("Rate limit test: sending %u requests\n", total);

	start = ktime_get();
	for (i = 0; i < total; i++) {
		reply_len = sizeof(reply);
		rc = cxi_send_msg_to_pf(dev, request_msg, strlen(request_msg) + 1,
					reply, &reply_len);
		if (rc != 0) {
			pr_err("BAD: rate limit test: request %u failed: %d\n", i, rc);
			return false;
		}
	}
	end = ktime_get();

	elapsed_ms = ktime_to_ms(ktime_sub(end, start));
	expected_min_ms = MSEC_PER_SEC * RATE_LIMIT_TEST_OVER_COUNT / RATE_LIMIT_TEST_RATE_ASSUMED;

	pr_info("Rate limit test: %u requests took %lld ms (expected >= %lld ms)\n",
		total, elapsed_ms, expected_min_ms);

	/* Generous slack for scheduling jitter; this only needs to show that
	 * throttling occurred, not match the configured rate precisely.
	 */
	if (elapsed_ms < expected_min_ms / 2) {
		pr_err("BAD: rate limit test: requests were not throttled as expected\n");
		return false;
	}

	pr_info("Rate limit test: requests were throttled as expected\n");
	return true;
}

/* Send a message to the PF, which will be relayed to msg_relay(), and
 * get the reply. This function is only run on a VF.
 */
static void test_work(struct work_struct *work)
{
	struct tdev *tdev = container_of(work, struct tdev, test_work.work);
	struct cxi_dev *dev = tdev->dev;
	char reply[100];
	size_t reply_len;
	int rc;
	bool pass_msgtest = false;
	bool pass_ratetest = false;

	reply_len = sizeof(reply);
	rc = cxi_send_msg_to_pf(dev, request_msg, strlen(request_msg) + 1,
				reply, &reply_len);

	if (rc != 0) {
		pr_err("BAD: Reply has return code %d\n", rc);
	} else if (reply_len != strlen(reply_msg) + 1) {
		pr_err("BAD: Reply has unexpected length %zu\n", reply_len);
	} else if (memcmp(reply_msg, reply, strlen(reply_msg) + 1)) {
		pr_err("BAD: Reply has unexpected data\n");
	} else {
		pr_info("Reply is valid\n");
		pass_msgtest = true;
	}

	pass_ratetest = test_rate_limit(dev);

	pr_info("Test done\n");
	pr_info("Message test: %s\n", pass_msgtest ? "PASS" : "FAIL");
	pr_info("Rate limit test: %s\n", pass_ratetest ? "PASS" : "FAIL");
}

/* Core is adding a new device */
static int add_device(struct cxi_dev *cdev)
{
	struct tdev *tdev;
	int rc;

	tdev = kzalloc(sizeof(*tdev), GFP_KERNEL);
	if (tdev == NULL)
		return -ENOMEM;

	tdev->dev = cdev;

	if (cdev->is_physfn) {
		rc = cxi_register_msg_relay(cdev, msg_relay, tdev);
		if (rc) {
			dev_err(&cdev->pdev->dev, "BAD: msg_relay registration failed: %d\n", rc);
			kfree(tdev);
			return rc;
		}
	} else {
		INIT_DELAYED_WORK(&tdev->test_work, test_work);
		schedule_delayed_work(&tdev->test_work, 2 * HZ);
	}

	mutex_lock(&dev_list_mutex);
	list_add_tail(&tdev->dev_list, &dev_list);
	mutex_unlock(&dev_list_mutex);

	return 0;
}

static void remove_device(struct cxi_dev *dev)
{
	struct tdev *tdev;
	bool found = false;

	/* Find the device in the list */
	mutex_lock(&dev_list_mutex);
	list_for_each_entry_reverse(tdev, &dev_list, dev_list) {
		if (tdev->dev == dev) {
			found = true;
			list_del(&tdev->dev_list);
			break;
		}
	}
	mutex_unlock(&dev_list_mutex);

	if (!found)
		return;

	if (dev->is_physfn)
		cxi_unregister_msg_relay(dev);
	else
		cancel_delayed_work_sync(&tdev->test_work);

	kfree(tdev);

	pr_info("Removing VF/PF comm client device %s\n", dev->name);
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
		pr_err("BAD: Couldn't register client\n");
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
MODULE_DESCRIPTION("Cray eXascale Interconnect (CXI) VF/PF test driver");
MODULE_AUTHOR("Cray Inc.");
