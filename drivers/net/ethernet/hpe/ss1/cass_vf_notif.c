// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>

#include "cass_core.h"
#include "cxi_core.h"
#include "cass_vf_notif.h"

#if !defined(CXI_DISABLE_SRIOV)

/* *resp points to a buffer of *resp_len bytes. If this is not large enough for the response,
 * the handler should kvzalloc a new buffer, set *resp to point to it, and set *resp_len to the
 * size of the new buffer. The caller is responsible for freeing this buffer with kvfree.
 */

static int cass_vf_notif_ping_handler(struct cass_dev *hw,
				      const void *cmd_in, void **resp,
				      size_t *resp_len)
{
	*resp_len = 0;
	complete(&hw->vf_notif_ready);
	return 0;
}

static int cass_vf_notif_async_event_handler(struct cass_dev *hw,
					     const void *cmd_in, void **resp,
					     size_t *resp_len)
{
	const struct cass_vf_notif_async_event *notif = cmd_in;

	/* Dispatch the event to the VF ethernet driver. */
	cxi_send_async_event(&hw->cdev, (enum cxi_async_event)notif->event);
	return 0;
}

static int cass_vf_notif_mac_addr_change_handler(struct cass_dev *hw,
					     const void *cmd_in, void **resp,
					     size_t *resp_len)
{
	/* Notify registered cxi_clients about the MAC change. */
	cxi_send_async_event(&hw->cdev, CXI_EVENT_MAC_ADDR_CHANGE);
	return 0;
}

static int cass_vf_notif_spoof_chk_handler(struct cass_dev *hw,
					   const void *cmd_in, void **resp,
					   size_t *resp_len)
{
	const struct cass_vf_notif_spoof_chk_change *notif = cmd_in;

	hw->cdev.spoof_chk = notif->spoof_chk;
	cxi_send_async_event(&hw->cdev, CXI_EVENT_SPOOF_CHK_CHANGE);
	return 0;
}

static const struct cass_vf_notif_info vf_notif_info[] = {
	[CASS_VF_NOTIF_OP_PING] = {
		.req_size   = sizeof(struct cass_vf_notif_ping),
		.name       = "PING",
		.handler    = cass_vf_notif_ping_handler, },
	[CASS_VF_NOTIF_OP_ASYNC_EVENT] = {
		.req_size   = sizeof(struct cass_vf_notif_async_event),
		.name       = "ASYNC_EVENT",
		.handler    = cass_vf_notif_async_event_handler, },
	[CASS_VF_NOTIF_OP_MAC_ADDR_CHANGE] = {
		.req_size   = sizeof(struct cass_vf_notif_mac_addr_change),
		.name       = "MAC_ADDR_CHANGE",
		.handler    = cass_vf_notif_mac_addr_change_handler, },
	[CASS_VF_NOTIF_OP_SPOOF_CHK_CHANGE] = {
		.req_size   = sizeof(struct cass_vf_notif_spoof_chk_change),
		.name       = "SPOOF_CHK_CHANGE",
		.handler    = cass_vf_notif_spoof_chk_handler, },
};

int dispatch_vf_notif(struct cass_dev *hw, const void *req, size_t req_len,
		      void **rsp, size_t *rsp_len)
{
	const struct cass_vf_notif_common *common_req = req;
	enum cass_vf_notif_ops op;
	const struct cass_vf_notif_info *info;

	op = common_req->op;
	if (op <= CASS_VF_NOTIF_OP_INVALID || op >= CASS_VF_NOTIF_OP_MAX)
		return -EINVAL;

	info = &vf_notif_info[op];
	if (!info->handler)
		return -EOPNOTSUPP;

	if (req_len != info->req_size)
		return -EINVAL;

	cxidev_dbg(&hw->cdev, "VF notification received: %s\n", info->name);

	return info->handler(hw, req, rsp, rsp_len);
}

#endif /* CXI_DISABLE_SRIOV */
