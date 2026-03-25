// SPDX-License-Identifier: GPL-2.0
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>

#include "cass_core.h"
#include "cxi_core.h"
#include "cass_vf_notif.h"

#if !defined(CXI_DISABLE_SRIOV)

static int cass_vf_notif_ping_handler(struct cass_dev *hw,
				      const void *cmd_in, void *resp,
				      size_t *resp_len)
{
	return 0;
}

static const struct cass_vf_notif_info vf_notif_info[] = {
	[CASS_VF_NOTIF_OP_PING] = {
		.req_size   = sizeof(struct cass_vf_notif_ping),
		.name       = "PING",
		.handler    = cass_vf_notif_ping_handler, },
};

int dispatch_vf_notif(struct cass_dev *hw, const void *req, size_t req_len,
		      void *rsp, size_t *rsp_len)
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
