/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

#include <linux/kernel.h>
#include <linux/types.h>

#ifndef	_CASS_VF_NOTIF_H
#define	_CASS_VF_NOTIF_H

enum cass_vf_notif_ops {
	CASS_VF_NOTIF_OP_INVALID = 0,
	CASS_VF_NOTIF_OP_PING,
	CASS_VF_NOTIF_OP_MAX,
};

struct cass_vf_notif_common {
	enum cass_vf_notif_ops op;
};

struct cass_vf_notif_ping {
	enum cass_vf_notif_ops op;
};

struct cass_vf_notif_info {
	unsigned int req_size;
	const char *name;
	int (*handler)(struct cass_dev *hw, const void *cmd_in,
		       void *resp, size_t *resp_len);
};

int dispatch_vf_notif(struct cass_dev *hw, const void *req, size_t req_len,
		      void *rsp, size_t *rsp_len);

#endif	/* _CASS_VF_NOTIF_H_ */
