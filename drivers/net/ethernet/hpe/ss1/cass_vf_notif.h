/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>

#ifndef	_CASS_VF_NOTIF_H
#define	_CASS_VF_NOTIF_H

enum cass_vf_notif_ops {
	CASS_VF_NOTIF_OP_INVALID = 0,
	CASS_VF_NOTIF_OP_PING,
	CASS_VF_NOTIF_OP_ASYNC_EVENT,
	CASS_VF_NOTIF_OP_MAC_ADDR_CHANGE,
	CASS_VF_NOTIF_OP_SPOOF_CHK_CHANGE,
	CASS_VF_NOTIF_OP_MC_SW_RX_FANOUT_PKT,
	CASS_VF_NOTIF_OP_MAX,
};

struct cass_vf_notif_common {
	enum cass_vf_notif_ops op;
};

struct cass_vf_notif_ping {
	enum cass_vf_notif_ops op;
};

/* Generic notification: forwards a cxi_async_event from the PF to the VF. */
struct cass_vf_notif_async_event {
	enum cass_vf_notif_ops op;
	unsigned int event; /* enum cxi_async_event */
};

/* PF -> VF RX software-switch fanout packet notification. */
struct cass_vf_notif_mc_sw_rx_fanout_pkt {
	enum cass_vf_notif_ops op;
	u32 csum;
	u16 frame_len;
	u8 csum_state;
	u8 frame[];
};

/* Notification: PF admin assigned a new MAC address to the VF. */
struct cass_vf_notif_mac_addr_change {
	enum cass_vf_notif_ops op;
	u64 mac; /* new assigned MAC, host-endian 48-bit */
};

/* Notification: PF admin changed the TX source-MAC spoof-check setting. */
struct cass_vf_notif_spoof_chk_change {
	enum cass_vf_notif_ops op;
	bool spoof_chk; /* true = enforce SMAC == ndev->dev_addr on TX */
};

struct cass_vf_notif_info {
	unsigned int req_size;
	const char *name;
	int (*handler)(struct cass_dev *hw, const void *cmd_in,
		       void **resp, size_t *resp_len);
};

int dispatch_vf_notif(struct cass_dev *hw, const void *req, size_t req_len,
		      void **rsp, size_t *rsp_len);

#endif	/* _CASS_VF_NOTIF_H_ */
