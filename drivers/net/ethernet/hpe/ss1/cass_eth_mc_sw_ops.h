/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

/* Core <-> Ethernet software-switch contract.
 *
 * Minimal interface shared between the core (cxi-ss1) and the Ethernet driver
 * (cxi-eth) for the multicast software switch. The functions declared here are
 * implemented in core (cass_eth_mc_sw_ops.c) and called by the Ethernet
 * driver; the ops table is implemented by the Ethernet driver and invoked by
 * core. This header intentionally exposes no Ethernet-private types, so core
 * can reference the contract without depending on the software-switch
 * implementation (see cxi_eth_mc_sw.h/.c).
 */

#ifndef __CXI_ETH_MC_SW_OPS_H__
#define __CXI_ETH_MC_SW_OPS_H__

#include <linux/types.h>
#include <linux/errno.h>

#include <linux/hpe/cxi/cxi.h>

struct cass_dev;
struct cxi_eth;
struct cass_eth_mc_sw;

struct cass_eth_mc_sw_ops {
	int (*sync_rx_mode_filters_pf)(void *ctx,
				       const u64 *mc_mac_addrs, u16 mc_count,
				       u16 ndev_flags, bool is_vf,
				       u8 vf_index);
	void (*cleanup_vf)(void *ctx, unsigned int vf_num);
	int (*vf_recv_rxfout_pkt)(void *ctx,
				  const u8 *frame, u16 frame_len,
				  u8 csum_state, u32 csum);
	int (*sriov_configure)(void *ctx, int num_vfs);
	int (*pf_recv_vf_bum_tx_pkt)(void *ctx, const u8 *frame, u16 frame_len,
				     bool is_vf, u8 vf_index);
};

void cass_eth_mc_sw_reg_ops(struct cxi_dev *cdev,
			    const struct cass_eth_mc_sw_ops *ops,
			    void *ctx);
void cass_eth_mc_sw_unreg_ops(struct cxi_dev *cdev);

int cass_eth_mc_sw_sync_rx_mode(struct cxi_dev *cdev,
				const u64 *mc_mac_addrs, u16 mc_count,
				u16 ndev_flags, bool is_vf, u8 vf_index);

void cass_eth_mc_sw_cleanup_vf(struct cxi_dev *cdev, unsigned int vf_num);

int cass_eth_mc_sw_sriov_configure(struct cass_dev *hw, int num_vfs);

int cass_eth_mc_sw_vf_notif_rxfanout_hdlr(struct cass_dev *hw,
					  const void *cmd_in,
					  void **resp, size_t *resp_len);

int cass_eth_mc_sw_pf_recv_txfwd_from_vf(struct cxi_dev *cdev,
					 const u8 *frame, u16 frame_len,
					 bool is_vf, u8 vf_index);

/* Lifecycle of the opaque per-device software-switch registration state
 * (struct cass_eth_mc_sw). Allocated by core probe, released by core remove.
 */
int cass_eth_mc_sw_alloc(struct cass_dev *hw);
void cass_eth_mc_sw_free(struct cass_dev *hw);

/* Registered PF Ethernet context, or NULL if the switch is not registered. */
struct cxi_eth *cass_eth_mc_sw_ctx(const struct cass_dev *hw);

#endif /* __CXI_ETH_MC_SW_OPS_H__ */
