/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 Hewlett Packard Enterprise Development LP */

/* Ethernet multicast software switch.
 *
 * Ethernet-private interface for the cxi-eth multicast software-switch
 * implementation (cxi_eth_mc_sw.c). It covers:
 *   - the PF-side MAC filter subscription tables (multicast/unicast) and the
 *     per-function RX-mode flag shadow;
 *   - the software dispatcher that fans PF-received multicast/broadcast/
 *     promiscuous frames out to subscribed VFs.
 *
 * The core <-> eth contract (RX dispatch callback and reconcile/cleanup ops)
 * lives separately in cass_eth_mc_sw_ops.h so that core has no dependency on the
 * Ethernet-private types declared here.
 */

#ifndef __CXI_ETH_MC_SW_H__
#define __CXI_ETH_MC_SW_H__

#include <linux/types.h>
#include <linux/skbuff.h>

#include "cxi_core.h"
#include "cass_eth_mc_sw_ops.h"

struct cxi_eth;
struct rx_queue;

int cxi_eth_mc_sw_init(struct cxi_eth *dev);
void cxi_eth_mc_sw_fini(struct cxi_eth *dev);
int cxi_eth_mc_sw_reconcile(struct cxi_eth *dev,
			    const u64 *mc_mac_addrs, u16 mc_count,
			    u16 ndev_flags, bool is_vf, u8 vf_index);
bool cxi_eth_mc_sw_rxfout_route(struct rx_queue *rx, struct sk_buff *skb);
void cxi_eth_mc_sw_txfwd_capture(struct cxi_eth *dev, struct sk_buff *skb);
void cxi_eth_mc_sw_sysfs_remove(struct cxi_eth *dev);

#endif /* __CXI_ETH_MC_SW_H__ */
