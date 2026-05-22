// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019, 2022, 2024-2026 Hewlett Packard Enterprise Development LP */

/* Core driver support for Ethernet devices */

#include <linux/hpe/cxi/cxi.h>
#include <linux/etherdevice.h>

#include "cass_core.h"
#include "cxi_internal.h"

/**
 * cxi_set_ethernet_threshold() - Configure the Ethernet buffer threshold
 * @cdev: CXI device
 * @threshold: Threshold to set
 *
 * See C_LPE_CFG_ETHERNET_THRESHOLD documentation
 */
void cxi_set_ethernet_threshold(struct cxi_dev *cdev, unsigned int threshold)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	union c_lpe_cfg_ethernet_threshold eth_thr = {
		.threshold = threshold,
	};

	if (!cdev->is_physfn)
		return;

	cass_write(hw, C_LPE_CFG_ETHERNET_THRESHOLD, &eth_thr, sizeof(eth_thr));
}
EXPORT_SYMBOL(cxi_set_ethernet_threshold);

/**
 * cxi_set_roce_rcv_seg() - Control RoCE receive segmentation
 *
 * Whether to enable or disable the RoCE receive segmentation. When
 * enabled, the HW will put the RoCE payload in a separate SKB
 * fragment, and the driver will add the RoCE CRC in a third fragment.
 *
 * @cdev: CXI device
 * @enable: true to enable, false to disable
 */
void cxi_set_roce_rcv_seg(struct cxi_dev *cdev, bool enable)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	union c_ixe_cfg_roce cfg_roce;

	if (!cdev->is_physfn)
		return;

	cass_read(hw, C_IXE_CFG_ROCE, &cfg_roce, sizeof(cfg_roce));
	cfg_roce.enable_1k = enable;
	cfg_roce.enable_2k = enable;
	cfg_roce.enable_4k = enable;
	cass_write(hw, C_IXE_CFG_ROCE, &cfg_roce, sizeof(cfg_roce));
}
EXPORT_SYMBOL(cxi_set_roce_rcv_seg);

static void cxi_eth_devinfo_vf(struct cxi_dev *cdev, struct cxi_eth_info *eth_info)
{
	const struct cxi_eth_dev_info_get_cmd cmd = {
		.op = CXI_OP_ETH_DEV_INFO_GET,
		.buf_size = sizeof(*eth_info),
	};
	size_t resp_len = sizeof(*eth_info);
	int rc;

	rc = cxi_send_msg_to_pf(cdev, &cmd, sizeof(cmd), eth_info, &resp_len);
	if (rc)
		goto err;

	if (resp_len != sizeof(*eth_info)) {
		cxidev_err(cdev, "Invalid response length: %zu (expected %zu)\n",
			   resp_len, sizeof(*eth_info));
		goto err;
	}

	/* Do not expose the PF MAC address to VFs */
	memset(eth_info->default_mac_addr, 0, sizeof(eth_info->default_mac_addr));

	return;
err:
	memset(eth_info, 0, sizeof(*eth_info));
}

/**
 * cxi_eth_devinfo() - Get some current Ethernet related device information
 *
 * @cdev: CXI device
 * @eth_info: structure to return the information
 *
 * When called on the PF, default_mac_addr is filled with the PF hardware
 * address. When called on a VF, default_mac_addr is filled with zeroes.
 */
void cxi_eth_devinfo(struct cxi_dev *cdev, struct cxi_eth_info *eth_info)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	union c_ixe_cfg_parser cfg_parser;

	if (!cdev->is_physfn) {
		cxi_eth_devinfo_vf(cdev, eth_info);
		return;
	}

	cass_read(hw, C_IXE_CFG_PARSER, &cfg_parser, sizeof(cfg_parser));
	eth_info->max_segment_size = (cfg_parser.eth_segment + 1) * 128;
	ether_addr_copy(eth_info->default_mac_addr, hw->default_mac_addr);

	mutex_lock(&hw->qsfp_eeprom_lock);
	eth_info->qsfp_eeprom_len = hw->qsfp_eeprom_page_len;
	memcpy(eth_info->qsfp_eeprom, hw->qsfp_eeprom_page0, hw->qsfp_eeprom_page_len);
	mutex_unlock(&hw->qsfp_eeprom_lock);

	if (hw->fw_versions[FW_QSPI_BLOB])
		strscpy(eth_info->fw_version, hw->fw_versions[FW_QSPI_BLOB],
			sizeof(eth_info->fw_version));

	if (hw->fw_versions[FW_OPROM])
		strscpy(eth_info->erom_version, hw->fw_versions[FW_OPROM],
			sizeof(eth_info->erom_version));

	eth_info->ptp_clock_index = ptp_clock_index(hw->ptp_clock);
	eth_info->min_free_shift = cdev->prop.min_free_shift;
}
EXPORT_SYMBOL(cxi_eth_devinfo);

/**
 * cxi_eth_vf_get_assigned_mac_internal() - Retrieve the PF-admin-assigned MAC for a VF
 * @cdev:   PF CXI device
 * @vf_num: VF index (0-based)
 * @mac:    output; set to the assigned MAC, or 0 if no MAC has been set
 *
 * Returns 0 on success, negative errno on failure.
 */
int cxi_eth_vf_get_assigned_mac_internal(struct cxi_dev *cdev, unsigned int vf_num,
					u64 *mac)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);

	if (vf_num >= hw->num_vfs)
		return -EINVAL;

	mutex_lock(&hw->rmu_eth_lock);
	*mac = hw->vf_eth_cfg[vf_num].own_mac;
	mutex_unlock(&hw->rmu_eth_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_eth_vf_get_assigned_mac_internal);

/**
 * cxi_eth_vf_get_assigned_mac() - Get this VF's admin-assigned MAC address
 * @cdev: VF CXI device
 * @mac:  output buffer (ETH_ALEN bytes)
 *
 * Returns 0 on success (mac filled), negative errno on failure.
 */
int cxi_eth_vf_get_assigned_mac(struct cxi_dev *cdev, u8 *mac)
{
	const struct cxi_eth_vf_mac_get_cmd cmd = {
		.op = CXI_OP_ETH_VF_MAC_GET,
	};
	struct cxi_eth_vf_mac_get_resp resp = {};
	size_t resp_len = sizeof(resp);
	int rc;

	if (cdev->is_physfn)
		return -EOPNOTSUPP;

	rc = cxi_send_msg_to_pf(cdev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc)
		return rc;

	u64_to_ether_addr(resp.mac, mac);
	return 0;
}
EXPORT_SYMBOL(cxi_eth_vf_get_assigned_mac);

/**
 * cxi_eth_validate_vf_mac() - Ask the PF whether a MAC address is permitted for this VF
 * @cdev: VF CXI device
 * @mac:  Proposed MAC address (ETH_ALEN bytes)
 *
 * Returns 0 if the PF allows the address, -EPERM if denied by policy,
 * -EINVAL for an invalid address, or another negative errno on comms failure.
 */
int cxi_eth_validate_vf_mac(struct cxi_dev *cdev, const u8 *mac)
{
	struct cxi_eth_vf_mac_validate_cmd cmd = {
		.op = CXI_OP_ETH_VF_MAC_VALIDATE,
	};
	size_t resp_len = 0;

	if (cdev->is_physfn)
		return -EOPNOTSUPP;

	cmd.mac = ether_addr_to_u64(mac);

	return cxi_send_msg_to_pf(cdev, &cmd, sizeof(cmd), NULL, &resp_len);
}
EXPORT_SYMBOL(cxi_eth_validate_vf_mac);

/**
 * cxi_set_led_beacon() - Activate or deactivate LED beacon
 *
 * @cdev: CXI device
 * @state: true to activate, false to deactivate
 */
void cxi_set_led_beacon(struct cxi_dev *cdev, bool state)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);

	if (!cdev->is_physfn)
		return;

	hw->qsfp_beacon_active = state;
	cass_link_set_led(hw);
}
EXPORT_SYMBOL(cxi_set_led_beacon);

/**
 * cxi_set_eth_name() - Set an Ethernet device name to a CXI interface
 *
 * When an Ethernet interface is added, call this function to match
 * both interfaces. This is to be used primarily for logging, as it's
 * not always clear which CXI device an Ethernet interface belongs to.
 *
 * @cdev: CXI device
 * @name: Ethernet name assigned to the device, such as "hsn0" or "eth0".
 */
void cxi_set_eth_name(struct cxi_dev *cdev, const char *name)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);

	strscpy(cdev->eth_name, name, sizeof(cdev->eth_name));

	/* Update name in sbl/sl (only in PF) */
	if (cdev->is_physfn)
		hw->link_ops->eth_name_set(hw, cdev->eth_name);
}
EXPORT_SYMBOL(cxi_set_eth_name);

/**
 * cxi_eth_cfg_timestamp() - timestamping of packets
 *
 * @cdev: CXI device
 * @config: timestamp configuration. TX filter must be
 *          HWTSTAMP_TX_ON/OFF, and RX filter must be
 *          HWTSTAMP_FILTER_NONE or HWTSTAMP_FILTER_PTP_V2_L2_EVENT.
 *
 * TODO: locking ? from caller?
 */
int cxi_eth_cfg_timestamp(struct cxi_dev *cdev,
			  struct hwtstamp_config *config)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	union c_hni_cfg_gen cfg_gen;

	if (!cdev->is_physfn)
		return -EOPNOTSUPP;

	if (config->flags != 0)
		return -EINVAL;

	if (config->tx_type != HWTSTAMP_TX_OFF &&
	    config->tx_type != HWTSTAMP_TX_ON)
		return -EINVAL;

	if (config->rx_filter != HWTSTAMP_FILTER_NONE &&
	    config->rx_filter != HWTSTAMP_FILTER_PTP_V2_L2_EVENT)
		return -EINVAL;

	/* Turn everything on if any timestamping is requested. */
	if (config->tx_type != HWTSTAMP_TX_OFF)
		config->tx_type = HWTSTAMP_TX_ON;

	cass_read(hw, C_HNI_CFG_GEN, &cfg_gen, sizeof(cfg_gen));

	cfg_gen.tx_timestamp_en = config->tx_type == HWTSTAMP_TX_ON;
	cfg_gen.rx_timestamp_en =
		config->rx_filter == HWTSTAMP_FILTER_PTP_V2_L2_EVENT;

	if (cfg_gen.tx_timestamp_en) {
		/* Only program IEEE-1588 packets. */
		static const union c_hni_cfg_txts_l2_mask l2_mask = {
			.dmac = ~0,
			.ethertype = 0,
		};
		static const union c_hni_cfg_txts_l2_match l2_match = {
			.dmac = 0,
			.ethertype = PTP_L2_ETHERTYPE,
		};
		static const union c_hni_cfg_txts_l3_mask l3_mask = {
			.hdr = ~0,
		};
		static const union c_hni_cfg_txts_l3_match l3_match = {
			.hdr = 0,
		};
		union c_hni_pml_sts_tx_pcs tx_ts;

		cass_write(hw, C_HNI_CFG_TXTS_L2_MASK,
			   &l2_mask, sizeof(l2_mask));
		cass_write(hw, C_HNI_CFG_TXTS_L2_MATCH,
			   &l2_match, sizeof(l2_match));
		cass_write(hw, C_HNI_CFG_TXTS_L3_MASK,
			   &l3_mask, sizeof(l3_mask));
		cass_write(hw, C_HNI_CFG_TXTS_L3_MATCH,
			   &l3_match, sizeof(l3_match));

		/* Set the timestamp format/shift in 2 CSRs */
		cfg_gen.timestamp_fmt = hw->tx_timestamp_shift;

		if (cass_version(hw, CASSINI_1)) {
			union c1_hni_pml_cfg_pcs cfg_pcs;

			cass_read(hw, C1_HNI_PML_CFG_PCS, &cfg_pcs, sizeof(cfg_pcs));
			cfg_pcs.timestamp_shift = hw->tx_timestamp_shift;
			cass_write(hw, C1_HNI_PML_CFG_PCS, &cfg_pcs, sizeof(cfg_pcs));

			/* Clear the timestamp_valid bit just in case */
			cass_read(hw, C1_HNI_PML_STS_TX_PCS, &tx_ts, sizeof(tx_ts));
			tx_ts.timestamp_valid = 0;
			cass_write(hw, C1_HNI_PML_STS_TX_PCS, &tx_ts, sizeof(tx_ts));
		} else {
			union ss2_port_pml_cfg_pcs cfg_pcs;

			cass_read(hw, SS2_PORT_PML_CFG_PCS, &cfg_pcs, sizeof(cfg_pcs));
			cfg_pcs.timestamp_shift = hw->tx_timestamp_shift;
			cass_write(hw, SS2_PORT_PML_CFG_PCS, &cfg_pcs, sizeof(cfg_pcs));

			/* Clear the timestamp_valid bit just in case */
			cass_read(hw, SS2_PORT_PML_STS_TX_PCS(0), &tx_ts, sizeof(tx_ts));
			tx_ts.timestamp_valid = 0;
			cass_write(hw, SS2_PORT_PML_STS_TX_PCS(0), &tx_ts, sizeof(tx_ts));
		}
	}

	if (cfg_gen.rx_timestamp_en) {
		/* WORKAROUND: Cassini ERRATA-3258, only program IEEE-1588 packets. */
		static const union c_hni_cfg_rxts_l2_mask l2_mask = {
			.dmac = 0,
			.ethertype = 0,
		};
		static const union c_hni_cfg_rxts_l2_match l2_match = {
			.dmac = PTP_L2_MAC,
			.ethertype = PTP_L2_ETHERTYPE,
		};
		static const union c_hni_cfg_rxts_l3_mask l3_mask = {
			.hdr = ~0,
		};
		static const union c_hni_cfg_rxts_l3_match l3_match = {
			.hdr = 0,
		};

		cass_write(hw, C_HNI_CFG_RXTS_L2_MASK,
			   &l2_mask, sizeof(l2_mask));
		cass_write(hw, C_HNI_CFG_RXTS_L2_MATCH,
			   &l2_match, sizeof(l2_match));
		cass_write(hw, C_HNI_CFG_RXTS_L3_MASK,
			   &l3_mask, sizeof(l3_mask));
		cass_write(hw, C_HNI_CFG_RXTS_L3_MATCH,
			   &l3_match, sizeof(l3_match));
	}

	cass_write(hw, C_HNI_CFG_GEN, &cfg_gen, sizeof(cfg_gen));
	cass_flush_pci(hw);

	return 0;
}
EXPORT_SYMBOL(cxi_eth_cfg_timestamp);

/**
 * cxi_eth_get_tx_timestamp() - Retrieve current Ethernet TX timestamp
 *
 * After the driver requested timestamping of Ethernet TX packets, the
 * Ethernet driver can retrieve the current timestamp upon the send
 * completion.
 *
 * @cdev: CXI device
 * @tstamps: storage to return the timestamp
 **/
int cxi_eth_get_tx_timestamp(struct cxi_dev *cdev,
			     struct skb_shared_hwtstamps *tstamps)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	union c_hni_err_elapsed_time err_elapsed_time;
	union c_hni_cfg_rt_offset rt_offset;
	union c_hni_pml_sts_tx_pcs tx_ts;
	struct timespec64 ts;
	u64 ts_sec;
	u64 curr_sec;
	u64 diff_sec;

	if (!cdev->is_physfn)
		return -EOPNOTSUPP;

	/* Note: union c_hni_pml_sts_tx_pcs and union
	 * ss2_port_pml_sts_tx_pcs are identical structures.
	 */
	if (cass_version(hw, CASSINI_1))
		cass_read(hw, C1_HNI_PML_STS_TX_PCS, &tx_ts, sizeof(tx_ts));
	else
		cass_read(hw, SS2_PORT_PML_STS_TX_PCS(0), &tx_ts, sizeof(tx_ts));

	cass_read(hw, C_HNI_ERR_ELAPSED_TIME,
		  &err_elapsed_time, sizeof(err_elapsed_time));
	cass_read(hw, C_HNI_CFG_RT_OFFSET, &rt_offset, sizeof(rt_offset));

	if (WARN_ON_ONCE(!tx_ts.timestamp_valid))
		return -ENODATA;

	switch (hw->tx_timestamp_shift) {
	case 0:
		ts.tv_nsec = tx_ts.timestamp & (BIT(30) - 1) * 1;
		ts_sec = tx_ts.timestamp >> 30;
		curr_sec = err_elapsed_time.seconds & ((BIT(2) - 1));
		diff_sec = BIT(2);
		break;
	case 1:
		ts.tv_nsec = (tx_ts.timestamp & (BIT(28) - 1)) * 4;
		ts_sec = tx_ts.timestamp >> 28;
		curr_sec = err_elapsed_time.seconds & ((BIT(4) - 1));
		diff_sec = BIT(4);
		break;
	case 2:
		ts.tv_nsec = (tx_ts.timestamp & (BIT(26) - 1)) * 16;
		ts_sec = tx_ts.timestamp >> 26;
		curr_sec = err_elapsed_time.seconds & ((BIT(6) - 1));
		diff_sec = BIT(6);
		break;
	case 3:
		ts.tv_nsec = (tx_ts.timestamp & (BIT(24) - 1)) * 64;
		ts_sec = tx_ts.timestamp >> 24;
		curr_sec = err_elapsed_time.seconds & ((BIT(8) - 1));
		diff_sec = BIT(8);
		break;
	default:
		/* Normally unreachable */
		cxidev_WARN_ONCE(cdev, true, "bad tx_timestamp_shift");
		return -EINVAL;
	}

	if (curr_sec < ts_sec)
		diff_sec += curr_sec - ts_sec;
	else
		diff_sec = curr_sec - ts_sec;

	ts.tv_sec = rt_offset.seconds + err_elapsed_time.seconds - diff_sec;

	tstamps->hwtstamp = timespec64_to_ktime(ts);

	/* Clear valid bit for next packet. */
	tx_ts.timestamp_valid = 0;
	if (cass_version(hw, CASSINI_1))
		cass_write(hw, C1_HNI_PML_STS_TX_PCS, &tx_ts, sizeof(tx_ts));
	else
		cass_write(hw, SS2_PORT_PML_STS_TX_PCS(0), &tx_ts, sizeof(tx_ts));

	return 0;
}
EXPORT_SYMBOL(cxi_eth_get_tx_timestamp);

static void cxi_eth_get_pause_vf(struct cxi_dev *cdev, struct ethtool_pauseparam *pause)
{
	struct cxi_eth_pause_get_cmd cmd = {
		.op = CXI_OP_ETH_PAUSE_GET,
	};
	struct cxi_eth_get_pause_resp resp = {};
	size_t resp_len = sizeof(resp);
	int rc;

	rc = cxi_send_msg_to_pf(cdev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc) {
		/* On error, set pause to disabled */
		pause->tx_pause = false;
		pause->rx_pause = false;
		return;
	}

	pause->tx_pause = resp.tx_pause;
	pause->rx_pause = resp.rx_pause;
}

/**
 * cxi_eth_get_pause() - Enable of disable the RX and TX pause packets
 *
 * @cdev: CXI device
 * @pause: ethtool parameters
 */
void cxi_eth_get_pause(struct cxi_dev *cdev, struct ethtool_pauseparam *pause)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	union c_hni_cfg_pause_tx_ctrl tx_ctrl_cfg;
	union c_hni_cfg_pause_rx_ctrl rx_ctrl_cfg;

	if (!cdev->is_physfn) {
		cxi_eth_get_pause_vf(cdev, pause);
		return;
	}

	cass_read(hw, C_HNI_CFG_PAUSE_TX_CTRL, &tx_ctrl_cfg,
		  sizeof(tx_ctrl_cfg));
	pause->tx_pause = tx_ctrl_cfg.enable_send_pause != 0;

	cass_read(hw, C_HNI_CFG_PAUSE_RX_CTRL, &rx_ctrl_cfg,
		  sizeof(rx_ctrl_cfg));
	pause->rx_pause = rx_ctrl_cfg.enable_rec_pause != 0;
}
EXPORT_SYMBOL(cxi_eth_get_pause);

/**
 * cxi_eth_set_pause() - Enable of disable the RX and TX pause packets
 *
 * @cdev: CXI device
 * @pause: ethtool parameters
 */
void cxi_eth_set_pause(struct cxi_dev *cdev, const struct ethtool_pauseparam *pause)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);

	if (!cdev->is_physfn)
		return;

	cass_tc_set_tx_pause_all(hw, pause->tx_pause);
	cass_tc_set_rx_pause_all(hw, pause->rx_pause);
}
EXPORT_SYMBOL(cxi_eth_set_pause);
