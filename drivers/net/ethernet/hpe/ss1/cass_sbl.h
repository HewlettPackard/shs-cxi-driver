/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020-2024 Hewlett Packard Enterprise Development LP */

#ifndef _CXI_SBL_H
#define _CXI_SBL_H

#include <linux/phy/phy.h>
#include <uapi/ethernet/sbl-abi.h>
#include "cass_port.h"

struct cass_dev;
struct cxi_link_info;

#define PCA_SHASTA_BRAZOS_PASS_1_PN        "102325100"
#define PCA_SHASTA_BRAZOS_PASS_2_PN        "102325101"
#define PCA_SHASTA_BRAZOS_PASS_3_PN        "102325102"
#define PCA_SHASTA_BRAZOS_PASS_4_PN        "P41345-"

#define PCA_SHASTA_SAWTOOTH_PASS_1_PN      "102251000"
#define PCA_SHASTA_SAWTOOTH_PASS_2_PN      "102251001"
#define PCA_SHASTA_SAWTOOTH_PASS_3_PN      "P43012-"

#define CASS_LINK_ASYNC_DOWN_TIMEOUT              5000
#define CASS_LINK_ASYNC_DOWN_INTERVAL              500
#define CASS_LINK_ASYNC_RESET_TIMEOUT             5000
#define CASS_LINK_ASYNC_RESET_INTERVAL             500
#define CASS_PORT_DEFAULT_OPT_FLAGS                  0

#define CASS_PCS_NUM_FECL_CNTRS                           8

/**
 * @brief default link options flags
 */
#define CASS_LINK_ATTR_DEFAULT_OPT_FLAGS                  0
#define CASS_SBL_PORT_CONFIG1_PRE                         4
#define CASS_SBL_PORT_CONFIG2_ATTEN                       12
#define CASS_SBL_PORT_CONFIG2_GS1                         0
#define CASS_SBL_PORT_CONFIG2_NUM_INTR                    4
#define CASS_SBL_PORT_CONFIG2_INTR0                       0x2c
#define CASS_SBL_PORT_CONFIG2_DATA0                       0x0909
#define CASS_SBL_PORT_CONFIG2_INTR1                       0x6c
#define CASS_SBL_PORT_CONFIG2_DATA1                       0x3
#define CASS_SBL_PORT_CONFIG2_INTR2                       0x2c
#define CASS_SBL_PORT_CONFIG2_DATA2                       0x090a
#define CASS_SBL_PORT_CONFIG2_INTR3                       0x6c
#define CASS_SBL_PORT_CONFIG2_DATA3                       0xa
#define CASS_SBL_PORT_CONFIG3_ATTEN                       6
#define CASS_SBL_PORT_CONFIG3_PRE                         4
#define CASS_SBL_PORT_CONFIG3_POST                        0
#define CASS_SBL_PORT_CONFIG3_GS1                         0

#define CASS_SBL_SC_MASKED_OUT                            0
#define CASS_SBL_SC_MASKED_IN                             0xffffffffffffffff
#define CASS_SBL_SC_NA                                    0x0
#define CASS_SBL_SC_LP_SWITCH                             0x1
#define CASS_SBL_SC_MT_ELEC                               0x1
#define CASS_SBL_SC_MT_OPT_ANY                            0x6
#define CASS_SBL_SC_LBM_ANY                               0xff
#define CASS_SBL_SC_LM_100                                0x2
#define CASS_SBL_SC_LM_200                                0x1

/* NOTE: don't forget to add sysfs entries if changing this */

/* Link up FEC check */
#define CASS_SBL_UP_MIN_FEC_WINDOW             250    /* ms */


/**
 * enum cass_lmon_direction - link monitor direction flags
 *
 * @CASS_LMON_DIRECTION_INVALID: Invalid
 * @CASS_LMON_DIRECTION_NONE:    no action requested
 * @CASS_LMON_DIRECTION_UP:      port should try to come up
 * @CASS_LMON_DIRECTION_DOWN:    port should try to come down
 * @CASS_LMON_DIRECTION_RESET:   port should reset
 */
enum cass_lmon_direction {
	CASS_LMON_DIRECTION_INVALID = 0,
	CASS_LMON_DIRECTION_NONE,
	CASS_LMON_DIRECTION_UP,
	CASS_LMON_DIRECTION_DOWN,
	CASS_LMON_DIRECTION_RESET,
};

/**
 * enum cass_phy_mode - Phy mode for Cassini SerDes
 * @PHY_MODE_NORMAL:		normal operation
 * @PHY_MODE_TX_DISABLED:	Transmitter disabled
 * @PHY_MODE_LOW_POWER:		SerDes in low power mode
 * @PHY_MODE_OFF:		SerDes powered off
 * @PHY_MODE_SPECIAL:		special operation flag
 *
 * Phy mode for Cassini SerDes
 */
enum cass_phy_mode {
	PHY_MODE_NORMAL		= 0,
	PHY_MODE_TX_DISABLED	= 1,
	PHY_MODE_LOW_POWER	= 2,
	PHY_MODE_OFF		= 4,
	PHY_MODE_SPECIAL	= 8,
};

/**
 * enum cass_pause_type - Pause type for Cassini
 * @CASS_PAUSE_TYPE_INVALID:	invalid pause type
 * @CASS_PAUSE_TYPE_NONE:		no pause specified
 * @CASS_PAUSE_TYPE_GLOBAL:		standard pause
 * @CASS_PAUSE_TYPE_802_3X:		standard pause
 * @CASS_PAUSE_TYPE_PFC:		priority flow control pause
 * @CASS_PAUSE_TYPE_802_1QBB:	priority flow control pause
 *
 * Pause type for Cassini
 */
enum cass_pause_type {
	CASS_PAUSE_TYPE_INVALID  = 0,
	CASS_PAUSE_TYPE_NONE,
	CASS_PAUSE_TYPE_GLOBAL,
	CASS_PAUSE_TYPE_802_3X   = CASS_PAUSE_TYPE_GLOBAL,
	CASS_PAUSE_TYPE_PFC,
	CASS_PAUSE_TYPE_802_1QBB = CASS_PAUSE_TYPE_PFC,
};

/**
 * enum cass_sbl_counters_idx - Software counter indexes
 *
 * Counters cannot be reset
 *
 * @link_up:                            link reached up state
 * @link_up_tries:                      link up called
 * @link_down:                          link reached down state
 * @link_down_tries:                    link down called
 * @link_async_down:                    link async down triggers down
 * @link_async_down_tries:              link async down called
 * @link_reset:                         link reset completed
 * @link_reset_tries:                   link reset called
 * @link_auto_restart:                  lmon link auto-restarted
 * @link_down_origin_config:            after config
 * @link_down_origin_bl_lfault:         pcs local fault
 * @link_down_origin_bl_rfault:         pcr remote fault
 * @link_down_origin_bl_align:          pcs align
 * @link_down_origin_bl_down:           pcs link down
 * @link_down_origin_bl_hiser:          pcs high serdes error rate
 * @link_down_origin_bl_llr:            llr error
 * @link_down_origin_bl_unknown:        base link unknown
 * @link_down_origin_lmon_ucw:          lmon high ucw rate
 * @link_down_origin_lmon_ccw:          lmon high ccw rate
 * @link_down_origin_lmon_llr_tx_replay:lmon high llr tx replay rate
 * @link_down_origin_headshell_removed: headshell removed
 * @link_down_origin_headshell_error:   headshell in error
 * @link_down_origin_media_removed:     media removed
 * @link_down_origin_cmd:               user command
 * @SBL_COUNTERS:                       sbl counters defined in sbl_counters.h
 * @CASS_SBL_NUM_COUNTERS:              the number of counters
 */
enum cass_sbl_counters_idx {
	link_up,
	link_up_tries,
	link_down,
	link_down_tries,
	link_async_down,
	link_async_down_tries,
	link_reset,
	link_reset_tries,
	link_auto_restart,
	link_down_origin_config,
	link_down_origin_bl_lfault,
	link_down_origin_bl_rfault,
	link_down_origin_bl_align,
	link_down_origin_bl_down,
	link_down_origin_bl_hiser,
	link_down_origin_bl_llr,
	link_down_origin_bl_unknown,
	link_down_origin_lmon_ucw,
	link_down_origin_lmon_ccw,
	link_down_origin_lmon_llr_tx_replay,
	link_down_origin_headshell_removed,
	link_down_origin_headshell_error,
	link_down_origin_media_removed,
	link_down_origin_cmd,
	SBL_COUNTERS,
	CASS_SBL_NUM_COUNTERS,
};


int cass_sbl_init(struct cass_dev *hw);
int cass_sbl_link_start(struct cass_dev *hw);
void cass_sbl_link_fini(struct cass_dev *hw);
int cass_sbl_power_on(struct cass_dev *hw);
int cass_sbl_power_off(struct cass_dev *hw);
void cass_sbl_set_defaults(struct cass_dev *hw);
int cass_sbl_configure(struct cass_dev *hw);
int cass_sbl_reset(struct cass_dev *hw);

/*
 * link monitors (lmon)
 */
int  cass_lmon_start_all(struct cass_dev *hw);
int  cass_lmon_stop_all(struct cass_dev *hw);
void cass_lmon_kill_all(struct cass_dev *hw);
int cass_lmon_get_dirn(struct cass_dev *hw);
void cass_lmon_set_dirn(struct cass_dev *hw, int dirn);
bool cass_lmon_get_active(struct cass_dev *hw);
void cass_lmon_set_active(struct cass_dev *hw, bool state);
void cass_lmon_set_up_pause(struct cass_dev *hw, bool state);
bool cass_lmon_get_up_pause(struct cass_dev *hw);
int  cass_lmon_request_up(struct cass_dev *hw);
int  cass_lmon_request_down(struct cass_dev *hw);
int  cass_lmon_request_reset(struct cass_dev *hw);
const char *cass_lmon_dirn_str(enum cass_lmon_direction dirn);

/*
 * misc
 */
int  cass_link_get_down_origin(struct cass_dev *hw);
void cass_link_set_down_origin(struct cass_dev *hw, int origin);
const char *cass_link_state_str(enum cass_link_status state);
const char *cass_link_down_origin_str(u32 origin);
void cass_tc_get_hni_pause_cfg(struct cass_dev *hw);

/*
 * Port database
 */
int cass_port_new_port_db(struct cass_dev *hw);
void cass_port_del_port_db(struct cass_dev *hw);

/*
 * link state access
 */
int  cass_link_get_state(struct cass_dev *hw);
void cass_link_set_state(struct cass_dev *hw, int state, int err);

/*
 * set link led
 */
void cass_link_set_led(struct cass_dev *hw);

/*
 * sysfs
 */
int cass_link_sysfs_sprint(struct cass_dev *hw, char *buf, size_t size);
int cass_pause_sysfs_sprint(struct cass_dev *hw, char *buf, size_t size);

/*
 * Text output helpers
 */
const char *cass_port_subtype_str(enum cass_port_subtype subtype);
const char *cass_link_state_str(enum cass_link_status state);
const char *cass_pause_type_str(enum cass_pause_type type);

/*
 * principal link functions
 */
void cass_link_async_down(struct cass_dev *hw, u32 origin);
int  cass_link_async_down_wait(struct cass_dev *hw, u32 origin);
int cass_link_async_reset_wait(struct cass_dev *hw, u32 origin);

void cass_sbl_mode_get(struct cass_dev *hw, struct cxi_link_info *link_info);
void cass_sbl_mode_set(struct cass_dev *hw, const struct cxi_link_info *link_info);
void cass_sbl_pml_recovery_set(struct cass_dev *hw, bool set);
void cass_sbl_get_debug_flags(struct cass_dev *hw, u32 *flags);
void cass_sbl_set_debug_flags(struct cass_dev *hw, u32 clr_flags, u32 set_flags);
void cass_sbl_link_mode_to_speed(u32 link_mode, int *speed);
void cass_sbl_link_speed_to_mode(int speed, u32 *link_mode);

int cass_sbl_media_config(struct cass_dev *hw, void *attr);
int cass_sbl_media_unconfig(struct cass_dev *hw);
int cass_sbl_link_config(struct cass_dev *hw);
bool cass_sbl_is_link_up(struct cass_dev *hw);

bool cass_sbl_pml_pcs_aligned(struct cass_dev *hw);
void cass_sbl_exit(struct cass_dev *hw);

/*
 * sbl counters
 */
int cass_sbl_counters_init(struct cass_dev *hw);
void cass_sbl_counters_term(struct cass_dev *hw);
void cass_sbl_counters_down_origin_inc(struct cass_dev *hw, int down_origin);
void cass_sbl_counters_update(struct cass_dev *hw);

/*
 * lmon counters
 */
int cass_lmon_counters_init(struct cass_dev *hw);
void cass_lmon_counters_term(struct cass_dev *hw);

int cass_sbl_set_eth_name(struct cass_dev *hw, const char *name);
#endif	/* _CXI_SBL_H */
