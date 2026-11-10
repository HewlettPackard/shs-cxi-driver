/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020-2026 Hewlett Packard Enterprise Development LP */

#ifndef _CASS_PORT_H_
#define _CASS_PORT_H_

#include "uapi/ethernet/sbl-abi.h"

#define CASS_SBL_LINK_RESTART_TIME_SIZE 10

/**
 * @brief software counter names initialisers
 *
 *   provides a name for each counter index
 *
 */
#define CASS_SBL_COUNTER_NAMES  "link_up", \
				"link_up_tries", \
				"link_down", \
				"link_down_tries", \
				"link_async_down", \
				"link_async_down_tries", \
				"link_reset", \
				"link_reset_tries", \
				"link_auto_restart", \
				"link_down_origin_config", \
				"link_down_origin_bl_lfault", \
				"link_down_origin_bl_rfault", \
				"link_down_origin_bl_align", \
				"link_down_origin_bl_down", \
				"link_down_origin_bl_hiser", \
				"link_down_origin_bl_llr", \
				"link_down_origin_bl_unknown", \
				"link_down_origin_lmon_ucw", \
				"link_down_origin_lmon_ccw", \
				"link_down_origin_lmon_llr_tx_replay", \
				"link_down_origin_headshell_removed", \
				"link_down_origin_headshell_error", \
				"link_down_origin_media_removed", \
				"link_down_origin_cmd", \
				SBL_COUNTERS_NAME

#define CASS_LMON_COUNTER_NAMES "lmon_wakeup", \
				"lmon_active", \
				"lmon_limiter"

/**
 * enum cass_port_subtype - The sub-type of a port
 * @CASS_PORT_SUBTYPE_INVALID: Invalid
 * @CASS_PORT_SUBTYPE_LOCAL:   Local group fabric port
 * @CASS_PORT_SUBTYPE_GLOBAL:  Global (inter-group) fabric port
 * @CASS_PORT_SUBTYPE_IEEE:    Standard Ethernet NIC
 * @CASS_PORT_SUBTYPE_CASSINI: Cassini NIC
 *
 * The sub-type of a port
 */
enum cass_port_subtype {
	CASS_PORT_SUBTYPE_INVALID = 0,
	CASS_PORT_SUBTYPE_LOCAL,
	CASS_PORT_SUBTYPE_GLOBAL,
	CASS_PORT_SUBTYPE_IEEE,
	CASS_PORT_SUBTYPE_CASSINI,
};

/**
 * enum cass_port_command - Commands that can be issued to a port
 * @CASS_CMD_NULL:       Invalid
 * @CASS_CMD_NOOP:       Do nothing (for testing)
 * @CASS_CMD_PORT_START: Request port starts
 * @CASS_CMD_PORT_STOP:  Request port stops
 * @CASS_CMD_PORT_RESET: Request port reset
 * @CASS_CMD_LINK_UP:    Request link bring-up
 * @CASS_CMD_LINK_DOWN:  Request link bring-down
 * @CASS_CMD_LINK_RESET: Request link resets
 *
 * Commands that can be issued to a port
 */
enum cass_port_command {
	CASS_CMD_NULL = 0,
	CASS_CMD_NOOP,
	CASS_CMD_PORT_START,
	CASS_CMD_PORT_STOP,
	CASS_CMD_PORT_RESET,
	CASS_CMD_LINK_UP,
	CASS_CMD_LINK_DOWN,
	CASS_CMD_LINK_RESET,
};

/**
 * enum cass_port_status - The status of a port
 * @CASS_PORT_STATUS_UNKNOWN:          State unknown
 * @CASS_PORT_STATUS_NOT_PRESENT:      Port not present in hardware
 * @CASS_PORT_STATUS_UNCONFIGURED:     Port is not configured
 * @CASS_PORT_STATUS_STARTING:         Port Starting
 * @CASS_PORT_STATUS_UP:               Port Up
 * @CASS_PORT_STATUS_RUNNING:          Port Up and Link Up
 * @CASS_PORT_STATUS_RUNNING_DEGRADED: Port Up and Link Up but link degraded
 * @CASS_PORT_STATUS_STOPPING:         Port Stopping
 * @CASS_PORT_STATUS_DOWN:             Port is down and ready to start
 * @CASS_PORT_STATUS_RESETTING:        Port is resetting
 * @CASS_PORT_STATUS_ERROR:            Port has an Error
 *
 * The status of a port
 */
enum cass_port_status {
	CASS_PORT_STATUS_UNKNOWN          = 0,
	CASS_PORT_STATUS_NOT_PRESENT      = 1<<0,
	CASS_PORT_STATUS_UNCONFIGURED     = 1<<1,
	CASS_PORT_STATUS_STARTING         = 1<<2,
	CASS_PORT_STATUS_UP               = 1<<3,
	CASS_PORT_STATUS_RUNNING          = 1<<4,
	CASS_PORT_STATUS_RUNNING_DEGRADED = 1<<5,
	CASS_PORT_STATUS_STOPPING         = 1<<6,
	CASS_PORT_STATUS_DOWN             = 1<<7,
	CASS_PORT_STATUS_RESETTING        = 1<<8,
	CASS_PORT_STATUS_ERROR            = 1<<9,
};

/**
 * enum cass_link_status - Status of the link
 *
 * @CASS_LINK_STATUS_UNKNOWN:		State unknown
 * @CASS_LINK_STATUS_UNCONFIGURED:	Link is not configured
 * @CASS_LINK_STATUS_STARTING:		Link bring-up in progress
 * @CASS_LINK_STATUS_UP:		Link Up
 * @CASS_LINK_STATUS_STOPPING:		Link bring-down in progress
 * @CASS_LINK_STATUS_DOWN:		Link Down
 * @CASS_LINK_STATUS_RESETTING:		Link reset in progress
 * @CASS_LINK_STATUS_ERROR:		Link has an error
 */
enum cass_link_status {
	CASS_LINK_STATUS_UNKNOWN      = 0,
	CASS_LINK_STATUS_UNCONFIGURED = 1<<0,
	CASS_LINK_STATUS_STARTING     = 1<<1,
	CASS_LINK_STATUS_UP           = 1<<2,
	CASS_LINK_STATUS_STOPPING     = 1<<3,
	CASS_LINK_STATUS_DOWN         = 1<<4,
	CASS_LINK_STATUS_RESETTING    = 1<<5,
	CASS_LINK_STATUS_ERROR        = 1<<6,
};

/**
 * enum cass_link_status - Link configuration option flags
 * @CASS_LINK_OPT_UP_AUTO_RESTART:	Keep trying to bring up a link that has
 *					gone down
 * @CASS_LINK_OPT_NO_SHUTDOWN:		Keep trying to bring up a link that has
 *					gone down
 * @CASS_LINK_OPT_RESTART_ON_INSERT:    Allow link restart if up before
 *                                      headshell remove
 *
 * Link configuration option flags
 */
enum cass_link_options {
	CASS_LINK_OPT_UP_AUTO_RESTART    = 1<<1,
	CASS_LINK_OPT_NO_SHUTDOWN        = CASS_LINK_OPT_UP_AUTO_RESTART,
	CASS_LINK_OPT_RESTART_ON_INSERT  = 1<<2,
};

/**
 * enum cass_link_down_origin - The reason the link went down
 * @CASS_DOWN_ORIGIN_UNKNOWN:		Origin is not known
 * @CASS_DOWN_ORIGIN_NONE:		not coming down
 * @CASS_DOWN_ORIGIN_CONFIG:		down after config
 * @CASS_DOWN_ORIGIN_BL_LFAULT:		base link - local fault
 * @CASS_DOWN_ORIGIN_BL_RFAULT:		base link - remote fault
 * @CASS_DOWN_ORIGIN_BL_ALIGN:		base link - alignment lost
 * @CASS_DOWN_ORIGIN_BL_DOWN:		base link - link down
 * @CASS_DOWN_ORIGIN_BL_HISER:		base link - high serdes errors
 * @CASS_DOWN_ORIGIN_BL_LLR:		base link - llr max buffer
 * @CASS_DOWN_ORIGIN_BL_UNKNOWN:	base link - some other reason
 * @CASS_DOWN_ORIGIN_LMON_UCW:		lmon - high uncorrected fec error rate
 * @CASS_DOWN_ORIGIN_LMON_CCW:		lmon - high corrected fec error rate
 * @CASS_DOWN_ORIGIN_LLR_TX_REPLAY:	lmon - high llr_tx_replay fec error rate
 * @CASS_DOWN_ORIGIN_HEADSHELL_REMOVED: headshell removed
 * @CASS_DOWN_ORIGIN_HEADSHELL_ERROR:   headshell fault
 * @CASS_DOWN_ORIGIN_MEDIA_REMOVED:     media removed
 * @CASS_DOWN_ORIGIN_CMD:               direct command
 *
 * The last reason why the link has gone down.
 */
enum cass_link_down_origin {
	CASS_DOWN_ORIGIN_UNKNOWN,
	CASS_DOWN_ORIGIN_NONE,
	CASS_DOWN_ORIGIN_CONFIG,
	CASS_DOWN_ORIGIN_BL_LFAULT,
	CASS_DOWN_ORIGIN_BL_RFAULT,
	CASS_DOWN_ORIGIN_BL_ALIGN,
	CASS_DOWN_ORIGIN_BL_DOWN,
	CASS_DOWN_ORIGIN_BL_HISER,
	CASS_DOWN_ORIGIN_BL_LLR,
	CASS_DOWN_ORIGIN_BL_UNKNOWN,
	CASS_DOWN_ORIGIN_LMON_UCW,
	CASS_DOWN_ORIGIN_LMON_CCW,
	CASS_DOWN_ORIGIN_LLR_TX_REPLAY,
	CASS_DOWN_ORIGIN_HEADSHELL_REMOVED,
	CASS_DOWN_ORIGIN_HEADSHELL_ERROR,
	CASS_DOWN_ORIGIN_MEDIA_REMOVED,
	CASS_DOWN_ORIGIN_CMD,
};

/**
 * enum cass_port_config_flags - Configure/unconfigured state
 * @CASS_TYPE_CONFIGURED:	type info has been configured
 * @CASS_PORT_CONFIGURED:	port info  has been configured
 * @CASS_LINK_CONFIGURED:	link info has been configured
 * @CASS_MEDIA_CONFIGURED:	media info has been configured
 *
 * Configured/uncofigured state for tpml
 */
enum cass_port_config_flags {
	CASS_TYPE_CONFIGURED   = (1<<0),
	CASS_PORT_CONFIGURED   = (1<<1),
	CASS_LINK_CONFIGURED   = (1<<2),
	CASS_MEDIA_CONFIGURED  = (1<<3),
};

/**
 * enum cass_counters_idx - Software counter indexes
 *
 * Counters cannot be reset
 *
 * @lmon_wakeup:                        lmon wakeup
 * @lmon_active:                        lmon active
 * @lmon_limiter:                       lmon limiter
 */
enum cass_lmon_counters_idx {
	lmon_wakeup,
	lmon_active,
	lmon_limiter,
	CASS_LMON_NUM_COUNTERS,
};

/**
 * struct cass_link_attr - Attributes for link configuration
 * @bl:                 base-link attributes
 * @options:            option flags for links
 * @el:                 ether link specific attributes;
 * @el.mattr:           cable related configuration
 *
 * These attributes must be configured for a link.
 * Different setting will be required for fabric or Ethernet links
 * The anonymous union is not required by base link.
 */
struct cass_link_attr {
	struct sbl_base_link_attr bl;
	__u32 options;
	struct sbl_media_attr mattr;
};

/**
 * struct cass_port - port-specific values
 *
 * @subtype:                  ieee or casssini
 * @lock:                     TODO what lock type?
 * @lmon:                     link monitor thread
 * @lmon_dirn:                lmon direction
 * @lmon_wq:                  wq for waking the link monitor
 * @lmon_active:              lmon is awake
 * @lmon_limiter_on:          rate limiter is active
 * @lmon_up_pause:            link up is paused
 * @lmon_wake_jiffies:        end of wake count period
 * @lmon_wake_cnt:            wakeups in period
 * @lmon_counters:            sw counter block (can never be cleared)
 * @config_state:             what has been configured
 * @lattr:                    link related configuration
 * @lstate:                   link state
 * @prev_lstate:              previous link state
 * @lerr:                     error number that caused error state
 * @hstate:                   headshell state
 * @link_down_origin:         reason we are going down
 * @link_restart_count:       auto link restarts since last up command
 * @link_restart_time_idx     auto link restarts current buffer index
 * @link_restart_time_buf     auto link restarts timestamp buffer
 * @pause_lock:               lock on pause state access
 * @pause_type:               type of pause (global/pfc)
 * @tx_pause:                 enable tx pause
 * @rx_pause:                 enable rx pause
 */
struct cass_port {
	int subtype;
	spinlock_t lock;
	struct task_struct *lmon;
	int lmon_dirn;
	wait_queue_head_t lmon_wq;
	bool lmon_active;
	bool lmon_limiter_on;
	bool lmon_up_pause;
	unsigned long lmon_wake_jiffies;
	int lmon_wake_cnt;
	atomic_t *lmon_counters;
	u32 config_state;
	struct cass_link_attr lattr;
	u32 lstate;
	u32 prev_lstate;
	u32 lerr;
	u32 hstate;
	u32 link_down_origin;
	u32 link_restart_count;
	u32 link_restart_time_idx;
	time64_t link_restart_time_buf[CASS_SBL_LINK_RESTART_TIME_SIZE];
	spinlock_t pause_lock;
	u32 pause_type;
	bool tx_pause;
	bool rx_pause;
	time64_t start_time;
};
#endif
