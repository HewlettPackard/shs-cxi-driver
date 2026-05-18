// SPDX-License-Identifier: GPL-2.0
/*
 * Cassini LINK
 * Copyright 2022, 2024-2026 Hewlett Packard Enterprise Development LP
 */

#include <linux/kernel.h>
#include <linux/hpe/cxi/cxi.h>
#include <uapi/ethernet/cxi-abi.h>

#include "cass_core.h"
#include "cass_sbl.h"
#include "cass_sl.h"
#include "cxi_internal.h"

static const struct cxi_link_ops cxi_link_ops_sbl = {
	.init = cass_sbl_init,
	.link_start = cass_sbl_link_start,
	.link_fini = cass_sbl_link_fini,
	.mode_get  = cass_sbl_mode_get,
	.mode_set  = cass_sbl_mode_set,
	.flags_get = cass_sbl_get_debug_flags,
	.flags_set = cass_sbl_set_debug_flags,
	.link_up   = cass_sbl_power_on,
	.link_down = cass_sbl_power_off,
	.is_pcs_aligned = cass_sbl_pml_pcs_aligned,
	.media_config = cass_sbl_media_config,
	.media_unconfig = cass_sbl_media_unconfig,
	.link_config  = cass_sbl_link_config,
	.link_reset = cass_sbl_reset,
	.link_exit = cass_sbl_exit,
	.pml_recovery_set = cass_sbl_pml_recovery_set,
	.is_link_up = cass_sbl_is_link_up,
	.eth_name_set = cass_sbl_set_eth_name,
};

static const struct cxi_link_ops cxi_link_ops_sl = {
	.init               = cass_sl_init,
	.link_start         = cass_sbl_link_start, /* TODO - temporary */
	.link_fini          = cass_sl_link_fini,
	.mode_get           = cass_sl_mode_get,
	.mode_set           = cass_sl_mode_set,
	.flags_get          = cass_sl_flags_get,
	.flags_set          = cass_sl_flags_set,
	.link_up            = cass_sl_link_up,
	.link_down          = cass_sl_link_down,
	.is_pcs_aligned     = cass_sl_is_pcs_aligned,
	.media_config       = cass_sl_media_config,
	.media_unconfig     = cass_sl_media_unconfig,
	.link_config        = cass_sl_link_config,
	.link_reset         = cass_sl_link_down,
	.link_exit          = cass_sl_exit,
	.pml_recovery_set   = cass_sl_pml_recovery_set,
	.is_link_up	    = cass_sl_is_link_up,
	.eth_name_set	    = cass_sl_connect_id_set,
};

void cxi_set_link_ops(struct cass_dev *hw)
{
	if (cass_version(hw, CASSINI_1))
		hw->link_ops = &cxi_link_ops_sbl;
	else
		hw->link_ops = &cxi_link_ops_sl;
}

void cxi_link_mode_get(struct cxi_dev *cxi_dev, struct cxi_link_info *link_info)
{
	struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cdev);

	hw->link_ops->mode_get(hw, link_info);
}
EXPORT_SYMBOL(cxi_link_mode_get);

void cxi_link_mode_set(struct cxi_dev *cxi_dev, const struct cxi_link_info *link_info)
{
	struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cdev);

	hw->link_ops->mode_set(hw, link_info);
}
EXPORT_SYMBOL(cxi_link_mode_set);

void cxi_link_flags_get(struct cxi_dev *cxi_dev, u32 *flags)
{
	struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cdev);

	hw->link_ops->flags_get(hw, flags);
}
EXPORT_SYMBOL(cxi_link_flags_get);

void cxi_link_flags_set(struct cxi_dev *cxi_dev, u32 clr_flags, u32 set_flags)
{
	struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cdev);

	hw->link_ops->flags_set(hw, clr_flags, set_flags);
}
EXPORT_SYMBOL(cxi_link_flags_set);

void cxi_link_use_unsupported_cable(struct cxi_dev *cxi_dev, bool use)
{
	struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cdev);

	cxidev_dbg(&hw->cdev, "use unsupported cable\n");

	if (use)
		hw->sl.link_policy.options |= SL_LINK_POLICY_OPT_USE_UNSUPPORTED_CABLE;
	else
		hw->sl.link_policy.options &= ~SL_LINK_POLICY_OPT_USE_UNSUPPORTED_CABLE;
}
EXPORT_SYMBOL(cxi_link_use_unsupported_cable);

void cxi_link_use_supported_ss200_cable(struct cxi_dev *cxi_dev, bool use)
{
        struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cdev);

        cxidev_dbg(&hw->cdev, "use supported ss200 cable\n");

        if (use)
                hw->sl.link_policy.options |= SL_LINK_POLICY_OPT_USE_SUPPORTED_SS200_CABLE;
        else
                hw->sl.link_policy.options &= ~SL_LINK_POLICY_OPT_USE_SUPPORTED_SS200_CABLE;
}
EXPORT_SYMBOL(cxi_link_use_supported_ss200_cable);

void cxi_link_ignore_media_error(struct cxi_dev *cxi_dev, bool ignore)
{
        struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cdev);

        cxidev_dbg(&hw->cdev, "ignore media error\n");

        if (ignore)
                hw->sl.link_policy.options |= SL_LINK_POLICY_OPT_IGNORE_MEDIA_ERROR;
        else
                hw->sl.link_policy.options &= ~SL_LINK_POLICY_OPT_IGNORE_MEDIA_ERROR;
}
EXPORT_SYMBOL(cxi_link_ignore_media_error);

void cxi_pml_recovery_set(struct cxi_dev *cxi_dev, bool set)
{
	struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cdev);

	hw->link_ops->pml_recovery_set(hw, set);
}
EXPORT_SYMBOL(cxi_pml_recovery_set);

void cxi_link_los_lol_hide(struct cxi_dev *cxi_dev, bool enable)
{
       struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cdev);

       cxidev_dbg(&hw->cdev, "los_lol_hide\n");

       if (enable)
               hw->sl.link_config.options |= SL_LINK_CONFIG_OPT_LOS_LOL_UP_FAIL_HIDE;
       else
               hw->sl.link_config.options &= ~SL_LINK_CONFIG_OPT_LOS_LOL_UP_FAIL_HIDE;
}
EXPORT_SYMBOL(cxi_link_los_lol_hide);

/**
 * cxi_link_state_get_vf() - Query the PF for the current link state (VF)
 *
 * @cdev: VF CXI device
 * @up: set to true if the link is up, false otherwise
 *
 * Return: 0 on success, negative error code on failure.
 */
static int cxi_link_state_get_vf(struct cxi_dev *cdev, bool *up)
{
	const struct cxi_eth_link_state_get_cmd cmd = {
		.op = CXI_OP_ETH_LINK_STATE_GET,
	};
	struct cxi_eth_get_link_state_resp resp = {};
	size_t resp_len = sizeof(resp);
	int rc;

	rc = cxi_send_msg_to_pf(cdev, &cmd, sizeof(cmd), &resp, &resp_len);
	if (rc) {
		cxidev_warn(cdev, "failed to query link state from PF: %d\n", rc);
		return rc;
	}

	*up = resp.link_up;

	return 0;
}

/**
 * cxi_link_state_get() - Query the current link state
 *
 * @cdev: the device
 * @up: set to true if the link is up, false otherwise
 *
 * Return: 0 on success, negative error code on failure.
 */
int cxi_link_state_get(struct cxi_dev *cdev, bool *up)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);

	if (!cdev->is_physfn)
		return cxi_link_state_get_vf(cdev, up);

	*up = hw->link_ops->is_link_up(hw);

	return 0;
}
EXPORT_SYMBOL(cxi_link_state_get);

/**
 * cxi_link_state_get_internal() - Query the current link state
 *
 * When @vf_en is true, applies the per-VF link-state override (set via
 * ndo_set_vf_link_state) on top of the physical link state.
 *
 * @cdev: the device
 * @up: set to true if the (effective) link is up, false otherwise
 * @vf_en: true if a per-VF override should be considered
 * @vf_num: VF index (0-based); ignored when @vf_en is false
 *
 * Return: 0 on success, negative error code on failure.
 */
int cxi_link_state_get_internal(struct cxi_dev *cdev, bool *up,
				bool vf_en, u8 vf_num)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	u32 link_state;
	int rc;

	rc = cxi_link_state_get(cdev, up);
	if (rc || !vf_en)
		return rc;

	mutex_lock(&hw->rmu_eth_lock);
	link_state = hw->vf_eth_cfg[vf_num].link_state;
	mutex_unlock(&hw->rmu_eth_lock);

	if (link_state == IFLA_VF_LINK_STATE_ENABLE)
		*up = true;
	else if (link_state == IFLA_VF_LINK_STATE_DISABLE)
		*up = false;

	return 0;
}
EXPORT_SYMBOL(cxi_link_state_get_internal);

/**
 * cxi_notify_vfs_link_event() - Forward a link-state event to connected VFs
 *
 * @cdev: the PF device
 * @event: CXI_EVENT_LINK_UP or CXI_EVENT_LINK_DOWN
 *
 * Skips VFs whose effective link state is fixed by a non-AUTO override, since
 * their carrier state is unaffected by physical link changes.
 */
int cxi_notify_vfs_link_event(struct cxi_dev *cdev, enum cxi_async_event event)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int i;
	int rc;
	int first_error = 0;

	if (!cdev->is_physfn)
		return -EINVAL;

	for (i = 0; i < hw->num_vfs; i++) {
		u32 override;

		mutex_lock(&hw->rmu_eth_lock);
		override = hw->vf_eth_cfg[i].link_state;
		mutex_unlock(&hw->rmu_eth_lock);

		if (override != IFLA_VF_LINK_STATE_AUTO)
			continue;

		rc = cxi_notify_vf_async_event(cdev, i, event);
		if (rc && !first_error)
			first_error = rc;
	}

	return first_error;
}
EXPORT_SYMBOL(cxi_notify_vfs_link_event);
