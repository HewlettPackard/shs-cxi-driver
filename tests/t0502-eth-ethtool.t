#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Comprehensive ethtool coverage for the cxi-eth driver on both the SR-IOV PF
# and a VF. Every reachable ethtool option that maps to cxi_eth_ethtool_ops is
# exercised via shared helpers so the PF and VF run the identical battery.
#
# Expected-results matrix. The ethtool ops table is shared, but PF-only
# operations that touch the physical link, PHY, transceiver or firmware are
# gated on is_physfn and return EOPNOTSUPP on a VF: the physical port is owned
# by the PF, so a VF must not query or reconfigure it.
#
#   ethtool option              callback                 PF result            VF result
#   --------------------------  -----------------------  -------------------  -----------------
#   -i                          cxi_get_drvinfo          OK (cxi_eth)         OK (cxi_eth)
#   -S                          cxi_get_ethtool_stats    OK                   OK
#   -k (netdev core)            n/a                      OK                   OK
#   -a / --show-pause           cxi_get_pauseparam       OK                   OK
#   -g / --show-ring            cxi_get_ringparam        OK                   OK
#   -l / --show-channels        cxi_get_channels         OK                   OK
#   -T / --show-time-stamping   cxi_get_ts_info          OK                   OK
#   --show-priv-flags           cxi_get_priv_flags       OK, lists roce-opt   OK, all off
#   -x / --show-rxfh            cxi_get_rxfh             OK                   OK
#   --set-fec                   cxi_set_fecparam         REJECTED (ENOTSUPP)  REJECTED
#   -L combined N               cxi_set_channels         REJECTED (EINVAL)    REJECTED (EINVAL)
#   -A autoneg on               cxi_set_pauseparam       REJECTED (EINVAL)    REJECTED (EINVAL)
#   -G rx-jumbo N               cxi_set_ringparam        REJECTED (EINVAL)    REJECTED (EINVAL)
#   <no opt> (link ksettings)   cxi_get_link_ksettings   OK                   EOPNOTSUPP (CLI ok*)
#   -s autoneg on               cxi_set_link_ksettings   OK (PHY bounce)      EOPNOTSUPP
#   -s duplex half              cxi_set_link_ksettings   REJECTED (ENOTSUPP)  EOPNOTSUPP
#   --set-priv-flags roce-opt   cxi_set_priv_flags       OK, toggles          EOPNOTSUPP
#   --set-priv-flags 2x lpbk    cxi_set_priv_flags       REJECTED (EINVAL)    EOPNOTSUPP
#   -p / --identify             cxi_set_phys_id          OK (LED beacon)      EOPNOTSUPP
#   -m / --module-info          cxi_get_module_info      MEDIA-DEPENDENT      EOPNOTSUPP
#   --show-fec                  cxi_get_fecparam         FEATURE-DEPENDENT    EOPNOTSUPP
#
# * get_link_ksettings returns EOPNOTSUPP on a VF, but `ethtool <if>` still
#   exits 0 by falling back to get_link, so only the setter path is asserted.

. ./preamble.sh

test_description="ethtool full option coverage on cxi-eth PF and VF"

. ./sharness.sh

CXI_DIR=$(realpath "$(dirname "$0")/..")
VF_SCRIPT="$CXI_DIR/scripts/cxi_vf.sh"

PFDEV=/sys/class/cxi/cxi0
NUM_VFS=2

PF_IF=
VF_IF=

VF_PARENT_SVC_ID=
VF_PARENT_SVC_YAML=/tmp/cxi-ethtool-all-parent.yaml

# ---------------------------------------------------------------------------
# ethtool helpers (take an interface name; return 0 on the expected result)
# ---------------------------------------------------------------------------

# Retry a command up to $1 times (short settle between tries). On the PF,
# link-touching ethtool ops can transiently fail while the SL/PML layer is
# busy from a preceding op; retrying makes the functional check deterministic.
retry() {
	local n="$1"; shift
	local i
	for ((i = 0; i < n; i++)); do
		"$@" && return 0
		sleep 0.2
	done
	return 1
}

# Poll --show-priv-flags until flag $2 reads value $3 (on/off) on iface $1,
# tolerating transient empty/error output right after a set.
wait_privflag() {
	local ifc="$1" flag="$2" want="$3" i
	for ((i = 0; i < 50; i++)); do
		[[ $(ethtool --show-priv-flags "$ifc" 2>/dev/null |
			grep -c "$flag"'\s*: '"$want") -eq 1 ]] && return 0
		sleep 0.1
	done
	return 1
}

# Positive queries: must succeed.
et_driver()   { ethtool -i "$1" | grep -q '^driver: cxi_eth$'; }
et_link()     { ethtool "$1" >/dev/null; }
et_stats()    { ethtool -S "$1" >/dev/null; }
et_features() { ethtool -k "$1" >/dev/null; }
et_pause()    { ethtool -a "$1" >/dev/null; }
et_ring()     { ethtool -g "$1" >/dev/null; }
et_channels() { ethtool -l "$1" >/dev/null; }
et_tsinfo()   { ethtool -T "$1" >/dev/null; }
et_identify() { retry 10 ethtool -p "$1" 1; }
et_privflags() { ethtool --show-priv-flags "$1" | grep -q 'roce-opt'; }

# Reversible state change: roce-opt off -> on -> off, verified each step.
# Sets are retried and readbacks are polled to absorb transient PF link-busy.
et_privtoggle() {
	local ifc="$1"

	wait_privflag "$ifc" roce-opt off &&
	retry 10 ethtool --set-priv-flags "$ifc" roce-opt on &&
	wait_privflag "$ifc" roce-opt on &&
	retry 10 ethtool --set-priv-flags "$ifc" roce-opt off &&
	wait_privflag "$ifc" roce-opt off
}

# Negative cases: the driver must reject these (helper returns 0 when rejected).
et_fec_set_neg()    { ! ethtool --set-fec "$1" encoding rs; }
et_link_dup_neg()   { ! ethtool -s "$1" speed 10000 duplex half autoneg off; }
et_channels_neg()   { ! ethtool -L "$1" combined 1; }
et_pause_neg()      { ! ethtool -A "$1" autoneg on; }
et_ring_jumbo_neg() { ! ethtool -G "$1" rx-jumbo 8; }
et_loopback_excl()  { ! ethtool --set-priv-flags "$1" internal-loopback on external-loopback on; }

# Feature/media-dependent: exercise the code path without asserting an outcome
# (netsim has no optics and may be single-RSS-queue). The final No-Oops check
# guards against a crash in these paths.
et_module()   { ethtool -m "$1" >/dev/null 2>&1 || true; }
et_rxfh()     { ethtool -x "$1" >/dev/null 2>&1 || true; }
et_fec_show() { ethtool --show-fec "$1" >/dev/null 2>&1 || true; }

# VF negatives: PF-only link/PHY/transceiver/firmware ops must be refused on a
# VF (helper returns 0 when the op is rejected). et_link_autoneg_neg is the
# reproducer for the VF kdump: on the PF it would bounce the PHY, on a VF it
# must fail cleanly with EOPNOTSUPP before touching the (uninitialized) link.
et_link_autoneg_neg() { ! ethtool -s "$1" autoneg on; }
et_privtoggle_neg()   { ! ethtool --set-priv-flags "$1" roce-opt on; }
et_identify_neg()     { ! ethtool -p "$1" 1; }
et_module_neg()       { ! ethtool -m "$1" >/dev/null 2>&1; }
et_fec_show_neg()     { ! ethtool --show-fec "$1" >/dev/null 2>&1; }

# Emit the full ethtool battery for one interface.
# $1 interface, $2 tag (PF/VF), $3 sharness prereq ("" for PF, SRIOV for VF),
# $4 mode ("pf" or "vf"): selects PF-owns-link vs VF-forbidden expectations.
emit_suite() {
	local ifc="$1" tag="$2" pre="$3" mode="$4"

	# --- Ops that behave identically on PF and VF ---

	# Positive queries.
	test_expect_success $pre "$tag -i: driver == cxi_eth"            "et_driver '$ifc'"
	test_expect_success $pre "$tag -S: statistics readable"          "et_stats '$ifc'"
	test_expect_success $pre "$tag -k: offload features readable"    "et_features '$ifc'"
	test_expect_success $pre "$tag -a: pause params readable"        "et_pause '$ifc'"
	test_expect_success $pre "$tag -g: ring params readable"         "et_ring '$ifc'"
	test_expect_success $pre "$tag -l: channels readable"            "et_channels '$ifc'"
	test_expect_success $pre "$tag -T: timestamp info readable"      "et_tsinfo '$ifc'"
	test_expect_success $pre "$tag --show-priv-flags lists roce-opt" "et_privflags '$ifc'"
	test_expect_success $pre "$tag -x RSS table (feature-dependent)" "et_rxfh '$ifc'"

	# Negative on both function types (rejected before any is_physfn gate).
	test_expect_success $pre "$tag --set-fec rejected (ENOTSUPP)"    "et_fec_set_neg '$ifc'"
	test_expect_success $pre "$tag -L combined rejected (EINVAL)"    "et_channels_neg '$ifc'"
	test_expect_success $pre "$tag -A autoneg on rejected (EINVAL)"  "et_pause_neg '$ifc'"
	test_expect_success $pre "$tag -G rx-jumbo rejected (EINVAL)"    "et_ring_jumbo_neg '$ifc'"

	if [[ "$mode" == pf ]]; then
		# --- PF owns the physical link/PHY/transceiver/firmware ---
		test_expect_success $pre "$tag (no opt): link settings readable"   "et_link '$ifc'"
		test_expect_success $pre "$tag --set-priv-flags roce-opt on/off"   "et_privtoggle '$ifc'"
		test_expect_success $pre "$tag -s duplex half rejected (ENOTSUPP)" "et_link_dup_neg '$ifc'"
		test_expect_success $pre "$tag loopback flags mutually exclusive"  "et_loopback_excl '$ifc'"
		test_expect_success $pre "$tag -m optics EEPROM (media-dependent)" "et_module '$ifc'"
		test_expect_success $pre "$tag --show-fec (feature-dependent)"     "et_fec_show '$ifc'"

		# LED identify runs last: on the PF it drives PML/LED hardware and
		# can briefly perturb a following get_priv_flags read, so keep it
		# after the priv-flag checks.
		test_expect_success $pre "$tag -p 1: identify (LED) accepted"      "et_identify '$ifc'"
	else
		# --- VF must not touch PF-owned state: EOPNOTSUPP ---
		# get_link_ksettings is gated too, but `ethtool <if>` still exits 0
		# by falling back to get_link, so assert the setter path instead.
		test_expect_success $pre "$tag -s autoneg on not supported"        "et_link_autoneg_neg '$ifc'"
		test_expect_success $pre "$tag --set-priv-flags not supported"     "et_privtoggle_neg '$ifc'"
		test_expect_success $pre "$tag -p identify not supported"          "et_identify_neg '$ifc'"
		test_expect_success $pre "$tag -m module info not supported"       "et_module_neg '$ifc'"
		test_expect_success $pre "$tag --show-fec not supported"           "et_fec_show_neg '$ifc'"
	fi
}

# ---------------------------------------------------------------------------
# Interface discovery and VF provisioning helpers
# ---------------------------------------------------------------------------

# Resolve the single netdev under a sysfs net directory, waiting for its name
# to stabilize. udev may rename the interface (e.g. eth0 -> ethN) 1-2s after the
# driver creates it; caching the transient name would leave later ethtool ops
# pointing at a name that no longer exists. Return the name once it has been
# unchanged for ~1s. Echoes the stable name on stdout.
function wait_stable_iface {
	local dir="$1" cur prev="" stable=0 i
	for ((i = 0; i < 200; i++)); do
		cur=$(find "$dir" -mindepth 1 -maxdepth 1 -type d \
			-printf '%f\n' 2>/dev/null | head -1)
		if [[ -n "$cur" && "$cur" == "$prev" ]]; then
			((stable++))
			[[ $stable -ge 10 ]] && { echo "$cur"; return 0; }
		else
			stable=0
		fi
		prev=$cur
		sleep 0.1
	done
	[[ -n "$cur" ]] && { echo "$cur"; return 0; }
	return 1
}

function find_pf_iface {
	udevadm settle 2>/dev/null || true
	PF_IF=$(wait_stable_iface "$PFDEV/device/net") && [[ -n "$PF_IF" ]]
}

# Wait until the link layer is ready enough for link-dependent ethtool ops.
# Right after cxi-eth loads, get_priv_flags/set_phys_id can transiently fail
# until the SL layer initializes. Poll --show-priv-flags until it succeeds.
function wait_eth_ready {
	local ifc="$1" i
	for ((i = 0; i < 100; i++)); do
		ethtool --show-priv-flags "$ifc" 2>/dev/null | grep -q 'roce-opt' &&
			return 0
		sleep 0.1
	done
	return 1
}

# Remove all VFs and confirm the count returns to zero (removal is async).
function remove_vfs {
	echo 0 > "$PFDEV/device/sriov_numvfs" || return 1
	local i
	for ((i = 0; i < 50; i++)); do
		[[ $(cat "$PFDEV/device/sriov_numvfs") -eq 0 ]] && return 0
		sleep 0.1
	done
	return 1
}

function find_vf_iface {
	udevadm settle 2>/dev/null || true
	VF_IF=$(wait_stable_iface "$PFDEV/device/virtfn0/net") && [[ -n "$VF_IF" ]]
}


function create_vfs {
	cd $CXI_DIR/scripts &&
	$VF_SCRIPT setup $NUM_VFS &&
	[[ $(cat "$PFDEV/device/sriov_numvfs") -eq $NUM_VFS ]]
}

# ---------------------------------------------------------------------------
# Test flow
# ---------------------------------------------------------------------------

test_expect_success "Inserting driver stack" "
	insmod ../../../../slingshot_base_link/drivers/net/ethernet/hpe/sbl/cxi-sbl.ko &&
	insmod ../../../../sl-driver/drivers/net/ethernet/hpe/sl/cxi-sl.ko &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-ss1.ko &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-user.ko &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-eth.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

# --- PF battery (always run) ---

test_expect_success "Locate PF ethernet interface" "
	find_pf_iface && [[ -n \"\$PF_IF\" ]]
"

test_expect_success "PF link layer ready for ethtool" "
	wait_eth_ready \$PF_IF
"

emit_suite "$PF_IF" "PF" "" pf

# --- VF battery (only when SR-IOV is supported) ---

if [[ $(cat "$PFDEV/device/sriov_totalvfs" 2>/dev/null || echo 0) -gt 0 ]]; then
	test_set_prereq SRIOV
else
	echo "Driver built without SR-IOV support, skipping VF ethtool tests"
fi

test_expect_success SRIOV "Create VFs" "
	create_vfs
"

test_expect_success SRIOV "Locate VF ethernet interface" "
	find_vf_iface && [[ -n \"\$VF_IF\" ]]
"

test_expect_success SRIOV "VF link layer ready for ethtool" "
	wait_eth_ready \$VF_IF
"

emit_suite "$VF_IF" "VF" "SRIOV" vf

test_expect_success SRIOV "PF and VF report the same ethtool driver" "
	[[ \$(ethtool -i \$PF_IF | sed -n 's/^driver: //p') == \
	   \$(ethtool -i \$VF_IF | sed -n 's/^driver: //p') ]]
"

test_expect_success SRIOV "Remove VFs" "
	remove_vfs
"

test_expect_success "module removal" "
	rmmod cxi-eth cxi-user cxi-ss1 cxi-sl cxi-sbl &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "No Oops" "
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

dmesg > ../$(basename "$0").dmesg.txt

test_done
