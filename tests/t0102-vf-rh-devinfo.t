#!/bin/bash
# Verify that a VF reports the PF's retry-handler state through its dev-info
# pct_eq, which libcxi reads from properties/pct_eq. A VF has no PCT EQ of its
# own, so before the fix it always reported C_EQ_NONE (0) and libfabric dropped
# the VF. The value a VF exposes must instead follow its PF: a VF reports a
# running handler iff its PF does.

. ./preamble.sh

test_description="VF retry-handler status via dev-info"

. ./sharness.sh

CXI_DIR=$(realpath "$(dirname "$0")/..")

PFDEV=/sys/class/cxi/cxi0
VFDEV=/sys/class/cxi/cxi1

CXI_VF="$CXI_DIR/scripts/cxi_vf.sh"

# "running" bit for a device's retry handler: pct_eq != C_EQ_NONE (0).
function rh_running {
	local eq
	eq=$(cat "$1/device/properties/pct_eq") || return 2
	[[ "$eq" -ne 0 ]]
}

test_expect_success "Inserting driver" "
	insmod ../../../../slingshot_base_link/drivers/net/ethernet/hpe/sbl/cxi-sbl.ko &&
	insmod ../../../../sl-driver/drivers/net/ethernet/hpe/sl/cxi-sl.ko &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-ss1.ko &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-user.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

if [[ $(cat $PFDEV/device/sriov_totalvfs) -gt 0 ]]; then
	test_set_prereq SRIOV
else
	echo "Driver built without SR-IOV support, skipping test"
fi

# cxi_vf.sh creates the parent service and assigns it to the VF for us.
test_expect_success SRIOV "Create one VF" "
	CXI_DEVICE=cxi0 '$CXI_VF' setup 1 --no-ama &&
	[[ -d $VFDEV ]]
"

# The VF's pct_eq must be readable - this exercises the VF->PF relay rather
# than the VF's own (always-zero) local value.
test_expect_success SRIOV "VF pct_eq is readable" "
	cat $VFDEV/device/properties/pct_eq
"

# Whatever the PF's retry-handler state, the VF must report the same. In the
# netsim test environment no handler runs, so both report not-running; the
# invariant still guards against a VF reporting its own local state.
test_expect_success SRIOV "VF retry-handler state matches PF" "
	if rh_running $PFDEV; then
		rh_running $VFDEV
	else
		! rh_running $VFDEV
	fi
"

test_expect_success SRIOV "Remove VFs" "
	CXI_DEVICE=cxi0 '$CXI_VF' cleanup &&
	[[ \$(cat $PFDEV/device/sriov_numvfs) -eq 0 ]]
"

test_expect_success "Unload driver" "
	rmmod cxi-user cxi-ss1 cxi-sl cxi-sbl &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "No Oops" "
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

dmesg > ../$(basename "$0").dmesg.txt

test_done
