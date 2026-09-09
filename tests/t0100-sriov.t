#!/bin/bash

# Add and remove VFs, and check that the devices have been created in
# /sys/class/cxi/. The PF is always present in /sys/class/cxi/, while
# the VFs will come and go.

. ./preamble.sh

test_description="Basic tests for cxi-ss1"

. ./sharness.sh

CXI_DIR=$(realpath "$(dirname "$0")/..")

# Originally, only the PF device is present, so it should be cxi0
PFDEV=/sys/class/cxi/cxi0

# The first VF should be cxi1
VFDEV=/sys/class/cxi/cxi1

TOTALVFS=64

# Check the number of cxi device is correct
# Arg 1 is the number of expected cxi device
function check_cxi {
	NCXI=$(ls /sys/class/cxi/ | wc -w)
	[[ $NCXI -eq $1 ]]
}

# Create a given number of VFs
function create_vfs {
	echo $1 > $PFDEV/device/sriov_numvfs &&
	[[ $(cat $PFDEV/device/sriov_numvfs) -eq $1 ]]
}

VF_PARENT_SVC_ID=
SVC_TOOL="$CXI_DIR/tests/svc_tool/svc_tool"

function create_vf_parent_service {
	[[ -x "$SVC_TOOL" ]] || {
		echo "ERROR: svc_tool not found at $SVC_TOOL" >&5
		return 1
	}

	VF_PARENT_SVC_ID=$("$SVC_TOOL" sriov cxi0 2>&5) || {
		echo "failed to create parent service via svc_tool" >&5
		return 1
	}
	[[ -n "$VF_PARENT_SVC_ID" ]] || {
		echo "svc_tool returned empty svc_id" >&5
		return 1
	}

	local vf
	for ((vf = 0; vf < TOTALVFS; vf++)); do
		echo "$VF_PARENT_SVC_ID" > "$PFDEV/vf/$vf/svc_id" 2>&5 || { echo "failed to set svc_id $VF_PARENT_SVC_ID for VF $vf: $?" >&5; return 1; }
	done
}

function apply_ratelimits {
	local limit=$1
	local burst=$2

	for ((vf = 0; vf < TOTALVFS; vf++)); do
		echo "$limit" > "$PFDEV/vf/$vf/msg_rate_limit" 2>&5 || { echo "failed to set msg_rate_limit $limit for VF $vf: $?" >&5; return 1; }
		echo "$burst" > "$PFDEV/vf/$vf/msg_rate_burst" 2>&5 || { echo "failed to set msg_rate_burst $burst for VF $vf: $?" >&5; return 1; }
	done
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
	echo "Driver built without SR-IOV support, skipping SR-IOV tests"
fi

test_expect_success SRIOV "Number of total VFs" "
	[[ $(cat $PFDEV/device/sriov_totalvfs) -eq $TOTALVFS ]]
"

test_expect_success SRIOV "No VFs at first" "
	[[ $(cat $PFDEV/device/sriov_numvfs) -eq 0 ]] && check_cxi 1
"

test_expect_success SRIOV "Create parent service and assign it to all VFs" "
	create_vf_parent_service
"

test_expect_success SRIOV "Create VFs" "
    create_vfs $((TOTALVFS / 3)) && check_cxi $((TOTALVFS / 3 + 1)) &&
    [[ $(cat $PFDEV/device/properties/rdzv_get_idx) -eq $(cat $PFDEV/device/properties/rdzv_get_idx) ]]
"

test_expect_success SRIOV "Can't change the number of VFs" "
    ! create_vfs $((TOTALVFS / 3 + 1))
"

test_expect_success SRIOV "Remove existing VFs" "
	echo 0 > $PFDEV/device/sriov_numvfs && check_cxi 1
"

test_expect_success SRIOV "Create the maximum number of VFs" "
	create_vfs $TOTALVFS && check_cxi $((TOTALVFS + 1))
"

# test-vfpfcomm is now competing with cxi-user for the message channel
test_expect_success SRIOV "Inserting VF/PF comm test driver" "
    rmmod cxi_user &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/tests/test-vfpfcomm.ko &&
	apply_ratelimits 200 50 &&
	sleep 4 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success SRIOV "Check VF/PF comm" "
	[ $(dmesg | grep -c 'Message test: PASS') -eq $TOTALVFS ]
"

test_expect_success SRIOV "Check VF/PF ratelimit" "
	[ $(dmesg | grep -c 'Rate limit test: PASS') -eq $TOTALVFS ]
"

test_expect_success SRIOV "Remove VF/PF comm test drive, reinsert cxi-user" "
	rmmod test-vfpfcomm &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-user.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success SRIOV "Remove existing VFs" "
	create_vfs 0 && check_cxi 1
"

test_expect_success SRIOV "Try to create more VFs than allowed" "
	! create_vfs $((TOTALVFS + 1)) && check_cxi 1
"

test_expect_success SRIOV "Create some VFs and remove the driver" "
	create_vfs $((TOTALVFS / 2)) && check_cxi $((TOTALVFS / 2 + 1)) &&
	rmmod cxi-user cxi-ss1 cxi-sbl &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ] &&
	[[ ! -d /sys/module/cxi-user ]] &&
	[[ ! -d /sys/module/cxi-ss1 ]] &&
	[[ ! -d /sys/module/cxi-sbl ]] &&
	[[ ! -d /sys/class/cxi ]]
"

test_expect_success "No Oops" "
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

dmesg > ../$(basename "$0").dmesg.txt

test_done
