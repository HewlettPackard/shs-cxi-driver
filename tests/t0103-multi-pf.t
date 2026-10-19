#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright 2026 Hewlett Packard Enterprise Development LP

export NETSIM_NICS=2
VM_NETSIM_ARGS=(-N 2)

. ./preamble.sh

test_description="Shared SR-IOV listener and EQ proof across multiple PFs"

. ./sharness.sh

CXI_DIR=$(realpath "$(dirname "$0")/..")
SVC_TOOL="$CXI_DIR/tests/svc_tool/svc_tool"
PF0=/sys/class/cxi/cxi0
PF1=/sys/class/cxi/cxi1

function prepare_pf {
	local pf=$1 count=$2 nid=$3 svc vf

	echo "$nid" > "$pf/device/properties/nid" &&
	svc=$("$SVC_TOOL" sriov "$(basename "$pf")") || return 1
	for ((vf = 0; vf < count; vf++)); do
		echo "$svc" > "$pf/vf/$vf/svc_id" || return 1
	done
}

function vf_device {
	local pci=$1 dev

	for dev in /sys/class/cxi/*; do
		if [[ $(realpath "$dev/device") == "$pci" ]]; then
			echo "$dev"
			return 0
		fi
	done
	echo "No CXI device for VF $pci" >&2
	return 1
}

function check_vfs {
	local pf=$1 count=$2 vf pci dev nid expected

	[[ $(cat "$pf/device/sriov_numvfs") -eq $count ]] || return 1
	expected=$(cat "$pf/device/properties/nid") || return 1
	for ((vf = 0; vf < count; vf++)); do
		pci=$(realpath "$pf/device/virtfn$vf") &&
		dev=$(vf_device "$pci") &&
		nid=$(cat "$dev/device/properties/nid") &&
		[[ $((nid & 0xfffff)) -eq $((expected)) &&
		   $((nid >> 20)) -eq $((vf + 1)) ]] &&
		cat "$dev/device/properties/pct_eq" || return 1
	done
}

function rebind_vf {
	local pci

	pci=$(realpath "$PF1/device/virtfn0") || return 1
	echo "${pci##*/}" > "$pci/driver/unbind" &&
	echo "${pci##*/}" > "$PF1/device/driver/bind"
}

test_expect_success "Inserting drivers for two PFs" "
	insmod ../../../../slingshot_base_link/drivers/net/ethernet/hpe/sbl/cxi-sbl.ko &&
	insmod ../../../../sl-driver/drivers/net/ethernet/hpe/sl/cxi-sl.ko &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-ss1.ko &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-user.ko &&
	[[ -d $PF0 && -d $PF1 ]]
"

if [[ -r $PF0/device/sriov_totalvfs &&
      -r $PF1/device/sriov_totalvfs ]] &&
   [[ $(cat "$PF0/device/sriov_totalvfs") -ge 2 &&
      $(cat "$PF1/device/sriov_totalvfs") -ge 3 ]]; then
	test_set_prereq SRIOV
fi

test_expect_success SRIOV "Assign distinct PF identities and parent services" "
	prepare_pf $PF0 2 17 &&
	prepare_pf $PF1 3 34
"

test_expect_success SRIOV "Connect the same local VF indices on both PFs" "
	echo 2 > $PF0/device/sriov_numvfs &&
	echo 2 > $PF1/device/sriov_numvfs &&
	check_vfs $PF0 2 &&
	check_vfs $PF1 2
"

test_expect_success SRIOV "Reconnect the second PF with unequal VF counts" "
	echo 0 > $PF1/device/sriov_numvfs &&
	echo 3 > $PF1/device/sriov_numvfs &&
	check_vfs $PF0 2 &&
	check_vfs $PF1 3
"

test_expect_success SRIOV "Reconnect a VF while both PFs remain registered" "
	rebind_vf &&
	check_vfs $PF0 2 &&
	check_vfs $PF1 3
"

test_expect_success SRIOV "Remove the first PF's VFs without disrupting the second" "
	echo 0 > $PF0/device/sriov_numvfs &&
	check_vfs $PF0 0 &&
	check_vfs $PF1 3
"

test_expect_success SRIOV "Re-register the first PF after the second PF" "
	echo 2 > $PF0/device/sriov_numvfs &&
	check_vfs $PF0 2 &&
	check_vfs $PF1 3
"

test_expect_success SRIOV "Stop the last listener and start it again" "
	echo 0 > $PF0/device/sriov_numvfs &&
	echo 0 > $PF1/device/sriov_numvfs &&
	echo 3 > $PF1/device/sriov_numvfs &&
	check_vfs $PF1 3 &&
	echo 0 > $PF1/device/sriov_numvfs
"

test_expect_success "Unload drivers without an Oops" "
	rmmod cxi-user cxi-ss1 cxi-sl cxi-sbl &&
	! dmesg | grep -E 'BUG:|WARNING:|Oops:|Modules linked in'
"

dmesg > ../$(basename "$0").dmesg.txt

test_done
