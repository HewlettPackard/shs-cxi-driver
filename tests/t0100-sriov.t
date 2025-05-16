#!/bin/bash

# Add and remove VFs, and check that the devices have been created in
# /sys/class/cxi/. The PF is always present in /sys/class/cxi/, while
# the VFs will come and go.

. ./preamble.sh

test_description="Basic tests for cxi-ss1"

. ./sharness.sh

# Originally, only the PF device is present, so it should be cxi0
PFDEV=/sys/class/cxi/cxi0/device

# The first VF should be cxi1
VFDEV=/sys/class/cxi/cxi1/device

# Expected number of VFs the device supports
# TODO this should be 64. qemu crashes with more.
TOTALVFS=6

# Check the number of cxi device is correct
# Arg 1 is the number of expected cxi device
function check_cxi {
	NCXI=$(ls /sys/class/cxi/ | wc -w)
	[[ $NCXI -eq $1 ]]
}

# Create a given number of VFs
function create_vfs {
	echo $1 > $PFDEV/sriov_numvfs &&
	[[ $(cat $PFDEV/sriov_numvfs) -eq $1 ]]
}

test_expect_success "Inserting driver" "
	insmod ../../../../slingshot_base_link/cxi-sbl.ko &&
	insmod ../../../../sl-driver/knl/cxi-sl.ko &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-ss1.ko &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-user.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

#test_expect_success "Number of total VFs" "
#	[[ $(cat $PFDEV/sriov_totalvfs) -eq $TOTALVFS ]]
#"

test_expect_success "No VFs at first" "
	[[ $(cat $PFDEV/sriov_numvfs) -eq 0 ]] && check_cxi 1
"

test_expect_success "Create VFs" "
    create_vfs $((TOTALVFS / 3)) && check_cxi $((TOTALVFS / 3 + 1))
    [[ $(cat $PFDEV/properties/rdzv_get_idx) -eq $(cat $PFDEV/properties/rdzv_get_idx) ]]
"

test_expect_success "Can't change the number of VFs" "
    ! create_vfs $((TOTALVFS / 3 + 1))
"

test_expect_success "Remove existing VFs" "
	echo 0 > $PFDEV/sriov_numvfs
	[[ $(cat $PFDEV/sriov_numvfs) -ne 0 ]] && check_cxi 1
"

#test_expect_success "Create the maximum number of VFs" "
#	create_vfs $TOTALVFS && check_cxi $((TOTALVFS + 1))
#"

# test-vfpfcomm is now competing with cxi-user for the message channel
#test_expect_success "Inserting VF/PF comm test driver" "
#	insmod ../../../cxi/tests/test-vfpfcomm.ko &&
#	sleep 4 &&
#	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
#"

#test_expect_success "Check VF/PF comm" "
#	[ $(dmesg | grep -c 'Reply is valid') -eq $TOTALVFS ]
#"

#test_expect_success "Remove VF/PF comm test driver" "
#	rmmod test-vfpfcomm &&
#	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
#"

test_expect_success "Remove existing VFs" "
	create_vfs 0 && check_cxi 1
"

#test_expect_success "Try to create more VFs than allowed" "
#	! create_vfs $((TOTALVFS + 1)) && check_cxi 1
#"

#test_expect_success "Create some VFs and remove the driver" "
#	create_vfs $((TOTALVFS / 2)) && check_cxi $((TOTALVFS / 2 + 1)) &&
#	rmmod cxi-user cxi-ss1 cxi-sbl &&
#	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ] &&
#	[[ ! -d /sys/module/cxi-user ]] &&
#	[[ ! -d /sys/module/cxi-ss1 ]] &&
#	[[ ! -d /sys/module/cxi-sbl ]] &&
#	[[ ! -d /sys/class/cxi ]]
#"

test_expect_success "No Oops" "
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

dmesg > ../$(basename "$0").dmesg.txt

test_done
