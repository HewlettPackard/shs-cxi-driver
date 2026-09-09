#!/bin/bash

# Test the ethtool private flags can be set and reset

. ./preamble.sh

test_description="Basic ethernet test"

. ./sharness.sh

test_expect_success "One device is present" "
	[ $(lspci -n | grep -c '17db:0501') -eq 1 ]
"

test_expect_success "Inserting driver" "
	modprobe ptp &&
	insmod ../../../../slingshot_base_link/drivers/net/ethernet/hpe/sbl/cxi-sbl.ko &&
	insmod ../../../../sl-driver/drivers/net/ethernet/hpe/sl/cxi-sl.ko &&
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-ss1.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Inserting CXI ethernet driver" "
	insmod ../../../drivers/net/ethernet/hpe/ss1/cxi-eth.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

sleep 0.5

# Find the eth device name
for f in /sys/class/net/*
do
    [[ -d "$f/device/cxi" ]] || continue

    ETH_INTF=$(basename "$f")
done

test_expect_success "eth interface exists" "
	[[ -v ETH_INTF ]]
"

# Driver exposes either the Cassini1 loopback names or the Cassini2 names.
LOOPBACK_1=$(ethtool --show-priv-flags "$ETH_INTF" 2>/dev/null |
	awk '/internal-loopback|loopback-serdes/ { print $1; exit }')
LOOPBACK_2=$(ethtool --show-priv-flags "$ETH_INTF" 2>/dev/null |
	awk '/external-loopback|loopback-media/ { print $1; exit }')
LOOPBACK_HOST=$(ethtool --show-priv-flags "$ETH_INTF" 2>/dev/null |
	awk '/loopback-host/ { print $1; exit }')

# For these modes, check they are off, turn them on, check, turn them
# off and check.
for i in "$LOOPBACK_1" "$LOOPBACK_2" "$LOOPBACK_HOST" "llr" "precoding" "ifg-hpc" "roce-opt"
do
    [ -n "$i" ] || continue
    set -- $i

    test_expect_success "testing whether $1 can be set" "
        [[ $(ethtool --show-priv-flags $ETH_INTF | grep -c $1'\s*: off') -eq 1 ]] &&
        ethtool --set-priv-flags $ETH_INTF $1 on
"

    test_expect_success "testing whether $1 can be reset" "
        [[ $(ethtool --show-priv-flags $ETH_INTF | grep -c $1'\s*: on') -eq 1 ]] &&
        ethtool --set-priv-flags $ETH_INTF $1 off
"

    test_expect_success "testing whether $1 mode is off" "
        [[ $(ethtool --show-priv-flags $ETH_INTF | grep -c $1'\s*: off') -eq 1 ]]
"

done

# Both loopback modes are exclusive on either hardware generation.
test_expect_success "testing whether the supported loopback modes are exclusive" "
        [ -n \"$LOOPBACK_1\" ] && [ -n \"$LOOPBACK_2\" ] &&
        ! ethtool --set-priv-flags $ETH_INTF $LOOPBACK_1 on $LOOPBACK_2 on
        if [ -n \"$LOOPBACK_HOST\" ]; then
                ! ethtool --set-priv-flags $ETH_INTF $LOOPBACK_1 on $LOOPBACK_HOST on ||
                ! ethtool --set-priv-flags $ETH_INTF $LOOPBACK_2 on $LOOPBACK_HOST on
        fi
"

test_expect_success "module removal" "
	rmmod cxi-eth cxi-ss1 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "No Oops" "
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

dmesg > ../$(basename "$0").dmesg.txt

test_done
