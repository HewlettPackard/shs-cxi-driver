#!/bin/sh

# Setup script run inside a VF VM (used by start_vm.sh).
# Sources the common setup and additionally loads cxi-eth for networking.

. ./startvm-setup.sh

insmod ../drivers/net/ethernet/hpe/ss1/cxi-eth.ko
