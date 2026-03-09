#!/bin/sh

# Setup script run in the VM, used by the testit.sh script.

modprobe configfs
mount -t configfs none /sys/kernel/config
modprobe ptp
insmod ../../slingshot_base_link/drivers/net/ethernet/hpe/sbl/cxi-sbl.ko
insmod ../../sl-driver/drivers/net/ethernet/hpe/sl/cxi-sl.ko
insmod ../drivers/net/ethernet/hpe/ss1/cxi-ss1.ko disable_default_svc=0
insmod ../drivers/net/ethernet/hpe/ss1/cxi-user.ko
