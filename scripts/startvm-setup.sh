#!/bin/sh

# Setup script run in the VM, used by the testit.sh script.

modprobe ptp
modprobe iommu_v2 >/dev/null 2>/dev/null || modprobe amd_iommu_v2 >/dev/null 2>/dev/null
insmod ../../slingshot_base_link/cxi-sbl.ko
insmod ../../sl-driver/knl/cxi-sl.ko
insmod ../cxi/cxi-ss1.ko disable_default_svc=0
insmod ../cxi/cxi-user.ko
