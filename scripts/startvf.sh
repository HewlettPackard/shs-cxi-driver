#!/bin/bash

# Start a VM bound to a VF.
#
# Environment variables CXI_DEVICE and CXI_VF control the PF device, and VF
# index to use. Defaults are cxi0 and 0.

DIR=$(dirname $(realpath "$0"))
cd $DIR

VM_INIT_SCRIPT=${VM_INIT_SCRIPT:='./startvm-setup.sh'}
CXI_DEVICE=${CXI_DEVICE:='cxi0'}
CXI_VF=${CXI_VF:=0}

. ../tests/framework.sh

# Load vsock modules on host for VF-PF communication
modprobe vsock 2>/dev/null || echo "Warning: Could not load vsock module" >&2
modprobe vhost_vsock 2>/dev/null || echo "Warning: Could not load vhost_vsock module" >&2

# -M q35 = Standard PC (Q35 + ICH9, 2009) (alias of pc-q35-2.10)
# MSI-X needs interrupt remapping enabled to fully work.
# w/ Intel IOMMU. Intremap on requires kernel-irqchip=off OR kernel-irqchip=split
QEMU_OPTS="--qemu-opts -machine q35,kernel-irqchip=split -global q35-pcihost.pci-hole64-size=40G -device intel-iommu,intremap=on,caching-mode=on $CCN_OPTS"

# Example to create a VM with 2 numa nodes with one cpu each
# QEMU_OPTS="$QEMU_OPTS -smp cpus=2 -object memory-backend-ram,size=512M,id=m0 -object memory-backend-ram,size=512M,id=m1 -numa node,memdev=m0,cpus=0,nodeid=0 -numa node,memdev=m1,cpus=1,nodeid=1"

# Example to add a VM with 9 numa nodes, including 7 without a cpu.
#QEMU_OPTS="$QEMU_OPTS -smp cpus=2
#	-object memory-backend-ram,size=1G,id=m0 -numa node,memdev=m0,cpus=0,nodeid=0
#	-object memory-backend-ram,size=128M,id=m1 -numa node,memdev=m1,nodeid=1
#	-object memory-backend-ram,size=128M,id=m2 -numa node,memdev=m2,nodeid=2
#	-object memory-backend-ram,size=128M,id=m3 -numa node,memdev=m3,nodeid=3
#	-object memory-backend-ram,size=128M,id=m4 -numa node,memdev=m4,nodeid=4
#	-object memory-backend-ram,size=128M,id=m5 -numa node,memdev=m5,nodeid=5
#	-object memory-backend-ram,size=128M,id=m6 -numa node,memdev=m6,cpus=1,nodeid=6
#	-object memory-backend-ram,size=128M,id=m7 -numa node,memdev=m7,nodeid=7
#	-object memory-backend-ram,size=128M,id=m8 -numa node,memdev=m8,nodeid=8"

KERN_OPTS="--kopt iommu=pt --kopt intel_iommu=on --kopt iomem=relaxed"
KERN_OPTS="$KERN_OPTS --kopt transparent_hugepage=never --kopt hugepagesz=1g --kopt default_hugepagesz=1g --kopt hugepages=1"

# For some reason the euler image needs a ton of RAM to boot
QEMU_OPTS="$QEMU_OPTS -m 10G"

# Make sure we have enough VFs to satisfy the request
if [ ! -d "/sys/class/cxi/${CXI_DEVICE}" ]; then
	echo "Error: Device ${CXI_DEVICE} not found" >&2
	exit 1
fi

if [ ! -f "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs" ]; then
	echo "Error: Device ${CXI_DEVICE} does not support SR-IOV" >&2
	echo "Ensure that an SR-IOV capable version of the driver is loaded" >&2
	exit 1
fi

NUM_VFS=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs")
if [[ $NUM_VFS -eq 0 ]]; then
	echo $(($CXI_VF + 1)) > "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs"
	NUM_VFS=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs")
fi
if [[ $NUM_VFS -le $CXI_VF ]]; then
	echo "Error: Requested VF $CXI_VF but only $NUM_VFS VFs available" >&2
	exit 1
fi

# Get VF info
PCIFN=$(basename $(readlink "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${CXI_VF}"))
VENDOR=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${CXI_VF}/vendor")
DEVICE=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${CXI_VF}/device")
if [ -d "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${CXI_VF}/driver" ]; then
	DRIVER=$(readlink -f "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${CXI_VF}/driver")
else
	DRIVER=""
fi

# Unbind VF from cxi core driver.
if [ ! -z "$DRIVER" ]; then
	if [ $(basename "$DRIVER") != "cxi_ss1" ]; then
		echo "WARNING: VF $CXI_VF was bound to $(basename "$DRIVER") and not cxi_ss1" >&2
	fi
	echo "$PCIFN" > "$DRIVER/unbind"
fi

# Bind the VF to vfio driver
modprobe vfio_pci
# No way to tell if the device ID is already registered; suppress stderr so that
# the command fails silently if that's the case.
echo "${VENDOR##*x}" "${DEVICE##*x}" > /sys/bus/pci/drivers/vfio-pci/new_id 2>/dev/null
echo "$PCIFN" > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null

# Tell qemu to bind the VF
QEMU_OPTS="$QEMU_OPTS -device vfio-pci,host=$PCIFN"

# Add vhost-vsock device for VF-PF communication with a random guest CID
CID=$(shuf -i 3-2147483647 -n 1) # CIDs 0-2 are reserved
QEMU_OPTS="$QEMU_OPTS -device vhost-vsock-pci,guest-cid=${CID}"

PATH=$QEMU_DIR:$VIRTME_DIR:/sbin:$PATH
VIRTME_OPTS="--rodir=/lib/firmware=$(pwd)/../../hms-artifacts"

if [[ $TESTING -eq 1 ]]; then
	# Put additional options here...
	VIRTME_OPTS="--rwdir=$(pwd)/../tests/tmptests ${VIRTME_OPTS}"
fi

if [[ -v KDIR ]]; then
    KERNEL="--kdir $KDIR --mods=auto"
else
    KERNEL="--installed-kernel"
fi

# Preserve terminal settings in case the VM or qemu is killed.
# Otherwise the terminal is irresponsive
TTY_STATE=$(stty -g 2>/dev/null || true)
trap 'if [[ -n "$TTY_STATE" ]]; then stty "$TTY_STATE" 2>/dev/null || true; fi' EXIT

# Start the VM, execute the script inside, and exit ...
#virtme-run --installed-kernel --pwd --script-sh $VM_INIT_SCRIPT $KERN_OPTS $QEMU_OPTS

# ... or start a VM and execute the script but don't exit
virtme-run $KERNEL --pwd --init-sh $VM_INIT_SCRIPT $VIRTME_OPTS $KERN_OPTS $QEMU_OPTS
VM_EXIT=$?

# If qemu was killed (e.g. SIGKILL -> 137), exit quietly.
if [[ $VM_EXIT -ge 128 ]]; then
	echo "Info: VM terminated by signal $((VM_EXIT - 128))" >&2
	exit $VM_EXIT
fi

# ... or just start a clean VM
#virtme-run --installed-kernel --pwd $KERN_OPTS $QEMU_OPTS

# Restore VF to host
if [ -e /sys/bus/pci/drivers/vfio-pci/unbind ]; then
	echo "$PCIFN" > /sys/bus/pci/drivers/vfio-pci/unbind
fi
if [ -e /sys/bus/pci/drivers/cxi_ss1/bind ]; then
	echo "$PCIFN" > /sys/bus/pci/drivers/cxi_ss1/bind
fi
