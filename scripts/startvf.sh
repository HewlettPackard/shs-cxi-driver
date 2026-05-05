#!/bin/bash

# Start a VM on the first available VF.
#
# Scans VFs on CXI_DEVICE and claims the first one not already bound to
# vfio-pci (i.e. not yet passed to a VM). A lock file serializes concurrent
# invocations so that two instances cannot claim the same VF.
#
# Usage: start_vm.sh [vf_index]
#
# Arguments:
#   vf_index        Optional VF index to use. If omitted, the first available
#                   VF is selected automatically.
#
# Environment variables:
#   CXI_DEVICE      PF device to use. Default: cxi0
#   VM_INIT_SCRIPT  Init script to run inside the VM. Default: ./startvf-setup.sh
#   KDIR            If set, boot the kernel from this directory instead of the
#                   installed kernel.
#   TESTING         Set to 1 to mount the tests/tmptests directory into the VM.

DIR=$(dirname "$(realpath "$0")")
cd "$DIR"

REQUESTED_VF=${1:-}
VM_INIT_SCRIPT=${VM_INIT_SCRIPT:='./startvf-setup.sh'}
CXI_DEVICE=${CXI_DEVICE:='cxi0'}

. ../tests/framework.sh

# Load vsock modules on host for VF-PF communication
modprobe vsock 2>/dev/null || echo "Warning: Could not load vsock module" >&2
modprobe vhost_vsock 2>/dev/null || echo "Warning: Could not load vhost_vsock module" >&2

# -M q35 = Standard PC (Q35 + ICH9, 2009) (alias of pc-q35-2.10)
# MSI-X needs interrupt remapping enabled to fully work.
# w/ Intel IOMMU. Intremap on requires kernel-irqchip=off OR kernel-irqchip=split
QEMU_OPTS="--qemu-opts -machine q35,kernel-irqchip=split -global q35-pcihost.pci-hole64-size=40G -device intel-iommu,intremap=on,caching-mode=on $CCN_OPTS"

KERN_OPTS="--kopt iommu=pt --kopt intel_iommu=on --kopt iomem=relaxed"
KERN_OPTS="$KERN_OPTS --kopt transparent_hugepage=never --kopt hugepagesz=1g --kopt default_hugepagesz=1g --kopt hugepages=1"

# For some reason the euler image needs a ton of RAM to boot
QEMU_OPTS="$QEMU_OPTS -m 10G"

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
	echo "Error: No VFs provisioned on ${CXI_DEVICE}. Run setup_vfs.sh first." >&2
	exit 1
fi

# Use a lock file to serialise concurrent invocations so two instances cannot
# claim the same VF.
LOCK_FILE="/tmp/cxi_vf_${CXI_DEVICE}.lock"
exec 9>"$LOCK_FILE"
flock 9

# Find the VF to use: explicit index if provided, else first available.
CXI_VF=-1
if [[ -n "$REQUESTED_VF" ]]; then
	if ! [[ "$REQUESTED_VF" =~ ^[0-9]+$ ]]; then
		echo "Error: vf_index must be a non-negative integer" >&2
		exit 1
	fi
	if [[ $REQUESTED_VF -ge $NUM_VFS ]]; then
		echo "Error: Requested VF $REQUESTED_VF but only $NUM_VFS VFs available" >&2
		exit 1
	fi
	VF_PATH="/sys/class/cxi/${CXI_DEVICE}/device/virtfn${REQUESTED_VF}"
	if [ ! -e "$VF_PATH" ]; then
		echo "Error: VF $REQUESTED_VF symlink not found at $VF_PATH" >&2
		exit 1
	fi
	if [ -d "${VF_PATH}/driver" ]; then
		DRIVER=$(basename "$(readlink "${VF_PATH}/driver")")
		if [ "$DRIVER" = "vfio-pci" ]; then
			echo "Error: Requested VF $REQUESTED_VF is already in use (vfio-pci)" >&2
			exit 1
		fi
	fi
	CXI_VF=$REQUESTED_VF
else
	# Find the first VF not already bound to vfio-pci.
	for ((i=0; i<NUM_VFS; i++)); do
		VF_PATH="/sys/class/cxi/${CXI_DEVICE}/device/virtfn${i}"
		if [ ! -e "$VF_PATH" ]; then
			echo "  VF $i: symlink not found at $VF_PATH" >&2
			continue
		fi
		if [ -d "${VF_PATH}/driver" ]; then
			DRIVER=$(basename "$(readlink "${VF_PATH}/driver")")
			if [ "$DRIVER" = "vfio-pci" ]; then
				echo "  VF $i: in use (vfio-pci)" >&2
				continue
			fi
			echo "  VF $i: available (driver=$DRIVER)" >&2
		else
			echo "  VF $i: available (no driver)" >&2
		fi
		CXI_VF=$i
		break
	done
fi

if [[ $CXI_VF -eq -1 ]]; then
	echo "Error: No available VFs on ${CXI_DEVICE} (all $NUM_VFS are in use or missing)" >&2
	exit 1
fi

echo "Claiming VF $CXI_VF on ${CXI_DEVICE}" >&2

# Get VF info
PCIFN=$(basename "$(readlink "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${CXI_VF}")")
VENDOR=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${CXI_VF}/vendor")
DEVICE=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${CXI_VF}/device")
if [ -d "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${CXI_VF}/driver" ]; then
	DRIVER=$(readlink -f "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${CXI_VF}/driver")
else
	DRIVER=""
fi

# Unbind VF from cxi core driver.
if [ -n "$DRIVER" ]; then
	if [ "$(basename "$DRIVER")" != "cxi_ss1" ]; then
		echo "WARNING: VF $CXI_VF was bound to $(basename "$DRIVER") and not cxi_ss1" >&2
	fi
	echo "$PCIFN" > "$DRIVER/unbind"
fi

# Bind the VF to vfio driver. Registering the device ID may fail silently if
# already registered.
modprobe vfio_pci
echo "${VENDOR##*x}" "${DEVICE##*x}" > /sys/bus/pci/drivers/vfio-pci/new_id 2>/dev/null
echo "$PCIFN" > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null

# VF is now claimed — release the lock so other instances can claim a different VF.
flock -u 9

# Tell qemu to bind the VF
QEMU_OPTS="$QEMU_OPTS -device vfio-pci,host=$PCIFN"

# Add vhost-vsock device for VF-PF communication with a random guest CID
CID=$(shuf -i 3-2147483647 -n 1) # CIDs 0-2 are reserved
QEMU_OPTS="$QEMU_OPTS -device vhost-vsock-pci,guest-cid=${CID}"

PATH=$QEMU_DIR:$VIRTME_DIR:/sbin:$PATH
VIRTME_OPTS="--rodir=/lib/firmware=$(pwd)/../../hms-artifacts"

if [[ $TESTING -eq 1 ]]; then
	VIRTME_OPTS="--rwdir=$(pwd)/../tests/tmptests ${VIRTME_OPTS}"
fi

if [[ -v KDIR ]]; then
	KERNEL="--kdir $KDIR --mods=auto"
else
	KERNEL="--installed-kernel"
fi

# Preserve terminal settings in case the VM or qemu is killed.
TTY_STATE=$(stty -g 2>/dev/null || true)
trap 'if [[ -n "$TTY_STATE" ]]; then stty "$TTY_STATE" 2>/dev/null || true; fi' EXIT

virtme-run $KERNEL --pwd --init-sh $VM_INIT_SCRIPT $VIRTME_OPTS $KERN_OPTS $QEMU_OPTS
VM_EXIT=$?

# If qemu was killed (e.g. SIGKILL -> 137), exit quietly.
if [[ $VM_EXIT -ge 128 ]]; then
	echo "Info: VM terminated by signal $((VM_EXIT - 128))" >&2
	exit $VM_EXIT
fi

# Restore VF to host
if [ -e /sys/bus/pci/drivers/vfio-pci/unbind ]; then
	echo "$PCIFN" > /sys/bus/pci/drivers/vfio-pci/unbind
fi
if [ -e /sys/bus/pci/drivers/cxi_ss1/bind ]; then
	echo "$PCIFN" > /sys/bus/pci/drivers/cxi_ss1/bind
fi
