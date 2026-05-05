#!/bin/bash

# Manage SR-IOV VFs on a CXI device.
#
# Usage:
#   cxi_vf.sh list                               Show PF and all VF details
#   cxi_vf.sh setup <N> [--no-ama] [--wait-ama] Create N VFs (kills any running VMs first)
#   cxi_vf.sh remove                             Remove all VFs (equivalent to setup 0)
#
# Options:
#   --no-ama    Skip automatic AMA MAC address assignment to VFs
#   --wait-ama  Wait until the PF has an AMA MAC before creating VFs
#
# Environment variable CXI_DEVICE controls the PF device. Default: cxi0.

CXI_DEVICE=${CXI_DEVICE:='cxi0'}
CMD=${1:-list}
NO_AMA=0
WAIT_AMA=0

# Re-exec with sudo for commands that write to sysfs.
if [ "$CMD" != "list" ] && [ "$(id -u)" -ne 0 ]; then
	exec sudo --preserve-env=CXI_DEVICE "$0" "$@"
fi

# --------------------------------------------------------------------------- #
# Helpers

die() { echo "Error: $*" >&2; exit 1; }

check_device() {
	[ -d "/sys/class/cxi/${CXI_DEVICE}" ] ||
		die "Device ${CXI_DEVICE} not found"
	[ -f "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs" ] ||
		die "Device ${CXI_DEVICE} does not support SR-IOV. Ensure an SR-IOV capable driver is loaded."
}

print_dev_info() {
	local label="$1"
	local pci_path="$2"
	local vf_sysfs="$3"   # symlink path (for driver resolution)
	local vf_index="$4"   # numeric VF index (for ip link show parsing)
	local pf_net_dev="$5" # PF net interface (for ip link show)

	local pcifn
	pcifn=$(basename "$(readlink "$vf_sysfs" 2>/dev/null || echo "$pci_path")")

	local driver="(none)"
	[ -d "${vf_sysfs}/driver" ] && driver=$(basename "$(readlink "${vf_sysfs}/driver")")

	local cxi_dev cxi_field
	cxi_dev=$(ls "${pci_path}/cxi/" 2>/dev/null | head -1)
	cxi_dev=${cxi_dev:-(none)}
	[ "$cxi_dev" != "(none)" ] && cxi_field="  cxi=${cxi_dev}" || cxi_field=""

	local suffix=""
	local net_info
	if [ "$driver" = "vfio-pci" ]; then
		# VF is inside a VM — get MAC and link-state from PF's ip link show output.
		local vf_mac="(unknown)" vf_link="(unknown)"
		if [ -n "$pf_net_dev" ] && [ -n "$vf_index" ]; then
			local vf_line
			vf_line=$(ip link show "$pf_net_dev" 2>/dev/null | awk "/vf ${vf_index} /")
			vf_mac=$(echo "$vf_line" | awk '{print $4}')
			vf_mac=${vf_mac:-(unknown)}
			vf_link=$(echo "$vf_line" | grep -oP 'link-state \K\S+' | tr -d ',')
			vf_link=${vf_link:-(unknown)}
		fi
		net_info="mac=${vf_mac}  link=${vf_link}"
		local qemu_pid
		qemu_pid=$(pgrep -f "vfio-pci,host=${pcifn}" 2>/dev/null || true)
		if [ -n "$qemu_pid" ]; then
			suffix="  [running in VM, PID=${qemu_pid}]"
		else
			suffix="  [bound to vfio-pci, no VM detected]"
		fi
	else
		local net_dev
		net_dev=$(ls "${pci_path}/net/" 2>/dev/null | head -1)
		if [ -n "$net_dev" ]; then
			local net_path="/sys/class/net/${net_dev}"
			local mac link ip
			mac=$(cat "${net_path}/address" 2>/dev/null || echo "(unknown)")
			link=$(cat "${net_path}/operstate" 2>/dev/null || echo "(unknown)")
			ip=$(ip -4 addr show "$net_dev" 2>/dev/null | awk '/inet /{print $2}' | head -1)
			ip=${ip:-(none)}
			net_info="net=${net_dev}  mac=${mac}"
			[ "$ip" != "(none)" ] && net_info+="  ip=${ip}"
			net_info+="  link=${link}"
		else
			net_info="net=(none)"
		fi
	fi

	echo "  ${label}: ${pcifn}  driver=${driver}${cxi_field}  ${net_info}${suffix}"
}

cmd_list() {
	check_device

	local pf_pci_path
	pf_pci_path=$(readlink -f "/sys/class/cxi/${CXI_DEVICE}/device")
	local pf_pcifn
	pf_pcifn=$(basename "$pf_pci_path")
	local pf_driver="(none)"
	[ -d "${pf_pci_path}/driver" ] && pf_driver=$(basename "$(readlink "${pf_pci_path}/driver")")
	local pf_cxi_dev
	pf_cxi_dev=$(ls "${pf_pci_path}/cxi/" 2>/dev/null | head -1)
	pf_cxi_dev=${pf_cxi_dev:-(none)}
	local pf_net_dev
	pf_net_dev=$(ls "${pf_pci_path}/net/" 2>/dev/null | head -1)
	local pf_net_info
	if [ -n "$pf_net_dev" ]; then
		local net_path="/sys/class/net/${pf_net_dev}"
		local mac link ip
		mac=$(cat "${net_path}/address" 2>/dev/null || echo "(unknown)")
		link=$(cat "${net_path}/operstate" 2>/dev/null || echo "(unknown)")
		ip=$(ip -4 addr show "$pf_net_dev" 2>/dev/null | awk '/inet /{print $2}' | head -1)
		ip=${ip:-(none)}
		pf_net_info="${pf_net_dev}  mac=${mac}"
		[ "$ip" != "(none)" ] && pf_net_info+="  ip=${ip}"
		pf_net_info+="  link=${link}"
	else
		pf_net_info="(none)"
	fi

	local num_vfs total_vfs
	num_vfs=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs")
	total_vfs=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_totalvfs")

	echo "PF (${CXI_DEVICE}): ${pf_pcifn}  driver=${pf_driver}  cxi=${pf_cxi_dev}  net=${pf_net_info}"
	echo "VFs: ${num_vfs} / ${total_vfs} max"

	if [[ $num_vfs -eq 0 ]]; then
		echo "  (no VFs provisioned)"
		return
	fi

	for ((i=0; i<num_vfs; i++)); do
		local vf_sysfs="/sys/class/cxi/${CXI_DEVICE}/device/virtfn${i}"
		if [ ! -e "$vf_sysfs" ]; then
			echo "  VF $i: symlink not found" >&2
			continue
		fi
		local vf_pci_path
		vf_pci_path=$(readlink -f "$vf_sysfs")
		print_dev_info "VF $i" "$vf_pci_path" "$vf_sysfs" "$i" "$pf_net_dev"
	done
}

kill_vfio_vfs() {
	local num_vfs="$1"
	for ((i=0; i<num_vfs; i++)); do
		local vf_path="/sys/class/cxi/${CXI_DEVICE}/device/virtfn${i}"
		[ -e "$vf_path" ] || continue
		local pcifn driver
		pcifn=$(basename "$(readlink "$vf_path")")
		[ -d "${vf_path}/driver" ] || continue
		driver=$(basename "$(readlink "${vf_path}/driver")")
		[ "$driver" = "vfio-pci" ] || continue

		local qemu_pid
		qemu_pid=$(pgrep -f "vfio-pci,host=${pcifn}" || true)
		if [ -n "$qemu_pid" ]; then
			echo "Killing QEMU (PID $qemu_pid) holding VF $i ($pcifn)" >&2
			kill "$qemu_pid"
			for _ in {1..10}; do
				kill -0 "$qemu_pid" 2>/dev/null || break
				sleep 0.5
			done
			kill -9 "$qemu_pid" 2>/dev/null || true
		fi
		echo "$pcifn" > /sys/bus/pci/drivers/vfio-pci/unbind 2>/dev/null || true
	done
}

set_ama() {
	local actual="$1"
	local pf_pci_path
	pf_pci_path=$(readlink -f "/sys/class/cxi/${CXI_DEVICE}/device")
	local pf_net_dev
	pf_net_dev=$(ls "${pf_pci_path}/net/" 2>/dev/null | head -1)

	[ -n "$pf_net_dev" ] || return

	local pf_mac
	pf_mac=$(cat "/sys/class/net/${pf_net_dev}/address" 2>/dev/null || true)
	if [[ "$pf_mac" == 02:00:00:* ]]; then
		echo "Configuring AMA to VFs" >&2
		local b1 b2 b3 b4 b5 b6
		IFS=: read -r b1 b2 b3 b4 b5 b6 <<< "$pf_mac"
		for ((i=0; i<actual; i++)); do
			local vf_num_hex
			vf_num_hex=$(printf "%02x" $((i + 1)))
			local vf_mac="${b1}:${b2}:${vf_num_hex}:${b4}:${b5}:${b6}"
			ip link set "$pf_net_dev" vf "$i" mac "$vf_mac" 2>/dev/null ||
				echo "Warning: failed to set MAC for VF $i" >&2
		done
	else
		echo "WARNING: skipping AMA assigned to VFs since the PF does not have an AMA set" >&2
	fi
}

wait_for_ama() {
	local pf_pci_path
	pf_pci_path=$(readlink -f "/sys/class/cxi/${CXI_DEVICE}/device")
	local pf_net_dev
	pf_net_dev=$(ls "${pf_pci_path}/net/" 2>/dev/null | head -1)
	[ -n "$pf_net_dev" ] ||
		{ echo "Warning: no net device on PF, cannot wait for AMA" >&2; return; }

	local pf_mac
	pf_mac=$(cat "/sys/class/net/${pf_net_dev}/address" 2>/dev/null || true)
	if [[ "$pf_mac" != 02:00:00:* ]]; then
		echo "Waiting for AMA..." >&2
		while true; do
			pf_mac=$(cat "/sys/class/net/${pf_net_dev}/address" 2>/dev/null || true)
			[[ "$pf_mac" == 02:00:00:* ]] && break
			sleep 1
		done
	fi
}

cmd_setup() {
	local num_vfs="$1"
	check_device
	[[ $WAIT_AMA -eq 1 ]] && wait_for_ama

	local total_vfs
	total_vfs=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_totalvfs")
	[[ $num_vfs -le $total_vfs ]] ||
		die "Requested $num_vfs VFs but device supports at most $total_vfs"

	local current_vfs
	current_vfs=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs")

	kill_vfio_vfs "$current_vfs"

	if [[ $current_vfs -ne 0 ]]; then
		echo "Tearing down $current_vfs existing VFs on ${CXI_DEVICE}..." >&2
		echo 0 > "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs"
		for ((i=0; i<current_vfs; i++)); do
			for _ in {1..20}; do
				[ ! -e "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${i}" ] && break
				sleep 0.1
			done
		done
	fi

	if [[ $num_vfs -eq 0 ]]; then
		echo "All VFs removed from ${CXI_DEVICE}." >&2
		return
	fi

	# Disable autoprobe before creating VFs so vfio-pci (or any other driver
	# with a registered dynamic ID) cannot claim them at creation time.
	local autoprobe="/sys/class/cxi/${CXI_DEVICE}/device/sriov_drivers_autoprobe"
	[ -f "$autoprobe" ] && echo 0 > "$autoprobe"

	echo "Provisioning $num_vfs VFs on ${CXI_DEVICE}..." >&2
	echo "$num_vfs" > "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs"
	local actual
	actual=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs")

	# Wait for virtfnX symlinks to appear.
	for ((i=0; i<actual; i++)); do
		for _ in {1..20}; do
			[ -e "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${i}" ] && break
			sleep 0.1
		done
	done

	# While autoprobe is still off, read the VF device ID and remove it from
	# vfio-pci's dynamic table so it won't reclaim VFs after autoprobe is
	# re-enabled.
	if [ -e "/sys/class/cxi/${CXI_DEVICE}/device/virtfn0" ]; then
		local vf_vendor vf_device_id
		vf_vendor=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/virtfn0/vendor" 2>/dev/null || true)
		vf_device_id=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/virtfn0/device" 2>/dev/null || true)
		if [ -n "$vf_vendor" ] && [ -n "$vf_device_id" ] &&
		   [ -e /sys/bus/pci/drivers/vfio-pci/remove_id ]; then
			echo "${vf_vendor##*x} ${vf_device_id##*x}" > /sys/bus/pci/drivers/vfio-pci/remove_id 2>/dev/null || true
		fi
	fi

	# Re-enable autoprobe — vfio-pci no longer has the VF ID registered,
	# so cxi_ss1 can bind normally.
	[ -f "$autoprobe" ] && echo 1 > "$autoprobe"

	# Bind each VF to cxi_ss1.
	for ((i=0; i<actual; i++)); do
		local vf_path="/sys/class/cxi/${CXI_DEVICE}/device/virtfn${i}"
		[ -e "$vf_path" ] || continue
		local pcifn
		pcifn=$(basename "$(readlink "$vf_path")")
		echo "$pcifn" > /sys/bus/pci/drivers/cxi_ss1/bind 2>/dev/null || true
	done

	# Assign AMA-derived MAC addresses to VFs if the PF uses AMA addressing.
	[[ $NO_AMA -eq 0 ]] && set_ama "$actual"

	cmd_list
}

# --------------------------------------------------------------------------- #
# Dispatch

case "$CMD" in
	list)
		cmd_list
		;;
	setup)
		[[ -n "$2" ]] || die "Usage: $0 setup <num_vfs> [--no-ama] [--wait-ama]"
		[[ "$2" =~ ^[0-9]+$ ]] || die "num_vfs must be a non-negative integer"
		for opt in "${@:3}"; do
			case "$opt" in
				--no-ama)   NO_AMA=1 ;;
				--wait-ama) WAIT_AMA=1 ;;
				*) die "Unknown option: $opt" ;;
			esac
		done
		cmd_setup "$2"
		;;
	remove)
		cmd_setup 0
		;;
	*)
		echo "Usage: $0 {list|setup <N> [--no-ama] [--wait-ama]|remove}" >&2
		exit 1
		;;
esac
