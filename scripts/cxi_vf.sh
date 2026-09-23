#!/bin/bash

# Manage SR-IOV VFs on a CXI device.
#
# Usage:
#   cxi_vf.sh list                               Show PF and all VF details
#   cxi_vf.sh setup <N> [--create-service PRESET|--use-service ID] [--no-ama] [--wait-ama] Create N VFs
#   cxi_vf.sh cleanup                             Remove all VFs (equivalent to setup 0)
#   cxi_vf.sh self-test <N> [--create-service PRESET|--use-service ID] [--no-ama] [--wait-ama] [--static-arp]  Self-contained loopback test setup:
#                                                  sets PF MAC to 02:00:00:00:00:00, creates N VFs
#                                                  with AMA-derived MACs, places each interface in
#                                                  its own netns (ns_pf, ns_vf0, ns_vf1, ...),
#                                                  assigns 192.168.1.x/16 addresses, and prints
#                                                  NS/IFACE/IP arrays for eval in the caller shell.
#
# Options:
#   --no-ama    Skip automatic AMA MAC address assignment to VFs
#   --wait-ama  Wait until the PF has an AMA MAC before creating VFs
#   --static-arp Add static ARP entries for all interfaces in self-test namespaces
#   --create-service Create a parent service from preset: eth (default), sriov, or criterion
#   --use-service    Assign an existing parent service ID to all VFs
#
# Environment variable CXI_DEVICE controls the PF device. Default: cxi0.

CXI_DEVICE=${CXI_DEVICE:='cxi0'}
CMD=${1:-list}
NO_AMA=0
WAIT_AMA=0
CREATE_SERVICE_PRESET=eth
CREATE_SERVICE_REQUESTED=0
USE_SERVICE_ID=
USE_SERVICE_REQUESTED=0
ENSURE_PF_MAC=0
STATIC_ARP=0

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
CXI_ETH_KO="${SCRIPT_DIR}/../drivers/net/ethernet/hpe/ss1/cxi-eth.ko"
SVC_TOOL="${SCRIPT_DIR}/../tests/svc_tool/svc_tool"

# --------------------------------------------------------------------------- #
# Helpers

die() { echo "Error: $*" >&2; exit 1; }

validate_service_options() {
	if [[ $USE_SERVICE_REQUESTED -eq 1 && $CREATE_SERVICE_REQUESTED -eq 1 ]]; then
		die "--use-service and --create-service are mutually exclusive"
	fi
	if [[ $CREATE_SERVICE_REQUESTED -eq 1 && ( -z "$CREATE_SERVICE_PRESET" || "$CREATE_SERVICE_PRESET" == --* ) ]]; then
		die "--create-service requires a preset"
	fi
	if [[ $USE_SERVICE_REQUESTED -eq 1 && ! "$USE_SERVICE_ID" =~ ^[1-9][0-9]*$ ]]; then
		die "--use-service requires a positive numeric service ID"
	fi
}

parse_setup_options() {
	local allow_static_arp="$1"
	shift

	while [[ $# -gt 0 ]]; do
		case "$1" in
			--no-ama)   NO_AMA=1; shift ;;
			--wait-ama) WAIT_AMA=1; shift ;;
			--static-arp)
				[[ $allow_static_arp -eq 1 ]] || die "Unknown option: $1"
				STATIC_ARP=1
				shift
				;;
			--create-service=*)
				CREATE_SERVICE_PRESET="${1#*=}"
				CREATE_SERVICE_REQUESTED=1
				shift
				;;
			--create-service)
				[[ -n "${2:-}" ]] || die "--create-service requires a preset"
				CREATE_SERVICE_PRESET="$2"
				CREATE_SERVICE_REQUESTED=1
				shift 2
				;;
			--use-service=*)
				USE_SERVICE_ID="${1#*=}"
				USE_SERVICE_REQUESTED=1
				shift
				;;
			--use-service)
				[[ -n "${2:-}" ]] || die "--use-service requires a service ID"
				USE_SERVICE_ID="$2"
				USE_SERVICE_REQUESTED=1
				shift 2
				;;
			--service|--service=*) die "Use --create-service PRESET instead of --service" ;;
			*) die "Unknown option: $1" ;;
		esac
	done

	validate_service_options
}

create_vf_parent_svc() {
	local preset="$1"
	local svc_id

	if [ ! -x "$SVC_TOOL" ]; then
		echo "svc_tool not found at $SVC_TOOL." >&2
		echo "Create a parent service, e.g.:" >&2
		echo "  cxi_service create -y cxi_service_template_parent.yaml" >&2
		echo "Then assign it with --use-service <svc_id>, or manually:" >&2
		echo "  echo <svc_id> > /sys/class/cxi/${CXI_DEVICE}/vf/<vf>/svc_id" >&2
		die "No svc_tool available; assign a parent service to the VFs and re-run"
	fi

	svc_id=$("$SVC_TOOL" "$preset" "$CXI_DEVICE") ||
		die "Failed to create $preset parent service via svc_tool"
	[[ -n "$svc_id" ]] || die "svc_tool returned empty svc_id"

	echo "$svc_id"
}

# Assign a parent service to all VFs
assign_vf_parent_svc() {
	local count="$1"
	local svc_id="$2"
	local i

	for ((i=0; i<count; i++)); do
		echo "$svc_id" > "/sys/class/cxi/${CXI_DEVICE}/vf/${i}/svc_id" ||
			die "Failed to assign svc_id $svc_id to VF $i"
	done
}

ensure_vf_parent_svc() {
	local count="$1"
	local i svc_id needs_svc=0

	if [[ -n "$USE_SERVICE_ID" ]]; then
		echo "Assigning parent service $USE_SERVICE_ID to all VFs." >&2
		assign_vf_parent_svc "$count" "$USE_SERVICE_ID"
		return 0
	fi

	if [[ $CREATE_SERVICE_REQUESTED -eq 1 ]]; then
		echo "Creating $CREATE_SERVICE_PRESET parent service and assigning it to all VFs." >&2
		svc_id=$(create_vf_parent_svc "$CREATE_SERVICE_PRESET")
		assign_vf_parent_svc "$count" "$svc_id"
		return 0
	fi

	for ((i=0; i<count; i++)); do
		svc_id=$(cat "/sys/class/cxi/${CXI_DEVICE}/vf/${i}/svc_id" 2>/dev/null || echo 0)
		if [[ "$svc_id" -eq 0 ]]; then
			needs_svc=1
			break
		fi
	done
	[[ $needs_svc -eq 0 ]] && return 0

	echo "No service assigned to the VFs. Creating a default parent service and assigning it to all VFs." >&2
	svc_id=$(create_vf_parent_svc "$CREATE_SERVICE_PRESET")
	assign_vf_parent_svc "$count" "$svc_id"
}

# Populate PF_PCI_PATH and PF_NET_DEV globals for the current CXI_DEVICE.
init_pf() {
	PF_PCI_PATH=$(readlink -f "/sys/class/cxi/${CXI_DEVICE}/device")
	PF_NET_DEV=$(ls "${PF_PCI_PATH}/net/" 2>/dev/null | head -1)
}

check_device() {
	[ -d "/sys/class/cxi/${CXI_DEVICE}" ] ||
		die "Device ${CXI_DEVICE} not found"
	[ -f "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs" ] ||
		die "Device ${CXI_DEVICE} does not support SR-IOV. Ensure an SR-IOV capable driver is loaded."
}

# Build a "net=DEV  mac=MAC  [ip=IP]  link=STATE" string for a net device.
# Result is stored in the global NET_INFO_STR.
net_info_str() {
	local net_dev="$1"
	local net_path="/sys/class/net/${net_dev}"
	local mac link ip
	mac=$(cat "${net_path}/address" 2>/dev/null || echo "(unknown)")
	link=$(cat "${net_path}/operstate" 2>/dev/null || echo "(unknown)")
	ip=$(ip -4 addr show "$net_dev" 2>/dev/null | awk '/inet /{print $2}' | head -1)
	ip=${ip:-(none)}
	NET_INFO_STR="net=${net_dev}  mac=${mac}"
	[ "$ip" != "(none)" ] && NET_INFO_STR+="  ip=${ip}"
	NET_INFO_STR+="  link=${link}"
}

# Wait for virtfnN symlinks to appear or disappear in sysfs.
# $1 = VF count, $2 = "appear" | "disappear"
wait_virtfn() {
	local count="$1" mode="$2"
	for ((i=0; i<count; i++)); do
		for _ in {1..20}; do
			if [[ "$mode" == "appear" ]]; then
				[ -e "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${i}" ] && break
			else
				[ ! -e "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${i}" ] && break
			fi
			sleep 0.1
		done
	done
}

# Resolve a VF index to its PCI path and net device.
# Sets globals VF_PCI_PATH and VF_NET_DEV.
init_vf() {
	local idx="$1"
	VF_PCI_PATH=$(readlink -f "/sys/class/cxi/${CXI_DEVICE}/device/virtfn${idx}")
	VF_NET_DEV=$(ls "${VF_PCI_PATH}/net/" 2>/dev/null | head -1)
}

# Create a network namespace and configure an interface inside it.
# $1 = namespace name, $2 = interface, $3 = IP address with prefix (e.g. 192.168.1.1/16)
setup_netns() {
	ip netns del "$1" 2>/dev/null || true
	ip netns add "$1"
	ip link set "$2" netns "$1"
	ip -n "$1" link set "$2" up
	ip -n "$1" addr add "$3" dev "$2"
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
			net_info_str "$net_dev"
			net_info="$NET_INFO_STR"
		else
			net_info="net=(none)"
		fi
	fi

	echo "  ${label}: ${pcifn}  driver=${driver}${cxi_field}  ${net_info}${suffix}"
}

cmd_list() {
	check_device
	init_pf
	local pf_pci_path="$PF_PCI_PATH"
	local pf_net_dev="$PF_NET_DEV"
	local pf_pcifn
	pf_pcifn=$(basename "$pf_pci_path")
	local pf_driver="(none)"
	[ -d "${pf_pci_path}/driver" ] && pf_driver=$(basename "$(readlink "${pf_pci_path}/driver")")
	local pf_cxi_dev
	pf_cxi_dev=$(ls "${pf_pci_path}/cxi/" 2>/dev/null | head -1)
	pf_cxi_dev=${pf_cxi_dev:-(none)}
	local pf_net_info
	if [ -n "$pf_net_dev" ]; then
		net_info_str "$pf_net_dev"
		pf_net_info="$NET_INFO_STR"
	else
		pf_net_info="(none)"
	fi

	local num_vfs total_vfs
	num_vfs=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs")
	total_vfs=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_totalvfs")

	echo "PF (${CXI_DEVICE}): ${pf_pcifn}  driver=${pf_driver}  cxi=${pf_cxi_dev}  ${pf_net_info}"
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
		init_vf "$i"
		print_dev_info "VF $i" "$VF_PCI_PATH" "$vf_sysfs" "$i" "$pf_net_dev"
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
	init_pf
	[ -n "$PF_NET_DEV" ] || return

	local pf_mac
	pf_mac=$(cat "/sys/class/net/${PF_NET_DEV}/address" 2>/dev/null || true)
	if [[ "$pf_mac" != 02:00:00:* ]]; then
		if [[ $ENSURE_PF_MAC -eq 1 ]]; then
			echo "Setting PF MAC to 02:00:00:00:00:00..." >&2
			ip link set "$PF_NET_DEV" address 02:00:00:00:00:00 ||
				die "Failed to set PF MAC address"
			pf_mac="02:00:00:00:00:00"
		else
			echo "WARNING: skipping AMA assigned to VFs since the PF does not have an AMA set" >&2
			return
		fi
	fi

	echo "Configuring AMA to VFs" >&2
	local b1 b2 b3 b4 b5 b6
	IFS=: read -r b1 b2 b3 b4 b5 b6 <<< "$pf_mac"
	for ((i=0; i<actual; i++)); do
		local vf_num_hex
		vf_num_hex=$(printf "%02x" $((i + 1)))
		local vf_mac="${b1}:${b2}:${vf_num_hex}:${b4}:${b5}:${b6}"
		ip link set "$PF_NET_DEV" vf "$i" mac "$vf_mac" 2>/dev/null ||
			echo "Warning: failed to set MAC for VF $i" >&2
	done
}

wait_for_ama() {
	init_pf
	[ -n "$PF_NET_DEV" ] ||
		{ echo "Warning: no net device on PF, cannot wait for AMA" >&2; return; }

	local pf_mac
	pf_mac=$(cat "/sys/class/net/${PF_NET_DEV}/address" 2>/dev/null || true)
	if [[ "$pf_mac" != 02:00:00:* ]]; then
		echo "Waiting for AMA..." >&2
		while true; do
			pf_mac=$(cat "/sys/class/net/${PF_NET_DEV}/address" 2>/dev/null || true)
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

	teardown

	if [[ $num_vfs -eq 0 ]]; then
		echo "All VFs removed from ${CXI_DEVICE}." >&2
		return
	fi

	# The svc_id sysfs nodes must be assigned before VFs bind to cxi_ss1.
	ensure_vf_parent_svc "$num_vfs"

	# Disable autoprobe before creating VFs so vfio-pci (or any other driver
	# with a registered dynamic ID) cannot claim them at creation time.
	local autoprobe="/sys/class/cxi/${CXI_DEVICE}/device/sriov_drivers_autoprobe"
	[ -f "$autoprobe" ] && echo 0 > "$autoprobe"

	echo "Provisioning $num_vfs VFs on ${CXI_DEVICE}..." >&2
	echo "$num_vfs" > "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs" ||
		die "Could not create virtual functions. See dmesg log."
	local actual
	actual=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs")

	# Wait for virtfnX symlinks to appear.
	wait_virtfn "$actual" appear

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

# Remove any ns_pf / ns_vfN namespaces, kill vfio VMs, and remove all VFs.
# Safe to call when no namespaces or VFs exist.
teardown() {
	# Remove leftover self-test namespaces (no-op if none exist).
	for ns in $(ip netns list | awk '{print $1}' | grep -E '^ns_(pf|vf[0-9]+)$'); do
		echo "Removing existing namespace ${ns}..." >&2
		ip netns del "$ns" 2>/dev/null || true
	done

	# Kill VMs and remove VFs.
	local current_vfs
	current_vfs=$(cat "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs" 2>/dev/null || echo 0)
	kill_vfio_vfs "$current_vfs"
	if [[ $current_vfs -ne 0 ]]; then
		echo "Tearing down $current_vfs existing VFs on ${CXI_DEVICE}..." >&2
		echo 0 > "/sys/class/cxi/${CXI_DEVICE}/device/sriov_numvfs"
		wait_virtfn "$current_vfs" disappear
	fi

	# After namespace/VF removal the PF net device may take a moment to
	# reappear in sysfs; retry for up to 5 seconds before giving up.
	init_pf
	local retries=50
	while [[ -z "$PF_NET_DEV" && $retries -gt 0 ]]; do
		sleep 0.1
		init_pf
		((retries--))
	done
}

cmd_self_test() {
	local num_vfs="$1"
	check_device

	# Step 0: Tear down any leftover namespaces and VFs from a previous run
	# so that interfaces are back in the root netns before we try to locate them.
	teardown
	local pf_pci_path="$PF_PCI_PATH"
	local pf_net_dev="$PF_NET_DEV"
	if [ -z "$pf_net_dev" ]; then
		echo "cxi-eth driver not loaded — inserting ${CXI_ETH_KO}..." >&2
		insmod "${CXI_ETH_KO}" || die "Failed to insmod cxi-eth.ko"
		init_pf
	fi

	# Step 1: Create VFs; set_ama will ensure the PF has an AMA MAC (setting
	# 02:00:00:00:00:00 if not already set) and derive VF MACs from it.
	ENSURE_PF_MAC=1
	cmd_setup "$num_vfs"

	# Re-read PF net device — cmd_setup calls teardown+init_pf internally and
	# VF net devices may have appeared; the pre-setup capture could be stale.
	init_pf
	pf_net_dev="$PF_NET_DEV"
	[ -n "$pf_net_dev" ] || die "No net device found on PF ${CXI_DEVICE} after setup"

	# Step 2: Create one netns per interface, bring it up, assign IPs.
	local -a NS IFACE IP MAC

	# Re-read PF MAC — set_ama may have just set it.
	local pf_mac
	pf_mac=$(cat "/sys/class/net/${pf_net_dev}/address" 2>/dev/null || true)

	# PF.
	local pf_ns="ns_pf"
	echo "Creating namespace ${pf_ns} for PF (${pf_net_dev}, 192.168.1.1/16)..." >&2
	setup_netns "$pf_ns" "$pf_net_dev" 192.168.1.1/16
	NS[0]="$pf_ns"
	IFACE[0]="$pf_net_dev"
	IP[0]="192.168.1.1/16"
	MAC[0]="$pf_mac"

	# VFs — use a sequential index so skipped VFs don't leave sparse array holes.
	local idx=1
	for ((i=0; i<num_vfs; i++)); do
		local vf_sysfs="/sys/class/cxi/${CXI_DEVICE}/device/virtfn${i}"
		[ -e "$vf_sysfs" ] || { echo "Warning: VF $i sysfs entry missing, skipping" >&2; continue; }
		init_vf "$i"
		if [ -z "$VF_NET_DEV" ]; then
			echo "Warning: no net device for VF $i, skipping namespace" >&2
			continue
		fi

		local vf_ns="ns_vf${i}"
		local vf_ip="192.168.1.$((idx + 1))/16"
		local vf_mac
		vf_mac=$(cat "${VF_PCI_PATH}/net/${VF_NET_DEV}/address" 2>/dev/null || true)
		vf_mac=${vf_mac:-(unknown)}

		echo "Creating namespace ${vf_ns} for VF $i (${VF_NET_DEV}, ${vf_ip})..." >&2
		setup_netns "$vf_ns" "$VF_NET_DEV" "$vf_ip"

		NS[$idx]="$vf_ns"
		IFACE[$idx]="$VF_NET_DEV"
		IP[$idx]="$vf_ip"
		MAC[$idx]="$vf_mac"
		((idx++))
	done

	# Step 3: Add static ARP entries in every namespace for all other interfaces.
	local total=${#NS[@]}
	if [[ $STATIC_ARP -eq 1 ]]; then
		echo "Adding static ARP entries..." >&2
		for ((a=0; a<total; a++)); do
			for ((b=0; b<total; b++)); do
				[[ $a -eq $b ]] && continue
				local peer_ip="${IP[$b]%%/*}"
				echo "  [${NS[$a]}] ${peer_ip} lladdr ${MAC[$b]} dev ${IFACE[$a]}" >&2
				ip -n "${NS[$a]}" neigh replace "$peer_ip" \
					lladdr "${MAC[$b]}" dev "${IFACE[$a]}" nud permanent
			done
		done
	fi

	# Step 4: Ensure all interfaces are up after full configuration.
	echo "Bringing all interfaces up..." >&2
	for ((a=0; a<total; a++)); do
		ip -n "${NS[$a]}" link set "${IFACE[$a]}" up
	done

	# Print arrays to stdout so the caller can eval them.
	echo ""
	echo "Self-test ready. Eval the following in your shell:"
	echo "NS=(${NS[*]})"
	echo "IFACE=(${IFACE[*]})"
	echo "IP=(${IP[*]})"
	echo "MAC=(${MAC[*]})"
	echo ""
	echo "Example pings:"
	local count=0
	for ((a=0; a<total; a++)); do
		for ((b=0; b<total; b++)); do
			[[ $a -eq $b ]] && continue
			[[ $count -ge 3 ]] && break 2
			local dst_ip="${IP[$b]%%/*}"
			local src_label dst_label
			src_label=$([[ $a -eq 0 ]] && echo "PF" || echo "VF$((a - 1))")
			dst_label=$([[ $b -eq 0 ]] && echo "PF" || echo "VF$((b - 1))")
			printf "  # %s -> %s\n" "$src_label" "$dst_label"
			printf "  ip netns exec %s ping %s\n" "${NS[$a]}" "$dst_ip"
			((count++))
		done
	done

	# Step 5: Ping matrix.
	echo ""
	run_ping_matrix NS IP
}

run_ping_matrix() {
	local -n _NS="$1"
	local -n _IP="$2"
	local total=${#_NS[@]}

	# Build label array: index 0 -> "PF", 1 -> "VF0", etc.
	local -a LABEL
	LABEL[0]="PF"
	for ((i=1; i<total; i++)); do
		LABEL[$i]="VF$((i - 1))"
	done

	echo "Ping matrix:"
	local all_ok=1
	for ((a=0; a<total; a++)); do
		for ((b=0; b<total; b++)); do
			[[ $a -eq $b ]] && continue
			local dst_ip="${_IP[$b]%%/*}"
			local out
			out=$(ip netns exec "${_NS[$a]}" \
				ping -c 3 -W 2 -q "$dst_ip" 2>&1)
			local loss rtt
			loss=$(echo "$out" | grep -oP '\d+(?=% packet loss)')
			rtt=$(echo  "$out" | grep -oP 'rtt.*= [0-9.]+/\K[0-9.]+' | head -1)
			rtt=${rtt:-"?"}
			if [[ "$loss" == "0" ]]; then
				printf "  %-6s to %-6s: OK (%s%% loss, %s ms)\n" \
					"${LABEL[$a]}" "${LABEL[$b]}" "$loss" "$rtt"
			else
				printf "  %-6s to %-6s: FAIL (%s%% loss)\n" \
					"${LABEL[$a]}" "${LABEL[$b]}" "${loss:-100}"
				all_ok=0
			fi
		done
	done

	echo ""
	if [[ $all_ok -eq 1 ]]; then
		echo "All pings passed."
	else
		echo "Some pings FAILED." >&2
	fi
}

# --------------------------------------------------------------------------- #
# Dispatch

# Check for a Cassini device before doing anything else (including sudo).
check_device

# Re-exec with sudo for commands that write to sysfs.
if [[ "$CMD" == "setup" || "$CMD" == "cleanup" || "$CMD" == "self-test" ]] && [ "$(id -u)" -ne 0 ]; then
	exec sudo --preserve-env=CXI_DEVICE "$0" "$@"
fi

case "$CMD" in
	list)
		cmd_list
		;;
	setup)
		[[ -n "$2" ]] || die "Usage: $0 setup <num_vfs> [--create-service PRESET|--use-service ID] [--no-ama] [--wait-ama]"
		[[ "$2" =~ ^[0-9]+$ ]] || die "num_vfs must be a non-negative integer"
		num_vfs="$2"
		shift 2
		parse_setup_options 0 "$@"
		cmd_setup "$num_vfs"
		;;
	cleanup)
		cmd_setup 0
		;;
	self-test)
		[[ -n "$2" ]] || die "Usage: $0 self-test <num_vfs> [--create-service PRESET|--use-service ID] [--no-ama] [--wait-ama] [--static-arp]"
		[[ "$2" =~ ^[0-9]+$ ]] || die "num_vfs must be a non-negative integer"
		num_vfs="$2"
		shift 2
		parse_setup_options 1 "$@"
		cmd_self_test "$num_vfs"
		;;
	*)
		echo "Usage: $0 {list|setup <N> [--create-service PRESET|--use-service ID] [--no-ama] [--wait-ama]|cleanup|self-test <N> [--create-service PRESET|--use-service ID] [--no-ama] [--wait-ama] [--static-arp]}" >&2
		exit 1
		;;
esac
