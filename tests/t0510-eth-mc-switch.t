#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Ethernet mc-switch test suite: pkt_tool send/recv across network namespaces.
# Part 1 (delivery):       unicast, broadcast, multicast, allmulti, promisc, VLAN/MAC.
# Part 2 (filter removal): delivery stops when mcast/allmulti/promisc filter is removed.
# Part 3 (txfwd/rxfanout): VF->PF BUM relay and PF->VF fan-out module parameter tests.

. ./preamble.sh

test_description="eth mc-switch: delivery, filter removal, and txfwd/rxfanout tests"

SHARNESS_TEST_DIRECTORY=/tmp/sharness-tests-$$
mkdir -p "$SHARNESS_TEST_DIRECTORY" || exit 1
SHARNESS_TEST_SRCDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export SHARNESS_TEST_DIRECTORY SHARNESS_TEST_SRCDIR

. ./sharness.sh

PKT_ROOT="$SHARNESS_TEST_SRCDIR/pkt_test"
# pkt_tool must be pre-built (e.g. by the top-level make); tests never build it.
PKT_TOOL="$PKT_ROOT/pkt_tool"
SVC_TOOL="$SHARNESS_TEST_SRCDIR/svc_tool/svc_tool"

CXI_DIR=$(realpath "$SHARNESS_TEST_SRCDIR/..")
VF_SCRIPT="$CXI_DIR/scripts/cxi_vf.sh"
SCRIPTS_DIR="$CXI_DIR/scripts"
ETH_KO="$CXI_DIR/drivers/net/ethernet/hpe/ss1/cxi-eth.ko"
SBL_KO="$CXI_DIR/../slingshot_base_link/drivers/net/ethernet/hpe/sbl/cxi-sbl.ko"
SL_KO="$CXI_DIR/../sl-driver/drivers/net/ethernet/hpe/sl/cxi-sl.ko"
SS1_KO="$CXI_DIR/drivers/net/ethernet/hpe/ss1/cxi-ss1.ko"
USER_KO="$CXI_DIR/drivers/net/ethernet/hpe/ss1/cxi-user.ko"
CXI_DEVICE=${CXI_DEVICE:-cxi0}
NUM_VFS=${NUM_VFS:-2}

# Load the full CXI driver stack (sbl, sl, ss1, user) if not already present.
# Each test runs in a fresh harness VM where nothing pre-loads the driver; when
# run inside a manually-started VM the modules may already be loaded, so this is
# idempotent (returns early when the device is already present).
load_cxi_stack() {
	[[ -d "/sys/class/cxi/$CXI_DEVICE" ]] && return 0
	insmod "$SBL_KO"  2>/dev/null || true
	insmod "$SL_KO"   2>/dev/null || true
	insmod "$SS1_KO" || { echo "ERROR: failed to insmod cxi-ss1 ($SS1_KO)" >&2; return 1; }
	insmod "$USER_KO" 2>/dev/null || true
	local i
	for ((i=0; i<50; i++)); do
		[[ -d "/sys/class/cxi/$CXI_DEVICE" ]] && return 0
		sleep 0.1
	done
	echo "ERROR: /sys/class/cxi/$CXI_DEVICE missing after loading driver stack" >&2
	return 1
}

# Create a parent CXI service with enough resources for NUM_VFS VF ethernet
# clients and assign it to each VF slot.  Must be called after the PF driver
# is loaded (sysfs vf/N/svc_id exists at PF probe time) and before VFs bind.
setup_vf_parent_svc() {
	[[ -x "$SVC_TOOL" ]] || {
		echo "ERROR: svc_tool not found at $SVC_TOOL" >&2
		return 1
	}

	if [[ -z "$VF_PARENT_SVC_ID" ]]; then
		local svc_id
		svc_id=$("$SVC_TOOL" eth "$CXI_DEVICE") || {
			echo "ERROR: failed to create parent service via svc_tool" >&2
			return 1
		}
		[[ -n "$svc_id" ]] || {
			echo "ERROR: svc_tool returned empty svc_id" >&2
			return 1
		}
		VF_PARENT_SVC_ID="$svc_id"
	fi

	# (Re)assign the parent service to every VF slot before the VFs bind.
	local i
	for ((i=0; i<NUM_VFS; i++)); do
		echo "$VF_PARENT_SVC_ID" > "/sys/class/cxi/$CXI_DEVICE/vf/$i/svc_id" || {
			echo "ERROR: failed to assign svc_id $VF_PARENT_SVC_ID to VF $i" >&2
			return 1
		}
	done
}

NS_PF=${NS_PF:-ns_pf}
NS_VF0=${NS_VF0:-ns_vf0}
NS_VF1=${NS_VF1:-ns_vf1}

# Packets for baseline delivery check (phase 1)
COUNT=${COUNT:-10}
INTERVAL_MS=${INTERVAL_MS:-50}
TIMEOUT_MS=${TIMEOUT_MS:-15000}
ETHERTYPE=${ETHERTYPE:-0x88B5}
CLEANUP_NAMESPACES=${CLEANUP_NAMESPACES:-1}

# Negative check: receiver timeout after filter removal.
# Must be long enough to allow the sender to complete and any in-flight
# packets to drain, but short enough to keep the test suite fast.
NEG_TIMEOUT_MS=${NEG_TIMEOUT_MS:-3000}
SETTLE_TIMEOUT_MS=${SETTLE_TIMEOUT_MS:-2500}
TRANSITION_DRAIN_TIMEOUT_MS=${TRANSITION_DRAIN_TIMEOUT_MS:-700}

MCAST_MAC=${MCAST_MAC:-01:00:20:00:00:97}
ALLMULTI_MAC=${ALLMULTI_MAC:-01:00:5e:10:10:10}
BROADCAST_MAC=${BROADCAST_MAC:-ff:ff:ff:ff:ff:ff}
PROMISC_DST_MAC=${PROMISC_DST_MAC:-02:de:ad:be:ef:01}

# Fixed window (ms) a counting receiver stays up to tally every copy delivered.
RX_WINDOW_MS=${RX_WINDOW_MS:-4000}
PROMISC_MCAST_MAC=${PROMISC_MCAST_MAC:-01:00:5e:0a:0b:0c}
TEST_UC_MAC_PF=${TEST_UC_MAC_PF:-02:aa:bb:cc:dd:01}
TEST_UC_MAC_VF=${TEST_UC_MAC_VF:-02:aa:bb:cc:dd:02}
TEST_UC_MAC_PF_NEW=${TEST_UC_MAC_PF_NEW:-02:aa:bb:cc:dd:03}

# VLAN configuration
VLAN_ID=${VLAN_ID:-100}
VLAN_TAG="vlan$VLAN_ID"

recv_pf_pid=""
recv_vf0_pid=""
recv_vf1_pid=""

cleanup() {
	if [[ -n "$recv_pf_pid" ]]; then
		kill "$recv_pf_pid" 2>/dev/null || true
		recv_pf_pid=""
	fi
	if [[ -n "$recv_vf0_pid" ]]; then
		kill "$recv_vf0_pid" 2>/dev/null || true
		recv_vf0_pid=""
	fi
	if [[ -n "$recv_vf1_pid" ]]; then
		kill "$recv_vf1_pid" 2>/dev/null || true
		recv_vf1_pid=""
	fi

	if [[ "$CLEANUP_NAMESPACES" -eq 1 ]]; then
		ns_remove_namespaces || true
	fi
}

ns_iface() {
	local ns="$1"
	ip -n "$ns" -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1
}

ns_mac() {
	local ns="$1"
	local iface="$2"
	ip netns exec "$ns" cat "/sys/class/net/$iface/address"
}

reset_namespaces() {
	ns_remove_namespaces 2>&1 || true
	local ok=0
	local try
	for try in 1 2 3; do
		ns_create_namespaces 2>&1 && { ok=1; break; }
		echo "WARN: create attempt $try failed, retrying..." >&2
		sleep 0.5
	done
	[[ "$ok" -eq 1 ]] || { echo "ERROR: Failed to create namespaces after retries" >&2; return 1; }
	local ns
	for ns in "$NS_PF" "$NS_VF0" "$NS_VF1"; do
		ip netns list | awk '{print $1}' | grep -qx "$ns" || \
			{ echo "ERROR: Namespace $ns missing" >&2; return 1; }
	done
}

check_dmesg() {
	local start="$1"
	if dmesg | tail -n +"$start" | grep -Eiq "BUG:|Oops:|Kernel panic"; then
		echo "FAIL: Critical kernel issue found in dmesg" >&5
		return 1
	fi
}

wait_receiver_ready() {
	local recv_pid="$1"
	local max_retries=100
	local retry_count=0

	# Wait for receiver process to become ready by checking if it's in a stable state
	# (no longer actively forking, has entered wait state)
	while [[ $retry_count -lt $max_retries ]]; do
		# Check if process is still running
		if ! kill -0 "$recv_pid" 2>/dev/null; then
			echo "ERROR: Receiver process $recv_pid died prematurely" >&2
			return 1
		fi

		# Check if process has entered wait state (Sleep/Running state)
		if [[ -r "/proc/$recv_pid/stat" ]]; then
			local stat_line stat_state
			stat_line=$(cat "/proc/$recv_pid/stat" 2>/dev/null)
			stat_state=$(echo "$stat_line" | awk '{print $3}')
			# S = sleeping (waiting for events), which means ready
			# D = disk sleep, R = running, T = stopped
			if [[ "$stat_state" == "S" ]] || [[ "$stat_state" == "R" ]]; then
				# Give the receiver additional time to bind socket and listen
				sleep 0.15
				return 0
			fi
		fi

		sleep 0.01
		((retry_count++))
	done

	echo "WARNING: Receiver readiness timeout after $((max_retries * 10))ms, proceeding anyway" >&2
	return 0
}


wait_maddr_absent() {
	local ns="$1"
	local iface="$2"
	local mac="$3"
	local timeout_ms="$4"
	local retries=$((timeout_ms / 50))
	local i

	for ((i=0; i<retries; i++)); do
		if ! ip -n "$ns" maddr show dev "$iface" | grep -Eiq "(^|[[:space:]])$mac($|[[:space:]])"; then
			return 0
		fi
		sleep 0.05
	done

	return 1
}

wait_maddr_present() {
	local ns="$1"
	local iface="$2"
	local mac="$3"
	local timeout_ms="$4"
	local retries=$((timeout_ms / 50))
	local i

	for ((i=0; i<retries; i++)); do
		if ip -n "$ns" maddr show dev "$iface" | grep -Eiq "(^|[[:space:]])$mac($|[[:space:]])"; then
			return 0
		fi
		sleep 0.05
	done

	return 1
}

wait_link_flag_state() {
	local ns="$1"
	local iface="$2"
	local flag="$3"
	local should_be_set="$4"
	local timeout_ms="$5"
	local retries=$((timeout_ms / 50))
	local i

	for ((i=0; i<retries; i++)); do
		local has_flag=0
		if ip -n "$ns" -o link show "$iface" | grep -qw "$flag"; then
			has_flag=1
		fi

		if [[ "$should_be_set" -eq 1 && "$has_flag" -eq 1 ]]; then
			return 0
		fi
		if [[ "$should_be_set" -eq 0 && "$has_flag" -eq 0 ]]; then
			return 0
		fi

		sleep 0.05
	done

	return 1
}

force_rxmode_baseline_off() {
	local ns="$1"
	local iface="$2"

	ip -n "$ns" link set "$iface" promisc off 2>/dev/null || true
	ip -n "$ns" link set "$iface" allmulticast off 2>/dev/null || true

	wait_link_flag_state "$ns" "$iface" PROMISC 0 "$SETTLE_TIMEOUT_MS" || return 1
	wait_link_flag_state "$ns" "$iface" ALLMULTI 0 "$SETTLE_TIMEOUT_MS" || return 1

	return 0
}

# ---------------------------------------------------------------------------
# Namespace management (identical to t0510)
# ---------------------------------------------------------------------------

# Find mc_sw_txfwd_mod_parm sysfs path.
txfwd_param_path() {
local m
for m in cxi_eth cxi-eth; do
if [[ -e "/sys/module/$m/parameters/mc_sw_txfwd_mod_parm" ]]; then
echo "/sys/module/$m/parameters/mc_sw_txfwd_mod_parm"
return 0
fi
done
return 1
}

# Find mc_sw_rxfanout_mod_parm sysfs path.
rxfanout_param_path() {
local m
for m in cxi_eth cxi-eth; do
if [[ -e "/sys/module/$m/parameters/mc_sw_rxfanout_mod_parm" ]]; then
echo "/sys/module/$m/parameters/mc_sw_rxfanout_mod_parm"
return 0
fi
done
return 1
}

# Extract matched packet count from receiver stderr (0 if absent).
rx_matched() {
local n
n=$(grep -oE 'matched [0-9]+' "$1" 2>/dev/null | awk '{print $2}' | tail -1)
echo "${n:-0}"
}

# Send COUNT frames; return matching copies tallied by receiver within RX_WINDOW_MS.
# $1 src_ns  $2 src_if  $3 rx_ns  $4 rx_if  $5 traffic  $6 dst  $7 payload
measure_rx() {
local errf rxpid
errf=$(mktemp)
ip netns exec "$3" "$PKT_TOOL" --mode recv --iface "$4" \
	--traffic "$5" --expect-dst "$6" --expect-payload "$7" \
	--count 1000000 --timeout-ms "$RX_WINDOW_MS" \
	--ethertype "$ETHERTYPE" >/dev/null 2>"$errf" &
rxpid=$!
wait_receiver_ready "$rxpid" || echo "WARN: measure_rx: receiver $rxpid did not become ready" >&2
ip netns exec "$1" "$PKT_TOOL" --mode send --iface "$2" \
	--dst-mac "$6" --traffic "$5" --count "$COUNT" \
	--interval-ms "$INTERVAL_MS" --payload "$7" \
	--ethertype "$ETHERTYPE" >/dev/null 2>&1
wait "$rxpid" 2>/dev/null || true
rx_matched "$errf"
rm -f "$errf"
}

# Send COUNT frames; count copies on source and peer; print "SRC PEER".
# PEER-SRC isolates relay contribution (switch copies cancel out).
# $1 src_ns  $2 src_if  $3 peer_ns  $4 peer_if  $5 traffic  $6 dst  $7 payload
measure_pair() {
local es ep sp pp
es=$(mktemp)
ep=$(mktemp)
ip netns exec "$1" "$PKT_TOOL" --mode recv --iface "$2" \
	--traffic "$5" --expect-dst "$6" --expect-payload "$7" \
	--count 1000000 --timeout-ms "$RX_WINDOW_MS" \
	--ethertype "$ETHERTYPE" >/dev/null 2>"$es" &
sp=$!
ip netns exec "$3" "$PKT_TOOL" --mode recv --iface "$4" \
	--traffic "$5" --expect-dst "$6" --expect-payload "$7" \
	--count 1000000 --timeout-ms "$RX_WINDOW_MS" \
	--ethertype "$ETHERTYPE" >/dev/null 2>"$ep" &
pp=$!
wait_receiver_ready "$sp" || echo "WARN: measure_pair: source receiver $sp did not become ready" >&2
wait_receiver_ready "$pp" || echo "WARN: measure_pair: peer receiver $pp did not become ready" >&2
ip netns exec "$1" "$PKT_TOOL" --mode send --iface "$2" \
	--dst-mac "$6" --traffic "$5" --count "$COUNT" \
	--interval-ms "$INTERVAL_MS" --payload "$7" \
	--ethertype "$ETHERTYPE" >/dev/null 2>&1
wait "$sp" 2>/dev/null || true
wait "$pp" 2>/dev/null || true
echo "$(rx_matched "$es") $(rx_matched "$ep")"
rm -f "$es" "$ep"
}

# ---------------------------------------------------------------------------
ensure_ns_exists() {
	local ns="$1"
	ip netns list | awk '{print $1}' | grep -qx "$ns" || ip netns add "$ns"
	ip -n "$ns" link set lo up
}

move_iface_to_ns() {
	local iface="$1"
	local ns="$2"

	if ip -n "$ns" -o link show "$iface" >/dev/null 2>&1; then
		return
	fi

	ip link set "$iface" netns "$ns"
	ip -n "$ns" link set "$iface" up
}

get_pf_iface() {
	find "/sys/class/cxi/$CXI_DEVICE/device/net" -mindepth 1 -maxdepth 1 \
		-type d -printf '%f\n' | head -1
}

wait_pf_iface() {
	local tries="${1:-20}"
	local delay="${2:-0.2}"
	local pf_if=""
	local i

	for ((i=0; i<tries; i++)); do
		pf_if=$(get_pf_iface)
		if [[ -n "$pf_if" ]]; then
			echo "$pf_if"
			return 0
		fi
		sleep "$delay"
	done

	return 1
}

get_vf_iface() {
	local idx="$1"
	find "/sys/class/cxi/$CXI_DEVICE/device/virtfn${idx}/net" \
		-mindepth 1 -maxdepth 1 -type d -printf '%f\n' | head -1
}

ns_create_namespaces() {
	[[ -x "$VF_SCRIPT" ]] || {
		echo "ERROR: Cannot find executable cxi_vf.sh at $VF_SCRIPT" >&2
		return 1
	}

	if [[ ! "$NUM_VFS" =~ ^[0-9]+$ ]]; then
		echo "ERROR: NUM_VFS must be a non-negative integer" >&2
		return 1
	fi

	if [[ ! -d "/sys/class/cxi/$CXI_DEVICE" ]]; then
		echo "ERROR: No /sys/class/cxi found. Start the VM first (./startvm.sh)," >&2
		echo "       then run this script inside the VM." >&2
		return 1
	fi

	if ! find "/sys/class/cxi/$CXI_DEVICE/device/net" -mindepth 1 -maxdepth 1 \
	     -type d >/dev/null 2>&1; then
		[[ -f "$ETH_KO" ]] || {
			echo "ERROR: PF netdev missing and cxi-eth.ko not found at $ETH_KO" >&2
			return 1
		}
		echo "Loading cxi-eth.ko to create PF netdev..."
		insmod "$ETH_KO" || true
	fi

	setup_vf_parent_svc || {
		echo "ERROR: failed to create/assign VF parent service" >&2
		return 1
	}

	echo "Provisioning $NUM_VFS VF(s) with $VF_SCRIPT setup"
	cd "$SCRIPTS_DIR"
	"$VF_SCRIPT" setup "$NUM_VFS" || {
		echo "ERROR: Failed to setup VFs" >&2
		return 1
	}

	local PF_IF
	PF_IF=$(wait_pf_iface 25 0.2 || true)
	if [[ -z "$PF_IF" ]]; then
		echo "PF netdev missing after VF setup. Reloading cxi-eth..."
		insmod "$ETH_KO" 2>/dev/null || true
		PF_IF=$(wait_pf_iface 25 0.2 || true)
	fi
	[[ -n "$PF_IF" ]] || {
		echo "ERROR: Unable to determine PF netdev for $CXI_DEVICE" >&2
		return 1
	}

	local i VF_MAC
	for ((i=0; i<NUM_VFS; i++)); do
		VF_MAC=$(printf "02:00:%02x:00:00:00" $((i+1)))
		ip link set "$PF_IF" vf "$i" mac "$VF_MAC" 2>/dev/null || true
		# trusted=on: allow macvlan/multicast filter install from VF
		# spoofchk=off: driver does not yet enforce source MAC on VF TX
		ip link set "$PF_IF" vf "$i" trust on spoofchk off 2>/dev/null || true
	done

	ensure_ns_exists ns_pf
	for ((i=0; i<NUM_VFS; i++)); do
		ensure_ns_exists "ns_vf${i}"
	done

	PF_IF=$(wait_pf_iface 10 0.2 || true)
	[[ -n "$PF_IF" ]] || {
		echo "ERROR: Unable to determine PF netdev for $CXI_DEVICE" >&2
		return 1
	}

	move_iface_to_ns "$PF_IF" ns_pf

	for ((i=0; i<NUM_VFS; i++)); do
		local VF_IF
		VF_IF=$(get_vf_iface "$i")
		[[ -n "$VF_IF" ]] || {
			echo "ERROR: Unable to determine netdev for VF $i" >&2
			return 1
		}
		move_iface_to_ns "$VF_IF" "ns_vf${i}"
	done

	echo ""
	echo "Namespaces created:"
	ip netns list
	return 0
}

ns_remove_namespaces() {
	if [[ -x "$VF_SCRIPT" ]]; then
		"$VF_SCRIPT" cleanup || true
	fi

	local ns
	for ns in $(ip netns list | awk '{print $1}' | \
	            grep -E '^ns_(pf|vf[0-9]+)$' || true); do
		ip netns del "$ns" 2>/dev/null || true
	done
	return 0
}

# ---------------------------------------------------------------------------
# Setup: wait for PF netdev and verify pkt_tool and svc_tool (shared across all tests)
# ---------------------------------------------------------------------------
test_expect_success "setup and check tools" "
echo \"Checking namespace management setup\" &&
load_cxi_stack &&
[[ -x \"$VF_SCRIPT\" ]] || {
	echo \"ERROR: driver stack load failed or VF_SCRIPT not executable: $VF_SCRIPT\" >&2
	return 1
} &&

# Note: Driver loading and PF netdev verification happens in ns_create_namespaces()
# called by individual tests. This avoids early setup failures on read-only filesystems.
# Tools must be pre-built; the test suite never compiles anything.
[[ -x \"\$PKT_TOOL\" ]] || {
	echo \"ERROR: pkt_tool not found at \$PKT_TOOL;\" >&2
	return 1
} &&
[[ -x \"\$SVC_TOOL\" ]] || {
	echo \"ERROR: svc_tool not found at \$SVC_TOOL;\" >&2
	return 1
}
"

# ---------------------------------------------------------------------------
# Test 1: PF multicast filter removal stops PF delivery
#
# Phase 1 (baseline): PF subscribes to MCAST_MAC; VF1 sends COUNT packets;
#                     PF receives them successfully.
# Filter removal: ip maddr del MCAST_MAC on PF interface.
# Phase 2 (negative): VF1 sends COUNT more packets; PF receiver waits
#                     NEG_TIMEOUT_MS and should time out with zero matches,
#                     confirming NAPI no longer delivers the group to PF.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Test 1: Unicast — VF1 to PF
# ---------------------------------------------------------------------------
test_expect_success "unicast: VF1 to PF" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

PF_MAC=\$(ns_mac \"\$NS_PF\" \"\$PF_IF\")
VF1_MAC=\$(ns_mac \"\$NS_VF1\" \"\$VF1_IF\")
[[ -n \"\$PF_MAC\" ]]  || { echo \"FAIL: No MAC for \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF1_MAC\" ]] || { echo \"FAIL: No MAC for \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Starting unicast receiver: \$NS_PF/\$PF_IF\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic normal \
	--expect-src \"\$VF1_MAC\" \
	--expect-dst \"\$PF_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"Sending \$COUNT unicast packets: \$NS_VF1/\$VF1_IF to \$PF_MAC\" >&5
if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$PF_MAC\" \
	--traffic normal \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"unicast-pkt-test\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid || { echo \"FAIL: Receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT unicast packets sent and received\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 2: Unicast — PF to VF0
# ---------------------------------------------------------------------------
test_expect_success "unicast: PF to VF0" "
DMESG_START=\$(dmesg | wc -l)
recv_vf0_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }

PF_MAC=\$(ns_mac \"\$NS_PF\" \"\$PF_IF\")
VF0_MAC=\$(ns_mac \"\$NS_VF0\" \"\$VF0_IF\")
[[ -n \"\$PF_MAC\" ]]  || { echo \"FAIL: No MAC for \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_MAC\" ]] || { echo \"FAIL: No MAC for \$NS_VF0\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up

echo \"Starting unicast receiver: \$NS_VF0/\$VF0_IF\" >&5
ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF0_IF\" \
	--traffic normal \
	--expect-src \"\$PF_MAC\" \
	--expect-dst \"\$VF0_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf0_pid=\$!
wait_receiver_ready \$recv_vf0_pid || return 1

echo \"Sending \$COUNT unicast packets: \$NS_PF/\$PF_IF to \$VF0_MAC\" >&5
if ! ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$PF_IF\" \
	--dst-mac \"\$VF0_MAC\" \
	--traffic normal \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"unicast-vf-test\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_vf0_pid 2>/dev/null || true
	return 1
fi

wait \$recv_vf0_pid || { echo \"FAIL: Receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT unicast packets sent by PF and received by VF0\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 3: Broadcast — PF to VF0 and VF1
# ---------------------------------------------------------------------------
test_expect_success "broadcast: PF to VF0 and VF1" "
DMESG_START=\$(dmesg | wc -l)
recv_vf0_pid=\"\"
recv_vf1_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Starting broadcast receiver: \$NS_VF0/\$VF0_IF\" >&5
ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF0_IF\" \
	--traffic broadcast \
	--expect-dst \"\$BROADCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf0_pid=\$!

echo \"Starting broadcast receiver: \$NS_VF1/\$VF1_IF\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF1_IF\" \
	--traffic broadcast \
	--expect-dst \"\$BROADCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf1_pid=\$!
wait_receiver_ready \$recv_vf0_pid || return 1
wait_receiver_ready \$recv_vf1_pid || return 1

echo \"Sending \$COUNT broadcast packets: \$NS_PF/\$PF_IF to \$BROADCAST_MAC\" >&5
if ! ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$PF_IF\" \
	--dst-mac \"\$BROADCAST_MAC\" \
	--traffic broadcast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"broadcast-pkt-test\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_vf0_pid \$recv_vf1_pid 2>/dev/null || true
	return 1
fi

wait \$recv_vf0_pid || { echo \"FAIL: VF0 receiver failed\" >&5; kill \$recv_vf1_pid 2>/dev/null; return 1; }
wait \$recv_vf1_pid || { echo \"FAIL: VF1 receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT broadcast packets received by both VF0 and VF1\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 4: Broadcast — VF0 to PF and VF1
# ---------------------------------------------------------------------------
test_expect_success "broadcast: VF0 to PF and VF1" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"
recv_vf1_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Starting broadcast receiver: \$NS_PF/\$PF_IF\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic broadcast \
	--expect-dst \"\$BROADCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!

echo \"Starting broadcast receiver: \$NS_VF1/\$VF1_IF\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF1_IF\" \
	--traffic broadcast \
	--expect-dst \"\$BROADCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf1_pid=\$!
wait_receiver_ready \$recv_pf_pid  || return 1
wait_receiver_ready \$recv_vf1_pid || return 1

echo \"Sending \$COUNT broadcast packets: \$NS_VF0/\$VF0_IF to \$BROADCAST_MAC\" >&5
if ! ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF0_IF\" \
	--dst-mac \"\$BROADCAST_MAC\" \
	--traffic broadcast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"broadcast-pkt-test\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_pf_pid \$recv_vf1_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid  || { echo \"FAIL: PF receiver failed\"  >&5; kill \$recv_vf1_pid 2>/dev/null; return 1; }
wait \$recv_vf1_pid || { echo \"FAIL: VF1 receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT broadcast packets received by both PF and VF1\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 5: Multicast — PF to VF0 and VF1
# ---------------------------------------------------------------------------
test_expect_success "multicast: PF to VF0 and VF1" "
DMESG_START=\$(dmesg | wc -l)
recv_vf0_pid=\"\"
recv_vf1_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Adding multicast addresses\" >&5
ip -n \"\$NS_VF0\" maddr add \"\$MCAST_MAC\" dev \"\$VF0_IF\"
ip -n \"\$NS_VF1\" maddr add \"\$MCAST_MAC\" dev \"\$VF1_IF\"

echo \"Starting multicast receiver: \$NS_VF0/\$VF0_IF\" >&5
ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF0_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf0_pid=\$!

echo \"Starting multicast receiver: \$NS_VF1/\$VF1_IF\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF1_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf1_pid=\$!
wait_receiver_ready \$recv_vf0_pid || return 1
wait_receiver_ready \$recv_vf1_pid || return 1

echo \"Sending \$COUNT multicast packets: \$NS_PF/\$PF_IF to \$MCAST_MAC\" >&5
if ! ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$PF_IF\" \
	--dst-mac \"\$MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"DEADBEEF\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_vf0_pid \$recv_vf1_pid 2>/dev/null || true
	return 1
fi

wait \$recv_vf0_pid || { echo \"FAIL: VF0 receiver failed\" >&5; kill \$recv_vf1_pid 2>/dev/null; return 1; }
wait \$recv_vf1_pid || { echo \"FAIL: VF1 receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT multicast packets received by both VF0 and VF1\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 6: Multicast — VF0 to PF and VF1
# ---------------------------------------------------------------------------
test_expect_success "multicast: VF0 to PF and VF1" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"
recv_vf1_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Adding multicast addresses\" >&5
ip -n \"\$NS_PF\"  maddr add \"\$MCAST_MAC\" dev \"\$PF_IF\"
ip -n \"\$NS_VF1\" maddr add \"\$MCAST_MAC\" dev \"\$VF1_IF\"

echo \"Starting multicast receiver: \$NS_PF/\$PF_IF\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!

echo \"Starting multicast receiver: \$NS_VF1/\$VF1_IF\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF1_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf1_pid=\$!
wait_receiver_ready \$recv_pf_pid  || return 1
wait_receiver_ready \$recv_vf1_pid || return 1

echo \"Sending \$COUNT multicast packets: \$NS_VF0/\$VF0_IF to \$MCAST_MAC\" >&5
if ! ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF0_IF\" \
	--dst-mac \"\$MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"DEADBEEF\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_pf_pid \$recv_vf1_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid  || { echo \"FAIL: PF receiver failed\"  >&5; kill \$recv_vf1_pid 2>/dev/null; return 1; }
wait \$recv_vf1_pid || { echo \"FAIL: VF1 receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT multicast packets received by both PF and VF1\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 7: Allmulti — PF to VF0 and VF1
# ---------------------------------------------------------------------------
test_expect_success "allmulti: PF to VF0 and VF1" "
DMESG_START=\$(dmesg | wc -l)
recv_vf0_pid=\"\"
recv_vf1_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

PF_MAC=\$(ns_mac \"\$NS_PF\" \"\$PF_IF\")
[[ -n \"\$PF_MAC\" ]] || { echo \"FAIL: No MAC for \$NS_PF\" >&5; return 1; }

ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" allmulticast on
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" allmulticast on
ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up

echo \"Starting allmulti receiver: \$NS_VF0/\$VF0_IF\" >&5
ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF0_IF\" \
	--traffic allmulti \
	--expect-src \"\$PF_MAC\" \
	--expect-dst \"\$ALLMULTI_MAC\" \
	--rx-allmulti \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf0_pid=\$!

echo \"Starting allmulti receiver: \$NS_VF1/\$VF1_IF\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF1_IF\" \
	--traffic allmulti \
	--expect-src \"\$PF_MAC\" \
	--expect-dst \"\$ALLMULTI_MAC\" \
	--rx-allmulti \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf1_pid=\$!
wait_receiver_ready \$recv_vf0_pid || return 1
wait_receiver_ready \$recv_vf1_pid || return 1

echo \"Sending \$COUNT allmulti packets: \$NS_PF/\$PF_IF to \$ALLMULTI_MAC\" >&5
if ! ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$PF_IF\" \
	--dst-mac \"\$ALLMULTI_MAC\" \
	--traffic allmulti \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"allmulti-pkt-test\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_vf0_pid \$recv_vf1_pid 2>/dev/null || true
	return 1
fi

wait \$recv_vf0_pid || { echo \"FAIL: VF0 receiver failed\" >&5; kill \$recv_vf1_pid 2>/dev/null; return 1; }
wait \$recv_vf1_pid || { echo \"FAIL: VF1 receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT allmulti packets received by both VF0 and VF1\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 8: Allmulti — VF0 to PF and VF1
# ---------------------------------------------------------------------------
test_expect_success "allmulti: VF0 to PF and VF1" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"
recv_vf1_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

VF0_MAC=\$(ns_mac \"\$NS_VF0\" \"\$VF0_IF\")
[[ -n \"\$VF0_MAC\" ]] || { echo \"FAIL: No MAC for \$NS_VF0\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  allmulticast on
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" allmulticast on
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up

echo \"Starting allmulti receiver: \$NS_PF/\$PF_IF\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic allmulti \
	--expect-src \"\$VF0_MAC\" \
	--expect-dst \"\$ALLMULTI_MAC\" \
	--rx-allmulti \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!

echo \"Starting allmulti receiver: \$NS_VF1/\$VF1_IF\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF1_IF\" \
	--traffic allmulti \
	--expect-src \"\$VF0_MAC\" \
	--expect-dst \"\$ALLMULTI_MAC\" \
	--rx-allmulti \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf1_pid=\$!
wait_receiver_ready \$recv_pf_pid  || return 1
wait_receiver_ready \$recv_vf1_pid || return 1

echo \"Sending \$COUNT allmulti packets: \$NS_VF0/\$VF0_IF to \$ALLMULTI_MAC\" >&5
if ! ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF0_IF\" \
	--dst-mac \"\$ALLMULTI_MAC\" \
	--traffic allmulti \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"allmulti-pkt-test\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_pf_pid \$recv_vf1_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid  || { echo \"FAIL: PF receiver failed\"  >&5; kill \$recv_vf1_pid 2>/dev/null; return 1; }
wait \$recv_vf1_pid || { echo \"FAIL: VF1 receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT allmulti packets received by both PF and VF1\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 9: Promisc — PF to VF0 and VF1
# ---------------------------------------------------------------------------
test_expect_success "promisc: PF to VF0 and VF1" "
DMESG_START=\$(dmesg | wc -l)
recv_vf0_pid=\"\"
recv_vf1_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

PF_MAC=\$(ns_mac \"\$NS_PF\" \"\$PF_IF\")
[[ -n \"\$PF_MAC\" ]] || { echo \"FAIL: No MAC for \$NS_PF\" >&5; return 1; }

ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" promisc on
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" promisc on
ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
sleep 0.5

echo \"Starting promisc receiver: \$NS_VF0/\$VF0_IF (dst=\$PROMISC_MCAST_MAC)\" >&5
ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF0_IF\" \
	--traffic multicast \
	--expect-src \"\$PF_MAC\" \
	--expect-dst \"\$PROMISC_MCAST_MAC\" \
	--rx-allmulti \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf0_pid=\$!

echo \"Starting promisc receiver: \$NS_VF1/\$VF1_IF (dst=\$PROMISC_MCAST_MAC)\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF1_IF\" \
	--traffic multicast \
	--expect-src \"\$PF_MAC\" \
	--expect-dst \"\$PROMISC_MCAST_MAC\" \
	--rx-allmulti \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf1_pid=\$!
wait_receiver_ready \$recv_vf0_pid || return 1
wait_receiver_ready \$recv_vf1_pid || return 1

echo \"Sending \$COUNT mcast packets: \$NS_PF/\$PF_IF to \$PROMISC_MCAST_MAC\" >&5
if ! ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$PF_IF\" \
	--dst-mac \"\$PROMISC_MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"promisc-vf-mcast\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_vf0_pid \$recv_vf1_pid 2>/dev/null || true
	return 1
fi

wait \$recv_vf0_pid || { echo \"FAIL: VF0 receiver failed\" >&5; kill \$recv_vf1_pid 2>/dev/null; return 1; }
wait \$recv_vf1_pid || { echo \"FAIL: VF1 receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT non-subscribed mcast packets received by both VF0 and VF1 in promisc mode\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 10: Promisc — VF0 to PF and VF1
# ---------------------------------------------------------------------------
test_expect_success "promisc: VF0 to PF and VF1" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"
recv_vf1_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

VF0_MAC=\$(ns_mac \"\$NS_VF0\" \"\$VF0_IF\")
[[ -n \"\$VF0_MAC\" ]] || { echo \"FAIL: No MAC for \$NS_VF0\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  promisc on
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" promisc on
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
sleep 0.5

echo \"Starting promisc receiver: \$NS_PF/\$PF_IF (dst=\$PROMISC_MCAST_MAC)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic multicast \
	--expect-src \"\$VF0_MAC\" \
	--expect-dst \"\$PROMISC_MCAST_MAC\" \
	--rx-allmulti \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!

echo \"Starting promisc receiver: \$NS_VF1/\$VF1_IF (dst=\$PROMISC_MCAST_MAC)\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF1_IF\" \
	--traffic multicast \
	--expect-src \"\$VF0_MAC\" \
	--expect-dst \"\$PROMISC_MCAST_MAC\" \
	--rx-allmulti \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf1_pid=\$!
wait_receiver_ready \$recv_pf_pid  || return 1
wait_receiver_ready \$recv_vf1_pid || return 1

echo \"Sending \$COUNT mcast packets: \$NS_VF0/\$VF0_IF to \$PROMISC_MCAST_MAC\" >&5
if ! ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF0_IF\" \
	--dst-mac \"\$PROMISC_MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"promisc-vf-mcast\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_pf_pid \$recv_vf1_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid  || { echo \"FAIL: PF receiver failed\"  >&5; kill \$recv_vf1_pid 2>/dev/null; return 1; }
wait \$recv_vf1_pid || { echo \"FAIL: VF1 receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT non-subscribed mcast packets received by both PF and VF1 in promisc mode\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 11: Unicast VLAN/MAC — VF1 to PF via VLAN interface
# ---------------------------------------------------------------------------
test_expect_success "uc_vlanmac: VF1 to PF via VLAN interface" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

# Bring up base interfaces
ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

# Create VLAN interfaces
echo \"Creating VLAN \$VLAN_ID interfaces on \$PF_IF and \$VF1_IF\" >&5
ip -n \"\$NS_PF\"  link add link \"\$PF_IF\"  name \"\$VLAN_TAG\" type vlan id \"\$VLAN_ID\"
ip -n \"\$NS_VF1\" link add link \"\$VF1_IF\" name \"\$VLAN_TAG\" type vlan id \"\$VLAN_ID\"
ip -n \"\$NS_PF\"  link set \"\$VLAN_TAG\" up
ip -n \"\$NS_VF1\" link set \"\$VLAN_TAG\" up

# Get base interface MACs
PF_MAC=\$(ns_mac \"\$NS_PF\" \"\$PF_IF\")
VF1_MAC=\$(ns_mac \"\$NS_VF1\" \"\$VF1_IF\")
[[ -n \"\$PF_MAC\" ]]  || { echo \"FAIL: No MAC for \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF1_MAC\" ]] || { echo \"FAIL: No MAC for \$NS_VF1\" >&5; return 1; }

echo \"PF base: \$PF_IF (\$PF_MAC), VF1 base: \$VF1_IF (\$VF1_MAC)\" >&5
echo \"Test UC MAC: PF VLAN=\$TEST_UC_MAC_PF, VF1 source=\$VF1_MAC\" >&5

# Program UC MAC address on PF VLAN interface.
echo \"Setting UC MAC on PF VLAN interface...\" >&5
ip -n \"\$NS_PF\" link set dev \"\$VLAN_TAG\" address \"\$TEST_UC_MAC_PF\"

sleep 0.3

echo \"Starting UC receiver: \$NS_PF/\$VLAN_TAG (dst=\$TEST_UC_MAC_PF)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VLAN_TAG\" \
	--traffic normal \
	--expect-src \"\$VF1_MAC\" \
	--expect-dst \"\$TEST_UC_MAC_PF\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"Sending \$COUNT UC VLAN packets: \$NS_VF1/\$VLAN_TAG to \$TEST_UC_MAC_PF\" >&5
if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VLAN_TAG\" \
	--dst-mac \"\$TEST_UC_MAC_PF\" \
	--traffic normal \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"vlanmac-uc-test\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid || { echo \"FAIL: Receiver failed\" >&5; return 1; }
echo \"PASS: \$COUNT VLAN/MAC packets sent and received\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 11b: Unicast VLAN/MAC on the VF side (mirror of the VF1->PF case).
# A trusted VF installs a distinct secondary unicast MAC on a VLAN
# sub-interface, then both directions of traffic are verified.
# NOTE: spoofchk enforcement of secondary UC MACs is deferred to a later commit.
# ---------------------------------------------------------------------------
test_expect_success "uc_vlanmac: PF <-> VF0 via distinct VF VLAN MAC (trust)" "
DMESG_START=\$(dmesg | wc -l)
recv_vf_pid=\"\"
recv_pf_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }

# Trust VF0 so it may install a secondary (VLAN) unicast MAC filter.
ip -n \"\$NS_PF\" link set \"\$PF_IF\" vf 0 trust on spoofchk off

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up

# Create VLAN interfaces
echo \"Creating VLAN \$VLAN_ID interfaces on \$PF_IF and \$VF0_IF\" >&5
ip -n \"\$NS_PF\"  link add link \"\$PF_IF\"  name \"\$VLAN_TAG\" type vlan id \"\$VLAN_ID\"
ip -n \"\$NS_VF0\" link add link \"\$VF0_IF\" name \"\$VLAN_TAG\" type vlan id \"\$VLAN_ID\"
ip -n \"\$NS_PF\"  link set \"\$VLAN_TAG\" up
ip -n \"\$NS_VF0\" link set \"\$VLAN_TAG\" up

# Program distinct UC MACs on each VLAN interface. Setting the VF VLAN MAC to a
# value different from the VF base MAC makes the VF install a secondary unicast
# filter (allowed because the VF is trusted).
echo \"PF VLAN MAC=\$TEST_UC_MAC_PF, VF0 VLAN MAC=\$TEST_UC_MAC_VF\" >&5
ip -n \"\$NS_PF\"  link set dev \"\$VLAN_TAG\" address \"\$TEST_UC_MAC_PF\"
ip -n \"\$NS_VF0\" link set dev \"\$VLAN_TAG\" address \"\$TEST_UC_MAC_VF\"
sleep 0.3

# Direction 1: PF -> VF0. VF0 receives on its secondary UC (VLAN) MAC.
echo \"Starting UC receiver: \$NS_VF0/\$VLAN_TAG (dst=\$TEST_UC_MAC_VF)\" >&5
ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VLAN_TAG\" \
	--traffic normal \
	--expect-src \"\$TEST_UC_MAC_PF\" \
	--expect-dst \"\$TEST_UC_MAC_VF\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf_pid=\$!
wait_receiver_ready \$recv_vf_pid || return 1

echo \"Sending \$COUNT UC VLAN packets: \$NS_PF/\$VLAN_TAG to \$TEST_UC_MAC_VF\" >&5
if ! ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VLAN_TAG\" \
	--dst-mac \"\$TEST_UC_MAC_VF\" \
	--traffic normal \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"vlanmac-uc-vf-rx\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: PF->VF0 sender error\" >&5
	kill \$recv_vf_pid 2>/dev/null || true
	return 1
fi
wait \$recv_vf_pid || { echo \"FAIL: VF0 did not receive on secondary UC MAC\" >&5; return 1; }
echo \"PASS: PF -> VF0 on distinct VLAN MAC\" >&5

# Direction 2: VF0 -> PF sourced from its secondary UC (VLAN) MAC.
echo \"Starting UC receiver: \$NS_PF/\$VLAN_TAG (dst=\$TEST_UC_MAC_PF)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VLAN_TAG\" \
	--traffic normal \
	--expect-src \"\$TEST_UC_MAC_VF\" \
	--expect-dst \"\$TEST_UC_MAC_PF\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"Sending \$COUNT UC VLAN packets: \$NS_VF0/\$VLAN_TAG to \$TEST_UC_MAC_PF\" >&5
if ! ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VLAN_TAG\" \
	--dst-mac \"\$TEST_UC_MAC_PF\" \
	--traffic normal \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"vlanmac-uc-vf-tx\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: VF0->PF sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	return 1
fi
wait \$recv_pf_pid || { echo \"FAIL: PF did not receive VF0 traffic from secondary UC MAC\" >&5; return 1; }
echo \"PASS: VF0 -> PF from distinct VLAN MAC\" >&5

cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 12: Unicast VLAN/MAC — stale PF secondary-UC filter must be removed
# after the PF's own unicast address list changes (VLAN interface MAC change).
# Verifies the PF's local unicast reconcile drops a stale secondary-UC filter
# when the VLAN interface MAC changes.
# ---------------------------------------------------------------------------
test_expect_success "uc_vlanmac: PF stale filter removed after VLAN MAC change" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

# Defensive: earlier tests (promisc/allmulti) leave the PF and/or VF
# interfaces in promiscuous/allmulticast mode, and namespace recreation
# does not reset those flags. Clear them explicitly so this test's
# negative filter check cannot be masked by leftover state from prior
# tests.
ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  promisc off allmulticast off
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" promisc off allmulticast off
sleep 0.3

echo \"Creating VLAN \$VLAN_ID interfaces on \$PF_IF and \$VF1_IF\" >&5
ip -n \"\$NS_PF\"  link add link \"\$PF_IF\"  name \"\$VLAN_TAG\" type vlan id \"\$VLAN_ID\"
ip -n \"\$NS_VF1\" link add link \"\$VF1_IF\" name \"\$VLAN_TAG\" type vlan id \"\$VLAN_ID\"
ip -n \"\$NS_PF\"  link set \"\$VLAN_TAG\" up
ip -n \"\$NS_VF1\" link set \"\$VLAN_TAG\" up

VF1_MAC=\$(ns_mac \"\$NS_VF1\" \"\$VF1_IF\")
[[ -n \"\$VF1_MAC\" ]] || { echo \"FAIL: No MAC for \$NS_VF1\" >&5; return 1; }

echo \"Old UC MAC: \$TEST_UC_MAC_PF, new UC MAC: \$TEST_UC_MAC_PF_NEW\" >&5

# Program the old UC MAC on the PF VLAN interface and confirm it is
# reachable, establishing the PF-owned secondary UC filter (vf_index == -1)
# that mc_sw_eth_reconcile_uc() must later treat as stale.
echo \"Setting old UC MAC on PF VLAN interface...\" >&5
ip -n \"\$NS_PF\" link set dev \"\$VLAN_TAG\" address \"\$TEST_UC_MAC_PF\"
sleep 0.3

echo \"Baseline: verifying old UC MAC \$TEST_UC_MAC_PF is reachable\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VLAN_TAG\" \
	--traffic normal \
	--expect-src \"\$VF1_MAC\" \
	--expect-dst \"\$TEST_UC_MAC_PF\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VLAN_TAG\" \
	--dst-mac \"\$TEST_UC_MAC_PF\" \
	--traffic normal \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"vlanmac-stale-baseline\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Baseline sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid || { echo \"FAIL: Baseline receiver failed; old UC MAC not reachable\" >&5; return 1; }
recv_pf_pid=\"\"
echo \"PASS: baseline old UC MAC \$TEST_UC_MAC_PF reachable\" >&5

# Change the VLAN interface's MAC address. This drops \$TEST_UC_MAC_PF from
# the PF netdev's own secondary unicast list and adds \$TEST_UC_MAC_PF_NEW,
# triggering ndo_set_rx_mode() -> cxi_eth_sync_rx_mode(vf_index=-1) ->
# mc_sw_eth_reconcile_uc(), which must remove the now-stale PF subscription
# for \$TEST_UC_MAC_PF.
echo \"Changing VLAN interface MAC from \$TEST_UC_MAC_PF to \$TEST_UC_MAC_PF_NEW\" >&5
ip -n \"\$NS_PF\" link set dev \"\$VLAN_TAG\" address \"\$TEST_UC_MAC_PF_NEW\"
sleep 0.3

# Negative check: the old UC MAC filter must no longer be programmed, so no
# frame sent to it should be delivered to the PF VLAN interface.
echo \"Verifying old UC MAC \$TEST_UC_MAC_PF is no longer reachable (stale filter check)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VLAN_TAG\" \
	--traffic normal \
	--expect-src \"\$VF1_MAC\" \
	--expect-dst \"\$TEST_UC_MAC_PF\" \
	--count 1 \
	--timeout-ms 2000 \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VLAN_TAG\" \
	--dst-mac \"\$TEST_UC_MAC_PF\" \
	--traffic normal \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"vlanmac-stale-negative\" \
	--ethertype \"\$ETHERTYPE\" >/dev/null 2>&1 || true

if wait \$recv_pf_pid; then
	echo \"FAIL: stale UC MAC filter for \$TEST_UC_MAC_PF still active after MAC change (mc_sw_eth_reconcile_uc bug)\" >&5
	return 1
fi
recv_pf_pid=\"\"
echo \"PASS: stale UC MAC \$TEST_UC_MAC_PF correctly removed\" >&5

# Positive check: the new UC MAC must now be reachable.
echo \"Verifying new UC MAC \$TEST_UC_MAC_PF_NEW is reachable\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VLAN_TAG\" \
	--traffic normal \
	--expect-src \"\$VF1_MAC\" \
	--expect-dst \"\$TEST_UC_MAC_PF_NEW\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VLAN_TAG\" \
	--dst-mac \"\$TEST_UC_MAC_PF_NEW\" \
	--traffic normal \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"vlanmac-stale-newmac\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: New-MAC sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid || { echo \"FAIL: New UC MAC \$TEST_UC_MAC_PF_NEW not reachable\" >&5; return 1; }
echo \"PASS: new UC MAC \$TEST_UC_MAC_PF_NEW reachable after change\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"


test_expect_success "mc_filter_removal: PF maddr del stops PF multicast delivery" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Applying deterministic RX mode baseline before mc_filter_removal test\" >&5
force_rxmode_baseline_off \"\$NS_PF\" \"\$PF_IF\" || {
	echo \"FAIL: Could not clear PF promisc/allmulti baseline\" >&5
	return 1
}
force_rxmode_baseline_off \"\$NS_VF1\" \"\$VF1_IF\" || {
	echo \"FAIL: Could not clear VF1 promisc/allmulti baseline\" >&5
	return 1
}

# --- Phase 1: baseline delivery ---
echo \"[Phase 1] Subscribing PF to \$MCAST_MAC\" >&5
ip -n \"\$NS_PF\" maddr add \"\$MCAST_MAC\" dev \"\$PF_IF\"

echo \"[Phase 1] Starting multicast receiver on PF\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 1] Sending \$COUNT multicast packets from VF1\" >&5
if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"mc-removal-phase1-seq\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Phase 1 sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid || { echo \"FAIL: Phase 1 PF receiver failed (baseline)\" >&5; return 1; }
recv_pf_pid=\"\"
echo \"[Phase 1] PASS: Baseline delivery confirmed\" >&5

# --- Filter removal ---
echo \"Removing PF multicast subscription for \$MCAST_MAC\" >&5
ip -n \"\$NS_PF\" maddr del \"\$MCAST_MAC\" dev \"\$PF_IF\"
if ! wait_maddr_absent \"\$NS_PF\" \"\$PF_IF\" \"\$MCAST_MAC\" \"\$SETTLE_TIMEOUT_MS\"; then
	echo \"FAIL: maddr entry \$MCAST_MAC still present after del on \$PF_IF\" >&5
	return 1
fi

# Drain a possible transition-time frame that raced with filter removal.
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \\
	--mode recv \\
	--iface \"\$PF_IF\" \\
	--traffic multicast \\
	--expect-dst \"\$MCAST_MAC\" \\
	--count 1 \\
	--timeout-ms \"\$TRANSITION_DRAIN_TIMEOUT_MS\" \\
	--ethertype \"\$ETHERTYPE\" >/dev/null 2>&1 || true

# --- Phase 2: negative check (delivery must stop) ---
echo \"[Phase 2] Starting negative receiver on PF (should time out)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--expect-payload \"mc-removal-phase2-seq\" \
	--count 1 \
	--timeout-ms \"\$NEG_TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 2] Sending \$COUNT multicast packets from VF1\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"mc-removal-phase2-seq\" \
	--ethertype \"\$ETHERTYPE\" || true

if wait \$recv_pf_pid; then
	echo \"FAIL: PF received multicast packets after maddr del\" >&5
	recv_pf_pid=\"\"
	return 1
fi
recv_pf_pid=\"\"
echo \"[Phase 2] PASS: PF did not receive multicast after filter removal\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 2: Broadcast filter removal stops broadcast delivery to PF
#
# Phase 1 (baseline): PF receives packets sent to ff:ff:ff:ff:ff:ff.
# Filter removal: clear IFF_BROADCAST on PF interface (ifconfig -broadcast).
# Phase 2 (negative): VF1 sends to ff:ff:ff:ff:ff:ff; PF receiver should
#                     time out because broadcast filtering was removed.
# Note: Some interfaces keep IFF_BROADCAST immutable; in that case this test
#       is treated as not applicable and exits successfully.
# ---------------------------------------------------------------------------
test_expect_success "broadcast_filter_removal: PF broadcast filter removal stops broadcast delivery" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Applying deterministic RX mode baseline before broadcast test\" >&5
force_rxmode_baseline_off \"\$NS_PF\" \"\$PF_IF\" || {
	echo \"FAIL: Could not clear PF promisc/allmulti baseline\" >&5
	return 1
}
force_rxmode_baseline_off \"\$NS_VF1\" \"\$VF1_IF\" || {
	echo \"FAIL: Could not clear VF1 promisc/allmulti baseline\" >&5
	return 1
}

# --- Phase 1: baseline broadcast delivery ---
echo \"[Phase 1] Starting broadcast receiver on PF\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic broadcast \
	--expect-dst \"\$BROADCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 1] Sending \$COUNT broadcast packets from VF1\" >&5
if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$BROADCAST_MAC\" \
	--traffic broadcast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"bcast-removal-phase1-seq\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Phase 1 sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid || { echo \"FAIL: Phase 1 PF receiver failed (baseline)\" >&5; return 1; }
recv_pf_pid=\"\"
echo \"[Phase 1] PASS: Baseline broadcast delivery confirmed\" >&5

# --- Filter removal ---
echo \"Removing broadcast filter by clearing IFF_BROADCAST on PF\" >&5
ip netns exec \"\$NS_PF\" ifconfig \"\$PF_IF\" -broadcast || true

if ! wait_link_flag_state \"\$NS_PF\" \"\$PF_IF\" BROADCAST 0 \"\$SETTLE_TIMEOUT_MS\"; then
	echo \"SKIP: IFF_BROADCAST is immutable on \$PF_IF; skipping filter-removal delivery check\" >&5
	cleanup
	return 0
fi

# Drain a possible transition-time frame that raced with broadcast disable.
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \\
	--mode recv \\
	--iface \"\$PF_IF\" \\
	--traffic broadcast \\
	--expect-dst \"\$BROADCAST_MAC\" \\
	--count 1 \\
	--timeout-ms \"\$TRANSITION_DRAIN_TIMEOUT_MS\" \\
	--ethertype \"\$ETHERTYPE\" >/dev/null 2>&1 || true

# --- Phase 2: negative check ---
echo \"[Phase 2] Starting negative receiver on PF (should time out)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic broadcast \
	--expect-dst \"\$BROADCAST_MAC\" \
	--expect-payload \"bcast-removal-phase2-seq\" \
	--count 1 \
	--timeout-ms \"\$NEG_TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 2] Sending \$COUNT broadcast packets from VF1\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$BROADCAST_MAC\" \
	--traffic broadcast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"bcast-removal-phase2-seq\" \
	--ethertype \"\$ETHERTYPE\" || true

if wait \$recv_pf_pid; then
	echo \"FAIL: PF received broadcast packets after broadcast filter removal\" >&5
	recv_pf_pid=\"\"
	return 1
fi
recv_pf_pid=\"\"
echo \"[Phase 2] PASS: PF did not receive broadcast after filter removal\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 3: VF0 multicast filter removal stops VF0 delivery; PF unaffected
#
# Phase 1 (baseline): Both PF and VF0 subscribe to MCAST_MAC; VF1 sends;
#                     both PF and VF0 receive.
# Filter removal: ip maddr del MCAST_MAC on VF0 only.
# Phase 2 (split check):
#   - PF still receives (positive: proxy state retains PF subscription).
#   - VF0 no longer receives (negative: VF0 bitmap cleared in proxy state).
# ---------------------------------------------------------------------------
test_expect_success "mc_filter_removal: VF0 maddr del stops VF0 delivery; PF unaffected" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"
recv_vf0_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Applying deterministic RX mode baseline before VF0 multicast removal test\" >&5
force_rxmode_baseline_off \"\$NS_PF\" \"\$PF_IF\" || {
	echo \"FAIL: Could not clear PF promisc/allmulti baseline\" >&5
	return 1
}
force_rxmode_baseline_off \"\$NS_VF0\" \"\$VF0_IF\" || {
	echo \"FAIL: Could not clear VF0 promisc/allmulti baseline\" >&5
	return 1
}
force_rxmode_baseline_off \"\$NS_VF1\" \"\$VF1_IF\" || {
	echo \"FAIL: Could not clear VF1 promisc/allmulti baseline\" >&5
	return 1
}

# --- Phase 1: baseline delivery to both PF and VF0 ---
echo \"[Phase 1] Subscribing PF and VF0 to \$MCAST_MAC\" >&5
ip -n \"\$NS_PF\"  maddr add \"\$MCAST_MAC\" dev \"\$PF_IF\"
ip -n \"\$NS_VF0\" maddr add \"\$MCAST_MAC\" dev \"\$VF0_IF\"

echo \"[Phase 1] Starting receivers on PF and VF0\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!

ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF0_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf0_pid=\$!
wait_receiver_ready \$recv_pf_pid  || return 1
wait_receiver_ready \$recv_vf0_pid || return 1

echo \"[Phase 1] Sending \$COUNT multicast packets from VF1\" >&5
if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--payload \"vf0-mc-phase1-seq\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Phase 1 sender error\" >&5
	kill \$recv_pf_pid \$recv_vf0_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid  || { echo \"FAIL: Phase 1 PF receiver failed\"  >&5; kill \$recv_vf0_pid 2>/dev/null; return 1; }
wait \$recv_vf0_pid || { echo \"FAIL: Phase 1 VF0 receiver failed\" >&5; return 1; }
recv_pf_pid=\"\"
recv_vf0_pid=\"\"
echo \"[Phase 1] PASS: Baseline delivery to both PF and VF0 confirmed\" >&5

# --- Filter removal on VF0 only ---
echo \"Removing VF0 multicast subscription for \$MCAST_MAC\" >&5
ip -n \"\$NS_VF0\" maddr del \"\$MCAST_MAC\" dev \"\$VF0_IF\"
if ! wait_maddr_absent \"\$NS_VF0\" \"\$VF0_IF\" \"\$MCAST_MAC\" \"\$SETTLE_TIMEOUT_MS\"; then
	echo \"FAIL: maddr entry \$MCAST_MAC still present after del on \$VF0_IF\" >&5
	return 1
fi

# Drain a possible transition-time frame that raced with VF0 filter removal.
ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \\
	--mode recv \\
	--iface \"\$VF0_IF\" \\
	--traffic multicast \\
	--expect-dst \"\$MCAST_MAC\" \\
	--count 1 \\
	--timeout-ms \"\$TRANSITION_DRAIN_TIMEOUT_MS\" \\
	--ethertype \"\$ETHERTYPE\" >/dev/null 2>&1 || true

# --- Phase 2: PF still receives; VF0 does not ---
echo \"[Phase 2] Starting positive receiver on PF (must still receive)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!

echo \"[Phase 2] Starting negative receiver on VF0 (must NOT receive)\" >&5
ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$VF0_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--expect-payload \"vf0-mc-phase2-seq\" \
	--count 1 \
	--timeout-ms \"\$NEG_TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_vf0_pid=\$!
wait_receiver_ready \$recv_pf_pid  || return 1
wait_receiver_ready \$recv_vf0_pid || return 1

echo \"[Phase 2] Sending \$COUNT multicast packets from VF1\" >&5
if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--payload \"vf0-mc-phase2-seq\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Phase 2 sender error\" >&5
	kill \$recv_pf_pid \$recv_vf0_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid || { echo \"FAIL: Phase 2 PF lost delivery after VF0-only filter removal\" >&5; kill \$recv_vf0_pid 2>/dev/null; return 1; }
recv_pf_pid=\"\"
echo \"[Phase 2] PASS: PF still receives after VF0 filter removal\" >&5

if wait \$recv_vf0_pid; then
	echo \"FAIL: VF0 received multicast packets after its own maddr del\" >&5
	recv_vf0_pid=\"\"
	return 1
fi
recv_vf0_pid=\"\"
echo \"[Phase 2] PASS: VF0 did not receive multicast after filter removal\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 4: Allmulti flag removal stops non-subscribed multicast delivery to PF
#
# Phase 1 (baseline): PF sets allmulticast on; receives packets sent to
#                     ALLMULTI_MAC (a group PF has NOT explicitly joined).
# Filter removal: ip link set PF allmulticast off.
# Phase 2 (negative): VF1 sends to ALLMULTI_MAC; PF receiver should time
#                     out since allmulti flag is cleared in the shared
#                     proxy_filter state and NAPI will not deliver the frame.
# ---------------------------------------------------------------------------
test_expect_success "allmulti_off: PF allmulticast off stops non-subscribed mcast delivery" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

VF1_MAC=\$(ns_mac \"\$NS_VF1\" \"\$VF1_IF\")
[[ -n \"\$VF1_MAC\" ]] || { echo \"FAIL: No MAC for \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Applying deterministic RX mode baseline before allmulti test\" >&5
force_rxmode_baseline_off \"\$NS_PF\" \"\$PF_IF\" || {
	echo \"FAIL: Could not clear PF promisc/allmulti baseline\" >&5
	return 1
}
force_rxmode_baseline_off \"\$NS_VF0\" \"\$VF0_IF\" || {
	echo \"FAIL: Could not clear VF0 promisc/allmulti baseline\" >&5
	return 1
}
force_rxmode_baseline_off \"\$NS_VF1\" \"\$VF1_IF\" || {
	echo \"FAIL: Could not clear VF1 promisc/allmulti baseline\" >&5
	return 1
}


# --- Phase 1: baseline with allmulticast on ---
echo \"[Phase 1] Enabling allmulticast on PF\" >&5
ip -n \"\$NS_PF\" link set \"\$PF_IF\" allmulticast on

echo \"[Phase 1] Starting allmulti receiver on PF\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic allmulti \
	--expect-src \"\$VF1_MAC\" \
	--expect-dst \"\$ALLMULTI_MAC\" \
	--rx-allmulti \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 1] Sending \$COUNT allmulti packets from VF1 to \$ALLMULTI_MAC\" >&5
if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$ALLMULTI_MAC\" \
	--traffic allmulti \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"allmulti-phase1-seq\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Phase 1 sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid || { echo \"FAIL: Phase 1 PF receiver failed (baseline)\" >&5; return 1; }
recv_pf_pid=\"\"
echo \"[Phase 1] PASS: Baseline allmulti delivery confirmed\" >&5

# --- Filter removal ---
echo \"Disabling allmulticast on PF\" >&5
ip -n \"\$NS_PF\" link set \"\$PF_IF\" allmulticast off
if ! wait_link_flag_state \"\$NS_PF\" \"\$PF_IF\" ALLMULTI 0 \"\$SETTLE_TIMEOUT_MS\"; then
	echo \"FAIL: IFF_ALLMULTI remains set on \$PF_IF after allmulticast off\" >&5
	return 1
fi

# Drain a possible transition-time frame that raced with allmulti disable.
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \\
	--mode recv \\
	--iface \"\$PF_IF\" \\
	--traffic allmulti \\
	--expect-src \"\$VF1_MAC\" \\
	--expect-dst \"\$ALLMULTI_MAC\" \\
	--count 1 \\
	--timeout-ms \"\$TRANSITION_DRAIN_TIMEOUT_MS\" \\
	--ethertype \"\$ETHERTYPE\" >/dev/null 2>&1 || true

# --- Phase 2: negative check ---
# NOTE: do NOT use --rx-allmulti here; that would call PACKET_MR_ALLMULTI and
# re-enable IFF_ALLMULTI on the interface, defeating the test.
echo \"[Phase 2] Starting negative receiver on PF (should time out)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic allmulti \
	--expect-src \"\$VF1_MAC\" \
	--expect-dst \"\$ALLMULTI_MAC\" \
	--expect-payload \"allmulti-phase2-seq\" \
	--count 1 \
	--timeout-ms \"\$NEG_TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 2] Sending \$COUNT allmulti packets from VF1\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$ALLMULTI_MAC\" \
	--traffic allmulti \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"allmulti-phase2-seq\" \
	--ethertype \"\$ETHERTYPE\" || true

if wait \$recv_pf_pid; then
	echo \"FAIL: PF received non-subscribed multicast after allmulticast off\" >&5
	recv_pf_pid=\"\"
	return 1
fi
recv_pf_pid=\"\"
echo \"[Phase 2] PASS: PF did not receive after allmulticast off\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 5: Promisc flag removal stops unmatched unicast delivery to PF
#
# Phase 1 (baseline): PF sets promisc on; receives packets sent to
#                     PROMISC_DST_MAC (a UC address PF does not own).
# Filter removal: ip link set PF promisc off.
# Phase 2 (negative): VF1 sends to the same unmatched UC MAC; PF receiver
#                     should time out as NAPI no longer delivers the frame.
#
# Note: TX checksum offload on VF1 must be disabled when PF is in promisc
# mode (nic-emu HW limitation), and restored after.
# ---------------------------------------------------------------------------
test_expect_success "promisc_off: PF promisc off stops unmatched UC delivery" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

VF1_MAC=\$(ns_mac \"\$NS_VF1\" \"\$VF1_IF\")
[[ -n \"\$VF1_MAC\" ]] || { echo \"FAIL: No MAC for \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Applying deterministic RX mode baseline before promisc test\" >&5
force_rxmode_baseline_off \"\$NS_PF\" \"\$PF_IF\" || {
	echo \"FAIL: Could not clear PF promisc/allmulti baseline\" >&5
	return 1
}
force_rxmode_baseline_off \"\$NS_VF0\" \"\$VF0_IF\" || {
	echo \"FAIL: Could not clear VF0 promisc/allmulti baseline\" >&5
	return 1
}
force_rxmode_baseline_off \"\$NS_VF1\" \"\$VF1_IF\" || {
	echo \"FAIL: Could not clear VF1 promisc/allmulti baseline\" >&5
	return 1
}

echo \"Disabling TX checksum offload on \$VF1_IF (promisc mode workaround)\" >&5
ip netns exec \"\$NS_VF1\" ethtool -K \"\$VF1_IF\" tx-checksumming off

# --- Phase 1: baseline with promisc on ---
echo \"[Phase 1] Enabling promisc on PF\" >&5
ip -n \"\$NS_PF\" link set \"\$PF_IF\" promisc on

echo \"[Phase 1] Starting promisc receiver on PF (dst=\$PROMISC_DST_MAC)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic normal \
	--expect-src \"\$VF1_MAC\" \
	--expect-dst \"\$PROMISC_DST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 1] Sending \$COUNT packets to \$PROMISC_DST_MAC from VF1\" >&5
if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$PROMISC_DST_MAC\" \
	--traffic normal \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"promisc-phase1-seq\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Phase 1 sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	ip netns exec \"\$NS_VF1\" ethtool -K \"\$VF1_IF\" tx-checksumming on || true
	return 1
fi

wait \$recv_pf_pid || {
	echo \"FAIL: Phase 1 PF receiver failed (baseline)\" >&5
	ip netns exec \"\$NS_VF1\" ethtool -K \"\$VF1_IF\" tx-checksumming on || true
	return 1
}
recv_pf_pid=\"\"
echo \"[Phase 1] PASS: Baseline promisc delivery confirmed\" >&5

# --- Filter removal ---
echo \"Disabling promisc on PF\" >&5
ip -n \"\$NS_PF\" link set \"\$PF_IF\" promisc off
if ! wait_link_flag_state \"\$NS_PF\" \"\$PF_IF\" PROMISC 0 \"\$SETTLE_TIMEOUT_MS\"; then
	echo \"FAIL: IFF_PROMISC remains set on \$PF_IF after promisc off\" >&5
	return 1
fi

# Drain a possible transition-time frame that raced with promisc disable.
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \\
	--mode recv \\
	--iface \"\$PF_IF\" \\
	--traffic normal \\
	--expect-src \"\$VF1_MAC\" \\
	--expect-dst \"\$PROMISC_DST_MAC\" \\
	--count 1 \\
	--timeout-ms \"\$TRANSITION_DRAIN_TIMEOUT_MS\" \\
	--ethertype \"\$ETHERTYPE\" >/dev/null 2>&1 || true

# --- Phase 2: negative check ---
echo \"[Phase 2] Starting negative receiver on PF (should time out)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic normal \
	--expect-src \"\$VF1_MAC\" \
	--expect-dst \"\$PROMISC_DST_MAC\" \
	--expect-payload \"promisc-phase2-seq\" \
	--count 1 \
	--timeout-ms \"\$NEG_TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 2] Sending \$COUNT packets to \$PROMISC_DST_MAC from VF1\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$PROMISC_DST_MAC\" \
	--traffic normal \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"promisc-phase2-seq\" \
	--ethertype \"\$ETHERTYPE\" || true

if wait \$recv_pf_pid; then
	echo \"FAIL: PF received unmatched UC packet after promisc off\" >&5
	recv_pf_pid=\"\"
	ip netns exec \"\$NS_VF1\" ethtool -K \"\$VF1_IF\" tx-checksumming on || true
	return 1
fi
recv_pf_pid=\"\"
echo \"[Phase 2] PASS: PF did not receive after promisc off\" >&5

echo \"Re-enabling TX checksum offload on \$VF1_IF\" >&5
ip netns exec \"\$NS_VF1\" ethtool -K \"\$VF1_IF\" tx-checksumming on || true
cleanup
check_dmesg \"\$DMESG_START\"
"

# ---------------------------------------------------------------------------
# Test 6: Multicast filter re-add restores delivery after removal
#
# Phase 1 (baseline): PF subscribes; receives.
# Phase 2 (removal):  PF unsubscribes; receiver times out (no delivery).
# Phase 3 (re-add):   PF re-subscribes; receives again.
#
# This validates the full add/remove/re-add lifecycle of the shared
# multicast xarray state in the proxy_filter.
# ---------------------------------------------------------------------------
test_expect_success "mc_filter_readd: delivery resumes after maddr del and re-add" "
DMESG_START=\$(dmesg | wc -l)
recv_pf_pid=\"\"

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

PF_IF=\$(ns_iface \"\$NS_PF\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$PF_IF\" ]]  || { echo \"FAIL: No interface in \$NS_PF\"  >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_PF\"  link set \"\$PF_IF\"  up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Applying deterministic RX mode baseline before mc_filter_readd test\" >&5
force_rxmode_baseline_off \"\$NS_PF\" \"\$PF_IF\" || {
	echo \"FAIL: Could not clear PF promisc/allmulti baseline\" >&5
	return 1
}
force_rxmode_baseline_off \"\$NS_VF1\" \"\$VF1_IF\" || {
	echo \"FAIL: Could not clear VF1 promisc/allmulti baseline\" >&5
	return 1
}

# --- Phase 1: baseline delivery ---
echo \"[Phase 1] Subscribing PF to \$MCAST_MAC\" >&5
ip -n \"\$NS_PF\" maddr add \"\$MCAST_MAC\" dev \"\$PF_IF\"

echo \"[Phase 1] Starting multicast receiver on PF\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 1] Sending \$COUNT multicast packets from VF1\" >&5
if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"mc-readd-phase1-seq\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Phase 1 sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid || { echo \"FAIL: Phase 1 PF receiver failed (baseline)\" >&5; return 1; }
recv_pf_pid=\"\"
echo \"[Phase 1] PASS: Baseline delivery confirmed\" >&5

# --- Phase 2: removal confirmation ---
echo \"Removing PF multicast subscription for \$MCAST_MAC\" >&5
ip -n \"\$NS_PF\" maddr del \"\$MCAST_MAC\" dev \"\$PF_IF\"
if ! wait_maddr_absent \"\$NS_PF\" \"\$PF_IF\" \"\$MCAST_MAC\" \"\$SETTLE_TIMEOUT_MS\"; then
	echo \"FAIL: maddr entry \$MCAST_MAC still present after del on \$PF_IF\" >&5
	return 1
fi

# Drain a possible transition-time frame that raced with filter removal.
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \\
	--mode recv \\
	--iface \"\$PF_IF\" \\
	--traffic multicast \\
	--expect-dst \"\$MCAST_MAC\" \\
	--count 1 \\
	--timeout-ms \"\$TRANSITION_DRAIN_TIMEOUT_MS\" \\
	--ethertype \"\$ETHERTYPE\" >/dev/null 2>&1 || true

echo \"[Phase 2] Starting negative receiver on PF (should time out)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--expect-payload \"mc-readd-phase2-seq\" \
	--count 1 \
	--timeout-ms \"\$NEG_TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 2] Sending \$COUNT multicast packets from VF1\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"mc-readd-phase2-seq\" \
	--ethertype \"\$ETHERTYPE\" || true

if wait \$recv_pf_pid; then
	echo \"FAIL: PF received multicast after removal (phase 2)\" >&5
	recv_pf_pid=\"\"
	return 1
fi
recv_pf_pid=\"\"
echo \"[Phase 2] PASS: Delivery stopped after filter removal\" >&5

# --- Phase 3: re-add restores delivery ---
echo \"Re-adding PF multicast subscription for \$MCAST_MAC\" >&5
ip -n \"\$NS_PF\" maddr add \"\$MCAST_MAC\" dev \"\$PF_IF\"
if ! wait_maddr_present \"\$NS_PF\" \"\$PF_IF\" \"\$MCAST_MAC\" \"\$SETTLE_TIMEOUT_MS\"; then
	echo \"FAIL: maddr entry \$MCAST_MAC not present after re-add on \$PF_IF\" >&5
	return 1
fi

echo \"[Phase 3] Starting multicast receiver on PF (should receive again)\" >&5
ip netns exec \"\$NS_PF\" \"\$PKT_TOOL\" \
	--mode recv \
	--iface \"\$PF_IF\" \
	--traffic multicast \
	--expect-dst \"\$MCAST_MAC\" \
	--count \"\$COUNT\" \
	--timeout-ms \"\$TIMEOUT_MS\" \
	--ethertype \"\$ETHERTYPE\" &
recv_pf_pid=\$!
wait_receiver_ready \$recv_pf_pid || return 1

echo \"[Phase 3] Sending \$COUNT multicast packets from VF1\" >&5
if ! ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" \
	--mode send \
	--iface \"\$VF1_IF\" \
	--dst-mac \"\$MCAST_MAC\" \
	--traffic multicast \
	--count \"\$COUNT\" \
	--interval-ms \"\$INTERVAL_MS\" \
	--payload \"mc-readd-phase3-seq\" \
	--ethertype \"\$ETHERTYPE\"; then
	echo \"FAIL: Phase 3 sender error\" >&5
	kill \$recv_pf_pid 2>/dev/null || true
	return 1
fi

wait \$recv_pf_pid || { echo \"FAIL: Phase 3 PF receiver failed (delivery not restored after re-add)\" >&5; return 1; }
recv_pf_pid=\"\"
echo \"[Phase 3] PASS: Delivery restored after filter re-add\" >&5
cleanup
check_dmesg \"\$DMESG_START\"
"


test_expect_success "rxfanout param: default on, read-only" "
P=\$(rxfanout_param_path || true)
if [[ -z \"\$P\" ]]; then
	insmod \"$ETH_KO\" 2>/dev/null || true
	sleep 1
	P=\$(rxfanout_param_path || true)
fi
[[ -n \"\$P\" ]] || { echo \"FAIL: mc_sw_rxfanout_mod_parm not found (feature compiled out?)\" >&5; return 1; }

val=\$(cat \"\$P\")
[[ \"\$val\" == Y || \"\$val\" == 1 ]] || { echo \"FAIL: default not on (got \$val)\" >&5; return 1; }

# 0444: the sysfs node must not be writable.
perm=\$(stat -c '%a' \"\$P\")
[[ \"\$perm\" == 444 ]] || { echo \"FAIL: expected mode 444, got \$perm\" >&5; return 1; }
if echo Y > \"\$P\" 2>/dev/null; then
	echo \"FAIL: rxfanout param unexpectedly writable at runtime\" >&5
	return 1
fi

echo \"PASS: rxfanout param exists, defaults on, and is read-only\" >&5
"

test_expect_success "txfwd param: default on, toggles" "
P=\$(txfwd_param_path || true)
if [[ -z \"\$P\" ]]; then
	# cxi-eth may not be loaded yet on this test run.
	insmod \"$ETH_KO\" 2>/dev/null || true
	sleep 1
	P=\$(txfwd_param_path || true)
fi
[[ -n \"\$P\" ]] || { echo \"FAIL: mc_sw_txfwd_mod_parm not found (feature compiled out?)\" >&5; return 1; }

val=\$(cat \"\$P\")
[[ \"\$val\" == Y || \"\$val\" == 1 ]] || { echo \"FAIL: default not on (got \$val)\" >&5; return 1; }

echo Y > \"\$P\" || { echo \"FAIL: cannot enable (param not writable)\" >&5; return 1; }
val=\$(cat \"\$P\")
[[ \"\$val\" == Y || \"\$val\" == 1 ]] || { echo \"FAIL: enable did not take (got \$val)\" >&5; echo N > \"\$P\"; return 1; }

echo N > \"\$P\" || { echo \"FAIL: cannot disable\" >&5; return 1; }
val=\$(cat \"\$P\")
[[ \"\$val\" == N || \"\$val\" == 0 ]] || { echo \"FAIL: disable did not take (got \$val)\" >&5; return 1; }

echo \"PASS: txfwd param defaults on and toggles via sysfs\" >&5
"

# Relay delivery tests (rxfanout on). VF0 sends; PEER-SRC >= COUNT/2 = relay on.

test_expect_success "txfwd on: broadcast relayed to peer VF" "
DMESG_START=\$(dmesg | wc -l)
thresh=\$((COUNT / 2))

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

P=\$(txfwd_param_path || true)
[[ -n \"\$P\" ]] || { echo \"FAIL: txfwd param not found\" >&5; return 1; }

VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo Y > \"\$P\" || { echo \"FAIL: cannot enable txfwd\" >&5; return 1; }
res=\$(measure_pair \"\$NS_VF0\" \"\$VF0_IF\" \"\$NS_VF1\" \"\$VF1_IF\" broadcast \"\$BROADCAST_MAC\" txbc-on)
src=\${res% *}; peer=\${res#* }
echo \"broadcast copies: source(VF0)=\$src peer(VF1)=\$peer\" >&5

[[ \$((peer - src)) -ge \$thresh ]] || { echo \"FAIL: relay did not reach peer (peer=\$peer src=\$src)\" >&5; return 1; }

check_dmesg \"\$DMESG_START\" || return 1
echo \"PASS: relay delivered \$((peer - src)) extra broadcast copies to the peer\" >&5
cleanup
"

test_expect_success "txfwd off: broadcast not relayed" "
DMESG_START=\$(dmesg | wc -l)
thresh=\$((COUNT / 2))

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

P=\$(txfwd_param_path || true)
[[ -n \"\$P\" ]] || { echo \"FAIL: txfwd param not found\" >&5; return 1; }

VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo N > \"\$P\" || { echo \"FAIL: cannot disable txfwd\" >&5; return 1; }
res=\$(measure_pair \"\$NS_VF0\" \"\$VF0_IF\" \"\$NS_VF1\" \"\$VF1_IF\" broadcast \"\$BROADCAST_MAC\" txbc-off)
src=\${res% *}; peer=\${res#* }
echo Y > \"\$P\"
echo \"broadcast copies: source(VF0)=\$src peer(VF1)=\$peer\" >&5

[[ \$((peer - src)) -lt \$thresh ]] || { echo \"FAIL: peer got a relay bonus with txfwd off (peer=\$peer src=\$src)\" >&5; return 1; }

check_dmesg \"\$DMESG_START\" || return 1
echo \"PASS: no relay contribution with txfwd off (peer=\$peer ~ source=\$src)\" >&5
cleanup
"

test_expect_success "txfwd on: multicast relayed to peer VF" "
DMESG_START=\$(dmesg | wc -l)
thresh=\$((COUNT / 2))

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

P=\$(txfwd_param_path || true)
[[ -n \"\$P\" ]] || { echo \"FAIL: txfwd param not found\" >&5; return 1; }

VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Subscribing VF0 and VF1 to \$MCAST_MAC\" >&5
ip -n \"\$NS_VF0\" maddr add \"\$MCAST_MAC\" dev \"\$VF0_IF\"
ip -n \"\$NS_VF1\" maddr add \"\$MCAST_MAC\" dev \"\$VF1_IF\"

echo Y > \"\$P\" || { echo \"FAIL: cannot enable txfwd\" >&5; return 1; }
res=\$(measure_pair \"\$NS_VF0\" \"\$VF0_IF\" \"\$NS_VF1\" \"\$VF1_IF\" multicast \"\$MCAST_MAC\" txmc-on)
src=\${res% *}; peer=\${res#* }
echo \"multicast copies: source(VF0)=\$src peer(VF1)=\$peer\" >&5

[[ \$((peer - src)) -ge \$thresh ]] || { echo \"FAIL: relay did not reach peer (peer=\$peer src=\$src)\" >&5; return 1; }

check_dmesg \"\$DMESG_START\" || return 1
echo \"PASS: relay delivered \$((peer - src)) extra multicast copies to the peer\" >&5
cleanup
"

test_expect_success "txfwd off: multicast not relayed" "
DMESG_START=\$(dmesg | wc -l)
thresh=\$((COUNT / 2))

echo \"Setting up namespaces\" >&5
reset_namespaces || return 1

P=\$(txfwd_param_path || true)
[[ -n \"\$P\" ]] || { echo \"FAIL: txfwd param not found\" >&5; return 1; }

VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; return 1; }

ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"Subscribing VF0 and VF1 to \$MCAST_MAC\" >&5
ip -n \"\$NS_VF0\" maddr add \"\$MCAST_MAC\" dev \"\$VF0_IF\"
ip -n \"\$NS_VF1\" maddr add \"\$MCAST_MAC\" dev \"\$VF1_IF\"

echo N > \"\$P\" || { echo \"FAIL: cannot disable txfwd\" >&5; return 1; }
res=\$(measure_pair \"\$NS_VF0\" \"\$VF0_IF\" \"\$NS_VF1\" \"\$VF1_IF\" multicast \"\$MCAST_MAC\" txmc-off)
src=\${res% *}; peer=\${res#* }
echo Y > \"\$P\"
echo \"multicast copies: source(VF0)=\$src peer(VF1)=\$peer\" >&5

[[ \$((peer - src)) -lt \$thresh ]] || { echo \"FAIL: peer got a relay bonus with txfwd off (peer=\$peer src=\$src)\" >&5; return 1; }

check_dmesg \"\$DMESG_START\" || return 1
echo \"PASS: no relay contribution with txfwd off (peer=\$peer ~ source=\$src)\" >&5
cleanup
"

# Reload cxi-eth with rxfanout=0; confirm txfwd is gated on rxfanout.
reload_cxi_eth() {
	# $1 = extra insmod args (may be empty).
	local args="$1"
	local m
	ns_remove_namespaces >/dev/null 2>&1 || true
	if [[ -w "/sys/class/cxi/$CXI_DEVICE/device/sriov_numvfs" ]]; then
		echo 0 > "/sys/class/cxi/$CXI_DEVICE/device/sriov_numvfs" 2>/dev/null || true
	fi
	for m in cxi_eth cxi-eth; do
		rmmod "$m" 2>/dev/null && break
	done
	sleep 0.5
	# shellcheck disable=SC2086
	insmod "$ETH_KO" $args || return 1
	sleep 1
	return 0
}

test_expect_success "rxfanout off: txfwd has no effect" "
DMESG_START=\$(dmesg | wc -l)
recv_vf1_pid=\"\"

echo \"Reloading cxi-eth with mc_sw_rxfanout_mod_parm=0\" >&5
reload_cxi_eth \"mc_sw_rxfanout_mod_parm=0\" || { echo \"FAIL: reload with rxfanout=0 failed\" >&5; reload_cxi_eth \"\" || true; return 1; }

RP=\$(rxfanout_param_path || true)
[[ -n \"\$RP\" ]] || { echo \"FAIL: rxfanout param missing after reload\" >&5; reload_cxi_eth \"\" || true; return 1; }
val=\$(cat \"\$RP\")
[[ \"\$val\" == N || \"\$val\" == 0 ]] || { echo \"FAIL: rxfanout not off after reload (got \$val)\" >&5; reload_cxi_eth \"\" || true; return 1; }

P=\$(txfwd_param_path || true)
[[ -n \"\$P\" ]] || { echo \"FAIL: txfwd param not found\" >&5; reload_cxi_eth \"\" || true; return 1; }
echo Y > \"\$P\" || { echo \"FAIL: cannot write txfwd param\" >&5; reload_cxi_eth \"\" || true; return 1; }

echo \"Setting up namespaces (rxfanout=0, txfwd=Y)\" >&5
reset_namespaces || { reload_cxi_eth \"\" || true; return 1; }

VF0_IF=\$(ns_iface \"\$NS_VF0\")
VF1_IF=\$(ns_iface \"\$NS_VF1\")
[[ -n \"\$VF0_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF0\" >&5; reload_cxi_eth \"\" || true; return 1; }
[[ -n \"\$VF1_IF\" ]] || { echo \"FAIL: No interface in \$NS_VF1\" >&5; reload_cxi_eth \"\" || true; return 1; }

ip -n \"\$NS_VF0\" link set \"\$VF0_IF\" up
ip -n \"\$NS_VF1\" link set \"\$VF1_IF\" up

echo \"VF0 sends broadcast; with rxfanout off, txfwd=Y must NOT deliver to VF1\" >&5
ip netns exec \"\$NS_VF1\" \"\$PKT_TOOL\" --mode recv --iface \"\$VF1_IF\" --traffic broadcast --expect-dst \"\$BROADCAST_MAC\" --expect-payload rxf-off --count 1 --timeout-ms 4000 --ethertype \"\$ETHERTYPE\" &
recv_vf1_pid=\$!
wait_receiver_ready \$recv_vf1_pid || { reload_cxi_eth \"\" || true; return 1; }

ip netns exec \"\$NS_VF0\" \"\$PKT_TOOL\" --mode send --iface \"\$VF0_IF\" --dst-mac \"\$BROADCAST_MAC\" --traffic broadcast --count \"\$COUNT\" --interval-ms \"\$INTERVAL_MS\" --payload rxf-off --ethertype \"\$ETHERTYPE\" || true

# VF1 receiving (exit 0) would mean txfwd took effect despite rxfanout off.
if wait \$recv_vf1_pid; then
	echo \"FAIL: VF1 received relayed BUM even though rxfanout=0\" >&5
	reload_cxi_eth \"\" || true
	return 1
fi

check_dmesg \"\$DMESG_START\" || { reload_cxi_eth \"\" || true; return 1; }

echo \"Restoring default cxi-eth (rxfanout on)\" >&5
reload_cxi_eth \"\" || { echo \"FAIL: could not restore default module\" >&5; return 1; }
RP=\$(rxfanout_param_path || true)
val=\$(cat \"\$RP\")
[[ \"\$val\" == Y || \"\$val\" == 1 ]] || { echo \"FAIL: rxfanout not restored to on (got \$val)\" >&5; return 1; }

echo \"PASS: with rxfanout off, enabling txfwd has no effect (VF1 got nothing)\" >&5
cleanup
"

test_done
