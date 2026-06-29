#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
# Copyright 2026 Hewlett Packard Enterprise Development LP
#
# Start a cxi-driver VM interactively (optionally loading the test driver).
# This is a thin wrapper over the shared launcher in devbootstrap/vm-tools.
#
# Arguments are passed straight to netsim (NIC count, VM count, USE_XTERM, ...);
# see the usage in devbootstrap/vm-tools/startvm.sh, or run `netsim -h`.
#
# TESTING=1 ./startvm.sh exposes ../tests/tmptests read-write in the VM.

DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
cd "$DIR"

VM_TOOLS_DIR="$(realpath "$DIR/../../vm-tools")"
source "$VM_TOOLS_DIR/vm-lib.sh"
source "$DIR/../vm.conf"

VM_NETSIM_ARGS=("$@")

if [[ "${TESTING:-0}" -eq 1 ]]; then
	vm_startvm --interactive --rwdir "$VM_TEST_RWDIR"
else
	vm_startvm --interactive
fi
