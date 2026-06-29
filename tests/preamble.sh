# SPDX-License-Identifier: GPL-2.0
# Preamble to run a test in a VM. Hides the complexity of setting up tests.
# Sourced first by every test (`. ./preamble.sh`).
#
# Thin shim over the shared VM framework in devbootstrap/vm-tools: framework.sh
# sources the shared launcher and exposes startvm()/vm_in_guest.

[[ $(basename $0) = "preamble.sh" ]] &&
	echo "This script is only intended to be run by tests. Exiting." && exit 1

. ./framework.sh

# If not in a VM, start one and re-run this test inside it, then exit.
if ! vm_in_guest; then
	startvm "$(realpath "$0")"
	exit 0
fi

# sharness needs to write to some files and results. Put everything in
# a temporary directory that the VM can write to.
SHARNESS_TEST_DIRECTORY=$(pwd)/tmptests

# Load the baseline modules shared across repos (configfs, ptp, ...).
. "$VM_TOOLS_DIR/startvm-setup-common.sh"
