# SPDX-License-Identifier: GPL-2.0
# Framework for testing
#
# This must be sourced by a test script

# Source the shared VM-launch framework and this repo's configuration.
# vm-lib.sh provides vm_startvm(); vm.conf supplies the cxi-driver specifics
# (memory, firmware rodir, $NETSIM_CCN device, nested-VM hook).
#
# Resolve paths from this script's own location, not from $(pwd) or a hardcoded
# repo name, so the right vm.conf is used regardless of the checkout directory
# (cxi-driver, PR-cxi-driver, PR-cxi-driver_2, ...). vm-tools comes from the
# flat workspace root; vm.conf comes from this repo's own checkout.
REPO_DIR=$(realpath "$(dirname "${BASH_SOURCE[0]}")/..")
TOP_DIR=$(realpath "$REPO_DIR/..")
source "$TOP_DIR/vm-tools/vm-lib.sh"
source "$REPO_DIR/vm.conf"

# An error was found. Dump the script stack, and display the message
# in the argument, and exit.
function error {
    echo "Error at:"
    local frame=0
    while caller $frame; do
        ((frame++));
    done

    echo $1

    exit 1
}

# Start a VM, run the test script inside it, and exit.
# arg 1 = the script to run inside the VM
function startvm {
    vm_startvm --rwdir "$(pwd)/tmptests" "$1"
}

# Returns the log name for the output
# ie. if the script is called test1.sh, the output is test1.log
# arg 1: an optional suffix
# Output sample: basic1.log         (without an argument)
# Output sample: basic1-foo.log     (with foo as an argument)
function log {
    local suffix

    if [ -z "$1" ]; then
        suffix=""
    else
        suffix="-$1"
    fi

    echo $(basename $0 .sh)$suffix.log
}

# Count the number of regex occurrence in one or more files and bail
# out if the count is not right
# arg 1 = count
# arg 2 = grep regex
# arg 3 = filename(s)
function ecount()
{
    local C=$(egrep "$2" ${@:3} | wc -l)

    [ $C -eq $1 ] || error "counted $C, expected $1 for \"$2\" in ${@:3}"
}
