#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Bootstrap verification script for cxi-driver development environment.
#
# This script checks that required tools and sibling repositories are available
# for local development, testing, and CI parity.
#
# Usage:
#   ./scripts/dev-setup.sh                              # Check local prerequisites
#   ./scripts/dev-setup.sh --fix                        # Suggest fixes
#   ./scripts/dev-setup.sh --remote HOST --repo-path /path/to/cxi-driver  # Check remote host
#
# Remote Usage Examples:
#   ./scripts/dev-setup.sh --remote buildhost.example.com --repo-path /home/user/cxi-driver
#   ./scripts/dev-setup.sh --remote buildhost --repo-path ~/work/cxi-driver --fix
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERBOSE=${VERBOSE:-0}
FIX_MODE=0
REMOTE_HOST=""
REPO_PATH=""

# Track failures (critical vs optional)
FAILURES=0
OPTIONAL_FAILURES=0
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --fix)
            FIX_MODE=1
            shift
            ;;
        --verbose|-v)
            VERBOSE=1
            shift
            ;;
        --remote)
            REMOTE_HOST="$2"
            shift 2
            ;;
        --repo-path)
            REPO_PATH="$2"
            shift 2
            ;;
        --help|-h)
            cat <<EOF
Usage: $(basename "$0") [OPTION]

Verify cxi-driver development prerequisites and sibling repository structure.

OPTIONS:
  --fix                              Show suggested fixes for missing prerequisites
  --verbose, -v                      Enable verbose output
  --remote HOST                      Check prerequisites on remote host (requires --repo-path)
  --repo-path PATH                   Path to cxi-driver repo on local or remote system
  --help, -h                         Show this help message

LOCAL EXAMPLES:
  $(basename "$0")                       # Check local prerequisites
  $(basename "$0") --fix                 # Show suggested fixes for local system
  $(basename "$0") --verbose             # Detailed output

REMOTE EXAMPLES:
  $(basename "$0") --remote buildhost --repo-path /home/user/cxi-driver
  $(basename "$0") --remote buildhost.example.com --repo-path ~/work/cxi-driver --fix
  $(basename "$0") --remote buildhost --repo-path /opt/cxi-driver --verbose

NOTES:
  - Remote execution requires SSH access to the target host
  - The script is copied to the remote system for execution
  - SSH must be configured for non-interactive login (key-based auth recommended)
  - Parent sibling repos are checked relative to the --repo-path location

EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Utility functions
log_info() {
    if [[ $VERBOSE -eq 1 ]]; then
        echo "[INFO] $*"
    fi
}

log_pass() {
    echo -e "${GREEN}✓${NC} $*"
}

log_fail() {
    echo -e "${RED}✗${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $*"
}

# Track failures
FAILURES=0

# Check for tool OR sibling repository (for optional tools with repo fallback)
check_tool_or_repo() {
    local tool=$1
    local package_name=$2
    local repo_name=$3

    if command -v "$tool" &>/dev/null; then
        log_pass "Tool found: $tool"
        return 0
    elif [[ -d "../${repo_name}" ]]; then
        log_pass "Tool fallback available: $tool (via ../$repo_name repository)"
        return 0
    else
        log_fail "Tool missing: $tool (package: $package_name) and repo ../$repo_name not found"
        if [[ $FIX_MODE -eq 1 ]]; then
            if [[ "$OSTYPE" == "darwin"* ]]; then
                log_warn "  macOS: brew install $package_name"
            elif command -v apt-get &>/dev/null; then
                log_warn "  Ubuntu/Debian: sudo apt-get install $package_name"
            elif command -v yum &>/dev/null; then
                log_warn "  RHEL/CentOS: sudo yum install $package_name"
            elif command -v zypper &>/dev/null; then
                log_warn "  SLES: sudo zypper install $package_name"
            else
                log_warn "  Install using your system package manager: $package_name"
            fi
            log_warn "  OR clone the $repo_name repository as a sibling"
        fi
        ((FAILURES++))
        return 1
    fi
}

# Check for required tools
check_tool() {
    local tool=$1
    local package_name=${2:-$tool}

    if command -v "$tool" &>/dev/null; then
        log_pass "Tool found: $tool"
        return 0
    else
        log_fail "Tool missing: $tool (package: $package_name)"
        if [[ $FIX_MODE -eq 1 ]]; then
            # Provide platform-specific install commands
            if [[ "$OSTYPE" == "darwin"* ]]; then
                log_warn "  macOS: brew install $package_name"
            elif command -v apt-get &>/dev/null; then
                log_warn "  Ubuntu/Debian: sudo apt-get install $package_name"
            elif command -v yum &>/dev/null; then
                log_warn "  RHEL/CentOS: sudo yum install $package_name"
            elif command -v zypper &>/dev/null; then
                log_warn "  SLES: sudo zypper install $package_name"
            else
                log_warn "  Install using your system package manager: $package_name"
            fi
        fi
        ((FAILURES++))
        return 1
    fi
}

# Check for sibling repository
check_sibling_repo() {
    local repo_name=$1
    local repo_path="../${repo_name}"

    if [[ -d "$repo_path" ]]; then
        log_pass "Sibling repository found: $repo_name"
        return 0
    else
        log_fail "Sibling repository missing: $repo_name"
        if [[ $FIX_MODE -eq 1 ]]; then
            log_warn "  From parent of cxi-driver repo root, clone:"
            log_warn "    git clone <repo-url> $repo_name"
        fi
        ((FAILURES++))
        return 1
    fi
}

# Check for optional sibling repository (doesn't count as critical failure)
check_optional_sibling_repo() {
    local repo_name=$1
    local repo_path="../${repo_name}"

    if [[ -d "$repo_path" ]]; then
        log_pass "Optional sibling repository found: $repo_name"
        return 0
    else
        log_warn "Optional sibling repository missing: $repo_name"
        if [[ $FIX_MODE -eq 1 ]]; then
            log_warn "  From parent of cxi-driver repo root, clone:"
            log_warn "    git clone <repo-url> $repo_name"
        fi
        ((OPTIONAL_FAILURES++))
        return 0  # Don't fail for optional repos
    fi
}

# Check for optional tool (doesn't count as critical failure)
check_optional_tool() {
    local tool=$1
    local package_name=${2:-$tool}

    if command -v "$tool" &>/dev/null; then
        log_pass "Tool found: $tool"
        return 0
    else
        log_warn "Optional tool missing: $tool (package: $package_name)"
        if [[ $FIX_MODE -eq 1 ]]; then
            if [[ "$OSTYPE" == "darwin"* ]]; then
                log_warn "  macOS: brew install $package_name"
            elif command -v apt-get &>/dev/null; then
                log_warn "  Ubuntu/Debian: sudo apt-get install $package_name"
            elif command -v yum &>/dev/null; then
                log_warn "  RHEL/CentOS: sudo yum install $package_name"
            elif command -v zypper &>/dev/null; then
                log_warn "  SLES: sudo zypper install $package_name"
            else
                log_warn "  Install using your system package manager: $package_name"
            fi
        fi
        ((OPTIONAL_FAILURES++))
        return 0  # Don't fail for optional tools
    fi
}

# Check for development file
check_dev_file() {
    local file=$1
    local description=$2

    if [[ -f "$file" ]]; then
        log_pass "Development file found: $description"
        return 0
    else
        log_fail "Development file missing: $description at $file"
        ((FAILURES++))
        return 1
    fi
}

# ============================================================================
# Remote execution handler
# ============================================================================

run_remote_checks() {
    local host=$1
    local repo_path=$2

    # Validate inputs
    if [[ -z "$host" ]] || [[ -z "$repo_path" ]]; then
        echo "Error: --remote requires both HOST and --repo-path" >&2
        exit 1
    fi

    # Expand ~ to home directory for display
    local expanded_path="${repo_path/#\~/$HOME}"

    echo "Connecting to remote host: $host"
    echo "Repository path: $repo_path"
    echo "Building command for remote execution..."
    echo

    # Build the remote command
    local remote_cmd="cd '$repo_path' && bash scripts/dev-setup.sh"

    if [[ $FIX_MODE -eq 1 ]]; then
        remote_cmd="$remote_cmd --fix"
    fi

    if [[ $VERBOSE -eq 1 ]]; then
        remote_cmd="$remote_cmd --verbose"
    fi

    # Execute remotely via SSH
    ssh -t "$host" "$remote_cmd"
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        echo
        echo "✓ Remote verification successful"
    else
        echo
        echo "✗ Remote verification failed (exit code: $exit_code)"
    fi

    exit $exit_code
}

# ============================================================================
# Verification workflow
# ============================================================================

# Handle remote execution mode
if [[ -n "$REMOTE_HOST" ]]; then
    run_remote_checks "$REMOTE_HOST" "$REPO_PATH"
fi

echo "=== cxi-driver Development Environment Check ==="
echo

echo "1. Checking required build tools..."
check_tool "make" "make"
check_tool "gcc" "gcc/build-essential"
check_tool "git" "git"
check_tool "perl" "perl"
check_tool "bash" "bash"
echo

echo "2. Checking VM and test tools..."
check_tool "prove" "perl-modules (for prove)"
check_tool_or_repo "virtme-run" "virtme" "virtme"
check_optional_tool "qemu-system-x86_64" "qemu"
echo

echo "3. Checking required sibling repositories..."
check_sibling_repo "slingshot_base_link"
check_sibling_repo "sl-driver"
check_sibling_repo "nic-emu" || log_warn "  VM tests require nic-emu"
check_optional_sibling_repo "cassini-qemu"
check_sibling_repo "virtme" || log_warn "  VM tests require virtme or system virtme-run binary"
check_sibling_repo "hms-artifacts" || log_warn "  VM tests may require hms-artifacts"
echo

echo "4. Checking repository structure..."
check_dev_file "$REPO_ROOT/Makefile" "Root Makefile"
check_dev_file "$REPO_ROOT/README" "README"
check_dev_file "$REPO_ROOT/contrib/install-git-hook.sh" "Pre-commit hook installer"
check_dev_file "$REPO_ROOT/contrib/checkpatch.pl" "Checkpatch script"
check_dev_file "$REPO_ROOT/CONTRIBUTING.md" "Contributor guide"
check_dev_file "$REPO_ROOT/SECURITY.md" "Security policy"
echo

echo "5. Checking kernel build environment..."
if [[ -d "/lib/modules/$(uname -r)/build" ]]; then
    log_pass "Kernel build tree available for current kernel"
else
    log_warn "Kernel build tree not available for $(uname -r)"
    if [[ $FIX_MODE -eq 1 ]]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            log_warn "  macOS: Kernel modules build is Linux-only. Use make check-style for linting."
        elif command -v apt-get &>/dev/null; then
            log_warn "  Ubuntu/Debian: sudo apt-get install linux-headers-$(uname -r)"
        elif command -v yum &>/dev/null; then
            log_warn "  RHEL/CentOS: sudo yum install kernel-devel"
        elif command -v zypper &>/dev/null; then
            log_warn "  SLES: sudo zypper install kernel-devel"
        fi
        log_warn "  Or set KDIR=/path/to/kernel/source for custom kernel builds"
    fi
fi
echo

# Final status
echo "=== Summary ==="
if [[ $FAILURES -eq 0 ]]; then
    log_pass "All critical checks passed!"
    if [[ $OPTIONAL_FAILURES -gt 0 ]]; then
        echo
        log_warn "$OPTIONAL_FAILURES optional components missing (only needed for full VM testing)"
    fi
    echo
    echo "Next steps:"
    echo "  1. Install pre-commit hook: ./contrib/install-git-hook.sh"
    echo "  2. Build the drivers: make"
    echo "  3. Run preflight checks: make check-smoke && make check-style"
    echo "  4. Run full tests: make check (requires VM)"
    echo
    exit 0
else
    log_fail "$FAILURES critical checks failed"
    if [[ $FIX_MODE -eq 0 ]]; then
        echo
        echo "Run with --fix for suggested remediation steps."
    else
        echo
        echo "Remediation guidance provided above. After installing missing prerequisites, re-run:"
        echo "  $0"
    fi
    echo
    exit 1
fi
