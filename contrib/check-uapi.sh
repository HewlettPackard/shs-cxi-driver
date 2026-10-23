#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Check the CXI UAPI header for ABI backwards compatibility across Git refs.
#
# Derived from the Linux kernel's scripts/check-uapi.sh (GPL-2.0-only).
# The compile recipe, abidiff invocation, suppression strategy and
# exit-code handling follow upstream. Differences: a single header is
# extracted with `git show` instead of `make headers_install`, and the
# suppressions live in a committed file (contrib/check-uapi.suppr).

set -o errexit
set -o pipefail

print_usage() {
	name=$(basename "$0")
	cat << EOF
$name - check the CXI UAPI header for ABI stability across Git refs

By default, the working tree copy of the UAPI header is compared against
the version at the merge-base of HEAD and \$UPSTREAM_BRANCH (origin/main).
Types may be added; existing types must not change size, layout, or
enumerator values.

Usage: $name [-b BASE_REF] [-p PAST_REF] [-v] [-q]

Options:
    -b BASE_REF    Git ref whose header is checked (default: working tree)
    -p PAST_REF    Git ref to compare against
                   (default: merge-base of HEAD and \$UPSTREAM_BRANCH)
    -v             Verbose: print the full abidiff report
    -q             Quiet: suppress output on success
    -h             Show this help

Environment:
    ABIDIFF           Path to abidiff (default: abidiff)
    CC                C compiler (default: gcc)
    UPSTREAM_BRANCH   Branch used to find the default PAST_REF
                      (default: origin/main)
    CASSINI_HEADERS   Include directory for cassini_user_defs.h
                      (default: ../cassini-headers/install/include)
    UAPI_HEADER       Header to check relative to the repo root
                      (default: include/uapi/ethernet/cxi-abi.h)

Exit status:
    0  no incompatible ABI change
    1  incompatible ABI change detected, or usage/tool error

Examples:
    # Check uncommitted changes against the PR base
    $name

    # Check HEAD against the last release
    $name -b HEAD -p <remote>/release/shs-14.0
EOF
}

eprintf() {
	# shellcheck disable=SC2059
	printf "$@" >&2
}

# Resolve a ref and print its short SHA, or die
resolve_ref() {
	local -r ref="$1"

	if ! git rev-parse --verify --quiet "${ref}^{commit}" > /dev/null; then
		eprintf "error - unknown git ref '%s'\n" "$ref"
		exit 1
	fi
	git rev-parse --short "$ref"
}

# Extract the UAPI header for a ref (or the working tree) into a
# directory that mirrors the include/ layout
extract_header() {
	local -r ref="$1"
	local -r out_dir="$2"
	local -r rel="${UAPI_HEADER#include/}"

	mkdir -p "$(dirname "${out_dir}/${rel}")"
	if [ -z "$ref" ]; then
		cp "${UAPI_HEADER}" "${out_dir}/${rel}"
	else
		git show "${ref}:${UAPI_HEADER}" > "${out_dir}/${rel}"
	fi
}

# Compile a dummy TU that includes the header, keeping all type DWARF.
# Flags match upstream do_compile(); the pre-includes supply the libc
# types cxi-abi.h relies on its includer for (as ucxi/ does via
# cxi_prov_hw.h), and -D__user= matches ucxi/Makefile.
do_compile() {
	local -r inc_dir="$1"
	local -r out="$2"
	local -r rel="${UAPI_HEADER#include/}"

	{
		printf '#include <stddef.h>\n'
		printf '#include <stdint.h>\n'
		printf '#include <stdbool.h>\n'
		printf '#include "%s"\n' "$rel"
		printf 'int f(void) { return 0; }\n'
	} | \
		"$CC" \
		  -shared \
		  -nostdlib \
		  -fPIC \
		  -o "$out" \
		  -x c \
		  -O0 \
		  -fno-eliminate-unused-debug-types \
		  -g \
		  -D__user= \
		  "-I${inc_dir}" \
		  "-I${CASSINI_HEADERS}" \
		  -
}

# Perform the A/B compilation and compare output ABI
compare_abi() {
	local -r past_desc="$1"
	local -r base_desc="$2"
	local -r log="${TMP_DIR}/abidiff.log"
	local ret=0

	if ! do_compile "${TMP_DIR}/past" "${TMP_DIR}/past.bin" 2> "${TMP_DIR}/cc.log"; then
		eprintf "error - could not compile %s at %s\n" "$UAPI_HEADER" "$past_desc"
		cat "${TMP_DIR}/cc.log" >&2
		return 1
	fi

	if ! do_compile "${TMP_DIR}/base" "${TMP_DIR}/base.bin" 2> "${TMP_DIR}/cc.log"; then
		eprintf "error - could not compile %s at %s\n" "$UAPI_HEADER" "$base_desc"
		cat "${TMP_DIR}/cc.log" >&2
		return 1
	fi

	"$ABIDIFF" --non-reachable-types \
		--suppressions "$SUPPRESSIONS" \
		"${TMP_DIR}/past.bin" "${TMP_DIR}/base.bin" > "$log" || ret="$?"

	if [ "$VERBOSE" = "true" ]; then
		cat "$log"
	fi

	if [ "$ret" -eq 0 ]; then
		if [ "$QUIET" != "true" ]; then
			printf "No ABI differences detected in %s from %s -> %s\n" \
				"$UAPI_HEADER" "$past_desc" "$base_desc"
		fi
		return 0
	fi

	# Bits in abidiff's return code can be used to determine the type of error
	if [ $((ret & 0x2)) -gt 0 ]; then
		eprintf "error - abidiff did not run properly\n"
		cat "$log" >&2
		exit 1
	fi

	# If the only changes were additions (not modifications to existing
	# APIs), then there's no problem. Ignore these diffs.
	if grep "Unreachable types summary" "$log" | grep -q "0 removed" &&
	   grep "Unreachable types summary" "$log" | grep -q "0 changed"; then
		if [ "$QUIET" != "true" ]; then
			printf "Only additions detected in %s from %s -> %s (compatible)\n" \
				"$UAPI_HEADER" "$past_desc" "$base_desc"
		fi
		return 0
	fi

	{
		warn_str=$(printf "==== ABI differences detected in %s from %s -> %s ====" \
			"$UAPI_HEADER" "$past_desc" "$base_desc")
		printf "%s\n" "$warn_str"
		# Show removed/changed types; drop the (compatible) added-types list
		sed -e '/added types unreachable from any public interface/,$d' \
		    -e '/summary:/d' -e '/^$/d' -e 's/^/  /g' "$log"
		printf -- "=%.0s" $(seq 0 ${#warn_str})
		printf "\n"
		printf "Existing UAPI types must keep their size, member offsets and\n"
		printf "enumerator values. Add new commands/structs instead of changing\n"
		printf "existing ones. See contrib/check-uapi.suppr for allowed exceptions.\n"
	} >&2

	return 1
}

# Check that a minimum software version number is satisfied
min_version_is_satisfied() {
	local -r min_version="$1"
	local -r version_installed="$2"

	printf "%s\n%s\n" "$min_version" "$version_installed" \
		| sort -Vc > /dev/null 2>&1
}

# Make sure we have the tools we need and the arguments make sense
check_deps() {
	ABIDIFF="${ABIDIFF:-abidiff}"
	CC="${CC:-gcc}"
	UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-origin/main}"
	UAPI_HEADER="${UAPI_HEADER:-include/uapi/ethernet/cxi-abi.h}"
	CASSINI_HEADERS="${CASSINI_HEADERS:-../cassini-headers/install/include}"

	# changed_enumerators_regexp needs 2.4; the committed suppression file
	# uses the exact-name form so 2.3 (SLE 15 PackageHub) is sufficient.
	local -r abidiff_min_version="2.3"

	if ! command -v "$ABIDIFF" > /dev/null 2>&1; then
		eprintf "error - abidiff not found!\n"
		eprintf "Please install libabigail version %s or greater\n" "$abidiff_min_version"
		eprintf "  SLES/openSUSE: zypper install libabigail-tools (PackageHub)\n"
		eprintf "  RHEL/Fedora:   dnf install libabigail\n"
		eprintf "  Debian/Ubuntu: apt install abigail-tools\n"
		exit 1
	fi

	local -r abidiff_version="$("$ABIDIFF" --version | cut -d ' ' -f 2)"
	if ! min_version_is_satisfied "$abidiff_min_version" "$abidiff_version"; then
		eprintf "error - abidiff version too old: %s\n" "$abidiff_version"
		eprintf "Please install libabigail version %s or greater\n" "$abidiff_min_version"
		exit 1
	fi

	if ! command -v "$CC" > /dev/null 2>&1; then
		eprintf "error - compiler '%s' not found\n" "$CC"
		exit 1
	fi

	if [ ! -d "$CASSINI_HEADERS" ]; then
		eprintf "error - cassini headers not found at %s\n" "$CASSINI_HEADERS"
		eprintf "Set CASSINI_HEADERS to the directory containing cassini_user_defs.h\n"
		exit 1
	fi

	if [ ! -f "$SUPPRESSIONS" ]; then
		eprintf "error - suppression file %s not found\n" "$SUPPRESSIONS"
		exit 1
	fi

	if [ -z "$BASE_REF" ] && [ ! -f "$UAPI_HEADER" ]; then
		eprintf "error - %s not found in working tree\n" "$UAPI_HEADER"
		exit 1
	fi
}

run() {
	local base_desc past_desc
	local -r rel="${UAPI_HEADER#include/}"

	if [ -n "$BASE_REF" ]; then
		base_desc="$(resolve_ref "$BASE_REF")"
	else
		base_desc="dirty tree"
	fi

	if [ -z "$PAST_REF" ]; then
		if ! PAST_REF="$(git merge-base "$UPSTREAM_BRANCH" HEAD 2> /dev/null)"; then
			eprintf "error - cannot find merge-base of HEAD and %s\n" "$UPSTREAM_BRANCH"
			eprintf "Set UPSTREAM_BRANCH or pass -p PAST_REF explicitly\n"
			exit 1
		fi
	fi
	past_desc="$(resolve_ref "$PAST_REF")"

	extract_header "$PAST_REF" "${TMP_DIR}/past"
	extract_header "$BASE_REF" "${TMP_DIR}/base"

	if cmp -s "${TMP_DIR}/past/${rel}" "${TMP_DIR}/base/${rel}"; then
		if [ "$QUIET" != "true" ]; then
			printf "%s is identical at %s and %s\n" \
				"$UAPI_HEADER" "$past_desc" "$base_desc"
		fi
		return 0
	fi

	compare_abi "$past_desc" "$base_desc"
}

main() {
	local -r script_dir="$(cd "$(dirname "$0")" && pwd)"

	BASE_REF=""
	PAST_REF=""
	VERBOSE="false"
	QUIET="false"
	SUPPRESSIONS="${script_dir}/check-uapi.suppr"

	while getopts "hb:p:vq" opt; do
		case $opt in
		h) print_usage; exit 0 ;;
		b) BASE_REF="$OPTARG" ;;
		p) PAST_REF="$OPTARG" ;;
		v) VERBOSE="true" ;;
		q) QUIET="true" ;;
		*) print_usage; exit 1 ;;
		esac
	done

	if ! git rev-parse --show-toplevel > /dev/null 2>&1; then
		eprintf "error - must be run from inside the cxi-driver git repository\n"
		exit 1
	fi
	cd "$(git rev-parse --show-toplevel)"

	check_deps

	TMP_DIR="$(mktemp -d)"
	trap 'rm -rf "$TMP_DIR"' EXIT

	run
}

main "$@"
