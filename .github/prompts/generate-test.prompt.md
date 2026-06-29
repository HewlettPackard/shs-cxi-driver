---
mode: ask
description: >
  Generate a new CXI driver integration test for a specified subsystem or
  feature. Produces a complete Sharness TAP test file ready to drop into tests/.
---

# Generate CXI Driver Integration Test

Generate a Sharness integration test for the CXI (Cassini) driver.

## Instructions

1. **Identify the subsystem** being tested (ATU, EQ, CQ, CP, Ethernet, SR-IOV, etc.)
2. **Choose the correct test number range** (see `tests/README.md` for ranges)
3. **Generate a complete test file** following the template below

## Required Information

Before generating, confirm:
- What subsystem or feature does this test cover?
- What is the expected behavior being validated?
- Does this test require multiple VMs, multiple NICs, or just a single VM?
- Does it test error paths (expected failures) or success paths?

## Test File Template

```bash
#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Test: <one-line description of what is being tested>

. $(dirname $0)/preamble.sh

test_description="<Short description for TAP header — shown in prove output>"

. $SHARNESS_PATH

# ---------------------------------------------------------------------------
# Setup — runs once; fail here to skip remaining tests
# ---------------------------------------------------------------------------

test_expect_success "Setup: verify CXI device is available" "
    ls /sys/class/cxi/cxi0
"

test_expect_success "Setup: verify required modules are loaded" "
    lsmod | grep -q cxi_ss1
"

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

test_expect_success "<Subsystem>: <description of normal case>" "
    # Use && to chain commands — last exit code determines pass/fail
    command_one &&
    command_two &&
    verify_result
"

test_expect_success "<Subsystem>: another scenario" "
    setup_command &&
    action_command &&
    verify_command
"

test_expect_failure "<Subsystem>: rejects invalid input" "
    invalid_command
"

# ---------------------------------------------------------------------------
# Cleanup — runs after all tests regardless of pass/fail
# ---------------------------------------------------------------------------

test_expect_success "Cleanup: restore original state" "
    cleanup_command || true
"

test_done
```

## Naming and Placement

- File name: `tests/t<NNNN>-<subsystem>-<brief>.t`
- Make the file executable: `chmod +x tests/t<NNNN>-<brief>.t`
- Register in `tests/README.md` inventory table

## Quality Checklist

- [ ] Uses `test_expect_success` / `test_expect_failure` (not raw `if` statements)
- [ ] Commands chained with `&&` (not `;`) so failures propagate correctly
- [ ] Cleanup test uses `|| true` to prevent cleanup failures from failing the suite
- [ ] Avoids hardcoded paths — uses environment variables from `preamble.sh`
- [ ] Verifiable in a single VM (unless multi-VM is explicitly required)
- [ ] Does not leave device in modified state after completion
