# CXI Driver — Integration Tests

This directory contains integration tests for the CXI (Cassini) driver. All tests
require a QEMU VM with netsim-simulated Cassini hardware. Tests are written using
the [Sharness](https://github.com/chriscool/sharness) TAP framework.

---

## Quick Start

```bash
# From repository root — build + start VM + run all tests
make check

# From inside a running VM
cd /path/to/cxi-driver/tests
prove -v *.t          # Run all tests with verbose TAP output
./t0010-basic.t       # Run a single test

# Run with debug output
sh -x t0010-basic.t
```

---

## Test Framework

- **Framework**: [Sharness](https://github.com/chriscool/sharness) — shell-based TAP testing derived from git's test suite
- **Protocol**: TAP (Test Anything Protocol) — `ok N - description` / `not ok N - description`
- **Runner**: `prove` (Perl TAP runner; provides summary and failure details)
- **Shared setup**: `preamble.sh` — loads before every test; loads driver modules, sets environment
- **Definitions**: `framework.sh` — Sharness macros and helper functions

### Test Structure

```bash
#!/bin/bash
. $(dirname $0)/preamble.sh      # Load common setup

test_description="Brief description"
. $SHARNESS_PATH                  # Load Sharness macros

test_expect_success "Test case name" "
    shell_commands &&
    that_must_all_succeed
"

test_expect_failure "This should fail" "
    command_that_should_error
"

test_done
```

---

## Test Inventory

### Basic Device (t00xx)

| Test | Description |
|------|-------------|
| `t0010-basic.t` | Device presence, sysfs attributes, basic driver functionality |
| `t0011-rm-driver.t` | Module load/unload lifecycle (rmmod + insmod) |
| `t0012-qos.t` | QoS profile creation and configuration |
| `t0013-nid-mac.t` | Network ID and MAC address assignment |

### SR-IOV Virtual Functions (t01xx)

| Test | Description |
|------|-------------|
| `t0100-sriov.t` | SR-IOV VF creation, deletion, and basic VF operations |
| `t0101-tmpldrv.t` | Template driver for VF testing |

### Domain, DMAC, and Resource Management (t02xx)

| Test | Description |
|------|-------------|
| `t0200-domain.t` | Communication domain creation and lifecycle |
| `t0201-dmac.t` | DMA controller basic operations |
| `t0202-eq_reserved_fc.t` | Event queue reserved flow control |
| `t0203-eq-alloc.t` | Event queue allocation limits and error handling |
| `t0204-service.t` | Communication service (endpoint) management |
| `t0205-rgroup.t` | Resource group allocation and bandwidth partitioning |
| `t0206-exclusive-cp.t` | Exclusive communication profile operations |
| `t0210-configfs-rgroup.t` | Resource group management via configfs |
| `t0211-configfs-rx-tx-profile.t` | RX/TX profile configuration via configfs |
| `t0212-configfs-test-cov.t` | Configfs coverage tests |
| `t0213-configfs-test-inv-uid-gid.t` | Configfs invalid UID/GID error handling |

### User-Space Interface (t03xx)

| Test | Description |
|------|-------------|
| `t0300-ucxi.t` | ucxi user-space API: ioctl operations, error handling |

### ATU Memory Mapping (t04xx)

| Test | Description |
|------|-------------|
| `t0400-atu.t` | ATU DMA mapping: allocation, map/unmap, error paths |

### Ethernet Driver (t05xx)

| Test | Description |
|------|-------------|
| `t0500-eth.t` | Ethernet: link up/down, packet TX/RX, ethtool operations |
| `t0501-eth-pflags.t` | Ethernet private flags configuration |

### Slingshot Base Link (t06xx)

| Test | Description |
|------|-------------|
| `t0600-sbl.t` | SBL link management: link training, state machine |

### DMAC API (t07xx)

| Test | Description |
|------|-------------|
| `t0700-dmac-api.t` | DMAC user-space API validation |

### Telemetry API (t08xx)

| Test | Description |
|------|-------------|
| `t0801-telem-api.t` | Hardware telemetry counter API |

### AMO Remap (t09xx)

| Test | Description |
|------|-------------|
| `t0900-amo_remap.t` | Atomic Memory Operation remap configuration |

### PtlTE — Portals Table Entry (t10xx)

| Test | Description |
|------|-------------|
| `t1000-ptlte.t` | Portals Table Entry allocation and lifecycle |

---

## Numeric Range Assignments for New Tests

When adding a new test, use the next available number in the appropriate range:

| Range | Subsystem | Next Available |
|-------|-----------|----------------|
| t0010–t0099 | Basic device and module lifecycle | t0014 |
| t0100–t0199 | SR-IOV and VF management | t0102 |
| t0200–t0299 | Domain, DMAC, EQ, service, rgroup | t0214 |
| t0300–t0399 | ucxi user-space API | t0301 |
| t0400–t0499 | ATU memory mapping | t0401 |
| t0500–t0599 | Ethernet driver | t0502 |
| t0600–t0699 | SBL | t0601 |
| t0700–t0799 | DMAC API | t0701 |
| t0800–t0899 | Telemetry API | t0802 |
| t0900–t0999 | AMO remap | t0901 |
| t1000–t1099 | PtlTE / Portals | t1001 |
| t1100+ | New subsystems | t1100 |

---

## VM Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `NETSIM_NICS` | Number of simulated Cassini devices | 1 |
| `KDIR` | Kernel source directory | `/lib/modules/$(uname -r)/build` |
| `TESTING` | Makes test dirs writable in VM | (unset) |

---

## Troubleshooting

**Tests fail immediately**: Verify modules are loaded (`lsmod | grep cxi`) and the
netsim device is present (`lspci | grep 17db`).

**`make check` hangs**: The VM may not have started. Check the terminal running
`startvm.sh` for boot errors.

**Single test debugging**: Run with `sh -x t0010-basic.t 2>&1 | head -100` to see
the exact commands and their output.
