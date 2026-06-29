---
name: cxi-extension-patterns
description: >
  Extension guide for the CXI (Cassini) driver. Step-by-step procedures for
  adding a new hardware subsystem, adding a new Ethernet feature, adding a new
  test scenario, and adding a new sysfs attribute. Load when adding a new
  driver component, test, or public interface.
---

# CXI Extension Patterns

## Adding a New Hardware Subsystem

Example: adding a hypothetical "FQ" (Flow Queue) subsystem.

### Step 1: Create the source file

```
drivers/net/ethernet/hpe/ss1/cass_fq.c
drivers/net/ethernet/hpe/ss1/cass_fq.h
```

File naming rule: `cass_<subsystem>.{c,h}` for hardware implementation.

### Step 2: Register with the Makefile (Kbuild)

In `drivers/net/ethernet/hpe/ss1/Makefile`:
```makefile
cxi-ss1-objs += cass_fq.o
```

### Step 3: Header structure

```c
/* cass_fq.h — internal header, NOT in include/linux/hpe/cxi/ */
#ifndef _CASS_FQ_H
#define _CASS_FQ_H

#include "cass_core.h"

struct cass_fq {
    struct cass_dev *hw;    /* back-pointer to device */
    /* subsystem-specific fields */
};

/* Lifecycle */
struct cass_fq *cass_fq_alloc(struct cass_dev *hw, /* params */);
void cass_fq_free(struct cass_fq *fq);

#endif /* _CASS_FQ_H */
```

### Step 4: Initialize in cass_core.c

In the device `.add` callback chain (typically `cass_dev_init()` or equivalent):
```c
ret = cass_fq_init(hw);
if (ret) {
    dev_err(&hw->pdev->dev, "FQ init failed: %d\n", ret);
    goto err_fq;
}
```

In the device cleanup (`.remove` callback chain, reverse order):
```c
cass_fq_cleanup(hw);
```

### Step 5: Expose to clients (optional)

If the subsystem needs a public API in `include/linux/hpe/cxi/`:
```c
/* include/linux/hpe/cxi/cxi.h — add to public API */
struct cxi_fq_params { /* ... */ };
struct cxi_fq *cxi_fq_alloc(struct cxi_dev *dev, struct cxi_fq_params *params);
void cxi_fq_free(struct cxi_fq *fq);
```

Document in `docs/ABI/testing/` if any sysfs attributes are added.

### Step 6: Add a test

```
tests/t####-fq.t       # use the next available numeric range
```

See "Adding a New Test" below.

### Step 7: Update documentation

- `drivers/net/ethernet/hpe/ss1/README.md` — add FQ to the subsystem list
- `CONTEXT.md` — add FQ to the domain model if it's a major component
- `GLOSSARY.md` — define FQ abbreviation
- `.github/copilot-instructions.md` — if FQ introduces new patterns or pitfalls

---

## Adding a New Ethernet Feature

For changes to `cxi_eth.c` or `cxi_eth_ops.c`:

1. **Check existing pattern** — read the relevant section in `cxi_eth.c` first
2. **ethtool operations** — add to the `ethtool_ops` struct in `cxi_eth_ops.c`
3. **netdev features** — advertise via `NETIF_F_*` flags in `cxi_eth.c`
4. **NAPI budget** — do not exceed NAPI budget in any single poll iteration
5. **Test** — add or extend `tests/t0500-eth.t` or `tests/t0501-eth-pflags.t`

---

## Adding a New Test Scenario

### Naming Convention

```
tests/t<NNNN>-<description>.t
```

| Range | Subsystem |
|-------|-----------|
| t0010–t0099 | Basic device, module lifecycle |
| t0100–t0199 | SR-IOV / VF management |
| t0200–t0299 | Domain, DMAC, EQ, service, rgroup |
| t0300–t0399 | ucxi user-space API |
| t0400–t0499 | ATU memory mapping |
| t0500–t0599 | Ethernet driver |
| t0600–t0699 | SBL (Slingshot Base Link) |
| t0700–t0799 | DMAC API |
| t0800–t0899 | Telemetry API |
| t0900–t0999 | AMO remap |
| t1000–t1099 | PtlTE / Portals |
| t1100+      | New subsystems |

### Test Template

```bash
#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Test: brief description of what this test covers

. $(dirname $0)/preamble.sh

test_description="Short description for TAP header"

. $SHARNESS_PATH

# Setup (runs once before tests)
test_expect_success "Setup: verify device available" "
    ls /sys/class/cxi/cxi0
"

# Individual test cases
test_expect_success "Feature X works under normal conditions" "
    # test commands here
    # use && to chain; last exit code determines pass/fail
    echo test > /sys/class/cxi/cxi0/device/some_attr &&
    cat /sys/class/cxi/cxi0/device/some_attr | grep -q expected_value
"

test_expect_failure "Feature X rejects invalid input" "
    echo invalid > /sys/class/cxi/cxi0/device/some_attr
"

test_done
```

### Running the New Test

```bash
# In VM:
cd tests && ./t1100-fq.t

# Verbose:
cd tests && sh -x t1100-fq.t

# Full suite (from host):
make check
```

---

## Adding a New sysfs Attribute

1. **Implement** — add `DEVICE_ATTR_RO/RW/WO(name, ...)` in the relevant `cass_*.c`
2. **Register** — add to the `attrs[]` array in the device attribute group
3. **Document** — create `docs/ABI/testing/sysfs-cxi-<name>`:

```
What:           /sys/class/cxi/cxi<N>/device/<attribute>
Date:           June 2026
KernelVersion:  6.x
Contact:        hpe-hpc-platform@hpe.com
Description:    Brief description of what the attribute exposes.
                Include units, valid values, and read/write semantics.
```

4. **Test** — add a test case to the appropriate `tests/t*.t` file
