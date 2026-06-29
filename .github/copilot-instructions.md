# CXI Driver - AI Coding Assistant Instructions

> **Trust signal:** This file is the authoritative source for CXI driver
> AI-assisted development. Copilot should follow these patterns and conventions
> in all code generation, review, and documentation tasks for this repository.

# Project Context

This driver supports the Cassini NIC.

## Hardware Documentation

Before proposing driver changes, consult:

- Cassini 3:
  - `../cassini-arch-doc/cis`
  - `../cassini-arch-doc/csdg`

## Development Guidelines

- Never invent register fields.
- When documentation and code disagree, identify the discrepancy.

## Architecture Overview

This is the **CXI (Cassini) core driver** for HPE's Cassini 1 and 2 high-performance networking hardware. The codebase implements a layered kernel driver architecture:

```
userspace: libfabric/CXI provider
----------------------------------------
kernel:    cxi-eth | cxi-user | kfabric
           --------|---------|--------
              CXI core (cxi-ss1)
           --------|----------
           SBL/SL | Cassini HW
```

**Key Components:**
- `drivers/net/ethernet/hpe/ss1/` - Core hardware driver (`cxi-ss1`) and Ethernet driver
- `include/linux/hpe/cxi/` - Public CXI subsystem APIs
- `ucxi/` - User-space communication interface
- `tests/` - VM-based integration test suite

## Essential Patterns

### Client Registration Architecture
The CXI core uses a client registration pattern where kernel drivers register as clients:

```c
// In cxi_core.c - clients register to get device notifications
struct cxi_client cxiu_client = {
    .add = add_device,       // Called when CXI device appears
    .remove = remove_device, // Called when device removed
    .async_event = async_event
};
cxi_register_client(&cxiu_client);
```

### Hardware Abstraction Layers
- `struct cxi_dev` - Generic CXI device interface (exposed to clients)
- `struct cass_dev` - Cassini-specific hardware implementation (embeds cxi_dev)
- Driver works with cass_dev internally, exposes cxi_dev to clients

### Queue Management Pattern
The Ethernet driver uses dedicated queue structures with event-driven processing:
- **RX queues** (`struct rx_queue`) - Receive packet processing with NAPI
- **TX queues** (`struct tx_queue`) - Transmit with completion events
- **Event queues** (EQ) - Hardware event notification via CXI core
- **Command queues** (CQ) - Hardware command submission

## Development Workflows

### Building
```bash
# Standard build (uses running kernel)
make

# Build with custom kernel
export KDIR=/path/to/kernel/source
make

# Build specific components
make -C drivers/net/ethernet/hpe/ss1
make -C ucxi
```

### Testing with VMs
All testing uses QEMU VMs with simulated Cassini hardware via `netsim`:

```bash
# Run full test suite
make check

# Start development VM (auto-loads drivers)
cd scripts && ./startvm.sh

# Run specific test
cd tests && ./t0010-basic.t

# Multi-NIC testing
./startvm.sh -N 2  # 2 NICs on single VM
./startvm.sh -n 2  # 2 separate VMs
```

### Critical VM Environment Variables
- `NETSIM_NICS` - Number of simulated Cassini devices
- `KDIR` - Custom kernel source path
- `TESTING=1` - Makes test directories writable in VM

## Module Dependencies & Load Order
```bash
# Correct loading sequence (handled by startvm-setup.sh)
insmod cxi-sbl.ko      # Slingshot Base Link
insmod cxi-sl.ko       # Slingshot Link
insmod cxi-ss1.ko      # CXI core driver
insmod cxi-user.ko     # User communication
```

## Key File Relationships

### Core Driver Files
- `cass_core.c/.h` - Main hardware driver entry point and device management
- `cxi_core.c` - Client registration and CXI subsystem interface
- `cxi_user_core.c` - User-space API implementation
- `cass_*.c` - Hardware-specific implementations (ATU, EQ, CQ, etc.)

### Hardware Resource Management
- **Communication Profiles (CP)** - `cass_cpt.c` - Traffic shaping/QoS configuration
- **Event Queues** - `cass_eq.c` - Hardware event delivery mechanism
- **Address Translation Unit** - `cass_atu.c` - Memory mapping for DMA
- **Command Queues** - `cass_cq.c` - Hardware command submission

### Ethernet Integration
- `cxi_eth.c` - Main Ethernet netdev integration
- `cxi_eth_ops.c` - Network operations (TX/RX, channel management)
- Uses standard Linux network stack (NAPI, netdev queues, ethtool)

## Debugging Patterns

### Dynamic Debug
```bash
# Enable all CXI debug
echo 'module cxi_ss1 +p' > /proc/dynamic_debug/control

# File-specific debug
echo 'file cass_atu.c +p' > /proc/dynamic_debug/control
```

### sysfs Debug Interface
- `/sys/class/cxi/cxi0/device/` - Per-device configuration and status
- `/sys/kernel/debug/cxi/` - Debug counters and state dumps
- Error masking: `/sys/class/cxi/cxi0/device/err_flgs_irqa/`

### Hardware Simulation Notes
- All development uses QEMU + netsim (no real hardware required)
- Cassini devices appear as PCI devices `17db:0501` (Cassini 1) or `1590:0371` (Cassini 2)
- VM environment includes Intel IOMMU simulation for SR-IOV testing

## Common Pitfalls
1. **Build dependencies** - Requires `slingshot_base_link` and `sl-driver` built first
2. **Module load order** - SBL → SL → CXI core → CXI user
3. **VM testing only** - No baremetal testing infrastructure
4. **Memory alignment** - Hardware requires page-aligned buffers for queues
5. **Client removal** - Must call client remove callbacks in reverse order

## Integration Points
- **libfabric provider** - Userspace HPC communication library
- **KFabric** - In-kernel fabric interface
- **Slingshot ecosystem** - Depends on SBL/SL drivers for link management
- **Linux network stack** - Standard netdev/ethtool integration for Ethernet

## Code Quality & Standards

### Kernel Coding Style
- Enforced by checkpatch.pl via `make check-style` target
- Check code before commit: `perl contrib/checkpatch.pl --git HEAD~..HEAD`
- Common issues: line length (80 chars), spacing, naming conventions
- Use `make check-style` as pre-PR validation step

### Testing Requirements
- Test naming convention: `t####-description.t` (e.g., `t0010-basic.t`, `t0500-eth.t`)
- All tests must pass in VM environment via `make check`
- Use `make check-smoke` for quick non-VM validation (fast feedback loop)
- Pre-commit hook: Run `./contrib/install-git-hook.sh` to automate pre-push checks

### Pre-Commit Checklist (from CONTRIBUTING.md)
1. Run `make check-style` - no checkpatch violations
2. Run `make check-smoke` - builds drivers/ss1 and ucxi
3. Run full `make check` if modifying tests (requires VM)
4. Verify CONTRIBUTING.md and SECURITY.md are in place
5. Validate with `scripts/dev-setup.sh` (should show "All critical checks passed!")

## Build System & Tooling

### New Makefile Targets
- `make check-smoke` - Builds driver modules and ucxi only (no VM required, ~30 sec)
- `make check-style` - Runs checkpatch validation on git diff (platform-independent)
- `make check` - Full test suite with VM (requires virtme/qemu/cassini-qemu)

### Bootstrap & Prerequisites
- `scripts/dev-setup.sh` - Validates development environment
  - Checks required tools: make, gcc, git, perl, bash, prove
  - Checks sibling repos: slingshot_base_link, sl-driver, nic-emu, virtme, hms-artifacts
  - Checks kernel build tree at `/lib/modules/$(uname -r)/build` or custom `KDIR`
  - Run with `--fix` flag to show platform-specific remediation steps
  - Critical prerequisite before starting development

### Build Customization
- `KDIR` - Override kernel source (default: running kernel)
- `CHECKPATCH` - Path to checkpatch.pl script
- `CHECKPATCH_BASE` - Git ref for diff baseline (default: HEAD)
- `TESTING=1` - Required for VM test environment (makes dirs writable)

## CI/CD Pipeline

### Jenkinsfile Variants
- `Jenkinsfile` - Main build orchestration
- `Jenkinsfile.cxi_vm` - VM-based integration testing
- `Jenkinsfile.rpmbuild.rhel.x86_64` / `.aarch64` - RPM packaging
- `Jenkinsfile.nbs.x86_64` / `.aarch64` - Network Build System artifacts

### RPM Build Process
- Specs file: `cray-cxi-driver.spec` with DKMS template
- DKMS config: `dkms.conf.in` - Templated for multi-kernel support
- Build prep: `runBuildPrep.basekernel.sh` for environment setup
- Multi-kernel RPM: `rpm_build_multikernel.sh` for kernel-specific variants

### Expected PR Gates
1. Code style validation (checkpatch.pl)
2. Build verification (check-smoke)
3. Full test suite (make check with VM)
4. Documentation requirements (CONTRIBUTING.md, SECURITY.md present)

## Documentation Reference

### Essential Files for Contributors
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Developer onboarding, workflow, testing
- **[SECURITY.md](../SECURITY.md)** - Vulnerability reporting and disclosure process
- **[README-debugging.md](../README-debugging.md)** - Debugging guide for kernel driver
- **[.github/copilot-instructions.md](.github/copilot-instructions.md)** - This file
- **[docs/ABI/](../docs/ABI/)** - Public API documentation and ABI stability

### Test Framework Documentation
- `tests/framework.sh` - Sharness test framework definitions
- `tests/preamble.sh` - Common test setup and utilities
- Individual tests in `tests/t####-*.t` use TAP (Test Anything Protocol)

## Error Handling & Recovery

### Error Propagation Patterns
- Kernel errors propagate via `ERR_PTR()` / `PTR_ERR()` for pointer returns
- Use `-errno` for negative error codes (standard kernel pattern)
- Client removal must handle errors gracefully (no cascading failures)

### Error Masking Strategy
- Error flags exposed via sysfs: `/sys/class/cxi/cxi0/device/err_flgs_irqa/`
- Transient errors (e.g., link flaps) do not cause module panic
- Critical hardware errors logged but allow graceful shutdown
- Client notified of errors via async_event callback

### Recovery Patterns
- Device reset on critical errors (ATU, command queue failures)
- Queue state rebuild after error recovery
- Client re-registration after device recovery
- No force-unload during client removal (wait for completion)

## Performance & Profiling

### Profiling Tools
- **bpftrace examples** in `trace-debug/` directory
  - `cxi_cp.bt` - Communication profile tracing
  - `cxi_map.bt` - Memory mapping analysis
  - `cxi_tracepoint.h` - Custom kernel tracepoints

### Performance Bottlenecks to Avoid
- Spinlock contention in event queue processing (use lock-free where possible)
- Memory allocations in data path (pre-allocate buffers in rx_queue/tx_queue)
- DMA mapping overhead (batch operations when feasible)
- NAPI poll loop overstaying its budget (keep processing time < 2ms typical)

### Optimization Opportunities
- Event queue batching for multi-packet processing
- Cache locality in command submission
- TX/RX queue depth tuning per hardware revision
- Zero-copy packet forwarding paths

## Memory Safety

### DMA Buffer Alignment
- Hardware requires page-aligned (4KB) buffers for queues
- Queue structures: `struct rx_queue`, `struct tx_queue`, `struct event_queue`
- Allocation pattern: Use `__get_free_pages()` or kmalloc with GFP_DMA flag
- Document alignment requirements in struct definitions

### Memory Leak Prevention
- Client removal must free all allocated queues (see cxi_user_core.c for reference)
- Event queue cleanup in reverse order of allocation
- Use `kref` for reference-counted device objects
- Static analyzers: `make C=1` enables sparse checking

### Reference Counting Patterns
- Device lifecycle: `cxi_dev_get()` / `cxi_dev_put()` for safe async operations
- Queue lifecycle tied to client registration/removal
- Event notification held until client processes (no use-after-free)

---

This driver is production networking infrastructure for HPE supercomputing systems. Changes require extensive VM testing and understanding of hardware event flows.

## Maintenance Matrix

When you change one artifact, update all correlated artifacts listed here.

| Trigger | Also Update |
|---------|------------|
| New Makefile target added | `CONTRIBUTING.md` (Pre-Commit Checklist), `copilot-instructions.md` (Build System) |
| New/changed public ABI | `docs/ABI/testing/` entry, `GLOSSARY.md` if new abbreviation |
| New source file added | `drivers/net/ethernet/hpe/ss1/README.md` (file table) |
| New script added | `scripts/README.md` |
| New test file added | `tests/README.md` (inventory table), numeric range table |
| New domain abbreviation | `GLOSSARY.md`, `.github/skills/cxi-glossary/SKILL.md` |
| New hardware subsystem | `ARCHITECTURE.md`, `CONTEXT.md` domain model, `cxi-hardware-patterns` SKILL.md |
| New agent or prompt | `.github/README.md`, `AGENTS.md` routing table |
| Instruction file added/changed | `.github/README.md` instructions table |
| CODEOWNERS change | `.github/README.md` |