# CXI Driver — Session Context

> This file is the quick-orientation reference for every AI session working on this
> repository. It covers tech stack, directory layout, domain model, architectural
> patterns, anti-patterns, and commands. See [.github/copilot-instructions.md](.github/copilot-instructions.md)
> for the full authoritative guidance.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | C (GNU C, kernel dialect) |
| Kernel API | Linux netdev, CXI subsystem, Kbuild |
| Hardware | HPE Cassini 1 (`17db:0501`) and Cassini 2 (`1590:0371`) PCI devices |
| Simulation | QEMU + netsim (simulated Cassini via PCI passthrough) |
| Testing | Sharness (TAP-based), `prove`, VM-only integration tests |
| CI/CD | Jenkins (6 Jenkinsfiles), RPM packaging (DKMS, multi-kernel) |
| Build | GNU Make + Linux Kbuild |
| Style | kernel checkpatch.pl (enforced via `make check-style`) |
| Packaging | DKMS RPM for RHEL x86_64 + aarch64, NBS artifacts |

---

## Annotated Directory Layout

```
cxi-driver/
├── drivers/net/ethernet/hpe/ss1/   # Core hardware driver (cxi-ss1) + Ethernet driver
│   ├── cxi_core.c / cxi_core.h     #   Client registration subsystem (add/remove/async_event)
│   ├── cass_core.c / cass_core.h   #   PCI device lifecycle, hardware init, IRQ setup
│   ├── cass_atu.c                  #   Address Translation Unit — DMA memory mapping
│   ├── cass_eq.c                   #   Event Queues — hardware event delivery
│   ├── cass_cq.c                   #   Command Queues — hardware command submission
│   ├── cass_cpt.c                  #   Communication Profiles — QoS/traffic shaping
│   ├── cxi_eth.c                   #   Ethernet netdev integration (NAPI, netdev)
│   ├── cxi_eth_ops.c               #   TX/RX operations, channel management
│   └── cass_*.c                    #   All other hardware subsystems (sriov, dmac, etc.)
├── include/linux/hpe/cxi/          # Public CXI subsystem API headers
├── ucxi/                           # User-space communication interface (ioctl/netlink)
│   ├── test_ucxi.c                 #   Main user-space test harness
│   ├── test_ucxi_atu.c             #   ATU (memory mapping) tests
│   └── test_ucxi_common.{c,h}      #   Shared test utilities
├── tests/                          # VM-based integration tests (Sharness/TAP)
│   ├── t00xx-*.t                   #   Basic device presence and driver load
│   ├── t01xx-*.t                   #   SR-IOV virtual function tests
│   ├── t02xx-*.t                   #   Domain, DMAC, EQ, service, rgroup tests
│   ├── t03xx-*.t                   #   ucxi user-space API tests
│   ├── t04xx-*.t                   #   ATU memory mapping tests
│   ├── t05xx-*.t                   #   Ethernet driver tests
│   ├── t06xx-*.t                   #   SBL (Slingshot Base Link) tests
│   ├── t07xx-*.t                   #   DMAC API tests
│   ├── t08xx-*.t                   #   Telemetry API tests
│   ├── t09xx-*.t                   #   AMO remap tests
│   ├── t10xx-*.t                   #   PtlTE (Portals Table Entry) tests
│   ├── preamble.sh                 #   Common VM setup and module loading
│   ├── framework.sh                #   Sharness definitions
│   └── run-tests.sh                #   Test runner (called by make check)
├── scripts/                        # Build, VM, and development utility scripts
│   ├── startvm.sh                  #   Start development VM (auto-loads drivers)
│   ├── startvm-setup.sh            #   VM initialization (insmod sequence)
│   ├── dev-setup.sh                #   Prerequisite checker (local and --remote)
│   ├── cxi_mgmt                    #   CXI management utility
│   └── *.sh / *.bt                 #   Other VM scripts and bpftrace examples
├── docs/                           # Technical documentation
│   ├── ABI/testing/                #   sysfs ABI stability documentation
│   └── phy_state_machine.uml       #   PHY link state machine diagram
├── trace-debug/                    # bpftrace observability examples
│   ├── cxi_cp.bt                   #   Communication profile tracing
│   ├── cxi_map.bt                  #   Memory mapping analysis
│   └── cxi_tracepoint.h            #   Custom kernel tracepoints
├── contrib/                        # Third-party tools
│   ├── checkpatch.pl               #   Linux kernel style checker
│   └── install-git-hook.sh         #   Pre-push hook installer
├── .github/                        # GitHub and AI-context artifacts
│   ├── copilot-instructions.md     #   Primary AI coding instruction (authoritative)
│   ├── agents/                     #   Specialized AI agent definitions
│   ├── instructions/               #   Scoped coding instruction files
│   ├── prompts/                    #   Reusable task prompts
│   ├── skills/                     #   On-demand domain knowledge packages
│   ├── CODEOWNERS                  #   Code review assignments
│   ├── pull_request_template.md    #   PR checklist with risk assessment
│   └── ISSUE_TEMPLATE/             #   Bug report and feature request templates
├── Makefile                        # Top-level build (delegates to Kbuild)
├── CONTEXT.md                      # This file — AI session orientation
├── AGENTS.md                       # AI agent routing index
├── GLOSSARY.md                     # Domain abbreviation definitions
├── CONTRIBUTING.md                 # Developer workflow guide
├── SECURITY.md                     # Vulnerability reporting policy
└── README                          # Project overview, build, test instructions
```

---

## Domain Model

```
libfabric / CXI provider (userspace)
        |
        | write() / netlink
        v
   ucxi (cxi-user.ko)     ← user-space test harness
        |
        v
 CXI Core (cxi-ss1.ko)
   ├── Client Registration (cxi_client: add/remove/async_event callbacks)
   ├── ATU — Address Translation Unit (DMA memory mapping, IOVA management)
   ├── EQ  — Event Queues (hardware event delivery, interrupt coalescing)
   ├── CQ  — Command Queues (hardware command submission, doorbell writes)
   └── CP  — Communication Profiles (QoS classification, traffic shaping)
        |
   Ethernet (cxi-eth.ko)  ← standard Linux netdev + NAPI
        |
        v
   SBL / SL (cxi-sbl.ko + cxi-sl.ko)
        |
        v
   Cassini Hardware (PCIe `17db:0501` or `1590:0371`)
        |
        v
   Slingshot HPC Fabric
```

**Key struct relationships:**
- `struct cass_dev` — Cassini-specific hardware state (internal; embeds `cxi_dev`)
- `struct cxi_dev` — Generic CXI device interface (exposed to clients)
- `struct cxi_client` — Registration callbacks: `.add`, `.remove`, `.async_event`
- `struct rx_queue` / `struct tx_queue` — Ethernet RX/TX with NAPI
- `struct event_queue` — Hardware event notification object

---

## Architectural Patterns

### Client Registration
Kernel drivers (cxi-user, kfabric) register with the CXI core to receive device notifications:
```c
struct cxi_client my_client = {
    .add          = my_add_device,    // called when Cassini device appears
    .remove       = my_remove_device, // called on device removal
    .async_event  = my_async_event,   // called on hardware events
};
cxi_register_client(&my_client);
```

### Hardware Abstraction
- Internal code works with `cass_dev` (full hardware access)
- Clients receive `cxi_dev` (generic interface, safe to expose)
- Cast: `container_of(cxi_dev, struct cass_dev, cxi_dev)`

### Queue Management
All queues are page-aligned (4 KB) pre-allocated structures, event-driven:
- RX path: hardware DMA → `struct rx_queue` → NAPI poll → network stack
- TX path: network stack → `struct tx_queue` → doorbell write → hardware CQ
- Events: hardware interrupt → `struct event_queue` → client `async_event` callback

### Module Load Order (critical — violations cause silent failure)
```
cxi-sbl.ko → cxi-sl.ko → cxi-ss1.ko → cxi-user.ko
```

---

## Anti-Patterns

❌ **Out-of-order module loading** — SBL and SL must be loaded before cxi-ss1. Loading
   cxi-ss1 first causes hardware initialization to fail silently with no error message.

❌ **Unaligned DMA buffers** — Hardware requires 4 KB page-aligned buffers for all queues.
   Passing unaligned buffers causes silent hardware hang, not a kernel OOPS. Use
   `__get_free_pages()` or `kmalloc(size, GFP_KERNEL | __GFP_ZERO)` with alignment.

❌ **Client callbacks in forward order** — `client.remove` callbacks MUST be called in
   reverse registration order. Forward-order removal causes deadlock with lock hierarchy
   in cxi-ss1 locking (reverse-load-order matches reverse-lock-order).

❌ **Memory allocations in event queue hot path** — The EQ interrupt handler runs with
   IRQ disabled. `kmalloc(GFP_KERNEL)` will deadlock. Pre-allocate all buffers in the
   `rx_queue`/`tx_queue` init path.

❌ **Baremetal testing** — No baremetal testing infrastructure exists. All tests run in
   QEMU VM with netsim. Running test scripts outside the VM environment will fail or
   produce false results.

❌ **Skipping checkpatch before commit** — All PRs gate on `make check-style`. Fixing
   checkpatch violations after the fact is painful; run `make check-style` before every
   commit.

---

## Build, Test, and Run Commands

```bash
# Prerequisites (run once)
./scripts/dev-setup.sh              # Check local environment
./scripts/dev-setup.sh --fix        # Show remediation for missing prereqs
./scripts/dev-setup.sh --remote HOST --repo-path /path/to/cxi-driver  # Check remote

# Building
make                                # Build with running kernel
KDIR=/path/to/kernel make           # Build with custom kernel
make -C drivers/net/ethernet/hpe/ss1 # Build driver only
make -C ucxi                        # Build user-space tests only

# Style and smoke checks (no VM required, ~30 seconds)
make check-style                    # Run checkpatch on git diff
make check-smoke                    # Build drivers/ss1 + ucxi (no VM)

# Full test suite (requires VM)
make check                          # Build + start VM + run all 26 tests
cd tests && ./t0010-basic.t         # Run single test in VM
./scripts/startvm.sh                # Start dev VM interactively
./scripts/startvm.sh -N 2           # 2 NICs on single VM
./scripts/startvm.sh -n 2           # 2 separate VMs

# Pre-commit checklist
make check-style                    # No checkpatch violations
make check-smoke                    # Builds cleanly
./contrib/install-git-hook.sh       # Install pre-push hook (one-time)
```

---

## Testing Strategy

- **Framework**: Sharness (TAP-based shell testing), runner: `prove`
- **Naming convention**: `tests/t####-description.t` — numeric prefix groups by subsystem
- **Simulation**: QEMU + netsim simulates Cassini 1/2 as PCI device `17db:0501`/`1590:0371`
- **Execution**: All tests require the VM; `make check` orchestrates VM start + test run
- **Fast path**: `make check-smoke` builds without VM for rapid compilation validation
- **Environment**: `NETSIM_NICS=N` controls simulated NIC count; `KDIR` overrides kernel

---

## Known Gaps and Constraints

- **VM-only testing** — No baremetal test infrastructure; all validation requires QEMU + netsim
- **Sibling repo dependencies** — Requires 6 sibling repos checked out in parent directory
  (slingshot_base_link, sl-driver, nic-emu, virtme, cassini-qemu, hms-artifacts)
- **Kernel build tree required** — `/lib/modules/$(uname -r)/build` or custom `KDIR`
- **No security scanning in CI** — SAST/secret scanning not yet integrated into Jenkinsfiles
- **AI-context layer nascent** — Agents, skills, and instruction files being actively built
- **No CHANGELOG** — Release notes are embedded in the RPM spec (`cray-cxi-driver.spec`)

---

## Critical Prerequisites (for new contributors)

```bash
# Required sibling repositories (clone alongside cxi-driver)
slingshot_base_link   # SBL driver dependency
sl-driver             # SL driver dependency
nic-emu               # NIC emulation
virtme                # VM kernel testing framework (or system virtme-run binary)
cassini-qemu          # QEMU with Cassini support
hms-artifacts         # Build artifacts

# Required tools
make gcc git perl bash prove         # Build and test tools
qemu-system-x86_64                   # VM execution
```
