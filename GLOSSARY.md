# CXI Driver — Domain Glossary

Abbreviations and terms used throughout the CXI driver codebase, documentation, and hardware specifications.

## Hardware Subsystems

| Term | Full Name | Description |
|------|-----------|-------------|
| **ATU** | Address Translation Unit | Hardware component responsible for DMA memory mapping and IOVA (I/O Virtual Address) management. Maps kernel virtual addresses to hardware I/O addresses for zero-copy transfers. |
| **EQ** | Event Queue | Hardware mechanism for delivering completion events and error notifications from Cassini hardware to the driver. Polled via NAPI or interrupt-driven. |
| **CQ** | Command Queue | Hardware submission ring for sending commands to Cassini. Commands are written by the driver or by the user, and consumed by hardware asynchronously. Doorbell writes trigger processing. |
| **CP** | Communication Profile | Per-connection QoS and traffic classification configuration. Controls traffic shaping, retry policies, and routing hints for the Slingshot fabric. |
| **DMAC** | DMA Controller | Direct Memory Access controller managing bulk data transfers between host memory and Cassini hardware without CPU involvement. |
| **PtlTE** | Portals Table Entry | Hardware table entry used by the Portals network protocol (libfabric) for rendezvous message matching and one-sided operations. |

## Networking and Fabric

| Term | Full Name | Description |
|------|-----------|-------------|
| **SBL** | Slingshot Base Link driver | HPE Slingshot low-level link layer driver (`cxi-sbl.ko`). Must be loaded before SL and cxi-ss1. |
| **SL** | Slingshot Link driver | HPE Slingshot link management driver (`cxi-sl.ko`). Manages PHY state machine, link training, and fabric topology. Must be loaded after SBL and before cxi-ss1. |
| **NID** | Network ID | Hardware node identifier assigned to each Cassini device on the Slingshot fabric. Used for routing and addressing. |
| **VNI** | Virtual Network Identifier | Logical network partition identifier used for traffic isolation in multi-tenant HPC environments. |
| **AMO** | Atomic Memory Operation | Hardware-accelerated atomic operations (add, swap, compare-and-swap) on remote memory without intermediate CPU involvement. |

## Linux Kernel

| Term | Full Name | Description |
|------|-----------|-------------|
| **NAPI** | New API | Linux kernel's high-performance interrupt mitigation mechanism for network drivers. Switches from interrupt-driven to poll-driven reception under load. |
| **IOMMU** | I/O Memory Management Unit | Hardware that provides memory isolation and address translation for DMA operations. Prevents hardware from accessing unauthorized memory regions. |
| **SR-IOV** | Single Root I/O Virtualization | PCI standard that allows a single physical function (PF) to appear as multiple virtual functions (VFs) for VM passthrough and isolation. |
| **VF** | Virtual Function | An SR-IOV sub-function of a physical Cassini device, exposed to VMs or containers for direct hardware access. |
| **PF** | Physical Function | The primary PCI function of a Cassini device; manages VFs and has full hardware access. |
| **KFabric** | Kernel Fabric | In-kernel fabric interface providing the same high-performance fabric operations (libfabric semantics) to kernel-space consumers. |

## Driver Architecture

| Term | Full Name | Description |
|------|-----------|-------------|
| **cxi_dev** | CXI Device | Generic device abstraction (`struct cxi_dev`) exposed to client drivers. Hides Cassini-specific details; safe for external use. |
| **cass_dev** | Cassini Device | Internal full-hardware device state (`struct cass_dev`). Embeds `cxi_dev`; used only within cxi-ss1. |
| **cxi_client** | CXI Client | Registration callback structure (`struct cxi_client`) with `.add`, `.remove`, `.async_event` function pointers. Used by cxi-user, kfabric, cxi-eth. |

## Build and Testing

| Term | Full Name | Description |
|------|-----------|-------------|
| **netsim** | Network Simulator | HPE's Cassini hardware simulator for QEMU. Presents a virtual Cassini PCI device to the VM without requiring real hardware. |
| **virtme** | Virtual Machine Environment | Lightweight kernel testing framework that boots a kernel directly in QEMU without a full disk image. Used by `startvm.sh`. |
| **DKMS** | Dynamic Kernel Module Support | Framework that automatically rebuilds kernel modules when the kernel is upgraded. Used for RPM packaging. |
| **NBS** | Network Build System | HPE internal artifact distribution system for driver packages. |
| **TAP** | Test Anything Protocol | Standard output format for test results. Each line is `ok N - description` or `not ok N - description`. Used by Sharness. |
| **Sharness** | Shell-based Harness | Test framework (derived from git's test suite) used by `tests/*.t` scripts. Provides `test_expect_success` and related helpers. |

## File Naming Conventions

| Pattern | Meaning |
|---------|---------|
| `cass_*.c` | Cassini hardware-specific implementation (ATU, EQ, CQ, CP, core) |
| `cxi_*.c` | CXI subsystem interface (core client API, Ethernet integration, user API) |
| `t####-description.t` | Integration test: 4-digit number groups by subsystem (see tests/README.md) |
| `Jenkinsfile.*` | CI pipeline variant (cxi_vm = VM tests; rpmbuild = RPM packaging) |
