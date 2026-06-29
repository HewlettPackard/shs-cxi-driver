---
name: cxi-glossary
description: >
  Domain glossary for the CXI (Cassini) driver. Defines all hardware subsystem
  abbreviations, networking terms, kernel terms, and driver architecture vocabulary.
  Load when you encounter unfamiliar abbreviations like ATU, EQ, CQ, CP, SBL, SL,
  DMAC, NAPI, SR-IOV, KFabric, netsim, or cass_dev/cxi_dev.
---

# CXI Domain Glossary

## Hardware Subsystems

**ATU** — Address Translation Unit
: Hardware component managing DMA memory mapping and IOVA (I/O Virtual Address)
space. Translates kernel virtual addresses to hardware I/O addresses for zero-copy
transfers. Source: `cass_atu.c`, `cass_atu.h`.

**EQ** — Event Queue
: Hardware mechanism delivering completion events and error notifications from
Cassini to the driver. Can be polled (NAPI) or interrupt-driven. Overflows cause
hardware stall. Source: `cass_eq.c`.

**CQ** — Command Queue
: Hardware submission ring for sending commands to Cassini. Driver writes commands;
hardware consumes asynchronously when triggered by doorbell write. Source: `cass_cq.c`.

**CP** — Communication Profile
: Per-connection QoS and traffic classification configuration. Controls traffic
shaping, retry policies, and routing hints for the Slingshot fabric. Source: `cass_cpt.c`.

**DMAC** — DMA Controller
: Direct Memory Access controller for bulk data movement between host memory and
Cassini hardware without CPU involvement. Source: `cass_dmac.c`.

**PtlTE** — Portals Table Entry
: Hardware table entry for the Portals network protocol. Used by libfabric for
rendezvous message matching and one-sided RDMA operations.

## Fabric and Networking

**SBL** — Slingshot Base Link
: HPE's low-level link layer driver (`cxi-sbl.ko`). Manages physical link training,
signal integrity, and electrical characteristics. Must load before SL and cxi-ss1.

**SL** — Slingshot Link
: HPE's link management driver (`cxi-sl.ko`). Manages PHY state machine, link
training negotiation, topology discovery. Must load after SBL and before cxi-ss1.

**NID** — Network ID
: Hardware node identifier for each Cassini device on the Slingshot fabric. Used
for packet routing and addressing. Configured via sysfs.

**VNI** — Virtual Network Identifier
: Logical network partition ID for multi-tenant HPC environment isolation.

**AMO** — Atomic Memory Operation
: Hardware-accelerated atomic operations (add, swap, CAS) on remote memory without
intermediate CPU involvement. Tested in `t0900-amo_remap.t`.

**KFabric** — Kernel Fabric
: In-kernel fabric interface providing libfabric-like semantics to kernel consumers.
One of the CXI core client drivers.

## Linux Kernel

**NAPI** — New API
: Linux high-performance interrupt mitigation for network drivers. Under load,
switches from interrupt-driven to poll-driven RX processing to batch completions.

**IOMMU** — I/O Memory Management Unit
: Hardware providing memory isolation and address translation for DMA. Prevents
hardware from accessing unauthorized memory. Simulated via Intel VT-d in QEMU.

**SR-IOV** — Single Root I/O Virtualization
: PCI standard allowing one physical function (PF) to appear as multiple virtual
functions (VFs) for VM passthrough. Tested in `t0100-sriov.t`.

**VF / PF** — Virtual Function / Physical Function
: VF: SR-IOV sub-function exposed to VMs. PF: primary Cassini PCI function with
full hardware management access.

## Driver Architecture

**cxi_dev** / **cass_dev**
: `struct cxi_dev` — generic interface exposed to client drivers.
  `struct cass_dev` — full hardware state, internal to cxi-ss1, embeds cxi_dev.
  Cast: `container_of(cxi_dev_ptr, struct cass_dev, cxi_dev)`.

**cxi_client**
: `struct cxi_client` registration callbacks: `.add(cxi_dev)`, `.remove(cxi_dev)`,
  `.async_event(cxi_dev, event)`. Used by cxi-user, kfabric, cxi-eth.

## Build and Testing

**netsim** — Network Simulator
: HPE's Cassini hardware emulator for QEMU. Presents a virtual Cassini PCI device
(`17db:0501` for Cassini 1, `1590:0371` for Cassini 2) without real hardware.

**virtme** — Virtual Machine Environment
: Lightweight kernel testing framework. Boots a kernel directly in QEMU using the
host's root filesystem. Used by `startvm.sh`.

**DKMS** — Dynamic Kernel Module Support
: Automatically rebuilds driver modules when the kernel is upgraded. Used for RPM
packaging (`dkms.conf.in`, `cray-cxi-driver.spec`).

**NBS** — New Build System
: HPE internal artifact distribution for driver packages (`Jenkinsfile.nbs.*`).

**Sharness** — Shell-based Harness
: Git-derived test framework used by `tests/*.t` scripts. Provides
`test_expect_success "description" "shell commands"` and TAP output.

**TAP** — Test Anything Protocol
: Standard test output format: `ok N - description` / `not ok N - description`.
Used by Sharness; consumed by `prove`.
