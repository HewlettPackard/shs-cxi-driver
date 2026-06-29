# CXI Driver Architecture

This document describes the architecture of the CXI (Cassini) kernel driver for
HPE's Cassini 1 and Cassini 2 high-performance networking hardware.

---

## System Context

The CXI driver operates as a core kernel module that mediates access between
high-performance computing applications and Cassini ASIC hardware. It is part of
HPE's Slingshot fabric ecosystem.

```
┌────────────────────────────────────────────────────────────────────┐
│ User Space                                                         │
│  libfabric / CXI provider  │  MPI runtime  │  other HPC apps       │
└───────────────────┬────────────────────────────────────────────────┘
                    │ POSIX / write()
┌───────────────────▼────────────────────────────────────────────────┐
│ Kernel Space                                                       │
│                                                                    │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐                         │
│  │ cxi-eth  │  │ cxi-user  │  │ kfabric  │  ← client drivers.      │
│  └────┬─────┘  └─────┬─────┘  └────┬─────┘                         │
│       │              │             │                               │
│  ┌────▼──────────────▼─────────────▼──────────────────────────┐    │
│  │                CXI Core (cxi-ss1)                          │    │
│  │   Client registration │ ATU │ EQ │ CQ │ CP │ SVC │ RGroup  │    │
│  └────▲───────────────────────────┬───────────────────────────┘    │
│       │(link mgmt)                │                                │
│  ┌────▼────────────────────────┐  │                                │
│  │ SBL (Slingshot Base Link)   │  │                                │
│  │ SL  (Slingshot Link)        │  │                                │
│  └─────────────────────────────┘  │                                │
└───────────────────────────────────┼────────────────────────────────┘
                                    │ PCIe
┌───────────────────────────────────▼────────────────────────────────┐
│ Cassini ASIC (1 or 2)                                              │
│  Fabric port │ HNI │ ATU │ Event queues │ Command queues │ PHY     │
└────────────────────────────────────────────────────────────────────┘
```

---

## Module Descriptions

### cxi-ss1 — CXI Core Driver

**Source:** `drivers/net/ethernet/hpe/ss1/`

The central kernel module. Owns the PCI device lifecycle, exports the CXI
subsystem API to client drivers, and implements all hardware resource management.

**PCI device IDs:**
- Cassini 1: `17db:0501`
- Cassini 2: `1590:0371`

**Key responsibilities:**
- PCI probe/remove lifecycle (`cass_core.c`)
- Client registration and notification (`cxi_core.c`)
- Hardware resource allocation: ATU, EQ, CQ, CP, SVC, LNI, CT, PT
- Interrupt handling and event delivery
- sysfs and debugfs interfaces
- Error detection, reporting, and recovery

### cxi-eth — Ethernet Driver

**Source:** `drivers/net/ethernet/hpe/ss1/cxi_eth.c`, `cxi_eth_ops.c`

Registers Cassini as a standard Linux netdev. Built into the same `.ko` as the
CXI core but logically separate. Uses NAPI for RX processing, ring buffer
management for TX/RX queues, and ethtool for configuration.

### cxi-user — User-Space Interface

**Source:** `drivers/net/ethernet/hpe/ss1/cxi_user_core.c` (kernel side)

Exposes CXI resources to user space via a character device (`/dev/cxi*`). Used
by libfabric and the `ucxi/` test utilities. Registers as a CXI client.

### kfabric — In-Kernel Fabric Interface

External module. Registers as a CXI client to use Cassini hardware for in-kernel
RDMA operations. Not included in this repository.

---

## Layered Architecture

### Layer 0: Hardware (Cassini ASIC)

- PCIe BAR-mapped control/status registers (CSRs)
- DMA-capable hardware with its own IOMMU (ATU)
- Hardware event queues for asynchronous completion delivery
- Command queues for control plane operations
- Network-on-chip fabric with up to 200 Gb/s bandwidth

### Layer 1: Hardware Abstraction (cass_dev)

`struct cass_dev` is the internal representation of a Cassini device. It embeds
`struct cxi_dev` as its first field (for safe `container_of` casting) and adds
all hardware-specific state.

**Key files:** `cass_core.c`, `cass_core.h`

### Layer 2: CXI Subsystem API (cxi_dev)

`struct cxi_dev` is the external representation exposed to client drivers. It
carries only the information clients need without exposing hardware internals.

The CXI subsystem API is defined in `include/linux/hpe/cxi/cxi.h`.

**Key files:** `cxi_core.c`, `include/linux/hpe/cxi/`

### Layer 3: Client Drivers

Client drivers register with the CXI subsystem using:

```c
struct cxi_client my_client = {
    .add          = my_add_device,
    .remove       = my_remove_device,
    .async_event  = my_async_event,
};
cxi_register_client(&my_client);
```

The `add` callback is called for each existing and future CXI device. The `remove`
callback is called before device removal. `async_event` delivers hardware events
(link state changes, errors).

---

## Key Subsystems

### ATU — Address Translation Unit

**Source:** `cass_atu.c`

Maps kernel virtual addresses to I/O virtual addresses (IOVA) for hardware DMA.
Manages the IOVA address space with an IOMMU-backed allocator.

- All DMA buffers must be registered via `cass_atu_map()` before hardware use
- Buffers must be unmapped via `cass_atu_unmap()` when no longer needed
- IOVA leaks cause eventual ATU exhaustion (silent packet drops or hangs)

### EQ — Event Queue

**Source:** `cass_eq.c`

Ring buffer in host memory that hardware writes completion events into. The driver
polls EQs in NAPI context (Ethernet) or interrupt context (fabric).

- Pre-allocate all event handler resources before enabling an EQ
- EQ overflow drops events silently; size queues appropriately
- Always drain before free (`cass_eq_drain()`)

### CQ — Command Queue

**Source:** `cass_cq.c`

Ring buffer in host memory that the driver writes hardware commands into. Hardware
reads commands when the doorbell register is written.

- Fill all fields before calling `cass_cq_submit()`
- When CQ is full, backpressure the caller (do not spin-wait in kernel context)
- Completions arrive via EQ, not inline

### CP — Communication Profile

**Source:** `cass_cpt.c`

Per-connection QoS descriptor. Configures traffic class, retry policy, and fabric
routing. CP slots are a limited hardware resource.

### SVC — Service

**Source:** `cass_svc.c`

A communication endpoint that encapsulates a CP and resource limits for a
specific communication pattern. Services are allocated per-client.

### RGroup — Resource Group

**Source:** `cass_rgroup.c`, `cxi_rgroup.c`

Partitions hardware bandwidth resources among competing clients or tenants.
Configurable via configfs (`/sys/kernel/config/cxi/`).

### DMAC — DMA Controller

**Source:** `cass_dmac.c`

Manages bulk DMA transfer operations independent of the fabric data path.

### LNI — Logical Network Interface

**Source:** `cass_lni.c`

Logical endpoint for network communication, tying together addressing, QoS, and
resource group membership.

---

## Data Flow: Ethernet TX Path

```
netdev TX queue
       │
       ▼
cxi_eth_ops.c: cxi_eth_start_xmit()
       │
       ├─ ATU: map skb data buffers → IOVA
       │
       ├─ CQ: write TX descriptor (IOVA, length, CP ID)
       │
       └─ doorbell write → hardware processes TX
              │
              ▼
       Hardware DMA reads packet data from host memory
              │
              ▼
       Packet transmitted on fabric port
              │
              ▼
       Completion event written to EQ
              │
              ▼
       NAPI poll: cass_eq_get_event() → free TX buffer
```

## Data Flow: Ethernet RX Path

```
Packet arrives on fabric port
       │
       ▼
Hardware DMA writes packet into pre-posted RX buffer (host memory)
       │
       ▼
Hardware writes completion event to EQ
       │
       ▼
NAPI poll (budget-limited): cxi_eth_ops.c
       │
       ├─ Read EQ completion → identify RX buffer
       ├─ Build skb from RX buffer
       ├─ netif_receive_skb() → Linux network stack
       └─ Replenish RX ring with new buffer + ATU mapping
```

---

## Module Dependency and Load Order

```
cxi-sbl.ko          Slingshot Base Link (external repo)
    │
cxi-sl.ko           Slingshot Link (external repo)
    │
cxi-ss1.ko          CXI core + Ethernet
    │
cxi-user.ko         User-space interface (optional)
```

**Critical:** `cxi-ss1` will fail to probe if SBL/SL symbols are not available.
Loading in the wrong order produces `Unknown symbol` errors.

---

## Configuration Interfaces

| Interface | Path | Purpose |
|-----------|------|---------|
| sysfs | `/sys/class/cxi/cxi*/device/` | Per-device status and configuration |
| debugfs | `/sys/kernel/debug/cxi/` | Debug counters, queue state |
| configfs | `/sys/kernel/config/cxi/` | Resource groups, RX/TX profiles |
| write() | `/dev/cxi*` | User-space hardware access (ucxi) |
| netlink | — | Device management (cxi_mgmt) |
| ethtool | standard | Ethernet configuration and statistics |
| ProcFS | `/proc/dynamic_debug/control` | Enable/disable debug messages |

---

## Hardware Simulation

All development uses QEMU with the `netsim` plugin simulating Cassini hardware.
No real hardware is required for driver development or CI testing.

- netsim provides PCIe device emulation, register access, and DMA
- Does not model all real-hardware behaviors (analog PHY, cable detection)
- Multi-NIC testing: `./scripts/startvm.sh -N 2` (two NICs, one VM)
- Multi-VM testing: `./scripts/startvm.sh -n 2` (two VMs, separate network)

---

## Error Handling Strategy

1. **Hardware errors** — detected via error flags in sysfs (`err_flgs_irqa`)
2. **Propagation** — `ERR_PTR()` / `PTR_ERR()` for pointers; negative errno for integers
3. **Client notification** — errors delivered via `async_event` callback
4. **Recovery** — transient errors (link flap) do not panic; critical errors trigger device reset
5. **No force-unload** — client removal waits for completion rather than forcing teardown

---

## Related Documents

- [CONTEXT.md](CONTEXT.md) — Session orientation and quick reference
- [GLOSSARY.md](GLOSSARY.md) — Domain abbreviation definitions
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) — Current limitations and constraints
- [README-debugging.md](README-debugging.md) — Debugging guide
- [drivers/net/ethernet/hpe/ss1/README.md](drivers/net/ethernet/hpe/ss1/README.md) — Source file reference
- [docs/ABI/testing/](docs/ABI/testing/) — Public ABI documentation
