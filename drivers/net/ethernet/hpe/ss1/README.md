# CXI Core Driver (cxi-ss1) — Module Reference

This directory contains the HPE Cassini core driver (`cxi-ss1`) and Ethernet driver
(`cxi-eth`). It builds into two kernel modules:
- `cxi-ss1.ko` — core hardware driver (ATU, EQ, CQ, CP, client registration)
- `cxi-eth.ko` — Ethernet netdev integration (bundled with cxi-ss1)

---

## Build

```bash
# From repository root (uses running kernel)
make

# From this directory
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Custom kernel
KDIR=/path/to/kernel make
```

---

## Module Architecture

```
cxi-ss1.ko
├── Client registration (cxi_core.c)       — add/remove/async_event callbacks
├── Device management (cass_core.c)        — PCI probe/remove, hardware init
├── Address Translation (cass_atu.c)       — DMA IOVA mapping
├── Event Queues (cass_eq.c)              — hardware event delivery
├── Command Queues (cass_cq.c)            — hardware command submission
├── Communication Profiles (cass_cpt.c)   — QoS / traffic shaping
├── SR-IOV (cass_sriov.c, cass_vf.c)     — virtual function management
├── Link management (cass_link.c, cass_sl.c, cass_sbl.c)
├── Telemetry (cass_telem.c)             — hardware counters and stats
└── User-space API (cxi_user_core.c)     — write()/netlink for ucxi client

cxi-eth.ko (embedded in cxi-ss1)
├── Netdev integration (cxi_eth.c)        — register_netdev, NAPI setup
├── TX/RX operations (cxi_eth_ops.c)     — packet processing
├── ethtool support (cxi_ethtool.c)      — stats, link settings
└── RoCE/RDMA integration (cass_rmu.c)  — RDMA over Converged Ethernet
```

---

## Key Source Files

### Core Subsystems

| File | Purpose |
|------|---------|
| `cass_core.c` / `cass_core.h` | PCI device lifecycle: probe, remove, hardware initialization, IRQ setup |
| `cxi_core.c` | Client registration subsystem: `cxi_register_client()`, `cxi_unregister_client()`, device notification dispatch |
| `cxi_user_core.c` | User-space ioctl handler for `cxi-user.ko` and the `ucxi/` test utilities |

### Hardware Subsystems

| File | Purpose |
|------|---------|
| `cass_atu.c` | Address Translation Unit — IOVA allocation, DMA buffer mapping/unmapping |
| `cass_hmm.c` | HMM (Heterogeneous Memory Management) — On-Demand Paging (ODP) support |
| `cass_eq.c` | Event Queues — allocation, polling, interrupt coalescing, depth management |
| `cass_cq.c` | Command Queues — ring buffer management, doorbell writes, backpressure |
| `cass_cpt.c` | Communication Profiles — QoS parameter configuration, traffic classification |
| `cass_dmac.c` | DMA Controller — bulk transfer management |
| `cass_irq.c` | Interrupt routing and coalescing configuration |
| `cass_sysfs.c` | sysfs attribute registration for `/sys/class/cxi/cxi*/device/` |
| `cass_ss1_debugfs.c` | debugfs entries for `/sys/kernel/debug/cxi/` |
| `cass_errors.c` | Hardware error classification, error flag interpretation |
| `cass_telem.c` | Hardware telemetry counters and statistics |

### Ethernet Driver

| File | Purpose |
|------|---------|
| `cxi_eth.c` | Main Ethernet integration: `register_netdev()`, NAPI setup, interrupt handlers |
| `cxi_eth_ops.c` | TX/RX packet processing, channel management, queue lifecycle |
| `cxi_ethtool.c` | ethtool operations: stats, link settings, ring parameters |
| `cass_rmu.c` / `cass_rmu_eth.c` | RoCE/RDMA MAC-level processing |
| `cass_ptp.c` | PTP (Precision Time Protocol) hardware timestamping |

### Link and PHY

| File | Purpose |
|------|---------|
| `cass_link.c` | Link state machine orchestration |
| `cass_sl.c` / `cass_sl_io.c` | Slingshot Link driver integration |
| `cass_sbl.c` | Slingshot Base Link driver integration |
| `cass_phy.c` / `cass_cable.c` | PHY and cable management |
| `cass_hni.c` | HNI (High-speed Network Interface) configuration |

### Resource Management

| File | Purpose |
|------|---------|
| `cass_sriov.c` | SR-IOV physical function management |
| `cass_vf.c` / `cass_vf_notif.c` | Virtual function lifecycle and notifications |
| `cass_svc.c` | Service (communication endpoint) management |
| `cass_rgroup.c` / `cxi_rgroup.c` | Resource group allocation (bandwidth partitioning) |
| `cass_rgid.c` | Resource group ID management |
| `cass_lni.c` | Logical Network Interface management |
| `cass_pt.c` | Portals Table management (PtlTE entries) |
| `cass_ct.c` | Counting Table management |

### QoS and Profiles

| File | Purpose |
|------|---------|
| `cxi_qos_profiles.c` | QoS profile CRUD operations |
| `cxi_rx_profile.c` / `cxi_tx_profile.c` | RX/TX traffic profile management |
| `cxi_rxtx_profile.c` / `cxi_rxtx_profile_list.c` | Combined RX/TX profile lists |
| `cass_rx_tx_profile.c` | Hardware-level RX/TX profile application |
| `cass_tc.c` | Traffic class configuration |

### GPU Integration (optional)

| File | Purpose |
|------|---------|
| `cass_amd_gpu.c` | AMD GPU peer-to-peer DMA support |
| `cass_nvidia_gpu.c` | NVIDIA GPU peer-to-peer DMA support |
| `cass_dma_buf.c` | DMA-BUF integration for GPU/accelerator zero-copy |
| `cass_p2p.c` | Generic peer-to-peer DMA coordination |

---

## Naming Conventions

| Pattern | Meaning |
|---------|---------|
| `cass_*.c` | Cassini hardware-specific implementation |
| `cxi_*.c` | CXI subsystem interface (exposed to clients) |
| `cass_dev.*` | Internal hardware device struct (`struct cass_dev`) |
| `cxi_dev` | External device interface (`struct cxi_dev`, embedded in `cass_dev`) |

---

## Load Order (Must be followed exactly)

```bash
insmod cxi-sbl.ko       # Slingshot Base Link
insmod cxi-sl.ko        # Slingshot Link
insmod cxi-ss1.ko       # CXI core driver + Ethernet
insmod cxi-user.ko      # User-space communication (optional)
```

---

## Debugging

```bash
# Enable debug messages for specific files
echo 'file cass_atu.c +p' > /proc/dynamic_debug/control
echo 'module cxi_ss1 +p' > /proc/dynamic_debug/control

# sysfs interface
ls /sys/class/cxi/cxi0/device/
cat /sys/class/cxi/cxi0/device/err_flgs_irqa

# debugfs
ls /sys/kernel/debug/cxi/cxi0/
```

See [README-debugging.md](../../../../../../README-debugging.md) for the full debugging guide.
