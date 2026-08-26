# CXI Driver Scripts

Utility scripts for development, VM management, debugging, and hardware testing.

---

## Development Environment

### `dev-setup.sh`

Validates the development environment prerequisites. Run before starting work.

```bash
./scripts/dev-setup.sh          # Check all prerequisites
./scripts/dev-setup.sh --fix    # Show platform-specific remediation steps
./scripts/dev-setup.sh --remote user@host  # Check prerequisites on remote host
```

Checks for: build tools (make, gcc, git, perl), required sibling repositories
(`slingshot_base_link`, `sl-driver`, `nic-emu`, `virtme`, `hms-artifacts`,
`cassini-headers`), and kernel build tree. Outputs pass/fail with a summary line.

---

## VM Management

### `startvm.sh`

Start a QEMU development VM with simulated Cassini hardware.

```bash
./scripts/startvm.sh            # Start VM with 1 Cassini NIC
./scripts/startvm.sh -N 2       # 2 NICs on a single VM
./scripts/startvm.sh -n 2       # 2 separate VMs
./scripts/startvm.sh --kdir /path/to/kernel  # Custom kernel
```

The VM auto-loads drivers via `startvm-setup.sh` and provides a shell for
interactive testing. Press Ctrl+A X to exit.

### `startvm-setup.sh`

Runs inside the VM at startup. Loads drivers in correct order:
1. `cxi-sbl.ko`
2. `cxi-sl.ko`
3. `cxi-ss1.ko`
4. `cxi-user.ko` (if available)

Not intended to be run manually.

### `startvf.sh` / `startvf-setup.sh`

Start a VM with SR-IOV virtual functions enabled. `startvf-setup.sh` is the VM-side
companion script that configures VFs at startup.

```bash
./scripts/startvf.sh            # Start VF test VM
```

### `roce-vms.sh`

Start two VMs with RoCE (RDMA over Converged Ethernet) networking for multi-node
Ethernet/RDMA testing.

```bash
./scripts/roce-vms.sh
```

---

## Ethernet Testing

### `start-eth.sh`

Configure and start Ethernet on a running Cassini device inside a VM.

```bash
./scripts/start-eth.sh          # Bring up cxi0 as Ethernet interface
```

Assigns IP addresses, sets link parameters, and activates the interface.

### `test-eth-driver.sh`

Run a quick Ethernet functional test (TX/RX ping, link state transitions).

```bash
./scripts/test-eth-driver.sh
```

---

## Debug and Introspection

### `ddebug.sh`

Enable or disable dynamic debug messages for CXI modules.

```bash
./scripts/ddebug.sh enable      # Enable all CXI debug output
./scripts/ddebug.sh enable cass_atu.c   # File-specific debug
./scripts/ddebug.sh disable     # Disable all
```

### `cxi_mgmt`

Command-line management tool for CXI device configuration. Queries and sets
device parameters via netlink.

```bash
./scripts/cxi_mgmt list         # List all CXI devices
./scripts/cxi_mgmt info cxi0    # Show device info
```

### `cxi_vf.sh`

Script for SR-IOV virtual function configuration.

```bash
./scripts/cxi_vf.sh create 4   # Create 4 VFs on cxi0
./scripts/cxi_vf.sh destroy    # Remove all VFs
```

---

## BPFtrace Observability

These scripts require `bpftrace` and must be run inside a VM with the driver loaded.

### `csr_access.bt`

Trace CSR (Control/Status Register) read and write operations to identify
unexpected hardware register accesses.

```bash
bpftrace scripts/csr_access.bt
```

### `eq_alloc.bt`

Trace event queue allocations and deallocations to detect EQ leaks.

```bash
bpftrace scripts/eq_alloc.bt
```

### `eth-frags.bt`

Trace Ethernet packet fragment processing for scatter-gather debugging.

```bash
bpftrace scripts/eth-frags.bt
```

See also [trace-debug/](../trace-debug/) for additional bpftrace examples.

---

## Related Directories

- `tests/` — Integration test suite (run with `make check`)
- `trace-debug/` — Additional bpftrace examples for performance profiling
- `ucxi/` — User-space test utilities for the ucxi interface
