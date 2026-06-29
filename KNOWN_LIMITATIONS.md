# Known Limitations

This document lists known limitations, constraints, and unimplemented features
in the CXI (Cassini) driver. Each entry explains the limitation, its impact, and
any planned work.

---

## Test Infrastructure

### VM-Only Testing

**Limitation:** All integration tests require QEMU VMs with simulated Cassini
hardware (netsim). There is no baremetal CI test environment.

**Impact:** Test latency is higher than typical unit-test workflows. Developers
working within the devbootstrap environment have access to the full VM stack
(`virtme`, `cassini-qemu`, `nic-emu`, and `snif` are all managed by `devenv.yaml`
as sibling repositories). Developers outside that environment must provision those
repos separately before running the full test suite.

**Workaround:** Use `make check-smoke` for fast build validation (no VM needed, ~30
seconds). For the full test suite, clone the `virtme` repo into the devbootstrap
development environment as a sibling of this repository and run `scripts/dev-setup.sh`
to verify all prerequisites are in place.

---

## Hardware Simulation

### netsim Does Not Simulate All Hardware Behaviors

**Limitation:** The netsim QEMU plugin simulates Cassini register interfaces and
DMA but does not model all real-hardware timing, error injection, or analog
behaviors (cable detection, PHY negotiation at electrical level).

**Impact:** Some failure modes only manifest on real hardware. Tests passing in VM
do not guarantee they will pass on production Cassini nodes.

**Workaround:** Critical hardware-specific paths are tested on baremetal in the
Cassini lab during pre-release validation.

---

## SR-IOV

### VF Count Limited by Simulation

**Limitation:** In netsim VMs, the number of SR-IOV virtual functions is limited
by the QEMU device configuration. Real hardware supports up to 64 VFs per
physical function on Cassini 1 and 2, and 256 VFs on Cassini 3.

**Impact:** SR-IOV tests (`tests/t0100-sriov.t`) use a reduced VF count.

---

## Peer-to-Peer DMA (GPU Support)

### GPU P2P Requires Kernel Config and Hardware

**Limitation:** AMD GPU (`cass_amd_gpu.c`) and NVIDIA GPU (`cass_nvidia_gpu.c`)
peer-to-peer DMA paths require specific kernel config options (`CONFIG_HSA_AMD`,
`CONFIG_NVIDIA_PEERMEM`) and the corresponding GPU hardware or driver. These paths
are not tested in the standard VM environment.

**Impact:** P2P functionality is build-tested only in the standard CI pipeline.
Full validation requires access to GPU + Cassini hardware.

---

## Link Management

### SBL and SL Must Be Loaded First

**Limitation:** The CXI core driver (`cxi-ss1`) depends on the Slingshot Base Link
(`cxi-sbl`) and Slingshot Link (`cxi-sl`) drivers, which must be loaded before
`cxi-ss1`. There is no automatic dependency enforcement in the kernel module system
for this ordering.

**Impact:** Incorrect load order causes probe failures or undefined behavior.

**Workaround:** Always use `startvm-setup.sh` or the documented load order. See
[CONTRIBUTING.md](CONTRIBUTING.md).

---

## Performance

### NAPI Budget Tuning Is Not Automated

**Limitation:** The NAPI poll budget (`napi_complete_done`) is a fixed value and
not dynamically tuned to workload patterns.

**Impact:** Under very high packet rates or very small packet sizes, CPU utilization
may be suboptimal.

**Planned:** Dynamic NAPI budget adaptation is under consideration for a future
release.

---

## ABI Stability

### `docs/ABI/testing/` Entries Are "Testing" Stability

**Limitation:** sysfs attributes documented under `docs/ABI/testing/` have
"testing" ABI stability, meaning they may change between kernel versions without
deprecation notice.

**Impact:** External tools reading these sysfs paths should be prepared for
attribute removal or semantics changes.

---

## Documentation

### Hardware Register Specifications Are Not Public

**Limitation:** Cassini hardware register-level documentation (CSR specifications)
is not included in this repository.

**Impact:** CSR definitions are available via the `cassini-headers` sibling repo
in the devbootstrap environment. Deeper micro-architectural documentation requires
access to HPE internal resources.
