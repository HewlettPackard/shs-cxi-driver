# ucxi — User-Space CXI Interface

The `ucxi/` directory contains user-space test utilities that exercise the CXI
driver's user-space API. These tools are used in integration tests and for manual
hardware validation inside the development VM.

---

## Purpose

The `ucxi` interface provides user-space access to core CXI hardware resources
(ATU mappings, communication profiles, event queues, etc.) via `write()` on a
character device. This enables:

1. **Integration testing** — validate hardware functionality without kernel-level test code
2. **API validation** — confirm the ucxi `write()`-based command ABI behaves as documented
3. **Development support** — interactive hardware exploration during driver development

The kernel-side implementation lives in:
- `drivers/net/ethernet/hpe/ss1/cxi_user_core.c` — `write()` dispatch (`ucxi_write`)
- `drivers/net/ethernet/hpe/ss1/cxi_user_mmap.c` — mmap for queue memory

---

## Build

```bash
# From repository root
make -C ucxi

# Or directly
cd ucxi && make KDIR=/lib/modules/$(uname -r)/build
```

Produces test binaries that must be run inside a VM with `cxi-user.ko` loaded.

---

## Source Files

| File | Purpose |
|------|---------|
| `test_ucxi.c` | Main ucxi API test suite — opens `/dev/cxi0`, exercises all major commands |
| `test_ucxi_atu.c` | ATU-focused tests — memory map/unmap, IOVA allocation, error paths |
| `test_ucxi_common.c` | Shared helper functions for all ucxi tests |
| `test_ucxi_common.h` | Header for shared test utilities and command wrappers |
| `test_cp.c` | Communication profile (CP) allocation and parameter validation |
| `test_nlmsg.c` | Netlink message interface tests for device management |
| `test_csr_access.c` | CSR (Control/Status Register) read/write via command struct |

---

## Running Inside the VM

```bash
# Verify driver is loaded
lsmod | grep cxi_user
ls /dev/cxi*

# Run the main ucxi test
./test_ucxi /dev/cxi0

# ATU tests
./test_ucxi_atu /dev/cxi0

# Communication profile tests
./test_cp /dev/cxi0
```

The integration test `tests/t0300-ucxi.t` runs these automatically as part of
`make check`.

---

## Command Interface

The ucxi command interface provides user-space access to:

- **Domain allocation** — create isolated communication namespaces
- **ATU mappings** — register memory for hardware DMA access
- **Event queue allocation** — receive hardware completion events
- **Command queue allocation** — submit hardware commands
- **Communication profile allocation** — configure QoS/traffic parameters
- **Counting table (CT) allocation** — hardware atomic counter support
- **Portals table (PT) allocation** — Portals messaging endpoints

The interface is defined in `include/uapi/ethernet/cxi-abi.h`.

---

## Command Pattern in Tests

The ucxi interface uses `write()` with typed command structs.
Each command embeds an opcode and a response pointer:

```c
struct cxi_cp_alloc_cmd cmd = {};
struct cxi_cp_alloc_resp resp = {};

cmd.op   = CXI_OP_CP_ALLOC;
cmd.resp = &resp;
cmd.lni  = lni;
cmd.vni  = vni;
cmd.tc   = tc;

rc = write(dev->fd, &cmd, sizeof(cmd));
if (rc != sizeof(cmd)) {
    perror("alloc cp");
    return NULL;
}
/* resp.cp_hndl and resp.lcid are now populated */
```

The same pattern applies to free operations:

```c
struct cxi_cp_free_cmd cmd = {
    .op      = CXI_OP_CP_FREE,
    .cp_hndl = cp->cp_hndl,
};

rc = write(dev->fd, &cmd, sizeof(cmd));
if (rc != sizeof(cmd))
    perror("free cp");
```

---

## Related

- `drivers/net/ethernet/hpe/ss1/cxi_user_core.c` — kernel-side `write()` handler (`ucxi_write`)
- `include/uapi/ethernet/cxi-abi.h` — command struct and opcode definitions
- `tests/t0300-ucxi.t` — integration test that runs these utilities
- `include/linux/hpe/cxi/` — kernel-internal CXI API
