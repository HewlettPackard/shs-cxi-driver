---
applyTo: "drivers/**/*.c,drivers/**/*.h,include/**/*.h,ucxi/**/*.c,ucxi/**/*.h"
---

# CXI Driver — Kernel Driver Patterns

These rules apply to all C source files in the CXI driver. Follow them precisely;
violations are caught by `make check-style` (checkpatch.pl) and block PR merges.

## File Naming

- `cass_*.c` / `cass_*.h` — Cassini hardware-specific code (ATU, EQ, CQ, CP, core)
- `cxi_*.c` / `cxi_*.h` — CXI subsystem interface code (client API, Ethernet, user API)
- Never mix hardware implementation details into `cxi_*` files
- New hardware subsystem files must follow the `cass_<subsystem>.c` pattern

## Module Load Order

The correct load sequence is strictly enforced by hardware initialization dependencies:
```
cxi-sbl.ko → cxi-sl.ko → cxi-ss1.ko → cxi-user.ko
```
Never attempt to load cxi-ss1 before SBL and SL are loaded. Failures are silent.

## Error Handling

- Functions returning pointers: use `ERR_PTR(-errno)` on error, test with `IS_ERR()`
- Functions returning integers: use negative errno values (`-ENOMEM`, `-EINVAL`, etc.)
- Always propagate errors; never swallow them with a bare `return`
- Use `PTR_ERR()` to extract the error code from a pointer
- Check every allocation and every hardware operation return code

```c
/* Correct pointer return pattern */
struct cxi_dev *cxi_get_device(int idx)
{
    struct cass_dev *dev = find_device(idx);
    if (!dev)
        return ERR_PTR(-ENODEV);
    return &dev->cxi_dev;
}

/* Correct caller pattern */
cxi_dev = cxi_get_device(idx);
if (IS_ERR(cxi_dev))
    return PTR_ERR(cxi_dev);
```

## Memory Alignment

- Hardware queues (RX, TX, EQ, CQ) require **4 KB page-aligned** buffers
- Use `__get_free_pages(GFP_KERNEL, order)` for aligned queue allocations
- Never use `kmalloc()` for queue memory without verifying alignment
- Document alignment requirements in struct definitions with a comment

## Client Registration

When implementing a new CXI client (e.g., a new kernel subsystem that uses Cassini):

```c
static struct cxi_client my_client = {
    .add          = my_add_device,    /* required */
    .remove       = my_remove_device, /* required */
    .async_event  = my_async_event,   /* required */
};

/* Register at module init */
ret = cxi_register_client(&my_client);

/* Unregister at module exit — removes trigger remove() on all active devices */
cxi_unregister_client(&my_client);
```

Client `.remove` callbacks are called in reverse registration order. Implement cleanup
in `.remove` to match what `.add` allocated — in reverse order.

## Hardware Abstraction Boundary

- External (client-facing) code: use `struct cxi_dev *`
- Internal (cxi-ss1 only) code: use `struct cass_dev *` via `container_of()`
- Never expose `struct cass_dev` to client drivers
- Cast pattern: `struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cxi_dev);`

## Locking Discipline

- Event queue (EQ) interrupt handler runs with IRQs disabled — no sleeping allocations
- Use `GFP_ATOMIC` for any allocation in interrupt or softirq context
- Pre-allocate queue buffers in the `.add` / init path, never in the hot data path
- Document lock ordering in comments when acquiring multiple locks

## Kernel-Doc Comments

All exported functions and public structs must have kernel-doc format comments:

```c
/**
 * cxi_register_client - Register a CXI subsystem client
 * @client: Client registration structure with callbacks
 *
 * Returns 0 on success, negative errno on failure.
 * The @client structure must remain valid until cxi_unregister_client() is called.
 */
int cxi_register_client(struct cxi_client *client)
```
