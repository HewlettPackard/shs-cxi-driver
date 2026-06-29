---
name: cxi-hardware-patterns
description: >
  Hardware implementation patterns for the CXI (Cassini) driver. Covers ATU
  (DMA memory mapping), EQ (event queues), CQ (command queues), CP (communication
  profiles), hardware abstraction boundaries (cxi_dev vs cass_dev), DMA buffer
  alignment requirements, and event-driven queue lifecycle. Load when implementing
  or debugging any hardware subsystem in drivers/net/ethernet/hpe/ss1/.
---

# CXI Hardware Implementation Patterns

## Hardware Abstraction Boundary

Two struct types represent a Cassini device at different abstraction levels:

```c
/* INTERNAL — only used within cxi-ss1 */
struct cass_dev {
    struct cxi_dev cxi_dev;   /* must be first — used for container_of */
    /* hardware-specific fields */
    void __iomem   *regs;
    struct pci_dev *pdev;
    /* ... ATU, EQ, CQ state ... */
};

/* EXTERNAL — exposed to client drivers (cxi-user, kfabric, cxi-eth) */
struct cxi_dev {
    /* safe, hardware-agnostic fields only */
};

/* Cast pattern (inside cxi-ss1 only) */
struct cass_dev *hw = container_of(cxi_dev, struct cass_dev, cxi_dev);
```

**Rule:** Never expose `struct cass_dev` to client drivers. Never call `container_of`
on a `cxi_dev` pointer from outside `cxi-ss1`.

---

## ATU — Address Translation Unit

### Purpose
Maps kernel virtual addresses to hardware IOVA for DMA. Manages the I/O virtual
address space so hardware can directly read/write host memory safely.

### Allocation Pattern
```c
/* Map a kernel buffer for hardware DMA access */
ret = cass_atu_map(hw, virt_addr, size, flags, &iova_handle);
if (ret)
    return ret;

/* Use iova_handle for hardware commands */
cmd.src_addr = iova_handle.iova;

/* Unmap when done */
cass_atu_unmap(hw, &iova_handle);
```

### Constraints
- Always unmap in error paths (IOVA leak causes eventual ATU exhaustion)
- Mappings are per-device; not portable across Cassini devices
- Large mappings (>= 2 MB) use huge pages automatically if available

---

## EQ — Event Queue

### Purpose
Hardware delivers completion events and error notifications through event queues.
The driver polls EQs in NAPI context for Ethernet traffic. For RDMA traffic,
user-space polls EQs directly using helpers from `libcassini.h` (in the
`cassini-headers` repository).

### Lifecycle
```c
/* Allocate (in .add callback or driver init) */
eq = cass_eq_alloc(hw, depth, flags);
if (IS_ERR(eq))
    return PTR_ERR(eq);

/* Poll for events (NAPI context — no sleeping allowed) */
while ((event = cass_eq_get_event(eq)) != NULL) {
    process_event(event);
    cass_eq_ack_event(eq, event);
}

/* Free (in .remove callback — after stopping all traffic) */
cass_eq_free(eq);
```

### Critical Rules
- EQ polling runs in NAPI context with BH disabled — no `GFP_KERNEL` allocations
- Pre-allocate all event handler buffers before enabling the EQ
- EQ overflow is not fully silent: dropped event count is visible via
  `status->unackd_dropped_event` in the EQ status descriptor
- Always drain the EQ before freeing it (`cass_eq_drain()`)

---

## CQ — Command Queue

### Purpose
Submits commands to Cassini hardware. Commands are written to a ring buffer;
hardware consumes them when the doorbell register is written.

### Command Submission Pattern
```c
/* Acquire a CQ slot */
ret = cass_cq_get_slot(cq, &cmd_ptr);
if (ret)
    return ret; /* CQ full — retry or backpressure caller */

/* Fill the command */
cmd_ptr->opcode = CXI_CMD_<OPERATION>;
cmd_ptr->address = iova;
cmd_ptr->length = size;

/* Submit — doorbell write triggers hardware processing */
cass_cq_submit(cq);
```

### Constraints
- Never write partial commands — fill all fields before `cass_cq_submit()`
- CQ depth is fixed at allocation time; backpressure the caller when full
- Commands are processed asynchronously; completion arrives via EQ

---

## CP — Communication Profile

### Purpose
Configures per-connection QoS: traffic class, retry policy, and fabric routing
hints. Each active connection references a CP by ID.

### Lifecycle
```c
/* Allocate a CP with specific QoS parameters */
cp = cass_cp_alloc(hw, &params);
if (IS_ERR(cp))
    return PTR_ERR(cp);

/* CP ID is used in subsequent commands */
cmd.cp_id = cp->id;

/* Free when connection closes */
cass_cp_free(cp);
```

### Constraints
- CP slots are a limited hardware resource — free unused CPs promptly
- CP parameters cannot be modified after allocation; free and re-allocate to change,
  except: if the CP was allocated with the exclusive flag, the VNI can be updated
  via `cxi_cp_modify()` while the CP is not in use

---

## DMA Buffer Alignment

All queue structures (EQ ring, CQ ring, RX/TX descriptors) require **4 KB alignment**:

```c
/* CORRECT: page-aligned allocation */
void *buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
                                      get_order(size));
if (!buf)
    return -ENOMEM;

/* INCORRECT: kmalloc is not guaranteed page-aligned for large sizes */
void *buf = kmalloc(size, GFP_KERNEL);  /* DO NOT use for queue memory */
```

**Cleanup:**
```c
free_pages((unsigned long)buf, get_order(size));
```

### Why This Matters
Cassini hardware reads the physical base address of queues from registers. If the
address is not page-aligned, the hardware uses the wrong physical address for DMA
and silently corrupts or hangs — no kernel OOPS, no error message.

---

## Event-Driven Queue Processing — Ethernet RX Path

```
Hardware DMA → rx_queue ring buffer (pre-allocated, 4KB-aligned)
                           ↓
              Hardware writes completion to EQ
                           ↓
              NAPI poll: cass_eq_get_event() → process rx descriptor
                           ↓
              Build skb from rx buffer → netif_receive_skb()
                           ↓
              Replenish rx_queue with new buffer
```

**Key rule:** The NAPI poll function must complete within its budget. If `work_done
>= budget`, return `budget` (reschedule). If `work_done < budget`, call
`napi_complete_done()` and re-enable interrupts.

---

## Reference Counting for Devices

```c
/* Increment before async use of cxi_dev */
cxi_dev_get(cxi_dev);

/* Decrement when done — triggers cxi_dev_release() if count reaches zero */
cxi_dev_put(cxi_dev);
```

Always call `cxi_dev_get()` before storing a `cxi_dev` pointer for use in a
work queue, timer, or deferred context. Call `cxi_dev_put()` when the deferred
work completes.
