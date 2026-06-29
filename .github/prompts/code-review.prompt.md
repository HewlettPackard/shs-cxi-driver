---
mode: ask
description: >
  Review a CXI driver change for correctness, safety, and code quality.
  Produces a structured review with findings grouped by severity.
---

# CXI Driver Code Review

Review the changes in the current branch (or the provided diff) for the CXI
(Cassini) kernel driver. Produce a structured review with findings grouped by
severity.

## Review Checklist

### 1. Code Style
- [ ] No checkpatch.pl violations (`make check-style`)
- [ ] Line length ≤ 80 characters as a general guideline; use good judgement for exceptions (e.g. long strings or URLs)
- [ ] Naming: `cass_*` for hardware-internal, `cxi_*` for client-facing
- [ ] Commit message format: `subsystem: short description` (50 chars subject)
- [ ] No trailing whitespace

### 2. Hardware Risk
- [ ] DMA buffers are page-aligned (4 KB) — not `kmalloc` for queue memory
- [ ] All ATU mappings are unmapped in error paths
- [ ] No sleeping in NAPI poll functions
- [ ] CQ slots fully filled before `cass_cq_submit()`
- [ ] EQ drained before `cass_eq_free()`

### 3. Error Handling
- [ ] All error paths return `-errno` (negative error codes)
- [ ] `ERR_PTR()` / `PTR_ERR()` used correctly for pointer returns
- [ ] No resource leaks in early-exit error paths
- [ ] `goto` cleanup labels in correct reverse-allocation order

### 4. Memory Safety
- [ ] No use-after-free: `cxi_dev_get()` before async, `cxi_dev_put()` after
- [ ] `kref` used for shared objects with multiple owners
- [ ] `container_of(cxi_dev → cass_dev)` only inside `cxi-ss1` module
- [ ] No integer overflow in size calculations for allocations

### 5. Locking
- [ ] spinlocks held only in non-sleeping context
- [ ] lock/unlock pairs balanced on all code paths
- [ ] No double-acquire of the same spinlock

### 6. Client Interface Changes
- [ ] Public API changes in `include/linux/hpe/cxi/` are backward compatible
- [ ] New ioctls have corresponding `docs/ABI/testing/` entries
- [ ] Client registration callbacks (`add`, `remove`, `async_event`) handle errors

### 7. Test Evidence
- [ ] New functionality has a corresponding test in `tests/t*.t`
- [ ] Existing tests still pass (`make check`)
- [ ] `make check-smoke` passes (build-only validation)

### 8. Documentation
- [ ] `drivers/net/ethernet/hpe/ss1/README.md` updated for new source files
- [ ] `GLOSSARY.md` updated for new abbreviations
- [ ] kernel-doc comments on new exported functions

## Output Format

For each finding, state:
- **Severity**: Critical / Major / Minor / Nit
- **File:Line**: exact location
- **Finding**: what is wrong
- **Suggestion**: how to fix it

End with a summary: **Approve**, **Approve with suggestions**, or **Request changes**.
