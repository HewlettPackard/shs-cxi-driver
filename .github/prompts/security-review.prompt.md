4---
mode: ask
description: >
  Review a CXI driver change for security-relevant properties: privilege
  boundaries, memory safety, integer arithmetic, and user-kernel data flows.
  Produces a targeted security finding report.
---

# CXI Driver Security Review

Review the changes in the current branch (or the provided diff) for
security-relevant issues in the CXI (Cassini) kernel driver. Focus on
kernel-privilege concerns and user-kernel trust boundaries.

## Security Review Checklist

### 1. User-Kernel Trust Boundary
- [ ] All data from user-space (`ucxi` write() commands, netlink, sysfs stores)
  is validated before use — no kernel-controlled struct fields trusted from user
- [ ] `copy_from_user()` / `get_user()` used for all user-space reads; never
  dereference user pointers directly
- [ ] Output buffers to user-space are zeroed before `copy_to_user()` to avoid
  leaking kernel stack/heap content
- [ ] Sysfs `store` handlers reject values outside valid range before applying
- [ ] Netlink attribute lengths validated with `nla_len()` before access

### 2. Integer Safety
- [ ] No unchecked addition/multiplication before use as an allocation size
  (`check_add_overflow`, `array_size()`, `struct_size()`)
- [ ] Signed/unsigned mismatches that could produce unexpectedly large values
- [ ] No user-controlled shift amounts (`>> user_val`) that could exceed type
  width

### 3. Memory Safety
- [ ] No use-after-free: client removal callbacks complete before memory is freed
- [ ] DMA mappings unmapped before freeing the underlying buffer
- [ ] No out-of-bounds ring-buffer indexing (CQ slot index masked or checked)
- [ ] `kref` prevents premature object destruction during async operations
- [ ] No kernel stack address passed to `dma_map_single()`

### 4. Privilege & Access Control
- [ ] Privileged operations (e.g., `CXI_OP_*` admin commands in ucxi) check
  `capable(CAP_NET_ADMIN)` or equivalent before proceeding
- [ ] SR-IOV VF enumeration cannot be used to access PF-only resources
- [ ] sysfs attributes that allow writes (`0644`, `0200`, etc.) are intentional
  and do not expose privileged hardware state without a capability check
- [ ] No PID/UID-based access control that could be bypassed with CLONE_NEWUSER

### 5. Error-Path Cleanup
- [ ] Error paths release all acquired resources in reverse order (no partial
  cleanup leading to a double-free or leaked mapping)
- [ ] `ERR_PTR` paths do not leave hardware in an inconsistent state that a
  subsequent caller could exploit

### 6. Logging
- [ ] No sensitive data (keys, capabilities, raw user buffers) printed to
  kernel log
- [ ] No WARN_ON in a user-triggerable path (converts user error to kernel WARN)
- [ ] Rate-limited logging for user-triggerable error conditions
  (`pr_err_ratelimited`)

## Output Format

List findings as:

```
[SEVERITY] <file>:<line> — <description>
```

Severity: **CRITICAL** (exploitable) | **HIGH** (memory safety) |
**MEDIUM** (hardening gap) | **LOW** (defence-in-depth).

Conclude with one of:

- **No security findings** — change is clear
- **Findings require resolution before merge** — list blocking items
- **Informational findings only** — non-blocking, document if desired
