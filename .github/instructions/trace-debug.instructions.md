---
applyTo: "trace-debug/**"
---

# CXI Driver — Trace and Debug Scripts

Rules for adding or modifying scripts in `trace-debug/`.

## File Types

| Extension | Tool | Purpose |
|-----------|------|---------|
| `.bt` | bpftrace | Kernel-function and tracepoint probes |
| `.h` | C header | Inline tracepoint definitions (`TRACE_EVENT`) |
| `.diff` | patch | Provisional kernel patches for out-of-tree tracepoints |

## bpftrace Script Conventions

- Begin every `.bt` file with a block comment containing:
  - One-line description of what is being traced
  - `To run:` with the exact `bpftrace <file>.bt` invocation
  - `Output:` with a representative sample of output lines
- Inline struct definitions for any kernel type accessed via bpftrace must
  mirror the kernel struct field layout exactly — bpftrace cannot resolve
  kernel headers at runtime.  Copy from the relevant `cass_*.h` or
  `include/linux/hpe/cxi/` header and note the source in a comment.
- Use `kfunc:`/`kretfunc:` probes (BTF-based) in preference to `kprobe:` where
  the target function is exported with BTF.
- Use tid-keyed maps (`@map[tid]`) to correlate entry/return probes.
- Do not hardcode PID values — use `/comm == "process_name"/` filters instead.
- Scripts must be runnable as-is: `bpftrace trace-debug/<script>.bt`.

## Tracepoint Header Conventions (`cxi_tracepoint.h`)

- All `TRACE_EVENT` definitions must be guarded by `CXI_TRACE_ENABLE` and
  provide a no-op fallback for builds without tracing enabled (see existing
  `#if 0` / stub pattern).
- New tracepoints must use the `TRACE_SYSTEM cxi` namespace.
- Add a short comment above each `TRACE_EVENT` block explaining the event and
  when it fires.

## Adding a New Script

1. Name the file after the subsystem or call path being traced:
   `cxi_<subsystem>.bt` (e.g., `cxi_eq.bt`, `cxi_cq.bt`).
2. Copy the struct layout comment pattern from an existing script (`cxi_map.bt`
   is the canonical example).
3. Test in the VM environment (`scripts/startvm.sh`) before committing — some
   `kfunc:` probes require BTF symbols that only exist in the test kernel.
4. Update `trace-debug/` file list in `scripts/README.md` if one exists; no
   separate documentation file is required.

## What Not to Do

- Do not embed absolute paths or username-specific paths in scripts.
- Do not add `sleep`, polling loops, or `system()` calls — bpftrace probes are
  event-driven.
- Do not commit `.diff` files that apply to an already-merged kernel change;
  remove the diff once the tracepoint lands upstream.
