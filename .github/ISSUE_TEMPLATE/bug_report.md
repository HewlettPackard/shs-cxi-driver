---
name: Bug Report
about: Report a problem with the CXI driver
labels: bug
---

## Summary

<!-- One-sentence description of the problem -->

## Environment

- **Kernel version**: `uname -r`
- **Driver version / commit**: `git rev-parse HEAD`
- **Hardware**: Cassini 1 (`17db:0501`) / Cassini 2 (`1590:0371`) / netsim VM
- **Distribution**: (e.g., RHEL 9, SLES 15, upstream kernel)
- **Loaded modules**: `lsmod | grep cxi`

## Steps to Reproduce

1.
2.
3.

## Expected Behavior

<!-- What should have happened -->

## Actual Behavior

<!-- What actually happened -->

## Error Output

```
# Paste relevant dmesg, kernel log, or error messages here
```

## sysfs Error Flags (if applicable)

```bash
# Run: cat /sys/class/cxi/cxi0/device/err_flgs_irqa
```

## Additional Context

<!-- Any other relevant information: link up/down events, traffic patterns,
concurrent operations, SR-IOV configuration, etc. -->

## Risk Assessment

- [ ] This is a data corruption issue
- [ ] This causes a kernel panic / oops
- [ ] This is a performance regression
- [ ] This affects production workloads
