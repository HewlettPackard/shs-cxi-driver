---
name: Feature Request
about: Propose a new feature or enhancement for the CXI driver
labels: enhancement
---

## Summary

<!-- One-sentence description of the proposed feature or enhancement -->

## Motivation

<!-- Why is this needed? What problem does it solve? What use case does it enable? -->

## Proposed Approach

<!-- High-level description of how you'd implement this.
     Reference relevant source files if you have a starting point. -->

## Alternatives Considered

<!-- What other approaches did you consider and why are they less suitable? -->

## Hardware Scope

- [ ] Cassini 1 only
- [ ] Cassini 2 only
- [ ] Both Cassini 1 and 2
- [ ] Ethernet driver
- [ ] HPC fabric (kfabric / ucxi)
- [ ] SR-IOV / VF support

## Estimated Impact

- [ ] New kernel ABI (sysfs attributes, ioctls) — requires `docs/ABI/testing/` entry
- [ ] Changes existing behavior — requires migration notes
- [ ] Performance impact — requires benchmark data
- [ ] Requires new test scenario in `tests/`

## Additional Context

<!-- Design documents, references to hardware specifications, related issues, etc. -->
