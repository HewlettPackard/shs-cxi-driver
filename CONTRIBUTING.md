# Contributing to cxi-driver

## Scope

This repository contains the CXI (Cassini) core and Ethernet drivers. Changes should be validated with the VM-based test workflow used by this project.

## Your First Task

If you are new to this repository, here is a suggested first sequence:

1. **Validate your environment** — Run `./scripts/dev-setup.sh`. All critical checks must pass before building.
2. **Build the drivers** — Run `make check-smoke` from the repository root. This builds `cxi-ss1` and `ucxi` (~30 seconds, no VM required).
3. **Read the architecture** — Skim [CONTEXT.md](CONTEXT.md) and [ARCHITECTURE.md](ARCHITECTURE.md) for the system mental model.
4. **Start a VM** — Run `./scripts/startvm.sh` and verify the drivers load cleanly (`lsmod | grep cxi`).
5. **Run the smoke tests** — Inside the VM, run `cd tests && ./t0010-basic.t` to confirm the test framework works.
6. **Pick a small task** — Look for issues labeled `good-first-issue` or start with a documentation fix.

## Prerequisites

Verify your development environment by running:

```bash
./scripts/dev-setup.sh
```

This script checks for required tools and sibling repositories. For suggested fixes, run:

```bash
./scripts/dev-setup.sh --fix
```

Key prerequisites include:
- Linux kernel build environment compatible with your target kernel.
- Sibling repositories: slingshot_base_link, sl-driver, nic-emu, virtme, cassini-qemu, hms-artifacts
- Tooling: bash, make, gcc/clang, qemu, perl/prove

## Build

From repository root:

```bash
make
```

Build with custom kernel:

```bash
export KDIR=/path/to/linux
make
```

## Test

Full test suite (VM-based):

```bash
make check
```

Run one test:

```bash
cd tests
./t0010-basic.t
```

Run tests from inside a VM:

```bash
cd scripts
TESTING=1 ./startvm.sh
# in VM shell:
cd ../tests
./t0010-basic.t
```

## VM Workflow

Start a VM that loads driver components:

```bash
cd scripts
./startvm.sh
```

Use `-N` for NIC count or `-n` for multiple VMs as needed.

## Branch Naming Policy

Branch names must follow one of these patterns:

| Pattern | Use For |
|---------|---------|
| `feature/<description>` | New features or subsystems |
| `fix/<description>` | Bug fixes |
| `docs/<description>` | Documentation-only changes |
| `refactor/<description>` | Non-functional refactoring |
| `test/<description>` | New or updated tests only |

Examples:
- `feature/fq-subsystem`
- `fix/atu-unmap-error-path`
- `docs/update-architecture-md`

The pre-commit hook enforces this policy on `git push`.

## Coding and Commit Hygiene

Install the pre-commit hook:

```bash
./contrib/install-git-hook.sh
```

The hook checks branch policy and runs `checkpatch.pl` against staged changes.

## Pull Request Expectations

Follow [.github/pull_request_template.md](.github/pull_request_template.md):

- Describe intent clearly (feature vs defect fix).
- Link design docs when applicable.
- Reference Jira items (or `N/A`).
- State risk level (`HIGH | MEDIUM | LOW | NONE`).
- Include test evidence (local VM tests and/or CI runs).

## Changelog

This project does not maintain a hand-written CHANGELOG file. Release notes are
generated from git commit messages and PR titles. Use descriptive, scoped commit
messages (`subsystem: short description`) so they appear correctly in generated
release notes. For significant changes, add a summary to the PR description.

## Recommended Pre-PR Checklist

- Fast preflight passes with `make check-smoke`.
- Style checks pass with `make check-style` (or install the pre-commit hook).
- Build succeeds with `make`.
- Relevant tests pass (`make check` and/or focused tests under `tests/`).
- No obvious dmesg oops/regressions in VM runs.
- Patch passes local checkpatch hook.
- PR includes risk and test evidence.
