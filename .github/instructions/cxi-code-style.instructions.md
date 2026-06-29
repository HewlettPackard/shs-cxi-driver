---
applyTo: "**"
---

# CXI Driver — Code Style and Contribution Rules

These rules apply to all files. Follow them before opening a PR.

## Style Enforcement

- **Checker**: `perl contrib/checkpatch.pl --git HEAD~..HEAD`
- **CI gate**: `make check-style` runs checkpatch on git diff; zero violations required
- **Line length**: 80 characters as a general guideline; use good judgement for exceptions (e.g. long strings or URLs)
- **Indentation**: tabs (not spaces) for C source files
- **Blank lines**: one blank line between functions; no trailing whitespace

Run `make check-style` before every commit. Fix all warnings and errors — do not ignore
or suppress checkpatch output.

## Commit Message Format

```
subsystem: short description in imperative mood (≤72 chars)

Optional body explaining why (not what — the diff shows what).
Wrap at 72 characters.

Signed-off-by: Your Name <your@email.com>
```

**Subsystem prefixes** (use the most specific that applies):
- `cxi-ss1:` — core driver changes
- `cxi-eth:` — Ethernet driver changes
- `cxi-user:` — user-space interface changes
- `atu:`, `eq:`, `cq:`, `cpt:` — specific hardware subsystem
- `tests:` — test changes
- `docs:` — documentation only
- `build:` — Makefile, Kbuild, CI changes

**Examples:**
```
atu: fix IOVA double-free on error path

eq: add interrupt coalescing support for Cassini 2

docs: update CONTRIBUTING.md with remote dev-setup instructions
```

## Branch Policy

- `main` is protected — all changes via PR
- Feature branches: `feature/ISSUE-short-description`
- Bugfix branches: `fix/ISSUE-short-description`
- Never force-push to `main`

## PR Requirements (from pull_request_template.md)

Before submitting a PR:
1. `make check-style` — zero checkpatch violations
2. `make check-smoke` — builds drivers/ss1 and ucxi cleanly
3. `make check` — full VM test suite passes (if touching driver code or tests)
4. Describe the risk level in the PR template (Low / Medium / High)
5. Link to any design docs for non-trivial changes
6. Confirm test evidence (which tests ran, what passed)

Pre-commit hook: run `./contrib/install-git-hook.sh` once to automate step 1.

## What NOT to Do

- Do not use `// C99 comments` — use `/* C89 block comments */`
- Do not cast `void *` unnecessarily — kernel APIs return typed pointers
- Do not `#include` private headers across subsystem boundaries
- Do not add `printk()` to the data path — use dynamic debug (`pr_debug()`)
- Do not submit WIP commits — squash before PR
