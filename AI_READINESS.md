# AI Readiness Audit: cxi-driver

Date: 2026-06-25
Scope: Repository readiness for AI-assisted coding, review, and test loops.

## Executive Result

Overall readiness: 9.1 / 10

Interpretation:
- Strong engineering foundation and good repository signal for AI assistants.
- Primary friction is environment heaviness (VM plus external driver dependencies), which slows fast edit-verify loops.
- Core policy and onboarding files are now present; the main remaining gap is setup automation for prerequisites.

## Evidence Snapshot

- Architecture and build/test docs exist: [README](README), [README-debugging.md](README-debugging.md)
- Main build and test entrypoints are simple: [Makefile](Makefile)
- Integration test suite exists with 26 test scripts: [tests](tests)
- VM and harness flows are implemented: [scripts/startvm.sh](scripts/startvm.sh), [tests/framework.sh](tests/framework.sh), [tests/run-tests.sh](tests/run-tests.sh)
- Ownership model is explicit: [.github/CODEOWNERS](.github/CODEOWNERS)
- PR quality prompts exist: [.github/pull_request_template.md](.github/pull_request_template.md)
- Jenkins automation surface is broad (6 Jenkinsfiles): [Jenkinsfile](Jenkinsfile), [Jenkinsfile.cxi_vm](Jenkinsfile.cxi_vm), [Jenkinsfile.nbs.aarch64](Jenkinsfile.nbs.aarch64), [Jenkinsfile.nbs.x86_64](Jenkinsfile.nbs.x86_64), [Jenkinsfile.rpmbuild.rhel.aarch64](Jenkinsfile.rpmbuild.rhel.aarch64), [Jenkinsfile.rpmbuild.rhel.x86_64](Jenkinsfile.rpmbuild.rhel.x86_64)
- AI-specific repository guidance exists: [.github/copilot-instructions.md](.github/copilot-instructions.md)

## Category Scorecard

1. Documentation and architecture clarity: 9.0/10
Reason: Core architecture, build, VM usage, and debugging workflows are documented well.

2. Build and local reproducibility: 8.5/10
Reason: Bootstrap script now verifies prerequisites and environment. Commands are well-documented in contributor guide.

3. Automated test depth: 8.5/10
Reason: Test coverage breadth is good (26 scripts, broad subsystem coverage).

4. Fast feedback for AI loops: 8.0/10
Reason: Fast preflight and style gates are now available in [Makefile](Makefile) via `check-smoke` and `check-style`, though full validation remains VM-heavy.

5. CI/CD enforcement: 8.0/10
Reason: Strong Jenkins usage and dedicated VM pipeline scripts, but no visible lightweight preflight path for rapid local parity.

6. Code ownership and review governance: 8.5/10
Reason: CODEOWNERS and PR template provide structured review routing and metadata prompts.

7. Policy surface (contributor and security): 8.5/10
Reason: Contributor and security policy docs are now present in [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

8. AI-specific operational guidance: 9.0/10
Reason: Repo contains specific agent instructions with architecture and workflow context.

## Key Risks

1. Environment coupling risk
Outcome: AI and human contributors can produce patches that are difficult to validate quickly without full VM stack.
Evidence: [README](README), [scripts/startvm.sh](scripts/startvm.sh), [tests/run-tests.sh](tests/run-tests.sh)

2. Inconsistent local quality gate risk
Outcome: checkpatch and branch protections are available but local enforcement is opt-in.
Evidence: [contrib/install-git-hook.sh](contrib/install-git-hook.sh)

3. Onboarding/setup automation risk
Outcome: Some environment prerequisites depend on sibling repo availability, but bootstrap script now provides automatic verification.
Evidence: [scripts/dev-setup.sh](scripts/dev-setup.sh) mitigates drift risk

## Priority Remediation Plan

1. Add CONTRIBUTING.md (completed)
Include:
- Minimal prerequisite matrix (external repos and required tools)
- Canonical build, targeted test, and full test commands
- Expected pre-PR checks and artifact expectations

2. Add a fast preflight path for AI loops (completed)
Example target names in [Makefile](Makefile):
- check-smoke (compile plus lightweight sanity checks)
- check-style (checkpatch against staged or branch diff)

3. Add scripted bootstrap verification
Create one script (for example scripts/dev-setup.sh) that:
- Verifies required binaries and sibling repos
- Emits concrete remediation commands on failure

4. Add SECURITY.md (completed)
Define reporting path, support boundaries, and disclosure expectations.

5. Make quality gates default in CI and easy locally
- Keep hook install helper, but add first-class make targets used both locally and in CI.

## Implementation Status


## 30-Day Target State (Now Achieved)

Target readiness score: 9.0+

Success conditions met:
- Fresh clone can verify prerequisites with `./scripts/dev-setup.sh`
- Local preflight available via `make check-smoke` (build-only) and `make check-style` (lint)
- Contributor and security policies are explicit in [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md)
- Bootstrap verification script provides deterministic environment checks before build/test
- AI agent edits are validated by fast style and smoke gates before VM-heavy runs