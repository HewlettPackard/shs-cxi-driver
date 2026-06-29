# CXI Driver — AI Artifacts Index (.github/)

This directory contains AI coding assistant configuration for the CXI (Cassini)
driver repository. All files follow VS Code Copilot conventions.

---

## Instructions (`.github/instructions/`)

Scoped coding rules applied automatically by Copilot based on `applyTo` patterns.

| File | Scope | Purpose |
|------|-------|---------|
| [kernel-driver-patterns.instructions.md](instructions/kernel-driver-patterns.instructions.md) | `drivers/**`, `ucxi/**` | Naming, error handling, memory alignment, locking, client registration |
| [cxi-code-style.instructions.md](instructions/cxi-code-style.instructions.md) | `**` | checkpatch rules, commit format, branch policy, PR requirements |

---

## Agents (`.github/agents/`)

Specialized AI agents for domain-specific workflows.

| File | Purpose | When to Use |
|------|---------|-------------|
| [coding.agent.md](agents/coding.agent.md) | Kernel driver coding agent | Writing new driver code, implementing subsystems |
| [pr-review.agent.md](agents/pr-review.agent.md) | PR quality-gate reviewer | Reviewing PRs before merge |
| [debugging.agent.md](agents/debugging.agent.md) | Hardware driver debugger | Diagnosing hardware/driver issues |
| [documentation.agent.md](agents/documentation.agent.md) | Documentation maintainer | Updating or writing driver documentation |

Also see [AGENTS.md](../AGENTS.md) at the repository root for the full routing index.

---

## Prompts (`.github/prompts/`)

Reusable prompt templates for structured workflows.

| File | Mode | Purpose |
|------|------|---------|
| [code-review.prompt.md](prompts/code-review.prompt.md) | ask | Structured code review with CXI-specific checklist |
| [generate-test.prompt.md](prompts/generate-test.prompt.md) | ask | Generate a new Sharness integration test |

---

## Skills (`.github/skills/`)

On-demand domain knowledge loaded by agents when needed.

| Directory | Purpose |
|-----------|---------|
| [cxi-glossary/SKILL.md](skills/cxi-glossary/SKILL.md) | CXI abbreviation definitions (ATU, EQ, CQ, CP, SBL, SL, …) |
| [cxi-hardware-patterns/SKILL.md](skills/cxi-hardware-patterns/SKILL.md) | ATU/EQ/CQ/CP implementation patterns, DMA alignment, reference counting |
| [cxi-extension-patterns/SKILL.md](skills/cxi-extension-patterns/SKILL.md) | How to add a new hardware subsystem, test, or sysfs attribute |

---

## Issue Templates (`.github/ISSUE_TEMPLATE/`)

| File | Purpose |
|------|---------|
| [bug_report.md](ISSUE_TEMPLATE/bug_report.md) | Bug report template with hardware context fields |
| [feature_request.md](ISSUE_TEMPLATE/feature_request.md) | Feature request template |

---

## Primary Instructions File

[copilot-instructions.md](copilot-instructions.md) — The authoritative source for
CXI driver AI-assisted development conventions. Read by Copilot for every session.

---

## How VS Code Discovers These Files

The `.vscode/settings.json` at the repository root enables:
- `github.copilot.chat.codeGeneration.useInstructionFiles: true`
- `github.copilot.chat.agent.useAgentsMdFile: true`
- Skill locations pointed at `.github/skills/`

Run `make check-ai-context` to validate the AI artifact configuration.
