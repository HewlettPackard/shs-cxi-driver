# CXI Driver — AI Agent Index

This file routes AI assistant requests to specialized agents for this repository.
Load it with `useAgentsMdFile: true` in `.vscode/settings.json` (already configured).

## Available Agents

| Task | Agent | Use When |
|------|-------|----------|
| Writing or modifying C kernel driver code | [coding](.github/agents/coding.agent.md) | Implementing features, fixing bugs, writing cass_*.c or cxi_*.c |
| Reviewing a PR or change for safety | [pr-review](.github/agents/pr-review.agent.md) | Before submitting a PR; reviewing hardware-risk changes |
| Debugging hardware / driver issues | [debugging](.github/agents/debugging.agent.md) | Kernel panics, hardware hangs, unexpected behavior |
| Updating READMEs, ABI docs, inline kernel-doc | [documentation](.github/agents/documentation.agent.md) | Adding or updating any documentation file |

## Available Skills (on-demand knowledge)

| Domain | Skill | Use When |
|--------|-------|----------|
| Domain abbreviations | [cxi-glossary](.github/skills/cxi-glossary/SKILL.md) | Need definitions for ATU, EQ, CQ, CP, SBL, etc. |
| Hardware patterns | [cxi-hardware-patterns](.github/skills/cxi-hardware-patterns/SKILL.md) | Implementing queue management, DMA, hardware abstraction |
| Extension guide | [cxi-extension-patterns](.github/skills/cxi-extension-patterns/SKILL.md) | Adding a new hardware feature or subsystem |

## Available Instructions (always-scoped)

| Scope | File | Covers |
|-------|------|--------|
| All C source files | [kernel-driver-patterns](.github/instructions/kernel-driver-patterns.instructions.md) | Naming, error handling, module load order, memory alignment |
| Style and commit | [cxi-code-style](.github/instructions/cxi-code-style.instructions.md) | checkpatch rules, commit format, PR checklist |

## Available Prompts (task templates)

| Task | Prompt |
|------|--------|
| Code review | [code-review](.github/prompts/code-review.prompt.md) |
| Generate test | [generate-test](.github/prompts/generate-test.prompt.md) |

## Quick Reference

```
Build:       make | make check-smoke | make check-style | make check
Style:       perl contrib/checkpatch.pl --git HEAD~..HEAD
Single test: cd tests && ./t0010-basic.t
VM:          cd scripts && ./startvm.sh
Prereqs:     ./scripts/dev-setup.sh [--fix] [--remote HOST --repo-path PATH]
```

See [CONTEXT.md](CONTEXT.md) for tech stack, directory layout, domain model, and anti-patterns.
See [.github/copilot-instructions.md](.github/copilot-instructions.md) for full authoritative guidance.
