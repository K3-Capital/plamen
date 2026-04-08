# Plamen Codex Adapter

This directory contains Codex-compatible configuration files generated from the
Plamen audit pipeline's Claude-side manifests. These files allow Plamen to run
inside the [Codex CLI](https://github.com/openai/codex) in addition to Claude Code.

## Installation

```bash
# From the Plamen repo directory:
plamen install --codex

# Or manually:
python scripts/codex_adapter.py
```

The installer:
1. Generates Codex config files into this `codex/` directory
2. Creates `~/.codex/` if it does not exist
3. Symlinks `~/.codex/plamen/` to the Plamen repo (shared methodology files)
4. Copies Codex-specific files (`config.toml`, agent TOMLs, `AGENTS.md`) into `~/.codex/`

## Usage

After installation, open the Codex CLI and use the Plamen skill:

```bash
codex
# Then inside Codex:
/plamen core /path/to/project
/plamen thorough /path/to/project --docs /path/to/whitepaper.pdf
```

## Architecture

### What is shared (via symlink)

The Plamen methodology files are shared between Claude Code and Codex via a
symlink at `~/.codex/plamen/` pointing to the Plamen repo. This includes:

- `prompts/` -- language-specific phase prompts (recon, inventory, depth, verification)
- `agents/` -- depth agent definitions and skill files
- `rules/` -- finding format, confidence scoring, chain analysis, report templates
- `hooks/` -- phase_gate.py watchdog and phase_manifest.json
- `custom-mcp/` -- MCP server source code

### What is Codex-specific (in this directory)

- `AGENTS.md` -- Condensed orchestrator rules (under 32KB for Codex context)
- `config.toml` -- Codex main config with model, MCP server mappings
- `agents/*.toml` -- Role TOML files for each agent type
- `skills/plamen/SKILL.md` -- The `/plamen` orchestrator skill for Codex
- `hooks.json` -- Codex hook format for phase_gate.py

### Regenerating

If you update Claude-side files (CLAUDE.md, phase_manifest.json, mcp.json.example,
agent definitions), regenerate the Codex files:

```bash
python scripts/codex_adapter.py
```

## Pilot Status (v1.1.8)

**Phase 1 integration proven.** A real Light-mode audit on Codex CLI got through
bootstrap → recon → breadth, spawned sub-agents, and produced a real finding.

### What Works
- Config loading (model, sandbox, approval, agent roles)
- AGENTS.md and shared methodology tree readable
- Watchdog initialization and artifact-based grace period
- EVM/Foundry language detection
- Sub-agent spawning for breadth analysis
- Real findings produced by breadth agents

### Known Issues (Phase 2)
- **Windows command compat**: Shared prompt templates use Unix-style commands
  (`rg`, `grep`, glob patterns like `src/**/*.sol`) that fail on Windows Codex
  (PowerShell). Need a Windows compatibility pass across recon/breadth templates.
- **Thread cap**: Codex defaults to 8 concurrent agents (`max_threads`). Light mode
  spawns 3-4 breadth agents plus recon, which is within budget, but Core/Thorough
  will exceed it. Need agent budgeting to respect the cap.
- **Non-git repos**: Some recon steps assume a git repository (`git rev-list`,
  `git log`). Need guards when `git rev-parse` fails.
- **Shell alias collisions**: `fc` collides with PowerShell `Format-Custom`.
  `Set-Content -NoNewline` unsupported in some contexts.

### Current Limitations
- **Generator**: Most adapter content is templated, not fully manifest-derived.
  MCP servers and hooks are manifest-driven; AGENTS.md, SKILL.md, and agent
  instructions are templated. Must re-run generator after Claude-side changes.
- **Context window**: Codex uses ~200K context vs Claude's 1M. Deep analysis
  agents may need prompt condensation for complex codebases.
- **Thorough mode**: Experimental. See Mode Support Status in `skills/plamen/SKILL.md`.
- **Model**: Default is `gpt-5.3-codex`. Change in `config.toml` to match your
  account (run `codex --available-models` to check).
