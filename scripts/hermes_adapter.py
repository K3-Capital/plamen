#!/usr/bin/env python3
"""Generate a Hermes-compatible Plamen skill from the Codex adapter.

Hermes in K3 Lens uses the OpenAI Codex provider, but it discovers reusable
procedures as Hermes skills under ``skills.external_dirs`` rather than via
``~/.codex``.  This generator keeps the Hermes skill close to the proven Codex
adapter while adding Hermes-specific orchestration notes (delegate_task, local
path discovery, and K3 Lens submodule installs).
"""

from __future__ import annotations

import argparse
import re
import textwrap
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PLAMEN_HOME = SCRIPT_DIR.parent
CODEX_SKILL = PLAMEN_HOME / "codex" / "skills" / "plamen" / "SKILL.md"
DEFAULT_OUTPUT_DIR = PLAMEN_HOME / "hermes" / "skills" / "plamen"


def _strip_frontmatter(markdown: str) -> str:
    """Remove YAML frontmatter from a markdown string if present."""
    if markdown.startswith("---\n"):
        end = markdown.find("\n---\n", 4)
        if end != -1:
            return markdown[end + len("\n---\n"):].lstrip()
    return markdown


def _adapt_codex_skill(codex_skill: str) -> str:
    body = _strip_frontmatter(codex_skill)
    body = body.replace("# Plamen Security Audit Pipeline (Codex Orchestrator)",
                        "# Plamen Security Audit Pipeline (Hermes + OpenAI Codex)")
    body = body.replace("Plamen Web3 Security Auditor -- Codex Runtime",
                        "Plamen Web3 Security Auditor -- Hermes/OpenAI Codex Runtime")
    body = body.replace("~/.codex/plamen", "{PLAMEN_HOME}")
    body = body.replace("~/.codex/agents/", "{PLAMEN_HOME}/codex/agents/")
    body = body.replace("~/.codex/agents", "{PLAMEN_HOME}/codex/agents")

    # The Codex skill uses slash-command language. Hermes loads skills by name
    # and semantic trigger, so make the invocation text provider-neutral.
    body = re.sub(r"```\n/plamen \[light\|core\|thorough\] \[path/to/project\]\n```",
                  "```\nUse this skill by asking Hermes to run Plamen in light, core, or thorough mode for a target project path.\n```",
                  body)

    hermes_notes = textwrap.dedent("""\
    ## Hermes Runtime Notes (K3 Lens)

    This skill is the Hermes/OpenAI Codex adapter for Plamen. It is designed to
    live inside the Plamen repository at `hermes/skills/plamen/SKILL.md`, while
    the full Plamen methodology remains in the same repository.

    Before starting an audit, resolve `PLAMEN_HOME`:

    1. If this skill is installed from the K3 Lens profile submodule, the repo is
       usually `/opt/k3-hermes-profile/skills/smart-contracts/plamen` for the
       long-lived service or `/opt/run-hermes-profile/skills/smart-contracts/plamen`
       for one-shot task containers.
    2. Otherwise, locate this `SKILL.md` and go up three directories from
       `hermes/skills/plamen/` to the Plamen repo root.
    3. If uncertain, use `search_files(target="files", pattern="phase_manifest.json")`
       or the terminal equivalent to find `{PLAMEN_HOME}/hooks/phase_manifest.json`.

    Before starting an audit, run a dependency preflight and record the result in
    `{PROJECT_ROOT}/.scratchpad/dependency_preflight.md` once the scratchpad path
    is known. At minimum, check `python3`, `git`, `node`, `npx`, `forge`, `cast`,
    `anvil`, and `slither` for EVM/Solidity targets. Treat Foundry and Slither as
    required for EVM builds/static analysis; if either is missing, stop and ask for
    the Hermes image or task environment to be fixed rather than silently skipping
    build/static phases. `SOLODIT_API_KEY` is recommended for RAG/Solodit lookups;
    if it is absent, mark RAG as unavailable and continue with code analysis plus
    web-search fallback. Solana, Aptos, Sui, Medusa, Trident, and full MCP/RAG
    database dependencies from `docs/setup.md` are optional or language-specific in
    K3 Lens unless that audit target explicitly requires them.

    Hermes does not consume Codex agent TOML files directly. When this document
    says to spawn an agent from `{PLAMEN_HOME}/codex/agents/<role>.toml`, read
    that TOML as role guidance, then use Hermes `delegate_task` with the relevant
    toolsets (usually `terminal`, `file`, and `web`). Keep each delegated agent's
    scope restricted to its assigned output file and do not exceed the runtime's
    configured delegation concurrency.

    Do not run `plamen install --codex` inside K3 Lens containers. K3 Lens makes
    this skill available by mounting the deployment-owned submodule under the
    Hermes profile skills directory; updates are normal git submodule pointer
    changes in the IaC repo.

    """)

    return textwrap.dedent("""\
    ---
    name: plamen
    description: "Run the Plamen Web3 smart-contract security audit pipeline from Hermes/OpenAI Codex"
    ---

    """) + hermes_notes + body


def generate_hermes_skill(output_dir: Path) -> Path:
    codex_skill = CODEX_SKILL.read_text(encoding="utf-8")
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "SKILL.md"
    out_path.write_text(_adapt_codex_skill(codex_skill), encoding="utf-8")
    return out_path


def generate_readme(output_dir: Path) -> Path:
    content = textwrap.dedent("""\
    # Plamen Hermes adapter

    This directory contains the Hermes-compatible Plamen skill. It is generated
    from `codex/skills/plamen/SKILL.md` by `scripts/hermes_adapter.py` with
    Hermes-specific notes for K3 Lens and `delegate_task` orchestration.

    ## Regenerate

    ```bash
    python3 scripts/hermes_adapter.py
    ```

    The full Plamen methodology stays in the repository root (`prompts/`,
    `rules/`, `hooks/`, `agents/`, and `custom-mcp/`). The generated skill refers
    to that root as `{PLAMEN_HOME}` at runtime.
    """)
    out_path = output_dir / "README.md"
    out_path.write_text(content, encoding="utf-8")
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Hermes-compatible Plamen skill")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR),
                        help="Output directory for Hermes skill (default: hermes/skills/plamen)")
    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    skill_path = generate_hermes_skill(output_dir)
    readme_path = generate_readme(output_dir)
    print(f"Generated {skill_path.relative_to(PLAMEN_HOME)}")
    print(f"Generated {readme_path.relative_to(PLAMEN_HOME)}")


if __name__ == "__main__":
    main()
