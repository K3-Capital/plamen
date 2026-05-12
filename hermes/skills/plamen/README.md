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
