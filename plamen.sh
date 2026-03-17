#!/usr/bin/env bash
PYTHON=$(command -v python3 || command -v python)
exec "$PYTHON" "$HOME/.claude/plamen.py" "$@"
