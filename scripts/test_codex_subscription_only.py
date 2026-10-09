"""Subscription-only Codex auth policy tests (KCA-727 fork delta).

Fixtures only: synthetic auth.json files and fake API-key environment
values. No network access, no real provider traffic, no real credentials.

Covers the driver's subscription-only enforcement:
  - _codex_home_dir / _codex_auth_available / _codex_auth_is_chatgpt
    (a ChatGPT OAuth auth file is the only accepted authentication source;
    API-key environment variables never satisfy the preflight)
  - _phase_subprocess_env (inherited CODEX_API_KEY / OPENAI_API_KEY are
    scrubbed from every phase subprocess environment)
  - _build_codex_cmd / _build_codex_cmd_no_model carry the forced-login
    -c overrides even though phase invocations use --ignore-user-config
  - clamp_phase_timeouts (K3 deployment delta: the pinned revision's phase
    budgets exceed the validator ceiling and would abort every run)

Run: `python test_codex_subscription_only.py` or `pytest scripts/`.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402


PASS, FAIL = 0, 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label} :: {detail}")


_FAKE_CHATGPT_AUTH = {
    "auth_mode": "chatgpt",
    "tokens": {
        "access_token": "fake-access-token",
        "refresh_token": "fake-refresh-token",
        "id_token": "fake-id-token",
    },
    "last_refresh": "2026-01-01T00:00:00+00:00",
}

_FORCED_LOGIN_PAIRS = (
    ["-c", 'forced_login_method="chatgpt"'],
    ["-c", 'cli_auth_credentials_store="file"'],
)


@contextlib.contextmanager
def _env(**values: str | None):
    """Temporarily set/unset environment variables (None removes)."""
    saved = {key: os.environ.get(key) for key in values}
    try:
        for key, value in values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _mkfix(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=f"plamen_codex_{prefix}_"))


def _write_auth(codex_home: Path, payload) -> Path:
    codex_home.mkdir(parents=True, exist_ok=True)
    auth = codex_home / "auth.json"
    if isinstance(payload, str):
        auth.write_text(payload, encoding="utf-8")
    else:
        auth.write_text(json.dumps(payload), encoding="utf-8")
    return auth


# --------------------------------------------------------------------------
# Auth source resolution
# --------------------------------------------------------------------------

def test_S1_chatgpt_file_in_codex_home_is_accepted():
    """A synthetic ChatGPT auth file under $CODEX_HOME satisfies the gate."""
    fix = _mkfix("accepted")
    empty_home = _mkfix("emptyhome")
    _write_auth(fix / "codexhome", _FAKE_CHATGPT_AUTH)
    with _env(CODEX_HOME=str(fix / "codexhome"), HOME=str(empty_home)):
        check("S1a CODEX_HOME chatgpt file satisfies auth",
              D._codex_auth_available() is True, "")
        check("S1b chatgpt detector reads CODEX_HOME",
              D._codex_auth_is_chatgpt() is True, "")


def test_S2_codex_home_wins_with_no_home_fallback():
    """An API-key file under $CODEX_HOME is refused even when $HOME holds a
    chatgpt file: the preflight must not fall back to another store."""
    fix_home = _mkfix("home")
    _write_auth(fix_home / ".codex", _FAKE_CHATGPT_AUTH)
    fix_ch = _mkfix("ch")
    _write_auth(fix_ch / "codexhome",
                {"auth_mode": "apikey", "OPENAI_API_KEY": "fake-key"})
    with _env(CODEX_HOME=str(fix_ch / "codexhome"), HOME=str(fix_home)):
        check("S2a CODEX_HOME apikey file refused (no ~/.codex fallback)",
              D._codex_auth_available() is False, "")


def test_S3_home_fallback_when_codex_home_unset():
    """Without $CODEX_HOME the default ~/.codex location is used."""
    fix = _mkfix("homefb")
    _write_auth(fix / ".codex", _FAKE_CHATGPT_AUTH)
    with _env(CODEX_HOME=None, HOME=str(fix)):
        check("S3a unset CODEX_HOME falls back to ~/.codex",
              D._codex_auth_available() is True, "")


# --------------------------------------------------------------------------
# API-key fallback refusal (negative evidence)
# --------------------------------------------------------------------------

def test_S4_api_key_env_never_satisfies_auth():
    """CODEX_API_KEY / OPENAI_API_KEY alone must not pass the preflight."""
    fix = _mkfix("noauth")
    empty = _mkfix("nofile")
    codex_home = str(empty / "codexhome")
    with _env(CODEX_HOME=codex_home, HOME=str(fix),
              CODEX_API_KEY="sk-fake-codex-env", OPENAI_API_KEY=None):
        check("S4a CODEX_API_KEY alone refused",
              D._codex_auth_available() is False, "")
    with _env(CODEX_HOME=codex_home, HOME=str(fix),
              CODEX_API_KEY=None, OPENAI_API_KEY="sk-fake-openai-env"):
        check("S4b OPENAI_API_KEY alone refused",
              D._codex_auth_available() is False, "")
    with _env(CODEX_HOME=codex_home, HOME=str(fix),
              CODEX_API_KEY="sk-fake-codex-env",
              OPENAI_API_KEY="sk-fake-openai-env"):
        check("S4c both env keys together refused",
              D._codex_auth_available() is False, "")


def test_S5_apikey_mode_file_refused():
    """An auth.json that stores an API key is not subscription auth."""
    fix = _mkfix("apikey")
    _write_auth(fix / "codexhome",
                {"auth_mode": "apikey", "OPENAI_API_KEY": "sk-fake"})
    with _env(CODEX_HOME=str(fix / "codexhome"), HOME=str(fix)):
        check("S5a apikey-mode auth file refused",
              D._codex_auth_available() is False, "")


def test_S6_missing_or_corrupt_file_refused():
    """Missing, corrupt, and non-object auth files fail closed."""
    fix = _mkfix("corrupt")
    with _env(CODEX_HOME=str(fix / "missing"), HOME=str(fix)):
        check("S6a missing auth file refused",
              D._codex_auth_available() is False, "")
    _write_auth(fix / "bad", "{ not json")
    with _env(CODEX_HOME=str(fix / "bad"), HOME=str(fix)):
        check("S6b corrupt auth file refused",
              D._codex_auth_available() is False, "")
    _write_auth(fix / "list", "[1, 2, 3]")
    with _env(CODEX_HOME=str(fix / "list"), HOME=str(fix)):
        check("S6c non-object auth file refused",
              D._codex_auth_available() is False, "")


# --------------------------------------------------------------------------
# Phase subprocess environment scrubbing
# --------------------------------------------------------------------------

def test_S7_phase_env_scrubs_api_keys():
    sp = _mkfix("env")
    with _env(CODEX_API_KEY="sk-fake", OPENAI_API_KEY="sk-fake2",
              PLAMEN_KEEP_SENTINEL="1"):
        env = D._phase_subprocess_env(sp)
    check("S7a CODEX_API_KEY scrubbed", "CODEX_API_KEY" not in env, "")
    check("S7b OPENAI_API_KEY scrubbed", "OPENAI_API_KEY" not in env, "")
    check("S7c unrelated environment preserved",
          env.get("PLAMEN_KEEP_SENTINEL") == "1", "")
    check("S7d existing claude-phase tweaks preserved",
          env.get("ANTHROPIC_DISABLE_AUTOUPDATE") == "1"
          and env.get("PLAMEN_SCRATCHPAD") == str(sp), "")


# --------------------------------------------------------------------------
# Command builders carry the forced-login policy
# --------------------------------------------------------------------------

def _contains_pair(argv: list[str], pair: list[str]) -> bool:
    return any(argv[i:i + 2] == pair for i in range(len(argv) - 1))


def test_S8_cmd_builders_force_subscription_login():
    cmd = D._build_codex_cmd("gpt-5.4")
    nomodel = D._build_codex_cmd_no_model()
    for label, argv in (
        ("S8a _build_codex_cmd", cmd),
        ("S8b _build_codex_cmd_no_model", nomodel),
    ):
        for pair in _FORCED_LOGIN_PAIRS:
            desc = " ".join(pair)
            check(f"{label} includes {desc}",
                  _contains_pair(argv, pair), " ".join(argv))
    check("S8c both builders ignore user config (policy must ride CLI flags)",
          "--ignore-user-config" in cmd and "--ignore-user-config" in nomodel, "")
    check("S8d stdin prompt marker preserved", cmd[-1] == "-", "")


# --------------------------------------------------------------------------
# Fake-codex launch smoke (real subprocess, synthetic credentials)
# --------------------------------------------------------------------------

def test_S9_fake_codex_launch_scrubbed_env_and_flags():
    fix = _mkfix("launch")
    sp = fix / "scratch"
    sp.mkdir()
    out = fix / "fake_out.json"
    fake = fix / "fake_codex.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "json.dump({\n"
        "    'argv': sys.argv[1:],\n"
        "    'codex_api_key_present': 'CODEX_API_KEY' in os.environ,\n"
        "    'openai_api_key_present': 'OPENAI_API_KEY' in os.environ,\n"
        "    'codex_home': os.environ.get('CODEX_HOME'),\n"
        "}, open(os.environ['FAKE_CODEX_OUT'], 'w'))\n",
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    original_bin = D.CODEX_BIN
    D.CODEX_BIN = str(fake)
    try:
        cmd = D._build_codex_cmd("gpt-5.4",
                                 output_last_message=str(fix / "olm.md"))
        with _env(CODEX_API_KEY="sk-fake", OPENAI_API_KEY="sk-fake2",
                  CODEX_HOME=str(fix / "codexhome"),
                  FAKE_CODEX_OUT=str(out)):
            env = D._phase_subprocess_env(sp)
            proc = subprocess.run(cmd, env=env, input="",
                                  capture_output=True, text=True)
        payload = json.loads(out.read_text(encoding="utf-8"))
    finally:
        D.CODEX_BIN = original_bin
    check("S9a fake codex spawned successfully",
          proc.returncode == 0, proc.stderr)
    check("S9b child env has no CODEX_API_KEY",
          payload["codex_api_key_present"] is False, "")
    check("S9c child env has no OPENAI_API_KEY",
          payload["openai_api_key_present"] is False, "")
    check("S9d child receives CODEX_HOME",
          payload["codex_home"] == str(fix / "codexhome"), str(payload))
    check("S9e child argv carries forced chatgpt login",
          _contains_pair(payload["argv"], _FORCED_LOGIN_PAIRS[0]),
          str(payload["argv"]))
    check("S9f child argv carries file credential store",
          _contains_pair(payload["argv"], _FORCED_LOGIN_PAIRS[1]),
          str(payload["argv"]))


def test_S10_phase_timeout_clamp_restores_runnability():
    """K3 deployment delta: clamping makes every (mode, pipeline) graph
    validate; originals are restored so the fixture never leaks state."""
    originals = [
        (phase, phase.base_timeout_s)
        for phase in list(D.SC_PHASES) + list(D.L1_PHASES)
    ]
    try:
        adjusted = D.clamp_phase_timeouts()
        for phases, pipeline in ((D.SC_PHASES, "sc"), (D.L1_PHASES, "l1")):
            max_timeout = max(p.base_timeout_s for p in phases)
            check(f"S10a {pipeline}: all phases <= ceiling after clamp",
                  max_timeout <= D._PHASE_TIMEOUT_CEILING_S,
                  f"max={max_timeout}")
            for mode in ("light", "core", "thorough"):
                issues = D.validate_phase_graph(phases, mode, pipeline)
                check(f"S10b {pipeline}/{mode}: graph valid after clamp",
                      not issues, repr(issues[:2]))
        clamp_names = sorted(name for name, _, _ in adjusted)
        check("S10c breadth was among the clamped phases",
              "breadth" in clamp_names, repr(clamp_names))
        again = D.clamp_phase_timeouts()
        check("S10d clamp is idempotent (second pass adjusts nothing)",
              again == [], repr(again))
    finally:
        for phase, timeout in originals:
            phase.base_timeout_s = timeout


def main() -> None:
    tests = [
        test_S1_chatgpt_file_in_codex_home_is_accepted,
        test_S2_codex_home_wins_with_no_home_fallback,
        test_S3_home_fallback_when_codex_home_unset,
        test_S4_api_key_env_never_satisfies_auth,
        test_S5_apikey_mode_file_refused,
        test_S6_missing_or_corrupt_file_refused,
        test_S7_phase_env_scrubs_api_keys,
        test_S8_cmd_builders_force_subscription_login,
        test_S9_fake_codex_launch_scrubbed_env_and_flags,
        test_S10_phase_timeout_clamp_restores_runnability,
    ]
    print(f"Running {len(tests)} subscription-only Codex tests...")
    for t in tests:
        print(f"\n[{t.__name__}]")
        t()
    print(f"\n{'=' * 48}")
    print(f"  PASS: {PASS}   FAIL: {FAIL}")
    print('=' * 48)
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
