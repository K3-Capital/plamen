"""Subscription-only Codex auth policy tests (KCA-727 fork delta).

Fixtures only: synthetic auth.json files and fake API-key environment
values plus a fake executable that records its argv/stdin/environment.
No network access, no real provider traffic, no real credentials.

Covers the driver's subscription-only enforcement:
  - _codex_home_dir / _codex_auth_record / _codex_auth_available /
    _codex_auth_is_chatgpt: native resolved-mode semantics (explicit
    chatgpt, or legacy missing/null auth_mode with OAuth tokens and no API
    key field), structural token checks (native-loadable JWT id_token,
    non-empty access/refresh), API-mode rejection, and no age-based
    rejection of legitimately stale sessions.
  - _phase_subprocess_env (inherited CODEX_API_KEY / OPENAI_API_KEY are
    scrubbed from every phase subprocess environment)
  - _build_codex_cmd / _build_codex_cmd_no_model carry the forced-login
    -c overrides even though phase invocations use --ignore-user-config
  - _detect_codex_auth_error: native auth-store structure failures are
    classified as permanent credential failures.
  - Native key-field parity: missing/null auth_mode x absent/null/empty/
    nonempty/wrong-typed API-key fields follow the pinned Option::is_some()
    resolution; wrong-typed native fields fail the record.
  - Strict native JWT payload decoding: alphabet, length and canonicality
    (URL_SAFE_NO_PAD), so characters Python's decoder ignores and
    non-canonical tails are refused.
  - Launch-path refusal: native API-mode records are refused before any
    child launch, with the auth store left byte-identical (no logout
    mutation), via run_phase and the recovery shard.
  - Native claim/timestamp typing: known JWT claims (fedramp bool etc.)
    and last_refresh RFC 3339 syntax are validated like the pinned native
    structs; unknown claims stay ignored; stale sessions stay accepted.
  - Signal-scoped classification: `item.*` audit/tool content never
    classifies as an auth failure; error/turn.failed events and raw CLI
    diagnostics still do.
  - Value-bearing auth diagnostics (serde echoes of record values) are
    scrubbed from persisted attempt/canonical/recovery logs, with audit
    content preserved and the redacted marker still classifiable.
  - Native duplicate-field rejection: repeated known fields fail like the
    serde derive ("duplicate field") in records, tokens and JWT claims;
    NaN/Infinity/-Infinity (Python-only JSON extensions) are refused;
    duplicates of unknown fields stay ignored.
  - Cancellation safety: SIGINT during a phase or recovery attempt
    stops/reaps the owned child tree, completes promptly, propagates the
    interruption, and never leaves raw values in the logs. Owned
    same-group descendants are tracked through finalization: a
    SIGTERM-resistant tool is escalated and reaped, a stdout-retaining
    descendant is cleaned after a normal leader exit, the reader is
    proven finished and its stream closed, and an interruption during
    finalization still completes the same cleanup before propagating.
    A single SIGINT inside the TERM grace does not abort owned-group
    shutdown: the bounded completion (KILL escalation included) runs to
    the same deadline, the cleanup result is checked, and only then is
    the interruption re-raised.
  - _run_verify_recovery_shard: a Codex-mode recovery shard uses the same
    hardened auth check, prompt translation, command builder, model retry
    and scrubbed environment as ordinary phases; Claude-mode behavior is
    preserved separately.
  - _translate_prompt_for_codex: requires the ephemeral methodology alias
    $HOME/.codex/plamen (runtime handoff requirement).
  - clamp_phase_timeouts (K3 deployment delta: the pinned revision's phase
    budgets exceed the validator ceiling and would abort every run)

Run: `python test_codex_subscription_only.py` or `pytest scripts/`.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import re
import stat
import subprocess
import signal
import sys
import tempfile
import threading
import time
import unittest.mock as mock
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


def _fake_id_token(exp: int = 4102444800) -> str:
    """A structurally native-loadable (but entirely synthetic) ID token.

    Three base64url segments; the payload decodes to a JSON claims object
    with a ChatGPT auth namespace — the shape the pinned native loader
    accepts. It is not a real session.
    """
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}')
    payload = base64.urlsafe_b64encode(json.dumps({
        "email": "fixture@example.invalid",
        "exp": exp,
        "https://api.openai.com/auth": {
            "chatgpt_plan_type": "plus",
            "chatgpt_user_id": "user-fixture",
            "chatgpt_account_id": "acct-fixture",
        },
    }).encode("utf-8"))
    return (
        header.rstrip(b"=").decode("ascii")
        + "."
        + payload.rstrip(b"=").decode("ascii")
        + ".sig"
    )


def _tokens(**overrides) -> dict:
    tokens = {
        "access_token": "fake-access-token",
        "refresh_token": "fake-refresh-token",
        "id_token": _fake_id_token(),
    }
    tokens.update(overrides)
    return tokens


_FAKE_CHATGPT_AUTH = {
    "auth_mode": "chatgpt",
    "tokens": _tokens(),
    "last_refresh": "2026-01-01T00:00:00+00:00",
}

_FORCED_LOGIN_PAIRS = (
    ["-c", 'forced_login_method="chatgpt"'],
    ["-c", 'cli_auth_credentials_store="file"'],
)

# Fake provider executable used by the launch tests. Records argv (full,
# including argv[0]), selected environment flags and the stdin prompt;
# behavior is driven by FAKE_* environment variables.
_FAKE_AGENT_SCRIPT = """#!/usr/bin/env python3
import json, os, pathlib, sys

marker_dir = pathlib.Path(os.environ["FAKE_MARKER_DIR"])
marker_dir.mkdir(parents=True, exist_ok=True)
attempt = len(list(marker_dir.glob("attempt_*.json"))) + 1
stdin_text = ""
try:
    stdin_text = sys.stdin.read()
except Exception:
    pass
payload = {
    "argv": sys.argv,
    "attempt": attempt,
    "codex_api_key_present": "CODEX_API_KEY" in os.environ,
    "openai_api_key_present": "OPENAI_API_KEY" in os.environ,
    "anthropic_api_key_present": "ANTHROPIC_API_KEY" in os.environ,
    "prompt_mentions_recovery": "RECOVERY VERIFICATION SHARD" in stdin_text,
    "prompt_mentions_codex_path": "~/.codex/plamen/" in stdin_text,
}
(marker_dir / ("attempt_%d.json" % attempt)).write_text(json.dumps(payload))

if os.environ.get("FAKE_FAIL_MODEL") == "1" and "--model" in sys.argv:
    print("not supported when using Codex with a ChatGPT account", flush=True)
    sys.exit(1)
if os.environ.get("FAKE_AUTH_ERROR") == "1":
    print("error: invalid ID token format", flush=True)
    sys.exit(1)
value_marker = os.environ.get("FAKE_AUTH_VALUE_ERROR", "")
if value_marker:
    print('invalid type: string "%s", expected a boolean at line 1 column 94' % value_marker, flush=True)
    if os.environ.get("FAKE_SLEEP"):
        import time as _time
        _time.sleep(float(os.environ["FAKE_SLEEP"]))
    sys.exit(1)
item_marker = os.environ.get("FAKE_ITEM_ECHO", "")
if item_marker:
    print(json.dumps({"type": "item.completed", "item": {"id": "item_9", "type": "agent_message", "text": 'note: invalid type: string "%s", expected a boolean at line 1 column 94' % item_marker}}), flush=True)
    print("login trace: %s" % item_marker, flush=True)
    sys.exit(1)
write_ids = os.environ.get("FAKE_WRITE_VERIFY", "")
if write_ids:
    scratch = pathlib.Path(os.environ["FAKE_SCRATCH"])
    for fid in write_ids.split(","):
        (scratch / ("verify_%s.md" % fid)).write_text(
            "RECOVERED VERIFICATION CONTENT\\n" * 6, encoding="utf-8"
        )
sys.exit(0)
"""


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


# --------------------------------------------------------------------------
# Native-compatible auth record resolution (missing/null legacy modes)
# --------------------------------------------------------------------------

def test_S11_legacy_oauth_records_without_mode_are_accepted():
    """Native resolves a missing/null auth_mode to ChatGPT when OAuth
    tokens are present and no API key field is; the predicate must match."""
    fix = _mkfix("legacy")
    for label, drop in (("missing", True), ("null", False)):
        home = fix / label
        payload = json.loads(json.dumps(_FAKE_CHATGPT_AUTH))
        if drop:
            payload.pop("auth_mode")
        else:
            payload["auth_mode"] = None
        _write_auth(home, payload)
        with _env(CODEX_HOME=str(home), HOME=str(fix)):
            check(f"S11 {label} auth_mode legacy record accepted",
                  D._codex_auth_available() is True, "")
            check(f"S11 {label} chatgpt detector agrees",
                  D._codex_auth_is_chatgpt() is True, "")


def test_S12_structural_and_api_negatives_rejected():
    """API-mode, mixed, mode-only and malformed-token records are refused."""
    fix = _mkfix("neg")
    tokens = _tokens()
    padded_segments = _fake_id_token().split(".")
    padded_segments[1] = padded_segments[1] + "=="
    padded = ".".join(padded_segments)
    cases = {
        "explicit apikey mode": {"auth_mode": "apikey", "tokens": tokens},
        "explicit chatgptAuthTokens mode":
            {"auth_mode": "chatgptAuthTokens", "tokens": tokens},
        "explicit agentIdentity mode":
            {"auth_mode": "agentIdentity", "tokens": tokens},
        "legacy with API key field":
            {"tokens": tokens, "OPENAI_API_KEY": "fake-key"},
        "legacy with API key field only": {"OPENAI_API_KEY": "fake-key"},
        "mode only no tokens": {"auth_mode": "chatgpt"},
        "tokens missing id_token":
            {"auth_mode": "chatgpt",
             "tokens": {k: v for k, v in tokens.items() if k != "id_token"}},
        "malformed id token not a JWT":
            {"auth_mode": "chatgpt", "tokens": _tokens(id_token="fake-id")},
        "malformed id token two segments":
            {"auth_mode": "chatgpt", "tokens": _tokens(id_token="abc.def")},
        "padded JWT payload":
            {"auth_mode": "chatgpt", "tokens": _tokens(id_token=padded)},
        "empty access token":
            {"auth_mode": "chatgpt", "tokens": _tokens(access_token="")},
        "non-string refresh token":
            {"auth_mode": "chatgpt", "tokens": _tokens(refresh_token=123)},
    }
    for label, payload in cases.items():
        home = fix / label.replace(" ", "_")
        _write_auth(home, payload)
        with _env(CODEX_HOME=str(home), HOME=str(fix)):
            check(f"S12 {label} rejected",
                  D._codex_auth_available() is False, "")


def test_S13_stale_but_structured_sessions_are_accepted():
    """Age alone is not unusability: native refreshes stale sessions."""
    fix = _mkfix("stale")
    payload = json.loads(json.dumps(_FAKE_CHATGPT_AUTH))
    payload["last_refresh"] = "2025-01-01T00:00:00+00:00"
    payload["tokens"] = _tokens(id_token=_fake_id_token(exp=946684800))
    _write_auth(fix / "home", payload)
    with _env(CODEX_HOME=str(fix / "home"), HOME=str(fix)):
        check("S13 expired-but-structural record accepted (native refresh)",
              D._codex_auth_available() is True, "")


# --------------------------------------------------------------------------
# Auth-store structure failures classify as permanent credential failures
# --------------------------------------------------------------------------

def test_S14_auth_error_detector_classifies_structure_failures():
    fix = _mkfix("detect")

    def _log(name: str, body: str) -> Path:
        path = fix / name
        path.write_text(body, encoding="utf-8")
        return path

    check("S14a invalid ID token format classified",
          D._detect_codex_auth_error(
              _log("a.log", "Error checking login status: invalid ID token format")
          ) is True, "")
    check("S14b missing id_token field classified",
          D._detect_codex_auth_error(
              _log("b.log", "failed to load auth.json: missing field `id_token`")
          ) is True, "")
    check("S14c token-data-unavailable classified",
          D._detect_codex_auth_error(
              _log("c.log", "Error: Token data is not available.")
          ) is True, "")
    check("S14d model-not-available not misclassified as auth",
          D._detect_codex_auth_error(
              _log("d.log", "The model gpt-5.5 is not available for your plan")
          ) is False, "")
    check("S14e plain 401 still classified",
          D._detect_codex_auth_error(
              _log("e.log", "ERROR: unexpected status 401 Unauthorized")
          ) is True, "")


# --------------------------------------------------------------------------
# Verify-recovery shard: Codex-mode parity (F1 corrections)
# --------------------------------------------------------------------------

def _run_recovery_with_fake(
    *,
    pipeline: str,
    backend: str = "codex",
    with_auth: bool = True,
    home_alias: bool = True,
    fake_env: dict | None = None,
):
    """Run _run_verify_recovery_shard against a fake provider executable.

    Returns (fix, scratchpad, marker_dir, result, log_records).
    """
    fix = _mkfix(f"recovery_{pipeline}")
    proj = fix / "proj"
    proj.mkdir()
    sp = fix / "scratch"
    sp.mkdir()
    home = fix / "home"
    (home / ".codex").mkdir(parents=True)
    if home_alias:
        (home / ".codex" / "plamen").mkdir()
    codex_home = fix / "codexhome"
    if with_auth:
        _write_auth(codex_home, _FAKE_CHATGPT_AUTH)
    else:
        codex_home.mkdir(parents=True, exist_ok=True)

    config = {
        "scratchpad": str(sp),
        "pipeline": pipeline,
        "project_root": str(proj),
        "language": "solidity",
        "mode": "light",
        "cli_backend": backend,
    }
    missing = [
        ("F-1", {"finding id": "F-1", "severity": "High", "title": "One"}),
        ("F-2", {"finding id": "F-2", "severity": "Medium", "title": "Two"}),
    ]

    marker = fix / "markers"
    fake = fix / "fake_agent.py"
    fake.write_text(_FAKE_AGENT_SCRIPT, encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

    original_codex = D.CODEX_BIN
    original_claude = D.CLAUDE_BIN
    D.CODEX_BIN = str(fake)
    D.CLAUDE_BIN = str(fake)

    records: list[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            try:
                records.append(record.getMessage())
            except Exception:
                pass

    handler = _Collect()
    logger = D.log
    logger.addHandler(handler)

    env = {
        "HOME": str(home),
        "CODEX_HOME": str(codex_home),
        "FAKE_MARKER_DIR": str(marker),
        "FAKE_SCRATCH": str(sp),
    }
    if fake_env:
        env.update(fake_env)
    try:
        with _env(**env):
            result = D._run_verify_recovery_shard(config, missing)
    finally:
        D.CODEX_BIN = original_codex
        D.CLAUDE_BIN = original_claude
        logger.removeHandler(handler)
    return fix, sp, marker, result, records


def _attempt_payloads(marker: Path) -> list[dict]:
    if not marker.exists():
        return []
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(marker.glob("attempt_*.json"))
    ]


def test_S15_recovery_codex_launch_sc_and_l1():
    """Codex-mode recovery uses the hardened codex path for both pipelines."""
    for pipeline in ("sc", "l1"):
        fix, sp, marker, result, records = _run_recovery_with_fake(
            pipeline=pipeline,
            fake_env={
                "CODEX_API_KEY": "fake-1",
                "OPENAI_API_KEY": "fake-2",
                "ANTHROPIC_API_KEY": "fake-anthropic",
                "FAKE_WRITE_VERIFY": "F-1,F-2",
            },
        )
        attempts = _attempt_payloads(marker)
        check(f"S15 {pipeline}: exactly one recovery spawn",
              len(attempts) == 1, str([a.get("attempt") for a in attempts]))
        if not attempts:
            continue
        payload = attempts[0]
        argv = payload["argv"]
        check(f"S15 {pipeline}: launched the codex-style invocation",
              "exec" in argv[1:], " ".join(argv))
        check(f"S15 {pipeline}: claude flags absent",
              "-p" not in argv, " ".join(argv))
        check(f"S15 {pipeline}: forced chatgpt login flag present",
              _contains_pair(argv, _FORCED_LOGIN_PAIRS[0]), " ".join(argv))
        check(f"S15 {pipeline}: file credential store flag present",
              _contains_pair(argv, _FORCED_LOGIN_PAIRS[1]), " ".join(argv))
        check(f"S15 {pipeline}: inherited CODEX_API_KEY scrubbed",
              payload["codex_api_key_present"] is False, "")
        check(f"S15 {pipeline}: inherited OPENAI_API_KEY scrubbed",
              payload["openai_api_key_present"] is False, "")
        check(f"S15 {pipeline}: unrelated ANTHROPIC_API_KEY preserved",
              payload["anthropic_api_key_present"] is True, "")
        check(f"S15 {pipeline}: prompt carried the recovery directive",
              payload["prompt_mentions_recovery"] is True, "")
        if pipeline == "sc":
            check("S15 sc: methodology paths translated to the codex alias",
                  payload["prompt_mentions_codex_path"] is True, "")
        check(f"S15 {pipeline}: recovered files accepted (no still-missing)",
              result == [], str(result))
        check(f"S15 {pipeline}: pre-created verify targets exist",
              (sp / "verify_F-1.md").exists(), "")


def test_S16_recovery_codex_missing_oauth_fails_clearly_without_spawn():
    fix, sp, marker, result, records = _run_recovery_with_fake(
        pipeline="sc", with_auth=False,
    )
    check("S16a no spawn without OAuth", _attempt_payloads(marker) == [], "")
    check("S16b all findings returned as still missing",
          sorted(result) == ["F-1", "F-2"], str(result))
    check("S16c clear subscription-OAuth failure logged",
          any("subscription OAuth not available" in r for r in records),
          " | ".join(records[-6:]))


def test_S17_recovery_codex_model_rejection_retries_without_model():
    fix, sp, marker, result, records = _run_recovery_with_fake(
        pipeline="sc",
        fake_env={"FAKE_FAIL_MODEL": "1", "FAKE_WRITE_VERIFY": "F-1,F-2"},
    )
    attempts = _attempt_payloads(marker)
    check("S17a two attempts ran", len(attempts) == 2,
          str([a.get("attempt") for a in attempts]))
    if len(attempts) == 2:
        first, second = attempts
        check("S17b attempt 1 used --model", "--model" in first["argv"], "")
        check("S17c attempt 2 dropped --model",
              "--model" not in second["argv"], " ".join(second["argv"]))
        check("S17d attempt 2 kept forced chatgpt login",
              _contains_pair(second["argv"], _FORCED_LOGIN_PAIRS[0]), "")
        check("S17e retry logged",
              any("Retrying without --model" in r for r in records), "")
    check("S17f recovered after retry", result == [], str(result))


def test_S18_recovery_codex_auth_error_is_permanent_no_retry():
    fix, sp, marker, result, records = _run_recovery_with_fake(
        pipeline="sc", fake_env={"FAKE_AUTH_ERROR": "1"},
    )
    check("S18a single attempt only (auth failure is not retried)",
          len(_attempt_payloads(marker)) == 1, "")
    check("S18b clear permanent auth failure logged",
          any("Codex authentication error" in r for r in records), "")
    check("S18c findings returned as still missing",
          sorted(result) == ["F-1", "F-2"], str(result))


def test_S19_recovery_claude_backend_preserved():
    """Explicit Claude-mode recovery keeps its launcher and flags."""
    fix, sp, marker, result, records = _run_recovery_with_fake(
        pipeline="sc", backend="claude", with_auth=False,
        fake_env={"CODEX_API_KEY": "fake-1", "FAKE_WRITE_VERIFY": "F-1,F-2"},
    )
    attempts = _attempt_payloads(marker)
    check("S19a one attempt ran", len(attempts) == 1, "")
    if attempts:
        argv = attempts[0]["argv"]
        check("S19b claude launcher flags present",
              "-p" in argv and "exec" not in argv, " ".join(argv))
        check("S19c claude model flag present", "--model" in argv, "")
        check("S19d claude recovery ignores the codex auth store",
              "--ignore-user-config" not in argv, " ".join(argv))
        check("S19e codex API keys scrubbed for claude too",
              attempts[0]["codex_api_key_present"] is False, "")
    check("S19f recovered without any Codex auth", result == [], str(result))


def test_S20_codex_prompt_translation_requires_methodology_alias():
    fix = _mkfix("alias")
    text = "Read ~/.claude/rules/finding-output-format.md before writing."
    with _env(HOME=str(fix / "noalias")):
        raised = False
        message = ""
        try:
            D._translate_prompt_for_codex(text, phase_name="verify_recovery")
        except RuntimeError as exc:
            raised = True
            message = str(exc)
    check("S20a missing $HOME/.codex/plamen raises RuntimeError", raised, "")
    check("S20b message names the alias remediation",
          ".codex" in message and "plamen" in message, message)
    home = fix / "alias"
    (home / ".codex" / "plamen").mkdir(parents=True)
    with _env(HOME=str(home)):
        translated = D._translate_prompt_for_codex(
            text, phase_name="verify_recovery",
        )
    check("S20c methodology path rewritten to the alias",
          "~/.codex/plamen/rules/finding-output-format.md" in translated,
          translated[:200])


def test_S21_recovery_codex_alias_missing_fails_clearly_without_spawn():
    fix, sp, marker, result, records = _run_recovery_with_fake(
        pipeline="sc", home_alias=False,
    )
    check("S21a no spawn without the methodology alias",
          _attempt_payloads(marker) == [], "")
    check("S21b clear translation failure logged",
          any("prompt translation failed" in r for r in records),
          " | ".join(records[-6:]))
    check("S21c findings returned as still missing",
          sorted(result) == ["F-1", "F-2"], str(result))


# --------------------------------------------------------------------------
# Native key-field resolution parity (review round 3, R1)
# --------------------------------------------------------------------------

def test_S22_native_key_field_resolution_parity():
    """Missing/null auth_mode x key-field matrix, matched to the pinned
    native resolved_mode(): explicit mode wins; otherwise the API-key
    field decides by PRESENCE (Option::is_some() — an empty string still
    resolves to API mode); wrong-typed fields fail the record."""
    fix = _mkfix("keyfield")
    tokens = _tokens()
    cases = (
        ("missing mode, key absent", {"tokens": tokens}, True),
        ("missing mode, key null",
            {"tokens": tokens, "OPENAI_API_KEY": None}, True),
        ("null mode, key absent",
            {"auth_mode": None, "tokens": tokens}, True),
        ("null mode, key null",
            {"auth_mode": None, "tokens": tokens, "OPENAI_API_KEY": None}, True),
        ("missing mode, key empty",
            {"tokens": tokens, "OPENAI_API_KEY": ""}, False),
        ("missing mode, key nonempty",
            {"tokens": tokens, "OPENAI_API_KEY": "fixture-key"}, False),
        ("null mode, key empty",
            {"auth_mode": None, "tokens": tokens, "OPENAI_API_KEY": ""}, False),
        ("null mode, key nonempty",
            {"auth_mode": None, "tokens": tokens,
             "OPENAI_API_KEY": "fixture-key"}, False),
        ("wrong-type key 42, missing mode",
            {"tokens": tokens, "OPENAI_API_KEY": 42}, False),
        ("wrong-type key 42, explicit chatgpt",
            {"auth_mode": "chatgpt", "tokens": tokens,
             "OPENAI_API_KEY": 42}, False),
        ("wrong-type mode 42", {"auth_mode": 42, "tokens": tokens}, False),
        ("wrong-type last_refresh 123",
            {"tokens": tokens, "last_refresh": 123}, False),
    )
    for label, payload, want in cases:
        home = fix / label.replace(",", "").replace(" ", "_")
        _write_auth(home, payload)
        with _env(CODEX_HOME=str(home), HOME=str(fix)):
            got = D._codex_auth_available()
            check(f"S22 {label}: accepted" if want else f"S22 {label}: refused",
                  got is want, f"got {got} want {want}")


def test_S23_strict_native_payload_decoding():
    """Strict URL_SAFE_NO_PAD parity: alphabet, length, canonicality."""
    fix = _mkfix("strict")
    header, payload, sig = _fake_id_token().split(".")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    # Non-canonical tail: the low bits of the last symbol are unused;
    # flipping them keeps Python's decoded bytes but is rejected by the
    # native strict decoder. Shape the payload length so 2 spare bits exist.
    raw = json.dumps({"exp": 4102444800, "chatgpt_fixture": True}).encode("utf-8")
    while len(base64.urlsafe_b64encode(raw).rstrip(b"=")) % 4 != 3:
        raw += b" "
    enc = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    last_bit_flipped = enc[:-1] + alphabet[alphabet.index(enc[-1]) ^ 1]
    # A payload whose encoded length is 1 mod 4 is invalid base64.
    bad_len = payload + "A" * ((1 - len(payload) % 4) % 4)
    assert len(bad_len) % 4 == 1
    cases = (
        ("valid control", f"{header}.{payload}.{sig}", True),
        ("signature with !!!! (never decoded natively)",   # native parity control
            f"{header}.{payload}.{sig}!!!!", True),
        ("payload with !! (ignored by Python's decoder)",
            f"{header}.{payload}!!.{sig}", False),
        ("payload with = padding", f"{header}.{payload}==.{sig}", False),
        ("non-canonical trailing bits", f"{header}.{last_bit_flipped}.{sig}", False),
        ("invalid encoded length (1 mod 4)", f"{header}.{bad_len}.{sig}", False),
    )
    for label, id_token, want in cases:
        home = fix / label.replace(" ", "_").replace("!", "")
        _write_auth(home, {"auth_mode": "chatgpt",
                           "tokens": _tokens(id_token=id_token)})
        with _env(CODEX_HOME=str(home), HOME=str(fix)):
            got = D._codex_auth_available()
            check(f"S23 {label}: accepted" if want else f"S23 {label}: refused",
                  got is want, f"got {got} want {want}")


def test_S24_typed_token_field_parity():
    """Native TokenData types account_id as Option<String>."""
    fix = _mkfix("typedfield")
    cases = (
        ("account_id string accepted",
            _tokens(account_id="acct-fixture"), True),
        ("account_id null accepted", _tokens(account_id=None), True),
        ("account_id integer refused", _tokens(account_id=42), False),
        ("account_id object refused", _tokens(account_id={"a": 1}), False),
    )
    for label, tokens, want in cases:
        home = fix / label.replace(" ", "_")
        _write_auth(home, {"auth_mode": "chatgpt", "tokens": tokens})
        with _env(CODEX_HOME=str(home), HOME=str(fix)):
            got = D._codex_auth_available()
            check(f"S24 {label}", got is want, f"got {got} want {want}")


def test_S25_native_load_failure_classification():
    """Native auth-store load errors (serde-position anchored, strict
    base64, forced-login violation) classify as permanent auth failures;
    audit prose with line/column text does not."""
    fix = _mkfix("classify3")

    def _log(name: str, body: str) -> Path:
        path = fix / name
        path.write_text(body, encoding="utf-8")
        return path

    true_cases = (
        ("forced-login violation",
         "ChatGPT login is required, but an API key is currently being used. Logging out."),
        ("strict base64 symbol",
         "Invalid symbol 33, offset 254. at line 1 column 425"),
        ("strict base64 last symbol",
         "Invalid last symbol 49, offset 58. at line 1 column 153"),
        ("strict base64 input length",
         "Invalid input length: 69 at line 1 column 163"),
        ("serde invalid type",
         "invalid type: integer `42`, expected a string at line 1 column 438"),
        ("serde invalid value",
         "invalid value: string \"garbage\", expected RFC 3339 date at line 1 column 52"),
        ("serde missing field",
         "missing field `access_token` at line 1 column 19"),
        ("serde eof",
         "EOF while parsing a value at line 1 column 0"),
    )
    false_cases = (
        ("solidity parser prose",
         "ParserError: Expected ';' but got '}' at line 5 column 3"),
        ("audit prose with line/column",
         "the invariant at line 3 column 2 was broken by reentrancy; see finding F-12"),
    )
    def _fn(label: str) -> str:
        return label.replace("/", "-").replace(" ", "_") + ".log"

    for label, body in true_cases:
        check(f"S25 classified: {label}",
              D._detect_codex_auth_error(_log(_fn(label), body)) is True, "")
    for label, body in false_cases:
        check(f"S25 not classified: {label}",
              D._detect_codex_auth_error(_log(_fn(label), body)) is False, "")


def test_S26_api_mode_record_refused_before_launch():
    """R1 acceptance: a native-resolved API-mode record (empty key field)
    is refused before any child launch, with the auth store left
    byte-identical — via run_phase and via the recovery shard."""
    fix = _mkfix("refuse")
    sp = fix / "scratch"
    sp.mkdir()
    proj = fix / "proj"
    proj.mkdir()
    (fix / "home" / ".codex" / "plamen").mkdir(parents=True)
    codex_home = fix / "codexhome"
    _write_auth(codex_home, {"tokens": _tokens(), "OPENAI_API_KEY": ""})
    auth_path = codex_home / "auth.json"
    before = auth_path.read_bytes()

    marker = fix / "markers"
    fake = fix / "fake_agent.py"
    fake.write_text(_FAKE_AGENT_SCRIPT, encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    original_codex = D.CODEX_BIN
    D.CODEX_BIN = str(fake)
    try:
        with _env(HOME=str(fix / "home"), CODEX_HOME=str(codex_home),
                  FAKE_MARKER_DIR=str(marker), FAKE_SCRATCH=str(sp),
                  PLAMEN_PLAIN_OUTPUT="1"):
            phase = [ph for ph in D.SC_PHASES if ph.name == "breadth"][0]
            phase_config = {
                "scratchpad": str(sp), "pipeline": "sc",
                "project_root": str(proj), "language": "solidity",
                "mode": "light", "cli_backend": "codex",
            }
            rc = D.run_phase(phase, dict(phase_config), 1)
            recovery = D._run_verify_recovery_shard(
                dict(phase_config),
                [("F-1", {"finding id": "F-1", "severity": "High",
                          "title": "One"})],
            )
    finally:
        D.CODEX_BIN = original_codex
    check("S26a run_phase refused the native API-mode record (EXIT_ERROR)",
          rc == D.EXIT_ERROR, f"rc={rc}")
    check("S26b no child was launched (no marker)",
          not (marker.exists() and list(marker.glob("attempt_*.json")))
          and not (marker.exists() and list(marker.iterdir())), "")
    check("S26c auth store bytes unchanged after run_phase",
          auth_path.read_bytes() == before, "")
    check("S26d recovery shard also refused",
          recovery == ["F-1"], str(recovery))
    check("S26e auth store still unchanged after recovery",
          auth_path.read_bytes() == before, "")


# --------------------------------------------------------------------------
# Native claim/timestamp typing and signal-scoped classification (R3 review)
# --------------------------------------------------------------------------

def _token_with_claims(claims: dict) -> str:
    header, _, signature = _fake_id_token().split(".")
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    return f"{header}.{payload}.{signature}"


def _case_dir(fix: Path, label: str) -> Path:
    return fix / re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")


def test_S27_native_claim_type_parity():
    """Known claims parsed by the pinned IdClaims/AuthClaims are
    type-checked; unknown claims stay ignored like native serde."""
    fix = _mkfix("claims")
    base = {"email": "fixture@example.invalid",
            "https://api.openai.com/auth": {"chatgpt_plan_type": "plus"}}
    auth_claim = "https://api.openai.com/auth"
    cases = (
        ("baseline claims accepted", base, True),
        ("fedramp false accepted",
            {auth_claim: {"chatgpt_plan_type": "plus",
                          "chatgpt_account_is_fedramp": False}}, True),
        ("fedramp true accepted",
            {auth_claim: {"chatgpt_plan_type": "plus",
                          "chatgpt_account_is_fedramp": True}}, True),
        ("fedramp string refused (value-bearing)",
            {auth_claim: {"chatgpt_account_is_fedramp":
                          "fixture-value-marker-0123456789"}}, False),
        ("fedramp null refused",
            {auth_claim: {"chatgpt_account_is_fedramp": None}}, False),
        ("plan type number refused",
            {auth_claim: {"chatgpt_plan_type": 42}}, False),
        ("auth claim non-object refused",
            {auth_claim: "fixture"}, False),
        ("email number refused", {"email": 42}, False),
        ("profile non-object refused",
            {"https://api.openai.com/profile": 7}, False),
        ("profile email number refused",
            {"https://api.openai.com/profile": {"email": 7}}, False),
        ("unknown claim ignored",
            {**base, "https://example.invalid/other": {"anything": [1, 2]}},
            True),
    )
    for label, claims, want in cases:
        home = _case_dir(fix, label)
        _write_auth(home, {"auth_mode": "chatgpt",
                           "tokens": _tokens(id_token=_token_with_claims(claims))})
        with _env(CODEX_HOME=str(home), HOME=str(fix)):
            got = D._codex_auth_available()
            check(f"S27 {label}", got is want, f"got {got} want {want}")


def test_S28_native_timestamp_parity():
    """last_refresh must match the native RFC 3339 grammar (space/t
    separators, leap second, trailing whitespace and Z/offsets accepted by
    native; out-of-range components refused); age is never a rejection
    criterion (native refresh handles stale sessions)."""
    fix = _mkfix("timestamps")
    cases = (
        ("offset accepted", "2026-01-01T00:00:00+00:00", True),
        ("zulu accepted", "2026-01-01T00:00:00Z", True),
        ("fractional + offset accepted", "2026-01-01T00:00:00.123456+02:30", True),
        ("stale-but-valid accepted", "2021-01-01T00:00:00Z", True),
        ("null accepted", None, True),
        ("space separator accepted (native control)",
            "2026-01-01 00:00:00Z", True),
        ("leap second accepted (native control)",
            "2016-12-31T23:59:60Z", True),
        ("trailing whitespace accepted (native control)",
            "2026-01-01T00:00:00Z\n", True),
        ("not-a-date refused", "not-a-date", False),
        ("date only refused", "2026-01-01", False),
        ("month 13 refused", "2026-13-01T00:00:00Z", False),
        ("day 32 refused", "2026-01-32T00:00:00Z", False),
        ("feb 30 refused", "2026-02-30T00:00:00Z", False),
        ("hour 25 refused", "2026-01-01T25:00:00Z", False),
        ("minute 61 refused", "2026-01-01T00:61:00Z", False),
        ("offset minute 60 refused (native out-of-range)",
            "2099-01-01T00:00:00+00:60", False),
        ("offset minute 99 refused (native out-of-range)",
            "2099-01-01T00:00:00+01:99", False),
        ("offset hour 24 refused (native out-of-range)",
            "2099-01-01T00:00:00+24:00", False),
        ("colon-less offset refused", "2026-01-01T00:00:00+0000", False),
        ("trailing junk refused", "2026-01-01T00:00:00Z junk", False),
        ("fullwidth digits refused (ASCII-only grammar)",
            "２０９９-01-01T00:00:00Z", False),
    )
    for label, value, want in cases:
        home = _case_dir(fix, label)
        record = {"auth_mode": "chatgpt", "tokens": _tokens()}
        record["last_refresh"] = value
        _write_auth(home, record)
        with _env(CODEX_HOME=str(home), HOME=str(fix)):
            got = D._codex_auth_available()
            check(f"S28 {label}", got is want, f"got {got} want {want}")


def test_S29_cli_signal_scoped_classification():
    """Audit/tool content in item.* events never classifies as auth; raw
    diagnostics and error/turn.failed payloads still do."""
    fix = _mkfix("signal")

    def _log(name: str, lines) -> Path:
        path = fix / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    item_agent = json.dumps({"type": "item.completed", "item": {
        "id": "item_1", "type": "agent_message",
        "text": "Application JSON loader: invalid type: integer `42`, "
                "expected a string at line 1 column 438"}})
    item_command = json.dumps({"type": "item.completed", "item": {
        "id": "item_2", "type": "command_execution",
        "command": "fixture parser",
        "aggregated_output": "Invalid symbol 33, offset 254. at line 1 column 425",
        "exit_code": 1, "status": "completed"}})
    item_violation = json.dumps({"type": "item.completed", "item": {
        "id": "item_3", "type": "agent_message",
        "text": "note: ChatGPT login is required, but an API key is "
                "currently being used"}})
    false_cases = (
        ("reviewer agent_message fixture", [item_agent]),
        ("reviewer command_execution fixture", [item_command]),
        ("violation phrase in audit content", [item_violation]),
        ("thread.started progress event", [json.dumps(
            {"type": "thread.started", "thread_id": "t-1"})]),
        ("401 inside command output", [json.dumps(
            {"type": "item.completed", "item": {
                "id": "item_4", "type": "command_execution",
                "aggregated_output": "HTTP 401 Unauthorized",
                "exit_code": 1, "status": "completed"}})]),
    )
    true_cases = (
        ("plain serde line", [
            "invalid type: integer `42`, expected a string at line 1 column 438"]),
        ("daily date diagnostic", [
            "input contains invalid characters at line 1 column 451"]),
        ("error event payload", [json.dumps(
            {"type": "error",
             "message": "invalid type: integer `42`, expected a string at line 1 column 438"})]),
        ("turn.failed payload", [json.dumps(
            {"type": "turn.failed", "error": {
                "message": "ChatGPT login is required, but an API key is "
                           "currently being used. Logging out."}})]),
        ("mixed audit + real diagnostic", [
            item_agent,
            "ERROR: invalid ID token format",
        ]),
    )
    for label, lines in false_cases:
        check(f"S29 not classified: {label}",
              D._detect_codex_auth_error(_log(_case_dir(fix, label).name + ".jsonl", lines)) is False, "")
    for label, lines in true_cases:
        check(f"S29 classified: {label}",
              D._detect_codex_auth_error(_log(_case_dir(fix, label).name + ".jsonl", lines)) is True, "")


_S30_MARKER = "FAKE-VALUE-MARKER-0123456789abcdef"


def _run_phase_with_fake(fix: Path, codex_home: Path, fake_env: dict | None = None):
    """Run run_phase('breadth') against the fake provider; returns
    (scratchpad, rc)."""
    sp = fix / "scratch"
    sp.mkdir()
    proj = fix / "proj"
    proj.mkdir()
    (fix / "home" / ".codex" / "plamen").mkdir(parents=True)
    fake = fix / "fake_agent.py"
    fake.write_text(_FAKE_AGENT_SCRIPT, encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    original = D.CODEX_BIN
    D.CODEX_BIN = str(fake)
    env = {
        "HOME": str(fix / "home"), "CODEX_HOME": str(codex_home),
        "FAKE_MARKER_DIR": str(fix / "markers"), "FAKE_SCRATCH": str(sp),
        "PLAMEN_PLAIN_OUTPUT": "1",
    }
    if fake_env:
        env.update(fake_env)
    try:
        with _env(**env):
            phase = [ph for ph in D.SC_PHASES if ph.name == "breadth"][0]
            cfg = {
                "scratchpad": str(sp), "pipeline": "sc",
                "project_root": str(proj), "language": "solidity",
                "mode": "light", "cli_backend": "codex",
            }
            rc = D.run_phase(phase, cfg, 1)
    finally:
        D.CODEX_BIN = original
    return sp, rc


def test_S30_value_bearing_auth_diagnostics_scrubbed_from_logs():
    """Serde value echoes of the record must not persist in attempt or
    canonical logs; audit content is preserved; the redacted marker stays
    classifiable; the recovery shard scrubs too."""
    marker = _S30_MARKER
    fix = _mkfix("scrub")
    codex_home = fix / "codexhome"
    _write_auth(codex_home, {"auth_mode": "chatgpt",
                             "tokens": _tokens(access_token=marker)})
    sp, rc = _run_phase_with_fake(
        fix, codex_home, {"FAKE_AUTH_VALUE_ERROR": marker},
    )
    attempt = sp / "_stdio_breadth.attempt1.log"
    canonical = sp / "_stdio_breadth.log"
    check("S30a run_phase returned failure", rc != 0, f"rc={rc}")
    check("S30b attempt log scrubbed of the echoed value",
          marker not in attempt.read_text(encoding="utf-8"), "")
    check("S30c canonical log scrubbed of the echoed value",
          marker not in canonical.read_text(encoding="utf-8"), "")
    text = canonical.read_text(encoding="utf-8")
    check("S30d redacted marker present",
          "auth-store load error" in text, "")
    check("S30e scrubbed marker stays auth-classifiable",
          D._detect_codex_auth_error(canonical) is True, "")
    check("S30f auth store untouched", marker in (
        codex_home / "auth.json").read_text(encoding="utf-8"), "")

    # Audit item content keeps its text; a plain signal line carrying the
    # record value (without a value-family shape) is value-redacted only.
    fix2 = _mkfix("scrub_audit")
    codex_home2 = fix2 / "codexhome"
    _write_auth(codex_home2, {"auth_mode": "chatgpt",
                              "tokens": _tokens(access_token=marker)})
    sp2, rc2 = _run_phase_with_fake(
        fix2, codex_home2, {"FAKE_ITEM_ECHO": marker},
    )
    text2 = (sp2 / "_stdio_breadth.log").read_text(encoding="utf-8")
    items = [line for line in text2.splitlines() if '"agent_message"' in line]
    traces = [line for line in text2.splitlines() if line.startswith("login trace:")]
    check("S30g audit item content preserved (value intact there)",
          bool(items) and marker in items[0], "")
    check("S30h plain signal line value-redacted",
          bool(traces) and marker not in traces[0]
          and "[redacted]" in traces[0], traces[:1])

    # Recovery shard path.
    fix3, sp3, marker_dir3, result3, records3 = _run_recovery_with_fake(
        pipeline="sc",
        fake_env={"FAKE_AUTH_VALUE_ERROR": marker},
    )
    recovery_log = sp3 / "_stdio_verify_recovery.attempt1.log"
    check("S30i recovery returned still-missing",
          result3 == ["F-1", "F-2"], str(result3))
    check("S30j recovery log scrubbed of the echoed value",
          marker not in recovery_log.read_text(encoding="utf-8"), "")
    check("S30k recovery redacted marker present + classifiable",
          "auth-store load error" in recovery_log.read_text(encoding="utf-8")
          and D._detect_codex_auth_error(recovery_log) is True, "")


# --------------------------------------------------------------------------
# Round-5: duplicate-key strictness, signal-scoped exclusions, first-write
# sanitization (review of daf552a)
# --------------------------------------------------------------------------

def test_S31_duplicate_key_and_known_field_strictness():
    """Occurrence-by-occurrence validation: duplicate keys that Python
    collapses (last wins) must fail like the native serde scan when an
    earlier occurrence is wrong-typed; agent_identity is type-checked."""
    fix = _mkfix("dups")
    base_tokens = _tokens()
    header, _, signature = _fake_id_token().split(".")
    def _token_for(claims_raw: bytes) -> str:
        payload = base64.urlsafe_b64encode(claims_raw).rstrip(b"=").decode()
        return f"{header}.{payload}.{signature}"

    duplicate_claim_token = _token_for(
        b'{"https://api.openai.com/auth":'
        b'{"chatgpt_account_is_fedramp":"SYNTHETIC-MARKER",'
        b'"chatgpt_account_is_fedramp":false}}'
    )
    dict_cases = (
        ("duplicate wrong-then-valid claim refused",
            {"auth_mode": "chatgpt",
             "tokens": _tokens(id_token=duplicate_claim_token)}, False),
        ("agent_identity integer refused",
            {"auth_mode": "chatgpt", "tokens": base_tokens,
             "agent_identity": 42}, False),
        ("agent_identity string accepted",
            {"auth_mode": "chatgpt", "tokens": base_tokens,
             "agent_identity": "fixture-agent-jwt"}, True),
        ("agent_identity null accepted",
            {"auth_mode": "chatgpt", "tokens": base_tokens,
             "agent_identity": None}, True),
        ("unknown top-level field ignored",
            {"auth_mode": "chatgpt", "tokens": base_tokens,
             "future_field": {"x": 1}}, True),
    )
    for label, payload, want in dict_cases:
        home = _case_dir(fix, label)
        _write_auth(home, payload)
        with _env(CODEX_HOME=str(home), HOME=str(fix)):
            check(f"S31 {label}", D._codex_auth_available() is want, "")
    tokens_json = json.dumps(base_tokens)
    raw_cases = (
        ("duplicate unknown auth_mode refused",
            '{"auth_mode": "bogus-mode", "auth_mode": "chatgpt", '
            f'"tokens": {tokens_json}}}', False),
        ("duplicate wrong-typed key field refused",
            '{"auth_mode": "chatgpt", '
            f'"tokens": {tokens_json}, '
            '"OPENAI_API_KEY": 42, "OPENAI_API_KEY": null}', False),
        ("duplicate wrong-typed tokens refused",
            '{"auth_mode": "chatgpt", "tokens": 42, '
            f'"tokens": {tokens_json}}}', False),
    )
    for label, raw, want in raw_cases:
        home = _case_dir(fix, label)
        home.mkdir()
        (home / "auth.json").write_text(raw, encoding="utf-8")
        with _env(CODEX_HOME=str(home), HOME=str(fix)):
            check(f"S31 {label}", D._codex_auth_available() is want, "")


def test_S32_quoted_quota_text_scoping():
    """An audit item quoting quota/model text neither masks a real auth
    failure nor registers as a rate limit; real signals still classify."""
    fix = _mkfix("quota")
    item_quota = json.dumps({"type": "item.completed", "item": {
        "id": "item_3", "type": "agent_message",
        "text": "Documentation example: usage_limit_reached is an API error code."}})
    item_model = json.dumps({"type": "item.completed", "item": {
        "id": "item_4", "type": "agent_message",
        "text": "The docs mention: model gpt-5.5 does not exist for this plan."}})
    cases = (
        ("quota item + real 401 event",
         [item_quota, json.dumps({"type": "error",
                                  "message": "HTTP 401 Unauthorized"})],
         True, False),
        ("quota item + native load-error line",
         [item_quota,
          "invalid type: integer `42`, expected a string at line 1 column 438"],
         True, False),
        ("model-quote item + real 401 event",
         [item_model, "ERROR: unexpected status 401 Unauthorized"],
         True, False),
        ("quota item + real quota event (still detected)",
         [item_quota, json.dumps({"type": "error",
                                  "message": "usage_limit_reached"})],
         False, True),
        ("quota item alone is neither",
         [item_quota], False, False),
    )
    for label, lines, want_auth, want_rate in cases:
        path = fix / (_case_dir(fix, label).name + ".jsonl")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        check(f"S32 auth: {label}",
              D._detect_codex_auth_error(path) is want_auth, "")
        check(f"S32 rate-limit rc=1: {label}",
              D._detect_codex_rate_limit(path, 1) is want_rate, "")


def test_S33_auth_values_never_persisted_before_cleanup():
    """The value must already be absent when the post-hoc scrub runs (the
    sanitizer applies at first write), and must never appear in the log
    while the child is still running (interrupt-safety)."""
    marker = "SYNTHETIC-REVIEW-INGRESS-MARKER"
    fix = _mkfix("ingress")
    codex_home = fix / "codexhome"
    _write_auth(codex_home, {"auth_mode": "chatgpt",
                             "tokens": _tokens(access_token=marker)})
    captured: list[bool] = []
    original = D._scrub_auth_value_diagnostics

    def observe(paths):
        captured.extend(
            marker in p.read_text(errors="replace") for p in paths if p.exists()
        )
        return original(paths)
    with mock.patch.object(D, "_scrub_auth_value_diagnostics", side_effect=observe):
        _run_phase_with_fake(fix, codex_home, {"FAKE_AUTH_VALUE_ERROR": marker})
    check("S33a scrub boundary observed", bool(captured), "")
    check("S33b value absent at the scrub boundary (sanitized at first write)",
          not any(captured), "")
    # Interrupt-safety: while the child is still running (it sleeps after
    # emitting the diagnostic), the persisted log already carries the
    # redacted marker and never the raw value.
    fix2 = _mkfix("ingress_live")
    home2 = fix2 / "codexhome"
    _write_auth(home2, {"auth_mode": "chatgpt",
                        "tokens": _tokens(access_token=marker)})
    sp2 = fix2 / "scratch"
    sp2.mkdir()
    proj2 = fix2 / "proj"
    proj2.mkdir()
    (fix2 / "home" / ".codex" / "plamen").mkdir(parents=True)
    fake = fix2 / "fake_agent.py"
    fake.write_text(_FAKE_AGENT_SCRIPT, encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    original_bin = D.CODEX_BIN
    D.CODEX_BIN = str(fake)
    result: dict = {}

    def _drive():
        with _env(HOME=str(fix2 / "home"), CODEX_HOME=str(home2),
                  FAKE_MARKER_DIR=str(fix2 / "markers"),
                  FAKE_SCRATCH=str(sp2), PLAMEN_PLAIN_OUTPUT="1",
                  FAKE_AUTH_VALUE_ERROR=marker, FAKE_SLEEP="6"):
            phase = [ph for ph in D.SC_PHASES if ph.name == "breadth"][0]
            result["rc"] = D.run_phase(phase, {
                "scratchpad": str(sp2), "pipeline": "sc",
                "project_root": str(proj2), "language": "solidity",
                "mode": "light", "cli_backend": "codex",
            }, 1)
    driver_thread = threading.Thread(target=_drive, daemon=True)
    seen_redacted = False
    try:
        driver_thread.start()
        attempt = sp2 / "_stdio_breadth.attempt1.log"
        for _ in range(120):
            time.sleep(0.1)
            if attempt.exists():
                text = attempt.read_text(encoding="utf-8", errors="replace")
                if "auth-store load error" in text:
                    seen_redacted = True
                    check("S33d raw value absent while child still running",
                          marker not in text, "")
                    break
    finally:
        driver_thread.join(timeout=30)
        D.CODEX_BIN = original_bin
    check("S33c redacted marker persisted while child still running",
          seen_redacted, "")
    check("S33e run completed", "rc" in result, "")


# --------------------------------------------------------------------------
# Round-6: native duplicate-field rejection, non-JSON constants, remaining
# load-error families, cancellation reaping (review of 5f5ad00)
# --------------------------------------------------------------------------

def _claim_record(raw_claims: str) -> dict:
    record = json.loads(json.dumps(_FAKE_CHATGPT_AUTH))
    parts = record["tokens"]["id_token"].split(".")
    parts[1] = base64.urlsafe_b64encode(raw_claims.encode()).rstrip(b"=").decode()
    record["tokens"]["id_token"] = ".".join(parts)
    return record


def test_S34_native_duplicate_known_fields_refused():
    """Repeated native-known fields are rejected like the serde derive
    ("duplicate field"), regardless of the values; duplicates of unknown
    fields stay ignored; the store is never rewritten."""
    fix = _mkfix("dupknown")
    base = json.dumps(_FAKE_CHATGPT_AUTH)
    claim_cases = {
        "email_null": '{"email":null,"email":"fixture@example.invalid"}',
        "profile_email":
            '{"https://api.openai.com/profile":'
            '{"email":null,"email":"fixture@example.invalid"}}',
        "auth_object":
            '{"https://api.openai.com/auth":null,'
            '"https://api.openai.com/auth":{}}',
        "fedramp_bool":
            '{"https://api.openai.com/auth":'
            '{"chatgpt_account_is_fedramp":false,'
            '"chatgpt_account_is_fedramp":true}}',
    }
    raw_cases = [
        ("duplicate auth_mode (well-typed)",
         base.replace('"auth_mode": "chatgpt"',
                      '"auth_mode":"chatgpt","auth_mode":"chatgpt"'), False),
        ("duplicate access_token (well-typed)",
         base.replace('"access_token": "fake-access-token"',
                      '"access_token":"fake-access-token",'
                      '"access_token":"fake-access-token"'), False),
    ]
    for label, raw_claims in claim_cases.items():
        raw_cases.append(
            (f"duplicate claim {label}",
             json.dumps(_claim_record(raw_claims)), False)
        )
    raw_cases.append(
        ("duplicate unknown fields ignored (compatibility control)",
         json.dumps(_claim_record('{"future_field":1,"future_field":2}')), True)
    )
    for label, raw, want in raw_cases:
        home = _case_dir(fix, label)
        home.mkdir()
        auth_path = home / "auth.json"
        auth_path.write_text(raw, encoding="utf-8")
        before = auth_path.read_bytes()
        with _env(CODEX_HOME=str(home), HOME=str(fix)):
            got = D._codex_auth_available()
        check(f"S34 {label}", got is want, f"got {got} want {want}")
        check(f"S34 {label}: store byte-identical",
              auth_path.read_bytes() == before, "")


def test_S35_non_json_constants_refused():
    """NaN/Infinity/-Infinity are Python extensions native serde_json
    refuses; both the record and the payload parser must reject them."""
    fix = _mkfix("constants")
    record_base = json.dumps(_FAKE_CHATGPT_AUTH)[:-1]
    for index, constant in enumerate(("NaN", "Infinity", "-Infinity")):
        for where in ("record", "claim"):
            if where == "record":
                raw = record_base + ',"future_field":' + constant + "}"
            else:
                raw = json.dumps(
                    _claim_record('{"future_field":' + constant + "}")
                )
            home = _case_dir(fix, f"c{index}_{where}")
            home.mkdir()
            (home / "auth.json").write_text(raw, encoding="utf-8")
            with _env(CODEX_HOME=str(home), HOME=str(fix)):
                got = D._codex_auth_available()
            check(f"S35 {constant} in {where} refused", got is False, "")


def test_S36_remaining_native_load_error_families_classify():
    """`duplicate field` and `invalid number` position-anchored diagnostics
    classify as permanent auth failures; item-scoped copies do not."""
    fix = _mkfix("families")
    diagnostics = (
        "duplicate field `auth_mode` at line 1 column 34",
        "duplicate field `chatgpt_account_is_fedramp` at line 1 column 95",
        "invalid number at line 1 column 499",
        "expected value at line 1 column 17",
    )
    for index, diagnostic in enumerate(diagnostics):
        plain = fix / f"plain_{index}.log"
        plain.write_text(diagnostic + "\n", encoding="utf-8")
        check(f"S36 classified: {diagnostic[:40]}",
              D._detect_codex_auth_error(plain) is True, "")
        scoped = fix / f"item_{index}.jsonl"
        scoped.write_text(json.dumps({
            "type": "item.completed",
            "item": {"id": "item_1", "type": "agent_message",
                     "text": diagnostic},
        }) + "\n", encoding="utf-8")
        check(f"S36 not classified in item: {diagnostic[:40]}",
              D._detect_codex_auth_error(scoped) is False, "")


def test_S37_cancellation_reaps_child_and_completes_quickly():
    """SIGINT during a recovery attempt and an ordinary phase: the driver
    stops/reaps the owned child, completes promptly, propagates the
    interruption (rc 130), and the log never holds the raw value."""
    marker = _S30_MARKER
    scripts_dir = Path(__file__).resolve().parent
    worker_src = """
import os, pathlib, sys
case = pathlib.Path(sys.argv[1]); route = sys.argv[2]
sys.path.insert(0, %r)
import plamen_driver as D
import test_codex_subscription_only as T
home = case / 'auth'
T._write_auth(home, {'auth_mode': 'chatgpt', 'tokens': T._tokens(access_token=%r)})
os.environ['CODEX_HOME'] = str(home)
os.environ['PLAMEN_PLAIN_OUTPUT'] = '1'
D.CODEX_BIN = str(case / 'fake_provider.py')
(case / 'prompt.txt').write_text('Synthetic prompt only.')
try:
    if route == 'phase':
        phase = next(p for p in D.SC_PHASES if p.name == 'recon')
        D.run_phase(phase, {'scratchpad': str(case/'scratch'),
                            'project_root': str(case/'project'),
                            'pipeline': 'sc', 'language': 'solidity',
                            'mode': 'light', 'cli_backend': 'codex'}, 1)
    else:
        D._run_recovery_attempt([sys.executable, str(case/'fake_provider.py')],
            case/'scratch'/'_stdio_verify_recovery.attempt1.log',
            snap=case/'prompt.txt', project_root=str(case/'project'),
            subprocess_env=dict(os.environ),
            popen_kwargs={'start_new_session': True},
            timeout=120, sanitize_stream=True)
except KeyboardInterrupt:
    print('REVIEW_SIGINT_PROPAGATED', flush=True)
    sys.exit(130)
""" % (str(scripts_dir), marker)
    diagnostic = 'invalid type: string "%s", expected a boolean at line 1 column 94' % marker
    for route in ("recovery", "phase"):
        case = _mkfix(f"sigint_{route}")
        (case / "scratch").mkdir()
        (case / "project").mkdir()
        fake = case / "fake_provider.py"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, time\n"
            "pathlib.Path(%r).write_text(str(os.getpid()))\n"
            "print(%r, flush=True)\n"
            "time.sleep(120)\n"
            % (str(case / "provider.pid"), diagnostic),
            encoding="utf-8",
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        worker = case / "worker.py"
        worker.write_text(worker_src, encoding="utf-8")
        env = {**os.environ, "PLAMEN_HOME": str(scripts_dir.parent)}
        driver = subprocess.Popen(
            [sys.executable, str(worker), str(case), route],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=env, start_new_session=True,
        )
        log = case / "scratch" / (
            "_stdio_verify_recovery.attempt1.log" if route == "recovery"
            else "_stdio_recon.attempt1.log")
        provider_pid = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            pid_file = case / "provider.pid"
            if pid_file.exists():
                provider_pid = int(pid_file.read_text())
            if provider_pid and log.exists() and log.stat().st_size:
                break
            time.sleep(0.02)
        check(f"S37 {route}: control ready",
              bool(provider_pid and log.exists() and log.stat().st_size), "")
        start = time.monotonic()
        os.kill(driver.pid, signal.SIGINT)
        try:
            out, _ = driver.communicate(timeout=10)
            finished = True
        except subprocess.TimeoutExpired:
            finished = False
            out = ""
            os.killpg(driver.pid, signal.SIGKILL)
            driver.communicate(timeout=5)
        elapsed = time.monotonic() - start
        provider_dead = False
        if provider_pid is not None:
            try:
                os.kill(provider_pid, 0)
            except ProcessLookupError:
                provider_dead = True
        if provider_pid is not None and not provider_dead:
            try:
                os.killpg(provider_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        text = log.read_text(encoding="utf-8", errors="replace")
        check(f"S37 {route}: driver completed promptly",
              finished and elapsed < 10, f"finished={finished} elapsed={elapsed:.2f}")
        check(f"S37 {route}: interruption propagated (rc 130)",
              driver.returncode == 130 and "REVIEW_SIGINT_PROPAGATED" in out,
              f"rc={driver.returncode}")
        check(f"S37 {route}: owned child reaped", provider_dead, "")
        check(f"S37 {route}: log sanitized",
              marker not in text and "auth-store load error" in text, "")


def test_S38_owned_descendant_lifecycle_and_finalizer_interrupt():
    """Owned same-group descendants: SIGINT escalation reaps a SIGTERM-
    resistant tool, a stdout-retaining tool is cleaned after a normal
    leader exit, and an interruption during finalization still completes
    cleanup before propagating."""
    marker = _S30_MARKER
    scripts_dir = Path(__file__).resolve().parent
    worker_src = """
import json, os, pathlib, sys
case = pathlib.Path(sys.argv[1]); mode = sys.argv[2]
sys.path.insert(0, %r)
import plamen_driver as D
import test_codex_subscription_only as T
home = case / 'auth'
T._write_auth(home, {'auth_mode': 'chatgpt', 'tokens': T._tokens(access_token=%r)})
os.environ['CODEX_HOME'] = str(home)
os.environ['PLAMEN_PLAIN_OUTPUT'] = '1'
D.CODEX_BIN = str(case / 'fake_provider.py')
(case / 'prompt.txt').write_text('Synthetic prompt only.')
original_drain = D._drain_pipe_reader
def observe_drain(reader, stream):
    (case / 'drain_entered').write_text('entered')
    try:
        original_drain(reader, stream)
    except BaseException:
        raise
    (case / 'reader_state.json').write_text(json.dumps({
        'reader_alive_after_finalizer': reader is not None and reader.is_alive(),
        'stream_closed_after_finalizer': stream is None or stream.closed,
    }))
D._drain_pipe_reader = observe_drain
try:
    phase = next(p for p in D.SC_PHASES if p.name == 'recon')
    D.run_phase(phase, {'scratchpad': str(case/'scratch'),
                        'project_root': str(case/'project'),
                        'pipeline': 'sc', 'language': 'solidity',
                        'mode': 'light', 'cli_backend': 'codex'}, 1)
except KeyboardInterrupt:
    print('REVIEW_SIGINT_PROPAGATED', flush=True)
    sys.exit(130)
print('REVIEW_PHASE_COMPLETED', flush=True)
sys.exit(0)
""" % (str(scripts_dir), marker)
    tool_src = (
        "import json, os, pathlib, signal, sys, time\n"
        "if sys.argv[1] == 'resistant':\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "case = pathlib.Path(sys.argv[2])\n"
        "(case / 'descendant.json').write_text(json.dumps("
        "{'pid': os.getpid(), 'pgid': os.getpgrp()}))\n"
        "deadline = time.monotonic() + 120\n"
        "while time.monotonic() < deadline:\n"
        "    if (case / 'driver_returned').exists():\n"
        "        (case / 'scratch' / 'post_return_tool_write.txt').write_text('x')\n"
        "    time.sleep(0.02)\n"
    )
    cases = (
        ("resistant", "sigint_live_resistant_descendant"),
        ("linger", "normal_leader_exit_stdout_retained"),
        ("linger", "sigint_after_leader_exit_stdout_retained"),
    )
    for variant, scenario in cases:
        case = _mkfix(f"desc_{scenario}_{variant}")
        (case / "scratch").mkdir()
        (case / "project").mkdir()
        tool = case / "synthetic_tool.py"
        tool.write_text(tool_src, encoding="utf-8")
        provider = case / "fake_provider.py"
        provider.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, subprocess, sys, time\n"
            "case = pathlib.Path(%r)\n"
            "(case / 'provider.json').write_text(json.dumps("
            "{'pid': os.getpid(), 'pgid': os.getpgrp()}))\n"
            "subprocess.Popen([sys.executable, str(case / 'synthetic_tool.py'),"
            " %r, str(case)])\n"
            "deadline = time.monotonic() + 10\n"
            "while not (case / 'descendant.json').exists() and "
            "time.monotonic() < deadline:\n"
            "    time.sleep(0.01)\n"
            "print(%r, flush=True)\n"
            "%s\n" % (
                str(case), variant,
                'invalid type: string "%s", expected a boolean at line 1 column 94' % marker,
                "time.sleep(120)" if variant == "resistant" else "sys.exit(0)",
            ),
            encoding="utf-8",
        )
        provider.chmod(provider.stat().st_mode | stat.S_IXUSR)
        worker = case / "worker.py"
        worker.write_text(worker_src, encoding="utf-8")
        env = {**os.environ, "PLAMEN_HOME": str(scripts_dir.parent)}
        driver = subprocess.Popen(
            [sys.executable, str(worker), str(case), variant],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=env, start_new_session=True,
        )
        log = case / "scratch" / "_stdio_recon.attempt1.log"
        provider_pid = descendant_pid = pgid = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if (case / "provider.json").exists():
                meta = json.loads((case / "provider.json").read_text())
                provider_pid, pgid = meta["pid"], meta["pgid"]
            if (case / "descendant.json").exists():
                descendant_pid = json.loads(
                    (case / "descendant.json").read_text()
                )["pid"]
            if provider_pid and descendant_pid and log.exists() and log.stat().st_size:
                break
            time.sleep(0.02)
        check(f"S38 {scenario}: control ready",
              bool(provider_pid and descendant_pid), "")

        def _running(pid):
            try:
                stat_text = Path(f"/proc/{pid}/stat").read_text()
            except FileNotFoundError:
                return False
            return stat_text[stat_text.rfind(")") + 2:].split()[0] not in {"Z", "X"}

        start = time.monotonic()
        try:
            if "sigint_after" in scenario:
                wait_deadline = time.monotonic() + 5
                while time.monotonic() < wait_deadline and (
                    _running(provider_pid) or not (case / "drain_entered").exists()
                ):
                    time.sleep(0.02)
                os.kill(driver.pid, signal.SIGINT)
            elif variant == "resistant":
                os.kill(driver.pid, signal.SIGINT)
            out, _ = driver.communicate(timeout=15)
            finished = True
        except subprocess.TimeoutExpired:
            finished = False
            out = ""
            os.killpg(driver.pid, signal.SIGKILL)
            driver.communicate(timeout=5)
        elapsed = time.monotonic() - start
        tool_dead = descendant_pid is not None and not _running(descendant_pid)
        if not tool_dead and pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        post_write = (case / "scratch" / "post_return_tool_write.txt").exists()
        log_text = (
            log.read_text(encoding="utf-8", errors="replace")
            if log.exists() else ""
        )
        state_file = case / "reader_state.json"
        state = json.loads(state_file.read_text()) if state_file.exists() else None
        check(f"S38 {scenario}: driver completed promptly",
              finished and elapsed < 15, f"finished={finished} elapsed={elapsed:.2f}")
        check(f"S38 {scenario}: owned tool reaped before return", tool_dead, "")
        check(f"S38 {scenario}: no post-return scratch write", not post_write, "")
        check(f"S38 {scenario}: log sanitized",
              marker not in log_text and "auth-store load error" in log_text, "")
        if "sigint" in scenario:
            check(f"S38 {scenario}: interruption propagated (rc 130)",
                  driver.returncode == 130 and "REVIEW_SIGINT_PROPAGATED" in out,
                  f"rc={driver.returncode}")
        else:
            check(f"S38 {scenario}: normal completion rc 0",
                  driver.returncode == 0 and "REVIEW_PHASE_COMPLETED" in out,
                  f"rc={driver.returncode}")
        if state is not None:
            check(f"S38 {scenario}: reader finished",
                  not state["reader_alive_after_finalizer"], "")
            check(f"S38 {scenario}: stream closed",
                  state["stream_closed_after_finalizer"], "")


def test_S39_single_sigint_during_term_grace_finishes_cleanup():
    """One SIGINT during the TERM grace of owned-group cleanup must not
    abort shutdown: the bounded group completion still runs to the same
    deadline (KILL escalation included), the reader/pipe cleanup
    completes, and only then does the interruption propagate."""
    marker = _S30_MARKER
    scripts_dir = Path(__file__).resolve().parent
    worker_src = """
import json, os, pathlib, sys
case = pathlib.Path(sys.argv[1]); route = sys.argv[2]
sys.path.insert(0, %r)
import plamen_driver as D
import test_codex_subscription_only as T
home = case / 'auth'
T._write_auth(home, {'auth_mode': 'chatgpt', 'tokens': T._tokens(access_token=%r)})
os.environ['CODEX_HOME'] = str(home)
os.environ['PLAMEN_PLAIN_OUTPUT'] = '1'
D.CODEX_BIN = str(case / 'fake_provider.py')
(case / 'prompt.txt').write_text('Synthetic prompt only.')
original_drain = D._drain_pipe_reader
def observe_drain(reader, stream):
    (case / 'drain_entered').write_text('entered')
    try:
        original_drain(reader, stream)
    finally:
        (case / 'reader_state.json').write_text(json.dumps({
            'reader_alive_after_finalizer': reader is not None and reader.is_alive(),
            'stream_closed_after_finalizer': stream is None or stream.closed,
        }))
D._drain_pipe_reader = observe_drain
cfg = {'scratchpad': str(case/'scratch'), 'project_root': str(case/'project'),
       'pipeline': 'sc', 'language': 'solidity', 'mode': 'light',
       'cli_backend': 'codex', 'scope_file': '', 'docs_path': '', 'scope_notes': ''}
try:
    if route == 'phase':
        phase = next(p for p in D.SC_PHASES if p.name == 'recon')
        rc = D.run_phase(phase, cfg, 1)
        print('REVIEW_NORMAL_PHASE_RC=' + str(rc), flush=True)
    else:
        (case / 'scratch' / 'verification_queue.md').write_text(
            chr(10).join([
                '# Verification Queue',
                '',
                '| Finding ID | Severity | Title | Location | Preferred Tag |',
                '|------------|----------|-------|----------|---------------|',
                '| H-01 | High | Test finding | src/Vault.sol:L42 | [CODE-TRACE] |',
            ]) + chr(10), encoding='utf-8')
        missing = D.identify_missing_verify_ids(case / 'scratch')
        result = D._run_verify_recovery_shard(cfg, missing)
        print('REVIEW_RECOVERY_MISSING=' + json.dumps(result), flush=True)
except KeyboardInterrupt:
    print('REVIEW_SIGINT_PROPAGATED', flush=True)
    sys.exit(130)
sys.exit(0)
""" % (str(scripts_dir), marker)
    tool_src = (
        "import json, os, pathlib, signal, sys, time\n"
        "def term_handler(signum, frame):\n"
        "    pathlib.Path(sys.argv[3]).write_text('TERM received')\n"
        "signal.signal(signal.SIGTERM, term_handler)\n"
        "case = pathlib.Path(sys.argv[2])\n"
        "(case / 'descendant.json').write_text(json.dumps("
        "{'pid': os.getpid(), 'pgid': os.getpgrp()}))\n"
        "deadline = time.monotonic() + 120\n"
        "while time.monotonic() < deadline:\n"
        "    if (case / 'driver_returned').exists():\n"
        "        (case / 'scratch' / 'post_return_tool_write.txt').write_text('x')\n"
        "    time.sleep(0.02)\n"
    )
    for route in ("phase", "recovery"):
        case = _mkfix(f"termgrace_{route}")
        (case / "scratch").mkdir()
        (case / "project").mkdir()
        tool = case / "synthetic_tool.py"
        tool.write_text(tool_src, encoding="utf-8")
        provider = case / "fake_provider.py"
        provider.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, subprocess, sys, time\n"
            "case = pathlib.Path(%r)\n"
            "(case / 'provider.json').write_text(json.dumps("
            "{'pid': os.getpid(), 'pgid': os.getpgrp()}))\n"
            "subprocess.Popen([sys.executable, str(case / 'synthetic_tool.py'),"
            " 'resistant', str(case), %r])\n"
            "deadline = time.monotonic() + 10\n"
            "while not (case / 'descendant.json').exists() and "
            "time.monotonic() < deadline:\n"
            "    time.sleep(0.01)\n"
            "print(%r, flush=True)\n"
            "sys.exit(0)\n" % (
                str(case), str(case / "tool_term_received"),
                'invalid type: string "%s", expected a boolean at line 1 column 94' % marker,
            ),
            encoding="utf-8",
        )
        provider.chmod(provider.stat().st_mode | stat.S_IXUSR)
        worker = case / "worker.py"
        worker.write_text(worker_src, encoding="utf-8")
        env = {**os.environ, "PLAMEN_HOME": str(scripts_dir.parent)}
        driver = subprocess.Popen(
            [sys.executable, str(worker), str(case), route],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=env, start_new_session=True,
        )
        log = case / "scratch" / (
            "_stdio_recon.attempt1.log" if route == "phase"
            else "_stdio_verify_recovery.attempt1.log")
        provider_pid = descendant_pid = pgid = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if (case / "provider.json").exists():
                meta = json.loads((case / "provider.json").read_text())
                provider_pid, pgid = meta["pid"], meta["pgid"]
            if (case / "descendant.json").exists():
                descendant_pid = json.loads(
                    (case / "descendant.json").read_text()
                )["pid"]
            if provider_pid and descendant_pid and log.exists() and log.stat().st_size:
                break
            if driver.poll() is not None:
                _dbg_out, _ = driver.communicate()
                print("S39 worker died early:", driver.returncode, repr(_dbg_out[-1500:]))
                break
            time.sleep(0.02)
        check(f"S39 {route}: control ready",
              bool(provider_pid and descendant_pid), "")

        def _running(pid):
            try:
                stat_text = Path(f"/proc/{pid}/stat").read_text()
            except FileNotFoundError:
                return False
            return stat_text[stat_text.rfind(")") + 2:].split()[0] not in {"Z", "X"}

        term_wait = time.monotonic() + 8
        while not (case / "tool_term_received").exists() and time.monotonic() < term_wait:
            time.sleep(0.02)
        check(f"S39 {route}: TERM observed before single SIGINT",
              (case / "tool_term_received").exists(), "")
        start = time.monotonic()
        os.kill(driver.pid, signal.SIGINT)
        try:
            out, _ = driver.communicate(timeout=15)
            finished = True
        except subprocess.TimeoutExpired:
            finished = False
            out = ""
            os.killpg(driver.pid, signal.SIGKILL)
            driver.communicate(timeout=5)
        elapsed = time.monotonic() - start
        tool_dead = descendant_pid is not None and not _running(descendant_pid)
        if not tool_dead and pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        post_write = (case / "scratch" / "post_return_tool_write.txt").exists()
        log_text = (
            log.read_text(encoding="utf-8", errors="replace")
            if log.exists() else ""
        )
        state_file = case / "reader_state.json"
        state = json.loads(state_file.read_text()) if state_file.exists() else None
        check(f"S39 {route}: completed within 15s of the SIGINT",
              finished and elapsed < 15, f"finished={finished} elapsed={elapsed:.2f}")
        check(f"S39 {route}: interruption propagated (rc 130)",
              driver.returncode == 130 and "REVIEW_SIGINT_PROPAGATED" in out,
              f"rc={driver.returncode}")
        check(f"S39 {route}: owned writer reaped at return", tool_dead, "")
        check(f"S39 {route}: no post-return scratch write", not post_write, "")
        check(f"S39 {route}: log sanitized",
              marker not in log_text and "auth-store load error" in log_text, "")
        check(f"S39 {route}: reader finished and stream closed",
              state is not None and not state["reader_alive_after_finalizer"]
              and state["stream_closed_after_finalizer"], str(state))


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
        test_S11_legacy_oauth_records_without_mode_are_accepted,
        test_S12_structural_and_api_negatives_rejected,
        test_S13_stale_but_structured_sessions_are_accepted,
        test_S14_auth_error_detector_classifies_structure_failures,
        test_S15_recovery_codex_launch_sc_and_l1,
        test_S16_recovery_codex_missing_oauth_fails_clearly_without_spawn,
        test_S17_recovery_codex_model_rejection_retries_without_model,
        test_S18_recovery_codex_auth_error_is_permanent_no_retry,
        test_S19_recovery_claude_backend_preserved,
        test_S20_codex_prompt_translation_requires_methodology_alias,
        test_S21_recovery_codex_alias_missing_fails_clearly_without_spawn,
        test_S22_native_key_field_resolution_parity,
        test_S23_strict_native_payload_decoding,
        test_S24_typed_token_field_parity,
        test_S25_native_load_failure_classification,
        test_S26_api_mode_record_refused_before_launch,
        test_S27_native_claim_type_parity,
        test_S28_native_timestamp_parity,
        test_S29_cli_signal_scoped_classification,
        test_S30_value_bearing_auth_diagnostics_scrubbed_from_logs,
        test_S31_duplicate_key_and_known_field_strictness,
        test_S32_quoted_quota_text_scoping,
        test_S33_auth_values_never_persisted_before_cleanup,
        test_S34_native_duplicate_known_fields_refused,
        test_S35_non_json_constants_refused,
        test_S36_remaining_native_load_error_families_classify,
        test_S37_cancellation_reaps_child_and_completes_quickly,
        test_S38_owned_descendant_lifecycle_and_finalizer_interrupt,
        test_S39_single_sigint_during_term_grace_finishes_cleanup,
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
