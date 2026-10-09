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
