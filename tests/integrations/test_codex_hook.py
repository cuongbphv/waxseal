"""Tests for the Codex CLI hook (integrations/codex/hook.py).

Contract verified against openai/codex source, rust-v0.149.0 (2026-08-21):

- Lifecycle hooks configured in ~/.codex/hooks.json or config.toml
  [[hooks.PreToolUse]] tables; events include PreToolUse, PostToolUse,
  UserPromptSubmit, SessionStart/End, Stop.
- The hook receives ONE JSON object on STDIN (never argv — that is the
  legacy `notify` mechanism, which is turn-level only). snake_case fields:
  session_id, turn_id, cwd, hook_event_name, model, permission_mode,
  tool_name, tool_input, tool_use_id; PostToolUse adds tool_response.
- Hook stdout is parsed as camelCase decision JSON (`decision`,
  `continue`, `updatedInput`); exit code 2 blocks the tool call. An audit
  observer must exit 0 with empty stdout on every path.

The script is exercised exactly as codex runs it: a subprocess with the
event on stdin.
"""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from waxseal import AuditLog

HOOK_PATH = Path(__file__).parent.parent.parent / "src" / "waxseal" / "integrations" / "codex.py"
SRC = str(Path(__file__).parent.parent.parent / "src")


def _spawn_env(**overrides: str) -> dict[str, str]:
    """A scrubbed env that can still start CPython on Windows.

    SYSTEMROOT is how the CRT and OpenSSL find the OS (CryptGenRandom lives
    under it); without it a spawned python.exe can fail interpreter-side
    initialization in ways that look like library bugs — the 0.1.5 MR saw
    SSLError 0xa080024 on windows/3.14 the moment an import chain touched
    an SSL context. Passing it through is not a hole in the scrub: the vars
    under test (HOME and friends) stay fully controlled by `overrides`.
    """
    base = {"PYTHONPATH": SRC}
    if "SYSTEMROOT" in os.environ:  # POSIX has no such var; Windows needs it
        base["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    base.update(overrides)
    return base


def run_hook(
    event: dict[str, Any] | str, trail: Path, **env_overrides: str
) -> subprocess.CompletedProcess[str]:
    import os

    env = {**os.environ, "PYTHONPATH": SRC, "WAXSEAL_TRAIL": str(trail), **env_overrides}
    stdin = event if isinstance(event, str) else json.dumps(event)
    return subprocess.run(
        [sys.executable, str(HOOK_PATH)],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        encoding="utf-8",
    )


def pre_tool_use(**overrides: object) -> dict[str, Any]:
    event: dict[str, Any] = {
        "session_id": "sess-1",
        "turn_id": "turn-1",
        "transcript_path": None,
        "cwd": "/work/project",
        "hook_event_name": "PreToolUse",
        "model": "some-model",
        "permission_mode": "default",
        "tool_name": "shell",
        "tool_input": {"command": "ls -la"},
        "tool_use_id": "call-1",
    }
    event.update(overrides)
    return event


def read_payload(trail: Path, line_no: int = 0) -> dict[str, Any]:
    line = trail.read_text(encoding="utf-8").splitlines()[line_no]
    result: dict[str, Any] = json.loads(base64.b64decode(json.loads(line)["payload_b64"]))
    return result


class TestObserveOnly:
    def test_exit_zero_and_silent_stdout(self, tmp_path: Path) -> None:
        # stdout is parsed as decision JSON (approve/block/updatedInput) —
        # an audit hook must never speak there.
        proc = run_hook(pre_tool_use(), tmp_path / "trail.jsonl")
        assert proc.returncode == 0
        assert proc.stdout == ""

    def test_appends_one_verified_entry(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(pre_tool_use(), trail)
        result = AuditLog.open(trail).verify(measure_drops=False)
        assert result.ok
        assert result.checked == 1

    def test_action_fields_land_in_the_payload(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(pre_tool_use(), trail)
        payload = read_payload(trail)
        assert payload["event"] == "PreToolUse"
        assert payload["tool_name"] == "shell"
        assert payload["tool_input"]["command"] == "ls -la"
        assert payload["session_id"] == "sess-1"
        assert payload["turn_id"] == "turn-1"
        assert payload["tool_use_id"] == "call-1"


class TestPostToolUse:
    def test_tool_response_is_recorded(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(
            pre_tool_use(hook_event_name="PostToolUse", tool_response={"output": "total 0"}),
            trail,
        )
        payload = read_payload(trail)
        assert payload["event"] == "PostToolUse"
        assert payload["tool_response"] == {"output": "total 0"}

    def test_huge_response_is_clipped_with_visible_marker(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(
            pre_tool_use(hook_event_name="PostToolUse", tool_response="y" * 1_000_000),
            trail,
        )
        assert len(trail.read_bytes()) < 100_000
        assert "truncated" in read_payload(trail)["tool_response"]
        assert AuditLog.open(trail).verify(measure_drops=False).ok


class TestRedaction:
    def test_secret_in_tool_input_never_reaches_disk(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        secret = "sk-abcdef1234567890abcdef"
        run_hook(
            pre_tool_use(tool_input={"command": f"export OPENAI_API_KEY={secret}"}),
            trail,
        )
        assert secret.encode() not in trail.read_bytes()
        assert AuditLog.open(trail).verify(measure_drops=False).ok

    def test_secret_in_user_prompt_never_reaches_disk(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        secret = "npm_Xk2fjPq81mNbV4wZs7AyQm3RtU8vLc5dEn"
        run_hook(
            {
                "session_id": "sess-1",
                "hook_event_name": "UserPromptSubmit",
                "cwd": "/work",
                "prompt": f"publish with {secret} now",
            },
            trail,
        )
        assert secret.encode() not in trail.read_bytes()
        assert "now" in read_payload(trail)["prompt"]


class TestNeverBlocks:
    def test_garbage_stdin_still_exits_zero(self, tmp_path: Path) -> None:
        proc = run_hook("not json{{", tmp_path / "trail.jsonl")
        assert proc.returncode == 0
        assert proc.stdout == ""

    def test_broken_trail_path_exits_zero_with_labelled_drop(self, tmp_path: Path) -> None:
        # Exit 2 blocks the tool call: a broken audit disk must degrade to a
        # stderr notice, never a veto.
        blocked = tmp_path / "blocked"
        blocked.write_text("a file where the trail dir should be", encoding="utf-8")
        proc = run_hook(pre_tool_use(), blocked / "trail.jsonl")
        assert proc.returncode == 0
        assert proc.stdout == ""
        assert "dropped" in proc.stderr


class TestDefaultTrailLocation:
    def test_defaults_under_codex_home(self, tmp_path: Path) -> None:
        proc = subprocess.run(
            [sys.executable, str(HOOK_PATH)],
            input=json.dumps(pre_tool_use()),
            capture_output=True,
            text=True,
            timeout=30,
            env=_spawn_env(HOME=str(tmp_path)),
            encoding="utf-8",
        )
        assert proc.returncode == 0
        from waxseal.domain.segments import project_slug

        trail = (
            tmp_path
            / ".codex"
            / "waxseal"
            / "trails"
            / project_slug(pre_tool_use()["cwd"])
            / "trail.00000.jsonl"
        )
        assert AuditLog.open(trail).verify(measure_drops=False).checked == 1

    def test_codex_home_env_is_respected(self, tmp_path: Path) -> None:
        # codex resolves its home via CODEX_HOME; the trail should follow it.
        proc = subprocess.run(
            [sys.executable, str(HOOK_PATH)],
            input=json.dumps(pre_tool_use()),
            capture_output=True,
            text=True,
            timeout=30,
            env=_spawn_env(HOME=str(tmp_path), CODEX_HOME=str(tmp_path / "cx")),
            encoding="utf-8",
        )
        assert proc.returncode == 0
        from waxseal.domain.segments import project_slug

        trail = (
            tmp_path
            / "cx"
            / "waxseal"
            / "trails"
            / project_slug(pre_tool_use()["cwd"])
            / "trail.00000.jsonl"
        )
        assert AuditLog.open(trail).verify(measure_drops=False).checked == 1
