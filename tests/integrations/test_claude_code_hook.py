"""Tests for the Claude Code hook (integrations/claude-code/hook.py).

Contract verified against https://code.claude.com/docs/en/hooks.md (2026-08):

- The hook is a command receiving ONE JSON event on stdin. Common fields:
  session_id, transcript_path, cwd, permission_mode, hook_event_name,
  tool_use_id; PreToolUse adds tool_name + tool_input, PostToolUse adds
  tool_output (older releases: tool_response), UserPromptSubmit adds prompt.
- Exit 2 BLOCKS (PreToolUse: the tool call; UserPromptSubmit: the prompt).
  An audit observer must exit 0 on every path, including its own failures.
- On UserPromptSubmit, stdout of an exit-0 hook is INJECTED INTO MODEL
  CONTEXT. An audit hook must therefore never write to stdout — diagnostics
  go to stderr (visible, exit 0 = non-blocking notice).

The script is exercised exactly as Claude Code runs it: a subprocess with
the event on stdin.
"""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from waxseal import AuditLog

HOOK_PATH = (
    Path(__file__).parent.parent.parent / "src" / "waxseal" / "integrations" / "claude_code.py"
)
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
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/work/project",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la", "description": "List files"},
        "tool_use_id": "toolu_01",
    }
    event.update(overrides)
    return event


def read_payload(trail: Path, line_no: int = 0) -> dict[str, Any]:
    line = trail.read_text(encoding="utf-8").splitlines()[line_no]
    result: dict[str, Any] = json.loads(base64.b64decode(json.loads(line)["payload_b64"]))
    return result


class TestObserveOnly:
    def test_exit_zero_and_silent_stdout_on_success(self, tmp_path: Path) -> None:
        # stdout is injected into model context on UserPromptSubmit and parsed
        # for decision JSON elsewhere — an audit hook must never speak there.
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
        assert payload["tool_name"] == "Bash"
        assert payload["tool_input"]["command"] == "ls -la"
        assert payload["session_id"] == "sess-1"
        assert payload["tool_use_id"] == "toolu_01"
        assert payload["cwd"] == "/work/project"


class TestPostToolUse:
    def test_tool_output_is_recorded(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(
            pre_tool_use(hook_event_name="PostToolUse", tool_output="total 0\n"),
            trail,
        )
        payload = read_payload(trail)
        assert payload["event"] == "PostToolUse"
        assert payload["tool_output"] == "total 0\n"

    def test_legacy_tool_response_field_is_recorded(self, tmp_path: Path) -> None:
        # Older Claude Code releases named the field tool_response; record it
        # under the same key so trails stay uniform across versions.
        trail = tmp_path / "trail.jsonl"
        run_hook(
            pre_tool_use(hook_event_name="PostToolUse", tool_response={"stdout": "ok"}),
            trail,
        )
        assert read_payload(trail)["tool_output"] == {"stdout": "ok"}

    def test_huge_output_is_clipped_with_visible_marker(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(
            pre_tool_use(hook_event_name="PostToolUse", tool_output="y" * 1_000_000),
            trail,
        )
        assert len(trail.read_bytes()) < 100_000
        assert "truncated" in read_payload(trail)["tool_output"]
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
        # The original incident class: a key pasted into the chat itself.
        trail = tmp_path / "trail.jsonl"
        secret = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
        proc = run_hook(
            {
                "session_id": "sess-1",
                "hook_event_name": "UserPromptSubmit",
                "cwd": "/work",
                "prompt": f"my github token is {secret}, please fix CI",
            },
            trail,
        )
        assert proc.stdout == ""  # exit-0 stdout would be injected into context
        assert secret.encode() not in trail.read_bytes()
        payload = read_payload(trail)
        assert payload["event"] == "UserPromptSubmit"
        assert "please fix CI" in payload["prompt"]


class TestNeverBlocks:
    def test_garbage_stdin_still_exits_zero(self, tmp_path: Path) -> None:
        proc = run_hook("this is not json{{", tmp_path / "trail.jsonl")
        assert proc.returncode == 0
        assert proc.stdout == ""

    def test_broken_trail_path_exits_zero_with_labelled_drop(self, tmp_path: Path) -> None:
        # Exit 2 would BLOCK the tool call / prompt; a broken audit disk must
        # degrade to a visible stderr notice, never a veto.
        blocked = tmp_path / "blocked"
        blocked.write_text("a file where the trail dir should be", encoding="utf-8")
        proc = run_hook(pre_tool_use(), blocked / "trail.jsonl")
        assert proc.returncode == 0
        assert proc.stdout == ""
        assert "dropped" in proc.stderr


class TestDefaultTrailLocation:
    def test_defaults_under_claude_home(self, tmp_path: Path) -> None:
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
        # 0.1.5: the default is routed per project (the event's cwd), so the
        # host directory rung is unchanged but a slug directory sits under it.
        from waxseal.domain.segments import project_slug

        trail = (
            tmp_path
            / ".claude"
            / "waxseal"
            / "trails"
            / project_slug("/work/project")
            / "trail.00000.jsonl"
        )
        assert AuditLog.open(trail).verify(measure_drops=False).checked == 1
