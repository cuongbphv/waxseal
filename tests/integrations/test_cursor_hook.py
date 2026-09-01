"""Tests for the Cursor hook (integrations/cursor/hook.py).

Contract verified against https://cursor.com/docs/hooks (2026-08-21):

- hooks.json (project .cursor/hooks.json or ~/.cursor/hooks.json) maps event
  names to commands; the hook receives ONE JSON event on stdin and answers
  on stdout. Common fields: conversation_id, generation_id, model,
  hook_event_name, workspace_roots, transcript_path.
- Exit code 2 BLOCKS the action (= permission deny). Empty stdout on exit 0
  is treated as {} → allow. before* events parse stdout for
  permission/continue decisions — an audit observer must exit 0 and stay
  SILENT on stdout so it can never veto or override another hook's decision.
- Event payloads: beforeShellExecution {command, cwd}; afterShellExecution
  {command, output, duration}; beforeMCPExecution {tool_name, tool_input};
  afterFileEdit {file_path, edits: [{old_string, new_string}]};
  beforeSubmitPrompt {prompt, attachments}; stop {status}.

The script is exercised exactly as Cursor runs it: a subprocess with the
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

HOOK_PATH = Path(__file__).parent.parent.parent / "src" / "waxseal" / "integrations" / "cursor.py"
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
        input=stdin, capture_output=True, text=True, env=env, timeout=30,
    )


def shell_event(**overrides: object) -> dict[str, Any]:
    event: dict[str, Any] = {
        "conversation_id": "conv-1",
        "generation_id": "gen-1",
        "model": "some-model",
        "hook_event_name": "beforeShellExecution",
        "workspace_roots": ["/work/project"],
        "command": "ls -la",
        "cwd": "/work/project",
    }
    event.update(overrides)
    return event


def read_payload(trail: Path, line_no: int = 0) -> dict[str, Any]:
    line = trail.read_text().splitlines()[line_no]
    result: dict[str, Any] = json.loads(
        base64.b64decode(json.loads(line)["payload_b64"])
    )
    return result


class TestObserveOnly:
    def test_exit_zero_and_silent_stdout(self, tmp_path: Path) -> None:
        # before* events parse stdout as a permission decision; anything the
        # audit hook printed could veto or override real policy hooks.
        proc = run_hook(shell_event(), tmp_path / "trail.jsonl")
        assert proc.returncode == 0
        assert proc.stdout == ""

    def test_appends_one_verified_entry(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(shell_event(), trail)
        result = AuditLog.open(trail).verify(measure_drops=False)
        assert result.ok
        assert result.checked == 1

    def test_action_fields_land_in_the_payload(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(shell_event(), trail)
        payload = read_payload(trail)
        assert payload["event"] == "beforeShellExecution"
        assert payload["command"] == "ls -la"
        assert payload["cwd"] == "/work/project"
        assert payload["conversation_id"] == "conv-1"


class TestEventCoverage:
    def test_after_shell_records_output_and_duration(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(
            shell_event(hook_event_name="afterShellExecution", output="total 0", duration=42),
            trail,
        )
        payload = read_payload(trail)
        assert payload["event"] == "afterShellExecution"
        assert payload["output"] == "total 0"
        assert payload["duration"] == 42

    def test_file_edit_records_path_and_edits(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(
            {
                "conversation_id": "conv-1",
                "hook_event_name": "afterFileEdit",
                "file_path": "/work/project/app.py",
                "edits": [{"old_string": "a = 1", "new_string": "a = 2"}],
            },
            trail,
        )
        payload = read_payload(trail)
        assert payload["file_path"] == "/work/project/app.py"
        assert payload["edits"][0]["new_string"] == "a = 2"

    def test_mcp_execution_records_tool_fields(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(
            {
                "conversation_id": "conv-1",
                "hook_event_name": "beforeMCPExecution",
                "tool_name": "search",
                "tool_input": "{\"q\": \"docs\"}",
            },
            trail,
        )
        payload = read_payload(trail)
        assert payload["tool_name"] == "search"


class TestRedaction:
    def test_secret_in_command_never_reaches_disk(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        secret = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
        run_hook(shell_event(command=f"git push https://{secret}@github.example/r"), trail)
        assert secret.encode() not in trail.read_bytes()
        assert AuditLog.open(trail).verify(measure_drops=False).ok

    def test_secret_written_into_a_file_edit_never_reaches_disk(self, tmp_path: Path) -> None:
        # The incident class this repo exists for: the agent writes a key
        # into a file; the edit diff carries the cleartext.
        trail = tmp_path / "trail.jsonl"
        secret = "sk-abcdef1234567890abcdef"
        run_hook(
            {
                "conversation_id": "conv-1",
                "hook_event_name": "afterFileEdit",
                "file_path": "/work/.env",
                "edits": [{"old_string": "", "new_string": f"OPENAI_API_KEY={secret}"}],
            },
            trail,
        )
        assert secret.encode() not in trail.read_bytes()

    def test_secret_in_prompt_never_reaches_disk(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        # Literal split: GitHub push protection blocks the contiguous glpat- fixture.
        secret = "glpat-" + "Xk2fjPq81mNbV4wZs7Ay"
        proc = run_hook(
            {
                "conversation_id": "conv-1",
                "hook_event_name": "beforeSubmitPrompt",
                "prompt": f"deploy with token {secret} please",
            },
            trail,
        )
        assert proc.stdout == ""  # a printed 'continue' decision could block prompts
        assert secret.encode() not in trail.read_bytes()
        assert "please" in read_payload(trail)["prompt"]


class TestNeverBlocks:
    def test_garbage_stdin_still_exits_zero(self, tmp_path: Path) -> None:
        proc = run_hook("not json{{", tmp_path / "trail.jsonl")
        assert proc.returncode == 0
        assert proc.stdout == ""

    def test_broken_trail_path_exits_zero_with_labelled_drop(self, tmp_path: Path) -> None:
        # Exit 2 = deny: a broken audit disk must degrade to a stderr notice,
        # never a veto over the user's shell command.
        blocked = tmp_path / "blocked"
        blocked.write_text("a file where the trail dir should be")
        proc = run_hook(shell_event(), blocked / "trail.jsonl")
        assert proc.returncode == 0
        assert proc.stdout == ""
        assert "dropped" in proc.stderr

    def test_huge_output_is_clipped_with_visible_marker(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        run_hook(
            shell_event(hook_event_name="afterShellExecution", output="y" * 1_000_000),
            trail,
        )
        assert len(trail.read_bytes()) < 100_000
        assert "truncated" in read_payload(trail)["output"]


class TestDefaultTrailLocation:
    def test_defaults_under_cursor_home(self, tmp_path: Path) -> None:
        proc = subprocess.run(
            [sys.executable, str(HOOK_PATH)],
            input=json.dumps(shell_event()),
            capture_output=True, text=True, timeout=30,
            env=_spawn_env(HOME=str(tmp_path)),
        )
        assert proc.returncode == 0
        from waxseal.domain.segments import project_slug

        trail = (
            tmp_path / ".cursor" / "waxseal" / "trails"
            / project_slug(shell_event()["cwd"]) / "trail.00000.jsonl"
        )
        assert AuditLog.open(trail).verify(measure_drops=False).checked == 1
