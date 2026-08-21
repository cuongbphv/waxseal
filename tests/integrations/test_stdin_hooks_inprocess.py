"""In-process runs of the stdin hook mains (claude_code / codex / cursor).

The sibling test files exercise these hooks the way the hosts do — a
subprocess per event — which is the honest contract test but invisible to
coverage (pytest-cov does not instrument subprocesses here). These tests
drive the same main() in-process so the measured suite actually covers the
shipped hook logic; assertions mirror the subprocess files.
"""

from __future__ import annotations

import importlib
import io
import json
import sys
from pathlib import Path

import pytest

from waxseal import AuditLog

MODULES = [
    "waxseal.integrations.claude_code",
    "waxseal.integrations.codex",
    "waxseal.integrations.cursor",
]


@pytest.fixture(params=MODULES)
def hook(request):
    return importlib.import_module(request.param)


def run_main(monkeypatch, hook, stdin_text: str, trail: Path) -> int:
    monkeypatch.setenv("WAXSEAL_TRAIL", str(trail))
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))
    return hook.main()


def test_event_is_appended_and_verifies(monkeypatch, hook, tmp_path: Path, capsys) -> None:
    trail = tmp_path / "trail.jsonl"
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": "ls"}}
    assert run_main(monkeypatch, hook, json.dumps(event), trail) == 0
    # stdout is parsed by the hosts as decision JSON — must stay empty.
    assert capsys.readouterr().out == ""
    result = AuditLog.open(trail).verify(measure_drops=False)
    assert result.ok
    assert result.checked == 1


def test_secret_is_redacted_before_disk(monkeypatch, hook, tmp_path: Path) -> None:
    trail = tmp_path / "trail.jsonl"
    secret = "sk-abcdef1234567890abcdef"
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": f"export KEY={secret}"}}
    run_main(monkeypatch, hook, json.dumps(event), trail)
    assert secret.encode() not in trail.read_bytes()


def test_malformed_stdin_exits_zero_with_labelled_drop(
    monkeypatch, hook, tmp_path: Path, capsys
) -> None:
    # Nonzero would veto the user's tool call or prompt on some hosts.
    assert run_main(monkeypatch, hook, "not json {", tmp_path / "trail.jsonl") == 0
    err = capsys.readouterr().err
    assert "dropped" in err


def test_unopenable_trail_exits_zero_with_labelled_drop(
    monkeypatch, hook, tmp_path: Path, capsys
) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where the trail dir should be")
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}}
    assert run_main(monkeypatch, hook, json.dumps(event), blocker / "trail.jsonl") == 0
    assert "dropped" in capsys.readouterr().err
