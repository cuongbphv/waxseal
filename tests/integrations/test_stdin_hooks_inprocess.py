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
    # Honest limit (adapters/drops.py's own docstring): the SAME broken
    # directory that blocks the trail also blocks the .drops sidecar next to
    # it — a disk too broken to hold a write cannot bear witness to its own
    # failure either. FileDropRecorder swallows that, it does not fake it.
    assert not (blocker / "trail.jsonl.drops").exists()


def test_open_failure_still_leaves_a_drop_record(
    monkeypatch, hook, tmp_path: Path, capsys
) -> None:
    # Unlike the blocker-file case above, the trail's OWN directory is
    # writable here — only AuditLog.open() itself fails (e.g. a corrupt
    # backend) — so the sidecar write in the except-branch can and must
    # succeed (M5: every failure path stays silent on stdout AND leaves a
    # measurable drop record).
    monkeypatch.setattr(
        AuditLog, "open", staticmethod(lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("x")))
    )
    trail = tmp_path / "trail.jsonl"
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}}
    assert run_main(monkeypatch, hook, json.dumps(event), trail) == 0
    assert capsys.readouterr().out == ""

    drops = trail.parent / (trail.name + ".drops")
    assert drops.exists()
    assert len(drops.read_text().splitlines()) == 1
