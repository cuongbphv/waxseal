"""The stdin -> parse -> sanitize -> append -> fail-open loop, shared.

`claude_code`, `codex` and `cursor` used to carry one copy each of this loop,
identical in code and already drifting in their comments. The hosts keep what
differs (payload type, field map, trail resolution, Claude Code's chain-server
branch); `_stdin_hook.run_stdin_hook` owns what does not. The in-process hook
tests pin each host's observable behaviour; these pin the seam itself.
"""

from __future__ import annotations

import importlib
import io
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from waxseal import AuditLog
from waxseal.integrations import _stdin_hook
from waxseal.sources.rotation import DEFAULT_MAX_SEGMENT_BYTES

HOSTS = [
    "waxseal.integrations.claude_code",
    "waxseal.integrations.codex",
    "waxseal.integrations.cursor",
]

EVENT = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}


def _feed(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))


def _echo(event: dict[str, Any]) -> dict[str, Any]:
    return {"event": event.get("hook_event_name")}


@pytest.mark.parametrize("name", HOSTS)
def test_every_stdin_host_routes_through_the_shared_loop(name: str) -> None:
    host: types.ModuleType = importlib.import_module(name)
    assert host.run_stdin_hook is _stdin_hook.run_stdin_hook


def test_a_local_target_is_appended_through_the_segmented_writer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    trail = tmp_path / "trail.jsonl"
    _feed(monkeypatch, json.dumps(EVENT))
    code = _stdin_hook.run_stdin_hook(
        payload_type="application/vnd.test.hook-event+json",
        build_payload=_echo,
        resolve_target=lambda _event: trail,
        max_segment_bytes=DEFAULT_MAX_SEGMENT_BYTES,
    )
    assert code == 0
    assert capsys.readouterr().out == ""
    result = AuditLog.open(trail).verify(measure_drops=False)
    assert result.ok
    assert result.checked == 1


def test_a_dropped_write_is_labelled_on_stderr_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Rule 6: the loss is visible, never silent, and never a veto.
    monkeypatch.setattr(AuditLog, "try_append", lambda self, **kw: False)
    _feed(monkeypatch, json.dumps(EVENT))
    code = _stdin_hook.run_stdin_hook(
        payload_type="application/vnd.test.hook-event+json",
        build_payload=_echo,
        resolve_target=lambda _event: tmp_path / "trail.jsonl",
        max_segment_bytes=DEFAULT_MAX_SEGMENT_BYTES,
    )
    assert code == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "dropped write for 'PreToolUse'" in captured.err


def test_a_url_target_uses_the_hosts_remote_opener(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The remote branch belongs to the host that resolves URLs (Claude Code):
    # the loop only hands the target and the event over, so a chain id derived
    # from the event still reaches the opener.
    seen: list[tuple[str, dict[str, Any]]] = []
    local = AuditLog.open(tmp_path / "stand-in.jsonl")

    def opener(target: str, event: dict[str, Any]) -> AuditLog:
        seen.append((target, event))
        return local

    _feed(monkeypatch, json.dumps(EVENT))
    code = _stdin_hook.run_stdin_hook(
        payload_type="application/vnd.test.hook-event+json",
        build_payload=_echo,
        resolve_target=lambda _event: "http://127.0.0.1:9/",
        max_segment_bytes=DEFAULT_MAX_SEGMENT_BYTES,
        open_remote=opener,
    )
    assert code == 0
    assert capsys.readouterr().out == ""
    assert seen == [("http://127.0.0.1:9/", EVENT)]
    assert local.verify(measure_drops=False).checked == 1


def test_a_url_target_with_no_remote_opener_is_a_labelled_drop_not_a_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A host that resolves a URL without saying how to open one is a host bug,
    # and a host bug is still not a veto over the user's work: exit 0, the loss
    # on stderr, and no sidecar invented for a target that has no next-to.
    monkeypatch.chdir(tmp_path)
    _feed(monkeypatch, json.dumps(EVENT))
    code = _stdin_hook.run_stdin_hook(
        payload_type="application/vnd.test.hook-event+json",
        build_payload=_echo,
        resolve_target=lambda _event: "http://127.0.0.1:9/",
        max_segment_bytes=DEFAULT_MAX_SEGMENT_BYTES,
    )
    assert code == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "cannot open trail (entry dropped)" in captured.err
    assert not list(tmp_path.iterdir())
