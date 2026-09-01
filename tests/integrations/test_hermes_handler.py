"""Tests for the hermes-agent hook handler (integrations/hermes/handler.py).

The handler is loaded the same way hermes-agent's HookRegistry loads it
(importlib from file path), so these tests exercise the exact artifact that
ships. The hermes contract: handle(event_type, context) sync, errors must
never propagate into the agent pipeline.
"""

import importlib.util
import json
import sys
import types
from collections.abc import Iterator
from pathlib import Path

import pytest

from waxseal import AuditLog


@pytest.fixture()
def handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[types.ModuleType]:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    name = "waxseal.integrations.hermes_gateway"
    sys.modules.pop(name, None)
    module = importlib.import_module(name)
    yield module
    sys.modules.pop(name, None)


def trail_path(tmp_path: Path) -> Path:
    return tmp_path / "hermes-home" / "audit" / "trail.jsonl"


class TestAppend:
    def test_event_is_appended_to_the_trail(self, handler: types.ModuleType, tmp_path: Path) -> None:
        handler.handle("agent:start", {"session_id": "s1", "message": "hello"})
        log = AuditLog.open(trail_path(tmp_path))
        result = log.verify(measure_drops=False)
        assert result.ok
        assert result.checked == 1

    def test_event_type_and_context_land_in_the_payload(
        self, handler: types.ModuleType, tmp_path: Path
    ) -> None:
        handler.handle("agent:end", {"session_id": "s1", "response": "done"})
        line = trail_path(tmp_path).read_text().splitlines()[0]
        import base64

        payload = json.loads(base64.b64decode(json.loads(line)["payload_b64"]))
        assert payload["event"] == "agent:end"
        assert payload["session_id"] == "s1"
        assert payload["response"] == "done"

    def test_multiple_events_form_one_verified_chain(self, handler: types.ModuleType, tmp_path: Path) -> None:
        for event in ("session:start", "agent:start", "agent:step", "agent:end"):
            handler.handle(event, {"session_id": "s1"})
        assert AuditLog.open(trail_path(tmp_path)).verify(measure_drops=False).checked == 4


class TestRedaction:
    def test_secret_in_message_never_reaches_disk(self, handler: types.ModuleType, tmp_path: Path) -> None:
        # Issue #487's stated risk: "Tool call args may contain secrets".
        handler.handle(
            "agent:step",
            {"session_id": "s1", "message": "run: export OPENAI_KEY=sk-abcdef1234567890abcdef"},
        )
        raw = trail_path(tmp_path).read_bytes()
        assert b"sk-abcdef1234567890abcdef" not in raw
        assert AuditLog.open(trail_path(tmp_path)).verify(measure_drops=False).ok


class TestNeverBlocksThePipeline:
    def test_unserializable_context_values_are_sanitized_not_fatal(
        self, handler: types.ModuleType, tmp_path: Path
    ) -> None:
        handler.handle("agent:step", {"session_id": "s1", "weird": object(), "n": 1})
        result = AuditLog.open(trail_path(tmp_path)).verify(measure_drops=False)
        assert result.ok
        assert result.checked == 1

    def test_none_context_is_fine(self, handler: types.ModuleType, tmp_path: Path) -> None:
        handler.handle("gateway:startup", None)
        assert AuditLog.open(trail_path(tmp_path)).verify(measure_drops=False).checked == 1

    def test_handle_never_raises_even_if_trail_dir_is_a_file(
        self, handler: types.ModuleType, tmp_path: Path
    ) -> None:
        # Hermes contract: hook errors are logged, never raised. Simulate a
        # broken environment: the audit dir path is occupied by a file.
        home = tmp_path / "hermes-home"
        home.mkdir(parents=True)
        (home / "audit").write_text("not a directory")
        handler.handle("agent:start", {"session_id": "s1"})  # must not raise
