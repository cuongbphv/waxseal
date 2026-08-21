"""Tests for the LangChain callback handler (integrations/langchain/handler.py).

Contract verified against langchain-core 1.6.0 (installed source, 2026-08-21):

- BaseCallbackHandler is importable from langchain_core.callbacks; handlers
  attach via invoke(..., config={"callbacks": [handler]}) and inherit down to
  tool runs.
- Keyword-only params: on_tool_start(serialized, input_str, *, run_id,
  parent_run_id=None, tags=None, metadata=None, inputs=None, **kwargs);
  on_tool_end(output: Any, *, run_id, parent_run_id=None, **kwargs);
  on_tool_error(error: BaseException, *, run_id, ...). run_id is uuid.UUID.
- handle_event catches and logs handler exceptions unless raise_error is
  True. The audit handler keeps raise_error = False (fail-open) but labels
  and counts every dropped write itself — LangChain's swallow-and-log is
  silent at the trail level, which rule 6 forbids.

langchain_core is NOT a test dependency: the module under test only needs
the BaseCallbackHandler *name*, so a stub is injected into sys.modules —
the signatures exercised below are the verified 1.6.0 ones.
"""

import base64
import importlib.util
import json
import sys
import uuid
from pathlib import Path

import pytest

from waxseal import AuditLog


class _StubBaseCallbackHandler:
    raise_error: bool = False
    run_inline: bool = False


@pytest.fixture()
def handler_module(monkeypatch: pytest.MonkeyPatch):
    import types

    pkg = types.ModuleType("langchain_core")
    callbacks = types.ModuleType("langchain_core.callbacks")
    callbacks.BaseCallbackHandler = _StubBaseCallbackHandler
    pkg.callbacks = callbacks
    monkeypatch.setitem(sys.modules, "langchain_core", pkg)
    monkeypatch.setitem(sys.modules, "langchain_core.callbacks", callbacks)

    name = "waxseal.integrations.langchain"
    sys.modules.pop(name, None)
    module = importlib.import_module(name)
    yield module
    sys.modules.pop(name, None)


@pytest.fixture()
def make_handler(handler_module, tmp_path: Path):
    def _make(trail: Path | None = None):
        return handler_module.WaxsealCallbackHandler(trail or tmp_path / "trail.jsonl")

    return _make


RUN_ID = uuid.uuid4()


def tool_start_kwargs():
    # The exact keyword-only shape langchain-core 1.6.0 invokes with.
    return dict(
        run_id=RUN_ID, parent_run_id=None, tags=["agent"], metadata={"m": 1},
        inputs={"query": "SELECT 1"},
    )


def read_payload(trail: Path, line_no: int = 0) -> dict:
    line = trail.read_text().splitlines()[line_no]
    return json.loads(base64.b64decode(json.loads(line)["payload_b64"]))


class TestContract:
    def test_is_a_base_callback_handler(self, handler_module, make_handler) -> None:
        # The callback manager type-gates on this class; anything else is
        # silently ignored at attach time.
        assert isinstance(make_handler(), _StubBaseCallbackHandler)

    def test_raise_error_stays_false(self, make_handler) -> None:
        # raise_error=True would let a broken audit disk abort the user's
        # agent run — the audit observer must stay fail-open (and labelled).
        assert make_handler().raise_error is False


class TestToolEvents:
    def test_tool_start_and_end_chain_two_verified_entries(
        self, make_handler, tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        h = make_handler(trail)
        h.on_tool_start({"name": "sql_db_query"}, "SELECT 1", **tool_start_kwargs())
        h.on_tool_end("rows: 1", run_id=RUN_ID, parent_run_id=None)
        result = AuditLog.open(trail).verify(measure_drops=False)
        assert result.ok
        assert result.checked == 2

    def test_dispatch_payload_fields(self, make_handler, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        make_handler(trail).on_tool_start(
            {"name": "sql_db_query"}, "SELECT 1", **tool_start_kwargs()
        )
        payload = read_payload(trail)
        assert payload["phase"] == "dispatch"
        assert payload["tool_name"] == "sql_db_query"
        assert payload["input_str"] == "SELECT 1"
        assert payload["inputs"] == {"query": "SELECT 1"}
        assert payload["run_id"] == str(RUN_ID)

    def test_tool_error_records_type_and_message(self, make_handler, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        make_handler(trail).on_tool_error(
            TimeoutError("query exceeded 30s"), run_id=RUN_ID, parent_run_id=None
        )
        payload = read_payload(trail)
        assert payload["phase"] == "error"
        assert payload["error_type"] == "TimeoutError"
        assert "30s" in payload["error_message"]

    def test_non_string_tool_output_is_recorded(self, make_handler, tmp_path: Path) -> None:
        # on_tool_end's output is Any in langchain-core >= 1.x (was str);
        # a handler assuming str drops structured ToolMessage outputs.
        trail = tmp_path / "trail.jsonl"
        make_handler(trail).on_tool_end({"rows": [1, 2]}, run_id=RUN_ID)
        assert read_payload(trail)["output"] == {"rows": [1, 2]}


class TestRedactionAndClipping:
    def test_secret_in_tool_input_never_reaches_disk(self, make_handler, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        secret = "sk-abcdef1234567890abcdef"
        make_handler(trail).on_tool_start(
            {"name": "shell"}, f"export OPENAI_API_KEY={secret}", **tool_start_kwargs()
        )
        assert secret.encode() not in trail.read_bytes()
        assert AuditLog.open(trail).verify(measure_drops=False).ok

    def test_huge_output_is_clipped_with_visible_marker(
        self, make_handler, tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_handler(trail).on_tool_end("y" * 1_000_000, run_id=RUN_ID)
        assert len(trail.read_bytes()) < 100_000
        assert "truncated" in read_payload(trail)["output"]


class TestNeverBlocksTheRun:
    def test_broken_trail_never_raises_and_labels_the_drop(
        self, make_handler, tmp_path: Path, capsys
    ) -> None:
        # LangChain would swallow a raise (raise_error=False), but that
        # swallow is silent — the handler must label the drop itself.
        blocked = tmp_path / "blocked"
        blocked.write_text("a file where the trail dir should be")
        h = make_handler(blocked / "trail.jsonl")
        h.on_tool_start({"name": "shell"}, "ls", **tool_start_kwargs())  # must not raise
        assert "dropped" in capsys.readouterr().err
