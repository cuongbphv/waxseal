"""Tests for the hermes-agent plugin (integrations/hermes/plugin/__init__.py).

Contract verified against hermes-agent v2026.8.18 source:

- Plugins live at ~/.hermes/plugins/<name>/ with plugin.yaml + __init__.py
  exposing register(ctx); ctx.register_hook(name, callback)
  (hermes_cli/plugins.py:3109).
- Callbacks are invoked with keyword arguments; payloads evolve additively,
  so callbacks MUST accept **kwargs or they silently lose new fields
  (hermes_cli/plugins.py:5071-5076 — narrow signatures get a subset).
- post_tool_call kwargs (model_tools.py:1172-1187): tool_name, args, result,
  task_id, session_id, tool_call_id, turn_id, api_request_id, duration_ms,
  status, error_type, error_message, middleware_trace.
- pre_tool_call dict returns are parsed as block/approve/modify directives
  (hermes_cli/plugins.py:5968+). An AUDIT hook must therefore return None,
  or it can veto tool calls by accident.

The plugin module is loaded from its file path, the way tests must exercise
the exact artifact that ships.
"""

import base64
import importlib.util
import json
import sys
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from waxseal import AuditLog


class FakeCtx:
    """Minimal stand-in for hermes' PluginRegistration context."""

    def __init__(self) -> None:
        self.hooks: dict[str, Callable[..., object]] = {}

    def register_hook(self, hook_name: str, callback: Callable[..., object]) -> None:
        self.hooks[hook_name] = callback


# The exact post_tool_call payload shape from model_tools.py:1172-1187,
# plus telemetry_schema_version which invoke_hook injects (plugins.py:5099).
def post_tool_call_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = dict(
        tool_name="terminal",
        args={"command": "ls -la"},
        result="total 0\ndrwxr-xr-x  2 u  u  64 .",
        task_id="task-1",
        session_id="sess-1",
        tool_call_id="call-1",
        turn_id="turn-1",
        api_request_id="req-1",
        duration_ms=12.5,
        status="ok",
        error_type=None,
        error_message=None,
        middleware_trace=[],
        telemetry_schema_version=1,
    )
    kwargs.update(overrides)
    return kwargs


@pytest.fixture()
def plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[types.ModuleType]:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    name = "waxseal.integrations.hermes"
    sys.modules.pop(name, None)
    module = importlib.import_module(name)
    yield module
    sys.modules.pop(name, None)


@pytest.fixture()
def ctx(plugin: types.ModuleType) -> FakeCtx:
    fake = FakeCtx()
    plugin.register(fake)
    return fake


def trail_path(tmp_path: Path) -> Path:
    return tmp_path / "hermes-home" / "audit" / "trail.jsonl"


def read_payload(tmp_path: Path, line_no: int = 0) -> dict[str, Any]:
    line = trail_path(tmp_path).read_text().splitlines()[line_no]
    result: dict[str, Any] = json.loads(
        base64.b64decode(json.loads(line)["payload_b64"])
    )
    return result


class TestRegistration:
    def test_registers_pre_and_post_tool_call(self, ctx: FakeCtx) -> None:
        assert set(ctx.hooks) == {"pre_tool_call", "post_tool_call"}

    def test_manifest_declares_exactly_the_registered_hooks(
        self,
        plugin: types.ModuleType,
        ctx: FakeCtx,
    ) -> None:
        # PLUGIN_MANIFEST is what `waxseal install hermes` writes as
        # plugin.yaml and what `hermes plugins list` shows operators; drift
        # between manifest and register() misleads an audit review.
        import re

        declared = set(re.findall(r"^\s*-\s*(\w+)\s*$", plugin.PLUGIN_MANIFEST, re.MULTILINE))
        assert declared == set(ctx.hooks)


class TestOneWriterPerTrail:
    def test_repeated_calls_reuse_the_same_open_log(
        self,
        plugin: types.ModuleType,
        tmp_path: Path,
    ) -> None:
        # Rule 7: read-tail + append is one critical section. Handing each
        # hook call its own AuditLog would put two writers on one trail
        # inside a single process, and both could extend the same prev_hash.
        first = plugin._get_log()
        assert plugin._get_log() is first

    def test_a_different_hermes_home_gets_its_own_log(
        self, plugin: types.ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The cache is keyed by resolved path, not "one per process": a
        # relocated HERMES_HOME must not keep appending to the old trail.
        first = plugin._get_log()
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "other-home"))
        assert plugin._get_log() is not first


class TestPostToolCall:
    def test_appends_one_verified_entry_per_tool_result(self, ctx: FakeCtx, tmp_path: Path) -> None:
        ctx.hooks["post_tool_call"](**post_tool_call_kwargs())
        result = AuditLog.open(trail_path(tmp_path)).verify(measure_drops=False)
        assert result.ok
        assert result.checked == 1

    def test_action_fields_land_in_the_payload(self, ctx: FakeCtx, tmp_path: Path) -> None:
        ctx.hooks["post_tool_call"](
            **post_tool_call_kwargs(status="error", error_type="ToolError", duration_ms=3.0)
        )
        payload = read_payload(tmp_path)
        assert payload["phase"] == "result"
        assert payload["tool_name"] == "terminal"
        assert payload["tool_call_id"] == "call-1"
        assert payload["session_id"] == "sess-1"
        assert payload["status"] == "error"
        assert payload["error_type"] == "ToolError"
        assert payload["duration_ms"] == 3.0

    def test_unknown_future_kwargs_are_accepted(self, ctx: FakeCtx, tmp_path: Path) -> None:
        # Hook payloads evolve additively (plugins.py:5074) — a callback that
        # cannot swallow new kwargs breaks on the next hermes release.
        ctx.hooks["post_tool_call"](
            **post_tool_call_kwargs(brand_new_field={"nested": True})
        )
        assert AuditLog.open(trail_path(tmp_path)).verify(measure_drops=False).ok


class TestPreToolCall:
    def test_records_dispatch_before_execution(self, ctx: FakeCtx, tmp_path: Path) -> None:
        ctx.hooks["pre_tool_call"](
            tool_name="terminal",
            args={"command": "rm -rf build"},
            task_id="task-1",
            session_id="sess-1",
            tool_call_id="call-1",
            turn_id="turn-1",
            api_request_id="req-1",
            middleware_trace=[],
            telemetry_schema_version=1,
        )
        payload = read_payload(tmp_path)
        assert payload["phase"] == "dispatch"
        assert payload["tool_name"] == "terminal"

    def test_returns_none_so_it_can_never_veto_a_tool_call(self, ctx: FakeCtx) -> None:
        # pre_tool_call dict returns are parsed as block/approve/modify
        # directives — an audit observer returning anything else could
        # block or mutate real tool calls.
        ret = ctx.hooks["pre_tool_call"](
            tool_name="terminal", args={}, telemetry_schema_version=1
        )
        assert ret is None


class TestRedaction:
    def test_secret_in_args_never_reaches_disk(self, ctx: FakeCtx, tmp_path: Path) -> None:
        secret = "sk-abcdef1234567890abcdef"
        ctx.hooks["post_tool_call"](
            **post_tool_call_kwargs(args={"command": f"export OPENAI_KEY={secret}"})
        )
        assert secret.encode() not in trail_path(tmp_path).read_bytes()
        assert AuditLog.open(trail_path(tmp_path)).verify(measure_drops=False).ok


class TestTruncation:
    def test_huge_result_is_clipped_with_a_visible_marker(
        self,
        ctx: FakeCtx,
        tmp_path: Path,
    ) -> None:
        # Tool results can be megabytes (file reads, terminal dumps); the
        # trail must stay append-cheap and the clipping must be visible,
        # never silent (fail-open must be labelled).
        ctx.hooks["post_tool_call"](**post_tool_call_kwargs(result="y" * 1_000_000))
        raw = trail_path(tmp_path).read_bytes()
        assert len(raw) < 100_000
        payload = read_payload(tmp_path)
        assert "truncated" in payload["result"]
        assert AuditLog.open(trail_path(tmp_path)).verify(measure_drops=False).ok


class TestNeverBlocksThePipeline:
    def test_callback_never_raises_when_trail_dir_is_broken(
        self, ctx: FakeCtx, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The dispatcher isolates exceptions, but a raise would still be
        # logged as a plugin failure every call; degrade to a labelled
        # dropped write instead.
        home = tmp_path / "hermes-home"
        home.mkdir(parents=True)
        (home / "audit").write_text("not a directory")
        ctx.hooks["post_tool_call"](**post_tool_call_kwargs())  # must not raise
        assert "dropped" in capsys.readouterr().out

    def test_unserializable_values_are_sanitized_not_fatal(
        self,
        ctx: FakeCtx,
        tmp_path: Path,
    ) -> None:
        ctx.hooks["post_tool_call"](
            **post_tool_call_kwargs(args={"weird": object()}, result=object())
        )
        assert AuditLog.open(trail_path(tmp_path)).verify(measure_drops=False).checked == 1
