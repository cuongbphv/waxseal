"""Tests for the OpenAI Agents SDK hooks (integrations/openai-agents/hooks.py).

Contract verified against openai.github.io/openai-agents-python (/ref/lifecycle,
2026-08-21):

- `from agents import RunHooks`; attach via Runner.run(agent, input,
  hooks=...). All hook methods are async:
  on_agent_start(context, agent); on_agent_end(context, agent, output);
  on_handoff(context, from_agent, to_agent);
  on_tool_start(context, agent, tool);
  on_tool_end(context, agent, tool, result: object).
- Tool INPUT is not a parameter: for function tools the context is a
  ToolContext exposing tool_name, tool_call_id, tool_arguments; other tool
  families pass a plain RunContextWrapper — so those attributes must be
  read with getattr and may be absent.
- The docs do not promise hook exceptions are swallowed; the SDK awaits
  hooks inline, so a raise can abort the user's run. Every failure path in
  the audit hooks must therefore be caught and labelled.

openai-agents is NOT a test dependency: a stub `agents` module providing
the RunHooks base name is injected; the call shapes exercised below are the
verified documented ones.
"""

import asyncio
import base64
import importlib.util
import json
import sys
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from waxseal import AuditLog


@pytest.fixture()
def hooks_module(monkeypatch: pytest.MonkeyPatch) -> Iterator[types.ModuleType]:
    stub = types.ModuleType("agents")
    setattr(stub, "RunHooks", type("RunHooks", (), {}))  # noqa: B010
    monkeypatch.setitem(sys.modules, "agents", stub)
    name = "waxseal.integrations.openai_agents"
    sys.modules.pop(name, None)
    module = importlib.import_module(name)
    yield module
    sys.modules.pop(name, None)


@pytest.fixture()
def make_hooks(
    hooks_module: types.ModuleType, tmp_path: Path
) -> Callable[..., Any]:
    def _make(trail: Path | None = None) -> Any:
        return hooks_module.WaxsealRunHooks(trail or tmp_path / "trail.jsonl")

    return _make


def tool_context(**overrides: object) -> SimpleNamespace:
    # The ToolContext shape function tools receive (tool_name /
    # tool_call_id / tool_arguments verified from the docs snippet).
    ns = SimpleNamespace(
        tool_name="get_weather",
        tool_call_id="call-1",
        tool_arguments='{"city": "Hanoi"}',
        usage=SimpleNamespace(total_tokens=10),
    )
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


AGENT = SimpleNamespace(name="assistant")
TOOL = SimpleNamespace(name="get_weather")


def read_payload(trail: Path, line_no: int = 0) -> dict[str, Any]:
    line = trail.read_text().splitlines()[line_no]
    result: dict[str, Any] = json.loads(
        base64.b64decode(json.loads(line)["payload_b64"])
    )
    return result


class TestContract:
    def test_is_a_run_hooks_subclass(self, make_hooks: Callable[..., Any]) -> None:
        # Runner.run type-gates on RunHooks; anything else fails at attach.
        assert isinstance(make_hooks(), sys.modules["agents"].RunHooks)


class TestToolEvents:
    def test_tool_start_and_end_chain_two_verified_entries(
        self, make_hooks: Callable[..., Any], tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        h = make_hooks(trail)
        asyncio.run(h.on_tool_start(tool_context(), AGENT, TOOL))
        asyncio.run(h.on_tool_end(tool_context(), AGENT, TOOL, "sunny, 32°C"))
        result = AuditLog.open(trail).verify(measure_drops=False)
        assert result.ok
        assert result.checked == 2

    def test_dispatch_payload_fields(self, make_hooks: Callable[..., Any], tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        asyncio.run(make_hooks(trail).on_tool_start(tool_context(), AGENT, TOOL))
        payload = read_payload(trail)
        assert payload["phase"] == "dispatch"
        assert payload["tool_name"] == "get_weather"
        assert payload["agent_name"] == "assistant"
        assert payload["tool_call_id"] == "call-1"
        assert payload["tool_arguments"] == '{"city": "Hanoi"}'

    def test_result_is_recorded(self, make_hooks: Callable[..., Any], tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        asyncio.run(make_hooks(trail).on_tool_end(tool_context(), AGENT, TOOL, {"temp": 32}))
        payload = read_payload(trail)
        assert payload["phase"] == "result"
        assert payload["result"] == {"temp": 32}

    def test_plain_context_without_tool_metadata_still_records(
        self, make_hooks: Callable[..., Any], tmp_path: Path
    ) -> None:
        # Non-function tool families pass a plain RunContextWrapper: no
        # tool_name/tool_call_id/tool_arguments attributes at all.
        trail = tmp_path / "trail.jsonl"
        plain = SimpleNamespace(usage=None)
        asyncio.run(make_hooks(trail).on_tool_start(plain, AGENT, TOOL))
        payload = read_payload(trail)
        assert payload["tool_name"] == "get_weather"  # falls back to tool.name
        assert payload["tool_arguments"] is None


class TestLifecycleEvents:
    def test_agent_start_end_and_handoff_are_recorded(
        self, make_hooks: Callable[..., Any], tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        h = make_hooks(trail)
        other = SimpleNamespace(name="specialist")
        asyncio.run(h.on_agent_start(tool_context(), AGENT))
        asyncio.run(h.on_handoff(tool_context(), AGENT, other))
        asyncio.run(h.on_agent_end(tool_context(), AGENT, "final answer"))
        assert AuditLog.open(trail).verify(measure_drops=False).checked == 3
        assert read_payload(trail, 1)["phase"] == "handoff"
        assert read_payload(trail, 1)["to_agent"] == "specialist"
        assert read_payload(trail, 2)["output"] == "final answer"


class TestRedactionAndClipping:
    def test_secret_in_tool_arguments_never_reaches_disk(
        self, make_hooks: Callable[..., Any], tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        secret = "sk-abcdef1234567890abcdef"
        ctx = tool_context(tool_arguments=f'{{"api_key": "{secret}"}}')
        asyncio.run(make_hooks(trail).on_tool_start(ctx, AGENT, TOOL))
        assert secret.encode() not in trail.read_bytes()
        assert AuditLog.open(trail).verify(measure_drops=False).ok

    def test_huge_result_is_clipped_with_visible_marker(
        self, make_hooks: Callable[..., Any], tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        asyncio.run(make_hooks(trail).on_tool_end(tool_context(), AGENT, TOOL, "y" * 1_000_000))
        assert len(trail.read_bytes()) < 100_000
        assert "truncated" in read_payload(trail)["result"]


class TestNeverAbortsTheRun:
    def test_broken_trail_never_raises_and_labels_the_drop(
        self, make_hooks: Callable[..., Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Hooks are awaited inline by the SDK — a raise here aborts the
        # user's run. It must degrade to a labelled drop instead.
        blocked = tmp_path / "blocked"
        blocked.write_text("a file where the trail dir should be")
        h = make_hooks(blocked / "trail.jsonl")
        asyncio.run(h.on_tool_start(tool_context(), AGENT, TOOL))  # must not raise
        assert "dropped" in capsys.readouterr().err

    def test_open_failure_still_leaves_a_drop_record(
        self,
        make_hooks: Callable[..., Any],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # M5: the pre-open failure branch has no AuditLog to route through
        # yet, so it calls FileDropRecorder directly. tmp_path is writable,
        # so unlike the blocked-directory case above, the record must land.
        monkeypatch.setattr(
            AuditLog, "open",
            staticmethod(lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("x"))),
        )
        trail = tmp_path / "trail.jsonl"
        h = make_hooks(trail)
        asyncio.run(h.on_tool_start(tool_context(), AGENT, TOOL))
        assert "dropped" in capsys.readouterr().err
        drops = tmp_path / "trail.jsonl.drops"
        assert drops.exists()
        assert len(drops.read_text().splitlines()) == 1
