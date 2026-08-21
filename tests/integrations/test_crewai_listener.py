"""Tests for the CrewAI event listener (integrations/crewai/listener.py).

Contract verified against crewai 1.15.17 (PyPI wheel source, 2026-08-21):

- Everything imports from crewai.events (the pre-1.0 crewai.utilities.events
  path no longer exists). BaseEventListener.__init__ calls
  self.setup_listeners(crewai_event_bus) on the GLOBAL bus singleton —
  instantiating the listener IS the registration.
- Handlers register via @crewai_event_bus.on(EventClass) and are invoked as
  (source, event). ToolUsageEvent carries tool_name, tool_args (dict|str),
  agent_role, agent_id, task_id, task_name; ToolUsageFinishedEvent adds
  output, started_at, finished_at, from_cache; ToolUsageErrorEvent adds
  error.
- The bus wraps handlers in try/except and only PRINTS failures — a raise
  inside a handler is a silently dropped audit record, so the listener must
  label and count its own drops (rule 6).

crewai is NOT a test dependency: a stub bus reproducing the verified
registration mechanics is injected into sys.modules; the event shapes
exercised below are the verified 1.15.17 ones.
"""

import base64
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from waxseal import AuditLog


class _FakeBus:
    """Reproduces the verified registration surface of CrewAIEventsBus."""

    def __init__(self) -> None:
        self.handlers: dict[type, object] = {}

    def on(self, event_type: type):
        def decorator(fn):
            self.handlers[event_type] = fn
            return fn

        return decorator


def _event_class(name: str, event_type: str) -> type:
    def __init__(self, **kwargs):
        self.type = event_type
        for k, v in kwargs.items():
            setattr(self, k, v)

    return type(name, (), {"__init__": __init__})


@pytest.fixture()
def stub(monkeypatch: pytest.MonkeyPatch):
    bus = _FakeBus()

    class BaseEventListener:
        def __init__(self) -> None:
            # Verified: the real base class registers on the global bus
            # singleton at construction time.
            self.setup_listeners(bus)

    events = types.ModuleType("crewai.events")
    events.BaseEventListener = BaseEventListener
    events.crewai_event_bus = bus
    for name, etype in [
        ("ToolUsageStartedEvent", "tool_usage_started"),
        ("ToolUsageFinishedEvent", "tool_usage_finished"),
        ("ToolUsageErrorEvent", "tool_usage_error"),
        ("TaskStartedEvent", "task_started"),
        ("TaskCompletedEvent", "task_completed"),
        ("TaskFailedEvent", "task_failed"),
        ("CrewKickoffStartedEvent", "crew_kickoff_started"),
        ("CrewKickoffCompletedEvent", "crew_kickoff_completed"),
        ("CrewKickoffFailedEvent", "crew_kickoff_failed"),
    ]:
        setattr(events, name, _event_class(name, etype))
    pkg = types.ModuleType("crewai")
    pkg.events = events
    monkeypatch.setitem(sys.modules, "crewai", pkg)
    monkeypatch.setitem(sys.modules, "crewai.events", events)

    name = "waxseal.integrations.crewai"
    sys.modules.pop(name, None)
    module = importlib.import_module(name)
    yield types.SimpleNamespace(module=module, bus=bus, events=events)
    sys.modules.pop(name, None)


def read_payload(trail: Path, line_no: int = 0) -> dict:
    line = trail.read_text().splitlines()[line_no]
    return json.loads(base64.b64decode(json.loads(line)["payload_b64"]))


def tool_started(events, **overrides):
    fields = dict(
        tool_name="web_search",
        tool_args={"query": "waxseal"},
        agent_role="Researcher",
        agent_id="agent-1",
        task_id="task-1",
        task_name="research",
    )
    fields.update(overrides)
    return events.ToolUsageStartedEvent(**fields)


class TestRegistration:
    def test_instantiation_registers_all_audited_events(self, stub, tmp_path: Path) -> None:
        stub.module.WaxsealEventListener(tmp_path / "trail.jsonl")
        registered = {cls.__name__ for cls in stub.bus.handlers}
        assert registered == {
            "ToolUsageStartedEvent", "ToolUsageFinishedEvent", "ToolUsageErrorEvent",
            "TaskStartedEvent", "TaskCompletedEvent", "TaskFailedEvent",
            "CrewKickoffStartedEvent", "CrewKickoffCompletedEvent",
            "CrewKickoffFailedEvent",
        }


class TestToolEvents:
    def test_started_and_finished_chain_two_verified_entries(
        self, stub, tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        stub.module.WaxsealEventListener(trail)
        stub.bus.handlers[stub.events.ToolUsageStartedEvent]("crew", tool_started(stub.events))
        stub.bus.handlers[stub.events.ToolUsageFinishedEvent](
            "crew",
            stub.events.ToolUsageFinishedEvent(
                tool_name="web_search", tool_args={"query": "waxseal"},
                agent_role="Researcher", agent_id="agent-1",
                task_id="task-1", task_name="research",
                output="10 results", from_cache=False,
            ),
        )
        result = AuditLog.open(trail).verify(measure_drops=False)
        assert result.ok
        assert result.checked == 2

    def test_action_fields_land_in_the_payload(self, stub, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        stub.module.WaxsealEventListener(trail)
        stub.bus.handlers[stub.events.ToolUsageStartedEvent]("crew", tool_started(stub.events))
        payload = read_payload(trail)
        assert payload["event"] == "tool_usage_started"
        assert payload["tool_name"] == "web_search"
        assert payload["tool_args"] == {"query": "waxseal"}
        assert payload["agent_role"] == "Researcher"
        assert payload["task_id"] == "task-1"

    def test_tool_error_is_recorded(self, stub, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        stub.module.WaxsealEventListener(trail)
        stub.bus.handlers[stub.events.ToolUsageErrorEvent](
            "crew",
            stub.events.ToolUsageErrorEvent(
                tool_name="web_search", tool_args={}, agent_role="Researcher",
                agent_id="agent-1", task_id="task-1", task_name="research",
                error=TimeoutError("search timed out"),
            ),
        )
        payload = read_payload(trail)
        assert payload["event"] == "tool_usage_error"
        assert "timed out" in payload["error"]


class TestLifecycleEvents:
    def test_crew_and_task_events_are_recorded(self, stub, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        stub.module.WaxsealEventListener(trail)
        stub.bus.handlers[stub.events.CrewKickoffStartedEvent](
            "crew", stub.events.CrewKickoffStartedEvent(crew_name="research-crew", inputs={"q": 1})
        )
        stub.bus.handlers[stub.events.TaskCompletedEvent](
            "crew",
            stub.events.TaskCompletedEvent(task_id="task-1", task_name="research", output="done"),
        )
        assert AuditLog.open(trail).verify(measure_drops=False).checked == 2
        assert read_payload(trail, 0)["crew_name"] == "research-crew"
        assert read_payload(trail, 1)["event"] == "task_completed"


class TestRedactionAndClipping:
    def test_secret_in_tool_args_never_reaches_disk(self, stub, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        stub.module.WaxsealEventListener(trail)
        secret = "sk-abcdef1234567890abcdef"
        stub.bus.handlers[stub.events.ToolUsageStartedEvent](
            "crew", tool_started(stub.events, tool_args={"header": f"Bearer {secret}"})
        )
        assert secret.encode() not in trail.read_bytes()
        assert AuditLog.open(trail).verify(measure_drops=False).ok

    def test_huge_output_is_clipped_with_visible_marker(self, stub, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        stub.module.WaxsealEventListener(trail)
        stub.bus.handlers[stub.events.ToolUsageFinishedEvent](
            "crew",
            stub.events.ToolUsageFinishedEvent(
                tool_name="t", tool_args={}, agent_role="r", agent_id="a",
                task_id="t1", task_name="n", output="y" * 1_000_000,
            ),
        )
        assert len(trail.read_bytes()) < 100_000
        assert "truncated" in read_payload(trail)["output"]


class TestNeverBlocksTheCrew:
    def test_broken_trail_never_raises_and_labels_the_drop(
        self, stub, tmp_path: Path, capsys
    ) -> None:
        # The bus would swallow a raise, but that swallow is silent — the
        # listener must label the drop itself.
        blocked = tmp_path / "blocked"
        blocked.write_text("a file where the trail dir should be")
        stub.module.WaxsealEventListener(blocked / "trail.jsonl")
        stub.bus.handlers[stub.events.ToolUsageStartedEvent]("crew", tool_started(stub.events))
        assert "dropped" in capsys.readouterr().err
