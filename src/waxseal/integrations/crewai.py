"""waxseal-audit event listener for CrewAI.

Appends tool usage, task, and crew lifecycle events to a tamper-evident hash
chain. Instantiate it once at your entry point (crew.py / main.py / flow.py)
and keep the reference alive, because construction IS the registration:

    from waxseal.integrations.crewai import WaxsealEventListener
    audit = WaxsealEventListener("~/.waxseal/crewai-trail.jsonl")

Contract verified against crewai 1.15.17 (PyPI wheel source, 2026-08-21):

- Everything imports from crewai.events (the pre-1.0 crewai.utilities.events
  path is gone). BaseEventListener.__init__ calls
  self.setup_listeners(crewai_event_bus) on the global bus singleton.
- Handlers register via @crewai_event_bus.on(EventClass), invoked (source,
  event). ToolUsageEvent carries tool_name, tool_args (dict|str),
  agent_role/agent_id/task_id/task_name; Finished adds output/from_cache;
  Error adds error.
- The bus wraps handlers in try/except and only PRINTS failures, so a raise
  here is a silently dropped audit record. Every failure path below instead
  degrades to a labelled, counted dropped write (chain integrity ≠ trail
  completeness).

Ships in the wheel: `pip install waxseal crewai`, then import from
waxseal.integrations.crewai, with no file copying.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from crewai.events import (
    BaseEventListener,
    CrewKickoffCompletedEvent,
    CrewKickoffFailedEvent,
    CrewKickoffStartedEvent,
    TaskCompletedEvent,
    TaskFailedEvent,
    TaskStartedEvent,
    ToolUsageErrorEvent,
    ToolUsageFinishedEvent,
    ToolUsageStartedEvent,
)

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor

# _sanitize redacts BEFORE clipping: a clip can split a secret across the
# boundary (a PEM losing its END marker stops matching) and land it on disk.
_REDACTOR = RegexRedactor()

PAYLOAD_TYPE = "application/vnd.crewai.event+json"

# Tool outputs can be megabytes (scraped pages, file reads). Clip stored
# fields, visibly, because silent truncation would read as "the full output".
MAX_FIELD_CHARS = 4096

# Attributes copied off each event when present. Deliberately curated:
# events also carry live agent/task/crew objects, which are neither
# serializable nor audit data.
_EVENT_ATTRS = (
    "tool_name", "tool_args", "agent_role", "agent_id", "agent_key",
    "task_id", "task_name", "crew_name", "inputs", "output", "from_cache",
    "error", "total_tokens", "event_id",
)


def _clip(text: str) -> str:
    if len(text) <= MAX_FIELD_CHARS:
        return text
    return text[:MAX_FIELD_CHARS] + f"…[truncated {len(text) - MAX_FIELD_CHARS} chars]"


def _sanitize(value: Any) -> Any:
    """Keep the payload JSON-serializable and bounded whatever the event holds."""
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return _clip(_REDACTOR.redact_text(value))
    if isinstance(value, dict):
        return {str(k): _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return _clip(_REDACTOR.redact_text(repr(value)))


class WaxsealEventListener(BaseEventListener):
    def __init__(self, trail: Path | str = "~/.waxseal/crewai-trail.jsonl") -> None:
        # Set state BEFORE super().__init__: the base class registers (and
        # may fire) setup_listeners during construction.
        self._trail = Path(trail).expanduser()
        self._log: AuditLog | None = None
        super().__init__()

    def _record(self, event: Any) -> None:
        payload: dict[str, Any] = {"event": getattr(event, "type", type(event).__name__)}
        for name in _EVENT_ATTRS:
            if hasattr(event, name):
                payload[name] = _sanitize(getattr(event, name))
        try:
            if self._log is None:
                self._log = AuditLog.open(
                    self._trail, redactor=RegexRedactor(), record_drops=True
                )
        except Exception as e:  # broken environment: never block the crew
            print(f"[waxseal-audit] cannot open trail (entry dropped): {e}", file=sys.stderr)
            # No AuditLog to route this through, so record it directly,
            # best-effort (FileDropRecorder.record() never raises).
            from waxseal.adapters.drops import FileDropRecorder

            FileDropRecorder(self._trail).record(
                reason=type(e).__name__, payload_type=PAYLOAD_TYPE
            )
            return
        if not self._log.try_append(payload=payload, payload_type=PAYLOAD_TYPE):
            # Labelled fail-open: the bus swallows raises silently, so the
            # loss must be made visible here and counted on the writer.
            print(
                f"[waxseal-audit] dropped write for {payload['event']!r} "
                f"(total dropped: {self._log.dropped_writes})",
                file=sys.stderr,
            )

    def setup_listeners(self, crewai_event_bus: Any) -> None:
        audited = (
            ToolUsageStartedEvent, ToolUsageFinishedEvent, ToolUsageErrorEvent,
            TaskStartedEvent, TaskCompletedEvent, TaskFailedEvent,
            CrewKickoffStartedEvent, CrewKickoffCompletedEvent, CrewKickoffFailedEvent,
        )
        for event_class in audited:
            @crewai_event_bus.on(event_class)
            def _handler(source: Any, event: Any) -> None:
                self._record(event)
