"""waxseal-audit run hooks for the OpenAI Agents SDK.

Appends every tool call, agent start/end, and handoff to a tamper-evident
hash chain. Attach per run:

    from waxseal.integrations.openai_agents import WaxsealRunHooks
    result = await Runner.run(agent, "input", hooks=WaxsealRunHooks(trail))

The trail argument is optional: with none given, `WAXSEAL_TRAIL` is honoured,
and `DEFAULT_TRAIL` is the last resort. An argument passed here always wins
over the environment.

Contract verified against openai.github.io/openai-agents-python
(/ref/lifecycle, 2026-08-21):

- All RunHooks methods are async: on_agent_start(context, agent);
  on_agent_end(context, agent, output); on_handoff(context, from_agent,
  to_agent); on_tool_start(context, agent, tool);
  on_tool_end(context, agent, tool, result: object).
- Tool INPUT is not a parameter. Function tools receive a ToolContext
  exposing tool_name / tool_call_id / tool_arguments; other tool families
  pass a plain RunContextWrapper, so read those attributes with getattr.
- The SDK awaits hooks inline and does not promise to swallow exceptions:
  a raise here can abort the user's run. Every failure path below degrades
  to a labelled, counted dropped write instead (chain integrity ≠ trail
  completeness).

Ships in the wheel: `pip install waxseal openai-agents`, then import from
waxseal.integrations.openai_agents, with no file copying.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from agents import RunHooks

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.integrations._trail import resolve_trail

# _sanitize redacts BEFORE clipping: a clip can split a secret across the
# boundary (a PEM losing its END marker stops matching) and land it on disk.
_REDACTOR = RegexRedactor()

PAYLOAD_TYPE = "application/vnd.openai-agents.run-event+json"

# Tool results can be megabytes (file reads, API dumps). Clip stored fields,
# visibly, because silent truncation would read as "the full result".
MAX_FIELD_CHARS = 4096

#: Where this integration writes when the caller names no path and
#: `WAXSEAL_TRAIL` is unset.
DEFAULT_TRAIL = "~/.waxseal/openai-agents-trail.jsonl"


def _clip(text: str) -> str:
    if len(text) <= MAX_FIELD_CHARS:
        return text
    return text[:MAX_FIELD_CHARS] + f"…[truncated {len(text) - MAX_FIELD_CHARS} chars]"


def _sanitize(value: Any) -> Any:
    """Keep the payload JSON-serializable and bounded whatever the run holds."""
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return _clip(_REDACTOR.redact_text(value))
    if isinstance(value, dict):
        return {str(k): _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return _clip(_REDACTOR.redact_text(repr(value)))


class WaxsealRunHooks(RunHooks):
    def __init__(self, trail: Path | str | None = None) -> None:
        """``trail`` wins over `WAXSEAL_TRAIL`, which wins over
        `DEFAULT_TRAIL`. The default is a None sentinel rather than the path
        itself so "the caller passed nothing" stays distinguishable from
        "the caller passed the default path" — without that distinction
        there is nowhere for the environment rung to sit, and an operator's
        `WAXSEAL_TRAIL` would be silently ignored by this integration while
        the stdin hooks honoured it.
        """
        self._trail = resolve_trail(trail, default=lambda: Path(DEFAULT_TRAIL).expanduser())
        self._log: AuditLog | None = None

    def _append(self, payload: dict[str, Any]) -> None:
        try:
            if self._log is None:
                self._log = AuditLog.open(
                    self._trail, redactor=RegexRedactor(), record_drops=True
                )
        except Exception as e:  # broken environment: never abort the run
            print(f"[waxseal-audit] cannot open trail (entry dropped): {e}", file=sys.stderr)
            # No AuditLog to route this through, so record it directly,
            # best-effort (FileDropRecorder.record() never raises).
            from waxseal.adapters.drops import FileDropRecorder

            FileDropRecorder(self._trail).record(
                reason=type(e).__name__, payload_type=PAYLOAD_TYPE
            )
            return
        if not self._log.try_append(payload=payload, payload_type=PAYLOAD_TYPE):
            # Labelled fail-open: the SDK gives no second chance to report
            # this: the loss must be visible here and counted on the writer.
            print(
                f"[waxseal-audit] dropped write for {payload.get('phase')!r} "
                f"(total dropped: {self._log.dropped_writes})",
                file=sys.stderr,
            )

    def _tool_payload(self, phase: str, context: Any, agent: Any, tool: Any) -> dict[str, Any]:
        # ToolContext (function tools) carries the call metadata; other tool
        # families pass a plain wrapper without these attributes.
        return {
            "phase": phase,
            "agent_name": getattr(agent, "name", None),
            "tool_name": getattr(context, "tool_name", None) or getattr(tool, "name", None),
            "tool_call_id": getattr(context, "tool_call_id", None),
            "tool_arguments": _sanitize(getattr(context, "tool_arguments", None)),
        }

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        """Record the dispatch before execution, so an attempt that kills the
        process (or never returns) is still on the chain."""
        self._append(self._tool_payload("dispatch", context, agent, tool))

    async def on_tool_end(self, context: Any, agent: Any, tool: Any, result: Any) -> None:
        payload = self._tool_payload("result", context, agent, tool)
        payload["result"] = _sanitize(result)
        self._append(payload)

    async def on_agent_start(self, context: Any, agent: Any) -> None:
        self._append({"phase": "agent_start", "agent_name": getattr(agent, "name", None)})

    async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
        self._append(
            {
                "phase": "agent_end",
                "agent_name": getattr(agent, "name", None),
                "output": _sanitize(output),
            }
        )

    async def on_handoff(self, context: Any, from_agent: Any, to_agent: Any) -> None:
        self._append(
            {
                "phase": "handoff",
                "from_agent": getattr(from_agent, "name", None),
                "to_agent": getattr(to_agent, "name", None),
            }
        )
