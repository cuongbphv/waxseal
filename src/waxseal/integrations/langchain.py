"""waxseal-audit callback handler for LangChain / LangGraph.

Appends every tool call (dispatch, result, error) and agent decision to a
tamper-evident hash chain. Attach it at invoke time so it inherits down to
tool runs:

    from waxseal.integrations.langchain import WaxsealCallbackHandler
    agent.invoke(input, config={"callbacks": [WaxsealCallbackHandler(trail)]})

The trail argument is optional: with none given, `WAXSEAL_TRAIL` is honoured,
and `DEFAULT_TRAIL` is the last resort. An argument passed here always wins
over the environment.

Contract verified against langchain-core 1.6.0 (installed source, 2026-08-21):

- on_tool_start(serialized, input_str, *, run_id, parent_run_id=None,
  tags=None, metadata=None, inputs=None, **kwargs); on_tool_end(output: Any,
  *, run_id, ...); on_tool_error(error: BaseException, *, run_id, ...).
  run_id/parent_run_id are uuid.UUID. output is Any (str in old versions).
- handle_event swallows handler exceptions unless raise_error is True.
  raise_error stays False here, because a broken audit disk must never abort
  the user's run, but LangChain's swallow is SILENT, so every failure path
  below labels and counts its own dropped write (fail-open must be visible).

Ships in the wheel: `pip install waxseal langchain-core`, then import from
waxseal.integrations.langchain, with no file copying.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.integrations import _sanitize as _sanitize_impl
from waxseal.integrations._trail import home_default, resolve_trail

MAX_FIELD_CHARS = _sanitize_impl.MAX_FIELD_CHARS
_clip = _sanitize_impl.clip
_sanitize = _sanitize_impl.sanitize

PAYLOAD_TYPE = "application/vnd.langchain.tool-event+json"

#: Where this integration writes when the caller names no path and
#: `WAXSEAL_TRAIL` is unset.
DEFAULT_TRAIL = "~/.waxseal/langchain-trail.jsonl"


class WaxsealCallbackHandler(BaseCallbackHandler):
    # True would let a broken audit disk abort the user's agent run; the
    # audit observer stays fail-open, and labels its own drops instead.
    raise_error: bool = False

    def __init__(self, trail: Path | str | None = None) -> None:
        """``trail`` wins over `WAXSEAL_TRAIL`, which wins over
        `DEFAULT_TRAIL`. The default is a None sentinel rather than the path
        itself so "the caller passed nothing" stays distinguishable from
        "the caller passed the default path" — without that distinction
        there is nowhere for the environment rung to sit, and an operator's
        `WAXSEAL_TRAIL` would be silently ignored by this integration while
        the stdin hooks honoured it.
        """
        # home_default(), not Path(...).expanduser(): the last rung has to
        # honour HOME, which ntpath.expanduser ignores in favour of USERPROFILE
        # (waxseal-fg4.20; the profile split is documented on home_default).
        self._trail = resolve_trail(trail, default=lambda: home_default(DEFAULT_TRAIL))
        self._log: AuditLog | None = None

    def _append(self, payload: dict[str, Any]) -> None:
        try:
            if self._log is None:
                self._log = AuditLog.open(
                    self._trail, redactor=RegexRedactor(), record_drops=True
                )
        except Exception as e:  # broken environment: never block the run
            print(f"[waxseal-audit] cannot open trail (entry dropped): {e}", file=sys.stderr)
            # No AuditLog to route this through, so record it directly,
            # best-effort (FileDropRecorder.record() never raises).
            from waxseal.adapters.drops import FileDropRecorder

            FileDropRecorder(self._trail).record(
                reason=type(e).__name__, payload_type=PAYLOAD_TYPE
            )
            return
        if not self._log.try_append(payload=payload, payload_type=PAYLOAD_TYPE):
            # Labelled fail-open (chain integrity ≠ trail completeness).
            print(
                f"[waxseal-audit] dropped write for {payload.get('phase')!r} "
                f"(total dropped: {self._log.dropped_writes})",
                file=sys.stderr,
            )

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Record the dispatch before execution, so an attempt that kills the
        process (or never returns) is still on the chain."""
        self._append(
            {
                "phase": "dispatch",
                "tool_name": (serialized or {}).get("name"),
                "input_str": _sanitize(input_str),
                "inputs": _sanitize(inputs),
                "tags": _sanitize(tags),
                "run_id": str(run_id),
                "parent_run_id": str(parent_run_id) if parent_run_id else None,
            }
        )

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._append(
            {
                "phase": "result",
                "output": _sanitize(output),
                "run_id": str(run_id),
                "parent_run_id": str(parent_run_id) if parent_run_id else None,
            }
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._append(
            {
                "phase": "error",
                "error_type": type(error).__name__,
                "error_message": _clip(str(error)),
                "run_id": str(run_id),
                "parent_run_id": str(parent_run_id) if parent_run_id else None,
            }
        )

    def on_agent_action(
        self,
        action: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._append(
            {
                "phase": "agent_action",
                "tool_name": getattr(action, "tool", None),
                "tool_input": _sanitize(getattr(action, "tool_input", None)),
                "run_id": str(run_id),
            }
        )

    def on_agent_finish(
        self,
        finish: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._append(
            {
                "phase": "agent_finish",
                "return_values": _sanitize(getattr(finish, "return_values", None)),
                "run_id": str(run_id),
            }
        )
