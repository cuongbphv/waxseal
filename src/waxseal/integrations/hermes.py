"""waxseal-audit: the hermes-agent plugin (action-level audit trail).

Appends every tool call (dispatch + result) to a tamper-evident hash chain
at `WAXSEAL_TRAIL`, else <hermes home>/audit/trail.jsonl. This is the
action-focused record hermes-agent issue #487 asked for: "agent performed
action X on resource Y at time T with result Z", chain-linked.

Contract verified against hermes-agent v2026.8.18:
- register(ctx) / ctx.register_hook (hermes_cli/plugins.py:3109).
- Callbacks take **kwargs: hook payloads evolve additively and a narrow
  signature silently loses new fields (hermes_cli/plugins.py:5074-5076).
- pre_tool_call return values are parsed as block/approve/modify directives
  (hermes_cli/plugins.py:5968+), so an audit observer MUST return None or it
  can veto/mutate real tool calls.
- The dispatcher isolates callback exceptions, but raising still logs a
  plugin failure per call; every failure path here degrades to a counted,
  printed dropped write instead (chain integrity ≠ trail completeness).

Ships in the wheel; `waxseal install hermes` writes a thin shim plugin to
~/.hermes/plugins/waxseal-audit/ that imports this module, so hermes only
needs `pip install waxseal` in its environment.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.integrations import _sanitize as _sanitize_impl
from waxseal.integrations._trail import hermes_home as _hermes_home
from waxseal.integrations._trail import resolve_trail

MAX_FIELD_CHARS = _sanitize_impl.MAX_FIELD_CHARS
_sanitize = _sanitize_impl.sanitize

PAYLOAD_TYPE = "application/vnd.hermes.tool-call+json"

# Written verbatim as plugin.yaml by `waxseal install hermes`. Lives next to
# register() so manifest and code cannot drift apart in a release.
PLUGIN_MANIFEST = (
    "name: waxseal-audit\n"
    'version: "0.1.0"\n'
    'description: "Tamper-evident, action-level audit trail: every tool call '
    "(dispatch + result) is appended to a SHA-256 hash chain at "
    "~/.hermes/audit/trail.jsonl (waxseal format). Secrets are redacted "
    "BEFORE hashing/storage. Verify anytime: "
    '`waxseal verify ~/.hermes/audit/trail.jsonl`."\n'
    "author: waxseal\n"
    "hooks:\n"
    "  - pre_tool_call\n"
    "  - post_tool_call\n"
)

# One log per resolved trail path: hermes loads this module once per
# process, but tests (and multi-home setups) may vary HERMES_HOME.
_logs: dict[Path, AuditLog] = {}


def _trail_path() -> Path:
    """Where this plugin writes.

    `WAXSEAL_TRAIL` is honoured here for the same reason the stdin hooks
    honour it: an operator who aims the variable at a path and then verifies
    that path must not be shown an empty file. There is no explicit-argument
    rung — hermes loads this module itself and passes no path — so the chain
    is `WAXSEAL_TRAIL` > `HERMES_HOME` > the home fallback, and that last
    rung reads `HOME` before ``Path.home()`` like every other integration.
    """
    return resolve_trail(default=lambda: _hermes_home() / "audit" / "trail.jsonl")


def _get_log() -> AuditLog:
    path = _trail_path()
    log = _logs.get(path)
    if log is None:
        log = AuditLog.open(path, redactor=RegexRedactor(), record_drops=True)
        _logs[path] = log
    return log


def _append(phase: str, kwargs: dict[str, Any], fields: tuple[str, ...]) -> None:
    try:
        log = _get_log()
    except Exception as e:  # broken environment: never block the pipeline
        print(f"[waxseal-audit] cannot open trail (entry dropped): {e}", flush=True)
        # No AuditLog to route this through, so record it directly,
        # best-effort (FileDropRecorder.record() never raises).
        from waxseal.adapters.drops import FileDropRecorder

        FileDropRecorder(_trail_path()).record(
            reason=type(e).__name__, payload_type=PAYLOAD_TYPE
        )
        return
    payload = {"phase": phase}
    payload.update({name: _sanitize(kwargs.get(name)) for name in fields})
    if not log.try_append(payload=payload, payload_type=PAYLOAD_TYPE):
        # Labelled fail-open: the loss is visible in the process log and
        # counted on the writer (log.dropped_writes).
        print(
            f"[waxseal-audit] dropped write for {phase!r} "
            f"{payload.get('tool_name')!r} (total dropped: {log.dropped_writes})",
            flush=True,
        )


_DISPATCH_FIELDS = (
    "tool_name", "args", "task_id", "session_id",
    "tool_call_id", "turn_id", "api_request_id",
)
_RESULT_FIELDS = _DISPATCH_FIELDS + (
    "result", "status", "duration_ms", "error_type", "error_message",
)


def on_pre_tool_call(**kwargs: Any) -> None:
    """Record the dispatch before execution, so an attempt that kills the
    process (or never returns) is still on the chain."""
    _append("dispatch", kwargs, _DISPATCH_FIELDS)
    return None  # anything else is a block/approve/modify directive


def on_post_tool_call(**kwargs: Any) -> None:
    _append("result", kwargs, _RESULT_FIELDS)
    return None


def register(ctx: Any) -> None:
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
