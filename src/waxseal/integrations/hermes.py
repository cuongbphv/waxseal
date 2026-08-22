"""waxseal-audit — hermes-agent plugin (action-level audit trail).

Appends every tool call (dispatch + result) to a tamper-evident hash chain
at <hermes home>/audit/trail.jsonl. This is the action-focused record
hermes-agent issue #487 asked for: "agent performed action X on resource Y
at time T with result Z", chain-linked.

Contract verified against hermes-agent v2026.8.18:
- register(ctx) / ctx.register_hook (hermes_cli/plugins.py:3109).
- Callbacks take **kwargs: hook payloads evolve additively and a narrow
  signature silently loses new fields (hermes_cli/plugins.py:5074-5076).
- pre_tool_call return values are parsed as block/approve/modify directives
  (hermes_cli/plugins.py:5968+) — an audit observer MUST return None or it
  can veto/mutate real tool calls.
- The dispatcher isolates callback exceptions, but raising still logs a
  plugin failure per call; every failure path here degrades to a counted,
  printed dropped write instead (chain integrity ≠ trail completeness).

Ships in the wheel; `waxseal install hermes` writes a thin shim plugin to
~/.hermes/plugins/waxseal-audit/ that imports this module, so hermes only
needs `pip install waxseal` in its environment.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor

# _sanitize redacts BEFORE clipping: a clip can split a secret across the
# boundary (a PEM losing its END marker stops matching) and land it on disk.
_REDACTOR = RegexRedactor()

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

# Tool results can be megabytes (file reads, terminal dumps). Clip stored
# fields, visibly — silent truncation would read as "the full result".
MAX_FIELD_CHARS = 4096

# One log per resolved trail path: hermes loads this module once per
# process, but tests (and multi-home setups) may vary HERMES_HOME.
_logs: dict[Path, AuditLog] = {}


def _hermes_home() -> Path:
    env = os.environ.get("HERMES_HOME")
    if env:
        return Path(env)
    try:
        # Inside a hermes process this is the authoritative resolver.
        from hermes_cli.config import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        return Path.home() / ".hermes"


def _get_log() -> AuditLog:
    path = _hermes_home() / "audit" / "trail.jsonl"
    log = _logs.get(path)
    if log is None:
        log = AuditLog.open(path, redactor=RegexRedactor(), record_drops=True)
        _logs[path] = log
    return log


def _clip(text: str) -> str:
    if len(text) <= MAX_FIELD_CHARS:
        return text
    return text[:MAX_FIELD_CHARS] + f"…[truncated {len(text) - MAX_FIELD_CHARS} chars]"


def _sanitize(value: Any) -> Any:
    """Keep the payload JSON-serializable and bounded whatever the args hold."""
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return _clip(_REDACTOR.redact_text(value))
    if isinstance(value, dict):
        return {str(k): _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return _clip(_REDACTOR.redact_text(repr(value)))


def _append(phase: str, kwargs: dict[str, Any], fields: tuple[str, ...]) -> None:
    try:
        log = _get_log()
    except Exception as e:  # broken environment: never block the pipeline
        print(f"[waxseal-audit] cannot open trail (entry dropped): {e}", flush=True)
        # No AuditLog to route this through — record it directly,
        # best-effort (FileDropRecorder.record() never raises).
        from waxseal.adapters.drops import FileDropRecorder

        FileDropRecorder(_hermes_home() / "audit" / "trail.jsonl").record(
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
