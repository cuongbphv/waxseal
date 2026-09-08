"""waxseal-audit hook for hermes-agent.

Appends every lifecycle event to a tamper-evident hash chain at
`WAXSEAL_TRAIL`, else <hermes home>/audit/trail.jsonl. Requires
`pip install waxseal` in the environment running the hermes gateway.

Hermes hook contract: handle(event_type, context), errors must never block
the pipeline, so every failure path degrades to a counted dropped write
(chain integrity ≠ trail completeness) instead of an exception.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.integrations._trail import hermes_home as _hermes_home
from waxseal.integrations._trail import resolve_trail

PAYLOAD_TYPE = "application/vnd.hermes.hook-event+json"

# Written verbatim as HOOK.yaml by `waxseal install hermes-gateway`. Lives
# next to handle() so manifest and code cannot drift apart in a release.
HOOK_MANIFEST = """\
name: waxseal-audit
description: >
  Tamper-evident audit trail for agent actions. Appends every lifecycle event
  to a SHA-256 hash chain at ~/.hermes/audit/trail.jsonl (waxseal format).
  Secrets are redacted BEFORE hashing/storage. Verify anytime with:
  `waxseal verify ~/.hermes/audit/trail.jsonl`.
events:
  - gateway:startup
  - session:start
  - session:end
  - session:reset
  - agent:start
  - agent:step
  - agent:end
  - "command:*"
"""

# One log per resolved trail path: hermes loads this module once per gateway
# process, but tests (and multi-home setups) may vary HERMES_HOME.
_logs: dict[Path, AuditLog] = {}


def _trail_path() -> Path:
    """Where this gateway writes.

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


def _sanitize(value: Any) -> Any:
    """Keep the payload JSON-serializable whatever the context contains."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return repr(value)


def handle(event_type: str, context: dict[str, Any] | None) -> None:
    try:
        log = _get_log()
    except Exception as e:  # broken environment: never block the pipeline
        print(f"[waxseal-audit] cannot open trail (event dropped): {e}", flush=True)
        # No AuditLog to route this through, so record it directly,
        # best-effort (FileDropRecorder.record() never raises).
        from waxseal.adapters.drops import FileDropRecorder

        FileDropRecorder(_trail_path()).record(reason=type(e).__name__, payload_type=PAYLOAD_TYPE)
        return
    payload = {"event": event_type, **_sanitize(context or {})}
    if not log.try_append(payload=payload, payload_type=PAYLOAD_TYPE):
        # Labelled fail-open: the loss is visible in the gateway log and
        # counted on the writer (log.dropped_writes).
        print(
            f"[waxseal-audit] dropped write for {event_type!r} "
            f"(total dropped: {log.dropped_writes})",
            flush=True,
        )
