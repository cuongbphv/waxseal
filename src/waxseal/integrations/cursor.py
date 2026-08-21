#!/usr/bin/env python3
"""waxseal-audit hook for Cursor (Agent Hooks).

Appends every hook event (shell commands, MCP tool calls, file edits,
prompts, lifecycle) to a tamper-evident hash chain. Configure it in
.cursor/hooks.json or ~/.cursor/hooks.json (see README.md next to this
file). Requires `pip install waxseal` in the interpreter this runs under.

Contract verified against https://cursor.com/docs/hooks (2026-08-21):

- One JSON event arrives on stdin; the reply goes on stdout. Exit code 2
  BLOCKS the action (= permission deny); empty stdout on exit 0 is treated
  as {} → allow. before* events parse stdout for permission/continue
  decisions.
- An audit observer therefore exits 0 on EVERY path and never writes to
  stdout — printing even an explicit "allow" could override a real policy
  hook's decision. Diagnostics go to stderr.

Secrets are redacted BEFORE hashing/storage (RegexRedactor): a key leaked
into a shell command, written into a file edit diff, or pasted into a
prompt reaches this trail only as ***REDACTED***.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor

# _sanitize redacts BEFORE clipping: a clip can split a secret across the
# boundary (a PEM losing its END marker stops matching) and land it on disk.
_REDACTOR = RegexRedactor()

PAYLOAD_TYPE = "application/vnd.cursor.hook-event+json"

# Shell outputs and file contents can be megabytes. Clip stored fields,
# visibly — silent truncation would read as "the full output".
MAX_FIELD_CHARS = 4096

# Per-event fields worth keeping, on top of the common envelope. Unlisted
# fields (e.g. beforeReadFile's full file content) are deliberately dropped:
# the trail records actions, not a copy of the workspace.
_EVENT_FIELDS = (
    "command", "cwd", "output", "duration", "sandbox",
    "tool_name", "tool_input", "result_json", "url",
    "file_path", "edits", "prompt", "attachments", "status", "loop_count",
    "error_message", "failure_type",
)
_COMMON_FIELDS = (
    "conversation_id", "generation_id", "model", "workspace_roots",
)


def _trail_path() -> Path:
    env = os.environ.get("WAXSEAL_TRAIL")
    if env:
        return Path(env)
    # HOME before Path.home(): ntpath resolves "~" from USERPROFILE and
    # ignores HOME, so a host that launches this hook with HOME set would
    # strand the trail in the wrong profile on Windows.
    home = os.environ.get("HOME")
    base = Path(home) if home else Path.home()
    return base / ".cursor" / "waxseal" / "trail.jsonl"


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


def build_payload(event: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"event": event.get("hook_event_name")}
    for name in _COMMON_FIELDS + _EVENT_FIELDS:
        if name in event:
            payload[name] = _sanitize(event[name])
    return payload


def main() -> int:
    # Every failure path returns 0: exit 2 is a deny, and an audit hook must
    # never veto the user's shell command, edit, or prompt.
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook event must be a JSON object")
    except Exception as e:
        print(f"[waxseal-audit] unreadable hook event (entry dropped): {e}", file=sys.stderr)
        return 0
    try:
        log = AuditLog.open(_trail_path(), redactor=RegexRedactor())
    except Exception as e:
        print(f"[waxseal-audit] cannot open trail (entry dropped): {e}", file=sys.stderr)
        return 0
    if not log.try_append(payload=build_payload(event), payload_type=PAYLOAD_TYPE):
        # Labelled fail-open (chain integrity ≠ trail completeness): the loss
        # is visible on stderr, never silent.
        print(
            f"[waxseal-audit] dropped write for {event.get('hook_event_name')!r}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover - measured via in-process tests
    sys.exit(main())
