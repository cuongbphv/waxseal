#!/usr/bin/env python3
"""waxseal-audit hook for OpenAI Codex CLI.

Appends every lifecycle hook event (tool dispatch, tool result, user prompt,
session lifecycle) to a tamper-evident hash chain. Configure it in
~/.codex/hooks.json or config.toml [[hooks.*]] tables (see README.md next to
this file). Requires `pip install waxseal` in the interpreter this runs
under.

Contract verified against openai/codex source, rust-v0.149.0 (2026-08-21):

- One JSON event arrives on STDIN (argv delivery is the legacy `notify`
  mechanism — turn-level only, not used here). snake_case fields:
  session_id, turn_id, cwd, hook_event_name, model, permission_mode,
  tool_name, tool_input, tool_use_id; PostToolUse adds tool_response.
- Hook stdout is parsed as camelCase decision JSON (`decision`, `continue`,
  `updatedInput`) and exit code 2 BLOCKS the tool call. An audit observer
  therefore exits 0 with empty stdout on EVERY path, including its own
  failures; diagnostics go to stderr.

Secrets are redacted BEFORE hashing/storage (RegexRedactor): a key leaked
into a command or pasted into a prompt reaches this trail only as
***REDACTED***.
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

PAYLOAD_TYPE = "application/vnd.codex.hook-event+json"

# Tool responses can be megabytes (file reads, terminal dumps). Clip stored
# fields, visibly — silent truncation would read as "the full output".
MAX_FIELD_CHARS = 4096

_COMMON_FIELDS = (
    "session_id", "turn_id", "cwd", "model", "permission_mode",
    "tool_name", "tool_input", "tool_use_id", "prompt",
    "agent_id", "agent_type",
)


def _trail_path() -> Path:
    env = os.environ.get("WAXSEAL_TRAIL")
    if env:
        return Path(env)
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home) / "waxseal" / "trail.jsonl"
    # HOME before Path.home(): ntpath resolves "~" from USERPROFILE and
    # ignores HOME, so a host that launches this hook with HOME set would
    # strand the trail in the wrong profile on Windows.
    home = os.environ.get("HOME")
    base = Path(home) if home else Path.home()
    return base / ".codex" / "waxseal" / "trail.jsonl"


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
    for name in _COMMON_FIELDS:
        if name in event:
            payload[name] = _sanitize(event[name])
    if "tool_response" in event:
        payload["tool_response"] = _sanitize(event["tool_response"])
    return payload


def main() -> int:
    # Every failure path returns 0: exit 2 blocks the tool call, and an
    # audit hook must never veto the user's work.
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
