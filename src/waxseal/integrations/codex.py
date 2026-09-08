#!/usr/bin/env python3
"""waxseal-audit hook for OpenAI Codex CLI.

Appends every lifecycle hook event (tool dispatch, tool result, user prompt,
session lifecycle) to a tamper-evident hash chain. Configure it in
~/.codex/hooks.json or config.toml [[hooks.*]] tables (see the repo's
integrations/codex/README.md). Requires `pip install waxseal` in the
interpreter this runs under.

Contract verified against openai/codex source, rust-v0.149.0 (2026-08-21):

- One JSON event arrives on STDIN (argv delivery is the legacy `notify`
  mechanism, turn-level only, not used here). snake_case fields:
  session_id, turn_id, cwd, hook_event_name, model, permission_mode,
  tool_name, tool_input, tool_use_id; PostToolUse adds tool_response.
- Hook stdout is parsed as camelCase decision JSON (`decision`, `continue`,
  `updatedInput`) and exit code 2 BLOCKS the tool call. An audit observer
  therefore exits 0 with empty stdout on EVERY path, including its own
  failures; diagnostics go to stderr.

Per-project routing (SPEC 20, on by default): the trail is keyed by the hook
event's cwd, so two projects never braid their histories into one file, and it
rolls over into sealed segments once the active one passes 16 MiB. There is no
new environment variable and no flag. `WAXSEAL_TRAIL` still wins on LOCATION
and is NOT a rotation off-switch: a trail named through it rotates too, and on
its first rotation it is adopted as the base segment.

Off-box archiving (`domain/archive.py`) is opt-in and, until this was wired, was
unreachable from any hook at all: `WAXSEAL_ARCHIVE` names where a SEALED
segment is copied — `s3://bucket/prefix/`, or a chain server's `https://`
base URL with `WAXSEAL_ARCHIVE_API_KEY` as its own import-write credential
(deliberately neither `WAXSEAL_API_KEY` nor `WAXSEAL_WITNESS_API_KEY`; see
`integrations/_archive.py`). Rotation itself still takes no environment
variable and no flag — this configures only where its output goes, and unset
means nothing is sent and the rotation line reads `archive_not_attempted`.

Secrets are redacted BEFORE hashing/storage (RegexRedactor): a key leaked
into a command or pasted into a prompt reaches this trail only as
***REDACTED***.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from waxseal.integrations import _sanitize as _sanitize_impl
from waxseal.integrations._stdin_hook import run_stdin_hook
from waxseal.integrations._trail import home_base, resolve_trail, routed_trail
from waxseal.sources.rotation import DEFAULT_MAX_SEGMENT_BYTES

MAX_FIELD_CHARS = _sanitize_impl.MAX_FIELD_CHARS
_sanitize = _sanitize_impl.sanitize

PAYLOAD_TYPE = "application/vnd.codex.hook-event+json"

_COMMON_FIELDS = (
    "session_id", "turn_id", "cwd", "model", "permission_mode",
    "tool_name", "tool_input", "tool_use_id", "prompt",
    "agent_id", "agent_type",
)


def _trail_path(event: dict[str, Any]) -> Path:
    return resolve_trail(default=lambda: routed_trail(_codex_home(), _project_key(event)))


def _codex_home() -> Path:
    # Codex relocates its whole state directory via CODEX_HOME; a trail left
    # behind in ~/.codex would not follow the session it belongs to. The
    # per-project trails nest UNDER this, so relocation still carries them.
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home) / "waxseal"
    return home_base() / ".codex" / "waxseal"


def _project_key(event: dict[str, Any]) -> str | None:
    """The event's `cwd` — a documented snake_case Codex hook field."""
    cwd = event.get("cwd")
    return cwd if isinstance(cwd, str) and cwd else None


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
    return run_stdin_hook(
        payload_type=PAYLOAD_TYPE,
        build_payload=build_payload,
        resolve_target=_trail_path,
        # The hook passes the built-in constant; the rotation notice says so,
        # so nobody reads 16777216 as something they configured.
        max_segment_bytes=DEFAULT_MAX_SEGMENT_BYTES,
    )


if __name__ == "__main__":  # pragma: no cover - measured via in-process tests
    sys.exit(main())
