#!/usr/bin/env python3
"""waxseal-audit hook for Cursor (Agent Hooks).

Appends every hook event (shell commands, MCP tool calls, file edits,
prompts, lifecycle) to a tamper-evident hash chain. Configure it in
.cursor/hooks.json or ~/.cursor/hooks.json (see the repo's
integrations/cursor/README.md). Requires `pip install waxseal` in the
interpreter this runs under.

Contract verified against https://cursor.com/docs/hooks (2026-08-21):

- One JSON event arrives on stdin; the reply goes on stdout. Exit code 2
  BLOCKS the action (= permission deny); empty stdout on exit 0 is treated
  as {} → allow. before* events parse stdout for permission/continue
  decisions.
- An audit observer therefore exits 0 on EVERY path and never writes to
  stdout, since printing even an explicit "allow" could override a real policy
  hook's decision. Diagnostics go to stderr.

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
into a shell command, written into a file edit diff, or pasted into a
prompt reaches this trail only as ***REDACTED***.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from waxseal.adapters.redactors import RegexRedactor
from waxseal.integrations import _sanitize as _sanitize_impl
from waxseal.integrations._archive import archive_destination
from waxseal.integrations._trail import home_base, resolve_trail, routed_trail
from waxseal.sources.rotation import (
    DEFAULT_MAX_SEGMENT_BYTES,
    active_segment,
    open_segmented,
)

MAX_FIELD_CHARS = _sanitize_impl.MAX_FIELD_CHARS
_sanitize = _sanitize_impl.sanitize

PAYLOAD_TYPE = "application/vnd.cursor.hook-event+json"

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


def _trail_path(event: dict[str, Any]) -> Path:
    return resolve_trail(
        default=lambda: routed_trail(
            home_base() / ".cursor" / "waxseal", _project_key(event)
        )
    )


def _project_key(event: dict[str, Any]) -> str | None:
    """The project key: `cwd` when Cursor sends one, else the FIRST of
    `workspace_roots`.

    Cursor sends `cwd` on the shell events and `workspace_roots` on the
    others, so keying on `cwd` alone would leave a multi-project developer's
    file edits and prompts braided into one shared trail while only their
    shell commands got routed. The first root, not all of them: a trail has
    one location, and a set-derived key would change the moment a second
    folder was added to the workspace.
    """
    cwd = event.get("cwd")
    if isinstance(cwd, str) and cwd:
        return cwd
    roots = event.get("workspace_roots")
    if isinstance(roots, list) and roots and isinstance(roots[0], str) and roots[0]:
        return roots[0]
    return None


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
    target = _trail_path(event)
    try:
        # The hook passes the built-in constant; the rotation notice says so,
        # so nobody reads 16777216 as something they configured.
        log = open_segmented(
            target,
            max_segment_bytes=DEFAULT_MAX_SEGMENT_BYTES,
            # J3's off-box copy, opt-in through `WAXSEAL_ARCHIVE`. `None` (the
            # unconfigured case) is passed through deliberately: rotation renders
            # it as `archive_not_attempted`, which is the line an operator who
            # believes they configured one needs to see.
            archive=archive_destination(),
            redactor=RegexRedactor(),
            record_drops=True,
        )
    except Exception as e:
        print(f"[waxseal-audit] cannot open trail (entry dropped): {e}", file=sys.stderr)
        # No AuditLog to route this through, so record it directly, best-effort
        # (FileDropRecorder.record() never raises). Beside the segment actually
        # in play: a `.drops` file in the wrong directory is a loss nobody finds.
        from waxseal.adapters.drops import FileDropRecorder

        FileDropRecorder(active_segment(target)).record(
            reason=type(e).__name__, payload_type=PAYLOAD_TYPE
        )
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
