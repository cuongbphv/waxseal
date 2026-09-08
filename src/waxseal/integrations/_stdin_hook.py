"""The one stdin -> parse -> sanitize -> append -> fail-open loop the stdin hooks share.

`claude_code`, `codex` and `cursor` each spelled this loop out for themselves.
The three copies were identical in code and had already begun to drift in
their comments, which is how a fail-open contract stops being one contract.
What differs stays on the host module: the payload type, the field map behind
`build_payload`, how the trail is resolved, and (Claude Code only) the
chain-server branch. What does not differ lives here:

- exit 0 on EVERY path, including this loop's own failures. Exit 2 is a veto
  on all three hosts, and an audit observer must never veto the user's work;
- nothing on stdout, ever. The hosts parse stdout as decision JSON (Claude
  Code injects it into model context on UserPromptSubmit), so even an
  explicit "allow" could override a real policy hook's decision;
- every loss labelled on stderr and, where a sidecar location exists,
  recorded in a `.drops` file beside the segment actually in play (rule 6;
  chain integrity ≠ trail completeness).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from waxseal.adapters.redactors import RegexRedactor
from waxseal.integrations._archive import archive_destination
from waxseal.log import AuditLog
from waxseal.sources.rotation import active_segment, open_segmented


def run_stdin_hook(
    *,
    payload_type: str,
    build_payload: Callable[[dict[str, Any]], dict[str, Any]],
    resolve_target: Callable[[dict[str, Any]], str | Path],
    max_segment_bytes: int,
    open_remote: Callable[[str, dict[str, Any]], AuditLog] | None = None,
) -> int:
    """Read one hook event from stdin and append it; return the exit code (0).

    ``resolve_target`` returns a ``Path`` for a local trail or a ``str`` for
    a chain server's base URL; only a host that resolves URLs passes
    ``open_remote``. ``max_segment_bytes`` is passed by the host, not read
    here, so the host module keeps naming the constant its tests and its
    rotation notice refer to.
    """
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook event must be a JSON object")
    except Exception as e:
        print(f"[waxseal-audit] unreadable hook event (entry dropped): {e}", file=sys.stderr)
        return 0
    target = resolve_target(event)
    try:
        if isinstance(target, str):
            if open_remote is None:
                raise TypeError("this hook resolves local paths only, got a URL target")
            log = open_remote(target, event)
        else:
            log = open_segmented(
                target,
                max_segment_bytes=max_segment_bytes,
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
        if isinstance(target, str):
            # Nowhere to record it: the loss is labelled on stderr and nothing
            # else, which is still better than inventing a sidecar location.
            return 0
        # No AuditLog to route this through, so record it directly. Best-effort
        # (FileDropRecorder.record() never raises): a trail we cannot even
        # open must not become a second failure on top of the first.
        from waxseal.adapters.drops import FileDropRecorder

        # Beside the segment actually in play, not beside the logical base:
        # a `.drops` file in the wrong directory is a loss nobody finds.
        FileDropRecorder(active_segment(target)).record(
            reason=type(e).__name__, payload_type=payload_type
        )
        return 0
    if not log.try_append(payload=build_payload(event), payload_type=payload_type):
        # Labelled fail-open (chain integrity ≠ trail completeness): the loss
        # is visible on stderr, never silent.
        print(
            f"[waxseal-audit] dropped write for {event.get('hook_event_name')!r}",
            file=sys.stderr,
        )
    return 0
