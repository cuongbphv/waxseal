#!/usr/bin/env python3
"""waxseal-audit hook for Claude Code.

Appends every hook event (tool dispatch, tool result, user prompt, session
lifecycle) to a tamper-evident hash chain. Configure it under "hooks" in
settings.json (see the repo's integrations/claude-code/README.md). Requires
`pip install waxseal` in the interpreter this script runs under.

Contract verified against https://code.claude.com/docs/en/hooks.md (2026-08):

- One JSON event arrives on stdin. PreToolUse carries tool_name + tool_input;
  PostToolUse adds tool_output (older releases: tool_response);
  UserPromptSubmit carries prompt.
- Exit code 2 BLOCKS the tool call (PreToolUse) or the prompt
  (UserPromptSubmit). An audit observer therefore exits 0 on EVERY path,
  including its own failures, because a broken audit disk must never veto work.
- On UserPromptSubmit, exit-0 stdout is INJECTED INTO MODEL CONTEXT, and on
  other events stdout is parsed for decision JSON. This script never writes
  to stdout; diagnostics go to stderr (shown as a non-blocking notice).

Secrets are redacted BEFORE hashing/storage (RegexRedactor), so a key that
Claude leaked into a command or that the user pasted into a prompt reaches
this trail only as ***REDACTED***, unlike the session transcript, which
this hook cannot and does not rewrite.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor

# _sanitize redacts BEFORE clipping: a clip can split a secret across the
# boundary (a PEM losing its END marker stops matching) and land it on disk.
_REDACTOR = RegexRedactor()

PAYLOAD_TYPE = "application/vnd.claude-code.hook-event+json"

# Tool outputs can be megabytes (file reads, terminal dumps). Clip stored
# fields, visibly, because silent truncation would read as "the full output".
MAX_FIELD_CHARS = 4096

# Common fields recorded for every event; per-event fields added below.
_COMMON_FIELDS = (
    "session_id", "cwd", "permission_mode", "tool_use_id",
    "tool_name", "tool_input", "prompt", "agent_id", "agent_type",
)


#: A `WAXSEAL_TRAIL` naming one of these is a chain SERVER (REMOTE.md), not a
#: file. `AuditLog.open` already dispatches on the scheme; the hook's job is to
#: keep the value a `str` so it reaches that check — `Path("http://host")`
#: collapses the `//` and drops the scheme, and the target would silently
#: become a local file named `http:`.
_REMOTE_SCHEMES = ("http://", "https://")

# A chain id may only be a safe path segment on the server, so a directory name
# is folded to lowercase and everything else becomes a separator.
_CHAIN_ID_UNSAFE = re.compile(r"[^a-z0-9._-]+")


def _is_remote(target: str) -> bool:
    return target.startswith(_REMOTE_SCHEMES)


def _chain_id(event: dict[str, Any]) -> str:
    """Which chain a remote append belongs to.

    One server holds many projects' trails, so a hook that always wrote to
    "default" would braid every project a developer touches into one chain.
    `WAXSEAL_CHAIN_ID` wins; otherwise the project directory names it.

    This is the minimal form of the per-project routing Workstream B specifies
    for local trails. It is deliberately not that slug: a chain id is read by
    people in a portal, and `waxseal` is a better name there than
    `waxseal-3f9a12bc84de`.
    """
    explicit = os.environ.get("WAXSEAL_CHAIN_ID")
    if explicit:
        return explicit
    cwd = event.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        return "default"
    name = _CHAIN_ID_UNSAFE.sub("-", PurePosixPath(cwd).name.lower()).strip("-._")
    return name or "default"


def _trail_target() -> str | Path:
    """Where this hook writes: a chain server's base URL, or a local path."""
    env = os.environ.get("WAXSEAL_TRAIL")
    if env and _is_remote(env):
        return env
    return _trail_path()


def _trail_path() -> Path:
    """The local file this hook writes to when no server is configured."""
    env = os.environ.get("WAXSEAL_TRAIL")
    if env:
        return Path(env)
    # HOME before Path.home(): ntpath resolves "~" from USERPROFILE and
    # ignores HOME, so a host that launches this hook with HOME set would
    # strand the trail in the wrong profile on Windows.
    home = os.environ.get("HOME")
    base = Path(home) if home else Path.home()
    return base / ".claude" / "waxseal" / "trail.jsonl"


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
    # tool_output is the documented field; tool_response is what older
# releases sent, so store either under one key so trails stay uniform.
    if "tool_output" in event or "tool_response" in event:
        payload["tool_output"] = _sanitize(event.get("tool_output", event.get("tool_response")))
    return payload


def main() -> int:
    # Every failure path returns 0: any other exit code is at best noise and
    # at worst (exit 2) a veto over the user's tool call or prompt.
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook event must be a JSON object")
    except Exception as e:
        print(f"[waxseal-audit] unreadable hook event (entry dropped): {e}", file=sys.stderr)
        return 0
    target = _trail_target()
    remote = isinstance(target, str)
    try:
        if remote:
            # A drop record is a sidecar file NEXT TO the trail, and a URL has
            # no next-to; AuditLog.open rejects the combination outright.
            log = AuditLog.open(
                target, redactor=RegexRedactor(), chain_id=_chain_id(event)
            )
        else:
            log = AuditLog.open(target, redactor=RegexRedactor(), record_drops=True)
    except Exception as e:
        print(f"[waxseal-audit] cannot open trail (entry dropped): {e}", file=sys.stderr)
        if remote:
            # Nowhere to record it: the loss is labelled on stderr and nothing
            # else, which is still better than inventing a sidecar location.
            return 0
        # No AuditLog to route this through, so record it directly. Best-effort
        # (FileDropRecorder.record() never raises): a trail we cannot even
        # open must not become a second failure on top of the first.
        from waxseal.adapters.drops import FileDropRecorder

        FileDropRecorder(target).record(reason=type(e).__name__, payload_type=PAYLOAD_TYPE)
        return 0
    if not log.try_append(payload=build_payload(event), payload_type=PAYLOAD_TYPE):
        # Labelled fail-open (chain integrity ≠ trail completeness): the loss
        # is visible in the hook notice, never silent.
        print(
            f"[waxseal-audit] dropped write for {event.get('hook_event_name')!r}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover - measured via in-process tests
    sys.exit(main())
