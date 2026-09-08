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

Per-project routing (SPEC 20, on by default): the trail is keyed by the hook
event's `cwd`, so two projects never braid their histories into one file, and
rolled over into sealed segments once the active one passes 16 MiB. There is
no new environment variable and no flag. `WAXSEAL_TRAIL` still wins on
LOCATION and is NOT a rotation off-switch: a trail named through it rotates
too, and on its first rotation it is adopted as the base segment.

Off-box archiving (`domain/archive.py`) is opt-in and, until this was wired, was
unreachable from any hook at all: `WAXSEAL_ARCHIVE` names where a SEALED
segment is copied — `s3://bucket/prefix/`, or a chain server's `https://`
base URL with `WAXSEAL_ARCHIVE_API_KEY` as its own import-write credential
(deliberately neither `WAXSEAL_API_KEY` nor `WAXSEAL_WITNESS_API_KEY`; see
`integrations/_archive.py`). Rotation itself still takes no environment
variable and no flag — this configures only where its output goes, and unset
means nothing is sent and the rotation line reads `archive_not_attempted`.

Secrets are redacted BEFORE hashing/storage (RegexRedactor), so a key that
Claude leaked into a command or that the user pasted into a prompt reaches
this trail only as ***REDACTED***, unlike the session transcript, which
this hook cannot and does not rewrite.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.integrations import _sanitize as _sanitize_impl
from waxseal.integrations._stdin_hook import run_stdin_hook
from waxseal.integrations._trail import env_trail, home_base, resolve_trail, routed_trail
from waxseal.sources.rotation import DEFAULT_MAX_SEGMENT_BYTES

MAX_FIELD_CHARS = _sanitize_impl.MAX_FIELD_CHARS
_sanitize = _sanitize_impl.sanitize

PAYLOAD_TYPE = "application/vnd.claude-code.hook-event+json"

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


def _trail_target(event: dict[str, Any]) -> str | Path:
    """Where this hook writes: a chain server's base URL, or a local path."""
    env = env_trail()
    if env is not None and _is_remote(env):
        return env
    return _trail_path(event)


def _trail_path(event: dict[str, Any]) -> Path:
    """The local file this hook writes to when no server is configured.

    Precedence is `_trail.resolve_trail`'s, unchanged: an explicit argument,
    then `WAXSEAL_TRAIL`, then the host's own default — which is now routed
    per project rather than shared.
    """
    return resolve_trail(
        default=lambda: routed_trail(_WAXSEAL_HOME(), _project_key(event))
    )


def _WAXSEAL_HOME() -> Path:  # noqa: N802 - a constant-shaped accessor, not a class
    """Claude Code's own waxseal home. FIXED: there is no
    `WAXSEAL_TRAIL_ROOT`, and `WAXSEAL_TRAIL` (above) is the one supported way
    to move the trail."""
    return home_base() / ".claude" / "waxseal"


def _project_key(event: dict[str, Any]) -> str | None:
    """The event's `cwd`, the documented Claude Code hook field."""
    cwd = event.get("cwd")
    return cwd if isinstance(cwd, str) and cwd else None


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


def _open_remote(target: str, event: dict[str, Any]) -> AuditLog:
    # A drop record is a sidecar file NEXT TO the trail, and a URL has
    # no next-to; AuditLog.open rejects the combination outright.
    return AuditLog.open(target, redactor=RegexRedactor(), chain_id=_chain_id(event))


def main() -> int:
    # Every failure path returns 0: any other exit code is at best noise and
    # at worst (exit 2) a veto over the user's tool call or prompt.
    return run_stdin_hook(
        payload_type=PAYLOAD_TYPE,
        build_payload=build_payload,
        resolve_target=_trail_target,
        # The hook passes the built-in constant; the rotation notice says
        # so, so nobody reads 16777216 as something they configured.
        max_segment_bytes=DEFAULT_MAX_SEGMENT_BYTES,
        open_remote=_open_remote,
    )


if __name__ == "__main__":  # pragma: no cover - measured via in-process tests
    sys.exit(main())
