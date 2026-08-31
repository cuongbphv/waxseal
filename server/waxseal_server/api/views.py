"""Response bodies shared by the credentialed and public read surfaces.

The same four reads are served under `/v1` (behind the write credential) and
under `/public/v1` (behind nothing). Writing the body once and mounting it twice
is what keeps the two from drifting: a fix to how an empty chain is reported
cannot land on one surface and miss the other.

The authorities still differ, and that difference lives in the routers. This
module knows how to render an answer; it does not know who is allowed to ask.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from fastapi.responses import JSONResponse

from waxseal_server.api.deps import Services, error, error_for, outcome_json
from waxseal_server.domain.errors import InvalidIdentifier

#: `report` is the one read whose stdout the server parses, because the UI needs
#: the fields rather than the text. Everything else is handed over verbatim.
JSON_REPORT_FLAG = "--json"

#: Reads whose subject is the DIRECTORY holding the trail, not the trail file.
#:
#: `waxseal segments` walks a segment group and the rotation bindings between its
#: files (SPEC.md section 20). Handed a trail file instead it printed "no such
#: segment directory" and exited 3, so every chain — rotated or not, intact or
#: not — reported `absent` about a directory that does exist. That is not a
#: verdict anyone computed, and it is the state CLAUDE.md rule 5 forbids
#: collapsing into. Workstream B shipped the command while forbidden from
#: touching `server/`, so this side was never adjusted (waxseal-fg4.16).
DIRECTORY_READS: Final[frozenset[str]] = frozenset({"segments"})


def head_body(services: Services, chain_id: str) -> JSONResponse:
    try:
        head = services.chains.head(chain_id)
    except InvalidIdentifier as exc:
        return error_for(exc, "invalid_chain_id")
    if head is None:
        # REMOTE.md section 4: 404 means "no entries yet". A fresh writer reads
        # it as (seq=-1, GENESIS); it is never an error.
        return error(404, "empty", "this chain has no entries yet")
    return JSONResponse({"seq": head[0], "entry_hash": head[1]})


def entries_body(services: Services, chain_id: str, cursor: str | None) -> JSONResponse:
    try:
        page, next_cursor = services.chains.page(
            chain_id, cursor=cursor, limit=services.settings.page_size
        )
    except InvalidIdentifier as exc:
        return error_for(exc, "invalid_chain_id")
    except ValueError as exc:
        return error(400, "invalid_cursor", str(exc))
    if not page and cursor is None:
        return error(404, "empty", "this chain has no entries yet")
    return JSONResponse({"entries": page, "next_cursor": next_cursor})


def receipts_head_body(services: Services, chain_id: str) -> JSONResponse:
    try:
        head = services.chains.receipt_head(chain_id)
    except InvalidIdentifier as exc:
        return error_for(exc, "invalid_chain_id")
    if head is None:
        return error(404, "empty", "no receipts issued for this chain yet")
    return JSONResponse({"receipt_seq": head[0], "receipt_head": head[1]})


def witness_body(services: Services, witness_id: str) -> JSONResponse:
    try:
        records = services.witnesses.checkpoints(witness_id)
    except InvalidIdentifier as exc:
        return error_for(exc, "invalid_witness_id")
    if not records:
        # REMOTE.md section 8: "this witness has seen nothing" is an answer.
        return error(404, "empty", "this witness has seen nothing yet")
    return JSONResponse({"checkpoints": records})


def cli_read_body(services: Services, trail: str, command: str, *args: str) -> JSONResponse:
    """Run one read through the CLI and render its outcome.

    `command` comes from a fixed set and `trail` is derived from a validated id,
    never from the request: the caller chooses which read to perform, never what
    to run.
    """
    body = outcome_json(services.cli.run(command, read_target(command, trail), *args))
    if command == "report":
        try:
            body["report"] = json.loads(body["stdout"])
        except json.JSONDecodeError:
            # No report to show — an absent or unreadable trail prints nothing.
            # None is "no report", never an empty one.
            body["report"] = None
    return JSONResponse(body)


def report_args(command: str) -> tuple[str, ...]:
    return (JSON_REPORT_FLAG,) if command == "report" else ()


def read_target(command: str, trail: str) -> str:
    """The path this read is actually about.

    Derived from the trail rather than taken from the request, so the caller
    still chooses only which read to perform — never what to point it at.
    """
    return str(Path(trail).parent) if command in DIRECTORY_READS else trail
