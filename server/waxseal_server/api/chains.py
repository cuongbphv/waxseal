"""The chain API — the write authority, gated by `WAXSEAL_API_KEY`.

This is the surface `RemoteBackend` speaks (REMOTE.md sections 4, 5 and 10). Its
one mutating route is the append, and its precondition is enforced inside the
storage layer's write lock rather than here: a check at this level would be a
race, not a guarantee.
"""

from __future__ import annotations

import json
from typing import Final

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from waxseal_server.api.deps import Authorizer, Services, error, error_for
from waxseal_server.api.views import (
    cli_read_body,
    entries_body,
    head_body,
    receipts_head_body,
    report_args,
)
from waxseal_server.domain.errors import (
    InvalidIdentifier,
    MalformedEnvelope,
    PreconditionFailed,
)
from waxseal_server.domain.operators import (
    SCOPE_ENTRIES_APPEND,
    SCOPE_HEAD_READ,
    SCOPE_PROOF_EXPORT,
    SCOPE_TRAILS_READ,
    SCOPE_VERIFY_RUN,
)
from waxseal_server.runtime.cli import READ_ONLY_COMMANDS

#: Reads offered over a live chain. Every one of these is in
#: `READ_ONLY_COMMANDS`. `segments` and `preflight` were both listed here while
#: the wheel still lacked them, on the rule that the honest answer is
#: "unavailable" from the CLI runner rather than a route that does not exist.
#: 0.1.5 shipped both — Workstreams B and E — and neither route needed a change,
#: which is the point of gating on `available()` instead of on a hard-coded
#: "not yet", and the reason this tuple stays safe to extend ahead of a wheel.
CHAIN_READS: Final[tuple[str, ...]] = ("verify", "report", "inspect", "segments", "preflight")


def router(services: Services, authz: Authorizer) -> APIRouter:
    api = APIRouter(prefix="/v1", tags=["chain"])

    def trail_for(chain_id: str) -> str:
        # The ACTIVE segment, not the base file name: a rotated chain's live
        # history is the newest segment, and `verify`/`inspect`/`export-proof`
        # asked about a sealed one would answer truthfully about the wrong
        # chain. `segments` is the read that speaks about the whole group, and
        # `read_target` already hands it this path's directory.
        return str(services.chains.active_trail_path(chain_id))

    @api.get("/chains/{chain_id}/head")
    def get_head(chain_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        return authz.require(authorization, SCOPE_HEAD_READ) or head_body(services, chain_id)

    @api.post("/chains/{chain_id}/entries")
    async def post_entry(
        chain_id: str, request: Request, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_ENTRIES_APPEND)
        if denied is not None:
            return denied
        try:
            envelope = json.loads(await request.body())
        except json.JSONDecodeError as exc:
            return error(400, "malformed_envelope", f"body is not JSON: {exc}")
        try:
            result = services.chains.append(chain_id, envelope)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        except MalformedEnvelope as exc:
            return error_for(exc)
        except PreconditionFailed as exc:
            # Never a 400: the client's correct response is to re-read /head and
            # rebuild, and only 409 tells it that.
            return error(409, "conflict", str(exc))
        return JSONResponse(
            status_code=201,
            content={"receipt_seq": result.receipt_seq, "receipt_head": result.receipt_head},
        )

    @api.get("/chains/{chain_id}/entries")
    def get_entries(
        chain_id: str,
        cursor: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        return authz.require(authorization, SCOPE_TRAILS_READ) or entries_body(
            services, chain_id, cursor
        )

    @api.get("/chains/{chain_id}/receipts/head")
    def get_receipts_head(chain_id: str) -> JSONResponse:
        # No guard by design (REMOTE.md section 10): the write credential grants
        # nothing here, and a third party auditing what this server has
        # acknowledged is the reason the endpoint exists.
        return receipts_head_body(services, chain_id)

    @api.get("/chains/{chain_id}/summary")
    def get_summary(
        chain_id: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_TRAILS_READ)
        if denied is not None:
            return denied
        try:
            summary = services.chains.summary(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        return JSONResponse(
            {
                "chain_id": summary.chain_id,
                "entries": summary.entries,
                "size_bytes": summary.size_bytes,
                # null, not a zeroed pair: seq 0 is a real entry, so there is no
                # in-band value that could mean "no head".
                "head": (
                    None
                    if summary.head is None
                    else {"seq": summary.head[0], "entry_hash": summary.head[1]}
                ),
                "receipt": (
                    None
                    if summary.receipt is None
                    else {
                        "receipt_seq": summary.receipt[0],
                        "receipt_head": summary.receipt[1],
                    }
                ),
            }
        )

    @api.get("/chains/{chain_id}/export-proof/{seq}")
    def get_export_proof(
        chain_id: str, seq: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_PROOF_EXPORT)
        if denied is not None:
            return denied
        if not seq.isdigit():
            return error(400, "invalid_seq", f"seq must be a non-negative integer, got {seq!r}")
        try:
            trail = trail_for(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        return cli_read_body(services, trail, "export-proof", seq)

    @api.get("/chains/{chain_id}/{command}")
    def get_chain_read(
        chain_id: str, command: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        # One route for every CLI-backed read, driven by CHAIN_READS. Adding a
        # read is one tuple entry, not a handler — which is how B's `segments`
        # and E's `preflight` both arrived in 0.1.5 with no handler written.
        denied = authz.require(authorization, SCOPE_VERIFY_RUN)
        if denied is not None:
            return denied
        if command not in CHAIN_READS:
            return error(404, "no_such_read", f"{command!r} is not a read this server offers")
        try:
            trail = trail_for(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        return cli_read_body(services, trail, command, *report_args(command))

    @api.get("/capabilities")
    def get_capabilities() -> JSONResponse:
        # Present-and-false, never omitted: "this build has no segments command"
        # and "the server did not answer" are different facts, and a UI that
        # cannot tell them apart will draw the wrong screen for one of them.
        available = services.cli.available()
        return JSONResponse(
            {"commands": {name: name in available for name in sorted(READ_ONLY_COMMANDS)}}
        )

    @api.get("/meta")
    def get_meta() -> JSONResponse:
        settings = services.settings
        # A server with no key configured is OPEN. Saying so is CLAUDE.md rule
        # 6: the degradation is in the output, never swallowed.
        return JSONResponse(
            {
                "version": "0.1.5",
                "write_auth": "bearer_required" if authz.locked() else "open",
                "witness_auth": "bearer_required" if settings.witness_api_key else "open",
                "public_read": "/public/v1",
                "web_ui": settings.web_ui_state,
            }
        )

    return api
