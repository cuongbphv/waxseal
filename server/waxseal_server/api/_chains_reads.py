"""Chain reads whose bodies already live in `views.py`, plus flagged CLI reads.

`ledger-status` and `cadence` are not here: they assemble argv from settings
or measurements, which is `runtime/`, and they must register BEFORE the
`{command}` catch-all in the parent facade.
"""

from __future__ import annotations

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from waxseal_server.api.deps import Authorizer, Services, error, error_for
from waxseal_server.api.views import (
    cli_read_body,
    entries_body,
    head_body,
    parsed_cli_body,
    receipts_head_body,
)
from waxseal_server.domain.errors import InvalidIdentifier
from waxseal_server.domain.identifiers import (
    require_chain_id,
    require_issued_spec,
    require_positive_int,
    require_root,
    require_whole_number,
)
from waxseal_server.domain.operators import (
    SCOPE_HEAD_READ,
    SCOPE_PROOF_EXPORT,
    SCOPE_TRAILS_READ,
    SCOPE_VERIFY_RUN,
)


def router(services: Services, authz: Authorizer) -> APIRouter:
    api = APIRouter()

    def trail_for(chain_id: str) -> str:
        return str(services.chains.active_trail_path(chain_id))

    @api.get("/chains/{chain_id}/head")
    def get_head(chain_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        return authz.require(authorization, SCOPE_HEAD_READ) or head_body(services, chain_id)

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

    # ------------------------------------------------------- reads with a flag
    #
    # These five cannot ride the catch-all below, because each turns a query
    # parameter into an element of `argv`. Every one validates before the
    # subprocess exists: a validator that rejects afterwards has already run the
    # command it meant to prevent. They are declared BEFORE the catch-all so
    # they win the route match rather than arriving as an unknown command.

    @api.get("/chains/{chain_id}/tail")
    def get_tail(
        chain_id: str,
        n: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        # TRAILS_READ, not VERIFY_RUN: `tail` prints entry content, so it is the
        # same disclosure as `/entries` and answers to the same scope. A writer
        # key must not be able to read back the trail it extends.
        denied = authz.require(authorization, SCOPE_TRAILS_READ)
        if denied is not None:
            return denied
        # Validated one at a time so each failure keeps its own label. Sharing a
        # try block would make the code depend on which check ran first.
        count: tuple[str, ...] = ()
        if n is not None:
            try:
                # Absent means the CLI's own default, never one restated here.
                count = ("-n", require_positive_int(n, "n"))
            except InvalidIdentifier as exc:
                return error_for(exc, "invalid_count")
        try:
            trail = trail_for(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        return cli_read_body(services, trail, "tail", *count)

    @api.get("/chains/{chain_id}/consistency")
    def get_consistency(
        chain_id: str,
        old_seq: str,
        old_root: str,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_VERIFY_RUN)
        if denied is not None:
            return denied
        try:
            seq = require_whole_number(old_seq, "old_seq")
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_seq")
        try:
            root = require_root(old_root, "old_root")
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_root")
        try:
            trail = trail_for(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        return cli_read_body(services, trail, "consistency", "--old-seq", seq, "--old-root", root)

    @api.get("/chains/{chain_id}/verify-handoff")
    def get_verify_handoff(
        chain_id: str,
        origin: str,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_VERIFY_RUN)
        if denied is not None:
            return denied
        try:
            # The origin is a chain id on THIS server, resolved to a path here.
            # Accepting a path from the caller would let a request name any file
            # on the host as the origin history.
            origin_trail = str(services.chains.active_trail_path(require_chain_id(origin)))
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_origin_id")
        try:
            trail = trail_for(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        return cli_read_body(services, trail, "verify-handoff", "--origin", origin_trail)

    @api.get("/chains/{chain_id}/reconcile-tickets")
    def get_reconcile_tickets(
        chain_id: str,
        issuer: str,
        lease_size: str,
        issued: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_VERIFY_RUN)
        if denied is not None:
            return denied
        try:
            issuer_name = require_chain_id(issuer)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_issuer")
        try:
            size = require_positive_int(lease_size, "lease_size")
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_lease_size")
        spec: tuple[str, ...] = ()
        if issued is not None:
            try:
                spec = ("--issued", require_issued_spec(issued))
            except InvalidIdentifier as exc:
                return error_for(exc, "invalid_issued")
        try:
            trail = trail_for(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        return parsed_cli_body(
            services,
            trail,
            "reconcile-tickets",
            "--issuer",
            issuer_name,
            "--lease-size",
            size,
            *spec,
            "--json",
        )

    return api
