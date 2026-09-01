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

from waxseal_server.api.deps import Authorizer, Services, error, error_for, outcome_json
from waxseal_server.api.views import (
    cli_read_body,
    entries_body,
    head_body,
    parsed_cli_body,
    receipts_head_body,
    report_args,
)
from waxseal_server.domain.errors import (
    InvalidIdentifier,
    MalformedEnvelope,
    PreconditionFailed,
)
from waxseal_server.domain.identifiers import (
    require_chain_id,
    require_issued_spec,
    require_measurement,
    require_positive_int,
    require_root,
    require_whole_number,
)
from waxseal_server.domain.operators import (
    SCOPE_ENTRIES_APPEND,
    SCOPE_HEAD_READ,
    SCOPE_PROOF_EXPORT,
    SCOPE_TRAILS_READ,
    SCOPE_VERIFY_RUN,
)
from waxseal_server.domain.settings import rpc_endpoints
from waxseal_server.runtime.cli import READ_ONLY_COMMANDS

#: Reads offered over a live chain. Every one of these is in
#: `READ_ONLY_COMMANDS`. `segments` and `preflight` were both listed here while
#: the wheel still lacked them, on the rule that the honest answer is
#: "unavailable" from the CLI runner rather than a route that does not exist.
#: 0.1.5 shipped both — Workstreams B and E — and neither route needed a change,
#: which is the point of gating on `available()` instead of on a hard-coded
#: "not yet", and the reason this tuple stays safe to extend ahead of a wheel.
CHAIN_READS: Final[tuple[str, ...]] = (
    "verify",
    "report",
    "inspect",
    "segments",
    "preflight",
    # Takes no flag, so it needs no handler of its own — the reason this tuple
    # exists. `checkpoint` prints the (seq, entry_hash, root) an operator pins
    # or anchors against.
    "checkpoint",
)


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
        return cli_read_body(
            services, trail, "consistency", "--old-seq", seq, "--old-root", root
        )

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

    @api.get("/chains/{chain_id}/ledger-status")
    def get_ledger_status(
        chain_id: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        """On-chain status for this trail, from the stored ledger settings.

        The one read whose arguments come from the settings store rather than
        the request: an operator configures the endpoints once, and a caller
        cannot point this server's RPC client at a host of their choosing.

        Three outcomes and none of them is a fabricated status. With no liveness
        address there is no command to run, so the answer is `not_configured` —
        a state, never an error and never a green tick borrowed from a chain
        nobody queried. With one endpoint the command itself refuses, and its
        `unverifiable` is carried through verbatim: one endpoint cannot disagree
        with itself, which is the eclipse a single voice would hide.
        """
        denied = authz.require(authorization, SCOPE_VERIFY_RUN)
        if denied is not None:
            return denied
        try:
            trail = trail_for(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")

        held = services.config.all()
        liveness = held.get("ledger_liveness_address")
        if liveness is None:
            # Reported as a first-class state with the key that would fix it.
            # A 404 here would make "nobody configured this" look like a bug.
            return JSONResponse(
                {
                    "configured": False,
                    "reason": "no_liveness_address",
                    "missing": ["ledger_liveness_address"],
                    "outcome": None,
                }
            )

        args: list[str] = []
        for endpoint in rpc_endpoints(held.get("ledger_rpc_urls")):
            args += ["--rpc", endpoint]
        args += ["--liveness", liveness]
        for key, flag in (
            ("ledger_registry_address", "--registry"),
            ("ledger_bond_address", "--bond"),
            ("ledger_writer_address", "--writer"),
            ("ledger_trail_id", "--trail-id"),
        ):
            value = held.get(key)
            if value is not None:
                args += [flag, value]

        # The command requires `--writer` with `--bond`. Refused here rather
        # than sent: argparse would answer with a usage error, which
        # `CliOutcome` correctly reports as `usage_error` — a server bug wearing
        # no verdict. Naming the missing setting instead is the useful answer.
        if "--bond" in args and "--writer" not in args:
            return JSONResponse(
                {
                    "configured": False,
                    "reason": "bond_without_writer",
                    "missing": ["ledger_writer_address"],
                    "outcome": None,
                }
            )

        # `outcome_json` rather than `cli_read_body`: the outcome is nested under
        # `configured` here, and re-parsing a rendered response to nest it would
        # be serialising a body just to take it apart again.
        outcome = outcome_json(services.cli.run("ledger-status", trail, *args, "--json"))
        return JSONResponse(
            {"configured": True, "reason": None, "missing": [], "outcome": outcome}
        )

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

    @api.get("/cadence")
    def get_cadence(
        lam: str,
        c: str,
        w: str,
        rho: str,
        delta: str,
        t_max: str,
        m: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        """The cost-optimal anchoring cadence, from measurements only.

        The one read on this server that opens no trail: every input is supplied
        by the operator, so a server holding no chains at all can still answer
        it. Each parameter is required and none has a default — a cadence
        computed from a number this server chose would be advice nobody
        measured, printed with the confidence of advice somebody did.
        """
        denied = authz.require(authorization, SCOPE_VERIFY_RUN)
        if denied is not None:
            return denied
        supplied = {"lam": lam, "c": c, "w": w, "rho": rho, "delta": delta, "t-max": t_max}
        if m is not None:
            supplied["M"] = m
        args: list[str] = []
        for flag, value in supplied.items():
            try:
                args += [f"--{flag}", require_measurement(value, flag)]
            except InvalidIdentifier as exc:
                return error_for(exc, "invalid_measurement")
        return JSONResponse(outcome_json(services.cli.run("cadence", *args)))

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
