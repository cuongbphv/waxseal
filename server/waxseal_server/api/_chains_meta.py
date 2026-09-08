"""Ledger-status, cadence, capabilities, and meta — argv lives in `runtime/`."""

from __future__ import annotations

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from waxseal_server.api.deps import Authorizer, Services, error_for, outcome_json
from waxseal_server.domain.errors import InvalidIdentifier
from waxseal_server.domain.operators import SCOPE_VERIFY_RUN
from waxseal_server.runtime.cadence import cadence_argv
from waxseal_server.runtime.cli import READ_ONLY_COMMANDS
from waxseal_server.runtime.ledger import ledger_status_argv


def router(services: Services, authz: Authorizer) -> APIRouter:
    api = APIRouter()

    def trail_for(chain_id: str) -> str:
        return str(services.chains.active_trail_path(chain_id))

    @api.get("/chains/{chain_id}/ledger-status")
    def get_ledger_status(
        chain_id: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        """On-chain status for this trail, from the stored ledger settings.

        The one read whose arguments come from the settings store rather than
        the request: an operator configures the endpoints once, and a caller
        cannot point this server's RPC client at a host of their choosing.

        Three outcomes and none of them is a fabricated status. With no liveness
        address there is no command to run, so the answer is `not_configured`
        — a state, never an error and never a green tick borrowed from a chain
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

        reason, missing, args = ledger_status_argv(services.config.all())
        if reason is not None:
            # Reported as a first-class state with the key that would fix it.
            # A 404 here would make "nobody configured this" look like a bug.
            return JSONResponse(
                {
                    "configured": False,
                    "reason": reason,
                    "missing": missing,
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
        try:
            args = cadence_argv(supplied)
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
