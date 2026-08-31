"""The public read point — no credential, and no write route to need one.

This is not "the same data with authentication turned off". It is a separate
surface, and a test asserts that every route on it is `GET`. Making the read
authority architectural rather than a permission bit is the mirror-node lesson
recorded in the 0.1.5 plan (Workstream G4, adoption 1): a third party auditing
this server should not have to be granted anything by it.

Everything published here is published because the check it supports would
otherwise rest on trusting the server's own word for it.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from waxseal.domain.report import SCOPE_ID, SCOPE_LINE, SCOPE_STATEMENT
from waxseal_server.api.deps import Services, error, error_for
from waxseal_server.api.views import (
    entries_body,
    head_body,
    receipts_head_body,
    witness_body,
)
from waxseal_server.domain.errors import DamagedReceiptLog, InvalidIdentifier


def router(services: Services) -> APIRouter:
    api = APIRouter(prefix="/public/v1", tags=["public"])

    @api.get("/scope")
    def get_scope() -> JSONResponse:
        # Served from the library that owns the frozen prose, so the UI cannot
        # drift from it by retyping. Available with no chains and no credential:
        # the statement qualifies every verdict this server prints, and a
        # qualification that disappears on an empty server is not one.
        return JSONResponse({"id": SCOPE_ID, "statement": SCOPE_STATEMENT, "line": SCOPE_LINE})

    @api.get("/chains")
    def get_chains() -> JSONResponse:
        return JSONResponse({"chains": services.chains.chain_ids()})

    @api.get("/chains/{chain_id}/head")
    def get_head(chain_id: str) -> JSONResponse:
        return head_body(services, chain_id)

    @api.get("/chains/{chain_id}/entries")
    def get_entries(chain_id: str, cursor: str | None = None) -> JSONResponse:
        return entries_body(services, chain_id, cursor)

    @api.get("/chains/{chain_id}/receipts")
    def get_receipts(chain_id: str) -> JSONResponse:
        # The records themselves, not just the server's verdict on them. A third
        # party who has to take the server's word for the server's own
        # acknowledgment history has not checked anything.
        try:
            records = services.chains.receipt_records(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        except DamagedReceiptLog as exc:
            # Not the 404 that means "there is no log", and not a 500 either:
            # unreadable is its own answer.
            return error_for(exc)
        if records is None:
            return error(404, "empty", "no receipts issued for this chain yet")
        return JSONResponse({"receipts": records})

    @api.get("/chains/{chain_id}/receipts/head")
    def get_receipts_head(chain_id: str) -> JSONResponse:
        return receipts_head_body(services, chain_id)

    @api.get("/chains/{chain_id}/receipts/verify")
    def get_receipts_verify(chain_id: str) -> JSONResponse:
        """Is the acknowledgment log internally consistent?"""
        try:
            report = services.chains.verify_receipt_log(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        return JSONResponse(
            {
                "verdict": report.verdict.value,
                "checked": report.checked,
                "reason": report.reason,
                "broken_receipt_seq": report.broken_receipt_seq,
                "exit_code": report.verdict.to_exit_code(),
            }
        )

    @api.get("/chains/{chain_id}/receipts/cross-check")
    def get_receipts_cross_check(chain_id: str) -> JSONResponse:
        """Does entry `seq` still carry the hash that was acknowledged for it?

        The other half of the question `verify` answers, and the half that
        catches a self-consistent local rewrite.
        """
        try:
            report = services.chains.cross_check_receipts(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        return JSONResponse(
            {
                "verdict": report.verdict.value,
                "checked": report.checked,
                "reason": report.reason,
                "broken_seq": report.broken_seq,
                "exit_code": report.verdict.to_exit_code(),
            }
        )

    @api.get("/witness/{witness_id}")
    def get_witness(witness_id: str) -> JSONResponse:
        return witness_body(services, witness_id)

    return api
