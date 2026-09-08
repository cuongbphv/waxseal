"""The one mutating chain route: POST an entry under the CAS precondition."""

from __future__ import annotations

import json

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from waxseal_server.api.deps import Authorizer, Services, error, error_for
from waxseal_server.domain.errors import (
    InvalidIdentifier,
    MalformedEnvelope,
    PreconditionFailed,
)
from waxseal_server.domain.operators import SCOPE_ENTRIES_APPEND


def router(services: Services, authz: Authorizer) -> APIRouter:
    api = APIRouter()

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

    return api
