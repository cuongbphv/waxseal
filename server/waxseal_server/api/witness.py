"""The witness — a DIFFERENT administrative authority (REMOTE.md section 8).

Its guard is built from `WAXSEAL_WITNESS_API_KEY` alone and never receives the
chain key, so the separation is structural rather than a comparison somebody has
to remember to write: a witness holding the chain's write credential could
append forged entries to the very chain it exists to cross-check.

Nothing here can make a witness hosted beside its own chain meaningful. That is
a deployment decision, and `docs/deployment.md` is where it is stated.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from waxseal_server.api.deps import Guard, Services, error, error_for
from waxseal_server.api.views import witness_body
from waxseal_server.domain.checkpoint import parse_checkpoint
from waxseal_server.domain.errors import InvalidIdentifier, MalformedEnvelope


def router(services: Services, guard: Guard) -> APIRouter:
    api = APIRouter(prefix="/v1", tags=["witness"])

    @api.post("/witness/{witness_id}")
    async def post_witness(
        witness_id: str, request: Request, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = guard(authorization)
        if denied is not None:
            return denied
        try:
            checkpoint = parse_checkpoint(json.loads(await request.body()))
        except json.JSONDecodeError as exc:
            return error(400, "malformed_checkpoint", f"body is not JSON: {exc}")
        except MalformedEnvelope as exc:
            return error_for(exc, "malformed_checkpoint")
        try:
            receipt = services.witnesses.record(witness_id, checkpoint)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_witness_id")
        return JSONResponse(status_code=201, content={"receipt": receipt})

    @api.get("/witness/{witness_id}")
    def get_witness(
        witness_id: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        return guard(authorization) or witness_body(services, witness_id)

    return api
