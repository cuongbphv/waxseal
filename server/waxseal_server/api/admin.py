"""Operators and API keys — the only routes that write anything but a chain.

Everything here mutates the SERVER's own records. None of it can touch a trail:
there is no scope that grants editing an entry, so no credential minted here can
be given one. That is why an Admin's own description reads "manages the server,
its operators and its keys — and cannot edit an entry, because nobody can".

A minted key's plaintext is returned in the `201` and nowhere else, ever. The
store keeps only its SHA-256, so this server cannot show a key twice and cannot
leak every key at once.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from waxseal_server.api.deps import Authorizer, Services, error, error_for, unauthorized
from waxseal_server.domain.errors import (
    InvalidIdentifier,
    NoSuchOperator,
    OperatorExists,
)
from waxseal_server.domain.operators import SCOPE_KEYS_MANAGE, ApiKey, Operator, Role


def operator_json(operator: Operator) -> dict[str, object]:
    return {
        "username": operator.username,
        "display_name": operator.display_name,
        "email": operator.email,
        "role": operator.role.value,
        "created_at": operator.created_at,
        "active": operator.active,
        "scopes": sorted(operator.scopes),
    }


def key_json(key: ApiKey) -> dict[str, object]:
    # No secret and no hash: this dict reaches a template, and a record that
    # could leak a credential by being rendered is a record that eventually will.
    return {
        "key_id": key.key_id,
        "username": key.username,
        "label": key.label,
        "fingerprint": key.fingerprint,
        "created_at": key.created_at,
        "last_used_at": key.last_used_at,
        "revoked_at": key.revoked_at,
        "active": key.active,
    }


async def _json_body(request: Request) -> dict[str, object] | JSONResponse:
    try:
        body = json.loads(await request.body())
    except json.JSONDecodeError as exc:
        return error(400, "malformed_body", f"body is not JSON: {exc}")
    if not isinstance(body, dict):
        return error(400, "malformed_body", "body must be a JSON object")
    return body


def router(services: Services, authz: Authorizer) -> APIRouter:
    api = APIRouter(prefix="/v1", tags=["admin"])

    @api.get("/whoami")
    def get_whoami(authorization: str | None = Header(default=None)) -> JSONResponse:
        """Who this credential is. Needs no scope beyond being a credential.

        The portal calls it to decide what to offer. A synthetic principal —
        the bootstrap key, or an unauthenticated open server — is reported with
        `is_operator: false`, so the UI never lists it as a person.
        """
        principal = authz.principal(authorization)
        if principal is None:
            return unauthorized()
        return JSONResponse(
            {
                "username": principal.operator.username,
                "role": principal.operator.role.value,
                "scopes": sorted(principal.scopes),
                "key_id": principal.key_id,
                # A bootstrap or open-server principal has no record behind it.
                "is_operator": principal.key_id is not None,
            }
        )

    @api.get("/operators")
    def get_operators(authorization: str | None = Header(default=None)) -> JSONResponse:
        return authz.require(authorization, SCOPE_KEYS_MANAGE) or JSONResponse(
            {"operators": [operator_json(o) for o in services.operators.operators()]}
        )

    @api.post("/operators")
    async def post_operator(
        request: Request, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_KEYS_MANAGE)
        if denied is not None:
            return denied
        body = await _json_body(request)
        if isinstance(body, JSONResponse):
            return body
        username = str(body.get("username", ""))
        try:
            role = Role(str(body.get("role", "")))
        except ValueError:
            return error(
                400,
                "invalid_role",
                f"role must be one of {sorted(r.value for r in Role)}",
            )
        try:
            operator = services.operators.create_operator(
                username=username,
                display_name=str(body.get("display_name") or username),
                email=(str(body["email"]) if body.get("email") else None),
                role=role,
            )
        except (InvalidIdentifier, OperatorExists) as exc:
            return error_for(exc)
        return JSONResponse(status_code=201, content=operator_json(operator))

    @api.patch("/operators/{username}")
    async def patch_operator(
        username: str, request: Request, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        """Correct an operator. There is no DELETE.

        An operator who acted is part of the history, and removing the row would
        orphan every key that names them. `active: false` revokes their access
        and leaves the history readable.
        """
        denied = authz.require(authorization, SCOPE_KEYS_MANAGE)
        if denied is not None:
            return denied
        body = await _json_body(request)
        if isinstance(body, JSONResponse):
            return body
        role: Role | None = None
        if "role" in body:
            try:
                role = Role(str(body["role"]))
            except ValueError:
                return error(
                    400,
                    "invalid_role",
                    f"role must be one of {sorted(r.value for r in Role)}",
                )
        active = body.get("active")
        if active is not None and not isinstance(active, bool):
            return error(400, "invalid_active", "active must be true or false")
        try:
            operator = services.operators.update_operator(
                username,
                display_name=(str(body["display_name"]) if body.get("display_name") else None),
                email=(str(body["email"]) if body.get("email") else None),
                # An explicit null means remove it; omitting the key leaves it.
                clear_email="email" in body and body["email"] is None,
                role=role,
                active=active,
            )
        except NoSuchOperator as exc:
            return error_for(exc)
        return JSONResponse(operator_json(operator))

    @api.get("/keys")
    def get_keys(
        username: str | None = None, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        return authz.require(authorization, SCOPE_KEYS_MANAGE) or JSONResponse(
            {"keys": [key_json(k) for k in services.operators.keys(username)]}
        )

    @api.post("/keys")
    async def post_key(
        request: Request, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_KEYS_MANAGE)
        if denied is not None:
            return denied
        body = await _json_body(request)
        if isinstance(body, JSONResponse):
            return body
        try:
            plaintext, record = services.operators.mint_key(
                username=str(body.get("username", "")),
                label=str(body.get("label") or "unnamed"),
            )
        except NoSuchOperator as exc:
            return error_for(exc)
        return JSONResponse(
            status_code=201,
            content={
                **key_json(record),
                # Returned here and nowhere else, ever again.
                "key": plaintext,
                "notice": "copy this now; the server stores only its SHA-256",
            },
        )

    @api.post("/keys/{key_id}/revoke")
    def post_revoke(
        key_id: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_KEYS_MANAGE)
        if denied is not None:
            return denied
        # `revoked` says what THIS call did. A retry reports false rather than
        # moving the timestamp and pretending it acted.
        return JSONResponse({"revoked": services.operators.revoke_key(key_id)})

    return api
