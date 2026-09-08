"""Configuration, in one place — and the refusals stated beside it.

The screen this serves exists because the configuration was previously spread
across a process environment nobody could see from the browser and a handful of
constants nobody could change without a redeploy. Both halves are here now, and
they are deliberately NOT the same half:

* `deployment` is what this process was started with. Read-only, because
  changing it means restarting the process that holds it.
* `stored` is what an operator may change without a redeploy.

A secret is never sent. `WAXSEAL_API_KEY`, `WAXSEAL_WITNESS_API_KEY` and the
database URL report only whether they are SET — the value never leaves the
server, in either direction. That is why this screen cannot become a way to read
a credential out of a deployment, which is the failure mode a "show me the
config" page invites.

`keys:manage` guards all of it, including the read. The deployment half
describes where a server keeps its data and which authorities are closed, which
is administrative reconnaissance rather than an audit finding — an auditor's
`trails:read` deliberately does not reach it.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from waxseal_server.api.deps import Authorizer, Services, error, error_for
from waxseal_server.domain.errors import InvalidIdentifier, NoSuchSetting
from waxseal_server.domain.operators import SCOPE_KEYS_MANAGE
from waxseal_server.domain.settings import FORBIDDEN, SPECS


def _secret_row(key: str, env: str, present: bool) -> dict[str, object]:
    """A credential, described but never disclosed.

    `state` is the whole row: "set" or "unset" and nothing else. There is no
    field this could put a value in, so no future edit here can start leaking
    one by accident.
    """
    return {
        "key": key,
        "env": env,
        "state": "set" if present else "unset",
        "secret": True,
        "editable": False,
        "reason": FORBIDDEN[key],
    }


def router(services: Services, authz: Authorizer) -> APIRouter:
    api = APIRouter(prefix="/v1", tags=["settings"])

    def deployment_rows() -> list[dict[str, object]]:
        s = services.settings
        return [
            # Paths, not secrets: an operator debugging "where did my trail go"
            # needs these, and they are already in the process listing.
            {
                "key": "data_dir",
                "env": "WAXSEAL_SERVER_DATA_DIR",
                "value": str(s.data_dir),
                "secret": False,
                "editable": False,
                "reason": FORBIDDEN["data_dir"],
            },
            {
                "key": "chains_dir",
                "env": None,
                "value": str(s.chains_dir),
                "secret": False,
                "editable": False,
                "reason": "derived_from_data_dir",
            },
            {
                "key": "web_ui",
                "env": None,
                "value": s.web_ui_state,
                "secret": False,
                "editable": False,
                "reason": "derived_from_the_build",
            },
            # `write_auth` and `witness_auth` are the two that matter most on
            # this screen: "open" is a real deployment state and rule 6 requires
            # it be visible rather than implied by an absent row.
            {
                "key": "write_auth",
                "env": None,
                "value": "bearer_required" if authz.locked() else "open",
                "secret": False,
                "editable": False,
                "reason": "derived_from_the_credentials_in_use",
            },
            {
                "key": "witness_auth",
                "env": None,
                "value": "bearer_required" if s.witness_api_key else "open",
                "secret": False,
                "editable": False,
                "reason": "derived_from_the_credentials_in_use",
            },
            _secret_row("api_key", "WAXSEAL_API_KEY", s.api_key is not None),
            _secret_row(
                "witness_api_key", "WAXSEAL_WITNESS_API_KEY", s.witness_api_key is not None
            ),
            _secret_row("database_url", "WAXSEAL_SERVER_DATABASE_URL", s.database_url is not None),
        ]

    def stored_rows() -> list[dict[str, object]]:
        held = services.config.all()
        return [
            {
                "key": spec.key,
                "kind": spec.kind.value,
                # The value in effect, and where it came from. A stored value
                # equal to the default is still `stored`: "somebody chose this"
                # and "nobody has touched it" are different facts.
                "value": held.get(spec.key, spec.default),
                "source": "stored" if spec.key in held else "default",
                "default": spec.default,
                "secret": False,
                "editable": True,
            }
            for spec in SPECS
        ]

    @api.get("/settings")
    def get_settings(authorization: str | None = Header(default=None)) -> JSONResponse:
        return authz.require(authorization, SCOPE_KEYS_MANAGE) or JSONResponse(
            {
                "deployment": deployment_rows(),
                "stored": stored_rows(),
                # Which store is answering. The in-memory one forgets on
                # restart, so an operator whose ledger endpoint vanished has the
                # reason on the screen rather than in a support thread.
                "backend": "memory" if services.settings.database_url is None else "postgres",
            }
        )

    @api.put("/settings/{key}")
    async def put_setting(
        key: str, request: Request, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_KEYS_MANAGE)
        if denied is not None:
            return denied
        try:
            body = json.loads(await request.body())
        except json.JSONDecodeError as exc:
            return error(400, "malformed_body", f"body is not JSON: {exc}")
        if not isinstance(body, dict) or not isinstance(body.get("value"), str):
            return error(400, "malformed_body", 'body must be {"value": "<string>"}')
        try:
            stored = services.config.set(key, body["value"])
        except NoSuchSetting as exc:
            # 404 rather than 400, and the message says whether the key is
            # unknown or deliberately environment-only.
            return error_for(exc)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_setting_value")
        return JSONResponse({"key": key, "value": stored, "source": "stored"})

    @api.post("/settings/{key}/reset")
    def post_reset(key: str, authorization: str | None = Header(default=None)) -> JSONResponse:
        """Revert one setting to its default.

        A POST rather than a DELETE, matching `keys/{key_id}/revoke`: this
        server has no DELETE anywhere, and `test_there_is_no_delete_anywhere`
        holds that line. `reset` reports what THIS call did, so a retry answers
        false rather than claiming it acted.
        """
        denied = authz.require(authorization, SCOPE_KEYS_MANAGE)
        if denied is not None:
            return denied
        try:
            reset = services.config.unset(key)
        except NoSuchSetting as exc:
            return error_for(exc)
        return JSONResponse({"key": key, "reset": reset})

    return api
