"""Scope checks for the write authority, and the single-credential witness guard.

Authorisation is a scope check, not a boolean. A route names the scope it needs
and `Authorizer` decides; the role table in `domain/operators.py` decides what a
scope belongs to. That indirection is the whole point: the writer account the
Claude Code hook uses can append and read the head, and cannot read the trail it
is appending to, without any route knowing that a writer exists.

The witness authority is deliberately NOT part of this. It has its own guard,
built from its own credential, because REMOTE.md section 8 requires a witness to
be a different administrative authority — and a witness that accepted an
operator key would be one this server administers.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Final

from fastapi.responses import JSONResponse

from waxseal_server.api._http_errors import forbidden, unauthorized
from waxseal_server.domain.clock import utc_now
from waxseal_server.domain.operators import Operator, Principal, Role, scopes_for_role
from waxseal_server.ports.operators import OperatorStore

BEARER_PREFIX: Final = "Bearer "

#: The bootstrap credential (`WAXSEAL_API_KEY`). It exists so a fresh deployment
#: can mint its first real key, and it is NOT an operator: it has no name, no
#: history, and nothing in the store. The portal labels it as such rather than
#: showing it in the operator list.
BOOTSTRAP_USERNAME: Final = "bootstrap"

#: A deployment with no credential configured anywhere. Every request is
#: admitted and `/v1/meta` reports `write_auth: open`, because a fail-open that
#: describes itself as secured is the false-confidence half of the collapse this
#: whole project exists to prevent (CLAUDE.md rule 6).
OPEN_USERNAME: Final = "unauthenticated"


def _synthetic(username: str) -> Operator:
    return Operator(
        username=username,
        display_name=username,
        email=None,
        role=Role.ADMIN,
        created_at=utc_now(),
    )


def bearer(authorization: str | None) -> str | None:
    if authorization is None or not authorization.startswith(BEARER_PREFIX):
        return None
    return authorization[len(BEARER_PREFIX) :]


Guard = Callable[[str | None], "JSONResponse | None"]


def guard_for(expected: str | None) -> Guard:
    """A single-credential guard, for an authority that has no operators.

    The witness uses this and nothing else. Built per-credential so the witness
    guard cannot accidentally consult the chain key or an operator key: it never
    receives either. REMOTE.md section 8 requires that separation, because a
    witness holding the chain's write credential could append forged entries to
    the very chain it cross-checks.
    """

    def guard(authorization: str | None) -> JSONResponse | None:
        if expected is None:
            return None
        token = bearer(authorization)
        if token is None or not secrets.compare_digest(token, expected):
            return unauthorized()
        return None

    return guard


class Authorizer:
    """Resolves a bearer token to a principal, and a principal to a yes or no."""

    def __init__(self, *, bootstrap_key: str | None, operators: OperatorStore) -> None:
        self._bootstrap = bootstrap_key
        self._operators = operators

    def locked(self) -> bool:
        """Whether this deployment requires a credential at all.

        True as soon as EITHER a bootstrap key is configured or one real key has
        been minted — so seeding an operator is what secures a server, rather
        than a separate step somebody can forget.
        """
        return self._bootstrap is not None or self._operators.has_active_key()

    def principal(self, authorization: str | None) -> Principal | None:
        if not self.locked():
            return Principal(
                operator=_synthetic(OPEN_USERNAME),
                key_id=None,
                scopes=scopes_for_role(Role.ADMIN),
            )
        token = bearer(authorization)
        if token is None:
            return None
        if self._bootstrap is not None and secrets.compare_digest(token, self._bootstrap):
            return Principal(
                operator=_synthetic(BOOTSTRAP_USERNAME),
                key_id=None,
                scopes=scopes_for_role(Role.ADMIN),
            )
        return self._operators.authenticate(token)

    def require(self, authorization: str | None, scope: str) -> JSONResponse | None:
        """None when the call may proceed, otherwise the refusal to return.

        Returning a response rather than raising keeps the check visible on the
        handler's first line — `return authz.require(...) or body(...)` — instead
        of hiding in a decorator.
        """
        principal = self.principal(authorization)
        if principal is None:
            return unauthorized()
        if not principal.allows(scope):
            return forbidden(scope)
        return None
