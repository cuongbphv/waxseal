"""What every router needs: the services it talks to, and who may call it.

`Services` is constructed once in `app.py` and handed to each router factory.
Explicit injection rather than module-level globals is what lets a test stand up
two servers with different credentials in one process, and what keeps a router
honest about its dependencies — a module that needs the CLI has to say so.

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
from dataclasses import dataclass
from typing import Any, Final

from fastapi.responses import JSONResponse

from waxseal_server.config import Settings
from waxseal_server.domain.clock import utc_now
from waxseal_server.domain.errors import (
    DamagedReceiptLog,
    InvalidIdentifier,
    MalformedEnvelope,
    NoSuchOperator,
    NoSuchSetting,
    OperatorExists,
    UnsupportedTrailFormat,
)
from waxseal_server.domain.operators import Operator, Principal, Role, scopes_for_role
from waxseal_server.ports.operators import OperatorStore
from waxseal_server.ports.settings import SettingsStore
from waxseal_server.runtime.cli import CliOutcome, WaxsealCli
from waxseal_server.storage.chains import ChainStore
from waxseal_server.storage.imports import ImportStore
from waxseal_server.storage.witness import WitnessStore

BEARER_PREFIX: Final = "Bearer "

#: One place where a domain failure becomes a status code. Adding an error type
#: without deciding its code is then impossible to do by accident.
STATUS_FOR_ERROR: Final[dict[type[Exception], tuple[int, str]]] = {
    InvalidIdentifier: (400, "invalid_identifier"),
    MalformedEnvelope: (400, "malformed_envelope"),
    UnsupportedTrailFormat: (400, "unsupported_trail_format"),
    NoSuchOperator: (404, "no_such_operator"),
    NoSuchSetting: (404, "no_such_setting"),
    OperatorExists: (409, "operator_exists"),
    DamagedReceiptLog: (422, "damaged_receipt_log"),
}

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


@dataclass(frozen=True, slots=True)
class Services:
    #: The frozen environment this process started with. Read-only everywhere.
    settings: Settings
    chains: ChainStore
    imports: ImportStore
    witnesses: WitnessStore
    operators: OperatorStore
    #: Operator-changeable configuration. Deliberately a DIFFERENT field from
    #: `settings`: one is the environment and cannot be written, the other is
    #: the store and holds no credential.
    config: SettingsStore
    cli: WaxsealCli


def error(status: int, code: str, detail: str = "") -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code, "detail": detail})


def error_for(exc: Exception, code: str | None = None) -> JSONResponse:
    """Map a domain failure to its one status code.

    `code` overrides only the label, never the status: a caller may say
    `invalid_chain_id` instead of `invalid_identifier` so the client sees which
    id it was, but it cannot decide that a malformed body is a 409.
    """
    for error_type, (status, default_code) in STATUS_FOR_ERROR.items():
        if isinstance(exc, error_type):
            return error(status, code or default_code, str(exc))
    raise exc  # pragma: no cover - an unmapped error is a bug, not a response


def unauthorized() -> JSONResponse:
    return error(401, "unauthorized", "a bearer token is required for this authority")


def forbidden(scope: str) -> JSONResponse:
    # Names the scope, not the role: an operator who is told "you need
    # keys:manage" can ask for exactly that, and learns nothing about who else
    # has it.
    return error(403, "forbidden", f"this credential does not grant {scope}")


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


def outcome_json(outcome: CliOutcome) -> dict[str, Any]:
    """One shape for every CLI-backed answer, with nothing collapsed.

    `verdict` is null wherever no verdict was computed and `status` says which
    non-verdict state that was, so a screen never has to read an exit code and
    guess whether 2 came from the verifier or from argparse.
    """
    return {
        "command": outcome.command,
        # The operator sees exactly what produced the verdict. A UI that shows a
        # conclusion without its command is asking to be trusted.
        "argv": list(outcome.argv),
        "exit_code": outcome.exit_code,
        "verdict": outcome.verdict.value if outcome.verdict else None,
        "status": outcome.status,
        "stdout": outcome.stdout,
        "stderr": outcome.stderr,
    }
