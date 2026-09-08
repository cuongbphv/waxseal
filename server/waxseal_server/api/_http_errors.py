"""HTTP error mapping for the write and admin authorities.

One place where a domain failure becomes a status code. Adding an error type
without deciding its code is then impossible to do by accident.
"""

from __future__ import annotations

from typing import Any, Final

from fastapi.responses import JSONResponse

from waxseal_server.domain.errors import (
    DamagedReceiptLog,
    InvalidIdentifier,
    MalformedEnvelope,
    NoSuchOperator,
    NoSuchSetting,
    OperatorExists,
    UnsupportedTrailFormat,
)
from waxseal_server.runtime.cli import CliOutcome

STATUS_FOR_ERROR: Final[dict[type[Exception], tuple[int, str]]] = {
    InvalidIdentifier: (400, "invalid_identifier"),
    MalformedEnvelope: (400, "malformed_envelope"),
    UnsupportedTrailFormat: (400, "unsupported_trail_format"),
    NoSuchOperator: (404, "no_such_operator"),
    NoSuchSetting: (404, "no_such_setting"),
    OperatorExists: (409, "operator_exists"),
    DamagedReceiptLog: (422, "damaged_receipt_log"),
}


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
