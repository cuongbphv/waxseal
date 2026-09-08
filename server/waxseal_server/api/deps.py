"""What every router needs: the services it talks to, and who may call it.

Compatibility facade for the 0.1.6 extract. Callers keep importing from
`waxseal_server.api.deps`; the implementations live in `_services`, `_auth`,
and `_http_errors`. The witness authority is still a different guard — nothing
here puts the chain key and the witness key on one Depends.
"""

from __future__ import annotations

from waxseal_server.api._auth import (
    BEARER_PREFIX,
    BOOTSTRAP_USERNAME,
    OPEN_USERNAME,
    Authorizer,
    Guard,
    bearer,
    guard_for,
)
from waxseal_server.api._http_errors import (
    STATUS_FOR_ERROR,
    error,
    error_for,
    forbidden,
    outcome_json,
    unauthorized,
)
from waxseal_server.api._services import Services

__all__ = [
    "BEARER_PREFIX",
    "BOOTSTRAP_USERNAME",
    "OPEN_USERNAME",
    "STATUS_FOR_ERROR",
    "Authorizer",
    "Guard",
    "Services",
    "bearer",
    "error",
    "error_for",
    "forbidden",
    "guard_for",
    "outcome_json",
    "unauthorized",
]
