"""The chain API — the write authority, gated by `WAXSEAL_API_KEY`.

This is the surface `RemoteBackend` speaks (REMOTE.md sections 4, 5 and 10). Its
one mutating route is the append, and its precondition is enforced inside the
storage layer's write lock rather than here: a check at this level would be a
race, not a guarantee.

Child routers carry the path ops; this module stays the facade `app.py` calls.
Include order is load-bearing: `{command}` is registered LAST so it cannot
steal `/ledger-status` or `/tail`.
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from waxseal_server.api._chains_meta import router as meta_router
from waxseal_server.api._chains_reads import router as reads_router
from waxseal_server.api._chains_writes import router as writes_router
from waxseal_server.api.deps import Authorizer, Services, error, error_for
from waxseal_server.api.views import cli_read_body, report_args
from waxseal_server.domain.errors import InvalidIdentifier
from waxseal_server.domain.operators import SCOPE_VERIFY_RUN

#: Reads offered over a live chain. Every one of these is in
#: `READ_ONLY_COMMANDS`. `segments` and `preflight` were both listed here while
#: the wheel still lacked them, on the rule that the honest answer is
#: "unavailable" from the CLI runner rather than a route that does not exist.
#: 0.1.5 shipped both — Workstreams B and E — and neither route needed a change,
#: which is the point of gating on `available()` instead of on a hard-coded
#: "not yet", and the reason this tuple stays safe to extend ahead of a wheel.
CHAIN_READS: Final[tuple[str, ...]] = (
    "verify",
    "report",
    "inspect",
    "segments",
    "preflight",
    # Takes no flag, so it needs no handler of its own — the reason this tuple
    # exists. `checkpoint` prints the (seq, entry_hash, root) an operator pins
    # or anchors against.
    "checkpoint",
)


def router(services: Services, authz: Authorizer) -> APIRouter:
    api = APIRouter(prefix="/v1", tags=["chain"])
    api.include_router(writes_router(services, authz))
    api.include_router(reads_router(services, authz))
    api.include_router(meta_router(services, authz))

    def trail_for(chain_id: str) -> str:
        # The ACTIVE segment, not the base file name: a rotated chain's live
        # history is the newest segment, and `verify`/`inspect`/`export-proof`
        # asked about a sealed one would answer truthfully about the wrong
        # chain. `segments` is the read that speaks about the whole group, and
        # `read_target` already hands it this path's directory.
        return str(services.chains.active_trail_path(chain_id))

    @api.get("/chains/{chain_id}/{command}")
    def get_chain_read(
        chain_id: str, command: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        # One route for every CLI-backed read, driven by CHAIN_READS. Adding a
        # read is one tuple entry, not a handler — which is how B's `segments`
        # and E's `preflight` both arrived in 0.1.5 with no handler written.
        denied = authz.require(authorization, SCOPE_VERIFY_RUN)
        if denied is not None:
            return denied
        if command not in CHAIN_READS:
            return error(404, "no_such_read", f"{command!r} is not a read this server offers")
        try:
            trail = trail_for(chain_id)
        except InvalidIdentifier as exc:
            return error_for(exc, "invalid_chain_id")
        return cli_read_body(services, trail, command, *report_args(command))

    return api
