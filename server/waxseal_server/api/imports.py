"""Imported trails — evidence from elsewhere, read-only from the moment it lands.

Imports have their own id namespace so no chain route can address one, and the
stored copy is `chmod 0400`, so "verify reports, never repairs" (CLAUDE.md rule
4) is enforced by the filesystem rather than by everyone remembering it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from fastapi import APIRouter, Header, UploadFile
from fastapi.responses import JSONResponse

from waxseal_server.api.deps import Authorizer, Services, error, error_for
from waxseal_server.api.views import cli_read_body, report_args
from waxseal_server.domain.errors import UnsupportedTrailFormat
from waxseal_server.domain.identifiers import is_import_id
from waxseal_server.domain.operators import SCOPE_IMPORT_WRITE, SCOPE_TRAILS_READ
from waxseal_server.runtime.entries import read_entries_for_display

#: Reads offered over an imported trail. `verify-proof` and `consistency` need
#: arguments an import screen does not have; the writing commands are absent
#: from `READ_ONLY_COMMANDS` entirely and so unreachable from here.
IMPORT_READS: Final[frozenset[str]] = frozenset(
    {"verify", "report", "inspect", "segments", "preflight", "head", "checkpoint"}
)


def router(services: Services, authz: Authorizer) -> APIRouter:
    api = APIRouter(prefix="/v1", tags=["imports"])

    def resolve(import_id: str) -> Path | JSONResponse:
        """The stored trail, or the response saying why there is not one.

        Malformed and unknown are different answers: one is the caller's
        mistake, the other is a fact about this server's store.
        """
        if not is_import_id(import_id):
            return error(400, "invalid_import_id", f"not a valid import id: {import_id!r}")
        if services.imports.get(import_id) is None:
            return error(404, "no_such_import", f"no import with id {import_id!r}")
        return services.imports.trail_path(import_id)

    @api.post("/imports")
    async def post_import(
        file: UploadFile, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_IMPORT_WRITE)
        if denied is not None:
            return denied
        try:
            record = services.imports.create(file.filename or "upload", await file.read())
        except UnsupportedTrailFormat as exc:
            return error_for(exc)
        return JSONResponse(status_code=201, content=record.to_json())

    @api.get("/imports")
    def get_imports(authorization: str | None = Header(default=None)) -> JSONResponse:
        return authz.require(authorization, SCOPE_TRAILS_READ) or JSONResponse(
            {"imports": [record.to_json() for record in services.imports.records()]}
        )

    @api.get("/imports/{import_id}")
    def get_import(
        import_id: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_TRAILS_READ)
        if denied is not None:
            return denied
        resolved = resolve(import_id)
        if isinstance(resolved, JSONResponse):
            return resolved
        record = services.imports.get(import_id)
        assert record is not None  # noqa: S101 - resolve() already proved it
        return JSONResponse(record.to_json())

    @api.get("/imports/{import_id}/entries")
    def get_import_entries(
        import_id: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_TRAILS_READ)
        if denied is not None:
            return denied
        resolved = resolve(import_id)
        if isinstance(resolved, JSONResponse):
            return resolved
        try:
            entries = read_entries_for_display(resolved, limit=services.settings.page_size)
        except Exception as exc:  # noqa: BLE001 - any backend failure is reportable
            # "I could not read it" must not arrive as an empty list, which
            # would claim a trail was read and found to hold nothing.
            return error(422, "unreadable_trail", f"{type(exc).__name__}: {exc}")
        return JSONResponse({"entries": entries, "next_cursor": None})

    @api.get("/imports/{import_id}/{command}")
    def get_import_read(
        import_id: str, command: str, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        denied = authz.require(authorization, SCOPE_TRAILS_READ)
        if denied is not None:
            return denied
        if command not in IMPORT_READS:
            return error(404, "no_such_read", f"{command!r} is not a read this server offers")
        resolved = resolve(import_id)
        if isinstance(resolved, JSONResponse):
            return resolved
        return cli_read_body(services, str(resolved), command, *report_args(command))

    return api
