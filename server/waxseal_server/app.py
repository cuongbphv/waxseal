"""Application wiring — and nothing else.

Three authorities are kept apart on purpose, and this file is where that
separation is actually made:

* the **chain API** (`/v1/chains/...`) is the write authority, guarded by
  `WAXSEAL_API_KEY`;
* the **witness** (`/v1/witness/...`) is guarded by `WAXSEAL_WITNESS_API_KEY`
  and never receives the chain key — REMOTE.md section 8 is explicit that a
  witness holding the chain's write credential could append forged entries to
  the very chain it exists to cross-check;
* the **public read point** (`/public/...`) is handed no guard at all and has no
  write route to need one.

Each guard is constructed from one credential and passed to one router, so a
router cannot consult a key it was never given. Everything else here is
composition: build the services, build the routers, mount the UI last.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from waxseal_server.api import admin as admin_api
from waxseal_server.api import chains as chains_api
from waxseal_server.api import imports as imports_api
from waxseal_server.api import public as public_api
from waxseal_server.api import witness as witness_api
from waxseal_server.api.deps import Authorizer, Services, guard_for
from waxseal_server.config import Settings
from waxseal_server.ports.operators import OperatorStore
from waxseal_server.runtime.cli import WaxsealCli
from waxseal_server.runtime.postgres import connection_factory
from waxseal_server.runtime.spa import UNBUILT_UI_PAGE, SpaStaticFiles
from waxseal_server.storage.chains import ChainStore
from waxseal_server.storage.imports import ImportStore
from waxseal_server.storage.operators_memory import InMemoryOperatorStore
from waxseal_server.storage.operators_postgres import PostgresOperatorStore
from waxseal_server.storage.witness import WitnessStore

API_VERSION = "0.1.5"


def build_operator_store(settings: Settings) -> OperatorStore:
    """PostgreSQL when one is configured, memory otherwise.

    The in-memory store is a dev convenience and forgets every operator on
    restart. `/v1/meta` reports which one is in use, so "my admin disappeared"
    has an answer on the screen rather than in a support thread.
    """
    if settings.database_url is None:
        return InMemoryOperatorStore()
    return PostgresOperatorStore(connection_factory(settings.database_url))


def build_services(settings: Settings, operators: OperatorStore | None = None) -> Services:
    return Services(
        settings=settings,
        chains=ChainStore(settings.chains_dir),
        imports=ImportStore(settings.imports_dir),
        witnesses=WitnessStore(settings.witness_dir),
        operators=operators if operators is not None else build_operator_store(settings),
        cli=WaxsealCli(),
    )


def create_app(settings: Settings, operators: OperatorStore | None = None) -> FastAPI:
    services = build_services(settings, operators)
    # The chain authority resolves a token to an operator and a scope set; the
    # witness authority is a single credential and never sees an operator key
    # (REMOTE.md section 8).
    authz = Authorizer(bootstrap_key=settings.api_key, operators=services.operators)
    witness_guard = guard_for(settings.witness_api_key)

    app = FastAPI(
        title="waxseal server",
        summary="Self-hosted chain server, witness, and public read point for waxseal trails.",
        version=API_VERSION,
    )
    app.state.services = services
    app.state.settings = settings
    app.state.authorizer = authz

    app.include_router(chains_api.router(services, authz))
    app.include_router(imports_api.router(services, authz))
    app.include_router(admin_api.router(services, authz))
    app.include_router(witness_api.router(services, witness_guard))
    app.include_router(public_api.router(services))

    @app.get("/health")
    def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    index = settings.static_dir / "index.html"
    if index.is_file():
        # Mounted LAST so every API route above wins: a 404 from `/v1` must stay
        # a 404 from `/v1`, never a web page handed back to a data question.
        app.mount("/", SpaStaticFiles(directory=settings.static_dir, html=True), name="web")
    else:

        @app.get("/", response_class=HTMLResponse)
        def unbuilt_ui() -> HTMLResponse:
            return HTMLResponse(UNBUILT_UI_PAGE)

    return app
