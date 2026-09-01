# waxseal-server

A self-hosted chain server, witness, and public read point for waxseal trails,
with a read-only web portal (0.1.5, Workstream I).

This is a separate application, not part of the `waxseal` wheel. CLAUDE.md rule
1 ("no new runtime dependencies") constrains `[project] dependencies` of the
wheel; this directory is allowed its own stack (FastAPI + uvicorn) on the same
footing as `contracts/`, and nothing here is packaged into the wheel.

```bash
docker compose -f server/docker-compose.yml up --build   # http://127.0.0.1:8000
```

Full operator documentation, including the threat model and what self-hosting
does and does not buy: [`docs/deployment.md`](docs/deployment.md).

## Layout

Layered the way the library it serves is layered (CLAUDE.md's architecture
section), with a one-way dependency arrow and a test that enforces it
(`tests/test_architecture.py`, which carries its own falsifiability receipt —
add a forbidden import and it goes red):

```
waxseal_server/
  api/         FastAPI routers, one per authority. The only layer that knows HTTP.
    deps.py    the Services container and the two credential guards
    views.py   response bodies shared by the credentialed and public surfaces
  runtime/     adapters to things outside the process: the waxseal CLI, the
               built web bundle, reading a trail for display
  storage/     persistence — files and locks, no knowledge of requests
  domain/      pure logic: envelope and checkpoint parsing, identifier shapes,
               the receipt chain, the result types. No I/O at all.
  config.py    settings, read from the environment and passed down explicitly
  app.py       composition root: build the services, build the routers, mount
               the UI last
```

Two properties this buys, both checked rather than asserted: `domain/` imports
nothing that touches a filesystem, so the rules are testable without standing a
server up; and each credential guard is built from one key and handed to one
router, so the witness router cannot consult the chain key — it never receives
it.

## Design in one paragraph

The **write** path uses waxseal as a library: `POST /v1/chains/{id}/entries`
hands the posted envelope to `JSONLBackend.append`, whose builder runs under the
backend's own file lock, so the compare-and-set of REMOTE.md section 4 is atomic
with the append rather than a check racing beside it. Every **read/verify**
surface shells out to the `waxseal` CLI and reports its exit code, because the
CLI is the stable contract and a server with its own verifier would be a second
opinion to reconcile. The server never re-derives an `entry_hash` and has no
route that edits, deletes or repairs anything.

## Tests

```bash
cd server && uv sync --extra dev && uv run pytest --cov=waxseal_server
```

The suite has its own 100% line-and-branch floor, kept out of the wheel's gate.
The load-bearing one is `tests/test_contract_vs_client.py`: it runs the
library's own backend-conformance contract (`tests/adapters/backend_contract.py`,
imported rather than restated) against this server over real TCP, using the
shipped `RemoteBackend`, `HTTPAnchorSink` and `HTTPWitness` unmodified. If a real
waxseal client cannot tell this server apart from the backends waxseal ships
with, that is the claim worth making.

## Web UI

Vue 3 + Vite, in `web/`. `npm run build` writes into `waxseal_server/static` and
the server picks it up on the next start. The API runs fine without it — `/`
then serves a page saying the UI was not built, and `GET /v1/meta` reports
`"web_ui": "not_built"`.
