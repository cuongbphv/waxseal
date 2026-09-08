# waxseal web console

A read-only web UI for the self-hosted waxseal server. Vue 3 + vue-router + Vite,
TypeScript throughout, hand-written CSS. No UI library, no CSS framework, no state
library, no icon package.

## What it is (and is not)

Every verdict shown is produced by the waxseal CLI behind the server, and every verdict
panel prints the `argv` that produced it so an operator can reproduce it. The console has
no control that edits, deletes, repairs, reorders, or re-signs anything - waxseal reports,
it never repairs, and neither does this UI.

Five states are rendered distinctly and never collapsed into a pass/fail pair:
`ok`, `broken`, `unverifiable`, `absent`, `unavailable` (plus `usage_error` and
`unexpected_exit`, which mean no verdict was computed at all). `unverifiable` never wears
`broken`'s treatment, and `absent` is never drawn as a failure. Where the API returns
`null` - `completeness.dropped_writes`, `separation.tau`, `receipts.checked` - the screen
prints "not measured" / "not declared" / "not recorded", never `0`.

## Develop

```sh
npm install
npm run dev
```

The dev server proxies `/v1`, `/public` and `/health` to `http://127.0.0.1:8000`, so run
the API alongside it:

```sh
cd ..                       # server/
uv run uvicorn --factory 'waxseal_server.app:create_app' --port 8000
```

If the server is configured with `WAXSEAL_API_KEY`, paste the token into the **API token**
field in the black nav bar. It is kept in `sessionStorage` (this tab only) and is sent as
`Authorization: Bearer …` on `/v1` requests. `/public/v1` requests never carry it.

## Build

```sh
npm run build       # vite build
npm run typecheck   # vue-tsc --noEmit
```

Output goes to `../waxseal_server/static/` (`build.outDir`, with `emptyOutDir: true`), so
the built bundle sits next to the FastAPI app that serves it.

The router uses **path history**, not hash history: `SpaStaticFiles` in
`waxseal_server/app.py` answers any unmatched non-API path with `index.html`, so a refresh
of `/chains/default` reaches the router (and an unmatched `/v1/...` or `/public/...` stays
a real 404 rather than being handed a web page). Both halves are covered by
`tests/test_static_ui.py`.

`base` is therefore `'/'` and not `'./'`. Relative asset URLs would resolve against the
deep route - the browser would request `/chains/assets/index-*.js`, `SpaStaticFiles` would
answer that 404 with `index.html`, and the module loader would be handed HTML. A blank page
on refresh only. If the bundle ever moves off the site root, `base` moves with it.

The `static/` directory is generated - it is git-ignored and safe to delete.

## Design system

Every colour, type step, radius and spacing value lives in `src/styles/tokens.css` as a
CSS custom property; no other file contains a literal hex. The system has one interactive
accent (`--color-primary`, `#0066cc`) and no second one. Status colours are declared in
their own commented block and never appear on a button or a link - and every status is
carried by its word, so the screen reads correctly with the colour removed.

There is no `box-shadow` anywhere: the design system has exactly one shadow and it is
reserved for product photography, which this app has none of. Elevation comes from surface
change and 1px hairlines.
