"""Serving the built web bundle, and saying so plainly when there is none.

Two behaviours live here, and both exist because a bare 404 would be a lie by
omission:

* a client-side route must reach the router on a refresh, so an unmatched path
  gets `index.html`;
* an unmatched path under an API prefix must NOT — answering a data request with
  a web page turns "no such endpoint" into a parse error three layers away.

`_API_PREFIXES` is the seam between those two. It is a tuple rather than a
scattered set of `startswith` calls so that mounting a new API family is one
edit in one place.
"""

from __future__ import annotations

from typing import Any, Final

from fastapi.staticfiles import StaticFiles

# Starlette's, not FastAPI's: StaticFiles raises the base class, and catching
# only the subclass would let every miss through as a bare 404.
from starlette.exceptions import HTTPException as StarletteHTTPException

#: Prefixes whose 404 is an answer, not a missing page.
API_PREFIXES: Final[tuple[str, ...]] = (
    "/v1",
    "/public",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
)

UNBUILT_UI_PAGE: Final = """<!doctype html>
<meta charset="utf-8"><title>waxseal server — API only</title>
<style>body{font:17px/1.47 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;
color:#1d1d1f;background:#f5f5f7;margin:0;padding:80px 24px;}
main{max-width:640px;margin:0 auto}
h1{font-size:40px;font-weight:600;line-height:1.1;margin:0 0 24px}
code{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:2px 6px}
a{color:#0066cc}</style>
<main>
<h1>The API is running. The web UI was not built.</h1>
<p>This is the labelled absence, not a missing page: the server is serving
<code>/v1</code> and <code>/public/v1</code> normally, and only the browser
front end is absent from this deployment.</p>
<p>To build it: <code>cd server/web &amp;&amp; npm install &amp;&amp; npm run build</code>.
The output lands in <code>waxseal_server/static</code> and this page is replaced
on the next start.</p>
<p><a href="/docs">OpenAPI docs</a> · <a href="/public/v1/chains">public read point</a></p>
</main>
"""


class SpaStaticFiles(StaticFiles):
    """Serve the built UI, falling back to its shell for client-side routes."""

    async def get_response(self, path: str, scope: Any) -> Any:
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404 or scope["path"].startswith(API_PREFIXES):
                raise
            return await super().get_response("index.html", scope)
