"""Refuse POST bodies larger than the measured envelope budget.

The clipped-tool-result ceiling (`tests/test_entry_size_receipt.py`) is
6_374 B. One mebibyte is two orders of magnitude of headroom for a redacted
envelope, and a stop so a client cannot fill the volume by posting a dump
that never went through `_sanitize`. The JSON error shape is the existing
`{error, detail}` pair; REMOTE.md is not edited here.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from waxseal_server.api._http_errors import error

MAX_BODY_BYTES = 1_048_576


def refuse_oversized_post(method: str, content_length: str | None) -> JSONResponse | None:
    if method != "POST":
        return None
    if content_length is None or not content_length.isdigit():
        return None
    if int(content_length) > MAX_BODY_BYTES:
        return error(
            413, "payload_too_large", f"body exceeds {MAX_BODY_BYTES} bytes"
        )
    return None


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        refused = refuse_oversized_post(
            request.method, request.headers.get("content-length")
        )
        if refused is not None:
            return refused
        return await call_next(request)
