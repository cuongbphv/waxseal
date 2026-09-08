"""Refuse POST bodies larger than the measured envelope budget.

The clipped-tool-result ceiling (`tests/test_entry_size_receipt.py`) is
6_374 B. One mebibyte is two orders of magnitude of headroom for a redacted
envelope, and a stop so a client cannot fill the volume by posting a dump
that never went through `_sanitize`. The JSON error shape is the existing
`{error, detail}` pair. REMOTE.md section 4 names the 413 on POST /entries;
a missing Content-Length does not skip the count.
"""

from __future__ import annotations

from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

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


class BodySizeLimitMiddleware:
    """Count POST bytes as they stream. Content-Length is the cheap path;
    chunked POST still hits the same 1 MiB stop. Ingress
    `proxy-body-size` is a coarser outer cap, not a substitute.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope.get("method", "")
        headers = Headers(scope=scope)
        refused = refuse_oversized_post(method, headers.get("content-length"))
        if refused is not None:
            await refused(scope, receive, send)
            return
        if method != "POST":
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        received = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                await self.app(scope, receive, send)
                return
            chunk = message.get("body", b"")
            received += len(chunk)
            if received > MAX_BODY_BYTES:
                response = error(
                    413,
                    "payload_too_large",
                    f"body exceeds {MAX_BODY_BYTES} bytes",
                )
                await response(scope, receive, send)
                return
            chunks.append(chunk)
            more_body = bool(message.get("more_body", False))

        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {
                    "type": "http.request",
                    "body": b"".join(chunks),
                    "more_body": False,
                }
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)
