"""POST bodies larger than the measured envelope budget are refused, not stored.

The clipped-tool-result ceiling in `tests/test_entry_size_receipt.py` is
6_374 B. The default here is 1 MiB: two orders of magnitude of headroom for
a redacted envelope, and a hard stop so a client cannot fill the volume by
posting a dump that never went through `_sanitize`.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.types import Message, Receive, Scope, Send
from waxseal_server.api._body_limit import (
    MAX_BODY_BYTES,
    BodySizeLimitMiddleware,
    _too_large,
    refuse_oversized_post,
)
from waxseal_server.app import Settings, create_app


@pytest.fixture
def anyio_backend() -> str:
    # asyncio only: trio is not installed, and the middleware runs under
    # uvicorn's asyncio loop in production.
    return "asyncio"


async def _drop(_message: Message) -> None:
    return None


def test_a_post_over_one_mib_is_413_with_the_existing_error_shape(tmp_path: Path) -> None:
    client = TestClient(create_app(Settings(data_dir=tmp_path / "data")))
    body = b"x" * (MAX_BODY_BYTES + 1)
    resp = client.post(
        "/v1/chains/default/entries",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 413
    assert resp.json() == {
        "error": "payload_too_large",
        "detail": f"body exceeds {MAX_BODY_BYTES} bytes",
    }


def test_a_post_at_the_limit_is_not_413(tmp_path: Path) -> None:
    # Exactly MAX_BODY_BYTES is still admitted to the handler; it will fail
    # as malformed JSON, which is a 400, never a size refusal.
    client = TestClient(create_app(Settings(data_dir=tmp_path / "data")))
    resp = client.post(
        "/v1/chains/default/entries",
        content=b"{" + b"x" * (MAX_BODY_BYTES - 2) + b"}",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code != 413


def test_a_get_is_not_subject_to_the_post_budget(tmp_path: Path) -> None:
    client = TestClient(create_app(Settings(data_dir=tmp_path / "data")))
    assert client.get("/health").status_code == 200


def test_missing_or_unreadable_content_length_is_not_a_size_refusal() -> None:
    assert refuse_oversized_post("POST", None) is None
    assert refuse_oversized_post("POST", "not-a-number") is None
    assert refuse_oversized_post("GET", str(MAX_BODY_BYTES + 1)) is None
    assert refuse_oversized_post("POST", str(MAX_BODY_BYTES)) is None


def test_a_chunked_post_over_one_mib_is_413(tmp_path: Path) -> None:
    # Content-Length is the cheap path. Chunked POST omits it, and the
    # guard must still count streamed bytes - otherwise a client that
    # just leaves the header off walks past the 1 MiB stop.
    client = TestClient(create_app(Settings(data_dir=tmp_path / "data")))

    def chunks() -> Iterator[bytes]:
        yield b"x" * (MAX_BODY_BYTES + 1)

    resp = client.post(
        "/v1/chains/default/entries",
        content=chunks(),
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 413
    assert resp.json()["error"] == "payload_too_large"


def test_a_chunked_post_under_the_limit_is_not_413(tmp_path: Path) -> None:
    client = TestClient(create_app(Settings(data_dir=tmp_path / "data")))

    def chunks() -> Iterator[bytes]:
        yield b'{"not":"an envelope"}'

    resp = client.post(
        "/v1/chains/default/entries",
        content=chunks(),
        headers={"content-type": "application/json"},
    )
    assert resp.status_code != 413


@pytest.mark.anyio
async def test_a_non_http_scope_is_passed_through() -> None:
    seen: list[str] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(str(scope["type"]))

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    await BodySizeLimitMiddleware(app)({"type": "lifespan"}, receive, _drop)
    assert seen == ["lifespan"]


@pytest.mark.anyio
async def test_a_disconnect_during_post_is_passed_through() -> None:
    seen: list[str] = []

    async def app(_scope: Scope, _receive: Receive, _send: Send) -> None:
        seen.append("app")

    async def receive() -> Message:
        return {"type": "http.disconnect"}

    await BodySizeLimitMiddleware(app)(
        {"type": "http", "method": "POST", "headers": []},
        receive,
        _drop,
    )
    assert seen == ["app"]


@pytest.mark.anyio
async def test_a_handler_that_reads_the_body_twice_gets_the_replay() -> None:
    # ASGI: once the final body chunk has been delivered, receive() yields
    # the connection's own subsequent messages (http.disconnect when the
    # client goes away). A replay that answered every later call with a
    # synthetic empty http.request would hide the disconnect from the
    # handler forever.
    messages: list[Message] = []

    async def app(_scope: Scope, receive: Receive, send: Send) -> None:
        messages.append(await receive())
        messages.append(await receive())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    sent = False

    async def receive() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": b'{"x":1}', "more_body": False}
        return {"type": "http.disconnect"}

    await BodySizeLimitMiddleware(app)(
        {"type": "http", "method": "POST", "headers": []},
        receive,
        _drop,
    )
    assert messages == [
        {"type": "http.request", "body": b'{"x":1}', "more_body": False},
        {"type": "http.disconnect"},
    ]


@pytest.mark.anyio
async def test_both_413_paths_produce_one_identical_body() -> None:
    # The refusal used to be spelled twice - once for the Content-Length
    # path, once inside the counting loop. Two spellings of one error drift
    # apart the first time someone edits one of them; there is one helper
    # and both paths must return exactly its bytes.
    async def app(_scope: Scope, _receive: Receive, _send: Send) -> None:
        raise AssertionError("an oversized body reached the handler")

    sent = False

    async def receive() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {
                "type": "http.request",
                "body": b"x" * (MAX_BODY_BYTES + 1),
                "more_body": False,
            }
        return {"type": "http.disconnect"}

    streamed: list[Message] = []

    async def send(message: Message) -> None:
        streamed.append(message)

    await BodySizeLimitMiddleware(app)(
        {"type": "http", "method": "POST", "headers": []},
        receive,
        send,
    )
    streamed_body = b"".join(
        bytes(m["body"]) for m in streamed if m["type"] == "http.response.body"
    )
    declared = refuse_oversized_post("POST", str(MAX_BODY_BYTES + 1))
    assert declared is not None
    assert declared.status_code == 413
    assert streamed[0]["status"] == 413
    assert streamed_body == declared.body == _too_large().body


@pytest.mark.anyio
async def test_a_post_with_a_valid_content_length_is_not_buffered() -> None:
    # The ASGI server enforces framing: a body cannot exceed the
    # Content-Length it declared. Once that header has passed the cheap
    # check there is nothing left for the middleware to count, so buffering
    # the body a second time only costs memory. The handler must get the
    # server's own receive, untouched and unread.
    reads_before_app: list[int] = []
    handed: list[Receive] = []
    reads = 0

    async def receive() -> Message:
        nonlocal reads
        reads += 1
        return {"type": "http.request", "body": b'{"x":1}', "more_body": False}

    async def app(_scope: Scope, receive_in_app: Receive, _send: Send) -> None:
        reads_before_app.append(reads)
        handed.append(receive_in_app)

    await BodySizeLimitMiddleware(app)(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-length", b"7")],
        },
        receive,
        _drop,
    )
    assert reads_before_app == [0]
    assert handed == [receive]
