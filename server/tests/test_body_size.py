"""POST bodies larger than the measured envelope budget are refused, not stored.

The clipped-tool-result ceiling in `tests/test_entry_size_receipt.py` is
6_374 B. The default here is 1 MiB: two orders of magnitude of headroom for
a redacted envelope, and a hard stop so a client cannot fill the volume by
posting a dump that never went through `_sanitize`.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient
from waxseal_server.api._body_limit import MAX_BODY_BYTES, refuse_oversized_post
from waxseal_server.app import Settings, create_app


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

    def chunks() -> object:
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

    def chunks() -> object:
        yield b'{"not":"an envelope"}'

    resp = client.post(
        "/v1/chains/default/entries",
        content=chunks(),
        headers={"content-type": "application/json"},
    )
    assert resp.status_code != 413


def test_a_non_http_scope_is_passed_through() -> None:
    asyncio.run(_a_non_http_scope_is_passed_through())


async def _a_non_http_scope_is_passed_through() -> None:
    from waxseal_server.api._body_limit import BodySizeLimitMiddleware

    seen: list[str] = []

    async def app(scope: dict[str, object], receive: object, send: object) -> None:
        seen.append(str(scope["type"]))

    async def receive() -> dict[str, object]:
        return {"type": "lifespan.startup"}

    async def send(_message: object) -> None:
        return None

    await BodySizeLimitMiddleware(app)({"type": "lifespan"}, receive, send)
    assert seen == ["lifespan"]


def test_a_disconnect_during_post_is_passed_through() -> None:
    asyncio.run(_a_disconnect_during_post_is_passed_through())


async def _a_disconnect_during_post_is_passed_through() -> None:
    from waxseal_server.api._body_limit import BodySizeLimitMiddleware

    seen: list[str] = []

    async def app(_scope: object, _receive: object, _send: object) -> None:
        seen.append("app")

    async def receive() -> dict[str, object]:
        return {"type": "http.disconnect"}

    async def send(_message: object) -> None:
        return None

    await BodySizeLimitMiddleware(app)(
        {"type": "http", "method": "POST", "headers": []},
        receive,
        send,
    )
    assert seen == ["app"]


def test_a_handler_that_reads_the_body_twice_gets_the_replay() -> None:
    asyncio.run(_a_handler_that_reads_the_body_twice_gets_the_replay())


async def _a_handler_that_reads_the_body_twice_gets_the_replay() -> None:
    from waxseal_server.api._body_limit import BodySizeLimitMiddleware

    bodies: list[bytes] = []

    async def app(
        _scope: object,
        receive: object,
        send: object,
    ) -> None:
        first = await receive()  # type: ignore[misc]
        second = await receive()  # type: ignore[misc]
        bodies.append(first["body"])
        bodies.append(second["body"])
        await send({"type": "http.response.start", "status": 200, "headers": []})  # type: ignore[misc]
        await send({"type": "http.response.body", "body": b"ok"})  # type: ignore[misc]

    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": b'{"x":1}', "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: object) -> None:
        return None

    await BodySizeLimitMiddleware(app)(
        {"type": "http", "method": "POST", "headers": []},
        receive,
        send,
    )
    assert bodies == [b'{"x":1}', b""]
