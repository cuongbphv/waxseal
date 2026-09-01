"""Tests for HTTPAnchorSink — a real external witness, unlike FileAnchorSink's
local sidecar (see ports/anchor.py's AnchorSink docstring)."""

from __future__ import annotations

import json

import pytest

from waxseal.adapters.anchors import HTTPAnchorSink
from waxseal.adapters.remote import RemoteRequest, RemoteResponse
from waxseal.domain.checkpoint import Checkpoint

CP = Checkpoint(seq=2, entry_hash="e" * 64, root="r" * 64)


class TestAnchor:
    def test_posts_checkpoint_fields_as_json_body(self) -> None:
        captured: list[RemoteRequest] = []

        def transport(request: RemoteRequest) -> RemoteResponse:
            captured.append(request)
            return RemoteResponse(status=200, body=b"{}")

        HTTPAnchorSink("http://anchor.example/v1/anchors", transport=transport).anchor(CP)
        assert len(captured) == 1
        assert captured[0].method == "POST"
        assert captured[0].url == "http://anchor.example/v1/anchors"
        sent_body = captured[0].body
        assert sent_body is not None
        body = json.loads(sent_body)
        assert body == {"seq": 2, "entry_hash": "e" * 64, "root": "r" * 64}

    def test_returns_receipt_from_response_body(self) -> None:
        def transport(request: RemoteRequest) -> RemoteResponse:
            return RemoteResponse(status=201, body=json.dumps({"receipt": "ots:abc123"}).encode())

        receipt = HTTPAnchorSink("http://anchor.example", transport=transport).anchor(CP)
        assert receipt == "ots:abc123"

    def test_returns_none_when_response_has_no_receipt(self) -> None:
        def transport(request: RemoteRequest) -> RemoteResponse:
            return RemoteResponse(status=200, body=b"")

        assert HTTPAnchorSink("http://anchor.example", transport=transport).anchor(CP) is None

    def test_non_2xx_raises(self) -> None:
        def transport(request: RemoteRequest) -> RemoteResponse:
            return RemoteResponse(status=503, body=b"unavailable")

        sink = HTTPAnchorSink("http://anchor.example", transport=transport)
        with pytest.raises(RuntimeError, match="503"):
            sink.anchor(CP)

    def test_api_key_sent_as_bearer_header(self) -> None:
        captured: list[RemoteRequest] = []

        def transport(request: RemoteRequest) -> RemoteResponse:
            captured.append(request)
            return RemoteResponse(status=200, body=b"{}")

        HTTPAnchorSink(
            "http://anchor.example", transport=transport, api_key="tok-abc"
        ).anchor(CP)
        assert captured[0].headers["Authorization"] == "Bearer tok-abc"

    def test_no_api_key_means_no_authorization_header(self) -> None:
        captured: list[RemoteRequest] = []

        def transport(request: RemoteRequest) -> RemoteResponse:
            captured.append(request)
            return RemoteResponse(status=200, body=b"{}")

        HTTPAnchorSink("http://anchor.example", transport=transport).anchor(CP)
        assert "Authorization" not in captured[0].headers
