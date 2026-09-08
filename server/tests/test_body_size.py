"""POST bodies larger than the measured envelope budget are refused, not stored.

The clipped-tool-result ceiling in `tests/test_entry_size_receipt.py` is
6_374 B. The default here is 1 MiB: two orders of magnitude of headroom for
a redacted envelope, and a hard stop so a client cannot fill the volume by
posting a dump that never went through `_sanitize`.
"""

from __future__ import annotations

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
