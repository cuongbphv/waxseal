"""Tests for OtsAnchorSink and the OpenTimestamps receipt framing.

The sink's whole job is one POST and one honest label. What it must NOT do is
claim more than it did: the proof it stores is pending, opaque, and never
parsed here (domain/ots.py explains why a partial parser would be worse than
none).
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from waxseal.adapters.ots import OtsAnchorSink
from waxseal.adapters.remote import RemoteRequest, RemoteResponse
from waxseal.domain.checkpoint import Checkpoint, checkpoint_frame
from waxseal.domain.ots import (
    OTS_ACCEPT,
    PENDING_NOTE,
    RECEIPT_PREFIX,
    decode_receipt,
    encode_receipt,
    ots_digest,
)

CP = Checkpoint(seq=4, entry_hash="a" * 64, root="b" * 64)
PROOF = b"\x00\x01\x02pending-proof-bytes"


def recording(status: int = 200, body: bytes = PROOF) -> tuple[list[RemoteRequest], object]:
    seen: list[RemoteRequest] = []

    def transport(request: RemoteRequest) -> RemoteResponse:
        seen.append(request)
        return RemoteResponse(status=status, body=body)

    return seen, transport


class TestDigestSubmission:
    def test_posts_thirty_two_raw_bytes_to_the_digest_endpoint(self) -> None:
        seen, transport = recording()
        OtsAnchorSink("https://calendar.example", transport=transport).anchor(CP)

        assert seen[0].method == "POST"
        assert seen[0].url == "https://calendar.example/digest"
        assert seen[0].body == hashlib.sha256(checkpoint_frame(CP)).digest()
        assert len(seen[0].body) == 32

    def test_sends_the_calendar_media_type_in_accept(self) -> None:
        seen, transport = recording()
        OtsAnchorSink("https://calendar.example", transport=transport).anchor(CP)
        assert seen[0].headers["Accept"] == OTS_ACCEPT

    def test_does_not_set_a_request_content_type(self) -> None:
        # Standard OpenTimestamps clients do not, and a calendar that keys off
        # its absence would reject a request this library invented.
        seen, transport = recording()
        OtsAnchorSink("https://calendar.example", transport=transport).anchor(CP)
        assert "Content-Type" not in seen[0].headers

    def test_a_trailing_slash_on_the_calendar_url_is_tolerated(self) -> None:
        seen, transport = recording()
        OtsAnchorSink("https://calendar.example/", transport=transport).anchor(CP)
        assert seen[0].url == "https://calendar.example/digest"

    def test_the_digest_is_of_the_frame_not_the_root(self) -> None:
        assert ots_digest(checkpoint_frame(CP)) != bytes.fromhex(CP.root)


class TestReceipt:
    def test_a_proof_becomes_a_pending_ots_receipt(self) -> None:
        _, transport = recording()
        receipt = OtsAnchorSink("https://cal", transport=transport).anchor(CP)
        assert receipt is not None and receipt.startswith(RECEIPT_PREFIX)
        assert decode_receipt(receipt) == PROOF

    def test_round_trips_through_base64(self) -> None:
        assert decode_receipt(encode_receipt(b"\xff\x00\xab")) == b"\xff\x00\xab"
        assert base64.b64decode(encode_receipt(PROOF).removeprefix(RECEIPT_PREFIX))

    def test_another_sinks_receipt_is_not_decoded_as_ots(self) -> None:
        assert decode_receipt("rfc3161:AAAA") is None

    def test_base64_this_build_cannot_decode_reads_as_not_readable(self) -> None:
        # Not an exception and not a failure: extracting a proof is a
        # convenience, and refusing to invent bytes is the whole contract.
        assert decode_receipt("ots:!!!not base64!!!") is None

    def test_the_pending_note_says_it_was_not_checked(self) -> None:
        assert "NOT checked" in PENDING_NOTE
        assert "ots upgrade" in PENDING_NOTE


class TestRefusals:
    def test_a_non_200_raises(self) -> None:
        _, transport = recording(status=500)
        with pytest.raises(RuntimeError, match="500"):
            OtsAnchorSink("https://cal", transport=transport).anchor(CP)

    def test_an_empty_body_raises_rather_than_filing_an_empty_proof(self) -> None:
        _, transport = recording(body=b"")
        with pytest.raises(RuntimeError, match="empty proof"):
            OtsAnchorSink("https://cal", transport=transport).anchor(CP)
