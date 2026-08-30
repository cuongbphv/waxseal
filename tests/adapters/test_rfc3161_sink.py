"""Tests for Rfc3161AnchorSink and RecordingAnchorSink.

The property that matters: a receipt only ever lands in the sidecar when a
third party actually issued it FOR THE BYTES beside it. Every failure mode
below is checked twice — the call raises, and the sidecar is unchanged.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from waxseal.adapters.anchors import (
    MultiAnchorSink,
    RecordingAnchorSink,
    SinkReceipt,
    read_anchor_records,
)
from waxseal.adapters.remote import RemoteRequest, RemoteResponse
from waxseal.adapters.rfc3161 import ACCEPT, CONTENT_TYPE, Rfc3161AnchorSink
from waxseal.domain.checkpoint import Checkpoint, checkpoint_frame
from waxseal.domain.rfc3161 import (
    SHA256_OID,
    _der_int,
    _der_oid,
    _tlv,
    decode_receipt,
)

CP = Checkpoint(seq=2, entry_hash="e" * 64, root="r" * 64)

SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
TSTINFO_OID = "1.2.840.113549.1.9.16.1.4"


def granted_response(
    message: bytes, *, nonce: int | None = None, status: int = 0, digest: str = SHA256_OID
) -> bytes:
    """A minimal but structurally complete TimeStampResp for ``message``."""
    algid = _tlv(0x30, _der_oid(digest) + _tlv(0x05, b""))
    imprint = _tlv(0x30, algid + _tlv(0x04, hashlib.sha256(message).digest()))
    tst = _tlv(
        0x30,
        _der_int(1)
        + _der_oid("1.2.3.4.1")
        + imprint
        + _der_int(7)
        + _tlv(0x18, b"20260823090000Z")
        + (_der_int(nonce) if nonce is not None else b""),
    )
    signed = _tlv(
        0x30,
        _der_int(3)
        + _tlv(0x31, b"")
        + _tlv(0x30, _der_oid(TSTINFO_OID) + _tlv(0xA0, _tlv(0x04, tst)))
        + _tlv(0x31, b""),
    )
    token = _tlv(0x30, _der_oid(SIGNED_DATA_OID) + _tlv(0xA0, signed))
    return _tlv(0x30, _tlv(0x30, _der_int(status)) + token)


def honest_tsa(nonce: int) -> tuple[list[RemoteRequest], object]:
    seen: list[RemoteRequest] = []

    def transport(request: RemoteRequest) -> RemoteResponse:
        seen.append(request)
        # A real TSA stamps whatever imprint it was handed; reconstructing the
        # frame here would let the fake agree with a broken encoder.
        return RemoteResponse(status=200, body=granted_response(FRAME, nonce=nonce))

    return seen, transport


FRAME = checkpoint_frame(CP)


class TestRequest:
    def test_posts_a_timestamp_query_with_the_right_headers(self) -> None:
        seen, transport = honest_tsa(1234)
        Rfc3161AnchorSink(
            "http://tsa.example/tsr", transport=transport, nonce_fn=lambda: 1234
        ).anchor(CP)

        assert len(seen) == 1
        assert seen[0].method == "POST"
        assert seen[0].headers["Content-Type"] == CONTENT_TYPE
        assert seen[0].headers["Accept"] == ACCEPT

    def test_the_imprint_is_the_checkpoint_frame_not_the_root(self) -> None:
        # The frame is what every other sink witnesses, and (v2) what carries
        # the aggregate binding. Stamping the root alone would leave the
        # binding outside the attestation.
        seen, transport = honest_tsa(1)
        Rfc3161AnchorSink("http://tsa", transport=transport, nonce_fn=lambda: 1).anchor(CP)
        assert hashlib.sha256(FRAME).digest() in seen[0].body

    def test_the_nonce_is_injectable(self) -> None:
        seen, transport = honest_tsa(0x4242)
        Rfc3161AnchorSink("http://tsa", transport=transport, nonce_fn=lambda: 0x4242).anchor(CP)
        assert bytes([0x02, 0x02, 0x42, 0x42]) in seen[0].body

    def test_the_default_nonce_is_random_and_present(self) -> None:
        # Not asserting the value — asserting that two anchors do not reuse
        # one, which is the only property a replay check depends on.
        bodies: list[bytes] = []

        def transport(request: RemoteRequest) -> RemoteResponse:
            bodies.append(request.body)
            return RemoteResponse(status=200, body=b"")

        sink = Rfc3161AnchorSink("http://tsa", transport=transport)
        for _ in range(2):
            with pytest.raises(RuntimeError, match="malformed_token"):
                sink.anchor(CP)
        assert bodies[0] != bodies[1]


class TestReceipt:
    def test_a_good_token_becomes_an_rfc3161_receipt(self) -> None:
        _, transport = honest_tsa(9)
        result = Rfc3161AnchorSink(
            "http://tsa", transport=transport, nonce_fn=lambda: 9
        ).anchor(CP)
        assert isinstance(result, SinkReceipt)
        assert result.receipt.startswith("rfc3161:")
        assert decode_receipt(result.receipt) == granted_response(FRAME, nonce=9)

    def test_the_returned_payload_carries_the_request_nonce(self) -> None:
        # The nonce used to die with the request — checked on the response,
        # then dropped — so a verifier reading the stored receipt had nothing
        # to compare and NONCE_MISMATCH was unreachable on re-verify (the gap
        # SPEC.md section 17 documented). The sink now hands it back for
        # recording.
        _, transport = honest_tsa(9)
        result = Rfc3161AnchorSink(
            "http://tsa", transport=transport, nonce_fn=lambda: 9
        ).anchor(CP)
        assert isinstance(result, SinkReceipt)
        assert result.nonce == 9

    def test_the_receipt_round_trips_through_base64(self) -> None:
        _, transport = honest_tsa(9)
        result = Rfc3161AnchorSink(
            "http://tsa", transport=transport, nonce_fn=lambda: 9
        ).anchor(CP)
        assert isinstance(result, SinkReceipt)
        assert base64.b64decode(result.receipt.removeprefix("rfc3161:"), validate=True)


class TestRefusals:
    def sink(self, body: bytes, *, status: int = 200) -> Rfc3161AnchorSink:
        def transport(request: RemoteRequest) -> RemoteResponse:
            return RemoteResponse(status=status, body=body)

        return Rfc3161AnchorSink("http://tsa", transport=transport, nonce_fn=lambda: 5)

    def test_a_non_200_raises(self) -> None:
        with pytest.raises(RuntimeError, match="503"):
            self.sink(b"", status=503).anchor(CP)

    def test_a_token_for_other_bytes_is_refused(self) -> None:
        # The headline refusal: a TSA (or a proxy in front of it) that answers
        # about something else must not leave a receipt behind.
        with pytest.raises(RuntimeError, match="receipt_imprint_mismatch"):
            self.sink(granted_response(b"other bytes", nonce=5)).anchor(CP)

    def test_a_replayed_token_with_the_wrong_nonce_is_refused(self) -> None:
        with pytest.raises(RuntimeError, match="nonce_mismatch"):
            self.sink(granted_response(FRAME, nonce=6)).anchor(CP)

    def test_a_rejection_is_refused(self) -> None:
        rejection = _tlv(0x30, _tlv(0x30, _der_int(2)))
        with pytest.raises(RuntimeError, match="timestamp_rejected"):
            self.sink(rejection).anchor(CP)

    def test_garbage_is_refused(self) -> None:
        with pytest.raises(RuntimeError, match="malformed_token"):
            self.sink(b"not der at all").anchor(CP)


class TestRecordingAnchorSink:
    def test_records_the_receipt_the_external_sink_returned(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        _, transport = honest_tsa(3)
        sink = RecordingAnchorSink(
            trail,
            Rfc3161AnchorSink("http://tsa", transport=transport, nonce_fn=lambda: 3),
            now_fn=lambda: "2026-08-23T09:00:00+00:00",
        )
        receipt = sink.anchor(CP)

        records = read_anchor_records(trail).records
        assert len(records) == 1
        assert records[0].receipt == receipt
        assert records[0].sink == "rfc3161"
        assert records[0].ts == "2026-08-23T09:00:00+00:00"
        assert records[0].checkpoint.seq == 2

    def test_a_failed_publish_records_nothing(self, tmp_path: Path) -> None:
        # A record with no third party behind it is worse than no record: it
        # reads as an anchor that somebody else holds.
        trail = tmp_path / "trail.jsonl"

        class Failing:
            name = "rfc3161"

            def anchor(self, checkpoint: Checkpoint) -> str | None:
                raise RuntimeError("network down")

        sink = RecordingAnchorSink(trail, Failing())
        with pytest.raises(RuntimeError, match="network down"):
            sink.anchor(CP)
        assert not Path(str(trail) + ".anchors").exists()

    def test_the_sidecar_is_owner_only(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"

        class Quiet:
            name = "quiet"

            def anchor(self, checkpoint: Checkpoint) -> str | None:
                return None

        RecordingAnchorSink(trail, Quiet()).anchor(CP)
        sidecar = Path(str(trail) + ".anchors")
        assert sidecar.exists()
        assert json.loads(sidecar.read_text())["sink"] == "quiet"

    def test_a_sink_without_a_name_still_files_its_receipt(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"

        class Anonymous:
            def anchor(self, checkpoint: Checkpoint) -> str | None:
                return "x:1"

        RecordingAnchorSink(trail, Anonymous()).anchor(CP)
        assert read_anchor_records(trail).records[0].sink == "external"

    def test_the_aggregate_binding_survives_into_the_record(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        bound = Checkpoint(
            seq=1, entry_hash="a" * 64, root="b" * 64, agg_commit="c" * 64, agg_epoch=2
        )

        class Quiet:
            name = "quiet"

            def anchor(self, checkpoint: Checkpoint) -> str | None:
                return None

        RecordingAnchorSink(trail, Quiet()).anchor(bound)
        record = read_anchor_records(trail).records[0]
        assert record.version == 2
        assert record.checkpoint.agg_epoch == 2


class TestMultiAnchorSink:
    """waxseal-4yk: one checkpoint, fanned out to two independently-recording
    sinks. Each ``Quiet``/``Failing`` fake below plays the same role
    ``RecordingAnchorSink``'s own tests already give them — a real
    ``RecordingAnchorSink`` around ``Rfc3161AnchorSink``/``OtsAnchorSink`` is
    exercised end to end through the CLI in test_cli_receipts.py; this class
    is the sink-fan-out contract in isolation.
    """

    def test_needs_at_least_two_sinks(self) -> None:
        class Quiet:
            name = "quiet"

            def anchor(self, checkpoint: Checkpoint) -> str | None:
                return None

        with pytest.raises(ValueError, match="at least two"):
            MultiAnchorSink([Quiet()])

    def test_both_sinks_publish_the_identical_checkpoint(self) -> None:
        seen: list[Checkpoint] = []

        def recorder(name: str) -> object:
            class Recorder:
                def anchor(self, checkpoint: Checkpoint) -> str | None:
                    seen.append(checkpoint)
                    return None

            Recorder.name = name  # type: ignore[attr-defined]
            return Recorder()

        multi = MultiAnchorSink([recorder("a"), recorder("b")])
        multi.anchor(CP)

        assert seen == [CP, CP]
        assert multi.failures == []

    def test_one_sink_failing_does_not_stop_the_other_from_recording(
        self, tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"

        class Failing:
            name = "rfc3161"

            def anchor(self, checkpoint: Checkpoint) -> str | None:
                raise RuntimeError("network down")

        multi = MultiAnchorSink(
            [Failing(), RecordingAnchorSink(trail, _Quiet())]
        )
        multi.anchor(CP)

        records = read_anchor_records(trail).records
        assert len(records) == 1
        assert records[0].sink == "quiet"
        # Labelled, not silent (CLAUDE.md rule 6): the caller can see which
        # sink failed and why.
        assert multi.failures == [("rfc3161", "network down")]

    def test_every_sink_failing_raises_with_both_reasons(self) -> None:
        class Failing:
            def __init__(self, name: str, reason: str) -> None:
                self.name = name
                self._reason = reason

            def anchor(self, checkpoint: Checkpoint) -> str | None:
                raise RuntimeError(self._reason)

        multi = MultiAnchorSink([Failing("rfc3161", "tsa down"), Failing("ots", "cal down")])
        with pytest.raises(RuntimeError, match="rfc3161: tsa down; ots: cal down"):
            multi.anchor(CP)

    def test_the_name_joins_both_child_names(self) -> None:
        class Named:
            def __init__(self, name: str) -> None:
                self.name = name

            def anchor(self, checkpoint: Checkpoint) -> str | None:
                return None

        multi = MultiAnchorSink([Named("rfc3161"), Named("ots")])
        assert multi.name == "rfc3161+ots"


class _Quiet:
    name = "quiet"

    def anchor(self, checkpoint: Checkpoint) -> str | None:
        return None


class TestNoncePersistence:
    """The stored nonce is what makes a swapped token from a DIFFERENT request
    (same imprint, so the structural check passes) detectable at re-verify
    time rather than only at anchor time — the gap SPEC.md section 17 used to
    state as unfixable with a record format that did not carry it."""

    def filed_record(self, tmp_path: Path, nonce: int | None):
        trail = tmp_path / "trail.jsonl"

        def transport(request: RemoteRequest) -> RemoteResponse:
            return RemoteResponse(status=200, body=granted_response(FRAME, nonce=nonce))

        RecordingAnchorSink(
            trail, Rfc3161AnchorSink("http://tsa", transport=transport, nonce_fn=lambda: nonce)
        ).anchor(CP)
        return trail, read_anchor_records(trail).records[0]

    def test_the_record_carries_the_request_nonce(self, tmp_path: Path) -> None:
        _, record = self.filed_record(tmp_path, 3)
        assert record.nonce == 3

    def test_the_nonce_is_stored_as_a_decimal_string(self, tmp_path: Path) -> None:
        # A 64-bit nonce as a bare JSON number is lossy in readers that parse
        # numbers as doubles; the sidecar stores it as a decimal string.
        trail, _ = self.filed_record(tmp_path, 2**63 + 1)
        obj = json.loads(Path(str(trail) + ".anchors").read_text())
        assert obj["nonce"] == str(2**63 + 1)

    def test_the_optional_field_does_not_bump_the_record_version(
        self, tmp_path: Path
    ) -> None:
        # Additive and optional: a reader that predates the field must keep
        # reading these records, so they stay v1 (beads-v1.2.2 class).
        _, record = self.filed_record(tmp_path, 3)
        assert record.version == 1

    def test_a_nonceless_request_leaves_the_field_absent(self, tmp_path: Path) -> None:
        # Absent, not null-or-zero: absence means "nothing to compare",
        # never a value (CLAUDE.md rule 5).
        trail, record = self.filed_record(tmp_path, None)
        assert record.nonce is None
        assert "nonce" not in json.loads(Path(str(trail) + ".anchors").read_text())

    def test_a_legacy_record_without_the_field_reads_as_nonce_none(
        self, tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        Path(str(trail) + ".anchors").write_text(
            json.dumps(
                {
                    "entry_hash": "e" * 64,
                    "receipt": None,
                    "root": "r" * 64,
                    "seq": 0,
                    "sink": "file",
                    "ts": "t",
                    "v": 1,
                }
            )
            + "\n"
        )
        assert read_anchor_records(trail).records[0].nonce is None
