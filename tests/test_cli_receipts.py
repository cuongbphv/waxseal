"""CLI: what `verify --anchors` says about each kind of anchor receipt.

This file freezes the exit-code table, because the distinctions it encodes are
the ones an operator's alerting will be built on:

- a token that attests these exact bytes -> 0, and the line still says the
  signature was NOT verified;
- a token that attests OTHER bytes -> 1, checked and false;
- a token or receipt type this build cannot read -> 2, unverifiable by name;
- a pending OpenTimestamps proof -> unchanged exit with a printed note,
  because it is opaque by design rather than by version skew.

Note the deliberate asymmetry with a malformed sidecar: the sidecar is OUR
format, so garbage in it is exit 1, while unreadable third-party bytes inside
a receipt are exit 2.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.adapters.anchors import read_anchor_records
from waxseal.adapters.remote import RemoteRequest, RemoteResponse
from waxseal.cli import main
from waxseal.domain.checkpoint import Checkpoint, checkpoint_for, checkpoint_frame
from waxseal.domain.rfc3161 import _der_int, _der_oid, _tlv

PT = "application/vnd.test.event+json"


def granted_response(
    message: bytes, *, gen_time: bytes = b"20260823090000Z", nonce: int | None = None
) -> bytes:
    algid = _tlv(0x30, _der_oid("2.16.840.1.101.3.4.2.1") + _tlv(0x05, b""))
    imprint = _tlv(0x30, algid + _tlv(0x04, hashlib.sha256(message).digest()))
    tst = _tlv(
        0x30,
        _der_int(1)
        + _der_oid("1.2.3.4.1")
        + imprint
        + _der_int(7)
        + _tlv(0x18, gen_time)
        + (_der_int(nonce) if nonce is not None else b""),
    )
    signed = _tlv(
        0x30,
        _der_int(3)
        + _tlv(0x31, b"")
        + _tlv(0x30, _der_oid("1.2.840.113549.1.9.16.1.4") + _tlv(0xA0, _tlv(0x04, tst)))
        + _tlv(0x31, b""),
    )
    token = _tlv(0x30, _der_oid("1.2.840.113549.1.7.2") + _tlv(0xA0, signed))
    return _tlv(0x30, _tlv(0x30, _der_int(0)) + token)


def trail_with_receipt(tmp_path: Path, receipt: str | None, *, nonce: str | None = None) -> Path:
    """A two-entry trail whose one anchor record carries ``receipt``.

    Callable more than once per test: the entries are written only if the
    trail is not there yet, so the checkpoint (and therefore the frame a
    receipt must attest) stays the same across calls. ``nonce`` is the stored
    request nonce (decimal string, as the sink files it); omitted, the record
    reads exactly as every record written before the field existed.
    """
    path = tmp_path / "trail.jsonl"
    if not path.exists():
        log = AuditLog.open(path)
        for i in range(2):
            log.append(payload={"i": i}, payload_type=PT)
    cp = checkpoint_for(AuditLog.open(path).entry_hashes())
    record: dict[str, object] = {
        "entry_hash": cp.entry_hash,
        "receipt": receipt,
        "root": cp.root,
        "seq": cp.seq,
        "sink": "rfc3161",
        "ts": "2026-08-23T09:00:00+00:00",
        "v": 1,
    }
    if nonce is not None:
        record["nonce"] = nonce
    Path(str(path) + ".anchors").write_text(json.dumps(record) + "\n", encoding="utf-8")
    return path


def frame_of(path: Path) -> bytes:
    log = AuditLog.open(path)
    return checkpoint_frame(checkpoint_for(log.entry_hashes()))


def rfc3161_receipt(der: bytes) -> str:
    return "rfc3161:" + base64.b64encode(der).decode()


class TestAttestedTime:
    def test_a_token_for_these_bytes_passes_and_prints_the_time(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, None)
        receipt = rfc3161_receipt(granted_response(frame_of(path)))
        path = trail_with_receipt(tmp_path, receipt)

        assert main(["verify", str(path), "--anchors"]) == 0
        out = capsys.readouterr().out
        assert "attested time (RFC 3161" in out
        assert "2026-08-23T09:00:00+00:00" in out

    def test_the_line_never_claims_the_signature_was_verified(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The single most quotable line this library prints. If it ever loses
        # this caveat, a structural check starts reading as authentication.
        path = trail_with_receipt(tmp_path, None)
        path = trail_with_receipt(tmp_path, rfc3161_receipt(granted_response(frame_of(path))))
        main(["verify", str(path), "--anchors"])
        assert "signature NOT verified" in capsys.readouterr().out


class TestCheckedAndFalse:
    def test_a_token_attesting_other_bytes_is_exit_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, rfc3161_receipt(granted_response(b"other bytes")))
        assert main(["verify", str(path), "--anchors"]) == 1
        out = capsys.readouterr().out
        assert "ANCHOR BROKEN" in out
        assert "receipt_imprint_mismatch" in out

    def test_the_break_still_admits_the_signature_is_unchecked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, rfc3161_receipt(granted_response(b"other")))
        main(["verify", str(path), "--anchors"])
        assert "signature itself is still unverified" in capsys.readouterr().out


class TestNonceReplay:
    """A token swapped in from a DIFFERENT request over the same imprint
    passes every structural check except the nonce. Before the record carried
    the request nonce, re-verify had nothing to compare it against, so
    NONCE_MISMATCH was reachable at publish time only (the gap SPEC.md
    section 17 stated plainly). With a stored nonce it is checked-and-false:
    exit 1, same class as ``receipt_imprint_mismatch``."""

    def test_a_replayed_token_with_another_requests_nonce_is_exit_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, None)
        # Valid DER, the RIGHT imprint — only the nonce betrays the swap.
        receipt = rfc3161_receipt(granted_response(frame_of(path), nonce=6))
        path = trail_with_receipt(tmp_path, receipt, nonce="5")
        assert main(["verify", str(path), "--anchors"]) == 1
        out = capsys.readouterr().out
        assert "ANCHOR BROKEN" in out
        assert "nonce_mismatch" in out

    def test_the_matching_nonce_still_passes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, None)
        receipt = rfc3161_receipt(granted_response(frame_of(path), nonce=5))
        path = trail_with_receipt(tmp_path, receipt, nonce="5")
        assert main(["verify", str(path), "--anchors"]) == 0
        assert "attested time (RFC 3161" in capsys.readouterr().out

    def test_a_legacy_record_without_a_stored_nonce_keeps_its_verdict(self, tmp_path: Path) -> None:
        # Absence is not a mismatch (CLAUDE.md rule 5): every record written
        # before the field existed must verify exactly as it did — for those,
        # replay detection remains anchor-time-only.
        path = trail_with_receipt(tmp_path, None)
        receipt = rfc3161_receipt(granted_response(frame_of(path), nonce=6))
        path = trail_with_receipt(tmp_path, receipt)
        assert main(["verify", str(path), "--anchors"]) == 0

    def test_a_stored_nonce_that_is_not_an_integer_is_a_malformed_sidecar(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The nonce field is OUR format: garbage in it is exit 1
        # (malformed_anchor), not a foreign format this build happens
        # not to read.
        path = trail_with_receipt(tmp_path, None)
        receipt = rfc3161_receipt(granted_response(frame_of(path), nonce=5))
        path = trail_with_receipt(tmp_path, receipt, nonce="not-a-number")
        assert main(["verify", str(path), "--anchors"]) == 1
        assert "malformed_anchor" in capsys.readouterr().out


class TestUnverifiableReceipts:
    def test_an_unparseable_token_is_exit_2_not_exit_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, rfc3161_receipt(b"not der"))
        assert main(["verify", str(path), "--anchors"]) == 2
        out = capsys.readouterr().out
        assert "malformed_token" in out
        assert "NOT evidence of tampering" in out

    def test_a_receipt_whose_base64_will_not_decode_is_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, "rfc3161:!!! not base64 !!!")
        assert main(["verify", str(path), "--anchors"]) == 2
        assert "NOT evidence of tampering" in capsys.readouterr().out

    def test_a_rejected_status_is_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rejection = _tlv(0x30, _tlv(0x30, _der_int(2)))
        path = trail_with_receipt(tmp_path, rfc3161_receipt(rejection))
        assert main(["verify", str(path), "--anchors"]) == 2
        assert "timestamp_rejected" in capsys.readouterr().out

    def test_a_receipt_type_from_a_newer_build_is_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # RFC 6962 section 4.6: an unrecognized type is opaque, not an error.
        path = trail_with_receipt(tmp_path, "sigstore:AAAA")
        assert main(["verify", str(path), "--anchors"]) == 2
        out = capsys.readouterr().out
        assert "'sigstore'" in out
        assert "NOT evidence of tampering" in out


class TestOpenTimestampsIsNoted:
    def test_a_pending_proof_prints_a_note_and_does_not_change_the_exit(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, "ots:" + base64.b64encode(b"proof").decode())
        assert main(["verify", str(path), "--anchors"]) == 0
        out = capsys.readouterr().out
        assert "pending OpenTimestamps proof" in out
        assert "NOT checked" in out

    def test_it_is_not_silently_treated_as_a_pass(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, "ots:" + base64.b64encode(b"proof").decode())
        main(["verify", str(path), "--anchors"])
        assert "ots upgrade" in capsys.readouterr().out


class TestReportCarriesTheSameCaveats:
    """`report` is the artifact an auditor keeps; `verify` is the one an
    operator watches. A caveat that reaches only the second is a caveat that
    does not reach the file anybody reads six months later.

    Both commands run the same `_anchor_check`, and the notes lived on the
    printed line rather than on the summary, so `report --anchors` rendered
    `Anchors: ok (1 checked)` over a pending proof and over an aggregate
    binding it had not checked. Rule 6: an unperformed check is stated.
    """

    def test_markdown_report_states_the_pending_proof(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, "ots:" + base64.b64encode(b"proof").decode())
        assert main(["report", str(path), "--anchors"]) == 0
        out = capsys.readouterr().out
        assert "pending OpenTimestamps proof" in out
        assert "NOT checked" in out

    def test_json_report_carries_the_notes_as_data(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, "ots:" + base64.b64encode(b"proof").decode())
        assert main(["report", str(path), "--anchors", "--json"]) == 0
        notes = json.loads(capsys.readouterr().out)["anchors"]["notes"]
        assert any("pending OpenTimestamps proof" in note for note in notes)

    def test_a_clean_sidecar_carries_no_notes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The counterweight: notes must mean something, so a check with
        # nothing to caveat must not manufacture one.
        path = trail_with_receipt(tmp_path, None)
        assert main(["report", str(path), "--anchors", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["anchors"]["notes"] == []


class TestUnchangedBehaviour:
    def test_a_record_with_no_receipt_reads_exactly_as_before(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, None)
        assert main(["verify", str(path), "--anchors"]) == 0
        out = capsys.readouterr().out
        assert "anchors ok (checked=1" in out
        assert "note:" not in out

    def test_a_malformed_sidecar_is_still_exit_1(self, tmp_path: Path) -> None:
        # Our format, our verdict: garbage here is a break, not a foreign
        # format this build happens not to read.
        path = trail_with_receipt(tmp_path, None)
        Path(str(path) + ".anchors").write_text("{ not json\n", encoding="utf-8")
        assert main(["verify", str(path), "--anchors"]) == 1

    def test_a_broken_chain_shape_still_beats_a_receipt_verdict(self, tmp_path: Path) -> None:
        path = trail_with_receipt(tmp_path, rfc3161_receipt(granted_response(b"other")))
        anchors = Path(str(path) + ".anchors")
        record = json.loads(anchors.read_text(encoding="utf-8"))
        record["entry_hash"] = "f" * 64
        anchors.write_text(json.dumps(record) + "\n", encoding="utf-8")
        assert main(["verify", str(path), "--anchors"]) == 1


class TestAnchorSubcommandSinks:
    def test_no_flag_keeps_the_local_sidecar_sink(self, tmp_path: Path) -> None:
        from waxseal.cli import _anchor_sink

        sink = _anchor_sink(tmp_path / "t.jsonl", tsa_url=None, ots_calendar=None)
        assert type(sink).__name__ == "FileAnchorSink"

    def test_tsa_url_wraps_the_timestamp_sink_in_a_recorder(self, tmp_path: Path) -> None:
        from waxseal.cli import _anchor_sink

        sink = _anchor_sink(tmp_path / "t.jsonl", tsa_url="http://tsa", ots_calendar=None)
        assert type(sink).__name__ == "RecordingAnchorSink"
        assert sink.name == "rfc3161"  # type: ignore[attr-defined]

    def test_ots_calendar_wraps_the_calendar_sink_in_a_recorder(self, tmp_path: Path) -> None:
        from waxseal.cli import _anchor_sink

        sink = _anchor_sink(tmp_path / "t.jsonl", tsa_url=None, ots_calendar="http://cal")
        assert type(sink).__name__ == "RecordingAnchorSink"
        assert sink.name == "ots"  # type: ignore[attr-defined]

    def test_both_targets_together_write_two_records_over_the_same_checkpoint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # waxseal-4yk: the two used to be mutually exclusive at the argparse
        # level. One `anchor` run now reaches both independent domains — the
        # same checkpoint (computed once), one sidecar record per sink.
        path = tmp_path / "trail.jsonl"
        AuditLog.open(path).append(payload={"i": 0}, payload_type=PT)
        frame = frame_of(path)

        monkeypatch.setattr("waxseal.adapters.rfc3161._default_nonce", lambda: 4242)

        def tsa_transport(request: RemoteRequest) -> RemoteResponse:
            return RemoteResponse(status=200, body=granted_response(frame, nonce=4242))

        def ots_transport(request: RemoteRequest) -> RemoteResponse:
            return RemoteResponse(status=200, body=b"\x00pending-proof")

        monkeypatch.setattr(
            "waxseal.adapters.rfc3161.urllib_transport", lambda timeout=10.0: tsa_transport
        )
        monkeypatch.setattr(
            "waxseal.adapters.ots.urllib_transport", lambda timeout=10.0: ots_transport
        )

        rc = main(["anchor", str(path), "--tsa-url", "http://tsa", "--ots-calendar", "http://cal"])
        assert rc == 0

        records = read_anchor_records(path).records
        assert len(records) == 2
        assert {r.sink for r in records} == {"rfc3161", "ots"}
        assert {r.checkpoint.entry_hash for r in records} == {records[0].checkpoint.entry_hash}
        assert {r.checkpoint.root for r in records} == {records[0].checkpoint.root}
        assert {r.checkpoint.seq for r in records} == {records[0].checkpoint.seq}

    def test_tsa_unreachable_still_records_the_ots_result_and_labels_the_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        AuditLog.open(path).append(payload={"i": 0}, payload_type=PT)

        def ots_transport(request: RemoteRequest) -> RemoteResponse:
            return RemoteResponse(status=200, body=b"\x00pending-proof")

        monkeypatch.setattr(
            "waxseal.adapters.ots.urllib_transport", lambda timeout=10.0: ots_transport
        )

        # Port 0 is unroutable, so this fails without touching the network.
        rc = main(
            [
                "anchor",
                str(path),
                "--tsa-url",
                "http://127.0.0.1:0/tsr",
                "--ots-calendar",
                "http://cal",
            ]
        )
        assert rc == 1

        records = read_anchor_records(path).records
        assert len(records) == 1
        assert records[0].sink == "ots"

        err = capsys.readouterr().err
        assert "rfc3161" in err
        assert "nothing recorded" in err

    def test_an_unreachable_tsa_records_nothing_and_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        AuditLog.open(path).append(payload={"i": 0}, payload_type=PT)
        # Port 0 is unroutable, so this fails without touching the network.
        assert main(["anchor", str(path), "--tsa-url", "http://127.0.0.1:0/tsr"]) == 1
        assert not Path(str(path) + ".anchors").exists()
        assert "nothing recorded" in capsys.readouterr().err


class TestReceiptVerdictUnit:
    def test_a_checkpoint_with_a_binding_is_framed_as_v2_before_checking(self) -> None:
        # The receipt has to be checked against the SAME frame the sink sent,
        # binding included — otherwise every v2 anchor would read as a
        # mismatch the moment a trail started aggregating.
        from waxseal.adapters.anchors import AnchorRecord
        from waxseal.cli import _receipt_verdict

        cp = Checkpoint(seq=1, entry_hash="a" * 64, root="b" * 64, agg_commit="c" * 64, agg_epoch=2)
        record = AnchorRecord(
            checkpoint=cp,
            sink="rfc3161",
            receipt=rfc3161_receipt(granted_response(checkpoint_frame(cp))),
            ts="t",
            version=2,
        )
        assert _receipt_verdict(record).status == "checked"
