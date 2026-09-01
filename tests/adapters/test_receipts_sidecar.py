"""The `.receipts` sidecar file itself (adapters/receipts.py).

Same discipline as `.anchors`/`.drops`/`.attest`: one JSON object per line,
O_APPEND under the file lock, mode 0600, named `<trail>.receipts` through the
same `with_name(name + suffix)` convention. SPEC.md section 19.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from waxseal.adapters.receipts import append_receipt, read_receipts, receipts_path
from waxseal.domain.receipt_fingerprint import receipt_fingerprint
from waxseal.domain.receipts import MalformedRecord, ReceiptRecord, UnreadableRecord

H0 = "a" * 64
H1 = "b" * 64
HEAD = "d" * 64


def test_sidecar_sits_beside_the_trail_under_the_anchors_convention(tmp_path: Path) -> None:
    trail = tmp_path / "trail.jsonl"
    assert receipts_path(trail) == tmp_path / "trail.jsonl.receipts"


def test_an_absent_sidecar_is_present_false_not_an_empty_one(tmp_path: Path) -> None:
    # Rule 5: "not recorded" and "recorded nothing" are different states.
    sidecar = read_receipts(tmp_path / "trail.jsonl")
    assert sidecar.present is False
    assert sidecar.lines == ()


def test_a_present_but_empty_sidecar_reports_present_true(tmp_path: Path) -> None:
    trail = tmp_path / "trail.jsonl"
    receipts_path(trail).write_text("")
    sidecar = read_receipts(trail)
    assert sidecar.present is True
    assert sidecar.lines == ()


def test_records_append_in_order_and_read_back(tmp_path: Path) -> None:
    trail = tmp_path / "trail.jsonl"
    append_receipt(
        trail,
        seq=0,
        entry_hash=H0,
        receipt_seq=0,
        receipt_head=HEAD,
        source="https://ledger.example",
        ts="2026-09-01T00:00:00+00:00",
    )
    append_receipt(
        trail,
        seq=1,
        entry_hash=H1,
        receipt_seq=1,
        receipt_head=HEAD,
        source="https://ledger.example",
        ts="2026-09-01T00:00:01+00:00",
    )
    lines = read_receipts(trail).lines
    assert [record.seq for record in lines if isinstance(record, ReceiptRecord)] == [0, 1]
    assert [record.line_no for record in lines] == [1, 2]


def test_appending_never_rewrites_an_existing_record(tmp_path: Path) -> None:
    # Append-only: the second record must leave the first byte-for-byte alone.
    trail = tmp_path / "trail.jsonl"
    append_receipt(
        trail, seq=0, entry_hash=H0, receipt_seq=0, receipt_head=HEAD, source="s", ts="t"
    )
    first = receipts_path(trail).read_text()
    append_receipt(
        trail, seq=1, entry_hash=H1, receipt_seq=1, receipt_head=HEAD, source="s", ts="t"
    )
    assert receipts_path(trail).read_text().startswith(first)


def test_sidecar_is_created_0600(tmp_path: Path) -> None:
    # As sensitive as the trail it corroborates (attest.py's precedent).
    trail = tmp_path / "trail.jsonl"
    append_receipt(
        trail, seq=0, entry_hash=H0, receipt_seq=0, receipt_head=HEAD, source="s", ts="t"
    )
    assert stat.S_IMODE(receipts_path(trail).stat().st_mode) == 0o600


def test_a_record_is_exactly_spec_19s_json_object(tmp_path: Path) -> None:
    trail = tmp_path / "trail.jsonl"
    append_receipt(
        trail,
        seq=0,
        entry_hash=H0,
        receipt_seq=4,
        receipt_head=HEAD,
        source="https://ledger.example",
        ts="2026-09-01T00:00:00+00:00",
    )
    obj = json.loads(receipts_path(trail).read_text())
    assert obj == {
        "entry_hash": H0,
        # waxseal-fg4.9: derived, checked separately below (test_fingerprint.py's
        # own style) rather than pinned as a literal here.
        "receipt_frame_fingerprint": receipt_fingerprint(),
        "receipt_head": HEAD,
        "receipt_seq": 4,
        "seq": 0,
        "source": "https://ledger.example",
        "ts": "2026-09-01T00:00:00+00:00",
        "v": 1,
    }


def test_blank_lines_are_skipped_but_line_numbers_stay_physical(tmp_path: Path) -> None:
    # An operator asked to look at line N must find the record there.
    trail = tmp_path / "trail.jsonl"
    receipts_path(trail).write_text("\n\n{not json\n")
    lines = read_receipts(trail).lines
    assert isinstance(lines[0], MalformedRecord)
    assert lines == (MalformedRecord(line_no=3, detail=lines[0].detail),)


def test_a_torn_line_is_read_as_a_malformed_record_not_a_crash(tmp_path: Path) -> None:
    trail = tmp_path / "trail.jsonl"
    receipts_path(trail).write_text('{"seq": 0, "entry_h\n')
    assert isinstance(read_receipts(trail).lines[0], MalformedRecord)


def test_a_newer_record_version_survives_reading(tmp_path: Path) -> None:
    trail = tmp_path / "trail.jsonl"
    receipts_path(trail).write_text(json.dumps({"v": 7, "seq": 0}) + "\n")
    assert read_receipts(trail).lines == (UnreadableRecord(line_no=1, version="7"),)


def test_a_record_this_build_wrote_reads_back_as_recognized(tmp_path: Path) -> None:
    # waxseal-fg4.9: read_receipts threads one ReceiptFrameRegistry through
    # every line it parses (adapters/receipts.py) rather than building one
    # per line; this is the end-to-end proof that a record this build itself
    # wrote is recognized on the way back in.
    trail = tmp_path / "trail.jsonl"
    append_receipt(
        trail, seq=0, entry_hash=H0, receipt_seq=0, receipt_head=HEAD, source="s", ts="t"
    )
    lines = read_receipts(trail).lines
    assert len(lines) == 1
    assert isinstance(lines[0], ReceiptRecord)
    assert lines[0].receipt_frame_fingerprint == receipt_fingerprint()


def test_a_record_declaring_an_alien_receipt_frame_survives_reading(tmp_path: Path) -> None:
    from waxseal.domain.receipts import UnrecognizedReceiptFrame

    trail = tmp_path / "trail.jsonl"
    receipts_path(trail).write_text(
        json.dumps(
            {
                "entry_hash": H0,
                "receipt_frame_fingerprint": "f" * 64,
                "receipt_head": HEAD,
                "receipt_seq": 0,
                "seq": 0,
                "source": "s",
                "ts": "t",
                "v": 1,
            }
        )
        + "\n"
    )
    assert read_receipts(trail).lines == (
        UnrecognizedReceiptFrame(line_no=1, fingerprint="f" * 64),
    )
