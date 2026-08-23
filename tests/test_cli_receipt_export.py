"""CLI: `waxseal receipt` — extract stored anchor receipts for external tools.

waxseal deliberately refuses to verify a CMS signature or an OpenTimestamps
proof (SPEC.md sections 17/18); `openssl ts -verify` and `ots verify` are the
delegated verifiers, and both need the raw bytes as FILES. Before this
command the extraction recipe was hand-written Python in
docs/anchoring-external-time.md — a recipe an operator under incident
pressure has to type correctly against an undocumented internal API.

Exit codes mirror the trail commands: 0 = wrote at least one receipt,
2 = sidecar present but nothing to extract (absence, never success and never
tampering), 3 = trail or sidecar missing (nothing read, nothing created),
1 = the sidecar itself is malformed (our format, our verdict).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from waxseal.cli import main
from waxseal.domain.checkpoint import Checkpoint, checkpoint_frame


def record(
    seq: int = 1, receipt: str | None = None, v: int = 1
) -> dict[str, object]:
    return {
        "entry_hash": "e" * 64,
        "receipt": receipt,
        "root": "r" * 64,
        "seq": seq,
        "sink": "x",
        "ts": "t",
        "v": v,
    }


def trail_with_sidecar(tmp_path: Path, records: list[dict[str, object]]) -> Path:
    # The command reads only the sidecar — the trail merely has to exist
    # (extraction is not verification; `verify --anchors` is the cross-check).
    trail = tmp_path / "trail.jsonl"
    trail.write_text("")
    Path(str(trail) + ".anchors").write_text(
        "".join(json.dumps(r) + "\n" for r in records)
    )
    return trail


def rfc3161_receipt(der: bytes) -> str:
    return "rfc3161:" + base64.b64encode(der).decode()


def ots_receipt(proof: bytes) -> str:
    return "ots:" + base64.b64encode(proof).decode()


def frame_for(seq: int) -> bytes:
    return checkpoint_frame(Checkpoint(seq=seq, entry_hash="e" * 64, root="r" * 64))


class TestNothingReadNothingCreated:
    def test_a_missing_trail_is_exit_3_and_creates_no_out_dir(
        self, tmp_path: Path
    ) -> None:
        out = tmp_path / "receipts"
        code = main(["receipt", str(tmp_path / "absent.jsonl"), "--out", str(out)])
        assert code == 3
        assert not out.exists()

    def test_a_missing_sidecar_is_exit_3_and_creates_no_out_dir(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        trail.write_text("")
        out = tmp_path / "receipts"
        assert main(["receipt", str(trail), "--out", str(out)]) == 3
        assert not out.exists()
        assert ".anchors" in capsys.readouterr().err

    def test_a_url_target_is_refused(self, tmp_path: Path) -> None:
        # A remote trail has no local sidecar location, same as `anchor`.
        assert main(["receipt", "https://x.example/t", "--out", str(tmp_path)]) == 1


class TestExtraction:
    def test_an_rfc3161_receipt_becomes_a_tsr_and_a_frame(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = trail_with_sidecar(tmp_path, [record(seq=1, receipt=rfc3161_receipt(b"DER"))])
        out = tmp_path / "a" / "receipts"  # nested: --out is created as needed
        assert main(["receipt", str(trail), "--out", str(out)]) == 0
        assert (out / "seq-1.tsr").read_bytes() == b"DER"
        # The frame is what the token's imprint commits to — without it the
        # operator has nothing to hand `openssl ts -verify -data`.
        assert (out / "seq-1.frame").read_bytes() == frame_for(1)
        lines = capsys.readouterr().out.splitlines()
        assert sum(1 for line in lines if line.startswith("wrote ")) == 2

    def test_an_ots_receipt_becomes_an_ots_file(self, tmp_path: Path) -> None:
        trail = trail_with_sidecar(tmp_path, [record(seq=4, receipt=ots_receipt(b"PROOF"))])
        out = tmp_path / "receipts"
        assert main(["receipt", str(trail), "--out", str(out)]) == 0
        assert (out / "seq-4.ots").read_bytes() == b"PROOF"
        assert (out / "seq-4.frame").read_bytes() == frame_for(4)

    def test_seq_filters_to_one_record(self, tmp_path: Path) -> None:
        trail = trail_with_sidecar(
            tmp_path,
            [
                record(seq=0, receipt=rfc3161_receipt(b"A")),
                record(seq=1, receipt=rfc3161_receipt(b"B")),
            ],
        )
        out = tmp_path / "receipts"
        assert main(["receipt", str(trail), "--seq", "0", "--out", str(out)]) == 0
        assert (out / "seq-0.tsr").read_bytes() == b"A"
        assert not (out / "seq-1.tsr").exists()

    def test_duplicate_seq_records_do_not_overwrite_each_other(
        self, tmp_path: Path
    ) -> None:
        # A duplicate record from a racing anchor trigger is a supported race
        # (adapters/anchors.py) — but the receipts differ (different serials),
        # and silently overwriting one would discard evidence.
        trail = trail_with_sidecar(
            tmp_path,
            [
                record(seq=1, receipt=rfc3161_receipt(b"FIRST")),
                record(seq=1, receipt=rfc3161_receipt(b"SECOND")),
            ],
        )
        out = tmp_path / "receipts"
        assert main(["receipt", str(trail), "--out", str(out)]) == 0
        assert (out / "seq-1.tsr").read_bytes() == b"FIRST"
        assert (out / "seq-1-2.tsr").read_bytes() == b"SECOND"
        assert (out / "seq-1-2.frame").exists()

    def test_the_trail_and_sidecar_are_untouched(self, tmp_path: Path) -> None:
        trail = trail_with_sidecar(tmp_path, [record(seq=1, receipt=rfc3161_receipt(b"D"))])
        sidecar = Path(str(trail) + ".anchors")
        before = sidecar.read_bytes()
        main(["receipt", str(trail), "--out", str(tmp_path / "receipts")])
        assert sidecar.read_bytes() == before
        assert trail.read_bytes() == b""


class TestNothingToExtract:
    def test_a_record_without_a_receipt_is_exit_2_labelled(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = trail_with_sidecar(tmp_path, [record(seq=1, receipt=None)])
        out = tmp_path / "receipts"
        assert main(["receipt", str(trail), "--out", str(out)]) == 2
        printed = capsys.readouterr().out
        assert "nothing to extract" in printed
        assert "NOT evidence of tampering" in printed
        assert not out.exists()

    def test_a_seq_that_matches_no_record_is_exit_2(self, tmp_path: Path) -> None:
        trail = trail_with_sidecar(tmp_path, [record(seq=1, receipt=rfc3161_receipt(b"D"))])
        assert main(
            ["receipt", str(trail), "--seq", "9", "--out", str(tmp_path / "r")]
        ) == 2

    def test_an_unknown_receipt_type_is_labelled_and_skipped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # RFC 6962 section 4.6: an unrecognized type is opaque, not an error —
        # and not silently dropped either (CLAUDE.md rule 6).
        trail = trail_with_sidecar(tmp_path, [record(seq=1, receipt="sigstore:AAAA")])
        assert main(["receipt", str(trail), "--out", str(tmp_path / "r")]) == 2
        printed = capsys.readouterr().out
        assert "'sigstore'" in printed
        assert "NOT evidence of tampering" in printed

    def test_an_unreadable_record_version_is_noted(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = trail_with_sidecar(tmp_path, [record(seq=1, receipt="x", v=99)])
        assert main(["receipt", str(trail), "--out", str(tmp_path / "r")]) == 2
        assert "unreadable format version" in capsys.readouterr().out

    def test_extracting_something_still_exits_0_beside_a_skipped_receipt(
        self, tmp_path: Path
    ) -> None:
        trail = trail_with_sidecar(
            tmp_path,
            [
                record(seq=0, receipt="sigstore:AAAA"),
                record(seq=1, receipt=rfc3161_receipt(b"D")),
            ],
        )
        assert main(["receipt", str(trail), "--out", str(tmp_path / "r")]) == 0


class TestMalformedSidecar:
    def test_a_malformed_sidecar_is_exit_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Our format, our verdict — same asymmetry `verify --anchors` keeps.
        trail = tmp_path / "trail.jsonl"
        trail.write_text("")
        Path(str(trail) + ".anchors").write_text("{ not json\n")
        assert main(["receipt", str(trail), "--out", str(tmp_path / "r")]) == 1
        assert "malformed_anchor" in capsys.readouterr().err
