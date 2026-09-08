"""`waxseal segments <dir>`: read-only multi-segment verification (SPEC 20).

Condition R throughout: every "it reports X" criterion is asserted by running
`main()` and reading stdout, following `cadence`'s precedent — a verdict an
operator cannot see is not a verdict.

Exit codes are `Verdict.to_exit_code()`: 0 intact, 1 broken, 2
intact-but-unverifiable, plus 3 for "nothing was read" (no such directory, or
a directory holding no segments), the same shape `verify` already uses.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from waxseal import AuditLog
from waxseal.cli import main
from waxseal.sources.rotation import open_segmented

PT = "application/vnd.test.event+json"
TINY = 5000


def fill_over(path: Path, threshold: int = TINY) -> AuditLog:
    log = AuditLog.open(path)
    i = 0
    while not path.exists() or path.stat().st_size <= threshold:
        log.append(payload={"i": i}, payload_type=PT)
        i += 1
    return log


def rotate(base: Path, times: int = 1) -> None:
    """Produce ``times`` rotations under ``base``'s directory.

    Every segment but the LAST is grown back over the threshold so the next
    open rotates again; the last one is left holding only its rotation
    binding, which is what a freshly rotated trail actually looks like.
    """
    fill_over(base)
    for n in range(times):
        log = open_segmented(base, max_segment_bytes=TINY, notice=lambda _m: None)
        if n == times - 1:
            continue
        path = _active(base)
        while path.stat().st_size <= TINY:
            log.append(payload={"pad": path.name}, payload_type=PT)


def _active(base: Path) -> Path:
    from waxseal.sources.rotation import active_segment

    return active_segment(base)


def rewrite(path: Path, line_no: int, mutate: object) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[line_no])
    assert callable(mutate)
    mutate(obj)
    lines[line_no] = json.dumps(obj)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def set_payload(obj: dict[str, Any], payload: object) -> None:
    obj["payload_b64"] = base64.b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii")


class TestNothingRead:
    def test_a_missing_directory_exits_3(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["segments", str(tmp_path / "nope")]) == 3
        assert "no such" in capsys.readouterr().err

    def test_a_directory_with_no_segments_exits_3(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # An unrotated single trail is `waxseal verify`'s job; saying "ok, one
        # segment, all bindings hold" about it would be a verdict about
        # something that was never checked.
        fill_over(tmp_path / "trail.jsonl")
        assert main(["segments", str(tmp_path)]) == 3
        err = capsys.readouterr().err
        assert "no sealed segments" in err
        assert "waxseal verify" in err

    def test_a_file_instead_of_a_directory_exits_3(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        fill_over(path)
        assert main(["segments", str(path)]) == 3


class TestIntact:
    def test_a_rotated_pair_exits_0(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.00000.jsonl")
        assert main(["segments", str(tmp_path)]) == 0
        out = capsys.readouterr().out
        assert "trail.00000" in out
        assert "trail.00001" in out
        assert "ok" in out

    def test_every_segment_state_is_printed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.00000.jsonl", times=3)
        assert main(["segments", str(tmp_path)]) == 0
        out = capsys.readouterr().out
        for name in ("trail.00000", "trail.00001", "trail.00002", "trail.00003"):
            assert name in out, name

    def test_an_adopted_unnumbered_base_verifies_with_its_segment(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.jsonl")
        assert main(["segments", str(tmp_path)]) == 0
        out = capsys.readouterr().out
        assert "trail.00000" in out
        assert "trail " in out or "trail:" in out or "trail\n" in out

    def test_the_summary_names_the_aggregate_verdict(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.00000.jsonl")
        main(["segments", str(tmp_path)])
        out = capsys.readouterr().out
        assert "2 segment(s)" in out

    def test_it_appends_nothing_and_creates_nothing(self, tmp_path: Path) -> None:
        rotate(tmp_path / "trail.00000.jsonl")
        before = {p.name: p.read_bytes() for p in sorted(tmp_path.iterdir())}
        main(["segments", str(tmp_path)])
        after = {p.name: p.read_bytes() for p in sorted(tmp_path.iterdir())}
        assert after == before


class TestMissingSegment:
    def test_a_deleted_middle_segment_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Settled by the repository owner, 31/08/2026: BROKEN, exit 1. A
        # surviving binding is positive evidence the segment existed, so
        # deleting it must not downgrade the directory to exit 2.
        rotate(tmp_path / "trail.00000.jsonl", times=2)
        (tmp_path / "trail.00001.jsonl").unlink()
        assert main(["segments", str(tmp_path)]) == 1
        out = capsys.readouterr().out
        assert "segment_missing" in out
        assert "trail.00001" in out

    def test_the_missing_segment_is_never_printed_as_tampered(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.00000.jsonl", times=2)
        (tmp_path / "trail.00001.jsonl").unlink()
        main(["segments", str(tmp_path)])
        line = next(ln for ln in capsys.readouterr().out.splitlines() if "trail.00001" in ln)
        assert "missing" in line
        assert "tamper" not in line.lower()
        assert "broken" not in line.lower()

    def test_the_surviving_segments_still_report_their_own_state(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.00000.jsonl", times=2)
        (tmp_path / "trail.00001.jsonl").unlink()
        main(["segments", str(tmp_path)])
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("  ")]
        rendered = {ln.split()[0].rstrip(":") for ln in lines}
        assert {"trail.00000", "trail.00001", "trail.00002"} <= rendered

    def test_deleting_the_prefix_does_not_downgrade_to_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The segment that is left becomes the LOWEST ordinal present, but it
        # still carries a binding naming its predecessor — so it is still
        # asked about it. Exempting the lowest one unconditionally would make
        # prefix deletion free.
        rotate(tmp_path / "trail.00000.jsonl", times=2)
        (tmp_path / "trail.00000.jsonl").unlink()
        (tmp_path / "trail.00001.jsonl").unlink()
        assert main(["segments", str(tmp_path)]) == 1
        assert "segment_missing" in capsys.readouterr().out


class TestBrokenBindings:
    def test_a_non_first_segment_without_a_binding_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.00000.jsonl")
        # A second segment whose seq 0 is an ordinary event, not a binding.
        fill_over(tmp_path / "trail.00002.jsonl")
        assert main(["segments", str(tmp_path)]) == 1
        out = capsys.readouterr().out
        assert "rotation_binding_missing" in out
        assert "trail.00002" in out

    def test_a_tampered_binding_payload_exits_1_naming_that_segment(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.00000.jsonl")
        segment = tmp_path / "trail.00001.jsonl"
        original = json.loads(
            base64.b64decode(
                json.loads(segment.read_text(encoding="utf-8").splitlines()[0])["payload_b64"]
            )
        )

        def flip(obj: dict[str, Any]) -> None:
            set_payload(obj, {**original, "head_hash": "f" * 64})

        rewrite(segment, 0, flip)
        assert main(["segments", str(tmp_path)]) == 1
        out = capsys.readouterr().out
        # The chain break inside trail.00001 is what an edited payload really
        # is; the segment named is the edited one either way.
        assert "trail.00001" in out
        assert "payload_hash_mismatch" in out or "rotation_binding_mismatch" in out

    def test_a_rewritten_predecessor_tail_exits_1_with_a_binding_mismatch(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The attack the binding exists to catch: the closing segment is
        # replaced with a shorter, self-consistent chain, so its own
        # `verify` still says ok but the tail the binding named is gone.
        base = tmp_path / "trail.00000.jsonl"
        rotate(base)
        lines = base.read_text(encoding="utf-8").splitlines()
        base.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        assert AuditLog.open(base).verify(measure_drops=False).ok

        assert main(["segments", str(tmp_path)]) == 1
        out = capsys.readouterr().out
        assert "rotation_binding_mismatch" in out
        assert "trail.00001" in out


class TestUnverifiable:
    def test_an_unknown_fingerprint_aggregates_to_exit_2_not_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The beads-v1.2.2 replay, one layer up: a row from a schema this
        # build does not know must never make a whole segment directory
        # report tampering.
        from waxseal.domain.hashing import compute_entry_hash
        from waxseal.domain.header import EntryHeader

        rotate(tmp_path / "trail.00000.jsonl")
        segment = tmp_path / "trail.00001.jsonl"
        last = len(segment.read_text(encoding="utf-8").splitlines()) - 1

        def restamp(obj: dict[str, Any]) -> None:
            obj["header"]["hash_version"] = "e" * 64
            obj["entry_hash"] = compute_entry_hash(EntryHeader(**obj["header"]))

        rewrite(segment, last, restamp)
        assert main(["segments", str(tmp_path)]) == 2
        out = capsys.readouterr().out
        assert "unknown_fingerprint" in out
        assert "unverifiable" in out

    def test_an_unparseable_binding_payload_is_unverifiable(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.00000.jsonl")
        segment = tmp_path / "trail.00001.jsonl"

        def blank(obj: dict[str, Any]) -> None:
            # A binding the payload hash still matches, but whose fields this
            # build cannot read: unverifiable by name, never tampered.
            payload = {"chain_id": "slug/trail.00000"}
            set_payload(obj, payload)
            from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
            from waxseal.domain.header import EntryHeader

            raw = base64.b64decode(obj["payload_b64"])
            obj["header"]["payload_hash"] = compute_payload_hash(raw)
            obj["entry_hash"] = compute_entry_hash(EntryHeader(**obj["header"]))

        rewrite(segment, 0, blank)
        assert main(["segments", str(tmp_path)]) == 2
        out = capsys.readouterr().out
        assert "rotation_binding_unreadable" in out

    def test_a_torn_segment_is_reported_and_never_repaired(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Crash window mid-genesis-append: the first line of the new segment
        # is half-written. Rule 4 — reported, never repaired.
        rotate(tmp_path / "trail.00000.jsonl")
        segment = tmp_path / "trail.00001.jsonl"
        segment.write_text('{"header": {"seq": 0, "ts": "2026-\n', encoding="utf-8")
        before = segment.read_bytes()

        assert main(["segments", str(tmp_path)]) == 2
        out = capsys.readouterr().out
        assert "segment_unreadable" in out
        assert segment.read_bytes() == before

    def test_a_binding_against_a_torn_predecessor_is_unchecked_not_broken(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.00000.jsonl", times=2)
        (tmp_path / "trail.00001.jsonl").write_text("{not json\n", encoding="utf-8")
        assert main(["segments", str(tmp_path)]) == 2
        out = capsys.readouterr().out
        assert "segment_unreadable" in out
        assert "rotation_binding_unchecked" in out


class TestBrokenChainInsideASegment:
    def test_a_break_names_the_segment_and_the_seq(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rotate(tmp_path / "trail.00000.jsonl")
        segment = tmp_path / "trail.00001.jsonl"
        last = len(segment.read_text(encoding="utf-8").splitlines()) - 1

        def touch_ts(obj: dict[str, Any]) -> None:
            obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"

        rewrite(segment, last, touch_ts)
        assert main(["segments", str(tmp_path)]) == 1
        out = capsys.readouterr().out
        assert "entry_hash_mismatch" in out
        assert f"seq={last}" in out
        assert "trail.00001" in out

    def test_a_break_outranks_an_unverifiable_segment_elsewhere(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Verdict.join, not max() over exit codes: 2 is the larger code but
        # the weaker finding, so a real break must still win.
        rotate(tmp_path / "trail.00000.jsonl", times=2)
        (tmp_path / "trail.00001.jsonl").write_text("{not json\n", encoding="utf-8")
        segment = tmp_path / "trail.00002.jsonl"
        last = len(segment.read_text(encoding="utf-8").splitlines()) - 1

        def touch_ts(obj: dict[str, Any]) -> None:
            obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"

        rewrite(segment, last, touch_ts)
        assert main(["segments", str(tmp_path)]) == 1
        assert "segment_unreadable" in capsys.readouterr().out


class TestUnusualSegmentContents:
    def test_a_zero_byte_segment_has_no_binding_to_check(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Crash between creating the new segment file and writing its genesis
        # line: the file is there and holds nothing.
        rotate(tmp_path / "trail.00000.jsonl")
        (tmp_path / "trail.00002.jsonl").write_bytes(b"")
        assert main(["segments", str(tmp_path)]) == 1
        assert "rotation_binding_missing" in capsys.readouterr().out

    def test_a_non_json_genesis_payload_is_not_a_binding(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Raw bytes are a legal payload (SPEC: payload is arbitrary bytes), so
        # a seq 0 that will not decode as JSON is simply not a binding.
        rotate(tmp_path / "trail.00000.jsonl")
        AuditLog.open(tmp_path / "trail.00002.jsonl").append(
            payload=b"\xff\xfe raw bytes", payload_type=PT
        )
        assert main(["segments", str(tmp_path)]) == 1
        assert "rotation_binding_missing" in capsys.readouterr().out

    def test_a_header_only_reader_yields_no_binding_rather_than_a_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # `Entry.payload` is Optional by contract (None means "not available
        # to this reader"). The JSONL backend `segments` walks always carries
        # payload bytes, but a verdict must not depend on that staying true.
        from waxseal.cli import _read_segment
        from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader
        from waxseal.domain.verify import VerifyResult

        rotate(tmp_path / "trail.00000.jsonl")
        header = EntryHeader(
            seq=0,
            ts="2026-08-31T00:00:00+00:00",
            hash_version="a" * 64,
            payload_type="application/vnd.waxseal.rotation-binding+json",
            payload_hash="b" * 64,
            prev_hash=GENESIS_PREV_HASH,
        )
        entry = Entry(header=header, entry_hash="c" * 64, payload=None)
        result = VerifyResult(
            ok=True,
            checked=1,
            broken_seq=None,
            reason=None,
            unverifiable=(),
            dropped_writes=None,
        )
        monkeypatch.setattr(AuditLog, "_verify_and_entries", lambda self: (result, [entry]))
        read = _read_segment(tmp_path / "trail.00001.jsonl")
        assert read.genesis_payload is None
        assert read.genesis_payload_type == ("application/vnd.waxseal.rotation-binding+json")
