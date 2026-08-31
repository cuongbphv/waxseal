"""Sealed-segment rotation: create-a-new-file, bind it, never rename (SPEC 20).

The mechanism under test is `sources/rotation.py::open_segmented`. It is the
one place in waxseal where the read-tail + append critical section spans TWO
files (CLAUDE.md rule 7, widened one level): the closing segment's tail is
read and the new segment's genesis binding is appended under a single
`segments.lock`, so N racing writers produce exactly one rotation.

`adapters/atomic.py` stays the single owner of the atomic-replace syscall:
nothing here renames anything. The active segment is simply the highest ordinal
present, and rotation only ever CREATES a file.
"""

from __future__ import annotations

import base64
import json
import threading
from pathlib import Path
from typing import Any

import pytest

from waxseal import AuditLog, Checkpoint
from waxseal.domain.header import GENESIS_PREV_HASH
from waxseal.domain.segments import ROTATION_PAYLOAD_TYPE
from waxseal.sources.rotation import (
    DEFAULT_MAX_SEGMENT_BYTES,
    active_segment,
    discover_segments,
    open_segmented,
)

PT = "application/vnd.test.event+json"

# A measured stored event line is ~462 bytes and a rotation binding ~624, so a
# test threshold has to sit well ABOVE one entry: a threshold under one entry
# would make every single open rotate again, which is a property of the
# fixture, not of the code. 5000 bytes leaves room for a fresh segment plus
# the eight events the concurrency tests write into it. The 16 MiB production
# constant is exercised on its own below.
TINY = 5000


def notices() -> tuple[list[str], Any]:
    lines: list[str] = []
    return lines, lines.append


def fill(path: Path, n: int = 1) -> AuditLog:
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)
    return log


def fill_over(path: Path, threshold: int = TINY) -> AuditLog:
    """Append real entries until ``path`` is past ``threshold``."""
    log = AuditLog.open(path)
    i = 0
    while not path.exists() or path.stat().st_size <= threshold:
        log.append(payload={"i": i}, payload_type=PT)
        i += 1
    return log


def grow_over(base: Path, log: AuditLog, threshold: int = TINY) -> None:
    """Append through ``log`` until its own active segment is past
    ``threshold``, so the next open rotates."""
    path = active_segment(base)
    i = 0
    while path.stat().st_size <= threshold:
        log.append(payload={"pad": i}, payload_type=PT)
        i += 1


def genesis_of(path: Path) -> dict[str, Any]:
    first = path.read_text(encoding="utf-8").splitlines()[0]
    return json.loads(first)


def payload_of(line: dict[str, Any]) -> Any:
    return json.loads(base64.b64decode(line["payload_b64"]))


def rotation_bindings(directory: Path) -> list[tuple[Path, Any]]:
    found = []
    for path in sorted(directory.glob("*.jsonl")):
        for entry in AuditLog.open(path).entries():
            if entry.header.payload_type == ROTATION_PAYLOAD_TYPE:
                assert entry.payload is not None
                found.append((path, json.loads(entry.payload)))
    return found


class TestNoRotationBelowTheThreshold:
    def test_a_fresh_trail_opens_at_the_path_it_was_given(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.jsonl"
        log = open_segmented(base)
        log.append(payload={"i": 0}, payload_type=PT)
        assert base.exists()
        assert sorted(p.name for p in tmp_path.glob("*.jsonl")) == ["trail.jsonl"]

    def test_a_small_trail_is_reopened_not_rotated(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.jsonl"
        fill(base, 2)
        open_segmented(base, max_segment_bytes=DEFAULT_MAX_SEGMENT_BYTES).append(
            payload={"i": 2}, payload_type=PT
        )
        assert sorted(p.name for p in tmp_path.glob("*.jsonl")) == ["trail.jsonl"]
        assert AuditLog.open(base).verify(measure_drops=False).checked == 3

    def test_an_oversized_file_with_no_complete_entry_is_not_rotated(
        self, tmp_path: Path
    ) -> None:
        # Nothing to bind a new segment to: there is no tail yet.
        base = tmp_path / "trail.jsonl"
        base.write_bytes(b"\n" * (TINY + 1))
        lines, notice = notices()
        open_segmented(base, max_segment_bytes=TINY, notice=notice)
        assert list(tmp_path.glob("*.jsonl")) == [base]


class TestRotationCreatesAndBinds:
    def test_an_unnumbered_base_is_adopted_and_the_next_segment_is_ordinal_zero(
        self, tmp_path: Path
    ) -> None:
        base = tmp_path / "trail.jsonl"
        fill_over(base)
        log = open_segmented(base, max_segment_bytes=TINY)
        log.append(payload={"i": "after"}, payload_type=PT)
        assert sorted(p.name for p in tmp_path.glob("*.jsonl")) == [
            "trail.00000.jsonl",
            "trail.jsonl",
        ]

    def test_a_numbered_active_segment_rotates_to_the_next_ordinal(
        self, tmp_path: Path
    ) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        open_segmented(base, max_segment_bytes=TINY)
        assert (tmp_path / "trail.00001.jsonl").exists()

    def test_the_new_segments_genesis_is_the_closing_tail_binding(
        self, tmp_path: Path
    ) -> None:
        base = tmp_path / "trail.00000.jsonl"
        closing = fill_over(base)
        hashes = closing.entry_hashes()
        tail_seq = len(hashes) - 1
        tail_hash = hashes[tail_seq]

        open_segmented(base, max_segment_bytes=TINY)

        line = genesis_of(tmp_path / "trail.00001.jsonl")
        assert line["header"]["payload_type"] == ROTATION_PAYLOAD_TYPE
        assert payload_of(line) == {
            "chain_id": f"{tmp_path.name}/trail.00000",
            "seq": tail_seq,
            "head_hash": tail_hash,
        }

    def test_segments_are_linked_by_the_binding_and_never_by_prev_hash(
        self, tmp_path: Path
    ) -> None:
        # A NEW chain: seq 0, prev_hash 64 zeros. Extending prev_hash across
        # the file boundary would make the whole history one chain again,
        # which is the growth problem rotation exists to solve.
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        open_segmented(base, max_segment_bytes=TINY)
        header = genesis_of(tmp_path / "trail.00001.jsonl")["header"]
        assert header["seq"] == 0
        assert header["prev_hash"] == GENESIS_PREV_HASH

    def test_both_segments_verify_on_their_own_after_rotation(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        log = open_segmented(base, max_segment_bytes=TINY)
        log.append(payload={"i": "after"}, payload_type=PT)
        assert AuditLog.open(base).verify(measure_drops=False).ok
        new = AuditLog.open(tmp_path / "trail.00001.jsonl").verify(measure_drops=False)
        assert new.ok
        assert new.checked == 2

    def test_the_closing_segment_gains_nothing_after_rotation(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        before = base.read_bytes()
        log = open_segmented(base, max_segment_bytes=TINY)
        log.append(payload={"i": "after"}, payload_type=PT)
        assert base.read_bytes() == before

    def test_rotation_renames_nothing(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        inode_before = base.stat().st_ino
        open_segmented(base, max_segment_bytes=TINY)
        assert base.stat().st_ino == inode_before

    def test_a_third_rotation_keeps_ordinals_ascending(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        for _ in range(3):
            log = open_segmented(base, max_segment_bytes=TINY)
            grow_over(base, log)
        assert sorted(p.name for p in tmp_path.glob("*.jsonl")) == [
            "trail.00000.jsonl",
            "trail.00001.jsonl",
            "trail.00002.jsonl",
            "trail.00003.jsonl",
        ]


class TestThresholdLabel:
    def test_the_built_in_default_is_sixteen_mebibytes(self) -> None:
        assert DEFAULT_MAX_SEGMENT_BYTES == 16 * 1024 * 1024 == 16777216

    def test_the_notice_prints_the_value_and_names_it_the_built_in_default(
        self, tmp_path: Path
    ) -> None:
        # Rule 6: a threshold, like a fail-open, carries its provenance —
        # "16777216" alone would read as something an operator had configured.
        base = tmp_path / "trail.00000.jsonl"
        fill(base, 1)
        lines, notice = notices()
        open_segmented(base, max_segment_bytes=DEFAULT_MAX_SEGMENT_BYTES, notice=notice)
        # 16 MiB is not reached, so nothing rotates and nothing is printed.
        assert lines == []
        # Padded with blank lines BEFORE the stored entry: the tail stays
        # readable (blank lines are not entries), which is what a real 16 MiB
        # segment looks like from the tail read's point of view.
        base.write_bytes(b"\n" * DEFAULT_MAX_SEGMENT_BYTES + base.read_bytes())
        open_segmented(base, max_segment_bytes=DEFAULT_MAX_SEGMENT_BYTES, notice=notice)
        assert len(lines) == 1
        assert "rotated at 16777216 bytes (built-in default)" in lines[0]

    def test_a_programmatic_caller_supplied_threshold_is_labelled_as_such(
        self, tmp_path: Path
    ) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        lines, notice = notices()
        open_segmented(base, max_segment_bytes=TINY, notice=notice)
        assert f"rotated at {TINY} bytes (caller-supplied)" in lines[0]

    def test_the_notice_names_both_segments(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        lines, notice = notices()
        open_segmented(base, max_segment_bytes=TINY, notice=notice)
        assert "trail.00000.jsonl" in lines[0]
        assert "trail.00001.jsonl" in lines[0]

    def test_the_default_notice_goes_to_stderr_never_stdout(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A hook's stdout is parsed by its host (Claude Code injects it into
        # model context); diagnostics belong on stderr.
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        open_segmented(base, max_segment_bytes=TINY)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "rotated at" in captured.err


class TestSidecarsFollowTheSegment:
    def test_drops_land_beside_the_new_segment(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        log = open_segmented(base, max_segment_bytes=TINY, record_drops=True)
        # A payload canonical_json cannot encode: try_append fails open and
        # records the loss (rule 6), and it must be recorded against the
        # segment actually being written.
        assert not log.try_append(payload={"bad": object()}, payload_type=PT)
        assert (tmp_path / "trail.00001.jsonl.drops").exists()
        assert not (tmp_path / "trail.00000.jsonl.drops").exists()

    def test_every_sidecar_name_derives_from_the_segment_with_no_new_code(
        self, tmp_path: Path
    ) -> None:
        # attest.py:68, drops.py:35 and anchors.py:136 all derive their path as
        # with_name(name + suffix), so a segment file carries its own sidecars
        # with zero code change. Proven, not assumed.
        from waxseal.adapters.anchors import _sidecar_path
        from waxseal.adapters.attest import FileAttestor
        from waxseal.adapters.drops import FileDropRecorder

        segment = tmp_path / "trail.00007.jsonl"
        assert _sidecar_path(segment).name == "trail.00007.jsonl.anchors"
        assert FileDropRecorder(segment)._path.name == "trail.00007.jsonl.drops"
        attestor = FileAttestor(segment, initial_key=b"k" * 32)
        assert attestor._attest_path.name == "trail.00007.jsonl.attest"
        assert attestor._agg_path.name == "trail.00007.jsonl.sealagg"


class TestFinalCheckpoint:
    def test_no_anchor_sink_means_no_checkpoint_attempt(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        lines, notice = notices()
        open_segmented(base, max_segment_bytes=TINY, notice=notice)
        assert not any("checkpoint" in line for line in lines)

    def test_the_closing_segment_gets_a_final_checkpoint(self, tmp_path: Path) -> None:
        class Sink:
            def __init__(self) -> None:
                self.checkpoints: list[Checkpoint] = []

            def anchor(self, cp: Checkpoint) -> None:
                self.checkpoints.append(cp)

        base = tmp_path / "trail.00000.jsonl"
        closing = fill_over(base)
        tail_seq = len(closing.entry_hashes()) - 1
        sink = Sink()
        open_segmented(base, max_segment_bytes=TINY, anchor_sink=sink)
        assert len(sink.checkpoints) == 1
        assert sink.checkpoints[0].seq == tail_seq

    def test_a_failing_final_checkpoint_is_labelled_and_never_blocks(
        self, tmp_path: Path
    ) -> None:
        class Broken:
            def anchor(self, cp: Checkpoint) -> None:
                raise OSError("sink offline")

        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        lines, notice = notices()
        open_segmented(base, max_segment_bytes=TINY, notice=notice, anchor_sink=Broken())
        assert (tmp_path / "trail.00001.jsonl").exists()
        assert any("final checkpoint" in line and "sink offline" in line for line in lines)


class TestCrashWindows:
    def test_a_crash_before_the_genesis_append_leaves_no_new_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)

        def boom(self: AuditLog, **kwargs: Any) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(AuditLog, "append", boom)
        with pytest.raises(OSError, match="disk full"):
            open_segmented(base, max_segment_bytes=TINY)
        assert not (tmp_path / "trail.00001.jsonl").exists()

    def test_the_next_open_retries_the_rotation_and_loses_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = tmp_path / "trail.00000.jsonl"
        closing = fill_over(base)
        expected_hash = closing.entry_hashes()[-1]

        def boom(self: AuditLog, **kwargs: Any) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(AuditLog, "append", boom)
        with pytest.raises(OSError):
            open_segmented(base, max_segment_bytes=TINY)
        monkeypatch.undo()

        open_segmented(base, max_segment_bytes=TINY)
        assert payload_of(genesis_of(tmp_path / "trail.00001.jsonl"))["head_hash"] == (
            expected_hash
        )

    def test_an_unreadable_closing_tail_is_labelled_and_does_not_rotate(
        self, tmp_path: Path
    ) -> None:
        # A torn last line from a crash mid-flush. Reported, never repaired
        # (rule 4), and never a crash on the writer's path.
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        with open(base, "a", encoding="utf-8") as f:
            f.write('{"header": {"seq": 1, "ts": "2026-')
        lines, notice = notices()
        open_segmented(base, max_segment_bytes=TINY, notice=notice)
        assert not (tmp_path / "trail.00001.jsonl").exists()
        assert any("NOT rotating" in line for line in lines)


class TestActiveSegmentAndDiscovery:
    def test_the_active_segment_is_the_highest_ordinal_present(self, tmp_path: Path) -> None:
        for name in ("trail.jsonl", "trail.00000.jsonl", "trail.00001.jsonl"):
            fill(tmp_path / name, 1)
        assert active_segment(tmp_path / "trail.jsonl").name == "trail.00001.jsonl"

    def test_the_unnumbered_base_is_active_until_the_first_rotation(
        self, tmp_path: Path
    ) -> None:
        fill(tmp_path / "trail.jsonl", 1)
        assert active_segment(tmp_path / "trail.jsonl").name == "trail.jsonl"

    def test_a_never_written_path_is_its_own_active_segment(self, tmp_path: Path) -> None:
        assert active_segment(tmp_path / "trail.00000.jsonl").name == "trail.00000.jsonl"

    def test_a_not_yet_created_project_directory_is_not_an_error(
        self, tmp_path: Path
    ) -> None:
        # The routed default names a per-project directory that does not exist
        # until the first append, and the threshold check runs BEFORE the lock
        # that would create it.
        base = tmp_path / "trails" / "project-0123456789ab" / "trail.00000.jsonl"
        assert active_segment(base) == base
        open_segmented(base).append(payload={"i": 0}, payload_type=PT)
        assert base.exists()

    def test_a_foreign_stem_is_not_part_of_this_trail(self, tmp_path: Path) -> None:
        fill(tmp_path / "trail.00000.jsonl", 1)
        fill(tmp_path / "other.00009.jsonl", 1)
        assert active_segment(tmp_path / "trail.jsonl").name == "trail.00000.jsonl"

    def test_a_loosely_numbered_name_is_not_a_segment(self, tmp_path: Path) -> None:
        fill(tmp_path / "trail.00000.jsonl", 1)
        fill(tmp_path / "trail.7.jsonl", 1)
        assert active_segment(tmp_path / "trail.jsonl").name == "trail.00000.jsonl"

    def test_discovery_orders_the_base_before_its_numbered_segments(
        self, tmp_path: Path
    ) -> None:
        for name in ("trail.00001.jsonl", "trail.jsonl", "trail.00000.jsonl"):
            fill(tmp_path / name, 1)
        assert [p.name for p in discover_segments(tmp_path)] == [
            "trail.jsonl",
            "trail.00000.jsonl",
            "trail.00001.jsonl",
        ]

    def test_discovery_ignores_a_stem_that_never_rotated(self, tmp_path: Path) -> None:
        # An unrotated single trail is not a segment directory: `waxseal
        # verify` is the command for it, and `waxseal segments` says so.
        fill(tmp_path / "trail.jsonl", 1)
        assert discover_segments(tmp_path) == []

    def test_discovery_of_a_missing_directory_is_empty_not_an_error(
        self, tmp_path: Path
    ) -> None:
        assert discover_segments(tmp_path / "nope") == []

    def test_discovery_covers_every_stem_in_the_directory(self, tmp_path: Path) -> None:
        for name in ("a.00000.jsonl", "a.00001.jsonl", "b.00000.jsonl", "b.00001.jsonl"):
            fill(tmp_path / name, 1)
        assert [p.name for p in discover_segments(tmp_path)] == [
            "a.00000.jsonl",
            "a.00001.jsonl",
            "b.00000.jsonl",
            "b.00001.jsonl",
        ]


class TestConcurrentRotation:
    """N writers racing one over-threshold segment.

    FALSIFIABILITY RECEIPT — measured 31/08/2026, not argued from theory.
    The `with file_lock(directory / _LOCK_BASE):` line in `open_segmented`
    was replaced by `contextlib.nullcontext()` (the only change) and these
    two tests were run:

        8 writers, threshold 5000 B, closing segment already over threshold

        with segments.lock     : segments=2, rotation_bindings=1   (3/3 runs)
        without segments.lock  : segments=3 or 4, rotation_bindings=8
                                 (3/3 runs; new-segment entry count came out
                                 5, 7, 12 and 14 across 6 runs instead of 9)

        both tests FAILED on every run without the lock:
          test_n_racing_writers_produce_exactly_one_rotation
            -> "Left contains one/2 more item(s): 'trail.00002.jsonl'"
          test_no_fork_and_no_event_split_across_segments
            -> "assert 12 == (8 + 1)" / "assert 5 == (8 + 1)" / "assert 14 == (8 + 1)"

    Note what does NOT break: the chain itself. Every segment still verified
    ok in every run, because each backend append holds its own per-file lock.
    What the missing segments.lock loses is the ONE-rotation invariant — a
    duplicate rotation binding per racing writer, and events scattered across
    segments nobody bound — which is why this critical section has to span
    both files rather than relying on the per-file lock underneath it.
    """

    def test_n_racing_writers_produce_exactly_one_rotation(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.00000.jsonl"
        fill_over(base)
        writers = 8
        ready = threading.Barrier(writers)
        errors: list[BaseException] = []

        def write(i: int) -> None:
            try:
                ready.wait(timeout=20)
                log = open_segmented(base, max_segment_bytes=TINY, notice=lambda _m: None)
                log.append(payload={"writer": i}, payload_type=PT)
            except BaseException as e:  # noqa: BLE001 - reported, not swallowed
                errors.append(e)

        threads = [threading.Thread(target=write, args=(i,)) for i in range(writers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert errors == []

        segments = sorted(p.name for p in tmp_path.glob("*.jsonl"))
        assert segments == ["trail.00000.jsonl", "trail.00001.jsonl"]
        # Exactly one rotation happened: one binding, not one per writer.
        assert len(rotation_bindings(tmp_path)) == 1

    def test_no_fork_and_no_event_split_across_segments(self, tmp_path: Path) -> None:
        base = tmp_path / "trail.00000.jsonl"
        closing_entries = len(fill_over(base).entry_hashes())
        writers = 8
        ready = threading.Barrier(writers)

        def write(i: int) -> None:
            ready.wait(timeout=20)
            log = open_segmented(base, max_segment_bytes=TINY, notice=lambda _m: None)
            log.append(payload={"writer": i}, payload_type=PT)

        threads = [threading.Thread(target=write, args=(i,)) for i in range(writers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        closing = AuditLog.open(base).verify(measure_drops=False)
        opened = AuditLog.open(tmp_path / "trail.00001.jsonl").verify(measure_drops=False)
        assert closing.ok and opened.ok
        # The closing segment was already over threshold before any writer
        # ran, so every event belongs to the new segment: 1 binding + N events.
        assert closing.checked == closing_entries
        assert opened.checked == writers + 1
