"""End-to-end tests for AuditLog with automatic anchoring: DESIGN.md's
anchoring-automation upgrade path, built on the Checkpoint primitives in
domain/checkpoint.py and the FileAnchorSink sidecar in adapters/anchors.py."""

import json
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.adapters.anchors import FileAnchorSink
from waxseal.domain.anchoring import batch_root
from waxseal.domain.checkpoint import Checkpoint

PT = "application/vnd.test.event+json"


def open_anchored(tmp_path: Path, *, anchor_every: int | None = 2) -> AuditLog:
    trail = tmp_path / "trail.jsonl"
    return AuditLog.open(
        trail,
        anchor_sink=FileAnchorSink(trail, now_fn=lambda: "2026-08-22T00:00:00+00:00"),
        anchor_every=anchor_every,
        now_fn=lambda: "2026-08-22T00:00:00+00:00",
    )


class TestAutoAnchoring:
    def test_anchors_every_n_appends(self, tmp_path: Path) -> None:
        log = open_anchored(tmp_path, anchor_every=2)
        for i in range(5):
            log.append(payload={"i": i}, payload_type=PT)
        lines = (tmp_path / "trail.jsonl.anchors").read_text().splitlines()
        # 5 appends, anchor_every=2 -> triggers when (seq+1) % 2 == 0: seq 1, 3.
        assert len(lines) == 2
        assert [json.loads(line)["seq"] for line in lines] == [1, 3]

    def test_no_anchoring_without_anchor_every(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = AuditLog.open(trail, anchor_sink=FileAnchorSink(trail))
        log.append(payload={"i": 0}, payload_type=PT)
        assert not (tmp_path / "trail.jsonl.anchors").exists()

    def test_no_anchoring_without_a_sink_even_with_anchor_every(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = AuditLog.open(trail, anchor_every=1)
        log.append(payload={"i": 0}, payload_type=PT)
        assert not (tmp_path / "trail.jsonl.anchors").exists()

    def test_non_positive_anchor_every_is_rejected_at_construction(
        self, tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        for bad in (0, -1):
            with pytest.raises(ValueError, match="anchor_every"):
                AuditLog.open(trail, anchor_sink=FileAnchorSink(trail), anchor_every=bad)

    def test_anchor_record_matches_checkpoint_for_that_prefix(self, tmp_path: Path) -> None:
        log = open_anchored(tmp_path, anchor_every=3)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        entries = list(log._backend.entries())
        hashes = [e.entry_hash for e in entries]
        line = (tmp_path / "trail.jsonl.anchors").read_text().splitlines()[0]
        obj = json.loads(line)
        assert obj["seq"] == 2
        assert obj["entry_hash"] == hashes[-1]
        assert obj["root"] == batch_root(hashes)
        assert obj["sink"] == "file"
        assert obj["v"] == 1


class TestExplicitAnchor:
    def test_anchor_method_returns_checkpoint_and_writes_sidecar(self, tmp_path: Path) -> None:
        log = open_anchored(tmp_path, anchor_every=None)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        cp = log.anchor()
        assert cp.seq == 2
        assert len((tmp_path / "trail.jsonl.anchors").read_text().splitlines()) == 1

    def test_anchor_on_empty_trail_raises(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = AuditLog.open(trail, anchor_sink=FileAnchorSink(trail))
        with pytest.raises(ValueError, match="empty"):
            log.anchor()

    def test_anchor_without_sink_raises(self, tmp_path: Path) -> None:
        log = AuditLog.open(tmp_path / "trail.jsonl")
        log.append(payload={"i": 0}, payload_type=PT)
        with pytest.raises(ValueError, match="anchor_sink"):
            log.anchor()

    def test_a_stale_hash_snapshot_does_not_rewind_the_incremental_tree(
        self, tmp_path: Path
    ) -> None:
        log = open_anchored(tmp_path, anchor_every=None)
        for i in range(5):
            log.append(payload={"i": i}, payload_type=PT)
        hashes = log.entry_hashes()
        prefix_root = log._merkle_root_for(hashes[:3])
        assert prefix_root == batch_root(hashes[:3])
        assert log._merkle.size == 5
        assert log.anchor().root == batch_root(hashes)

    def test_anchor_rebuilds_when_memory_last_leaf_disagrees_with_disk(
        self, tmp_path: Path
    ) -> None:
        from waxseal.domain.anchoring import IncrementalMerkle

        log = open_anchored(tmp_path, anchor_every=None)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        hashes = log.entry_hashes()
        log._merkle = IncrementalMerkle.from_hashes([*hashes[:-1], "ab" * 32])
        assert log._merkle.size == len(hashes)
        assert log._merkle.last_leaf != hashes[-1]
        cp = log.anchor()
        assert cp.root == batch_root(hashes)
        assert cp.entry_hash == hashes[-1]
        assert log._merkle.last_leaf == hashes[-1]


class TestAnchorFailuresNeverPropagate:
    class FailingSink:
        name = "failing"

        def anchor(self, checkpoint: Checkpoint) -> None:
            raise RuntimeError("network down")

    def test_failing_sink_increments_anchor_failures_not_dropped_writes(
        self, tmp_path: Path
    ) -> None:
        log = AuditLog.open(
            tmp_path / "trail.jsonl", anchor_sink=self.FailingSink(), anchor_every=1
        )
        entry = log.append(payload={"i": 0}, payload_type=PT)
        assert entry is not None
        assert log.anchor_failures == 1
        assert log.dropped_writes == 0
        assert len(list(log._backend.entries())) == 1

    def test_try_append_never_raises_on_anchor_failure(self, tmp_path: Path) -> None:
        log = AuditLog.open(
            tmp_path / "trail.jsonl", anchor_sink=self.FailingSink(), anchor_every=1
        )
        assert log.try_append(payload={"i": 0}, payload_type=PT) is True
        assert log.anchor_failures == 1


class TestFileAnchorSinkSidecar:
    def test_records_round_trip(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        sink = FileAnchorSink(trail, now_fn=lambda: "2026-08-22T00:00:00+00:00")
        cp = Checkpoint(seq=4, entry_hash="ab" * 32, root="cd" * 32)
        sink.anchor(cp)
        [record] = list(sink.records())
        assert record == cp

    def test_no_sidecar_yields_nothing(self, tmp_path: Path) -> None:
        sink = FileAnchorSink(tmp_path / "trail.jsonl")
        assert list(sink.records()) == []

    def test_duplicate_anchor_is_harmless_idempotent_content(self, tmp_path: Path) -> None:
        # A race between two anchor_every triggers can write the SAME
        # checkpoint twice; the record is idempotent, so this is harmless,
        # not corruption (plan's explicit design tradeoff for running the
        # anchor step outside the append lock).
        trail = tmp_path / "trail.jsonl"
        sink = FileAnchorSink(trail, now_fn=lambda: "2026-08-22T00:00:00+00:00")
        cp = Checkpoint(seq=4, entry_hash="ab" * 32, root="cd" * 32)
        sink.anchor(cp)
        sink.anchor(cp)
        records = list(sink.records())
        assert len(records) == 2
        assert records[0] == records[1] == cp


class TestSidecarAppendCriticalSection:
    """A torn concurrent append is the one way this sidecar reads as tampered
    with no attacker present: ``read_anchor_records`` raises on a line that is
    not a record, and the CLI renders that ANCHOR BROKEN (exit 1). Duplicate
    records from racing anchor triggers are a supported, documented race
    (module docstring of adapters/anchors.py), so the append itself must be
    one critical section — CLAUDE.md rule 7 applied to the sidecar.

    The receipt lines get long enough (64 KiB) that one append spans several
    write() syscalls: without the lock, a concurrent writer lands between
    them and interleaves the lines.

    Falsifiability receipt, actually measured (not assumed): with the
    ``file_lock`` in ``_append_record`` replaced by ``contextlib.nullcontext``
    this test failed on all 6 of 6 runs (2026-08-23, Windows 11, CPython via
    uv). Five runs lost records outright (captured counts: 27, 26, 23, 22 of
    32 survived — the count assertion, not a parse error, because Windows
    O_APPEND is a
    non-atomic seek-to-end + write, so a concurrent buffer chunk lands at the
    same offset and OVERWRITES its rival's); one run tore a line instead:
    ``json.decoder.JSONDecodeError: Extra data: line 1 column 13 (char 12)``
    from ``read_anchor_records`` — exactly the accidental corruption the CLI
    would have reported as ANCHOR BROKEN.
    """

    def test_concurrent_appends_never_tear_a_record(self, tmp_path: Path) -> None:
        import threading
        from concurrent.futures import ThreadPoolExecutor

        from waxseal.adapters.anchors import RecordingAnchorSink, read_anchor_records

        trail = tmp_path / "trail.jsonl"
        threads, per_thread = 8, 4

        def receipt_for(worker_id: int) -> str:
            # Per-worker bytes, so an overlap of two workers' writes cannot
            # reassemble into a line that happens to look intact.
            return chr(ord("a") + worker_id) * 65536

        class BigReceiptWitness:
            name = "fake-witness"

            def __init__(self, worker_id: int) -> None:
                self._receipt = receipt_for(worker_id)

            def anchor(self, checkpoint: Checkpoint) -> str:
                return self._receipt

        barrier = threading.Barrier(threads)

        def worker(worker_id: int) -> None:
            sink = RecordingAnchorSink(
                trail,
                BigReceiptWitness(worker_id),
                now_fn=lambda: "2026-08-23T00:00:00+00:00",
            )
            barrier.wait()
            for i in range(per_thread):
                sink.anchor(
                    Checkpoint(
                        seq=worker_id * per_thread + i, entry_hash="ab" * 32, root="cd" * 32
                    )
                )

        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(worker, range(threads)))

        # The strict reader is the assertion: it raises on any torn line.
        sidecar = read_anchor_records(trail)
        assert len(sidecar.records) == threads * per_thread
        assert sidecar.unreadable_versions == ()
        expected = {receipt_for(w) for w in range(threads)}
        assert all(record.receipt in expected for record in sidecar.records)


class TestReceiptAutoRecording:
    """The README-advertised pattern — `AuditLog.open(trail, anchor_sink=<external>,
    anchor_every=N)` — contacted the external witness (e.g. an RFC 3161 TSA) and
    DISCARDED every returned receipt: `append`'s auto-anchor ignored
    `sink.anchor(cp)`'s return value, and only the CLI wrapped sinks in
    RecordingAnchorSink. A receipt that never lands anywhere is evidence paid
    for and thrown away — worse than an anchor failure, because it is silent.
    `open()` on a LOCAL path must auto-wrap a non-recording sink so receipts
    land in `<trail>.anchors`; sinks that already record (RecordingAnchorSink,
    FileAnchorSink) and path-less backends (memory, remote) keep current
    behavior."""

    class StubWitness:
        name = "stub-witness"

        def __init__(self) -> None:
            self.calls = 0

        def anchor(self, checkpoint: Checkpoint) -> str:
            self.calls += 1
            return "stub-receipt-bytes"

    def test_open_records_external_receipt_in_anchors_sidecar(self, tmp_path: Path) -> None:
        from waxseal.adapters.anchors import read_anchor_records

        trail = tmp_path / "trail.jsonl"
        witness = self.StubWitness()
        log = AuditLog.open(trail, anchor_sink=witness, anchor_every=1)
        log.append(payload={"i": 0}, payload_type=PT)
        assert witness.calls == 1
        sidecar = read_anchor_records(trail)
        assert len(sidecar.records) == 1
        assert sidecar.records[0].receipt == "stub-receipt-bytes"
        assert sidecar.records[0].sink == "stub-witness"

    def test_already_wrapped_recording_sink_is_not_double_wrapped(self, tmp_path: Path) -> None:
        from waxseal.adapters.anchors import RecordingAnchorSink, read_anchor_records

        trail = tmp_path / "trail.jsonl"
        sink = RecordingAnchorSink(trail, self.StubWitness())
        log = AuditLog.open(trail, anchor_sink=sink, anchor_every=1)
        log.append(payload={"i": 0}, payload_type=PT)
        # One record per checkpoint, not two: double-wrapping would file the
        # same receipt twice and make the sidecar overstate anchor coverage.
        assert len(read_anchor_records(trail).records) == 1

    def test_file_anchor_sink_already_records_and_is_not_wrapped(self, tmp_path: Path) -> None:
        from waxseal.adapters.anchors import read_anchor_records

        trail = tmp_path / "trail.jsonl"
        log = AuditLog.open(trail, anchor_sink=FileAnchorSink(trail), anchor_every=1)
        log.append(payload={"i": 0}, payload_type=PT)
        # FileAnchorSink writes the sidecar itself; wrapping it would file
        # every checkpoint twice.
        assert len(read_anchor_records(trail).records) == 1

    def test_pathless_backend_keeps_sink_unwrapped(self, tmp_path: Path) -> None:
        # No local trail path (memory, remote) means no sidecar location to
        # record into — wrapping would invent one. Current behavior is kept.
        from waxseal.adapters.memory import MemoryBackend

        witness = self.StubWitness()
        log = AuditLog(MemoryBackend(), anchor_sink=witness, anchor_every=1)
        log.append(payload={"i": 0}, payload_type=PT)
        assert witness.calls == 1
        assert log._anchor_sink is witness
        assert not list(tmp_path.iterdir())


class TestSidecarPermissions:
    def test_anchors_sidecar_is_created_owner_only(self, tmp_path: Path) -> None:
        import os
        import sys

        if sys.platform == "win32":
            pytest.skip("POSIX permission bits")
        old_umask = os.umask(0o022)
        try:
            trail = tmp_path / "trail.jsonl"
            FileAnchorSink(trail).anchor(
                Checkpoint(seq=0, entry_hash="aa" * 32, root="bb" * 32)
            )
            mode = (tmp_path / "trail.jsonl.anchors").stat().st_mode
            assert (mode & 0o777) == 0o600
        finally:
            os.umask(old_umask)


class TestAnchorConcurrency:
    """Falsifiability receipt, actually measured (not assumed): with
    AuditLog._append_lock replaced by contextlib.nullcontext, 4 threads x 20
    appends on a shared anchored log (no attestor) forked 0 out of 5 runs
    (measured 2026-08-22: entries=80/80 and verify_chain().ok True every
    run). That is expected, not a gap — JSONLBackend already serializes
    read-tail+append in its OWN lock (CLAUDE.md rule 7, exercised by
    backend_contract.py's n-thread test); AuditLog._append_lock exists to
    additionally serialize a SIDECAR step with the append, which is exactly
    what TestAttestationCriticalSection in test_sealed_log.py already
    receipts for FileAttestor (240 appends, 1 attestation, with the lock
    removed). The anchor step here runs outside that same lock by design
    (see `append` in log.py), so this class instead pins the two properties
    that design actually promises: the chain still cannot fork (the
    backend's own lock), and a race between two anchor_every triggers only
    ever duplicates a harmless idempotent sidecar record, never corrupts one
    (see TestFileAnchorSinkSidecar above)."""

    def test_concurrent_anchored_appends_do_not_fork_and_anchors_stay_well_formed(
        self, tmp_path: Path
    ) -> None:
        from concurrent.futures import ThreadPoolExecutor

        log = open_anchored(tmp_path, anchor_every=5)
        threads, per_thread = 4, 20

        def worker(worker_id: int) -> None:
            for i in range(per_thread):
                log.append(payload={"w": worker_id, "i": i}, payload_type=PT)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(worker, range(threads)))

        total = threads * per_thread
        entries = list(log._backend.entries())
        assert len(entries) == total
        assert log.verify().ok

        lines = (tmp_path / "trail.jsonl.anchors").read_text().splitlines()
        # anchor_every=5 over `total` appends triggers at least total//5 times;
        # a race can duplicate a trigger but never skip or corrupt one.
        assert len(lines) >= total // 5
        for line in lines:
            obj = json.loads(line)  # never a half-written/corrupted line
            assert set(obj) == {"entry_hash", "receipt", "root", "seq", "sink", "ts", "v"}
