"""Cost receipts for the 0.1.5 Workstream A performance fixes.

Every assertion here counts something exact — bytes read off disk, `mkdir`
calls, live payload objects — and nothing here measures wall-clock time. A
CI-flaky timing bound is worse than no bound: it gets loosened until it
proves nothing (CLAUDE.md: tests never sleep to pass).

One receipt is NOT a byte count, and the reason is a finding rather than a
shortcut. `waxseal tail -n 5` over a JSONL trail reads the whole file either
way: `entries()` is a forward-only scan, so `list(...)[-5:]` and
`deque(maxlen=5)` read byte-for-byte the same input. What `list()` costs is
*retention* — 2000 decoded entries held at once so 1995 of them can be
thrown away. So the A1 receipt counts live payload objects, which CPython
reference counting makes as deterministic as a byte count.

## Falsifiability receipts (executed, then restored)

Each fix below was backed out of this tree, the receipt re-run, the number
recorded, and the fix restored. A cost bound nobody has watched fail is not a
bound.

**A1 - `_tail()` retention.** Reverted `cli.py::_tail` to:

    -    window: deque[Entry] = deque(maxlen=n)
    -    for entry in log.entries():
    -        window.append(entry)
    -    for entry in window:
    +    entries = list(log.entries())
    +    for entry in entries[-n:]:

    RED   peak live payloads = 2000 ("assert 2000 <= 8")
    GREEN peak live payloads = 6 - the 5-row window plus the one in flight

**A3 - `_integrity_scan` resume.** Reverted the method body to `byte_offset =
0` / `line_no = 0` with no `f.seek(byte_offset)` and no `self._scanned_*`
write-back:

    RED   first scan 22_390 bytes, second scan 24_630 bytes over a trail that
          had grown by 2_240 ("assert 24630 == 2240") - the second scan
          replayed the prefix it had already cleared
    GREEN first scan 22_390 bytes, second scan 2_240 bytes - exactly the
          bytes appended since the first scan, not one byte more

**A2 - one `mkdir` per append.** Restored the deleted
`self._path.parent.mkdir(parents=True, exist_ok=True)` inside `append()`:

    RED   2 mkdir calls for one append ("assert 2 == 1")
    GREEN 1 - the one `file_lock()` already makes

**A4 - `report` reads once.** Reverted `_report` to `log.verify(...)` plus a
separate `list(log.entries())`:

    RED   185_380 bytes read off a 92_690-byte trail (exactly 2x)
    GREEN 92_690 - one pass
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from waxseal.adapters.anchors import FileAnchorSink
from waxseal.adapters.jsonl import JSONLBackend, JSONLCorruptionError
from waxseal.adapters.receipts import append_receipt
from waxseal.cli import _report, _tail, _verify
from waxseal.cli._anchors import _anchor_check, _receipts_check, _witness_verdicts
from waxseal.cli.pin import _pin_check
from waxseal.domain.fingerprint import fingerprint
from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader
from waxseal.log import AuditLog

PAYLOAD_TYPE = "application/vnd.test.event+json"


def _byte_len(data: str | bytes) -> int:
    return len(data) if isinstance(data, bytes) else len(data.encode("utf-8"))


class _CountingFile:
    """Records the byte length of every slice handed back through iteration
    or ``.read()``. Same instrument as ``tests/adapters/test_jsonl.py``'s
    ``_ByteCountingFile``; kept separate so neither module's receipts can be
    changed out from under the other."""

    def __init__(self, fileobj: Any, sink: list[int]) -> None:
        self._fileobj = fileobj
        self._sink = sink

    def __enter__(self) -> _CountingFile:
        self._fileobj.__enter__()
        return self

    def __exit__(self, *exc: Any) -> Any:
        return self._fileobj.__exit__(*exc)

    def __iter__(self) -> _CountingFile:
        return self

    def __next__(self) -> Any:
        line = next(self._fileobj)
        self._sink.append(_byte_len(line))
        return line

    def read(self, *args: Any, **kwargs: Any) -> Any:
        data = self._fileobj.read(*args, **kwargs)
        self._sink.append(_byte_len(data))
        return data

    def seek(self, *args: Any, **kwargs: Any) -> Any:
        return self._fileobj.seek(*args, **kwargs)

    def tell(self, *args: Any, **kwargs: Any) -> Any:
        return self._fileobj.tell(*args, **kwargs)


def _count_reads_of(
    path: Path, monkeypatch: pytest.MonkeyPatch, sink: list[int]
) -> None:
    """Patch ``waxseal.adapters.jsonl.open`` so reads of ``path`` are counted."""
    real_open = open

    def counting_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        f = real_open(file, *args, **kwargs)
        if Path(file) == path:
            return _CountingFile(f, sink)
        return f

    import waxseal.adapters.jsonl as jsonl_module

    monkeypatch.setattr(jsonl_module, "open", counting_open, raising=False)


def _build_entry(seq: int, prev_hash: str, payload: bytes) -> Entry:
    header = EntryHeader(
        seq=seq,
        ts="2026-08-31T06:00:00+00:00",
        hash_version=fingerprint(),
        payload_type=PAYLOAD_TYPE,
        payload_hash=compute_payload_hash(payload),
        prev_hash=prev_hash,
    )
    return Entry(header=header, entry_hash=compute_entry_hash(header), payload=payload)


class _TrackedPayload(bytes):
    """A payload that decrements a shared counter when it is deallocated.

    A `bytes` subclass rather than a stand-in object, so nothing downstream
    has to special-case it: it IS the payload. `Entry` is a slotted frozen
    dataclass and therefore not weak-referenceable, which is why retention
    is measured through the payload rather than the entry.
    """

    _counter: list[int]

    def __new__(cls, data: bytes, counter: list[int]) -> _TrackedPayload:
        obj = super().__new__(cls, data)
        obj._counter = counter
        counter[0] += 1
        return obj

    def __del__(self) -> None:
        self._counter[0] -= 1


class _StreamingLog:
    """Just enough of ``AuditLog`` for ``_tail``: an ``entries()`` that builds
    entries lazily, so the only strong references to them are the ones the
    code under test holds."""

    def __init__(self, n: int) -> None:
        self._n = n
        self.live = [0]
        self.peak = 0

    def entries(self) -> Iterator[Entry]:
        prev_hash = GENESIS_PREV_HASH
        for seq in range(self._n):
            payload = _TrackedPayload(b'{"i":%d}' % seq, self.live)
            entry = _build_entry(seq, prev_hash, payload)
            prev_hash = entry.entry_hash
            self.peak = max(self.peak, self.live[0])
            yield entry
            # The generator frame's own locals would otherwise hold one more
            # entry alive across the yield, adding a constant to every
            # measurement below for no reason.
            del entry, payload


class TestTailRetention:
    def test_tail_holds_only_the_requested_window(self, capsys: pytest.CaptureFixture[str]) -> None:
        log = _StreamingLog(2000)

        assert _tail(log, 5) == 0  # type: ignore[arg-type]

        out = capsys.readouterr().out.splitlines()
        assert len(out) == 5
        assert "seq=1999" in out[-1]
        assert log.peak <= 8, (
            f"tail -n 5 over a 2000-entry trail held {log.peak} decoded payloads "
            "at once — the whole trail is being materialized before the window "
            "is sliced off the end"
        )

    def test_tail_prints_the_same_lines_a_full_materialization_would(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The streaming fix is only allowed to change cost. This pins the
        # output byte-for-byte against the slice it replaced.
        log = _StreamingLog(40)
        assert _tail(log, 7) == 0  # type: ignore[arg-type]
        streamed = capsys.readouterr().out

        expected = "".join(
            f"seq={e.header.seq} ts={e.header.ts} type={e.header.payload_type} "
            f"hash={e.entry_hash[:12]}\n"
            for e in list(_StreamingLog(40).entries())[-7:]
        )
        assert streamed == expected

    def test_tail_of_a_trail_shorter_than_the_window_prints_everything(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # deque(maxlen=n) and entries[-n:] must agree when n exceeds the
        # trail length: both print the whole trail, neither pads.
        log = _StreamingLog(3)
        assert _tail(log, 10) == 0  # type: ignore[arg-type]
        assert len(capsys.readouterr().out.splitlines()) == 3


class TestAppendMakesTheParentOnce:
    def test_append_creates_the_trail_parent_exactly_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # file_lock() already mkdirs the parent before taking the lock, so a
        # second mkdir inside append() is a syscall per append that can never
        # find anything left to do.
        calls: list[Path] = []
        real_mkdir = Path.mkdir

        def counting_mkdir(self: Path, *args: Any, **kwargs: Any) -> Any:
            calls.append(self)
            return real_mkdir(self, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", counting_mkdir)
        backend = JSONLBackend(tmp_path / "nested" / "trail.jsonl", integrity_scan_every=None)
        backend.append(lambda seq, prev: _build_entry(seq, prev, b"{}"))

        assert len(calls) == 1, (
            f"one append made {len(calls)} mkdir calls ({calls}) — the trail parent "
            "is created twice per append, once by the lock and once again inside it"
        )

    def test_append_still_creates_a_missing_parent_directory(self, tmp_path: Path) -> None:
        # The removed mkdir must not be load-bearing: the trail still lands
        # in a directory that did not exist when append() was called.
        path = tmp_path / "does" / "not" / "exist" / "trail.jsonl"
        backend = JSONLBackend(path, integrity_scan_every=None)
        backend.append(lambda seq, prev: _build_entry(seq, prev, b"{}"))
        assert path.exists()


class TestIntegrityScanResume:
    def _scan_bytes(
        self, backend: JSONLBackend, path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> int:
        sink: list[int] = []
        _count_reads_of(path, monkeypatch, sink)
        backend._integrity_scan()
        monkeypatch.undo()
        return sum(sink)

    def test_second_scan_reads_only_the_bytes_appended_since_the_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "trail.jsonl"
        # integrity_scan_every=None: the scans under measurement are the two
        # explicit calls below, never one the append loop fired on its own.
        backend = JSONLBackend(path, integrity_scan_every=None)
        for _ in range(50):
            backend.append(lambda seq, prev: _build_entry(seq, prev, b"{}"))

        size_after_50 = path.stat().st_size
        first = self._scan_bytes(backend, path, monkeypatch)
        assert first == size_after_50

        for _ in range(5):
            backend.append(lambda seq, prev: _build_entry(seq, prev, b"{}"))
        new_bytes = path.stat().st_size - size_after_50
        second = self._scan_bytes(backend, path, monkeypatch)

        assert second == new_bytes, (
            f"second scan read {second} bytes, expected exactly the {new_bytes} "
            f"appended since the first scan (trail is now {path.stat().st_size} "
            "bytes) — the scan is replaying the prefix it already cleared"
        )

    def test_corruption_after_the_resume_point_reports_absolute_line_and_offset(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The numbers in JSONLCorruptionError address the FILE, not the
        # scanned region. An operator handed "line 3" for line 53 would open
        # the wrong row of the wrong trail.
        path = tmp_path / "trail.jsonl"
        backend = JSONLBackend(path, integrity_scan_every=None)
        for _ in range(50):
            backend.append(lambda seq, prev: _build_entry(seq, prev, b"{}"))
        backend._integrity_scan()  # clears lines 1..50

        for _ in range(5):
            backend.append(lambda seq, prev: _build_entry(seq, prev, b"{}"))

        raw = path.read_bytes().split(b"\n")
        corrupt_line_no = 53
        raw[corrupt_line_no - 1] = raw[corrupt_line_no - 1][:-5]
        path.write_bytes(b"\n".join(raw))
        expected_offset = sum(len(line) + 1 for line in raw[: corrupt_line_no - 1])

        with pytest.raises(JSONLCorruptionError) as exc_info:
            backend._integrity_scan()
        assert exc_info.value.line_no == corrupt_line_no
        assert exc_info.value.byte_offset == expected_offset
        assert isinstance(exc_info.value.cause, json.JSONDecodeError)

    def test_a_trail_shorter_than_the_cleared_prefix_is_rescanned_whole(
        self, tmp_path: Path
    ) -> None:
        # Resuming from a remembered offset is only sound while the file is
        # the one that was cleared. A trail that got shorter (rotated,
        # truncated, replaced) is a different file at the same path, and the
        # remembered offset would seek past corruption that is now in front
        # of it.
        path = tmp_path / "trail.jsonl"
        backend = JSONLBackend(path, integrity_scan_every=None)
        for _ in range(50):
            backend.append(lambda seq, prev: _build_entry(seq, prev, b"{}"))
        backend._integrity_scan()

        lines = path.read_bytes().split(b"\n")[:10]
        lines[3] = lines[3][:-5]
        path.write_bytes(b"\n".join(lines))

        with pytest.raises(JSONLCorruptionError) as exc_info:
            backend._integrity_scan()
        assert exc_info.value.line_no == 4

    def test_a_fresh_backend_scans_the_whole_file_it_did_not_write(
        self, tmp_path: Path
    ) -> None:
        # The resume point is per-instance in-memory state: a new process
        # (new backend object) has cleared nothing and must scan everything.
        path = tmp_path / "trail.jsonl"
        writer = JSONLBackend(path, integrity_scan_every=None)
        for _ in range(9):
            writer.append(lambda seq, prev: _build_entry(seq, prev, b"{}"))
        writer._integrity_scan()

        lines = path.read_bytes().split(b"\n")
        lines[2] = lines[2][:-5]
        path.write_bytes(b"\n".join(lines))

        reader = JSONLBackend(path, integrity_scan_every=None)
        with pytest.raises(JSONLCorruptionError) as exc_info:
            reader._integrity_scan()
        assert exc_info.value.line_no == 3


class TestReportReadsOnce:
    def test_report_reads_the_trail_in_a_single_pass(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path)
        for i in range(200):
            log.append(payload={"i": i}, payload_type=PAYLOAD_TYPE)
        size = path.stat().st_size

        sink: list[int] = []
        _count_reads_of(path, monkeypatch, sink)
        code = _report(log, None, check_anchors=False, as_json=True)
        monkeypatch.undo()
        capsys.readouterr()

        assert code == 0
        assert sum(sink) == size, (
            f"report read {sum(sink)} bytes off a {size}-byte trail — it is "
            "verifying and summarizing in two separate passes"
        )

    def test_an_unterminated_final_line_is_re_read_by_the_next_scan(
        self, tmp_path: Path
    ) -> None:
        # A tail without its newline is a torn write, not a cleared line: the
        # bytes that complete it have not been seen yet, so clearing the
        # offset past them would skip whatever they turn out to be.
        path = tmp_path / "trail.jsonl"
        backend = JSONLBackend(path, integrity_scan_every=None)
        for _ in range(3):
            backend.append(lambda seq, prev: _build_entry(seq, prev, b"{}"))
        path.write_bytes(path.read_bytes()[:-1])  # drop the final newline

        backend._integrity_scan()  # clean: lines 1-2 cleared, line 3 is not

        lines = path.read_bytes().split(b"\n")
        lines[2] = lines[2][:-5]
        path.write_bytes(b"\n".join(lines))

        with pytest.raises(JSONLCorruptionError) as extra_info:
            backend._integrity_scan()
        assert extra_info.value.line_no == 3


class TestVerifyReadsHashesOnce:
    """P1: `verify --anchors --pin --witness` used to rematerialize the
    trail for each dimension. Receipt counts bytes read of the trail file
    only. RED (before the hashes argument) was k times the size; GREEN is
    one pass.
    """

    def test_verify_with_anchors_pin_and_witness_reads_the_trail_once(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, anchor_sink=FileAnchorSink(path))
        for i in range(40):
            log.append(payload={"i": i}, payload_type=PAYLOAD_TYPE)
        log.anchor()
        size = path.stat().st_size

        sink: list[int] = []
        _count_reads_of(path, monkeypatch, sink)
        code = _verify(
            log,
            path,
            check_anchors=True,
            pin_path=tmp_path / "pin.json",
            target=str(path),
            witnesses=["http://127.0.0.1:1"],
        )
        monkeypatch.undo()
        capsys.readouterr()

        assert code in (0, 2)
        assert sum(sink) == size, (
            f"verify --anchors --pin --witness read {sum(sink)} bytes off a "
            f"{size}-byte trail ({sum(sink) / size:.1f}x) — each dimension is "
            "calling entry_hashes() on its own pass"
        )

    def test_omitted_hashes_still_materializes_the_trail(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, anchor_sink=FileAnchorSink(path))
        entry = log.append(payload={"i": 0}, payload_type=PAYLOAD_TYPE)
        log.anchor()
        append_receipt(
            path,
            seq=0,
            entry_hash=entry.entry_hash,
            receipt_seq=0,
            receipt_head=entry.entry_hash,
            source="https://ledger.example",
            ts="2026-09-01T00:00:00+00:00",
        )

        assert _anchor_check(log, path).summary.ok
        assert _receipts_check(log, path).summary.ok
        assert _witness_verdicts(log, ["http://127.0.0.1:1"])
        check, _pending = _pin_check(
            log, tmp_path / "pin.json", target=str(path), chain_id=None
        )
        capsys.readouterr()
        assert check.summary.ok


class TestEntryHashesSkipPayloadDecode:
    """P2: `entry_hashes()` used to reconstruct every Entry, base64-decoding
    payload bytes that no hash check reads. Receipt counts `b64decode` calls
    during one `entry_hashes()` pass. RED = one decode per row; GREEN = 0.
    """

    def test_entry_hashes_does_not_decode_payload_b64(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path)
        n = 40
        for i in range(n):
            log.append(payload={"i": i, "blob": "x" * 200}, payload_type=PAYLOAD_TYPE)
        expected = [e.entry_hash for e in log.entries()]

        import base64

        sink: list[int] = []
        real = base64.b64decode

        def counting(
            data: str | bytes, altchars: bytes | None = None, validate: bool = False
        ) -> bytes:
            sink.append(1)
            return real(data, altchars, validate)

        monkeypatch.setattr("waxseal.adapters._envelope.base64.b64decode", counting)
        hashes = log.entry_hashes()
        monkeypatch.undo()

        assert hashes == expected
        assert sum(sink) == 0, (
            f"entry_hashes() decoded payload_b64 {sum(sink)} times on a "
            f"{n}-row trail — hashes-only callers do not need the payload"
        )


class TestBatchRootHashInvocations:
    """P3 measure-only. `batch_root` walks a full RFC 6962 tree on every
    call, so with `anchor_every=N` the cumulative SHA-256 count is
    O(n^2/N). Incremental Merkle would not change the rooted value
    (golden vectors stay byte-for-byte) but is an algorithm change next
    to frozen vectors -- owner must approve before any implementation.

    P4 is not a hash count: every server GET read/verify shells out
    (`server/waxseal_server/runtime/cli.py` `WaxsealCli.run`) because the
    CLI is the sole verdict authority. That is a design decision, not a
    leftover. Finding + proposal live in the b13c RE-MEASURE note.
    """

    def test_batch_root_still_matches_rfc6962_golden_vectors(self) -> None:
        from tests.domain.test_anchoring import RFC_LEAVES, RFC_ROOTS
        from waxseal.domain.anchoring import batch_root

        for size, expected in enumerate(RFC_ROOTS):
            assert batch_root(RFC_LEAVES[:size]) == expected

    @pytest.mark.parametrize("n", (1, 8, 32, 256))
    def test_one_full_tree_of_n_leaves_is_2n_minus_1_sha256_calls(
        self, n: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        from waxseal.domain import anchoring
        from waxseal.domain.anchoring import batch_root

        hashes = [hashlib.sha256(f"leaf-{i}".encode()).hexdigest() for i in range(n)]
        sink: list[int] = []
        real = hashlib.sha256

        def counting(data: bytes = b"", usedforsecurity: bool = True) -> hashlib._Hash:
            sink.append(1)
            return real(data)

        monkeypatch.setattr(anchoring.hashlib, "sha256", counting)
        batch_root(hashes)
        assert sum(sink) == 2 * n - 1, (
            f"batch_root of {n} leaves hashed {sum(sink)} times; "
            "the current recursive tree is 2n-1 (n leaves + n-1 nodes). "
            "Cumulative under anchor_every=N at sizes N,2N,...,mN is "
            "N*m*(m+1)-m (n=1000 N=10 -> 100900), which is the O(n^2/N) "
            "the plan named."
        )


