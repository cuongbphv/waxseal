"""Tests for the JSONL backend (SPEC.md section 7)."""

import json
from pathlib import Path
from typing import Any

import pytest

from waxseal.adapters import jsonl as jsonl_module
from waxseal.adapters._envelope import to_obj
from waxseal.adapters.jsonl import (
    _TAIL_SEEK_CHUNK,
    JSONLBackend,
    JSONLCorruptionError,
    read_last_line,
)
from waxseal.domain.fingerprint import fingerprint
from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash, header_frame
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader


def build_entry(seq: int, prev_hash: str, payload: bytes = b"{}") -> Entry:
    header = EntryHeader(
        seq=seq,
        ts="2026-08-21T06:00:00+00:00",
        hash_version=fingerprint(),
        payload_type="application/vnd.test.event+json",
        payload_hash=compute_payload_hash(payload),
        prev_hash=prev_hash,
    )
    return Entry(header=header, entry_hash=compute_entry_hash(header), payload=payload)


def build_entry_v2(seq: int, prev_hash: str, payload: bytes = b"{}") -> Entry:
    """Sibling of ``build_entry``, lp64v2-signed — for the cross-backend v2
    parity net (waxseal-7tk.7.5). ``build_entry`` itself stays v1-only: many
    other tests across this suite depend on that default for their own
    purposes."""
    header = EntryHeader(
        seq=seq,
        ts="2026-08-21T06:00:00+00:00",
        hash_version=fingerprint(),
        payload_type="application/vnd.test.event+json",
        payload_hash=compute_payload_hash(payload),
        prev_hash=prev_hash,
    )
    return Entry(
        header=header,
        entry_hash=compute_entry_hash(header, frame=header_frame),
        payload=payload,
    )


class TestAppend:
    def test_first_append_gets_seq_0_and_genesis_prev(self, tmp_path: Path) -> None:
        backend = JSONLBackend(tmp_path / "trail.jsonl")
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(0, GENESIS_PREV_HASH)]

    def test_second_append_links_to_first(self, tmp_path: Path) -> None:
        backend = JSONLBackend(tmp_path / "trail.jsonl")
        first = backend.append(lambda seq, prev: build_entry(seq, prev))
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(1, first.entry_hash)]

    def test_line_layout_matches_spec(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        JSONLBackend(path).append(lambda seq, prev: build_entry(seq, prev, b'{"a":1}'))
        line = path.read_text(encoding="utf-8").splitlines()[0]
        obj = json.loads(line)
        assert set(obj) == {"header", "entry_hash", "payload_b64"}
        assert set(obj["header"]) == {
            "seq",
            "ts",
            "hash_version",
            "payload_type",
            "payload_hash",
            "prev_hash",
        }
        import base64

        assert base64.b64decode(obj["payload_b64"]) == b'{"a":1}'


class TestReadLastLinePublic:
    def test_the_private_alias_is_gone(self) -> None:
        # 0.1.6 promoted read_last_line and kept `_read_last_line` bound for
        # one release; nothing in src/, server/ or tests/ imports it any more
        # (tests/architecture/test_layers.py forbids the import), so a leftover
        # binding would only be a second name for one function.
        assert not hasattr(jsonl_module, "_read_last_line")

    def test_missing_and_empty_files_yield_none(self, tmp_path: Path) -> None:
        assert read_last_line(tmp_path / "absent.jsonl") is None
        empty = tmp_path / "empty.jsonl"
        empty.write_bytes(b"")
        assert read_last_line(empty) is None

    def test_it_returns_the_last_non_blank_line(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        path.write_bytes(b'{"a":1}\n{"b":2}\n\n')
        assert read_last_line(path) == b'{"b":2}'


class TestRoundTrip:
    def test_entries_round_trip_byte_exact(self, tmp_path: Path) -> None:
        backend = JSONLBackend(tmp_path / "trail.jsonl")
        written = [
            backend.append(lambda seq, prev: build_entry(seq, prev, b'{"vi\xe1\xbb\x87t":1}'))
            for _ in range(3)
        ]
        assert list(backend.entries()) == written

    def test_empty_file_yields_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        path.touch()
        assert list(JSONLBackend(path).entries()) == []

    def test_missing_file_yields_nothing(self, tmp_path: Path) -> None:
        assert list(JSONLBackend(tmp_path / "absent.jsonl").entries()) == []

    def test_a_blank_line_in_the_trail_is_skipped_not_parsed(self, tmp_path: Path) -> None:
        # An editor that leaves a trailing newline, or a partial flush, must
        # not turn into a JSON error mid-audit — nor into a phantom entry.
        path = tmp_path / "trail.jsonl"
        backend = JSONLBackend(path)
        backend.append(lambda seq, prev: build_entry(seq, prev, b"a"))
        body = path.read_text(encoding="utf-8")
        path.write_text(f"\n{body}\n\n", encoding="utf-8")
        assert len(list(backend.entries())) == 1


class TestTrailPermissions:
    def test_trail_file_is_created_owner_only(self, tmp_path: Path) -> None:
        # The trail holds prompts, tool output, and file contents at a
        # predictable path (~/.claude/waxseal/...): default-umask 0644 hands
        # every local user the whole audit trail. Only the sealkey was 0600.
        import os
        import sys

        import pytest

        if sys.platform == "win32":
            pytest.skip("POSIX permission bits")
        from waxseal import AuditLog

        old_umask = os.umask(0o022)
        try:
            trail = tmp_path / "trail.jsonl"
            AuditLog.open(trail).append(
                payload={"i": 0}, payload_type="application/vnd.test.event+json"
            )
            assert (trail.stat().st_mode & 0o777) == 0o600
        finally:
            os.umask(old_umask)


def _byte_len(data: "str | bytes") -> int:
    return len(data) if isinstance(data, bytes) else len(data.encode("utf-8"))


class _ByteCountingFile:
    """Wraps a real file object and records the byte length of every slice
    handed back through iteration or .read(), so the cost receipt below
    counts bytes actually read rather than wall-clock time (CLAUDE.md rule 9:
    wall-clock is flaky on CI; a byte count is not).

    ``seek``/``tell`` pass through uncounted (positioning reads no bytes) —
    the tail-read fix (waxseal-7tk.1.2) opens the trail in binary mode and
    seeks from EOF, unlike the old whole-file forward parse this wrapper was
    first written against."""

    def __init__(self, fileobj: Any, sink: list[int]) -> None:
        self._fileobj = fileobj
        self._sink = sink

    def __enter__(self) -> "_ByteCountingFile":
        self._fileobj.__enter__()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._fileobj.__exit__(*exc)

    def __iter__(self) -> "_ByteCountingFile":
        return self

    def __next__(self) -> str:
        line: str = next(self._fileobj)
        self._sink.append(_byte_len(line))
        return line

    def read(self, *args: Any, **kwargs: Any) -> "str | bytes":
        data: str | bytes = self._fileobj.read(*args, **kwargs)
        self._sink.append(_byte_len(data))
        return data

    def seek(self, *args: Any, **kwargs: Any) -> int:
        pos: int = self._fileobj.seek(*args, **kwargs)
        return pos

    def tell(self, *args: Any, **kwargs: Any) -> int:
        pos: int = self._fileobj.tell(*args, **kwargs)
        return pos


class TestCostReceipt:
    def _bytes_read_by_last_append(
        self, path: Path, n: int, monkeypatch: "pytest.MonkeyPatch"
    ) -> int:
        # Build n-1 entries with the real open(), then instrument only the
        # nth (last) append so we measure one append's read cost, not the
        # cost of building the fixture trail.
        #
        # integrity_scan_every=None: this test isolates the tail-read fix
        # (waxseal-7tk.1.2) from the periodic corruption scan, a separate,
        # deliberate feature with its own amortized-cost tests below. Without
        # this, n=1000 lands exactly on the default scan_every=1000 boundary
        # and the scan's full-file read would masquerade as a tail-read
        # regression here.
        backend = JSONLBackend(path, integrity_scan_every=None)
        for _ in range(n - 1):
            backend.append(lambda seq, prev: build_entry(seq, prev))

        sink: list[int] = []
        real_open = open

        def counting_open(file: Any, *args: Any, **kwargs: Any) -> Any:
            f = real_open(file, *args, **kwargs)
            if Path(file) == path:
                return _ByteCountingFile(f, sink)
            return f

        import waxseal.adapters.jsonl as jsonl_module

        monkeypatch.setattr(jsonl_module, "open", counting_open, raising=False)
        backend.append(lambda seq, prev: build_entry(seq, prev))
        monkeypatch.undo()
        return sum(sink)

    # Falsifiability receipt (CLAUDE.md rule 9 — state the incident, not the
    # mechanics): measured on this tree before any fix, `_tail_locked()`
    # parses every prior line on every append (full O(n) scan). Observed:
    # bytes_read(n=10) = 4_023, bytes_read(n=1000) = 448_441, ratio ~111.5x.
    # The assertion below (ratio <= 2x) fails with
    # "448441 <= 8046" — proving this test is not vacuously true today.
    # It must start passing only once waxseal-7tk.1.2 (seek-from-end tail
    # read) lands; do not "fix" it by loosening the bound.
    def test_append_does_not_scan_the_trail(
        self, tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:
        bytes_at_10 = self._bytes_read_by_last_append(tmp_path / "n10.jsonl", 10, monkeypatch)
        bytes_at_1000 = self._bytes_read_by_last_append(tmp_path / "n1000.jsonl", 1000, monkeypatch)
        assert bytes_at_1000 <= bytes_at_10 * 2, (
            f"append at n=1000 read {bytes_at_1000} bytes vs n=10 read "
            f"{bytes_at_10} bytes (ratio {bytes_at_1000 / bytes_at_10:.1f}x) "
            "— _tail_locked() is scanning the whole trail, not just the tail"
        )

    def _bytes_read_by_all_appends(
        self,
        path: Path,
        n: int,
        integrity_scan_every: int | None,
        monkeypatch: "pytest.MonkeyPatch",
        *,
        resumable_scan: bool = True,
    ) -> int:
        # Unlike _bytes_read_by_last_append (which isolates one call to
        # prove the tail-read fix), the amortized-scan claim is about total
        # cost across n appends, so every append here is instrumented.
        #
        # resumable_scan=False restores the pre-0.1.5 scan, which re-read the
        # whole file on every fire, by resetting the resume point before each
        # call. It is how the falsifiability receipt below still has a "bad"
        # configuration to fail against (waxseal-aa4 A3).
        if not resumable_scan:
            real_scan = JSONLBackend._integrity_scan

            def full_scan(self: JSONLBackend) -> None:
                self._scanned_offset = 0
                self._scanned_lines = 0
                real_scan(self)

            monkeypatch.setattr(JSONLBackend, "_integrity_scan", full_scan)
        backend = JSONLBackend(path, integrity_scan_every=integrity_scan_every)
        sink: list[int] = []
        real_open = open

        def counting_open(file: Any, *args: Any, **kwargs: Any) -> Any:
            f = real_open(file, *args, **kwargs)
            if Path(file) == path:
                return _ByteCountingFile(f, sink)
            return f

        import waxseal.adapters.jsonl as jsonl_module

        monkeypatch.setattr(jsonl_module, "open", counting_open, raising=False)
        for _ in range(n):
            backend.append(lambda seq, prev: build_entry(seq, prev))
        monkeypatch.undo()
        return sum(sink)

    # C4 amortized claim: with the default integrity_scan_every=1000 the
    # periodic scan fires once in the first 1000 appends (at seq 999) and
    # once more by append 2000 (at seq 1999, over a now-larger file). Total
    # bytes read across n=2000 must stay close to 2x the n=1000 total —
    # dominated by the O(1)-per-append tail read — not blow up as a second
    # independent O(n) term stacked on top.
    def test_periodic_scan_cost_is_amortized_not_per_append(
        self, tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:
        bytes_1000 = self._bytes_read_by_all_appends(
            tmp_path / "amortized-1000.jsonl", 1000, 1000, monkeypatch
        )
        bytes_2000 = self._bytes_read_by_all_appends(
            tmp_path / "amortized-2000.jsonl", 2000, 1000, monkeypatch
        )
        assert bytes_2000 <= bytes_1000 * 2.5, (
            f"n=2000 total read {bytes_2000} bytes vs n=1000 total read "
            f"{bytes_1000} bytes (ratio {bytes_2000 / bytes_1000:.2f}x) — "
            "periodic integrity scan cost is not amortized "
            "(expected O(n / integrity_scan_every), not O(n))"
        )

    # Falsifiability receipt (CLAUDE.md rule 9): the identical measurement
    # and identical 2.5x bound, over a configuration that must NOT satisfy
    # it — confirming test_periodic_scan_cost_is_amortized_not_per_append is
    # not vacuously true (a bound that holds no matter what "amortized"
    # means would prove nothing about this feature).
    #
    # The "bad" configuration changed in 0.1.5 (waxseal-aa4 A3), and that is
    # a finding worth recording rather than a bound quietly relaxed. It used
    # to be integrity_scan_every=1 alone: firing a WHOLE-FILE scan on every
    # append made total cost O(n^2), and this test measured 9_069_595 bytes
    # at n=2000 against 4_523_596 at n=1000 once the scan became resumable —
    # ratio 2.00x, comfortably inside the bound, i.e. the receipt had stopped
    # falsifying anything. The scan now resumes from the last byte offset it
    # parsed clean, so scan_every=1 costs O(bytes appended) and no longer
    # breaks amortization by itself. What carries the amortization now is the
    # resume, so that is what this receipt removes: with the resume point
    # reset before every scan (resumable_scan=False, the pre-0.1.5 whole-file
    # scan) the same measurement reads 228_245_760 bytes at n=1000 and
    # 906_006_760 at n=2000 — ratio 3.97x, the O(n^2) shape the bound is
    # there to catch.
    #
    # Every number above was re-measured after waxseal-fg4.1 moved the
    # periodic scan to BEFORE the pending write, and each came down by one
    # trail line per fire (~449 bytes) — 4_524_045/9_070_045 and
    # 228_694_650/906_905_650 as first recorded. Both ratios are unchanged to
    # two decimals: the line the scan no longer sees on this fire is read on
    # the next one, so the shape this receipt measures never depended on it.
    def test_falsifiability_unresumed_scan_breaks_the_amortized_bound(
        self, tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:
        bytes_1000 = self._bytes_read_by_all_appends(
            tmp_path / "falsify-1000.jsonl", 1000, 1, monkeypatch, resumable_scan=False
        )
        bytes_2000 = self._bytes_read_by_all_appends(
            tmp_path / "falsify-2000.jsonl", 2000, 1, monkeypatch, resumable_scan=False
        )
        assert bytes_2000 > bytes_1000 * 2.5, (
            f"n=2000 total read {bytes_2000} bytes vs n=1000 total read "
            f"{bytes_1000} bytes (ratio {bytes_2000 / bytes_1000:.2f}x) — "
            "expected a non-resuming whole-file scan on every append to "
            "break the 2.5x bound; if it doesn't, the amortized test above "
            "is not actually falsifiable"
        )


class TestIntegrityScan:
    def test_periodic_scan_detects_corrupted_middle_line(self, tmp_path: Path) -> None:
        # Small interval so the test doesn't need 1000 appends to trigger.
        path = tmp_path / "trail.jsonl"
        backend = JSONLBackend(path, integrity_scan_every=10)
        for _ in range(9):
            backend.append(lambda seq, prev: build_entry(seq, prev))

        lines = path.read_text(encoding="utf-8").splitlines()
        corrupted_line_no = 5
        # Truncate the line's closing bytes so json.loads() must fail on it —
        # not a hash/chain tamper, a raw on-disk parse failure (rule 4: this
        # is a storage sanity check, never a verify_chain verdict).
        lines[corrupted_line_no - 1] = lines[corrupted_line_no - 1][:-5]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # The scan fires on this append and reports the line — as a labelled
        # warning, not as an exception, and the append still lands
        # (waxseal-fg4.1: it used to raise, from AFTER the write). The
        # line/offset facts are unchanged; only who hears them changed.
        with pytest.warns(RuntimeWarning) as caught:
            entry = backend.append(lambda seq, prev: build_entry(seq, prev))
        assert entry.header.seq == 9
        message = str(caught[0].message)
        assert f"line {corrupted_line_no}" in message
        assert "JSONDecodeError" in message
        with pytest.raises(JSONLCorruptionError) as exc_info:
            backend._integrity_scan()
        assert exc_info.value.line_no == corrupted_line_no
        assert isinstance(exc_info.value.cause, json.JSONDecodeError)
        assert str(corrupted_line_no) in str(exc_info.value)

    def test_periodic_scan_skips_blank_lines_without_raising(self, tmp_path: Path) -> None:
        # A blank line (partial flush, stray editor newline) is not a
        # corrupt entry — entries() already skips these (see
        # TestRoundTrip.test_a_blank_line_in_the_trail_is_skipped_not_parsed
        # above); the periodic scan must treat it the same way, not raise.
        path = tmp_path / "trail.jsonl"
        backend = JSONLBackend(path, integrity_scan_every=10)
        for _ in range(9):
            backend.append(lambda seq, prev: build_entry(seq, prev))
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n")
        backend.append(lambda seq, prev: build_entry(seq, prev))  # seq=9, seq+1==10: triggers scan

    def test_disabled_scan_leaves_corruption_undetected(self, tmp_path: Path) -> None:
        # integrity_scan_every=None is an explicit, deliberate opt-out — the
        # corruption must survive silently even past the point a default
        # configuration would have scanned.
        path = tmp_path / "trail.jsonl"
        backend = JSONLBackend(path, integrity_scan_every=None)
        for _ in range(9):
            backend.append(lambda seq, prev: build_entry(seq, prev))

        lines = path.read_text(encoding="utf-8").splitlines()
        lines[4] = lines[4][:-5]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Append well past where a default (1000-interval) scan would have
        # fired at least once, to show the silence isn't just "hasn't hit
        # the boundary yet".
        for _ in range(1200):
            backend.append(lambda seq, prev: build_entry(seq, prev))
        # No JSONLCorruptionError raised anywhere above — that is the point.


class TestScanNeverInvalidatesADurableAppend:
    """waxseal-fg4.1: ``_integrity_scan()`` used to run AFTER the entry was
    written and flushed, so a ``JSONLCorruptionError`` about some OTHER,
    pre-existing line surfaced as an exception from an append that had already
    durably succeeded. A caller retrying on exception then recorded the same
    event twice — two entries, contiguous seq, no gap, so ``verify()`` still
    returns ok and the duplicate is invisible to chain integrity. That is
    trail-completeness damage no verdict can see.
    """

    def _trail_with_nine_entries_and_a_torn_line(self, path: Path) -> JSONLBackend:
        backend = JSONLBackend(path, integrity_scan_every=10)
        for _ in range(9):
            backend.append(lambda seq, prev: build_entry(seq, prev))
        lines = path.read_text(encoding="utf-8").splitlines()
        # Line 5 unparseable: a torn write or an out-of-band edit, NOT a hash
        # tamper. The next append is the one whose scan fires on it.
        lines[4] = lines[4][:-5]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return backend

    def _rows_holding(self, path: Path, payload: bytes) -> int:
        # Counts by payload_hash, not by base64 body: the header hash is what
        # identifies the event regardless of how the envelope stores bytes.
        return path.read_text(encoding="utf-8").count(compute_payload_hash(payload))

    def test_a_caller_retrying_on_exception_does_not_double_append(
        self, tmp_path: Path, recwarn: "pytest.WarningsRecorder"
    ) -> None:
        # recwarn, not pytest.warns: this test asserts the duplicate is gone,
        # deliberately without asserting HOW the scan reports (that is
        # test_pre_existing_corruption_is_reported_as_a_labelled_warning's
        # job), so a regression here fails on the row count and says so.
        path = tmp_path / "trail.jsonl"
        backend = self._trail_with_nine_entries_and_a_torn_line(path)
        marker = b'{"event":"the-one-event-this-caller-records"}'

        # The caller pattern the bug punishes: retry once on any exception.
        for _attempt in range(2):
            try:
                backend.append(lambda seq, prev: build_entry(seq, prev, marker))
                break
            except Exception:
                continue

        rows = self._rows_holding(path, marker)
        assert rows == 1, (
            f"the caller recorded one event and the trail holds {rows} rows for it "
            "— an append that already reached disk reported failure, so the retry "
            "wrote it again (contiguous seq, no gap, invisible to verify)"
        )

    def test_pre_existing_corruption_is_reported_as_a_labelled_warning(
        self, tmp_path: Path
    ) -> None:
        # Rule 6: the degraded scan is labelled in the output, never swallowed.
        path = tmp_path / "trail.jsonl"
        backend = self._trail_with_nine_entries_and_a_torn_line(path)
        with pytest.warns(RuntimeWarning) as caught:
            entry = backend.append(lambda seq, prev: build_entry(seq, prev))
        assert entry.header.seq == 9
        messages = [str(w.message) for w in caught]
        assert any("waxseal" in m and "line 5" in m for m in messages), messages

    def test_the_scan_itself_still_raises_when_called_directly(self, tmp_path: Path) -> None:
        # The exception is not gone, only removed from append()'s failure
        # modes: an explicit check still gets the line and offset it needs.
        path = tmp_path / "trail.jsonl"
        backend = self._trail_with_nine_entries_and_a_torn_line(path)
        with pytest.raises(JSONLCorruptionError) as exc_info:
            backend._integrity_scan()
        assert exc_info.value.line_no == 5
        assert isinstance(exc_info.value.cause, json.JSONDecodeError)


class TestTailReadEdgeCases:
    def _line_for(self, entry: Entry) -> str:
        return json.dumps(to_obj(entry, backend="JSONL"), sort_keys=True, separators=(",", ":"))

    def test_missing_file_first_append_is_genesis(self, tmp_path: Path) -> None:
        backend = JSONLBackend(tmp_path / "absent.jsonl")
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(0, GENESIS_PREV_HASH)]

    def test_empty_file_first_append_is_genesis(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        path.touch()
        backend = JSONLBackend(path)
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(0, GENESIS_PREV_HASH)]

    def test_file_with_only_a_trailing_newline_is_genesis(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        path.write_text("\n", encoding="utf-8")
        backend = JSONLBackend(path)
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(0, GENESIS_PREV_HASH)]

    def test_last_line_without_trailing_newline(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        first = build_entry(0, GENESIS_PREV_HASH)
        path.write_text(self._line_for(first), encoding="utf-8")  # no trailing \n
        backend = JSONLBackend(path)
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(1, first.entry_hash)]

    def test_single_trailing_blank_line_after_last_entry(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        first = build_entry(0, GENESIS_PREV_HASH)
        path.write_text(self._line_for(first) + "\n\n", encoding="utf-8")
        backend = JSONLBackend(path)
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(1, first.entry_hash)]

    def test_last_line_longer_than_seek_chunk_forces_multiple_iterations(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "trail.jsonl"
        first = build_entry(0, GENESIS_PREV_HASH, payload=b"x")
        big_payload = b"y" * (_TAIL_SEEK_CHUNK * 2)
        second = build_entry(1, first.entry_hash, payload=big_payload)
        assert len(self._line_for(second)) > _TAIL_SEEK_CHUNK
        path.write_text(
            self._line_for(first) + "\n" + self._line_for(second) + "\n", encoding="utf-8"
        )
        backend = JSONLBackend(path)
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(2, second.entry_hash)]

    def test_file_with_exactly_one_entry_on_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        first = JSONLBackend(path).append(lambda seq, prev: build_entry(seq, prev))
        # Fresh backend instance: the tail must come from re-reading the
        # file, not from any state held by the writer that created it.
        backend = JSONLBackend(path)
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(1, first.entry_hash)]
