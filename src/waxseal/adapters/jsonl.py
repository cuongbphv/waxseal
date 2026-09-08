"""JSONL backend (SPEC.md section 7).

One JSON object per line: {"header": {...}, "entry_hash": "...", "payload_b64": "..."}.
Payload bytes are stored base64 so the stored bytes are exactly the hashed
bytes. Text round-trips (newline translation, encoding guesses) are how
byte-exactness quietly dies.
"""

from __future__ import annotations

import json
import os
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path

from waxseal.adapters._envelope import from_obj, tail_fields, to_obj
from waxseal.adapters.filelock import file_lock
from waxseal.domain.header import GENESIS_PREV_HASH, Entry

# Read backward from EOF this many bytes at a time when hunting for the last
# line. Any stored line under this size resolves in one seek+read (the O(1)
# tail read waxseal-7tk.1 exists to restore); a longer line just loops.
_TAIL_SEEK_CHUNK = 4096


class JSONLCorruptionError(Exception):
    """A stored line failed to parse as JSON during the periodic integrity scan.

    This is NOT a verify_chain verdict (CLAUDE.md rule 4: verify reports,
    never repairs): it carries no hash comparison and must never be read as
    "broken" or "unverifiable" in the tamper-evidence sense. It reports a
    storage-layer fact one level below the chain: a line that cannot even be
    parsed back as the JSON envelope it was written as (e.g. a torn write
    from a crash mid-flush, or an out-of-band edit).

    NOT one of ``append()``'s failure modes (waxseal-fg4.1): only a direct
    ``_integrity_scan()`` call raises this. An append that hits it reports the
    same line and offset as a labelled ``RuntimeWarning`` and still lands,
    because an append that reached disk must never report failure — see
    ``JSONLBackend.append``.
    """

    def __init__(self, line_no: int, byte_offset: int, cause: Exception) -> None:
        self.line_no = line_no
        self.byte_offset = byte_offset
        self.cause = cause
        super().__init__(
            f"trail corrupted at line {line_no} (byte offset {byte_offset}): {cause!r}"
        )

    def __str__(self) -> str:
        return (
            f"trail corrupted at line {self.line_no} "
            f"(byte offset {self.byte_offset}): {self.cause!r}"
        )


def read_last_line(path: Path) -> bytes | None:
    """Return the raw bytes of the trail's last non-blank line, or None if
    there is no complete entry yet (missing file, empty file, or a file
    holding only whitespace/newlines).

    Seeks backward from EOF in fixed-size chunks instead of parsing forward
    from the start, the fix for the O(n^2) append bug (waxseal-7tk.1),
    where ``_tail_locked()`` used to replay and payload-decode the entire
    trail, inside the write lock, on every single append.
    """
    if not path.exists():
        return None
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        remaining = f.tell()
        if remaining == 0:
            return None
        chunk = b""
        while True:
            read_size = min(_TAIL_SEEK_CHUNK, remaining)
            remaining -= read_size
            f.seek(remaining)
            chunk = f.read(read_size) + chunk
            # Trailing blank lines (a lone "\n", or several) are not an
            # entry, so strip them before looking for the newline that ends
            # the last real line.
            trimmed = chunk.rstrip(b"\r\n")
            newline_at = trimmed.rfind(b"\n")
            if newline_at != -1:
                return trimmed[newline_at + 1 :]
            if remaining == 0:
                # Reached the start of the file with no interior newline
                # found: the whole (trimmed) file is the one and only line.
                return trimmed or None


# One-release compatibility alias: rotation and the server imported the
# private name. Keep it bound to the same function so a leftover import
# does not become an AttributeError while those callers are updated.
_read_last_line = read_last_line


class JSONLBackend:
    def __init__(self, path: Path | str, *, integrity_scan_every: int | None = 1000) -> None:
        self._path = Path(path).expanduser()
        # Default is 1000, not None: a storage-corruption safety net should
        # not be something an operator has to remember to opt into (same
        # "wired for real" stance as this release's other defaults).
        self._integrity_scan_every = integrity_scan_every
        # Resume point for _integrity_scan: bytes and lines of this file that
        # this object has already parsed clean. In-memory and per-instance on
        # purpose — see _integrity_scan's docstring for what that does and
        # does not cover.
        self._scanned_offset = 0
        self._scanned_lines = 0

    def append(self, build: Callable[[int, str], Entry]) -> Entry:
        # Lock covers read-tail AND write: two writers must never both build
        # on the same prev_hash (CLAUDE.md rule 7).
        with file_lock(self._path):
            next_seq, prev_hash = self._tail_locked()
            # BEFORE the write, never after (waxseal-fg4.1). The scan used to
            # fire once the entry was on disk and flushed, so a
            # JSONLCorruptionError about some OTHER, pre-existing line came out
            # of an append that had already durably succeeded: a caller that
            # retries on exception wrote the same event twice, contiguous seq,
            # no gap, so verify() still returns ok and the duplicate is
            # invisible to chain integrity (and try_append counted a drop for
            # an entry that was on the chain, which is dropped_writes lying —
            # rule 5). Position, not only the except-clause below, is what
            # makes that unrepresentable: ANY way the scan can fail — an
            # OSError off the read, a warning filter escalated to an error —
            # now lands where there is no durable write to lie about.
            #
            # Same predicate on the same entry as before the move (next_seq IS
            # this entry's seq), so the scan still fires on exactly the appends
            # it used to, over the same bytes minus the pending line, which the
            # next fire picks up. next_seq > 0 because nothing stored is
            # nothing to check, and because scan_every=1 would otherwise
            # stat() a file this first append has not created yet.
            if (
                self._integrity_scan_every is not None
                and next_seq > 0
                and (next_seq + 1) % self._integrity_scan_every == 0
            ):
                try:
                    self._integrity_scan()
                except JSONLCorruptionError as exc:
                    # Fail-open, LABELLED (rule 6), through the same channel
                    # the sibling SQLite adapter uses for its own degraded
                    # path. Damage to bytes written long ago is not grounds to
                    # veto a new entry: refusing would silence the host's whole
                    # trail over one old torn line, and rule 4 forbids the only
                    # other exit (repairing it). The operator is told; nothing
                    # is fixed, nothing is dropped.
                    warnings.warn(
                        "waxseal: periodic trail integrity scan found an "
                        f"unparseable stored line: {exc} — this append still "
                        "landed; the scan reports storage, never a chain verdict",
                        RuntimeWarning,
                        stacklevel=2,
                    )
            entry = build(next_seq, prev_hash)
            line = json.dumps(to_obj(entry, backend="JSONL"), sort_keys=True, separators=(",", ":"))
            # No mkdir here: file_lock() creates the parent for the .lock file
            # before this block is entered (adapters/filelock.py), so a second
            # one was a syscall per append with nothing left to do.
            # 0600 like the sealkey: the trail holds prompts and tool output at
            # a predictable path, and a default umask would hand it to every
            # local user. Only applies at creation; existing perms are kept.
            fd = os.open(self._path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8", newline="") as f:
                f.write(line + "\n")
                f.flush()
            return entry

    def entries(self) -> Iterator[Entry]:
        if not self._path.exists():
            return
        with open(self._path, encoding="utf-8", newline="") as f:
            for line in f:
                if line.strip():
                    yield from_obj(json.loads(line))

    def entry_hashes(self) -> list[str]:
        """The trail's hashes without reconstructing payload bytes.

        `from_obj` base64-decodes every `payload_b64` even when the caller
        only needs `entry_hash` (anchor, consistency, pin, witness). The
        payload is stored so `entries()` can return it; a hashes-only pass
        must not pay that decode (P2 / test_perf_receipts).
        """
        if not self._path.exists():
            return []
        hashes: list[str] = []
        with open(self._path, encoding="utf-8", newline="") as f:
            for line in f:
                if line.strip():
                    hashes.append(str(json.loads(line)["entry_hash"]))
        return hashes

    def _tail_locked(self) -> tuple[int, str]:
        last_line = read_last_line(self._path)
        if last_line is None:
            return 0, GENESIS_PREV_HASH
        seq, entry_hash = tail_fields(json.loads(last_line))
        return seq + 1, entry_hash

    def _integrity_scan(self) -> None:
        """Parse every not-yet-cleared stored line as JSON, amortized every
        ``integrity_scan_every`` appends (not every append, since that full
        replay on every call was the O(n^2) bug this module was fixed for).

        Raises ``JSONLCorruptionError`` on the first unparseable line. From
        ``append`` that raise is caught and re-reported as a labelled warning
        (waxseal-fg4.1): the periodic fire happens before the pending write,
        so a caller never sees this method's failure attributed to an append
        that had already landed.

        This is a storage sanity check, one layer below tamper-evidence: it
        answers "can every stored line still be parsed at all", nothing
        about hashes or chain verdicts. Do not read a clean scan as
        `verify_chain`-style "ok" (CLAUDE.md rule 4): it checks a strictly
        weaker, unrelated property.

        SCOPE, stated because a resumable scan is a narrower claim than a
        whole-file one: the scan resumes from the last byte offset THIS
        object parsed clean, so repeated scans cost O(bytes appended), not
        O(file) each time (the cumulative O(n^2 / N) this method was fixed
        for). What it therefore does not see is an out-of-band edit to a
        region this same object already cleared. That is a deliberate trade,
        not an oversight: the whole-file guarantee never existed anyway
        (a fresh process clears nothing and rescans everything, and only
        `verify` speaks about the chain). A file that got SHORTER than the
        cleared prefix is treated as a different file at this path and
        rescanned from byte 0, because a remembered offset would otherwise
        seek past corruption now sitting in front of it.
        """
        byte_offset = self._scanned_offset
        line_no = self._scanned_lines
        if self._path.stat().st_size < byte_offset:
            byte_offset = 0
            line_no = 0
        with open(self._path, "rb") as f:
            f.seek(byte_offset)
            for raw in f:
                line_no += 1
                stripped = raw.strip()
                if stripped:
                    try:
                        json.loads(stripped)
                    except json.JSONDecodeError as exc:
                        # Absolute in the file, never relative to the resume
                        # point: an operator handed line 3 for line 53 opens
                        # the wrong row.
                        raise JSONLCorruptionError(line_no, byte_offset, exc) from exc
                byte_offset += len(raw)
                if raw.endswith(b"\n"):
                    # Only a newline-terminated line is cleared. A tail
                    # without one is a partial write whose remaining bytes
                    # must be re-read, not skipped.
                    self._scanned_offset = byte_offset
                    self._scanned_lines = line_no
