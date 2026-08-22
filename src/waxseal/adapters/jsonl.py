"""JSONL backend (SPEC.md section 7).

One JSON object per line: {"header": {...}, "entry_hash": "...", "payload_b64": "..."}.
Payload bytes are stored base64 so the stored bytes are exactly the hashed
bytes — text round-trips (newline translation, encoding guesses) are how
byte-exactness quietly dies.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from pathlib import Path

from waxseal.adapters._envelope import from_obj, to_obj
from waxseal.adapters.filelock import file_lock
from waxseal.domain.header import GENESIS_PREV_HASH, Entry


class JSONLBackend:
    def __init__(self, path: Path | str) -> None:
        self._path = Path(path).expanduser()

    def append(self, build: Callable[[int, str], Entry]) -> Entry:
        # Lock covers read-tail AND write: two writers must never both build
        # on the same prev_hash (CLAUDE.md rule 7).
        with file_lock(self._path):
            next_seq, prev_hash = self._tail_locked()
            entry = build(next_seq, prev_hash)
            line = json.dumps(to_obj(entry, backend="JSONL"), sort_keys=True, separators=(",", ":"))
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # 0600 like the sealkey: the trail holds prompts and tool output at
            # a predictable path — a default umask would hand it to every
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

    def _tail_locked(self) -> tuple[int, str]:
        last: Entry | None = None
        for last in self.entries():  # noqa: B007 - we want the final element
            pass
        if last is None:
            return 0, GENESIS_PREV_HASH
        return last.header.seq + 1, last.entry_hash
