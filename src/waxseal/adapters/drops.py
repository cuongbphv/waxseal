"""FileDropRecorder: a metadata-only sidecar counting dropped writes.

Same sidecar shape as adapters/attest.py and adapters/anchors.py (one JSON
object per line, O_APPEND, 0600), but the number it produces is read as "at
least N drops measured", never "exactly N", because the sidecar can itself be
deleted, rotated, or (on an unwritable disk) never written to in the first
place. That last case is exactly why ``record()`` swallows every exception:
a disk too broken to hold a drop record cannot bear witness to its own
failure, and refusing to raise here just accepts that limit instead of
turning a dropped write into an unhandled one.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path


def _default_now() -> str:
    return datetime.now(UTC).isoformat()


class FileDropRecorder:
    def __init__(
        self,
        trail_path: Path | str,
        *,
        now_fn: Callable[[], str] | None = None,
        source: str = "library",
    ) -> None:
        trail = Path(trail_path).expanduser()
        self._path = trail.with_name(trail.name + ".drops")
        self._now = now_fn or _default_now
        self._source = source

    def record(
        self, *, reason: str, payload_type: str | None = None, source: str | None = None
    ) -> None:
        # Metadata only: no payload field exists to accidentally populate.
        # See ports/drops.py's docstring: the payload has not been through
        # redact-before-hash yet, so it must never reach any sidecar.
        fd = None
        try:
            record = {
                "payload_type": payload_type,
                "reason": reason,
                "source": source if source is not None else self._source,
                "ts": self._now(),
                "v": 1,
            }
            line = json.dumps(record, sort_keys=True, separators=(",", ":"))
            fd = os.open(self._path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8", newline="") as f:
                fd = None  # ownership transferred to the file object above
                f.write(line + "\n")
                f.flush()
        except Exception:
            # ports/drops.py's contract is "never raises", full stop, so this
            # is invoked from try_append's own except-block (log.py), and a
            # failure surfacing here would turn an already-handled drop into
            # an unhandled one. Deliberately broader than OSError: a broken
            # now_fn or an unserializable value must be swallowed exactly
            # like a failed write, not treated as a different class of
            # problem this recorder is somehow allowed to raise on.
            if fd is not None:
                os.close(fd)

    def count(self) -> int:
        """Non-empty lines in the sidecar, or 0 if it does not exist yet.

        Counts lines, not parsed records: a malformed line is still evidence
        that SOMETHING was appended here, and this method's contract is a
        measured minimum, not a validated total (cli/verify.py's drop-reporting
        path is where malformed lines get surfaced/counted separately).
        """
        if not self._path.exists():
            return 0
        with open(self._path, encoding="utf-8", newline="") as f:
            return sum(1 for line in f if line.strip())


def read_drop_count(trail_path: Path | str) -> int | None:
    """The sidecar's count, or None if it does not exist, meaning "never measured",
    distinct from FileDropRecorder.count()'s 0 ("measured this sidecar,
    found nothing"). Mirrors CLAUDE.md's None-vs-0 rule for dropped_writes
    itself, one layer down."""
    trail = Path(trail_path).expanduser()
    path = trail.with_name(trail.name + ".drops")
    if not path.exists():
        return None
    with open(path, encoding="utf-8", newline="") as f:
        return sum(1 for line in f if line.strip())
