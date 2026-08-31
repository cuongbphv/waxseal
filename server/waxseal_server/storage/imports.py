"""Imported trails — evidence from somewhere else, stored read-only.

An imported trail is another system's history. The server verifies it and shows
what it found; it never appends to it, never repairs it, and never lets it act
as a live chain. "Verify reports, never repairs" (CLAUDE.md rule 4) is enforced
here by the storage layer rather than by convention: the stored copy is chmod'd
read-only, and imports live in their own namespace so no chain route can address
one.

The idea is the repository owner's own need — verify foreign trails centrally —
and the repository already had the shape of it in `sources/openclaw.py`, which
is an importer of exactly this kind one layer down.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from waxseal_server.domain.errors import InvalidIdentifier, UnsupportedTrailFormat
from waxseal_server.domain.identifiers import require_import_id

# Exactly the suffixes `AuditLog.open` and the CLI can dispatch on. Accepting
# anything else would store a file whose every verdict is "no backend for this
# suffix" — a stored file that can never be evidence.
SUPPORTED_SUFFIXES: Final[frozenset[str]] = frozenset({".jsonl", ".db", ".sqlite", ".sqlite3"})
_META_NAME: Final = "meta.json"


@dataclass(frozen=True, slots=True)
class ImportRecord:
    import_id: str
    filename: str
    size: int
    sha256: str
    imported_at: str
    ordinal: int

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


class ImportStore:
    def __init__(self, root: Path | str) -> None:
        self._root = Path(root).expanduser()

    @property
    def root(self) -> Path:
        return self._root

    def _dir(self, import_id: str) -> Path:
        return self._root / require_import_id(import_id)

    def trail_path(self, import_id: str) -> Path:
        record = self.get(import_id)
        if record is None:
            raise InvalidIdentifier(f"no such import: {import_id!r}")
        return self._dir(import_id) / record.filename

    def create(self, filename: str, data: bytes) -> ImportRecord:
        # Basename only: an upload's declared filename is attacker-supplied text
        # and has no authority over where anything lands.
        name = Path(filename.replace("\\", "/")).name
        suffix = Path(name).suffix.lower()
        if suffix not in SUPPORTED_SUFFIXES:
            raise UnsupportedTrailFormat(
                f"waxseal has no backend for {suffix or name!r}; "
                f"use one of {sorted(SUPPORTED_SUFFIXES)}"
            )
        if not data:
            raise UnsupportedTrailFormat("an empty upload is not a trail")

        self._root.mkdir(parents=True, exist_ok=True)
        import_id = uuid.uuid4().hex
        directory = self._dir(import_id)
        directory.mkdir(parents=True)

        target = directory / name
        target.write_bytes(data)
        # Read-only for everyone, set explicitly so a permissive umask cannot
        # widen it. The bit is the claim; a comment in the UI would not be.
        os.chmod(target, 0o400)

        record = ImportRecord(
            import_id=import_id,
            filename=name,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            imported_at=datetime.now(UTC).isoformat(),
            # A monotonic position, so "newest first" survives two imports
            # landing in the same clock tick.
            ordinal=self._next_ordinal(),
        )
        (directory / _META_NAME).write_text(
            json.dumps(record.to_json(), sort_keys=True, indent=2), encoding="utf-8"
        )
        return record

    def _next_ordinal(self) -> int:
        return sum(1 for child in self._root.iterdir() if (child / _META_NAME).exists())

    def get(self, import_id: str) -> ImportRecord | None:
        try:
            meta = self._dir(import_id) / _META_NAME
        except InvalidIdentifier:
            return None
        if not meta.exists():
            return None
        return ImportRecord(**json.loads(meta.read_text(encoding="utf-8")))

    def records(self) -> list[ImportRecord]:
        if not self._root.is_dir():
            return []
        found = [
            record
            for child in self._root.iterdir()
            if child.is_dir() and (record := self.get(child.name)) is not None
        ]
        return sorted(found, key=lambda r: r.ordinal, reverse=True)
