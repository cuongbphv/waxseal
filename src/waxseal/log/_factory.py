"""Backend selection for AuditLog.open. Does not construct AuditLog."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from waxseal.adapters.jsonl import JSONLBackend
from waxseal.adapters.mode_notice import notice_if_group_or_world_readable
from waxseal.ports.drops import DropRecorder

_SQLITE_SUFFIXES = frozenset({".db", ".sqlite", ".sqlite3"})


@dataclass(frozen=True, slots=True)
class OpenedBackend:
    backend: Any
    drop_recorder: DropRecorder | None
    trail_path: Path | None


def open_backend(
    path: Path | str,
    *,
    record_drops: bool = False,
    chain_id: str = "default",
    timeout: float = 10.0,
    receipts_trail: Path | str | None = None,
) -> OpenedBackend:
    """Pick a backend and optional drop recorder. Never constructs AuditLog."""
    if isinstance(path, str) and path.startswith(("http://", "https://")):
        # MUST come before Path(path): Path() collapses "//" and drops
        # the scheme, so checking suffix on a mangled URL would never
        # even reach a backend choice, the same class of bug M0's suffix
        # dispatch below already guards against for local paths.
        if record_drops:
            raise ValueError(
                "record_drops requires a local trail path (a .drops sidecar "
                "needs somewhere to live) — not supported for a remote URL target"
            )
        from waxseal.adapters.remote import RemoteBackend

        remote_backend: Any = RemoteBackend(
            path,
            api_key=os.environ.get("WAXSEAL_API_KEY"),
            chain_id=chain_id,
            timeout=timeout,
            # SPEC.md section 19: where the server's per-append
            # acknowledgment is filed. Threaded from here because
            # RemoteBackend has accepted it since 63dbe2d and no documented
            # entry point passed it, which made the sidecar reachable only
            # by hand-constructing the backend -- built and unreachable is
            # not shipped. `None` stays "not recorded", never an error: a
            # receipt is corroboration, and the chain lives server-side
            # either way.
            receipts_trail=receipts_trail,
        )
        return OpenedBackend(
            backend=remote_backend,
            drop_recorder=None,
            trail_path=None,
        )
    if receipts_trail is not None:
        # The mirror image of the record_drops refusal above. A receipt is
        # a SERVER's acknowledgment that it accepted an append; a local
        # backend issues none, so accepting the argument here would name a
        # sidecar location nothing would ever write to -- an operator
        # reading "not recorded" could not tell that from a server that
        # never issued one.
        raise ValueError(
            "receipts_trail requires a remote (http/https) trail target: a "
            "receipt is the server's own acknowledgment of an append, and a "
            "local backend issues none"
        )
    p = Path(path).expanduser()
    if p.exists():
        notice_if_group_or_world_readable(p)
    if p.suffix == ".jsonl":
        backend: Any = JSONLBackend(p)
    elif p.suffix in _SQLITE_SUFFIXES:
        from waxseal.adapters.sqlite import SQLiteBackend

        backend = SQLiteBackend(p)
    else:
        raise ValueError(
            f"no backend for {p.suffix!r}: use .jsonl or one of {sorted(_SQLITE_SUFFIXES)}"
        )
    drop_recorder = None
    if record_drops:
        from waxseal.adapters.drops import FileDropRecorder

        drop_recorder = FileDropRecorder(p)
    return OpenedBackend(backend=backend, drop_recorder=drop_recorder, trail_path=p)
