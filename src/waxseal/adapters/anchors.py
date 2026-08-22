"""FileAnchorSink: a local sidecar record of checkpoints.

Same sidecar shape as adapters/attest.py (one JSON object per line, O_APPEND,
0600), applied to Checkpoints instead of Attestations. This is the LOCAL
baseline, not an independent witness: the sidecar lives right next to the
trail, so a writer able to rewrite the trail can rewrite this file too. Its
purpose is to give ``waxseal verify --anchors`` something to check trail
history against between real external anchor events, and to give an actual
external sink (OpenTimestamps, an RFC 3161 TSA, a pushed git commit — none of
which this zero-dependency library implements) a queue of checkpoints to
publish. A duplicate record from a race (two anchor_every triggers landing
close together) is harmless: the content is idempotent, and each record is
checked independently.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

from waxseal.adapters.remote import RemoteRequest, Transport, urllib_transport
from waxseal.domain.checkpoint import Checkpoint


def _default_now() -> str:
    return datetime.now(UTC).isoformat()


class FileAnchorSink:
    name = "file"

    def __init__(
        self, trail_path: Path | str, *, now_fn: Callable[[], str] | None = None
    ) -> None:
        trail = Path(trail_path).expanduser()
        self._path = trail.with_name(trail.name + ".anchors")
        self._now = now_fn or _default_now

    def anchor(self, checkpoint: Checkpoint) -> str | None:
        # No receipt of its own to give — a local file is not an external
        # witness (see module docstring); a real sink (HTTPAnchorSink and
        # friends) returns whatever its service hands back.
        record = {
            "entry_hash": checkpoint.entry_hash,
            "receipt": None,
            "root": checkpoint.root,
            "seq": checkpoint.seq,
            "sink": self.name,
            "ts": self._now(),
            "v": 1,
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        # 0600 like every other sidecar (attest.py precedent): the anchor
        # queue is as sensitive as the trail it describes.
        fd = os.open(self._path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", newline="") as f:
            f.write(line + "\n")
            f.flush()
        return None

    def records(self) -> Iterator[Checkpoint]:
        if not self._path.exists():
            return
        with open(self._path, encoding="utf-8", newline="") as f:
            for line in f:
                if line.strip():
                    obj = json.loads(line)
                    yield Checkpoint(
                        seq=int(obj["seq"]),
                        entry_hash=str(obj["entry_hash"]),
                        root=str(obj["root"]),
                    )


class HTTPAnchorSink:
    """Publishes a checkpoint to an HTTP endpoint — a real external witness,
    unlike FileAnchorSink's local sidecar (see AnchorSink's own docstring for
    why that distinction matters). Shares RemoteBackend's Transport
    abstraction so both use the same stdlib-only urllib plumbing and the same
    Authorization: Bearer auth convention (never argv, never a URL param).
    """

    name = "http"

    def __init__(
        self,
        url: str,
        *,
        transport: Transport | None = None,
        api_key: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._url = url
        self._transport = transport or urllib_transport(timeout=timeout)
        self._api_key = api_key

    def anchor(self, checkpoint: Checkpoint) -> str | None:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._api_key is not None:
            headers["Authorization"] = f"Bearer {self._api_key}"
        body = json.dumps(
            {
                "seq": checkpoint.seq,
                "entry_hash": checkpoint.entry_hash,
                "root": checkpoint.root,
            }
        ).encode("utf-8")
        resp = self._transport(
            RemoteRequest(method="POST", url=self._url, headers=headers, body=body)
        )
        if resp.status not in (200, 201):
            # AnchorSink's own contract: raise on failure, never return as if
            # it had succeeded with no receipt.
            raise RuntimeError(f"anchor POST to {self._url} failed: HTTP {resp.status}")
        if not resp.body:
            return None
        receipt = json.loads(resp.body).get("receipt")
        return str(receipt) if receipt is not None else None
