"""FileAnchorSink: a local sidecar record of checkpoints.

Same sidecar shape as adapters/attest.py (one JSON object per line, O_APPEND,
0600), applied to Checkpoints instead of Attestations. This is the LOCAL
baseline, not an independent witness: the sidecar lives right next to the
trail, so a writer able to rewrite the trail can rewrite this file too. Its
purpose is to give ``waxseal verify --anchors`` something to check trail
history against between real external anchor events, and to give an actual
external sink a queue of checkpoints to publish. External sinks ship as
adapters/rfc3161.py, adapters/ots.py and ``HTTPAnchorSink`` below; each
reaches this file through ``RecordingAnchorSink`` (wrapped explicitly by the
CLI, or by AuditLog itself for any path-backed trail); others (a pushed git
commit, a signed release) still need tooling outside this package. A
duplicate record from a race (two
anchor_every triggers landing close together) is harmless: the content is
idempotent, and each record is checked independently.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from waxseal.adapters.filelock import file_lock
from waxseal.adapters.remote import RemoteRequest, Transport, urllib_transport
from waxseal.domain.checkpoint import Checkpoint, SinkReceipt

# Record versions this build knows how to read. A record stamped with anything
# else is reported unreadable-by-name rather than skipped or treated as a
# failure: the beads-v1.2.2 class applied to the sidecar's own format.
_KNOWN_RECORD_VERSIONS = frozenset({1, 2})

# Records written before the version stamp existed. They predate every
# optional field, so v1 is not a guess.
_DEFAULT_RECORD_VERSION = 1


def _default_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    """One line of the `.anchors` sidecar.

    ``receipt`` is whatever the external sink handed back, opaque here by
    design: a timestamp token or a calendar proof is the sink's format, not
    this module's, and inventing a parse for it would manufacture verdicts.
    ``nonce`` is the RFC 3161 request nonce when the sink supplied one;
    ``None`` means "not recorded" (every record written before the field
    existed), never "zero": with no stored nonce the comparison is skipped,
    not failed (CLAUDE.md rule 5).
    """

    checkpoint: Checkpoint
    sink: str
    receipt: str | None
    ts: str
    version: int
    nonce: int | None = None


@dataclass(frozen=True, slots=True)
class AnchorSidecar:
    """What the sidecar holds, plus what this build could not read of it.

    The two are kept apart because they mean different things: records are
    evidence to check, unreadable versions are coverage this build does not
    have. Folding them together would let missing coverage read as a pass.
    """

    records: tuple[AnchorRecord, ...]
    unreadable_versions: tuple[str, ...]


def read_anchor_records(trail_path: Path | str) -> AnchorSidecar:
    """Read the `.anchors` sidecar for ``trail_path``.

    The single reader for this file. The sink's own ``records()`` goes
    through it too, because two parsers for one format are two chances to
    disagree about it. Raises on bytes that are not records at all,
    ValueError (including json.JSONDecodeError) for unparseable JSON or an
    unconvertible field, KeyError for a record missing ``seq``/``entry_hash``/
    ``root``, TypeError for a field of the wrong shape. Rendering any of those
    as a verdict belongs to the caller, which knows the exit code; inventing
    data here would be worse than refusing.
    """
    path = _sidecar_path(trail_path)
    if not path.exists():
        return AnchorSidecar(records=(), unreadable_versions=())

    records: list[AnchorRecord] = []
    unreadable: list[str] = []
    with open(path, encoding="utf-8", newline="") as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError(f"anchor record must be a JSON object, got {type(obj).__name__}")
            version = obj.get("v", _DEFAULT_RECORD_VERSION)
            if version not in _KNOWN_RECORD_VERSIONS:
                unreadable.append(str(version))
                continue
            records.append(
                AnchorRecord(
                    checkpoint=Checkpoint(
                        seq=int(obj["seq"]),
                        entry_hash=str(obj["entry_hash"]),
                        root=str(obj["root"]),
                        agg_commit=_optional_str(obj, "agg_commit"),
                        agg_epoch=_optional_int(obj, "agg_epoch"),
                    ),
                    sink=str(obj.get("sink", "unknown")),
                    receipt=_optional_str(obj, "receipt"),
                    ts=str(obj.get("ts", "")),
                    version=int(version),
                    # A garbage nonce raises ValueError like any other
                    # unconvertible field: this is OUR format, so unreadable
                    # bytes here are a verdict for the caller, not a skip.
                    nonce=_optional_int(obj, "nonce"),
                )
            )
    return AnchorSidecar(records=tuple(records), unreadable_versions=tuple(unreadable))


def _sidecar_path(trail_path: Path | str) -> Path:
    trail = Path(trail_path).expanduser()
    return trail.with_name(trail.name + ".anchors")


def _optional_str(obj: dict[str, Any], key: str) -> str | None:
    value = obj.get(key)
    return None if value is None else str(value)


def _optional_int(obj: dict[str, Any], key: str) -> int | None:
    value = obj.get(key)
    return None if value is None else int(value)


class FileAnchorSink:
    name = "file"

    def __init__(self, trail_path: Path | str, *, now_fn: Callable[[], str] | None = None) -> None:
        self._trail = Path(trail_path).expanduser()
        self._path = _sidecar_path(self._trail)
        self._now = now_fn or _default_now

    def anchor(self, checkpoint: Checkpoint) -> str | None:
        # No receipt of its own to give: a local file is not an external
        # witness (see module docstring); a real sink (HTTPAnchorSink and
        # friends) returns whatever its service hands back.
        _append_record(
            self._path, _record_obj(checkpoint, sink=self.name, receipt=None, ts=self._now())
        )
        return None

    def records(self) -> Iterator[Checkpoint]:
        """Checkpoints only, for callers that just need the chain-shape claim.

        Records whose version this build cannot read are absent here by
        construction; a caller that must distinguish "no anchors" from "anchors
        this build could not read" uses ``read_anchor_records`` instead.
        """
        for record in read_anchor_records(self._trail).records:
            yield record.checkpoint


def _append_record(path: Path, record: dict[str, Any]) -> None:
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    # The append is a critical section (CLAUDE.md rule 7, same lock the JSONL
    # backend uses, lock file next to the sidecar). Racing anchor triggers are
    # a supported race, but only for WHOLE records: bare O_APPEND interleaves
    # a multi-chunk write (and on Windows, whose O_APPEND is a non-atomic
    # seek-to-end + write, even overwrites the rival's chunk (measured losing
    # 5-10 of 32 records in tests/test_anchored_log.py's receipt), and a torn
    # line makes the strict reader above report ANCHOR BROKEN with no attacker
    # present: an accident masquerading as tampering.
    with file_lock(path):
        # 0600 like every other sidecar (attest.py precedent): the anchor
        # queue is as sensitive as the trail it describes.
        fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", newline="") as f:
            f.write(line + "\n")
            f.flush()


class RecordingAnchorSink:
    """Publishes through ``external`` and keeps what came back.

    The external sink is the evidence; this is only the filing cabinet. The
    order is deliberate: publish first, record second, and if the publish
    raises, write nothing. A record whose receipt never existed would claim an
    anchor that no third party holds: the one direction in which a
    bookkeeping bug becomes a false assurance.
    """

    def __init__(
        self,
        trail_path: Path | str,
        external: Any,
        *,
        now_fn: Callable[[], str] | None = None,
    ) -> None:
        self._path = _sidecar_path(trail_path)
        self._external = external
        self._now = now_fn or _default_now
        self.name = getattr(external, "name", "external")

    def anchor(self, checkpoint: Checkpoint) -> str | None:
        result = self._external.anchor(checkpoint)
        receipt: str | None
        nonce: int | None
        if isinstance(result, SinkReceipt):
            receipt, nonce = result.receipt, result.nonce
        else:
            receipt, nonce = result, None
        _append_record(
            self._path,
            _record_obj(checkpoint, sink=self.name, receipt=receipt, ts=self._now(), nonce=nonce),
        )
        return receipt


class MultiAnchorSink:
    """Fan the SAME checkpoint out to more than one independently-recording
    sink in one ``AuditLog.anchor()`` call (waxseal-4yk, closing conformance.md
    gap G3).

    The paper's anchor-selection corollary recommends publishing one
    checkpoint to both an RFC 3161 authority (a minutes-scale detection
    window) and an OpenTimestamps calendar (long-horizon non-repudiation): tau
    rises by one per independent domain reached. Before this, ``--tsa-url``
    and ``--ots-calendar`` sat in a mutually exclusive argparse group, so
    reaching both took two `anchor` runs back to back.

    Each entry in ``sinks`` is expected to already be its own
    ``RecordingAnchorSink`` wrapping one external target, so a sink that
    publishes still writes its own sidecar record exactly as it always has,
    this class only decides which sinks get called and how a partial failure
    is reported, never how one success is recorded.

    A sink raising must not cost the others their record (CLAUDE.md rule 6:
    fail-open must be labelled, never silent), caught per sink and collected
    in ``.failures`` as ``(name, reason)`` for the caller to print, exactly
    the way `cli/anchor.py`'s single-sink path already labels a raised exception
    rather than swallowing it. Only when EVERY sink fails does this itself
    raise, because at that point nothing published at all and the existing
    "nothing recorded" handling on the caller's side already covers it.
    """

    def __init__(self, sinks: Sequence[Any]) -> None:
        if len(sinks) < 2:
            raise ValueError("MultiAnchorSink needs at least two sinks")
        self._sinks = tuple(sinks)
        self.name = "+".join(getattr(sink, "name", "external") for sink in self._sinks)
        self.failures: list[tuple[str, str]] = []

    def anchor(self, checkpoint: Checkpoint) -> None:
        self.failures = []
        published = 0
        for sink in self._sinks:
            name = getattr(sink, "name", "external")
            try:
                sink.anchor(checkpoint)
            except (OSError, RuntimeError) as e:
                self.failures.append((name, str(e)))
                continue
            published += 1
        if published == 0:
            # Nobody published: same all-or-nothing shape a single external
            # sink failing has always had, so the caller's existing
            # "nothing recorded" except clause applies unchanged.
            raise RuntimeError("; ".join(f"{name}: {reason}" for name, reason in self.failures))


def _record_obj(
    checkpoint: Checkpoint,
    *,
    sink: str,
    receipt: str | None,
    ts: str,
    nonce: int | None = None,
) -> dict[str, Any]:
    """The sidecar record for a checkpoint, at the lowest version that can
    carry it. A checkpoint with no aggregate binding still produces exactly
    the v1 record shape, so nothing about existing sidecars changes. The
    nonce is optional and ADDITIVE, with no version bump: a reader that predates
    the field must keep reading these records (the beads-v1.2.2 class), and a
    reader that knows it treats absence as "skip the comparison", never as a
    mismatch. Stored as a decimal string because a 64-bit value as a bare
    JSON number is lossy in readers that parse numbers as doubles."""
    record: dict[str, Any] = {
        "entry_hash": checkpoint.entry_hash,
        "receipt": receipt,
        "root": checkpoint.root,
        "seq": checkpoint.seq,
        "sink": sink,
        "ts": ts,
        "v": 1,
    }
    if nonce is not None:
        record["nonce"] = str(nonce)
    if checkpoint.agg_commit is not None:
        record["agg_commit"] = checkpoint.agg_commit
        record["agg_epoch"] = checkpoint.agg_epoch
        record["v"] = 2
    return record


class HTTPAnchorSink:
    """Publishes a checkpoint to an HTTP endpoint: a real external witness,
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
        payload: dict[str, Any] = {
            "seq": checkpoint.seq,
            "entry_hash": checkpoint.entry_hash,
            "root": checkpoint.root,
        }
        if checkpoint.agg_commit is not None:
            # A receiver that predates the binding ignores unknown keys (the
            # wire contract says so), so sending it costs nothing and a
            # witness that does understand it gets the stronger claim.
            payload["agg_commit"] = checkpoint.agg_commit
            payload["agg_epoch"] = checkpoint.agg_epoch
        body = json.dumps(payload).encode("utf-8")
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
