"""AuditLog, the public facade.

Composes: redact → canonical payload bytes → payload_hash → header built under
the backend's lock → append. Verification is delegated to the pure domain
verifier; this class only adds the completeness dimension (dropped_writes),
because chain integrity ≠ trail completeness (CLAUDE.md rule 5).
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from waxseal.adapters.jsonl import JSONLBackend
from waxseal.domain.anchoring import IncrementalMerkle
from waxseal.domain.canonical import canonical_json
from waxseal.domain.checkpoint import Checkpoint, checkpoint_for
from waxseal.domain.fingerprint import fingerprint
from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
from waxseal.domain.header import Entry, EntryHeader
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.sealing import AttestResult
from waxseal.domain.verify import VerifyResult, verify_chain
from waxseal.log._anchoring import (
    aggregate_binding,
    maybe_record_anchor_sink,
)
from waxseal.log._anchoring import (
    verify_anchored_aggregates as check_anchored_aggregates,
)
from waxseal.log._attestation import verify_sidecar
from waxseal.log._factory import open_backend
from waxseal.ports.aggregate import AggregateSource
from waxseal.ports.drops import DropRecorder
from waxseal.ports.redact import Redactor
from waxseal.ports.sign import Verifier

# DSSE rule (SPEC section 1): a generic JSON type defeats the point of
# payload_type: it names neither the schema nor the producer.
_REJECTED_PAYLOAD_TYPES = frozenset({"application/json", "text/json"})


class AttestationFailure(RuntimeError):
    """Raised by append() when the entry IS durably on the chain but its
    attestation failed. Distinct from an append failure so callers never
    account a persisted entry as a dropped write (CLAUDE.md rule 5)."""


def _default_now() -> str:
    return datetime.now(UTC).isoformat()


class AuditLog:
    def __init__(
        self,
        backend: JSONLBackend | Any,
        *,
        redactor: Redactor | None = None,
        now_fn: Callable[[], str] | None = None,
        registry: VersionRegistry | None = None,
        attestor: Any | None = None,
        anchor_sink: Any | None = None,
        anchor_every: int | None = None,
        drop_recorder: DropRecorder | None = None,
        aggregate_source: AggregateSource | None = None,
        trail_path: Path | None = None,
    ) -> None:
        if anchor_every is not None and anchor_every < 1:
            raise ValueError("anchor_every must be a positive integer")
        self._backend = backend
        # Where the trail lives on disk; None for backends with no local file
        # (memory, remote). Public and read-only in spirit: sources key their
        # cross-process coordination (e.g. the openclaw ingest lock) off the
        # trail's location, and exposing the path keeps them from reaching for
        # the backend this facade exists to encapsulate.
        self.trail_path = trail_path
        self._redactor = redactor
        self._now = now_fn or _default_now
        self._registry = registry or VersionRegistry()
        self._attestor = attestor
        # Resolved once, here, so "where the aggregate comes from" has exactly
        # one answer. An attestor is an AggregateSource when it keeps an
        # accumulator; a key-less caller supplies a read-only one instead.
        self._aggregate_source: Any = attestor if aggregate_source is None else aggregate_source
        self._anchor_sink = maybe_record_anchor_sink(anchor_sink, trail_path)
        self._anchor_every = anchor_every
        self._drop_recorder = drop_recorder
        self._dropped = 0
        self._attest_failures = 0
        self._anchor_failures = 0
        # Append + attest must be one critical section: the backend's own lock
        # ends when append returns, and the sealkey's read-modify-write outside
        # it let concurrent threads desync epoch from seq (a prior review
        # measured 8 threads x 30 appends → 240 entries, 1 attestation).
        # Serializes threads sharing this instance; a second sealed writer
        # instance/process still fails loudly (epoch mismatch), never forges.
        self._append_lock = threading.Lock()
        # RFC 6962 forest grown with the trail. Empty until the first
        # append or anchor on this instance; an opened existing trail is
        # rebuilt once from entry_hashes(), never guessed.
        self._merkle = IncrementalMerkle()

    @classmethod
    def open(
        cls,
        path: Path | str,
        *,
        redactor: Redactor | None = None,
        now_fn: Callable[[], str] | None = None,
        registry: VersionRegistry | None = None,
        attestor: Any | None = None,
        anchor_sink: Any | None = None,
        anchor_every: int | None = None,
        record_drops: bool = False,
        chain_id: str = "default",
        timeout: float = 10.0,
        receipts_trail: Path | str | None = None,
    ) -> AuditLog:
        """Open a trail at ``path``.

        Dispatches on the scheme and suffix: a URL is the remote backend, a
        ``.db``/``.sqlite``/``.sqlite3`` suffix is SQLite, everything else
        is JSONL. ``record_drops=True`` attaches a sidecar counter;
        ``dropped_writes is None`` still means the count was never measured.
        """
        opened = open_backend(
            path,
            record_drops=record_drops,
            chain_id=chain_id,
            timeout=timeout,
            receipts_trail=receipts_trail,
        )
        return cls(
            opened.backend,
            redactor=redactor,
            now_fn=now_fn,
            registry=registry,
            attestor=attestor,
            anchor_sink=anchor_sink,
            anchor_every=anchor_every,
            drop_recorder=opened.drop_recorder,
            trail_path=opened.trail_path,
        )

    def append(self, *, payload: dict[str, Any] | bytes, payload_type: str) -> Entry:
        """Append one entry. A dict is redacted (if a redactor is configured)
        then hashed; bytes plus a configured redactor are refused, because
        the Redactor port only sees dicts and "redacted" would otherwise be
        a claim nothing checked.
        """
        if payload_type in _REJECTED_PAYLOAD_TYPES:
            raise ValueError(
                f"payload_type must be application-specific, not {payload_type!r} "
                "(e.g. 'application/vnd.myagent.toolcall+json')"
            )
        payload_bytes = self._canonical_payload(payload)
        payload_hash = compute_payload_hash(payload_bytes)
        ts = self._now()

        def build(seq: int, prev_hash: str) -> Entry:
            header = EntryHeader(
                seq=seq,
                ts=ts,
                # The identity is derived, never typed: fingerprint() is
                # the SHA-256 of this build's descriptor, so a change to the
                # field set or the encoding cannot keep the old identity.
                # A row whose fingerprint a reader does not implement is
                # reported unverifiable by name, never tampered
                # (CLAUDE.md: migration-060 / beads-v1.2.2).
                hash_version=fingerprint(),
                payload_type=payload_type,
                payload_hash=payload_hash,
                prev_hash=prev_hash,
            )
            return Entry(
                header=header,
                entry_hash=compute_entry_hash(header),
                payload=payload_bytes,
            )

        with self._append_lock:
            entry = self._backend.append(build)
            # Merkle tracks the durable chain, not a successful seal: an
            # AttestationFailure still left the row on disk (CLAUDE.md: the
            # entry is not a dropped write).
            self._note_appended(entry)
            if self._attestor is not None:
                # Attest AFTER the entry is durably appended. A crash between
                # the two leaves the sidecar one behind, and FileAttestor refuses
                # to re-align silently, which is the honest failure mode.
                try:
                    self._attestor.attest(entry.header.seq, entry.entry_hash)
                except Exception as e:
                    raise AttestationFailure(
                        f"entry seq={entry.header.seq} is on the chain but its "
                        f"attestation failed: {e}"
                    ) from e
        if (
            self._anchor_sink is not None
            and self._anchor_every is not None
            and (entry.header.seq + 1) % self._anchor_every == 0
        ):
            # Deliberately OUTSIDE the append lock: this is a best-effort,
            # fire-and-forget publish, never a gate on normal appends. A race
            # between two triggers can duplicate a checkpoint record, which
            # is harmless (idempotent content, checked independently), and the
            # alternative of holding the lock across sidecar I/O would repeat
            # the attest_failures precedent's own hazard for no benefit here,
            # since anchoring, unlike attesting, is not a per-entry contract.
            try:
                self.anchor()
            except Exception:
                self._anchor_failures += 1
        return entry

    def verify_attestations(
        self,
        *,
        initial_key: bytes | None = None,
        verifier: Verifier | None = None,
    ) -> AttestResult:
        """Verify the attestation sidecar. fs-hmac seals need `initial_key`
        (A_0); signer attestations need a `verifier`. Schemes neither can
        handle are reported unverifiable-by-name, never as tampering."""
        if self._attestor is None:
            raise ValueError("this log was opened without an attestor")
        return verify_sidecar(
            self._attestor,
            self._backend,
            self._registry,
            initial_key=initial_key,
            verifier=verifier,
        )

    def try_append(self, *, payload: dict[str, Any] | bytes, payload_type: str) -> bool:
        """Best-effort append: never raises. A lost write increments
        dropped_writes and returns False, so the loss is measured, not silent
        (CLAUDE.md rule 6).

        An AttestationFailure is NOT a lost write and returns True: the entry
        is durably on the chain, only its seal is missing. It increments
        attest_failures instead and surfaces as attestation_gap on verify,
        counting it as dropped would make dropped_writes lie (rule 5).
        """
        try:
            self.append(payload=payload, payload_type=payload_type)
            return True
        except AttestationFailure:
            # The entry persisted, so counting it as dropped would make
            # dropped_writes lie. The missing seal gets its own counter and
            # shows up as attestation_gap on verify.
            self._attest_failures += 1
            return True
        except Exception as e:
            self._dropped += 1
            if self._drop_recorder is not None:
                # DropRecorder contract (ports/drops.py) is "never raises",
                # this call is trusted, not wrapped, same as attestor.attest()
                # above trusts its own contract.
                self._drop_recorder.record(reason=type(e).__name__, payload_type=payload_type)
            return False

    @property
    def dropped_writes(self) -> int:
        return self._dropped

    @property
    def attest_failures(self) -> int:
        return self._attest_failures

    @property
    def anchor_failures(self) -> int:
        return self._anchor_failures

    def with_anchor_sink(
        self,
        sink: Any,
        *,
        anchor_every: int | None = None,
        aggregate_source: AggregateSource | None = None,
    ) -> AuditLog:
        """A view of this same trail that publishes checkpoints to ``sink``.

        Lets a read-only caller (the CLI's `anchor`) attach a sink without
        reaching for the backend object, which would hand it an append path
        outside this facade's attestation and anchoring. Shares the backend
        deliberately (it is the same trail, not a copy) but takes its own
        append lock, so this view is for anchoring, not for concurrent writes
        alongside the original.

        ``aggregate_source`` lets a caller holding no seal key still bind the
        trail's accumulator into the checkpoint (ports/aggregate.py); omitted,
        the view keeps whatever source this log already had.
        """
        return AuditLog(
            self._backend,
            redactor=self._redactor,
            now_fn=self._now,
            registry=self._registry,
            attestor=self._attestor,
            anchor_sink=sink,
            anchor_every=anchor_every,
            drop_recorder=self._drop_recorder,
            aggregate_source=(
                self._aggregate_source if aggregate_source is None else aggregate_source
            ),
            trail_path=self.trail_path,
        )

    def entries(self) -> Iterator[Entry]:
        """Every entry in write order: the read side of the facade.

        Readers (the CLI, reports, proof export) go through this rather than
        the backend attribute: which backend is behind an AuditLog is the
        facade's business, and a caller holding the backend directly would be
        free to append behind the attestation and anchoring this class owns.
        """
        return iter(self._backend.entries())

    def entry_hashes(self) -> list[str]:
        """Entry hashes in write order: the input every checkpoint, pin, and
        witness check is computed over. One materializing pass, defined once,
        because two spellings of "the trail's hashes" are two chances to
        disagree about them.

        The list is inherent, not an unoptimized leftover: `batch_root` and
        `consistency_proof` (RFC 6962 / RFC 9162) hash the leaves pairwise
        upward, so every leaf is needed again after the last one is read, and
        `membership_proof` indexes into them. A streaming variant of this
        method cannot exist without a second read of the whole trail, which
        is strictly worse. Callers that only need the chain verdict and a
        forward pass over entries have `_verify_and_entries` / `entries()`
        instead — do not "optimize" this one into a generator.
        """
        reader = getattr(self._backend, "entry_hashes", None)
        if callable(reader):
            return list(reader())
        return [entry.entry_hash for entry in self.entries()]

    def anchor(self) -> Checkpoint:
        """Checkpoint the current trail and publish it via ``anchor_sink``.

        Called automatically every ``anchor_every`` appends, or explicitly
        (e.g. from the CLI). Raises ValueError with no sink configured or an
        empty trail (nothing to checkpoint); the sink's own ``anchor()`` may
        raise too, and auto-anchoring catches that (see ``append``); an
        explicit call does not, so a caller asking for it gets to see why.
        """
        if self._anchor_sink is None:
            raise ValueError("this log was opened without an anchor_sink")
        hashes = self.entry_hashes()
        if not hashes:
            raise ValueError("cannot anchor an empty trail")
        agg_commit, agg_epoch = self._aggregate_binding()
        with self._append_lock:
            root = self._merkle_root_for(hashes)
        cp = checkpoint_for(
            hashes, agg_commit=agg_commit, agg_epoch=agg_epoch, root=root
        )
        self._anchor_sink.anchor(cp)
        return cp

    def _note_appended(self, entry: Entry) -> None:
        # seq is 0-based: a tree that already holds seq leaves is the
        # prefix this row extends. Any other size means this instance
        # opened an existing trail (or a with_anchor_sink view) and must
        # rebuild from disk rather than push onto an empty forest.
        if self._merkle.size == entry.header.seq:
            self._merkle.push(entry.entry_hash)
        else:
            self._merkle = IncrementalMerkle.from_hashes(self.entry_hashes())

    def _merkle_root_for(self, hashes: list[str]) -> str:
        if self._merkle.size == len(hashes):
            if hashes and self._merkle.last_leaf != hashes[-1]:
                # Same length, different last leaf: the in-memory forest
                # was built from a different prefix than disk (an
                # out-of-process rewrite of equal length). Recompute from
                # the hashes this checkpoint will publish.
                tree = IncrementalMerkle.from_hashes(hashes)
                self._merkle = tree
                return tree.root()
            return self._merkle.root()
        tree = IncrementalMerkle.from_hashes(hashes)
        if self._merkle.size == 0:
            # First use on this instance: keep the rebuilt forest so the
            # next anchor does not walk the prefix again. Do not overwrite
            # a live tree another thread already extended past `hashes`.
            self._merkle = tree
        return tree.root()

    def _aggregate_binding(self) -> tuple[str | None, int | None]:
        return aggregate_binding(self._aggregate_source)

    def verify_anchored_aggregates(self, *, initial_key: bytes) -> AttestResult:
        """Check every anchored aggregate commitment against the attestations.

        The check the local sidecars cannot make. ``verify_attestations``
        compares `.sealagg` against `.attest`, both under whoever owns the
        trail, so an attacker who truncates the trail and restores an older
        accumulator satisfies it. The commitments here come from anchor
        records a third party witnessed, so passing this requires not having
        rewritten what that third party holds.

        Anchor records with no binding (every record written before it
        existed, and every trail that never aggregated) are counted
        ``unverifiable``: no aggregate claim was made, so there is none to
        check, and calling that a pass would report coverage nobody has.
        """
        if self._attestor is None:
            raise ValueError("verify_anchored_aggregates needs an attestor")
        return check_anchored_aggregates(
            self._attestor,
            self._aggregate_source,
            initial_key=initial_key,
        )

    def verify(self, *, measure_drops: bool = True) -> VerifyResult:
        """Report chain integrity. Never repairs. Unknown fingerprints are
        unverifiable by name, never tampered. ``dropped_writes is None``
        means completeness was not measured, never the same as ``0``.
        """
        result = verify_chain(self._backend.entries(), self._registry)
        if not measure_drops:
            return result
        if self._drop_recorder is not None and hasattr(self._drop_recorder, "count"):
            # The sidecar's own count survives across process restarts, so a
            # fresh process's in-memory counter would otherwise read 0 for
            # history it never observed (None-vs-0, CLAUDE.md rule 5).
            return replace(
                result, dropped_writes=self._drop_recorder.count(), drops_source="sidecar"
            )
        # No durable recorder: only this process's own counter, reset every
        # AuditLog.open. Reporting it as anything but "process" scope would
        # overstate what was actually measured.
        return replace(result, dropped_writes=self._dropped, drops_source="process")

    def _verify_and_entries(self) -> tuple[VerifyResult, list[Entry]]:
        """The chain verdict and the entries it was computed over, from ONE
        pass over the backend.

        `report` needs both, and reading the trail twice to get them made a
        read-only command cost double for a verdict and a summary of the same
        bytes. Deliberately not a public method taking caller-supplied
        entries: a verdict must be computed over what this log actually
        stores, never over rows handed in from outside, and the registry that
        decides which rows are recomputable stays owned by this class.

        `dropped_writes` is left at `None` (verify_chain's own value): a
        process that observed no writes has not measured completeness, and
        `None` is never the same as `0` (CLAUDE.md rule 5).
        """
        entries = list(self._backend.entries())
        return verify_chain(entries, self._registry), entries

    def _canonical_payload(self, payload: dict[str, Any] | bytes) -> bytes:
        if isinstance(payload, bytes):
            if self._redactor is not None:
                # Same refuse as sources.decisions.commit_input: the
                # Redactor port only sees dicts, so "redacted" would be a
                # claim nothing checked (CLAUDE.md rule 6).
                raise ValueError(
                    "a redactor cannot inspect bytes; redact the input as a dict, "
                    "or commit the bytes without claiming they were redacted"
                )
            return payload
        if isinstance(payload, dict):
            if self._redactor is not None:
                payload = self._redactor.redact(payload)
            return canonical_json(payload)
        raise TypeError(f"payload must be dict or bytes, got {type(payload).__name__}")
