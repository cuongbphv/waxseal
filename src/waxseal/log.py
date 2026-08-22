"""AuditLog — the public facade.

Composes: redact → canonical payload bytes → payload_hash → header built under
the backend's lock → append. Verification is delegated to the pure domain
verifier; this class only adds the completeness dimension (dropped_writes),
because chain integrity ≠ trail completeness (CLAUDE.md rule 5).
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from waxseal.adapters.jsonl import JSONLBackend
from waxseal.domain.checkpoint import Checkpoint, checkpoint_for
from waxseal.domain.fingerprint import fingerprint_v1
from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
from waxseal.domain.header import Entry, EntryHeader
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.sealing import (
    FS_HMAC_AGG_SCHEME,
    SEAL_FRAME_PREFIX,
    AttestResult,
    verify_aggregate,
    verify_seals,
)
from waxseal.domain.verify import VerifyResult, verify_chain
from waxseal.ports.drops import DropRecorder
from waxseal.ports.redact import Redactor
from waxseal.ports.sign import Verifier

# DSSE rule (SPEC section 1): a generic JSON type defeats the point of
# payload_type — it names neither the schema nor the producer.
_REJECTED_PAYLOAD_TYPES = frozenset({"application/json", "text/json"})

_SQLITE_SUFFIXES = frozenset({".db", ".sqlite", ".sqlite3"})


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
    ) -> None:
        if anchor_every is not None and anchor_every < 1:
            raise ValueError("anchor_every must be a positive integer")
        self._backend = backend
        self._redactor = redactor
        self._now = now_fn or _default_now
        self._registry = registry or VersionRegistry()
        self._attestor = attestor
        self._anchor_sink = anchor_sink
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
    ) -> AuditLog:
        if isinstance(path, str) and path.startswith(("http://", "https://")):
            # MUST come before Path(path): Path() collapses "//" and drops
            # the scheme, so checking suffix on a mangled URL would never
            # even reach a backend choice — same class of bug M0's suffix
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
            )
            return cls(
                remote_backend,
                redactor=redactor,
                now_fn=now_fn,
                registry=registry,
                attestor=attestor,
                anchor_sink=anchor_sink,
                anchor_every=anchor_every,
                drop_recorder=None,
            )
        p = Path(path).expanduser()
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
        return cls(
            backend,
            redactor=redactor,
            now_fn=now_fn,
            registry=registry,
            attestor=attestor,
            anchor_sink=anchor_sink,
            anchor_every=anchor_every,
            drop_recorder=drop_recorder,
        )

    def append(self, *, payload: dict[str, Any] | bytes, payload_type: str) -> Entry:
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
                hash_version=fingerprint_v1(),
                payload_type=payload_type,
                payload_hash=payload_hash,
                prev_hash=prev_hash,
            )
            return Entry(
                header=header, entry_hash=compute_entry_hash(header), payload=payload_bytes
            )

        with self._append_lock:
            entry = self._backend.append(build)
            if self._attestor is not None:
                # Attest AFTER the entry is durably appended. A crash between
                # the two leaves the sidecar one behind — FileAttestor refuses
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
            # is harmless (idempotent content, checked independently) — the
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
        try:
            attestations = list(self._attestor.attestations())
        except (ValueError, KeyError, TypeError):
            # The sidecar is attacker-writable by threat model. Malformed
            # bytes are a verdict, never an exception — crashing the verifier
            # on attacker-supplied input would deny the audit (same fail-closed
            # rule as anchoring.verify_membership).
            return AttestResult(
                ok=False,
                checked=0,
                broken_seq=None,
                reason="malformed_attestation",
                unverifiable=(),
            )

        # journald CVE-2023-31437 lesson: what the reader consumes (the trail)
        # and what is authenticated (the sidecar) must be cross-checked. The
        # expected hash is RECOMPUTED from the trail header — the stored
        # entry_hash field is attacker-writable.
        entries = list(self._backend.entries())
        for position, att in enumerate(attestations):
            if position >= len(entries):
                mismatch: int | None = att.seq
            else:
                header = entries[position].header
                expected = (
                    compute_entry_hash(header)
                    if self._registry.recomputable(header.hash_version)
                    else entries[position].entry_hash
                )
                mismatch = att.seq if att.entry_hash != expected else None
            if mismatch is not None:
                return AttestResult(
                    ok=False,
                    checked=0,
                    broken_seq=mismatch,
                    reason="attest_trail_mismatch",
                    unverifiable=(),
                )

        if len(attestations) < len(entries):
            # Coverage, not integrity: rows past the sidecar's end carry no
            # seal at all. Without this check a truncated (or failure-starved)
            # sidecar verifies "ok" over whatever remains — the fs-hmac
            # continuity check cannot see it when the keyfile epoch still
            # matches the attestation count, and signer mode has no keyfile.
            return AttestResult(
                ok=False,
                checked=0,
                broken_seq=len(attestations),
                reason="attestation_gap",
                unverifiable=(),
            )

        if initial_key is not None and hasattr(self._attestor, "check_continuity"):
            # Ma-Tsudik truncation attack: consistent tail-chopping of trail +
            # sidecar passes both checks above; the one-way keyfile cannot lie.
            try:
                reason = self._attestor.check_continuity(initial_key, len(attestations))
            except (ValueError, KeyError, TypeError):
                # Keyfile bytes are on the same attacker-writable disk: a
                # mangled keyfile must surface as a verdict, not a crash.
                reason = "malformed_keyfile"
            if reason is not None:
                return AttestResult(
                    ok=False,
                    checked=0,
                    broken_seq=None,
                    reason=reason,
                    unverifiable=(),
                )

        if verifier is not None:
            checked = 0
            unverifiable: list[int] = []
            scheme = f"sig-{verifier.algorithm}-v1"
            for att in attestations:
                if att.scheme != scheme:
                    unverifiable.append(att.seq)
                    continue
                try:
                    frame = SEAL_FRAME_PREFIX + att.entry_hash.encode("ascii")
                    signature = bytes.fromhex(att.value)
                except (ValueError, UnicodeEncodeError):
                    return AttestResult(
                        ok=False,
                        checked=checked,
                        broken_seq=att.seq,
                        reason="malformed_attestation",
                        unverifiable=tuple(unverifiable),
                    )
                if not verifier.verify(frame, signature):
                    return AttestResult(
                        ok=False,
                        checked=checked,
                        broken_seq=att.seq,
                        reason="signature_invalid",
                        unverifiable=tuple(unverifiable),
                    )
                checked += 1
            return AttestResult(
                ok=True,
                checked=checked,
                broken_seq=None,
                reason=None,
                unverifiable=tuple(unverifiable),
            )
        if initial_key is None:
            raise ValueError("provide initial_key (fs-hmac) or verifier (signatures)")
        result = verify_seals(attestations, initial_key)
        if not result.ok:
            return result
        if hasattr(self._attestor, "read_aggregate"):
            # FssAgg: an independent, ADDITIONAL gate checked only once the
            # per-entry seals themselves are already intact — it exists to
            # catch what a per-position check structurally cannot (rows
            # missing entirely), not to duplicate seal_mismatch's more
            # specific broken_seq. A trail rewritten consistently down to
            # the .sealagg sidecar itself (an attacker who controls every
            # file) is the same honest limit anchoring already documents.
            try:
                agg_data = self._attestor.read_aggregate()
            except (ValueError, KeyError, TypeError):
                return AttestResult(
                    ok=False, checked=result.checked, broken_seq=None,
                    reason="malformed_aggregate", unverifiable=result.unverifiable,
                )
            has_agg_row = any(att.scheme == FS_HMAC_AGG_SCHEME for att in attestations)
            if has_agg_row and agg_data is None:
                return AttestResult(
                    ok=False, checked=result.checked, broken_seq=None,
                    reason="aggregate_missing", unverifiable=result.unverifiable,
                )
            if agg_data is not None:
                agg_start, epoch, agg = agg_data
                reason = verify_aggregate(
                    attestations, initial_key, agg_start=agg_start, epoch=epoch, agg=agg
                )
                if reason is not None:
                    return AttestResult(
                        ok=False, checked=result.checked, broken_seq=None,
                        reason=reason, unverifiable=result.unverifiable,
                    )
        return result

    def try_append(self, *, payload: dict[str, Any] | bytes, payload_type: str) -> bool:
        """Best-effort append: never raises. A failure increments
        dropped_writes so the loss is measured, not silent (CLAUDE.md rule 6)."""
        try:
            self.append(payload=payload, payload_type=payload_type)
            return True
        except AttestationFailure:
            # The entry persisted — counting it as dropped would make
            # dropped_writes lie. The missing seal gets its own counter and
            # shows up as attestation_gap on verify.
            self._attest_failures += 1
            return True
        except Exception as e:
            self._dropped += 1
            if self._drop_recorder is not None:
                # DropRecorder contract (ports/drops.py) is "never raises" —
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

    def anchor(self) -> Checkpoint:
        """Checkpoint the current trail and publish it via ``anchor_sink``.

        Called automatically every ``anchor_every`` appends, or explicitly
        (e.g. from the CLI). Raises ValueError with no sink configured or an
        empty trail (nothing to checkpoint); the sink's own ``anchor()`` may
        raise too — auto-anchoring catches that (see ``append``), an
        explicit call does not, so a caller asking for it gets to see why.
        """
        if self._anchor_sink is None:
            raise ValueError("this log was opened without an anchor_sink")
        hashes = [entry.entry_hash for entry in self._backend.entries()]
        if not hashes:
            raise ValueError("cannot anchor an empty trail")
        cp = checkpoint_for(hashes)
        self._anchor_sink.anchor(cp)
        return cp

    def verify(self, *, measure_drops: bool = True) -> VerifyResult:
        result = verify_chain(self._backend.entries(), self._registry)
        if not measure_drops:
            return result
        if self._drop_recorder is not None and hasattr(self._drop_recorder, "count"):
            # The sidecar's own count survives across process restarts — a
            # fresh process's in-memory counter would otherwise read 0 for
            # history it never observed (None-vs-0, CLAUDE.md rule 5).
            return replace(
                result, dropped_writes=self._drop_recorder.count(), drops_source="sidecar"
            )
        # No durable recorder: only this process's own counter, reset every
        # AuditLog.open — reporting it as anything but "process" scope would
        # overstate what was actually measured.
        return replace(result, dropped_writes=self._dropped, drops_source="process")

    def _canonical_payload(self, payload: dict[str, Any] | bytes) -> bytes:
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, dict):
            if self._redactor is not None:
                payload = self._redactor.redact(payload)
            return json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
        raise TypeError(f"payload must be dict or bytes, got {type(payload).__name__}")
