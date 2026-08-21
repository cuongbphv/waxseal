"""AuditLog — the public facade.

Composes: redact → canonical payload bytes → payload_hash → header built under
the backend's lock → append. Verification is delegated to the pure domain
verifier; this class only adds the completeness dimension (dropped_writes),
because chain integrity ≠ trail completeness (CLAUDE.md rule 5).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from waxseal.adapters.jsonl import JSONLBackend
from waxseal.domain.fingerprint import fingerprint_v1
from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
from waxseal.domain.header import Entry, EntryHeader
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.sealing import SEAL_FRAME_PREFIX, AttestResult, verify_seals
from waxseal.domain.verify import VerifyResult, verify_chain
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
    ) -> None:
        self._backend = backend
        self._redactor = redactor
        self._now = now_fn or _default_now
        self._registry = registry or VersionRegistry()
        self._attestor = attestor
        self._dropped = 0
        self._attest_failures = 0
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
    ) -> AuditLog:
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
        return cls(
            backend, redactor=redactor, now_fn=now_fn, registry=registry, attestor=attestor
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
        return verify_seals(attestations, initial_key)

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
        except Exception:
            self._dropped += 1
            return False

    @property
    def dropped_writes(self) -> int:
        return self._dropped

    @property
    def attest_failures(self) -> int:
        return self._attest_failures

    def verify(self, *, measure_drops: bool = True) -> VerifyResult:
        result = verify_chain(self._backend.entries(), self._registry)
        if measure_drops:
            # Only this process's own counter — a fresh process reporting 0
            # for history it never observed would be a lie (None = unmeasured).
            return replace(result, dropped_writes=self._dropped)
        return result

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
