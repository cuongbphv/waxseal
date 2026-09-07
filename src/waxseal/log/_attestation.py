"""Sidecar attestation checks. Receives the attestor and backend as arguments."""

from __future__ import annotations

from typing import Any

from waxseal.domain.hashing import compute_entry_hash
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.sealing import (
    FS_HMAC_AGG_SCHEME,
    SEAL_FRAME_PREFIX,
    AttestResult,
    verify_aggregate,
    verify_seals,
)
from waxseal.ports.sign import Verifier


def verify_sidecar(
    attestor: Any,
    backend: Any,
    registry: VersionRegistry,
    *,
    initial_key: bytes | None = None,
    verifier: Verifier | None = None,
) -> AttestResult:
    """Verify the attestation sidecar. fs-hmac seals need `initial_key`
    (A_0); signer attestations need a `verifier`. Schemes neither can
    handle are reported unverifiable-by-name, never as tampering."""
    try:
        attestations = list(attestor.attestations())
    except (ValueError, KeyError, TypeError):
        # The sidecar is attacker-writable by threat model. Malformed
        # bytes are a verdict, never an exception, since crashing the verifier
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
    # expected hash is RECOMPUTED from the trail header, so the stored
    # entry_hash field is attacker-writable.
    entries = list(backend.entries())
    for position, att in enumerate(attestations):
        if position >= len(entries):
            mismatch: int | None = att.seq
        else:
            header = entries[position].header
            # Dispatch by fingerprint (registry.encoder_for), exactly
            # like verify_chain (domain/verify.py) and verify_proof_bundle
            # (domain/export.py): recompute a row only under the encoding
            # its own hash_version names, never under whatever this build
            # happens to implement.
            encoder = registry.encoder_for(header.hash_version)
            expected = (
                compute_entry_hash(header, frame=encoder)
                if encoder is not None
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
        # sidecar verifies "ok" over whatever remains. The fs-hmac
        # continuity check cannot see it when the keyfile epoch still
        # matches the attestation count, and signer mode has no keyfile.
        return AttestResult(
            ok=False,
            checked=0,
            broken_seq=len(attestations),
            reason="attestation_gap",
            unverifiable=(),
        )

    if initial_key is not None and hasattr(attestor, "check_continuity"):
        # Ma-Tsudik truncation attack: consistent tail-chopping of trail +
        # sidecar passes both checks above; the one-way keyfile cannot lie.
        try:
            reason = attestor.check_continuity(initial_key, len(attestations))
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
    if hasattr(attestor, "read_aggregate"):
        # FssAgg: an independent, ADDITIONAL gate checked only once the
        # per-entry seals themselves are already intact. It exists to
        # catch what a per-position check structurally cannot (rows
        # missing entirely), not to duplicate seal_mismatch's more
        # specific broken_seq. A trail rewritten consistently down to
        # the .sealagg sidecar itself (an attacker who controls every
        # file) is the same honest limit anchoring already documents.
        try:
            agg_data = attestor.read_aggregate()
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
