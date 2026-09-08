"""Proof bundles: one entry, provable on its own (pure; no I/O).

An auditor asking about a single decision has two bad options with a plain
hash chain: take the institution's word for one row, or receive the entire
trail (every other customer's decisions included) to check the links. A
bundle is the third option. It carries one entry plus the RFC 6962 sibling
hashes tying it to a batch root, so the row checks out offline against a root
that was anchored somewhere the institution cannot reach (``domain.anchoring``,
``domain.checkpoint``). Handing over one decision no longer means handing over
all of them, and the recipient still verifies rather than trusts.

What the root adds over recomputing the entry hash: an entry rebuilt
consistently, with the header edited and ``entry_hash`` recomputed to match, passes
every local check. It cannot pass membership against a root published before
the edit. That is the whole-trail-rewrite gap the chain alone cannot close,
narrowed to a single exported row.

Verification is fail-closed and never raises, matching ``domain.anchoring``:
a bundle arrives from outside, and crashing the verifier on hostile bytes
would deny the audit itself. Parsing is the separate step that raises, and it
raises only ``ValueError``, so a CLI can turn it into a verdict.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from waxseal.domain.anchoring import batch_root, membership_proof, verify_membership
from waxseal.domain.hashing import LpEncodingError, compute_entry_hash, compute_payload_hash
from waxseal.domain.header import Entry, EntryHeader, header_from_obj, header_to_obj
from waxseal.domain.registry import VersionRegistry

BUNDLE_VERSION: Final = "waxseal-proof-bundle-v1"


@dataclass(frozen=True, slots=True)
class ProofBundle:
    """One entry plus its membership proof against ``root``.

    There is no separate index field: the chain is contiguous from seq 0, so
    the batch index *is* ``header.seq``. Carrying both would be two numbers
    that must agree, and a bundle whose index and seq disagreed would have no
    honest interpretation.
    """

    header: EntryHeader
    entry_hash: str
    payload: bytes | None
    batch_size: int
    proof: tuple[str, ...]
    root: str


@dataclass(frozen=True, slots=True)
class BundleResult:
    ok: bool
    reason: str | None
    # True when this build cannot recompute the entry's hash because it does
    # not know the row's schema fingerprint. Not a failure and never
    # tampering: membership against the anchored root still holds, because
    # the root commits to the stored entry_hash whatever schema produced it.
    unverifiable: bool


def build_proof_bundle(entries: Sequence[Entry], seq: int) -> ProofBundle:
    """Bundle the entry at ``seq`` against a root over the whole batch.

    ``seq`` outside the batch raises IndexError rather than proving some
    other entry, the same contract ``membership_proof`` keeps for
    operator-supplied indices.
    """
    if not 0 <= seq < len(entries):
        raise IndexError(f"seq {seq} outside batch of size {len(entries)}")
    hashes = [entry.entry_hash for entry in entries]
    entry = entries[seq]
    return ProofBundle(
        header=entry.header,
        entry_hash=entry.entry_hash,
        payload=entry.payload,
        batch_size=len(hashes),
        proof=membership_proof(hashes, seq),
        root=batch_root(hashes),
    )


def verify_proof_bundle(bundle: ProofBundle, registry: VersionRegistry) -> BundleResult:
    """Check a bundle offline. Never raises; see the module docstring."""
    seq = bundle.header.seq
    if bundle.batch_size < 1 or not 0 <= seq < bundle.batch_size:
        return BundleResult(ok=False, reason="malformed_bundle", unverifiable=False)
    if not _is_sha256_hex(bundle.entry_hash) or not _is_sha256_hex(bundle.root):
        return BundleResult(ok=False, reason="malformed_bundle", unverifiable=False)

    unverifiable = not registry.recomputable(bundle.header.hash_version)
    if not unverifiable:
        # Only recompute under a schema the row was actually written with.
        # Doing otherwise would report a row tampered for having a fingerprint
        # this build does not implement (the migration-060 failure class).
        # Dispatch by fingerprint (registry.encoder_for), exactly like
        # verify_chain (domain/verify.py): recompute the row only under the
        # encoding its own hash_version names.
        encoder = registry.encoder_for(bundle.header.hash_version)
        assert encoder is not None  # type-narrowing; recomputable() already proved this
        try:
            recomputed = compute_entry_hash(bundle.header, frame=encoder)
        except LpEncodingError:
            # waxseal-lmv (never-raise fuzzing sweep): mirrors
            # domain/verify.py's identical fix. A header field can be a
            # `str` with no UTF-8 form (a lone UTF-16 surrogate --
            # json.loads('"\ud800"') produces one, and a bundle is exactly
            # the "operator- and attacker-supplied JSON" this module's own
            # docstring names). `lp()` labels that LpEncodingError instead
            # of a bare UnicodeEncodeError (gap G4), but it was left uncaught
            # here, so this function's own "never raises" promise (see its
            # docstring) broke on exactly the input it exists to survive. A
            # header this build cannot even encode can never reproduce the
            # stored hash, so this is the existing entry_hash_mismatch
            # finding, not a new incident class (CLAUDE.md rules 4/5/6).
            return BundleResult(ok=False, reason="entry_hash_mismatch", unverifiable=False)
        if recomputed != bundle.entry_hash:
            return BundleResult(ok=False, reason="entry_hash_mismatch", unverifiable=False)
        if (
            bundle.payload is not None
            and compute_payload_hash(bundle.payload) != bundle.header.payload_hash
        ):
            return BundleResult(ok=False, reason="payload_hash_mismatch", unverifiable=False)

    if not verify_membership(bundle.entry_hash, seq, bundle.batch_size, bundle.proof, bundle.root):
        return BundleResult(ok=False, reason="membership_not_proven", unverifiable=unverifiable)
    return BundleResult(ok=True, reason=None, unverifiable=unverifiable)


def bundle_to_json(bundle: ProofBundle) -> str:
    """Serialize a bundle for an auditor to keep and re-check later.

    Indented and version-stamped on purpose: this artifact outlives the tool
    that produced it, so it must be readable by a person and identifiable by
    a program without guessing from its shape. It is not hashed, so pretty
    printing costs nothing.
    """
    return json.dumps(
        {
            "bundle_version": BUNDLE_VERSION,
            "header": header_to_obj(bundle.header),
            "entry_hash": bundle.entry_hash,
            "payload_b64": (
                None if bundle.payload is None else base64.b64encode(bundle.payload).decode("ascii")
            ),
            "batch_size": bundle.batch_size,
            "proof": list(bundle.proof),
            "root": bundle.root,
        },
        indent=2,
        sort_keys=True,
    )


def bundle_from_json(text: str) -> ProofBundle:
    """Parse a serialized bundle.

    Raises ``ValueError``, and only ``ValueError``, on anything malformed,
    including a format version this build does not know. That last one is a
    parse refusal, not a tampering verdict: an unrecognized format is
    something this reader cannot check, and saying so is the honest answer
    (an unknown *schema fingerprint* inside a well-formed bundle is a
    different question, and ``verify_proof_bundle`` answers it with
    ``unverifiable``).
    """
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"bundle is not valid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError("bundle must be a JSON object")
    version = obj.get("bundle_version")
    if version != BUNDLE_VERSION:
        raise ValueError(f"unknown bundle format {version!r}; this build reads {BUNDLE_VERSION}")
    for field in ("header", "entry_hash", "batch_size", "proof", "root"):
        if field not in obj:
            raise ValueError(f"bundle is missing {field!r}")

    proof_raw = obj["proof"]
    if not isinstance(proof_raw, list) or not all(isinstance(p, str) for p in proof_raw):
        raise ValueError("bundle proof must be a list of hex strings")

    batch_size = obj["batch_size"]
    if isinstance(batch_size, bool) or not isinstance(batch_size, int):
        raise ValueError("bundle batch_size must be an integer")

    return ProofBundle(
        header=header_from_obj(obj["header"]),
        entry_hash=str(obj["entry_hash"]),
        payload=_decode_payload(obj.get("payload_b64")),
        batch_size=batch_size,
        proof=tuple(proof_raw),
        root=str(obj["root"]),
    )


def _decode_payload(value: Any) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("bundle payload_b64 must be a base64 string or null")
    try:
        # validate=True so stray characters are an error rather than being
        # silently discarded into different bytes than the producer sent.
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"bundle payload_b64 is not valid base64: {e}") from e


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)
