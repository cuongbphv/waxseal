"""Forward-secure sealing: key-evolving HMAC over entry hashes.

Construction (Bellare–Yee 1997/2003; Schneier–Kelsey 1999): the epoch key
evolves one-way per entry, A_{j+1} = SHA-256(A_j), and the previous key is
discarded. A seal is HMAC-SHA256(A_j, framed entry_hash). An attacker who
compromises the machine at epoch t holds only A_t and cannot forge seals for
epochs < t — so a rewritten chain suffix (which a keyless hash chain cannot
detect) fails seal verification at the rewritten entry.

Verification holds A_0 and walks the epochs forward. Unknown attestation
schemes are unverifiable-by-name, never tampering (RFC 6962 principle),
and still advance the epoch clock so later seals verify.

Honest limits (see DESIGN.md §6): Python cannot guarantee memory zeroization
of old keys, and entries written AFTER compromise carry no guarantee under
any scheme. Forward security here is about pre-compromise history.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from waxseal.domain.hashing import lp

FS_HMAC_SCHEME: Final = "fs-hmac-sha256-v1"
SEAL_FRAME_PREFIX: Final = b"waxseal-seal-v1\n"

# FssAgg (Ma-Tsudik 2007): folds every per-entry seal into ONE running,
# KEYED accumulator so an attacker who truncates the trail loses the ability
# to reproduce it — they hold only the current epoch key, and the fold at
# each step is HMAC'd under that step's now-discarded key, not a plain hash
# of the public values (see TestVerifyAggregate's refold-without-key test:
# a keyless refold from public values alone cannot reproduce a real fold).
# Only the LATEST mu is ever persisted (adapters/attest.py's .sealagg,
# replace-only) — storing every intermediate mu would hand an attacker who
# copies mu_{t'-1} exactly the truncation hole this scheme exists to close.
FS_HMAC_AGG_SCHEME: Final = "fs-hmac-agg-sha256-v1"
AGG_FRAME_PREFIX: Final = b"waxseal-agg-v1\n"
AGG_GENESIS: Final = "0" * 64

# What an external witness gets to see. The accumulator itself must never be
# published — the comment above says why persisting an intermediate mu reopens
# the truncation hole, and an anchor stream is a persisted record like any
# other. A commitment carries the same evidentiary weight for anyone holding
# A_0 (they can recompute mu and check it) while telling an attacker who holds
# only the current key nothing they can fold.
AGG_COMMIT_FRAME_PREFIX: Final = b"waxseal-aggcommit-v1\n"


@dataclass(frozen=True, slots=True)
class Attestation:
    seq: int
    entry_hash: str
    scheme: str
    value: str  # hex MAC for fs-hmac; hex signature for signer schemes
    key_id: str | None = None


@dataclass(frozen=True, slots=True)
class AttestResult:
    ok: bool
    checked: int
    broken_seq: int | None
    reason: str | None
    unverifiable: tuple[int, ...]


def generate_key() -> bytes:
    return secrets.token_bytes(32)


def evolve_key(key: bytes) -> bytes:
    return hashlib.sha256(key).digest()


def seal_entry(epoch_key: bytes, entry_hash: str) -> str:
    return hmac.new(
        epoch_key, SEAL_FRAME_PREFIX + entry_hash.encode("ascii"), hashlib.sha256
    ).hexdigest()


def verify_seals(attestations: Iterable[Attestation], initial_key: bytes) -> AttestResult:
    checked = 0
    unverifiable: list[int] = []
    key = initial_key
    for position, att in enumerate(attestations):
        if att.seq != position:
            # journald CVE-2023-31439 lesson: seq↔epoch binding must hold in
            # BOTH directions — a seal claiming another position is a break.
            return AttestResult(
                ok=False,
                checked=checked,
                broken_seq=att.seq,
                reason="seal_sequence_mismatch",
                unverifiable=tuple(unverifiable),
            )
        if att.scheme in (FS_HMAC_SCHEME, FS_HMAC_AGG_SCHEME):
            try:
                expected = seal_entry(key, att.entry_hash)
                matches = hmac.compare_digest(expected, att.value)
            except (UnicodeEncodeError, TypeError):
                # Attacker-writable sidecar: a non-ASCII "hash", or a value
                # hmac.compare_digest itself refuses (it rejects any non-ASCII
                # str), must be a verdict, not a crash that denies the audit.
                return AttestResult(
                    ok=False,
                    checked=checked,
                    broken_seq=att.seq,
                    reason="malformed_attestation",
                    unverifiable=tuple(unverifiable),
                )
            if not matches:
                return AttestResult(
                    ok=False,
                    checked=checked,
                    broken_seq=att.seq,
                    reason="seal_mismatch",
                    unverifiable=tuple(unverifiable),
                )
            checked += 1
        else:
            unverifiable.append(att.seq)
        # The epoch clock is positional: it advances through opaque rows too,
        # otherwise one foreign attestation would desync every later seal.
        key = evolve_key(key)
    return AttestResult(
        ok=True,
        checked=checked,
        broken_seq=None,
        reason=None,
        unverifiable=tuple(unverifiable),
    )


def aggregate_step(epoch_key: bytes, prev_agg: str, value: str) -> str:
    """One FssAgg fold: mu_i = HMAC-SHA256(A_i, frame(mu_{i-1}, value_i)).

    ``epoch_key`` is the SAME key that sealed this row (the epoch key BEFORE
    it evolves) — the fold commits to the whole prefix under a key an
    attacker who later compromises the machine no longer holds.
    """
    frame = AGG_FRAME_PREFIX + bytes.fromhex(prev_agg) + lp(value)
    return hmac.new(epoch_key, frame, hashlib.sha256).hexdigest()


def verify_aggregate(
    attestations: Iterable[Attestation],
    initial_key: bytes,
    *,
    agg_start: int,
    epoch: int,
    agg: str,
) -> str | None:
    """Check a persisted FssAgg accumulator against the full attestation
    list. Fails closed and never raises (same contract as
    ``anchoring.verify_membership``): the sidecar holding ``agg``/``epoch``/
    ``agg_start`` is attacker-writable by threat model.

    Returns ``None`` when it verifies, else one of:

    - ``malformed_aggregate``: agg_start out of [0, epoch], agg is not hex,
      or an aggregate-scheme row's value cannot be folded (non-UTF-8 —
      an attacker-writable sidecar is not obligated to hand back clean
      bytes, and a fold that cannot even run is a verdict, not a crash).
    - ``aggregate_epoch_mismatch``: either ``epoch`` claims more rows than
      exist (a dropped/truncated row), or an aggregate-scheme row sits PAST
      ``epoch`` — a fold the writer performed but never persisted (a crash
      between the keyfile/attest writes and the ``.sealagg`` write).
    - ``aggregate_mismatch``: the fold over the given rows does not
      reproduce ``agg`` (a tampered value, or a wrong ``agg_start``).

    Rows before ``agg_start`` are skipped (aggregation may start mid-trail —
    DESIGN.md's upgrade path); they still advance the epoch key so later
    folds line up, matching ``verify_seals``' positional clock. Rows at or
    after ``epoch`` are similarly skipped for folding, but ONLY if they are
    not themselves aggregate-scheme: a trail may switch a ``FileAttestor``
    back to plain ``fs-hmac-sha256-v1`` after aggregating for a while, and
    that scheme's own rows never touch ``.sealagg`` again — treating the
    resulting positional gap as a break would turn an ordinary configuration
    change into a false tampering alarm (the incident class this whole
    project exists to make unrepresentable).
    """
    atts = list(attestations)
    if not 0 <= agg_start <= epoch:
        return "malformed_aggregate"
    if epoch > len(atts):
        return "aggregate_epoch_mismatch"
    try:
        bytes.fromhex(agg)
    except ValueError:
        return "malformed_aggregate"
    if any(att.scheme == FS_HMAC_AGG_SCHEME for att in atts[epoch:]):
        return "aggregate_epoch_mismatch"

    key = initial_key
    running = AGG_GENESIS
    for position, att in enumerate(atts):
        if position >= epoch:
            break
        if position >= agg_start and att.scheme == FS_HMAC_AGG_SCHEME:
            try:
                running = aggregate_step(key, running, att.value)
            except (ValueError, UnicodeEncodeError):
                return "malformed_aggregate"
        key = evolve_key(key)
    if running != agg:
        return "aggregate_mismatch"
    return None


def aggregate_commit(epoch: int, agg: str) -> str:
    """A publishable commitment to the accumulator ``agg`` at ``epoch``.

    ``sha256`` over a PAE-style frame binding both values, so a commitment
    cannot be replayed against a different epoch. Hiding follows from ``agg``
    being a 256-bit HMAC output that nobody without A_0 can predict — the
    commitment reveals no value an attacker could fold, which is why this and
    not the accumulator is what goes into an anchor.

    Raises ValueError if ``agg`` is not hex. This is only ever called on a
    value the library produced, so bad input here is a bug rather than the
    attacker-supplied case the ``verify_*`` functions are hardened against.
    """
    bytes.fromhex(agg)
    frame = AGG_COMMIT_FRAME_PREFIX + struct.pack(">Q", 2) + lp(str(epoch)) + lp(agg)
    return hashlib.sha256(frame).hexdigest()


def verify_anchored_aggregate(
    attestations: Iterable[Attestation],
    initial_key: bytes,
    *,
    agg_start: int,
    anchored_epoch: int,
    anchored_commit: str,
) -> str | None:
    """Check the trail against an aggregate commitment held by a witness.

    This is the check ``verify_aggregate`` cannot make. That one compares the
    local `.sealagg` against the local attestations — both under the same
    authority, so an attacker who truncates the trail and restores an older
    accumulator satisfies it. Here the epoch and commitment come from outside
    (an anchor record a third party attested), so the same attacker has to
    have rewritten something they do not control.

    Fails closed and never raises; the attestation list is attacker-writable
    by threat model. Returns ``None`` when it verifies, else one of:

    - ``malformed_anchored_aggregate``: ``agg_start`` outside
      ``[0, anchored_epoch]``, a commitment that is not hex, or a row whose
      value the fold cannot run over.
    - ``anchored_aggregate_epoch_mismatch``: the trail no longer holds as many
      rows as were anchored. THE truncation case — replaying an old
      accumulator cannot manufacture rows that are gone.
    - ``anchored_aggregate_mismatch``: the fold over the anchored prefix does
      not reproduce the anchored commitment (a rewritten row inside it, a
      forged commitment, or the wrong key).

    Unlike ``verify_aggregate``, aggregate-scheme rows PAST ``anchored_epoch``
    are not a discrepancy: an anchor describes a past state, and a trail is
    supposed to have grown since.
    """
    atts = list(attestations)
    if not 0 <= agg_start <= anchored_epoch:
        return "malformed_anchored_aggregate"
    try:
        bytes.fromhex(anchored_commit)
    except ValueError:
        return "malformed_anchored_aggregate"
    if anchored_epoch > len(atts):
        return "anchored_aggregate_epoch_mismatch"

    key = initial_key
    running = AGG_GENESIS
    for position, att in enumerate(atts):
        if position >= anchored_epoch:
            break
        if position >= agg_start and att.scheme == FS_HMAC_AGG_SCHEME:
            try:
                running = aggregate_step(key, running, att.value)
            except (ValueError, UnicodeEncodeError):
                return "malformed_anchored_aggregate"
        key = evolve_key(key)

    if not hmac.compare_digest(aggregate_commit(anchored_epoch, running), anchored_commit):
        return "anchored_aggregate_mismatch"
    return None
