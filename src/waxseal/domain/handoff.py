"""Cross-trail handoff binding (SPEC D3; docs/plans/waxseal-paper-conformance.md).

``on_handoff`` in ``integrations/openai_agents.py`` records a handoff phase
carrying only ``from_agent``/``to_agent`` NAMES. A name commits to nothing
cryptographically -- it is a label, not evidence. When agent B's task is
delegated from agent A and each keeps its OWN trail, B's first entry for the
delegated task should instead carry a pointer into A's chain at the moment of
handoff: ``(chain_id, seq, head_hash)`` -- A's chain identity, the sequence
number, and A's ``entry_hash`` at that seq.

That pointer is committed the same way every other payload is: canonicalized
by ``domain.canonical.canonical_json``, hashed into ``payload_hash``, which is
itself one of the six fields ``EntryHeader`` hashes into B's ``entry_hash``
(CLAUDE.md's envelope design). So once ANY of B's later entries is anchored
(``domain.anchoring.batch_root`` over B's entry hashes), the anchored root
transitively pins A's prefix up to the recorded seq -- a rewrite of A behind
that point can no longer reproduce the ``head_hash`` this binding named.
``binding_holds`` below is the other half of that check: it compares a parsed
binding against A's OWN current entry hashes, which is what turns "B's
anchored root still contains this exact binding" into "A's history has not
changed since the handoff".

The binding carries ONLY the pointer triple -- no business data, by design.
A handoff entry that carried business data would fall under whatever
retention/erasure policy governs business data elsewhere in the trail, and an
erased handoff entry breaks the transitive pin it exists to provide. A triple
that IS the whole payload has no such policy basis for deletion, which is
what lets "anchoring survives erasure of ordinary payloads elsewhere" hold
for this one entry type even where it does not hold for others. Nothing here
forces that erasure exemption administratively -- domain code cannot -- it
only makes the entry small and business-data-free enough for one to be
argued in the first place.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

HANDOFF_PAYLOAD_TYPE: Final = "application/vnd.waxseal.handoff-binding+json"

_SHA256_HEX: Final = re.compile(r"\A[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class HandoffBinding:
    """A pointer, nothing else: which chain, which sequence, which head hash.

    ``head_hash`` is the origin trail's ordinary ``Entry.entry_hash`` at
    ``seq`` -- not a payload hash, not a checkpoint root. Any reader of the
    origin trail already has this value for free (``AuditLog.entry_hashes()``),
    so verifying a binding needs no new machinery on the origin side.
    """

    chain_id: str
    seq: int
    head_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.chain_id, str) or not self.chain_id:
            raise ValueError("chain_id must be a non-empty string")
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or self.seq < 0:
            raise ValueError("seq must be a non-negative integer")
        if not isinstance(self.head_hash, str) or not _SHA256_HEX.match(self.head_hash):
            raise ValueError("head_hash must be 64 lowercase hex characters (a SHA-256 digest)")


def to_payload(binding: HandoffBinding) -> dict[str, Any]:
    """Plain-JSON dict for ``AuditLog.append`` -- ``canonical_json`` hashes
    this exactly like any other payload (CLAUDE.md: payload schema changes
    never touch the chain)."""
    return {"chain_id": binding.chain_id, "seq": binding.seq, "head_hash": binding.head_hash}


def from_payload(payload: Any) -> HandoffBinding:
    """Parse a handoff-binding payload read back off a trail.

    Raises ``ValueError`` -- and only ``ValueError`` -- on anything malformed,
    matching ``domain.decision.from_payload``'s contract: unparseable is a
    third verdict, distinct from intact and from tampered, and this function
    must not pre-empt the chain check's own answer about those bytes.
    """
    if not isinstance(payload, dict):
        raise ValueError("handoff-binding payload must be a JSON object")
    try:
        chain_id = payload["chain_id"]
        seq = payload["seq"]
        head_hash = payload["head_hash"]
    except KeyError as e:
        raise ValueError(f"handoff-binding payload missing field: {e}") from e
    return HandoffBinding(chain_id=chain_id, seq=seq, head_hash=head_hash)


def binding_holds(binding: HandoffBinding, origin_entry_hashes: Sequence[str]) -> bool:
    """True iff ``origin_entry_hashes`` (the origin trail's CURRENT hashes, in
    write order) still holds, at ``binding.seq``, exactly the hash this
    binding committed to at handoff time.

    Never raises: an out-of-range seq (the origin trail was truncated, or
    never reached that far) is reported as ``False`` -- the pin does not
    hold -- the same fail-closed shape as ``domain.anchoring.verify_membership``
    and ``verify_consistency``, never an exception on attacker-shaped input.

    This is the ORIGIN-side half of transitive anchoring; the DELEGATE-side
    half (that this binding's own entry is really in the anchored batch) is
    an ordinary ``anchoring.verify_membership`` call against the delegate's
    checkpoint -- composed by the caller, not reinvented here.
    """
    if not 0 <= binding.seq < len(origin_entry_hashes):
        return False
    return origin_entry_hashes[binding.seq] == binding.head_hash
