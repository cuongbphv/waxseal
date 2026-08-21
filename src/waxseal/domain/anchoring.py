"""External anchoring: batch roots and membership proofs (RFC 6962 §2.1).

A hash chain by itself cannot resist an adversary who can rewrite the whole
trail file — every ``prev_hash`` downstream of the edit is recomputable
(DESIGN.md threat model). The counter is to publish a single *batch root*
somewhere the log writer cannot reach (a ticket, a signed release, another
host). Once a root is anchored, any entry's presence in that batch is
checkable offline from a handful of sibling hashes, and a rewritten trail can
no longer reproduce the anchored root.

Hashing carries the RFC 6962 0x00/0x01 leaf/node prefixes: without that
domain separation an attacker could smuggle an inner node in as a leaf
built by gluing two child hashes together (the CVE-2012-2459 collision
class).

Proof checking implements RFC 9162 §2.1.3.2 and fails closed: input that is
malformed or out of range yields "not proven", never an exception — crashing
a verifier on attacker-supplied bytes would deny the audit itself, and
"cannot check" must stay distinct from "checked and false" (CLAUDE.md rule 5).

Callers hold ``Entry.entry_hash`` hex strings, so that is the input type; the
hex is decoded first so the tree commits to the 32 hash bytes rather than
their ASCII spelling.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + leaf).digest()


def _pair_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _split_point(n: int) -> int:
    """RFC 6962 split: the largest power of two strictly below n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _tree_hash(leaves: Sequence[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _split_point(n)
    return _pair_hash(_tree_hash(leaves[:k]), _tree_hash(leaves[k:]))


def _audit_path(m: int, leaves: Sequence[bytes]) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = _split_point(len(leaves))
    if m < k:
        return [*_audit_path(m, leaves[:k]), _tree_hash(leaves[k:])]
    return [*_audit_path(m - k, leaves[k:]), _tree_hash(leaves[:k])]


def batch_root(entry_hashes: Sequence[str]) -> str:
    """Root committing to every given entry hash (hex in, hex out).

    Feed it ``[entry.entry_hash for entry in entries]`` and store the result
    out of the writer's reach.
    """
    return _tree_hash([bytes.fromhex(h) for h in entry_hashes]).hex()


def membership_proof(entry_hashes: Sequence[str], index: int) -> tuple[str, ...]:
    """Sibling hashes tying the entry at ``index`` to the batch root
    (RFC 6962 §2.1.1).

    An index outside the batch raises IndexError: the request comes from an
    operator, and quietly proving some other entry would be worse than
    refusing.
    """
    if not 0 <= index < len(entry_hashes):
        raise IndexError(f"index {index} outside batch of size {len(entry_hashes)}")
    leaves = [bytes.fromhex(h) for h in entry_hashes]
    return tuple(h.hex() for h in _audit_path(index, leaves))


def verify_membership(
    entry_hash: str,
    index: int,
    batch_size: int,
    proof: Sequence[str],
    root: str,
) -> bool:
    """Check a membership proof against an anchored root (RFC 9162 §2.1.3.2).

    Returns False on anything that does not check out — bad hex, impossible
    index, wrong length, wrong root. Never raises: see module docstring.
    """
    if index < 0 or batch_size < 1 or index >= batch_size:
        return False
    try:
        node = _leaf_hash(bytes.fromhex(entry_hash))
        siblings = [bytes.fromhex(p) for p in proof]
    except ValueError:
        return False

    fn, sn = index, batch_size - 1
    for sibling in siblings:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            node = _pair_hash(sibling, node)
            if fn % 2 == 0:
                while True:
                    fn //= 2
                    sn //= 2
                    if fn % 2 == 1 or fn == 0:
                        break
        else:
            node = _pair_hash(node, sibling)
        fn //= 2
        sn //= 2
    return sn == 0 and node.hex() == root
