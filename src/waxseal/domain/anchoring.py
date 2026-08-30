"""External anchoring: batch roots and membership proofs (RFC 6962 §2.1).

A hash chain by itself cannot resist an adversary who can rewrite the whole
trail file, because every ``prev_hash`` downstream of the edit is recomputable
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
malformed or out of range yields "not proven", never an exception, since crashing
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


def _consistency_subproof(m: int, leaves: Sequence[bytes], complete: bool) -> list[bytes]:
    """RFC 9162 §2.1.4.1 SUBPROOF(m, D_n, complete), leaves-in/hashes-out."""
    n = len(leaves)
    if m == n:
        return [] if complete else [_tree_hash(leaves)]
    k = _split_point(n)
    if m <= k:
        return [*_consistency_subproof(m, leaves[:k], complete), _tree_hash(leaves[k:])]
    return [*_consistency_subproof(m - k, leaves[k:], False), _tree_hash(leaves[:k])]


def consistency_proof(entry_hashes: Sequence[str], old_size: int) -> tuple[str, ...]:
    """Sibling hashes proving the tree at ``old_size`` is a prefix of the
    current tree (RFC 9162 §2.1.4.1: PROOF(m, D_n) = SUBPROOF(m, D_n, true)).

    ``old_size`` must be in ``[1, len(entry_hashes)]``: a size-0 "tree" has no
    root to prove consistency with, and a size beyond the current batch does
    not exist yet: out of range raises IndexError rather than proving some
    other size by surprise, matching ``membership_proof``'s contract for
    operator-supplied indices.
    """
    n = len(entry_hashes)
    if not 1 <= old_size <= n:
        raise IndexError(f"old_size {old_size} outside range [1, {n}]")
    leaves = [bytes.fromhex(h) for h in entry_hashes]
    return tuple(h.hex() for h in _consistency_subproof(old_size, leaves, True))


def verify_consistency(
    old_root: str,
    old_size: int,
    new_root: str,
    new_size: int,
    proof: Sequence[str],
) -> bool:
    """Check a consistency proof between two tree sizes (RFC 9162 §2.1.4.2).

    Returns False on anything that does not check out: bad hex, a shrinking
    or non-positive size, a missing/extra/reordered proof hash, or a root
    that does not match. Never raises: see module docstring.
    """
    if old_size < 1 or new_size < old_size:
        return False
    try:
        old_hash = bytes.fromhex(old_root)
        new_hash = bytes.fromhex(new_root)
        path = [bytes.fromhex(p) for p in proof]
    except ValueError:
        return False

    if old_size == new_size:
        return not path and old_hash == new_hash

    if not path:
        return False
    if old_size & (old_size - 1) == 0:  # old_size is an exact power of two
        path = [old_hash, *path]

    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = sr = path[0]
    for sibling in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _pair_hash(sibling, fr)
            sr = _pair_hash(sibling, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _pair_hash(sr, sibling)
        fn >>= 1
        sn >>= 1

    return fr == old_hash and sr == new_hash and sn == 0


def verify_membership(
    entry_hash: str,
    index: int,
    batch_size: int,
    proof: Sequence[str],
    root: str,
) -> bool:
    """Check a membership proof against an anchored root (RFC 9162 §2.1.3.2).

    Returns False on anything that does not check out: bad hex, impossible
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
