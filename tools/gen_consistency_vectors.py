"""Independent cross-check for RFC 9162 consistency proofs.

Deliberately does NOT import waxseal: it re-implements SUBPROOF (RFC 9162
section 2.1.4.1, "Generating a Consistency Proof") and the verifier (section
2.1.4.2, "Verifying Consistency between Two Tree Heads") straight from the RFC
text, in a clean-room second copy, so it can catch a bug shared between
``domain.anchoring.consistency_proof`` and ``verify_consistency`` that a
round-trip test against itself never would (the two functions could be
wrong in the same way and still "verify" each other).

Run directly to compare against the installed waxseal build:

    uv run python tools/gen_consistency_vectors.py

Exits nonzero and prints the first mismatch if the two implementations ever
disagree, for any (old_size, new_size) pair up to the size checked.
"""

from __future__ import annotations

import hashlib

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + leaf).digest()


def _pair_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _split_point(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _tree_hash(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _split_point(n)
    return _pair_hash(_tree_hash(leaves[:k]), _tree_hash(leaves[k:]))


def batch_root(entry_hashes: list[str]) -> str:
    return _tree_hash([bytes.fromhex(h) for h in entry_hashes]).hex()


def _subproof(m: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    # RFC 9162 section 2.1.4.1:
    #   SUBPROOF(m, D_m, true)  = {}
    #   SUBPROOF(m, D_m, false) = {MTH(D_m)}
    #   SUBPROOF(m, D_n, b), m < n, k = largest power of two < n:
    #     m <= k: SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
    #     m >  k: SUBPROOF(m-k, D[k:n], false) : MTH(D[0:k])
    n = len(leaves)
    if m == n:
        return [] if complete else [_tree_hash(leaves)]
    k = _split_point(n)
    if m <= k:
        return [*_subproof(m, leaves[:k], complete), _tree_hash(leaves[k:])]
    return [*_subproof(m - k, leaves[k:], False), _tree_hash(leaves[:k])]


def consistency_proof(entry_hashes: list[str], old_size: int) -> tuple[str, ...]:
    n = len(entry_hashes)
    if not 1 <= old_size <= n:
        raise IndexError(f"old_size {old_size} outside range [1, {n}]")
    leaves = [bytes.fromhex(h) for h in entry_hashes]
    return tuple(h.hex() for h in _subproof(old_size, leaves, True))


def verify_consistency(
    old_root: str, old_size: int, new_root: str, new_size: int, proof: tuple[str, ...]
) -> bool:
    # RFC 9162 section 2.1.4.2, transcribed field for field from the quoted
    # RFC text (fetched 2026-08-22): prepend first_hash when first_size is a
    # power of two, align fn/sn while LSB(fn) is set, then per remaining
    # proof element either fold both accumulators (LSB(fn) set or fn==sn,
    # with an extra alignment shift when that branch was entered via
    # fn==sn while LSB(fn) was clear) or fold sr alone.
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
    if old_size & (old_size - 1) == 0:
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


def _entry_hashes(n: int) -> list[str]:
    return [hashlib.sha256(f"entry-{i}".encode()).hexdigest() for i in range(n)]


def main() -> None:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from waxseal.domain import anchoring as wx  # imported ONLY here, for comparison

    max_size = 66
    checked = 0
    for new_size in range(1, max_size + 1):
        hashes = _entry_hashes(new_size)
        new_root = batch_root(hashes)
        assert new_root == wx.batch_root(hashes), f"batch_root mismatch at n={new_size}"
        for old_size in range(1, new_size + 1):
            old_root = batch_root(hashes[:old_size])
            mine = consistency_proof(hashes, old_size)
            theirs = wx.consistency_proof(hashes, old_size)
            if mine != theirs:
                print(f"PROOF MISMATCH old={old_size} new={new_size}")
                print(f"  independent: {mine}")
                print(f"  waxseal:     {theirs}")
                sys.exit(1)
            ok_mine = verify_consistency(old_root, old_size, new_root, new_size, mine)
            ok_theirs = wx.verify_consistency(old_root, old_size, new_root, new_size, theirs)
            if not (ok_mine and ok_theirs):
                print(f"VERIFY MISMATCH old={old_size} new={new_size}: "
                      f"independent={ok_mine} waxseal={ok_theirs}")
                sys.exit(1)
            checked += 1
    print(f"OK: {checked} (old_size, new_size) pairs match, sizes 1..{max_size}")


if __name__ == "__main__":
    main()
