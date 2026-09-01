"""Cross-language vectors: the Solidity contracts against the Python domain.

`tools/gen_consistency_vectors.py` answers "does waxseal implement RFC 9162?"
by transcribing the RFC a second time in the same language. This file answers a
different question: "do the on-chain verifier and the off-chain verifier agree
on the same bytes?" A contract that slashes a bond, or an anchor a verifier
trusts, is worth nothing if the two implementations part company on some input
neither author thought about.

Two disciplines make that a real check rather than a ceremonial one.

INTERMEDIATE HASHES, NOT VERDICTS. A vector that recorded only "Python says
true, Solidity says true" would pass even if the two walked different trees to
reach it. Every consistency vector therefore carries the full accumulator trace
-- the `fr` and `sr` values after each fold step -- and `Rfc9162.sol` exposes
`verifyConsistencyTraced` for no other reason than to be compared against it.

NEGATIVES, WITH REASONS. Agreement on well-formed input is the easy half; a
verifier is defined by what it refuses. Roughly half these vectors are proofs
that MUST be rejected -- a flipped bit, a dropped sibling, an extra sibling,
a reordered pair, a forged root, an impossible size -- and each records WHICH
rejection, so the test asserts both sides refused for the same reason and not
merely that both refused. `Rfc9162.Fail` and `_FAIL` below are the same
enumeration in two languages.

The generator is the only place `verify_consistency` gets reimplemented for
instrumentation, so every vector's `expect_ok` is cross-checked against the
SHIPPED `domain.anchoring.verify_consistency` before it is written out. An
instrumented copy that had drifted from the real one would produce agreeing
traces for a function nobody runs.

Run:

    uv run --extra dev python tools/gen_contract_vectors.py            # write
    uv run --extra dev python tools/gen_contract_vectors.py --check    # verify

`--check` regenerates in memory and exits non-zero if the committed vectors
differ, which is what CI runs: a change to the Python encoding that would move
a hash turns the build red instead of silently re-freezing the vectors
(CLAUDE.md rule 3 -- a frozen-hash failure means STOP, not "update the file").
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "src"))
sys.path.insert(0, str(_REPO / "tools"))

import gen_consistency_vectors as rfc  # noqa: E402  clean-room RFC transcription

from waxseal.domain import anchoring as wx  # noqa: E402
from waxseal.domain.checkpoint import Checkpoint, checkpoint_frame  # noqa: E402
from waxseal.domain.fingerprint import (  # noqa: E402
    ALGORITHM,
    DESCRIPTOR_PREFIX,
    HEADER_FIELDS,
    fingerprint_for,
)
from waxseal.domain.hashing import ENCODING, lp  # noqa: E402

VECTOR_DIR = _REPO / "contracts" / "vectors"

# Mirrors `Rfc9162.Fail` member for member. The contract's enum and this dict
# are one enumeration in two languages; a vector carries the member and both
# sides must name the same one.
_FAIL = {
    "none": 0,
    "size_range": 1,
    "equal_size_mismatch": 2,
    "empty_proof": 3,
    "proof_too_long": 4,
    "old_root_mismatch": 5,
    "new_root_mismatch": 6,
    "proof_too_short": 7,
}
_FAIL_NAME = {v: k for k, v in _FAIL.items()}

# The signing domain separator, duplicated in CheckpointCodec.sol. Not imported
# from waxseal: at the time this lands, `domain/bond.py` (workstream F1) may not
# have chosen it yet, and a generator that imported a constant that does not
# exist would fail for a reason unrelated to what it checks. The vectors are the
# contract between the two -- if F1 picks different bytes, these vectors go red,
# which is the intended way to discover the disagreement.
SIGNING_PREFIX = b"waxseal-checkpoint-sig-v1\n"


def _hex(value: bytes) -> str:
    return "0x" + value.hex()


def signing_digest(trail_id: bytes, checkpoint: Checkpoint) -> bytes:
    """The 32 bytes a trail writer signs for one checkpoint.

    A domain-separated SHA-256 over the checkpoint frame with the trail id
    bound in. Both fields are 64-character hex spellings so the frame uses
    `domain.hashing.lp` unmodified -- the on-chain side has to reproduce this
    byte for byte, and an encoder with only one arm to implement is an encoder
    with fewer ways to disagree.

    Not an EIP-191 or EIP-712 envelope: these bytes must be producible by a
    Python verifier whose only crypto is hashlib.
    """
    frame_hash = hashlib.sha256(checkpoint_frame(checkpoint)).digest()
    return hashlib.sha256(
        SIGNING_PREFIX + struct.pack(">Q", 2) + lp(trail_id.hex()) + lp(frame_hash.hex())
    ).digest()


def descriptor_frame(fields: tuple[str, ...]) -> bytes:
    """The bytes `FingerprintRegistry.register` is handed.

    Rebuilt here rather than imported because `domain/fingerprint.py` exposes
    only the finished digest. The reconstruction is checked against
    `fingerprint_for` below, so a drift in the frozen descriptor form fails
    here instead of producing a registry vector for bytes waxseal would never
    submit.
    """
    components = (ALGORITHM, ENCODING, *fields)
    frame = DESCRIPTOR_PREFIX + struct.pack(">Q", len(components))
    for component in components:
        encoded = component.encode("utf-8")
        frame += struct.pack(">Q", len(encoded)) + encoded
    return frame


def verify_consistency_traced(
    old_root: bytes,
    old_size: int,
    new_root: bytes,
    new_size: int,
    proof: list[bytes],
) -> tuple[bool, int, list[bytes], list[bytes]]:
    """`domain.anchoring.verify_consistency`, instrumented.

    Statement for statement the same walk, with the accumulators recorded and
    the rejection reason named. Every caller cross-checks the boolean against
    the shipped function; this copy exists to see INSIDE the walk, not to
    replace it.
    """
    if old_size < 1 or new_size < old_size:
        return False, _FAIL["size_range"], [], []
    if old_size == new_size:
        if not proof and old_root == new_root:
            return True, _FAIL["none"], [], []
        return False, _FAIL["equal_size_mismatch"], [], []
    if not proof:
        return False, _FAIL["empty_proof"], [], []

    path = list(proof)
    if old_size & (old_size - 1) == 0:
        path = [old_root, *path]

    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = sr = path[0]
    fr_trace = [fr]
    sr_trace = [sr]
    for sibling in path[1:]:
        if sn == 0:
            return False, _FAIL["proof_too_long"], fr_trace, sr_trace
        if fn & 1 or fn == sn:
            fr = wx._pair_hash(sibling, fr)
            sr = wx._pair_hash(sibling, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = wx._pair_hash(sr, sibling)
        fn >>= 1
        sn >>= 1
        fr_trace.append(fr)
        sr_trace.append(sr)

    if fr != old_root:
        return False, _FAIL["old_root_mismatch"], fr_trace, sr_trace
    if sr != new_root:
        return False, _FAIL["new_root_mismatch"], fr_trace, sr_trace
    if sn != 0:
        return False, _FAIL["proof_too_short"], fr_trace, sr_trace
    return True, _FAIL["none"], fr_trace, sr_trace


def entry_hashes(n: int) -> list[str]:
    """Deterministic stand-in entry hashes, stable across runs and machines."""
    return [hashlib.sha256(f"waxseal-contract-vector-{i}".encode()).hexdigest() for i in range(n)]


def _consistency_case(
    name: str,
    old_root: str,
    old_size: int,
    new_root: str,
    new_size: int,
    proof: list[str],
) -> dict[str, Any]:
    """One vector, with its verdict taken from BOTH Python implementations."""
    old_b = bytes.fromhex(old_root)
    new_b = bytes.fromhex(new_root)
    proof_b = [bytes.fromhex(p) for p in proof]
    ok, fail, fr_trace, sr_trace = verify_consistency_traced(
        old_b, old_size, new_b, new_size, proof_b
    )
    shipped = wx.verify_consistency(old_root, old_size, new_root, new_size, proof)
    if shipped != ok:
        raise AssertionError(
            f"{name}: instrumented verifier says {ok}, "
            f"domain.anchoring.verify_consistency says {shipped}"
        )
    clean = rfc.verify_consistency(old_root, old_size, new_root, new_size, tuple(proof))
    if clean != ok:
        raise AssertionError(
            f"{name}: instrumented verifier says {ok}, clean-room RFC transcription says {clean}"
        )
    return {
        "name": name,
        "oldRoot": "0x" + old_root,
        "oldSize": old_size,
        "newRoot": "0x" + new_root,
        "newSize": new_size,
        "proof": ["0x" + p for p in proof],
        "expectOk": ok,
        "expectFail": fail,
        "expectFailName": _FAIL_NAME[fail],
        "frTrace": [_hex(h) for h in fr_trace],
        "srTrace": [_hex(h) for h in sr_trace],
    }


def _flip_first_byte(value: str) -> str:
    raw = bytearray.fromhex(value)
    raw[0] ^= 0x01
    return raw.hex()


def build_tree_vectors() -> list[dict[str, Any]]:
    """Roots the Solidity `treeHash` must reproduce.

    Python recurses on the RFC split point; the contract folds bottom-up,
    promoting an odd node. The two are the same tree, but "are the same" is a
    claim, and sizes 1..9 plus each side of a power-of-two boundary are where a
    wrong promotion rule shows up.
    """
    vectors = []
    for n in [*range(1, 10), 15, 16, 17, 31, 32, 33]:
        hashes = entry_hashes(n)
        root = wx.batch_root(hashes)
        if root != rfc.batch_root(hashes):
            raise AssertionError(f"batch_root disagreement at n={n}")
        vectors.append(
            {
                "name": f"tree_n{n}",
                "leaves": ["0x" + h for h in hashes],
                "root": "0x" + root,
            }
        )
    return vectors


def build_consistency_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []

    # Positives: every (old_size, new_size) pair up to 9, plus a few larger
    # trees. Small sizes are where the power-of-two prepend and the alignment
    # loop switch behaviour; large ones are where an off-by-one in the walk
    # would still find a plausible-looking root.
    for new_size in [*range(1, 10), 16, 17, 31, 32, 33]:
        hashes = entry_hashes(new_size)
        new_root = wx.batch_root(hashes)
        for old_size in range(1, new_size + 1):
            old_root = wx.batch_root(hashes[:old_size])
            proof = list(wx.consistency_proof(hashes, old_size))
            if tuple(proof) != rfc.consistency_proof(hashes, old_size):
                raise AssertionError(f"proof disagreement old={old_size} new={new_size}")
            case = _consistency_case(
                f"ok_{old_size}_of_{new_size}", old_root, old_size, new_root, new_size, proof
            )
            if not case["expectOk"]:
                raise AssertionError(f"honest proof rejected: {case['name']}")
            vectors.append(case)

    # Negatives. Each is derived from one honest proof by exactly one change,
    # so the reason it is rejected is attributable to that change.
    base_n = 8
    hashes = entry_hashes(base_n)
    new_root = wx.batch_root(hashes)

    for old_size in (3, 5, 6, 7):
        honest = list(wx.consistency_proof(hashes, old_size))
        old_root = wx.batch_root(hashes[:old_size])
        tag = f"{old_size}_of_{base_n}"

        mutated = [*honest]
        mutated[0] = _flip_first_byte(mutated[0])
        vectors.append(
            _consistency_case(
                f"bad_flipped_first_sibling_{tag}", old_root, old_size, new_root, base_n, mutated
            )
        )

        mutated = [*honest]
        mutated[-1] = _flip_first_byte(mutated[-1])
        vectors.append(
            _consistency_case(
                f"bad_flipped_last_sibling_{tag}", old_root, old_size, new_root, base_n, mutated
            )
        )

        vectors.append(
            _consistency_case(
                f"bad_dropped_sibling_{tag}", old_root, old_size, new_root, base_n, honest[:-1]
            )
        )

        vectors.append(
            _consistency_case(
                f"bad_extra_sibling_{tag}",
                old_root,
                old_size,
                new_root,
                base_n,
                [*honest, honest[-1]],
            )
        )

        if len(honest) >= 2:
            swapped = [honest[1], honest[0], *honest[2:]]
            vectors.append(
                _consistency_case(
                    f"bad_reordered_siblings_{tag}",
                    old_root,
                    old_size,
                    new_root,
                    base_n,
                    swapped,
                )
            )

        vectors.append(
            _consistency_case(
                f"bad_forged_old_root_{tag}",
                _flip_first_byte(old_root),
                old_size,
                new_root,
                base_n,
                honest,
            )
        )

        vectors.append(
            _consistency_case(
                f"bad_forged_new_root_{tag}",
                old_root,
                old_size,
                _flip_first_byte(new_root),
                base_n,
                honest,
            )
        )

        # A proof for one prefix presented as a proof for a different one: the
        # split-view move, and the one an attacker actually has material for.
        other = 4 if old_size != 4 else 2
        vectors.append(
            _consistency_case(
                f"bad_proof_for_other_size_{tag}",
                old_root,
                old_size,
                new_root,
                base_n,
                list(wx.consistency_proof(hashes, other)),
            )
        )

    # Structural rejections that never reach the walk at all.
    honest_3 = list(wx.consistency_proof(hashes, 3))
    root_3 = wx.batch_root(hashes[:3])
    vectors.append(
        _consistency_case("bad_zero_old_size", root_3, 0, new_root, base_n, honest_3)
    )
    vectors.append(
        _consistency_case("bad_shrinking_tree", new_root, base_n, root_3, 3, honest_3)
    )
    vectors.append(_consistency_case("bad_empty_proof", root_3, 3, new_root, base_n, []))
    vectors.append(
        _consistency_case("bad_equal_size_with_proof", root_3, 3, root_3, 3, honest_3)
    )
    vectors.append(
        _consistency_case(
            "bad_equal_size_root_mismatch", root_3, 3, _flip_first_byte(root_3), 3, []
        )
    )
    vectors.append(_consistency_case("ok_equal_size_no_proof", root_3, 3, root_3, 3, []))

    # The truncated-but-still-folding proof. Every other negative above is
    # caught by a root mismatch, which leaves `proof_too_short` -- the branch
    # that checks the walk actually CONSUMED the new tree -- unreached by any
    # naturally derived vector, because reaching it while both roots still
    # match would take a SHA-256 collision. So it is constructed backwards
    # instead: pick the old root and the single sibling, then define the new
    # root as what the walk produces, and claim a tree size the walk never
    # reaches. Both roots check out and `sn` is still 1. An implementation
    # that dropped the final `sn == 0` test -- an easy line to lose, since it
    # looks redundant next to two root comparisons -- would accept this and
    # call a five-leaf tree consistent on the evidence of a three-leaf walk.
    seed = hashlib.sha256(b"waxseal-short-proof-seed").digest()
    sibling = hashlib.sha256(b"waxseal-short-proof-sibling").digest()
    vectors.append(
        _consistency_case(
            "bad_truncated_proof_folding_to_both_roots",
            seed.hex(),
            2,
            wx._pair_hash(seed, sibling).hex(),
            5,
            [sibling.hex()],
        )
    )

    return vectors


def build_inclusion_vectors() -> list[dict[str, Any]]:
    """Inclusion proofs, which is what `proveNonExtension` slashes on.

    The negatives matter more here than anywhere else in this file: a bond is
    taken on the strength of two of these, so a proof the contract accepts and
    Python rejects is a free slash of an honest writer.
    """
    vectors: list[dict[str, Any]] = []
    for batch_size in (1, 2, 3, 5, 8, 9):
        hashes = entry_hashes(batch_size)
        root = wx.batch_root(hashes)
        for index in range(batch_size):
            proof = list(wx.membership_proof(hashes, index))
            ok = wx.verify_membership(hashes[index], index, batch_size, proof, root)
            if not ok:
                raise AssertionError(f"honest inclusion proof rejected at {index}/{batch_size}")
            vectors.append(
                {
                    "name": f"ok_{index}_of_{batch_size}",
                    "entryHash": "0x" + hashes[index],
                    "index": index,
                    "batchSize": batch_size,
                    "proof": ["0x" + p for p in proof],
                    "root": "0x" + root,
                    "expectOk": True,
                }
            )

    hashes = entry_hashes(8)
    root = wx.batch_root(hashes)
    honest = list(wx.membership_proof(hashes, 3))

    def negative(name: str, entry: str, index: int, size: int, proof: list[str], r: str) -> None:
        ok = wx.verify_membership(entry, index, size, proof, r)
        if ok:
            raise AssertionError(f"{name}: expected rejection, Python accepted")
        vectors.append(
            {
                "name": name,
                "entryHash": "0x" + entry,
                "index": index,
                "batchSize": size,
                "proof": ["0x" + p for p in proof],
                "root": "0x" + r,
                "expectOk": False,
            }
        )

    negative("bad_wrong_leaf", _flip_first_byte(hashes[3]), 3, 8, honest, root)
    negative("bad_wrong_index", hashes[3], 4, 8, honest, root)
    flipped = [_flip_first_byte(honest[0]), *honest[1:]]
    negative("bad_flipped_sibling", hashes[3], 3, 8, flipped, root)
    negative("bad_dropped_sibling", hashes[3], 3, 8, honest[:-1], root)
    negative("bad_extra_sibling", hashes[3], 3, 8, [*honest, honest[0]], root)
    negative("bad_reordered_siblings", hashes[3], 3, 8, [honest[1], honest[0], honest[2]], root)
    negative("bad_forged_root", hashes[3], 3, 8, honest, _flip_first_byte(root))
    negative("bad_index_outside_batch", hashes[3], 8, 8, honest, root)
    # A leaf hash offered where a raw entry hash belongs: the CVE-2012-2459
    # move the 0x00/0x01 prefixes exist to block. It must fail, and it must
    # fail on BOTH sides -- a contract that omitted the leaf prefix would
    # accept this one.
    negative(
        "bad_inner_node_as_leaf",
        hashlib.sha256(b"\x00" + bytes.fromhex(hashes[3])).hexdigest(),
        3,
        8,
        honest,
        root,
    )
    return vectors


def build_checkpoint_vectors() -> list[dict[str, Any]]:
    """Frame bytes, frame hash and signing digest, for `CheckpointCodec.sol`.

    `seq` is spelled in decimal and the two hashes in lowercase hex INSIDE the
    frame, so the contract has to reproduce both spellings. The seq values
    below straddle every digit-count boundary a naive decimal writer gets
    wrong.
    """
    vectors = []
    hashes = entry_hashes(40)
    for seq in (0, 1, 9, 10, 39):
        checkpoint = Checkpoint(
            seq=seq, entry_hash=hashes[seq], root=wx.batch_root(hashes[: seq + 1])
        )
        frame = checkpoint_frame(checkpoint)
        frame_hash = hashlib.sha256(frame).digest()
        trail_id = hashlib.sha256(f"trail-{seq}".encode()).digest()
        vectors.append(
            {
                "name": f"checkpoint_seq{seq}",
                "trailId": _hex(trail_id),
                "seq": seq,
                "entryHash": "0x" + checkpoint.entry_hash,
                "root": "0x" + checkpoint.root,
                "frame": _hex(frame),
                "frameHash": _hex(frame_hash),
                "signingDigest": _hex(signing_digest(trail_id, checkpoint)),
            }
        )
    return vectors


def build_fingerprint_vectors() -> list[dict[str, Any]]:
    """Descriptor bytes and the fingerprint the registry computes from them.

    The registry's whole guarantee is that `fp = sha256(descriptor)` is
    computed ON CHAIN, so these vectors are what proves the on-chain digest is
    the same identity `domain/fingerprint.py` produces off chain. The widened
    field set is the "migration 060" shape: one extra field, and the identity
    must MOVE.
    """
    vectors = []
    widened = (*HEADER_FIELDS, "actor")
    for name, fields in (("header_fields", HEADER_FIELDS), ("widened_fields", widened)):
        frame = descriptor_frame(fields)
        expected = fingerprint_for(fields)
        if hashlib.sha256(frame).hexdigest() != expected:
            raise AssertionError(f"{name}: rebuilt descriptor frame does not match fingerprint_for")
        vectors.append(
            {
                "name": name,
                "fields": list(fields),
                "descriptor": _hex(frame),
                "fingerprint": "0x" + expected,
            }
        )
    if vectors[0]["fingerprint"] == vectors[1]["fingerprint"]:
        raise AssertionError("widening the field set did not move the fingerprint")
    return vectors


def build_head_vectors() -> list[dict[str, Any]]:
    """A trail's successive anchored heads, each with the proof it extends the last.

    `AnchoringLiveness.submit` requires a consistency proof against the head it
    already holds. That gate is why these exist: strictly increasing seq stops
    replay and the signature stops a stranger, but neither stops the WRITER
    from advancing the public head onto a tree that does not contain the one it
    already published. Only the proof does.
    """
    hashes = entry_hashes(12)
    vectors = []
    prev: int | None = None
    for seq in (0, 2, 5, 8, 11):
        proof: list[str] = []
        if prev is not None:
            proof = list(wx.consistency_proof(hashes[: seq + 1], prev + 1))
            if not wx.verify_consistency(
                wx.batch_root(hashes[: prev + 1]),
                prev + 1,
                wx.batch_root(hashes[: seq + 1]),
                seq + 1,
                proof,
            ):
                raise AssertionError(f"honest head proof {prev}->{seq} does not verify")
        vectors.append(
            {
                "name": f"head_seq{seq}",
                "seq": seq,
                "entryHash": "0x" + hashes[seq],
                "root": "0x" + wx.batch_root(hashes[: seq + 1]),
                "proofFromPrev": ["0x" + h for h in proof],
            }
        )
        prev = seq
    return vectors


def _forked_hashes() -> list[str]:
    """The same trail with entry 1 rewritten.

    Index 1 and not a later one on purpose: the fork has to fall BEFORE the
    earlier anchored head for the earlier head to stop being a prefix. A
    rewrite after the anchored head leaves that head a perfectly good prefix,
    which is the mistake that makes a non-extension test pass vacuously.
    """
    hashes = entry_hashes(12)
    hashes[1] = hashlib.sha256(b"waxseal-contract-vector-1-REWRITTEN").hexdigest()
    return hashes


def build_fork_vectors() -> list[dict[str, Any]]:
    """A head on a rewritten trail, and the best proof its writer could offer.

    The proof is generated honestly over the FORKED tree, so it is not
    malformed and not random -- it is exactly what a writer that had quietly
    rewritten history would compute and submit. It must still be rejected,
    because the old root it folds to is the forked trail's, not the one the
    contract recorded.
    """
    honest = entry_hashes(12)
    forked = _forked_hashes()
    old_seq, new_seq = 2, 8
    proof = list(wx.consistency_proof(forked[: new_seq + 1], old_seq + 1))
    if wx.verify_consistency(
        wx.batch_root(honest[: old_seq + 1]),
        old_seq + 1,
        wx.batch_root(forked[: new_seq + 1]),
        new_seq + 1,
        proof,
    ):
        raise AssertionError("a rewritten trail verified as an extension of the honest one")
    return [
        {
            "name": "forked_head",
            "oldSeq": old_seq,
            "oldRoot": "0x" + wx.batch_root(honest[: old_seq + 1]),
            "seq": new_seq,
            "entryHash": "0x" + forked[new_seq],
            "root": "0x" + wx.batch_root(forked[: new_seq + 1]),
            "proofFromPrev": ["0x" + h for h in proof],
        }
    ]


def build_nonextension_vectors() -> list[dict[str, Any]]:
    """The divergent leaf that positively proves a non-extension.

    One index, two inclusion proofs, each valid against its own signed root,
    carrying different entry hashes. A prefix cannot disagree with its
    extension about a leaf they both contain, so this evidence cannot be
    manufactured against an honest writer -- which is why the bond contract
    slashes on THIS and not on a consistency proof that merely failed to
    verify. A failing proof shows only that the prover did not supply a working
    one; absence of evidence would be a free slash of anyone.
    """
    honest = entry_hashes(12)
    forked = _forked_hashes()
    older_seq, newer_seq = 2, 8
    index = 1
    older_proof = list(wx.membership_proof(honest[: older_seq + 1], index))
    newer_proof = list(wx.membership_proof(forked[: newer_seq + 1], index))
    older_root = wx.batch_root(honest[: older_seq + 1])
    newer_root = wx.batch_root(forked[: newer_seq + 1])
    if not wx.verify_membership(honest[index], index, older_seq + 1, older_proof, older_root):
        raise AssertionError("older inclusion proof does not verify")
    if not wx.verify_membership(forked[index], index, newer_seq + 1, newer_proof, newer_root):
        raise AssertionError("newer inclusion proof does not verify")
    if honest[index] == forked[index]:
        raise AssertionError("the two trails agree at the divergent index")
    return [
        {
            "name": "divergent_leaf",
            "index": index,
            "olderSeq": older_seq,
            "olderEntryHash": "0x" + honest[older_seq],
            "olderRoot": "0x" + older_root,
            "olderLeaf": "0x" + honest[index],
            "olderProof": ["0x" + h for h in older_proof],
            "newerSeq": newer_seq,
            "newerEntryHash": "0x" + forked[newer_seq],
            "newerRoot": "0x" + newer_root,
            "newerLeaf": "0x" + forked[index],
            "newerProof": ["0x" + h for h in newer_proof],
        }
    ]


def build_all() -> dict[str, list[dict[str, Any]]]:
    return {
        "tree": build_tree_vectors(),
        "consistency": build_consistency_vectors(),
        "inclusion": build_inclusion_vectors(),
        "checkpoint": build_checkpoint_vectors(),
        "fingerprint": build_fingerprint_vectors(),
        "heads": build_head_vectors(),
        "fork": build_fork_vectors(),
        "nonextension": build_nonextension_vectors(),
    }


def _render(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


# Each cheatcode call hands the WHOLE json string to the cheatcode address as
# calldata, and EVM memory is never reclaimed inside a call frame. One 280 KB
# file parsed a few hundred times is hundreds of megabytes of memory and an
# immediate MemoryOOG. Chunking keeps each parsed string small; the chunk size
# is a memory budget, nothing more, and does not affect which vectors exist.
CHUNK_SIZE = 16


def _layout(groups: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        name: {
            "count": len(vectors),
            "chunks": (len(vectors) + CHUNK_SIZE - 1) // CHUNK_SIZE,
            "chunkSize": CHUNK_SIZE,
        }
        for name, vectors in groups.items()
    }


def _files(groups: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    out = {"index.json": _render(_layout(groups))}
    for name, vectors in groups.items():
        for chunk in range((len(vectors) + CHUNK_SIZE - 1) // CHUNK_SIZE):
            slice_ = vectors[chunk * CHUNK_SIZE : (chunk + 1) * CHUNK_SIZE]
            out[f"{name}-{chunk:03d}.json"] = _render(slice_)
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv[1:]
    groups = build_all()
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    files = _files(groups)
    drift = []

    stale = {p.name for p in VECTOR_DIR.glob("*.json")} - set(files)
    for name in sorted(stale):
        if check:
            drift.append(f"contracts/vectors/{name}: present but no longer generated")
        else:
            (VECTOR_DIR / name).unlink()

    for filename, rendered in files.items():
        path = VECTOR_DIR / filename
        if check:
            if not path.exists():
                drift.append(f"{path.relative_to(_REPO)}: missing")
            elif path.read_text(encoding="utf-8") != rendered:
                drift.append(f"{path.relative_to(_REPO)}: differs from regenerated vectors")
        else:
            path.write_text(rendered, encoding="utf-8")

    for name, vectors in groups.items():
        verb = "checked" if check else "wrote"
        chunks = (len(vectors) + CHUNK_SIZE - 1) // CHUNK_SIZE
        print(f"{verb} {name}: {len(vectors)} vectors in {chunks} chunk file(s)")

    positives = sum(1 for v in groups["consistency"] if v["expectOk"])
    negatives = len(groups["consistency"]) - positives
    print(f"consistency: {positives} accepted, {negatives} rejected")
    reasons = sorted({v["expectFailName"] for v in groups["consistency"] if not v["expectOk"]})
    print(f"rejection reasons exercised: {', '.join(reasons)}")

    if drift:
        print("VECTOR DRIFT — the committed vectors no longer match the Python side:")
        for line in drift:
            print(f"  {line}")
        print("This is a frozen-hash failure. STOP and find out what moved (CLAUDE.md rule 3).")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
