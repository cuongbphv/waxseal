// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title RFC 9162 Merkle verification, byte-for-byte with waxseal's Python
/// @notice A second implementation of `src/waxseal/domain/anchoring.py`, in a
///         second language, checked against the first by generated cross
///         vectors (`tools/gen_contract_vectors.py` -> `test/Vectors.g.sol`).
///
/// Why sha256 and not keccak256: SPEC.md section 10 fixes the tree on SHA-256
/// with RFC 6962 domain separation, and that choice is already inside issued
/// RFC 3161 receipts and frozen golden vectors. The EVM has a SHA-256
/// precompile (0x02), so agreement costs gas, not correctness. Reaching for
/// keccak256 here because it is the cheaper EVM-native hash would fork the
/// tree from every root waxseal has ever published.
///
/// The 0x00 leaf / 0x01 node prefixes are not decoration: without them an
/// inner node can be smuggled in as a leaf by gluing two child hashes
/// together (CVE-2012-2459).
///
/// Both verifiers FAIL CLOSED and never revert on proof content. A verifier
/// that an attacker can revert is a verifier an attacker can silence, and
/// "cannot check" must stay distinct from "checked and false" (CLAUDE.md rule
/// 5) -- which is what `Fail` carries: every rejection names WHY, and the
/// cross vectors assert Python and Solidity reject for the SAME reason, not
/// merely that both said no.
library Rfc9162 {
    /// @dev Rejection reasons. Mirrored value-for-value by `_FAIL_*` in
    ///      tools/gen_contract_vectors.py; a vector carries the expected
    ///      member and both sides must agree on it.
    enum Fail {
        None, //               0: verified
        SizeRange, //          1: oldSize == 0, or newSize < oldSize
        EqualSizeMismatch, //  2: oldSize == newSize with a proof, or roots differ
        EmptyProof, //         3: a proof was required and none was supplied
        ProofTooLong, //       4: sn exhausted with proof elements left over
        OldRootMismatch, //    5: folded prefix root != the claimed old root
        NewRootMismatch, //    6: folded current root != the claimed new root
        ProofTooShort //       7: proof ran out before sn was exhausted
    }

    bytes1 internal constant LEAF_PREFIX = 0x00;
    bytes1 internal constant NODE_PREFIX = 0x01;

    function leafHash(bytes32 leaf) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(LEAF_PREFIX, leaf));
    }

    function pairHash(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(NODE_PREFIX, left, right));
    }

    /// @notice Largest power of two strictly below `n` (RFC 6962 split point).
    function splitPoint(uint256 n) internal pure returns (uint256 k) {
        k = 1;
        while (k * 2 < n) {
            k *= 2;
        }
    }

    /// @notice Merkle tree head over `leaves` (RFC 6962 section 2.1).
    /// @dev Iterative, not recursive: `_tree_hash` in Python recurses, and an
    ///      EVM stack is not a Python stack. The shape of the tree is fixed by
    ///      the split point, so the levels can be folded bottom-up instead,
    ///      producing identical hashes -- which the cross vectors check
    ///      against Python's recursive result rather than assuming.
    function treeHash(bytes32[] memory leaves) internal pure returns (bytes32) {
        uint256 n = leaves.length;
        if (n == 0) {
            return sha256("");
        }
        bytes32[] memory level = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            level[i] = leafHash(leaves[i]);
        }
        while (n > 1) {
            uint256 out = 0;
            for (uint256 i = 0; i < n; i += 2) {
                if (i + 1 < n) {
                    level[out] = pairHash(level[i], level[i + 1]);
                } else {
                    // An odd node is promoted, not paired with itself: RFC 6962
                    // splits at the largest power of two below n, which is
                    // exactly this bottom-up promotion.
                    level[out] = level[i];
                }
                out++;
            }
            n = out;
        }
        return level[0];
    }

    /// @notice RFC 9162 section 2.1.4.2, transcribed against
    ///         `domain/anchoring.py::verify_consistency` statement for
    ///         statement.
    /// @return ok true iff the tree at `oldSize` is a prefix of the tree at
    ///         `newSize`
    /// @return reason why not, when `ok` is false
    function verifyConsistency(
        bytes32 oldRoot,
        uint256 oldSize,
        bytes32 newRoot,
        uint256 newSize,
        bytes32[] memory proof
    ) internal pure returns (bool ok, Fail reason) {
        (ok, reason,,) = verifyConsistencyTraced(oldRoot, oldSize, newRoot, newSize, proof);
    }

    /// @notice `verifyConsistency` plus the intermediate accumulator values.
    /// @dev The trace exists for one reason: a cross-vector test that only
    ///      checks "Python said true and Solidity said true" would pass even
    ///      if the two walked different trees to get there. `frTrace[i]` and
    ///      `srTrace[i]` are the two accumulators after fold step `i`, index 0
    ///      being their common seed. The generator emits the same sequence
    ///      from Python and the test compares element by element.
    function verifyConsistencyTraced(
        bytes32 oldRoot,
        uint256 oldSize,
        bytes32 newRoot,
        uint256 newSize,
        bytes32[] memory proof
    )
        internal
        pure
        returns (bool ok, Fail reason, bytes32[] memory frTrace, bytes32[] memory srTrace)
    {
        bytes32[] memory emptyTrace = new bytes32[](0);
        if (oldSize < 1 || newSize < oldSize) {
            return (false, Fail.SizeRange, emptyTrace, emptyTrace);
        }
        if (oldSize == newSize) {
            if (proof.length == 0 && oldRoot == newRoot) {
                return (true, Fail.None, emptyTrace, emptyTrace);
            }
            return (false, Fail.EqualSizeMismatch, emptyTrace, emptyTrace);
        }
        if (proof.length == 0) {
            return (false, Fail.EmptyProof, emptyTrace, emptyTrace);
        }

        bytes32[] memory path = proof;
        if (oldSize & (oldSize - 1) == 0) {
            // An exact power of two has no recorded prefix root in the proof:
            // the claimed old root IS that node. Prepending it is what makes
            // a forged old root fail at the `fr == oldRoot` check rather than
            // silently verifying.
            path = new bytes32[](proof.length + 1);
            path[0] = oldRoot;
            for (uint256 i = 0; i < proof.length; i++) {
                path[i + 1] = proof[i];
            }
        }

        uint256 fn = oldSize - 1;
        uint256 sn = newSize - 1;
        while (fn & 1 == 1) {
            fn >>= 1;
            sn >>= 1;
        }

        frTrace = new bytes32[](path.length);
        srTrace = new bytes32[](path.length);
        bytes32 fr = path[0];
        bytes32 sr = path[0];
        frTrace[0] = fr;
        srTrace[0] = sr;
        uint256 steps = 1;

        for (uint256 i = 1; i < path.length; i++) {
            if (sn == 0) {
                return
                    (false, Fail.ProofTooLong, _truncate(frTrace, steps), _truncate(srTrace, steps));
            }
            if (fn & 1 == 1 || fn == sn) {
                fr = pairHash(path[i], fr);
                sr = pairHash(path[i], sr);
                while (fn & 1 == 0 && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            } else {
                sr = pairHash(sr, path[i]);
            }
            fn >>= 1;
            sn >>= 1;
            frTrace[steps] = fr;
            srTrace[steps] = sr;
            steps++;
        }

        frTrace = _truncate(frTrace, steps);
        srTrace = _truncate(srTrace, steps);
        if (fr != oldRoot) {
            return (false, Fail.OldRootMismatch, frTrace, srTrace);
        }
        if (sr != newRoot) {
            return (false, Fail.NewRootMismatch, frTrace, srTrace);
        }
        if (sn != 0) {
            return (false, Fail.ProofTooShort, frTrace, srTrace);
        }
        return (true, Fail.None, frTrace, srTrace);
    }

    /// @notice RFC 9162 section 2.1.3.2 inclusion check, matching
    ///         `domain/anchoring.py::verify_membership`.
    /// @dev Takes the raw entry hash, not its leaf hash: the leaf prefix is
    ///      applied here so a caller cannot pass an inner node in as a leaf.
    function verifyInclusion(
        bytes32 entryHash,
        uint256 index,
        uint256 batchSize,
        bytes32[] memory proof,
        bytes32 root
    ) internal pure returns (bool) {
        if (batchSize < 1 || index >= batchSize) {
            return false;
        }
        bytes32 node = leafHash(entryHash);
        uint256 fn = index;
        uint256 sn = batchSize - 1;
        for (uint256 i = 0; i < proof.length; i++) {
            if (sn == 0) {
                return false;
            }
            if (fn % 2 == 1 || fn == sn) {
                node = pairHash(proof[i], node);
                if (fn % 2 == 0) {
                    while (true) {
                        fn /= 2;
                        sn /= 2;
                        if (fn % 2 == 1 || fn == 0) {
                            break;
                        }
                    }
                }
            } else {
                node = pairHash(node, proof[i]);
            }
            fn /= 2;
            sn /= 2;
        }
        return sn == 0 && node == root;
    }

    function _truncate(bytes32[] memory arr, uint256 n)
        private
        pure
        returns (bytes32[] memory out)
    {
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = arr[i];
        }
    }
}
