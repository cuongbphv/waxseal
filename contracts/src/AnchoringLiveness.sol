// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {CheckpointCodec} from "./CheckpointCodec.sol";
import {Rfc9162} from "./Rfc9162.sol";

/// @title Anchoring Liveness Contract (ALC)
/// @notice Records the latest signed checkpoint per trail and lets anyone ask
///         whether the trail's writer has gone quiet for longer than the
///         deadline it committed to.
///
/// The paper's claim is narrow and this contract does not widen it. The ALC
/// makes SILENCE expensive and PUBLIC. It does not attest that any entry is
/// honest, does not close coverage (a write dropped before it reached the
/// trail leaves no seq gap and no trace here either), does not timestamp
/// individual entries, and does not help at all against a writer whose key is
/// stolen before it signs. It also LEAKS: delta and the submission rate are
/// public, so anchoring cadence and fleet size are readable by anyone.
///
/// Anyone may submit, but only a WRITER-SIGNED head is accepted. That is the
/// paper's "any party may submit" without its obvious failure mode: an
/// unsigned submit path would let a stranger keep a dead trail looking alive
/// by posting invented digests, which is worse than no liveness signal at
/// all, because it is a liveness signal that reads green.
contract AnchoringLiveness {
    struct Head {
        uint64 seq;
        uint64 blockTime;
        bytes32 entryHash;
        bytes32 root;
        bool seen;
    }

    /// @dev Set once at registration and never again. Rotating the writer or
    ///      the deadline from inside the contract would let a delinquent
    ///      trail retroactively redefine what "on time" meant; a new key or a
    ///      new deadline is a new trail id, which is the same append-only
    ///      discipline the fingerprint registry uses.
    mapping(bytes32 => address) public writerOf;
    mapping(bytes32 => uint64) public deadlineOf;

    mapping(bytes32 => Head) private _head;

    event TrailRegistered(bytes32 indexed trailId, address indexed writer, uint64 deadline);
    event HeadAdvanced(
        bytes32 indexed trailId, uint64 seq, bytes32 entryHash, bytes32 root, uint64 blockTime
    );

    error TrailAlreadyRegistered(bytes32 trailId);
    error TrailNotRegistered(bytes32 trailId);
    error ZeroWriter();
    error ZeroDeadline();
    error SeqNotIncreasing(uint64 submitted, uint64 current);
    error BadWriterSignature(address recovered, address expected);
    error NotAnExtension(Rfc9162.Fail reason);

    /// @notice Bind a trail id to its writer key and its anchoring deadline.
    function registerTrail(bytes32 trailId, address writer, uint64 deadline) external {
        if (writerOf[trailId] != address(0)) {
            revert TrailAlreadyRegistered(trailId);
        }
        if (writer == address(0)) {
            revert ZeroWriter();
        }
        // A zero deadline would make every trail delinquent from the block
        // after its first submit, which reads as a permanent alarm and
        // trains operators to ignore the signal.
        if (deadline == 0) {
            revert ZeroDeadline();
        }
        writerOf[trailId] = writer;
        deadlineOf[trailId] = deadline;
        emit TrailRegistered(trailId, writer, deadline);
    }

    /// @notice Record a writer-signed head, strictly ahead of the last one.
    /// @param consistencyProof RFC 9162 proof that the recorded head's tree is
    ///        a prefix of this one. Ignored (and must be empty) for the first
    ///        submit, which has no predecessor to extend.
    /// @dev Three independent gates, none of which subsumes the others:
    ///      strictly increasing seq stops replay of an old signed head;
    ///      the signature stops a stranger inventing a head; and the
    ///      consistency proof stops the WRITER ITSELF from advancing the
    ///      public head onto a tree that does not contain the one it already
    ///      published. Without the third gate a writer could rewrite history
    ///      and keep anchoring, and every check here would still pass.
    function submit(
        bytes32 trailId,
        uint64 seq,
        bytes32 entryHash,
        bytes32 root,
        bytes calldata signature,
        bytes32[] calldata consistencyProof
    ) external {
        address writer = writerOf[trailId];
        if (writer == address(0)) {
            revert TrailNotRegistered(trailId);
        }

        bytes32 digest = CheckpointCodec.signingDigest(trailId, seq, entryHash, root);
        address recovered = CheckpointCodec.recoverSigner(digest, signature);
        if (recovered != writer) {
            revert BadWriterSignature(recovered, writer);
        }

        Head storage head = _head[trailId];
        if (head.seen) {
            if (seq <= head.seq) {
                revert SeqNotIncreasing(seq, head.seq);
            }
            _requireExtends(head.seq, head.root, seq, root, consistencyProof);
        }

        head.seq = seq;
        head.entryHash = entryHash;
        head.root = root;
        head.blockTime = uint64(block.timestamp);
        head.seen = true;
        emit HeadAdvanced(trailId, seq, entryHash, root, uint64(block.timestamp));
    }

    /// @dev Split out of `submit` only because the combined frame ran the
    ///      legacy codegen out of stack slots; `via_ir` would also fix it,
    ///      but a compiler pipeline switch is a bigger change to a contract's
    ///      produced bytecode than moving four arguments.
    ///
    ///      Tree sizes are seq + 1: seq is a zero-based index and the tree is
    ///      over every entry hash up to and including it.
    function _requireExtends(
        uint64 oldSeq,
        bytes32 oldRoot,
        uint64 newSeq,
        bytes32 newRoot,
        bytes32[] calldata consistencyProof
    ) private pure {
        (bool extends, Rfc9162.Fail reason) = Rfc9162.verifyConsistency(
            oldRoot, uint256(oldSeq) + 1, newRoot, uint256(newSeq) + 1, consistencyProof
        );
        if (!extends) {
            revert NotAnExtension(reason);
        }
    }

    /// @notice The last head recorded for `trailId`.
    function lastSeen(bytes32 trailId)
        external
        view
        returns (uint64 seq, bytes32 entryHash, bytes32 root, uint64 blockTime)
    {
        Head storage head = _head[trailId];
        if (!head.seen) {
            revert TrailNotRegistered(trailId);
        }
        return (head.seq, head.entryHash, head.root, head.blockTime);
    }

    /// @notice Whether the trail has gone past its deadline without anchoring.
    /// @dev Reverts for a trail that is unregistered or has never submitted,
    ///      rather than returning false. `bool` is a two-valued type and the
    ///      honest answer here is three-valued: live, delinquent, or nothing
    ///      to judge. A revert is what lets the off-chain reader map the
    ///      third case to `unreachable_or_absent` instead of silently
    ///      reporting a trail that has never anchored as "live" -- which is
    ///      the beads v1.2.2 collapse (an unknown state forced into a binary
    ///      and landing on the reassuring side).
    function isDelinquent(bytes32 trailId) external view returns (bool) {
        if (writerOf[trailId] == address(0)) {
            revert TrailNotRegistered(trailId);
        }
        Head storage head = _head[trailId];
        if (!head.seen) {
            revert TrailNotRegistered(trailId);
        }
        return block.timestamp > uint256(head.blockTime) + uint256(deadlineOf[trailId]);
    }
}
