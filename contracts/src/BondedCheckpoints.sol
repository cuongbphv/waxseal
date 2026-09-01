// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {CheckpointCodec} from "./CheckpointCodec.sol";
import {Rfc9162} from "./Rfc9162.sol";

/// @title Bonded equivocation contract
/// @notice A trail writer posts a bond. Anyone who can exhibit the writer's
///         own two signatures over irreconcilable claims takes half of it.
///
/// Scope, stated before the mechanism, because this is the contract most
/// likely to be over-read: a bond makes equivocation EXPENSIVE once it is
/// caught. It does not make it impossible, does not detect a writer who
/// simply never publishes, does not prove any single entry honest, and is
/// worth exactly the deposit -- a writer for whom the lie is worth more than
/// the bond will still tell it. "Tamper-proof" is not a word this contract
/// earns; tamper-EVIDENT with a priced penalty is.
///
/// Two proof families, and the difference between them is the whole design:
///
///   proveEquivocation -- the writer signed two DIFFERENT heads at the SAME
///   seq. Positive evidence, self-contained, nothing to interpret.
///
///   proveNonExtension -- the writer signed an older and a newer head where
///   the older tree is not a prefix of the newer. The tempting construction
///   is "supply a consistency proof and let the contract check it FAILS", and
///   that construction is WRONG: a failing proof shows only that the PROVER
///   did not supply a working one, which is absence of evidence, not
///   evidence. Slashing on it would let anyone burn an honest writer's bond
///   by submitting garbage. That is exactly the collapse this repository is
///   built to refuse -- "unverifiable" rendered as "guilty" (CLAUDE.md rule
///   5). So non-extension is proved POSITIVELY, by a divergent leaf: one
///   index, two inclusion proofs, each valid against its own signed root,
///   carrying two different entry hashes. A prefix cannot disagree with its
///   extension about a leaf they both contain, so this cannot be produced
///   against an honest writer at all.
///
/// The RFC 9162 consistency verifier still ships here, exposed as a view and
/// used as a positive gate by AnchoringLiveness: it says "this DOES extend",
/// which is a claim a proof can establish.
contract BondedCheckpoints {
    struct SignedCheckpoint {
        uint64 seq;
        bytes32 entryHash;
        bytes32 root;
        bytes signature;
    }

    /// @dev One leaf, claimed at `index`, with the inclusion proof tying it to
    ///      whichever signed root it is checked against.
    struct LeafClaim {
        uint256 index;
        bytes32 entryHash;
        bytes32[] proof;
    }

    struct Bond {
        uint256 amount;
        uint64 unlockAt;
        bool withdrawRequested;
        bool slashed;
    }

    /// @dev Half to the prover. Not all of it: a full payout makes proving
    ///      profitable enough to bait, and a small one makes proving cost
    ///      more gas than it returns. The remainder is not paid to anyone,
    ///      so equivocating is a loss to the writer rather than a transfer
    ///      to a counterparty who might be the writer's own second address.
    uint256 public constant PROVER_SHARE_BPS = 5000;
    uint256 private constant BPS_DENOMINATOR = 10000;

    /// @dev Must be at least the largest anchoring deadline the bonded
    ///      writer operates under. A withdrawal window shorter than the
    ///      deadline lets a writer equivocate, wait out the delay, and leave
    ///      before the evidence can even become due. Immutable, set at
    ///      deployment: an adjustable delay is an admin key by another name.
    uint64 public immutable withdrawDelay;

    mapping(address => Bond) private _bonds;

    /// @dev Never paid out and reachable by no function. This contract has no
    ///      owner and no sweep, so the balance is unspendable -- a burn in
    ///      effect, without depending on how any particular chain treats a
    ///      transfer to address(0).
    uint256 public burnedTotal;

    event Deposited(address indexed writer, uint256 amount, uint256 total);
    event WithdrawRequested(address indexed writer, uint64 unlockAt);
    event Withdrawn(address indexed writer, uint256 amount);
    event Slashed(address indexed writer, address indexed prover, uint256 toProver, uint256 burned);

    error ZeroDeposit();
    error AlreadySlashed();
    error NoBond();
    error WithdrawNotRequested();
    error WithdrawNotDue(uint64 unlockAt);
    error PayoutFailed();
    error SignerMismatch(address a, address b);
    error NotBonded(address writer);
    error SameCheckpoint();
    error SeqNotOlder(uint64 older, uint64 newer);
    error LeafIndexOutsideOlderTree(uint256 index, uint64 olderSeq);
    error LeavesAgree(bytes32 entryHash);
    error InclusionProofFailed(bool olderOk, bool newerOk);

    constructor(uint64 withdrawDelay_) {
        withdrawDelay = withdrawDelay_;
    }

    /// @notice Post or top up a bond for `msg.sender`.
    /// @dev A top-up cancels any pending withdrawal request. Otherwise a
    ///      writer could file the request, keep anchoring for the whole
    ///      delay, and exit the instant it expires with the bond never
    ///      having been at risk during the window it was supposedly covering.
    function deposit() external payable {
        if (msg.value == 0) {
            revert ZeroDeposit();
        }
        Bond storage bond = _bonds[msg.sender];
        if (bond.slashed) {
            revert AlreadySlashed();
        }
        bond.amount += msg.value;
        bond.withdrawRequested = false;
        bond.unlockAt = 0;
        emit Deposited(msg.sender, msg.value, bond.amount);
    }

    /// @notice Start the withdrawal clock.
    function requestWithdraw() external {
        Bond storage bond = _bonds[msg.sender];
        if (bond.amount == 0) {
            revert NoBond();
        }
        if (bond.slashed) {
            revert AlreadySlashed();
        }
        bond.withdrawRequested = true;
        bond.unlockAt = uint64(block.timestamp) + withdrawDelay;
        emit WithdrawRequested(msg.sender, bond.unlockAt);
    }

    /// @notice Take the bond back once the delay has elapsed.
    function withdraw() external {
        Bond storage bond = _bonds[msg.sender];
        if (bond.slashed) {
            revert AlreadySlashed();
        }
        if (!bond.withdrawRequested) {
            revert WithdrawNotRequested();
        }
        if (block.timestamp < bond.unlockAt) {
            revert WithdrawNotDue(bond.unlockAt);
        }
        uint256 amount = bond.amount;
        if (amount == 0) {
            revert NoBond();
        }
        // State first, transfer last. The recipient is an arbitrary address
        // and may be a contract that calls straight back in.
        bond.amount = 0;
        bond.withdrawRequested = false;
        bond.unlockAt = 0;
        (bool sent,) = payable(msg.sender).call{value: amount}("");
        if (!sent) {
            revert PayoutFailed();
        }
        emit Withdrawn(msg.sender, amount);
    }

    function bondOf(address writer)
        external
        view
        returns (uint256 amount, uint64 unlockAt, bool withdrawRequested, bool slashed)
    {
        Bond storage bond = _bonds[writer];
        return (bond.amount, bond.unlockAt, bond.withdrawRequested, bond.slashed);
    }

    /// @notice Slash a writer that signed two different heads at one seq.
    /// @dev The seq is a single parameter rather than one per checkpoint,
    ///      so "same seq" is structural and cannot be got wrong by a caller
    ///      or forgotten by a future editor.
    function proveEquivocation(
        bytes32 trailId,
        uint64 seq,
        SignedCheckpoint calldata a,
        SignedCheckpoint calldata b
    ) external {
        if (a.entryHash == b.entryHash && a.root == b.root) {
            // Identical content is not equivocation; a signature is
            // deterministic enough that two encodings of the same claim prove
            // nothing. CheckpointCodec also rejects the high-s malleable twin,
            // so this cannot be reached by re-encoding one signature.
            revert SameCheckpoint();
        }
        address writer = _recoverBoth(
            CheckpointCodec.signingDigest(trailId, seq, a.entryHash, a.root),
            a.signature,
            CheckpointCodec.signingDigest(trailId, seq, b.entryHash, b.root),
            b.signature
        );
        _slash(writer, msg.sender);
    }

    /// @notice Slash a writer whose newer head does not contain its older one.
    /// @dev Positive evidence only: `index` is a leaf position both trees
    ///      contain, and the two inclusion proofs put DIFFERENT entry hashes
    ///      there, each against the root the writer itself signed. See the
    ///      contract header for why a failing consistency proof is not
    ///      accepted in its place.
    function proveNonExtension(
        bytes32 trailId,
        SignedCheckpoint calldata older,
        SignedCheckpoint calldata newer,
        LeafClaim calldata inOlder,
        LeafClaim calldata inNewer
    ) external {
        if (older.seq >= newer.seq) {
            revert SeqNotOlder(older.seq, newer.seq);
        }
        if (inOlder.index != inNewer.index || inOlder.index > older.seq) {
            revert LeafIndexOutsideOlderTree(inOlder.index, older.seq);
        }
        if (inOlder.entryHash == inNewer.entryHash) {
            revert LeavesAgree(inOlder.entryHash);
        }
        address writer = _recoverBoth(
            CheckpointCodec.signingDigest(trailId, older.seq, older.entryHash, older.root),
            older.signature,
            CheckpointCodec.signingDigest(trailId, newer.seq, newer.entryHash, newer.root),
            newer.signature
        );
        bool olderOk = Rfc9162.verifyInclusion(
            inOlder.entryHash, inOlder.index, uint256(older.seq) + 1, inOlder.proof, older.root
        );
        bool newerOk = Rfc9162.verifyInclusion(
            inNewer.entryHash, inNewer.index, uint256(newer.seq) + 1, inNewer.proof, newer.root
        );
        if (!olderOk || !newerOk) {
            revert InclusionProofFailed(olderOk, newerOk);
        }
        _slash(writer, msg.sender);
    }

    /// @notice The RFC 9162 consistency check, callable off chain.
    /// @dev Exposed so a verifier can ask the chain the same question it asks
    ///      `domain/anchoring.verify_consistency`, and compare. The reason
    ///      code is returned, not just the boolean: a caller that cannot tell
    ///      "the roots disagree" from "the proof was the wrong length" has
    ///      lost the distinction the whole library is about.
    function checkConsistency(
        bytes32 oldRoot,
        uint256 oldSize,
        bytes32 newRoot,
        uint256 newSize,
        bytes32[] calldata proof
    ) external pure returns (bool ok, Rfc9162.Fail reason) {
        return Rfc9162.verifyConsistency(oldRoot, oldSize, newRoot, newSize, proof);
    }

    /// @notice `checkConsistency` with the intermediate accumulator values.
    function traceConsistency(
        bytes32 oldRoot,
        uint256 oldSize,
        bytes32 newRoot,
        uint256 newSize,
        bytes32[] calldata proof
    )
        external
        pure
        returns (bool ok, Rfc9162.Fail reason, bytes32[] memory fr, bytes32[] memory sr)
    {
        return Rfc9162.verifyConsistencyTraced(oldRoot, oldSize, newRoot, newSize, proof);
    }

    function _recoverBoth(bytes32 digestA, bytes memory sigA, bytes32 digestB, bytes memory sigB)
        private
        view
        returns (address writer)
    {
        address recoveredA = CheckpointCodec.recoverSigner(digestA, sigA);
        address recoveredB = CheckpointCodec.recoverSigner(digestB, sigB);
        if (recoveredA != recoveredB || recoveredA == address(0)) {
            revert SignerMismatch(recoveredA, recoveredB);
        }
        if (_bonds[recoveredA].amount == 0) {
            // No bond is not "innocent": the evidence may be perfectly good
            // and there is simply nothing here to take. Reverting keeps the
            // prover's gas from buying a state change that pays nothing, and
            // leaves the proof reusable if a bond is later posted.
            revert NotBonded(recoveredA);
        }
        return recoveredA;
    }

    function _slash(address writer, address prover) private {
        Bond storage bond = _bonds[writer];
        if (bond.slashed) {
            revert AlreadySlashed();
        }
        uint256 amount = bond.amount;
        uint256 toProver = (amount * PROVER_SHARE_BPS) / BPS_DENOMINATOR;
        uint256 burned = amount - toProver;
        bond.amount = 0;
        bond.slashed = true;
        bond.withdrawRequested = false;
        bond.unlockAt = 0;
        burnedTotal += burned;
        (bool sent,) = payable(prover).call{value: toProver}("");
        if (!sent) {
            revert PayoutFailed();
        }
        emit Slashed(writer, prover, toProver, burned);
    }
}
