// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {VectorTest} from "./Vm.sol";
import {BondedCheckpoints} from "../src/BondedCheckpoints.sol";
import {CheckpointCodec} from "../src/CheckpointCodec.sol";
import {Rfc9162} from "../src/Rfc9162.sol";

contract BondedCheckpointsTest is VectorTest {
    BondedCheckpoints internal bonded;

    uint256 internal constant WRITER_KEY = 0xA11CE;
    uint256 internal constant OTHER_KEY = 0xB0B;
    bytes32 internal constant TRAIL = keccak256("waxseal-test-trail");
    uint64 internal constant DELAY = 7200;
    uint256 internal constant BOND = 10 ether;

    address internal writer;

    receive() external payable {}

    function setUp() public {
        bonded = new BondedCheckpoints(DELAY);
        writer = vm.addr(WRITER_KEY);
        vm.warp(1_800_000_000);
        vm.deal(address(this), 100 ether);
        _bondFor(WRITER_KEY, BOND);
    }

    /// @dev The bond is keyed by the address the checkpoint signatures recover
    ///      to, so it has to be posted BY that address -- a bond credited to
    ///      the test contract would make every slash below a slash of the
    ///      wrong account, and every assertion would still pass.
    function _bondFor(uint256 key, uint256 amount) internal {
        address from = vm.addr(key);
        vm.deal(from, amount);
        vm.prank(from);
        bonded.deposit{value: amount}();
    }

    function _sign(uint256 key, uint64 seq, bytes32 entryHash, bytes32 root)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 digest = CheckpointCodec.signingDigest(TRAIL, seq, entryHash, root);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _cp(uint256 key, uint64 seq, bytes32 entryHash, bytes32 root)
        internal
        pure
        returns (BondedCheckpoints.SignedCheckpoint memory)
    {
        return BondedCheckpoints.SignedCheckpoint({
            seq: seq, entryHash: entryHash, root: root, signature: _sign(key, seq, entryHash, root)
        });
    }

    // ---- equivocation ----------------------------------------------------

    function test_equivocationSlashesAndPaysTheProver() public {
        uint256 before = address(this).balance;
        bonded.proveEquivocation(
            TRAIL,
            4,
            _cp(WRITER_KEY, 4, keccak256("head-a"), keccak256("root-a")),
            _cp(WRITER_KEY, 4, keccak256("head-b"), keccak256("root-b"))
        );
        (uint256 amount,,, bool slashed) = bonded.bondOf(writer);
        require(slashed && amount == 0, "bond not slashed");
        uint256 expected = (BOND * bonded.PROVER_SHARE_BPS()) / 10000;
        require(address(this).balance == before + expected, "prover not paid the share");
        require(bonded.burnedTotal() == BOND - expected, "remainder not burned");
        require(address(bonded).balance == BOND - expected, "burned funds left the contract");
    }

    /// @dev Only the SAME seq is equivocation. Two heads at different seqs are
    ///      an ordinary trail advancing.
    function test_differentSeqIsNotEquivocation() public {
        bytes memory call = abi.encodeCall(
            BondedCheckpoints.proveEquivocation,
            (
                TRAIL,
                4,
                _cp(WRITER_KEY, 4, keccak256("a"), keccak256("ra")),
                _cp(WRITER_KEY, 5, keccak256("b"), keccak256("rb"))
            )
        );
        (bool ok,) = address(bonded).call(call);
        // The struct's seq is not what the digest uses -- the shared `seq`
        // parameter is -- so a checkpoint signed at a different seq simply
        // fails to recover to the writer.
        require(!ok, "checkpoints at different seqs were treated as equivocation");
        (,,, bool slashed) = bonded.bondOf(writer);
        require(!slashed, "bond slashed on non-evidence");
    }

    function test_identicalCheckpointsAreNotEquivocation() public {
        (bool ok, bytes memory err) = address(bonded)
            .call(
                abi.encodeCall(
                    BondedCheckpoints.proveEquivocation,
                    (
                        TRAIL,
                        4,
                        _cp(WRITER_KEY, 4, keccak256("a"), keccak256("ra")),
                        _cp(WRITER_KEY, 4, keccak256("a"), keccak256("ra"))
                    )
                )
            );
        require(!ok, "one checkpoint submitted twice was slashed as equivocation");
        require(bytes4(err) == BondedCheckpoints.SameCheckpoint.selector, "wrong reason");
    }

    /// @notice Two different keys signing different things is not one writer
    ///         equivocating.
    function test_twoDifferentSignersIsNotEquivocation() public {
        (bool ok, bytes memory err) = address(bonded)
            .call(
                abi.encodeCall(
                    BondedCheckpoints.proveEquivocation,
                    (
                        TRAIL,
                        4,
                        _cp(WRITER_KEY, 4, keccak256("a"), keccak256("ra")),
                        _cp(OTHER_KEY, 4, keccak256("b"), keccak256("rb"))
                    )
                )
            );
        require(!ok, "two separate writers were slashed as one equivocation");
        require(bytes4(err) == BondedCheckpoints.SignerMismatch.selector, "wrong reason");
        (,,, bool slashed) = bonded.bondOf(writer);
        require(!slashed, "bond slashed");
    }

    function test_forgedSignaturesSlashNobody() public {
        BondedCheckpoints.SignedCheckpoint memory a =
            _cp(WRITER_KEY, 4, keccak256("a"), keccak256("ra"));
        BondedCheckpoints.SignedCheckpoint memory b =
            _cp(WRITER_KEY, 4, keccak256("b"), keccak256("rb"));
        a.signature = new bytes(65);
        (bool ok, bytes memory err) = address(bonded)
            .call(abi.encodeCall(BondedCheckpoints.proveEquivocation, (TRAIL, 4, a, b)));
        require(!ok, "a junk signature slashed a bond");
        require(bytes4(err) == BondedCheckpoints.SignerMismatch.selector, "wrong reason");
    }

    /// @notice A trail id the writer never signed for cannot be used to slash it.
    function test_wrongTrailIdSlashesNobody() public {
        (bool ok,) = address(bonded)
            .call(
                abi.encodeCall(
                    BondedCheckpoints.proveEquivocation,
                    (
                        keccak256("some-other-trail"),
                        4,
                        _cp(WRITER_KEY, 4, keccak256("a"), keccak256("ra")),
                        _cp(WRITER_KEY, 4, keccak256("b"), keccak256("rb"))
                    )
                )
            );
        require(!ok, "signatures for one trail slashed a bond under another trail id");
    }

    function test_slashingIsOnceOnly() public {
        bonded.proveEquivocation(
            TRAIL,
            4,
            _cp(WRITER_KEY, 4, keccak256("a"), keccak256("ra")),
            _cp(WRITER_KEY, 4, keccak256("b"), keccak256("rb"))
        );
        (bool ok, bytes memory err) = address(bonded)
            .call(
                abi.encodeCall(
                    BondedCheckpoints.proveEquivocation,
                    (
                        TRAIL,
                        5,
                        _cp(WRITER_KEY, 5, keccak256("c"), keccak256("rc")),
                        _cp(WRITER_KEY, 5, keccak256("d"), keccak256("rd"))
                    )
                )
            );
        require(!ok, "an emptied bond was slashed twice");
        require(bytes4(err) == BondedCheckpoints.NotBonded.selector, "wrong reason");
    }

    // ---- non-extension ---------------------------------------------------

    struct Fixture {
        uint64 olderSeq;
        bytes32 olderEntryHash;
        bytes32 olderRoot;
        bytes32 olderLeaf;
        bytes32[] olderProof;
        uint64 newerSeq;
        bytes32 newerEntryHash;
        bytes32 newerRoot;
        bytes32 newerLeaf;
        bytes32[] newerProof;
        uint256 index;
    }

    function _fixture() internal view returns (Fixture memory f) {
        string memory json = _chunk("nonextension", 0);
        f.index = vm.parseJsonUint(json, _at(0, "index"));
        f.olderSeq = uint64(vm.parseJsonUint(json, _at(0, "olderSeq")));
        f.olderEntryHash = vm.parseJsonBytes32(json, _at(0, "olderEntryHash"));
        f.olderRoot = vm.parseJsonBytes32(json, _at(0, "olderRoot"));
        f.olderLeaf = vm.parseJsonBytes32(json, _at(0, "olderLeaf"));
        f.olderProof = vm.parseJsonBytes32Array(json, _at(0, "olderProof"));
        f.newerSeq = uint64(vm.parseJsonUint(json, _at(0, "newerSeq")));
        f.newerEntryHash = vm.parseJsonBytes32(json, _at(0, "newerEntryHash"));
        f.newerRoot = vm.parseJsonBytes32(json, _at(0, "newerRoot"));
        f.newerLeaf = vm.parseJsonBytes32(json, _at(0, "newerLeaf"));
        f.newerProof = vm.parseJsonBytes32Array(json, _at(0, "newerProof"));
    }

    function _leaf(Fixture memory f, bool older)
        internal
        pure
        returns (BondedCheckpoints.LeafClaim memory)
    {
        return BondedCheckpoints.LeafClaim({
            index: f.index,
            entryHash: older ? f.olderLeaf : f.newerLeaf,
            proof: older ? f.olderProof : f.newerProof
        });
    }

    function _older(Fixture memory f)
        internal
        pure
        returns (BondedCheckpoints.SignedCheckpoint memory)
    {
        return _cp(WRITER_KEY, f.olderSeq, f.olderEntryHash, f.olderRoot);
    }

    function _newer(Fixture memory f)
        internal
        pure
        returns (BondedCheckpoints.SignedCheckpoint memory)
    {
        return _cp(WRITER_KEY, f.newerSeq, f.newerEntryHash, f.newerRoot);
    }

    /// @notice A rewritten trail is slashed on a divergent leaf, not on a
    ///         consistency proof that happened to fail.
    function test_nonExtensionSlashesOnADivergentLeaf() public {
        Fixture memory f = _fixture();
        uint256 before = address(this).balance;
        bonded.proveNonExtension(TRAIL, _older(f), _newer(f), _leaf(f, true), _leaf(f, false));
        (uint256 amount,,, bool slashed) = bonded.bondOf(writer);
        require(slashed && amount == 0, "bond not slashed");
        require(address(this).balance > before, "prover not paid");
    }

    /// @notice The two signed heads really are inconsistent -- the on-chain
    ///         RFC 9162 verifier says so, on the same inputs Python does.
    /// @dev This is what the divergent leaf is EVIDENCE OF. The contract does
    ///      not slash on this call's result, because "no valid proof was
    ///      supplied" is the prover's failure, not the writer's guilt; the
    ///      assertion here records that the underlying claim is true.
    function test_theTwoHeadsAreGenuinelyInconsistent() public view {
        Fixture memory f = _fixture();
        string memory json = _chunk("fork", 0);
        (bool ok, Rfc9162.Fail reason) = bonded.checkConsistency(
            f.olderRoot,
            uint256(f.olderSeq) + 1,
            f.newerRoot,
            uint256(f.newerSeq) + 1,
            vm.parseJsonBytes32Array(json, _at(0, "proofFromPrev"))
        );
        require(!ok, "the forked head verified as an extension");
        require(reason == Rfc9162.Fail.OldRootMismatch, "wrong reason");
    }

    /// @notice AN HONEST WRITER CANNOT BE SLASHED THIS WAY.
    /// @dev The whole reason non-extension is proved positively. A prefix and
    ///      its extension agree at every leaf the prefix contains, so the
    ///      required evidence -- two valid inclusion proofs at one index
    ///      carrying different leaves -- does not exist to be produced.
    function test_honestExtensionCannotBeSlashed() public {
        Fixture memory f = _fixture();
        BondedCheckpoints.LeafClaim memory sameLeaf = BondedCheckpoints.LeafClaim({
            index: f.index, entryHash: f.olderLeaf, proof: f.olderProof
        });
        (bool ok, bytes memory err) = address(bonded)
            .call(
                abi.encodeCall(
                    BondedCheckpoints.proveNonExtension,
                    (TRAIL, _honestHead(1), _honestHead(3), sameLeaf, sameLeaf)
                )
            );
        require(!ok, "an honest writer was slashed");
        require(bytes4(err) == BondedCheckpoints.LeavesAgree.selector, "wrong reason");
        (,,, bool slashed) = bonded.bondOf(writer);
        require(!slashed, "bond slashed");
    }

    function _honestHead(uint256 i)
        internal
        view
        returns (BondedCheckpoints.SignedCheckpoint memory)
    {
        string memory heads = _chunk("heads", 0);
        return _cp(
            WRITER_KEY,
            uint64(vm.parseJsonUint(heads, _at(i, "seq"))),
            vm.parseJsonBytes32(heads, _at(i, "entryHash")),
            vm.parseJsonBytes32(heads, _at(i, "root"))
        );
    }

    /// @notice Two different leaves with proofs that do not check out slash nobody.
    /// @dev This is the free-slash attempt: claim divergence, supply proofs
    ///      that do not verify. If the contract slashed on the CLAIM rather
    ///      than the PROOF, anyone could empty any bond for the price of gas.
    function test_unprovenDivergenceSlashesNobody() public {
        Fixture memory f = _fixture();
        BondedCheckpoints.LeafClaim memory bogus = BondedCheckpoints.LeafClaim({
            index: f.index, entryHash: keccak256("invented leaf"), proof: f.newerProof
        });
        (bool ok, bytes memory err) = address(bonded)
            .call(
                abi.encodeCall(
                    BondedCheckpoints.proveNonExtension,
                    (TRAIL, _older(f), _newer(f), _leaf(f, true), bogus)
                )
            );
        require(!ok, "an unproven claim of divergence slashed a bond");
        require(bytes4(err) == BondedCheckpoints.InclusionProofFailed.selector, "wrong reason");
        (,,, bool slashed) = bonded.bondOf(writer);
        require(!slashed, "bond slashed");
    }

    function test_nonExtensionRequiresTheOlderSeqToBeOlder() public {
        Fixture memory f = _fixture();
        (bool ok, bytes memory err) = address(bonded)
            .call(
                abi.encodeCall(
                    BondedCheckpoints.proveNonExtension,
                    (TRAIL, _newer(f), _older(f), _leaf(f, false), _leaf(f, true))
                )
            );
        require(!ok, "the two heads were accepted in the wrong order");
        require(bytes4(err) == BondedCheckpoints.SeqNotOlder.selector, "wrong reason");
    }

    /// @dev A leaf beyond the older tree is not a leaf both trees contain, so
    ///      disagreeing about it proves nothing.
    function test_leafOutsideTheOlderTreeProvesNothing() public {
        Fixture memory f = _fixture();
        BondedCheckpoints.LeafClaim memory a = _leaf(f, true);
        BondedCheckpoints.LeafClaim memory b = _leaf(f, false);
        a.index = uint256(f.olderSeq) + 1;
        b.index = uint256(f.olderSeq) + 1;
        (bool ok, bytes memory err) = address(bonded)
            .call(
                abi.encodeCall(
                    BondedCheckpoints.proveNonExtension, (TRAIL, _older(f), _newer(f), a, b)
                )
            );
        require(!ok, "a leaf outside the older tree was accepted as evidence");
        require(bytes4(err) == BondedCheckpoints.LeafIndexOutsideOlderTree.selector, "wrong reason");
    }

    // ---- bond lifecycle --------------------------------------------------

    function test_withdrawRequiresTheDelay() public {
        Withdrawer w = new Withdrawer();
        vm.deal(address(w), 1 ether);
        w.deposit(bonded, 1 ether);
        (bool ok, bytes memory err) = w.tryWithdraw(bonded);
        require(
            !ok && bytes4(err) == BondedCheckpoints.WithdrawNotRequested.selector, "unrequested"
        );
        w.request(bonded);
        (ok, err) = w.tryWithdraw(bonded);
        require(!ok && bytes4(err) == BondedCheckpoints.WithdrawNotDue.selector, "too early");
        vm.warp(block.timestamp + DELAY);
        (ok,) = w.tryWithdraw(bonded);
        require(ok, "withdraw refused after the delay");
        require(address(w).balance == 1 ether, "funds not returned");
    }

    /// @dev A top-up cancels a pending request. Otherwise a writer files the
    ///      request, keeps anchoring through the whole window, and exits the
    ///      moment it expires with the bond never actually at risk.
    function test_topUpCancelsAPendingWithdrawal() public {
        Withdrawer w = new Withdrawer();
        vm.deal(address(w), 2 ether);
        w.deposit(bonded, 1 ether);
        w.request(bonded);
        w.deposit(bonded, 1 ether);
        vm.warp(block.timestamp + DELAY + 1);
        (bool ok, bytes memory err) = w.tryWithdraw(bonded);
        require(!ok, "a cancelled withdrawal still completed");
        require(bytes4(err) == BondedCheckpoints.WithdrawNotRequested.selector, "wrong reason");
    }

    /// @notice A slashed bond is closed for good: no withdrawal, no top-up.
    /// @dev And the slash is confined to the writer it names -- an unrelated
    ///      bonded party keeps its own bond and its own pending withdrawal.
    function test_slashedBondIsClosedAndTheSlashIsConfined() public {
        Withdrawer w = new Withdrawer();
        vm.deal(address(w), 2 ether);
        w.deposit(bonded, 1 ether);
        w.request(bonded);

        bonded.proveEquivocation(
            TRAIL,
            4,
            _cp(WRITER_KEY, 4, keccak256("a"), keccak256("ra")),
            _cp(WRITER_KEY, 4, keccak256("b"), keccak256("rb"))
        );
        (,,, bool slashed) = bonded.bondOf(writer);
        require(slashed, "not slashed");

        vm.deal(writer, 1 ether);
        vm.prank(writer);
        (bool ok, bytes memory err) =
            address(bonded).call{value: 1 ether}(abi.encodeCall(BondedCheckpoints.deposit, ()));
        require(!ok, "a slashed writer topped its bond back up");
        require(bytes4(err) == BondedCheckpoints.AlreadySlashed.selector, "wrong reason");

        vm.prank(writer);
        (ok, err) = address(bonded).call(abi.encodeCall(BondedCheckpoints.withdraw, ()));
        require(!ok, "a slashed writer withdrew");
        require(bytes4(err) == BondedCheckpoints.AlreadySlashed.selector, "wrong reason");

        vm.warp(block.timestamp + DELAY + 1);
        (ok,) = w.tryWithdraw(bonded);
        require(ok, "an unrelated bond was frozen by someone else's slash");
    }

    function test_zeroDepositRejected() public {
        (bool ok, bytes memory err) =
            address(bonded).call{value: 0}(abi.encodeCall(BondedCheckpoints.deposit, ()));
        require(!ok && bytes4(err) == BondedCheckpoints.ZeroDeposit.selector, "zero deposit");
    }

    function test_unbondedWriterCannotBeProvenAgainst() public {
        (bool ok, bytes memory err) = address(bonded)
            .call(
                abi.encodeCall(
                    BondedCheckpoints.proveEquivocation,
                    (
                        TRAIL,
                        4,
                        _cp(OTHER_KEY, 4, keccak256("a"), keccak256("ra")),
                        _cp(OTHER_KEY, 4, keccak256("b"), keccak256("rb"))
                    )
                )
            );
        require(!ok, "slashed a writer with no bond");
        require(bytes4(err) == BondedCheckpoints.NotBonded.selector, "wrong reason");
    }
}

/// @dev A bonded party that is not the test contract, for the lifecycle paths.
contract Withdrawer {
    receive() external payable {}

    function deposit(BondedCheckpoints bonded, uint256 amount) external {
        bonded.deposit{value: amount}();
    }

    function request(BondedCheckpoints bonded) external {
        bonded.requestWithdraw();
    }

    function tryWithdraw(BondedCheckpoints bonded) external returns (bool ok, bytes memory err) {
        (ok, err) = address(bonded).call(abi.encodeCall(BondedCheckpoints.withdraw, ()));
    }
}
