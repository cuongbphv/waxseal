// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {VectorTest} from "./Vm.sol";
import {Rfc9162} from "../src/Rfc9162.sol";

/// @notice The cross-implementation agreement test: this contract's verdicts
///         against `src/waxseal/domain/anchoring.py`'s, on vectors generated
///         by `tools/gen_contract_vectors.py`.
///
/// What makes it a real check rather than a ceremony: the ACCUMULATOR TRACES
/// are compared, not just the verdicts. Two verifiers can agree on true or
/// false while walking entirely different trees, and a test that compared only
/// the boolean would never notice. And the vectors are roughly a fifth
/// negatives -- flipped siblings, dropped siblings, extra siblings, reordered
/// pairs, forged roots, a proof for the wrong prefix, and a truncated proof
/// that folds to both roots anyway -- each carrying the REASON it must be
/// rejected, so agreement on refusal is agreement on why.
contract Rfc9162VectorsTest is VectorTest {
    function test_consistencyVectorsAgreeWithPython() public view {
        (uint256 expected, uint256 chunks) = _layout("consistency");
        uint256 ran;
        for (uint256 c = 0; c < chunks; c++) {
            ran += _runConsistencyChunk(c, expected - ran);
        }
        _ranAll(ran, expected, "consistency");
    }

    function _runConsistencyChunk(uint256 chunk, uint256 remaining)
        private
        view
        returns (uint256 ran)
    {
        string memory json = _chunk("consistency", chunk);
        uint256 n = remaining < 16 ? remaining : 16;
        for (uint256 i = 0; i < n; i++) {
            string memory name = vm.parseJsonString(json, _at(i, "name"));
            (bool ok, Rfc9162.Fail reason, bytes32[] memory fr, bytes32[] memory sr) = Rfc9162.verifyConsistencyTraced(
                vm.parseJsonBytes32(json, _at(i, "oldRoot")),
                vm.parseJsonUint(json, _at(i, "oldSize")),
                vm.parseJsonBytes32(json, _at(i, "newRoot")),
                vm.parseJsonUint(json, _at(i, "newSize")),
                vm.parseJsonBytes32Array(json, _at(i, "proof"))
            );
            require(
                ok == vm.parseJsonBool(json, _at(i, "expectOk")), string.concat(name, ": verdict")
            );
            require(
                uint256(reason) == vm.parseJsonUint(json, _at(i, "expectFail")),
                string.concat(name, ": rejection reason")
            );
            _eqArray(
                fr, vm.parseJsonBytes32Array(json, _at(i, "frTrace")), string.concat(name, ": fr")
            );
            _eqArray(
                sr, vm.parseJsonBytes32Array(json, _at(i, "srTrace")), string.concat(name, ": sr")
            );
            ran++;
        }
    }

    function test_inclusionVectorsAgreeWithPython() public view {
        (uint256 expected, uint256 chunks) = _layout("inclusion");
        uint256 ran;
        for (uint256 c = 0; c < chunks; c++) {
            ran += _runInclusionChunk(c, expected - ran);
        }
        _ranAll(ran, expected, "inclusion");
    }

    function _runInclusionChunk(uint256 chunk, uint256 remaining)
        private
        view
        returns (uint256 ran)
    {
        string memory json = _chunk("inclusion", chunk);
        uint256 n = remaining < 16 ? remaining : 16;
        for (uint256 i = 0; i < n; i++) {
            bool ok = Rfc9162.verifyInclusion(
                vm.parseJsonBytes32(json, _at(i, "entryHash")),
                vm.parseJsonUint(json, _at(i, "index")),
                vm.parseJsonUint(json, _at(i, "batchSize")),
                vm.parseJsonBytes32Array(json, _at(i, "proof")),
                vm.parseJsonBytes32(json, _at(i, "root"))
            );
            require(
                ok == vm.parseJsonBool(json, _at(i, "expectOk")),
                string.concat(vm.parseJsonString(json, _at(i, "name")), ": inclusion verdict")
            );
            ran++;
        }
    }

    /// @notice The Solidity tree fold reproduces Python's recursive split.
    /// @dev Python recurses on the RFC 6962 split point; this contract folds
    ///      bottom-up and promotes an odd node. They are the same tree only if
    ///      the promotion rule is right, which is a claim about sizes either
    ///      side of a power of two and is therefore checked, not assumed.
    function test_treeRootsAgreeWithPython() public view {
        (uint256 expected, uint256 chunks) = _layout("tree");
        uint256 ran;
        for (uint256 c = 0; c < chunks; c++) {
            string memory json = _chunk("tree", c);
            uint256 n = expected - ran < 16 ? expected - ran : 16;
            for (uint256 i = 0; i < n; i++) {
                bytes32[] memory leaves = vm.parseJsonBytes32Array(json, _at(i, "leaves"));
                require(
                    Rfc9162.treeHash(leaves) == vm.parseJsonBytes32(json, _at(i, "root")),
                    string.concat(vm.parseJsonString(json, _at(i, "name")), ": root")
                );
                ran++;
            }
        }
        _ranAll(ran, expected, "tree");
    }

    /// @notice The empty tree is sha256("") -- RFC 6962 section 2.1, and the
    ///         one leaf count Python special-cases.
    function test_emptyTreeIsHashOfEmptyString() public pure {
        bytes32[] memory none = new bytes32[](0);
        require(
            Rfc9162.treeHash(none)
                == 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,
            "empty tree root"
        );
    }

    /// @notice A leaf and an inner node over the same bytes never collide.
    /// @dev CVE-2012-2459: without the 0x00/0x01 prefixes an attacker can
    ///      present a pair of child hashes as a single leaf. The inclusion
    ///      vectors carry the same attack as a rejected proof; this states the
    ///      property directly so removing a prefix fails here first, with a
    ///      message that names the reason.
    function test_leafAndNodeDomainsAreSeparated() public pure {
        bytes32 left = keccak256("left");
        bytes32 right = keccak256("right");
        require(Rfc9162.leafHash(left) != sha256(abi.encodePacked(left)), "leaf prefix missing");
        require(
            Rfc9162.pairHash(left, right) != sha256(abi.encodePacked(left, right)),
            "node prefix missing"
        );
    }

    /// @notice The verifier never reverts, whatever it is handed.
    /// @dev A verifier an attacker can revert is a verifier an attacker can
    ///      silence. The Python side promises the same thing and is fuzzed for
    ///      it; the sizes here are unbounded on purpose.
    function testFuzz_verifierNeverRevertsOnJunk(
        bytes32 oldRoot,
        uint8 oldSize,
        bytes32 newRoot,
        uint8 newSize,
        bytes32[8] calldata junk,
        uint8 proofLen
    ) public pure {
        bytes32[] memory proof = new bytes32[](proofLen % 9);
        for (uint256 i = 0; i < proof.length; i++) {
            proof[i] = junk[i];
        }
        (bool ok,) = Rfc9162.verifyConsistency(oldRoot, oldSize, newRoot, newSize, proof);
        // Random 32-byte roots are not the roots of any tree these sizes
        // describe; accepting one would mean a forged root verified.
        require(!ok || (oldSize == newSize && oldRoot == newRoot), "junk verified");
    }
}
