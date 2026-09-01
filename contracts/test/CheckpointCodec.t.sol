// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {VectorTest} from "./Vm.sol";
import {CheckpointCodec} from "../src/CheckpointCodec.sol";

/// @notice The checkpoint frame, its hash and the signing digest, against the
///         bytes `domain/checkpoint.py` and `domain/hashing.py` produce.
/// @dev The frame carries `seq` in DECIMAL and both hashes in lowercase HEX,
///      inside lp64 length prefixes. Three separate spellings the contract has
///      to get exactly right, and none of them is checkable by inspection --
///      which is why the vectors carry the whole frame, not only its digest.
contract CheckpointCodecTest is VectorTest {
    function test_frameAndDigestAgreeWithPython() public view {
        (uint256 expected, uint256 chunks) = _layout("checkpoint");
        uint256 ran;
        for (uint256 c = 0; c < chunks; c++) {
            string memory json = _chunk("checkpoint", c);
            uint256 n = expected - ran < 16 ? expected - ran : 16;
            for (uint256 i = 0; i < n; i++) {
                string memory name = vm.parseJsonString(json, _at(i, "name"));
                uint256 seq = vm.parseJsonUint(json, _at(i, "seq"));
                bytes32 entryHash = vm.parseJsonBytes32(json, _at(i, "entryHash"));
                bytes32 root = vm.parseJsonBytes32(json, _at(i, "root"));

                bytes memory frame = CheckpointCodec.frame(seq, entryHash, root);
                require(
                    keccak256(frame) == keccak256(vm.parseJsonBytes(json, _at(i, "frame"))),
                    string.concat(name, ": frame bytes")
                );
                require(
                    sha256(frame) == vm.parseJsonBytes32(json, _at(i, "frameHash")),
                    string.concat(name, ": frame hash")
                );
                require(
                    CheckpointCodec.signingDigest(
                        vm.parseJsonBytes32(json, _at(i, "trailId")), seq, entryHash, root
                    ) == vm.parseJsonBytes32(json, _at(i, "signingDigest")),
                    string.concat(name, ": signing digest")
                );
                ran++;
            }
        }
        _ranAll(ran, expected, "checkpoint");
    }

    function test_decimalMatchesPythonStr() public pure {
        require(keccak256(bytes(CheckpointCodec.decimal(0))) == keccak256("0"), "0");
        require(keccak256(bytes(CheckpointCodec.decimal(7))) == keccak256("7"), "7");
        require(keccak256(bytes(CheckpointCodec.decimal(10))) == keccak256("10"), "10");
        require(keccak256(bytes(CheckpointCodec.decimal(100))) == keccak256("100"), "100");
        require(
            keccak256(bytes(CheckpointCodec.decimal(18446744073709551615)))
                == keccak256("18446744073709551615"),
            "uint64 max"
        );
    }

    /// @dev Lowercase, no 0x prefix -- `bytes.hex()` in Python. Two characters
    ///      of disagreement here and every signature verification in the
    ///      liveness and bond contracts recovers the wrong address.
    function test_hexMatchesPythonBytesHex() public pure {
        require(
            keccak256(bytes(CheckpointCodec.hex32(bytes32(0))))
                == keccak256("0000000000000000000000000000000000000000000000000000000000000000"),
            "zero"
        );
        require(
            keccak256(
                bytes(
                    CheckpointCodec.hex32(
                        0xdeadbeef00000000000000000000000000000000000000000000000000000001
                    )
                )
            ) == keccak256("deadbeef00000000000000000000000000000000000000000000000000000001"),
            "lowercase, unprefixed"
        );
    }

    /// @dev lp64: 8-byte big-endian length over a TAGGED payload. The tag is
    ///      what makes absent and every possible string differ in their first
    ///      encoded byte, so injectivity holds with no side condition.
    function test_lpIsLengthPrefixedAndTagged() public pure {
        bytes memory encoded = CheckpointCodec.lp("ab");
        require(encoded.length == 11, "8 length bytes + tag + 2");
        require(encoded[7] == bytes1(uint8(3)), "length counts the tag");
        require(encoded[8] == bytes1(uint8(1)), "string tag 0x01");
        require(encoded[9] == "a" && encoded[10] == "b", "payload");
    }

    /// @dev The trail id is inside the digest. Without it, a signature over
    ///      one trail's checkpoint is a valid signature for the identical
    ///      (seq, entryHash, root) on every other trail the same key writes.
    function test_trailIdChangesTheSigningDigest() public pure {
        bytes32 h = keccak256("entry");
        bytes32 r = keccak256("root");
        require(
            CheckpointCodec.signingDigest(bytes32(uint256(1)), 4, h, r)
                != CheckpointCodec.signingDigest(bytes32(uint256(2)), 4, h, r),
            "trail id not bound into the digest"
        );
    }

    /// @dev The frame prefix separates a checkpoint from a signing request over
    ///      the same content: an RFC 3161 sink stamps the frame, a writer signs
    ///      the digest, and interchangeable bytes would make one usable as the
    ///      other.
    function test_signingDigestIsNotTheFrameHash() public pure {
        bytes32 h = keccak256("entry");
        bytes32 r = keccak256("root");
        require(
            CheckpointCodec.signingDigest(bytes32(0), 4, h, r)
                != sha256(CheckpointCodec.frame(4, h, r)),
            "signing digest not domain-separated from the frame"
        );
    }

    function test_recoverSignerRoundTrips() public pure {
        uint256 key = 0xA11CE;
        bytes32 digest = CheckpointCodec.signingDigest(bytes32(uint256(9)), 3, "a", "b");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        require(
            CheckpointCodec.recoverSigner(digest, abi.encodePacked(r, s, v)) == vm.addr(key),
            "round trip"
        );
    }

    /// @dev EIP-2. The high-s twin of a valid signature recovers the SAME
    ///      address, so accepting it would make one signed checkpoint into two
    ///      "different" signatures over identical content -- a free
    ///      equivocation proof against an honest writer.
    function test_recoverSignerRejectsHighS() public pure {
        uint256 key = 0xA11CE;
        bytes32 digest = keccak256("anything");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(n - uint256(s));
        uint8 flipped = v == 27 ? 28 : 27;
        require(
            CheckpointCodec.recoverSigner(digest, abi.encodePacked(r, highS, flipped))
                == address(0),
            "malleable twin accepted"
        );
    }

    /// @dev Malformed input returns address(0) rather than reverting: every
    ///      caller compares against a registered writer, which address(0)
    ///      never is, and reverting would let the attacker pick the failure.
    function test_recoverSignerFailsClosedOnJunk() public pure {
        bytes32 digest = keccak256("anything");
        require(CheckpointCodec.recoverSigner(digest, "") == address(0), "empty");
        require(CheckpointCodec.recoverSigner(digest, new bytes(64)) == address(0), "short");
        require(CheckpointCodec.recoverSigner(digest, new bytes(65)) == address(0), "v = 0");
    }
}
