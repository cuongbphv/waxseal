// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title The checkpoint frame and the checkpoint signing digest, on chain
/// @notice Reproduces `domain/checkpoint.py::checkpoint_frame` and the lp64
///         field encoder `domain/hashing.py::lp` exactly.
///
/// Why the contract rebuilds the frame instead of accepting a digest: the
/// equivocation and non-extension proofs compare STRUCTURED fields (same
/// trail, same seq, different head). A contract that took the signed digest
/// as an input would have to take the caller's word for which (seq,
/// entryHash, root) that digest covers, and a slashing contract that trusts
/// the prover's labelling of the evidence is not a slashing contract.
///
/// The lp64 encoding is not negotiable and not re-derived here: 8-byte
/// big-endian length over a TAGGED payload (0x01 then UTF-8 for a string).
/// The tag is what makes injectivity unconditional -- an earlier design
/// encoded "absent" as a six-byte sentinel that was itself valid UTF-8, so
/// exactly one string collided with it. Only string fields appear in a
/// checkpoint frame, so only the 0x01 arm is reachable from here; the 0x00
/// arm is omitted rather than written and never exercised.
library CheckpointCodec {
    /// @dev Frozen bytes. These are already inside externally issued RFC 3161
    ///      receipts on the Python side; moving them would orphan real
    ///      evidence, so this constant is append-only in the same sense the
    ///      fingerprint registry is.
    bytes internal constant FRAME_PREFIX_BARE = "waxseal-checkpoint-v1\n";

    /// @dev The signing domain separator. A checkpoint FRAME is what an RFC
    ///      3161 sink stamps; a checkpoint SIGNATURE is a different act by a
    ///      different party, so it gets its own prefix rather than reusing
    ///      the frame's. Without the separation a timestamp token over a
    ///      frame and a writer signature over the same frame would be
    ///      interchangeable bytes.
    bytes internal constant SIGNING_PREFIX = "waxseal-checkpoint-sig-v1\n";

    /// @notice `checkpoint_frame(Checkpoint(seq, entryHash, root))`, bare shape.
    /// @dev The hex strings are the 64-character LOWERCASE spelling, because
    ///      that is what `bytes.hex()` produces in Python and the frame
    ///      commits to the ASCII, not to the 32 bytes.
    function frame(uint256 seq, bytes32 entryHash, bytes32 root)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            FRAME_PREFIX_BARE, uint64(3), lp(decimal(seq)), lp(hex32(entryHash)), lp(hex32(root))
        );
    }

    /// @notice The 32 bytes a trail writer signs for one checkpoint.
    /// @dev The trail id is bound INTO the digest. Without it a checkpoint
    ///      signed for one trail is a valid signature for the same (seq,
    ///      entryHash, root) on any other trail the same key writes, and the
    ///      liveness contract is keyed by trail.
    ///
    ///      This is a raw SHA-256 digest, deliberately NOT an EIP-191
    ///      personal_sign or EIP-712 envelope: the same bytes must be
    ///      producible by a Python verifier that imports no crypto library
    ///      beyond hashlib. A signer therefore signs these 32 bytes directly
    ///      (`cast wallet sign --no-hash`), and a wallet that silently
    ///      prefixes "\x19Ethereum Signed Message" will not recover.
    function signingDigest(bytes32 trailId, uint256 seq, bytes32 entryHash, bytes32 root)
        internal
        pure
        returns (bytes32)
    {
        bytes32 frameHash = sha256(frame(seq, entryHash, root));
        return sha256(
            abi.encodePacked(SIGNING_PREFIX, uint64(2), lp(hex32(trailId)), lp(hex32(frameHash)))
        );
    }

    /// @notice lp64 one string field: 8-byte big-endian length over 0x01 + UTF-8.
    function lp(string memory value) internal pure returns (bytes memory) {
        bytes memory raw = bytes(value);
        return abi.encodePacked(uint64(raw.length + 1), bytes1(0x01), raw);
    }

    /// @notice Base-10 spelling of `value`, matching Python's `str(int)`.
    function decimal(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 digits;
        for (uint256 v = value; v != 0; v /= 10) {
            digits++;
        }
        bytes memory out = new bytes(digits);
        for (uint256 v = value; v != 0; v /= 10) {
            digits--;
            out[digits] = bytes1(uint8(48 + (v % 10)));
        }
        return string(out);
    }

    /// @notice 64-character lowercase hex, matching Python's `bytes.hex()`.
    /// @dev No "0x" prefix: `bytes.hex()` does not emit one, and a frame that
    ///      disagreed with Python by two characters would fail every cross
    ///      vector rather than fail quietly -- which is the point of hashing
    ///      the ASCII the two sides can both write down.
    function hex32(bytes32 value) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory out = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(value[i]);
            out[i * 2] = alphabet[b >> 4];
            out[i * 2 + 1] = alphabet[b & 0x0f];
        }
        return string(out);
    }

    /// @notice `ecrecover` over a waxseal checkpoint signing digest.
    /// @dev Returns address(0) on a malformed signature instead of
    ///      reverting, and every caller compares against a registered writer
    ///      -- so address(0) can never match. Reverting here would let an
    ///      attacker choose the failure mode; returning the zero address
    ///      keeps "did not recover" and "recovered someone else" the same
    ///      kind of answer to the caller.
    ///
    ///      `s` is bounded to the lower half order (EIP-2). The malleable
    ///      twin of a valid signature recovers the SAME address, which for an
    ///      equivocation proof would mean two "different" signatures over one
    ///      checkpoint -- self-equivocation on identical content. Rejecting
    ///      the high-s form removes that free-slash path.
    function recoverSigner(bytes32 digest, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) {
            return address(0);
        }
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        if (v != 27 && v != 28) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }
}
