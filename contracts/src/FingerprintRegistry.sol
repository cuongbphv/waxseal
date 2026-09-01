// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title Append-only on-chain registry of waxseal version descriptors
/// @notice `fp = sha256(descriptor)` computed ON CHAIN, so the registry maps
///         a fingerprint to bytes that actually hash to it -- there is no
///         path by which a submitter names a fingerprint and supplies
///         unrelated bytes.
///
/// This is the incident this library exists for, moved on chain. "Migration
/// 060" widened a hashed field set without changing the version identity and
/// every historical row failed verification. Here the identity IS the hash of
/// the descriptor, so widening the field set produces a DIFFERENT fingerprint
/// and a different registry slot, and the old slot keeps meaning what it
/// meant.
///
/// APPEND-ONLY IS THE ENTIRE FEATURE. There is:
///   - no owner, no admin role, no access control of any kind;
///   - no constructor, so no privileged address is ever recorded;
///   - no `update`, `revoke`, `remove`, `pause` or `migrate` function;
///   - no upgrade hook: no proxy admin, no `delegatecall` anywhere in this
///     file, no `selfdestruct`, no fallback and no receive;
///   - exactly ONE function that writes state, and its only assignment is
///     guarded by an existence check that reverts.
/// The set of function selectors is frozen in `contracts/abi/selectors.json`
/// and CI fails if it changes, so adding a write path is a red build and not
/// a quiet commit.
///
/// What would break it, stated plainly so a future editor recognises the
/// move: adding any second writer to `_descriptors`; removing the
/// `AlreadyRegistered` guard; making the mapping non-private and writable
/// from a derived contract; or deploying this behind a delegatecall proxy,
/// which relocates the storage this contract's guarantees are about into an
/// upgradeable one. The last of those is invisible in this file -- it is a
/// DEPLOYMENT property -- so a reader must check the deployed code, not just
/// this source.
///
/// Poisoning the registry now requires a SHA-256 collision or control of the
/// chain. That is the paper's claim; this file is what makes it enforced
/// rather than argued.
contract FingerprintRegistry {
    /// @dev The one and only piece of mutable state.
    mapping(bytes32 => bytes) private _descriptors;

    event FingerprintRegistered(bytes32 indexed fingerprint, bytes descriptor);

    error EmptyDescriptor();
    error AlreadyRegistered(bytes32 fingerprint);

    /// @notice Register a version descriptor. Never overwrites.
    /// @dev Rejects the empty descriptor. Not because sha256("") is
    ///      unrepresentable -- it is a perfectly good hash -- but because a
    ///      zero-length value is how `lookup` reports "absent", and admitting
    ///      one would make a registered fingerprint indistinguishable from an
    ///      unregistered one. Ambiguity between "recorded" and "never
    ///      recorded" is the exact confusion this repository refuses to ship
    ///      (CLAUDE.md rule 5: unmeasured is not absent).
    function register(bytes calldata descriptor) external returns (bytes32 fingerprint) {
        if (descriptor.length == 0) {
            revert EmptyDescriptor();
        }
        // Precompile 0x02. `sha256` and not `keccak256` because the
        // fingerprint must equal what `domain/fingerprint.py` computes off
        // chain; an EVM-native hash here would make every locally known
        // fingerprint unfindable in this registry.
        fingerprint = sha256(descriptor);
        if (_descriptors[fingerprint].length != 0) {
            revert AlreadyRegistered(fingerprint);
        }
        _descriptors[fingerprint] = descriptor;
        emit FingerprintRegistered(fingerprint, descriptor);
    }

    /// @notice The descriptor bytes for `fingerprint`, or empty if unregistered.
    /// @dev Empty is "not registered here", which a waxseal verifier maps to
    ///      `unreachable_or_absent` -- never to "disagrees" and never to
    ///      "tampered". A fingerprint this registry has not seen is
    ///      unverifiable BY NAME (RFC 6962 section 4.6), and the caller that
    ///      cannot tell absent from disagreeing has collapsed a three-valued
    ///      state into two.
    function lookup(bytes32 fingerprint) external view returns (bytes memory) {
        return _descriptors[fingerprint];
    }

    /// @notice Whether `fingerprint` has a descriptor recorded.
    function isRegistered(bytes32 fingerprint) external view returns (bool) {
        return _descriptors[fingerprint].length != 0;
    }
}
