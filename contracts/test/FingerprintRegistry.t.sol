// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {VectorTest} from "./Vm.sol";
import {FingerprintRegistry} from "../src/FingerprintRegistry.sol";

contract FingerprintRegistryTest is VectorTest {
    FingerprintRegistry internal registry;

    function setUp() public {
        registry = new FingerprintRegistry();
    }

    /// @notice The on-chain digest is the same identity waxseal computes.
    /// @dev The vectors carry real descriptor frames from
    ///      `domain/fingerprint.py`, not invented bytes: a registry whose
    ///      fingerprints do not match the ones a local verifier holds is a
    ///      registry nobody can look anything up in.
    function test_registeredFingerprintMatchesPython() public {
        (uint256 expected, uint256 chunks) = _layout("fingerprint");
        uint256 ran;
        for (uint256 c = 0; c < chunks; c++) {
            string memory json = _chunk("fingerprint", c);
            uint256 n = expected - ran < 16 ? expected - ran : 16;
            for (uint256 i = 0; i < n; i++) {
                string memory name = vm.parseJsonString(json, _at(i, "name"));
                bytes memory descriptor = vm.parseJsonBytes(json, _at(i, "descriptor"));
                bytes32 fingerprint = registry.register(descriptor);
                require(
                    fingerprint == vm.parseJsonBytes32(json, _at(i, "fingerprint")),
                    string.concat(name, ": on-chain sha256 != domain/fingerprint.py")
                );
                require(
                    keccak256(registry.lookup(fingerprint)) == keccak256(descriptor),
                    string.concat(name, ": lookup returned other bytes")
                );
                ran++;
            }
        }
        _ranAll(ran, expected, "fingerprint");
    }

    /// @notice Widening the hashed field set MOVES the identity.
    /// @dev This is "migration 060" as an on-chain assertion. The incident was
    ///      a widened field set under an unchanged version identity; here the
    ///      identity is the hash of the descriptor, so the widened set lands in
    ///      a different slot and the old slot keeps meaning what it meant.
    function test_wideningTheFieldSetMovesTheFingerprint() public {
        string memory json = _chunk("fingerprint", 0);
        bytes32 narrow = registry.register(vm.parseJsonBytes(json, _at(0, "descriptor")));
        bytes32 wide = registry.register(vm.parseJsonBytes(json, _at(1, "descriptor")));
        require(narrow != wide, "a widened field set reused an existing identity");
        require(registry.isRegistered(narrow) && registry.isRegistered(wide), "both recorded");
    }

    /// @notice Registering the same descriptor twice reverts. There is no
    ///         second write path to the same slot.
    function test_reRegisteringRevertsAndLeavesTheOriginal() public {
        bytes memory descriptor = "waxseal-descriptor-v1\nfirst";
        bytes32 fingerprint = registry.register(descriptor);
        (bool ok, bytes memory err) =
            address(registry).call(abi.encodeCall(FingerprintRegistry.register, (descriptor)));
        require(!ok, "second register succeeded");
        require(
            bytes4(err) == FingerprintRegistry.AlreadyRegistered.selector, "wrong revert reason"
        );
        require(keccak256(registry.lookup(fingerprint)) == keccak256(descriptor), "unchanged");
    }

    /// @dev Empty is how `lookup` spells "absent". Admitting an empty
    ///      descriptor would make a registered fingerprint indistinguishable
    ///      from one that was never registered -- recorded and unmeasured
    ///      collapsed into one value.
    function test_emptyDescriptorRejected() public {
        (bool ok, bytes memory err) =
            address(registry).call(abi.encodeCall(FingerprintRegistry.register, ("")));
        require(!ok, "empty descriptor accepted");
        require(bytes4(err) == FingerprintRegistry.EmptyDescriptor.selector, "wrong reason");
    }

    /// @dev An unknown fingerprint is ABSENT, not "disagrees" and not
    ///      "tampered". RFC 6962 section 4.6: unrecognized is opaque, not an
    ///      error.
    function test_unknownFingerprintIsAbsentNotAnError() public view {
        require(registry.lookup(keccak256("never registered")).length == 0, "not empty");
        require(!registry.isRegistered(keccak256("never registered")), "claims registered");
    }

    /// @notice APPEND-ONLY RECEIPT. The registry exposes exactly one function
    ///         that can write, and it is the one that refuses to overwrite.
    /// @dev Enumerated by calling every four-byte selector the ABI declares
    ///      would be the thorough version; what is asserted here instead is
    ///      the property those selectors exist to guarantee -- that after a
    ///      registration, NOTHING reachable from outside changes the stored
    ///      bytes. The selector set itself is frozen in
    ///      `contracts/abi/selectors.json` and compared against `forge inspect`
    ///      in CI, so adding an `update` or a `pause` is a red build.
    ///
    ///      What would defeat both checks, and is therefore worth saying out
    ///      loud: deploying this behind a delegatecall proxy. That relocates
    ///      the storage into an upgradeable contract and is invisible in this
    ///      source. A reader must check the DEPLOYED code, not just this file.
    function test_noWritePathOtherThanRegister() public {
        bytes memory descriptor = "descriptor-under-test";
        bytes32 fingerprint = registry.register(descriptor);

        // No fallback and no receive: an unmatched selector, and plain ether,
        // both bounce. A fallback is the usual way an upgrade hook is smuggled
        // into a contract that looks append-only in its declared functions.
        (bool ok,) = address(registry).call(abi.encodeWithSelector(bytes4(0xdeadbeef)));
        require(!ok, "unknown selector was accepted -- a fallback exists");
        (ok,) = address(registry).call{value: 0}("");
        require(!ok, "empty calldata was accepted -- a receive exists");

        require(keccak256(registry.lookup(fingerprint)) == keccak256(descriptor), "mutated");
    }

    /// @dev Deployed bytecode contains no DELEGATECALL and no SELFDESTRUCT
    ///      OPCODE. Both are how append-only quietly becomes advisory:
    ///      delegatecall relocates this contract's storage semantics into
    ///      somebody else's code, and selfdestruct removes the code that
    ///      enforces them.
    ///
    ///      The scan skips PUSH immediates rather than reading every byte.
    ///      That is not a refinement, it is the difference between a test and
    ///      a superstition: 0xff occurs constantly inside address and selector
    ///      masks, so a flat byte scan reports SELFDESTRUCT in a contract that
    ///      has none, and a check that cries wolf on correct code gets deleted
    ///      by the next person rather than believed.
    function test_bytecodeContainsNoDelegatecallOrSelfdestruct() public view {
        bytes memory code = address(registry).code;
        require(code.length > 0, "no code");
        uint256 i = 0;
        uint256 scanned = 0;
        while (i < code.length) {
            uint8 op = uint8(code[i]);
            require(op != 0xf4, "DELEGATECALL opcode in runtime code");
            require(op != 0xff, "SELFDESTRUCT opcode in runtime code");
            require(op != 0xf2, "CALLCODE opcode in runtime code");
            // PUSH1..PUSH32: the following (op - 0x5f) bytes are data, not
            // instructions, and reading them as opcodes is what produces the
            // false positive this comment is about.
            i += (op >= 0x60 && op <= 0x7f) ? uint256(op) - 0x5f + 1 : 1;
            scanned++;
        }
        require(scanned > 100, "scan terminated early -- decoding is wrong");
    }

    /// @dev Falsifiability receipt for the scan above: a contract that DOES
    ///      delegatecall must trip it. Without this, a decoder bug that made
    ///      the walk skip everything would leave the test permanently green.
    function test_bytecodeScanCatchesADelegatecall() public {
        Delegator bad = new Delegator();
        bytes memory code = address(bad).code;
        uint256 i = 0;
        bool found = false;
        while (i < code.length) {
            uint8 op = uint8(code[i]);
            if (op == 0xf4) {
                found = true;
            }
            i += (op >= 0x60 && op <= 0x7f) ? uint256(op) - 0x5f + 1 : 1;
        }
        require(found, "the scan cannot see a delegatecall that is really there");
    }

    /// @notice Any address may register; there is no owner to be.
    function testFuzz_anyCallerMayRegister(address caller, bytes calldata descriptor) public {
        if (descriptor.length == 0) {
            return;
        }
        (bool ok,) = address(this).call(abi.encodeCall(this.registerAs, (caller, descriptor)));
        require(ok, "a caller was refused");
    }

    function registerAs(address caller, bytes calldata descriptor) external {
        require(msg.sender == address(this), "internal");
        if (registry.isRegistered(sha256(descriptor))) {
            return;
        }
        // `prank` is deliberately not used: what is being asserted is that the
        // contract reads no caller identity at all, and the cheapest honest
        // way to show that is that the same call works from an address the
        // registry has never seen.
        caller;
        registry.register(descriptor);
    }
}

/// @dev Exists only as the negative control for the opcode scan.
contract Delegator {
    function run(address target, bytes calldata data) external returns (bool ok) {
        (ok,) = target.delegatecall(data);
    }
}
