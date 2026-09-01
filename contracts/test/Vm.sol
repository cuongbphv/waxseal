// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice The handful of Foundry cheatcodes these tests use, declared locally.
/// @dev There is no `lib/`, no forge-std and no git submodule under
///      `contracts/`. Cheatcodes are ordinary calls to a fixed address, so the
///      only thing forge-std would add here is a dependency that can be
///      re-pointed -- in a directory whose whole subject is registries that
///      cannot. Declaring the eleven signatures used costs less than vendoring
///      a library to get them.
interface Vm {
    function readFile(string calldata path) external view returns (string memory);
    function projectRoot() external view returns (string memory);
    function toString(uint256 value) external pure returns (string memory);
    function parseJsonUint(string calldata json, string calldata key)
        external
        pure
        returns (uint256);
    function parseJsonBool(string calldata json, string calldata key) external pure returns (bool);
    function parseJsonBytes(string calldata json, string calldata key)
        external
        pure
        returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key)
        external
        pure
        returns (bytes32);
    function parseJsonBytes32Array(string calldata json, string calldata key)
        external
        pure
        returns (bytes32[] memory);
    function parseJsonString(string calldata json, string calldata key)
        external
        pure
        returns (string memory);
    function sign(uint256 privateKey, bytes32 digest)
        external
        pure
        returns (uint8 v, bytes32 r, bytes32 s);
    function addr(uint256 privateKey) external pure returns (address);
    function warp(uint256 newTimestamp) external;
    function prank(address sender) external;
    function deal(address account, uint256 newBalance) external;
}

/// @notice Shared base: the cheatcode handle, assertions, and vector loading.
/// @dev `require` is the assertion. A failing test reverts with the message,
///      which is what `forge test` reports -- the same information forge-std's
///      assertEq would print, from a base contract that is 40 lines instead of
///      a vendored dependency.
contract VectorTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function _json(string memory name) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/vectors/", name, ".json"));
    }

    /// @dev The vector files are chunked so no single parsed string is large:
    ///      every cheatcode call copies the WHOLE json into calldata and EVM
    ///      memory is never reclaimed inside a frame, so one big file parsed a
    ///      few hundred times is an immediate MemoryOOG. `index.json` records
    ///      how many chunks and how many vectors each group has.
    function _chunk(string memory group, uint256 index) internal view returns (string memory) {
        return vm.readFile(
            string.concat(vm.projectRoot(), "/vectors/", group, "-", _pad3(index), ".json")
        );
    }

    function _layout(string memory group) internal view returns (uint256 count, uint256 chunks) {
        string memory index = vm.readFile(string.concat(vm.projectRoot(), "/vectors/index.json"));
        count = vm.parseJsonUint(index, string.concat("$.", group, ".count"));
        chunks = vm.parseJsonUint(index, string.concat("$.", group, ".chunks"));
    }

    /// @dev JSONPath into element `i` of a chunk's top-level array.
    function _at(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat("$[", _u(i), "].", field);
    }

    function _u(uint256 value) internal pure returns (string memory) {
        return Vm(address(uint160(uint256(keccak256("hevm cheat code"))))).toString(value);
    }

    function _pad3(uint256 value) internal pure returns (string memory) {
        if (value < 10) {
            return string.concat("00", _u(value));
        }
        if (value < 100) {
            return string.concat("0", _u(value));
        }
        return _u(value);
    }

    function _eqArray(bytes32[] memory actual, bytes32[] memory expected, string memory what)
        internal
        pure
    {
        require(actual.length == expected.length, string.concat(what, ": trace length"));
        for (uint256 i = 0; i < actual.length; i++) {
            require(actual[i] == expected[i], string.concat(what, ": trace element ", _u(i)));
        }
    }

    /// @dev Every vector-driven test ends by asserting it actually ran the
    ///      number of vectors the index claims. A loop that silently iterated
    ///      zero times -- a mis-typed group name, a chunk file that failed to
    ///      parse into an empty array -- passes every assertion inside it, and
    ///      a green suite that checked nothing is the one outcome a
    ///      cross-implementation vector test must never produce.
    function _ranAll(uint256 ran, uint256 expected, string memory group) internal pure {
        require(
            ran == expected,
            string.concat(group, ": ran ", _u(ran), " vectors, index says ", _u(expected))
        );
    }
}
