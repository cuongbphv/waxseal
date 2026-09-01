"""ABI encoder tests, cross-checked against Foundry's `cast` where present.

The encoder is checked against an INDEPENDENT implementation (`cast calldata`
/ `cast sig`) rather than against itself, the same discipline
`tests/test_vectors.py` holds golden vectors to. A hand-rolled encoder that
agrees only with its own expectations is a re-derivation of the author's
misreading of the ABI spec, not a conformance check.

The selector cross-check is the one that carries the incident: Python's
standard library has no keccak256, so the selectors in `domain/abi.py` are
frozen constants. Frozen constants with no external check are a wish. `cast
sig` is the check.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
from pathlib import Path

import pytest

from waxseal.domain import abi

CAST = shutil.which("cast")
NEEDS_CAST = pytest.mark.skipif(
    CAST is None,
    reason=(
        "UNMEASURED: Foundry's `cast` is not on PATH, so the frozen selectors and "
        "the calldata encoding were NOT cross-checked against an independent "
        "implementation this run. Install Foundry (foundryup) and re-run to measure."
    ),
)


def cast_out(*args: str) -> str:
    assert CAST is not None
    return subprocess.run(
        [CAST, *args], capture_output=True, text=True, check=True
    ).stdout.strip()


class TestUint:
    def test_encodes_right_aligned_in_one_word(self) -> None:
        assert abi.encode_uint(1) == b"\x00" * 31 + b"\x01"

    def test_encodes_the_largest_uint256(self) -> None:
        assert abi.encode_uint(2**256 - 1) == b"\xff" * 32

    def test_narrower_widths_still_occupy_a_full_word(self) -> None:
        assert abi.encode_uint(2**64 - 1, bits=64) == b"\x00" * 24 + b"\xff" * 8

    def test_a_value_too_large_for_its_width_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="does not fit"):
            abi.encode_uint(2**64, bits=64)

    def test_a_negative_value_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="negative"):
            abi.encode_uint(-1)

    def test_a_bool_is_not_silently_an_int(self) -> None:
        # bool is a subclass of int in Python; encoding True as uint 1 would
        # let a type confusion at a call site produce valid-looking calldata.
        with pytest.raises(abi.AbiError, match="not an int"):
            abi.encode_uint(True)  # type: ignore[arg-type]

    def test_a_width_that_is_not_a_legal_abi_width_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="bits"):
            abi.encode_uint(1, bits=12)

    def test_a_width_beyond_256_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="bits"):
            abi.encode_uint(1, bits=264)


class TestBool:
    def test_true_and_false(self) -> None:
        assert abi.encode_bool(True) == b"\x00" * 31 + b"\x01"
        assert abi.encode_bool(False) == b"\x00" * 32

    def test_a_non_bool_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="not a bool"):
            abi.encode_bool(1)  # type: ignore[arg-type]


class TestAddress:
    ADDR = "0x00000000000000000000000000000000000000aB"

    def test_encodes_left_padded_and_case_insensitively(self) -> None:
        assert abi.encode_address(self.ADDR) == b"\x00" * 31 + b"\xab"

    def test_a_short_address_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="address"):
            abi.encode_address("0xab")

    def test_a_non_hex_address_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="address"):
            abi.encode_address("0x" + "z" * 40)

    def test_a_non_string_address_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="address"):
            abi.encode_address(b"\x00" * 20)  # type: ignore[arg-type]


class TestBytes32:
    def test_accepts_raw_bytes(self) -> None:
        assert abi.encode_bytes32(b"\x11" * 32) == b"\x11" * 32

    def test_accepts_hex_with_and_without_the_prefix(self) -> None:
        assert abi.encode_bytes32("11" * 32) == b"\x11" * 32
        assert abi.encode_bytes32("0x" + "11" * 32) == b"\x11" * 32

    def test_a_wrong_length_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="bytes32"):
            abi.encode_bytes32(b"\x11" * 31)

    def test_hex_of_the_wrong_length_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="bytes32"):
            abi.encode_bytes32("11" * 31)

    def test_non_hex_text_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="bytes32"):
            abi.encode_bytes32("z" * 64)

    def test_another_type_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="bytes32"):
            abi.encode_bytes32(17)  # type: ignore[arg-type]


class TestDynamicBytes:
    def test_length_word_then_right_padded_data(self) -> None:
        encoded = abi.encode_bytes(b"\xde\xad\xbe\xef")
        assert isinstance(encoded, abi.Dynamic)
        assert encoded == abi.encode_uint(4) + b"\xde\xad\xbe\xef" + b"\x00" * 28

    def test_empty_bytes_are_a_bare_length_word(self) -> None:
        assert abi.encode_bytes(b"") == abi.encode_uint(0)

    def test_an_exact_multiple_of_a_word_gets_no_padding(self) -> None:
        assert abi.encode_bytes(b"\x01" * 32) == abi.encode_uint(32) + b"\x01" * 32

    def test_a_string_is_its_utf8_bytes(self) -> None:
        assert abi.encode_string("wax") == abi.encode_bytes(b"wax")

    def test_a_non_bytes_value_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="bytes"):
            abi.encode_bytes("wax")  # type: ignore[arg-type]

    def test_a_non_string_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="string"):
            abi.encode_string(b"wax")  # type: ignore[arg-type]


class TestBytes32Array:
    def test_length_word_then_elements(self) -> None:
        encoded = abi.encode_bytes32_array([b"\x11" * 32, "0x" + "22" * 32])
        assert isinstance(encoded, abi.Dynamic)
        assert encoded == abi.encode_uint(2) + b"\x11" * 32 + b"\x22" * 32

    def test_an_empty_array_is_a_bare_length_word(self) -> None:
        assert abi.encode_bytes32_array([]) == abi.encode_uint(0)


class TestEncodeCall:
    def test_static_args_sit_in_the_head(self) -> None:
        call = abi.encode_call(abi.SELECTOR_LOOKUP, [abi.encode_bytes32(b"\x07" * 32)])
        assert call == abi.SELECTOR_LOOKUP + b"\x07" * 32

    def test_a_dynamic_arg_becomes_an_offset_plus_a_tail(self) -> None:
        call = abi.encode_call(abi.SELECTOR_REGISTER, [abi.encode_bytes(b"\xaa")])
        assert call == (
            abi.SELECTOR_REGISTER
            + abi.encode_uint(32)
            + abi.encode_uint(1)
            + b"\xaa"
            + b"\x00" * 31
        )

    def test_two_dynamic_args_get_distinct_offsets(self) -> None:
        call = abi.encode_call(
            b"\x00\x00\x00\x00", [abi.encode_bytes(b"\xaa"), abi.encode_bytes(b"\xbb")]
        )
        head = call[4:68]
        assert head == abi.encode_uint(64) + abi.encode_uint(64 + 64)

    def test_a_selector_of_the_wrong_length_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="selector"):
            abi.encode_call(b"\x00", [])

    def test_a_static_arg_that_is_not_one_word_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="one 32-byte word"):
            abi.encode_call(b"\x00\x00\x00\x00", [b"\x01"])


class TestDecode:
    def test_words_splits_on_32_byte_boundaries(self) -> None:
        assert abi.decode_words(b"\x01" * 32 + b"\x02" * 32) == (b"\x01" * 32, b"\x02" * 32)

    def test_a_ragged_return_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="multiple of 32"):
            abi.decode_words(b"\x01" * 33)

    def test_uint_bool_address_and_bytes32_round_trip(self) -> None:
        assert abi.decode_uint(abi.encode_uint(2**64 - 1)) == 2**64 - 1
        assert abi.decode_bool(abi.encode_bool(True)) is True
        assert abi.decode_bool(abi.encode_bool(False)) is False
        assert abi.decode_address(abi.encode_address(TestAddress.ADDR)) == TestAddress.ADDR.lower()
        assert abi.decode_bytes32(abi.encode_bytes32(b"\x11" * 32)) == "11" * 32

    def test_a_word_of_the_wrong_size_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="32-byte word"):
            abi.decode_uint(b"\x01")

    def test_a_bool_word_that_is_neither_0_nor_1_is_refused(self) -> None:
        # Solidity guarantees a clean bool; anything else means the return was
        # decoded under the wrong signature, which must not read as `False`.
        with pytest.raises(abi.AbiError, match="bool"):
            abi.decode_bool(abi.encode_uint(2))

    def test_an_address_word_with_dirty_high_bytes_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="address"):
            abi.decode_address(b"\xff" + b"\x00" * 31)

    def test_dynamic_bytes_are_followed_from_their_offset(self) -> None:
        payload = b"\xde\xad\xbe\xef"
        blob = abi.encode_uint(32) + abi.encode_bytes(payload)
        assert abi.decode_bytes(blob) == payload

    def test_an_offset_past_the_end_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="offset"):
            abi.decode_bytes(abi.encode_uint(4096))

    def test_a_length_past_the_end_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="length"):
            abi.decode_bytes(abi.encode_uint(32) + abi.encode_uint(999))

    def test_an_unaligned_offset_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="offset"):
            abi.decode_bytes(abi.encode_uint(3) + b"\x00" * 64)

    def test_a_head_index_beyond_the_head_is_refused(self) -> None:
        with pytest.raises(abi.AbiError, match="offset"):
            abi.decode_bytes(abi.encode_uint(32), index=4)


class TestNoKeccakSmuggledIn:
    def test_the_module_never_imports_a_hash_library(self) -> None:
        # The measured trap this module exists around: `hashlib.sha3_256` is
        # NIST SHA3, not Ethereum's keccak256 (different padding, different
        # digest), so a selector computed from it is silently wrong. CLAUDE.md
        # rule 1 forbids adding a keccak dependency, so selectors are frozen
        # constants and NOTHING here hashes anything.
        # Parsed, not grepped: the module docstring names the trap on purpose
        # (CLAUDE.md rule 9 — comments carry the incident), so a text scan
        # would fail on the warning rather than on the mistake.
        tree = ast.parse(Path(abi.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert "hashlib" not in imported
        assert not [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr.startswith("sha3")
        ]


class TestFrozenSelectors:
    def test_every_selector_is_four_bytes(self) -> None:
        assert abi.SELECTORS
        for signature, selector in abi.SELECTORS.items():
            assert len(selector) == 4, signature

    def test_the_named_constants_are_exactly_the_table(self) -> None:
        # A constant that drifts out of SELECTORS would never be cross-checked
        # against `cast sig` below: the cross-check iterates the table.
        named = {
            value
            for name, value in vars(abi).items()
            if name.startswith("SELECTOR_") and isinstance(value, bytes)
        }
        assert named == set(abi.SELECTORS.values())

    @NEEDS_CAST
    def test_frozen_selectors_match_cast_sig(self) -> None:
        mismatches = []
        for signature, selector in abi.SELECTORS.items():
            measured = cast_out("sig", signature)
            if measured != "0x" + selector.hex():
                mismatches.append(f"{signature}: frozen 0x{selector.hex()} != cast {measured}")
        assert mismatches == []

    @NEEDS_CAST
    def test_the_stdlib_sha3_trap_is_real_and_not_folklore(self) -> None:
        # Receipt for the bead's measured constraint: sha3_256 disagrees with
        # keccak256 on the very first byte, so a selector taken from the
        # standard library would be wrong AND look plausible.
        import hashlib

        signature = "publish(bytes32,bytes)"
        keccak_selector = cast_out("sig", signature)
        nist = "0x" + hashlib.sha3_256(signature.encode()).hexdigest()[:8]
        assert keccak_selector == "0x70a74532"
        assert nist == "0x7a044878"
        assert keccak_selector != nist


class TestAgainstCastCalldata:
    @NEEDS_CAST
    def test_a_static_only_call_matches_cast(self) -> None:
        chain_id = "0x" + "11" * 32
        expected = cast_out("calldata", "lookup(bytes32)", chain_id)
        got = abi.encode_call(abi.SELECTOR_LOOKUP, [abi.encode_bytes32(chain_id)])
        assert "0x" + got.hex() == expected

    @NEEDS_CAST
    def test_a_mixed_static_and_dynamic_call_matches_cast(self) -> None:
        signature = "submit(bytes32,uint64,bytes32,bytes32,bytes)"
        chain_id = "0x" + "11" * 32
        entry_hash = "0x" + "22" * 32
        root = "0x" + "33" * 32
        sig = "0x" + "ab" * 65
        expected = cast_out("calldata", signature, chain_id, "42", entry_hash, root, sig)
        got = abi.encode_call(
            abi.SELECTOR_SUBMIT,
            [
                abi.encode_bytes32(chain_id),
                abi.encode_uint(42, bits=64),
                abi.encode_bytes32(entry_hash),
                abi.encode_bytes32(root),
                abi.encode_bytes(bytes.fromhex("ab" * 65)),
            ],
        )
        assert "0x" + got.hex() == expected

    @NEEDS_CAST
    def test_a_bytes32_array_call_matches_cast(self) -> None:
        signature = "proveNonExtension(bytes32,uint64,bytes32,uint64,bytes32,bytes32[])"
        chain_id = "0x" + "11" * 32
        old_root = "0x" + "22" * 32
        new_root = "0x" + "33" * 32
        proof = ["0x" + "44" * 32, "0x" + "55" * 32]
        expected = cast_out(
            "calldata", signature, chain_id, "3", old_root, "9", new_root, f"[{','.join(proof)}]"
        )
        got = abi.encode_call(
            abi.SELECTOR_PROVE_NON_EXTENSION,
            [
                abi.encode_bytes32(chain_id),
                abi.encode_uint(3, bits=64),
                abi.encode_bytes32(old_root),
                abi.encode_uint(9, bits=64),
                abi.encode_bytes32(new_root),
                abi.encode_bytes32_array(proof),
            ],
        )
        assert "0x" + got.hex() == expected
