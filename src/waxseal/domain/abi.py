"""Ethereum ABI encoding for the ledger layer (pure; no I/O; no hashing).

Why this module hand-rolls an encoder instead of importing one: CLAUDE.md
rule 1 keeps `[project] dependencies` empty, and the read path of the ledger
layer (liveness, registry lookup, bond status) has to build `eth_call`
calldata from the standard library alone. The subset here is deliberately
small — the static types plus dynamic `bytes`/`string`/`bytes32[]` — because
that is everything the three contracts' signatures use.

THE ONE THING THIS MODULE MUST NOT DO IS HASH. A function selector is the
first four bytes of keccak256 over the signature string, and Python's
standard library has no keccak256. `hashlib.sha3_256` is the NIST variant:
same sponge, different padding, DIFFERENT digest. Measured 01/09/2026:
`cast sig "publish(bytes32,bytes)"` is 0x70a74532 while sha3_256 of the same
string begins 7a044878. A selector taken from the standard library would be
wrong on every call and wrong in a way that still looks like a valid
selector, so the transaction would revert (or, far worse, land on whatever
unrelated function happened to collide).

So selectors are FROZEN CONSTANTS here, and their correctness is established
outside Python, by `cast sig` in tests/domain/test_abi.py (and, once
contracts/ exists, by `forge inspect` against the compiled artifacts). ABI
*encoding* needs no keccak at all — only the selector does — and that
boundary is why the constants can be frozen and the encoder cannot drift.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

WORD: Final = 32


class AbiError(ValueError):
    """Anything that cannot be encoded or decoded under the ABI subset here.

    A ValueError subclass so a caller that already guards remote input with
    `except ValueError` (the never-raise discipline in `domain/checkpoint.py`)
    keeps working, while a caller that wants to name this specific failure
    still can.
    """


class Dynamic(bytes):
    """Tail bytes of a dynamically-sized ABI value.

    The ABI splits an argument list into a head of fixed-size words and a
    tail; a dynamic value contributes an offset to the head and its bytes to
    the tail. Carrying that distinction in the TYPE rather than in a parallel
    list of flags means `encode_call` cannot be handed a dynamic value that
    was forgotten to be marked as one — the mistake that produces calldata a
    node accepts and decodes into different arguments than intended.
    """


# ---------------------------------------------------------------- encoding


def encode_uint(value: int, *, bits: int = 256) -> bytes:
    """One word holding an unsigned integer, right-aligned.

    `bool` is rejected even though it is an `int` subclass in Python: a
    boolean reaching a uint argument is a type confusion at the call site,
    and encoding it as 0/1 would produce calldata that is valid, wrong, and
    indistinguishable from intent.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise AbiError(f"uint{bits} value is not an int: {value!r}")
    if bits < 8 or bits > 256 or bits % 8:
        raise AbiError(f"not a legal ABI integer width: bits={bits}")
    if value < 0:
        raise AbiError(f"uint{bits} value is negative: {value}")
    if value >= 1 << bits:
        raise AbiError(f"value does not fit in uint{bits}: {value}")
    return value.to_bytes(WORD, "big")


def encode_bool(value: bool) -> bytes:
    if not isinstance(value, bool):
        raise AbiError(f"value is not a bool: {value!r}")
    return (1 if value else 0).to_bytes(WORD, "big")


def encode_address(value: str) -> bytes:
    """One word holding a 20-byte address, left-padded.

    No checksum validation: EIP-55 casing is an operator-facing typo guard,
    and rejecting a correctly-formed lowercase address for lacking it would
    refuse input every JSON-RPC endpoint accepts.
    """
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
        raise AbiError(f"not a 20-byte hex address: {value!r}")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise AbiError(f"not a 20-byte hex address: {value!r}") from exc
    return b"\x00" * 12 + raw


def encode_bytes32(value: bytes | str) -> bytes:
    """One word holding 32 raw bytes, given either as bytes or as hex."""
    if isinstance(value, bytes | bytearray):
        if len(value) != WORD:
            raise AbiError(f"bytes32 needs exactly 32 bytes, got {len(value)}")
        return bytes(value)
    if isinstance(value, str):
        text = value[2:] if value.startswith("0x") else value
        try:
            raw = bytes.fromhex(text)
        except ValueError as exc:
            raise AbiError(f"bytes32 hex is not hex: {value!r}") from exc
        if len(raw) != WORD:
            raise AbiError(f"bytes32 needs exactly 32 bytes, got {len(raw)}")
        return raw
    raise AbiError(f"bytes32 takes bytes or hex text, got {type(value).__name__}")


def _pad_right(raw: bytes) -> bytes:
    remainder = len(raw) % WORD
    return raw if not remainder else raw + b"\x00" * (WORD - remainder)


def encode_bytes(value: bytes) -> Dynamic:
    """Dynamic `bytes`: a length word followed by the data, right-padded."""
    if not isinstance(value, bytes | bytearray):
        raise AbiError(f"dynamic bytes takes bytes, got {type(value).__name__}")
    return Dynamic(encode_uint(len(value)) + _pad_right(bytes(value)))


def encode_string(value: str) -> Dynamic:
    """Dynamic `string`: UTF-8 bytes under the `bytes` encoding."""
    if not isinstance(value, str):
        raise AbiError(f"string takes text, got {type(value).__name__}")
    return encode_bytes(value.encode("utf-8"))


def encode_bytes32_array(values: Sequence[bytes | str]) -> Dynamic:
    """Dynamic `bytes32[]`: a length word followed by the elements.

    This is the RFC 9162 consistency proof's wire shape (`proveNonExtension`),
    so the elements go out in the order `domain/anchoring.py` produced them.
    Reordering them silently would turn a valid proof into an invalid one.
    """
    body = b"".join(encode_bytes32(value) for value in values)
    return Dynamic(encode_uint(len(values)) + body)


def encode_call(selector: bytes, args: Sequence[bytes]) -> bytes:
    """Assemble calldata: selector, head of words, then the dynamic tail."""
    if len(selector) != 4:
        raise AbiError(f"selector must be 4 bytes, got {len(selector)}")
    offset = WORD * len(args)
    heads: list[bytes] = []
    tails: list[bytes] = []
    for index, arg in enumerate(args):
        if isinstance(arg, Dynamic):
            heads.append(encode_uint(offset))
            tails.append(bytes(arg))
            offset += len(arg)
            continue
        if len(arg) != WORD:
            raise AbiError(f"static argument {index} is not one 32-byte word: {len(arg)} bytes")
        heads.append(arg)
    return selector + b"".join(heads) + b"".join(tails)


# ---------------------------------------------------------------- decoding
#
# Everything below reads a node's response, which is remote input under the
# same threat model as a witness answer: it is checked, never trusted, and a
# shape this build cannot read raises rather than decoding to a plausible
# value. A return decoded under the wrong signature that quietly yields
# `False` or `0` is the collapse CLAUDE.md rule 5 forbids.


def decode_words(data: bytes) -> tuple[bytes, ...]:
    if len(data) % WORD:
        raise AbiError(f"ABI return is not a multiple of 32 bytes: {len(data)}")
    return tuple(data[i : i + WORD] for i in range(0, len(data), WORD))


def _word(value: bytes) -> bytes:
    if len(value) != WORD:
        raise AbiError(f"expected a 32-byte word, got {len(value)} bytes")
    return value


def decode_uint(word: bytes) -> int:
    return int.from_bytes(_word(word), "big")


def decode_bool(word: bytes) -> bool:
    raw = decode_uint(word)
    if raw > 1:
        raise AbiError(f"bool word is neither 0 nor 1: {raw}")
    return raw == 1


def decode_address(word: bytes) -> str:
    raw = _word(word)
    if raw[:12] != b"\x00" * 12:
        raise AbiError(f"address word has dirty high bytes: {raw.hex()}")
    return "0x" + raw[12:].hex()


def decode_bytes32(word: bytes) -> str:
    return _word(word).hex()


def decode_bytes(data: bytes, *, index: int = 0) -> bytes:
    """Follow the head word at `index` to a dynamic `bytes` return value."""
    start = index * WORD
    if start + WORD > len(data):
        raise AbiError(f"head offset word {index} is past the end of {len(data)} bytes")
    offset = decode_uint(data[start : start + WORD])
    if offset % WORD or offset + WORD > len(data):
        raise AbiError(f"dynamic offset {offset} is not a usable position in {len(data)} bytes")
    length = decode_uint(data[offset : offset + WORD])
    body = offset + WORD
    if body + length > len(data):
        raise AbiError(f"declared length {length} runs past the end of {len(data)} bytes")
    return data[body : body + length]


# -------------------------------------------------------- frozen selectors
#
# Frozen because nothing in this process can compute them (see the module
# docstring). tests/domain/test_abi.py re-derives every one with `cast sig`
# and fails on any drift; when contracts/ lands, the same table is what a
# `forge inspect` cross-check compares against. Adding a function here means
# adding it to SELECTORS in the same edit, or the cross-check never sees it.

SELECTOR_REGISTER: Final = bytes.fromhex("82fbdc9c")
SELECTOR_LOOKUP: Final = bytes.fromhex("f39ec1f7")

SELECTOR_SUBMIT: Final = bytes.fromhex("b1768e7e")
SELECTOR_IS_DELINQUENT: Final = bytes.fromhex("f06b6eae")
SELECTOR_LAST_SEEN: Final = bytes.fromhex("1abfe8e2")
SELECTOR_DEADLINE: Final = bytes.fromhex("ee34cf1d")
SELECTOR_LATEST: Final = bytes.fromhex("79feb107")

SELECTOR_DEPOSIT: Final = bytes.fromhex("d0e30db0")
SELECTOR_WITHDRAW: Final = bytes.fromhex("3ccfd60b")
SELECTOR_BOND_OF: Final = bytes.fromhex("72d2b6c0")
SELECTOR_IS_SLASHED: Final = bytes.fromhex("b799036c")
SELECTOR_PROVE_EQUIVOCATION: Final = bytes.fromhex("ed02a93c")
SELECTOR_PROVE_NON_EXTENSION: Final = bytes.fromhex("cf35466d")

# Split out only because the flattened checkpoint pair runs past the line
# length; a struct argument would have shortened it and made the ABI tuple
# encoding a second thing to get right.
_EQUIVOCATION_SIGNATURE: Final = (
    "proveEquivocation(bytes32,uint64,bytes32,bytes32,bytes,bytes32,uint64,bytes32,bytes32,bytes)"
)

SELECTORS: Final[dict[str, bytes]] = {
    "register(bytes)": SELECTOR_REGISTER,
    "lookup(bytes32)": SELECTOR_LOOKUP,
    "submit(bytes32,uint64,bytes32,bytes32,bytes)": SELECTOR_SUBMIT,
    "isDelinquent(bytes32)": SELECTOR_IS_DELINQUENT,
    "lastSeen(bytes32)": SELECTOR_LAST_SEEN,
    "deadline(bytes32)": SELECTOR_DEADLINE,
    "latest(bytes32)": SELECTOR_LATEST,
    "deposit()": SELECTOR_DEPOSIT,
    "withdraw()": SELECTOR_WITHDRAW,
    "bondOf(address)": SELECTOR_BOND_OF,
    "isSlashed(address)": SELECTOR_IS_SLASHED,
    _EQUIVOCATION_SIGNATURE: SELECTOR_PROVE_EQUIVOCATION,
    "proveNonExtension(bytes32,uint64,bytes32,uint64,bytes32,bytes32[])": (
        SELECTOR_PROVE_NON_EXTENSION
    ),
}
