"""Golden vector generator — an INDEPENDENT implementation of SPEC.md.

Deliberately does NOT import waxseal: it re-implements sections 2-4 straight
from the SPEC prose, so the vectors cross-check the library instead of echoing
it. Run once to freeze tests/vectors/vectors.json; frozen vectors are
write-once (CLAUDE.md rule 3).

Note the two DIFFERENT length prefixes below, which is the easiest thing to get
wrong when implementing SPEC from prose: the header frame tags each field with
its type (section 2), while the descriptor frame does not (section 4). They are
different frames serving different purposes and must not be unified.
"""

import hashlib
import json
import struct
from pathlib import Path

GENESIS = "0" * 64
FIELDS = ("seq", "ts", "hash_version", "payload_type", "payload_hash", "prev_hash")
ENCODING = "lp64"


def lp(value: str | None) -> bytes:
    """SPEC section 2: type tag inside the length-prefixed region."""
    enc = b"\x00" if value is None else b"\x01" + value.encode("utf-8")
    return struct.pack(">Q", len(enc)) + enc


def descriptor_lp(value: str) -> bytes:
    """SPEC section 4: the descriptor frame's plain length prefix, untagged."""
    enc = value.encode("utf-8")
    return struct.pack(">Q", len(enc)) + enc


def fingerprint() -> str:
    components = ("sha256", ENCODING, *FIELDS)
    frame = b"waxseal-descriptor-v1\n" + struct.pack(">Q", len(components))
    for c in components:
        frame += descriptor_lp(c)
    return hashlib.sha256(frame).hexdigest()


def entry_hash(header: dict) -> str:
    frame = b"waxseal-lp64\n" + struct.pack(">Q", 6)
    for name in FIELDS:
        frame += lp(str(header[name]))
    return hashlib.sha256(frame).hexdigest()


def main() -> None:
    fp = fingerprint()
    payloads = [b"{}", b'{"action":"tool_call","tool":"bash"}', '{"vi":"Việt"}'.encode()]
    entries = []
    prev = GENESIS
    for i, payload in enumerate(payloads):
        header = {
            "seq": i,
            "ts": f"2026-08-21T00:00:{i:02d}+00:00",
            "hash_version": fp,
            "payload_type": "application/vnd.waxseal.vector+json",
            "payload_hash": hashlib.sha256(payload).hexdigest(),
            "prev_hash": prev,
        }
        eh = entry_hash(header)
        entries.append(
            {"header": header, "payload_utf8": payload.decode("utf-8"), "entry_hash": eh}
        )
        prev = eh

    vectors = {
        "spec": "waxseal SPEC v1",
        "descriptor_fingerprint": fp,
        "encoding": ENCODING,
        "lp_examples": [
            {"input": "abc", "hex": lp("abc").hex()},
            {"input": "", "hex": lp("").hex()},
            {"input": "Việt", "hex": lp("Việt").hex()},
        ],
        "null_lp_hex": lp(None).hex(),
        "entries": entries,
    }
    out = Path(__file__).resolve().parent.parent / "tests" / "vectors" / "vectors.json"
    out.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print(f"descriptor_fingerprint = {fp}")
    print(f"sha256(vectors.json)   = {hashlib.sha256(out.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
