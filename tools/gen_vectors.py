"""Golden vector generator — an INDEPENDENT implementation of SPEC.md.

Deliberately does NOT import waxseal: it re-implements sections 2-4 straight
from the SPEC prose, so the vectors cross-check the library instead of echoing
it. Run once to freeze tests/vectors/vectors.json; frozen vectors are
write-once (CLAUDE.md rule 3).
"""

import hashlib
import json
import struct
from pathlib import Path

GENESIS = "0" * 64
FIELDS = ("seq", "ts", "hash_version", "payload_type", "payload_hash", "prev_hash")


def lp(value: str) -> bytes:
    enc = value.encode("utf-8")
    return struct.pack(">Q", len(enc)) + enc


def fingerprint() -> str:
    components = ("sha256", "lp64v1", *FIELDS)
    frame = b"waxseal-descriptor-v1\n" + struct.pack(">Q", len(components))
    for c in components:
        frame += lp(c)
    return hashlib.sha256(frame).hexdigest()


def entry_hash(header: dict) -> str:
    frame = b"waxseal-v1\n" + struct.pack(">Q", 6)
    for name in FIELDS:
        frame += lp(str(header[name]))
    return hashlib.sha256(frame).hexdigest()


def main() -> None:
    fp = fingerprint()
    payloads = [b"{}", b'{"action":"tool_call","tool":"bash"}', "{\"vi\":\"Việt\"}".encode()]
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
        "lp_examples": [
            {"input": "abc", "hex": lp("abc").hex()},
            {"input": "", "hex": lp("").hex()},
            {"input": "Việt", "hex": lp("Việt").hex()},
        ],
        "null_sentinel_lp_hex": (struct.pack(">Q", 6) + b"\x00NULL\x00").hex(),
        "entries": entries,
    }
    out = Path(__file__).parent.parent / "tests" / "vectors" / "vectors.json"
    out.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out} (fingerprint {fp})")


if __name__ == "__main__":
    main()
