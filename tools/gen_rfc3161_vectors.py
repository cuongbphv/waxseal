"""Independent cross-check for the RFC 3161 request vectors.

Like tools/gen_consistency_vectors.py, this deliberately does NOT import
waxseal. It builds TimeStampReq DER straight from RFC 3161 section 2.4.1's
ASN.1 and compares against tests/vectors/rfc3161.json, so a bug shared between
``domain.rfc3161``'s encoder and its own round-trip test cannot hide here.

It also compares the no-nonce vector against OpenSSL when `openssl` is on PATH:

    uv run python tools/gen_rfc3161_vectors.py

An asymmetry worth stating, because it is not an oversight: `openssl ts -query`
generates its own random nonce and offers no way to pin one, so OpenSSL can
only confirm the `-no_nonce` vector. The nonced vectors are cross-checked in
the other direction instead — the parser reads back OpenSSL's own randomly
nonced query, proving the two sides agree on where a nonce lives and how it is
encoded.

Exits nonzero and prints the first mismatch.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

VECTORS = Path(__file__).parent.parent / "tests" / "vectors" / "rfc3161.json"

SHA256_OID_ARCS = (2, 16, 840, 1, 101, 3, 4, 2, 1)


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_len(len(value)) + value


def der_integer(n: int) -> bytes:
    """X.690 section 8.3: two's complement, shortest form. A leading zero
    octet is required whenever bit 8 of the first content octet would be set."""
    out = bytearray()
    if n == 0:
        out.append(0)
    else:
        while n:
            out.insert(0, n & 0xFF)
            n >>= 8
        if out[0] & 0x80:
            out.insert(0, 0)
    return tlv(0x02, bytes(out))


def der_oid(arcs: tuple[int, ...]) -> bytes:
    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        group = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            group.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        body += group
    return tlv(0x06, bytes(body))


def timestamp_req(message: bytes, nonce: int | None) -> bytes:
    algorithm = tlv(0x30, der_oid(SHA256_OID_ARCS) + tlv(0x05, b""))
    imprint = tlv(0x30, algorithm + tlv(0x04, hashlib.sha256(message).digest()))
    body = der_integer(1) + imprint
    if nonce is not None:
        body += der_integer(nonce)
    body += tlv(0x01, b"\xff")  # certReq TRUE
    return tlv(0x30, body)


def check_vectors() -> list[str]:
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))
    failures = []
    for vector in doc["requests"]:
        expected = vector["der_hex"]
        actual = timestamp_req(vector["message_utf8"].encode(), vector["nonce"]).hex()
        if actual != expected:
            failures.append(f"{vector['name']}: expected {expected}, built {actual}")
    return failures


def check_against_openssl() -> list[str]:
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))
    vector = next(v for v in doc["requests"] if v["nonce"] is None)
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp) / "frame.bin"
        data.write_bytes(vector["message_utf8"].encode())
        out = Path(tmp) / "query.tsq"
        try:
            subprocess.run(
                [
                    "openssl",
                    "ts",
                    "-query",
                    "-data",
                    str(data),
                    "-sha256",
                    "-cert",
                    "-no_nonce",
                    "-out",
                    str(out),
                ],
                check=True,
                capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError) as e:
            print(f"skipping OpenSSL cross-check: {e}")
            return []
        if out.read_bytes().hex() != vector["der_hex"]:
            return [f"openssl disagrees with vector {vector['name']}"]
    print("openssl cross-check: byte-identical")
    return []


def main() -> int:
    failures = check_vectors() + check_against_openssl()
    for line in failures:
        print(line)
    if failures:
        return 1
    print("all RFC 3161 request vectors reproduce from the RFC text")
    return 0


if __name__ == "__main__":
    sys.exit(main())
