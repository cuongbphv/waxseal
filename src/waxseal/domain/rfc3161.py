"""RFC 3161 timestamping: request encoding and STRUCTURAL token checking.

A checkpoint's ``ts`` is asserted by whoever wrote it. A Time-Stamp Authority's
token is asserted by somebody else — which is the whole value: it moves the
time claim into a different administrative authority, the same move anchoring
makes for the chain root.

What this module does and does not do
-------------------------------------
It encodes a TimeStampReq (RFC 3161 section 2.4.1) and parses a TimeStampResp
far enough to answer one question: *does this token attest the bytes we asked
it to attest?* It compares the token's messageImprint against a locally
recomputed SHA-256, its status, and its nonce.

It does **not** verify the CMS signature or the TSA's certificate chain. That
needs X.509 path validation and RSA/ECDSA verification, which a zero-dependency
library has no business reimplementing — a homegrown signature check that is
subtly wrong is worse than no check, because it reports authenticity nobody
established. Delegate it::

    openssl ts -verify -in receipt.tsr -data frame.bin -CAfile tsa-chain.pem

So a passing structural check means "this token is well-formed and commits to
these exact bytes", never "this token is genuine". Every output line that
reports it must say so.

Failure vocabulary
------------------
``check_timestamp_resp`` returns a reason string or None, and NEVER raises, on
any RESPONSE bytes whatsoever — the response arrives over the network from a
party outside our trust boundary, and a parser that crashes on it denies the
audit. The hardening covers ``der`` only: ``expected_message`` is supplied by
the caller, not the network, and passing a non-bytes value for it is an
ordinary programming error that surfaces as TypeError.
No reason contains the word "tamper": bytes this build cannot read are
unverifiable by name (RFC 6962 section 4.6), which is a different verdict from
bytes that were checked and found false. The two reasons that ARE
checked-and-false — ``receipt_imprint_mismatch`` and ``nonce_mismatch`` — say
the token attests something other than what sits next to it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

# How a token is carried in an `.anchors` record's `receipt` field. The prefix
# is what lets a reader dispatch on receipt type without guessing from the
# bytes — an unknown prefix stays unverifiable-by-name instead of being
# force-fed to whichever parser happens to be first.
RECEIPT_PREFIX: Final = "rfc3161:"

SHA256_OID: Final = "2.16.840.1.101.3.4.2.1"
_OID_SIGNED_DATA: Final = "1.2.840.113549.1.7.2"
_OID_TSTINFO: Final = "1.2.840.113549.1.9.16.1.4"

# granted(0) and grantedWithMods(1) both carry a usable token; RFC 3161
# section 2.4.2 gives every other value no token at all.
_ACCEPTED_STATUS: Final = frozenset({0, 1})

MALFORMED_TOKEN: Final = "malformed_token"
TIMESTAMP_REJECTED: Final = "timestamp_rejected"
RECEIPT_IMPRINT_MISMATCH: Final = "receipt_imprint_mismatch"
NONCE_MISMATCH: Final = "nonce_mismatch"
UNSUPPORTED_DIGEST_ALGORITHM: Final = "unsupported_digest_algorithm"

_TAG_BOOLEAN: Final = 0x01
_TAG_INTEGER: Final = 0x02
_TAG_OCTET_STRING: Final = 0x04
_TAG_NULL: Final = 0x05
_TAG_OID: Final = 0x06
_TAG_SEQUENCE: Final = 0x30
_TAG_GENERALIZED_TIME: Final = 0x18
_TAG_CONTEXT_0: Final = 0xA0
_TAG_CONTEXT_1: Final = 0xA1


class DerError(ValueError):
    """Malformed DER. Callers at a trust boundary turn this into a verdict."""


# -- encoding ----------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_int(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative INTEGER is not used anywhere in this profile")
    # One extra byte whenever the top bit would otherwise read as a sign bit,
    # which is why a nonce of 0x80 is three bytes and 0x7f is two.
    body = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return _tlv(_TAG_INTEGER, body)


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = bytearray([part & 0x7F])
        part >>= 7
        while part:
            chunk.insert(0, (part & 0x7F) | 0x80)
            part >>= 7
        body += chunk
    return _tlv(_TAG_OID, bytes(body))


_SHA256_ALGID: Final = _tlv(_TAG_SEQUENCE, _der_oid(SHA256_OID) + _tlv(_TAG_NULL, b""))


def encode_timestamp_req(
    message: bytes, *, nonce: int | None = None, cert_req: bool = True
) -> bytes:
    """DER TimeStampReq committing to ``sha256(message)``.

    ``nonce`` is injected rather than generated here: the domain layer owns no
    entropy (CLAUDE.md rule 8's sibling — a test must be able to freeze it, and
    the byte layout must be reproducible). Callers that want replay protection
    pass one and check it back on the response. ``nonce=None`` omits the field.

    ``cert_req`` defaults True, asking the TSA to include its certificates in
    the token. This library never reads them (see the module docstring), but
    whoever runs ``openssl ts -verify`` later needs them present, and a token
    issued without them cannot gain them afterwards.
    """
    imprint = _tlv(
        _TAG_SEQUENCE,
        _SHA256_ALGID + _tlv(_TAG_OCTET_STRING, hashlib.sha256(message).digest()),
    )
    body = _der_int(1) + imprint
    if nonce is not None:
        body += _der_int(nonce)
    if cert_req:
        # DEFAULT FALSE, so DER requires the field be omitted when false.
        body += _tlv(_TAG_BOOLEAN, b"\xff")
    return _tlv(_TAG_SEQUENCE, body)


# -- parsing -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Tlv:
    tag: int
    value: bytes


def _read_tlv(buf: bytes, offset: int) -> tuple[_Tlv, int]:
    if offset + 2 > len(buf):
        raise DerError("truncated tag/length")
    tag = buf[offset]
    if tag & 0x1F == 0x1F:
        raise DerError("high-tag-number form is not part of this profile")
    length = buf[offset + 1]
    offset += 2
    if length == 0x80:
        raise DerError("indefinite length is BER, not DER")
    if length & 0x80:
        count = length & 0x7F
        if count > 4:
            raise DerError("length field too large")
        if offset + count > len(buf):
            raise DerError("truncated length")
        length = int.from_bytes(buf[offset : offset + count], "big")
        offset += count
    if offset + length > len(buf):
        raise DerError("value runs past the end of the buffer")
    return _Tlv(tag, buf[offset : offset + length]), offset + length


def _read_all(buf: bytes) -> list[_Tlv]:
    items: list[_Tlv] = []
    offset = 0
    while offset < len(buf):
        item, offset = _read_tlv(buf, offset)
        items.append(item)
    return items


def _read_one(buf: bytes) -> _Tlv:
    items = _read_all(buf)
    if len(items) != 1:
        raise DerError(f"expected exactly one element, found {len(items)}")
    return items[0]


def _sequence(tlv: _Tlv, *, what: str) -> list[_Tlv]:
    if tlv.tag != _TAG_SEQUENCE:
        raise DerError(f"{what}: expected SEQUENCE, got tag 0x{tlv.tag:02x}")
    return _read_all(tlv.value)


def _integer(tlv: _Tlv, *, what: str) -> int:
    if tlv.tag != _TAG_INTEGER:
        raise DerError(f"{what}: expected INTEGER, got tag 0x{tlv.tag:02x}")
    if not tlv.value:
        raise DerError(f"{what}: empty INTEGER")
    return int.from_bytes(tlv.value, "big", signed=True)


def _oid(tlv: _Tlv, *, what: str) -> str:
    if tlv.tag != _TAG_OID or not tlv.value:
        raise DerError(f"{what}: expected OBJECT IDENTIFIER")
    first = tlv.value[0]
    root = min(first // 40, 2)
    parts = [str(root), str(first - 40 * root)]
    acc = 0
    pending = False
    for byte in tlv.value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        pending = True
        if not byte & 0x80:
            parts.append(str(acc))
            acc = 0
            pending = False
    if pending:
        raise DerError(f"{what}: OID ends mid-arc")
    return ".".join(parts)


def _generalized_time_to_iso(raw: str) -> str:
    """RFC 3161 section 2.4.2 pins genTime to UTC with a trailing Z. Anything
    else is a token this build will not date."""
    if not raw.endswith("Z"):
        raise DerError("genTime must be UTC (trailing Z)")
    body = raw[:-1]
    fraction = ""
    if "." in body:
        body, fraction = body.split(".", 1)
        if not fraction.isdigit():
            raise DerError("genTime has a non-numeric fraction")
    if len(body) != 14 or not body.isdigit():
        raise DerError("genTime is not YYYYMMDDHHMMSS")
    try:
        moment = datetime.strptime(body, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError as e:
        raise DerError(f"genTime is not a real instant: {e}") from e
    stamp = moment.isoformat()
    return stamp if not fraction else f"{stamp[:19]}.{fraction}{stamp[19:]}"


@dataclass(frozen=True, slots=True)
class TimestampToken:
    """The fields of a TSTInfo this library reads. Certificates and
    signerInfos are skipped over as opaque — see the module docstring."""

    digest_algorithm: str
    imprint: str
    serial_number: int
    gen_time: str
    gen_time_iso: str
    nonce: int | None = None


@dataclass(frozen=True, slots=True)
class TimestampResponse:
    status: int
    token: TimestampToken | None = None


def _parse_tst_info(tst: list[_Tlv]) -> TimestampToken:
    if len(tst) < 5:
        raise DerError("TSTInfo is missing required fields")
    _integer(tst[0], what="TSTInfo.version")
    _oid(tst[1], what="TSTInfo.policy")

    imprint = _sequence(tst[2], what="TSTInfo.messageImprint")
    if len(imprint) < 2:
        raise DerError("messageImprint is missing a field")
    algid = _sequence(imprint[0], what="messageImprint.hashAlgorithm")
    if not algid:
        raise DerError("hashAlgorithm is empty")
    # Parameters (NULL, absent, or anything else) are ignored on purpose: which
    # of the permitted encodings a TSA picked is a format variant, and treating
    # a variant as a failure is the migration-060 mistake in miniature.
    digest_algorithm = _oid(algid[0], what="hashAlgorithm.algorithm")
    if imprint[1].tag != _TAG_OCTET_STRING:
        raise DerError("hashedMessage is not an OCTET STRING")

    if tst[4].tag != _TAG_GENERALIZED_TIME:
        raise DerError("genTime is not a GeneralizedTime")
    try:
        gen_time = tst[4].value.decode("ascii")
    except UnicodeDecodeError as e:
        raise DerError("genTime is not ASCII") from e

    nonce: int | None = None
    for extra in tst[5:]:
        # accuracy (SEQUENCE) and ordering (BOOLEAN) may precede the nonce;
        # tsa [0] and extensions [1] follow it, so either one ends the search.
        if extra.tag == _TAG_INTEGER:
            nonce = _integer(extra, what="TSTInfo.nonce")
            break
        if extra.tag in (_TAG_CONTEXT_0, _TAG_CONTEXT_1):
            break

    return TimestampToken(
        digest_algorithm=digest_algorithm,
        imprint=imprint[1].value.hex(),
        serial_number=_integer(tst[3], what="TSTInfo.serialNumber"),
        gen_time=gen_time,
        gen_time_iso=_generalized_time_to_iso(gen_time),
        nonce=nonce,
    )


def _parse_token(content_info: _Tlv) -> TimestampToken:
    parts = _sequence(content_info, what="ContentInfo")
    if len(parts) != 2:
        raise DerError("ContentInfo must hold contentType and content")
    if _oid(parts[0], what="ContentInfo.contentType") != _OID_SIGNED_DATA:
        raise DerError("timeStampToken is not a CMS SignedData")
    if parts[1].tag != _TAG_CONTEXT_0:
        raise DerError("ContentInfo.content is not [0] EXPLICIT")

    signed_data = _sequence(_read_one(parts[1].value), what="SignedData")
    if len(signed_data) < 3:
        raise DerError("SignedData is missing encapContentInfo")
    encap = _sequence(signed_data[2], what="EncapsulatedContentInfo")
    if len(encap) < 2:
        raise DerError("EncapsulatedContentInfo carries no eContent")
    if _oid(encap[0], what="eContentType") != _OID_TSTINFO:
        raise DerError("encapsulated content is not a TSTInfo")
    if encap[1].tag != _TAG_CONTEXT_0:
        raise DerError("eContent is not [0] EXPLICIT")

    octets = _read_one(encap[1].value)
    if octets.tag != _TAG_OCTET_STRING:
        raise DerError("eContent is not an OCTET STRING")
    return _parse_tst_info(_sequence(_read_one(octets.value), what="TSTInfo"))


def parse_timestamp_resp(der: bytes) -> TimestampResponse:
    """Parse a TimeStampResp. Raises DerError on anything it cannot read;
    ``check_timestamp_resp`` is the boundary that turns that into a verdict."""
    items = _sequence(_read_one(der), what="TimeStampResp")
    if not items or len(items) > 2:
        raise DerError("TimeStampResp must hold a status and at most a token")
    status_info = _sequence(items[0], what="PKIStatusInfo")
    if not status_info:
        raise DerError("PKIStatusInfo is empty")
    status = _integer(status_info[0], what="PKIStatusInfo.status")
    if len(items) == 1:
        return TimestampResponse(status=status)
    return TimestampResponse(status=status, token=_parse_token(items[1]))


def read_timestamp_resp(
    der: bytes, expected_message: bytes, *, expected_nonce: int | None = None
) -> tuple[TimestampToken | None, str | None]:
    """``(token, reason)``: the token when it structurally attests
    ``expected_message``, otherwise None and a reason. Never raises — see the
    module docstring.

    Callers that want to PRINT the attested time need the token as well as the
    verdict, and parsing twice to get both would let the two readings drift.
    """
    try:
        response = parse_timestamp_resp(der)
    except Exception:
        # Deliberately broad. Every byte here came from outside the trust
        # boundary, and an unanticipated exception type reaching the caller
        # would take the audit down instead of producing a verdict.
        return (None, MALFORMED_TOKEN)
    if response.status not in _ACCEPTED_STATUS:
        return (None, TIMESTAMP_REJECTED)
    token = response.token
    if token is None:
        return (None, MALFORMED_TOKEN)
    if token.digest_algorithm != SHA256_OID:
        return (None, UNSUPPORTED_DIGEST_ALGORITHM)
    if token.imprint != hashlib.sha256(expected_message).hexdigest():
        return (None, RECEIPT_IMPRINT_MISMATCH)
    if expected_nonce is not None and token.nonce != expected_nonce:
        return (None, NONCE_MISMATCH)
    return (token, None)


def check_timestamp_resp(
    der: bytes, expected_message: bytes, *, expected_nonce: int | None = None
) -> str | None:
    """None when the token structurally attests ``expected_message``, else a
    reason. Never raises — see the module docstring."""
    return read_timestamp_resp(der, expected_message, expected_nonce=expected_nonce)[1]


def encode_receipt(der: bytes) -> str:
    """Wrap a TimeStampResp for storage in an anchor record's ``receipt``."""
    return RECEIPT_PREFIX + base64.b64encode(der).decode("ascii")


def decode_receipt(receipt: str) -> bytes | None:
    """The DER inside an ``rfc3161:`` receipt, or None when the string is not
    one — wrong prefix, or base64 this build cannot decode. None is "not
    readable here", never "the token is false"; the caller reports it as
    unverifiable and leaves the record alone."""
    if not receipt.startswith(RECEIPT_PREFIX):
        return None
    try:
        return base64.b64decode(receipt[len(RECEIPT_PREFIX) :], validate=True)
    except (binascii.Error, ValueError):
        return None
