"""Tests for RFC 3161 request encoding and structural token checking.

Three properties carry the weight here:

- the request bytes are frozen (tests/vectors/rfc3161.json, cross-checked
  against OpenSSL by tools/gen_rfc3161_vectors.py) — a TSA signs the imprint we
  send, so a silent change to that encoding invalidates every receipt taken
  before it;
- a token that attests *different* bytes is checked-and-false, not a format
  quibble;
- and nothing a hostile network can send makes the checker raise. The response
  crosses a trust boundary; a parser that throws on it denies the audit, which
  is exactly what an attacker who cannot forge a token would settle for.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from waxseal.domain.rfc3161 import (
    MALFORMED_TOKEN,
    NONCE_MISMATCH,
    RECEIPT_IMPRINT_MISMATCH,
    SHA256_OID,
    TIMESTAMP_REJECTED,
    UNSUPPORTED_DIGEST_ALGORITHM,
    DerError,
    _der_int,
    _der_len,
    _der_oid,
    _tlv,
    check_timestamp_resp,
    encode_timestamp_req,
    parse_timestamp_resp,
)

VECTORS_PATH = Path(__file__).parent.parent / "vectors" / "rfc3161.json"

# Write-once guard, same discipline as tests/vectors/vectors.json: a TSA
# receipt is only evidence as long as the bytes it committed to are still the
# bytes we would build today.
FROZEN_VECTORS_SHA256 = "f00341d603391ed194497f2285c5a6373a851c91a0c0d60724c8b7a5b180c765"


def vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def granted() -> tuple[bytes, bytes, dict]:
    """(response DER, the message it attests, the expected field values)."""
    vector = next(v for v in vectors()["responses"] if v["name"] == "freetsa-granted")
    return (
        base64.b64decode(vector["der_b64"]),
        vector["message_utf8"].encode(),
        vector["expect"],
    )


def rejected() -> bytes:
    vector = next(v for v in vectors()["responses"] if v["name"] == "freetsa-rejection")
    return base64.b64decode(vector["der_b64"])


# -- builders -----------------------------------------------------------------
#
# The captured response covers the happy path. Every WAY a response can be
# unreadable needs a response shaped exactly that way, and no TSA will issue
# one on request — so these assemble the nesting by hand, one knob per layer.

SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
TSTINFO_OID = "1.2.840.113549.1.9.16.1.4"


def sha256_algid() -> bytes:
    return _tlv(0x30, _der_oid(SHA256_OID) + _tlv(0x05, b""))


def message_imprint(message: bytes = b"message", *, algid: bytes | None = None) -> bytes:
    return _tlv(
        0x30,
        (sha256_algid() if algid is None else algid)
        + _tlv(0x04, hashlib.sha256(message).digest()),
    )


def tst_info(
    *,
    version: bytes | None = None,
    policy: bytes | None = None,
    imprint: bytes | None = None,
    serial: bytes | None = None,
    gen_time: bytes | None = None,
    extras: bytes = b"",
) -> bytes:
    return _tlv(
        0x30,
        (_der_int(1) if version is None else version)
        + (_der_oid("1.2.3.4.1") if policy is None else policy)
        + (message_imprint() if imprint is None else imprint)
        + (_der_int(42) if serial is None else serial)
        + (_tlv(0x18, b"20260823090000Z") if gen_time is None else gen_time)
        + extras,
    )


def signed_data(tst: bytes, *, encap: bytes | None = None, items: bytes | None = None) -> bytes:
    encapsulated = (
        _tlv(0x30, _der_oid(TSTINFO_OID) + _tlv(0xA0, _tlv(0x04, tst)))
        if encap is None
        else encap
    )
    body = _der_int(3) + _tlv(0x31, b"") + encapsulated + _tlv(0x31, b"")
    return _tlv(0x30, items if items is not None else body)


def content_info(
    sd: bytes, *, content_type: str = SIGNED_DATA_OID, content_tag: int = 0xA0
) -> bytes:
    return _tlv(0x30, _der_oid(content_type) + _tlv(content_tag, sd))


def response(token: bytes | None = None, *, status: bytes | None = None) -> bytes:
    status_info = _tlv(0x30, _der_int(0)) if status is None else status
    return _tlv(0x30, status_info + (token or b""))


def well_formed(**tst_kwargs: object) -> bytes:
    return response(content_info(signed_data(tst_info(**tst_kwargs))))  # type: ignore[arg-type]


class TestVectorsAreFrozen:
    def test_the_vector_file_has_not_changed(self) -> None:
        actual = hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest()
        assert actual == FROZEN_VECTORS_SHA256, (
            "tests/vectors/rfc3161.json changed. Frozen vectors are write-once "
            "(CLAUDE.md rule 3): add new ones, never edit these. If this failed "
            "after an encoder change, the encoder is the bug."
        )


class TestRequestEncoding:
    @pytest.mark.parametrize("vector", vectors()["requests"], ids=lambda v: v["name"])
    def test_matches_the_frozen_bytes(self, vector: dict) -> None:
        built = encode_timestamp_req(vector["message_utf8"].encode(), nonce=vector["nonce"])
        assert built.hex() == vector["der_hex"]

    def test_encoding_is_deterministic(self) -> None:
        first = encode_timestamp_req(b"hello", nonce=7)
        assert first == encode_timestamp_req(b"hello", nonce=7)

    def test_the_imprint_is_the_sha256_of_the_message(self) -> None:
        der = encode_timestamp_req(b"hello")
        assert hashlib.sha256(b"hello").digest() in der

    def test_a_nonce_with_the_high_bit_set_is_zero_padded(self) -> None:
        # X.690 section 8.3.2: without the pad, 0x80 would decode as -128 and
        # the TSA would echo back a nonce we never sent.
        der = encode_timestamp_req(b"x", nonce=0x80)
        assert bytes([0x02, 0x02, 0x00, 0x80]) in der

    def test_a_zero_nonce_is_one_byte(self) -> None:
        assert bytes([0x02, 0x01, 0x00]) in encode_timestamp_req(b"x", nonce=0)

    def test_cert_req_false_omits_the_field(self) -> None:
        # DEFAULT FALSE must be absent in DER, not encoded as 00.
        with_cert = encode_timestamp_req(b"x", cert_req=True)
        without = encode_timestamp_req(b"x", cert_req=False)
        assert len(without) == len(with_cert) - 3
        assert not without.endswith(b"\x01\x01\xff")

    def test_a_negative_nonce_is_a_caller_bug_not_a_verdict(self) -> None:
        with pytest.raises(ValueError):
            encode_timestamp_req(b"x", nonce=-1)


class TestParsingARealToken:
    def test_reads_every_field_of_the_captured_response(self) -> None:
        der, _, expect = granted()
        response = parse_timestamp_resp(der)
        assert response.status == expect["status"]
        token = response.token
        assert token is not None
        assert token.digest_algorithm == expect["digest_algorithm"] == SHA256_OID
        assert token.imprint == expect["imprint"]
        assert token.serial_number == expect["serial_number"]
        assert token.gen_time == expect["gen_time"]
        assert token.gen_time_iso == expect["gen_time_iso"]
        assert token.nonce == expect["nonce"]

    def test_the_imprint_is_the_sha256_of_the_message_we_sent(self) -> None:
        der, message, _ = granted()
        token = parse_timestamp_resp(der).token
        assert token is not None
        assert token.imprint == hashlib.sha256(message).hexdigest()

    def test_a_real_rejection_has_a_status_and_no_token(self) -> None:
        response = parse_timestamp_resp(rejected())
        assert response.status == 2
        assert response.token is None


class TestCheckedAndTrue:
    def test_the_captured_token_attests_its_message(self) -> None:
        der, message, expect = granted()
        assert check_timestamp_resp(der, message, expected_nonce=expect["nonce"]) is None

    def test_the_nonce_check_is_opt_in(self) -> None:
        der, message, _ = granted()
        assert check_timestamp_resp(der, message) is None


class TestCheckedAndFalse:
    """These are the only reasons that mean "this token is wrong about the
    bytes next to it". Everything in TestUnreadable means "this build could not
    read it", which is a different verdict and a different exit code."""

    def test_a_token_for_other_bytes_is_a_mismatch(self) -> None:
        der, _, _ = granted()
        assert check_timestamp_resp(der, b"different bytes") == RECEIPT_IMPRINT_MISMATCH

    def test_a_replayed_token_is_caught_by_the_nonce(self) -> None:
        der, message, expect = granted()
        assert (
            check_timestamp_resp(der, message, expected_nonce=expect["nonce"] + 1)
            == NONCE_MISMATCH
        )

    def test_a_rejection_is_reported_as_a_rejection(self) -> None:
        assert check_timestamp_resp(rejected(), b"anything") == TIMESTAMP_REJECTED

    def test_no_reason_ever_says_tampered(self) -> None:
        der, message, expect = granted()
        reasons = [
            check_timestamp_resp(der, b"other"),
            check_timestamp_resp(der, message, expected_nonce=expect["nonce"] + 1),
            check_timestamp_resp(rejected(), b"x"),
            check_timestamp_resp(b"", b"x"),
        ]
        assert all(r is not None and "tamper" not in r for r in reasons)


class TestUnreadable:
    def test_empty_input(self) -> None:
        assert check_timestamp_resp(b"", b"x") == MALFORMED_TOKEN

    @pytest.mark.parametrize("cut", [1, 2, 3, 8, 50, 200, 1000, 4000, 4635])
    def test_every_truncation_is_a_verdict_not_a_crash(self, cut: int) -> None:
        der, message, _ = granted()
        assert check_timestamp_resp(der[:cut], message) == MALFORMED_TOKEN

    def test_trailing_bytes_after_a_valid_response_are_refused(self) -> None:
        # A parser that stops at the end of the outer SEQUENCE lets an
        # attacker append a second, different token that some other tool reads.
        der, message, _ = granted()
        assert check_timestamp_resp(der + b"\x00", message) == MALFORMED_TOKEN

    def test_indefinite_length_is_refused(self) -> None:
        assert check_timestamp_resp(b"\x30\x80\x00\x00", b"x") == MALFORMED_TOKEN

    def test_an_absurd_length_field_is_refused(self) -> None:
        assert check_timestamp_resp(b"\x30\x85\x01\x02\x03\x04\x05", b"x") == MALFORMED_TOKEN

    def test_a_length_running_past_the_buffer_is_refused(self) -> None:
        assert check_timestamp_resp(b"\x30\x7f\x01", b"x") == MALFORMED_TOKEN

    def test_high_tag_number_form_is_refused(self) -> None:
        assert check_timestamp_resp(b"\x3f\x01\x00", b"x") == MALFORMED_TOKEN

    def test_a_status_only_response_with_a_granted_status_is_still_unreadable(self) -> None:
        # status 0 with no token: nothing to check, and calling that a pass
        # would report a timestamp nobody issued.
        der = bytes([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00])
        assert check_timestamp_resp(der, b"x") == MALFORMED_TOKEN

    def test_a_genTime_without_a_trailing_z_is_unreadable(self) -> None:
        der, message, _ = granted()
        _, _, expect = granted()
        broken = der.replace(
            expect["gen_time"].encode(), expect["gen_time"][:-1].encode() + b"+"
        )
        assert broken != der
        assert check_timestamp_resp(broken, message) == MALFORMED_TOKEN

    def test_an_impossible_genTime_is_unreadable(self) -> None:
        der, message, _ = granted()
        _, _, expect = granted()
        broken = der.replace(expect["gen_time"].encode(), b"20261332192217Z")
        assert broken != der
        assert check_timestamp_resp(broken, message) == MALFORMED_TOKEN

    @settings(max_examples=300, deadline=None)
    @given(st.binary(max_size=600))
    def test_arbitrary_bytes_never_raise_and_never_say_tampered(self, blob: bytes) -> None:
        reason = check_timestamp_resp(blob, b"message")
        assert reason is None or "tamper" not in reason


class TestBuiltTokens:
    """The builders assemble the same nesting the captured token has, so a
    passing baseline proves the malformation tests below actually isolate the
    one thing each of them breaks."""

    def test_a_hand_built_token_checks_out(self) -> None:
        assert check_timestamp_resp(well_formed(), b"message") is None

    def test_a_token_using_another_digest_is_unsupported(self) -> None:
        # Built rather than captured: no public TSA will issue a SHA-1 token
        # today, and the reason still has to exist for the ones that did. The
        # digest bytes are never compared — the OID decides first.
        sha1 = _tlv(0x30, _der_oid("1.3.14.3.2.26") + _tlv(0x05, b""))
        imprint = _tlv(0x30, sha1 + _tlv(0x04, b"\x11" * 20))
        der = well_formed(imprint=imprint)
        assert check_timestamp_resp(der, b"message") == UNSUPPORTED_DIGEST_ALGORITHM

    def test_absent_algorithm_parameters_are_accepted(self) -> None:
        # NULL and absent are both seen in the wild for SHA-2 AlgorithmIdentifier.
        # Treating one encoding as a failure is migration-060 in miniature.
        algid = _tlv(0x30, _der_oid(SHA256_OID))
        der = well_formed(imprint=message_imprint(algid=algid))
        assert check_timestamp_resp(der, b"message") is None

    def test_accuracy_and_ordering_before_the_nonce_are_skipped(self) -> None:
        extras = _tlv(0x30, _der_int(1)) + _tlv(0x01, b"\xff") + _der_int(99)
        token = parse_timestamp_resp(well_formed(extras=extras)).token
        assert token is not None and token.nonce == 99

    def test_a_tsa_field_ends_the_nonce_search(self) -> None:
        # [0] tsa and [1] extensions both follow nonce in TSTInfo. Reading an
        # INTEGER past them would pick up an unrelated value and call it a nonce.
        token = parse_timestamp_resp(well_formed(extras=_tlv(0xA0, _der_int(7)))).token
        assert token is not None and token.nonce is None

    def test_extensions_also_end_the_nonce_search(self) -> None:
        token = parse_timestamp_resp(well_formed(extras=_tlv(0xA1, _der_int(7)))).token
        assert token is not None and token.nonce is None

    def test_fractional_seconds_survive_into_the_iso_timestamp(self) -> None:
        der = well_formed(gen_time=_tlv(0x18, b"20260823090000.123Z"))
        token = parse_timestamp_resp(der).token
        assert token is not None
        assert token.gen_time_iso == "2026-08-23T09:00:00.123+00:00"


class TestEveryWayAResponseCanBeUnreadable:
    """One case per DER shape the walk refuses. Each is a format the parser
    cannot read — exit 2 territory — never a claim that anything was forged."""

    def cases() -> list[tuple[str, bytes]]:  # type: ignore[misc]  # noqa: N805
        return [
            ("status is not an INTEGER", response(status=_tlv(0x30, _tlv(0x04, b"\x00")))),
            ("PKIStatusInfo is empty", response(status=_tlv(0x30, b""))),
            ("PKIStatusInfo is not a SEQUENCE", response(status=_tlv(0x04, b"\x00"))),
            ("status INTEGER is empty", response(status=_tlv(0x30, _tlv(0x02, b"")))),
            (
                "a third top-level element",
                _tlv(0x30, _tlv(0x30, _der_int(0)) + content_info(signed_data(tst_info()))
                     + _der_int(1)),
            ),
            (
                "ContentInfo has one element",
                response(_tlv(0x30, _der_oid(SIGNED_DATA_OID))),
            ),
            (
                "contentType is not signedData",
                response(content_info(signed_data(tst_info()), content_type="1.2.3.4")),
            ),
            (
                "content is not [0] EXPLICIT",
                response(content_info(signed_data(tst_info()), content_tag=0xA1)),
            ),
            (
                "SignedData is too short",
                response(content_info(signed_data(tst_info(), items=_der_int(3)))),
            ),
            (
                "encapContentInfo has no eContent",
                response(content_info(signed_data(tst_info(), encap=_tlv(0x30, _der_oid(
                    TSTINFO_OID))))),
            ),
            (
                "eContentType is not TSTInfo",
                response(content_info(signed_data(tst_info(), encap=_tlv(
                    0x30, _der_oid("1.2.3.4") + _tlv(0xA0, _tlv(0x04, tst_info())))))),
            ),
            (
                "eContent is not [0] EXPLICIT",
                response(content_info(signed_data(tst_info(), encap=_tlv(
                    0x30, _der_oid(TSTINFO_OID) + _tlv(0xA1, _tlv(0x04, tst_info())))))),
            ),
            (
                "eContent is not an OCTET STRING",
                response(content_info(signed_data(tst_info(), encap=_tlv(
                    0x30, _der_oid(TSTINFO_OID) + _tlv(0xA0, _tlv(0x30, tst_info())))))),
            ),
            ("TSTInfo is missing fields", well_formed(gen_time=b"")),
            ("version is not an INTEGER", well_formed(version=_tlv(0x04, b"\x01"))),
            ("policy is not an OID", well_formed(policy=_tlv(0x02, b"\x01"))),
            ("messageImprint is not a SEQUENCE", well_formed(imprint=_tlv(0x04, b"\x00"))),
            (
                "messageImprint is missing a field",
                well_formed(imprint=_tlv(0x30, sha256_algid())),
            ),
            (
                "hashAlgorithm is empty",
                well_formed(imprint=_tlv(0x30, _tlv(0x30, b"") + _tlv(0x04, b"\x00"))),
            ),
            (
                "hashedMessage is not an OCTET STRING",
                well_formed(imprint=_tlv(0x30, sha256_algid() + _tlv(0x0C, b"x"))),
            ),
            ("serialNumber is not an INTEGER", well_formed(serial=_tlv(0x04, b"\x2a"))),
            ("genTime is not a GeneralizedTime", well_formed(gen_time=_tlv(0x04, b"x"))),
            ("genTime is not ASCII", well_formed(gen_time=_tlv(0x18, b"\xff" * 15))),
            ("genTime is the wrong length", well_formed(gen_time=_tlv(0x18, b"2026Z"))),
            (
                "genTime has a non-numeric fraction",
                well_formed(gen_time=_tlv(0x18, b"20260823090000.abcZ")),
            ),
            ("an OID ends mid-arc", well_formed(policy=_tlv(0x06, b"\x2a\x86"))),
            ("an empty OID", well_formed(policy=_tlv(0x06, b""))),
        ]

    @pytest.mark.parametrize(
        ("name", "der"), cases(), ids=lambda v: v if isinstance(v, str) else ""
    )
    def test_is_a_verdict_not_a_crash(self, name: str, der: bytes) -> None:
        assert check_timestamp_resp(der, b"message") == MALFORMED_TOKEN, name


class TestDerPrimitives:
    def test_long_form_lengths(self) -> None:
        # No TimeStampReq this library builds is long enough to need one, so
        # the encoder's long form is only ever exercised here — and it still
        # has to be right, because "0x81 0x80" and "0x80" differ by a whole
        # BER indefinite-length parse.
        assert _der_len(0x7F) == b"\x7f"
        assert _der_len(0x80) == b"\x81\x80"
        assert _der_len(0x1234) == b"\x82\x12\x34"

    def test_oid_round_trip_through_multibyte_arcs(self) -> None:
        der = _der_oid("1.2.840.113549.1.9.16.1.4")
        assert parse_timestamp_resp(well_formed(policy=der)) is not None
        assert der.hex() == "060b2a864886f70d0109100104"

    def test_a_response_that_is_not_a_sequence_is_refused(self) -> None:
        assert check_timestamp_resp(_tlv(0x04, b"\x00"), b"x") == MALFORMED_TOKEN


class TestParseRaisesForCallersThatWantIt:
    def test_parse_is_the_strict_door_check_is_the_tolerant_one(self) -> None:
        with pytest.raises(DerError):
            parse_timestamp_resp(b"\x30\x80")


class TestReceiptFraming:
    """The prefix is how a reader dispatches on receipt type. Getting it wrong
    means feeding a calendar proof to a DER parser and calling the result a
    verdict."""

    def test_round_trips(self) -> None:
        from waxseal.domain.rfc3161 import RECEIPT_PREFIX, decode_receipt, encode_receipt

        der, _, _ = granted()
        receipt = encode_receipt(der)
        assert receipt.startswith(RECEIPT_PREFIX)
        assert decode_receipt(receipt) == der

    def test_another_sinks_receipt_is_not_decoded_here(self) -> None:
        from waxseal.domain.rfc3161 import decode_receipt

        assert decode_receipt("ots:AAAA") is None

    def test_base64_this_build_cannot_decode_reads_as_not_readable(self) -> None:
        from waxseal.domain.rfc3161 import decode_receipt

        assert decode_receipt("rfc3161:!!! not base64 !!!") is None
