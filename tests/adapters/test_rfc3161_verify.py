"""The `rfc3161` extra's signature dimension: three answers, never two.

`domain/rfc3161.py` answers "does this token COMMIT to these bytes?" with no
dependencies, and says in its own docstring that it verifies neither the CMS
signature nor the certificate chain. This module's subject answers the other
question -- "was it signed by a TSA the operator named?" -- and its whole
reason for existing is that the answer has THREE values:

  valid      checked, holds.
  invalid    CHECKED, definite no. Verdict.BROKEN, exit 1.
  unchecked  never actually asked: extra absent, no CA bundle named, or a
             token shape this build cannot read. Verdict.UNVERIFIABLE, exit 2.

The test that matters most is the third one. An absent extra that quietly
comes back "valid" (or, at the CLI, exit 0) is false confidence -- the same
collapse "beads v1.2.2" shipped -- so `test_the_absent_extra_is_unchecked...`
carries a falsifiability receipt in its own docstring.

The vectors are minted here rather than frozen under `tests/vectors/`: they
carry freshly generated private keys, so a frozen copy would be a checked-in
key, and nothing in SPEC.md pins the CMS bytes (section 17 pins the REQUEST,
which `tests/vectors/rfc3161.json` already freezes).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from waxseal.adapters.rfc3161_verify import (
    SIGNATURE_INVALID,
    SIGNATURE_UNCHECKED,
    SIGNATURE_VALID,
    verify_token_signature,
)
from waxseal.domain.rfc3161 import SHA256_OID, _der_int, _der_oid, _tlv
from waxseal.domain.verdict import Verdict

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_SHA1 = "1.3.14.3.2.26"

MESSAGE = b"a checkpoint frame"


# -- minting ----------------------------------------------------------------


def issue(
    common_name: str,
    *,
    issuer_key: Any = None,
    issuer_name: x509.Name | None = None,
    ca: bool = False,
    key: Any = None,
) -> tuple[Any, x509.Certificate]:
    """A self-signed root, or a certificate issued by ``issuer_key``.

    EC by default: the branch-coverage tests build chains several links long
    and RSA key generation would make them cost seconds apiece.
    """
    key = key if key is not None else ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    not_before = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    signing_key = issuer_key if issuer_key is not None else key
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name if issuer_name is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        # Ed25519 takes no hash algorithm; every other key here does.
        .sign(
            signing_key,
            None if isinstance(signing_key, ed25519.Ed25519PrivateKey) else hashes.SHA256(),
        )
    )
    return key, cert


def tst_info(message: bytes) -> bytes:
    algid = _tlv(0x30, _der_oid(SHA256_OID) + _tlv(0x05, b""))
    imprint = _tlv(0x30, algid + _tlv(0x04, hashlib.sha256(message).digest()))
    return _tlv(
        0x30,
        _der_int(1)
        + _der_oid("1.2.3.4.1")
        + imprint
        + _der_int(7)
        + _tlv(0x18, b"20260823090000Z"),
    )


def signed_attrs(tst: bytes, *, digest: bytes | None = None) -> bytes:
    """The [0] IMPLICIT value bytes. What is SIGNED is the same bytes under an
    explicit SET tag (RFC 5652 section 5.4), which is why the adapter re-tags
    them rather than hashing what it found."""
    digest = hashlib.sha256(tst).digest() if digest is None else digest
    return _tlv(0x30, _der_oid(OID_CONTENT_TYPE) + _tlv(0x31, _der_oid(OID_TSTINFO))) + _tlv(
        0x30, _der_oid(OID_MESSAGE_DIGEST) + _tlv(0x31, _tlv(0x04, digest))
    )


def signer_info(
    *,
    cert: x509.Certificate,
    attrs: bytes | None,
    signature: bytes,
    sig_alg_oid: str = OID_ECDSA_SHA256,
    digest_alg_oid: str = SHA256_OID,
    sid: bytes | None = None,
) -> bytes:
    if sid is None:
        sid = _tlv(0x30, cert.issuer.public_bytes() + _der_int(cert.serial_number))
    body = _der_int(1) + sid + _tlv(0x30, _der_oid(digest_alg_oid) + _tlv(0x05, b""))
    if attrs is not None:
        body += _tlv(0xA0, attrs)
    body += _tlv(0x30, _der_oid(sig_alg_oid) + _tlv(0x05, b"")) + _tlv(0x04, signature)
    return _tlv(0x30, body)


def response(
    *,
    tst: bytes,
    signer_infos: bytes,
    certs: Sequence[x509.Certificate] = (),
    raw_certs: bytes = b"",
    extra: bytes = b"",
    econtent: bytes | None = None,
) -> bytes:
    der_certs = b"".join(c.public_bytes(serialization.Encoding.DER) for c in certs) + raw_certs
    signed_data = _tlv(
        0x30,
        _der_int(3)
        + _tlv(0x31, _tlv(0x30, _der_oid(SHA256_OID) + _tlv(0x05, b"")))
        + _tlv(
            0x30,
            _der_oid(OID_TSTINFO) + _tlv(0xA0, _tlv(0x04, tst) if econtent is None else econtent),
        )
        + (_tlv(0xA0, der_certs) if der_certs else b"")
        + extra
        + _tlv(0x31, signer_infos),
    )
    token = _tlv(0x30, _der_oid(OID_SIGNED_DATA) + _tlv(0xA0, signed_data))
    return _tlv(0x30, _tlv(0x30, _der_int(0)) + token)


def signed_token(
    *,
    key: Any,
    cert: x509.Certificate,
    certs: Sequence[x509.Certificate] | None = None,
    message: bytes = MESSAGE,
    wrong_signature: bool = False,
    attr_digest: bytes | None = None,
    rsa_key: bool = False,
    raw_certs: bytes = b"",
    extra: bytes = b"",
    **signer_info_kwargs: Any,
) -> bytes:
    """A TimeStampResp whose CMS SignedData is genuinely signed by ``key``."""
    tst = tst_info(message)
    attrs = signed_attrs(tst, digest=attr_digest)
    to_sign = _tlv(0x31, attrs)
    # A signature over DIFFERENT bytes, never a corrupted DER blob: the point
    # is a well-formed signature that does not verify (invalid), not one the
    # library cannot parse (which would be unchecked).
    signed_bytes = to_sign + b"!" if wrong_signature else to_sign
    if rsa_key:
        signature = key.sign(signed_bytes, padding.PKCS1v15(), hashes.SHA256())
        signer_info_kwargs.setdefault("sig_alg_oid", OID_SHA256_RSA)
    else:
        signature = key.sign(signed_bytes, ec.ECDSA(hashes.SHA256()))
    return response(
        tst=tst,
        signer_infos=signer_info(cert=cert, attrs=attrs, signature=signature, **signer_info_kwargs),
        certs=list(certs) if certs is not None else [cert],
        raw_certs=raw_certs,
        extra=extra,
    )


def ca_bundle(tmp_path: Path, *certs: x509.Certificate, name: str = "ca.pem") -> Path:
    path = tmp_path / name
    path.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs))
    return path


@pytest.fixture
def tsa(tmp_path: Path) -> tuple[bytes, Path]:
    """A token signed by a leaf whose root is in the bundle the fixture writes."""
    ca_key, ca_cert = issue("waxseal test root", ca=True)
    leaf_key, leaf_cert = issue("waxseal test TSA", issuer_key=ca_key, issuer_name=ca_cert.subject)
    return signed_token(key=leaf_key, cert=leaf_cert), ca_bundle(tmp_path, ca_cert)


# -- the three states -------------------------------------------------------


class TestValid:
    def test_a_token_signed_by_the_named_anchor_is_valid(self, tsa: tuple[bytes, Path]) -> None:
        der, ca_file = tsa
        check = verify_token_signature(der, ca_file=ca_file)
        assert check.state == SIGNATURE_VALID
        assert check.verdict is Verdict.OK

    def test_the_valid_label_still_names_what_was_not_checked(
        self, tsa: tuple[bytes, Path]
    ) -> None:
        # Rule 6: a check that ran but could not cover everything says so on
        # the same line. "Valid" here means "chains to the anchor you named",
        # never "this certificate is live today".
        der, ca_file = tsa
        label = verify_token_signature(der, ca_file=ca_file).label
        assert "revocation" in label
        assert "NOT checked" in label

    def test_a_chain_through_an_intermediate_carried_in_the_token(self, tmp_path: Path) -> None:
        root_key, root_cert = issue("root", ca=True)
        mid_key, mid_cert = issue(
            "intermediate", issuer_key=root_key, issuer_name=root_cert.subject, ca=True
        )
        leaf_key, leaf_cert = issue("tsa", issuer_key=mid_key, issuer_name=mid_cert.subject)
        der = signed_token(key=leaf_key, cert=leaf_cert, certs=[leaf_cert, mid_cert])
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, root_cert))
        assert check.state == SIGNATURE_VALID


class TestInvalid:
    """Checked, and the answer is a definite no. Exit 1, never exit 2."""

    def test_a_signature_that_does_not_verify(self, tmp_path: Path) -> None:
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        der = signed_token(key=leaf_key, cert=leaf_cert, wrong_signature=True)
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_INVALID
        assert check.verdict is Verdict.BROKEN
        assert check.verdict.to_exit_code() == 1

    def test_signed_attributes_committing_to_another_tstinfo(self, tmp_path: Path) -> None:
        # The seam a swapped TSTInfo would slip through: the signature is over
        # the ATTRIBUTES, so without this comparison a valid signature over
        # somebody else's messageDigest would read as authentic.
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        der = signed_token(
            key=leaf_key, cert=leaf_cert, attr_digest=hashlib.sha256(b"other").digest()
        )
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_INVALID
        assert "TSTInfo" in check.label

    def test_a_signer_that_chains_to_nobody_in_the_bundle(self, tmp_path: Path) -> None:
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        _, stranger = issue("a root the operator actually trusts", ca=True)
        der = signed_token(key=leaf_key, cert=leaf_cert)
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, stranger))
        assert check.state == SIGNATURE_INVALID
        assert "chain" in check.label

    def test_a_chain_that_runs_out_of_issuers_short_of_the_bundle(self, tmp_path: Path) -> None:
        root_key, root_cert = issue("root", ca=True)
        mid_key, mid_cert = issue(
            "intermediate", issuer_key=root_key, issuer_name=root_cert.subject, ca=True
        )
        leaf_key, leaf_cert = issue("tsa", issuer_key=mid_key, issuer_name=mid_cert.subject)
        # The intermediate is carried, the root is NOT in the bundle: the walk
        # takes one step and then has nowhere left to go.
        der = signed_token(key=leaf_key, cert=leaf_cert, certs=[leaf_cert, mid_cert])
        _, stranger = issue("stranger", ca=True)
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, stranger))
        assert check.state == SIGNATURE_INVALID


class TestUnchecked:
    """The third value. Everything here MUST be exit 2, and every label must
    name its own remedy -- an operator reading one line has to know which of
    the causes they hit."""

    def test_no_ca_bundle_named_is_unchecked_not_valid(self, tsa: tuple[bytes, Path]) -> None:
        der, _ = tsa
        check = verify_token_signature(der, ca_file=None)
        assert check.state == SIGNATURE_UNCHECKED
        assert check.verdict is Verdict.UNVERIFIABLE
        assert check.verdict.to_exit_code() == 2
        assert "--tsa-ca-file" in check.label

    def test_waxseal_names_no_default_trust_anchor(self, tsa: tuple[bytes, Path]) -> None:
        # The discipline `cadence` follows for its cost parameters: a default
        # here would silently decide whom the operator trusts.
        der, _ = tsa
        assert "default" in verify_token_signature(der, ca_file=None).label

    def test_the_absent_extra_is_unchecked_and_says_how_to_install_it(
        self, tsa: tuple[bytes, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """FALSIFIABILITY RECEIPT for the branch whose absence is the whole
        hazard, measured three ways (real numbers in the bead's report):

        - replace the ``except ImportError`` arm with
          ``return SignatureCheck(SIGNATURE_VALID, ...)`` and this test fails
          on the state, its CLI twin on ``assert 0 == 2``: exit 0 over a token
          nobody authenticated, the forbidden collapse itself;
        - delete the arm and this test fails on the LABEL: the never-raise net
          below still yields ``unchecked`` and exit 2, but the line degrades to
          "could not be checked (ModuleNotFoundError)" with no remedy in it,
          which is why the arm exists on top of the net rather than instead of
          it;
        - delete the arm AND narrow the net and it does not fail, it ERRORS,
          with ``ModuleNotFoundError`` escaping through ``verify``.
        """
        der, ca_file = tsa
        monkeypatch.setitem(sys.modules, "cryptography", None)
        check = verify_token_signature(der, ca_file=ca_file)
        assert check.state == SIGNATURE_UNCHECKED
        assert "waxseal[rfc3161]" in check.label

    def test_a_ca_bundle_that_is_not_there(self, tsa: tuple[bytes, Path], tmp_path: Path) -> None:
        der, _ = tsa
        check = verify_token_signature(der, ca_file=tmp_path / "nope.pem")
        assert check.state == SIGNATURE_UNCHECKED
        assert "nope.pem" in check.label

    def test_a_ca_bundle_that_is_not_pem(self, tsa: tuple[bytes, Path], tmp_path: Path) -> None:
        der, _ = tsa
        bundle = tmp_path / "junk.pem"
        bundle.write_bytes(b"not a certificate")
        check = verify_token_signature(der, ca_file=bundle)
        assert check.state == SIGNATURE_UNCHECKED

    def test_bytes_that_are_not_a_timestamp_response(self, tsa: tuple[bytes, Path]) -> None:
        _, ca_file = tsa
        check = verify_token_signature(b"\x30\x03not der", ca_file=ca_file)
        assert check.state == SIGNATURE_UNCHECKED

    def test_a_token_with_no_signer_info(self, tsa: tuple[bytes, Path]) -> None:
        _, ca_file = tsa
        der = response(tst=tst_info(MESSAGE), signer_infos=b"")
        assert verify_token_signature(der, ca_file=ca_file).state == SIGNATURE_UNCHECKED

    def test_a_signer_info_with_no_signed_attributes(self, tmp_path: Path) -> None:
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        der = response(
            tst=tst_info(MESSAGE),
            signer_infos=signer_info(cert=leaf_cert, attrs=None, signature=b"\x00"),
            certs=[leaf_cert],
        )
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_UNCHECKED

    def test_a_digest_algorithm_this_build_does_not_compare(self, tsa: tuple[bytes, Path]) -> None:
        _, ca_file = tsa
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        der = signed_token(key=leaf_key, cert=leaf_cert, digest_alg_oid=OID_SHA1)
        assert verify_token_signature(der, ca_file=ca_file).state == SIGNATURE_UNCHECKED

    def test_a_signature_algorithm_this_build_does_not_know(self, tmp_path: Path) -> None:
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        der = signed_token(key=leaf_key, cert=leaf_cert, sig_alg_oid="1.2.3.4.5")
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_UNCHECKED

    def test_a_token_carrying_no_certificate_for_its_signer(self, tmp_path: Path) -> None:
        # certReq FALSE is legal: the TSA is entitled to omit its certificate,
        # and then there is nothing to check rather than something false.
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        der = signed_token(key=leaf_key, cert=leaf_cert, certs=[])
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_UNCHECKED
        assert "certificate" in check.label

    def test_a_signer_identified_by_subject_key_identifier(self, tmp_path: Path) -> None:
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        der = signed_token(key=leaf_key, cert=leaf_cert, sid=_tlv(0x80, b"\x01\x02\x03"))
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_UNCHECKED

    def test_signed_attributes_with_no_message_digest(self, tmp_path: Path) -> None:
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        attrs = _tlv(0x30, _der_oid(OID_CONTENT_TYPE) + _tlv(0x31, _der_oid(OID_TSTINFO)))
        signature = leaf_key.sign(_tlv(0x31, attrs), ec.ECDSA(hashes.SHA256()))
        der = response(
            tst=tst_info(MESSAGE),
            signer_infos=signer_info(cert=leaf_cert, attrs=attrs, signature=signature),
            certs=[leaf_cert],
        )
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_UNCHECKED

    def test_a_key_that_cannot_take_the_declared_algorithm(self, tmp_path: Path) -> None:
        # An Ed25519 signer under an ECDSA signature algorithm: the primitive
        # raises something that is not InvalidSignature, and the never-raise
        # net turns it into unchecked rather than into a fake "invalid".
        ca_key, ca_cert = issue("root", ca=True)
        ed_key = ed25519.Ed25519PrivateKey.generate()
        _, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject, key=ed_key)
        tst = tst_info(MESSAGE)
        attrs = signed_attrs(tst)
        der = response(
            tst=tst,
            signer_infos=signer_info(
                cert=leaf_cert, attrs=attrs, signature=ed_key.sign(_tlv(0x31, attrs))
            ),
            certs=[leaf_cert],
        )
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_UNCHECKED


class TestHouseRules:
    def test_no_label_ever_says_tamper(self, tsa: tuple[bytes, Path], tmp_path: Path) -> None:
        # domain/rfc3161.py's rule, carried into the module that CAN say
        # "false": a signature that does not verify is checked-and-false, and
        # which row is the tamper is still an operator's call (rule 4).
        der, ca_file = tsa
        # The operator's own bundle path is echoed back verbatim, and this
        # test's tmp_path happens to contain its own name -- that string is
        # the operator's, not this module's vocabulary, so it comes out first.
        labels = [
            check.label.replace(str(ca_file), "<bundle>")
            for check in (
                verify_token_signature(der, ca_file=None),
                verify_token_signature(der, ca_file=ca_file),
                verify_token_signature(b"junk", ca_file=ca_file),
            )
        ]
        assert not any("tamper" in label for label in labels)

    def test_it_never_raises_whatever_the_bytes(self, tsa: tuple[bytes, Path]) -> None:
        _, ca_file = tsa
        for der in (b"", b"\x30", b"\x00" * 40, bytes(range(256))):
            assert verify_token_signature(der, ca_file=ca_file).state == SIGNATURE_UNCHECKED


class TestShapesTheParserMustSurvive:
    """Branches that exist because real CMS is baggier than the happy path."""

    def test_an_rsa_signer_verifies_too(self, tmp_path: Path) -> None:
        # The other half of the algorithm table. Real TSAs are still mostly
        # RSA, so the EC-everywhere convenience of the rest of this file must
        # not be the only path with a test.
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject, key=leaf_key)
        der = signed_token(key=leaf_key, cert=leaf_cert, rsa_key=True)
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_VALID

    def test_an_unreadable_certificate_in_the_bag_does_not_condemn_the_token(
        self, tmp_path: Path
    ) -> None:
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        der = signed_token(key=leaf_key, cert=leaf_cert, raw_certs=_tlv(0x30, b"\x02\x01\x01"))
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_VALID

    def test_a_crls_element_beside_the_certificates_is_stepped_over(self, tmp_path: Path) -> None:
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        # crls [1] IMPLICIT is optional and legal; a parser that assumed the
        # element after the certificates was always signerInfos would read the
        # CRLs as a SignerInfo.
        der = signed_token(key=leaf_key, cert=leaf_cert, extra=_tlv(0xA1, b""))
        assert verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert)).state == (
            SIGNATURE_VALID
        )

    def test_an_econtent_that_is_not_an_octet_string(self, tsa: tuple[bytes, Path]) -> None:
        _, ca_file = tsa
        der = response(tst=tst_info(MESSAGE), signer_infos=b"", econtent=_tlv(0x30, b""))
        assert verify_token_signature(der, ca_file=ca_file).state == SIGNATURE_UNCHECKED

    def test_a_message_digest_attribute_that_is_not_an_octet_string(self, tmp_path: Path) -> None:
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        attrs = _tlv(0x30, _der_oid(OID_CONTENT_TYPE) + _tlv(0x31, _der_oid(OID_TSTINFO))) + _tlv(
            0x30, _der_oid(OID_MESSAGE_DIGEST) + _tlv(0x31, _der_int(1))
        )
        signature = leaf_key.sign(_tlv(0x31, attrs), ec.ECDSA(hashes.SHA256()))
        der = response(
            tst=tst_info(MESSAGE),
            signer_infos=signer_info(cert=leaf_cert, attrs=attrs, signature=signature),
            certs=[leaf_cert],
        )
        check = verify_token_signature(der, ca_file=ca_bundle(tmp_path, ca_cert))
        assert check.state == SIGNATURE_UNCHECKED
        assert "messageDigest" in check.label
