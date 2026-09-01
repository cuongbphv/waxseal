"""Optional CMS/X.509 verification of an RFC 3161 token (the `rfc3161` extra).

`domain/rfc3161.py` answers one question with no dependencies: does this token
COMMIT to these exact bytes? It says in its own docstring that it verifies
neither the CMS signature nor the certificate chain, and names
``openssl ts -verify`` as the delegated route. That route stays the documented
primary one, and `waxseal receipt` still exists to feed it. This module is a
SECOND option, never a replacement: it answers the other question -- was this
token signed by a TSA the OPERATOR trusts? -- for operators who would rather
not shell out to openssl in a container that may not have it.

Two constraints shape everything here.

CLAUDE.md rule 1: `dependencies` stays `[]`. cryptography is imported INSIDE
`verify_token_signature`, so it can be legitimately absent on a correct
install, and its ImportError becomes a reported state rather than a crash --
the same shape `adapters/s3.py::_resolve_client` uses for boto3.

No default trust anchor. The CA bundle is named by the operator
(`--tsa-ca-file`), and nothing else is consulted: not the system store, not
certifi, not the certificates the token happens to carry as roots. A tool
whose output is evidence must not decide whom its operator trusts, and a
default store would do exactly that without a line of output naming which
anchors were in play. This is the discipline `domain/cadence.py` follows for
its cost parameters, for the same reason.

The Ternary Evidence Principle, in its natural habitat
------------------------------------------------------
A signature check has three answers, not two:

- ``signature_valid``: checked, and it holds.
- ``signature_invalid``: CHECKED, and the answer is a definite no. The bytes
  were signed by nobody the operator named, or the signature does not verify
  at all. ``Verdict.BROKEN``, exit 1.
- ``signature_unchecked``: the question was never actually put -- the extra is
  not installed, the operator named no CA bundle, or the token is in a shape
  this build cannot read. ``Verdict.UNVERIFIABLE``, exit 2.

Collapsing ``unchecked`` into ``valid`` -- an absent extra that quietly comes
back exit 0 -- is false confidence, "beads v1.2.2" in a new costume, and it is
the one outcome this module must never produce. Every unchecked label
therefore names its own remedy, so one line tells an operator which of the
three causes they hit and what to do about it.

Unreadable is unchecked, never invalid. A token whose CMS this build cannot
parse is unverifiable by name (RFC 6962 section 4.6), the same call
``domain/rfc3161.py`` makes for a token it cannot parse structurally. Only two
things earn ``invalid``: a signature that verifiably does not verify, and a
signer that verifiably does not chain to the named anchors.

Deliberately NOT checked, and said so on the ``valid`` label (CLAUDE.md rule
6): certificate validity windows, revocation (no network is opened here), and
the timeStamping extended key usage. What is claimed is a chain to the anchor
the operator named. Nothing more.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from waxseal.domain.rfc3161 import (
    SHA256_OID,
    _integer,
    _oid,
    _read_all,
    _read_one,
    _sequence,
    _tlv,
)
from waxseal.domain.verdict import Verdict

SIGNATURE_VALID: Final = "signature_valid"
SIGNATURE_INVALID: Final = "signature_invalid"
SIGNATURE_UNCHECKED: Final = "signature_unchecked"

_OID_MESSAGE_DIGEST: Final = "1.2.840.113549.1.9.4"
# rsaEncryption and sha256WithRSAEncryption both appear in the wild in a
# SignerInfo.signatureAlgorithm; both mean PKCS#1 v1.5 here, because the digest
# is pinned to SHA-256 a few lines earlier.
_RSA_PKCS1_OIDS: Final = frozenset({"1.2.840.113549.1.1.1", "1.2.840.113549.1.1.11"})
_ECDSA_OIDS: Final = frozenset({"1.2.840.10045.2.1", "1.2.840.10045.4.3.2"})

_TAG_OCTET_STRING: Final = 0x04
_TAG_SEQUENCE: Final = 0x30
_TAG_SET: Final = 0x31
_TAG_CONTEXT_0: Final = 0xA0

_INSTALL_HINT: Final = "install it with `pip install 'waxseal[rfc3161]'`"


@dataclass(frozen=True, slots=True)
class SignatureCheck:
    """One token's signature dimension: which of the three states, and the
    line an operator reads.

    ``label`` is not decoration. For ``signature_unchecked`` it is the only
    thing separating "nobody asked" from "asked and it holds", so it always
    names the cause AND the remedy.
    """

    state: str
    label: str

    @property
    def verdict(self) -> Verdict:
        """The repo's existing three-valued type, not a parallel one: the CLI
        already turns a ``Verdict`` into an exit code and joins it with every
        other dimension (``cli._Check``), so this dimension inherits both."""
        return _VERDICT[self.state]


_VERDICT: Final[dict[str, Verdict]] = {
    SIGNATURE_VALID: Verdict.OK,
    SIGNATURE_INVALID: Verdict.BROKEN,
    SIGNATURE_UNCHECKED: Verdict.UNVERIFIABLE,
}


class _Unchecked(Exception):
    """Internal: "the question could not be put", carrying the label that says
    why and what to do. Never escapes this module."""

    def __init__(self, label: str) -> None:
        super().__init__(label)
        self.label = label


@dataclass(frozen=True, slots=True)
class _Cms:
    """The parts of a CMS SignedData this check needs, as raw DER."""

    econtent: bytes
    signed_attrs_value: bytes
    signature: bytes
    digest_alg_oid: str
    sig_alg_oid: str
    issuer_der: bytes
    serial: int
    cert_ders: tuple[bytes, ...]


def verify_token_signature(der: bytes, *, ca_file: Path | str | None) -> SignatureCheck:
    """Check an RFC 3161 TimeStampResp's CMS signature against ``ca_file``.

    ``ca_file`` is ``None`` when the operator named no bundle: that is an
    ``unchecked`` answer with its own label, never a pass. Never raises --
    the DER arrives from outside the trust boundary, and a parser that dies on
    it denies the audit (``domain/rfc3161.py``'s contract, kept here).
    """
    try:
        return _verify(der, ca_file)
    except _Unchecked as exc:
        return SignatureCheck(SIGNATURE_UNCHECKED, exc.label)
    except Exception as exc:  # noqa: BLE001 - the never-raise net; see docstring
        # Deliberately broad, matching read_timestamp_resp: an unanticipated
        # exception type from a third-party primitive must become a verdict,
        # and it must become the WEAK verdict -- an unexpected failure is not
        # evidence that the signature is false.
        return SignatureCheck(
            SIGNATURE_UNCHECKED,
            f"{SIGNATURE_UNCHECKED}: this token could not be checked "
            f"({type(exc).__name__}: {exc}) -- unverifiable by name, and no statement "
            "is made about the signature either way",
        )


def _verify(der: bytes, ca_file: Path | str | None) -> SignatureCheck:
    if ca_file is None:
        raise _Unchecked(
            f"{SIGNATURE_UNCHECKED}: no CA bundle was named, so the CMS signature and "
            "the certificate chain were not checked -- pass --tsa-ca-file <bundle.pem> "
            "naming the TSA's trust anchor. waxseal has no default trust store on "
            "purpose: choosing one would decide whom you trust on your behalf"
        )
    try:
        from cryptography import exceptions as _exceptions
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding
    except ImportError as exc:
        raise _Unchecked(
            f"{SIGNATURE_UNCHECKED}: the 'rfc3161' extra is not installed (no "
            f"cryptography: {exc}), so nothing was verified about this token's "
            f"signature -- {_INSTALL_HINT}, or use the documented "
            "`openssl ts -verify` route (`waxseal receipt` writes its inputs)"
        ) from exc

    path = Path(ca_file)
    try:
        anchors = x509.load_pem_x509_certificates(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise _Unchecked(
            f"{SIGNATURE_UNCHECKED}: the CA bundle {path} could not be read as PEM "
            f"certificates ({type(exc).__name__}: {exc}) -- point --tsa-ca-file at the "
            "TSA's trust anchor in PEM form"
        ) from exc

    cms = _parse_cms(der)
    if cms.digest_alg_oid != SHA256_OID:
        raise _Unchecked(
            f"{SIGNATURE_UNCHECKED}: the signer used digest algorithm "
            f"{cms.digest_alg_oid}, which this build does not compare -- verify it with "
            "`openssl ts -verify` instead"
        )

    pool = []
    for cert_der in cms.cert_ders:
        try:
            pool.append(x509.load_der_x509_certificate(cert_der))
        except ValueError:
            # One unreadable certificate does not condemn the token; the
            # signer may well be another one in the same bag.
            continue
    signer = next(
        (
            cert
            for cert in pool
            if cert.serial_number == cms.serial and cert.issuer.public_bytes() == cms.issuer_der
        ),
        None,
    )
    if signer is None:
        raise _Unchecked(
            f"{SIGNATURE_UNCHECKED}: the token carries no certificate for its signer "
            "(a TSA answering certReq FALSE is entitled to omit it), so there was "
            "nothing to check the signature with -- ask the TSA for a token with "
            "certReq TRUE, or verify against the certificate out of band"
        )

    if _message_digest_attribute(cms.signed_attrs_value) != hashlib.sha256(cms.econtent).digest():
        return SignatureCheck(
            SIGNATURE_INVALID,
            f"{SIGNATURE_INVALID}: the signed attributes commit to a different TSTInfo "
            "than the token carries, so the signature does not cover the time this "
            "token claims",
        )

    public_key: Any = signer.public_key()
    signed_bytes = _tlv(_TAG_SET, cms.signed_attrs_value)
    try:
        if cms.sig_alg_oid in _RSA_PKCS1_OIDS:
            public_key.verify(cms.signature, signed_bytes, padding.PKCS1v15(), hashes.SHA256())
        elif cms.sig_alg_oid in _ECDSA_OIDS:
            public_key.verify(cms.signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
        else:
            raise _Unchecked(
                f"{SIGNATURE_UNCHECKED}: signature algorithm {cms.sig_alg_oid} is one "
                "this build does not verify -- verify it with `openssl ts -verify` "
                "instead"
            )
    except _exceptions.InvalidSignature:
        return SignatureCheck(
            SIGNATURE_INVALID,
            f"{SIGNATURE_INVALID}: the CMS signature does not verify under the signer "
            "certificate carried in the token",
        )

    if not _chains_to_anchor(signer, pool, anchors):
        return SignatureCheck(
            SIGNATURE_INVALID,
            f"{SIGNATURE_INVALID}: the signer certificate does not chain to any anchor "
            f"in {path} -- the signature is genuine for SOMEBODY, but not for anyone "
            "this bundle names",
        )

    return SignatureCheck(
        SIGNATURE_VALID,
        f"{SIGNATURE_VALID}: the CMS signature verifies and the signer chains to an "
        f"anchor in {path}. Certificate validity windows, revocation and the "
        "timeStamping extended key usage are NOT checked here",
    )


def _chains_to_anchor(leaf: Any, pool: list[Any], anchors: list[Any]) -> bool:
    """Walk issuer links from ``leaf`` until one is issued by an anchor.

    Bounded by ``visited`` rather than by a depth constant: every step
    consumes a distinct certificate out of the finite pool the token carried,
    so a token holding a certificate cycle terminates instead of spinning.
    Identity is by object, which is exactly right here -- ``pool`` holds one
    object per certificate the token carried, and two copies of the same
    certificate are two usable links, not one.

    Only issuer-name matching and the link signature are checked (that is all
    ``verify_directly_issued_by`` claims). Validity windows, path length and
    basic constraints are not, and the ``valid`` label says so.
    """
    current = leaf
    visited = {id(current)}
    while True:
        for anchor in anchors:
            if _directly_issued_by(current, anchor):
                return True
        nxt = next(
            (
                cert
                for cert in pool
                if id(cert) not in visited and _directly_issued_by(current, cert)
            ),
            None,
        )
        if nxt is None:
            return False
        visited.add(id(nxt))
        current = nxt


def _directly_issued_by(cert: Any, issuer: Any) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
    except Exception:  # noqa: BLE001 - "not this issuer" arrives as several types
        return False
    return True


def _parse_cms(der: bytes) -> _Cms:
    """The CMS SignedData parts, or ``_Unchecked``. Reuses the hardened DER
    reader in ``domain/rfc3161.py`` rather than growing a second one: a
    parser this module owned alone would be the one with fewer eyes on it, in
    the file where a bounds bug costs the most."""
    try:
        return _parse_cms_unguarded(der)
    except _Unchecked:
        raise
    except Exception as exc:  # noqa: BLE001 - every byte here is untrusted
        raise _Unchecked(
            f"{SIGNATURE_UNCHECKED}: the token's CMS structure is not one this build "
            f"reads ({type(exc).__name__}) -- unverifiable by name, NOT evidence that "
            "the signature is false"
        ) from exc


def _parse_cms_unguarded(der: bytes) -> _Cms:
    resp = _sequence(_read_one(der), what="TimeStampResp")
    content_info = _sequence(resp[1], what="ContentInfo")
    signed_data = _sequence(_read_one(content_info[1].value), what="SignedData")

    encap = _sequence(signed_data[2], what="EncapsulatedContentInfo")
    octets = _read_one(encap[1].value)
    if octets.tag != _TAG_OCTET_STRING:
        raise ValueError("eContent is not an OCTET STRING")
    econtent = octets.value

    signer_infos = _read_all(signed_data[-1].value)
    if len(signer_infos) != 1:
        raise _Unchecked(
            f"{SIGNATURE_UNCHECKED}: the token carries {len(signer_infos)} SignerInfo "
            "structures; this build checks a token signed exactly once -- verify it "
            "with `openssl ts -verify` instead"
        )
    signer = _sequence(signer_infos[0], what="SignerInfo")
    if len(signer) < 6 or signer[3].tag != _TAG_CONTEXT_0:
        raise _Unchecked(
            f"{SIGNATURE_UNCHECKED}: the SignerInfo carries no signed attributes, so "
            "there is nothing this build knows how to verify a signature over -- "
            "verify it with `openssl ts -verify` instead"
        )
    sid = signer[1]
    if sid.tag != _TAG_SEQUENCE:
        raise _Unchecked(
            f"{SIGNATURE_UNCHECKED}: the signer is identified by subject key "
            "identifier, a form this build does not resolve -- verify it with "
            "`openssl ts -verify` instead"
        )
    issuer_and_serial = _sequence(sid, what="IssuerAndSerialNumber")
    issuer_der = _tlv(issuer_and_serial[0].tag, issuer_and_serial[0].value)
    serial = _integer(issuer_and_serial[1], what="serialNumber")

    cert_ders: list[bytes] = []
    for element in signed_data[3:-1]:
        if element.tag == _TAG_CONTEXT_0:
            cert_ders.extend(_tlv(c.tag, c.value) for c in _read_all(element.value))

    return _Cms(
        econtent=econtent,
        signed_attrs_value=signer[3].value,
        signature=signer[5].value,
        digest_alg_oid=_oid(
            _sequence(signer[2], what="digestAlgorithm")[0], what="digestAlgorithm"
        ),
        sig_alg_oid=_oid(
            _sequence(signer[4], what="signatureAlgorithm")[0], what="signatureAlgorithm"
        ),
        issuer_der=issuer_der,
        serial=serial,
        cert_ders=tuple(cert_ders),
    )


def _message_digest_attribute(signed_attrs_value: bytes) -> bytes:
    """The messageDigest signed attribute: the only thing binding the
    signature to the TSTInfo the token actually carries."""
    for attr in _read_all(signed_attrs_value):
        parts = _sequence(attr, what="Attribute")
        if _oid(parts[0], what="attrType") != _OID_MESSAGE_DIGEST:
            continue
        value = _read_one(parts[1].value)
        if value.tag != _TAG_OCTET_STRING:
            break
        return value.value
    raise _Unchecked(
        f"{SIGNATURE_UNCHECKED}: the signed attributes carry no readable messageDigest, "
        "so nothing ties the signature to the TSTInfo beside it -- verify it with "
        "`openssl ts -verify` instead"
    )
