"""Signer/Verifier protocols for asymmetric attestations.

Implementations are INJECTED (e.g. Ed25519 from `cryptography` or PyNaCl);
waxseal never imports a crypto library (zero-dependency rule). `algorithm`
becomes part of the attestation scheme name, so verification treats an
algorithm it has no verifier for as unverifiable-by-name, never as tampering.
"""

from __future__ import annotations

from typing import Protocol


class Signer(Protocol):
    algorithm: str  # e.g. "ed25519"
    key_id: str

    def sign(self, data: bytes) -> bytes: ...


class Verifier(Protocol):
    algorithm: str

    def verify(self, data: bytes, signature: bytes) -> bool: ...
