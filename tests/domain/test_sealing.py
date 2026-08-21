"""Tests for forward-secure sealing (Bellare-Yee / Schneier-Kelsey key
evolution) and the generic attestation verification model.

Construction: per-entry epoch key A_{j+1} = SHA-256(A_j); seal_j =
HMAC-SHA256(A_j, frame(entry_hash_j)). An attacker who steals A_t cannot forge
seals for epochs < t. Verification holds A_0 and walks forward.
"""

import hashlib
import hmac as hmaclib

from waxseal.domain.sealing import (
    FS_HMAC_SCHEME,
    SEAL_FRAME_PREFIX,
    Attestation,
    evolve_key,
    generate_key,
    seal_entry,
    verify_seals,
)


def manual_seal(key: bytes, entry_hash: str) -> str:
    return hmaclib.new(
        key, SEAL_FRAME_PREFIX + entry_hash.encode("ascii"), hashlib.sha256
    ).hexdigest()


class TestPrimitives:
    def test_evolve_key_is_sha256_of_key(self) -> None:
        k0 = b"\x01" * 32
        assert evolve_key(k0) == hashlib.sha256(k0).digest()

    def test_generate_key_is_32_random_bytes(self) -> None:
        a, b = generate_key(), generate_key()
        assert len(a) == 32
        assert a != b

    def test_seal_matches_manual_hmac(self) -> None:
        k0 = b"\x02" * 32
        assert seal_entry(k0, "a" * 64) == manual_seal(k0, "a" * 64)

    def test_seals_differ_across_epochs_for_same_hash(self) -> None:
        k0 = b"\x03" * 32
        assert seal_entry(k0, "a" * 64) != seal_entry(evolve_key(k0), "a" * 64)


class TestVerifySeals:
    def make(self, n: int, k0: bytes) -> list[Attestation]:
        out = []
        key = k0
        for seq in range(n):
            entry_hash = hashlib.sha256(f"e{seq}".encode()).hexdigest()
            out.append(
                Attestation(
                    seq=seq,
                    entry_hash=entry_hash,
                    scheme=FS_HMAC_SCHEME,
                    value=seal_entry(key, entry_hash),
                )
            )
            key = evolve_key(key)
        return out

    def test_intact_seals_verify(self) -> None:
        k0 = b"\x04" * 32
        result = verify_seals(self.make(5, k0), k0)
        assert result.ok
        assert result.checked == 5
        assert result.broken_seq is None

    def test_forged_pre_compromise_seal_is_detected(self) -> None:
        # Attacker stole the epoch-3 key and rewrites entry 1: they cannot
        # produce a valid epoch-1 seal, and verification pinpoints it.
        k0 = b"\x05" * 32
        seals = self.make(5, k0)
        forged_hash = hashlib.sha256(b"forged").hexdigest()
        epoch3_key = evolve_key(evolve_key(evolve_key(k0)))
        seals[1] = Attestation(
            seq=1,
            entry_hash=forged_hash,
            scheme=FS_HMAC_SCHEME,
            value=seal_entry(epoch3_key, forged_hash),
        )
        result = verify_seals(seals, k0)
        assert not result.ok
        assert result.broken_seq == 1
        assert result.reason == "seal_mismatch"

    def test_unknown_scheme_is_unverifiable_not_tampered(self) -> None:
        # RFC 6962 principle applied to attestations: an unknown scheme is
        # opaque, never an error, never a break.
        k0 = b"\x06" * 32
        seals = self.make(3, k0)
        seals[1] = Attestation(
            seq=1, entry_hash=seals[1].entry_hash, scheme="post-quantum-magic-v9", value="??"
        )
        result = verify_seals(seals, k0)
        assert result.ok
        assert result.unverifiable == (1,)
        # The epoch clock still advances through the opaque row: row 2 sealed
        # under epoch 2 must still verify.
        assert result.checked == 2

    def test_empty_is_ok(self) -> None:
        result = verify_seals([], b"\x07" * 32)
        assert result.ok
        assert result.checked == 0
