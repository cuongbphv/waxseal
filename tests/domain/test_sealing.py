"""Tests for forward-secure sealing (Bellare-Yee / Schneier-Kelsey key
evolution) and the generic attestation verification model.

Construction: per-entry epoch key A_{j+1} = SHA-256(A_j); seal_j =
HMAC-SHA256(A_j, frame(entry_hash_j)). An attacker who steals A_t cannot forge
seals for epochs < t. Verification holds A_0 and walks forward.
"""

import hashlib
import hmac as hmaclib

from waxseal.domain.hashing import lp
from waxseal.domain.sealing import (
    AGG_FRAME_PREFIX,
    AGG_GENESIS,
    FS_HMAC_AGG_SCHEME,
    FS_HMAC_SCHEME,
    SEAL_FRAME_PREFIX,
    Attestation,
    aggregate_step,
    evolve_key,
    generate_key,
    seal_entry,
    verify_aggregate,
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

    def test_agg_scheme_rows_verify_exactly_like_fs_hmac(self) -> None:
        # The aggregate is an ADDITIONAL fold on top of the per-entry tag,
        # not a replacement for it — a fs-hmac-agg-sha256-v1 row carries the
        # identical HMAC construction and must verify (and be forgeable-
        # detectable) the same way.
        k0 = b"\x08" * 32
        seals = self.make(4, k0)
        agg_seals = [
            Attestation(seq=a.seq, entry_hash=a.entry_hash, scheme=FS_HMAC_AGG_SCHEME,
                        value=a.value)
            for a in seals
        ]
        result = verify_seals(agg_seals, k0)
        assert result.ok
        assert result.checked == 4

    def test_forged_agg_scheme_seal_is_detected(self) -> None:
        k0 = b"\x09" * 32
        seals = self.make(3, k0)
        agg_seals = [
            Attestation(seq=a.seq, entry_hash=a.entry_hash, scheme=FS_HMAC_AGG_SCHEME,
                        value=a.value)
            for a in seals
        ]
        agg_seals[1] = Attestation(
            seq=1, entry_hash=agg_seals[1].entry_hash, scheme=FS_HMAC_AGG_SCHEME,
            value="00" * 32,
        )
        result = verify_seals(agg_seals, k0)
        assert not result.ok
        assert result.broken_seq == 1
        assert result.reason == "seal_mismatch"


class TestAggregateStep:
    def test_matches_manual_hmac_fold(self) -> None:
        key = b"\x0a" * 32
        prev_agg = AGG_GENESIS
        value = "deadbeef"
        expected = hmaclib.new(
            key, AGG_FRAME_PREFIX + bytes.fromhex(prev_agg) + lp(value), hashlib.sha256
        ).hexdigest()
        assert aggregate_step(key, prev_agg, value) == expected

    def test_different_prev_agg_gives_different_result(self) -> None:
        key = b"\x0b" * 32
        a = aggregate_step(key, AGG_GENESIS, "v")
        b = aggregate_step(key, "1" * 64, "v")
        assert a != b

    def test_different_value_gives_different_result(self) -> None:
        key = b"\x0c" * 32
        a = aggregate_step(key, AGG_GENESIS, "v1")
        b = aggregate_step(key, AGG_GENESIS, "v2")
        assert a != b


class TestVerifyAggregate:
    def make_attestations(self, n: int, k0: bytes) -> list[Attestation]:
        out = []
        key = k0
        for seq in range(n):
            entry_hash = hashlib.sha256(f"e{seq}".encode()).hexdigest()
            out.append(
                Attestation(
                    seq=seq,
                    entry_hash=entry_hash,
                    scheme=FS_HMAC_AGG_SCHEME,
                    value=seal_entry(key, entry_hash),
                )
            )
            key = evolve_key(key)
        return out

    def fold(self, attestations: list[Attestation], k0: bytes, agg_start: int) -> str:
        key = k0
        running = AGG_GENESIS
        for position, att in enumerate(attestations):
            if position >= agg_start:
                running = aggregate_step(key, running, att.value)
            key = evolve_key(key)
        return running

    def test_intact_aggregate_verifies(self) -> None:
        k0 = b"\x0d" * 32
        atts = self.make_attestations(5, k0)
        agg = self.fold(atts, k0, agg_start=0)
        assert verify_aggregate(atts, k0, agg_start=0, epoch=5, agg=agg) is None

    def test_aggregate_starting_mid_trail_skips_earlier_rows(self) -> None:
        # DESIGN.md upgrade path: aggregation can be turned on mid-trail —
        # rows before agg_start fold in nothing, only the keyfile continuity
        # check (log.py) covers them.
        k0 = b"\x0e" * 32
        atts = self.make_attestations(6, k0)
        agg = self.fold(atts, k0, agg_start=3)
        assert verify_aggregate(atts, k0, agg_start=3, epoch=6, agg=agg) is None
        # Folding from 0 instead must NOT coincidentally match.
        assert verify_aggregate(atts, k0, agg_start=0, epoch=6, agg=agg) == "aggregate_mismatch"

    def test_tampered_value_breaks_the_fold(self) -> None:
        k0 = b"\x0f" * 32
        atts = self.make_attestations(4, k0)
        agg = self.fold(atts, k0, agg_start=0)
        tampered = list(atts)
        tampered[2] = Attestation(
            seq=2, entry_hash=atts[2].entry_hash, scheme=FS_HMAC_AGG_SCHEME, value="ff" * 32
        )
        assert verify_aggregate(tampered, k0, agg_start=0, epoch=4, agg=agg) == "aggregate_mismatch"

    def test_wrong_epoch_count_is_epoch_mismatch(self) -> None:
        # A row dropped from the .attest sidecar (truncation) changes the
        # attestation count without the stored epoch following — this is
        # exactly the truncation-resistance property the fold exists for.
        k0 = b"\x10" * 32
        atts = self.make_attestations(5, k0)
        agg = self.fold(atts, k0, agg_start=0)
        assert verify_aggregate(atts[:4], k0, agg_start=0, epoch=5, agg=agg) == (
            "aggregate_epoch_mismatch"
        )

    def test_negative_agg_start_is_malformed(self) -> None:
        k0 = b"\x11" * 32
        atts = self.make_attestations(3, k0)
        assert verify_aggregate(atts, k0, agg_start=-1, epoch=3, agg=AGG_GENESIS) == (
            "malformed_aggregate"
        )

    def test_agg_start_beyond_epoch_is_malformed(self) -> None:
        k0 = b"\x12" * 32
        atts = self.make_attestations(3, k0)
        assert verify_aggregate(atts, k0, agg_start=4, epoch=3, agg=AGG_GENESIS) == (
            "malformed_aggregate"
        )

    def test_non_hex_agg_is_malformed(self) -> None:
        k0 = b"\x13" * 32
        atts = self.make_attestations(3, k0)
        assert verify_aggregate(atts, k0, agg_start=0, epoch=3, agg="zz-not-hex") == (
            "malformed_aggregate"
        )

    def test_empty_aggregate_from_the_start_is_genesis(self) -> None:
        assert verify_aggregate([], b"\x14" * 32, agg_start=0, epoch=0, agg=AGG_GENESIS) is None

    def test_refold_without_the_epoch_key_cannot_reproduce_the_aggregate(self) -> None:
        # This is the property the whole construction rests on: an attacker
        # holding only the PUBLIC attestation values (not the epoch keys)
        # cannot refold a matching aggregate by guessing — HMAC needs the key.
        k0 = b"\x15" * 32
        atts = self.make_attestations(4, k0)
        real_agg = self.fold(atts, k0, agg_start=0)

        def refold_without_key(attestations: list[Attestation]) -> str:
            running = AGG_GENESIS
            for att in attestations:
                # Attacker's best guess: hash without any epoch key at all.
                running = hashlib.sha256(
                    AGG_FRAME_PREFIX + bytes.fromhex(running) + lp(att.value)
                ).hexdigest()
            return running

        assert refold_without_key(atts) != real_agg

    def test_switching_back_to_plain_scheme_is_not_a_false_epoch_mismatch(self) -> None:
        # A trail may attest N rows under fs-hmac-agg-sha256-v1, then switch
        # BACK to plain fs-hmac-sha256-v1 (FileAttestor(scheme=...) is a
        # per-instance choice, not a per-trail lock-in) and keep appending.
        # FileAttestor's plain branch never touches .sealagg, so its epoch
        # stays at N forever — that must not read as a dropped/truncated row
        # (CLAUDE.md incident class: a config change must never masquerade as
        # tampering) as long as no AGG-scheme row exists past position N.
        k0 = b"\x16" * 32
        agg_atts = self.make_attestations(3, k0)
        agg = self.fold(agg_atts, k0, agg_start=0)
        key_after_3 = k0
        for _ in range(3):
            key_after_3 = evolve_key(key_after_3)
        plain_atts = [
            Attestation(
                seq=3, entry_hash=("e" * 63) + "3", scheme=FS_HMAC_SCHEME,
                value=seal_entry(key_after_3, ("e" * 63) + "3"),
            )
        ]
        all_atts = agg_atts + plain_atts
        assert verify_aggregate(all_atts, k0, agg_start=0, epoch=3, agg=agg) is None

    def test_agg_row_past_the_persisted_epoch_is_a_real_desync(self) -> None:
        # Unlike the plain-scheme case above, an AGG-scheme row sitting past
        # `epoch` means the writer folded something the persisted state never
        # captured (a crash between the keyfile/attest writes and the
        # .sealagg write) — a genuine desync, not a scheme switch.
        k0 = b"\x17" * 32
        atts = self.make_attestations(4, k0)
        agg = self.fold(atts[:3], k0, agg_start=0)
        assert verify_aggregate(atts, k0, agg_start=0, epoch=3, agg=agg) == (
            "aggregate_epoch_mismatch"
        )

    def test_malformed_attestation_value_is_malformed_aggregate_not_a_crash(self) -> None:
        # The sidecar is attacker-writable by threat model (module docstring):
        # a lone UTF-16 surrogate in a JSON-decoded value cannot be UTF-8
        # encoded by lp() and must be a verdict, never an uncaught
        # UnicodeEncodeError (fail-closed rule, matches verify_membership).
        k0 = b"\x18" * 32
        atts = self.make_attestations(2, k0)
        atts[1] = Attestation(
            seq=1, entry_hash=atts[1].entry_hash, scheme=FS_HMAC_AGG_SCHEME, value="\ud800"
        )
        assert verify_aggregate(atts, k0, agg_start=0, epoch=2, agg=AGG_GENESIS) == (
            "malformed_aggregate"
        )


class TestVerifySealsMalformedValue:
    def test_non_ascii_attestation_value_is_malformed_not_a_crash(self) -> None:
        # hmac.compare_digest raises TypeError on a non-ASCII str; an
        # attacker-controlled sidecar value must be a verdict, never an
        # uncaught exception (same fail-closed rule as seal_entry's own
        # UnicodeEncodeError guard three lines above it in verify_seals).
        k0 = b"\x19" * 32
        entry_hash = hashlib.sha256(b"e0").hexdigest()
        atts = [
            Attestation(seq=0, entry_hash=entry_hash, scheme=FS_HMAC_SCHEME, value="\ud800")
        ]
        result = verify_seals(atts, k0)
        assert not result.ok
        assert result.reason == "malformed_attestation"
        assert result.broken_seq == 0
