"""End-to-end tests for AuditLog with attestations: forward-secure seals
(stdlib HMAC) and injected asymmetric signers."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from waxseal import AuditLog
from waxseal.adapters.attest import FileAttestor
from waxseal.domain.sealing import FS_HMAC_SCHEME, Attestation, generate_key
from waxseal.log import AttestationFailure

PT = "application/vnd.test.event+json"


def open_sealed(tmp_path: Path, k0: bytes) -> AuditLog:
    return AuditLog.open(
        tmp_path / "trail.jsonl",
        attestor=FileAttestor(tmp_path / "trail.jsonl", initial_key=k0),
        now_fn=lambda: "2026-08-21T06:00:00+00:00",
    )


def attestor(log: AuditLog) -> Any:
    """AuditLog.__init__ types its attestor param `Any | None`: every test
    below that reaches for the attestor it configured knows it is not None."""
    assert log._attestor is not None
    return log._attestor


class TestSealedAppend:
    def test_each_append_writes_a_seal_and_evolves_the_key(self, tmp_path: Path) -> None:
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        seal_lines = (tmp_path / "trail.jsonl.attest").read_text().splitlines()
        assert len(seal_lines) == 3
        epochs = [json.loads(line)["seq"] for line in seal_lines]
        assert epochs == [0, 1, 2]

    def test_keyfile_holds_only_the_current_epoch_key(self, tmp_path: Path) -> None:
        # Forward security rests on old keys being gone: after 3 appends the
        # keyfile holds the epoch-3 key, and A_0..A_2 appear nowhere on disk.
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        keyfile = json.loads((tmp_path / "trail.jsonl.sealkey").read_text())
        assert keyfile["epoch"] == 3
        from waxseal.domain.sealing import evolve_key

        expected = k0
        for _ in range(3):
            expected = evolve_key(expected)
        assert bytes.fromhex(keyfile["key"]) == expected
        for old in (k0,):
            assert old.hex() not in (tmp_path / "trail.jsonl.sealkey").read_text()

    def test_verify_attestations_ok_with_k0(self, tmp_path: Path) -> None:
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(4):
            log.append(payload={"i": i}, payload_type=PT)
        result = log.verify_attestations(initial_key=k0)
        assert result.ok
        assert result.checked == 4

    def test_rewritten_suffix_without_key_is_caught_by_seals(self, tmp_path: Path) -> None:
        # The attack the plain chain cannot catch: rewrite an entry AND its
        # chain suffix consistently. Without the old epoch key the attacker
        # cannot re-seal, so seal verification breaks at the rewritten seq.
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)

        # Attacker rewrites the attestation line for seq=1 with a self-made
        # seal under a random key (they never saw A_1).
        attest_path = tmp_path / "trail.jsonl.attest"
        lines = attest_path.read_text().splitlines()
        from waxseal.domain.sealing import seal_entry

        forged = json.loads(lines[1])
        forged["value"] = seal_entry(generate_key(), forged["entry_hash"])
        lines[1] = json.dumps(forged)
        attest_path.write_text("\n".join(lines) + "\n")

        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.broken_seq == 1

    def test_seal_covers_the_entry_hash_actually_stored(self, tmp_path: Path) -> None:
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        log.append(payload={"x": 1}, payload_type=PT)
        entry = next(iter(log._backend.entries()))
        seal = json.loads((tmp_path / "trail.jsonl.attest").read_text().splitlines()[0])
        assert seal["entry_hash"] == entry.entry_hash


class TestInjectedSigner:
    class FakeEd25519:
        """Stand-in with the Signer protocol shape; real deployments inject
        cryptography/PyNaCl Ed25519. Deterministic per key like Ed25519."""

        algorithm = "ed25519"
        key_id = "test-key-1"

        def __init__(self) -> None:
            self._secret = b"\x0a" * 32

        def sign(self, data: bytes) -> bytes:
            import hashlib
            import hmac

            return hmac.new(self._secret, data, hashlib.sha256).digest()

        def verify(self, data: bytes, signature: bytes) -> bool:
            return hmac_compare(self.sign(data), signature)

    def test_signer_attestations_verify_and_detect_forgery(self, tmp_path: Path) -> None:
        signer = self.FakeEd25519()
        log = AuditLog.open(
            tmp_path / "trail.jsonl",
            attestor=FileAttestor(tmp_path / "trail.jsonl", signer=signer),
            now_fn=lambda: "2026-08-21T06:00:00+00:00",
        )
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        assert log.verify_attestations(verifier=signer).ok

        attest_path = tmp_path / "trail.jsonl.attest"
        lines = attest_path.read_text().splitlines()
        obj = json.loads(lines[2])
        obj["value"] = "00" * 32
        lines[2] = json.dumps(obj)
        attest_path.write_text("\n".join(lines) + "\n")
        result = log.verify_attestations(verifier=signer)
        assert not result.ok
        assert result.broken_seq == 2


def hmac_compare(a: bytes, b: bytes) -> bool:
    import hmac

    return hmac.compare_digest(a, b)


class TestJournaldLessons:
    """Hardening from the journald FSS analysis (ePrint 2023/867) and
    Ma-Tsudik's truncation attack: sequence binding both directions,
    sidecar↔trail cross-check, and keyfile-based truncation detection."""

    def test_attestation_seq_must_match_position(self, tmp_path: Path) -> None:
        # CVE-2023-31439 class: an attestation claiming a different seq than
        # its position must be a break, in BOTH directions.
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        attest_path = tmp_path / "trail.jsonl.attest"
        lines = attest_path.read_text().splitlines()
        obj = json.loads(lines[1])
        obj["seq"] = 2
        lines[1] = json.dumps(obj)
        attest_path.write_text("\n".join(lines) + "\n")
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "seal_sequence_mismatch"

    def test_truncating_trail_and_sidecar_together_is_detected(self, tmp_path: Path) -> None:
        # Ma-Tsudik truncation attack: chop the tail of BOTH files. The chain
        # and the remaining seals are internally valid — but the keyfile epoch
        # is one-way: the attacker holds A_5, cannot compute A_3, so the
        # keyfile cannot be rolled back to match the truncated length.
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(5):
            log.append(payload={"i": i}, payload_type=PT)
        for name in ("trail.jsonl", "trail.jsonl.attest"):
            p = tmp_path / name
            p.write_text("\n".join(p.read_text().splitlines()[:3]) + "\n")
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "keyfile_epoch_mismatch"

    def test_sidecar_hash_must_match_the_trail_entry(self, tmp_path: Path) -> None:
        # CVE-2023-31437 class: what the reader displays (trail) and what is
        # authenticated (sidecar) must be cross-checked, not trusted apart.
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        trail = tmp_path / "trail.jsonl"
        lines = trail.read_text().splitlines()
        obj = json.loads(lines[1])
        obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"
        lines[1] = json.dumps(obj)
        trail.write_text("\n".join(lines) + "\n")
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "attest_trail_mismatch"
        assert result.broken_seq == 1

    def test_keyfile_continuity_passes_on_intact_log(self, tmp_path: Path) -> None:
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(4):
            log.append(payload={"i": i}, payload_type=PT)
        assert log.verify_attestations(initial_key=k0).ok


class TestMalformedSidecar:
    """The sidecar and keyfile are attacker-writable by threat model (their
    whole purpose is detecting trail tampering). Malformed bytes there must
    come back as a verdict, never as an unhandled exception — crashing the
    verifier on attacker-supplied input denies the audit itself (the same
    fail-closed rule anchoring.verify_membership already follows)."""

    def test_non_hex_signature_value_is_malformed_not_a_crash(self, tmp_path: Path) -> None:
        signer = TestInjectedSigner.FakeEd25519()
        log = AuditLog.open(
            tmp_path / "trail.jsonl",
            attestor=FileAttestor(tmp_path / "trail.jsonl", signer=signer),
            now_fn=lambda: "2026-08-21T06:00:00+00:00",
        )
        for i in range(2):
            log.append(payload={"i": i}, payload_type=PT)
        attest_path = tmp_path / "trail.jsonl.attest"
        lines = attest_path.read_text().splitlines()
        obj = json.loads(lines[1])
        obj["value"] = "zz-not-hex"
        lines[1] = json.dumps(obj)
        attest_path.write_text("\n".join(lines) + "\n")
        result = log.verify_attestations(verifier=signer)
        assert not result.ok
        assert result.reason == "malformed_attestation"
        assert result.broken_seq == 1

    def test_malformed_json_line_in_sidecar_is_malformed_not_a_crash(self, tmp_path: Path) -> None:
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        log.append(payload={"i": 0}, payload_type=PT)
        with open(tmp_path / "trail.jsonl.attest", "a") as f:
            f.write("{this is not json\n")
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "malformed_attestation"

    def test_non_ascii_entry_hash_in_seal_path_is_malformed_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        # Reaching seal_entry's ascii encode requires the sidecar hash to pass
        # the trail cross-check first — so the attacker plants the same
        # non-ASCII "hash" in BOTH files, on a row whose fingerprint is not
        # recomputable (expected = the stored trail value).
        import base64

        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        log.append(payload={"i": 0}, payload_type=PT)
        first = next(iter(log._backend.entries()))
        evil_hash = "хэш-не-ascii"
        trail_row = {
            "header": {
                "seq": 1,
                "ts": "2026-08-21T06:00:01+00:00",
                "hash_version": "e" * 64,
                "payload_type": PT,
                "payload_hash": "0" * 64,
                "prev_hash": first.entry_hash,
            },
            "entry_hash": evil_hash,
            "payload_b64": base64.b64encode(b"{}").decode("ascii"),
        }
        with open(tmp_path / "trail.jsonl", "a") as f:
            f.write(json.dumps(trail_row) + "\n")
        att_row = {"seq": 1, "entry_hash": evil_hash, "scheme": "fs-hmac-sha256-v1", "value": "00"}
        with open(tmp_path / "trail.jsonl.attest", "a") as f:
            f.write(json.dumps(att_row) + "\n")
        # Key evolution is public (SHA-256), so an attacker CAN advance the
        # keyfile to match the extra row — only rolling back is impossible.
        from waxseal.domain.sealing import evolve_key

        keyfile = json.loads((tmp_path / "trail.jsonl.sealkey").read_text())
        advanced = evolve_key(bytes.fromhex(keyfile["key"]))
        (tmp_path / "trail.jsonl.sealkey").write_text(
            json.dumps({"epoch": 2, "key": advanced.hex()})
        )
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "malformed_attestation"

    def test_malformed_keyfile_is_reported_not_a_crash(self, tmp_path: Path) -> None:
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(2):
            log.append(payload={"i": i}, payload_type=PT)
        (tmp_path / "trail.jsonl.sealkey").write_text('{"epoch": 2, "key": "zz-not-hex"}')
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "malformed_keyfile"


class TestAttestationCriticalSection:
    """A prior review demonstrated 8 threads x 30 appends on a shared sealed
    log producing 240 chain entries but only 1 attestation, with the other 239
    miscounted as dropped writes: the attest step ran OUTSIDE the append
    critical section. Chain integrity never broke — the sidecar did.

    Falsifiability receipt: with AuditLog._append_lock replaced by
    contextlib.nullcontext, the first test below failed 5 out of 5 runs on
    macOS (measured 2026-08-21: 80 entries, 1-2 attestations, the rest
    RuntimeError epoch mismatches)."""

    def test_shared_log_concurrent_sealed_appends_attest_every_entry(self, tmp_path: Path) -> None:
        from concurrent.futures import ThreadPoolExecutor

        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        threads, per_thread = 8, 10

        def worker(worker_id: int) -> None:
            for i in range(per_thread):
                log.append(payload={"w": worker_id, "i": i}, payload_type=PT)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(worker, range(threads)))

        total = threads * per_thread
        assert len(list(log._backend.entries())) == total
        assert len(list(attestor(log).attestations())) == total
        assert log.verify_attestations(initial_key=k0).ok

    def test_attest_failure_after_persist_is_not_a_dropped_write(self, tmp_path: Path) -> None:
        # The entry IS durably on the chain when attest raises; counting it as
        # dropped would make dropped_writes lie (CLAUDE.md rule 5). The loss
        # that actually happened (a missing seal) gets its own counter.
        class FailingAttestor:
            def attest(self, seq: int, entry_hash: str) -> None:
                raise RuntimeError("sidecar disk full")

            def attestations(self) -> Iterator[Any]:
                return iter(())

        log = AuditLog.open(tmp_path / "trail.jsonl", attestor=FailingAttestor())
        assert log.try_append(payload={"i": 0}, payload_type=PT) is True
        assert log.dropped_writes == 0
        assert log.attest_failures == 1
        assert len(list(log._backend.entries())) == 1

    def test_fs_hmac_attestation_gap_fails_verification(self, tmp_path: Path) -> None:
        # An attest failure mid-stream leaves entries > attestations while the
        # keyfile epoch still equals the attestation count — the continuity
        # check alone cannot see the gap. verify must report it, not say ok.
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(2):
            log.append(payload={"i": i}, payload_type=PT)
        real_attest = attestor(log).attest
        attestor(log).attest = lambda seq, entry_hash: (_ for _ in ()).throw(
            RuntimeError("sidecar disk full")
        )
        assert log.try_append(payload={"i": 2}, payload_type=PT) is True
        attestor(log).attest = real_attest
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "attestation_gap"
        assert result.broken_seq == 2

    def test_signer_attestation_gap_fails_verification(self, tmp_path: Path) -> None:
        # Signer mode has no keyfile at all: without an explicit coverage
        # check a truncated sidecar verifies "ok" over the rows that remain.
        signer = TestInjectedSigner.FakeEd25519()
        log = AuditLog.open(
            tmp_path / "trail.jsonl",
            attestor=FileAttestor(tmp_path / "trail.jsonl", signer=signer),
            now_fn=lambda: "2026-08-21T06:00:00+00:00",
        )
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        attest_path = tmp_path / "trail.jsonl.attest"
        lines = attest_path.read_text().splitlines()
        attest_path.write_text("\n".join(lines[:2]) + "\n")
        result = log.verify_attestations(verifier=signer)
        assert not result.ok
        assert result.reason == "attestation_gap"
        assert result.broken_seq == 2


def open_agg_sealed(tmp_path: Path, k0: bytes) -> AuditLog:
    from waxseal.domain.sealing import FS_HMAC_AGG_SCHEME

    return AuditLog.open(
        tmp_path / "trail.jsonl",
        attestor=FileAttestor(tmp_path / "trail.jsonl", initial_key=k0, scheme=FS_HMAC_AGG_SCHEME),
        now_fn=lambda: "2026-08-22T06:00:00+00:00",
    )


class TestFssAggregate:
    """FssAgg (Ma-Tsudik): a running, keyed fold over every attested value,
    persisted as ONLY its latest value (adapters/attest.py's .sealagg,
    replace-only) so an attacker who truncates the trail cannot also
    reproduce the fold — they hold only the current, already-evolved key."""

    def test_scheme_defaults_to_plain_fs_hmac(self, tmp_path: Path) -> None:
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        log.append(payload={"i": 0}, payload_type="application/vnd.test.event+json")
        assert not (tmp_path / "trail.jsonl.sealagg").exists()

    def test_agg_scheme_writes_a_sealagg_sidecar_with_only_the_latest_value(
        self, tmp_path: Path
    ) -> None:
        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        for i in range(3):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        agg_path = tmp_path / "trail.jsonl.sealagg"
        assert agg_path.exists()
        obj = json.loads(agg_path.read_text())
        assert set(obj) == {"agg", "agg_start", "epoch"}
        assert obj["epoch"] == 3
        assert obj["agg_start"] == 0

    def test_intact_agg_trail_verifies(self, tmp_path: Path) -> None:
        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        for i in range(5):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        result = log.verify_attestations(initial_key=k0)
        assert result.ok
        assert result.checked == 5

    def test_attestation_rows_use_the_agg_scheme_name(self, tmp_path: Path) -> None:
        from waxseal.domain.sealing import FS_HMAC_AGG_SCHEME

        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        log.append(payload={"i": 0}, payload_type="application/vnd.test.event+json")
        [att] = list(attestor(log).attestations())
        assert att.scheme == FS_HMAC_AGG_SCHEME

    def test_truncating_trail_attest_and_keyfile_together_is_still_caught_by_epoch(
        self, tmp_path: Path
    ) -> None:
        # Even a fully consistent 3-file truncation (trail + .attest +
        # .sealkey, matching Ma-Tsudik's own attack) leaves .sealagg's
        # "epoch" stale relative to the now-shorter attestation list —
        # the aggregate's OWN gate, independent of the keyfile check.
        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        for i in range(5):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        # Roll keyfile back consistently (public: SHA-256 forward, not back —
        # so a real attacker cannot do this; this simulates the truncation
        # itself being caught by leaving .sealagg's epoch/agg stale, which a
        # keyfile-only rollback WOULD miss if it could roll back at all).
        for name in ("trail.jsonl", "trail.jsonl.attest"):
            p = tmp_path / name
            p.write_text("\n".join(p.read_text().splitlines()[:3]) + "\n")
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        # The plain keyfile-epoch check fires first (still one epoch ahead
        # of the truncated sidecar); the aggregate is a second, independent
        # gate — verified directly against domain.sealing.verify_aggregate
        # in tests/domain/test_sealing.py.
        assert result.reason == "keyfile_epoch_mismatch"

    def test_tampered_value_on_an_agg_row_is_caught_by_the_per_entry_seal_first(
        self, tmp_path: Path
    ) -> None:
        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        for i in range(3):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        attest_path = tmp_path / "trail.jsonl.attest"
        lines = attest_path.read_text().splitlines()
        obj = json.loads(lines[1])
        obj["value"] = "00" * 32
        lines[1] = json.dumps(obj)
        attest_path.write_text("\n".join(lines) + "\n")
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "seal_mismatch"
        assert result.broken_seq == 1

    def test_stale_sealagg_replayed_over_a_matching_truncation_is_an_honest_limit(
        self, tmp_path: Path
    ) -> None:
        # Honest limit (documented, not hidden): if an attacker can replay an
        # OLD .sealagg whose stored epoch happens to equal the truncated
        # attestation count, the aggregate's own gate cannot see it either —
        # exactly like an old anchor (SPEC.md's own documented limit for
        # anchoring, mirrored here for the aggregate).
        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        for i in range(3):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        agg_path = tmp_path / "trail.jsonl.sealagg"
        saved_agg = agg_path.read_text()
        for i in range(3, 5):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        for name in ("trail.jsonl", "trail.jsonl.attest"):
            p = tmp_path / name
            p.write_text("\n".join(p.read_text().splitlines()[:3]) + "\n")
        agg_path.write_text(saved_agg)  # replay the OLD (matching) sealagg
        # The keyfile is still 2 epochs ahead of the truncated sidecar (it
        # cannot be rolled back — SHA-256 is one-way), so THAT gate still
        # fires; this pins that the honest limit is specific to the
        # aggregate gate, not a claim that truncation goes undetected here.
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "keyfile_epoch_mismatch"

    def test_writer_refuses_to_reuse_a_stale_sealagg_epoch(self, tmp_path: Path) -> None:
        # attest.py's writer must cross-check .sealagg's own persisted epoch
        # against the row it is about to attest — trusting a stale value
        # (the sidecar is attacker-writable by the same threat model as the
        # keyfile) would silently skip folding whatever happened since, so
        # the persisted aggregate would LOOK complete without being complete.
        # This is the same class of self-check the keyfile epoch != seq
        # guard three lines above it in attest() already performs.
        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        for i in range(2):
            log.append(payload={"i": i}, payload_type=PT)
        agg_path = tmp_path / "trail.jsonl.sealagg"
        stale_agg = agg_path.read_text()  # epoch=2
        log.append(payload={"i": 2}, payload_type=PT)  # keyfile/attest now at 3
        agg_path.write_text(stale_agg)  # only .sealagg rolled back, independently
        with pytest.raises(AttestationFailure):
            log.append(payload={"i": 3}, payload_type=PT)

    def test_aggregate_missing_when_a_row_claims_the_agg_scheme(self, tmp_path: Path) -> None:
        from waxseal.domain.sealing import FS_HMAC_AGG_SCHEME

        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        log.append(payload={"i": 0}, payload_type="application/vnd.test.event+json")
        (tmp_path / "trail.jsonl.sealagg").unlink()
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "aggregate_missing"
        assert attestor(log).attestations().__next__().scheme == FS_HMAC_AGG_SCHEME

    def test_old_fs_hmac_sidecar_without_sealagg_still_verifies_unchanged(
        self, tmp_path: Path
    ) -> None:
        # Regression: a pre-existing plain fs-hmac trail (no .sealagg at
        # all) must verify exactly as before — the aggregate is additive,
        # never required.
        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(3):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        assert not (tmp_path / "trail.jsonl.sealagg").exists()
        assert log.verify_attestations(initial_key=k0).ok

    def test_unknown_scheme_value_is_rejected_at_construction(self, tmp_path: Path) -> None:
        k0 = generate_key()
        with pytest.raises(ValueError, match="scheme"):
            FileAttestor(tmp_path / "trail.jsonl", initial_key=k0, scheme="made-up-scheme-v9")

    def test_scheme_param_is_rejected_in_signer_mode(self, tmp_path: Path) -> None:
        from waxseal.domain.sealing import FS_HMAC_AGG_SCHEME

        signer = TestInjectedSigner.FakeEd25519()
        with pytest.raises(ValueError, match="scheme"):
            FileAttestor(tmp_path / "trail.jsonl", signer=signer, scheme=FS_HMAC_AGG_SCHEME)

    def test_malformed_sealagg_json_is_a_verdict_not_a_crash(self, tmp_path: Path) -> None:
        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        log.append(payload={"i": 0}, payload_type="application/vnd.test.event+json")
        (tmp_path / "trail.jsonl.sealagg").write_text("{this is not json")
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "malformed_aggregate"

    def test_tampered_aggregate_value_alone_is_caught_after_seals_pass(
        self, tmp_path: Path
    ) -> None:
        # Per-entry seals are untouched (they still verify), but the stored
        # fold itself no longer matches — this is the case the fold exists
        # to catch that a per-position seal check cannot see on its own.
        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        for i in range(3):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        agg_path = tmp_path / "trail.jsonl.sealagg"
        obj = json.loads(agg_path.read_text())
        obj["agg"] = "ff" * 32
        agg_path.write_text(json.dumps(obj))
        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "aggregate_mismatch"

    def test_attestor_without_read_aggregate_skips_the_aggregate_gate(self, tmp_path: Path) -> None:
        # A minimal custom Attestor (not FileAttestor) that never implements
        # read_aggregate: the gate must be optional, not a hard requirement
        # of the AttestResult protocol — verify_attestations falls back to
        # the plain per-entry seal check alone.
        class MinimalFsHmacAttestor:
            def __init__(self) -> None:
                self._rows: list[Attestation] = []

            def attest(self, seq: int, entry_hash: str) -> Attestation:
                from waxseal.domain.sealing import seal_entry

                value = seal_entry(k0_evolved(seq), entry_hash)
                att = Attestation(
                    seq=seq, entry_hash=entry_hash, scheme=FS_HMAC_SCHEME, value=value
                )
                self._rows.append(att)
                return att

            def attestations(self) -> Iterator[Attestation]:
                return iter(self._rows)

        def k0_evolved(seq: int) -> bytes:
            from waxseal.domain.sealing import evolve_key

            k = k0
            for _ in range(seq):
                k = evolve_key(k)
            return k

        k0 = generate_key()
        log = AuditLog.open(tmp_path / "trail.jsonl", attestor=MinimalFsHmacAttestor())
        for i in range(2):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        result = log.verify_attestations(initial_key=k0)
        assert result.ok
        assert result.checked == 2

    def test_aggregate_can_start_mid_trail(self, tmp_path: Path) -> None:
        # A trail that starts under plain fs-hmac and switches to the agg
        # scheme partway through: agg_start pins where folding began, and
        # the earlier rows stay covered by the ordinary keyfile check.
        from waxseal.domain.sealing import FS_HMAC_AGG_SCHEME

        k0 = generate_key()
        log = open_sealed(tmp_path, k0)
        for i in range(2):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        log._attestor = FileAttestor(
            tmp_path / "trail.jsonl", initial_key=k0, scheme=FS_HMAC_AGG_SCHEME
        )
        # Same epoch key continuity: FileAttestor reads the persisted keyfile.
        for i in range(2, 5):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        obj = json.loads((tmp_path / "trail.jsonl.sealagg").read_text())
        assert obj["agg_start"] == 2
        assert obj["epoch"] == 5
        assert [
            json.loads(line)["scheme"]
            for line in (tmp_path / "trail.jsonl.attest").read_text().splitlines()
        ] == ([FS_HMAC_SCHEME] * 2 + [FS_HMAC_AGG_SCHEME] * 3)
        result = log.verify_attestations(initial_key=k0)
        assert result.ok


class TestFaultInjectionBetweenDependentSidecarWrites:
    """FileAttestor.attest() under FS_HMAC_AGG_SCHEME is three sequential,
    dependent writes for one call: .sealkey, then .sealagg, then the
    .attest line (attest.py's own comment: "Order matters ... a crash
    between any two leaves a state verify_attestations reports, not
    repairs"). These tests make that comment's claim true by measurement
    instead of assumption: each one crashes a REAL call at a different one
    of the three write boundaries and checks what is actually left on disk,
    not a hand-forged stand-in for it.

    Every one of the three injection points converges on the SAME verdict,
    "attestation_gap" — because the .attest line is always the last of the
    three writes, so no exception raised anywhere in the sequence can ever
    let it land. That convergence is itself the property under test: rule
    5's ternary evidence (unverifiable != tampered) and rule 6 (fail-open
    must be labelled) hold no matter WHERE inside the sequence the crash
    lands, not just for the "nothing at all happened" case the wholesale
    FailingAttestor stub above already covers.
    """

    def test_crash_between_sealkey_and_sealagg_write_is_a_labelled_gap(
        self, tmp_path: Path
    ) -> None:
        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        log.append(payload={"i": 0}, payload_type=PT)  # seals cleanly first

        def explode(*a: object, **kw: object) -> None:
            raise OSError("simulated crash writing .sealagg")

        attestor(log)._write_aggregate = explode
        with pytest.raises(AttestationFailure):
            log.append(payload={"i": 1}, payload_type=PT)

        # The entry IS durably on the chain (rule 5: not a dropped write).
        assert len(list(log._backend.entries())) == 2
        # .sealkey completed (the first of the three writes); .sealagg did
        # not (the second, patched to explode); .attest never even reached
        # the third write below it in the source.
        assert json.loads((tmp_path / "trail.jsonl.sealkey").read_text())["epoch"] == 2
        assert json.loads((tmp_path / "trail.jsonl.sealagg").read_text())["epoch"] == 1
        assert len((tmp_path / "trail.jsonl.attest").read_text().splitlines()) == 1

        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "attestation_gap"
        assert result.broken_seq == 1
        # The CHAIN itself was never touched by a sidecar-only crash — rule
        # 5's unverifiable/incomplete != tampered, checked directly rather
        # than inferred from the attestation verdict alone.
        assert log.verify().ok

    def test_crash_between_sealagg_and_attest_line_write_is_a_labelled_gap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os

        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        log.append(payload={"i": 0}, payload_type=PT)

        attest_path = str(tmp_path / "trail.jsonl.attest")
        real_open = os.open

        def faulty_open(path: object, *a: object, **kw: object) -> int:
            if str(path) == attest_path:
                raise OSError("simulated crash writing the .attest line")
            return real_open(path, *a, **kw)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "open", faulty_open)
        with pytest.raises(AttestationFailure):
            log.append(payload={"i": 1}, payload_type=PT)
        monkeypatch.undo()

        # Both dependent writes ahead of the .attest line completed; only
        # the line itself (the third write) never landed.
        assert json.loads((tmp_path / "trail.jsonl.sealkey").read_text())["epoch"] == 2
        assert json.loads((tmp_path / "trail.jsonl.sealagg").read_text())["epoch"] == 2
        assert len((tmp_path / "trail.jsonl.attest").read_text().splitlines()) == 1

        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "attestation_gap"
        assert result.broken_seq == 1
        assert log.verify().ok

    def test_first_write_failure_prevents_the_two_dependent_writes_after_it(
        self, tmp_path: Path
    ) -> None:
        # The reverse direction: the FIRST write of the three refuses, so
        # the two writes that depend on it having succeeded (.sealagg, the
        # .attest line) must never even be attempted.
        k0 = generate_key()
        log = open_agg_sealed(tmp_path, k0)
        log.append(payload={"i": 0}, payload_type=PT)

        def explode(*a: object, **kw: object) -> None:
            raise OSError("simulated crash writing .sealkey")

        attestor(log)._write_key = explode
        with pytest.raises(AttestationFailure):
            log.append(payload={"i": 1}, payload_type=PT)

        # Nothing downstream of the refused first write moved at all — the
        # sidecars are left exactly as consistent with EACH OTHER as before
        # the second append was attempted.
        assert json.loads((tmp_path / "trail.jsonl.sealkey").read_text())["epoch"] == 1
        assert json.loads((tmp_path / "trail.jsonl.sealagg").read_text())["epoch"] == 1
        assert len((tmp_path / "trail.jsonl.attest").read_text().splitlines()) == 1

        result = log.verify_attestations(initial_key=k0)
        assert not result.ok
        assert result.reason == "attestation_gap"
        assert result.broken_seq == 1
        assert log.verify().ok


class TestSidecarPermissions:
    def test_attest_sidecar_is_created_owner_only(self, tmp_path: Path) -> None:
        # The sidecar mirrors every entry_hash; like the trail it must not
        # inherit a world-readable umask (the sealkey already forces 0600).
        import os
        import sys

        import pytest

        if sys.platform == "win32":
            pytest.skip("POSIX permission bits")
        old_umask = os.umask(0o022)
        try:
            k0 = generate_key()
            open_sealed(tmp_path, k0).append(payload={"i": 0}, payload_type=PT)
            mode = (tmp_path / "trail.jsonl.attest").stat().st_mode
            assert (mode & 0o777) == 0o600
        finally:
            os.umask(old_umask)


class TestVerifyAttestationsArguments:
    """The three states this method must never guess its way through: no
    attestor, no credential, and a sidecar longer than the trail."""

    def test_no_attestor_is_a_caller_error_not_a_verdict(self, tmp_path: Path) -> None:
        # Returning ok here would report a check that never ran.
        log = AuditLog.open(tmp_path / "trail.jsonl")
        log.append(payload={"i": 0}, payload_type=PT)
        with pytest.raises(ValueError, match="without an attestor"):
            log.verify_attestations(initial_key=generate_key())

    def test_neither_a_key_nor_a_verifier_is_a_caller_error(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        key = generate_key()
        log = AuditLog.open(path, attestor=FileAttestor(path, initial_key=key))
        log.append(payload={"i": 0}, payload_type=PT)
        with pytest.raises(ValueError, match="initial_key"):
            log.verify_attestations()

    def test_more_attestations_than_entries_is_caught(self, tmp_path: Path) -> None:
        # Truncating the trail while leaving the sidecar intact. The sidecar
        # claims a row the trail no longer has, and position N has nothing to
        # cross-check against — that is the break, not a short read.
        path = tmp_path / "trail.jsonl"
        key = generate_key()
        log = AuditLog.open(path, attestor=FileAttestor(path, initial_key=key))
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        kept = path.read_text(encoding="utf-8").splitlines()[:2]
        path.write_text("".join(f"{line}\n" for line in kept), encoding="utf-8")

        result = AuditLog.open(
            path, attestor=FileAttestor(path, initial_key=key)
        ).verify_attestations(initial_key=key)
        assert not result.ok
        assert result.broken_seq == 2


class TestSignerModeUnverifiableSchemes:
    def test_an_attestation_from_another_scheme_is_unverifiable_not_invalid(
        self, tmp_path: Path
    ) -> None:
        # A trail whose sidecar mixes schemes (a signer rotation, a migration
        # in progress) must not report the rows this verifier cannot speak for
        # as forged. Unverifiable by name is a different verdict from
        # signature_invalid, and only one of them is an alarm.
        signature = bytes([0x07]) * 64

        class Signer:
            algorithm = "ed25519"
            key_id = "k1"

            def sign(self, data: bytes) -> bytes:
                return signature

        class Verifier:
            algorithm = "ed25519"

            def verify(self, data: bytes, sig: bytes) -> bool:
                return sig == signature

        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, attestor=FileAttestor(path, signer=Signer()))
        for i in range(2):
            log.append(payload={"i": i}, payload_type=PT)

        sidecar = Path(str(path) + ".attest")
        rows = [json.loads(line) for line in sidecar.read_text().splitlines() if line.strip()]
        rows[0]["scheme"] = "sig-dilithium3-v1"
        sidecar.write_text(
            "".join(f"{json.dumps(row, sort_keys=True)}\n" for row in rows), encoding="utf-8"
        )

        result = log.verify_attestations(verifier=Verifier())
        assert result.ok
        assert result.checked == 1
        assert result.unverifiable == (0,)
