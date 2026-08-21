"""End-to-end tests for AuditLog with attestations: forward-secure seals
(stdlib HMAC) and injected asymmetric signers."""

import json
from pathlib import Path

from waxseal import AuditLog
from waxseal.adapters.attest import FileAttestor
from waxseal.domain.sealing import generate_key

PT = "application/vnd.test.event+json"


def open_sealed(tmp_path: Path, k0: bytes) -> AuditLog:
    return AuditLog.open(
        tmp_path / "trail.jsonl",
        attestor=FileAttestor(tmp_path / "trail.jsonl", initial_key=k0),
        now_fn=lambda: "2026-08-21T06:00:00+00:00",
    )


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

    def test_truncating_trail_and_sidecar_together_is_detected(
        self, tmp_path: Path
    ) -> None:
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

    def test_malformed_json_line_in_sidecar_is_malformed_not_a_crash(
        self, tmp_path: Path
    ) -> None:
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
        att_row = {"seq": 1, "entry_hash": evil_hash, "scheme": "fs-hmac-sha256-v1",
                   "value": "00"}
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

    def test_shared_log_concurrent_sealed_appends_attest_every_entry(
        self, tmp_path: Path
    ) -> None:
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
        assert len(list(log._attestor.attestations())) == total
        assert log.verify_attestations(initial_key=k0).ok

    def test_attest_failure_after_persist_is_not_a_dropped_write(
        self, tmp_path: Path
    ) -> None:
        # The entry IS durably on the chain when attest raises; counting it as
        # dropped would make dropped_writes lie (CLAUDE.md rule 5). The loss
        # that actually happened (a missing seal) gets its own counter.
        class FailingAttestor:
            def attest(self, seq: int, entry_hash: str) -> None:
                raise RuntimeError("sidecar disk full")

            def attestations(self):  # noqa: ANN202 - test stub
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
        real_attest = log._attestor.attest
        log._attestor.attest = lambda seq, entry_hash: (_ for _ in ()).throw(
            RuntimeError("sidecar disk full")
        )
        assert log.try_append(payload={"i": 2}, payload_type=PT) is True
        log._attestor.attest = real_attest
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
