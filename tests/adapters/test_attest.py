"""FileAttestor's refusals and its keyfile continuity check.

`tests/test_sealed_log.py` covers sealing through AuditLog. This file covers
the attestor's own edges — the states where it must refuse rather than
improvise, because improvising here means writing a seal that says something
that is not true.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from waxseal.adapters.attest import FileAttestor
from waxseal.domain.sealing import FS_HMAC_AGG_SCHEME, evolve_key

KEY = b"\x33" * 32


class FakeSigner:
    algorithm = "ed25519"
    key_id = "k1"

    def sign(self, data: bytes) -> bytes:
        return b"\x01" * 64


class TestConstruction:
    def test_neither_a_key_nor_a_signer_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="exactly one"):
            FileAttestor(tmp_path / "t.jsonl")

    def test_both_a_key_and_a_signer_is_refused(self, tmp_path: Path) -> None:
        # Ambiguous configuration, and the ambiguity would decide silently
        # which of two very different attestation schemes the trail gets.
        with pytest.raises(ValueError, match="exactly one"):
            FileAttestor(tmp_path / "t.jsonl", initial_key=KEY, signer=FakeSigner())

    def test_a_scheme_with_a_signer_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="signer mode"):
            FileAttestor(tmp_path / "t.jsonl", signer=FakeSigner(), scheme=FS_HMAC_AGG_SCHEME)

    def test_an_unknown_scheme_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unknown scheme"):
            FileAttestor(tmp_path / "t.jsonl", initial_key=KEY, scheme="fs-hmac-sha512-v9")


class TestEpochDesync:
    def test_sealing_a_seq_the_keyfile_does_not_match_is_refused(self, tmp_path: Path) -> None:
        # A crash between append and attest leaves the keyfile one behind.
        # Re-aligning silently would seal a row with a key from a different
        # epoch, which is a forged history rather than a recovery.
        path = tmp_path / "trail.jsonl"
        attestor = FileAttestor(path, initial_key=KEY)
        attestor.attest(0, "a" * 64)
        with pytest.raises(RuntimeError, match="out of sync"):
            attestor.attest(0, "b" * 64)


class TestAttestations:
    def test_a_missing_sidecar_yields_nothing_rather_than_raising(self, tmp_path: Path) -> None:
        # "Never attested" is a state, not an error: a trail can legitimately
        # have no sidecar yet, and the verdict for that belongs to the caller.
        attestor = FileAttestor(tmp_path / "trail.jsonl", initial_key=KEY)
        Path(str(tmp_path / "trail.jsonl") + ".attest").unlink(missing_ok=True)
        assert list(attestor.attestations()) == []

    def test_blank_lines_in_the_sidecar_are_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        attestor = FileAttestor(path, initial_key=KEY)
        attestor.attest(0, "a" * 64)
        sidecar = Path(str(path) + ".attest")
        sidecar.write_text("\n" + sidecar.read_text() + "\n\n", encoding="utf-8")
        assert len(list(attestor.attestations())) == 1


class TestContinuity:
    def test_signer_mode_has_no_keyfile_to_check(self, tmp_path: Path) -> None:
        # Returning None here means "not applicable", and the caller must not
        # read it as "the keyfile checked out".
        attestor = FileAttestor(tmp_path / "trail.jsonl", signer=FakeSigner())
        assert attestor.check_continuity(KEY, 0) is None

    def test_a_missing_keyfile_is_named_not_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        attestor = FileAttestor(path, initial_key=KEY)
        Path(str(path) + ".sealkey").unlink()
        assert attestor.check_continuity(KEY, 0) == "keyfile_missing"

    def test_the_right_epoch_with_the_wrong_key_is_caught(self, tmp_path: Path) -> None:
        # The truncation defence rests on the keyfile being one-way. An
        # attacker who fakes the epoch counter but cannot compute the evolved
        # key has to be caught by the key itself.
        path = tmp_path / "trail.jsonl"
        attestor = FileAttestor(path, initial_key=KEY)
        attestor.attest(0, "a" * 64)
        keyfile = Path(str(path) + ".sealkey")
        keyfile.write_text(json.dumps({"epoch": 1, "key": ("cc" * 32)}), encoding="utf-8")
        assert attestor.check_continuity(KEY, 1) == "keyfile_key_mismatch"

    def test_a_continuous_keyfile_passes(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        attestor = FileAttestor(path, initial_key=KEY)
        attestor.attest(0, "a" * 64)
        assert attestor.check_continuity(KEY, 1) is None
        # Falsifiability receipt for the test above: the stored key really is
        # the evolved one, so "key_mismatch" was not passing by accident.
        stored = json.loads(Path(str(path) + ".sealkey").read_text())
        assert stored["key"] == evolve_key(KEY).hex()
