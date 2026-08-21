"""Tests for the CLI contract (CLAUDE.md): verify exits 0 intact / 1 broken /
2 intact-but-unverifiable-present. The CLI never writes to the log."""

import json
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.cli import main

PT = "application/vnd.test.event+json"


def make_trail(path: Path, n: int = 3) -> None:
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)


class TestVerify:
    def test_intact_trail_exits_0(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path)
        assert main(["verify", str(path)]) == 0
        assert "ok" in capsys.readouterr().out

    def test_broken_trail_exits_1_and_names_the_break(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 4)
        lines = path.read_text().splitlines()
        obj = json.loads(lines[1])
        obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"
        lines[1] = json.dumps(obj)
        path.write_text("\n".join(lines) + "\n")

        assert main(["verify", str(path)]) == 1
        out = capsys.readouterr().out
        assert "seq=1" in out
        assert "entry_hash_mismatch" in out

    def test_unverifiable_rows_exit_2_not_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # The beads-v1.2.2 replay: rows from an unknown (newer) schema must
        # NOT be reported as tampering — exit 2, distinct from broken.
        path = tmp_path / "trail.jsonl"
        make_trail(path, 2)
        lines = path.read_text().splitlines()
        # Re-sign row 1 under a fingerprint this binary does not know.
        from waxseal.domain.hashing import compute_entry_hash
        from waxseal.domain.header import EntryHeader

        obj = json.loads(lines[1])
        obj["header"]["hash_version"] = "e" * 64
        header = EntryHeader(**obj["header"])
        obj["entry_hash"] = compute_entry_hash(header)
        lines[1] = json.dumps(obj)
        path.write_text("\n".join(lines) + "\n")

        assert main(["verify", str(path)]) == 2
        out = capsys.readouterr().out
        assert "unverifiable" in out

    def test_verify_does_not_modify_the_file(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path)
        before = path.read_bytes()
        main(["verify", str(path)])
        assert path.read_bytes() == before


class TestTailAndInspect:
    def test_tail_prints_last_entries(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 5)
        assert main(["tail", str(path), "-n", "2"]) == 0
        out = capsys.readouterr().out
        assert "seq=3" in out
        assert "seq=4" in out
        assert "seq=2" not in out

    def test_inspect_prints_fingerprint_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        assert main(["inspect", str(path)]) == 0
        out = capsys.readouterr().out
        from waxseal import fingerprint_v1

        assert fingerprint_v1()[:12] in out
        assert "3" in out


class TestHead:
    def test_head_prints_seq_and_entry_hash_for_anchoring(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # `waxseal head` exists so operators can anchor the chain head
        # externally (OpenTimestamps / RFC 3161 / a git commit): an attacker
        # who rewrites the suffix cannot also rewrite the anchored head.
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        assert main(["head", str(path)]) == 0
        out = capsys.readouterr().out.strip()
        import json as _json

        from waxseal import AuditLog as _AuditLog

        entries = list(_AuditLog.open(path)._backend.entries())
        obj = _json.loads(out)
        assert obj == {"seq": 2, "entry_hash": entries[-1].entry_hash}

    def test_head_on_empty_trail_exits_1(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        path.touch()
        assert main(["head", str(path)]) == 1


class TestMissingTrail:
    def test_verify_on_missing_sqlite_path_does_not_create_a_database(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # Read-only contract: opening a missing .db used to CREATE an empty
        # 8KB database (mkdir + DDL) and then report "ok, checked=0".
        path = tmp_path / "nope.db"
        assert main(["verify", str(path)]) == 3
        assert not path.exists()
        assert "no such trail" in capsys.readouterr().err

    def test_verify_on_missing_jsonl_path_is_an_error_not_ok(self, tmp_path: Path) -> None:
        # A typo'd path must not verify as an intact empty chain.
        assert main(["verify", str(tmp_path / "nope.jsonl")]) == 3

    def test_tail_and_inspect_and_head_error_on_missing_path(self, tmp_path: Path) -> None:
        for command in ("tail", "inspect", "head"):
            assert main([command, str(tmp_path / "nope.jsonl")]) == 3
