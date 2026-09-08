"""CLI: what `verify` says about the `.receipts` sidecar (SPEC.md section 19).

This file freezes the exit-code table, because the distinctions it encodes are
what an operator's alerting gets built on:

| receipt_mismatch          | 1 |
| receipt_beyond_head       | 1 |
| malformed_receipt_record  | 1 |
| unreadable_record_version | 2 |
| no sidecar at all         | unchanged, `receipts: not recorded` |

The exit-1/exit-2 split is section 17's asymmetry and it is tested head-on
below: corrupt bytes in a format THIS project defines are a break, while a
record version only a NEWER build understands is unverifiable by name.
Collapsing them either way is the beads-v1.2.2 failure class.

The headline is `TestTheWindowIsOneEntry`: a rewrite the chain verifier itself
passes — every hash recomputed, self-consistent — is contradicted by a receipt
from the very next append, with no checkpoint and no anchor anywhere in the
picture.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.adapters.fake_chain_server import FakeChainServer, fake_transport
from waxseal import AuditLog
from waxseal.adapters._envelope import to_obj
from waxseal.adapters.receipts import receipts_path
from waxseal.adapters.remote import RemoteBackend
from waxseal.cli import main

PT = "application/vnd.test.event+json"
TS = "2026-09-01T00:00:00+00:00"
PAYLOADS: list[dict[str, object]] = [{"i": 0}, {"i": 1}, {"i": 2}]


def write_trail(path: Path, payloads: list[dict[str, object]]) -> AuditLog:
    """A plain local JSONL trail, written at a pinned timestamp so an honest
    trail and a rewritten one differ ONLY where their payloads differ."""
    log = AuditLog.open(path, now_fn=lambda: TS)
    for payload in payloads:
        log.append(payload=payload, payload_type=PT)
    return log


def acknowledged_trail(tmp_path: Path, payloads: list[dict[str, object]] | None = None) -> Path:
    """Append through a remote backend that issues receipts, then mirror what
    the server holds into a local trail beside the sidecar it just wrote.

    That mirror is what an operator verifies offline, and what an attacker with
    write access to the disk gets to rewrite.
    """
    trail = tmp_path / "trail.jsonl"
    backend = RemoteBackend(
        "https://ledger.example",
        transport=fake_transport(FakeChainServer(issue_receipts=True)),
        receipts_trail=trail,
        now_fn=lambda: TS,
    )
    remote = AuditLog(backend, now_fn=lambda: TS)
    for payload in payloads if payloads is not None else PAYLOADS:
        remote.append(payload=payload, payload_type=PT)
    trail.write_text(
        "".join(
            json.dumps(to_obj(entry, backend="JSONL"), sort_keys=True, separators=(",", ":")) + "\n"
            for entry in remote.entries()
        ),
        encoding="utf-8",
    )
    return trail


def rewrite_sidecar(trail: Path, edit: Callable[[list[dict[str, object]]], None]) -> None:
    records = [
        json.loads(line) for line in receipts_path(trail).read_text(encoding="utf-8").splitlines()
    ]
    edit(records)
    receipts_path(trail).write_text(
        "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in records),
        encoding="utf-8",
    )


class TestTheWindowIsOneEntry:
    def test_a_self_consistent_rewrite_the_chain_passes_contradicts_a_receipt(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The attack anchoring alone cannot see between checkpoints: every
        # header rebuilt, every hash recomputed, chain verifies clean.
        trail = acknowledged_trail(tmp_path)
        forged = tmp_path / "forged.jsonl"
        write_trail(forged, [{"i": 0}, {"i": "tampered"}, {"i": 2}])
        trail.write_text(forged.read_text(encoding="utf-8"), encoding="utf-8")

        assert main(["verify", str(forged)]) == 0  # the rewrite itself is a clean chain

        code = main(["verify", str(trail)])
        out = capsys.readouterr().out
        assert "ok (checked=3)" in out  # the chain dimension still says intact
        assert "RECEIPTS BROKEN at seq=1: receipt_mismatch" in out
        assert code == 1
        # No checkpoint, no anchor, no cadence: the contradiction is available
        # from the very next append, not from the next anchor event.
        assert not (tmp_path / "trail.jsonl.anchors").exists()

    def test_one_flipped_byte_of_the_trail_is_caught_at_that_seq(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = acknowledged_trail(tmp_path)
        lines = trail.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[1])
        flipped = "0" if entry["entry_hash"][0] != "0" else "1"
        entry["entry_hash"] = flipped + entry["entry_hash"][1:]
        lines[1] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        trail.write_text("\n".join(lines) + "\n", encoding="utf-8")

        code = main(["verify", str(trail)])
        out = capsys.readouterr().out
        assert "RECEIPTS BROKEN at seq=1: receipt_mismatch" in out
        assert code == 1


class TestTheReasonTable:
    def test_an_honest_trail_and_its_receipts_agree(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = acknowledged_trail(tmp_path)
        code = main(["verify", str(trail)])
        out = capsys.readouterr().out
        assert "receipts ok (checked=3, latest=seq 2)" in out
        assert code == 0

    def test_a_truncated_trail_is_receipt_beyond_head(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Rollback: the trail no longer reaches an entry the server acknowledged.
        trail = acknowledged_trail(tmp_path)
        lines = trail.read_text(encoding="utf-8").splitlines()
        trail.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

        code = main(["verify", str(trail)])
        out = capsys.readouterr().out
        assert "RECEIPTS BROKEN at seq=2: receipt_beyond_head" in out
        assert code == 1

    def test_a_malformed_record_is_exit_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = acknowledged_trail(tmp_path)
        with receipts_path(trail).open("a") as f:
            f.write("{this is not a record\n")

        code = main(["verify", str(trail)])
        out = capsys.readouterr().out
        assert "RECEIPTS BROKEN at line 4: malformed_receipt_record" in out
        assert code == 1

    def test_a_newer_record_version_is_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = acknowledged_trail(tmp_path)
        rewrite_sidecar(trail, lambda records: records[1].update(v=2))

        code = main(["verify", str(trail)])
        out = capsys.readouterr().out
        assert "unverifiable by name" in out
        assert "NOT evidence of tampering" in out
        assert code == 2


class TestTheAsymmetryIsNotCollapsed:
    """Same field, same corruption, one version stamp apart: exit 1 vs exit 2.

    This is the single test that would go green if someone "simplified" the
    reason table by treating every unreadable record alike.
    """

    @pytest.mark.parametrize(
        ("version", "expected_code"),
        [
            (1, 1),  # a version this build owns: corrupt bytes are a break
            (2, 2),  # a version only a newer build owns: unverifiable by name
        ],
    )
    def test_one_version_stamp_decides_break_versus_unverifiable(
        self, tmp_path: Path, version: int, expected_code: int
    ) -> None:
        trail = acknowledged_trail(tmp_path)

        def corrupt(records: list[dict[str, object]]) -> None:
            records[1]["v"] = version
            records[1]["entry_hash"] = "not-a-hash"

        rewrite_sidecar(trail, corrupt)
        assert main(["verify", str(trail)]) == expected_code

    def test_a_real_break_is_never_masked_by_an_unreadable_record(self, tmp_path: Path) -> None:
        # Verdict.join in severity order: 2 is the larger exit code and the
        # weaker finding, and it must never override a detected rewrite.
        trail = acknowledged_trail(tmp_path)

        def corrupt(records: list[dict[str, object]]) -> None:
            records[0]["entry_hash"] = "f" * 64  # a real mismatch, version 1
            records[1]["v"] = 9  # unreadable, in the same file

        rewrite_sidecar(trail, corrupt)
        assert main(["verify", str(trail)]) == 1


class TestAbsentIsNeverAFailure:
    def test_no_sidecar_prints_not_recorded_and_leaves_the_verdict_alone(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        write_trail(trail, PAYLOADS)
        code = main(["verify", str(trail)])
        out = capsys.readouterr().out
        assert "receipts: not recorded" in out
        assert code == 0

    def test_a_present_but_empty_sidecar_is_not_the_same_line(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Rule 5 one sidecar over: "checked, found nothing" is not "not
        # recorded", and neither is a failure.
        trail = tmp_path / "trail.jsonl"
        write_trail(trail, PAYLOADS)
        receipts_path(trail).write_text("", encoding="utf-8")
        code = main(["verify", str(trail)])
        out = capsys.readouterr().out
        assert "receipts: not recorded" not in out
        assert "0 record(s)" in out
        assert code == 0

    def test_a_url_target_has_no_local_sidecar_and_says_so(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = FakeChainServer(issue_receipts=True)
        AuditLog(
            RemoteBackend(
                "https://ledger.example", transport=fake_transport(server), now_fn=lambda: TS
            ),
            now_fn=lambda: TS,
        ).append(payload={"i": 0}, payload_type=PT)
        monkeypatch.setattr(
            "waxseal.adapters.remote.urllib_transport", lambda **_: fake_transport(server)
        )
        code = main(["verify", "https://ledger.example"])
        out = capsys.readouterr().out
        assert "receipts: not recorded" in out
        assert code == 0

    def test_a_sidecar_that_cannot_be_read_is_unverifiable_not_a_break(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # An environment fact, not a record-level finding: still never silent
        # (rule 6), and never reported as tampering.
        trail = tmp_path / "trail.jsonl"
        write_trail(trail, PAYLOADS)
        receipts_path(trail).mkdir()
        code = main(["verify", str(trail)])
        out = capsys.readouterr().out
        assert "could not be read" in out
        assert "NOT evidence of tampering" in out
        assert code == 2


class TestHonestLimit:
    def test_the_ok_line_never_implies_a_curated_rewrite_would_be_caught(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # SPEC section 19's honest limit, and the reason it is printed rather
        # than left in a doc: an attacker who rewrites BOTH files passes here.
        trail = acknowledged_trail(tmp_path)
        forged = tmp_path / "forged.jsonl"
        write_trail(forged, [{"i": 0}, {"i": "tampered"}, {"i": 2}])
        trail.write_text(forged.read_text(encoding="utf-8"), encoding="utf-8")

        def curate(records: list[dict[str, object]]) -> None:
            for record, entry in zip(records, AuditLog.open(forged).entries(), strict=True):
                record.update(entry_hash=entry.entry_hash)

        rewrite_sidecar(trail, curate)

        code = main(["verify", str(trail)])
        out = capsys.readouterr().out
        assert code == 0  # the curated rewrite passes, exactly as SPEC 19 says
        assert "curates BOTH" in out  # and the line says so, every time it passes
