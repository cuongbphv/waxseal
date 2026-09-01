"""CLI: `waxseal verify-handoff` — SPEC D3 cross-trail handoff binding.

Wires domain/handoff.py's `binding_holds` (read-only, no I/O) into a
subcommand exactly the way `consistency`/`reconcile-tickets` already wire
domain/anchoring.py and domain/tickets.py: this command opens the delegate
trail (positional `path`) and the origin trail (`--origin`, local path only —
no URL/remote support), scans the delegate for handoff-binding entries, and
checks each against the origin's CURRENT `entry_hashes()`. Appends nothing to
either trail (CLAUDE.md: "the CLI never appends chain entries").

Exit codes: 0 = nothing to check, or every binding found holds; 1 = at least
one binding no longer holds (a genuinely detected mismatch — `binding_holds`
is a deterministic comparison against the origin's own hashes, never merely
"unverifiable"); 3 = a named trail path does not exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.sources.handoff import record_handoff

OTHER_PT = "application/vnd.test.event+json"


def open_log(path: Path) -> AuditLog:
    return AuditLog.open(path)


def fill(log: AuditLog, n: int, *, prefix: str = "e") -> None:
    for i in range(n):
        log.append(payload={"i": i, "tag": prefix}, payload_type=OTHER_PT)


def tip(log: AuditLog) -> tuple[int, str]:
    entries = list(log.entries())
    last = entries[-1]
    return last.header.seq, last.entry_hash


class TestHoldingBinding:
    def test_valid_binding_holds_exit_0(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.cli import main

        origin_path = tmp_path / "origin.jsonl"
        log_origin = open_log(origin_path)
        fill(log_origin, 3, prefix="origin")
        seq_o, hash_o = tip(log_origin)

        delegate_path = tmp_path / "delegate.jsonl"
        log_delegate = open_log(delegate_path)
        record_handoff(log_delegate, chain_id="origin-chain", seq=seq_o, head_hash=hash_o)
        fill(log_delegate, 2, prefix="delegate")

        code = main(
            ["verify-handoff", str(delegate_path), "--origin", str(origin_path)]
        )
        out = capsys.readouterr().out

        assert code == 0
        assert "holds" in out
        assert "DOES NOT HOLD" not in out
        assert "all 1 handoff binding(s) hold" in out


class TestBrokenBinding:
    def test_rewritten_origin_no_longer_holds_exit_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.cli import main

        origin_path = tmp_path / "origin.jsonl"
        log_origin = open_log(origin_path)
        fill(log_origin, 3, prefix="origin")
        seq_o, hash_o = tip(log_origin)

        delegate_path = tmp_path / "delegate.jsonl"
        log_delegate = open_log(delegate_path)
        record_handoff(log_delegate, chain_id="origin-chain", seq=seq_o, head_hash=hash_o)
        fill(log_delegate, 2, prefix="delegate")

        # An attacker replaces the origin's ENTIRE trail with a different,
        # but self-consistent, one -- the same "whole-trail rewrite"
        # technique tests/test_sources_handoff.py's own rewritten-A test
        # uses (anchoring.py's module docstring names this as what a hash
        # chain alone cannot resist).
        rewritten_origin_path = tmp_path / "origin-rewritten.jsonl"
        log_rewritten = open_log(rewritten_origin_path)
        fill(log_rewritten, 3, prefix="origin-different-content")
        assert log_rewritten.verify().ok  # passes ITS OWN check; that is the threat

        code = main(
            ["verify-handoff", str(delegate_path), "--origin", str(rewritten_origin_path)]
        )
        out = capsys.readouterr().out

        assert code == 1
        assert f"seq {0}:" in out
        assert "DOES NOT HOLD" in out
        assert "no longer holds" in out


class TestNothingToCheck:
    def test_no_handoff_entries_is_exit_0_not_an_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.cli import main

        origin_path = tmp_path / "origin.jsonl"
        fill(open_log(origin_path), 1)

        delegate_path = tmp_path / "delegate.jsonl"
        fill(open_log(delegate_path), 2)  # ordinary entries, no handoff binding

        code = main(
            ["verify-handoff", str(delegate_path), "--origin", str(origin_path)]
        )
        out = capsys.readouterr().out

        assert code == 0
        assert "nothing to check" in out


class TestMultiHop:
    def test_two_level_delegation_a_to_b_to_c_all_hold(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.cli import main

        log_a = open_log(tmp_path / "a.jsonl")
        fill(log_a, 2, prefix="a")
        seq_a, hash_a = tip(log_a)

        log_b = open_log(tmp_path / "b.jsonl")
        record_handoff(log_b, chain_id="agent-a", seq=seq_a, head_hash=hash_a)
        fill(log_b, 2, prefix="b")
        seq_b, hash_b = tip(log_b)

        log_c = open_log(tmp_path / "c.jsonl")
        record_handoff(log_c, chain_id="agent-b", seq=seq_b, head_hash=hash_b)
        fill(log_c, 2, prefix="c")

        # C's own binding to B.
        code_c = main(
            ["verify-handoff", str(tmp_path / "c.jsonl"), "--origin", str(tmp_path / "b.jsonl")]
        )
        out_c = capsys.readouterr().out
        assert code_c == 0
        assert "all 1 handoff binding(s) hold" in out_c

        # B's own binding to A, one hop further out.
        code_b = main(
            ["verify-handoff", str(tmp_path / "b.jsonl"), "--origin", str(tmp_path / "a.jsonl")]
        )
        out_b = capsys.readouterr().out
        assert code_b == 0
        assert "all 1 handoff binding(s) hold" in out_b


class TestMissingOriginTrail:
    def test_origin_path_that_does_not_exist_is_exit_3(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.cli import main

        delegate_path = tmp_path / "delegate.jsonl"
        log_delegate = open_log(delegate_path)
        record_handoff(log_delegate, chain_id="origin-chain", seq=0, head_hash="a" * 64)

        code = main(
            [
                "verify-handoff",
                str(delegate_path),
                "--origin",
                str(tmp_path / "does-not-exist.jsonl"),
            ]
        )
        err = capsys.readouterr().err

        assert code == 3
        assert "no such origin trail" in err


class TestHeaderOnlyPayloadUnavailable:
    def test_entry_without_payload_bytes_is_skipped_not_treated_as_failing(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Entry.payload is None only for a header-only reader (its own
        # contract) -- never something jsonl/sqlite/postgres backends
        # produce from entries(). Same injection technique
        # tests/test_sources_decisions.py::test_entry_without_payload_bytes_
        # yields_none uses to reach that branch: poke a real backend's
        # stored Entry to drop its payload after the fact.
        from typing import cast

        from waxseal.adapters.memory import MemoryBackend
        from waxseal.cli import _verify_handoff
        from waxseal.domain.header import Entry

        origin_path = tmp_path / "origin.jsonl"
        fill(open_log(origin_path), 1)

        log_delegate = AuditLog(MemoryBackend())
        record_handoff(log_delegate, chain_id="origin-chain", seq=0, head_hash="a" * 64)
        stored = list(log_delegate._backend.entries())[0]
        # AuditLog.__init__ types its backend param `JSONLBackend | Any`;
        # cast to the concrete backend this test actually constructed.
        delegate_backend = cast(MemoryBackend, log_delegate._backend)
        delegate_backend._entries[0] = Entry(
            header=stored.header, entry_hash=stored.entry_hash, payload=None
        )

        code = _verify_handoff(log_delegate, origin_path=origin_path)
        out = capsys.readouterr().out

        assert code == 0
        assert "payload unavailable" in out
        assert "nothing to check" in out
