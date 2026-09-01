"""Tests for the OpenClaw audit-ledger source.

OpenClaw keeps its own metadata-only ledger (`audit_events` in
`state/openclaw.sqlite`) but prunes it — 30-day expiry, 100k row cap — and
records no hash per row. `docs/gateway/audit.md`: "It is not a lossless
compliance archive; if you need one, use an external system". This source is
that external system: it pages the documented `openclaw audit --json` export
into a waxseal chain.

Two properties get most of the test weight, because both are places where an
audit tool could lie:

- the export is newest-first (`ORDER BY sequence DESC`, `--cursor` means
  `sequence < cursor`), so the ingest must reverse it — a chain whose order
  disagrees with the ledger's own order would misreport what happened when;
- a hole in the sequence means rows were pruned OR dropped, and the two are
  indistinguishable from outside. It is reported as a gap, never as tampering,
  and never as a measured count of loss (CLAUDE.md rules 4 and 5).
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any

import pytest

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.sources.openclaw import (
    OPENCLAW_AUDIT_PAYLOAD_TYPE,
    OPENCLAW_GAP_PAYLOAD_TYPE,
    ingest,
    last_ingested_sequence,
)


def rec(seq: int, **kw: Any) -> dict[str, Any]:
    """One `audit_events` record as `openclaw audit --json` emits it
    (field names from src/audit/audit-event-store.ts parseAuditRecordBase)."""
    record = {
        "schemaVersion": 1,
        "sequence": seq,
        "eventId": f"evt-{seq}",
        "sourceSequence": seq,
        "occurredAt": 1_700_000_000_000 + seq,
        "redaction": "metadata_only",
        "kind": "tool_action",
        "action": "tool.action.finished",
        "status": "succeeded",
        "actorType": "agent",
        "actorId": "main",
        "agentId": "main",
        "runId": "run-1",
        "toolName": "Bash",
    }
    record.update(kw)
    return record


class FakeLedger:
    """Stands in for `openclaw audit --json`: newest-first pages, `--cursor`
    is exclusive and means `sequence < cursor` (audit-event-store.ts L664+)."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self.records = sorted(records, key=lambda r: r["sequence"], reverse=True)
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        limit = int(args[args.index("--limit") + 1])
        cursor = int(args[args.index("--cursor") + 1]) if "--cursor" in args else None
        rows = [r for r in self.records if cursor is None or r["sequence"] < cursor]
        page = rows[:limit]
        out: dict[str, Any] = {"events": page}
        if page and len(rows) > limit:
            out["nextCursor"] = page[-1]["sequence"]
        return json.dumps(out)


def open_log(tmp_path: Path, **kw: Any) -> AuditLog:
    return AuditLog.open(
        tmp_path / "trail.jsonl",
        now_fn=lambda: "2026-08-22T06:00:00+00:00",
        **kw,
    )


def payloads(log: AuditLog, payload_type: str) -> list[dict[str, Any]]:
    return [
        json.loads(e.payload)
        for e in log._backend.entries()
        if e.header.payload_type == payload_type and e.payload is not None
    ]


class TestLastIngestedSequence:
    def test_none_on_an_empty_trail(self, tmp_path: Path) -> None:
        # None is "never ingested", which is not the same fact as sequence 0
        # (CLAUDE.md rule 5) — a caller must be able to tell them apart.
        assert last_ingested_sequence(open_log(tmp_path)) is None

    def test_none_when_the_trail_holds_only_foreign_entries(self, tmp_path: Path) -> None:
        log = open_log(tmp_path)
        log.append(payload={"hello": "world"}, payload_type="application/vnd.test.other+json")
        assert last_ingested_sequence(log) is None

    def test_highest_ingested_sequence_wins_regardless_of_chain_order(
        self, tmp_path: Path
    ) -> None:
        log = open_log(tmp_path)
        for seq in (7, 9, 8):
            log.append(payload=rec(seq), payload_type=OPENCLAW_AUDIT_PAYLOAD_TYPE)
        assert last_ingested_sequence(log) == 9


class TestIngest:
    def test_single_page_lands_one_entry_per_record(self, tmp_path: Path) -> None:
        log = open_log(tmp_path)
        ledger = FakeLedger([rec(1), rec(2), rec(3)])

        result = ingest(log, run_fn=ledger)

        assert result.ingested == 3
        assert result.last_sequence == 3
        assert result.dropped == 0
        got = payloads(log, OPENCLAW_AUDIT_PAYLOAD_TYPE)
        assert [p["sequence"] for p in got] == [1, 2, 3]
        assert got[0]["eventId"] == "evt-1"
        assert log.verify().ok

    def test_pages_backwards_but_appends_in_ascending_sequence_order(
        self, tmp_path: Path
    ) -> None:
        log = open_log(tmp_path)
        ledger = FakeLedger([rec(s) for s in range(1, 11)])

        result = ingest(log, limit=3, run_fn=ledger)

        assert result.ingested == 10
        assert [p["sequence"] for p in payloads(log, OPENCLAW_AUDIT_PAYLOAD_TYPE)] == list(
            range(1, 11)
        )
        # Four pages of three, walking down via nextCursor.
        assert len(ledger.calls) == 4
        assert "--cursor" not in ledger.calls[0]
        assert ledger.calls[1][ledger.calls[1].index("--cursor") + 1] == "8"

    def test_rerun_is_idempotent(self, tmp_path: Path) -> None:
        log = open_log(tmp_path)
        ledger = FakeLedger([rec(s) for s in range(1, 6)])
        ingest(log, run_fn=ledger)

        again = ingest(log, run_fn=ledger)

        assert again.ingested == 0
        assert again.last_sequence == 5
        assert len(payloads(log, OPENCLAW_AUDIT_PAYLOAD_TYPE)) == 5

    def test_resume_only_takes_records_newer_than_the_last_ingested(
        self, tmp_path: Path
    ) -> None:
        log = open_log(tmp_path)
        ledger = FakeLedger([rec(s) for s in range(1, 4)])
        ingest(log, run_fn=ledger)

        ledger.records = sorted(
            [rec(s) for s in range(1, 7)], key=lambda r: r["sequence"], reverse=True
        )
        result = ingest(log, limit=2, run_fn=ledger)

        assert result.ingested == 3
        assert [p["sequence"] for p in payloads(log, OPENCLAW_AUDIT_PAYLOAD_TYPE)] == [
            1, 2, 3, 4, 5, 6,
        ]

    def test_stops_paging_once_it_reaches_already_ingested_records(
        self, tmp_path: Path
    ) -> None:
        log = open_log(tmp_path)
        ledger = FakeLedger([rec(s) for s in range(1, 21)])
        ingest(log, run_fn=ledger)
        ledger.calls.clear()
        ledger.records = sorted(
            [rec(s) for s in range(1, 23)], key=lambda r: r["sequence"], reverse=True
        )

        ingest(log, limit=5, run_fn=ledger)

        # One page contained both new records and the ingest boundary: no
        # reason to walk the rest of a 22-row ledger.
        assert len(ledger.calls) == 1

    def test_first_run_against_a_pruned_ledger_reports_no_gap(self, tmp_path: Path) -> None:
        # The ledger's oldest retained row is 5000; nothing is "missing"
        # relative to a chain that has never ingested anything.
        log = open_log(tmp_path)
        ledger = FakeLedger([rec(5000), rec(5001)])

        result = ingest(log, run_fn=ledger)

        assert result.gaps == ()
        assert payloads(log, OPENCLAW_GAP_PAYLOAD_TYPE) == []


class TestGaps:
    def test_prune_between_runs_is_recorded_as_a_gap_not_a_tamper(
        self, tmp_path: Path
    ) -> None:
        log = open_log(tmp_path)
        ingest(log, run_fn=FakeLedger([rec(1), rec(2)]))

        # Rows 3..9 aged out (or were dropped) before this run saw them.
        result = ingest(log, run_fn=FakeLedger([rec(10), rec(11)]))

        # This is the happy path: gaps=None means "not measured" (an
        # exceptional ingest kind, domain/openclaw.py), which does not apply
        # here.
        assert result.gaps is not None
        assert len(result.gaps) == 1
        gap = result.gaps[0]
        assert (gap.missing_after, gap.missing_before) == (2, 10)
        assert gap.cause == "prune_or_drop"
        notices = payloads(log, OPENCLAW_GAP_PAYLOAD_TYPE)
        assert len(notices) == 1
        assert notices[0]["missing_after"] == 2
        assert notices[0]["missing_before"] == 10
        assert notices[0]["cause"] == "prune_or_drop"
        # The chain is intact: a gap in OpenClaw's sequence is a completeness
        # fact about the ledger, never a tamper verdict about the chain.
        assert log.verify().ok

    def test_gap_notice_precedes_the_records_it_introduces(self, tmp_path: Path) -> None:
        log = open_log(tmp_path)
        ingest(log, run_fn=FakeLedger([rec(1)]))
        ingest(log, run_fn=FakeLedger([rec(5)]))

        kinds = [e.header.payload_type for e in log._backend.entries()]
        assert kinds == [
            OPENCLAW_AUDIT_PAYLOAD_TYPE,
            OPENCLAW_GAP_PAYLOAD_TYPE,
            OPENCLAW_AUDIT_PAYLOAD_TYPE,
        ]

    def test_hole_inside_one_run_is_recorded(self, tmp_path: Path) -> None:
        log = open_log(tmp_path)

        result = ingest(log, run_fn=FakeLedger([rec(1), rec(2), rec(9), rec(10)]))

        assert result.gaps is not None
        assert [(g.missing_after, g.missing_before) for g in result.gaps] == [(2, 9)]
        assert result.ingested == 4

    def test_gaps_are_unmeasured_when_a_kind_filter_narrows_the_export(
        self, tmp_path: Path
    ) -> None:
        # With --kind set, absent sequences are the filter doing its job.
        # Reporting them as loss would be a false alarm; reporting () would
        # claim a measurement that never ran (rule 5) — so it is None.
        log = open_log(tmp_path)

        result = ingest(log, kind="tool_action", run_fn=FakeLedger([rec(1), rec(4)]))

        assert result.gaps is None
        assert payloads(log, OPENCLAW_GAP_PAYLOAD_TYPE) == []
        assert result.ingested == 2

    def test_page_cap_gap_is_labelled_as_the_cap_not_as_prune(
        self, tmp_path: Path
    ) -> None:
        log = open_log(tmp_path)
        ingest(log, run_fn=FakeLedger([rec(1)]))
        ledger = FakeLedger([rec(s) for s in range(1, 12)])

        result = ingest(log, limit=2, max_pages=2, run_fn=ledger)

        assert result.truncated is True
        assert result.notice is not None and "max_pages" in result.notice
        # It fetched 11,10,9,8 — everything from 2..7 was left behind by OUR
        # cap, not by OpenClaw's pruning, and the entry says so.
        assert [p["sequence"] for p in payloads(log, OPENCLAW_AUDIT_PAYLOAD_TYPE)] == [
            1, 8, 9, 10, 11,
        ]
        assert result.gaps is not None
        assert [g.cause for g in result.gaps] == ["page_cap"]
        assert (result.gaps[0].missing_after, result.gaps[0].missing_before) == (1, 8)


class TestFilters:
    def test_kind_and_limit_reach_the_command_line(self, tmp_path: Path) -> None:
        ledger = FakeLedger([rec(1)])

        ingest(open_log(tmp_path), kind="tool_action", limit=42, run_fn=ledger)

        args = ledger.calls[0]
        assert args[:3] == ["audit", "--json", "--limit"]
        assert args[3] == "42"
        assert args[args.index("--kind") + 1] == "tool_action"

    def test_limit_is_clamped_to_the_documented_maximum(self, tmp_path: Path) -> None:
        # docs/cli/audit.md: "--limit <count>: activity page size from 1 to 500".
        ledger = FakeLedger([rec(1)])

        ingest(open_log(tmp_path), limit=9000, run_fn=ledger)

        assert ledger.calls[0][ledger.calls[0].index("--limit") + 1] == "500"

    def test_rejects_an_unknown_kind_before_running_anything(self, tmp_path: Path) -> None:
        ledger = FakeLedger([rec(1)])
        with pytest.raises(ValueError):
            ingest(open_log(tmp_path), kind="nonsense", run_fn=ledger)
        assert ledger.calls == []


class TestRedaction:
    def test_a_secret_in_an_exported_field_never_reaches_disk(self, tmp_path: Path) -> None:
        # The ledger is documented metadata-only, but redact-before-hash is
        # not conditional on trusting the source.
        secret = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        log = open_log(tmp_path, redactor=RegexRedactor())

        ingest(log, run_fn=FakeLedger([rec(1, toolName=f"Bash({secret})")]))

        # The envelope stores the payload base64-encoded, so absence of the
        # raw bytes proves little on its own — decode and look inside too.
        on_disk = (tmp_path / "trail.jsonl").read_bytes()
        assert secret.encode() not in on_disk
        stored = payloads(log, OPENCLAW_AUDIT_PAYLOAD_TYPE)
        assert secret not in json.dumps(stored)
        assert stored[0]["toolName"] == "Bash(***REDACTED***)"


class TestFailOpen:
    def test_a_failing_export_command_never_raises(self, tmp_path: Path) -> None:
        def boom(args: list[str]) -> str:
            raise RuntimeError("openclaw audit exited 1: gateway not running")

        result = ingest(open_log(tmp_path), run_fn=boom)

        assert result.ingested == 0
        assert result.notice is not None and "gateway not running" in result.notice
        # A read that never happened is unmeasured, not a measured zero.
        assert result.gaps is None

    def test_a_missing_binary_never_raises(self, tmp_path: Path) -> None:
        def missing(args: list[str]) -> str:
            raise FileNotFoundError("openclaw")

        result = ingest(open_log(tmp_path), run_fn=missing)

        assert result.ingested == 0
        assert result.notice is not None and "openclaw" in result.notice

    @pytest.mark.parametrize(
        "body",
        [
            "not json at all",
            '{"events": "not-a-list"}',
            "[]",
            '{"events": [{"sequence": "not-an-int"}]}',
            '{"events": [["nope"]]}',
            '{"events": [{"eventId": "no-sequence"}]}',
        ],
    )
    def test_unusable_export_output_is_reported_not_raised(
        self, tmp_path: Path, body: str
    ) -> None:
        log = open_log(tmp_path)

        result = ingest(log, run_fn=lambda args: body)

        assert result.ingested == 0
        assert result.notice is not None
        assert log.verify().ok

    def test_partial_page_damage_does_not_discard_the_good_records(
        self, tmp_path: Path
    ) -> None:
        # One unusable record must not cost the whole page: the loss is
        # counted (rule 6), the rest still lands.
        body = json.dumps({"events": [rec(3), {"eventId": "broken"}, rec(1)]})
        log = open_log(tmp_path)

        result = ingest(log, run_fn=lambda args: body)

        assert result.ingested == 2
        assert result.unusable == 1
        assert [p["sequence"] for p in payloads(log, OPENCLAW_AUDIT_PAYLOAD_TYPE)] == [1, 3]

    def test_append_failures_are_counted_as_dropped_writes(self, tmp_path: Path) -> None:
        log = open_log(tmp_path)
        calls = {"n": 0}
        real_append = log.append

        def flaky(*, payload: Any, payload_type: str) -> Any:
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("disk full")
            return real_append(payload=payload, payload_type=payload_type)

        log.append = flaky  # type: ignore[method-assign]
        result = ingest(log, run_fn=FakeLedger([rec(1), rec(2), rec(3)]))

        assert result.ingested == 2
        assert result.dropped == 1
        assert log.dropped_writes == 1
        assert log.verify().ok


class TestIngestCriticalSection:
    """ingest() claims idempotency, but the resume-point read and the append
    loop used to be two separate steps: two overlapping timer runs could both
    read the same resume point and both append the same ledger rows — a
    duplicated history, on a chain whose whole job is to be the reliable copy.
    Rule 7's shape again: read-tail (here, read-resume) + append must be one
    critical section, so the whole ingest run body holds one ingest lock.

    Scheduling note: the fetch seam runs after the resume read, so a barrier
    inside run_fn proves both runs read the resume point before either
    appended. With the lock, the second run can never reach the barrier (it
    is parked before its resume read), so the first run's wait must time out
    — the timeout bounds the attempt to force the bad schedule; the PASS is
    asserted on the stored rows, never on the clock (the rule 8 concern).

    Falsifiability receipt, actually measured (not assumed): against the
    pre-lock code (identical to the fixed code with the ingest lock removed),
    this test failed deterministically on its first run (2026-08-23, Windows
    11, CPython via uv): ``assert [1, 1, 2, 2] == [1, 2]`` — both runs read
    resume point None, met at the barrier, and each appended both rows.
    Re-verified after the fix by replacing the ``file_lock`` acquisition with
    ``contextlib.nullcontext()``: same failure, same duplicated rows.
    """

    def test_overlapping_ingest_runs_do_not_double_ingest(self, tmp_path: Path) -> None:
        import threading

        page = json.dumps({"events": [rec(2), rec(1)]})
        barrier = threading.Barrier(2)

        def rendezvous_fetch(args: list[str]) -> str:
            # Both runs sit here having already read the SAME resume point —
            # the exact interleaving two close timer ticks produce. With the
            # ingest lock in place only one run ever arrives, so the barrier
            # breaking on timeout is the expected (suppressed) outcome.
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait(timeout=2.0)
            return page

        results: list[Any] = []
        lock = threading.Lock()

        def timer_run() -> None:
            # Each timer tick opens its own AuditLog, as the real runner does.
            result = ingest(open_log(tmp_path), run_fn=rendezvous_fetch)
            with lock:
                results.append(result)

        t1 = threading.Thread(target=timer_run)
        t2 = threading.Thread(target=timer_run)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        stored = payloads(open_log(tmp_path), OPENCLAW_AUDIT_PAYLOAD_TYPE)
        assert sorted(p["sequence"] for p in stored) == [1, 2]
        assert sum(r.ingested for r in results) == 2
        assert open_log(tmp_path).verify().ok

    def test_an_unavailable_ingest_lock_is_reported_never_raised(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Windows' msvcrt.locking gives up with OSError after ~10s of another
        # run holding the lock. Backing off is correct — the holder is
        # ingesting these very rows — but the timer must see a labelled
        # notice, not a crash (rule 6) and not a silent 0.
        import waxseal.sources.openclaw as oc

        def held(target: Path) -> Any:
            raise OSError("locking violation: another run holds the lock")

        monkeypatch.setattr(oc, "file_lock", held)
        result = ingest(open_log(tmp_path), run_fn=FakeLedger([rec(1)]))

        assert result.ingested == 0
        assert result.notice is not None and "ingest lock" in result.notice
        # The run never read anything: unmeasured, not a measured zero.
        assert result.gaps is None

    def test_a_trail_with_no_local_path_still_ingests(self) -> None:
        # Memory (and remote) backends have no directory to keep a lock file
        # in; overlap there can only come from this process's own threads,
        # which the process-wide fallback lock serializes.
        from waxseal.adapters.memory import MemoryBackend

        log = AuditLog(MemoryBackend(), now_fn=lambda: "2026-08-22T06:00:00+00:00")
        result = ingest(log, run_fn=FakeLedger([rec(1), rec(2)]))

        assert result.ingested == 2
        assert [p["sequence"] for p in payloads(log, OPENCLAW_AUDIT_PAYLOAD_TYPE)] == [1, 2]


class TestTamperEvidence:
    def test_editing_an_ingested_row_is_caught_with_its_sequence(
        self, tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        log = open_log(tmp_path)
        ingest(log, run_fn=FakeLedger([rec(1), rec(2), rec(3)]))

        import base64

        lines = trail.read_text(encoding="utf-8").splitlines()
        envelope = json.loads(lines[1])
        payload = base64.b64decode(envelope["payload_b64"]).replace(b"Bash", b"Read")
        envelope["payload_b64"] = base64.b64encode(payload).decode()
        lines[1] = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        trail.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")

        result = open_log(tmp_path).verify()
        assert not result.ok
        assert result.broken_seq == 1
        assert result.reason == "payload_hash_mismatch"


class TestEdgeCases:
    def test_an_empty_ledger_ingests_nothing(self, tmp_path: Path) -> None:
        log = open_log(tmp_path)

        result = ingest(log, run_fn=FakeLedger([]))

        assert (result.ingested, result.last_sequence, result.gaps) == (0, None, ())
        assert result.notice is None

    def test_an_unparseable_ingested_payload_does_not_break_the_resume_scan(
        self, tmp_path: Path
    ) -> None:
        # An entry carrying the OpenClaw payload_type but not JSON can only
        # come from outside this module; it must not stop the resume point
        # being found, or an ingest would restart from zero and duplicate.
        log = open_log(tmp_path)
        log.append(payload=b"not json", payload_type=OPENCLAW_AUDIT_PAYLOAD_TYPE)
        log.append(payload=rec(4), payload_type=OPENCLAW_AUDIT_PAYLOAD_TYPE)

        assert last_ingested_sequence(log) == 4

    def test_a_failed_gap_notice_is_counted_as_a_dropped_write(self, tmp_path: Path) -> None:
        log = open_log(tmp_path)
        ingest(log, run_fn=FakeLedger([rec(1)]))
        real_append = log.append

        def refuse_gap_notices(*, payload: Any, payload_type: str) -> Any:
            if payload_type == OPENCLAW_GAP_PAYLOAD_TYPE:
                raise OSError("disk full")
            return real_append(payload=payload, payload_type=payload_type)

        log.append = refuse_gap_notices  # type: ignore[method-assign]
        result = ingest(log, run_fn=FakeLedger([rec(1), rec(5)]))

        # The record still lands and the gap is still reported by the result;
        # what was lost is the on-chain notice, and that loss is counted.
        assert result.ingested == 1
        assert result.dropped == 1
        assert [(g.missing_after, g.missing_before) for g in result.gaps or ()] == [(1, 5)]
        assert payloads(log, OPENCLAW_GAP_PAYLOAD_TYPE) == []
