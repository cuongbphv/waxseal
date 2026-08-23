#!/usr/bin/env python3
"""End-to-end demo: chain OpenClaw's audit ledger, then break it.

Runs with no OpenClaw installed — a stub stands in for `openclaw audit --json`,
serving newest-first pages exactly as the real export does. What it shows:

1. a first ingest, in ascending sequence order despite the backwards export;
2. a second ingest after the ledger pruned rows — recorded as a GAP, not as
   tampering, because prune and drop are indistinguishable from outside;
3. a re-run adding nothing (idempotent);
4. an edited row caught with its exact seq and reason.

    python integrations/openclaw/e2e_demo.py
"""

from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path
from typing import Any

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.sources.openclaw import (
    OPENCLAW_AUDIT_PAYLOAD_TYPE,
    OPENCLAW_GAP_PAYLOAD_TYPE,
    ingest,
)


def record(seq: int, tool: str) -> dict[str, Any]:
    """One `audit_events` row as `openclaw audit --json` emits it."""
    return {
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
        "sessionKey": "agent:main:main",
        "runId": "run-42",
        "toolName": tool,
    }


class StubLedger:
    """`openclaw audit --json`: newest first, `--cursor` means sequence < cursor."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = sorted(rows, key=lambda r: r["sequence"], reverse=True)

    def __call__(self, args: list[str]) -> str:
        limit = int(args[args.index("--limit") + 1])
        cursor = int(args[args.index("--cursor") + 1]) if "--cursor" in args else None
        rows = [r for r in self.rows if cursor is None or r["sequence"] < cursor]
        page = rows[:limit]
        out: dict[str, Any] = {"events": page}
        if page and len(rows) > limit:
            out["nextCursor"] = page[-1]["sequence"]
        return json.dumps(out)


def show(log: AuditLog) -> None:
    for entry in log.entries():
        payload = json.loads(entry.payload) if entry.payload else {}
        if entry.header.payload_type == OPENCLAW_GAP_PAYLOAD_TYPE:
            print(
                f"  seq {entry.header.seq}: GAP {payload['missing_after']}->"
                f"{payload['missing_before']} ({payload['cause']})"
            )
        elif entry.header.payload_type == OPENCLAW_AUDIT_PAYLOAD_TYPE:
            print(
                f"  seq {entry.header.seq}: ledger #{payload['sequence']} "
                f"{payload['action']} {payload.get('toolName', '-')} {payload['status']}"
            )


def main() -> int:
    trail = Path(tempfile.mkdtemp()) / "trail.jsonl"

    print("1. first ingest — the export is newest-first, the chain is not")
    ledger = StubLedger([record(101, "Bash"), record(102, "Read"), record(103, "Edit")])
    log = AuditLog.open(trail, redactor=RegexRedactor(), record_drops=True)
    result = ingest(log, limit=2, run_fn=ledger)
    print(f"   ingested {result.ingested}, last sequence {result.last_sequence}")
    show(log)

    print("\n2. the ledger pruned 104..109 before the next run")
    result = ingest(log, run_fn=StubLedger([record(110, "Bash"), record(111, "Write")]))
    print(f"   ingested {result.ingested}, gaps {result.gaps}")
    show(log)
    print("   verify:", "ok" if log.verify().ok else "BROKEN")
    print("   (a gap is a completeness fact about the ledger, never a tamper verdict)")

    print("\n3. re-run with nothing new")
    again = ingest(log, run_fn=StubLedger([record(110, "Bash"), record(111, "Write")]))
    print(f"   ingested {again.ingested} (idempotent), last sequence {again.last_sequence}")

    print("\n4. somebody edits an ingested row on disk")
    lines = trail.read_text(encoding="utf-8").splitlines()
    envelope = json.loads(lines[0])
    payload = base64.b64decode(envelope["payload_b64"]).replace(b"Bash", b"Curl")
    envelope["payload_b64"] = base64.b64encode(payload).decode()
    lines[0] = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    trail.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")

    verdict = AuditLog.open(trail).verify()
    print(f"   verify: ok={verdict.ok} broken_seq={verdict.broken_seq} reason={verdict.reason}")
    print(f"\ntrail: {trail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
