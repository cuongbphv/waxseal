"""waxseal-audit ingest runner for OpenClaw.

Pages `openclaw audit --json` into a tamper-evident chain at
`<openclaw home>/audit/trail.jsonl`. Meant for cron or a systemd timer:

    */5 * * * * python -m waxseal.integrations.openclaw

The ingest logic lives in `waxseal.sources.openclaw`; this module is the shell
around it. Two contracts it keeps:

- **Exit 0 on every path.** A missing binary, a stopped gateway, an unwritable
  trail: all report on stderr and return 0. A timer that flaps on a degraded
  audit is a timer the operator disables.
- **Nothing on stdout.** Same rule as the stdin hooks: stdout belongs to
  whoever invoked us, and a cron mail full of ingest chatter trains people to
  filter the one message that mattered.

The `waxseal` CLI has no `ingest` subcommand on purpose: CLAUDE.md's CLI
contract is "the CLI never writes to the log".
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.integrations._trail import home_base
from waxseal.integrations._trail import resolve_trail as _resolve_trail
from waxseal.sources.openclaw import DEFAULT_LIMIT, DEFAULT_MAX_PAGES, KINDS, ingest


def resolve_trail() -> Path:
    return _resolve_trail(default=_openclaw_default)


def _openclaw_default() -> Path:
    # OpenClaw relocates its state directory via OPENCLAW_HOME; a trail left
    # behind in ~/.openclaw would not follow the install it belongs to.
    home = os.environ.get("OPENCLAW_HOME")
    if home:
        return Path(home) / "audit" / "trail.jsonl"
    return home_base() / ".openclaw" / "audit" / "trail.jsonl"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m waxseal.integrations.openclaw",
        description="Append new OpenClaw audit-ledger records to a waxseal chain.",
    )
    parser.add_argument("--trail", type=Path, default=None, help="chain path")
    parser.add_argument("--kind", choices=KINDS, default=None, help="narrow the export")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="page size (max 500)")
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    args = parser.parse_args(argv)

    trail = args.trail if args.trail is not None else resolve_trail()
    try:
        log = AuditLog.open(trail, redactor=RegexRedactor(), record_drops=True)
    except Exception as e:
        print(f"[waxseal-audit] cannot open trail {trail} (nothing ingested): {e}", file=sys.stderr)
        return 0

    result = ingest(log, kind=args.kind, limit=args.limit, max_pages=args.max_pages)
    print(
        f"[waxseal-audit] ingested {result.ingested} (last sequence "
        f"{result.last_sequence if result.last_sequence is not None else 'none'}) -> {trail}",
        file=sys.stderr,
    )
    if result.notice:
        # Labelled degradation: the loss is visible in the timer's output and,
        # for gaps, on the chain itself.
        print(f"[waxseal-audit] {result.notice}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover - measured via in-process tests
    sys.exit(main())
