"""waxseal CLI — read-only by contract (CLAUDE.md).

verify: exit 0 = intact, 1 = broken (prints first break), 2 = intact but
unverifiable-by-name rows present (unknown schema fingerprint — NOT tampering).
Exit 3 = the trail path does not exist (nothing was read or created).
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from waxseal.log import AuditLog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="waxseal")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="verify chain integrity")
    p_verify.add_argument("path")

    p_tail = sub.add_parser("tail", help="print the last entries")
    p_tail.add_argument("path")
    p_tail.add_argument("-n", type=int, default=10)

    p_inspect = sub.add_parser("inspect", help="summarize the trail")
    p_inspect.add_argument("path")

    p_head = sub.add_parser(
        "head", help="print the chain head (seq + entry_hash) for external anchoring"
    )
    p_head.add_argument("path")

    p_install = sub.add_parser(
        "install", help="write the audit hook shim files for an agent framework"
    )
    from waxseal.integrations._install import TARGETS

    p_install.add_argument("target", choices=TARGETS)
    p_install.add_argument(
        "--home", type=Path, default=None,
        help="host home directory (default: the host's own, e.g. ~/.hermes)",
    )
    p_install.add_argument("--force", action="store_true",
                           help="overwrite shim files that differ")

    args = parser.parse_args(argv)

    if args.command == "install":
        # Writes host shim files only — never touches any audit log.
        from waxseal.integrations._install import install

        return install(args.target, args.home, args.force)

    trail = Path(args.path).expanduser()
    if not trail.exists():
        # Opening a missing SQLite path would CREATE an empty database (mkdir
        # + DDL) — a write side effect the read-only contract forbids — and a
        # typo'd path must not verify as an intact empty chain.
        print(f"error: no such trail: {trail}", file=sys.stderr)
        return 3

    log = AuditLog.open(args.path)

    if args.command == "verify":
        return _verify(log)
    if args.command == "tail":
        return _tail(log, args.n)
    if args.command == "head":
        return _head(log)
    return _inspect(log)


def _verify(log: AuditLog) -> int:
    # A CLI process saw no writes, so it cannot measure drops (None, not 0).
    result = log.verify(measure_drops=False)
    if not result.ok:
        print(f"BROKEN at seq={result.broken_seq}: {result.reason} (checked={result.checked})")
        return 1
    if result.unverifiable:
        print(
            f"ok (checked={result.checked}) but {len(result.unverifiable)} unverifiable "
            f"row(s) at seq={list(result.unverifiable)} — unknown schema fingerprint, "
            "NOT evidence of tampering"
        )
        return 2
    print(f"ok (checked={result.checked})")
    return 0


def _tail(log: AuditLog, n: int) -> int:
    entries = list(log._backend.entries())
    for entry in entries[-n:]:
        h = entry.header
        print(f"seq={h.seq} ts={h.ts} type={h.payload_type} hash={entry.entry_hash[:12]}")
    return 0


def _head(log: AuditLog) -> int:
    # Anchor this output externally (OpenTimestamps, RFC 3161 TSA, a pushed
    # git commit): a rewritten suffix cannot rewrite an already-anchored head.
    import json

    last = None
    for last in log._backend.entries():  # noqa: B007 - want the final element
        pass
    if last is None:
        return 1
    print(json.dumps({"seq": last.header.seq, "entry_hash": last.entry_hash}))
    return 0


def _inspect(log: AuditLog) -> int:
    total = 0
    by_fingerprint: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    for entry in log._backend.entries():
        total += 1
        by_fingerprint[entry.header.hash_version] += 1
        by_type[entry.header.payload_type] += 1
    print(f"entries: {total}")
    for fp, count in by_fingerprint.items():
        print(f"fingerprint {fp[:12]}…: {count}")
    for pt, count in by_type.items():
        print(f"payload_type {pt}: {count}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
