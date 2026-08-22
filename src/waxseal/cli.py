"""waxseal CLI — never writes to the log itself (CLAUDE.md's CLI contract).
`anchor` writes a local `<path>.anchors` sidecar (a record ABOUT the trail,
same class as `.attest`/`.drops`) — every other command, including
`checkpoint`, is read-only.

verify: exit 0 = intact, 1 = broken (prints first break), 2 = intact but
unverifiable-by-name rows present (unknown schema fingerprint — NOT tampering).
Exit 3 = the trail path does not exist (nothing was read or created).
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from waxseal.adapters.remote import RemoteError
from waxseal.log import AuditLog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="waxseal")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="verify chain integrity")
    p_verify.add_argument("path")
    p_verify.add_argument(
        "--anchors", action="store_true",
        help="also check the local anchor sidecar (<path>.anchors), if any",
    )

    p_tail = sub.add_parser("tail", help="print the last entries")
    p_tail.add_argument("path")
    p_tail.add_argument("-n", type=int, default=10)

    p_inspect = sub.add_parser("inspect", help="summarize the trail")
    p_inspect.add_argument("path")

    p_head = sub.add_parser(
        "head", help="print the chain head (seq + entry_hash) for external anchoring"
    )
    p_head.add_argument("path")

    p_checkpoint = sub.add_parser(
        "checkpoint",
        help="print a checkpoint (seq + entry_hash + Merkle root) for an anchor sink",
    )
    p_checkpoint.add_argument("path")

    p_anchor = sub.add_parser(
        "anchor", help="append a checkpoint to the local anchor sidecar (<path>.anchors)"
    )
    p_anchor.add_argument("path")

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

    is_url = args.path.startswith(("http://", "https://"))
    trail: Path | None
    if is_url:
        # Path(url) would collapse "//" and strip the scheme — never even
        # reach a meaningful check. A remote target has no local sidecar
        # location, so anchoring and .anchors/.drops sidecars are unavailable
        # for it (below); connectivity is verified per-command, not here.
        trail = None
        if args.command == "anchor":
            print(
                "error: `anchor` needs a local sidecar location; not supported "
                "for a remote URL target",
                file=sys.stderr,
            )
            return 1
    else:
        trail = Path(args.path).expanduser()
        if not trail.exists():
            # Opening a missing SQLite path would CREATE an empty database
            # (mkdir + DDL) — a write side effect the read-only contract
            # forbids — and a typo'd path must not verify as an intact empty
            # chain.
            print(f"error: no such trail: {trail}", file=sys.stderr)
            return 3

    try:
        log = AuditLog.open(args.path)
        if args.command == "verify":
            if is_url and args.anchors:
                # CLAUDE.md rule 6: a degraded guard must be labelled in the
                # output, never silently skipped — a URL target has no local
                # .anchors sidecar to check, so --anchors would otherwise be
                # a no-op the operator has no way to notice.
                print(
                    "note: --anchors has no effect for a remote URL target "
                    "(no local .anchors sidecar to check)",
                    file=sys.stderr,
                )
            return _verify(log, trail, check_anchors=args.anchors and not is_url, is_url=is_url)
        if args.command == "tail":
            return _tail(log, args.n)
        if args.command == "head":
            return _head(log)
        if args.command == "checkpoint":
            return _checkpoint(log)
        if args.command == "anchor":
            assert trail is not None  # guarded above: URL targets returned already
            return _anchor(log, trail)
        return _inspect(log, trail)
    except (OSError, RemoteError) as e:
        # OSError covers urllib's URLError/HTTPError/timeout; RemoteError is
        # raised for a reachable-but-non-protocol response (a 5xx, a
        # malformed body). Either way, for a URL target this is "nothing
        # read, nothing created" — the same spirit exit 3 already carries
        # for a missing local path.
        if is_url:
            print(f"error: cannot reach trail: {e}", file=sys.stderr)
            return 3
        raise


def _verify(
    log: AuditLog, trail: Path | None, *, check_anchors: bool = False, is_url: bool = False
) -> int:
    # A CLI process saw no writes, so it cannot measure drops (None, not 0).
    result = log.verify(measure_drops=False)
    if not result.ok:
        print(f"BROKEN at seq={result.broken_seq}: {result.reason} (checked={result.checked})")
        _print_drop_count(trail)
        return 1
    exit_code = 0
    if result.unverifiable:
        print(
            f"ok (checked={result.checked}) but {len(result.unverifiable)} unverifiable "
            f"row(s) at seq={list(result.unverifiable)} — unknown schema fingerprint, "
            "NOT evidence of tampering"
        )
        exit_code = 2
    else:
        print(f"ok (checked={result.checked})")
        if is_url and result.checked == 0:
            # GET /entries 404 means "empty" identically for a genuinely
            # fresh chain and for a mistyped chain_id/wrong path — unlike a
            # local path, there is no Path.exists() probe to tell them apart.
            # A bare "ok" here would let a typo silently verify nothing while
            # looking successful (CLAUDE.md rule 6: a degraded guard must be
            # labelled, never silent).
            print(
                "note: checked=0 for a remote URL target is indistinguishable "
                "from a wrong chain_id/path — this cannot confirm the chain "
                "you intended is actually reachable and non-empty"
            )
    _print_drop_count(trail)
    # trail is None only for a URL target, and main() already forces
    # check_anchors False in that case (no local sidecar to check) — this
    # guard just makes that invariant visible to mypy, not a new behavior.
    if check_anchors and trail is not None and _verify_anchors(log, trail) == 1:
        # Anchor breakage escalates to 1 regardless of the chain's own exit
        # code — it is still "broken", just a different dimension of it.
        return 1
    return exit_code


def _print_drop_count(trail: Path | None) -> None:
    # Completeness, not integrity (CLAUDE.md rule 5) — this never changes
    # the caller's exit code. No sidecar means "never measured" (unchanged
    # output, matching the pre-M5 behavior), not a printed "0". A URL target
    # has no local sidecar location at all — same as "never measured".
    if trail is None:
        return
    from waxseal.adapters.drops import read_drop_count

    count = read_drop_count(trail)
    if count is not None:
        print(f"dropped_writes >= {count} (measured minimum, from {trail}.drops)")


def _verify_anchors(log: AuditLog, trail: Path) -> int:
    import json

    from waxseal.adapters.anchors import FileAnchorSink
    from waxseal.domain.checkpoint import verify_checkpoint

    sink = FileAnchorSink(trail)
    try:
        records = list(sink.records())
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        # The sidecar is as attacker-writable as the trail it anchors
        # (same threat model as attest.py's sidecar) — malformed bytes are a
        # verdict, never a crash (fail-closed rule, verify_membership/
        # verify_checkpoint's own contract).
        print("ANCHOR BROKEN: malformed_anchor")
        return 1
    if not records:
        # Absence is not failure (CLAUDE.md rule 5: unmeasured != 0/ok).
        print("no anchors found (anchor coverage unmeasured)")
        return 0
    hashes = [entry.entry_hash for entry in log._backend.entries()]
    for cp in records:
        reason = verify_checkpoint(hashes, cp)
        if reason is not None:
            print(f"ANCHOR BROKEN at seq={cp.seq}: {reason}")
            return 1
    print(f"anchors ok (checked={len(records)}, latest=seq {records[-1].seq})")
    return 0


def _anchor(log: AuditLog, trail: Path) -> int:
    import json

    from waxseal.adapters.anchors import FileAnchorSink

    anchored = AuditLog(log._backend, anchor_sink=FileAnchorSink(trail))
    try:
        cp = anchored.anchor()
    except ValueError:
        return 1
    print(json.dumps({"seq": cp.seq, "entry_hash": cp.entry_hash, "root": cp.root}))
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


def _checkpoint(log: AuditLog) -> int:
    # Same anchoring rationale as `head`, plus a batch root: a membership
    # proof against this root can later prove any one entry was present
    # without needing the whole trail in hand (RFC 6962 section 2.1).
    import json

    from waxseal.domain.checkpoint import checkpoint_for

    hashes = [entry.entry_hash for entry in log._backend.entries()]
    if not hashes:
        return 1
    cp = checkpoint_for(hashes)
    print(json.dumps({"seq": cp.seq, "entry_hash": cp.entry_hash, "root": cp.root}))
    return 0


def _inspect(log: AuditLog, trail: Path | None) -> int:
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
    _print_drop_count(trail)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
