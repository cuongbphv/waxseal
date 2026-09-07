"""waxseal CLI router. Handlers live in sibling modules; this file parses
and dispatches. It never writes to the log itself (CLAUDE.md's CLI contract).
"""

from __future__ import annotations

import sys
from pathlib import Path

from waxseal.adapters.remote import RemoteError
from waxseal.cli._common import _survive_a_narrow_console
from waxseal.cli._parser import build_parser
from waxseal.log import AuditLog


def main(argv: list[str] | None = None) -> int:
    _survive_a_narrow_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    from waxseal.cli.pin import _pin_target

    if args.command in ("verify", "report") and args.pin is None and (
        args.expect_anchor_binding
        or args.max_anchor_age_s is not None
        or args.declare_topology is not None
    ):
        # A declaration with nowhere to land would otherwise be silently a
        # no-op, per CLAUDE.md rule 6 (a degraded/ineffective flag must be
        # labelled, never silent), enforced here as a usage error before the
        # trail is even opened, rather than as a quiet do-nothing.
        parser.error(
            "--expect-anchor-binding/--max-anchor-age-s/--declare-topology require "
            "--pin (there is no pin state file to declare against)"
        )

    if args.command in ("verify", "report") and args.trail_id is not None and not (
        args.liveness or args.registry
    ):
        # Same rule-6 shape as the pin-declaration check above: --trail-id
        # names WHICH on-chain trail to check, and checks nothing on its own.
        parser.error("--trail-id requires --liveness or --registry")

    if args.command == "ledger-status" and args.bond is not None and args.writer is None:
        parser.error("--bond requires --writer (the address whose bond status to check)")

    if args.command == "cadence":
        # Pure arithmetic over operator-supplied measurements: opens no
        # trail at all, unlike every other subcommand here.
        from waxseal.cli.cadence import _cadence
        return _cadence(
            lam=args.lam, c=args.c, w=args.w, rho=args.rho, M=args.M,
            delta=args.delta, t_max=args.t_max,
        )

    if args.command == "segments":
        # Takes a DIRECTORY, not a trail path, so it sits above the
        # single-trail plumbing below (the same reason `cadence` does).
        from waxseal.cli.segments import _segments
        return _segments(Path(args.dir).expanduser())

    if args.command == "preflight":
        # Sits above the shared trail plumbing because it owns its own
        # "nothing was read" rule: preflight reads LOCAL sidecars, so a URL
        # target has no location for any of them, and that is exit 3 (nothing
        # read, nothing created) rather than the exit 1 `anchor`/`receipt`
        # use — a reading command has no verdict codes to spend.
        from waxseal.cli.preflight import _preflight
        return _preflight(args.path, pin_path=args.pin)

    if args.command == "install":
        # Writes host shim files only, and never touches any audit log.
        from waxseal.integrations._install import install

        return install(args.target, args.home, args.force)

    if args.command == "verify-proof":
        # A bundle is self-contained by design: the auditor holds this one
        # file and no trail at all, so none of the trail plumbing below
        # applies to it.
        from waxseal.cli.report import _verify_proof
        return _verify_proof(Path(args.bundle).expanduser())

    if args.command == "registry":
        # Publishes a descriptor by fingerprint, not by trail: no audit log
        # is ever opened for this command, the same shape `cadence` has.
        from waxseal.cli.ledger import _registry_publish
        return _registry_publish(
            descriptor_of=args.descriptor_of,
            registry_addr=args.registry,
            rpc_urls=args.rpc,
            write_rpc=args.write_rpc,
        )

    if args.command == "bond":
        if args.bond_command == "deposit":
            from waxseal.cli.ledger import _bond_deposit
            return _bond_deposit(
                bond_addr=args.bond,
                rpc_urls=args.rpc,
                write_rpc=args.write_rpc,
                amount_wei=args.amount_wei,
            )
        from waxseal.cli.ledger import _bond_prove
        return _bond_prove(
            bond_addr=args.bond,
            rpc_urls=args.rpc,
            write_rpc=args.write_rpc,
            proof_path=Path(args.proof).expanduser(),
        )

    is_url = args.path.startswith(("http://", "https://"))
    trail: Path | None
    if is_url:
        # Path(url) would collapse "//" and strip the scheme, so it never even
        # reach a meaningful check. A remote target has no local sidecar
        # location, so anchoring and .anchors/.drops sidecars are unavailable
        # for it (below); connectivity is verified per-command, not here.
        trail = None
        if args.command in ("anchor", "receipt"):
            print(
                f"error: `{args.command}` needs a local sidecar location; not "
                "supported for a remote URL target",
                file=sys.stderr,
            )
            return 1
    else:
        trail = Path(args.path).expanduser()
        if not trail.exists():
            # Opening a missing SQLite path would CREATE an empty database
            # (mkdir + DDL), a write side effect the read-only contract
            # forbids, and a typo'd path must not verify as an intact empty
            # chain.
            print(f"error: no such trail: {trail}", file=sys.stderr)
            return 3

    if args.command == "receipt":
        # Extraction reads only the sidecar (the frame is recomputed from the
        # record itself, exactly as `verify --anchors` checks it): the trail
        # is never opened, keeping this read-only against both files.
        assert trail is not None  # guarded above: URL targets returned already
        from waxseal.cli.receipt import _receipt_export
        return _receipt_export(trail, seq=args.seq, out=args.out)

    try:
        log = AuditLog.open(args.path)
        if args.command == "verify":
            if is_url and args.anchors:
                # CLAUDE.md rule 6: a degraded guard must be labelled in the
                # output, never silently skipped, since a URL target has no local
                # .anchors sidecar to check, so --anchors would otherwise be
                # a no-op the operator has no way to notice.
                print(
                    "note: --anchors has no effect for a remote URL target "
                    "(no local .anchors sidecar to check)",
                    file=sys.stderr,
                )
            from waxseal.cli.verify import _verify
            from waxseal.domain.report import SCOPE_LINE
            code = _verify(
                log,
                trail,
                check_anchors=args.anchors and not is_url,
                is_url=is_url,
                pin_path=args.pin,
                target=_pin_target(args.path, trail),
                chain_id="default" if is_url else None,
                witnesses=args.witness,
                declare_expect_anchor_binding=args.expect_anchor_binding,
                declare_max_anchor_age_s=args.max_anchor_age_s,
                declare_topology=args.declare_topology,
                tsa_ca_file=args.tsa_ca_file,
                ledger_rpc_urls=args.rpc,
                ledger_liveness=args.liveness,
                ledger_registry=args.registry,
                ledger_trail_id=(
                    args.trail_id
                    if args.trail_id is not None
                    else _pin_target(args.path, trail)
                ),
            )
            # Printed here rather than inside _verify so it cannot drift
            # between that function's verdict paths. `report` carries the
            # same statement in its own body, so it is not repeated here.
            print(SCOPE_LINE)
            return code
        if args.command == "report":
            if is_url and args.anchors:
                print(
                    "note: --anchors has no effect for a remote URL target "
                    "(no local .anchors sidecar to check)",
                    file=sys.stderr,
                )
            from waxseal.cli.report import _report
            return _report(
                log,
                trail,
                check_anchors=args.anchors and not is_url,
                as_json=args.json,
                pin_path=args.pin,
                target=_pin_target(args.path, trail),
                chain_id="default" if is_url else None,
                witnesses=args.witness,
                declare_expect_anchor_binding=args.expect_anchor_binding,
                declare_max_anchor_age_s=args.max_anchor_age_s,
                declare_topology=args.declare_topology,
                tsa_ca_file=args.tsa_ca_file,
                ledger_rpc_urls=args.rpc,
                ledger_liveness=args.liveness,
                ledger_registry=args.registry,
                ledger_trail_id=(
                    args.trail_id
                    if args.trail_id is not None
                    else _pin_target(args.path, trail)
                ),
            )
        if args.command == "ledger-status":
            from waxseal.cli.ledger import _ledger_status
            return _ledger_status(
                log,
                rpc_urls=args.rpc,
                liveness=args.liveness,
                registry=args.registry,
                bond=args.bond,
                writer=args.writer,
                trail_id=(
                    args.trail_id
                    if args.trail_id is not None
                    else _pin_target(args.path, trail)
                ),
                as_json=args.json,
            )
        if args.command == "export-proof":
            from waxseal.cli.report import _export_proof
            return _export_proof(log, args.seq)
        if args.command == "tail":
            from waxseal.cli.inspect import _tail
            return _tail(log, args.n)
        if args.command == "head":
            from waxseal.cli.inspect import _head
            return _head(log)
        if args.command == "checkpoint":
            from waxseal.cli.inspect import _checkpoint
            return _checkpoint(log)
        if args.command == "consistency":
            from waxseal.cli.report import _consistency
            return _consistency(log, old_seq=args.old_seq, old_root=args.old_root)
        if args.command == "verify-handoff":
            from waxseal.cli.report import _verify_handoff
            return _verify_handoff(log, origin_path=Path(args.origin).expanduser())
        if args.command == "incidents":
            from waxseal.cli.incidents import _incidents
            return _incidents(
                log,
                window_h=args.report_window_h,
                as_of=args.as_of,
                since=args.since,
                as_json=args.json,
            )
        if args.command == "reconcile-tickets":
            from waxseal.cli.tickets import _reconcile_tickets
            return _reconcile_tickets(
                log,
                issuer=args.issuer,
                lease_size=args.lease_size,
                issued_spec=args.issued,
                as_json=args.json,
            )
        if args.command == "anchor":
            assert trail is not None  # guarded above: URL targets returned already
            from waxseal.cli.anchor import _anchor
            return _anchor(
                log,
                trail,
                witnesses=args.witness,
                tsa_url=args.tsa_url,
                ots_calendar=args.ots_calendar,
                evm_rpc=args.evm_rpc,
                evm_liveness=args.evm_liveness,
                evm_write_rpc=args.evm_write_rpc,
                evm_trail_id=args.evm_trail_id,
                evm_consistency_proof_file=args.evm_consistency_proof_file,
            )
        from waxseal.cli.inspect import _inspect
        return _inspect(log, trail)
    except (OSError, RemoteError) as e:
        # OSError covers urllib's URLError/HTTPError/timeout; RemoteError is
        # raised for a reachable-but-non-protocol response (a 5xx, a
        # malformed body). Either way, for a URL target this is "nothing
        # read, nothing created", the same spirit exit 3 already carries
        # for a missing local path.
        if is_url:
            print(f"error: cannot reach trail: {e}", file=sys.stderr)
            return 3
        raise
