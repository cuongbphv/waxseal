"""waxseal CLI. It never writes to the log itself (CLAUDE.md's CLI contract).

Some commands write files ABOUT a trail, never to it. `anchor` appends to the
local `<path>.anchors` sidecar (same class as `.attest`/`.drops`). `verify`
and `report` write the `--pin` state file when one is asked for and the run
found no break (exit 2 still advances it, per SPEC.md section 13), so the pin is
the verifier's own memory, deliberately NOT a sidecar of the trail, and the
operator names its path. `receipt` extracts stored receipts and the frames
they attest into the operator-named `--out` directory. `install` writes host
shim files only. Everything else, `checkpoint` and `head` included, only
reads.

verify: exit 0 = intact, 1 = broken (prints first break), 2 = intact but
unverifiable-by-name rows present (unknown schema fingerprint, NOT tampering).
Exit 3 = the trail path does not exist (nothing was read or created).
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import sys
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from waxseal.adapters.anchors import AnchorRecord
from waxseal.adapters.remote import RemoteError
from waxseal.domain.checkpoint import Checkpoint
from waxseal.domain.header import Entry
from waxseal.domain.pinning import PinState
from waxseal.domain.report import SCOPE_LINE, CheckSummary
from waxseal.domain.rfc3161 import NONCE_MISMATCH, RECEIPT_IMPRINT_MISMATCH
from waxseal.domain.separation import (
    SeparationTopology,
    counted_authorities,
    render_counted_authorities,
    render_separation_degree,
    separation_degree,
    separation_shortfall,
)
from waxseal.domain.verdict import Verdict
from waxseal.domain.witnessing import WitnessVerdict
from waxseal.log import AuditLog

# The only two RFC 3161 outcomes that mean "checked and false" rather than
# "not readable here": the token commits to bytes other than the record it
# sits beside. Everything else is a format this build cannot read.
_RECEIPT_CHECKED_FALSE: Final = frozenset({RECEIPT_IMPRINT_MISMATCH, NONCE_MISMATCH})

_PIN_HELP = (
    "check the trail against a checkpoint this verifier recorded previously, "
    "and record the current head on any run that finds no break "
    "(trust-on-first-use). Keep this "
    "file under a different authority than the trail — that separation is the "
    "entire security argument. See --expect-anchor-binding/--max-anchor-age-s/"
    "--declare-topology to declare what this pin should expect (SPEC 13.1); "
    "each takes effect only on a run that advances the pin"
)

_EXPECT_ANCHOR_BINDING_HELP = (
    "declare (onto --pin's state) that the .anchors sidecar is expected to "
    "carry a section 15 aggregate binding at or after the pinned seq. A run "
    "that finds only unbound records reports anchor_policy_downgrade, exit 2 "
    "— never evidence of tampering. Requires --pin; only takes effect on a "
    "run that advances it"
)

_MAX_ANCHOR_AGE_S_HELP = (
    "declare (onto --pin's state) a silence deadline in seconds: the newest "
    ".anchors record older than this (or no record at all) reports "
    "anchor_stale, exit 2. Requires --pin; only takes effect on a run that "
    "advances it"
)

_DECLARE_TOPOLOGY_HELP = (
    "declare (onto --pin's state) how many independent authorities hold a "
    "binding, as seal_escrow=<bool>,anchor_sinks=<int>,witness=<bool>,"
    "pin_separate=<bool> — all four subfields required together (SPEC 13.1: "
    "a partial declaration is malformed_pin, never silently defaulted). "
    "Requires --pin; only takes effect on a run that advances it"
)

_TSA_HELP = (
    "timestamp the checkpoint at an RFC 3161 Time-Stamp Authority and store "
    "the token in the sidecar record. Makes the time attested by a third "
    "party rather than asserted by this host. Nothing is recorded if the TSA "
    "is unreachable or answers about other bytes. The token's CMS signature "
    "is NOT verified by waxseal, here or on verify — check it with "
    "`openssl ts -verify`"
)

_OTS_HELP = (
    "submit the checkpoint digest to an OpenTimestamps calendar and store the "
    "PENDING proof. The Bitcoin attestation does not exist until the block "
    "confirms; complete it with `ots upgrade`"
)

_WITNESS_HELP = (
    "witness endpoint URL (repeatable). On `anchor`, publish the checkpoint "
    "there too; on `verify`, check the trail extends everything that witness "
    "saw. Point it at a host that is NOT the chain server — witnessing a "
    "server to itself proves nothing"
)


def _survive_a_narrow_console() -> None:
    """Never let an encoding crash swallow a verification verdict.

    Console output on Windows still defaults to a legacy codepage (cp1252 on
    this project's own report of the 0.1.1 install bug), which cannot encode
    the em dashes and ellipses in these messages. Without this, `report` on
    such a console dies with UnicodeEncodeError *after* doing the work,
    the operator gets a traceback instead of the answer, and a non-zero exit
    that means nothing about the chain. Degrading a dash to an escape is a
    cosmetic loss; losing the verdict is not.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        encoding = getattr(stream, "encoding", None)
        if reconfigure is None or encoding is None:
            continue
        try:
            # Only touch a stream that genuinely cannot carry this output.
            # A capable console keeps its own error handling untouched.
            "— … ▶".encode(encoding)
        except (UnicodeEncodeError, LookupError):
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="backslashreplace")


def _add_pin_declaration_arguments(p: argparse.ArgumentParser) -> None:
    """`--expect-anchor-binding`/`--max-anchor-age-s`/`--declare-topology`:
    the CLI writers for the three `PinState` declarations SPEC 13.1 defines
    (waxseal-ekd, closing conformance.md gap G2). Shared between `verify`
    and `report` since both already accept `--pin`: one definition so the
    two commands cannot drift apart on flag name or help text.
    """
    p.add_argument(
        "--expect-anchor-binding", action="store_true", default=False,
        help=_EXPECT_ANCHOR_BINDING_HELP,
    )
    p.add_argument(
        "--max-anchor-age-s", type=int, default=None, metavar="SECONDS",
        help=_MAX_ANCHOR_AGE_S_HELP,
    )
    p.add_argument(
        "--declare-topology", type=_declared_topology_arg, default=None, metavar="SPEC",
        help=_DECLARE_TOPOLOGY_HELP,
    )


def main(argv: list[str] | None = None) -> int:
    _survive_a_narrow_console()
    parser = argparse.ArgumentParser(prog="waxseal")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="verify chain integrity")
    p_verify.add_argument("path")
    p_verify.add_argument(
        "--anchors", action="store_true",
        help="also check the local anchor sidecar (<path>.anchors), if any",
    )
    p_verify.add_argument("--pin", type=Path, default=None, metavar="STATEFILE", help=_PIN_HELP)
    _add_pin_declaration_arguments(p_verify)
    p_verify.add_argument(
        "--witness", action="append", default=None, metavar="URL", help=_WITNESS_HELP
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
    p_anchor.add_argument(
        "--witness", action="append", default=None, metavar="URL", help=_WITNESS_HELP
    )
    p_anchor.add_argument("--tsa-url", metavar="URL", help=_TSA_HELP)
    p_anchor.add_argument("--ots-calendar", metavar="URL", help=_OTS_HELP)

    p_report = sub.add_parser(
        "report", help="print an auditor report: what the trail holds and what was checked"
    )
    p_report.add_argument("path")
    p_report.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    p_report.add_argument(
        "--anchors", action="store_true",
        help="also check the local anchor sidecar (<path>.anchors), if any",
    )
    p_report.add_argument("--pin", type=Path, default=None, metavar="STATEFILE", help=_PIN_HELP)
    _add_pin_declaration_arguments(p_report)
    p_report.add_argument(
        "--witness", action="append", default=None, metavar="URL", help=_WITNESS_HELP
    )

    p_export = sub.add_parser(
        "export-proof",
        help="print a standalone proof bundle for one entry (stdout; redirect to a file)",
    )
    p_export.add_argument("path")
    p_export.add_argument("seq", type=int)

    p_verify_proof = sub.add_parser(
        "verify-proof", help="check a proof bundle offline — no trail needed"
    )
    p_verify_proof.add_argument("bundle")

    p_consistency = sub.add_parser(
        "consistency",
        help="check the current head extends an earlier recorded state "
        "(RFC 9162 consistency proof; failure is split-view evidence)",
    )
    p_consistency.add_argument("path")
    p_consistency.add_argument(
        "--old-seq", type=int, required=True, metavar="N",
        help="seq of the earlier state, as printed by `waxseal checkpoint`",
    )
    p_consistency.add_argument(
        "--old-root", required=True, metavar="HEX",
        help="batch root of the earlier state, as printed by `waxseal checkpoint`",
    )

    p_verify_handoff = sub.add_parser(
        "verify-handoff",
        help="check every cross-trail handoff binding recorded on this "
        "(delegate) trail against an origin trail's current history "
        "(SPEC D3; read-only against both trails, appends nothing)",
    )
    p_verify_handoff.add_argument("path")
    p_verify_handoff.add_argument(
        "--origin", required=True, metavar="PATH",
        help="local path to the origin trail this delegate's handoff "
        "bindings point at (no URL/remote support — read-only, local "
        "path only)",
    )

    p_reconcile = sub.add_parser(
        "reconcile-tickets",
        help="reconcile an exogenous issuer's admission tickets against "
        "tickets present on the trail (positively-detected drops; D2)",
    )
    p_reconcile.add_argument("path")
    p_reconcile.add_argument(
        "--issuer", required=True, metavar="NAME",
        help="only reconcile tickets recorded under this issuer name",
    )
    p_reconcile.add_argument(
        "--lease-size", type=int, required=True, metavar="L",
        help="the issuer's lease size (no default — this is the issuer's "
        "own parameter, never guessed)",
    )
    p_reconcile.add_argument(
        "--issued", default=None, metavar="SPEC",
        help="ticket numbers the issuer reports as actually issued, e.g. "
        "'0-99' or '0,1,5-9' (comma-separated ints and inclusive ranges); "
        "omit when the issuer cannot be asked this run — reported as "
        "unmeasured (exit 2), never as zero drops",
    )
    p_reconcile.add_argument("--json", action="store_true", help="emit JSON instead of text")

    p_receipt = sub.add_parser(
        "receipt",
        help="extract stored anchor receipts to files for the external "
        "verifiers waxseal delegates to (openssl ts -verify, ots verify)",
    )
    p_receipt.add_argument("path")
    p_receipt.add_argument(
        "--seq", type=int, default=None, metavar="N",
        help="only receipts anchored at this seq (default: every record with one)",
    )
    p_receipt.add_argument(
        "--out", type=Path, required=True, metavar="DIR",
        help="directory to write receipt and frame files into (created if missing)",
    )

    p_cadence = sub.add_parser(
        "cadence",
        help="print the cost-optimal anchoring cadence for operator-supplied "
        "parameters (pure arithmetic; opens no trail at all)",
    )
    p_cadence.add_argument(
        "--lam", type=float, required=True, metavar="RATE",
        help="entry arrival rate (entries per unit time)",
    )
    p_cadence.add_argument(
        "--c", type=float, required=True, metavar="COST",
        help="marginal cost of one anchor operation (operator measurement, no default)",
    )
    p_cadence.add_argument(
        "--w", type=float, required=True, metavar="HARM",
        help="expected harm per rewritable record if compromised "
        "(operator measurement, no default)",
    )
    p_cadence.add_argument(
        "--rho", type=float, required=True, metavar="RATE",
        help="compromise hazard rate (operator measurement, no default)",
    )
    p_cadence.add_argument(
        "--M", type=int, default=1, metavar="N",
        help="agents sharing one anchor (default: 1 -- structural 'no fleet "
        "sharing', not a guessed measurement)",
    )
    p_cadence.add_argument(
        "--delta", type=float, required=True, metavar="SECONDS",
        help="anchor finality latency",
    )
    p_cadence.add_argument(
        "--t-max", type=float, required=True, metavar="SECONDS", dest="t_max",
        help="operator's tolerated detection window",
    )

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

    if args.command == "cadence":
        # Pure arithmetic over operator-supplied measurements: opens no
        # trail at all, unlike every other subcommand here.
        return _cadence(
            lam=args.lam, c=args.c, w=args.w, rho=args.rho, M=args.M,
            delta=args.delta, t_max=args.t_max,
        )

    if args.command == "install":
        # Writes host shim files only, and never touches any audit log.
        from waxseal.integrations._install import install

        return install(args.target, args.home, args.force)

    if args.command == "verify-proof":
        # A bundle is self-contained by design: the auditor holds this one
        # file and no trail at all, so none of the trail plumbing below
        # applies to it.
        return _verify_proof(Path(args.bundle).expanduser())

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
            )
        if args.command == "export-proof":
            return _export_proof(log, args.seq)
        if args.command == "tail":
            return _tail(log, args.n)
        if args.command == "head":
            return _head(log)
        if args.command == "checkpoint":
            return _checkpoint(log)
        if args.command == "consistency":
            return _consistency(log, old_seq=args.old_seq, old_root=args.old_root)
        if args.command == "verify-handoff":
            return _verify_handoff(log, origin_path=Path(args.origin).expanduser())
        if args.command == "reconcile-tickets":
            return _reconcile_tickets(
                log,
                issuer=args.issuer,
                lease_size=args.lease_size,
                issued_spec=args.issued,
                as_json=args.json,
            )
        if args.command == "anchor":
            assert trail is not None  # guarded above: URL targets returned already
            return _anchor(
                log,
                trail,
                witnesses=args.witness,
                tsa_url=args.tsa_url,
                ots_calendar=args.ots_calendar,
            )
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


@dataclass(frozen=True, slots=True)
class _Check:
    """One verification dimension's verdict plus the line `verify` prints for
    it. `report` renders the same summary its own way, so each check is
    computed in exactly one place and cannot say two different things."""

    summary: CheckSummary
    line: str

    @property
    def verdict(self) -> Verdict:
        if not self.summary.ok:
            return Verdict.BROKEN
        return Verdict.UNVERIFIABLE if self.summary.unverifiable else Verdict.OK

    @property
    def exit_code(self) -> int:
        return self.verdict.to_exit_code()


def _combine(codes: list[int]) -> int:
    """Broken beats unverifiable beats intact.

    Structural, not conventional: each code is read back into the ``Verdict``
    it came from (domain/verdict.py) and combined with ``Verdict.join`` in
    true severity order, then converted back to an exit code. This is no
    longer merely "deliberately not ``max``": ``int`` only ever means
    anything at this one CLI boundary function, everywhere else the
    combination happens on ``Verdict`` values themselves.
    """
    verdicts = (Verdict.from_exit_code(code) for code in codes)
    return functools.reduce(Verdict.join, verdicts, Verdict.OK).to_exit_code()


def _default_now() -> datetime:
    # Rule 8: timestamps are injectable. This is only the seam's default,
    # `pinned_ts` is produced through a now_fn parameter so a test can pin an
    # exact time instead of sleeping or patching a module global.
    return datetime.now(UTC)


def _verify(
    log: AuditLog,
    trail: Path | None,
    *,
    check_anchors: bool = False,
    is_url: bool = False,
    pin_path: Path | None = None,
    target: str | None = None,
    chain_id: str | None = None,
    witnesses: list[str] | None = None,
    now_fn: Callable[[], datetime] = _default_now,
    declare_expect_anchor_binding: bool = False,
    declare_max_anchor_age_s: int | None = None,
    declare_topology: SeparationTopology | None = None,
) -> int:
    # A CLI process saw no writes, so it cannot measure drops (None, not 0).
    result = log.verify(measure_drops=False)
    codes = [0]
    if not result.ok:
        print(f"BROKEN at seq={result.broken_seq}: {result.reason} (checked={result.checked})")
        codes.append(1)
    elif result.unverifiable:
        print(
            f"ok (checked={result.checked}) but {len(result.unverifiable)} unverifiable "
            f"row(s) at seq={list(result.unverifiable)} — unknown schema fingerprint, "
            "NOT evidence of tampering"
        )
        codes.append(2)
    else:
        print(f"ok (checked={result.checked})")
        if is_url and result.checked == 0:
            # GET /entries 404 means "empty" identically for a genuinely
            # fresh chain and for a mistyped chain_id/wrong path, unlike a
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

    # Every remaining dimension is checked even when an earlier one already
    # failed: an operator investigating a break needs to know whether the pin
    # and the anchors agree with it, not just that the run stopped.
    #
    # Anchors and witnesses are MEASURED here, ahead of the pin check, so
    # _pin_check can compare a declared_topology against what this run
    # actually observed (waxseal-7tk.3.2). Each dimension's own line still
    # PRINTS in the original order (pin, then anchors, then witnesses), so
    # only the underlying computation moved earlier, not the output.
    anchor_check: _Check | None = None
    observed_anchor_sinks: int | None = None
    observed_anchor_records: tuple[AnchorRecord, ...] | None = None
    observed_anchor_unreadable: bool | None = None
    # trail is None only for a URL target, and main() already forces
    # check_anchors False in that case (no local sidecar to check), and this
    # guard just makes that invariant visible to mypy, not a new behavior.
    if check_anchors and trail is not None:
        anchor_check = _anchor_check(log, trail)
        observed_anchor_sinks = _observed_anchor_sinks(trail)
        observed_anchor_records = _observed_anchor_records(trail)
        observed_anchor_unreadable = _observed_anchor_unreadable(trail)

    witness_verdicts: list[WitnessVerdict] | None = None
    observed_witness_consistent: bool | None = None
    if witnesses:
        witness_verdicts = _witness_verdicts(log, witnesses)
        observed_witness_consistent = _observed_witness_consistent(witness_verdicts)

    pending_pin: PinState | None = None
    if pin_path is not None:
        assert target is not None  # main() always passes both together
        check, pending_pin = _pin_check(
            log,
            pin_path,
            target=target,
            chain_id=chain_id,
            now_fn=now_fn,
            observed_anchor_sinks=observed_anchor_sinks,
            observed_witness_consistent=observed_witness_consistent,
            observed_anchor_records=observed_anchor_records,
            observed_anchor_unreadable=observed_anchor_unreadable,
            declare_expect_anchor_binding=declare_expect_anchor_binding,
            declare_max_anchor_age_s=declare_max_anchor_age_s,
            declare_topology=declare_topology,
        )
        print(check.line)
        codes.append(check.exit_code)

    if anchor_check is not None:
        print(anchor_check.line)
        # Anchor breakage escalates to 1 regardless of the chain's own exit
        # code: it is still "broken", just a different dimension of it.
        codes.append(anchor_check.exit_code)

    if witness_verdicts is not None:
        for verdict in witness_verdicts:
            print(_witness_line(verdict))
        codes.append(_witness_exit_code(witness_verdicts))

    # τ (waxseal-mfi, closing conformance.md gap G1): printed unconditionally,
    # never only when --pin is given: "not declared" must be as loud as any
    # other rule-5 "not measured" state, not something an operator only sees
    # by asking. `None` when no --pin was given, or the pin carries no
    # declared_topology; never inferred as 0 or 1 either way.
    declared_topology = pending_pin.declared_topology if pending_pin is not None else None
    print(_tau_line(declared_topology))

    code = _combine(codes)
    if pending_pin is not None and code != 1:
        # Only exit 1 (broken) freezes the pin, since advancing then would launder
        # the break into the new baseline. Exit 2 DOES advance (SPEC.md
        # section 13): unverifiable is not tampered, and refusing to pin a
        # trail with unknown fingerprints would disable pinning for exactly
        # the forward-compatible case this library exists for.
        _save_pin(pin_path, pending_pin)
    return code


def _tau_line(topology: SeparationTopology | None) -> str:
    """The τ line `verify` prints, always, even with no `--pin` at all
    (rule 5: "not declared" must never be a silent absence, the same
    discipline `_print_drop_count` gives dropped_writes). `report`'s own
    rendering goes through `build_report`/`AuditReport` instead, so the two
    surfaces share the same domain functions without sharing this string.
    """
    degree = separation_degree(topology)
    rendered = render_separation_degree(degree)
    if degree is None:
        return f"τ (separation degree): {rendered}"
    breakdown = render_counted_authorities(counted_authorities(topology))
    return f"τ (separation degree): {rendered} ({breakdown})"


def _print_drop_count(trail: Path | None) -> None:
    # Completeness, not integrity (CLAUDE.md rule 5): this never changes
    # the caller's exit code. No sidecar means "never measured" (unchanged
    # output, matching the pre-M5 behavior), not a printed "0". A URL target
    # has no local sidecar location at all, the same as "never measured".
    if trail is None:
        return
    from waxseal.adapters.drops import read_drop_count

    count = read_drop_count(trail)
    if count is not None:
        print(f"dropped_writes >= {count} (measured minimum, from {trail}.drops)")


def _anchor_check(log: AuditLog, trail: Path) -> _Check:
    """Check the `.anchors` sidecar against the trail as it stands now."""
    import json

    from waxseal.adapters.anchors import read_anchor_records
    from waxseal.domain.checkpoint import verify_checkpoint

    try:
        sidecar = read_anchor_records(trail)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        # The sidecar is as attacker-writable as the trail it anchors
        # (same threat model as attest.py's sidecar): malformed bytes are a
        # verdict, never a crash (fail-closed rule, verify_membership/
        # verify_checkpoint's own contract).
        return _Check(
            CheckSummary(ok=False, checked=0, reason="malformed_anchor"),
            "ANCHOR BROKEN: malformed_anchor",
        )

    records = sidecar.records
    if not records and not sidecar.unreadable_versions:
        # Absence is not failure (CLAUDE.md rule 5: unmeasured != 0/ok).
        return _Check(
            CheckSummary(ok=True, checked=0, reason="no_anchors_recorded"),
            "no anchors found (anchor coverage unmeasured)",
        )

    hashes = log.entry_hashes()
    for record in records:
        cp = record.checkpoint
        reason = verify_checkpoint(hashes, cp)
        if reason is not None:
            return _Check(
                CheckSummary(ok=False, checked=0, reason=reason),
                f"ANCHOR BROKEN at seq={cp.seq}: {reason}",
            )

    notes: list[str] = []
    receipts = [_receipt_verdict(record) for record in records]
    broken_receipt = next((r for r in receipts if r.status == _RECEIPT_BROKEN), None)
    if broken_receipt is not None:
        return _Check(
            CheckSummary(ok=False, checked=len(records), reason=broken_receipt.reason),
            f"ANCHOR BROKEN: {broken_receipt.note}",
        )
    notes.extend(r.note for r in receipts if r.note is not None)
    unverifiable_receipts = [r for r in receipts if r.status == _RECEIPT_UNVERIFIABLE]

    bound = sum(1 for r in records if r.checkpoint.agg_commit is not None)
    if bound:
        # The CLI holds no seal key, so the chain-shape claim of a v2 record
        # is checked and its aggregate claim is not. Rule 6: an unperformed
        # check is stated, never left to look like a performed one.
        notes.append(
            f"{bound} record(s) carry a forward-secure aggregate binding, NOT checked "
            "here (no seal key available to the CLI — use "
            "AuditLog.verify_anchored_aggregates)"
        )
    if sidecar.unreadable_versions:
        versions = ", ".join(sorted(set(sidecar.unreadable_versions)))
        notes.append(
            f"{len(sidecar.unreadable_versions)} record(s) in an unreadable format "
            f"version ({versions}) — unverifiable by name, NOT evidence of tampering"
        )

    line = (
        f"anchors ok (checked={len(records)}, latest=seq {records[-1].checkpoint.seq})"
        if records
        else "no readable anchors found (anchor coverage unmeasured)"
    )
    for note in notes:
        line += f"\n  note: {note}"

    # Two different ways this build can lack coverage, both exit 2 and both
    # named: a record version it cannot read, and a receipt format it cannot
    # read. Neither is evidence of tampering.
    reason = None
    if sidecar.unreadable_versions:
        reason = "unreadable_record_version"
    elif unverifiable_receipts:
        reason = unverifiable_receipts[0].reason
    return _Check(
        CheckSummary(
            ok=True,
            checked=len(records),
            reason=reason,
            unverifiable=bool(sidecar.unreadable_versions or unverifiable_receipts),
            notes=tuple(notes),
        ),
        line,
    )


def _observed_anchor_sinks(trail: Path) -> int:
    """How many distinct EXTERNAL anchor sinks this run actually sees
    recorded in the `.anchors` sidecar: the "observed" half of a
    declared-vs-observed separation comparison (waxseal-7tk.3.2).

    ``"file"`` (``FileAnchorSink.name``) is excluded: it is the local
    baseline this same sidecar always carries, explicitly not an independent
    witness per this module's own docstring, so counting it would let a
    trail anchor "to itself" and still look separated. A second, small read
    of the sidecar rather than a refactor of ``_anchor_check`` to return this
    count too (cheap, and this codebase already tolerates the same
    duplication in ``_report``'s witness handling.

    A sidecar this build cannot parse yields ``0``, the same as an empty one:
    ``_anchor_check`` already reports the malformed sidecar as its own
    ANCHOR BROKEN finding, and an unreadable file is not evidence that any
    external sink exists.
    """
    import json

    from waxseal.adapters.anchors import read_anchor_records

    try:
        records = read_anchor_records(trail).records
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return 0
    return len({r.sink for r in records if r.sink != "file"})


def _observed_anchor_records(trail: Path) -> tuple[AnchorRecord, ...]:
    """The `.anchors` sidecar's own records, for the ``anchor_staleness``
    comparison ``_pin_check`` runs against a declared ``max_anchor_age_s``
    (waxseal-7tk.4.1). A third read of the sidecar in this same call is
    accepted duplication in this codebase, per ``_observed_anchor_sinks``'s
    own docstring, not a refactor forced on this bead.

    A sidecar this build cannot parse yields ``()``, same treatment
    ``_observed_anchor_sinks`` gives it: ``_anchor_check`` already reports
    the malformed sidecar as its own ANCHOR BROKEN finding (exit 1), so this
    value only matters when that dimension is otherwise clean.
    """
    import json

    from waxseal.adapters.anchors import read_anchor_records

    try:
        return read_anchor_records(trail).records
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return ()


def _observed_anchor_unreadable(trail: Path) -> bool:
    """Whether the `.anchors` sidecar held any record in a format this build
    cannot read at all, for the ``anchor_policy_downgrade`` comparison
    (waxseal-7tk.5.1, W5/F2). A fourth read of the sidecar in this same
    call is accepted duplication in this codebase, per
    ``_observed_anchor_sinks``'s own docstring.

    A sidecar this build cannot even parse as JSON is the OPPOSITE case from
    ``_observed_anchor_sinks``/``_observed_anchor_records``: those two feed
    comparisons that only matter once the trail's anchor dimension is
    otherwise clean, so "0"/"()" is a safe default because ``_anchor_check``
    already reports the parse failure as its own ANCHOR BROKEN (exit 1)
    finding. This value feeds a DIFFERENT question, "can we say there is
    truly no binding", and catastrophic parse failure is the strongest
    possible instance of "cannot corroborate": a whole sidecar this build
    could not read might just as easily have carried a binding as not.
    Returning ``True`` here is the conservative (rule 5) choice, even though
    in practice the run's exit code is already forced to 1 by
    ``_anchor_check`` in that same case, making this value moot for the
    combined exit code, it still keeps this helper's own answer honest.
    """
    import json

    from waxseal.adapters.anchors import read_anchor_records

    try:
        return bool(read_anchor_records(trail).unreadable_versions)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return True


_RECEIPT_CHECKED: Final = "checked"
_RECEIPT_BROKEN: Final = "broken"
_RECEIPT_UNVERIFIABLE: Final = "unverifiable"
_RECEIPT_NOTED: Final = "noted"
_RECEIPT_ABSENT: Final = "absent"


@dataclass(frozen=True, slots=True)
class _ReceiptVerdict:
    status: str
    note: str | None = None
    reason: str | None = None


def _receipt_verdict(record: AnchorRecord) -> _ReceiptVerdict:
    """What this build can say about one anchor record's receipt.

    Five outcomes, and the distinctions between them are the whole point:

    - ``absent``    the record carries no receipt at all (FileAnchorSink has
      none to give). Nothing was claimed, so nothing is checked or faulted.
    - ``checked``   an RFC 3161 token that structurally attests this exact
      checkpoint frame. Still not "genuine": the CMS signature is delegated
      (domain/rfc3161.py), and the printed line says so.
    - ``broken``    a token that attests OTHER bytes. Checked and false.
    - ``unverifiable`` a token this build cannot read, or a receipt prefix
      from a newer waxseal. Unknown formats are opaque, not errors
      (RFC 6962 section 4.6).
    - ``noted``     an OpenTimestamps proof, opaque by design and labelled
      as such. Deliberately does NOT raise the exit code: an operator who
      anchors to a calendar would otherwise see exit 2 on every healthy verify
      and learn to ignore it, which costs more than it buys.
    """
    from waxseal.domain import ots, rfc3161
    from waxseal.domain.checkpoint import checkpoint_frame

    receipt = record.receipt
    seq = record.checkpoint.seq
    if receipt is None:
        return _ReceiptVerdict(_RECEIPT_ABSENT)

    if receipt.startswith(rfc3161.RECEIPT_PREFIX):
        der = rfc3161.decode_receipt(receipt)
        if der is None:
            return _ReceiptVerdict(
                _RECEIPT_UNVERIFIABLE,
                note=(
                    f"seq={seq}: RFC 3161 receipt is not readable by this build "
                    f"({rfc3161.MALFORMED_TOKEN}) — unverifiable by name, NOT evidence "
                    "of tampering"
                ),
                reason=rfc3161.MALFORMED_TOKEN,
            )
        frame = checkpoint_frame(record.checkpoint)
        # expected_nonce comes from the record when the sink stored one;
        # None (every record written before the field existed) skips the
        # comparison rather than failing it, since absence is not a mismatch.
        token, why = rfc3161.read_timestamp_resp(der, frame, expected_nonce=record.nonce)
        if token is not None:
            return _ReceiptVerdict(
                _RECEIPT_CHECKED,
                note=(
                    f"seq={seq}: attested time (RFC 3161, structural only — signature "
                    f"NOT verified): {token.gen_time_iso}"
                ),
            )
        if why in _RECEIPT_CHECKED_FALSE:
            return _ReceiptVerdict(
                _RECEIPT_BROKEN,
                note=(
                    f"seq={seq}: the RFC 3161 receipt attests different bytes than the "
                    f"record beside it ({why}) — note the signature itself is still "
                    "unverified here"
                ),
                reason=why,
            )
        return _ReceiptVerdict(
            _RECEIPT_UNVERIFIABLE,
            note=(
                f"seq={seq}: RFC 3161 receipt is not readable by this build ({why}) — "
                "unverifiable by name, NOT evidence of tampering"
            ),
            reason=why,
        )

    if receipt.startswith(ots.RECEIPT_PREFIX):
        return _ReceiptVerdict(_RECEIPT_NOTED, note=f"seq={seq}: {ots.PENDING_NOTE}")

    prefix = receipt.split(":", 1)[0]
    return _ReceiptVerdict(
        _RECEIPT_UNVERIFIABLE,
        note=(
            f"seq={seq}: receipt type {prefix!r} is unknown to this build — "
            "unverifiable by name, NOT evidence of tampering"
        ),
        reason="unknown_receipt_type",
    )


def _witness_verdicts(log: AuditLog, urls: list[str]) -> list[WitnessVerdict]:
    """Ask every configured witness what it saw and compare.

    An unreachable or unusable witness becomes an ``unreachable`` verdict
    rather than an exception: one notary being down must not deny the audit
    the other two would have provided. It is never silent: the caller prints
    every verdict, including this one.
    """
    from waxseal.adapters.remote import RemoteError
    from waxseal.adapters.witness import HTTPWitness
    from waxseal.domain.witnessing import check_witnessed, unreachable_witness

    hashes = log.entry_hashes()
    verdicts: list[WitnessVerdict] = []
    for url in urls:
        witness = HTTPWitness(url, api_key=_witness_api_key())
        try:
            observation = witness.fetch()
        except (OSError, RemoteError) as e:
            verdicts.append(unreachable_witness(witness.name, reason=str(e)))
            continue
        verdicts.append(check_witnessed(hashes, observation, name=witness.name))
    return verdicts


def _witness_line(verdict: WitnessVerdict) -> str:
    from waxseal.domain.witnessing import WITNESS_INCONSISTENT, WITNESS_UNREACHABLE

    if verdict.status == WITNESS_UNREACHABLE:
        # Rule 5 one layer up: a check that did not run is not a check that
        # passed, and not a break either. It contributes exit 2
        # (unverifiable), the same verdict an unknown fingerprint gets, for
        # the same reason (SPEC.md section 14).
        return (
            f"witness {verdict.name}: unreachable ({verdict.reason}) — NOT checked; "
            "an unreachable witness is never a pass"
        )
    if verdict.status == WITNESS_INCONSISTENT:
        return (
            f"witness {verdict.name}: INCONSISTENT at seq={verdict.broken_seq}: "
            f"{verdict.reason} — the local trail does not extend what this witness "
            "saw, which is evidence of split-view or a rewritten history"
        )
    line = f"witness {verdict.name}: consistent (checked={verdict.checked})"
    if verdict.reason is not None:
        line += f" — {verdict.reason}: this witness holds nothing, so it covers nothing"
    if verdict.unreadable:
        line += (
            f"\n  note: {verdict.unreadable} record(s) this build could not read — "
            "coverage this run did not measure"
        )
    return line


def _witness_exit_code(verdicts: list[WitnessVerdict]) -> int:
    from waxseal.domain.witnessing import WITNESS_INCONSISTENT, WITNESS_UNREACHABLE

    # Inconsistency is evidence of a split view, a break (1). A witness that
    # could not be asked is coverage this run does not have: unverifiable (2),
    # never a pass and never conflated with tampering (SPEC.md section 14).
    # _combine keeps "1 beats 2" when another dimension found a real break.
    if any(v.status == WITNESS_INCONSISTENT for v in verdicts):
        return 1
    if any(v.status == WITNESS_UNREACHABLE for v in verdicts):
        return 2
    return 0


def _observed_witness_consistent(verdicts: list[WitnessVerdict]) -> bool:
    """Whether this run reached at least one witness that returned a
    ``consistent`` verdict: the "observed" half of a declared-vs-observed
    separation comparison (waxseal-7tk.3.2). An ``unreachable`` or
    ``inconsistent`` witness does not count: neither is a witness this run
    actually confirmed agreement with.
    """
    from waxseal.domain.witnessing import WITNESS_CONSISTENT

    return any(v.status == WITNESS_CONSISTENT for v in verdicts)


def _witness_api_key() -> str | None:
    # Same rule as the chain backend: credentials come from the environment,
    # never from argv (where they would land in shell history and `ps`).
    # Deliberately NOT WAXSEAL_API_KEY: that is the chain server's WRITE
    # credential, and REMOTE.md section 8 puts a witness under a different
    # administrative authority: a witness handed the chain key could append
    # forged entries to the very chain it exists to cross-check.
    import os

    return os.environ.get("WAXSEAL_WITNESS_API_KEY")


def _pin_check(
    log: AuditLog,
    pin_path: Path,
    *,
    target: str,
    chain_id: str | None,
    now_fn: Callable[[], datetime] = _default_now,
    observed_anchor_sinks: int | None = None,
    observed_witness_consistent: bool | None = None,
    observed_anchor_records: tuple[AnchorRecord, ...] | None = None,
    observed_anchor_unreadable: bool | None = None,
    declare_expect_anchor_binding: bool = False,
    declare_max_anchor_age_s: int | None = None,
    declare_topology: SeparationTopology | None = None,
) -> tuple[_Check, PinState | None]:
    """Check the trail against what this verifier last confirmed.

    Returns the verdict and, when the run is allowed to record a new one, the
    pin state to write. Writing is the caller's job and happens only after
    every other dimension has reported: a pin that advances past a run which
    found a break elsewhere would record the broken state as confirmed.

    ``observed_anchor_sinks``/``observed_witness_consistent``/
    ``observed_anchor_records``/``observed_anchor_unreadable`` are what THIS
    run measured, or ``None`` when it did not measure that dimension at all
    (the caller did not pass ``--anchors``/``--witness``). Per CLAUDE.md rule
    5, ``None`` here must never be read as "0 sinks", "witness inconsistent",
    "zero anchor records", or "nothing unreadable": it means the comparison
    below is skipped entirely, the same way an undeclared topology skips it.
    An empty tuple for ``observed_anchor_records`` is a DIFFERENT, meaningful
    value: anchors WERE checked this run, and the sidecar held zero records.

    ``declare_expect_anchor_binding``/``declare_max_anchor_age_s``/
    ``declare_topology`` are what THIS run's CLI flags asked to declare
    (waxseal-ekd, closing conformance.md gap G2): ``--expect-anchor-binding``/
    ``--max-anchor-age-s``/``--declare-topology``. Each is merged onto
    whatever the stored pin already carried: a CLI declaration on this run
    wins, an omitted one falls back to what was already stored (or the
    ordinary "never declared" default when there is no stored pin at all).
    This is the same "advance preserves the declaration" rule every other
    branch below already followed for `stored.*`, and the merge just gives a
    CLI flag a way to override it, never a way to silently reset it.
    """
    from waxseal.adapters.pinstore import FilePinStore
    from waxseal.domain.checkpoint import checkpoint_for
    from waxseal.domain.pinning import (
        PinMalformed,
        PinState,
        PinVersionUnknown,
        anchor_policy_downgrade,
        anchor_staleness,
        check_pin,
        check_pin_target,
    )

    store = FilePinStore(pin_path)
    try:
        stored = store.load()
    except PinVersionUnknown as e:
        # A state file from a newer waxseal. Unverifiable BY NAME, the same
        # rule an unknown schema fingerprint gets, for the same reason.
        return (
            _Check(
                CheckSummary(ok=True, checked=0, reason="pin_version_unknown", unverifiable=True),
                f"pin unverifiable: pin_version_unknown ({e}) — NOT evidence of tampering",
            ),
            None,
        )
    except PinMalformed as e:
        # Never fall back to first-use here: re-pinning over an unreadable
        # state is the whole re-pin attack, and "the file was corrupt so I
        # trusted what I was served" is not a check.
        return (
            _Check(
                CheckSummary(ok=False, checked=0, reason="malformed_pin"),
                f"PIN BROKEN: malformed_pin ({e}) — refusing to re-pin over a "
                "state this build could not read",
            ),
            None,
        )

    hashes = log.entry_hashes()
    now_dt = now_fn()
    now = now_dt.isoformat()

    # Merge this run's CLI declarations onto whatever was already stored
    # (nothing, for a genuine first pin). A flag given this run wins; an
    # omitted one preserves the prior value exactly and never resets it to
    # the "never declared" default (that would silently undo an earlier
    # declaration the operator never asked to remove).
    #
    # Design choice, since SPEC 13.1 predates these flags and does not say:
    # the anchor_policy_downgrade/anchor_staleness/separation_shortfall
    # checks below still gate on `stored.*` (what a PRIOR run already wrote),
    # never on these `effective_*` values. A declaration made for the first
    # time on THIS run therefore does not also enforce itself against THIS
    # run's own anchor/witness observations: it takes effect starting the
    # NEXT run, once it has actually been written and read back. That is a
    # deliberate, conservative choice: the alternative (enforcing a brand
    # new expectation before the operator has had a chance to satisfy it,
    # e.g. anchoring at least once) would make the very act of declaring a
    # policy able to fail a run that was otherwise clean.
    effective_expect_anchor_binding = declare_expect_anchor_binding or (
        stored.expect_anchor_binding if stored is not None else False
    )
    effective_max_anchor_age_s = (
        declare_max_anchor_age_s
        if declare_max_anchor_age_s is not None
        else (stored.max_anchor_age_s if stored is not None else None)
    )
    effective_declared_topology = (
        declare_topology
        if declare_topology is not None
        else (stored.declared_topology if stored is not None else None)
    )

    if stored is None:
        if not hashes:
            return (
                _Check(
                    CheckSummary(ok=True, checked=0, reason="empty_trail_not_pinned"),
                    "pin: nothing to pin (the trail is empty) — no trust established",
                ),
                None,
            )
        head = checkpoint_for(hashes)
        return (
            _Check(
                CheckSummary(ok=True, checked=0, reason="trust_on_first_use"),
                f"PIN INITIALIZED (trust-on-first-use): recorded seq={head.seq} — this "
                "run establishes trust in what it was served, it does not verify "
                "against any prior history",
            ),
            PinState(
                target=target,
                chain_id=chain_id,
                checkpoint=head,
                pinned_ts=now,
                declared_topology=effective_declared_topology,
                max_anchor_age_s=effective_max_anchor_age_s,
                expect_anchor_binding=effective_expect_anchor_binding,
            ),
        )

    mismatch = check_pin_target(stored, target=target, chain_id=chain_id)
    if mismatch is not None:
        # A moved trail and the wrong file look identical from here. Either
        # comparing them or overwriting the pin would be a guess.
        return (
            _Check(
                CheckSummary(ok=False, checked=0, reason=mismatch),
                f"PIN BROKEN: pin_target_mismatch — this pin was recorded for "
                f"{stored.target!r} (chain_id={stored.chain_id!r}), not {target!r} "
                f"(chain_id={chain_id!r}); refusing to check or update it",
            ),
            None,
        )

    reason = check_pin(hashes, stored.checkpoint)
    if reason is not None:
        return (_Check(CheckSummary(ok=False, checked=0, reason=reason), _pin_break_line(
            reason, stored.checkpoint.seq
        )), None)

    head = checkpoint_for(hashes)

    # The pin matches, but three more declared-vs-observed comparisons can
    # still turn this into an exit-2 finding. Checked in this fixed order,
    # anchor_policy_downgrade FIRST, then anchor_staleness, then
    # separation_shortfall, and documented here because all three land on
    # _Check/CheckSummary, which carries only one `reason`: when a run
    # happens to trip more than one at once, this ordering decides which
    # single reason string surfaces. Not security-critical among the three
    # (every outcome here is exit 2/unverifiable either way), just a
    # tiebreak, but anchor_policy_downgrade goes first because it is the
    # direct F2 finding (SPEC §15 replay-plus-truncate protection silently
    # stripped) this release's own analysis singles out as the most
    # consequential exit-2 case.
    #
    # anchor_policy_downgrade (W5/F2): only compared when the operator asked
    # for the check AND this run actually checked anchors at all: `None`
    # means "not measured this run", never "no binding" (rule 5); an empty
    # tuple is the meaningfully different "checked, and there were none".
    if (
        stored.expect_anchor_binding
        and observed_anchor_records is not None
        and observed_anchor_unreadable is not None
    ):
        downgrade = anchor_policy_downgrade(
            stored.checkpoint.seq,
            tuple((r.checkpoint.seq, r.checkpoint.agg_commit) for r in observed_anchor_records),
            any_unreadable=observed_anchor_unreadable,
        )
        if downgrade is not None:
            detail = (
                "the operator expects an aggregate binding (SPEC §15), but the "
                ".anchors sidecar carries only v1-shaped records at or after the "
                "pinned seq — no binding found"
                if downgrade == "anchor_policy_downgrade"
                else "the operator expects an aggregate binding (SPEC §15), but "
                "some .anchors records are in a format this build cannot read — "
                "absence among the readable ones is not evidence there is truly "
                "no binding"
            )
            # Exit 2, never exit 1: a missing (or unreadable) binding is
            # absence of corroborating evidence for the declared policy, not
            # evidence the trail itself was tampered with.
            return (
                _Check(
                    CheckSummary(ok=True, checked=stored.checkpoint.seq + 1,
                                 reason=downgrade, unverifiable=True),
                    f"pin ok but {downgrade}: {detail} — NOT evidence of tampering, "
                    "the trail itself still verifies",
                ),
                PinState(
                    target=target,
                    chain_id=chain_id,
                    checkpoint=head,
                    pinned_ts=now,
                    declared_topology=effective_declared_topology,
                    max_anchor_age_s=effective_max_anchor_age_s,
                    expect_anchor_binding=effective_expect_anchor_binding,
                ),
            )

    # anchor_staleness (W4/C3): only compared when a deadline was actually
    # declared AND this run actually checked anchors at all: `None` means
    # "not measured this run", never "zero records" (rule 5); an empty tuple
    # is the meaningfully different "checked, and there were none".
    if stored.max_anchor_age_s is not None and observed_anchor_records is not None:
        staleness = anchor_staleness(
            stored.max_anchor_age_s,
            tuple((r.checkpoint.seq, r.ts) for r in observed_anchor_records),
            now=now_dt,
        )
        if staleness is not None:
            detail = (
                f"declared max_anchor_age_s={stored.max_anchor_age_s}s, but no "
                f".anchors record within that window was found as of {now}"
                if staleness == "anchor_stale"
                else "the newest .anchors record's ts could not be parsed as "
                "ISO-8601 — unverifiable by name, not evidence of staleness or "
                "freshness"
            )
            # Exit 2, never exit 1: silence (or an unreadable timestamp) is
            # absence of corroborating evidence for the declared deadline,
            # not evidence the trail itself was tampered with.
            return (
                _Check(
                    CheckSummary(ok=True, checked=stored.checkpoint.seq + 1,
                                 reason=staleness, unverifiable=True),
                    f"pin ok but {staleness}: {detail} — NOT evidence of tampering, "
                    "the trail itself still verifies",
                ),
                PinState(
                    target=target,
                    chain_id=chain_id,
                    checkpoint=head,
                    pinned_ts=now,
                    declared_topology=effective_declared_topology,
                    max_anchor_age_s=effective_max_anchor_age_s,
                    expect_anchor_binding=effective_expect_anchor_binding,
                ),
            )

    # A declared topology can still say this run observed LESS independence
    # than the operator claimed. Only compared when a topology was actually
    # declared AND this run actually measured both dimensions; otherwise
    # "not applicable" or "not measured", never a silent pass or a silent 0
    # (rule 5).
    if (
        stored.declared_topology is not None
        and observed_anchor_sinks is not None
        and observed_witness_consistent is not None
        and separation_shortfall(
            stored.declared_topology,
            observed_anchor_sinks=observed_anchor_sinks,
            observed_witness_consistent=observed_witness_consistent,
        )
    ):
        # Exit 2, never exit 1: a shortfall is "we observed less than
        # declared": an absence of corroborating evidence for the declared
        # topology, not evidence the trail itself was tampered with.
        return (
            _Check(
                CheckSummary(ok=True, checked=stored.checkpoint.seq + 1,
                             reason="separation_shortfall", unverifiable=True),
                f"pin ok but separation_shortfall: declared "
                f"anchor_sinks={stored.declared_topology.anchor_sinks} witness="
                f"{stored.declared_topology.witness}, this run observed "
                f"anchor_sinks={observed_anchor_sinks} "
                f"witness_consistent={observed_witness_consistent} — NOT evidence "
                "of tampering, the trail itself still verifies",
            ),
            PinState(
                target=target,
                chain_id=chain_id,
                checkpoint=head,
                pinned_ts=now,
                declared_topology=effective_declared_topology,
                max_anchor_age_s=effective_max_anchor_age_s,
                expect_anchor_binding=effective_expect_anchor_binding,
            ),
        )

    return (
        _Check(
            CheckSummary(ok=True, checked=stored.checkpoint.seq + 1, reason=None),
            f"pin ok (confirmed seq 0..{stored.checkpoint.seq} unchanged; "
            f"head is now seq {head.seq})",
        ),
        PinState(
            target=target,
            chain_id=chain_id,
            checkpoint=head,
            pinned_ts=now,
            declared_topology=effective_declared_topology,
            max_anchor_age_s=effective_max_anchor_age_s,
            expect_anchor_binding=effective_expect_anchor_binding,
        ),
    )


def _pin_break_line(reason: str, pinned_seq: int) -> str:
    explanations = {
        "pin_mismatch": (
            "history this verifier previously confirmed has been rewritten"
        ),
        "pin_beyond_head": (
            "the trail is shorter than what was already verified — a rollback "
            "or truncation of confirmed history"
        ),
        "malformed_pin": "the stored checkpoint is not a usable one",
    }
    return f"PIN BROKEN at pinned seq={pinned_seq}: {reason} — {explanations[reason]}"


def _save_pin(pin_path: Path | None, state: PinState) -> None:
    from waxseal.adapters.pinstore import FilePinStore

    assert pin_path is not None  # only reached when a pin was requested
    FilePinStore(pin_path).save(state)


def _pin_target(args_path: str, trail: Path | None) -> str:
    """How a pin names what it pinned.

    A local trail is resolved to an absolute path so running the same check
    from another directory is not mistaken for a different trail; a URL is
    kept verbatim, since normalizing it would be guessing at what the server
    considers the same endpoint.
    """
    return args_path if trail is None else str(trail.resolve())


def _report(
    log: AuditLog,
    trail: Path | None,
    *,
    check_anchors: bool,
    as_json: bool,
    pin_path: Path | None = None,
    target: str | None = None,
    chain_id: str | None = None,
    witnesses: list[str] | None = None,
    now_fn: Callable[[], datetime] = _default_now,
    declare_expect_anchor_binding: bool = False,
    declare_max_anchor_age_s: int | None = None,
    declare_topology: SeparationTopology | None = None,
) -> int:
    from waxseal.domain.report import build_report

    # One read pass for both halves: the verdict and the summary describe the
    # same bytes, and reading the trail twice to produce them made a read-only
    # command cost double on a large trail. dropped_writes stays None for the
    # same reason verify uses measure_drops=False: a CLI process observed no
    # writes, so it must report "not measured", never zero.
    result, entries = log._verify_and_entries()

    # Anchors and witnesses are measured before the pin check, same reorder
    # as _verify and for the same reason: _pin_check needs what this run
    # OBSERVED to compare against a declared_topology (waxseal-7tk.3.2).
    # build_report renders everything in one pass at the end, so, unlike
    # _verify, there is no per-check print order to preserve here.
    anchors: CheckSummary | None = None
    observed_anchor_sinks: int | None = None
    observed_anchor_records: tuple[AnchorRecord, ...] | None = None
    observed_anchor_unreadable: bool | None = None
    if check_anchors and trail is not None:
        anchors = _anchor_check(log, trail).summary
        observed_anchor_sinks = _observed_anchor_sinks(trail)
        observed_anchor_records = _observed_anchor_records(trail)
        observed_anchor_unreadable = _observed_anchor_unreadable(trail)

    witness_verdicts: tuple[WitnessVerdict, ...] | None = None
    observed_witness_consistent: bool | None = None
    if witnesses:
        witness_verdicts = tuple(_witness_verdicts(log, witnesses))
        observed_witness_consistent = _observed_witness_consistent(list(witness_verdicts))

    pin: CheckSummary | None = None
    pending_pin: PinState | None = None
    if pin_path is not None:
        assert target is not None  # main() always passes both together
        pin_check, pending_pin = _pin_check(
            log,
            pin_path,
            target=target,
            chain_id=chain_id,
            now_fn=now_fn,
            observed_anchor_sinks=observed_anchor_sinks,
            observed_witness_consistent=observed_witness_consistent,
            observed_anchor_records=observed_anchor_records,
            observed_anchor_unreadable=observed_anchor_unreadable,
            declare_expect_anchor_binding=declare_expect_anchor_binding,
            declare_max_anchor_age_s=declare_max_anchor_age_s,
            declare_topology=declare_topology,
        )
        pin = pin_check.summary
    if trail is not None:
        from waxseal.adapters.drops import read_drop_count

        count = read_drop_count(trail)
        if count is not None:
            result = replace(result, dropped_writes=count, drops_source="sidecar")

    # τ (waxseal-mfi, closing conformance.md gap G1): `None` when no --pin was
    # given, or the pin carries no declared_topology: same rule as _verify's
    # own derivation, never inferred as 0 or 1 either way.
    declared_topology = pending_pin.declared_topology if pending_pin is not None else None

    report = build_report(
        result,
        entries,
        anchors=anchors,
        pin=pin,
        witnesses=witness_verdicts,
        declared_topology=declared_topology,
    )
    if as_json:
        print(report.to_json())
    else:
        # to_markdown() already ends with a newline.
        print(report.to_markdown(), end="")

    codes = [0]
    if not result.ok:
        codes.append(1)
    elif result.unverifiable:
        codes.append(2)
    for summary in (anchors, pin):
        if summary is not None:
            codes.append(_Check(summary, "").exit_code)
    if witness_verdicts is not None:
        codes.append(_witness_exit_code(list(witness_verdicts)))
    code = _combine(codes)
    if pending_pin is not None and code != 1:
        # Same rule as _verify's write site: only exit 1 freezes the pin;
        # exit 2 advances because unverifiable is not tampered (SPEC.md
        # section 13).
        _save_pin(pin_path, pending_pin)
    return code


def _export_proof(log: AuditLog, seq: int) -> int:
    from waxseal.domain.export import build_proof_bundle, bundle_to_json

    entries = list(log.entries())
    try:
        bundle = build_proof_bundle(entries, seq)
    except IndexError as e:
        # The operator named a row that is not there. Printing some other
        # row's proof would be worse than refusing.
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(bundle_to_json(bundle))
    return 0


def _verify_proof(bundle_path: Path) -> int:
    from waxseal.domain.export import bundle_from_json, verify_proof_bundle
    from waxseal.domain.registry import VersionRegistry

    try:
        text = bundle_path.read_text(encoding="utf-8")
    except OSError as e:
        # Same spirit as a missing trail: nothing was read, nothing created.
        print(f"error: cannot read bundle: {e}", file=sys.stderr)
        return 3
    try:
        bundle = bundle_from_json(text)
    except ValueError as e:
        # Includes a bundle format this build does not know. That is a
        # refusal to parse, deliberately not a tampering verdict, since the two
        # must never be spelled the same way.
        print(f"error: cannot read bundle: {e}", file=sys.stderr)
        return 1

    result = verify_proof_bundle(bundle, VersionRegistry())
    if not result.ok:
        print(f"BROKEN at seq={bundle.header.seq}: {result.reason}")
        return 1
    if result.unverifiable:
        print(
            f"ok: seq={bundle.header.seq} is in the anchored batch "
            f"(root {bundle.root[:12]}…), but its schema fingerprint "
            f"{bundle.header.hash_version[:12]}… is unknown to this build — "
            "the entry hash could NOT be independently recomputed. "
            "Unverifiable by name, NOT evidence of tampering."
        )
        return 2
    print(
        f"ok: seq={bundle.header.seq} verified against root {bundle.root[:12]}… "
        f"(batch of {bundle.batch_size})"
    )
    return 0


def _consistency(log: AuditLog, *, old_seq: int, old_root: str) -> int:
    """Does today's trail extend the state the operator recorded earlier?

    The check a pin file makes automatically, offered here for a head that
    was recorded ANYWHERE: a ticket, a signed release, another host's copy
    of `waxseal checkpoint` output. A failed proof is evidence of a split
    view or rewritten history; which side is honest is an operator's
    decision, never this command's (CLAUDE.md rule 4).
    """
    from waxseal.domain.anchoring import batch_root, consistency_proof, verify_consistency

    # Malformed inputs are screened out BEFORE proving: verify_consistency
    # fails closed on them, and reporting an operator's typo as INCONSISTENT
    # would manufacture split-view evidence out of a slipped key.
    if old_seq < 0:
        print(
            "unverifiable: --old-seq must be a seq the trail once reached (>= 0) — "
            "nothing was checked"
        )
        return 2
    if len(old_root) != 64 or not _is_hex(old_root):
        print(
            "unverifiable: --old-root is not a 64-character hex SHA-256 root — "
            "nothing was checked"
        )
        return 2

    hashes = log.entry_hashes()
    old_size = old_seq + 1
    if old_size > len(hashes):
        # Could be a truncated trail; could be a mistyped --old-seq. From
        # here the two are indistinguishable, and a proof over entries that
        # are not there cannot be computed, so this is "cannot check",
        # stated with the ambiguity, never a tampering pronouncement.
        print(
            f"unverifiable: --old-seq {old_seq} is beyond the current head "
            f"(seq {len(hashes) - 1 if hashes else 'none — empty trail'}) — a "
            "consistency proof cannot be computed. If that seq was truly recorded, "
            "a truncation is one explanation and a mistyped --old-seq is another; "
            "this command cannot tell them apart"
        )
        return 2

    proof = consistency_proof(hashes, old_size)
    new_root = batch_root(hashes)
    if verify_consistency(old_root, old_size, new_root, len(hashes), proof):
        print(
            f"consistent: the current head (seq {len(hashes) - 1}, root "
            f"{new_root[:12]}…) extends the recorded state at seq {old_seq} "
            f"(RFC 9162 consistency proof, {len(proof)} hash(es))"
        )
        return 0
    print(
        f"INCONSISTENT at seq 0..{old_seq}: the trail's first {old_size} entries "
        f"produce root {batch_root(hashes[:old_size])[:12]}…, not the recorded "
        f"{old_root[:12]}… — evidence of a split view or rewritten history; "
        "which state is honest is an operator's decision, this command only "
        "reports that the two cannot both be the same log"
    )
    return 1


def _verify_handoff(delegate_log: AuditLog, *, origin_path: Path) -> int:
    """Check every cross-trail handoff binding recorded on ``delegate_log``
    against ``origin_path``'s current history (SPEC D3; domain/handoff.py).

    Read-only against both trails, appending nothing (CLAUDE.md's CLI
    contract: "the CLI never appends chain entries"). ``binding_holds`` is a
    pure comparison against the origin trail's OWN current entry hashes, so
    a failure here is a genuinely detected mismatch (the origin's history no
    longer matches what the binding committed to at handoff time): exit 1,
    not exit 2's "unverifiable": unlike an unknown fingerprint, there is
    nothing ambiguous left to resolve once the hashes are in hand.
    """
    import json

    from waxseal.domain.handoff import (
        HANDOFF_PAYLOAD_TYPE,
        HandoffBinding,
        binding_holds,
        from_payload,
    )

    bindings: list[tuple[int, HandoffBinding]] = []
    for entry in delegate_log.entries():
        if entry.header.payload_type != HANDOFF_PAYLOAD_TYPE:
            continue
        if entry.payload is None:
            # Header-only reader (Entry's own contract: None means "not
            # available here", matching sources/decisions.py's/files.py's
            # treatment of the same case) -- unavailable to check is a
            # third answer, never "does not hold" (rule 5).
            print(
                f"seq {entry.header.seq}: handoff-binding payload unavailable "
                "to this reader — skipped, not checked"
            )
            continue
        bindings.append((entry.header.seq, from_payload(json.loads(entry.payload))))

    if not bindings:
        print("nothing to check: no handoff-binding entries on this trail")
        return 0

    if not origin_path.exists():
        print(f"error: no such origin trail: {origin_path}", file=sys.stderr)
        return 3

    origin_hashes = AuditLog.open(origin_path).entry_hashes()

    all_hold = True
    for seq, binding in bindings:
        holds = binding_holds(binding, origin_hashes)
        print(
            f"seq {seq}: binding to chain {binding.chain_id!r} seq {binding.seq} "
            f"({binding.head_hash[:12]}…) — {'holds' if holds else 'DOES NOT HOLD'}"
        )
        if not holds:
            all_hold = False

    if all_hold:
        print(f"all {len(bindings)} handoff binding(s) hold against {origin_path}")
        return 0
    print(
        f"at least one handoff binding no longer holds against {origin_path} — "
        "the origin trail's history no longer matches what was recorded at "
        "handoff time; which side is honest is an operator's decision "
        "(CLAUDE.md rule 4)"
    )
    return 1


def _is_hex(value: str) -> bool:
    # bytes.fromhex tolerates whitespace, which a root never contains, so a
    # "root" with spaces smuggled past the length check must not reach the
    # proof as if it were well-formed.
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return " " not in value


_DECLARED_TOPOLOGY_FIELDS: Final = ("seal_escrow", "anchor_sinks", "witness", "pin_separate")


def _parse_declared_topology_spec(spec: str) -> SeparationTopology:
    """Parse ``--declare-topology``: comma-separated ``key=value`` pairs
    carrying all four ``SeparationTopology`` subfields together, e.g.
    ``"seal_escrow=true,anchor_sinks=2,witness=true,pin_separate=true"``.

    Raises ``ValueError`` on anything else, including a partial spec: SPEC
    13.1 says a partial ``declared_topology`` is ``malformed_pin``, never
    silently defaulted, and the same rule holds one layer up, at the CLI
    boundary that would otherwise have to guess the missing subfields.
    """
    fields: dict[str, str] = {}
    for raw in spec.split(","):
        token = raw.strip()
        if not token:
            continue
        key, sep, value = token.partition("=")
        if not sep:
            raise ValueError(f"expected key=value, got {token!r}")
        key = key.strip()
        if key in fields:
            raise ValueError(f"{key!r} given more than once")
        fields[key] = value.strip()

    missing = [f for f in _DECLARED_TOPOLOGY_FIELDS if f not in fields]
    if missing:
        raise ValueError(
            "declared_topology needs all four subfields together "
            f"({', '.join(_DECLARED_TOPOLOGY_FIELDS)}), missing: {', '.join(missing)}"
        )
    extra = sorted(set(fields) - set(_DECLARED_TOPOLOGY_FIELDS))
    if extra:
        raise ValueError(f"unknown declared_topology field(s): {', '.join(extra)}")

    return SeparationTopology(
        seal_escrow=_parse_bool_field("seal_escrow", fields["seal_escrow"]),
        anchor_sinks=_parse_int_field("anchor_sinks", fields["anchor_sinks"]),
        witness=_parse_bool_field("witness", fields["witness"]),
        pin_separate=_parse_bool_field("pin_separate", fields["pin_separate"]),
    )


def _parse_bool_field(name: str, value: str) -> bool:
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    raise ValueError(f"{name!r} must be 'true' or 'false', got {value!r}")


def _parse_int_field(name: str, value: str) -> int:
    try:
        return int(value.strip())
    except ValueError:
        raise ValueError(f"{name!r} must be an integer, got {value!r}") from None


def _declared_topology_arg(spec: str) -> SeparationTopology:
    """argparse ``type=`` for ``--declare-topology``: turns a malformed spec
    into a proper argparse usage error (exit 2, printed before the trail is
    ever opened) rather than a traceback or a silently-defaulted topology.
    """
    try:
        return _parse_declared_topology_spec(spec)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def _parse_issued_spec(spec: str) -> set[int]:
    """Parse ``--issued``: comma-separated non-negative ints and inclusive
    ``lo-hi`` ranges (e.g. ``"0-9,15,20-25"``). Raises ``ValueError`` on
    anything else, and the caller turns that into an unverifiable exit, never a
    guess at what the operator meant.
    """
    result: set[int] = set()
    for raw in spec.split(","):
        token = raw.strip()
        if not token:
            continue
        if "-" in token:
            lo_s, _, hi_s = token.partition("-")
            lo, hi = int(lo_s), int(hi_s)
            if hi < lo:
                raise ValueError(f"invalid range {token!r}: end before start")
            result.update(range(lo, hi + 1))
        else:
            result.add(int(token))
    return result


def _cadence(
    *, lam: float, c: float, w: float, rho: float, M: int, delta: float, t_max: float
) -> int:
    """`waxseal cadence` (C4): wires `domain/cadence.py`'s closed-form
    optimum into the CLI. Opens no trail; every input is an operator-
    supplied measurement, not a guess (`domain/cadence.py`'s own docstring
    on why `w`/`rho`/`c` have no defaults).

    Exit codes are this command's own convention, not verify's 0/1/2/3
    (there is no trail here for those to describe): 0 = a feasible cadence
    was computed, 1 = infeasible (`delta > t_max`, a labelled domain
    conclusion, not a crash: the anchor technology, not the cadence, is
    what's wrong), 2 = an invalid measurement (e.g. `w <= 0`), where nothing was
    computed, the same convention `reconcile-tickets` already uses for a
    malformed operator input.
    """
    from waxseal.domain.cadence import AnchorTechnologyInfeasible, flatness_bound, plan_cadence

    try:
        plan = plan_cadence(lam=lam, c=c, w=w, rho=rho, M=M, delta=delta, t_max=t_max)
    except AnchorTechnologyInfeasible as e:
        # Rule 6 (fail-open must be labelled) applied to a pure computation:
        # printing a clamped-anyway number here would look like an answer
        # and hide that no N can meet this window. See the module docstring
        # on `clamp_to_feasible`.
        print(f"INFEASIBLE: {e}")
        print(
            "no cadence exists that meets this detection window — the ANCHOR "
            "TECHNOLOGY, not the cadence, does not meet this requirement; use "
            "a faster anchor technology or a larger --t-max"
        )
        return 1
    except ValueError as e:
        # lam/c/w/rho <= 0 or M < 1: an invalid operator-supplied
        # measurement, reported the same way reconcile-tickets reports a
        # malformed --issued: nothing computed, never a bogus number.
        print(f"unverifiable: {e} — nothing was computed")
        return 2

    # Rule 5 / the Ternary Evidence Principle, applied here as "a band, not a
    # point": w/rho are order-of-magnitude operator estimates, so N_opt on
    # its own reads as more precise than the inputs support. flatness_bound
    # gives the concrete cost of trusting the band instead of the point: 2x
    # off costs 25% more, 3x off costs ~67% more.
    band_low = plan.n_opt / 2.0
    band_high = plan.n_opt * 2.0
    print(f"N* (unclamped optimum): {plan.n_star:.6g}")
    print(f"N_opt (clamped, feasible): {plan.n_opt:.6g}")
    print(
        f"clamp bounds [lam*delta, lam*t_max]: "
        f"[{plan.lower_bound:.6g}, {plan.upper_bound:.6g}]"
    )
    print(
        f"balance at N* (equal by construction): "
        f"anchor_term={plan.anchor_term:.6g}, exposure_term={plan.exposure_term:.6g}"
    )
    print(
        f"recommended band around N_opt (order-of-magnitude estimate, NOT a "
        f"single point): [{band_low:.6g}, {band_high:.6g}] — a cadence 2x off "
        f"costs {flatness_bound(2.0):.6g}x optimal, 3x off costs "
        f"{flatness_bound(3.0):.6g}x optimal (flatness_bound)"
    )
    return 0


def _reconcile_tickets(
    log: AuditLog, *, issuer: str, lease_size: int, issued_spec: str | None, as_json: bool
) -> int:
    """`waxseal reconcile-tickets` (D2): does the issuer's own account of
    which admission tickets it granted match what actually reached the
    trail? A missing ticket is a POSITIVELY DETECTED drop, not the measured
    minimum `verify`'s `dropped_writes` reports elsewhere. Read-only: it
    only scans entries already on the trail (CLAUDE.md's CLI contract).
    """
    import json

    from waxseal.domain.tickets import reconcile_tickets, render_reconciliation, scan_tickets

    issued: set[int] | None = None
    if issued_spec is not None:
        try:
            issued = _parse_issued_spec(issued_spec)
        except ValueError as e:
            print(f"unverifiable: --issued is malformed ({e}) — nothing was checked")
            return 2

    scan = scan_tickets(log.entries(), issuer=issuer)
    try:
        result = reconcile_tickets(present=scan.present, issued=issued, lease_size=lease_size)
    except ValueError as e:
        print(f"unverifiable: {e} — nothing was checked")
        return 2

    # An entry that claimed a ticket payload but could not be parsed is
    # neither confirmed present nor confirmed absent. It can only ever
    # weaken the verdict, via Verdict.join's severity order, never silently
    # leave a BROKEN/OK verdict looking more certain than it is.
    verdict = result.verdict.join(Verdict.UNVERIFIABLE) if scan.unreadable else result.verdict

    if as_json:
        print(
            json.dumps(
                {
                    "issuer": issuer,
                    "measured": result.measured,
                    "verdict": verdict.value,
                    "lease_size": result.lease_size,
                    "missing": list(result.missing) if result.missing is not None else None,
                    "blind_spot_window": (
                        list(result.blind_spot_window)
                        if result.blind_spot_window is not None
                        else None
                    ),
                    "blind_spot_missing": (
                        list(result.blind_spot_missing)
                        if result.blind_spot_missing is not None
                        else None
                    ),
                    "blind_spot_bound": result.blind_spot_bound,
                    "unreadable": list(scan.unreadable),
                }
            )
        )
    else:
        for line in render_reconciliation(result, scan=scan):
            print(line)

    return verdict.to_exit_code()


def _receipt_export(trail: Path, *, seq: int | None, out: Path) -> int:
    """Write each stored receipt, and the frame it attests, to files.

    waxseal refuses on principle to verify a CMS signature or an
    OpenTimestamps proof (SPEC.md sections 17/18), so `openssl ts -verify` and
    `ots verify` are the delegated verifiers, and both want FILES. Without
    this command the extraction recipe is hand-written Python against
    internal APIs, which is exactly the kind of incident-hour typing this
    CLI exists to remove.
    """
    from waxseal.adapters.anchors import read_anchor_records
    from waxseal.domain import ots, rfc3161
    from waxseal.domain.checkpoint import checkpoint_frame

    sidecar_file = trail.with_name(trail.name + ".anchors")
    if not sidecar_file.exists():
        # Same contract as a missing trail: nothing read, nothing created,
        # not even --out, so a typo'd path leaves no empty directory that
        # reads as "extraction ran and found nothing".
        print(f"error: no anchor sidecar: {sidecar_file}", file=sys.stderr)
        return 3
    try:
        sidecar = read_anchor_records(trail)
    except (ValueError, KeyError, TypeError):
        # The sidecar is this project's own format: unreadable bytes in it
        # are a break, never a foreign format (`verify --anchors` asymmetry).
        print("error: malformed_anchor — the sidecar could not be read", file=sys.stderr)
        return 1

    written = 0
    used: set[str] = set()
    for record in sidecar.records:
        rseq = record.checkpoint.seq
        if record.receipt is None or (seq is not None and rseq != seq):
            continue
        der = rfc3161.decode_receipt(record.receipt)
        if der is not None:
            payload, ext, kind = der, ".tsr", "RFC 3161 timestamp token"
        else:
            proof = ots.decode_receipt(record.receipt)
            if proof is None:
                # Skipped but never silently (CLAUDE.md rule 6): a receipt
                # type from a newer build, or bytes this build cannot
                # decode, is opaque rather than an error (RFC 6962 section 4.6).
                prefix = record.receipt.split(":", 1)[0]
                print(
                    f"seq={rseq}: receipt type {prefix!r} is not extractable by "
                    "this build — unverifiable by name, NOT evidence of tampering"
                )
                continue
            payload, ext, kind = proof, ".ots", "pending OpenTimestamps proof"

        # Duplicate records at one seq are a supported race (adapters/
        # anchors.py) but their receipts differ, and overwriting one would
        # discard evidence, so collisions get a numbered suffix.
        base, n = f"seq-{rseq}", 2
        while base in used:
            base, n = f"seq-{rseq}-{n}", n + 1
        used.add(base)
        out.mkdir(parents=True, exist_ok=True)
        receipt_path = out / (base + ext)
        receipt_path.write_bytes(payload)
        print(f"wrote {receipt_path} ({kind}, seq={rseq})")
        frame_path = out / (base + ".frame")
        frame_path.write_bytes(checkpoint_frame(record.checkpoint))
        print(f"wrote {frame_path} (checkpoint frame the receipt attests, seq={rseq})")
        written += 1

    if sidecar.unreadable_versions:
        print(
            f"note: {len(sidecar.unreadable_versions)} record(s) in an unreadable "
            "format version — unverifiable by name, NOT evidence of tampering"
        )
    if written == 0:
        # Absence, not success and not a break: no receipt means no
        # third-party evidence was stored, which is unmeasured coverage.
        print(
            "nothing to extract: no stored receipts match — absent receipts are "
            "unmeasured coverage, NOT success and NOT evidence of tampering"
        )
        return 2
    return 0


def _anchor(
    log: AuditLog,
    trail: Path,
    *,
    witnesses: list[str] | None = None,
    tsa_url: str | None = None,
    ots_calendar: str | None = None,
) -> int:
    import json

    from waxseal.adapters.anchors import MultiAnchorSink
    from waxseal.adapters.attest import AggregateReader

    # Read-only: binding the accumulator into the checkpoint needs the bytes
    # on disk, not the seal key the CLI deliberately never holds. Anchoring a
    # sealed trail without the binding would publish a chain shape nothing
    # ties back to the seals.
    sink = _anchor_sink(trail, tsa_url=tsa_url, ots_calendar=ots_calendar)
    anchored = log.with_anchor_sink(sink, aggregate_source=AggregateReader(trail))
    try:
        cp = anchored.anchor()
    except ValueError as e:
        # Both sources ("no anchor_sink", "cannot anchor an empty trail") name
        # something the operator can act on. A bare non-zero exit does not.
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (OSError, RuntimeError) as e:
        # An external sink that could not publish. RecordingAnchorSink wrote
        # nothing, so the sidecar still says what it said before, and an operator
        # who sees this must not believe a third party holds this checkpoint.
        # With two independent sinks configured this only fires when BOTH
        # failed (MultiAnchorSink's own contract): if either one held, the
        # loop below reports it instead of this all-or-nothing message.
        print(f"error: external anchor failed, nothing recorded: {e}", file=sys.stderr)
        return 1
    record: dict[str, object] = {"seq": cp.seq, "entry_hash": cp.entry_hash, "root": cp.root}
    if cp.agg_commit is not None:
        record["agg_commit"] = cp.agg_commit
        record["agg_epoch"] = cp.agg_epoch
    print(json.dumps(record))

    # waxseal-4yk: --tsa-url and --ots-calendar publish the SAME checkpoint to
    # two independent domains now (tau rises by one per domain reached, per
    # the anchor-selection corollary). One sink being unreachable must not
        # cost the other its record (CLAUDE.md rule 6): MultiAnchorSink already
    # let the reachable sink's record land; this only has to label the one
    # that didn't, in the same "error: ... nothing recorded" wording the
    # single-sink path above uses for a total failure.
    failed = False
    if isinstance(sink, MultiAnchorSink):
        for name, reason in sink.failures:
            print(
                f"error: external anchor failed, nothing recorded for {name}: {reason}",
                file=sys.stderr,
            )
            failed = True

    if not witnesses:
        return 1 if failed else 0
    witness_rc = _publish_to_witnesses(cp, witnesses)
    return 1 if (failed or witness_rc) else 0


def _anchor_sink(trail: Path, *, tsa_url: str | None, ots_calendar: str | None) -> object:
    """The sink `anchor` publishes through.

    With no external target this stays the local sidecar it has always been.
    a queue and a local cross-check, explicitly not an independent witness
    (adapters/anchors.py says so). With one, the sidecar becomes the filing
    cabinet for a receipt somebody else issued, which is the only version of
    this that survives an attacker holding the disk. With both (waxseal-4yk),
    a ``MultiAnchorSink`` fans the SAME checkpoint (computed once by
    ``AuditLog.anchor()``) out to both independently-recording sinks, so one
    run reaches two independent trust domains instead of requiring two runs.
    """
    from waxseal.adapters.anchors import FileAnchorSink, MultiAnchorSink, RecordingAnchorSink

    sinks: list[object] = []
    if tsa_url is not None:
        from waxseal.adapters.rfc3161 import Rfc3161AnchorSink

        sinks.append(RecordingAnchorSink(trail, Rfc3161AnchorSink(tsa_url)))
    if ots_calendar is not None:
        from waxseal.adapters.ots import OtsAnchorSink

        sinks.append(RecordingAnchorSink(trail, OtsAnchorSink(ots_calendar)))
    if len(sinks) == 2:
        return MultiAnchorSink(sinks)
    if sinks:
        return sinks[0]
    return FileAnchorSink(trail)


def _publish_to_witnesses(cp: Checkpoint, urls: list[str]) -> int:
    """Publish one checkpoint to every configured witness.

    A failed publish exits 1. Unlike automatic anchoring, which is
    best-effort because it must never break an append, this was asked for
    explicitly, and an operator who ran `anchor --witness` and got exit 0 is
    entitled to believe the witness has it.
    """
    from waxseal.adapters.remote import RemoteError
    from waxseal.adapters.witness import HTTPWitness

    failed = False
    for url in urls:
        witness = HTTPWitness(url, api_key=_witness_api_key())
        try:
            receipt = witness.anchor(cp)
        except (OSError, RemoteError, RuntimeError) as e:
            # stdout like every other verdict this CLI prints: an operator
            # piping the output to a log must not lose the one line saying
            # the checkpoint never left the machine.
            print(f"WITNESS PUBLISH FAILED {witness.name}: {e}")
            failed = True
            continue
        suffix = f" (receipt {receipt})" if receipt is not None else " (no receipt given)"
        print(f"published to witness {witness.name}{suffix}")
    return 1 if failed else 0


def _tail(log: AuditLog, n: int) -> int:
    # A bounded deque, not list(log.entries())[-n:]: the slice discarded
    # everything but the last n rows AFTER holding the whole decoded trail in
    # memory at once, so a read-only command's peak allocation grew with the
    # trail it was only printing the end of. Output is byte-identical.
    window: deque[Entry] = deque(maxlen=n)
    for entry in log.entries():
        window.append(entry)
    for entry in window:
        h = entry.header
        print(f"seq={h.seq} ts={h.ts} type={h.payload_type} hash={entry.entry_hash[:12]}")
    return 0


def _head(log: AuditLog) -> int:
    # Anchor this output externally (OpenTimestamps, RFC 3161 TSA, a pushed
    # git commit): a rewritten suffix cannot rewrite an already-anchored head.
    import json

    last = None
    for last in log.entries():  # noqa: B007 - want the final element
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

    hashes = log.entry_hashes()
    if not hashes:
        return 1
    cp = checkpoint_for(hashes)
    print(json.dumps({"seq": cp.seq, "entry_hash": cp.entry_hash, "root": cp.root}))
    return 0


def _inspect(log: AuditLog, trail: Path | None) -> int:
    total = 0
    by_fingerprint: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    for entry in log.entries():
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
