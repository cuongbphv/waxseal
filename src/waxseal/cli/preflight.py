from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from waxseal.cli._anchors import _tau_line
from waxseal.domain.preflight import (
    Observed,
    PreflightObservation,
    ladder_for,
    render_ladder,
)
from waxseal.domain.separation import (
    SeparationTopology,
)
from waxseal.log import AuditLog

_PREFLIGHT_SCOPE: Final = (
    "scope: this is a reading of CONFIGURATION, and not a verdict — nothing "
    "here says the trail verifies, or that any mechanism named PRESENT "
    "currently checks out. Run `waxseal verify <trail>` for that."
)

_PREFLIGHT_DOMAINS: Final = (
    "  distinct administrative domains: NOT MEASURED — an `.anchors` record "
    "names the sink TECHNOLOGY that wrote it (`rfc3161`, `ots`, `http`), "
    "never who OPERATES it, so two records may be one authority or two. The "
    "operator's own count is a pin's declared_topology.anchor_sinks "
    "(declared, not measured)."
)

_PREFLIGHT_PIN_NOT_A_RUNG: Final = (
    "  (the pin is not a stopper on this ladder: threat-model.md section 5 "
    "names seals, anchors, an external anchor and the SPEC 15 binding. The "
    "pin is section 4's table, and τ below.)"
)

_PREFLIGHT_WITNESS: Final = (
    "preflight contacts no witness: it opens no network connection at all, "
    "so a witness is never ABSENT here, only unmeasured; "
    "`waxseal verify --witness URL` is what checks one (SPEC 14)"
)

_PREFLIGHT_LEDGER: Final = (
    "preflight contacts no ledger: it opens no network connection at all, "
    "so a ledger is never ABSENT here, only unmeasured; "
    "`waxseal verify --rpc URL --liveness ADDR` is what checks one (F4)"
)

_PREFLIGHT_PREFIX_MECHANISM: Final = (
    "DESIGN.md §11 names exactly two mechanisms that raise a prefix from "
    "evidence to scoped proof — a finalized external ledger anchor (0.1.5 "
    "Workstream F) or a WORM-locked archived segment (S3 Object Lock, "
    "Workstream J1) — and preflight confirms neither: it opens no network "
    "connection and holds no storage credentials"
)


def _declared_bool(value: bool) -> str:
    # "true"/"false" rather than Python's True/False: this line sits beside
    # `--declare-topology`'s own spec grammar, and an operator copying a value
    # out of one into the other must not have to translate it.
    return "true" if value else "false"


def _observed_label(observed: Observed) -> str:
    """PRESENT / ABSENT / NOT MEASURED for one observation, worded once.

    Three states where a reader expects two, per CLAUDE.md rule 5: `None`
    means this run did not look, which is neither of the other two and must
    never be rendered as either.
    """
    if observed.found is None:
        return "NOT MEASURED"
    return "PRESENT" if observed.found else "ABSENT"


@dataclass(frozen=True, slots=True)
class _AnchorView:
    """What the `.anchors` sidecar shows a preflight run, as the ternary
    observations the ladder consumes plus the lines that report them.

    ``latest_seq`` is ``None`` for two different reasons — no anchor record
    exists, or the sidecar could not be read — and J4's immutable-prefix
    lines (below) tell those apart from ``records.found`` rather than
    guessing a checkpoint from an absent number.
    """

    lines: tuple[str, ...]
    records: Observed
    external: Observed
    aggregate: Observed
    latest_seq: int | None


def _preflight_anchors(trail: Path) -> _AnchorView:
    """Read the `.anchors` sidecar for what rungs 2, 3 and 4 name.

    A sidecar this build cannot parse makes ALL THREE unmeasured, never zero.
    This is the single easiest place in this command to lie by omission: a
    file that would not read might have carried anything, and "0 external
    sinks" is a measurement nobody took. Same conservative treatment
    `_observed_anchor_unreadable` already gives the same failure.
    """

    from waxseal.adapters.anchors import read_anchor_records

    name = trail.name + ".anchors"
    try:
        sidecar = read_anchor_records(trail)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        unparsed = Observed(
            None,
            f"{name} is present but this build could not parse it — NOT zero "
            "records (`waxseal verify --anchors` reports the parse failure "
            "itself)",
        )
        return _AnchorView(
            lines=(
                f"  anchor sidecar (SPEC 9): NOT MEASURED — {unparsed.detail}",
                f"  external anchor sinks: NOT MEASURED — {unparsed.detail}",
                _PREFLIGHT_DOMAINS,
                f"  aggregate binding (SPEC 15): NOT MEASURED — {unparsed.detail}",
            ),
            records=unparsed,
            external=unparsed,
            aggregate=unparsed,
            latest_seq=None,
        )

    unreadable = Observed(
        None,
        f"{len(sidecar.unreadable_versions)} record(s) in {name} are in a "
        f"format version this build cannot read "
        f"({', '.join(sorted(set(sidecar.unreadable_versions)))}) — "
        "unverifiable by name, NOT evidence of tampering, and NOT zero",
    )
    records = sidecar.records
    sinks: tuple[str, ...] | None = tuple(
        sorted({r.sink for r in records if r.sink != "file"})
    )
    bound = tuple(r for r in records if r.checkpoint.agg_commit is not None)

    if records:
        anchor_records = Observed(
            True,
            f"{len(records)} record(s) in {name}, latest at seq "
            f"{records[-1].checkpoint.seq}",
        )
    elif sidecar.unreadable_versions:
        anchor_records = unreadable
    else:
        anchor_records = Observed(False, f"no anchor record found in {name}")

    if sinks:
        external = Observed(
            True,
            f"{name} names {', '.join(sinks)} (the local `file` sink is "
            "excluded: a trail anchored only to its own disk is not separated "
            "from a writer who holds that disk)",
        )
    elif sidecar.unreadable_versions:
        external, sinks = unreadable, None
    else:
        external = Observed(
            False, f"no record in {name} names a sink other than `file`"
        )

    if bound:
        aggregate = Observed(
            True,
            f"{len(bound)} record(s) in {name} carry `agg_commit` — present, "
            "and NOT checked here: the CLI holds no seal key (use "
            "AuditLog.verify_anchored_aggregates)",
        )
    elif sidecar.unreadable_versions:
        aggregate = unreadable
    else:
        aggregate = Observed(False, f"no record in {name} carries `agg_commit`")

    count = "NOT MEASURED" if sinks is None else f"{len(sinks)} observed"
    return _AnchorView(
        lines=(
            f"  anchor sidecar (SPEC 9): {_observed_label(anchor_records)} — "
            f"{anchor_records.detail}",
            f"  external anchor sinks: {count} — {external.detail}",
            _PREFLIGHT_DOMAINS,
            f"  aggregate binding (SPEC 15): {_observed_label(aggregate)} — "
            f"{aggregate.detail}",
        ),
        records=anchor_records,
        external=external,
        aggregate=aggregate,
        latest_seq=records[-1].checkpoint.seq if records else None,
    )


def _preflight_immutable_prefix_lines(anchors: _AnchorView) -> tuple[str, str]:
    """J4 (waxseal-p8s): the prefix/tail split threat-model.md section 1 and
    DESIGN.md §11 both name, printed as trailing lines rather than folded
    into the ladder above it. Deliberately not a rung: the ladder's PRESENT
    means a mechanism is CONFIGURED (`domain/preflight.py`'s own docstring),
    never that a ledger anchor is finalized or a segment is WORM-locked —
    claims this command can never make, ladder or no ladder, because it
    opens no network connection and holds no storage credentials.
    """
    if anchors.latest_seq is not None:
        checkpoint = f"seq {anchors.latest_seq}"
        tail = f"seq {anchors.latest_seq} onward"
    elif anchors.records.found is None:
        checkpoint = "UNMEASURED (the .anchors sidecar could not be read)"
        tail = "the whole trail — no checkpoint could be read"
    else:
        checkpoint = "NONE (no anchor record on this trail)"
        tail = "the whole trail — nothing is anchored"
    prefix_line = (
        f"immutable prefix: up to checkpoint {checkpoint}, mechanism NOT "
        f"CONFIRMED this run (finalized ledger / WORM / none) — "
        f"{_PREFLIGHT_PREFIX_MECHANISM}"
    )
    tail_line = (
        f"tail from {tail}: tamper-evident only, never more — the live tail "
        "and write-time honesty are limits DESIGN.md §11 says no mechanism "
        "closes"
    )
    return prefix_line, tail_line


@dataclass(frozen=True, slots=True)
class _PinView:
    """The pin state's own lines, plus the topology it declared (or None).

    The topology travels separately because two later lines need it — τ, and
    "pin on separate storage" — and re-deriving it from a rendered string is
    how two surfaces start disagreeing about one fact.
    """

    lines: tuple[str, ...]
    topology: SeparationTopology | None


def _preflight_pin(pin_path: Path | None) -> _PinView:
    """Re-present what the pin state file declares. Never writes it.

    Every failure to read one is a labelled non-measurement, never a verdict
    (CLAUDE.md rule 6, and rule 4: reporting is this command's whole job).
    `verify --pin` is what turns a malformed state into a break; saying so
    here keeps one finding in one place instead of two that could drift.
    """
    if pin_path is None:
        return _PinView(
            lines=(
                "  pin state: NOT READ — no --pin given, so this run saw no "
                "declaration at all, which is not the same as a pin that "
                "declares nothing",
            ),
            topology=None,
        )

    from waxseal.adapters.pinstore import FilePinStore
    from waxseal.domain.pinning import PinMalformed, PinVersionUnknown

    try:
        stored = FilePinStore(pin_path).load()
    except PinVersionUnknown as e:
        return _PinView(
            lines=(
                f"  pin state: NOT READ — pin_version_unknown ({e}): a state "
                "file from a newer waxseal, unverifiable BY NAME and NOT "
                "evidence of tampering",
            ),
            topology=None,
        )
    except PinMalformed as e:
        return _PinView(
            lines=(
                f"  pin state: NOT READ — malformed_pin ({e}). Labelled, never "
                "swallowed (rule 6); `waxseal verify --pin` is what reports it "
                "as a break, preflight reports no verdict",
            ),
            topology=None,
        )

    if stored is None:
        return _PinView(
            lines=(
                f"  pin state: {pin_path} — no pin recorded yet (trust not "
                "established); NOT a declaration that nothing is separated",
            ),
            topology=None,
        )

    age = (
        "not declared"
        if stored.max_anchor_age_s is None
        else str(stored.max_anchor_age_s)
    )
    return _PinView(
        lines=(
            f"  pin state: {pin_path} — target={stored.target}, pinned seq="
            f"{stored.checkpoint.seq} at {stored.pinned_ts}",
            "  pin declarations (declared, not measured — an operator's claim "
            "about who holds what, which no run can corroborate from a trail):",
            f"    expect_anchor_binding: "
            f"{_declared_bool(stored.expect_anchor_binding)}",
            f"    max_anchor_age_s: {age}",
            f"    declared_topology: "
            f"{_render_declared_topology(stored.declared_topology)}",
        ),
        topology=stored.declared_topology,
    )


def _render_declared_topology(topology: SeparationTopology | None) -> str:
    if topology is None:
        # Never "seal_escrow=false, anchor_sinks=0, ...": that reads as a
        # measured floor, and it is the absence of a declaration.
        return "not declared"
    return (
        f"seal_escrow={_declared_bool(topology.seal_escrow)}, "
        f"anchor_sinks={topology.anchor_sinks}, "
        f"witness={_declared_bool(topology.witness)}, "
        f"pin_separate={_declared_bool(topology.pin_separate)}"
    )


def _preflight_trail_line(trail: Path) -> str:
    """How much of the trail this run could actually read.

    A trail whose lines will not parse is reported as NOT READ rather than
    raising: an information command must print a state for a torn file, not a
    traceback (`_read_segment` takes the same position for the same reason).
    """
    try:
        hashes = AuditLog.open(str(trail)).entry_hashes()
    except (ValueError, KeyError, TypeError, OSError):
        return (
            f"trail: {trail} — entries: NOT READ: this build could not read "
            "this trail's lines; `waxseal verify` reports what is wrong with "
            "them"
        )
    if not hashes:
        return f"trail: {trail} — 0 recorded entries, no head yet"
    return (
        f"trail: {trail} — {len(hashes)} recorded entries, "
        f"head seq={len(hashes) - 1}"
    )


def _preflight_segment_lines(trail: Path) -> tuple[str, ...]:
    """Whether this trail is one segment of several, and what that does to
    every rung below it.

    Decided here rather than ignored: sidecars are PER SEGMENT (SPEC 20.1),
    so a rung claim covering a whole directory would be an aggregate this
    command never measured — and reporting the best-configured segment's
    rung as the trail's would be exactly the collapse rule 5 forbids. So
    preflight reports the segment it was pointed at, says so, and names
    `waxseal segments` for the directory-wide walk it does not do.
    """
    from waxseal.domain.segments import SEGMENT_SUFFIX, segment_identity, segment_ordinal
    from waxseal.sources.rotation import discover_segments

    identity = segment_identity(trail.name)
    head = identity.rpartition(".")[0]
    # The same stem rule `sources/rotation.py` uses internally, spelled with
    # the public domain helpers rather than importing its private one.
    stem = head if head and segment_ordinal(trail.name, head) is not None else identity
    group = [
        path
        for path in discover_segments(trail.parent)
        if path.name == stem + SEGMENT_SUFFIX
        or segment_ordinal(path.name, stem) is not None
    ]
    if not group:
        return (
            f'segments: not rotated — no numbered segment of "{stem}" in '
            f"{trail.parent} (SPEC 20), so everything below describes this "
            "one file.",
        )
    names = [path.name for path in group]
    return (
        f"segments: this trail is segment {names.index(trail.name) + 1} of "
        f"{len(group)} ({identity}) under {trail.parent} — SPEC 20.",
        "  Every segment carries its OWN sidecars (SPEC 20.1), so every rung "
        "below describes THIS segment only, never the directory. `waxseal "
        "segments <dir>` walks all of them and the rotation bindings between "
        "them.",
    )


def _preflight(path: str, *, pin_path: Path | None) -> int:
    """`waxseal preflight <trail>` (Workstream E): which rung of
    docs/security/threat-model.md section 5's attacker-capability ladder this
    configuration stops, in that table's own language.

    Read-only and writes nothing at all — not even the two verifier-state
    carve-outs the CLI contract allows (`--pin` here only READS).

    Exit 0 always, because this is an information command and not a verdict:
    a configuration that stops nobody is still a successful reading, and
    spending exit 1 or 2 on it would create a second verdict source an
    operator would then have to reconcile against `verify`. The one exception
    is 3, "nothing was read", for a trail path that does not exist.

    Every fact here is re-presented from what already computes it —
    `adapters/anchors.py`'s records, `domain/pinning.py`'s state,
    `domain/separation.py`'s τ — and nothing is recomputed for a second
    opinion.
    """
    if path.startswith(("http://", "https://")):
        # Local-sidecar-only, the same limit `verify-handoff --origin`
        # carries: a remote trail has no `.anchors`/`.attest` location at all,
        # so there is nothing here to read rather than something that failed.
        print(
            "error: preflight reads local sidecars; no URL/remote support "
            f"(local trail path only): {path}",
            file=sys.stderr,
        )
        return 3
    trail = Path(path).expanduser()
    if not trail.exists():
        print(f"error: no such trail: {trail}", file=sys.stderr)
        return 3

    anchors = _preflight_anchors(trail)
    pin = _preflight_pin(pin_path)

    attest = trail.with_name(trail.name + ".attest")
    seal = (
        Observed(True, f"{attest.name} present beside this trail (SPEC 11)")
        if attest.exists()
        else Observed(
            False,
            f"no {attest.name} beside this trail (SPEC 11's own path; an "
            "attestor that stores seals elsewhere is not visible to this "
            "command)",
        )
    )
    witness_detail = _PREFLIGHT_WITNESS
    if pin.topology is not None and pin.topology.witness:
        # A declaration is a weaker claim than a measurement, and printing the
        # two alike is the collapse this repository exists to prevent — so it
        # rides along in the SAME line that says the rung was not measured,
        # never as a second line that could be quoted on its own.
        witness_detail += "; this pin DECLARES witness=true (declared, not measured)"
    witness = Observed(None, witness_detail)

    # ledger (waxseal-fg4.45): same shape as witness immediately above, for
    # the same reason — preflight opens no network connection, so this is
    # NOT_MEASURED unconditionally, with a declared-but-not-measured pin
    # topology riding along in the same line rather than a second one.
    ledger_detail = _PREFLIGHT_LEDGER
    if pin.topology is not None and pin.topology.ledger:
        ledger_detail += "; this pin DECLARES ledger=true (declared, not measured)"
    ledger = Observed(None, ledger_detail)

    print(f"preflight: {trail}")
    print(_preflight_trail_line(trail))
    for line in _preflight_segment_lines(trail):
        print(line)
    print()
    print(
        "observed configuration (PRESENT means the mechanism is CONFIGURED, "
        "not that it currently checks out)"
    )
    print(f"  seal (SPEC 11): {_observed_label(seal)} — {seal.detail}")
    for line in anchors.lines:
        print(line)
    print(f"  witness (SPEC 14): {_observed_label(witness)} — {witness.detail}")
    print(f"  ledger (F4): {_observed_label(ledger)} — {ledger.detail}")
    for line in pin.lines:
        print(line)
    print(_preflight_separate_storage_line(pin.topology))
    print(_PREFLIGHT_PIN_NOT_A_RUNG)
    print(_tau_line(pin.topology))
    print()
    for line in render_ladder(
        ladder_for(
            PreflightObservation(
                seal=seal,
                anchor_records=anchors.records,
                external_anchor=anchors.external,
                aggregate_binding=anchors.aggregate,
                witness=witness,
                ledger=ledger,
            )
        )
    ):
        print(line)
    # J4 (waxseal-p8s): the prefix/tail split, qualifying the ladder's PRESENT
    # ("configured") rather than adding a rung — see
    # `_preflight_immutable_prefix_lines`'s own docstring for why this reads
    # from `anchors` alone and never opens the network/S3 connection a real
    # ledger-finality or WORM-lock check would need.
    print()
    for line in _preflight_immutable_prefix_lines(anchors):
        print(line)
    print()
    print(_PREFLIGHT_SCOPE)
    return 0


def _preflight_separate_storage_line(topology: SeparationTopology | None) -> str:
    """Where the pin file lives is DECLARED and never measured.

    `separation_shortfall` already refuses to compare against `pin_separate`
    for this reason: nothing in a trail or its sidecars can corroborate or
    contradict it, so a run that printed it as a finding would be inventing
    evidence it never had.
    """
    if topology is None:
        return (
            "  pin on separate storage: NOT DECLARED — a declaration only; "
            "nothing in a trail or its sidecars can corroborate where the pin "
            "file lives (domain/separation.py)"
        )
    return (
        f"  pin on separate storage: DECLARED "
        f"{_declared_bool(topology.pin_separate)} — declared, not measured; "
        "no run can corroborate it (domain/separation.py)"
    )
