from __future__ import annotations

import argparse
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Final

from waxseal.adapters.anchors import AnchorRecord
from waxseal.cli._common import _Check, _default_now
from waxseal.domain.pinning import PinState
from waxseal.domain.report import (
    CheckSummary,
)
from waxseal.domain.separation import (
    SeparationTopology,
    ledger_shortfall,
    separation_shortfall,
)
from waxseal.log import AuditLog


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
    observed_ledger_ok: bool | None = None,
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

    ``observed_ledger_ok`` (waxseal-fg4.45) is the ledger dimension's own
    "what THIS run measured" value, the same shape as
    ``observed_witness_consistent`` and gated the same way at the call site:
    ``None`` means this run passed neither ``--rpc``/``--liveness`` nor
    ``--registry``, so the ledger comparison below is skipped entirely, not
    treated as "ledger not corroborated". ``True`` only when
    ``_ledger_check``'s verdict was ``Verdict.OK`` this run — delinquent,
    disagreeing, AND unreachable all fold to ``False`` here, the same
    precedent ``_observed_witness_consistent`` already sets for an
    unreachable-vs-inconsistent witness: neither is a ledger this run
    actually confirmed agreement with.

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

    # The pin matches, but four more declared-vs-observed comparisons can
    # still turn this into an exit-2 finding. Checked in this fixed order,
    # anchor_policy_downgrade FIRST, then anchor_staleness, then
    # ledger_shortfall (waxseal-fg4.45), then separation_shortfall, and
    # documented here because all four land on _Check/CheckSummary, which
    # carries only one `reason`: when a run happens to trip more than one at
    # once, this ordering decides which single reason string surfaces. Not
    # security-critical among the four (every outcome here is exit
    # 2/unverifiable either way), just a tiebreak, but anchor_policy_downgrade
    # goes first because it is the direct F2 finding (SPEC §15
    # replay-plus-truncate protection silently stripped) this release's own
    # analysis singles out as the most consequential exit-2 case.
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

    # ledger_shortfall (waxseal-fg4.45): only compared when a ledger
    # authority was actually declared AND this run actually checked it via
    # --rpc/--liveness/--registry: `None` means "not measured this run",
    # never "not corroborated" (rule 5) — the same shape anchor_staleness
    # above uses for its own not-measured-this-run case, and the reason
    # `ledger_shortfall`/`separation_shortfall` are gated independently
    # (`domain/separation.py`'s docstring on why they are sibling functions,
    # not one function with a third parameter).
    if (
        stored.declared_topology is not None
        and observed_ledger_ok is not None
        and ledger_shortfall(stored.declared_topology, observed_ledger_ok=observed_ledger_ok)
    ):
        # Exit 2, never exit 1: a shortfall is "we observed less than
        # declared": an absence of corroborating evidence for the declared
        # ledger authority, not evidence the trail itself was tampered with.
        return (
            _Check(
                CheckSummary(ok=True, checked=stored.checkpoint.seq + 1,
                             reason="ledger_shortfall", unverifiable=True),
                f"pin ok but ledger_shortfall: declared ledger=true, this run "
                f"observed ledger_ok={observed_ledger_ok} — NOT evidence of "
                "tampering, the trail itself still verifies",
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


_DECLARED_TOPOLOGY_FIELDS: Final = ("seal_escrow", "anchor_sinks", "witness", "pin_separate")

# `ledger` (waxseal-fg4.45's SeparationTopology.ledger, bool | None) is
# deliberately NOT in _DECLARED_TOPOLOGY_FIELDS above: that tuple is the
# required-together set the "missing" check walks, and every pin file (and
# every CLI invocation) written before this field existed omits it and must
# keep parsing unchanged. It gets its own optional slot instead, the same
# "fifth field, never required" shape domain/pinning.py's
# `_optional_bool_or_none` already gives it on the JSON side.
_DECLARED_TOPOLOGY_OPTIONAL_FIELD: Final = "ledger"


def _parse_declared_topology_spec(spec: str) -> SeparationTopology:
    """Parse ``--declare-topology``: comma-separated ``key=value`` pairs
    carrying all four ``SeparationTopology`` subfields together, e.g.
    ``"seal_escrow=true,anchor_sinks=2,witness=true,pin_separate=true"``,
    plus an OPTIONAL fifth ``ledger=true``/``ledger=false`` (waxseal-fg4.45's
    ``SeparationTopology.ledger``, one more independent authority to declare).

    ``ledger`` is never part of the required-together set: omitting it parses
    exactly as it did before this subfield existed (``ledger=None``, "never
    declared"), so every pre-fg4.45 spec string and every existing automation
    around this flag keeps working unchanged (rule 5 — ``None`` is not the
    same claim as a declared-false ledger).

    Raises ``ValueError`` on anything else, including a partial spec over the
    four required subfields: SPEC 13.1 says a partial ``declared_topology``
    is ``malformed_pin``, never silently defaulted, and the same rule holds
    one layer up, at the CLI boundary that would otherwise have to guess the
    missing subfields. A malformed ``ledger`` value is rejected the same way
    (``_parse_bool_field``'s "must be 'true' or 'false'" message) — being
    optional changes only whether it must be present, never how a value
    given for it is validated.
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
    allowed = {*_DECLARED_TOPOLOGY_FIELDS, _DECLARED_TOPOLOGY_OPTIONAL_FIELD}
    extra = sorted(set(fields) - allowed)
    if extra:
        raise ValueError(f"unknown declared_topology field(s): {', '.join(extra)}")

    ledger_raw = fields.get(_DECLARED_TOPOLOGY_OPTIONAL_FIELD)
    ledger = (
        _parse_bool_field(_DECLARED_TOPOLOGY_OPTIONAL_FIELD, ledger_raw)
        if ledger_raw is not None
        else None
    )

    return SeparationTopology(
        seal_escrow=_parse_bool_field("seal_escrow", fields["seal_escrow"]),
        anchor_sinks=_parse_int_field("anchor_sinks", fields["anchor_sinks"]),
        witness=_parse_bool_field("witness", fields["witness"]),
        pin_separate=_parse_bool_field("pin_separate", fields["pin_separate"]),
        ledger=ledger,
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
