"""Evaluation protocol item 8, the schema-evolution experiment (waxseal-4t1).

The paper calls this the centrepiece: "write under schema A, evolve to B, roll
the binary back, and compare three verifier designs on identical data. The
ordinal design refuses to run, the recompute-under-current design reports mass
tampering, and the fingerprint design reports intact rows intact and unknown
rows unverifiable. This is the smallest experiment that separates the failure
class." It was the last item of the eight-item protocol with no executable form
here. The other three unbuilt paper items need an on-chain component and are
tracked separately.

The two rolled-back designs below are CLAUDE.md's two founding incidents:

  * "migration 060": the hashed field set was widened without a version
    identity, so historical rows were recomputed under a tuple they had never
    been signed with, and every one of them failed. Design 2 below is that
    verifier. The direction is mirrored here, because the paper prescribes
    rolling the binary BACK, so it is the new rows that fail rather than the old
    ones. The failure class is the same either way: a row recomputed under a
    field tuple it was not signed with.
  * "beads v1.2.2": an accidental release migrated schema v53 to v65, and the
    reverted binary treated the unknown ordinal as a fatal error. Design 1 below
    is that verifier, including its one escape hatch, BD_IGNORE_SCHEMA_SKEW=1,
    which disabled safety entirely.

A word on "identical data", because an experiment whose identical-data claim is
quietly false proves nothing. Designs 2 and 3 run on literally the same
`list[Entry]` object. Design 1 cannot, since an ordinal version stamp is the
design variable itself, so it reads an ordinal *view* of that same chain
(`_ordinal_view`) derived from it row for row. Payloads, sequence numbers and
prev_hash links are the same in every run.

The control (`_schema_b_aware_verify`) is not one of the paper's three designs.
It models the binary as it stood BEFORE the rollback, one that knows schema B's
field set and owns a frame function for it, and it verifies all seven rows.
Without that reference point, "design 2 reports broken" would not yet be
evidence of a FALSE alarm, since it could just as well mean the data is bad. The
control is what establishes that the trail is genuinely intact, which in turn is
what makes the other two verdicts provably manufactured rather than detected.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace

from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint, fingerprint_for
from waxseal.domain.hashing import (
    FRAME_PREFIX,
    compute_entry_hash,
    compute_payload_hash,
    header_frame,
    lp,
)
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.verify import verify_chain

# --- The evolution: schema A (shipped) widened to schema B -----------------
#
# B adds one field. Under waxseal that is all it takes for the fingerprint to
# change automatically. That is the mechanism under test, so the experiment must
# not help it along by stamping anything by hand.

FIELDS_A = HEADER_FIELDS
FIELDS_B = (*HEADER_FIELDS, "actor")

FP_A = fingerprint()
FP_B = fingerprint_for(FIELDS_B)

N_A = 4  # rows written before the evolution (seq 0..3)
M_B = 3  # rows written after it (seq 4..6)

# The ordinal design's stamps for the same two schemas. Two integers, and the
# rolled-back binary ships knowing only the first.
ORDINAL_A = 1
ORDINAL_B = 2
ROLLED_BACK_MAX_KNOWN_ORDINAL = ORDINAL_A


def _frame_b(header: EntryHeader, actor: str) -> bytes:
    """Schema B's header frame: lp64 over seven fields instead of six.

    This is a legitimate future encoder rather than a mutation. The field count
    sits inside the frame, so a 7-field frame can never be confused with a
    6-field one even before the fingerprint is consulted. `domain/hashing.py`
    deliberately implements one encoding and only one, so this lives in the test
    instead: schema B is a hypothetical future build's shape, not this build's.
    """
    return (
        FRAME_PREFIX
        + struct.pack(">Q", 7)
        + lp(str(header.seq))
        + lp(header.ts)
        + lp(header.hash_version)
        + lp(header.payload_type)
        + lp(header.payload_hash)
        + lp(header.prev_hash)
        + lp(actor)
    )


def _build_evolved_trail() -> tuple[list[Entry], dict[int, str]]:
    """One trail spanning the evolution: N_A rows under A, then M_B under B.

    Every row is genuine. The B rows carry the entry_hash a schema-B writer
    really would have produced (over `_frame_b`) rather than a placeholder. If
    they carried a made-up hash, "design 2 reports them broken" would be true
    for the boring reason, and the experiment would prove nothing.

    Returns the chain and the out-of-band `actor` values, which have nowhere to
    live on a six-slot `EntryHeader`. That absence is itself faithful: a
    rolled-back binary genuinely cannot see schema B's extra field.
    """
    entries: list[Entry] = []
    actors: dict[int, str] = {}
    prev = GENESIS_PREV_HASH
    for i in range(N_A + M_B):
        payload = f'{{"i":{i}}}'.encode()
        under_b = i >= N_A
        header = EntryHeader(
            seq=i,
            ts=f"2026-08-30T09:00:{i:02d}+00:00",
            hash_version=FP_B if under_b else FP_A,
            payload_type="application/vnd.test.event+json",
            payload_hash=compute_payload_hash(payload),
            prev_hash=prev,
        )
        if under_b:
            actor = f"agent-{i}"
            actors[i] = actor
            entry_hash = hashlib.sha256(_frame_b(header, actor)).hexdigest()
        else:
            entry_hash = compute_entry_hash(header, frame=header_frame)
        entries.append(Entry(header=header, entry_hash=entry_hash, payload=payload))
        prev = entry_hash
    return entries, actors


def _ordinal_view(entries: Sequence[Entry]) -> tuple[tuple[int, int], ...]:
    """The same chain as the ordinal design would have stamped it: (seq, int).

    Derived row-for-row from `entries` so the two designs are compared on one
    trail and not on two trails that merely resemble each other.
    """
    return tuple(
        (e.header.seq, ORDINAL_B if e.header.hash_version == FP_B else ORDINAL_A) for e in entries
    )


# --- What a verifier design is allowed to say ------------------------------


@dataclass(frozen=True, slots=True)
class DesignVerdict:
    design: str
    rows_verified: int
    broken: tuple[tuple[int, str], ...]
    refused_to_run: bool
    # None = this design has no third state to report AT ALL, as opposed to `()`,
    # which would mean "measured, none found". The collapse theorem is visible in
    # this annotation: two of the three designs below have literally nowhere to
    # put "cannot check this row", so their report of it comes out as either a
    # break or a clean bill. That is CLAUDE.md rule 5 applied to the
    # experiment's own reporting, not just to the code under test.
    unverifiable: tuple[int, ...] | None


class SchemaVersionMismatch(RuntimeError):
    """The ordinal design's fatal error, by the name beads v1.2.2 printed."""


# --- Design 1: ordinal version identity (beads v1.2.2) ---------------------


def _ordinal_binary_verify(
    rows: Sequence[tuple[int, int]],
    *,
    known_max_version: int,
    ignore_schema_skew: bool = False,
) -> int:
    """Returns rows verified. Raises SchemaVersionMismatch on an unknown ordinal.

    `ignore_schema_skew` is the escape hatch, and it is modelled exactly as
    shipped: it does not verify the skewed rows under some fallback, it stops
    verifying anything. Two settings, refuse-everything and check-nothing.
    """
    if ignore_schema_skew:
        return 0
    verified = 0
    for seq, version in rows:
        if version > known_max_version:
            raise SchemaVersionMismatch(
                f"schema version mismatch at seq {seq}: trail says {version}, "
                f"this binary knows {known_max_version}"
            )
        verified += 1
    return verified


def ordinal_design(entries: Sequence[Entry], *, ignore_schema_skew: bool = False) -> DesignVerdict:
    rows = _ordinal_view(entries)
    try:
        verified = _ordinal_binary_verify(
            rows,
            known_max_version=ROLLED_BACK_MAX_KNOWN_ORDINAL,
            ignore_schema_skew=ignore_schema_skew,
        )
    except SchemaVersionMismatch:
        # Note what is lost: the rows written under the ordinal this binary DOES
        # know are refused along with the rest. There is no partial verdict.
        return DesignVerdict("ordinal", 0, (), refused_to_run=True, unverifiable=None)
    return DesignVerdict("ordinal", verified, (), refused_to_run=False, unverifiable=None)


# --- Design 2: recompute under the current field set (migration 060) -------


def recompute_under_current_design(entries: Iterable[Entry]) -> DesignVerdict:
    """`verify_chain`'s loop with the fingerprint dispatch DELETED.

    Every row is recomputed under this build's own 6-field frame, whatever
    fingerprint it was signed with. This is a faithful copy of
    domain/verify.py's loop in every other respect, including advancing
    expected_prev from the stored entry_hash, so the ONLY difference between this
    verdict and design 3's is the `registry.recomputable()` branch. It
    also serves as this file's falsifiability receipt: see
    TestFalsifiabilityReceipt.

    Unlike the real verifier it collects every break rather than returning the
    first, because "mass tampering alarm" is a claim about how many rows a
    single mismatch drags down and a first-break-only report cannot show it.
    """
    verified = 0
    breaks: list[tuple[int, str]] = []
    expected_prev = GENESIS_PREV_HASH
    for expected_seq, entry in enumerate(entries):
        header = entry.header
        if header.seq != expected_seq:
            breaks.append((header.seq, "seq_gap"))
        elif header.prev_hash != expected_prev:
            breaks.append((header.seq, "prev_hash_mismatch"))
        elif compute_entry_hash(header, frame=header_frame) != entry.entry_hash:
            breaks.append((header.seq, "entry_hash_mismatch"))
        elif (
            entry.payload is not None and compute_payload_hash(entry.payload) != header.payload_hash
        ):
            breaks.append((header.seq, "payload_hash_mismatch"))
        else:
            verified += 1
        expected_prev = entry.entry_hash
    return DesignVerdict(
        "recompute-under-current",
        verified,
        tuple(breaks),
        refused_to_run=False,
        unverifiable=None,
    )


# --- Design 3: descriptor-derived fingerprint identity (waxseal, real code) -


def fingerprint_design(entries: Sequence[Entry], registry: VersionRegistry) -> DesignVerdict:
    """No local reimplementation: this calls the shipped `verify_chain`."""
    result = verify_chain(entries, registry)
    breaks = () if result.broken_seq is None else ((result.broken_seq, result.reason or "unknown"),)
    return DesignVerdict(
        "fingerprint",
        result.checked,
        breaks,
        refused_to_run=False,
        unverifiable=result.unverifiable,
    )


# --- Control: the binary as it was BEFORE the rollback ---------------------


def _schema_b_aware_verify(entries: Sequence[Entry], actors: dict[int, str]) -> DesignVerdict:
    """Knows both field sets and owns a frame for each. Ground truth."""
    verified = 0
    breaks: list[tuple[int, str]] = []
    expected_prev = GENESIS_PREV_HASH
    for entry in entries:
        header = entry.header
        if header.prev_hash != expected_prev:
            breaks.append((header.seq, "prev_hash_mismatch"))
        else:
            if header.hash_version == FP_B:
                recomputed = hashlib.sha256(_frame_b(header, actors[header.seq])).hexdigest()
            else:
                recomputed = compute_entry_hash(header, frame=header_frame)
            if recomputed != entry.entry_hash:
                breaks.append((header.seq, "entry_hash_mismatch"))
            elif (
                entry.payload is not None
                and compute_payload_hash(entry.payload) != header.payload_hash
            ):
                breaks.append((header.seq, "payload_hash_mismatch"))
            else:
                verified += 1
        expected_prev = entry.entry_hash
    return DesignVerdict(
        "control-schema-b-aware", verified, tuple(breaks), refused_to_run=False, unverifiable=()
    )


def _rolled_back_registry() -> VersionRegistry:
    """The registry a rolled-back binary ships with: schema A only.

    A fresh VersionRegistry seeds exactly `fingerprint(): HEADER_FIELDS` and
    there is no removal API (CLAUDE.md rule 2), so "roll back" is constructed
    the same way tests/domain/test_knowledge_monotonicity.py constructs its
    subsets: by building a smaller registry, never by deleting from a bigger one.
    """
    return VersionRegistry()


# --- The experiment --------------------------------------------------------


class TestControlEstablishesTheTrailIsIntact:
    """Before any design is judged, prove the data itself is good."""

    def test_the_pre_rollback_binary_verifies_every_row(self) -> None:
        chain, actors = _build_evolved_trail()

        verdict = _schema_b_aware_verify(chain, actors)

        assert verdict.rows_verified == N_A + M_B == 7
        assert verdict.broken == ()
        # Every subsequent "broken" or "refused" verdict in this file is
        # therefore a FALSE alarm about a trail nothing tampered with.


class TestThreeDesignsOnTheSameTrail:
    """The paper's comparison. One assertion per design, never collapsed."""

    def test_ordinal_design_refuses_to_run_and_verifies_nothing(self) -> None:
        chain, _ = _build_evolved_trail()

        verdict = ordinal_design(chain)

        assert verdict.refused_to_run is True
        # Not "verified the 4 rows it understood, refused 3". Zero. The rows
        # written under the ordinal this binary knows are collateral damage --
        # that is what made beads v1.2.2 an outage rather than a warning.
        assert verdict.rows_verified == 0
        assert verdict.unverifiable is None

    def test_ordinal_design_raises_a_fatal_error_at_the_first_evolved_row(self) -> None:
        chain, _ = _build_evolved_trail()
        rows = _ordinal_view(chain)

        try:
            _ordinal_binary_verify(rows, known_max_version=ROLLED_BACK_MAX_KNOWN_ORDINAL)
        except SchemaVersionMismatch as exc:
            assert f"seq {N_A}" in str(exc)
        else:  # pragma: no cover - the assert below reports it if we get here
            raise AssertionError("ordinal design did not treat the unknown version as fatal")

    def test_recompute_under_current_design_reports_mass_tampering(self) -> None:
        chain, _ = _build_evolved_trail()

        verdict = recompute_under_current_design(chain)

        # Every row written under schema B, and only those, is called tampered.
        assert verdict.broken == tuple(
            (seq, "entry_hash_mismatch") for seq in range(N_A, N_A + M_B)
        )
        assert len(verdict.broken) == M_B == 3
        assert verdict.rows_verified == N_A
        assert verdict.unverifiable is None
        assert verdict.refused_to_run is False

    def test_fingerprint_design_reports_intact_intact_and_unknown_unverifiable(self) -> None:
        chain, _ = _build_evolved_trail()

        verdict = fingerprint_design(chain, _rolled_back_registry())

        # The three claims the paper asks this design to make, asserted apart:
        assert verdict.rows_verified == N_A  # intact rows reported intact
        assert verdict.unverifiable == tuple(range(N_A, N_A + M_B))  # unknown -> unverifiable
        assert verdict.broken == ()  # and NEVER tampered
        assert verdict.refused_to_run is False  # nor a refusal to run

    def test_the_three_verdicts_differ_on_one_trail(self) -> None:
        """The separation itself, stated as one comparison."""
        chain, _ = _build_evolved_trail()

        ordinal = ordinal_design(chain)
        recompute = recompute_under_current_design(chain)
        waxseal = fingerprint_design(chain, _rolled_back_registry())

        assert (ordinal.refused_to_run, len(ordinal.broken), ordinal.unverifiable) == (
            True,
            0,
            None,
        )
        assert (recompute.refused_to_run, len(recompute.broken), recompute.unverifiable) == (
            False,
            M_B,
            None,
        )
        assert (waxseal.refused_to_run, len(waxseal.broken), waxseal.unverifiable) == (
            False,
            0,
            tuple(range(N_A, N_A + M_B)),
        )


class TestRegisteringTheNameIsNotEnoughToRecompute:
    """Knowing schema B's fingerprint still must not license recomputation."""

    def test_registered_but_unhashable_schema_stays_unverifiable_never_broken(self) -> None:
        chain, _ = _build_evolved_trail()
        registry = VersionRegistry()
        assert registry.register(FIELDS_B) == FP_B

        verdict = fingerprint_design(chain, registry)

        # This build owns no 7-field frame, so even a registry that knows the
        # NAME must report the rows unverifiable rather than recompute them
        # under the 6-field frame they were not signed with. Knowing more turned
        # nothing into a break, which is knowledge monotonicity seen from the
        # other side.
        assert verdict.unverifiable == tuple(range(N_A, N_A + M_B))
        assert verdict.broken == ()
        assert verdict.rows_verified == N_A


class TestTheEscapeHatchIsNotAFix:
    """beads v1.2.2's BD_IGNORE_SCHEMA_SKEW=1, and what it buys."""

    def test_escape_hatch_turns_refusal_into_checking_nothing(self) -> None:
        chain, _ = _build_evolved_trail()

        verdict = ordinal_design(chain, ignore_schema_skew=True)

        assert verdict.refused_to_run is False
        assert verdict.rows_verified == 0  # not 7-verified: nothing was checked
        assert verdict.broken == ()
        # A caller that reads "no breaks" as "trail intact" now has false
        # confidence over the WHOLE trail, including the four rows this binary
        # could have checked. Both settings of the flag are the collapse
        # theorem: refuse everything, or check nothing.

    def test_neither_rolled_back_design_detects_a_tamper_in_a_row_it_cannot_hash(self) -> None:
        """Stated plainly, because the honest limit belongs in the receipt.

        A payload edit on a schema-B row is invisible to BOTH rolled-back
        designs, waxseal included. waxseal does not detect it. What waxseal does
        instead is decline to claim it checked the row, and that is the entire
        difference between the two reports.
        """
        chain, _ = _build_evolved_trail()
        tampered_seq = N_A + 1
        chain[tampered_seq] = replace(chain[tampered_seq], payload=b'{"i":"TAMPERED"}')

        hatched = ordinal_design(chain, ignore_schema_skew=True)
        waxseal = fingerprint_design(chain, _rolled_back_registry())

        # Neither reports a break. That much they share.
        assert hatched.broken == ()
        assert waxseal.broken == ()

        # The difference is what each one claims to have checked. The escape
        # hatch reports a clean run over a trail it never looked at; waxseal
        # reports four rows checked and names the three it could not, so no
        # reader can mistake the second for a clean bill on all seven.
        assert hatched.rows_verified == 0
        assert hatched.unverifiable is None
        assert waxseal.rows_verified == N_A
        assert waxseal.unverifiable == tuple(range(N_A, N_A + M_B))
        assert tampered_seq in (waxseal.unverifiable or ())


# --- Falsifiability receipt ------------------------------------------------
#
# CLAUDE.md's practice: a test that cannot fail proves nothing. The receipt for
# this experiment is already executed above rather than described, because
# `recompute_under_current_design` IS domain/verify.py's loop with exactly one
# behavior removed, the `registry.recomputable()` dispatch. If that dispatch
# were deleted from the shipped verifier, design 3's verdict would become
# design 2's, and the assertions in
# TestThreeDesignsOnTheSameTrail::test_fingerprint_design_... would go red with
# three manufactured `entry_hash_mismatch` breaks.
#
# The test below states that as an assertion instead of a comment, so the claim
# "these two differ only in that dispatch" is itself checked.
#
# EXECUTED RECEIPT (waxseal-4t1, 2026-08-30). Not a description of a mutation
# that could be run, but one that was. `VersionRegistry.encoder_for` in shipped
# code was temporarily replaced with `return _ENCODERS[ENCODING]`, i.e. hand
# every row the current 6-field frame regardless of what it was signed with,
# which is migration 060 injected into this library. Five tests in this file
# went red, among them
# test_fingerprint_design_reports_intact_intact_and_unknown_unverifiable with
#
#     assert with_dispatch.broken == ()
#     AssertionError: assert ((4, 'entry_hash_mismatch'),) == ()
#
# which is a manufactured tampering verdict against seq 4, a row the control above
# proves is genuinely intact. Reverting the one line turned all ten green
# again. The experiment can fail, and it fails on exactly the defect it exists
# to detect.


class TestFalsifiabilityReceipt:
    def test_removing_the_dispatch_is_what_manufactures_the_false_alarm(self) -> None:
        chain, _ = _build_evolved_trail()

        with_dispatch = fingerprint_design(chain, _rolled_back_registry())
        without_dispatch = recompute_under_current_design(chain)

        # Same input, same loop, one branch apart, and the verdicts come out
        # opposite on the rows that branch governs.
        assert with_dispatch.rows_verified == without_dispatch.rows_verified == N_A
        assert with_dispatch.broken == ()
        assert without_dispatch.broken != ()
        assert {seq for seq, _ in without_dispatch.broken} == set(with_dispatch.unverifiable or ())
