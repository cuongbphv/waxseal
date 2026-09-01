"""Tests for the auditor report (domain/report.py).

The report is what a supervisor or internal-audit function actually reads, so
its job is to state what was measured and — just as importantly — what was
not. Three distinctions must survive rendering, because collapsing any of
them turns the report into a more confident document than the evidence
supports:

- unverifiable-by-name is not tampering (exit 2 is not exit 1);
- ``dropped_writes=None`` is "never measured", not "measured zero";
- a sidecar that was not checked is not a sidecar that passed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

from waxseal import VerifyResult
from waxseal.domain.decision import (
    DECISION_PAYLOAD_TYPE,
    DecisionRecord,
    HumanOversight,
    ModelRef,
    to_payload,
)
from waxseal.domain.fingerprint import fingerprint
from waxseal.domain.hashing import compute_entry_hash
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader
from waxseal.domain.report import AuditReport, CheckSummary, build_report
from waxseal.domain.separation import SeparationTopology
from waxseal.domain.witnessing import (
    WITNESS_CONSISTENT,
    WITNESS_INCONSISTENT,
    WITNESS_UNREACHABLE,
    WitnessVerdict,
)

TOOL_TYPE = "application/vnd.test.toolcall+json"


def entry(seq: int, payload: bytes, payload_type: str, *, prev: str = GENESIS_PREV_HASH) -> Entry:
    header = EntryHeader(
        seq=seq,
        ts=f"2026-08-23T09:00:{seq:02d}+00:00",
        hash_version=fingerprint(),
        payload_type=payload_type,
        payload_hash=hashlib.sha256(payload).hexdigest(),
        prev_hash=prev,
    )
    return Entry(header=header, entry_hash=compute_entry_hash(header), payload=payload)


def decision_bytes(**overrides: object) -> bytes:
    base: dict[str, object] = {
        "decision_id": "d",
        "decision_type": "payment",
        "system_id": "agent",
        "model": ModelRef(name="m", version="v"),
        "input_commitment": "a" * 64,
        "outcome": "approve",
    }
    base.update(overrides)
    return json.dumps(to_payload(DecisionRecord(**base))).encode()  # type: ignore[arg-type]


def chain(*entries: Entry) -> list[Entry]:
    """Relink so prev_hash/seq are consistent — the report describes a trail,
    not a bag of rows."""
    out: list[Entry] = []
    prev = GENESIS_PREV_HASH
    for i, e in enumerate(entries):
        header = replace(e.header, seq=i, prev_hash=prev)
        linked = Entry(header=header, entry_hash=compute_entry_hash(header), payload=e.payload)
        out.append(linked)
        prev = linked.entry_hash
    return out


OK = VerifyResult(
    ok=True, checked=0, broken_seq=None, reason=None, unverifiable=(), dropped_writes=None
)


class TestInventory:
    def test_counts_entries_and_groups_by_payload_type(self) -> None:
        entries = chain(
            entry(0, b"a", TOOL_TYPE),
            entry(1, decision_bytes(), DECISION_PAYLOAD_TYPE),
            entry(2, b"c", TOOL_TYPE),
        )
        report = build_report(replace(OK, checked=3), entries)
        assert report.entries_total == 3
        assert dict(report.by_payload_type) == {TOOL_TYPE: 2, DECISION_PAYLOAD_TYPE: 1}

    def test_groups_by_fingerprint(self) -> None:
        entries = chain(entry(0, b"a", TOOL_TYPE), entry(1, b"b", TOOL_TYPE))
        report = build_report(OK, entries)
        assert dict(report.by_fingerprint) == {fingerprint(): 2}

    def test_reports_the_time_span_covered(self) -> None:
        entries = chain(entry(0, b"a", TOOL_TYPE), entry(1, b"b", TOOL_TYPE))
        report = build_report(OK, entries)
        assert report.first_ts == "2026-08-23T09:00:00+00:00"
        assert report.last_ts == "2026-08-23T09:00:01+00:00"

    def test_an_empty_trail_reports_no_span_rather_than_a_fake_one(self) -> None:
        report = build_report(OK, [])
        assert report.entries_total == 0
        assert report.first_ts is None and report.last_ts is None

    def test_counts_are_ordered_deterministically(self) -> None:
        # Two runs over the same trail must produce byte-identical reports,
        # or a diff between two audits is unreadable.
        entries = chain(
            entry(0, b"a", "application/vnd.test.zzz+json"),
            entry(1, b"b", "application/vnd.test.aaa+json"),
            entry(2, b"c", "application/vnd.test.aaa+json"),
        )
        report = build_report(OK, entries)
        assert report.by_payload_type == (
            ("application/vnd.test.aaa+json", 2),
            ("application/vnd.test.zzz+json", 1),
        )


class TestDecisionSummary:
    def test_counts_decisions_by_type(self) -> None:
        entries = chain(
            entry(0, decision_bytes(decision_type="payment"), DECISION_PAYLOAD_TYPE),
            entry(1, decision_bytes(decision_type="risk_scanning"), DECISION_PAYLOAD_TYPE),
            entry(2, decision_bytes(decision_type="payment"), DECISION_PAYLOAD_TYPE),
            entry(3, b"not a decision", TOOL_TYPE),
        )
        report = build_report(OK, entries)
        assert report.decisions_total == 3
        assert dict(report.by_decision_type) == {"payment": 2, "risk_scanning": 1}

    def test_counts_oversight_modes(self) -> None:
        entries = chain(
            entry(
                0,
                decision_bytes(human_oversight=HumanOversight(mode="reviewed")),
                DECISION_PAYLOAD_TYPE,
            ),
            entry(
                1,
                decision_bytes(human_oversight=HumanOversight(mode="automated")),
                DECISION_PAYLOAD_TYPE,
            ),
            entry(
                2,
                decision_bytes(human_oversight=HumanOversight(mode="reviewed")),
                DECISION_PAYLOAD_TYPE,
            ),
        )
        report = build_report(OK, entries)
        assert dict(report.by_oversight_mode) == {"reviewed": 2, "automated": 1}
        assert report.oversight_unrecorded == 0

    def test_unrecorded_oversight_is_its_own_count_not_an_automated_one(self) -> None:
        # rule 5, the version that matters most here: "nobody wrote down
        # whether a human looked at this" must never be reported as "a human
        # did not need to look at this".
        entries = chain(
            entry(0, decision_bytes(), DECISION_PAYLOAD_TYPE),
            entry(
                1,
                decision_bytes(human_oversight=HumanOversight(mode="automated")),
                DECISION_PAYLOAD_TYPE,
            ),
        )
        report = build_report(OK, entries)
        assert report.oversight_unrecorded == 1
        assert dict(report.by_oversight_mode) == {"automated": 1}

    def test_a_decision_row_that_does_not_parse_is_listed_not_hidden(self) -> None:
        entries = chain(
            entry(0, decision_bytes(), DECISION_PAYLOAD_TYPE),
            entry(1, b"{}", DECISION_PAYLOAD_TYPE),
            entry(2, b"not json", DECISION_PAYLOAD_TYPE),
        )
        report = build_report(OK, entries)
        assert report.decisions_malformed == (1, 2)
        # A row nobody could parse is not counted as a decision of any type.
        assert report.decisions_total == 1

    def test_a_header_only_decision_row_counts_as_malformed_here(self) -> None:
        entries = chain(entry(0, decision_bytes(), DECISION_PAYLOAD_TYPE))
        entries[0] = replace(entries[0], payload=None)
        report = build_report(OK, entries)
        assert report.decisions_malformed == (0,)

    def test_no_decisions_reports_zero_not_absence(self) -> None:
        report = build_report(OK, chain(entry(0, b"a", TOOL_TYPE)))
        assert report.decisions_total == 0
        assert report.by_decision_type == ()
        assert report.decisions_malformed == ()


class TestChainVerdictPassesThrough:
    def test_a_broken_chain_is_reported_as_broken(self) -> None:
        verdict = VerifyResult(
            ok=False,
            checked=2,
            broken_seq=2,
            reason="prev_hash_mismatch",
            unverifiable=(),
            dropped_writes=None,
        )
        report = build_report(verdict, chain(entry(0, b"a", TOOL_TYPE)))
        assert not report.ok
        assert report.broken_seq == 2
        assert report.reason == "prev_hash_mismatch"

    def test_unverifiable_rows_are_carried_and_do_not_make_the_report_broken(self) -> None:
        verdict = replace(OK, checked=1, unverifiable=(3, 4))
        report = build_report(verdict, chain(entry(0, b"a", TOOL_TYPE)))
        assert report.ok is True
        assert report.unverifiable == (3, 4)
        assert report.reason is None


class TestCompleteness:
    def test_unmeasured_drops_stay_none(self) -> None:
        report = build_report(replace(OK, dropped_writes=None), [])
        assert report.dropped_writes is None
        assert report.drops_source is None

    def test_measured_zero_is_distinct_from_unmeasured(self) -> None:
        report = build_report(
            replace(OK, dropped_writes=0, drops_source="sidecar"), []
        )
        assert report.dropped_writes == 0
        assert report.drops_source == "sidecar"


class TestSidecarChecks:
    def test_unchecked_sidecars_are_none_not_ok(self) -> None:
        report = build_report(OK, [])
        assert report.anchors is None
        assert report.attestations is None

    def test_sidecar_summaries_are_carried_through(self) -> None:
        report = build_report(
            OK,
            [],
            anchors=CheckSummary(ok=True, checked=3, reason=None),
            attestations=CheckSummary(ok=False, checked=7, reason="seal_mismatch"),
        )
        assert report.anchors == CheckSummary(ok=True, checked=3, reason=None)
        assert report.attestations is not None
        assert report.attestations.reason == "seal_mismatch"


class TestSeparationDegreeReporting:
    """τ and the enumerated authorities it counts — closing conformance.md
    gap G1: `separation_degree()`/`render_separation_degree()` existed,
    fully tested, and were called from nowhere in `src/` before waxseal-mfi.
    """

    def test_no_declared_topology_is_none_not_zero_or_one(self) -> None:
        report = build_report(OK, [])
        assert report.separation_degree is None
        assert report.counted_authorities is None

    def test_declared_topology_is_carried_through(self) -> None:
        topology = SeparationTopology(
            seal_escrow=True, anchor_sinks=2, witness=True, pin_separate=False
        )
        report = build_report(OK, [], declared_topology=topology)
        assert report.separation_degree == 5
        assert report.counted_authorities == (
            ("writer", 1),
            ("seal_escrow", 1),
            ("anchor_sinks", 2),
            ("witness", 1),
        )


class TestJsonRendering:
    def test_json_is_parseable_and_carries_the_verdict(self) -> None:
        entries = chain(entry(0, decision_bytes(), DECISION_PAYLOAD_TYPE))
        obj = json.loads(build_report(replace(OK, checked=1), entries).to_json())
        assert obj["chain"]["ok"] is True
        assert obj["chain"]["checked"] == 1
        assert obj["decisions"]["total"] == 1

    def test_unmeasured_drops_serialize_as_null_not_zero(self) -> None:
        obj = json.loads(build_report(OK, []).to_json())
        assert obj["completeness"]["dropped_writes"] is None

    def test_unchecked_sidecars_serialize_as_null(self) -> None:
        obj = json.loads(build_report(OK, []).to_json())
        assert obj["anchors"] is None
        assert obj["attestations"] is None

    def test_checked_sidecars_serialize_as_objects(self) -> None:
        obj = json.loads(
            build_report(OK, [], anchors=CheckSummary(ok=True, checked=2, reason=None)).to_json()
        )
        assert obj["anchors"] == {
            "ok": True,
            "checked": 2,
            "reason": None,
            "unverifiable": False,
            "notes": [],
        }

    def test_counts_serialize_as_objects_keyed_by_name(self) -> None:
        entries = chain(entry(0, b"a", TOOL_TYPE), entry(1, b"b", TOOL_TYPE))
        obj = json.loads(build_report(OK, entries).to_json())
        assert obj["inventory"]["by_payload_type"] == {TOOL_TYPE: 2}

    def test_json_is_stable_across_identical_inputs(self) -> None:
        entries = chain(entry(0, b"a", TOOL_TYPE), entry(1, b"b", "application/vnd.z+json"))
        assert build_report(OK, entries).to_json() == build_report(OK, entries).to_json()

    def test_undeclared_tau_serializes_as_null_never_zero_or_one(self) -> None:
        obj = json.loads(build_report(OK, []).to_json())
        assert obj["separation"]["tau"] is None
        assert obj["separation"]["counted_authorities"] is None

    def test_declared_tau_serializes_with_the_enumeration(self) -> None:
        topology = SeparationTopology(
            seal_escrow=False, anchor_sinks=1, witness=False, pin_separate=True
        )
        obj = json.loads(
            build_report(OK, [], declared_topology=topology).to_json()
        )
        assert obj["separation"]["tau"] == 3
        assert obj["separation"]["counted_authorities"] == [
            {"name": "writer", "count": 1},
            {"name": "anchor_sinks", "count": 1},
            {"name": "pin_separate", "count": 1},
        ]


class TestMarkdownRendering:
    def test_intact_trail_says_so(self) -> None:
        md = build_report(replace(OK, checked=5), []).to_markdown()
        assert "intact" in md.lower()

    def test_broken_trail_names_the_row_and_the_reason(self) -> None:
        verdict = VerifyResult(
            ok=False, checked=1, broken_seq=4, reason="entry_hash_mismatch",
            unverifiable=(), dropped_writes=None,
        )
        md = build_report(verdict, []).to_markdown()
        assert "4" in md and "entry_hash_mismatch" in md

    def test_unverifiable_rows_are_spelled_out_as_not_tampering(self) -> None:
        # The single most important sentence in the document: a reader who
        # skims must not come away thinking exit 2 meant someone edited the
        # log.
        md = build_report(replace(OK, unverifiable=(2, 3)), []).to_markdown()
        assert "NOT" in md and "tampering" in md.lower()
        assert "2" in md and "3" in md

    def test_unmeasured_drops_render_as_not_measured_never_as_zero(self) -> None:
        md = build_report(OK, []).to_markdown()
        line = next(line for line in md.splitlines() if "ropped" in line)
        assert "not measured" in line.lower()
        assert "0" not in line

    def test_measured_drops_render_as_a_minimum(self) -> None:
        md = build_report(replace(OK, dropped_writes=3, drops_source="sidecar"), []).to_markdown()
        line = next(line for line in md.splitlines() if "ropped" in line)
        assert ">= 3" in line

    def test_unchecked_sidecars_render_as_not_checked(self) -> None:
        md = build_report(OK, []).to_markdown()
        anchors_line = next(line for line in md.splitlines() if "Anchors" in line)
        assert "not checked" in anchors_line.lower()

    def test_a_passing_sidecar_check_renders_as_ok(self) -> None:
        md = build_report(OK, [], anchors=CheckSummary(ok=True, checked=4)).to_markdown()
        anchors_line = next(line for line in md.splitlines() if "Anchors" in line)
        assert "ok (4 checked)" in anchors_line

    def test_a_passing_check_that_measured_nothing_says_so(self) -> None:
        # "The sidecar is there and empty" passes without covering anything;
        # printing a bare "ok" would read as coverage it does not have.
        md = build_report(
            OK, [], anchors=CheckSummary(ok=True, checked=0, reason="no_anchors_recorded")
        ).to_markdown()
        anchors_line = next(line for line in md.splitlines() if "Anchors" in line)
        assert "no_anchors_recorded" in anchors_line

    def test_checked_sidecars_render_their_verdict(self) -> None:
        md = build_report(
            OK, [], attestations=CheckSummary(ok=False, checked=2, reason="seal_mismatch")
        ).to_markdown()
        assert "seal_mismatch" in md

    def test_decision_breakdown_is_rendered(self) -> None:
        entries = chain(
            entry(0, decision_bytes(decision_type="payment"), DECISION_PAYLOAD_TYPE),
            entry(
                1,
                decision_bytes(
                    decision_type="risk_scanning",
                    human_oversight=HumanOversight(mode="reviewed"),
                ),
                DECISION_PAYLOAD_TYPE,
            ),
        )
        md = build_report(OK, entries).to_markdown()
        assert "payment" in md and "risk_scanning" in md and "reviewed" in md

    def test_unrecorded_oversight_is_named_in_the_markdown(self) -> None:
        entries = chain(entry(0, decision_bytes(), DECISION_PAYLOAD_TYPE))
        md = build_report(OK, entries).to_markdown()
        assert "not recorded" in md.lower()

    def test_malformed_decision_rows_are_named_in_the_markdown(self) -> None:
        entries = chain(entry(0, b"{}", DECISION_PAYLOAD_TYPE))
        md = build_report(OK, entries).to_markdown()
        assert "unparseable" in md.lower() or "malformed" in md.lower()

    def test_markdown_omits_the_decision_section_when_there_are_none(self) -> None:
        md = build_report(OK, chain(entry(0, b"a", TOOL_TYPE))).to_markdown()
        assert "risk_scanning" not in md

    def test_undeclared_tau_renders_as_not_declared_never_zero_or_one(self) -> None:
        md = build_report(OK, []).to_markdown()
        line = next(line for line in md.splitlines() if "separation degree" in line)
        assert "not declared" in line
        assert "0" not in line and "1" not in line

    def test_declared_tau_renders_the_number_and_the_enumeration(self) -> None:
        topology = SeparationTopology(
            seal_escrow=True, anchor_sinks=2, witness=True, pin_separate=True
        )
        md = build_report(OK, [], declared_topology=topology).to_markdown()
        line = next(line for line in md.splitlines() if "separation degree" in line)
        assert "6" in line
        assert "writer(1)" in line and "anchor_sinks(2)" in line and "witness(1)" in line

    def test_report_is_immutable(self) -> None:
        report = build_report(OK, [])
        assert isinstance(report, AuditReport)
        try:
            report.ok = False  # type: ignore[misc]
        except Exception:
            return
        raise AssertionError("AuditReport must be frozen")


class TestWitnessRendering:
    """Each witness verdict has to survive into the document as its own
    three-valued outcome. A markdown renderer that flattens "unreachable" into
    a bullet an auditor skims as "fine" undoes the distinction the domain type
    exists to protect."""

    def verdict(self, **kwargs: object) -> WitnessVerdict:
        base: dict[str, object] = {
            "name": "notary-eu",
            "status": WITNESS_CONSISTENT,
            "checked": 2,
        }
        base.update(kwargs)
        return WitnessVerdict(**base)  # type: ignore[arg-type]

    def test_no_witnesses_configured_is_not_a_pass(self) -> None:
        md = build_report(OK, [], witnesses=None).to_markdown()
        assert "Witnesses: **not checked**" in md

    def test_an_empty_witness_list_says_none_configured(self) -> None:
        md = build_report(OK, [], witnesses=()).to_markdown()
        assert "none configured" in md

    def test_consistent_witness(self) -> None:
        md = build_report(OK, [], witnesses=(self.verdict(),)).to_markdown()
        assert "`notary-eu`: consistent (checked 2)" in md

    def test_a_witness_holding_nothing_says_it_covers_nothing(self) -> None:
        md = build_report(
            OK, [], witnesses=(self.verdict(checked=0, reason="no_checkpoints_witnessed"),)
        ).to_markdown()
        assert "covers nothing" in md

    def test_unreadable_records_are_counted_in_the_document(self) -> None:
        md = build_report(OK, [], witnesses=(self.verdict(unreadable=4),)).to_markdown()
        assert "4 record(s) unreadable by this build" in md

    def test_inconsistent_witness_names_the_seq_and_reason(self) -> None:
        md = build_report(
            OK,
            [],
            witnesses=(
                self.verdict(
                    status=WITNESS_INCONSISTENT,
                    checked=1,
                    reason="anchor_root_mismatch",
                    broken_seq=3,
                ),
            ),
        ).to_markdown()
        assert "**INCONSISTENT** at seq=3" in md
        assert "anchor_root_mismatch" in md

    def test_unreachable_witness_is_marked_as_not_a_pass(self) -> None:
        md = build_report(
            OK,
            [],
            witnesses=(
                self.verdict(status=WITNESS_UNREACHABLE, checked=0, reason="timed out"),
            ),
        ).to_markdown()
        assert "**unreachable**" in md
        assert "not a pass" in md

    def test_json_carries_every_field_of_every_verdict(self) -> None:
        obj = json.loads(
            build_report(
                OK,
                [],
                witnesses=(
                    self.verdict(
                        status=WITNESS_INCONSISTENT, reason="anchor_beyond_head", broken_seq=7
                    ),
                ),
            ).to_json()
        )
        assert obj["witnesses"] == [
            {
                "name": "notary-eu",
                "status": "inconsistent",
                "checked": 2,
                "reason": "anchor_beyond_head",
                "broken_seq": 7,
                "unreadable": 0,
            }
        ]


class TestUnverifiableSidecarRendering:
    def test_an_unverifiable_sidecar_is_never_rendered_as_tampering(self) -> None:
        # beads v1.2.2 in the report layer: a sidecar this build cannot read by
        # name must read as "not readable here", never as a break.
        md = build_report(
            OK,
            [],
            anchors=CheckSummary(
                ok=True, checked=0, reason="anchor_record_version_unknown", unverifiable=True
            ),
        ).to_markdown()
        assert "**unverifiable**" in md
        assert "NOT evidence of tampering" in md
        assert "BROKEN" not in md
