"""Sealed-segment naming, project slugs, and multi-segment verification (SPEC 20).

Pure-domain tests: nothing here touches the filesystem. The rotation
mechanism that writes these segments is tested in tests/test_sources_rotation.py
and the `waxseal segments` command in tests/test_cli_segments.py.
"""

from __future__ import annotations

import pytest

from waxseal.domain.handoff import HANDOFF_PAYLOAD_TYPE, HandoffBinding, to_payload
from waxseal.domain.segments import (
    ROTATION_PAYLOAD_TYPE,
    SEGMENT_BROKEN,
    SEGMENT_MISSING,
    SEGMENT_OK,
    SEGMENT_UNVERIFIABLE,
    SegmentRead,
    project_slug,
    segment_chain_id,
    segment_identity,
    segment_name,
    segment_ordinal,
    verify_segments,
)
from waxseal.domain.verdict import Verdict
from waxseal.domain.verify import VerifyResult

H0 = "a" * 64
H1 = "b" * 64
H2 = "c" * 64
EVENT_PT = "application/vnd.test.event+json"


def ok_result(checked: int = 2, unverifiable: tuple[int, ...] = ()) -> VerifyResult:
    return VerifyResult(
        ok=True,
        checked=checked,
        broken_seq=None,
        reason=None,
        unverifiable=unverifiable,
        dropped_writes=None,
    )


def broken_result(seq: int, reason: str) -> VerifyResult:
    return VerifyResult(
        ok=False,
        checked=seq,
        broken_seq=seq,
        reason=reason,
        unverifiable=(),
        dropped_writes=None,
    )


def base_segment(identity: str = "trail", hashes: tuple[str, ...] = (H0, H1)) -> SegmentRead:
    """The lowest segment present: its seq 0 is an ordinary event, not a binding."""
    return SegmentRead(
        identity=identity,
        chain=ok_result(len(hashes)),
        entry_hashes=hashes,
        genesis_payload_type=EVENT_PT,
        genesis_payload={"event": "PreToolUse"},
    )


def bound_segment(
    identity: str,
    *,
    to_chain: str,
    to_seq: int,
    to_hash: str,
    hashes: tuple[str, ...] = (H2,),
    chain: VerifyResult | None = None,
) -> SegmentRead:
    return SegmentRead(
        identity=identity,
        chain=ok_result(len(hashes)) if chain is None else chain,
        entry_hashes=hashes,
        genesis_payload_type=ROTATION_PAYLOAD_TYPE,
        genesis_payload=to_payload(
            HandoffBinding(chain_id=to_chain, seq=to_seq, head_hash=to_hash)
        ),
    )


class TestProjectSlug:
    def test_slug_is_deterministic_for_one_cwd(self) -> None:
        assert project_slug("/work/project") == project_slug("/work/project")

    def test_different_cwd_gives_a_different_slug(self) -> None:
        # The point of routing: two projects must never share one trail
        # directory just because their basenames match.
        a = project_slug("/work/alpha/project")
        b = project_slug("/work/beta/project")
        assert a != b
        # ...and the human-readable half is still the shared basename, so the
        # 48-bit suffix is what separates them.
        assert a.startswith("project-")
        assert b.startswith("project-")

    def test_slug_holds_only_lowercase_url_safe_characters(self) -> None:
        slug = project_slug("/Users/Ada/My Project (v2)!")
        assert slug == slug.lower()
        assert all(c.isdigit() or ("a" <= c <= "z") or c == "-" for c in slug), slug

    def test_readable_half_is_clipped_to_32_characters(self) -> None:
        long_name = "a" * 80
        slug = project_slug(f"/work/{long_name}")
        readable, _, digest = slug.rpartition("-")
        assert readable == "a" * 32
        assert len(digest) == 12

    def test_hash_half_is_twelve_hex_characters(self) -> None:
        _, _, digest = project_slug("/work/project").rpartition("-")
        assert len(digest) == 12
        assert all(c in "0123456789abcdef" for c in digest)

    def test_windows_separators_are_understood(self) -> None:
        # A hook on Windows sends a backslash cwd; the readable half must not
        # become the whole path with the separators mangled into dashes.
        assert project_slug(r"C:\Users\ada\project").startswith("project-")

    def test_trailing_separator_does_not_change_the_readable_half(self) -> None:
        assert project_slug("/work/project/").startswith("project-")

    def test_a_cwd_with_no_usable_basename_still_yields_a_slug(self) -> None:
        slug = project_slug("/")
        assert slug.startswith("unnamed-")

    def test_hash_is_over_the_literal_cwd_not_a_resolved_path(self) -> None:
        # Two spellings of the same directory are NOT merged: resolving them
        # is host-dependent (symlinks resolve differently per machine) and
        # would split one project into two slugs on the hosts that differ.
        assert project_slug("/work/project") != project_slug("/work/project/")

    def test_case_differences_in_the_path_change_the_hash(self) -> None:
        assert project_slug("/work/Project") != project_slug("/work/project")


class TestSegmentNaming:
    def test_name_is_zero_padded_so_lexicographic_equals_chronological(self) -> None:
        names = [segment_name("trail", n) for n in (0, 1, 9, 10, 99, 100)]
        assert names[0] == "trail.00000.jsonl"
        assert names == sorted(names)

    def test_ordinal_round_trips_through_the_name(self) -> None:
        assert segment_ordinal(segment_name("trail", 42), "trail") == 42

    def test_ordinal_rejects_a_name_that_is_not_a_numbered_segment(self) -> None:
        assert segment_ordinal("trail.jsonl", "trail") is None
        assert segment_ordinal("trail.1.jsonl", "trail") is None
        assert segment_ordinal("trail.000001.jsonl", "trail") is None
        assert segment_ordinal("trail.0000x.jsonl", "trail") is None
        assert segment_ordinal("other.00001.jsonl", "trail") is None
        assert segment_ordinal("trail.00001.txt", "trail") is None

    def test_ordinal_must_not_be_negative(self) -> None:
        with pytest.raises(ValueError):
            segment_name("trail", -1)

    def test_ordinal_past_the_name_space_is_refused_loudly(self) -> None:
        # A sixth digit widens the name, so lexicographic order stops matching
        # chronological order and segment_ordinal refuses to parse it at all —
        # the segment would silently vanish from discovery.
        assert segment_name("trail", 99999) == "trail.99999.jsonl"
        with pytest.raises(ValueError):
            segment_name("trail", 100000)

    def test_identity_drops_only_the_suffix(self) -> None:
        assert segment_identity("trail.00003.jsonl") == "trail.00003"
        assert segment_identity("trail.jsonl") == "trail"

    def test_chain_id_is_slug_then_segment_identity(self) -> None:
        assert segment_chain_id("project-0123456789ab", "trail.00001") == (
            "project-0123456789ab/trail.00001"
        )


class TestVerifySegmentsHappyPath:
    def test_a_single_segment_needs_no_binding(self) -> None:
        result = verify_segments([base_segment()])
        assert result.verdict is Verdict.OK
        assert [s.state for s in result.segments] == [SEGMENT_OK]

    def test_a_held_binding_verifies_the_whole_directory(self) -> None:
        segments = [
            base_segment("trail.00000"),
            bound_segment("trail.00001", to_chain="slug/trail.00000", to_seq=1, to_hash=H1),
        ]
        result = verify_segments(segments)
        assert result.verdict is Verdict.OK
        assert [s.state for s in result.segments] == [SEGMENT_OK, SEGMENT_OK]

    def test_a_moved_directory_still_verifies(self) -> None:
        # The slug half of chain_id records which project directory the
        # segment lived under at rotation time. Resolution is by segment
        # identity, so `mv` of the whole directory is not a break.
        segments = [
            base_segment("trail.00000"),
            bound_segment(
                "trail.00001", to_chain="a-different-slug/trail.00000", to_seq=1, to_hash=H1
            ),
        ]
        assert verify_segments(segments).verdict is Verdict.OK


class TestVerifySegmentsBindingFailures:
    def test_a_non_first_segment_without_a_binding_is_broken(self) -> None:
        segments = [base_segment("trail.00000"), base_segment("trail.00001", hashes=(H2,))]
        result = verify_segments(segments)
        assert result.verdict is Verdict.BROKEN
        assert result.segments[1].state == SEGMENT_BROKEN
        assert result.segments[1].reason == "rotation_binding_missing"
        assert result.segments[1].identity == "trail.00001"

    def test_a_handoff_binding_is_not_a_rotation_binding(self) -> None:
        # HANDOFF_PAYLOAD_TYPE is deliberately a different type: mixing
        # delegation with rotation would pollute verify-handoff, and a
        # rotation binding is mandatory at seq 0 where a handoff one is not.
        segments = [
            base_segment("trail.00000"),
            SegmentRead(
                identity="trail.00001",
                chain=ok_result(1),
                entry_hashes=(H2,),
                genesis_payload_type=HANDOFF_PAYLOAD_TYPE,
                genesis_payload=to_payload(
                    HandoffBinding(chain_id="slug/trail.00000", seq=1, head_hash=H1)
                ),
            ),
        ]
        result = verify_segments(segments)
        assert result.segments[1].reason == "rotation_binding_missing"
        assert result.verdict is Verdict.BROKEN

    def test_a_binding_naming_the_wrong_hash_is_a_mismatch(self) -> None:
        segments = [
            base_segment("trail.00000"),
            bound_segment("trail.00001", to_chain="slug/trail.00000", to_seq=1, to_hash=H2),
        ]
        result = verify_segments(segments)
        assert result.verdict is Verdict.BROKEN
        assert result.segments[1].reason == "rotation_binding_mismatch"
        assert result.segments[1].identity == "trail.00001"

    def test_a_binding_past_the_predecessors_end_is_a_mismatch(self) -> None:
        # binding_holds fails closed on an out-of-range seq: the predecessor
        # was truncated behind the point the binding committed to.
        segments = [
            base_segment("trail.00000"),
            bound_segment("trail.00001", to_chain="slug/trail.00000", to_seq=9, to_hash=H1),
        ]
        assert verify_segments(segments).segments[1].reason == "rotation_binding_mismatch"

    def test_an_unparseable_binding_payload_is_unverifiable_not_broken(self) -> None:
        for payload in (None, {"chain_id": "slug/trail.00000"}, "not-an-object", {"seq": -1}):
            segments = [
                base_segment("trail.00000"),
                SegmentRead(
                    identity="trail.00001",
                    chain=ok_result(1),
                    entry_hashes=(H2,),
                    genesis_payload_type=ROTATION_PAYLOAD_TYPE,
                    genesis_payload=payload,
                ),
            ]
            result = verify_segments(segments)
            assert result.verdict is Verdict.UNVERIFIABLE, payload
            assert result.segments[1].state == SEGMENT_UNVERIFIABLE, payload
            assert result.segments[1].reason == "rotation_binding_unreadable", payload


class TestVerifySegmentsMissing:
    def test_a_named_but_absent_predecessor_is_broken(self) -> None:
        # Settled by the repository owner, 31/08/2026: a surviving binding is
        # POSITIVE evidence the segment existed, so its absence is BROKEN
        # (exit 1). UNVERIFIABLE would let segment deletion downgrade itself.
        segments = [
            base_segment("trail.00000"),
            bound_segment("trail.00002", to_chain="slug/trail.00001", to_seq=5, to_hash=H1),
        ]
        result = verify_segments(segments)
        assert result.verdict is Verdict.BROKEN
        missing = [s for s in result.segments if s.state == SEGMENT_MISSING]
        assert [s.identity for s in missing] == ["trail.00001"]
        assert missing[0].reason == "segment_missing"

    def test_the_referring_segment_keeps_its_own_intact_state(self) -> None:
        segments = [
            base_segment("trail.00000"),
            bound_segment("trail.00002", to_chain="slug/trail.00001", to_seq=5, to_hash=H1),
        ]
        states = {s.identity: s.state for s in verify_segments(segments).segments}
        assert states == {
            "trail.00000": SEGMENT_OK,
            "trail.00001": SEGMENT_MISSING,
            "trail.00002": SEGMENT_OK,
        }

    def test_a_binding_on_the_lowest_present_segment_is_still_checked(self) -> None:
        # Exempting the lowest present segment unconditionally would make
        # prefix deletion free: delete segments 0 and 1, and segment 2 becomes
        # "the first" and stops being asked about its own binding. A binding
        # that IS present is checked whatever the segment's position.
        segments = [
            bound_segment("trail.00002", to_chain="slug/trail.00001", to_seq=5, to_hash=H1),
        ]
        result = verify_segments(segments)
        assert result.verdict is Verdict.BROKEN
        assert [s.identity for s in result.segments if s.state == SEGMENT_MISSING] == [
            "trail.00001"
        ]

    def test_one_missing_segment_is_reported_once_however_many_name_it(self) -> None:
        segments = [
            bound_segment("trail.00002", to_chain="slug/trail.00001", to_seq=5, to_hash=H1),
            bound_segment("trail.00003", to_chain="slug/trail.00001", to_seq=5, to_hash=H1),
        ]
        result = verify_segments(segments)
        assert [s.identity for s in result.segments].count("trail.00001") == 1


class TestVerifySegmentsChainVerdicts:
    def test_a_broken_chain_inside_one_segment_names_that_segment_and_its_seq(self) -> None:
        segments = [
            SegmentRead(
                identity="trail.00000",
                chain=broken_result(3, "entry_hash_mismatch"),
                entry_hashes=(H0, H1),
                genesis_payload_type=EVENT_PT,
                genesis_payload={"event": "PreToolUse"},
            )
        ]
        result = verify_segments(segments)
        assert result.verdict is Verdict.BROKEN
        assert result.segments[0].reason == "entry_hash_mismatch"
        assert result.segments[0].broken_seq == 3

    def test_an_unknown_fingerprint_stays_unverifiable_and_never_becomes_broken(self) -> None:
        segments = [
            base_segment("trail.00000"),
            bound_segment(
                "trail.00001",
                to_chain="slug/trail.00000",
                to_seq=1,
                to_hash=H1,
                chain=ok_result(0, unverifiable=(0, 1)),
            ),
        ]
        result = verify_segments(segments)
        assert result.verdict is Verdict.UNVERIFIABLE
        assert result.segments[1].state == SEGMENT_UNVERIFIABLE
        assert result.segments[1].reason == "unknown_fingerprint"

    def test_a_break_outranks_an_unverifiable_row_in_the_same_segment(self) -> None:
        # Verdict.join's severity order, not max() over exit codes: 2 is the
        # larger code but the weaker finding.
        segments = [
            base_segment("trail.00000"),
            bound_segment(
                "trail.00001",
                to_chain="slug/trail.00000",
                to_seq=1,
                to_hash=H2,
                chain=ok_result(0, unverifiable=(0,)),
            ),
        ]
        result = verify_segments(segments)
        assert result.verdict is Verdict.BROKEN
        assert result.segments[1].reason == "rotation_binding_mismatch"

    def test_a_broken_chain_suppresses_its_own_binding_finding(self) -> None:
        segments = [
            base_segment("trail.00000"),
            bound_segment(
                "trail.00001",
                to_chain="slug/trail.00000",
                to_seq=1,
                to_hash=H2,
                chain=broken_result(2, "prev_hash_mismatch"),
            ),
        ]
        result = verify_segments(segments)
        assert result.segments[1].reason == "prev_hash_mismatch"
        assert result.verdict is Verdict.BROKEN


class TestVerifySegmentsUnreadable:
    def test_a_segment_whose_lines_will_not_parse_is_unverifiable(self) -> None:
        # A torn first line from a crash mid-rotation. Reported, never
        # repaired (rule 4) and never called tampering (rule 5).
        segments = [SegmentRead(identity="trail.00000", chain=None)]
        result = verify_segments(segments)
        assert result.verdict is Verdict.UNVERIFIABLE
        assert result.segments[0].state == SEGMENT_UNVERIFIABLE
        assert result.segments[0].reason == "segment_unreadable"

    def test_a_binding_against_an_unreadable_predecessor_is_unchecked(self) -> None:
        segments = [
            SegmentRead(identity="trail.00000", chain=None),
            bound_segment("trail.00001", to_chain="slug/trail.00000", to_seq=1, to_hash=H1),
        ]
        result = verify_segments(segments)
        assert result.verdict is Verdict.UNVERIFIABLE
        assert result.segments[1].reason == "rotation_binding_unchecked"

    def test_an_empty_segment_has_no_binding_to_check(self) -> None:
        # Crash between creating the file and writing its genesis line.
        segments = [
            base_segment("trail.00000"),
            SegmentRead(identity="trail.00001", chain=ok_result(0)),
        ]
        result = verify_segments(segments)
        assert result.segments[1].reason == "rotation_binding_missing"
        assert result.verdict is Verdict.BROKEN


class TestVerifySegmentsEmptyInput:
    def test_no_segments_is_an_intact_verdict_with_nothing_in_it(self) -> None:
        # The "nothing here" decision belongs to the caller (the CLI turns it
        # into exit 3); this function reports only what it was given.
        result = verify_segments([])
        assert result.segments == ()
        assert result.verdict is Verdict.OK
