"""Segment-archive vocabulary — J3.

Three states, not two: a sealed segment that reached an archive, one that was
sent and did not arrive, and one nobody was asked to send. Collapsing the
third into either of the first two is the Ternary Evidence Principle's
collapse (CLAUDE.md, "Named principle") in its J3 clothing — "the segment is
safely off-box" and "nobody tried" are different facts about availability, and
an operator who cannot tell them apart discovers the difference only when the
original is gone.

The label table is swept the way ``tests/adapters/test_s3_worm.py`` sweeps
``_WORM_LABEL``: per-value correctness is not enough if two states can render
into sentences an operator reads the same way.
"""

from __future__ import annotations

import pytest

from waxseal.domain.archive import (
    _ARCHIVE_LABEL,
    ArchiveReport,
    ArchiveState,
    render_archive_state,
)


def report(state: ArchiveState, detail: str = "because") -> ArchiveReport:
    return ArchiveReport(state=state, destination="s3://bucket/trail.00000.jsonl", detail=detail)


class TestTheThreeStates:
    def test_there_are_exactly_three_states(self) -> None:
        assert {s.value for s in ArchiveState} == {
            "archive_stored",
            "archive_failed",
            "archive_not_attempted",
        }

    def test_every_state_has_its_own_label(self) -> None:
        # Spelled out, not derived: a missing state must raise in the
        # renderer rather than fall back to another state's sentence.
        assert set(_ARCHIVE_LABEL) == set(ArchiveState)

    def test_not_attempted_never_renders_as_stored_or_failed(self) -> None:
        line = render_archive_state(report(ArchiveState.NOT_ATTEMPTED))[0]
        assert line.startswith("archive_not_attempted:")
        assert "archive_stored" not in line
        assert "archive_failed" not in line

    def test_only_the_stored_line_says_a_copy_exists_off_box(self) -> None:
        claims = {
            state: "a copy of the sealed segment exists" in render_archive_state(report(state))[0]
            for state in ArchiveState
        }
        assert claims == {
            ArchiveState.STORED: True,
            ArchiveState.FAILED: False,
            ArchiveState.NOT_ATTEMPTED: False,
        }

    def test_every_line_names_the_state_the_destination_and_the_detail(self) -> None:
        for state in ArchiveState:
            line = render_archive_state(report(state, detail="the reason given"))[0]
            assert line.startswith(f"{state.value}:")
            assert "s3://bucket/trail.00000.jsonl" in line
            assert "the reason given" in line

    def test_the_renderer_returns_one_line_per_report(self) -> None:
        # domain.tickets / adapters.s3 style: a list, so a caller composes
        # report sections without re-splitting prose.
        assert len(render_archive_state(report(ArchiveState.STORED))) == 1


class TestDetailIsMandatory:
    def test_a_report_carries_both_a_destination_and_a_detail(self) -> None:
        # Rule 6: a degradation is recorded in the output. "failed" with no
        # reason and no destination is an alarm an operator cannot act on.
        with pytest.raises(TypeError):
            ArchiveReport(state=ArchiveState.FAILED)  # type: ignore[call-arg]
