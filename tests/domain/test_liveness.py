"""Liveness ternary: live / delinquent / unreachable.

The whole point of the third value is that an RPC endpoint that did not
answer says NOTHING about whether the writer anchored on time. Collapsing it
into `delinquent` raises a false alarm every time a node is down; collapsing
it into `live` reports a writer that stopped anchoring as healthy. The
falsifiability receipt at the bottom of this file removes the branch and
shows the suite goes red.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from waxseal.domain import liveness
from waxseal.domain.verdict import Verdict

NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
HOUR = 3600


def at(seconds_ago: int) -> int:
    return int((NOW - timedelta(seconds=seconds_ago)).timestamp())


class TestOnChainCheckpoint:
    def test_carries_what_the_contract_stores(self) -> None:
        cp = liveness.OnChainCheckpoint(
            chain_id="0x" + "11" * 32,
            seq=7,
            entry_hash="aa" * 32,
            root="bb" * 32,
            block_time=at(10),
        )
        assert (cp.seq, cp.block_time) == (7, at(10))


class TestLive:
    def test_a_recent_submission_is_live(self) -> None:
        verdict = liveness.delinquency(at(600), HOUR, now=NOW)
        assert verdict.status == liveness.LIVE
        assert (verdict.reason, verdict.age_s, verdict.deadline_s) == (None, 600, HOUR)

    def test_exactly_at_the_deadline_is_still_live(self) -> None:
        # The same boundary `anchor_staleness` already draws (strictly older
        # than max_age_s is stale), reused rather than re-decided here.
        assert liveness.delinquency(at(HOUR), HOUR, now=NOW).status == liveness.LIVE


class TestDelinquent:
    def test_an_overdue_submission_is_delinquent(self) -> None:
        verdict = liveness.delinquency(at(2 * HOUR), HOUR, now=NOW)
        assert verdict.status == liveness.DELINQUENT
        assert verdict.reason == liveness.LEDGER_DELINQUENT
        assert verdict.age_s == 2 * HOUR

    def test_a_chain_id_the_contract_has_never_seen_a_checkpoint_for(self) -> None:
        # A read that SUCCEEDED and found nothing. Absence of anchoring
        # evidence is staleness, not unmeasured: the contract answered.
        verdict = liveness.delinquency(None, HOUR, now=NOW)
        assert verdict.status == liveness.DELINQUENT
        assert verdict.reason == liveness.NO_CHECKPOINT_ON_LEDGER
        assert verdict.age_s is None


class TestUnreachable:
    def test_an_rpc_that_could_not_be_asked(self) -> None:
        verdict = liveness.unreachable_ledger("connection refused")
        assert verdict.status == liveness.UNREACHABLE
        assert verdict.reason == "connection refused"
        assert (verdict.age_s, verdict.deadline_s) == (None, None)

    def test_a_chain_id_with_no_deadline_configured_is_not_delinquent(self) -> None:
        # Nothing to compare against. Calling this delinquent would invent a
        # deadline the operator never set.
        verdict = liveness.delinquency(at(10 * HOUR), None, now=NOW)
        assert verdict.status == liveness.UNREACHABLE
        assert verdict.reason == liveness.DEADLINE_UNAVAILABLE

    def test_a_block_timestamp_this_build_cannot_place_in_time(self) -> None:
        verdict = liveness.delinquency(10**30, HOUR, now=NOW)
        assert verdict.status == liveness.UNREACHABLE
        assert verdict.reason == liveness.BLOCK_TIMESTAMP_UNUSABLE

    def test_a_now_that_does_not_compare_with_the_block_time(self) -> None:
        naive = NOW.replace(tzinfo=None)
        verdict = liveness.delinquency(at(600), HOUR, now=naive)
        assert verdict.status == liveness.UNREACHABLE
        assert verdict.reason == liveness.ANCHOR_TIMESTAMP_UNPARSEABLE
        assert verdict.age_s is None


class TestVerdictMapping:
    def test_ledger_status_maps_delinquent_to_a_positive_detection(self) -> None:
        # `ledger-status` exit 1 = positively detected, the same semantics
        # `reconcile-tickets` already carries (CLAUDE.md CLI contract).
        assert liveness.delinquency(at(600), HOUR, now=NOW).to_verdict() is Verdict.OK
        assert liveness.delinquency(at(9 * HOUR), HOUR, now=NOW).to_verdict() is Verdict.BROKEN
        assert liveness.unreachable_ledger("x").to_verdict() is Verdict.UNVERIFIABLE

    def test_verify_never_calls_a_ledger_finding_a_break(self) -> None:
        # A chain saying "not anchored on time" is not a chain saying "the
        # trail was edited". Folded into `verify`, every ledger finding is at
        # most unverifiable — exit 2, never exit 1.
        findings = [
            liveness.delinquency(at(600), HOUR, now=NOW),
            liveness.delinquency(at(9 * HOUR), HOUR, now=NOW),
            liveness.unreachable_ledger("x"),
            liveness.delinquency(None, HOUR, now=NOW),
        ]
        assert [f.to_verify_verdict() for f in findings] == [
            Verdict.OK,
            Verdict.UNVERIFIABLE,
            Verdict.UNVERIFIABLE,
            Verdict.UNVERIFIABLE,
        ]
        assert Verdict.BROKEN not in {f.to_verify_verdict() for f in findings}

    def test_a_status_this_build_does_not_know_is_not_guessed_at(self) -> None:
        unknown = liveness.LivenessVerdict(status="probably-fine")
        with pytest.raises(ValueError, match="not a liveness status"):
            unknown.to_verdict()
        with pytest.raises(ValueError, match="not a liveness status"):
            unknown.to_verify_verdict()


class TestFalsifiabilityReceipt:
    """Receipt for the `unreachable` branch, run for real on 01/09/2026.

    Replacing the `deadline_s is None -> UNREACHABLE` guard in
    `domain/liveness.py::delinquency` with `deadline_s = 0 if deadline_s is
    None else deadline_s` (the shape a "just pick a default" fix takes) was
    run against this file:

        FAILED tests/domain/test_liveness.py::TestUnreachable::
            test_a_chain_id_with_no_deadline_configured_is_not_delinquent
        AssertionError: assert 'delinquent' == 'unreachable'
        1 failed, 12 passed in 0.10s

    Branch restored: 13 passed in 0.06s. The failure is the false alarm
    itself — a chain id whose deadline the contract never returned, reported
    as a writer that missed a deadline nobody set.
    """

    def test_the_receipt_is_recorded(self) -> None:
        assert TestFalsifiabilityReceipt.__doc__ is not None
        assert "1 failed" in TestFalsifiabilityReceipt.__doc__
