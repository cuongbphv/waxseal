"""Anchoring-liveness ternary: live / delinquent / unreachable (pure; no I/O).

The Anchoring Liveness Contract is one of the three constructions the paper
describes as "designed and analysed, not implemented". What it buys is
narrow and worth stating before the code: a contract that records when a
writer last submitted a signed checkpoint turns "this trail stopped being
anchored" from something only a diligent auditor would notice into something
anyone can read off a public ledger. It does NOT attest that any individual
entry is honest, and it does not close coverage.

The third value is the whole design. An RPC endpoint that did not answer has
measured nothing about the writer's punctuality: reading that silence as
`delinquent` raises an alarm about a node outage, and reading it as `live`
reports a writer that stopped anchoring weeks ago as healthy. Both are the
collapse CLAUDE.md rule 5 forbids, arrived at from opposite directions.

The staleness decision itself is NOT re-implemented here. `anchor_staleness`
(`domain/pinning.py`) already decides "is the newest piece of anchoring
evidence older than the deadline", including the case that has no evidence
at all, and this module delegates to it so the two can never drift into
disagreeing about what "overdue" means.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from waxseal.domain.pinning import (
    ANCHOR_TIMESTAMP_UNPARSEABLE,
    anchor_staleness,
)
from waxseal.domain.verdict import Verdict

LIVE: Final = "live"
DELINQUENT: Final = "delinquent"
UNREACHABLE: Final = "unreachable"

# Reason strings. `ledger_delinquent` and `ledger_unreachable` are the two the
# CLI contract names; the rest distinguish cases an operator would otherwise
# have to guess between when reading a bare `unreachable`.
LEDGER_DELINQUENT: Final = "ledger_delinquent"
LEDGER_UNREACHABLE: Final = "ledger_unreachable"
NO_CHECKPOINT_ON_LEDGER: Final = "no_checkpoint_on_ledger"
DEADLINE_UNAVAILABLE: Final = "deadline_unavailable"
BLOCK_TIMESTAMP_UNUSABLE: Final = "block_timestamp_unusable"


@dataclass(frozen=True, slots=True)
class OnChainCheckpoint:
    """What the liveness contract stores for one trail.

    `block_time` is the CHAIN's clock (the block timestamp of the submitting
    transaction), never the writer's: a writer that could stamp its own
    submission time could claim punctuality it never had, which would make
    the whole contract decorative. It is a miner-influenced value with a
    tolerance of seconds, which is immaterial against deadlines measured in
    hours, and that tolerance is the reason `delta` should never be set near
    the block interval.

    Lives in domain because the ledger port returns it and a port may import
    domain at most (CLAUDE.md's layer DAG).
    """

    chain_id: str
    seq: int
    entry_hash: str
    root: str
    block_time: int


@dataclass(frozen=True, slots=True)
class LivenessVerdict:
    """One liveness reading, with the age it was decided on.

    `age_s` is `None` whenever nothing was measured — no checkpoint on the
    ledger, no usable block timestamp, no answer at all — and never `0`,
    which would read as "submitted this instant" (CLAUDE.md rule 5).
    """

    status: str
    reason: str | None = None
    age_s: int | None = None
    deadline_s: int | None = None

    def to_verdict(self) -> Verdict:
        """The `ledger-status` mapping: a delinquent writer is a POSITIVELY
        DETECTED finding, the same sense `reconcile-tickets` gives exit 1.
        The contract said, on its own record, that no checkpoint arrived in
        time; that is a measured fact about the writer, not an inference."""
        return _lookup(self.status, _LEDGER_STATUS)

    def to_verify_verdict(self) -> Verdict:
        """The `verify` mapping, where nothing here can ever reach exit 1.

        `verify` answers one question: was the trail edited? A chain saying
        "no checkpoint arrived within delta" is evidence about PUNCTUALITY,
        and a trail can be perfectly intact and hours late. Letting a
        delinquent reading raise `broken` would print "tampered" over a
        writer whose network was down, which is the false alarm that started
        this library.
        """
        return _lookup(self.status, _VERIFY_STATUS)


def _lookup(status: str, table: dict[str, Verdict]) -> Verdict:
    try:
        return table[status]
    except KeyError:
        raise ValueError(f"not a liveness status: {status!r}") from None


_LEDGER_STATUS: Final[dict[str, Verdict]] = {
    LIVE: Verdict.OK,
    DELINQUENT: Verdict.BROKEN,
    UNREACHABLE: Verdict.UNVERIFIABLE,
}

# Range is exactly {OK, UNVERIFIABLE}: BROKEN is not spelled anywhere in this
# table, so no liveness reading can produce `verify` exit 1 by construction,
# not by a reviewer's care.
_VERIFY_STATUS: Final[dict[str, Verdict]] = {
    LIVE: Verdict.OK,
    DELINQUENT: Verdict.UNVERIFIABLE,
    UNREACHABLE: Verdict.UNVERIFIABLE,
}


def _moment(block_ts: int) -> datetime | None:
    """The block timestamp as an aware datetime, or None if this build cannot
    place it in time at all (a chain reporting a year outside datetime's
    range, which is remote input, not a caller error)."""
    try:
        return datetime.fromtimestamp(block_ts, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _age_s(moment: datetime, now: datetime) -> int | None:
    try:
        return int((now - moment).total_seconds())
    except TypeError:
        # A naive `now` next to an aware block time. Reported as unmeasured,
        # never as age 0.
        return None


def delinquency(
    latest_block_ts: int | None,
    deadline_s: int | None,
    *,
    now: datetime,
) -> LivenessVerdict:
    """Decide liveness for one trail from what the contract returned.

    `latest_block_ts is None` means the contract ANSWERED and holds no
    checkpoint for this chain id; `deadline_s is None` means it holds no
    deadline. An endpoint that could not be reached must not come here at
    all — the caller that owns the network builds `unreachable_ledger`
    instead, which is what keeps this function pure.
    """
    if deadline_s is None:
        # Without a deadline there is nothing to be late against. Comparing
        # against a default would invent a policy the operator never set and
        # then report a writer delinquent under it.
        return LivenessVerdict(UNREACHABLE, reason=DEADLINE_UNAVAILABLE)

    records: tuple[tuple[int, str], ...] = ()
    moment: datetime | None = None
    if latest_block_ts is not None:
        moment = _moment(latest_block_ts)
        if moment is None:
            return LivenessVerdict(
                UNREACHABLE, reason=BLOCK_TIMESTAMP_UNUSABLE, deadline_s=deadline_s
            )
        records = ((0, moment.isoformat()),)

    stale = anchor_staleness(deadline_s, records, now=now)
    age = None if moment is None else _age_s(moment, now)
    if stale is None:
        return LivenessVerdict(LIVE, age_s=age, deadline_s=deadline_s)
    if stale == ANCHOR_TIMESTAMP_UNPARSEABLE:
        return LivenessVerdict(UNREACHABLE, reason=stale, deadline_s=deadline_s)
    return LivenessVerdict(
        DELINQUENT,
        reason=LEDGER_DELINQUENT if moment is not None else NO_CHECKPOINT_ON_LEDGER,
        age_s=age,
        deadline_s=deadline_s,
    )


def unreachable_ledger(reason: str) -> LivenessVerdict:
    """A ledger that could not be asked.

    Built by the caller that owns the network (the same split
    `unreachable_witness` uses in `domain/witnessing.py`), so `delinquency`
    stays a pure function of what a contract actually returned.
    """
    return LivenessVerdict(UNREACHABLE, reason=reason)
