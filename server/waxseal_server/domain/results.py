"""What a read returns.

Every one of these carries at least one field that is `| None` on purpose. That
is not defensive typing: it is the Ternary Evidence Principle in the type
system. `checked: int | None` cannot be rendered as a measured zero by accident,
and `head: tuple | None` cannot be confused with a head at seq 0, because there
is no in-band value either could borrow.
"""

from __future__ import annotations

from dataclasses import dataclass

from waxseal import Verdict


@dataclass(frozen=True, slots=True)
class AppendResult:
    """A `201`: the entry landed, and here is the receipt for it."""

    seq: int
    entry_hash: str
    receipt_seq: int
    receipt_head: str


@dataclass(frozen=True, slots=True)
class ChainSummary:
    """Counts and identities for one chain — and deliberately no verdict.

    Counting lines is not verifying them. A summary that carried a verdict would
    be claiming a check nobody ran; the verdict comes from the CLI, separately.
    """

    chain_id: str
    entries: int
    size_bytes: int
    head: tuple[int, str] | None
    receipt: tuple[int, str] | None


@dataclass(frozen=True, slots=True)
class ReceiptLogReport:
    """ "Is the acknowledgment log internally consistent?"

    `checked is None` means the log is absent — never measured — and must never
    render as 0, "measured, nothing wrong" (CLAUDE.md rule 5).
    """

    verdict: Verdict
    checked: int | None
    reason: str | None = None
    broken_receipt_seq: int | None = None


@dataclass(frozen=True, slots=True)
class ReceiptCrossCheck:
    """ "Does entry `seq` still carry the hash that was acknowledged for it?"

    `broken_seq` is the CHAIN's seq, not the receipt's: the operator's next
    question is which entry, and pointing at a receipt index would send them to
    the wrong place.
    """

    verdict: Verdict
    checked: int | None
    reason: str | None = None
    broken_seq: int | None = None
