"""Adversarial mutation-testing campaign (waxseal-br4 / plan doc T4).

Per-class tamper tests already exist (test_verify.py, test_postgres.py) and
assert the right broken_seq + reason for ONE instance of each class. What
they do not measure is the aggregate: over MANY mutated instances, what
fraction does verify_chain even notice, and — separately — of the ones it
notices, what fraction does it name correctly? A verifier that detects every
mutation but blames the wrong row is exactly as useless to an operator as one
that misses mutations outright: rule 9's "correct broken_seq + reason" is one
requirement, not two independent options, and this file is what makes that
measurable rather than merely asserted per-instance.

Two rates, reported and asserted SEPARATELY (the bead's own framing):
  (a) detection rate  = detected / total, over IN-SCOPE mutations
  (b) reason accuracy = correct(seq AND reason) / detected

"IN-SCOPE" excludes the two mutation shapes CLAUDE.md and
docs/security/threat-model.md already document as undetectable BY DESIGN
from chain verification alone: rewriting the whole trail with a
self-consistent re-chain, and truncating the tail. Both are the same
argument (threat-model.md section 1): entry_hash is a pure function of the
header and prev_hash is the previous entry_hash, so an attacker who can
rewrite the suffix can always re-link it into something verify_chain calls
`ok` — that is why anchoring/witnessing/sealing exist as SEPARATE mechanisms
(banking-poc scenarios 5 and 6, examples/banking-poc/README.md) and is not a
gap in verify_chain to fix. This file asserts that limitation explicitly
(never silently drops it) and keeps it out of the 100% floor asserted for
in-scope classes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

from tests.domain.test_verify import build_chain, registry
from waxseal.domain.fingerprint import fingerprint
from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader
from waxseal.domain.verify import verify_chain

# Chain length for the campaign. Large enough that "multiple different
# positions" (bead wording) is a real spread, small enough to keep the
# campaign fast; every mutation class below is exercised at every position
# it can meaningfully occupy.
N = 8


@dataclass(frozen=True, slots=True)
class MutationCase:
    label: str
    mutation_class: str
    build: Callable[[], list[Entry]]
    # Ground truth. For in_scope=True cases this is what a correct verifier
    # MUST report. For in_scope=False cases these are unused: the ground
    # truth there is "ok", asserted separately.
    expected_broken_seq: int | None
    expected_reason: str | None
    in_scope: bool


def _relink_from(chain: list[Entry], start_idx: int, prev_hash: str) -> None:
    """Recompute prev_hash + entry_hash forward from start_idx (mirrors
    tests/domain/test_knowledge_monotonicity.py's helper of the same name):
    the mechanical cost-model for "rewrite everything after the edited row",
    i.e. exactly what an attacker with write access to storage can always do
    (threat-model.md section 1)."""
    prev = prev_hash
    for i in range(start_idx, len(chain)):
        header = replace(chain[i].header, prev_hash=prev)
        entry_hash = compute_entry_hash(header)
        chain[i] = replace(chain[i], header=header, entry_hash=entry_hash)
        prev = entry_hash


def _edit_header_field_cases() -> list[MutationCase]:
    cases = []
    for i in range(N):

        def build(i: int = i) -> list[Entry]:
            chain = build_chain(N)
            tampered = replace(chain[i].header, ts="2027-01-01T00:00:00+00:00")
            chain[i] = replace(chain[i], header=tampered)
            return chain

        cases.append(
            MutationCase(
                label=f"edit_header_field@{i}",
                mutation_class="edit_header_field",
                build=build,
                expected_broken_seq=i,
                expected_reason="entry_hash_mismatch",
                in_scope=True,
            )
        )
    return cases


def _flip_payload_bit_cases() -> list[MutationCase]:
    cases = []
    for i in range(N):

        def build(i: int = i) -> list[Entry]:
            chain = build_chain(N)
            assert chain[i].payload is not None
            flipped = bytearray(chain[i].payload)  # type: ignore[arg-type]
            flipped[0] ^= 0x01
            chain[i] = replace(chain[i], payload=bytes(flipped))
            return chain

        cases.append(
            MutationCase(
                label=f"flip_payload_bit@{i}",
                mutation_class="flip_payload_bit",
                build=build,
                expected_broken_seq=i,
                expected_reason="payload_hash_mismatch",
                in_scope=True,
            )
        )
    return cases


def _corrupt_entry_hash_cases() -> list[MutationCase]:
    cases = []
    for i in range(N):

        def build(i: int = i) -> list[Entry]:
            chain = build_chain(N)
            chain[i] = replace(chain[i], entry_hash="c" * 64)
            return chain

        cases.append(
            MutationCase(
                label=f"corrupt_entry_hash@{i}",
                mutation_class="corrupt_entry_hash",
                build=build,
                expected_broken_seq=i,
                expected_reason="entry_hash_mismatch",
                in_scope=True,
            )
        )
    return cases


def _corrupt_prev_hash_cases() -> list[MutationCase]:
    cases = []
    for i in range(N):

        def build(i: int = i) -> list[Entry]:
            chain = build_chain(N)
            bad_header = replace(chain[i].header, prev_hash="d" * 64)
            chain[i] = replace(chain[i], header=bad_header)
            return chain

        cases.append(
            MutationCase(
                label=f"corrupt_prev_hash@{i}",
                mutation_class="corrupt_prev_hash",
                build=build,
                expected_broken_seq=i,
                expected_reason="prev_hash_mismatch",
                in_scope=True,
            )
        )
    return cases


def _delete_non_tail_cases() -> list[MutationCase]:
    # Position N-1 (the tail) is deliberately excluded here — see
    # _tail_truncation_case below for why deleting the LAST record is not
    # the same mutation as deleting an interior one.
    cases = []
    for i in range(N - 1):

        def build(i: int = i) -> list[Entry]:
            chain = build_chain(N)
            del chain[i]
            return chain

        cases.append(
            MutationCase(
                label=f"delete_record@{i}",
                mutation_class="delete_record",
                build=build,
                expected_broken_seq=i + 1,  # the shifted-up entry's stale header.seq
                expected_reason="seq_gap",
                in_scope=True,
            )
        )
    return cases


def _insert_record_cases() -> list[MutationCase]:
    # Insert positions 0..N-2: inserting after the last real entry would
    # just be a legitimately-extended chain (seq=N, correct prev_hash), not
    # a tamper of anything existing, so it is not part of this campaign.
    cases = []
    for i in range(N - 1):

        def build(i: int = i) -> list[Entry]:
            chain = build_chain(N)
            prev = chain[i - 1].entry_hash if i > 0 else GENESIS_PREV_HASH
            payload = b'{"forged":true}'
            header = EntryHeader(
                seq=i,
                ts="2026-08-21T09:00:00+00:00",
                hash_version=fingerprint(),
                payload_type="application/vnd.test.event+json",
                payload_hash=compute_payload_hash(payload),
                prev_hash=prev,
            )
            forged = Entry(
                header=header, entry_hash=compute_entry_hash(header), payload=payload
            )
            chain.insert(i, forged)
            return chain

        cases.append(
            MutationCase(
                label=f"insert_record@{i}",
                mutation_class="insert_record",
                build=build,
                # The inserted row itself carries the correct seq/prev_hash
                # for its position (it verifies as intact on its own); the
                # break surfaces one row later, where the ORIGINAL row now
                # occupying seq i's old slot still advertises header.seq=i.
                expected_broken_seq=i,
                expected_reason="seq_gap",
                in_scope=True,
            )
        )
    return cases


def _reorder_adjacent_cases() -> list[MutationCase]:
    cases = []
    for i in range(N - 1):

        def build(i: int = i) -> list[Entry]:
            chain = build_chain(N)
            chain[i], chain[i + 1] = chain[i + 1], chain[i]
            return chain

        cases.append(
            MutationCase(
                label=f"reorder_adjacent@{i}",
                mutation_class="reorder_adjacent",
                build=build,
                expected_broken_seq=i + 1,  # the swapped-forward entry's stale header.seq
                expected_reason="seq_gap",
                in_scope=True,
            )
        )
    return cases


def _tail_truncation_cases() -> list[MutationCase]:
    # OUT OF SCOPE, BY DESIGN (rule 9: state the incident, not the mechanics).
    # Deleting the chain's LAST record is not "a mutated record" the way
    # deleting an interior one is: nothing downstream references the removed
    # row's header.seq, so no positional or hash mismatch exists for
    # verify_chain to find. This is the exact class docs/security/threat-
    # model.md section 1 and banking-poc scenario 6 (examples/banking-poc/
    # README.md) name as needing a SEPARATE mechanism (the forward-secure
    # seal, SPEC 11) — not a bug in verify_chain, and not something a chain-
    # only verifier can ever close, because a shorter-but-internally-
    # consistent chain IS a valid chain.
    def build() -> list[Entry]:
        chain = build_chain(N)
        del chain[-1]
        return chain

    return [
        MutationCase(
            label="tail_truncation@last",
            mutation_class="tail_truncation",
            build=build,
            expected_broken_seq=None,
            expected_reason=None,
            in_scope=False,
        )
    ]


def _whole_trail_rewrite_cases() -> list[MutationCase]:
    # OUT OF SCOPE, BY DESIGN (rule 9). threat-model.md section 1: entry_hash
    # is a pure function of the header, and prev_hash is just the previous
    # entry_hash, so an attacker with write access to storage can edit any
    # row and mechanically re-link every row after it. The re-chained suffix
    # is a genuinely self-consistent chain; verify_chain reporting `ok` here
    # is CORRECT, not a miss — closing this requires a copy the attacker
    # cannot write (anchor/witness/pin, banking-poc scenario 5), which is a
    # different mechanism entirely, not a verify_chain defect.
    cases = []
    for i in range(N):

        def build(i: int = i) -> list[Entry]:
            chain = build_chain(N)
            prev_before = chain[i - 1].entry_hash if i > 0 else GENESIS_PREV_HASH
            tampered = replace(
                chain[i].header, ts="2027-01-01T00:00:00+00:00", prev_hash=prev_before
            )
            chain[i] = replace(
                chain[i], header=tampered, entry_hash=compute_entry_hash(tampered)
            )
            _relink_from(chain, i + 1, chain[i].entry_hash)
            return chain

        cases.append(
            MutationCase(
                label=f"whole_trail_rewrite@{i}",
                mutation_class="whole_trail_rewrite",
                build=build,
                expected_broken_seq=None,
                expected_reason=None,
                in_scope=False,
            )
        )
    return cases


def _all_cases() -> list[MutationCase]:
    return [
        *_edit_header_field_cases(),
        *_flip_payload_bit_cases(),
        *_corrupt_entry_hash_cases(),
        *_corrupt_prev_hash_cases(),
        *_delete_non_tail_cases(),
        *_insert_record_cases(),
        *_reorder_adjacent_cases(),
        *_tail_truncation_cases(),
        *_whole_trail_rewrite_cases(),
    ]


class TestMutationCampaign:
    """The aggregate measurement item 6 of the paper conformance protocol
    (plan doc T4) asked for: two rates, reported and asserted separately,
    never collapsed into one pass/fail (this is itself the Ternary Evidence
    Principle applied to the test suite's own reporting, CLAUDE.md 'Named
    principle' -- a verifier's aggregate self-report must not let 'detected
    but misattributed' collapse into either 'caught it' or 'missed it')."""

    def test_campaign_measures_detection_rate_and_reason_accuracy_separately(self) -> None:
        cases = _all_cases()
        in_scope = [c for c in cases if c.in_scope]
        out_of_scope = [c for c in cases if not c.in_scope]
        assert in_scope, "campaign must exercise at least one in-scope mutation"
        assert out_of_scope, "the documented-limitation classes must not be silently dropped"

        detected = 0
        correct = 0
        undetected: list[str] = []
        misattributed: list[tuple[str, int | None, str | None]] = []

        for case in in_scope:
            result = verify_chain(case.build(), registry())
            if result.ok:
                undetected.append(case.label)
                continue
            detected += 1
            if (
                result.broken_seq == case.expected_broken_seq
                and result.reason == case.expected_reason
            ):
                correct += 1
            else:
                misattributed.append((case.label, result.broken_seq, result.reason))

        detection_rate = detected / len(in_scope)
        # Reason accuracy is conditioned on detection (bead wording: "of the
        # mutations that WERE detected"); division by zero would mean
        # detection_rate == 0 and the assertion below already fails first.
        reason_accuracy = correct / detected if detected else 0.0

        out_of_scope_reported_ok = sum(
            1 for case in out_of_scope if verify_chain(case.build(), registry()).ok
        )

        summary = (
            f"\nmutation campaign over {len(in_scope)} in-scope single-record mutations "
            f"({sorted({c.mutation_class for c in in_scope})}):\n"
            f"  detection rate  = {detected}/{len(in_scope)} = {detection_rate:.2%}\n"
            f"  reason accuracy = {correct}/{detected} = {reason_accuracy:.2%}"
            " (fraction of DETECTED mutations with the exact broken_seq + reason)\n"
            f"  out-of-scope (documented limitation, not counted above): "
            f"{out_of_scope_reported_ok}/{len(out_of_scope)} correctly reported `ok` "
            f"({sorted({c.mutation_class for c in out_of_scope})})\n"
        )
        print(summary)

        assert detection_rate == 1.0, (
            f"detection rate {detection_rate:.2%} < 100% for internally-observable "
            f"mutations; undetected: {undetected}"
        )
        assert reason_accuracy == 1.0, (
            f"reason accuracy {reason_accuracy:.2%} < 100% among detected mutations; "
            f"misattributed (label, broken_seq, reason): {misattributed}"
        )
        # The two documented-limitation classes: verify_chain must report
        # these `ok`, not "detected", not a crash -- reporting ANYTHING else
        # here would mean the harness's own ground truth is wrong, since this
        # is the one place the correct verdict is deliberately NOT `broken`.
        assert out_of_scope_reported_ok == len(out_of_scope), (
            "a documented-limitation mutation was reported as broken -- either "
            "the mutation builder is wrong, or verify_chain regressed"
        )
