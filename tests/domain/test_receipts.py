"""Tests for the per-append receipt sidecar's pure half (domain/receipts.py).

SPEC.md section 19. A receipt is a second authority's acknowledgment, made at
write time, that entry `seq` carried `entry_hash` the moment it was accepted.
Reconciling it against the trail is a DETERMINISTIC comparison — the same
footing as a pin — so its failures are breaks, never unverifiable.

The five reasons SPEC section 19 (plus the waxseal-fg4.9 append) tabulates,
and the exit code each carries:

| receipt_mismatch                     | 1 |
| receipt_beyond_head                  | 1 |
| malformed_receipt_record             | 1 |
| unreadable_record_version            | 2 |
| unrecognized_receipt_frame_fingerprint | 2 |

The exit-1/exit-2 split is section 17's asymmetry, and it is the one thing in
this file that must never be collapsed: corrupt bytes in a format THIS project
defines are a break, while a record version only a NEWER build understands is
unverifiable by name (the beads-v1.2.2 lesson applied to the sidecar's own
format). waxseal-fg4.9 adds a SECOND, independent instance of the same split:
`unreadable_record_version` is about the RECORD's own shape (`v`);
`unrecognized_receipt_frame_fingerprint` is about the receipt_head HASH
FRAME's derived identity -- a different axis, tested separately below, never
collapsed into the first.
"""

from __future__ import annotations

import json

from waxseal.domain.receipt_fingerprint import receipt_fingerprint, receipt_fingerprint_for
from waxseal.domain.receipts import (
    MALFORMED_RECEIPT_RECORD,
    RECEIPT_BEYOND_HEAD,
    RECEIPT_FRAME_FINGERPRINT_FIELD,
    RECEIPT_MISMATCH,
    RECEIPT_RECORD_VERSION,
    UNREADABLE_RECORD_VERSION,
    UNRECOGNIZED_RECEIPT_FRAME_FINGERPRINT,
    MalformedRecord,
    ReceiptRecord,
    ReceiptSidecar,
    UnreadableRecord,
    UnrecognizedReceiptFrame,
    build_receipt_record,
    parse_receipt_line,
    reconcile_receipts,
)
from waxseal.domain.registry import ReceiptFrameRegistry
from waxseal.domain.verdict import Verdict

H0 = "a" * 64
H1 = "b" * 64
H2 = "c" * 64
HEAD = "d" * 64


def record_line(
    *,
    seq: int = 0,
    entry_hash: str = H0,
    receipt_seq: int = 0,
    receipt_head: str = HEAD,
    source: str = "https://ledger.example",
    ts: str = "2026-09-01T00:00:00+00:00",
) -> str:
    return json.dumps(
        build_receipt_record(
            seq=seq,
            entry_hash=entry_hash,
            receipt_seq=receipt_seq,
            receipt_head=receipt_head,
            source=source,
            ts=ts,
        ),
        sort_keys=True,
        separators=(",", ":"),
    )


def sidecar(*lines: str) -> ReceiptSidecar:
    return ReceiptSidecar(
        present=True,
        lines=tuple(parse_receipt_line(line, line_no=i) for i, line in enumerate(lines, start=1)),
    )


class TestRecordShape:
    def test_record_carries_exactly_the_keys_spec_19_names(self) -> None:
        record = build_receipt_record(
            seq=3,
            entry_hash=H0,
            receipt_seq=7,
            receipt_head=HEAD,
            source="https://ledger.example",
            ts="2026-09-01T00:00:00+00:00",
        )
        assert set(record) == {
            "entry_hash",
            RECEIPT_FRAME_FINGERPRINT_FIELD,
            "receipt_head",
            "receipt_seq",
            "seq",
            "source",
            "ts",
            "v",
        }
        assert record["v"] == RECEIPT_RECORD_VERSION
        # waxseal-fg4.9: derived, never a hand-written literal (CLAUDE.md
        # locked design, the same rule hash_version already follows).
        assert record[RECEIPT_FRAME_FINGERPRINT_FIELD] == receipt_fingerprint()

    def test_record_round_trips_through_the_parser(self) -> None:
        parsed = parse_receipt_line(record_line(seq=3, receipt_seq=7), line_no=1)
        assert parsed == ReceiptRecord(
            line_no=1,
            seq=3,
            entry_hash=H0,
            receipt_seq=7,
            receipt_head=HEAD,
            source="https://ledger.example",
            ts="2026-09-01T00:00:00+00:00",
        )
        assert isinstance(parsed, ReceiptRecord)
        assert parsed.receipt_frame_fingerprint == receipt_fingerprint()


class TestParseClassification:
    """Which bytes are a break and which are unverifiable — section 17's
    asymmetry, decided at parse time before any comparison happens."""

    def test_bytes_that_are_not_json_are_malformed(self) -> None:
        parsed = parse_receipt_line("{not json", line_no=4)
        assert isinstance(parsed, MalformedRecord)
        assert parsed.line_no == 4

    def test_a_json_array_is_malformed(self) -> None:
        assert isinstance(parse_receipt_line("[1, 2]", line_no=1), MalformedRecord)

    def test_a_record_missing_entry_hash_is_malformed(self) -> None:
        obj = json.loads(record_line())
        del obj["entry_hash"]
        assert isinstance(parse_receipt_line(json.dumps(obj), line_no=1), MalformedRecord)

    def test_a_non_hex_entry_hash_is_malformed(self) -> None:
        assert isinstance(
            parse_receipt_line(record_line(entry_hash="z" * 64), line_no=1), MalformedRecord
        )

    def test_a_non_hex_receipt_head_is_malformed(self) -> None:
        assert isinstance(
            parse_receipt_line(record_line(receipt_head="short"), line_no=1), MalformedRecord
        )

    def test_a_negative_seq_is_malformed(self) -> None:
        assert isinstance(parse_receipt_line(record_line(seq=-1), line_no=1), MalformedRecord)

    def test_a_negative_receipt_seq_is_malformed(self) -> None:
        assert isinstance(
            parse_receipt_line(record_line(receipt_seq=-1), line_no=1), MalformedRecord
        )

    def test_a_non_integer_seq_is_malformed(self) -> None:
        obj = json.loads(record_line())
        obj["seq"] = "three"
        assert isinstance(parse_receipt_line(json.dumps(obj), line_no=1), MalformedRecord)

    def test_a_boolean_seq_is_malformed(self) -> None:
        # bool is an int in Python: `True` must not silently become seq 1.
        obj = json.loads(record_line())
        obj["seq"] = True
        assert isinstance(parse_receipt_line(json.dumps(obj), line_no=1), MalformedRecord)

    def test_a_newer_version_is_unreadable_not_malformed(self) -> None:
        obj = json.loads(record_line())
        obj["v"] = 2
        parsed = parse_receipt_line(json.dumps(obj), line_no=9)
        assert parsed == UnreadableRecord(line_no=9, version="2")

    def test_version_is_read_before_content_so_a_newer_record_is_never_a_break(self) -> None:
        # The whole point of the asymmetry: this build cannot judge the
        # CONTENT of a shape it does not know, so it must not call it corrupt.
        obj = json.loads(record_line())
        obj["v"] = 99
        obj["entry_hash"] = "not-a-hash-in-this-build"
        assert isinstance(parse_receipt_line(json.dumps(obj), line_no=1), UnreadableRecord)

    def test_a_version_stamp_that_is_not_an_integer_is_malformed(self) -> None:
        # Found by the never-raise fuzz sweep, which crashed here on an
        # unhashable `v`. The classification is the interesting half: SPEC
        # section 19 fixes `v` as an integer, so a list/string/object can never
        # be "a version a newer build understands" — treating it as one would
        # hand an attacker a lever to downgrade any break to exit 2 just by
        # scribbling on the version field.
        bad_values: tuple[object, ...] = ([], {}, "1", None, True)
        for bad in bad_values:
            obj = json.loads(record_line())
            obj["v"] = bad
            parsed = parse_receipt_line(json.dumps(obj), line_no=1)
            assert isinstance(parsed, MalformedRecord), bad

    def test_missing_source_and_ts_are_metadata_and_do_not_break_a_record(self) -> None:
        obj = json.loads(record_line())
        del obj["source"]
        del obj["ts"]
        parsed = parse_receipt_line(json.dumps(obj), line_no=1)
        assert isinstance(parsed, ReceiptRecord)
        assert parsed.source == "unknown"
        assert parsed.ts == ""


class TestReceiptFrameFingerprint:
    """waxseal-fg4.9: the receipt_head hash frame's derived identity, checked
    the way an unknown `hash_version` is already checked elsewhere in this
    codebase (`domain/registry.py::VersionRegistry.recomputable`,
    `domain/verify.py`) -- unrecognized is unverifiable (exit 2), never a
    break, and is never confused with `v` (the record's own shape, tested
    above)."""

    def test_a_released_receipt_with_no_declared_frame_verifies_under_this_builds_identity(
        self,
    ) -> None:
        # The whole point (constraint 1): every receipt issued before this
        # change has no RECEIPT_FRAME_FINGERPRINT_FIELD key at all -- deleted
        # here to reconstruct that shape, since build_receipt_record now
        # always stamps it.
        obj = json.loads(record_line())
        del obj[RECEIPT_FRAME_FINGERPRINT_FIELD]
        parsed = parse_receipt_line(json.dumps(obj), line_no=1)
        assert isinstance(parsed, ReceiptRecord)
        assert parsed.receipt_frame_fingerprint == receipt_fingerprint()

    def test_this_builds_own_declared_frame_is_recognized(self) -> None:
        assert isinstance(parse_receipt_line(record_line(), line_no=1), ReceiptRecord)

    def test_build_receipt_record_accepts_an_explicit_fingerprint(self) -> None:
        # Exercised for a registered-but-alternate identity (e.g. a widened
        # future frame this build also knows how to declare), not because any
        # call site in this codebase should spell one out by hand.
        record = build_receipt_record(
            seq=0,
            entry_hash=H0,
            receipt_seq=0,
            receipt_head=HEAD,
            source="s",
            ts="t",
            receipt_frame_fingerprint="f" * 64,
        )
        assert record[RECEIPT_FRAME_FINGERPRINT_FIELD] == "f" * 64

    def test_an_unrecognized_declared_frame_is_unverifiable_not_malformed(self) -> None:
        obj = json.loads(record_line())
        obj[RECEIPT_FRAME_FINGERPRINT_FIELD] = "f" * 64
        parsed = parse_receipt_line(json.dumps(obj), line_no=5)
        assert parsed == UnrecognizedReceiptFrame(line_no=5, fingerprint="f" * 64)

    def test_frame_identity_is_read_before_content_so_it_is_never_a_break(self) -> None:
        # Mirrors test_version_is_read_before_content_so_a_newer_record_is_never_a_break:
        # this build must not judge the record's OTHER fields under a receipt
        # frame it does not recognize.
        obj = json.loads(record_line())
        obj[RECEIPT_FRAME_FINGERPRINT_FIELD] = "f" * 64
        obj["entry_hash"] = "not-a-hash-in-this-build"
        assert isinstance(parse_receipt_line(json.dumps(obj), line_no=1), UnrecognizedReceiptFrame)

    def test_a_non_hex64_declared_frame_is_malformed(self) -> None:
        # This project's own field failing to parse -- section 17's break
        # side, not the "newer build" side.
        obj = json.loads(record_line())
        obj[RECEIPT_FRAME_FINGERPRINT_FIELD] = "not-a-fingerprint"
        assert isinstance(parse_receipt_line(json.dumps(obj), line_no=1), MalformedRecord)

    def test_a_non_string_declared_frame_is_malformed(self) -> None:
        obj = json.loads(record_line())
        obj[RECEIPT_FRAME_FINGERPRINT_FIELD] = 12345
        assert isinstance(parse_receipt_line(json.dumps(obj), line_no=1), MalformedRecord)

    def test_widening_the_receipt_frame_field_set_changes_the_fingerprint(self) -> None:
        # The migration-060 protection this bead exists to give the receipt
        # frame: SPEC.md section 19's three receipt_head inputs, plus one,
        # cannot keep today's identity.
        from waxseal.domain.receipt_fingerprint import RECEIPT_FRAME_FIELDS

        widened = (*RECEIPT_FRAME_FIELDS, "chain_id")
        assert receipt_fingerprint_for(widened) != receipt_fingerprint()

    def test_a_registry_that_recognizes_the_value_accepts_it(self) -> None:
        # A caller-supplied registry (adapters/receipts.py builds one once per
        # read) is honored over the default, the same shape parse_receipt_line
        # already offers verify_chain-style callers.
        registry = ReceiptFrameRegistry()
        obj = json.loads(record_line())
        parsed = parse_receipt_line(json.dumps(obj), line_no=1, registry=registry)
        assert isinstance(parsed, ReceiptRecord)

    def test_falsifiability_a_registry_that_never_checks_would_silently_accept_anything(
        self,
    ) -> None:
        """Falsifiability receipt (Step 5): a registry that always claims to
        recognize a fingerprint -- the collapse this bead exists to prevent,
        constructed directly rather than by reverting history, since the
        check did not exist in any released build to revert to -- makes an
        ALIEN frame identity silently pass as a ReceiptRecord. The real
        (append-only) registry, same input, correctly reports it unverifiable.
        This is the "unknown vs broken" collapse CLAUDE.md's Named Principle
        describes, rebuilt on purpose to prove the fix is the thing standing
        between it and this file.
        """

        class _NaiveRegistryThatChecksNothing:
            def knows(self, fingerprint_: str) -> bool:  # noqa: ARG002 - the point
                return True  # the migration-060 collapse: always "known"

        alien = "e" * 64
        obj = json.loads(record_line())
        obj[RECEIPT_FRAME_FINGERPRINT_FIELD] = alien

        naive = parse_receipt_line(
            json.dumps(obj),
            line_no=1,
            registry=_NaiveRegistryThatChecksNothing(),  # type: ignore[arg-type]
        )
        assert isinstance(naive, ReceiptRecord), "naive registry: red without the real check"

        fixed = parse_receipt_line(json.dumps(obj), line_no=1, registry=ReceiptFrameRegistry())
        assert fixed == UnrecognizedReceiptFrame(line_no=1, fingerprint=alien)
        result = reconcile_receipts([H0], ReceiptSidecar(present=True, lines=(fixed,)))
        assert result.verdict.to_exit_code() == 2


class TestReconcileAgreement:
    def test_records_matching_the_trail_are_ok(self) -> None:
        result = reconcile_receipts(
            [H0, H1], sidecar(record_line(seq=0, entry_hash=H0), record_line(seq=1, entry_hash=H1))
        )
        assert result.verdict is Verdict.OK
        assert result.reason is None
        assert result.checked == 2
        assert result.broken_seq is None

    def test_a_sidecar_that_acknowledges_only_a_prefix_is_ok(self) -> None:
        # Receipts are best-effort: a miss is a gap in corroboration, never a
        # claim that the un-acknowledged entries are wrong.
        result = reconcile_receipts([H0, H1, H2], sidecar(record_line(seq=0, entry_hash=H0)))
        assert result.verdict is Verdict.OK
        assert result.checked == 1


class TestReconcileBreaks:
    def test_a_changed_entry_hash_is_receipt_mismatch_at_that_seq(self) -> None:
        result = reconcile_receipts(
            [H0, "f" * 64],
            sidecar(record_line(seq=0, entry_hash=H0), record_line(seq=1, entry_hash=H1)),
        )
        assert result.verdict is Verdict.BROKEN
        assert result.reason == RECEIPT_MISMATCH
        assert result.broken_seq == 1
        assert result.verdict.to_exit_code() == 1

    def test_a_trail_shorter_than_an_acknowledged_append_is_receipt_beyond_head(self) -> None:
        result = reconcile_receipts([H0], sidecar(record_line(seq=1, entry_hash=H1)))
        assert result.verdict is Verdict.BROKEN
        assert result.reason == RECEIPT_BEYOND_HEAD
        assert result.broken_seq == 1
        assert result.verdict.to_exit_code() == 1

    def test_an_empty_trail_with_an_acknowledged_append_is_beyond_head(self) -> None:
        result = reconcile_receipts([], sidecar(record_line(seq=0, entry_hash=H0)))
        assert result.reason == RECEIPT_BEYOND_HEAD
        assert result.broken_seq == 0

    def test_a_malformed_record_is_a_break_not_unverifiable(self) -> None:
        result = reconcile_receipts([H0], sidecar("{not json"))
        assert result.verdict is Verdict.BROKEN
        assert result.reason == MALFORMED_RECEIPT_RECORD
        assert result.broken_line == 1
        # A malformed record names no trustworthy seq: reporting one would be
        # inventing the very field that failed to parse.
        assert result.broken_seq is None
        assert result.verdict.to_exit_code() == 1

    def test_the_first_break_in_file_order_is_the_one_reported(self) -> None:
        result = reconcile_receipts(
            ["f" * 64, "f" * 64],
            sidecar(record_line(seq=0, entry_hash=H0), "{not json"),
        )
        assert result.reason == RECEIPT_MISMATCH
        assert result.broken_seq == 0


class TestReconcileUnverifiable:
    def test_a_newer_record_version_is_exit_2_not_exit_1(self) -> None:
        obj = json.loads(record_line())
        obj["v"] = 2
        result = reconcile_receipts([H0], sidecar(json.dumps(obj)))
        assert result.verdict is Verdict.UNVERIFIABLE
        assert result.reason == UNREADABLE_RECORD_VERSION
        assert result.unreadable_versions == ("2",)
        assert result.verdict.to_exit_code() == 2

    def test_a_real_break_outranks_an_unreadable_version(self) -> None:
        # Verdict.join in true severity order: 2 is the larger exit code but
        # the weaker finding, and an unreadable record must never mask a break.
        obj = json.loads(record_line(seq=1, entry_hash=H1))
        obj["v"] = 2
        result = reconcile_receipts(
            [H0], sidecar(record_line(seq=0, entry_hash=H1), json.dumps(obj))
        )
        assert result.verdict is Verdict.BROKEN
        assert result.reason == RECEIPT_MISMATCH
        assert result.unreadable_versions == ("2",)

    def test_an_unrecognized_receipt_frame_is_exit_2_not_exit_1(self) -> None:
        # Constraint 6: mirrors test_a_newer_record_version_is_exit_2_not_exit_1
        # for the SECOND identity axis (receipt_head's frame, not `v`).
        obj = json.loads(record_line())
        obj[RECEIPT_FRAME_FINGERPRINT_FIELD] = "f" * 64
        result = reconcile_receipts([H0], sidecar(json.dumps(obj)))
        assert result.verdict is Verdict.UNVERIFIABLE
        assert result.reason == UNRECOGNIZED_RECEIPT_FRAME_FINGERPRINT
        assert result.unrecognized_receipt_fingerprints == ("f" * 64,)
        assert result.verdict.to_exit_code() == 2
        # The unreadable_versions axis stays untouched -- the two never merge.
        assert result.unreadable_versions == ()

    def test_a_real_break_outranks_an_unrecognized_receipt_frame(self) -> None:
        obj = json.loads(record_line(seq=1, entry_hash=H1))
        obj[RECEIPT_FRAME_FINGERPRINT_FIELD] = "f" * 64
        result = reconcile_receipts(
            [H0], sidecar(record_line(seq=0, entry_hash=H1), json.dumps(obj))
        )
        assert result.verdict is Verdict.BROKEN
        assert result.reason == RECEIPT_MISMATCH
        assert result.unrecognized_receipt_fingerprints == ("f" * 64,)


class TestAbsentIsNotEmpty:
    """Rule 5, one sidecar over from section 12's own absent-vs-empty rule."""

    def test_an_absent_sidecar_is_ok_and_says_so(self) -> None:
        result = reconcile_receipts([H0], ReceiptSidecar(present=False))
        assert result.verdict is Verdict.OK
        assert result.present is False
        assert result.checked == 0
        assert result.reason is None

    def test_a_present_empty_sidecar_is_distinct_from_an_absent_one(self) -> None:
        result = reconcile_receipts([H0], ReceiptSidecar(present=True))
        assert result.verdict is Verdict.OK
        assert result.present is True
        assert result.checked == 0

    def test_an_absent_sidecar_never_fails_even_against_an_empty_trail(self) -> None:
        assert reconcile_receipts([], ReceiptSidecar(present=False)).verdict is Verdict.OK
