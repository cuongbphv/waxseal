"""Tests for chain verification (SPEC.md section 5).

Covers the three chain invariants (deletion, insert/reorder, edit), payload
integrity, and the load-bearing behavior of this whole library: an unknown
fingerprint is UNVERIFIABLE, never TAMPERED, and never a crash.
"""

import hashlib
from dataclasses import replace

from waxseal.domain.fingerprint import fingerprint
from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash, header_frame
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.verify import VerifyResult, verify_chain


def build_chain(n: int) -> list[Entry]:
    entries: list[Entry] = []
    prev = GENESIS_PREV_HASH
    for i in range(n):
        payload = f'{{"i":{i}}}'.encode()
        header = EntryHeader(
            seq=i,
            ts=f"2026-08-21T06:00:{i:02d}+00:00",
            hash_version=fingerprint(),
            payload_type="application/vnd.test.event+json",
            payload_hash=compute_payload_hash(payload),
            prev_hash=prev,
        )
        entry_hash = compute_entry_hash(header)
        entries.append(Entry(header=header, entry_hash=entry_hash, payload=payload))
        prev = entry_hash
    return entries


def build_chain_v2(n: int) -> list[Entry]:
    """Same shape as build_chain, but every row is stamped and hashed under
    fingerprint()/header_frame/lp (waxseal-7tk.7.3)."""
    entries: list[Entry] = []
    prev = GENESIS_PREV_HASH
    for i in range(n):
        payload = f'{{"i":{i}}}'.encode()
        header = EntryHeader(
            seq=i,
            ts=f"2026-08-21T06:00:{i:02d}+00:00",
            hash_version=fingerprint(),
            payload_type="application/vnd.test.event+json",
            payload_hash=compute_payload_hash(payload),
            prev_hash=prev,
        )
        entry_hash = compute_entry_hash(header, frame=header_frame)
        entries.append(Entry(header=header, entry_hash=entry_hash, payload=payload))
        prev = entry_hash
    return entries


def registry() -> VersionRegistry:
    return VersionRegistry()


class _V1OnlyRegistry(VersionRegistry):
    """A registry frozen to "knows only v1" -- simulates an older build
    encountering rows written under an encoding it predates (waxseal-7tk.7.3).
    Subclassing VersionRegistry (rather than a bespoke stand-in) keeps this
    exercising the real recomputable()/encoder_for() logic, just seeded
    with one fewer built-in fingerprint."""

    def __init__(self) -> None:
        super().__init__()
        v2 = fingerprint()
        del self._schemas[v2]
        del self._encoding[v2]


class TestIntactChain:
    def test_empty_chain_is_ok(self) -> None:
        result = verify_chain([], registry())
        assert result.ok
        assert result.checked == 0

    def test_intact_chain_verifies(self) -> None:
        result = verify_chain(build_chain(5), registry())
        assert result == VerifyResult(
            ok=True,
            checked=5,
            broken_seq=None,
            reason=None,
            unverifiable=(),
            dropped_writes=None,
        )

    def test_dropped_writes_is_none_meaning_not_measured(self) -> None:
        # CLAUDE.md rule 5: None = not measured, never 0.
        assert verify_chain(build_chain(1), registry()).dropped_writes is None


class TestTamperDetection:
    def test_deleted_entry_reports_seq_gap(self) -> None:
        chain = build_chain(5)
        del chain[2]
        result = verify_chain(chain, registry())
        assert not result.ok
        assert result.broken_seq == 3
        assert result.reason == "seq_gap"
        assert result.checked == 2

    def test_missing_genesis_reports_seq_gap_at_first_entry(self) -> None:
        chain = build_chain(3)[1:]
        result = verify_chain(chain, registry())
        assert not result.ok
        assert result.broken_seq == 1
        assert result.reason == "seq_gap"

    def test_edited_header_reports_entry_hash_mismatch(self) -> None:
        chain = build_chain(5)
        tampered = replace(chain[2].header, ts="2027-01-01T00:00:00+00:00")
        chain[2] = replace(chain[2], header=tampered)
        result = verify_chain(chain, registry())
        assert not result.ok
        assert result.broken_seq == 2
        assert result.reason == "entry_hash_mismatch"

    def test_relinked_entry_reports_prev_hash_mismatch(self) -> None:
        # An attacker rewrites entry 2 completely (valid hash over new content)
        # but cannot fix entry 3's prev_hash without rewriting the whole suffix.
        chain = build_chain(5)
        forged_header = replace(chain[2].header, ts="2027-01-01T00:00:00+00:00")
        chain[2] = replace(
            chain[2], header=forged_header, entry_hash=compute_entry_hash(forged_header)
        )
        result = verify_chain(chain, registry())
        assert not result.ok
        assert result.broken_seq == 3
        assert result.reason == "prev_hash_mismatch"

    def test_tampered_payload_reports_payload_hash_mismatch(self) -> None:
        chain = build_chain(3)
        chain[1] = replace(chain[1], payload=b'{"i":999}')
        result = verify_chain(chain, registry())
        assert not result.ok
        assert result.broken_seq == 1
        assert result.reason == "payload_hash_mismatch"

    def test_unencodable_header_field_reports_entry_hash_mismatch_not_a_crash(
        self,
    ) -> None:
        # waxseal-lmv (never-raise fuzzing sweep): a lone UTF-16 surrogate in
        # a header field is valid `str` -- `json.loads('"\\ud800"')` produces
        # one, so an attacker-writable JSONL trail can carry it -- but has no
        # UTF-8 form, so `lp()` raises `LpEncodingError` (gap G4,
        # test_properties.py). That error was labelled at `lp()` but never
        # caught here, so it still escaped `verify_chain` uncaught: the exact
        # "NEVER a crash" promise CLAUDE.md's Locked Design section makes for
        # a recomputable row. A header this build cannot even encode can
        # never reproduce the stored hash, so this is the existing
        # `entry_hash_mismatch` finding, not a new incident class or a crash
        # (CLAUDE.md rules 4/5/6).
        chain = build_chain(3)
        tampered = replace(chain[1].header, ts="\ud800")
        chain[1] = replace(chain[1], header=tampered)
        result = verify_chain(chain, registry())
        assert not result.ok
        assert result.broken_seq == 1
        assert result.reason == "entry_hash_mismatch"

    def test_first_break_wins_checked_counts_rows_before_it(self) -> None:
        chain = build_chain(6)
        chain[2] = replace(chain[2], payload=b"tampered")
        chain[4] = replace(chain[4], payload=b"also tampered")
        result = verify_chain(chain, registry())
        assert result.broken_seq == 2
        assert result.checked == 2


class TestUnverifiable:
    """Unknown fingerprint = unverifiable by name. The beads-v1.2.2 scenario:
    an old binary meeting rows written by a newer schema must degrade
    gracefully, not report tampering, not crash."""

    def _chain_with_foreign_row(self) -> list[Entry]:
        chain = build_chain(4)
        # Row 2 was written by a "newer" schema this binary does not know.
        foreign_header = replace(chain[2].header, hash_version="e" * 64)
        foreign_hash = compute_entry_hash(foreign_header)
        chain[2] = replace(chain[2], header=foreign_header, entry_hash=foreign_hash)
        # Row 3 links through the foreign row's stored entry_hash.
        relinked = replace(chain[3].header, prev_hash=foreign_hash)
        chain[3] = replace(chain[3], header=relinked, entry_hash=compute_entry_hash(relinked))
        return chain

    def test_unknown_fingerprint_is_reported_unverifiable_not_tampered(self) -> None:
        result = verify_chain(self._chain_with_foreign_row(), registry())
        assert result.ok
        assert result.unverifiable == (2,)

    def test_chain_stays_linked_through_unverifiable_rows(self) -> None:
        # The stored entry_hash of the foreign row still anchors row 3.
        result = verify_chain(self._chain_with_foreign_row(), registry())
        assert result.broken_seq is None

    def test_unverifiable_rows_are_not_counted_as_checked(self) -> None:
        result = verify_chain(self._chain_with_foreign_row(), registry())
        assert result.checked == 3

    def test_tamper_after_unverifiable_row_is_still_detected(self) -> None:
        chain = self._chain_with_foreign_row()
        chain[3] = replace(chain[3], payload=b"tampered")
        result = verify_chain(chain, registry())
        assert not result.ok
        assert result.broken_seq == 3
        assert result.reason == "payload_hash_mismatch"

    def test_payload_of_unverifiable_row_is_left_alone(self) -> None:
        # We must not judge a foreign row's payload against a schema we cannot
        # verify — even a mismatching payload_hash is out of scope for it.
        chain = self._chain_with_foreign_row()
        chain[2] = replace(chain[2], payload=b"anything")
        result = verify_chain(chain, registry())
        assert result.ok
        assert result.unverifiable == (2,)


class TestRegisteredButNotRecomputable:
    """The migration-060 class through the SUPPORTED api: register() maps a
    new field set to its fingerprint, but this build's hasher only implements
    the v1 frame. Recomputing a registered-but-different schema under the v1
    frame would misreport every such row as tampered — strictly worse than an
    unknown fingerprint, which already degrades to unverifiable."""

    def _chain_with_registered_foreign_row(self, reg: VersionRegistry) -> list[Entry]:
        fp2 = reg.register(
            ("seq", "ts", "hash_version", "payload_type", "payload_hash", "prev_hash", "actor")
        )
        chain = build_chain(4)
        foreign_header = replace(chain[2].header, hash_version=fp2)
        # The stored hash a newer writer produced under ITS frame; this build
        # cannot reproduce it and must not try.
        foreign_hash = "f" * 64
        chain[2] = replace(chain[2], header=foreign_header, entry_hash=foreign_hash)
        relinked = replace(chain[3].header, prev_hash=foreign_hash)
        chain[3] = replace(chain[3], header=relinked, entry_hash=compute_entry_hash(relinked))
        return chain

    def test_registered_non_v1_schema_is_unverifiable_not_tampered(self) -> None:
        reg = registry()
        result = verify_chain(self._chain_with_registered_foreign_row(reg), reg)
        assert result.ok
        assert result.reason is None
        assert result.unverifiable == (2,)

    def test_registered_non_v1_rows_are_not_counted_as_checked(self) -> None:
        reg = registry()
        result = verify_chain(self._chain_with_registered_foreign_row(reg), reg)
        assert result.checked == 3

    def test_v1_fingerprint_is_recomputable(self) -> None:
        assert registry().recomputable(fingerprint())

    def test_registered_non_v1_fingerprint_is_not_recomputable(self) -> None:
        reg = registry()
        fp2 = reg.register(("seq", "ts", "actor"))
        assert reg.knows(fp2)
        assert not reg.recomputable(fp2)

    def test_unknown_fingerprint_is_not_recomputable(self) -> None:
        assert not registry().recomputable("e" * 64)


class TestLp64V2Verification:
    """The real second encoding, not a hypothetical widened-field-tuple
    stand-in (waxseal-7tk.7.3): a row stamped with fingerprint() must
    verify `ok` through registry.encoder_for() dispatch to header_frame,
    and must degrade to `unverifiable` -- never `broken` -- for a registry
    that does not know fingerprint() at all. This is the concrete
    instance, for lp64v2 specifically, of the migration-060 / beads-v1.2.2
    failure class the whole project exists to make unrepresentable."""

    def test_v2_stamped_chain_verifies_ok_against_a_registry_that_knows_v2(self) -> None:
        result = verify_chain(build_chain_v2(4), registry())
        assert result.ok is True
        assert result.checked == 4
        assert result.unverifiable == ()
        assert result.broken_seq is None

    def test_v2_stamped_row_unverifiable_not_broken_when_registry_predates_v2(self) -> None:
        # The exact scenario CLAUDE.md names: an older build (here, a
        # registry that only ever learned fingerprint()) meeting a row
        # written under a newer encoding it does not recognize.
        chain = build_chain_v2(4)
        result = verify_chain(chain, _V1OnlyRegistry())
        assert result.ok is True
        assert result.broken_seq is None
        assert result.reason is None
        assert result.unverifiable == (0, 1, 2, 3)
        assert result.checked == 0

    def test_tampered_v2_stamped_row_is_still_caught_as_broken(self) -> None:
        # The v2 path must not weaken tamper detection: mirrors
        # TestTamperDetection.test_edited_header_reports_entry_hash_mismatch
        # but on a v2-stamped chain.
        chain = build_chain_v2(5)
        tampered = replace(chain[2].header, ts="2027-01-01T00:00:00+00:00")
        chain[2] = replace(chain[2], header=tampered)
        result = verify_chain(chain, registry())
        assert not result.ok
        assert result.broken_seq == 2
        assert result.reason == "entry_hash_mismatch"

    def test_tampered_v2_stamped_payload_is_still_caught_as_broken(self) -> None:
        chain = build_chain_v2(3)
        chain[1] = replace(chain[1], payload=b'{"i":999}')
        result = verify_chain(chain, registry())
        assert not result.ok
        assert result.broken_seq == 1
        assert result.reason == "payload_hash_mismatch"


class TestPayloadAbsent:
    def test_header_only_reader_skips_payload_check(self) -> None:
        # SPEC 5.4: payload check only "if payload bytes are available".
        chain = build_chain(3)
        headers_only = [replace(e, payload=None) for e in chain]
        result = verify_chain(headers_only, registry())
        assert result.ok
        assert result.checked == 3

    def test_wrong_payload_hash_in_header_breaks_chain_even_without_payload(self) -> None:
        chain = build_chain(3)
        bad_header = replace(chain[1].header, payload_hash=hashlib.sha256(b"lie").hexdigest())
        chain[1] = replace(chain[1], header=bad_header, payload=None)
        result = verify_chain(chain, registry())
        assert not result.ok
        assert result.reason == "entry_hash_mismatch"


class TestDropsSource:
    """drops_source: a trailing-default field (M5) — every construction
    site above this class predates it and must keep working unchanged."""

    def test_verify_chain_defaults_drops_source_to_none(self) -> None:
        result = verify_chain(build_chain(2), registry())
        assert result.drops_source is None

    def test_replace_can_set_drops_source_without_touching_other_fields(self) -> None:
        result = verify_chain(build_chain(2), registry())
        with_source = replace(result, dropped_writes=3, drops_source="sidecar")
        assert with_source.drops_source == "sidecar"
        assert with_source.dropped_writes == 3
        assert with_source.ok == result.ok
        assert with_source.checked == result.checked

    def test_positional_construction_still_works_without_drops_source(self) -> None:
        # Pins that the field is genuinely trailing-default: an old caller
        # naming every field but this one must not break.
        result = VerifyResult(
            ok=True, checked=0, broken_seq=None, reason=None, unverifiable=(), dropped_writes=None
        )
        assert result.drops_source is None
