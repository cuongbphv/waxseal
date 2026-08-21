"""Tests for chain verification (SPEC.md section 5).

Covers the three chain invariants (deletion, insert/reorder, edit), payload
integrity, and the load-bearing behavior of this whole library: an unknown
fingerprint is UNVERIFIABLE, never TAMPERED, and never a crash.
"""

import hashlib
from dataclasses import replace

from waxseal.domain.fingerprint import fingerprint_v1
from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
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
            hash_version=fingerprint_v1(),
            payload_type="application/vnd.test.event+json",
            payload_hash=compute_payload_hash(payload),
            prev_hash=prev,
        )
        entry_hash = compute_entry_hash(header)
        entries.append(Entry(header=header, entry_hash=entry_hash, payload=payload))
        prev = entry_hash
    return entries


def registry() -> VersionRegistry:
    return VersionRegistry()


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
        assert registry().recomputable(fingerprint_v1())

    def test_registered_non_v1_fingerprint_is_not_recomputable(self) -> None:
        reg = registry()
        fp2 = reg.register(("seq", "ts", "actor"))
        assert reg.knows(fp2)
        assert not reg.recomputable(fp2)

    def test_unknown_fingerprint_is_not_recomputable(self) -> None:
        assert not registry().recomputable("e" * 64)


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
