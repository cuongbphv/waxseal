"""Tests for cross-trail handoff binding + transitive anchoring (SPEC D3).

``record_handoff`` writes a minimal pointer entry -- (chain_id, seq,
head_hash) -- onto a DELEGATE's own trail, naming a moment in an ORIGIN
trail it does not otherwise touch. Once any later entry on the delegate's
trail is anchored (a Merkle batch root over its entry hashes), that root
transitively pins the origin's prefix up to the recorded seq: reading the
bound entry back off the anchored batch and comparing it against the
origin's own current entry hashes reveals whether the origin has been
rewritten since the handoff. This file proves that composition end to end,
for a 2-level delegation (A -> B) and a 2-hop one (A -> B -> C), and confirms
the one property CLAUDE.md forbids breaking: deleting the handoff payload
must report the row unverifiable-by-availability, never tampered.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from waxseal import AuditLog
from waxseal.domain.anchoring import membership_proof, verify_membership
from waxseal.domain.checkpoint import checkpoint_for
from waxseal.domain.fingerprint import fingerprint
from waxseal.domain.handoff import (
    HANDOFF_PAYLOAD_TYPE,
    HandoffBinding,
    binding_holds,
    from_payload,
)
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.verify import verify_chain
from waxseal.sources.handoff import record_handoff

FIXED_TS = "2026-08-29T09:00:00+00:00"
OTHER_PT = "application/vnd.test.event+json"


def open_log(path: Path) -> AuditLog:
    return AuditLog.open(path, now_fn=lambda: FIXED_TS)


def fill(log: AuditLog, n: int, *, prefix: str = "e") -> None:
    for i in range(n):
        log.append(payload={"i": i, "tag": prefix}, payload_type=OTHER_PT)


def tip(log: AuditLog) -> tuple[int, str]:
    entries = list(log.entries())
    last = entries[-1]
    return last.header.seq, last.entry_hash


class TestRecordHandoff:
    def test_entry_carries_the_handoff_payload_type(self, tmp_path: Path) -> None:
        log_a = open_log(tmp_path / "a.jsonl")
        fill(log_a, 2)
        seq_a, hash_a = tip(log_a)

        log_b = open_log(tmp_path / "b.jsonl")
        entry = record_handoff(log_b, chain_id="agent-a", seq=seq_a, head_hash=hash_a)
        assert entry.header.payload_type == HANDOFF_PAYLOAD_TYPE

    def test_payload_is_exactly_the_pointer_triple(self, tmp_path: Path) -> None:
        log_a = open_log(tmp_path / "a.jsonl")
        fill(log_a, 1)
        seq_a, hash_a = tip(log_a)

        log_b = open_log(tmp_path / "b.jsonl")
        entry = record_handoff(log_b, chain_id="agent-a", seq=seq_a, head_hash=hash_a)
        assert entry.payload is not None
        payload = json.loads(entry.payload)
        assert payload == {"chain_id": "agent-a", "seq": seq_a, "head_hash": hash_a}

    def test_handoff_entry_uses_the_same_fingerprint_as_every_other_entry(
        self, tmp_path: Path
    ) -> None:
        # D2/D3 measurement: a new PAYLOAD_TYPE does not create a new
        # hash_version. fingerprint() is computed over (algorithm, encoding,
        # HEADER FIELD NAMES) -- payload_type's per-entry VALUE never enters
        # it (domain/fingerprint.py:29-36).
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload={"i": 0}, payload_type=OTHER_PT)
        entry = record_handoff(log, chain_id="agent-a", seq=0, head_hash="a" * 64)
        assert entry.header.hash_version == fingerprint()
        assert log.verify().ok

    def test_recorded_binding_chains_and_verifies(self, tmp_path: Path) -> None:
        log_a = open_log(tmp_path / "a.jsonl")
        fill(log_a, 3)
        seq_a, hash_a = tip(log_a)

        log_b = open_log(tmp_path / "b.jsonl")
        record_handoff(log_b, chain_id="agent-a", seq=seq_a, head_hash=hash_a)
        fill(log_b, 2)
        assert log_b.verify().ok

    def test_jsonl_and_sqlite_produce_identical_entry_hashes(self, tmp_path: Path) -> None:
        jsonl_entry = record_handoff(
            open_log(tmp_path / "t.jsonl"), chain_id="agent-a", seq=0, head_hash="a" * 64
        )
        sqlite_entry = record_handoff(
            open_log(tmp_path / "t.db"), chain_id="agent-a", seq=0, head_hash="a" * 64
        )
        assert jsonl_entry.entry_hash == sqlite_entry.entry_hash
        assert jsonl_entry.payload == sqlite_entry.payload


class TestTransitiveAnchoringTwoLevel:
    """A delegates to B. Anchoring B's trail transitively pins A's prefix."""

    def _build(self, tmp_path: Path) -> tuple[AuditLog, AuditLog, int, str]:
        log_a = open_log(tmp_path / "a.jsonl")
        fill(log_a, 3, prefix="a")
        seq_a, hash_a = tip(log_a)

        log_b = open_log(tmp_path / "b.jsonl")
        record_handoff(log_b, chain_id="agent-a", seq=seq_a, head_hash=hash_a)
        fill(log_b, 2, prefix="b")
        return log_a, log_b, seq_a, hash_a

    def test_anchoring_b_transitively_pins_as_prefix(self, tmp_path: Path) -> None:
        log_a, log_b, seq_a, hash_a = self._build(tmp_path)

        b_hashes = log_b.entry_hashes()
        b_entries = list(log_b.entries())
        checkpoint = checkpoint_for(b_hashes)

        # Delegate-side leg: the handoff entry (index 0) is really part of
        # B's anchored batch -- ordinary membership_proof/verify_membership,
        # reused rather than reinvented.
        proof = membership_proof(b_hashes, 0)
        assert verify_membership(
            entry_hash=b_entries[0].entry_hash,
            index=0,
            batch_size=len(b_hashes),
            proof=proof,
            root=checkpoint.root,
        )

        # Origin-side leg: the binding this anchored entry carries still
        # names exactly A's current head at seq_a.
        assert b_entries[0].payload is not None
        binding = from_payload(json.loads(b_entries[0].payload))
        assert binding == HandoffBinding(chain_id="agent-a", seq=seq_a, head_hash=hash_a)
        assert binding_holds(binding, log_a.entry_hashes()) is True

    def test_transitive_pin_catches_a_whole_trail_rewrite_of_the_origin(
        self, tmp_path: Path
    ) -> None:
        _, log_b, seq_a, hash_a = self._build(tmp_path)
        b_entries = list(log_b.entries())
        assert b_entries[0].payload is not None
        binding = from_payload(json.loads(b_entries[0].payload))

        # An attacker replaces A's ENTIRE trail with a different, but
        # self-consistent, one -- the "whole-trail rewrite" anchoring.py's
        # module docstring names as what a hash chain alone cannot resist.
        rewritten_a = open_log(tmp_path / "a-rewritten.jsonl")
        fill(rewritten_a, 3, prefix="a-different-content")
        assert rewritten_a.verify().ok  # passes ITS OWN check; that is the threat

        # B's anchored binding still names the ORIGINAL head, so the
        # rewrite is caught the moment it is compared against the binding.
        assert binding_holds(binding, rewritten_a.entry_hashes()) is False
        assert binding.seq == seq_a
        assert binding.head_hash == hash_a


class TestMultiHopDelegation:
    """A -> B -> C. Anchoring C pins BOTH B's and A's prefixes."""

    def _build(
        self, tmp_path: Path
    ) -> tuple[AuditLog, AuditLog, AuditLog, int, str, int, str]:
        log_a = open_log(tmp_path / "a.jsonl")
        fill(log_a, 2, prefix="a")
        seq_a, hash_a = tip(log_a)

        log_b = open_log(tmp_path / "b.jsonl")
        record_handoff(log_b, chain_id="agent-a", seq=seq_a, head_hash=hash_a)
        fill(log_b, 2, prefix="b")
        seq_b, hash_b = tip(log_b)

        log_c = open_log(tmp_path / "c.jsonl")
        record_handoff(log_c, chain_id="agent-b", seq=seq_b, head_hash=hash_b)
        fill(log_c, 2, prefix="c")
        return log_a, log_b, log_c, seq_a, hash_a, seq_b, hash_b

    def test_anchoring_c_transitively_pins_b_and_a(self, tmp_path: Path) -> None:
        log_a, log_b, log_c, seq_a, hash_a, seq_b, hash_b = self._build(tmp_path)

        assert log_b.verify().ok
        assert log_c.verify().ok

        c_hashes = log_c.entry_hashes()
        c_entries = list(log_c.entries())
        checkpoint_c = checkpoint_for(c_hashes)

        proof = membership_proof(c_hashes, 0)
        assert verify_membership(
            entry_hash=c_entries[0].entry_hash,
            index=0,
            batch_size=len(c_hashes),
            proof=proof,
            root=checkpoint_c.root,
        )

        assert c_entries[0].payload is not None
        binding_b = from_payload(json.loads(c_entries[0].payload))
        assert binding_b == HandoffBinding(chain_id="agent-b", seq=seq_b, head_hash=hash_b)
        assert binding_holds(binding_b, log_b.entry_hashes()) is True  # pins B

        # B's own handoff-to-A entry (its index 0) is embedded in the SAME
        # hash that C's binding just confirmed against B's live trail --
        # reading it back off B pins A one hop further out.
        b_entries = list(log_b.entries())
        assert b_entries[0].payload is not None
        binding_a = from_payload(json.loads(b_entries[0].payload))
        assert binding_a == HandoffBinding(chain_id="agent-a", seq=seq_a, head_hash=hash_a)
        assert binding_holds(binding_a, log_a.entry_hashes()) is True  # pins A

    def test_multi_hop_pin_catches_a_rewrite_two_hops_up(self, tmp_path: Path) -> None:
        log_a, log_b, log_c, seq_a, hash_a, _seq_b, _hash_b = self._build(tmp_path)
        b_entries = list(log_b.entries())
        assert b_entries[0].payload is not None
        binding_a = from_payload(json.loads(b_entries[0].payload))

        rewritten_a = open_log(tmp_path / "a-rewritten.jsonl")
        fill(rewritten_a, 2, prefix="a-different-content")
        assert rewritten_a.verify().ok

        assert binding_holds(binding_a, rewritten_a.entry_hashes()) is False
        assert binding_a.seq == seq_a
        assert binding_a.head_hash == hash_a


class TestPayloadDeletionIsUnverifiableNotBroken:
    """CLAUDE.md rule 4 / SPEC 5.4: the payload check is conditional on
    availability. This is the EXISTING law (tests/domain/test_verify.py::
    TestPayloadAbsent); this class only confirms it already holds for the
    new handoff-binding payload type without touching verify.py."""

    def test_deleting_the_handoff_payload_is_reported_ok_not_broken(
        self, tmp_path: Path
    ) -> None:
        log_a = open_log(tmp_path / "a.jsonl")
        fill(log_a, 1)
        seq_a, hash_a = tip(log_a)

        log_b = open_log(tmp_path / "b.jsonl")
        record_handoff(log_b, chain_id="agent-a", seq=seq_a, head_hash=hash_a)
        fill(log_b, 2)

        entries = list(log_b.entries())
        redacted = [
            replace(e, payload=None) if e.header.seq == 0 else e for e in entries
        ]
        result = verify_chain(redacted, VersionRegistry())

        assert result.ok is True
        assert result.broken_seq is None
        assert result.reason is None
        assert result.checked == len(redacted)
        assert result.unverifiable == ()

    def test_contrast_a_genuinely_wrong_header_still_breaks(self, tmp_path: Path) -> None:
        # Confirms the distinction is real: it is availability, not a
        # blanket exemption for this payload type. A header lying about the
        # payload hash is still caught even without payload bytes present.
        import hashlib

        log_a = open_log(tmp_path / "a.jsonl")
        fill(log_a, 1)
        seq_a, hash_a = tip(log_a)

        log_b = open_log(tmp_path / "b.jsonl")
        record_handoff(log_b, chain_id="agent-a", seq=seq_a, head_hash=hash_a)

        entries = list(log_b.entries())
        lying_header = replace(
            entries[0].header, payload_hash=hashlib.sha256(b"lie").hexdigest()
        )
        tampered = [replace(entries[0], header=lying_header, payload=None)]
        result = verify_chain(tampered, VersionRegistry())

        assert result.ok is False
        assert result.reason == "entry_hash_mismatch"

