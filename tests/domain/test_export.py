"""Tests for proof bundles (domain/export.py).

An auditor asking about one decision should not need the whole trail, and the
institution should not have to hand over every other customer's decisions to
answer. A bundle is one entry plus the sibling hashes tying it to an anchored
root: checkable offline, against a root the institution could not rewrite
after the fact.

The verifier reads operator- and attacker-supplied JSON, so it follows the
same fail-closed rule as ``domain.anchoring``: anything that does not check
out is "not proven", never an exception — crashing the verifier on hostile
bytes would deny the audit itself.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace

import pytest

from waxseal import VersionRegistry, batch_root
from waxseal.domain.export import (
    BUNDLE_VERSION,
    ProofBundle,
    build_proof_bundle,
    bundle_from_json,
    bundle_to_json,
    verify_proof_bundle,
)
from waxseal.domain.fingerprint import fingerprint
from waxseal.domain.hashing import compute_entry_hash
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader


def make_entries(n: int) -> list[Entry]:
    entries: list[Entry] = []
    prev = GENESIS_PREV_HASH
    for seq in range(n):
        payload = json.dumps({"i": seq}, separators=(",", ":")).encode("ascii")
        import hashlib

        header = EntryHeader(
            seq=seq,
            ts=f"2026-08-23T09:00:0{seq}+00:00",
            hash_version=fingerprint(),
            payload_type="application/vnd.test.decision+json",
            payload_hash=hashlib.sha256(payload).hexdigest(),
            prev_hash=prev,
        )
        entry = Entry(header=header, entry_hash=compute_entry_hash(header), payload=payload)
        entries.append(entry)
        prev = entry.entry_hash
    return entries


REGISTRY = VersionRegistry()


class TestBuildProofBundle:
    def test_bundle_carries_the_entry_and_the_anchored_root(self) -> None:
        entries = make_entries(5)
        bundle = build_proof_bundle(entries, 2)
        assert bundle.header == entries[2].header
        assert bundle.entry_hash == entries[2].entry_hash
        assert bundle.payload == entries[2].payload
        assert bundle.batch_size == 5
        assert bundle.root == batch_root([e.entry_hash for e in entries])

    @pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 8, 9, 17])
    def test_every_entry_of_every_batch_size_verifies(self, size: int) -> None:
        entries = make_entries(size)
        for seq in range(size):
            result = verify_proof_bundle(build_proof_bundle(entries, seq), REGISTRY)
            assert result.ok, (size, seq, result.reason)
            assert result.reason is None
            assert result.unverifiable is False

    def test_index_is_the_entry_seq(self) -> None:
        # The chain is contiguous from 0, so batch index == seq. Storing both
        # would be two fields that must agree; the bundle stores one.
        bundle = build_proof_bundle(make_entries(4), 3)
        assert bundle.header.seq == 3

    def test_seq_outside_the_batch_raises_indexerror(self) -> None:
        # An operator asked for an entry that is not there. Quietly proving
        # some other entry would be worse than refusing (membership_proof's
        # own contract for operator-supplied indices).
        entries = make_entries(3)
        for bad in (-1, 3, 99):
            with pytest.raises(IndexError):
                build_proof_bundle(entries, bad)

    def test_empty_trail_raises(self) -> None:
        with pytest.raises(IndexError):
            build_proof_bundle([], 0)

    def test_a_header_only_entry_yields_a_bundle_without_payload(self) -> None:
        entries = make_entries(3)
        entries[1] = replace(entries[1], payload=None)
        bundle = build_proof_bundle(entries, 1)
        assert bundle.payload is None
        # Still provable: the root commits to entry hashes, not payloads.
        assert verify_proof_bundle(bundle, REGISTRY).ok


class TestVerifyProofBundle:
    def test_a_tampered_payload_is_caught(self) -> None:
        bundle = build_proof_bundle(make_entries(4), 1)
        result = verify_proof_bundle(replace(bundle, payload=b'{"i":99}'), REGISTRY)
        assert not result.ok
        assert result.reason == "payload_hash_mismatch"

    def test_a_tampered_header_field_is_caught(self) -> None:
        bundle = build_proof_bundle(make_entries(4), 1)
        forged = replace(bundle, header=replace(bundle.header, ts="2026-01-01T00:00:00+00:00"))
        result = verify_proof_bundle(forged, REGISTRY)
        assert not result.ok
        assert result.reason == "entry_hash_mismatch"

    def test_an_unencodable_header_field_reports_entry_hash_mismatch_not_a_crash(
        self,
    ) -> None:
        # waxseal-lmv (never-raise fuzzing sweep): same gap as
        # test_verify.py's sibling test -- a lone UTF-16 surrogate is valid
        # `str` (json.loads('"\\ud800"') produces one; a bundle is exactly
        # the "operator- and attacker-supplied JSON" this module's own
        # docstring names) but `lp()` raises `LpEncodingError`, uncaught here
        # before this fix. "Never raises" (this function's own docstring)
        # must hold for this case too, not just malformed bundle shape.
        bundle = build_proof_bundle(make_entries(4), 1)
        forged = replace(bundle, header=replace(bundle.header, ts="\ud800"))
        result = verify_proof_bundle(forged, REGISTRY)
        assert not result.ok
        assert result.reason == "entry_hash_mismatch"

    def test_a_recomputed_but_unanchored_entry_fails_membership(self) -> None:
        # The subtle forgery: rebuild the entry consistently so its own hash
        # checks out, then try to pass it off as part of an anchored batch.
        # Only the root catches this.
        entries = make_entries(4)
        bundle = build_proof_bundle(entries, 1)
        forged_header = replace(bundle.header, ts="2026-01-01T00:00:00+00:00")
        forged = replace(
            bundle,
            header=forged_header,
            entry_hash=compute_entry_hash(forged_header),
        )
        result = verify_proof_bundle(forged, REGISTRY)
        assert not result.ok
        assert result.reason == "membership_not_proven"

    def test_a_tampered_root_is_caught(self) -> None:
        bundle = build_proof_bundle(make_entries(4), 1)
        result = verify_proof_bundle(replace(bundle, root="f" * 64), REGISTRY)
        assert not result.ok
        assert result.reason == "membership_not_proven"

    def test_a_tampered_sibling_hash_is_caught(self) -> None:
        bundle = build_proof_bundle(make_entries(4), 1)
        broken = ("0" * 64, *bundle.proof[1:])
        result = verify_proof_bundle(replace(bundle, proof=broken), REGISTRY)
        assert not result.ok
        assert result.reason == "membership_not_proven"

    def test_a_bundle_from_a_different_batch_size_is_caught(self) -> None:
        bundle = build_proof_bundle(make_entries(4), 1)
        result = verify_proof_bundle(replace(bundle, batch_size=8), REGISTRY)
        assert not result.ok
        assert result.reason == "membership_not_proven"

    @pytest.mark.parametrize(
        "field,value",
        [
            ("batch_size", 0),
            ("batch_size", -1),
            ("entry_hash", "nothex"),
            ("root", "nothex"),
        ],
    )
    def test_structurally_impossible_bundles_are_malformed_not_crashes(
        self, field: str, value: object
    ) -> None:
        bundle = build_proof_bundle(make_entries(4), 1)
        # The mismatched types across this parametrize table (e.g. "root"
        # given a bare str instead of a tuple[str, ...]) ARE the fixture: the
        # test proves a structurally-wrong field is reported as
        # "malformed_bundle" rather than crashing, so `field`/`value` cannot
        # be well-typed for dataclasses.replace()'s per-field signature here.
        result = verify_proof_bundle(
            replace(bundle, **{field: value}),  # type: ignore[arg-type]
            REGISTRY,
        )
        assert not result.ok
        assert result.reason == "malformed_bundle"

    def test_seq_beyond_the_batch_is_malformed(self) -> None:
        bundle = build_proof_bundle(make_entries(4), 1)
        forged = replace(bundle, header=replace(bundle.header, seq=9))
        result = verify_proof_bundle(forged, REGISTRY)
        assert not result.ok
        assert result.reason == "malformed_bundle"

    def test_negative_seq_is_malformed(self) -> None:
        bundle = build_proof_bundle(make_entries(4), 1)
        forged = replace(bundle, header=replace(bundle.header, seq=-1))
        result = verify_proof_bundle(forged, REGISTRY)
        assert not result.ok
        assert result.reason == "malformed_bundle"

    def test_non_hex_sibling_is_malformed_not_a_crash(self) -> None:
        bundle = build_proof_bundle(make_entries(4), 1)
        result = verify_proof_bundle(replace(bundle, proof=("zz" * 32,)), REGISTRY)
        assert not result.ok
        assert result.reason in {"malformed_bundle", "membership_not_proven"}


class TestUnknownFingerprintIsNotTampering:
    def test_unknown_fingerprint_reports_unverifiable_never_broken(self) -> None:
        # The whole point of the library, applied to a single-entry export:
        # a verifier must not recompute a row under a tuple it was not signed
        # with, and must not call it tampered for being unrecognized.
        entries = make_entries(3)
        entries[1] = Entry(
            header=replace(entries[1].header, hash_version="f" * 64),
            entry_hash=entries[1].entry_hash,
            payload=entries[1].payload,
        )
        bundle = build_proof_bundle(entries, 1)
        result = verify_proof_bundle(bundle, REGISTRY)
        assert result.unverifiable is True
        assert result.reason is None
        # Membership against the anchored root is still meaningful: the root
        # commits to the stored entry_hash whether or not this build can
        # reproduce it.
        assert result.ok

    def test_an_unverifiable_entry_still_fails_membership_if_not_anchored(self) -> None:
        entries = make_entries(3)
        bundle = build_proof_bundle(entries, 1)
        forged = replace(
            bundle,
            header=replace(bundle.header, hash_version="f" * 64),
            entry_hash="a" * 64,
        )
        result = verify_proof_bundle(forged, REGISTRY)
        assert result.unverifiable is True
        assert not result.ok
        assert result.reason == "membership_not_proven"

    def test_payload_hash_is_not_checked_for_an_unverifiable_row(self) -> None:
        # Recomputing anything about a row under a schema it was not written
        # with is the one lie the library must never tell — including about
        # its payload.
        entries = make_entries(3)
        entries[1] = Entry(
            header=replace(entries[1].header, hash_version="f" * 64),
            entry_hash=entries[1].entry_hash,
            payload=b"whatever bytes",
        )
        result = verify_proof_bundle(build_proof_bundle(entries, 1), REGISTRY)
        assert result.ok and result.unverifiable is True


class TestJsonRoundTrip:
    def test_round_trip_preserves_every_field(self) -> None:
        bundle = build_proof_bundle(make_entries(6), 4)
        assert bundle_from_json(bundle_to_json(bundle)) == bundle

    def test_round_trip_of_a_payloadless_bundle(self) -> None:
        bundle = replace(build_proof_bundle(make_entries(3), 1), payload=None)
        restored = bundle_from_json(bundle_to_json(bundle))
        assert restored.payload is None
        assert restored == bundle

    def test_serialized_form_is_versioned(self) -> None:
        # A bundle handed to an auditor outlives the tool that made it; the
        # reader must be able to say which format it is looking at rather
        # than guessing from shape.
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(3), 0)))
        assert obj["bundle_version"] == BUNDLE_VERSION

    def test_payload_travels_as_base64_so_any_bytes_survive(self) -> None:
        entries = make_entries(2)
        entries[0] = replace(entries[0], payload=b"\x00\xff not utf-8")
        obj = json.loads(bundle_to_json(build_proof_bundle(entries, 0)))
        assert base64.b64decode(obj["payload_b64"]) == b"\x00\xff not utf-8"

    def test_a_json_bundle_verifies_after_the_round_trip(self) -> None:
        entries = make_entries(7)
        restored = bundle_from_json(bundle_to_json(build_proof_bundle(entries, 5)))
        assert verify_proof_bundle(restored, REGISTRY).ok

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "not json",
            "[]",
            "null",
            "{}",
            '{"bundle_version": "waxseal-proof-bundle-v1"}',
            '{"bundle_version": "some-other-format-v9", "header": {}}',
        ],
    )
    def test_malformed_json_raises_valueerror_only(self, text: str) -> None:
        # One catchable exception type: the CLI turns it into a verdict, and
        # a parser that can raise anything makes that impossible to write.
        with pytest.raises(ValueError):
            bundle_from_json(text)

    def test_missing_header_field_raises_valueerror(self) -> None:
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(3), 0)))
        del obj["header"]["ts"]
        with pytest.raises(ValueError):
            bundle_from_json(json.dumps(obj))

    def test_non_list_proof_raises_valueerror(self) -> None:
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(3), 0)))
        obj["proof"] = "not a list"
        with pytest.raises(ValueError):
            bundle_from_json(json.dumps(obj))

    def test_non_string_sibling_raises_valueerror(self) -> None:
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(4), 0)))
        obj["proof"] = [123]
        with pytest.raises(ValueError):
            bundle_from_json(json.dumps(obj))

    def test_non_string_payload_b64_raises_valueerror(self) -> None:
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(3), 0)))
        obj["payload_b64"] = {"bytes": [1, 2, 3]}
        with pytest.raises(ValueError):
            bundle_from_json(json.dumps(obj))

    def test_header_that_is_not_an_object_raises_valueerror(self) -> None:
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(3), 0)))
        obj["header"] = "seq 0"
        with pytest.raises(ValueError):
            bundle_from_json(json.dumps(obj))

    @pytest.mark.parametrize("bad_seq", ["abc", None, [0], {}])
    def test_non_integer_header_seq_raises_valueerror(self, bad_seq: object) -> None:
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(3), 0)))
        obj["header"]["seq"] = bad_seq
        with pytest.raises(ValueError):
            bundle_from_json(json.dumps(obj))

    def test_a_string_integer_seq_is_coerced_not_rejected(self) -> None:
        # Some JSON producers stringify numbers; that is a shape difference,
        # not a corrupt header, and the hash check downstream still decides.
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(3), 1)))
        obj["header"]["seq"] = "1"
        assert bundle_from_json(json.dumps(obj)).header.seq == 1

    def test_bad_base64_payload_raises_valueerror(self) -> None:
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(3), 0)))
        obj["payload_b64"] = "!!!!not base64!!!!"
        with pytest.raises(ValueError):
            bundle_from_json(json.dumps(obj))

    def test_non_integer_batch_size_raises_valueerror(self) -> None:
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(3), 0)))
        obj["batch_size"] = "many"
        with pytest.raises(ValueError):
            bundle_from_json(json.dumps(obj))

    def test_bundle_is_immutable(self) -> None:
        bundle = build_proof_bundle(make_entries(2), 0)
        with pytest.raises(Exception):  # noqa: B017 - FrozenInstanceError
            bundle.root = "f" * 64  # type: ignore[misc]

    def test_the_serialized_bundle_is_a_plain_json_object(self) -> None:
        obj = json.loads(bundle_to_json(build_proof_bundle(make_entries(3), 1)))
        assert isinstance(obj, dict)
        assert set(obj) == {
            "bundle_version",
            "header",
            "entry_hash",
            "payload_b64",
            "batch_size",
            "proof",
            "root",
        }


class TestProofBundleConstruction:
    def test_bundle_can_be_built_directly_for_a_foreign_producer(self) -> None:
        # The bundle is a wire format; another implementation must be able to
        # produce one without going through this library's builder.
        entries = make_entries(3)
        from waxseal.domain.anchoring import membership_proof

        hashes = [e.entry_hash for e in entries]
        bundle = ProofBundle(
            header=entries[0].header,
            entry_hash=entries[0].entry_hash,
            payload=entries[0].payload,
            batch_size=3,
            proof=membership_proof(hashes, 0),
            root=batch_root(hashes),
        )
        assert verify_proof_bundle(bundle, REGISTRY).ok
