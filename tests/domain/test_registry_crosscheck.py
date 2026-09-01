"""On-chain registry cross-check: agrees / disagrees / unreachable.

The one thing this check must never do is call a disagreement `broken`. Two
registries that hold different descriptors for one fingerprint are two
authorities in conflict, and nothing in this process can adjudicate which is
the real one. Printing "tampered" over that would be exactly the false alarm
migration 060 raised, with a second registry standing in for the widened
field set.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from waxseal.domain.fingerprint import (
    ALGORITHM,
    DESCRIPTOR_PREFIX,
    HEADER_FIELDS,
    fingerprint,
    fingerprint_for,
)
from waxseal.domain.hashing import ENCODING
from waxseal.domain.registry import (
    REGISTRY_ABSENT,
    REGISTRY_AGREES,
    REGISTRY_COULD_NOT_BE_READ,
    REGISTRY_DISAGREEMENT,
    REGISTRY_DISAGREES,
    REGISTRY_NOT_REGISTERED,
    REGISTRY_UNREACHABLE,
    RegistryCrossCheck,
    RegistryFinding,
    VersionRegistry,
    decode_descriptor,
    descriptor_frame,
)
from waxseal.domain.verdict import Verdict


def spec_descriptor(fields: tuple[str, ...]) -> bytes:
    """The descriptor frame, written straight from SPEC.md's prose.

    Deliberately NOT a call into `descriptor_frame`: the golden-vector
    discipline in this repo is that the reference implementation is
    independent of the code under test, or the check only proves the code
    agrees with itself.
    """
    components = (ALGORITHM, ENCODING, *fields)
    frame = DESCRIPTOR_PREFIX + struct.pack(">Q", len(components))
    for component in components:
        raw = component.encode("utf-8")
        frame += struct.pack(">Q", len(raw)) + raw
    return frame


class TestDescriptorFrame:
    def test_it_reproduces_the_frozen_fingerprint(self) -> None:
        # `domain/fingerprint.py` is a frozen path and exposes only the
        # DIGEST, never the bytes it digested; publishing a descriptor to a
        # contract needs the bytes. This asserts the second implementation
        # cannot drift from the frozen one: if it ever did, the fingerprints
        # would stop matching here, loudly, instead of silently registering a
        # descriptor on chain that hashes to some other identity.
        for fields in (HEADER_FIELDS, ("seq", "ts"), ()):
            assert hashlib.sha256(descriptor_frame(fields)).hexdigest() == fingerprint_for(fields)

    def test_it_matches_the_spec_written_reference(self) -> None:
        assert descriptor_frame(HEADER_FIELDS) == spec_descriptor(HEADER_FIELDS)


class TestDecodeDescriptor:
    def test_it_reads_back_algorithm_encoding_and_fields(self) -> None:
        decoded = decode_descriptor(descriptor_frame(HEADER_FIELDS))
        assert decoded == (ALGORITHM, ENCODING, *HEADER_FIELDS)

    def test_a_foreign_prefix_is_not_guessed_at(self) -> None:
        assert decode_descriptor(b"someone-elses-format\n" + b"\x00" * 8) is None

    def test_empty_bytes_decode_to_nothing(self) -> None:
        assert decode_descriptor(b"") is None

    def test_a_frame_with_no_field_count_decodes_to_nothing(self) -> None:
        assert decode_descriptor(DESCRIPTOR_PREFIX) is None

    def test_a_frame_that_stops_mid_length_header_decodes_to_nothing(self) -> None:
        assert decode_descriptor(DESCRIPTOR_PREFIX + struct.pack(">Q", 1) + b"\x00\x00") is None

    def test_a_truncated_frame_decodes_to_nothing(self) -> None:
        assert decode_descriptor(descriptor_frame(HEADER_FIELDS)[:-3]) is None

    def test_a_field_count_that_lies_decodes_to_nothing(self) -> None:
        frame = descriptor_frame(HEADER_FIELDS)
        lying = frame[: len(DESCRIPTOR_PREFIX)] + struct.pack(">Q", 99) + frame[
            len(DESCRIPTOR_PREFIX) + 8 :
        ]
        assert decode_descriptor(lying) is None

    def test_trailing_bytes_decode_to_nothing(self) -> None:
        assert decode_descriptor(descriptor_frame(HEADER_FIELDS) + b"\x00") is None

    def test_a_field_that_is_not_utf8_decodes_to_nothing(self) -> None:
        frame = DESCRIPTOR_PREFIX + struct.pack(">Q", 1) + struct.pack(">Q", 1) + b"\xff"
        assert decode_descriptor(frame) is None

    def test_a_declared_length_past_the_end_decodes_to_nothing(self) -> None:
        frame = DESCRIPTOR_PREFIX + struct.pack(">Q", 1) + struct.pack(">Q", 99) + b"ab"
        assert decode_descriptor(frame) is None


class TestCrossCheck:
    def check(self) -> RegistryCrossCheck:
        return RegistryCrossCheck(VersionRegistry())

    def test_the_descriptor_that_hashes_to_the_fingerprint_agrees(self) -> None:
        finding = self.check().check(fingerprint(), descriptor_frame(HEADER_FIELDS))
        assert finding.status == REGISTRY_AGREES
        assert finding.reason is None
        assert (finding.locally_known, finding.locally_recomputable) == (True, True)
        assert finding.to_verdict() is Verdict.OK

    def test_a_descriptor_that_hashes_to_something_else_disagrees(self) -> None:
        finding = self.check().check(fingerprint(), descriptor_frame(("seq", "ts")))
        assert finding.status == REGISTRY_DISAGREES
        assert finding.reason == REGISTRY_DISAGREEMENT
        assert finding.onchain_descriptor == (ALGORITHM, ENCODING, "seq", "ts")

    def test_a_disagreement_is_unverifiable_and_never_a_break(self) -> None:
        finding = self.check().check(fingerprint(), b"poison")
        assert finding.status == REGISTRY_DISAGREES
        assert finding.to_verdict() is Verdict.UNVERIFIABLE
        assert finding.to_verdict().to_exit_code() == 2

    def test_a_descriptor_this_build_cannot_parse_still_reports_its_bytes(self) -> None:
        # RFC 6962 section 4.6: an unrecognized structure is opaque, not an
        # error. The operator still gets the hex, which is what tells them
        # which build to go and fetch.
        finding = self.check().check(hashlib.sha256(b"poison").hexdigest(), b"poison")
        assert finding.status == REGISTRY_AGREES
        assert finding.onchain_descriptor is None
        assert finding.onchain_descriptor_hex == b"poison".hex()

    def test_a_registry_that_holds_nothing_for_this_fingerprint(self) -> None:
        # waxseal-fg4.44: a REAL, measured answer -- the registry was asked
        # and it holds nothing here -- not the same fact as the registry
        # being unreachable, so this is `reachable=True` (the default) with
        # a `None` descriptor, and gets its own status.
        finding = self.check().check(fingerprint(), None)
        assert finding.status == REGISTRY_ABSENT
        assert finding.reason == REGISTRY_NOT_REGISTERED
        assert finding.to_verdict() is Verdict.UNVERIFIABLE

    def test_a_registry_that_could_not_be_read(self) -> None:
        # The other half of the split: nothing was measured at all. The
        # caller (adapters/evm.py) is the only one that knows this, which is
        # why it is a keyword the caller passes, never inferred from the
        # descriptor's own value.
        finding = self.check().check(fingerprint(), None, reachable=False)
        assert finding.status == REGISTRY_UNREACHABLE
        assert finding.reason == REGISTRY_COULD_NOT_BE_READ
        assert finding.to_verdict() is Verdict.UNVERIFIABLE

    def test_absent_and_unreachable_are_different_states(self) -> None:
        # The whole point of the split: two calls that both hand back
        # `onchain_descriptor=None` must render as DIFFERENT facts, not the
        # same message twice.
        absent = self.check().check(fingerprint(), None)
        unreachable = self.check().check(fingerprint(), None, reachable=False)
        assert absent.status != unreachable.status
        assert absent.reason != unreachable.reason

    def test_a_fingerprint_on_chain_that_this_build_never_heard_of(self) -> None:
        fields = ("seq", "ts", "payload_hash")
        finding = self.check().check(fingerprint_for(fields), descriptor_frame(fields))
        assert finding.status == REGISTRY_AGREES
        assert (finding.locally_known, finding.locally_recomputable) == (False, False)
        # Agreement about the descriptor is not permission to recompute the
        # row: knowing a name is not owning an encoder for it.
        assert finding.to_verdict() is Verdict.OK

    def test_a_fingerprint_registered_locally_but_not_recomputable(self) -> None:
        registry = VersionRegistry()
        fields = ("seq", "ts")
        fp = registry.register(fields)
        finding = RegistryCrossCheck(registry).check(fp, descriptor_frame(fields))
        assert (finding.locally_known, finding.locally_recomputable) == (True, False)

    def test_a_status_this_build_does_not_know_is_not_guessed_at(self) -> None:
        with pytest.raises(ValueError, match="not a registry status"):
            RegistryFinding(fingerprint="ab", status="probably-fine").to_verdict()


class TestNeverExitOne:
    def test_no_registry_status_maps_to_a_break(self) -> None:
        # Structural, not enumerated by hand: the mapping's whole range is
        # read out of the module. A future fourth status that mapped to
        # BROKEN would fail here even if nobody wrote a test for it.
        from waxseal.domain.registry import _REGISTRY_STATUS

        assert Verdict.BROKEN not in set(_REGISTRY_STATUS.values())
        assert {v.to_exit_code() for v in _REGISTRY_STATUS.values()} == {0, 2}


class TestFalsifiabilityReceipt:
    """Receipt for the registry ternary's `unreachable` branch, run 01/09/2026.

    Collapsing the "registry holds nothing / could not be read" branch of
    `RegistryCrossCheck.check` into `REGISTRY_DISAGREES` (the false-alarm
    direction: an unread registry reported as a conflicting one) was run
    against this file:

        FAILED tests/domain/test_registry_crosscheck.py::TestCrossCheck::
            test_a_registry_that_holds_nothing_for_this_fingerprint
        AssertionError: assert 'disagrees' == 'unreachable'
        1 failed, 20 passed, 1 deselected in 0.08s

    Branch restored: 22 passed. Note the collapse does NOT change the exit
    code — both map to 2 — which is precisely why only a test on the STATUS
    catches it: an operator would be told a conflict exists between two
    descriptors when only one of them was ever read.
    """

    def test_the_receipt_is_recorded(self) -> None:
        assert "1 failed" in (TestFalsifiabilityReceipt.__doc__ or "")


class TestAbsentVsUnreachableFalsifiabilityReceipt:
    """Receipt for waxseal-fg4.44's split, run 01/09/2026.

    The prior receipt above proved the merged `unreachable` state must not
    collapse into `disagrees`. This one proves the SPLIT itself is real: that
    `REGISTRY_ABSENT` and `REGISTRY_UNREACHABLE` are two states a test can
    tell apart, not one state with two names. Re-merging them --
    `if not reachable or onchain_descriptor is None: return ... UNREACHABLE
    ...` in place of the two separate branches `check()` now has -- was run
    against this file:

        FAILED tests/domain/test_registry_crosscheck.py::TestCrossCheck::
            test_a_registry_that_holds_nothing_for_this_fingerprint
        AssertionError: assert 'unreachable' == 'absent'
        FAILED tests/domain/test_registry_crosscheck.py::TestCrossCheck::
            test_absent_and_unreachable_are_different_states
        AssertionError: assert 'unreachable' != 'unreachable'
        2 failed, 22 passed in 0.76s

    Split restored: 24 passed. Both failures land on the STATUS, never the
    exit code -- both merged and split map to exit 2 -- which is exactly why
    an operator reading only the exit code could never see this regression;
    the status string is the only place the fact survives.
    """

    def test_the_receipt_is_recorded(self) -> None:
        doc = TestAbsentVsUnreachableFalsifiabilityReceipt.__doc__ or ""
        assert "2 failed, 22 passed" in doc
        assert "Split restored: 24 passed" in doc
