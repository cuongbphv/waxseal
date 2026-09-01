"""Tests for the append-only version registry (SPEC.md section 4, CLAUDE.md rule 2)."""

import pytest

from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint, fingerprint_for
from waxseal.domain.hashing import header_frame
from waxseal.domain.receipt_fingerprint import (
    RECEIPT_FRAME_FIELDS,
    receipt_fingerprint,
    receipt_fingerprint_for,
)
from waxseal.domain.registry import ReceiptFrameRegistry, VersionRegistry


class TestVersionRegistry:
    def test_this_builds_schema_is_known_out_of_the_box(self) -> None:
        reg = VersionRegistry()
        assert reg.knows(fingerprint())

    def test_unknown_fingerprint_is_not_known(self) -> None:
        reg = VersionRegistry()
        assert not reg.knows("f" * 64)

    def test_register_new_schema_returns_its_fingerprint(self) -> None:
        reg = VersionRegistry()
        widened = (*HEADER_FIELDS, "redaction_version")
        fp = reg.register(widened)
        assert fp == fingerprint_for(widened)
        assert reg.knows(fp)

    def test_reregistering_same_schema_is_idempotent(self) -> None:
        reg = VersionRegistry()
        widened = (*HEADER_FIELDS, "redaction_version")
        assert reg.register(widened) == reg.register(widened)

    def test_fields_lookup_by_fingerprint(self) -> None:
        reg = VersionRegistry()
        assert reg.fields(fingerprint()) == HEADER_FIELDS

    def test_fields_for_unknown_fingerprint_raises_keyerror(self) -> None:
        reg = VersionRegistry()
        with pytest.raises(KeyError):
            reg.fields("f" * 64)

    def test_registry_is_append_only_no_removal_api(self) -> None:
        # CLAUDE.md rule 2: no way to remove or mutate a registered schema.
        reg = VersionRegistry()
        assert not hasattr(reg, "unregister")
        assert not hasattr(reg, "remove")


class TestEncoderFor:
    """encoder_for resolves a stored identity to the code that can reproduce
    it, and returns None rather than guessing. That None is the whole
    doctrine: a fingerprint this build does not implement is unverifiable by
    name, never recomputed under an encoding it was not signed with."""

    def test_this_builds_fingerprint_dispatches_to_its_frame(self) -> None:
        assert VersionRegistry().encoder_for(fingerprint()) is header_frame

    def test_unknown_fingerprint_has_no_encoder(self) -> None:
        assert VersionRegistry().encoder_for("f" * 64) is None

    def test_registered_but_unimplemented_schema_has_no_encoder(self) -> None:
        # A field tuple this build's hasher does not implement must degrade to
        # unverifiable, never be silently hashed under the wrong frame.
        reg = VersionRegistry()
        other = reg.register(("seq", "ts", "actor"))
        assert reg.knows(other)
        assert reg.encoder_for(other) is None

    def test_encoder_for_and_recomputable_agree(self) -> None:
        reg = VersionRegistry()
        other = reg.register(("seq", "ts", "actor"))
        for fp in (fingerprint(), "f" * 64, other):
            assert reg.recomputable(fp) == (reg.encoder_for(fp) is not None), fp

    def test_schema_is_known_and_recomputable_out_of_the_box(self) -> None:
        reg = VersionRegistry()
        assert reg.knows(fingerprint())
        assert reg.recomputable(fingerprint())
        assert reg.fields(fingerprint()) == HEADER_FIELDS


class TestReceiptFrameRegistry:
    """waxseal-fg4.9: the same append-only doctrine as VersionRegistry, kept
    as a wholly separate class/mechanism (domain/receipt_fingerprint.py) for
    the receipt_head frame (SPEC.md section 19) rather than a second use of
    VersionRegistry."""

    def test_this_builds_receipt_frame_is_known_out_of_the_box(self) -> None:
        assert ReceiptFrameRegistry().knows(receipt_fingerprint())

    def test_unknown_receipt_fingerprint_is_not_known(self) -> None:
        assert not ReceiptFrameRegistry().knows("f" * 64)

    def test_register_new_receipt_frame_returns_its_fingerprint(self) -> None:
        reg = ReceiptFrameRegistry()
        widened = (*RECEIPT_FRAME_FIELDS, "chain_id")
        fp = reg.register(widened)
        assert fp == receipt_fingerprint_for(widened)
        assert reg.knows(fp)

    def test_reregistering_same_receipt_frame_is_idempotent(self) -> None:
        reg = ReceiptFrameRegistry()
        widened = (*RECEIPT_FRAME_FIELDS, "chain_id")
        assert reg.register(widened) == reg.register(widened)

    def test_fields_lookup_by_receipt_fingerprint(self) -> None:
        assert ReceiptFrameRegistry().fields(receipt_fingerprint()) == RECEIPT_FRAME_FIELDS

    def test_fields_for_unknown_receipt_fingerprint_raises_keyerror(self) -> None:
        with pytest.raises(KeyError):
            ReceiptFrameRegistry().fields("f" * 64)

    def test_receipt_frame_registry_is_append_only_no_removal_api(self) -> None:
        # CLAUDE.md rule 2: no way to remove or mutate a registered schema.
        reg = ReceiptFrameRegistry()
        assert not hasattr(reg, "unregister")
        assert not hasattr(reg, "remove")

    def test_receipt_frame_registry_is_a_separate_mechanism_from_version_registry(self) -> None:
        # Constraint 2: the two are never the same object, and one knowing a
        # fingerprint never implies the other does.
        assert not isinstance(ReceiptFrameRegistry(), VersionRegistry)
        assert not VersionRegistry().knows(receipt_fingerprint())
        assert not ReceiptFrameRegistry().knows(fingerprint())
