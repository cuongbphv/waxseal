"""Tests for the append-only version registry (SPEC.md section 4, CLAUDE.md rule 2)."""

import pytest

from waxseal.domain.fingerprint import HEADER_V1_FIELDS, fingerprint_for, fingerprint_v1
from waxseal.domain.registry import VersionRegistry


class TestVersionRegistry:
    def test_v1_is_known_out_of_the_box(self) -> None:
        reg = VersionRegistry()
        assert reg.knows(fingerprint_v1())

    def test_unknown_fingerprint_is_not_known(self) -> None:
        reg = VersionRegistry()
        assert not reg.knows("f" * 64)

    def test_register_new_schema_returns_its_fingerprint(self) -> None:
        reg = VersionRegistry()
        widened = (*HEADER_V1_FIELDS, "redaction_version")
        fp = reg.register(widened)
        assert fp == fingerprint_for(widened)
        assert reg.knows(fp)

    def test_reregistering_same_schema_is_idempotent(self) -> None:
        reg = VersionRegistry()
        widened = (*HEADER_V1_FIELDS, "redaction_version")
        assert reg.register(widened) == reg.register(widened)

    def test_fields_lookup_by_fingerprint(self) -> None:
        reg = VersionRegistry()
        assert reg.fields(fingerprint_v1()) == HEADER_V1_FIELDS

    def test_fields_for_unknown_fingerprint_raises_keyerror(self) -> None:
        reg = VersionRegistry()
        with pytest.raises(KeyError):
            reg.fields("f" * 64)

    def test_registry_is_append_only_no_removal_api(self) -> None:
        # CLAUDE.md rule 2: no way to remove or mutate a registered schema.
        reg = VersionRegistry()
        assert not hasattr(reg, "unregister")
        assert not hasattr(reg, "remove")
