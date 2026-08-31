"""Operators, roles and API keys — the pure half.

The role table is the product's own sentence about itself: an Admin manages the
server and its keys and *still* cannot edit an entry, because nobody can. That
is not a permission the model forgot; it is a permission that does not exist, so
there is no scope anywhere in this file that grants it.

Keys are secrets, so the plaintext exists exactly once — at mint — and only its
SHA-256 is ever stored. A store that can show you a key again is a store that
can lose every key at once.
"""

from __future__ import annotations

import hashlib

import pytest
from waxseal_server.domain.operators import (
    KEY_PREFIX,
    Role,
    ScopeSet,
    hash_key,
    key_fingerprint,
    mint_key,
    scopes_for_role,
)


class TestRoles:
    def test_the_four_roles_the_design_names_all_exist(self) -> None:
        assert {r.value for r in Role} == {"admin", "auditor", "writer", "viewer"}

    def test_a_role_parses_from_its_wire_value(self) -> None:
        assert Role("admin") is Role.ADMIN

    def test_an_unknown_role_is_refused_rather_than_defaulted(self) -> None:
        # Defaulting an unrecognised role to the weakest one would be a silent
        # downgrade; defaulting to the strongest would be a silent escalation.
        with pytest.raises(ValueError):
            Role("superuser")


class TestScopes:
    def test_no_role_can_edit_an_entry(self) -> None:
        # The one assertion this module exists for. "Verify reports, never
        # repairs" (CLAUDE.md rule 4) has to be unrepresentable, not merely
        # unimplemented: there is no scope to grant.
        for role in Role:
            for scope in scopes_for_role(role):
                assert "write" not in scope or scope == "import:write", scope
                assert "delete" not in scope
                assert "edit" not in scope

    def test_admin_manages_keys_and_reads_trails(self) -> None:
        admin = scopes_for_role(Role.ADMIN)
        assert "keys:manage" in admin
        assert "trails:read" in admin

    def test_auditor_can_verify_and_import_but_not_manage_keys(self) -> None:
        auditor = scopes_for_role(Role.AUDITOR)
        assert {"trails:read", "verify:run", "import:write", "proof:export"} <= auditor
        assert "keys:manage" not in auditor

    def test_writer_can_append_and_read_the_head_and_nothing_else(self) -> None:
        # The machine account. It must be able to extend the chain and discover
        # the tail it is extending, and must not be able to read what is on it.
        assert scopes_for_role(Role.WRITER) == {"entries:append", "head:read"}

    def test_viewer_reads_and_writes_nothing(self) -> None:
        viewer = scopes_for_role(Role.VIEWER)
        assert viewer == {"trails:read", "public:read"}

    def test_a_scope_set_is_immutable(self) -> None:
        # Handing out a mutable set would let one request's check widen the next
        # request's permissions.
        with pytest.raises(AttributeError):
            scopes_for_role(Role.VIEWER).add("keys:manage")  # type: ignore[attr-defined]

    def test_every_role_has_at_least_one_scope(self) -> None:
        for role in Role:
            assert scopes_for_role(role), role

    def test_admin_is_a_superset_of_every_other_role(self) -> None:
        admin = scopes_for_role(Role.ADMIN)
        for role in Role:
            assert scopes_for_role(role) <= admin, role


class TestMinting:
    def test_a_minted_key_carries_the_product_prefix(self) -> None:
        plaintext, _ = mint_key()
        assert plaintext.startswith(KEY_PREFIX)

    def test_two_mints_never_collide(self) -> None:
        assert len({mint_key()[0] for _ in range(200)}) == 200

    def test_the_secret_has_at_least_128_bits_of_entropy(self) -> None:
        plaintext, _ = mint_key()
        body = plaintext[len(KEY_PREFIX) :]
        # base64url alphabet: 6 bits per character.
        assert len(body) * 6 >= 128

    def test_the_fingerprint_is_the_sha256_of_the_whole_key(self) -> None:
        # Computed from the prose, not from the implementation: a fingerprint
        # scheme only ever checked against itself checks nothing.
        plaintext, fingerprint = mint_key()
        assert fingerprint == hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    def test_hash_key_agrees_with_the_mint(self) -> None:
        plaintext, fingerprint = mint_key()
        assert hash_key(plaintext) == fingerprint

    def test_a_different_key_hashes_differently(self) -> None:
        assert hash_key("wxs_live_a") != hash_key("wxs_live_b")


class TestDisplayFingerprint:
    def test_it_shows_enough_to_recognise_and_too_little_to_use(self) -> None:
        plaintext, _ = mint_key()
        shown = key_fingerprint(plaintext)
        assert shown.startswith(KEY_PREFIX)
        assert shown.endswith("…")
        assert plaintext not in shown
        # Four characters of a 128-bit secret identifies a key among a handful
        # and brute-forces nothing.
        assert len(shown) == len(KEY_PREFIX) + 5

    def test_two_keys_usually_look_different(self) -> None:
        shown = {key_fingerprint(mint_key()[0]) for _ in range(50)}
        assert len(shown) > 40

    def test_it_refuses_a_string_that_is_not_a_key(self) -> None:
        with pytest.raises(ValueError):
            key_fingerprint("not-a-waxseal-key")


class TestScopeSetType:
    def test_it_is_a_frozenset_of_strings(self) -> None:
        scopes: ScopeSet = scopes_for_role(Role.ADMIN)
        assert isinstance(scopes, frozenset)
        assert all(isinstance(scope, str) for scope in scopes)
