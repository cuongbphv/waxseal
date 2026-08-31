"""The `OperatorStore` contract, applied to every adapter that claims to be one.

Mixed into a `Test*` class with a `store` fixture, exactly as the library does
for its storage backends. The point of running it against both the in-memory
adapter and real Postgres is that it makes the in-memory one a stand-in rather
than a convenient fiction: if the fast suite passes and Postgres does not, the
contract found it.

The class is deliberately not named `Test*` so pytest never collects it on its
own — it has no working fixture.
"""

from __future__ import annotations

from typing import Any

import pytest
from waxseal_server.domain.errors import (
    InvalidIdentifier,
    NoSuchOperator,
    OperatorExists,
)
from waxseal_server.domain.operators import KEY_PREFIX, Role, hash_key


class OperatorStoreContract:
    @pytest.fixture()
    def store(self) -> Any:
        raise NotImplementedError("subclasses must provide a `store` fixture")

    # --------------------------------------------------------------- operators

    def test_a_fresh_store_holds_nobody(self, store: Any) -> None:
        assert store.operators() == []

    def test_an_operator_round_trips(self, store: Any) -> None:
        made = store.create_operator(
            username="admin", display_name="Admin", email="admin@example.test", role=Role.ADMIN
        )
        assert store.get_operator("admin") == made
        assert made.role is Role.ADMIN
        assert made.active is True

    def test_an_operator_without_an_email_keeps_none_not_an_empty_string(
        self, store: Any
    ) -> None:
        # "" would render as a blank address in a UI; None renders as absent.
        made = store.create_operator(
            username="ci", display_name="ci", email=None, role=Role.WRITER
        )
        assert made.email is None
        assert store.get_operator("ci") is not None
        assert store.get_operator("ci").email is None

    def test_an_unknown_operator_is_none(self, store: Any) -> None:
        assert store.get_operator("nobody") is None

    def test_a_duplicate_username_is_refused(self, store: Any) -> None:
        store.create_operator(
            username="admin", display_name="Admin", email=None, role=Role.ADMIN
        )
        with pytest.raises(OperatorExists):
            store.create_operator(
                username="admin", display_name="Someone else", email=None, role=Role.VIEWER
            )

    def test_a_refused_duplicate_does_not_change_the_existing_operator(
        self, store: Any
    ) -> None:
        # Last-write-wins over who is an admin is the failure this refusal
        # exists to prevent, so the refusal has to leave the first one intact.
        store.create_operator(
            username="admin", display_name="Admin", email=None, role=Role.ADMIN
        )
        with pytest.raises(OperatorExists):
            store.create_operator(
                username="admin", display_name="Impostor", email=None, role=Role.VIEWER
            )
        assert store.get_operator("admin").role is Role.ADMIN
        assert store.get_operator("admin").display_name == "Admin"

    def test_operators_are_listed_oldest_first(self, store: Any) -> None:
        store.create_operator(username="admin", display_name="a", email=None, role=Role.ADMIN)
        store.create_operator(
            username="user-waxseal", display_name="b", email=None, role=Role.WRITER
        )
        assert [o.username for o in store.operators()] == ["admin", "user-waxseal"]

    @pytest.mark.parametrize("bad", ["Admin", "with space", "", "-leading", "a" * 65, "../x"])
    def test_a_username_that_is_not_a_safe_identifier_is_refused(
        self, store: Any, bad: str
    ) -> None:
        with pytest.raises(InvalidIdentifier):
            store.create_operator(
                username=bad, display_name="x", email=None, role=Role.VIEWER
            )

    def test_an_operator_can_be_corrected(self, store: Any) -> None:
        # A typo in an email is the ordinary case. Without an update path the
        # only fix is editing the database by hand, which is how a product
        # teaches its operators to bypass it.
        store.create_operator(
            username="admin", display_name="Admin", email="wrong@example.test", role=Role.ADMIN
        )
        updated = store.update_operator("admin", email="right@example.test")
        assert updated.email == "right@example.test"
        assert store.get_operator("admin").email == "right@example.test"

    def test_an_update_leaves_untouched_fields_alone(self, store: Any) -> None:
        store.create_operator(
            username="admin", display_name="Admin", email="a@b.c", role=Role.ADMIN
        )
        store.update_operator("admin", display_name="Administrator")
        after = store.get_operator("admin")
        assert after.display_name == "Administrator"
        assert after.email == "a@b.c"
        assert after.role is Role.ADMIN
        assert after.active is True

    def test_an_email_can_be_cleared(self, store: Any) -> None:
        # Clearing is distinct from "not supplied". A machine account that was
        # given a human's address by mistake must be able to lose it.
        store.create_operator(
            username="ci", display_name="ci", email="human@example.test", role=Role.WRITER
        )
        assert store.update_operator("ci", email=None, clear_email=True).email is None

    def test_a_role_can_be_changed(self, store: Any) -> None:
        store.create_operator(username="x", display_name="x", email=None, role=Role.VIEWER)
        updated = store.update_operator("x", role=Role.AUDITOR)
        assert updated.role is Role.AUDITOR
        assert updated.scopes == store.get_operator("x").scopes

    def test_an_operator_can_be_deactivated_and_reactivated(self, store: Any) -> None:
        # Deactivation, never deletion: an operator who acted is part of the
        # history, and removing the row would orphan every key that names them.
        store.create_operator(username="x", display_name="x", email=None, role=Role.ADMIN)
        assert store.update_operator("x", active=False).active is False
        assert store.update_operator("x", active=True).active is True

    def test_a_deactivated_operator_grants_nothing(self, store: Any) -> None:
        store.create_operator(username="x", display_name="x", email=None, role=Role.ADMIN)
        plaintext, _ = store.mint_key(username="x", label="k")
        store.update_operator("x", active=False)
        assert store.authenticate(plaintext) is None

    def test_reactivating_restores_the_key(self, store: Any) -> None:
        store.create_operator(username="x", display_name="x", email=None, role=Role.ADMIN)
        plaintext, _ = store.mint_key(username="x", label="k")
        store.update_operator("x", active=False)
        store.update_operator("x", active=True)
        assert store.authenticate(plaintext) is not None

    def test_updating_an_unknown_operator_is_refused(self, store: Any) -> None:
        with pytest.raises(NoSuchOperator):
            store.update_operator("ghost", email="x@y.z")

    def test_an_update_that_changes_nothing_is_still_the_current_record(
        self, store: Any
    ) -> None:
        made = store.create_operator(
            username="x", display_name="x", email=None, role=Role.ADMIN
        )
        assert store.update_operator("x") == made

    # -------------------------------------------------------------------- keys

    def test_a_fresh_store_holds_no_keys(self, store: Any) -> None:
        assert store.keys() == []

    def test_minting_returns_a_usable_plaintext_and_a_record(self, store: Any) -> None:
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        plaintext, record = store.mint_key(username="ci", label="hook")
        assert plaintext.startswith(KEY_PREFIX)
        assert record.username == "ci"
        assert record.label == "hook"
        assert record.active

    def test_the_record_never_carries_the_secret(self, store: Any) -> None:
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        plaintext, record = store.mint_key(username="ci", label="hook")
        rendered = repr(record)
        assert plaintext not in rendered
        assert hash_key(plaintext) not in rendered

    def test_minting_for_an_unknown_operator_is_refused(self, store: Any) -> None:
        # A key belonging to nobody is a credential with no role.
        with pytest.raises(NoSuchOperator):
            store.mint_key(username="ghost", label="hook")

    def test_keys_are_listed_newest_first(self, store: Any) -> None:
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        first = store.mint_key(username="ci", label="one")[1]
        second = store.mint_key(username="ci", label="two")[1]
        # noqa on the next line: `store.keys()` is the OperatorStore method, not
        # a mapping's — SIM118 cannot tell the difference.
        listed = [k.key_id for k in store.keys()]  # noqa: SIM118
        assert listed == [second.key_id, first.key_id]

    def test_keys_can_be_filtered_to_one_operator(self, store: Any) -> None:
        store.create_operator(username="admin", display_name="a", email=None, role=Role.ADMIN)
        store.create_operator(username="ci", display_name="c", email=None, role=Role.WRITER)
        store.mint_key(username="admin", label="admin key")
        store.mint_key(username="ci", label="ci key")
        assert [k.label for k in store.keys("ci")] == ["ci key"]

    def test_a_fresh_store_has_no_active_key(self, store: Any) -> None:
        assert store.has_active_key() is False

    def test_minting_gives_the_store_an_active_key(self, store: Any) -> None:
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        store.mint_key(username="ci", label="hook")
        assert store.has_active_key() is True

    def test_revoking_the_only_key_leaves_none_active(self, store: Any) -> None:
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        _, record = store.mint_key(username="ci", label="hook")
        store.revoke_key(record.key_id)
        assert store.has_active_key() is False

    # ---------------------------------------------------------- authentication

    def test_a_minted_key_authenticates_to_its_operator(self, store: Any) -> None:
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        plaintext, record = store.mint_key(username="ci", label="hook")

        principal = store.authenticate(plaintext)
        assert principal is not None
        assert principal.operator.username == "ci"
        assert principal.key_id == record.key_id
        assert principal.scopes == {"entries:append", "head:read"}

    def test_an_unknown_key_authenticates_to_nobody(self, store: Any) -> None:
        assert store.authenticate(KEY_PREFIX + "definitely-not-minted") is None

    def test_an_empty_token_authenticates_to_nobody(self, store: Any) -> None:
        assert store.authenticate("") is None

    def test_a_revoked_key_stops_working(self, store: Any) -> None:
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        plaintext, record = store.mint_key(username="ci", label="hook")
        assert store.revoke_key(record.key_id) is True
        assert store.authenticate(plaintext) is None

    def test_revoking_twice_reports_that_it_did_nothing(self, store: Any) -> None:
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        _, record = store.mint_key(username="ci", label="hook")
        store.revoke_key(record.key_id)
        assert store.revoke_key(record.key_id) is False

    def test_revoking_an_unknown_key_reports_that_it_did_nothing(self, store: Any) -> None:
        assert store.revoke_key("no-such-key") is False

    def test_a_revoked_key_is_still_listed(self, store: Any) -> None:
        # A revocation is part of the history an auditor came to read.
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        _, record = store.mint_key(username="ci", label="hook")
        store.revoke_key(record.key_id)
        [listed] = store.keys()
        assert listed.key_id == record.key_id
        assert listed.active is False
        assert listed.revoked_at is not None

    def test_revoking_one_key_leaves_the_others_working(self, store: Any) -> None:
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        keep_plaintext, _ = store.mint_key(username="ci", label="keep")
        _, drop = store.mint_key(username="ci", label="drop")
        store.revoke_key(drop.key_id)
        assert store.authenticate(keep_plaintext) is not None

    def test_using_a_key_records_when_it_was_last_used(self, store: Any) -> None:
        store.create_operator(username="ci", display_name="ci", email=None, role=Role.WRITER)
        plaintext, record = store.mint_key(username="ci", label="hook")
        assert record.last_used_at is None
        store.authenticate(plaintext)
        assert store.keys()[0].last_used_at is not None

    def test_each_role_authenticates_to_its_own_scopes(self, store: Any) -> None:
        for role in Role:
            username = f"u-{role.value}"
            store.create_operator(
                username=username, display_name=username, email=None, role=role
            )
            plaintext, _ = store.mint_key(username=username, label="k")
            principal = store.authenticate(plaintext)
            assert principal is not None
            assert principal.scopes == principal.operator.scopes
            assert not principal.allows("entries:edit")

    def test_two_keys_for_one_operator_both_authenticate_to_it(self, store: Any) -> None:
        store.create_operator(username="admin", display_name="a", email=None, role=Role.ADMIN)
        first, _ = store.mint_key(username="admin", label="laptop")
        second, _ = store.mint_key(username="admin", label="ci")
        assert store.authenticate(first).operator.username == "admin"
        assert store.authenticate(second).operator.username == "admin"
        assert store.authenticate(first).key_id != store.authenticate(second).key_id
