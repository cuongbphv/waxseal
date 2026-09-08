"""The `SettingsStore` contract, applied to every adapter that claims to be one.

Mixed into a `Test*` class with a `store` fixture, exactly as
`OperatorStoreContract` is. Running it against both the in-memory adapter and
real Postgres is what makes the fast one a stand-in rather than a convenient
fiction.

The class is deliberately not named `Test*` so pytest never collects it on its
own — it has no working fixture.
"""

from __future__ import annotations

from typing import Any

import pytest
from waxseal_server.domain.errors import InvalidIdentifier, NoSuchSetting
from waxseal_server.domain.settings import FORBIDDEN, rpc_endpoints


class SettingsStoreContract:
    @pytest.fixture()
    def store(self) -> Any:
        raise NotImplementedError("subclasses must provide a `store` fixture")

    # ------------------------------------------------------------------ empty

    def test_a_fresh_store_has_nothing_stored(self, store: Any) -> None:
        assert store.all() == {}

    def test_an_untouched_setting_is_none_not_an_empty_string(self, store: Any) -> None:
        # None is "nobody set this, apply the default". "" would look like a
        # value somebody chose.
        assert store.get("ledger_rpc_urls") is None

    # ------------------------------------------------------------ round trips

    def test_a_value_round_trips(self, store: Any) -> None:
        pair = "https://rpc-a.example.test,https://rpc-b.example.test"
        store.set("ledger_rpc_urls", pair)
        assert store.get("ledger_rpc_urls") == pair

    def test_all_lists_only_what_was_stored(self, store: Any) -> None:
        store.set("page_size", "250")
        assert store.all() == {"page_size": "250"}

    def test_setting_the_same_key_twice_replaces_it(self, store: Any) -> None:
        store.set("page_size", "250")
        store.set("page_size", "300")
        assert store.get("page_size") == "300"
        assert store.all() == {"page_size": "300"}

    def test_two_settings_do_not_collide(self, store: Any) -> None:
        store.set("page_size", "250")
        store.set("ledger_trail_id", "prod")
        assert store.get("page_size") == "250"
        assert store.get("ledger_trail_id") == "prod"

    # --------------------------------------------------------------- unsetting

    def test_unsetting_reverts_to_not_stored(self, store: Any) -> None:
        store.set("page_size", "250")
        assert store.unset("page_size") is True
        assert store.get("page_size") is None

    def test_unsetting_twice_reports_that_it_did_nothing(self, store: Any) -> None:
        store.set("page_size", "250")
        store.unset("page_size")
        assert store.unset("page_size") is False

    def test_unsetting_something_never_set_reports_that_it_did_nothing(self, store: Any) -> None:
        assert store.unset("ledger_bond_address") is False

    def test_unsetting_one_leaves_the_others(self, store: Any) -> None:
        store.set("page_size", "250")
        store.set("ledger_trail_id", "prod")
        store.unset("page_size")
        assert store.get("ledger_trail_id") == "prod"

    # -------------------------------------------------------------- refusals

    @pytest.mark.parametrize("key", sorted(FORBIDDEN))
    def test_an_environment_only_setting_cannot_be_read_here(self, store: Any, key: str) -> None:
        # Answering None would imply such a setting could exist in this store.
        with pytest.raises(NoSuchSetting):
            store.get(key)

    @pytest.mark.parametrize("key", sorted(FORBIDDEN))
    def test_an_environment_only_setting_cannot_be_written_here(self, store: Any, key: str) -> None:
        # The one that matters most: no adapter may accept a credential.
        with pytest.raises(NoSuchSetting):
            store.set(key, "something")

    def test_an_unknown_key_is_refused_rather_than_stored(self, store: Any) -> None:
        # A typo that saves cleanly is indistinguishable from a change that
        # took effect.
        with pytest.raises(NoSuchSetting):
            store.set("page_sizee", "250")
        assert store.all() == {}

    def test_an_unknown_key_cannot_be_unset_either(self, store: Any) -> None:
        with pytest.raises(NoSuchSetting):
            store.unset("nonsense")

    @pytest.mark.parametrize(
        ("key", "bad"),
        [
            ("page_size", "0"),
            ("page_size", "-5"),
            ("page_size", "abc"),
            ("page_size", ""),
            ("page_size", "99999999"),
            ("ledger_rpc_urls", "file:///etc/passwd,file:///etc/shadow"),
            ("ledger_rpc_urls", "not a url,also not a url"),
            ("ledger_rpc_urls", ""),
            # One endpoint cannot disagree with itself, so a cross-check
            # against it is not one. The floor lives in adapters/evm.py and is
            # enforced here so a setting cannot be saved in a state the command
            # would then refuse.
            ("ledger_rpc_urls", "https://rpc-a.example.test"),
            ("ledger_rpc_urls", "https://rpc-a.example.test,"),
            ("ledger_liveness_address", "0x1234"),
            ("ledger_liveness_address", "deadbeef"),
            ("ledger_trail_id", "../etc"),
            ("ledger_trail_id", "with space"),
        ],
    )
    def test_a_value_that_fails_its_spec_never_reaches_storage(
        self, store: Any, key: str, bad: str
    ) -> None:
        with pytest.raises(InvalidIdentifier):
            store.set(key, bad)
        assert store.all() == {}

    def test_a_refused_write_leaves_the_previous_value_intact(self, store: Any) -> None:
        store.set("page_size", "250")
        with pytest.raises(InvalidIdentifier):
            store.set("page_size", "0")
        assert store.get("page_size") == "250"

    def test_a_single_rpc_endpoint_is_refused_with_the_reason(self, store: Any) -> None:
        with pytest.raises(InvalidIdentifier, match="disagree with itself"):
            store.set("ledger_rpc_urls", "https://only.example.test")

    def test_two_endpoints_split_back_into_two(self, store: Any) -> None:
        store.set("ledger_rpc_urls", "https://a.example.test, https://b.example.test")
        assert rpc_endpoints(store.get("ledger_rpc_urls")) == [
            "https://a.example.test",
            "https://b.example.test",
        ]

    def test_an_unset_endpoint_list_is_empty_never_a_one_item_list(self, store: Any) -> None:
        assert rpc_endpoints(store.get("ledger_rpc_urls")) == []

    def test_an_empty_string_is_refused_rather_than_meaning_unset(self, store: Any) -> None:
        # "Back to default" is `unset`. Blanking a value is a different
        # instruction and must not share one.
        with pytest.raises(InvalidIdentifier):
            store.set("ledger_trail_id", "")
