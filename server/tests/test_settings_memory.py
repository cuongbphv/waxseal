"""The in-memory adapter, against the shared `SettingsStore` contract."""

from __future__ import annotations

import pytest
from settings_store_contract import SettingsStoreContract
from waxseal_server.storage.settings_memory import InMemorySettingsStore


class TestInMemorySettingsStore(SettingsStoreContract):
    @pytest.fixture()
    def store(self) -> InMemorySettingsStore:
        return InMemorySettingsStore()
