"""The in-memory adapter, against the shared `OperatorStore` contract."""

from __future__ import annotations

import pytest
from operator_store_contract import OperatorStoreContract
from waxseal_server.storage.operators_memory import InMemoryOperatorStore


class TestInMemoryOperatorStore(OperatorStoreContract):
    @pytest.fixture()
    def store(self) -> InMemoryOperatorStore:
        return InMemoryOperatorStore()
