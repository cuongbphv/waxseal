"""JSONL backend conformance to the shared backend contract.

Kept in its own module (rather than appended to test_jsonl.py) because
``backend_contract.py`` imports ``build_entry`` FROM ``test_jsonl.py`` —
importing the contract back into test_jsonl.py would be circular.
"""

from pathlib import Path

import pytest

from tests.adapters.backend_contract import BackendContractTests
from waxseal.adapters.jsonl import JSONLBackend


class TestJSONLBackendContract(BackendContractTests):
    @pytest.fixture()
    def backend(self, tmp_path: Path) -> JSONLBackend:
        return JSONLBackend(tmp_path / "trail.jsonl")
