from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from waxseal import AuditLog

# The library's OWN backend-conformance suite is the strongest statement this
# server can make: "a real waxseal client cannot tell this apart from the
# backends it ships with." Reaching it needs the repository root importable as
# the `tests` package, which is also why this directory deliberately has no
# `__init__.py` — two packages both named `tests` would shadow each other.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

PAYLOAD_TYPE = "application/vnd.waxseal-server-test.event+json"


def build_envelopes(tmp_path: Path, count: int) -> list[dict[str, Any]]:
    """Real client-side envelopes, produced by the library the server serves.

    Hand-rolling envelopes in the test would let the server agree with the test
    and disagree with every actual waxseal client — the one failure a wire
    contract exists to prevent.
    """
    trail = tmp_path / "fixture.jsonl"
    log = AuditLog.open(trail)
    for i in range(count):
        log.append(payload={"i": i}, payload_type=PAYLOAD_TYPE)
    return [json.loads(line) for line in trail.read_text().splitlines() if line.strip()]


@pytest.fixture
def envelopes(tmp_path: Path) -> list[dict[str, Any]]:
    return build_envelopes(tmp_path / "fixtures", 5)
