"""One clock, injectable.

CLAUDE.md rule 8: timestamps are injectable and tests never sleep to pass. The
server has the same need for its own records — an operator's `created_at`, a
key's `last_used_at` — and routing them through one function is what lets a
test freeze time without reaching into each store.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

NowFn = Callable[[], str]


def utc_now() -> str:
    """ISO-8601 with an explicit offset. Never a naive local timestamp: a
    record whose zone depends on the host is a record two hosts disagree on."""
    return datetime.now(UTC).isoformat()
