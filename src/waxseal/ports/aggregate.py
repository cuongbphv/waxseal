"""AggregateSource: where a checkpoint's forward-secure aggregate commitment
comes from.

Sealing and reading the accumulator are different privileges. Sealing needs
the current epoch key; committing to the accumulator that is already on disk
needs nothing but read access. Keeping them apart lets `waxseal anchor` — which
holds no key and must never be able to seal — still bind the aggregate into the
checkpoint it publishes. Without that split the CLI would anchor a sealed trail
as if it had no aggregate at all, and the anchor would witness a chain shape
that nothing ties back to the seals.

FileAttestor satisfies this port; so does the read-only AggregateReader.
"""

from __future__ import annotations

from typing import Protocol


class AggregateSource(Protocol):
    def read_aggregate(self) -> tuple[int, int, str] | None:
        """``(agg_start, epoch, agg)`` for the trail, or None when there is no
        accumulator — an unsealed trail, or a scheme that keeps none. None is
        "nothing to commit to", never "the aggregate is empty": a checkpoint
        must not claim a binding nothing can be checked against."""
        ...
