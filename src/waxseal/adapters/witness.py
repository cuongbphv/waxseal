"""HTTPWitness: an anchor endpoint that can also be read back.

Both halves of REMOTE.md's witness contract in one object, because they are one
service: POST a checkpoint, GET the checkpoints it holds. Shares
``HTTPAnchorSink``'s publish behavior and ``RemoteBackend``'s Transport, so
there is one stdlib-only HTTP path and one Bearer-header shape across the
package. The CREDENTIAL is not shared: the CLI hands witnesses
``WAXSEAL_WITNESS_API_KEY``, never the chain server's ``WAXSEAL_API_KEY``,
a witness holding the chain's write credential could append to the very
chain it exists to cross-check (REMOTE.md section 8).

Point it at a host that is NOT the chain server. A witness in the same
administrative domain as the writer it is supposed to check can be forked
alongside it, and the arrangement proves nothing. This class cannot enforce
that, and says so here because the deployment is the security argument.
"""

from __future__ import annotations

import json
from typing import Any

from waxseal.adapters.anchors import HTTPAnchorSink
from waxseal.adapters.remote import RemoteError, RemoteRequest, Transport, urllib_transport
from waxseal.domain.checkpoint import Checkpoint
from waxseal.domain.witnessing import WitnessObservation


class HTTPWitness:
    """An ``AnchorSink`` (publish) and a ``WitnessReader`` (read back)."""

    def __init__(
        self,
        url: str,
        *,
        name: str | None = None,
        transport: Transport | None = None,
        api_key: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._url = url
        # Verdicts are printed per witness, so the default identity is the URL
        # rather than a shared literal: three witnesses that all called
        # themselves "http" would make a disagreement unattributable.
        self.name = name or url
        self._transport = transport or urllib_transport(timeout=timeout)
        self._api_key = api_key
        self._sink = HTTPAnchorSink(
            url, transport=self._transport, api_key=api_key, timeout=timeout
        )

    def anchor(self, checkpoint: Checkpoint) -> str | None:
        return self._sink.anchor(checkpoint)

    def fetch(self) -> WitnessObservation:
        """Read back what this witness holds.

        A 404 is an answer: the witness has seen nothing. Anything else that
        is not a checkpoint list raises: a proxy error page or a changed API
        must never reach a verifier disguised as an empty observation, which
        would read as "no disagreement found".
        """
        headers = {"Accept": "application/json"}
        if self._api_key is not None:
            headers["Authorization"] = f"Bearer {self._api_key}"
        response = self._transport(
            RemoteRequest(method="GET", url=self._url, headers=headers, body=None)
        )
        if response.status == 404:
            return WitnessObservation(checkpoints=(), unreadable=0)
        if response.status != 200:
            raise RemoteError(f"witness GET {self._url} failed: HTTP {response.status}")

        try:
            payload = json.loads(response.body)
        except (ValueError, TypeError) as e:
            raise RemoteError(f"witness {self._url} returned an unparsable body: {e}") from e
        if not isinstance(payload, dict) or not isinstance(payload.get("checkpoints"), list):
            raise RemoteError(
                f"witness {self._url} returned no checkpoint list; "
                "an unusable answer is not an empty one"
            )

        checkpoints: list[Checkpoint] = []
        unreadable = 0
        for record in payload["checkpoints"]:
            parsed = _parse_checkpoint(record)
            if parsed is None:
                # Counted, never dropped: a witness holding records this build
                # cannot read has given less coverage than it appears to, and
                # the verdict must be able to say by how much.
                unreadable += 1
                continue
            checkpoints.append(parsed)
        return WitnessObservation(checkpoints=tuple(checkpoints), unreadable=unreadable)


def _parse_checkpoint(record: Any) -> Checkpoint | None:
    """One witnessed checkpoint, or ``None`` if this build cannot read it.

    Unknown extra keys are ignored on purpose, since a witness that records more
    than waxseal knows about is a newer witness, not a broken one.
    """
    if not isinstance(record, dict):
        return None
    try:
        return Checkpoint(
            seq=int(record["seq"]),
            entry_hash=str(record["entry_hash"]),
            root=str(record["root"]),
            agg_commit=None if record.get("agg_commit") is None else str(record["agg_commit"]),
            agg_epoch=None if record.get("agg_epoch") is None else int(record["agg_epoch"]),
        )
    except (KeyError, TypeError, ValueError):
        return None
