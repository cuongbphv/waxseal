"""OtsAnchorSink: submit a checkpoint digest to an OpenTimestamps calendar.

Wire protocol: POST the raw 32-byte SHA-256 to ``<calendar>/digest`` with
``Accept: application/vnd.opentimestamps.v1``; the calendar answers with a
pending proof. (Verified against opentimestamps-server's ``otsserver/rpc.py``
and python-opentimestamps' ``calendar.py``, 2026-08-23.)

One calendar per sink, on purpose. Redundancy in OpenTimestamps comes from
submitting the same digest to several calendars, which here is several anchor
events — an aggregating sink would have to decide what a partial failure means,
and that is an operator's call, not a default.

The proof this stores is PENDING and stays opaque: see domain/ots.py for why
this library does not parse or upgrade it.
"""

from __future__ import annotations

from waxseal.adapters.remote import RemoteRequest, Transport, urllib_transport
from waxseal.domain.checkpoint import Checkpoint, checkpoint_frame
from waxseal.domain.ots import OTS_ACCEPT, encode_receipt, ots_digest


class OtsAnchorSink:
    name = "ots"

    def __init__(
        self,
        calendar_url: str,
        *,
        transport: Transport | None = None,
        timeout: float = 10.0,
    ) -> None:
        # No default calendar: which public calendars are live changes over
        # time, and baking a stale URL into the library would send an
        # operator's digests nowhere while looking like it worked.
        self._url = calendar_url.rstrip("/") + "/digest"
        self._transport = transport or urllib_transport(timeout=timeout)

    def anchor(self, checkpoint: Checkpoint) -> str | None:
        response = self._transport(
            RemoteRequest(
                method="POST",
                url=self._url,
                headers={"Accept": OTS_ACCEPT},
                body=ots_digest(checkpoint_frame(checkpoint)),
            )
        )
        if response.status != 200:
            raise RuntimeError(f"calendar {self._url} refused the digest: HTTP {response.status}")
        if not response.body:
            # An empty 200 is not a timestamp. Returning None here would file
            # a record claiming an anchor with no proof behind it.
            raise RuntimeError(f"calendar {self._url} returned an empty proof")
        return encode_receipt(response.body)
