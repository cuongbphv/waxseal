"""Rfc3161AnchorSink: timestamp a checkpoint at an external Time-Stamp Authority.

This is the sink that makes a checkpoint's time attested rather than asserted.
It stamps ``sha256(checkpoint_frame(checkpoint))`` — the same bytes every other
sink witnesses — which is why the aggregate binding lives inside the frame
(domain/checkpoint.py) rather than beside it in JSON: a TSA signs the imprint,
so anything outside the framed bytes is outside the attestation.

The sink refuses to file a token that does not attest the frame it just sent.
Storing one anyway would put a receipt next to a record it says nothing about,
and a later reader would have no way to tell that from a genuine anchor.

The check that gate runs is STRUCTURAL ONLY. The token's CMS signature and the
TSA's certificate chain are not verified here or anywhere else in this library
(domain/rfc3161.py says why, and names the ``openssl ts -verify`` command that
does it). So a filed receipt means "a well-formed token committing to these
exact bytes came back from this URL", never "a genuine TSA issued it" — a
receipt this sink stored is still unauthenticated evidence.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable

from waxseal.adapters.remote import RemoteRequest, Transport, urllib_transport
from waxseal.domain.checkpoint import Checkpoint, SinkReceipt, checkpoint_frame
from waxseal.domain.rfc3161 import (
    check_timestamp_resp,
    encode_receipt,
    encode_timestamp_req,
)

CONTENT_TYPE = "application/timestamp-query"
ACCEPT = "application/timestamp-reply"


def _default_nonce() -> int:
    # 64 bits from the OS CSPRNG. The nonce only has to make a replayed token
    # from an earlier request implausible, and it is checked back on the
    # response before the receipt is kept.
    return secrets.randbits(64)


class Rfc3161AnchorSink:
    """POST a TimeStampReq, keep the reply as an ``rfc3161:`` receipt.

    ``nonce_fn`` is injectable so a test can freeze it (and so an operator
    talking to a TSA that rejects nonced requests can return None). Entropy
    lives here in the adapter, never in the domain encoder.
    """

    name = "rfc3161"

    def __init__(
        self,
        url: str,
        *,
        transport: Transport | None = None,
        nonce_fn: Callable[[], int | None] | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._url = url
        self._transport = transport or urllib_transport(timeout=timeout)
        self._nonce_fn = nonce_fn or _default_nonce

    def anchor(self, checkpoint: Checkpoint) -> SinkReceipt:
        frame = checkpoint_frame(checkpoint)
        nonce = self._nonce_fn()
        request = encode_timestamp_req(frame, nonce=nonce)
        response = self._transport(
            RemoteRequest(
                method="POST",
                url=self._url,
                headers={"Content-Type": CONTENT_TYPE, "Accept": ACCEPT},
                body=request,
            )
        )
        if response.status != 200:
            raise RuntimeError(f"timestamp request to {self._url} failed: HTTP {response.status}")
        reason = check_timestamp_resp(response.body, frame, expected_nonce=nonce)
        if reason is not None:
            # AnchorSink's contract is raise-on-failure. Filing this token
            # would record an anchor for bytes it does not attest.
            raise RuntimeError(f"timestamp response from {self._url} rejected: {reason}")
        # The nonce rides along for recording: checked here and then merely
        # dropped, a later verify would have nothing to compare, and a token
        # swapped in from a DIFFERENT request over the same imprint would pass
        # re-verify — the anchor-time-only gap SPEC.md section 17 describes
        # for records with no stored nonce.
        return SinkReceipt(encode_receipt(response.body), nonce=nonce)
