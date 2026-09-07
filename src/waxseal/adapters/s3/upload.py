"""Sealed-segment upload and the optional boto3 client resolve."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from waxseal.adapters.s3.worm import (
    WormReport,
    WormRetention,
    WormState,
    WormStrength,
    WormSubject,
    _utcnow,
    object_worm_state,
)


@dataclass(frozen=True, slots=True)
class SegmentUpload:
    """Result of archiving one sealed segment.

    ``uploaded`` and ``worm.state`` are independent facts and must stay
    separable: a PUT can succeed while the retention check cannot be made, so
    collapsing the two would let a successful REQUEST masquerade as a verified
    guarantee. Read by J3 (rotation archiving), which reads these fields and
    needs none of this module's internals. `waxseal preflight` (J4) does NOT
    read this dataclass — it names WORM as a mechanism without checking
    bucket/object state itself (see `bucket_worm_state`'s docstring).
    """

    key: str
    uploaded: bool
    worm: WormReport


def _resolve_client(client: Any | None) -> tuple[Any | None, str]:
    """The injected client, or one built from the ``s3`` extra if available.

    The ONLY boto3 import in waxseal, and it is inside a function: rule 1
    keeps ``dependencies = []``, so the import can legitimately fail on a
    correct installation. A missing extra is a deployment condition, not an
    S3 outcome -- the question was never even asked -- so it becomes a
    labelled UNKNOWN upstream rather than an ImportError escaping into a
    caller's rotation flow.
    """
    if client is not None:
        return client, "caller-injected client"
    try:
        import boto3
    except ImportError as exc:
        return None, (
            "the 's3' extra is not installed (no boto3), so nothing was uploaded and "
            f"no lock state could be asked for: {exc}"
        )
    return boto3.client("s3"), "client built from the installed 's3' extra (boto3)"
def upload_sealed_segment(
    client: Any | None,
    *,
    bucket: str,
    key: str,
    body: bytes,
    retention: WormRetention | None = None,
    now_fn: Callable[[], datetime] = _utcnow,
) -> SegmentUpload:
    """Upload one SEALED segment, optionally under operator-declared retention.

    Opt-in: with ``retention=None`` this is a plain archive PUT and the WORM
    state is still REPORTED rather than assumed, because a bucket default
    retention could lock the object without this call asking for it.

    The retention state is always established by ASKING afterwards, never
    inferred from the PUT having succeeded. A successful request only proves
    S3 accepted the parameters; a caller that printed "locked" on that basis
    would be trusting the writer at write time, which is the very thing this
    library exists not to do.

    A failed PUT propagates. There is then no stored object version whose
    WORM state could be reported at all, and manufacturing one would be worse
    than the exception. A missing ``s3`` extra does NOT propagate: nothing was
    attempted, so it is reported as UNKNOWN with a label (rule 6). J3's
    rotation flow is the layer that decides an archive failure never blocks a
    rotation; that policy is not this function's to assume.
    """
    resolved, origin = _resolve_client(client)
    if resolved is None:
        return SegmentUpload(
            key=key,
            uploaded=False,
            worm=WormReport(
                subject=WormSubject.OBJECT_VERSION,
                state=WormState.UNKNOWN,
                strength=WormStrength.UNESTABLISHED,
                detail=origin,
            ),
        )

    kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key, "Body": body}
    if retention is not None:
        kwargs["ObjectLockMode"] = retention.mode
        kwargs["ObjectLockRetainUntilDate"] = retention.retain_until
        # put_object documents Content-MD5 (or a checksum algorithm header) as
        # REQUIRED when a retention period is set. Transport integrity only --
        # the chain's own hash is SHA-256 over the entry header (SPEC.md).
        kwargs["ContentMD5"] = base64.b64encode(
            hashlib.md5(body, usedforsecurity=False).digest()
        ).decode("ascii")
    resolved.put_object(**kwargs)

    return SegmentUpload(
        key=key,
        uploaded=True,
        worm=object_worm_state(resolved, bucket=bucket, key=key, now_fn=now_fn),
    )
