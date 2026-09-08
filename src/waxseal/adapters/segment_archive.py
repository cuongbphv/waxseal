"""Where a SEALED segment goes so its history outlives its local file — J3.

Two destinations, one operation. ``s3_destination`` is a thin adapter over
J1's ``upload_sealed_segment``, which owns the PUT, the Content-MD5 that
retention requires, and the separate question of whether Object Lock is
actually in force; nothing here re-derives any of that. ``server_import
_destination`` posts the segment to the chain server's imported-trail
endpoint, where an imported trail is read-only from the moment it lands (the
stored copy is ``chmod 0400``) -- which is exactly the semantics an archived
segment wants, so J3 needed no new server-side concept.

Both answer with an ``ArchiveReport`` instead of raising, because the caller
is a rotation and an archive is never allowed to take a rotation down with it
(CLAUDE.md rule 6). Each catches its own failures so the report can still name
the destination it was headed for -- "something failed somewhere" is not an
actionable line. ``sources/rotation.py`` wraps the call anyway, for the
failures a destination could not anticipate.

No boto3 import at module scope, here or anywhere (rule 1): the client is
injected, and J1's ``_resolve_client`` is the single place the ``s3`` extra is
touched at all.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Final

from waxseal.adapters.remote import RemoteRequest, Transport, urllib_transport
from waxseal.adapters.s3 import WormRetention, render_worm_state, upload_sealed_segment
from waxseal.domain.archive import ArchiveDestination, ArchiveReport, ArchiveState

#: A FIXED boundary, with a refusal if the segment contains it, rather than a
#: random one that is merely unlikely to collide. A segment's bytes include
#: payloads an agent chose, so "unlikely" is the wrong guarantee to offer
#: about attacker-influenced input; a labelled refusal is a state an operator
#: can act on, and a boundary appearing inside the part would otherwise split
#: the body into a truncated segment the server stores without complaint.
_MULTIPART_BOUNDARY: Final = "waxseal-sealed-segment-boundary"

#: Bytes that would break out of the quoted ``filename=`` parameter and forge
#: extra multipart headers. A trail path comes from an environment variable,
#: so the name reaching here is not always a well-behaved identifier.
_UNSAFE_IN_FILENAME: Final = frozenset('"\\\r\n')

_IMPORTS_PATH: Final = "/v1/imports"


def _utcnow() -> datetime:
    # Injectable via now_fn (rule 8): J1 compares a retain-until date against
    # the clock, and a test must be able to pin both sides without sleeping.
    return datetime.now(UTC)


def _why(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def s3_destination(
    *,
    bucket: str,
    key_prefix: str = "",
    client: Any | None = None,
    retention: WormRetention | None = None,
    now_fn: Callable[[], datetime] = _utcnow,
) -> ArchiveDestination:
    """An archive destination that PUTs each sealed segment into ``bucket``.

    ``retention`` is the operator's own Object Lock declaration, passed
    through to J1 untouched: waxseal invents no retention policy. With it
    absent this is a plain archive PUT, and the WORM state is still ASKED for
    afterwards rather than assumed, so the report can say "stored" without
    claiming storage would refuse an overwrite.
    """

    def archive(name: str, body: bytes) -> ArchiveReport:
        key = f"{key_prefix}{name}"
        destination = f"s3://{bucket}/{key}"
        try:
            upload = upload_sealed_segment(
                client,
                bucket=bucket,
                key=key,
                body=body,
                retention=retention,
                now_fn=now_fn,
            )
        except Exception as e:  # noqa: BLE001 - labelled, never swallowed (rule 6)
            return ArchiveReport(state=ArchiveState.FAILED, destination=destination, detail=_why(e))
        if not upload.uploaded:
            # J1's ONLY non-raising way to not upload: the extra is absent, so
            # nothing was asked. Not a failure and not a success (rule 5).
            return ArchiveReport(
                state=ArchiveState.NOT_ATTEMPTED,
                destination=destination,
                detail=upload.worm.detail,
            )
        return ArchiveReport(
            state=ArchiveState.STORED,
            destination=destination,
            # J1's own rendered line, carried verbatim: whether the archived
            # object version is under retention is a DIFFERENT claim from
            # whether it arrived, and this is the sentence that keeps the two
            # apart (including worm_unknown, which never reads as locked).
            detail=render_worm_state(upload.worm)[0],
        )

    return archive


def server_import_destination(
    base_url: str,
    *,
    transport: Transport | None = None,
    api_key: str | None = None,
    timeout: float = 10.0,
) -> ArchiveDestination:
    """An archive destination that posts each sealed segment to the chain
    server's ``POST /v1/imports`` endpoint.

    The credential is the operator's import-write token and travels only as an
    ``Authorization`` header -- never argv, never a URL query parameter, both
    of which leak into process lists and access logs (``RemoteBackend``'s rule,
    unchanged).

    The default transport is the package's stdlib one, which opens only http
    and https: an archive URL arriving from a config file must not turn
    ``file:///…`` into a local copy wearing an upload's clothes.
    """
    base = base_url.rstrip("/")
    send = transport or urllib_transport(timeout=timeout)
    destination = f"{base}{_IMPORTS_PATH}"

    def archive(name: str, body: bytes) -> ArchiveReport:
        headers = {"Accept": "application/json"}
        if api_key is not None:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            encoded, content_type = _multipart(name, body)
            headers["Content-Type"] = content_type
            response = send(
                RemoteRequest(method="POST", url=destination, headers=headers, body=encoded)
            )
        except Exception as e:  # noqa: BLE001 - labelled, never swallowed (rule 6)
            return ArchiveReport(state=ArchiveState.FAILED, destination=destination, detail=_why(e))
        if response.status != 201:
            return ArchiveReport(
                state=ArchiveState.FAILED,
                destination=destination,
                detail=f"HTTP {response.status}: {response.body[:512]!r}",
            )
        return ArchiveReport(
            state=ArchiveState.STORED,
            destination=destination,
            detail=f"the server accepted it as an imported trail (HTTP 201, "
            f"{len(body)} bytes): {_import_id(response.body)}. An imported trail is "
            "read-only evidence there — no server route can append to or edit it.",
        )

    return archive


def _import_id(body: bytes) -> str:
    """The id the server gave the stored copy, or a note that it gave none.

    An operator restoring a segment needs the handle to fetch it back, and a
    201 whose body this build cannot read is still a successful upload -- so
    the unreadable case degrades to a label rather than to a failure verdict
    about an archive that did arrive.
    """
    try:
        parsed = json.loads(body)
        return f"import_id={parsed['import_id']}"
    except (ValueError, KeyError, TypeError):
        return "the response named no import_id this build could read"


def _multipart(name: str, body: bytes) -> tuple[bytes, str]:
    """The segment as a ``multipart/form-data`` part named ``file``, matching
    the endpoint's ``UploadFile`` parameter.

    Hand-rolled because rule 1 leaves no HTTP client library to do it, and
    checked rather than trusted: both refusals below are corrupt-or-forged
    uploads the server would otherwise accept in silence.
    """
    if set(name) & _UNSAFE_IN_FILENAME:
        raise ValueError(
            f"refusing to upload under filename {name!r}: it contains a byte that would "
            "escape the quoted filename parameter and forge multipart headers"
        )
    marker = f"--{_MULTIPART_BOUNDARY}".encode("ascii")
    if marker in body:
        raise ValueError(
            "refusing to upload: the segment's own bytes contain the multipart boundary "
            "delimiter, which would split the body and store a truncated segment"
        )
    head = (
        f"--{_MULTIPART_BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("ascii")
    tail = f"\r\n--{_MULTIPART_BOUNDARY}--\r\n".encode("ascii")
    return head + body + tail, f"multipart/form-data; boundary={_MULTIPART_BOUNDARY}"
