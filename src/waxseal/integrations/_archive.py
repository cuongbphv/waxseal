"""Where a hook's sealed segments go off-box: the env -> destination seam (J3).

J3 shipped both halves of the mechanism -- `adapters/segment_archive.py`'s two
destinations and `sources/rotation.py`'s three-state report -- and shipped
nothing that could configure one. Every hook called ``open_segmented`` without
``archive=``, so ``archive_not_attempted`` was the only line a hook-driven
rotation could ever print, forever. This module is the missing seam, and it is
deliberately the ONLY one: a hook takes no archive argument, so there is exactly
one place an operator configures this and exactly one place to look when the
line says nothing was sent.

``WAXSEAL_ARCHIVE`` names the destination by URL scheme:

* ``s3://bucket/prefix/`` -- J1's PUT, with the operator's own Object Lock
  policy left to the bucket. waxseal invents no retention here.
* ``https://server`` -- ``POST /v1/imports`` on a waxseal chain server, where
  an imported trail is read-only from the moment it lands.

Unset means unset: no destination is built, nothing is sent, and rotation
prints ``archive_not_attempted`` with its own "no archive destination
configured" detail. Opt-in stays opt-in, and the absence stays visible.

CREDENTIAL (a THIRD authority, not a reuse -- owner-visible decision made
01/09/2026 while wiring this)
---------------------------------------------------------------------------
The server import path reads ``WAXSEAL_ARCHIVE_API_KEY``. It is deliberately
neither of the two credentials that already exist:

* ``WAXSEAL_API_KEY`` is the CHAIN-WRITE credential: it appends to a live
  chain. Archiving needs only "create an imported, read-only trail". Reusing
  the chain key would put a token that can extend live history on every box
  that merely keeps backups, and would make an archive-only deployment
  impossible to express -- the exact over-grant that makes a compromised
  developer machine able to write history rather than only to preserve it.
* ``WAXSEAL_WITNESS_API_KEY`` belongs to the WITNESS authority, which is
  defined by being a different administrative authority from the server
  (CLAUDE.md: the server's write credential never crosses that boundary).
  Spending it on a server-facing write would collapse the one boundary τ
  counts, and would do it silently -- the separation degree an operator
  declares would no longer describe the deployment.

So the two write directions stay separately revocable: rotating the archive
token must not stop the trail being written, and rotating the chain token must
not stop archives arriving.

A value this build cannot use is NOT silently ignored and does not raise into a
hook (which would cost the developer their tool call). It becomes a destination
that reports ``archive_not_attempted`` naming the misconfiguration, so the
rotation line says nothing was sent AND why -- rule 6, and the third state kept
honest rather than collapsed into "nothing was configured".

Only the scheme of a bad value is ever echoed, never the value: an archive URL
can carry userinfo, and a hook's stderr is not a place to spill a credential
an operator typed into an environment variable.
"""

from __future__ import annotations

import os
import urllib.parse
from collections.abc import Mapping
from typing import Final

from waxseal.adapters.segment_archive import s3_destination, server_import_destination
from waxseal.domain.archive import ArchiveDestination, ArchiveReport, ArchiveState

#: The one place a hook's archive destination comes from.
ENV_ARCHIVE: Final = "WAXSEAL_ARCHIVE"

#: The import-write credential. See the module docstring: a third authority,
#: never `WAXSEAL_API_KEY` and never `WAXSEAL_WITNESS_API_KEY`.
ENV_ARCHIVE_API_KEY: Final = "WAXSEAL_ARCHIVE_API_KEY"

_S3_SCHEME: Final = "s3"
_HTTP_SCHEMES: Final = ("http", "https")

_SUPPORTED: Final = "s3://bucket/prefix/ or https://chain-server"


def archive_destination(
    env: Mapping[str, str] | None = None,
) -> ArchiveDestination | None:
    """The destination ``WAXSEAL_ARCHIVE`` names, or ``None`` when unset.

    ``None`` is the opted-out state and the caller must pass it through
    unchanged: ``sources/rotation.py`` turns it into the "no archive
    destination configured" line, which is what an operator who believes they
    configured one needs to see.
    """
    environ = os.environ if env is None else env
    value = environ.get(ENV_ARCHIVE, "").strip()
    if not value:
        return None
    scheme = urllib.parse.urlsplit(value).scheme.lower()
    if scheme == _S3_SCHEME:
        return _s3(value)
    if scheme in _HTTP_SCHEMES:
        # No api_key present means the header is simply not sent, and the
        # server answers 401. A refusal invented here would report "not
        # attempted" about a server that might not require a credential at
        # all; the server's own status is the honest answer.
        return server_import_destination(value, api_key=environ.get(ENV_ARCHIVE_API_KEY))
    return _unusable(
        f"scheme {scheme or '(none)'!r}",
        f"{ENV_ARCHIVE} names a scheme this build does not archive to "
        f"(supported: {_SUPPORTED}), so nothing was sent anywhere",
    )


def _s3(value: str) -> ArchiveDestination:
    parts = urllib.parse.urlsplit(value)
    bucket = parts.netloc
    if not bucket:
        return _unusable(
            "s3 (no bucket)",
            f"{ENV_ARCHIVE} is an s3 URL that names no bucket "
            f"(expected {_SUPPORTED}), so nothing was sent anywhere",
        )
    return s3_destination(bucket=bucket, key_prefix=_key_prefix(parts.path))


def _key_prefix(path: str) -> str:
    """The URL path as an S3 key prefix, always separator-terminated.

    ``s3://bucket/segments`` means the folder, not a rename: the destination
    concatenates prefix + segment name, so leaving the separator off would
    store ``segmentstrail.00000.jsonl`` -- an object nobody looks for under a
    name nobody chose.
    """
    prefix = path.lstrip("/")
    if not prefix or prefix.endswith("/"):
        return prefix
    return prefix + "/"


def _unusable(where: str, why: str) -> ArchiveDestination:
    """A destination that sends nothing and says so, naming the cause.

    NOT_ATTEMPTED rather than FAILED: nothing was sent, so nothing failed --
    the misconfiguration is upstream of the attempt. And not ``None``, because
    ``None`` renders as "no destination configured", which is a different fact
    from the one an operator who set the variable needs to read.
    """

    def archive(name: str, body: bytes) -> ArchiveReport:
        return ArchiveReport(
            state=ArchiveState.NOT_ATTEMPTED,
            destination=f"(the {ENV_ARCHIVE} value: {where})",
            detail=why,
        )

    return archive
