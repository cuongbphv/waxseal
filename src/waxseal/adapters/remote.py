"""RemoteBackend, an HTTP peer to JSONL/SQLite/S3 (DESIGN.md's remote
upgrade path). Wire contract v1 is documented normatively in REMOTE.md; this
is the reference client.

Trust model (REMOTE.md, DESIGN.md section 10): the server is a TRUSTED
WRITER, not bound against a malicious one. verify_chain still runs entirely
client-side over whatever entries() yields, so a corrupted or lying server
is caught the same way a corrupted local file is (tamper-evident, not
tamper-proof), but a server that consistently forges a full rewrite (every
header, every hash, self-consistent) is the same honest limit a local
attacker-writable disk already has. REMOTE.md's recommendation is the same
one anchoring already gives local backends: anchor the head independently
(checkpoint_for + an AnchorSink, e.g. adapters/anchors.py's HTTPAnchorSink)
rather than
trusting the server's own history as the last word.

Per-append receipts (SPEC.md section 19, REMOTE.md section 10): when the server
returns `receipt_seq`/`receipt_head` on a `201` and the caller named a local
trail to keep them beside, each acknowledgment is filed in a `.receipts`
sidecar. That is corroboration, never the evidence itself — the entry is
already durable when the `201` arrives, so a sidecar that cannot be written is
labelled and moved past, never allowed to fail or retry an append that
succeeded. It shrinks the rewrite window from the anchor cadence to one entry,
and no further: a rewrite that curates BOTH the trail and the sidecar passes
this check, and only the server's own receipt chain catches that.

CAS retry mirrors s3.py's conditional-write precedent: the server checks
(seq, prev_hash) atomically server-side; a 409 means another writer won the
race, so the client re-reads /head and rebuilds. It never forges ahead on a
stale tail (CLAUDE.md rule 7).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
import warnings
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from waxseal.adapters._envelope import from_obj, to_obj
from waxseal.adapters.receipts import append_receipt
from waxseal.domain.header import GENESIS_PREV_HASH, Entry
from waxseal.domain.receipts import RECEIPT_HEX64

_MAX_RACE_RETRIES = 32  # s3.py's own ceiling: same rationale, not a new number
# Pagination has no natural retry ceiling like a CAS race does, but an
# unbounded `while True` is still a hang waiting to happen against a broken
# or hostile server, the same "fail loudly instead of spinning forever"
# rationale as _MAX_RACE_RETRIES, just a far more generous bound since a
# legitimate large chain may need many pages.
_MAX_PAGES = 1_000_000


@dataclass(frozen=True, slots=True)
class RemoteRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None


@dataclass(frozen=True, slots=True)
class RemoteResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


Transport = Callable[[RemoteRequest], RemoteResponse]


def _warn_receipt(message: str) -> None:
    warnings.warn(f"receipt sidecar: {message}", RuntimeWarning, stacklevel=3)


def _receipt_fields(body: bytes) -> tuple[tuple[int, str] | None, str | None]:
    """Read `(receipt_seq, receipt_head)` out of a `201` body.

    Returns ``(fields, complaint)``. Both None is the quiet case REMOTE.md
    section 10 requires: a server that does not implement receipts is doing its
    job, not degrading. A complaint is anything this client cannot use, and it
    is never written: a half-understood acknowledgment stored in THIS project's
    own format would surface later as `malformed_receipt_record` — a break
    manufactured out of a server's bad field, with no tampering anywhere.
    """
    if not body.strip():
        return None, None
    try:
        obj = json.loads(body)
    except ValueError:
        return None, "the 201 body is not JSON"
    if not isinstance(obj, dict):
        return None, f"the 201 body is not a JSON object (got {type(obj).__name__})"
    if "receipt_seq" not in obj and "receipt_head" not in obj:
        return None, None
    if "receipt_seq" not in obj or "receipt_head" not in obj:
        # REMOTE.md section 10: both or neither. One alone names a position in
        # a chain with no head, or a head at no position.
        return None, "the 201 body carries only one of receipt_seq/receipt_head"
    receipt_seq, receipt_head = obj["receipt_seq"], obj["receipt_head"]
    if not isinstance(receipt_seq, int) or isinstance(receipt_seq, bool) or receipt_seq < 0:
        return None, f"receipt_seq is not a non-negative integer ({receipt_seq!r})"
    if (
        not isinstance(receipt_head, str)
        or len(receipt_head) != 64
        or not set(receipt_head) <= RECEIPT_HEX64
    ):
        return None, f"receipt_head is not 64 lowercase hex characters ({receipt_head!r})"
    return (receipt_seq, receipt_head), None


class RemoteError(RuntimeError):
    """Any HTTP response RemoteBackend cannot interpret as a protocol-defined
    state (404 = empty, 409 = lost race). A caller's try_append sees this
    like any other backend exception, so it becomes a drop, never a fork."""


_ALLOWED_SCHEMES: Final = frozenset({"http", "https"})


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Redirects are not part of REMOTE.md's wire contract, and stdlib's
    redirect handler re-sends EVERY header on the hop, the Authorization
    bearer token (WAXSEAL_API_KEY) included, to whatever host Location
    names, even across an https→http downgrade (the CVE-2018-1000007 /
    CVE-2018-18074 credential-leak class in requests/urllib3). So a 3xx is
    never followed: it re-raises as HTTPError and surfaces through the
    capture path below as its own status, which every caller already
    rejects like any other non-2xx."""

    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


_OPENER: Final = urllib.request.build_opener(_RefuseRedirects)


def urllib_transport(*, timeout: float = 10.0) -> Transport:
    """The stdlib transport (CLAUDE.md rule 1: zero runtime dependencies).

    HTTPError is captured as a RemoteResponse, since its status code is
    protocol-meaningful (404/409 are expected outcomes, not failures).
    URLError/socket timeout propagate uncaught: there is no protocol-defined
    status to carry "the server never answered" as, and inventing one would
    hide a real connectivity failure behind a fake HTTP response.

    Only http and https are opened. Every network adapter in the package
    funnels through here, and urllib's default opener also speaks ``file:``
    and ``ftp:``. Without this, a URL arriving from a config file or a CI
    variable makes ``--tsa-url file:///…`` a local file read wearing a
    timestamp reply's clothes. Raises ``ValueError`` before any request.
    """

    def transport(request: RemoteRequest) -> RemoteResponse:
        scheme = urllib.parse.urlsplit(request.url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise ValueError(
                f"refusing URL scheme {scheme or '(none)'!r}: this transport opens "
                f"only {', '.join(sorted(_ALLOWED_SCHEMES))}"
            )
        req = urllib.request.Request(
            request.url, data=request.body, headers=request.headers, method=request.method
        )
        try:
            with _OPENER.open(req, timeout=timeout) as resp:  # noqa: S310
                return RemoteResponse(
                    status=resp.status, headers=dict(resp.headers), body=resp.read()
                )
        except urllib.error.HTTPError as e:
            return RemoteResponse(status=e.code, headers=dict(e.headers or {}), body=e.read())

    return transport


def _default_now() -> str:
    return datetime.now(UTC).isoformat()


class RemoteBackend:
    def __init__(
        self,
        base_url: str,
        *,
        transport: Transport | None = None,
        api_key: str | None = None,
        chain_id: str = "default",
        timeout: float = 10.0,
        receipts_trail: Path | str | None = None,
        now_fn: Callable[[], str] | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._transport = transport or urllib_transport(timeout=timeout)
        self._api_key = api_key
        self._chain_id = chain_id
        # The trail path the `.receipts` sidecar is named after, exactly as
        # `.anchors` is named after the trail it anchors. None means the
        # caller named nowhere to keep acknowledgments, which is "not
        # recorded" and never an error: a receipt is corroboration, and this
        # backend's chain lives server-side either way.
        self._receipts_trail = None if receipts_trail is None else Path(receipts_trail)
        self._now = now_fn or _default_now

    def _url(self, path: str) -> str:
        # chain_id is caller-supplied (AuditLog.open(chain_id=...)), so quote it
        # so it cannot inject extra path segments or a query string into the
        # request the server sees.
        return f"{self._base}/v1/chains/{urllib.parse.quote(self._chain_id, safe='')}{path}"

    def _headers(self, *, json_body: bool) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if json_body:
            headers["Content-Type"] = "application/json"
        if self._api_key is not None:
            # Never argv, never a URL query param (both leak into process
            # lists / access logs): only ever this header.
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    # -- backend protocol -----------------------------------------------------
    def append(self, build: Callable[[int, str], Entry]) -> Entry:
        for _ in range(_MAX_RACE_RETRIES):
            next_seq, prev_hash = self._head()
            entry = build(next_seq, prev_hash)
            body = json.dumps(
                to_obj(entry, backend="Remote"), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            resp = self._transport(
                RemoteRequest(
                    method="POST",
                    url=self._url("/entries"),
                    headers=self._headers(json_body=True),
                    body=body,
                )
            )
            if resp.status == 201:
                self._record_receipt(entry, resp.body)
                return entry
            if resp.status == 409:
                continue  # lost the race server-side: re-read /head, rebuild
            raise RemoteError(f"POST /entries failed: HTTP {resp.status}: {resp.body!r}")
        raise RemoteError(
            f"append lost the server-side race {_MAX_RACE_RETRIES} times; "
            "writer contention is pathological"
        )

    # -- per-append receipts (SPEC.md section 19) -------------------------------
    def _record_receipt(self, entry: Entry, body: bytes) -> None:
        """File the server's acknowledgment beside the trail, best-effort.

        Nothing here may raise: the entry is already durable server-side when
        this runs, so a failure that propagated would report a persisted entry
        as a dropped write (the accounting error `AttestationFailure` exists to
        prevent one layer up). Every degradation is warned instead of
        swallowed — rule 6 — because a sidecar that silently stopped recording
        looks exactly like a server that never issued a receipt.
        """
        if self._receipts_trail is None:
            return
        try:
            fields, complaint = _receipt_fields(body)
            if complaint is not None:
                _warn_receipt(f"{complaint}; nothing recorded for seq={entry.header.seq}")
                return
            if fields is None:
                return
            receipt_seq, receipt_head = fields
            append_receipt(
                self._receipts_trail,
                seq=entry.header.seq,
                entry_hash=entry.entry_hash,
                receipt_seq=receipt_seq,
                receipt_head=receipt_head,
                source=self._base,
                ts=self._now(),
            )
        except Exception as e:
            # Deliberately broader than OSError, and for drops.py's reason: a
            # broken now_fn is a failed record exactly like a full disk, not a
            # different class of problem this path is allowed to raise on.
            _warn_receipt(f"could not record the acknowledgment for seq={entry.header.seq}: {e!r}")

    def entries(self) -> Iterator[Entry]:
        cursor: str | None = None
        for _ in range(_MAX_PAGES):
            if cursor is None:
                path = "/entries"
            else:
                path = f"/entries?cursor={urllib.parse.quote(cursor, safe='')}"
            resp = self._transport(
                RemoteRequest(
                    method="GET",
                    url=self._url(path),
                    headers=self._headers(json_body=False),
                    body=None,
                )
            )
            if resp.status == 404:
                return  # no chain at this chain_id yet, same as "empty"
            if resp.status != 200:
                raise RemoteError(f"GET /entries failed: HTTP {resp.status}: {resp.body!r}")
            page = self._parse_entries_page(resp.body)
            for obj in page["entries"]:
                yield from_obj(obj)
            next_cursor = page.get("next_cursor")
            if next_cursor is None:
                return
            if next_cursor == cursor:
                # A cursor that never advances cannot terminate this loop on
                # its own: a broken or hostile server handing back the same
                # token forever must fail loudly, not spin forever.
                raise RemoteError(
                    f"GET /entries returned the same cursor twice ({cursor!r}) "
                    "— the server is not making progress"
                )
            cursor = next_cursor
        raise RemoteError(
            f"GET /entries did not terminate within {_MAX_PAGES} pages; "
            "the server is either pathologically large or not terminating"
        )

    @staticmethod
    def _parse_entries_page(body: bytes) -> dict[str, Any]:
        # A 200 with an unparsable or unexpectedly-shaped body (a captive
        # portal, a proxy error page, a truncated response) is not a
        # protocol-defined outcome any more than a bad status code is. It
        # must become the same RemoteError a 5xx would, never an uncaught
        # JSONDecodeError/KeyError escaping through the CLI (cli.py's own
        # try/except only catches OSError/RemoteError).
        try:
            page = json.loads(body)
            if not isinstance(page, dict) or "entries" not in page:
                raise ValueError("missing 'entries' key")
        except (json.JSONDecodeError, ValueError) as e:
            raise RemoteError(f"GET /entries returned an unparsable body: {e}") from e
        return page

    # -- tail discovery ---------------------------------------------------------
    def _head(self) -> tuple[int, str]:
        resp = self._transport(
            RemoteRequest(
                method="GET",
                url=self._url("/head"),
                headers=self._headers(json_body=False),
                body=None,
            )
        )
        if resp.status == 404:
            return 0, GENESIS_PREV_HASH
        if resp.status != 200:
            raise RemoteError(f"GET /head failed: HTTP {resp.status}: {resp.body!r}")
        try:
            obj = json.loads(resp.body)
            return int(obj["seq"]) + 1, str(obj["entry_hash"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            raise RemoteError(f"GET /head returned an unparsable body: {e}") from e
