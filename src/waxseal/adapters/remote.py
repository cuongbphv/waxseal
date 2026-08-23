"""RemoteBackend — an HTTP peer to JSONL/SQLite/S3 (DESIGN.md's remote
upgrade path). Wire contract v1 is documented normatively in REMOTE.md; this
is the reference client.

Trust model (REMOTE.md, DESIGN.md section 10): the server is a TRUSTED
WRITER, not bound against a malicious one. verify_chain still runs entirely
client-side over whatever entries() yields, so a corrupted or lying server
is caught the same way a corrupted local file is (tamper-evident, not
tamper-proof) — but a server that consistently forges a full rewrite (every
header, every hash, self-consistent) is the same honest limit a local
attacker-writable disk already has. REMOTE.md's recommendation is the same
one anchoring already gives local backends: anchor the head independently
(checkpoint_for + an AnchorSink, e.g. adapters/anchors.py's HTTPAnchorSink)
rather than
trusting the server's own history as the last word.

CAS retry mirrors s3.py's conditional-write precedent: the server checks
(seq, prev_hash) atomically server-side; a 409 means another writer won the
race, so the client re-reads /head and rebuilds — never forges ahead on a
stale tail (CLAUDE.md rule 7).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Final

from waxseal.adapters._envelope import from_obj, to_obj
from waxseal.domain.header import GENESIS_PREV_HASH, Entry

_MAX_RACE_RETRIES = 32  # s3.py's own ceiling — same rationale, not a new number
# Pagination has no natural retry ceiling like a CAS race does, but an
# unbounded `while True` is still a hang waiting to happen against a broken
# or hostile server — same "fail loudly instead of spinning forever"
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


class RemoteError(RuntimeError):
    """Any HTTP response RemoteBackend cannot interpret as a protocol-defined
    state (404 = empty, 409 = lost race). A caller's try_append sees this
    like any other backend exception — it becomes a drop, never a fork."""


_ALLOWED_SCHEMES: Final = frozenset({"http", "https"})


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Redirects are not part of REMOTE.md's wire contract, and stdlib's
    redirect handler re-sends EVERY header on the hop — the Authorization
    bearer token (WAXSEAL_API_KEY) included — to whatever host Location
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

    HTTPError is captured as a RemoteResponse — its status code is
    protocol-meaningful (404/409 are expected outcomes, not failures).
    URLError/socket timeout propagate uncaught: there is no protocol-defined
    status to carry "the server never answered" as, and inventing one would
    hide a real connectivity failure behind a fake HTTP response.

    Only http and https are opened. Every network adapter in the package
    funnels through here, and urllib's default opener also speaks ``file:``
    and ``ftp:`` — without this, a URL arriving from a config file or a CI
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


class RemoteBackend:
    def __init__(
        self,
        base_url: str,
        *,
        transport: Transport | None = None,
        api_key: str | None = None,
        chain_id: str = "default",
        timeout: float = 10.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._transport = transport or urllib_transport(timeout=timeout)
        self._api_key = api_key
        self._chain_id = chain_id

    def _url(self, path: str) -> str:
        # chain_id is caller-supplied (AuditLog.open(chain_id=...)) — quote it
        # so it cannot inject extra path segments or a query string into the
        # request the server sees.
        return f"{self._base}/v1/chains/{urllib.parse.quote(self._chain_id, safe='')}{path}"

    def _headers(self, *, json_body: bool) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if json_body:
            headers["Content-Type"] = "application/json"
        if self._api_key is not None:
            # Never argv, never a URL query param (both leak into process
            # lists / access logs) — only ever this header.
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
                return entry
            if resp.status == 409:
                continue  # lost the race server-side: re-read /head, rebuild
            raise RemoteError(f"POST /entries failed: HTTP {resp.status}: {resp.body!r}")
        raise RemoteError(
            f"append lost the server-side race {_MAX_RACE_RETRIES} times; "
            "writer contention is pathological"
        )

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
                return  # no chain at this chain_id yet — same as "empty"
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
                # its own — a broken or hostile server handing back the same
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
        # protocol-defined outcome any more than a bad status code is — it
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
