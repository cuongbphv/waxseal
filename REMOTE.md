# waxseal REMOTE — wire contract v1

Status: REVIEW — this wire contract is complete and covered by the fake-server/real-HTTP
test matrix; already treated as append-only in practice, same discipline as SPEC.md (new
sections and new endpoints may be added; existing normative text here may never change
meaning). Formal freeze is still tied to SPEC.md's own v1.0 freeze — REVIEW marks
readiness for that, not a change to the condition.

The key words MUST, MUST NOT, SHOULD are to be interpreted as in RFC 2119.

This document specifies the HTTP contract `RemoteBackend` (`src/waxseal/adapters/remote.py`)
speaks to a chain server, so that any server implementing it — hosted, self-run, a thin
shim over an existing datastore — is a compatible waxseal peer alongside JSONL, SQLite,
and S3. waxseal ships the client only; it does not ship a server.

## 1. Trust model

**The server is a TRUSTED WRITER, not bound against a malicious one.** This is a
deliberate scope boundary, not an oversight:

- `verify_chain` runs entirely **client-side**, over whatever `entries()` yields. A
  server that corrupts, truncates, or reorders entries is caught exactly as a corrupted
  local file would be (`entry_hash_mismatch`, `seq_gap`, `prev_hash_mismatch`) — this is
  tamper-**evident**, the same guarantee every other backend gives.
- What no client-side check can catch is a server that **consistently forges a whole
  rewrite**: every header, every hash, self-consistent from genesis. A locally-writable
  disk has the identical blind spot. This is not specific to the remote backend.
- The mitigation is the same one waxseal already gives local backends: **anchor the
  head independently** — `AuditLog.anchor()` / `checkpoint_for` plus an `AnchorSink`
  (e.g. `HTTPAnchorSink`, posting to a *different* service than the chain server
  itself) — so a full rewrite has to also forge the anchor history, not just the chain.
- Do not build an access-control or Byzantine-fault-tolerant story on top of this
  contract and call it covered by waxseal. Authentication (section 5) controls who may
  *write*; it says nothing about whether a given writer is honest.

## 2. Base URL and resource model

All endpoints are namespaced under one chain:

```
{base_url}/v1/chains/{chain_id}/...
```

`chain_id` defaults to `"default"`. A server MAY host multiple independent chains under
distinct `chain_id` values; each behaves as a fully separate append-only sequence
starting from its own genesis.

## 3. Envelope wire format

The POST body for a single entry, and each element of the `entries` array in a list
response, is the **same JSON envelope SPEC.md section 7 already defines** for the
JSONL/S3 object-per-entry backends — reusing it is what makes entry_hash byte-parity
across backends free instead of a separate thing to test:

```json
{
  "header": {
    "seq": 0,
    "ts": "2026-08-21T06:00:00+00:00",
    "hash_version": "<64 lowercase hex chars>",
    "payload_type": "application/vnd.myagent.toolcall+json",
    "payload_hash": "<64 lowercase hex chars>",
    "prev_hash": "<64 lowercase hex chars, or 64 zeros for genesis>"
  },
  "entry_hash": "<64 lowercase hex chars>",
  "payload_b64": "<standard base64 of the payload bytes>"
}
```

A server MUST store and return this shape byte-faithfully (field values verbatim); it
MUST NOT re-derive or "correct" `entry_hash` — that is the client's job, both when
writing and when verifying on read.

## 4. Endpoints

### `GET /v1/chains/{chain_id}/head`

Returns the current tail.

- `200 {"seq": <int>, "entry_hash": "<hex>"}` — the highest `seq` durably accepted.
- `404` — the chain has no entries yet (equivalent to "empty", not an error). A fresh
  writer treats this exactly like `(seq=-1, entry_hash=GENESIS_PREV_HASH)`: the next
  entry to append has `seq=0` and `prev_hash` = 64 zeros.

This endpoint MUST be **authoritative and read-committed** — it must never report a
`seq`/`entry_hash` pair that a concurrent `POST /entries` could still invalidate. It is
advisory for tail *discovery* only; `POST /entries` (section below) is where correctness
is actually enforced, the same relationship S3Backend's `head.json` hint has to its own
conditional-write check.

### `POST /v1/chains/{chain_id}/entries`

Appends exactly one entry, atomically, with a compare-and-set precondition on the
envelope's own `(header.seq, header.prev_hash)`:

- `201` — accepted. The entry is now durably part of the chain at `header.seq`.
- `409` — **precondition failed**: another writer's entry already occupies `header.seq`,
  or the current tail's `entry_hash` no longer equals the posted `header.prev_hash`. The
  client MUST re-read `/head` and rebuild the entry against the fresh tail before
  retrying — never retry the same body. `RemoteBackend.append` retries up to 32 times
  (the same ceiling `S3Backend` uses for its own conditional-write race) before raising.
- `400` — malformed envelope (missing field, wrong type, non-hex hash). Not retried.
- `401` / `403` — authentication/authorization failure. Not retried.
- `5xx` — server error. Not retried by the client; the caller sees a `RemoteError` and
  (through `AuditLog.try_append`) it becomes a labelled, counted drop — never a fork.

The precondition check MUST be atomic with the append: two concurrent POSTs racing for
the same `seq` MUST NOT both succeed. This is the server-side equivalent of CLAUDE.md
rule 7 ("two writers must never both extend the same prev_hash") — a server that lets
both through has forked the chain, and `verify_chain` on the client will report it
(`seq_gap`), but detection after the fact is not the same as prevention.

### `GET /v1/chains/{chain_id}/entries[?cursor=<opaque>]`

Lists entries **in append order** (never re-sorted by `seq` — sorting would hide a
server-side reorder from the client verifier, exactly as `ReaderBackend.entries()`'s own
contract already requires for every other backend).

- `200 {"entries": [<envelope>, ...], "next_cursor": <opaque string> | null}` — a page.
  `next_cursor` is `null` when this is the last page; otherwise pass it back as
  `?cursor=` to fetch the next page. The cursor's format is entirely server-defined —
  clients MUST treat it as opaque.
- `404` — no entries at this `chain_id` (equivalent to an empty first page). A client
  MUST treat this identically to `200 {"entries": [], "next_cursor": null}`.

## 5. Authentication

A client MAY supply credentials via `WAXSEAL_API_KEY` (never a CLI argument, never a URL
query parameter — both leak into process listings and access logs). When present, every
request carries:

```
Authorization: Bearer <api_key>
```

The wire contract does not mandate a specific auth scheme server-side beyond accepting
this header; a server MAY also accept other schemes out of band, but a waxseal client
only ever sends this one.

## 6. Transport

The reference client (`urllib_transport`) uses only the Python standard library
(CLAUDE.md rule 1: zero runtime dependencies) — plain HTTP/1.1 request/response, JSON
bodies, no keep-alive assumptions, no server-sent events or websockets. A server
implementing this contract needs nothing more exotic than that on its side either.

## 7. Anchoring endpoint (HTTPAnchorSink)

`HTTPAnchorSink` (`adapters/anchors.py`) is a *separate* concern from the chain contract
above: it POSTs a `Checkpoint` (`{"seq", "entry_hash", "root"}`) to an operator-supplied
URL and expects `200`/`201`, optionally with `{"receipt": "<opaque string>"}` in the
response body. This URL SHOULD point at a service **independent of the chain server
itself** (section 1) — anchoring a chain server to itself proves nothing about that
server's honesty.
