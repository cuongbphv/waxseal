# waxseal REMOTE - wire contract v1

Status: REVIEW - this wire contract is complete and covered by the fake-server/real-HTTP
test matrix; already treated as append-only in practice, same discipline as SPEC.md (new
sections and new endpoints may be added; existing normative text here may never change
meaning). Formal freeze is still tied to SPEC.md's own v1.0 freeze - REVIEW marks
readiness for that, not a change to the condition.

The key words MUST, MUST NOT, SHOULD are to be interpreted as in RFC 2119.

This document specifies the HTTP contract `RemoteBackend` (`src/waxseal/adapters/remote.py`)
speaks to a chain server, so that any server implementing it - hosted, self-run, a thin
shim over an existing datastore - is a compatible waxseal peer alongside JSONL, SQLite,
and S3. waxseal ships the client only; it does not ship a server.

## 1. Trust model

**The server is a TRUSTED WRITER, not bound against a malicious one.** This is a
deliberate scope boundary, not an oversight:

- `verify_chain` runs entirely **client-side**, over whatever `entries()` yields. A
  server that corrupts, truncates, or reorders entries is caught exactly as a corrupted
  local file would be (`entry_hash_mismatch`, `seq_gap`, `prev_hash_mismatch`) - this is
  tamper-**evident**, the same guarantee every other backend gives.
- What `verify_chain` **alone** cannot catch is a server that **consistently forges a
  whole rewrite**: every header, every hash, self-consistent from genesis. A
  locally-writable disk has the identical blind spot. This is not specific to the
  remote backend.
- Two later additions narrow that blind spot without changing this trust model. A
  pinned head (SPEC.md section 13) catches a server that rewrites history this client
  already confirmed, or serves a shorter one - memory the server does not hold. Witness
  cross-check (section 8 below, SPEC.md section 14) catches a server showing two
  clients two different self-consistent histories, which fork consistency says a single
  client cannot detect from inside its own view. Neither makes the server trusted: they
  move the question to whether the pin and the witnesses sit under a different
  authority than the server does.
- The mitigation is the same one waxseal already gives local backends: **anchor the
  head independently** - `AuditLog.anchor()` / `checkpoint_for` plus an `AnchorSink`
  (e.g. `HTTPAnchorSink`, posting to a *different* service than the chain server
  itself) - so a full rewrite has to also forge the anchor history, not just the chain.
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
JSONL/S3 object-per-entry backends - reusing it is what makes entry_hash byte-parity
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
MUST NOT re-derive or "correct" `entry_hash` - that is the client's job, both when
writing and when verifying on read.

## 4. Endpoints

### `GET /v1/chains/{chain_id}/head`

Returns the current tail.

- `200 {"seq": <int>, "entry_hash": "<hex>"}` - the highest `seq` durably accepted.
- `404` - the chain has no entries yet (equivalent to "empty", not an error). A fresh
  writer treats this exactly like `(seq=-1, entry_hash=GENESIS_PREV_HASH)`: the next
  entry to append has `seq=0` and `prev_hash` = 64 zeros.

This endpoint MUST be **authoritative and read-committed** - it must never report a
`seq`/`entry_hash` pair that a concurrent `POST /entries` could still invalidate. It is
advisory for tail *discovery* only; `POST /entries` (section below) is where correctness
is actually enforced, the same relationship S3Backend's `head.json` hint has to its own
conditional-write check.

### `POST /v1/chains/{chain_id}/entries`

Appends exactly one entry, atomically, with a compare-and-set precondition on the
envelope's own `(header.seq, header.prev_hash)`:

- `201` - accepted. The entry is now durably part of the chain at `header.seq`.
- `409` - **precondition failed**: another writer's entry already occupies `header.seq`,
  or the current tail's `entry_hash` no longer equals the posted `header.prev_hash`. The
  client MUST re-read `/head` and rebuild the entry against the fresh tail before
  retrying - never retry the same body. `RemoteBackend.append` retries up to 32 times
  (the same ceiling `S3Backend` uses for its own conditional-write race) before raising.
- `400` - malformed envelope (missing field, wrong type, non-hex hash). Not retried.
- `413` - body exceeds 1 MiB (1048576 bytes). The server MUST refuse before
  the body is stored. A missing or unreadable `Content-Length` does not skip
  the limit: the server counts streamed bytes. The JSON error shape is
  `{"error": "payload_too_large", "detail": "body exceeds 1048576 bytes"}`.
  Not retried.
- `401` / `403` - authentication/authorization failure. Not retried.
- `5xx` - server error. Not retried by the client; the caller sees a `RemoteError` and
  (through `AuditLog.try_append`) it becomes a labelled, counted drop - never a fork.

The precondition check MUST be atomic with the append: two concurrent POSTs racing for
the same `seq` MUST NOT both succeed. This is the server-side equivalent of CLAUDE.md
rule 7 ("two writers must never both extend the same prev_hash") - a server that lets
both through has forked the chain, and `verify_chain` on the client will report it
(`seq_gap`), but detection after the fact is not the same as prevention.

### `GET /v1/chains/{chain_id}/entries[?cursor=<opaque>]`

Lists entries **in append order** (never re-sorted by `seq` - sorting would hide a
server-side reorder from the client verifier, exactly as `ReaderBackend.entries()`'s own
contract already requires for every other backend).

- `200 {"entries": [<envelope>, ...], "next_cursor": <opaque string> | null}` - a page.
  `next_cursor` is `null` when this is the last page; otherwise pass it back as
  `?cursor=` to fetch the next page. The cursor's format is entirely server-defined -
  clients MUST treat it as opaque.
- `404` - no entries at this `chain_id` (equivalent to an empty first page). A client
  MUST treat this identically to `200 {"entries": [], "next_cursor": null}`.

## 5. Authentication

A client MAY supply credentials via `WAXSEAL_API_KEY` (never a CLI argument, never a URL
query parameter - both leak into process listings and access logs). When present, every
request carries:

```
Authorization: Bearer <api_key>
```

The wire contract does not mandate a specific auth scheme server-side beyond accepting
this header; a server MAY also accept other schemes out of band, but a waxseal client
only ever sends this one.

## 6. Transport

The reference client (`urllib_transport`) uses only the Python standard library
(CLAUDE.md rule 1: zero runtime dependencies) - plain HTTP/1.1 request/response, JSON
bodies, no keep-alive assumptions, no server-sent events or websockets. A server
implementing this contract needs nothing more exotic than that on its side either.

## 7. Anchoring endpoint (HTTPAnchorSink)

`HTTPAnchorSink` (`adapters/anchors.py`) is a *separate* concern from the chain contract
above: it POSTs a `Checkpoint` (`{"seq", "entry_hash", "root"}`) to an operator-supplied
URL and expects `200`/`201`, optionally with `{"receipt": "<opaque string>"}` in the
response body. This URL SHOULD point at a service **independent of the chain server
itself** (section 1) - anchoring a chain server to itself proves nothing about that
server's honesty.

## 8. Witness read-back

A witness is an anchor endpoint that will also hand its checkpoints back, so a
client can check that the chain server has not shown it a different history
than it showed the witness (SPEC.md section 14).

```
GET <anchor-url>
200 {"checkpoints": [{"seq": <int>, "entry_hash": "<hex64>", "root": "<hex64>"}, ...]}
404                      # this witness has seen nothing yet - NOT an error
```

- Checkpoints SHOULD be returned oldest first. A client MUST NOT depend on the
  order: no checkpoint's verdict depends on another's. A client MAY stop at the
  first disagreement (this one does), so `checked` is a count of checkpoints
  reached before the verdict, never a claim of full coverage.
- A receiver MUST ignore keys it does not recognize, and a client MUST ignore
  extra keys on a checkpoint (that is how `agg_commit`/`agg_epoch` reached
  existing deployments without a version bump).
- Authentication uses section 5's `Authorization: Bearer` header shape, but a
  DIFFERENT credential: witness requests (both the POST of section 7 when the
  target is a witness, and this GET) carry the token from
  `WAXSEAL_WITNESS_API_KEY`. The chain server's `WAXSEAL_API_KEY` MUST NOT be
  sent to a witness: it is a WRITE credential for the chain, and a witness is
  by definition a different administrative authority - a witness holding the
  chain key could append forged entries to the very chain it exists to
  cross-check. When `WAXSEAL_WITNESS_API_KEY` is unset, witness requests are
  sent unauthenticated rather than falling back to the chain key.
- A record the client cannot parse is COUNTED, not skipped silently: the
  verdict reports how many were unreadable alongside how many were checked.
- Normative, and not enforceable by software: a witness is only worth asking
  if it is under a DIFFERENT administrative authority than the chain server.
  A server witnessing itself proves nothing (mirrors section 7).

## 9. Anchor body: aggregate binding

The POST body of section 7 MAY carry two additional keys when the checkpoint
binds a forward-secure aggregate (SPEC.md section 15):

```
{"seq": <int>, "entry_hash": "<hex64>", "root": "<hex64>", "agg_commit": "<hex64>", "agg_epoch": <int>}
```

Both appear together or neither appears. A receiver that predates them ignores
them under section 8's unknown-key rule, so no version negotiation is needed.

## 10. Per-append receipts (server receipt chain) - added in 0.1.5

A server MAY maintain a **receipt chain** per `chain_id`: a running hash over
the entries it has acknowledged, in acknowledgment order, computed with the
frame SPEC.md section 19 defines (`prev_receipt_head` = 64 zeros for the first
receipt). The chain exists so the server is bound by its own acknowledgments -
it cannot later re-tell the history of what it accepted without the retelling
being visible. A server that implements it:

- MUST include both `receipt_seq` and `receipt_head` in every `201` body for
  that chain - both or neither, section 9's rule:

  ```
  201 {"receipt_seq": <int>, "receipt_head": "<hex64>"}
  ```

- MUST treat the receipt chain as append-only: once a
  `(receipt_seq, receipt_head)` pair has been issued, the server MUST NOT ever
  answer a different `receipt_head` for that `receipt_seq`.
- SHOULD expose the current head read-only:

  ```
  GET /v1/chains/{chain_id}/receipts/head
  200 {"receipt_seq": <int>, "receipt_head": "<hex64>"}
  404                     # no receipts yet - NOT an error
  ```

  This endpoint SHOULD be readable without write credentials (a mirror-style
  read point): its value to a third party auditing the server's
  acknowledgment history is the reason it exists, and section 5's write
  credential grants nothing here.

A client receiving receipt fields on a `201` stores them in the `.receipts`
sidecar (SPEC.md section 19), best-effort - a failed sidecar write never fails
or retries the append. A `201` without them is a server that does not
implement this section: the client records nothing and MUST NOT treat it as an
error (absence is "not recorded", never "checked"). A receiver MUST ignore
keys it does not recognize (section 8's rule), which is how these fields reach
existing deployments without a version bump.

Trust model consequence (section 1 unchanged): a receipt narrows the window in
which a write-capable attacker on the writer's side can rewrite locally - from
the anchor cadence down to one entry. It does not make the server less trusted
or more honest, and a server and writer under one administrative authority
collapse the guarantee - the same sentence every other section ends on.

## 11. Segment rotation (server-hosted chains) - added in 0.1.5

A chain that has never rotated is UNCHANGED by this section - everything
above still describes it exactly. Whether and when a chain's storage rotates
is implementation-defined (the reference server bounds trail growth by
sealing the file it is writing once a size threshold is crossed) and is not
part of this wire contract. What follows becomes true only once a chain has
rotated at least once (SPEC.md section 20).

- **`GET /head` and cursorless `GET /entries` describe the ACTIVE SEGMENT,
  not the chain's full history.** The active segment is the file the server
  is currently appending to; after a first rotation that is a newer numbered
  file, and the file that used to be the whole chain becomes a SEALED
  segment. This is forced, not a convenience: each segment is its own chain
  with its own genesis `prev_hash` (64 zeros) and its own `seq` counting from
  0, linked to its predecessor only by a rotation-binding entry at the new
  segment's `seq` 0 (SPEC.md section 20.2) - never by continuing `prev_hash`
  across a file boundary. Concatenating segments before handing them to a
  client's `verify_chain` would produce a `seq` that restarts at 0
  mid-stream, indistinguishable from a fork - a false tamper alarm the server
  would manufacture out of its own housekeeping. A client can observe a
  rotation directly: `/head`'s `seq` visibly drops rather than continuing to
  climb (the new segment's `seq` 0 is the binding entry the server appends
  for itself, so a client's own next entry lands at `seq` 1, not 0).
- **The opaque cursor (section 4) now carries a segment identity alongside
  its offset.** The reference server's cursor is
  `e<offset>~<segment-identity>` (e.g. `e2~trail.00003`) - clients still MUST
  treat the whole string as opaque, but a paging read now finishes the
  segment it started on instead of being resumed at its offset inside
  whatever segment happens to be active by the time it comes back. A cursor
  issued before a chain's storage carried segment identity (bare
  `e<offset>`, no suffix) is refused with `400 invalid_cursor` rather than
  aimed at a guessed file. The correct response is the same as for any other
  opaque-cursor failure: drop it and restart paging from `cursor=null`.
- **`verify`, `report`, `inspect`, and `export-proof` target the active
  segment only; `segments` is the read that covers the whole group.** None of
  those four per-entry reads takes a segment selector, so an operator wanting
  a verdict or a proof for an entry that has already been sealed into an
  older segment has NO route through this API today. Say so plainly: these
  reads do not offer full-history coverage once a chain has rotated.
  `segments` reports the group and the rotation bindings between its files,
  and is the read to reach for when the question is about the chain as a
  whole rather than one entry.
- **`cross_check_receipts` keys `seq` to a LIST of hashes, not a single
  one.** Because `seq` restarts at 0 in every segment, a rotated chain can
  hold several entries recorded at the same `seq` - one per segment - and a
  receipt for that `seq` is satisfied by a match against any hash in the
  list. Detection power is unchanged: an edited or deleted entry still
  changes or removes its hash from the list either way. On a chain that has
  never rotated, every list has exactly one element - the same check it
  always was, generalized rather than altered.
