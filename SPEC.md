# waxseal SPEC v1

Status: DRAFT — golden vectors are shipped at tests/vectors/vectors.json and are
already write-once (CLAUDE.md rule 3); formal freeze is planned for v1.0. After freeze
this file is append-only: new sections and new vectors may be added; existing normative
text and existing vectors may never change.

The key words MUST, MUST NOT, SHOULD are to be interpreted as in RFC 2119.

## 1. Model

An audit log is an ordered sequence of **entries**. Each entry is an **envelope**:

```
Entry:
  header:      EntryHeader        # the only thing the chain hashes
  entry_hash:  hex string         # sha256 over canonical header bytes
  payload:     bytes              # arbitrary, referenced by header.payload_hash
```

```
EntryHeader (fields, in canonical order):
  seq           unsigned integer, contiguous from 0
  ts            RFC 3339 UTC timestamp string, e.g. "2026-08-21T06:00:00+00:00"
  hash_version  schema fingerprint (section 4), 64 lowercase hex chars
  payload_type  application-specific media type. MUST NOT be a generic type
                like "application/json" (DSSE rule); use e.g.
                "application/vnd.myagent.toolcall+json"
  payload_hash  sha256 hex (lowercase) of the payload bytes as stored
  prev_hash     entry_hash of the previous entry; genesis = 64 "0" chars
```

The chain hashes ONLY the header. Payload schema evolution never touches the chain.
Redaction (section 6) runs BEFORE `payload_hash` is computed.

## 2. lp64v1 canonical encoding

All hashing inputs are built with **lp64v1**:

- A *field value* is either a Unicode string or NULL (absent).
- `enc(value)`:
  - NULL          → the 6 bytes `0x00 0x4E 0x55 0x4C 0x4C 0x00` (`b"\x00NULL\x00"`)
  - string        → its UTF-8 bytes
- `lp(value)` = `u64be(len(enc(value))) || enc(value)` where `u64be` is an 8-byte
  big-endian unsigned integer.

The length prefix makes concatenation unambiguous across different field tuples: two
different field lists can never produce the same byte stream. The NULL sentinel is
distinct from the empty string (`lp("")` = 8 zero bytes; `lp(NULL)` = length 6 + sentinel).

Integers (`seq`) are encoded as their base-10 string with no leading zeros
(`0` for zero) before `lp()`.

Rationale: byte-level control, trivially portable to any language, no dependency on
ECMAScript number serialization (RFC 8785 JCS) and no non-canonical serializers
(protobuf explicitly documents its serialization as non-canonical — never hash it).

## 3. Entry hash

```
frame = b"waxseal-v1\n"
     || u64be(6)                                  # number of header fields in v1
     || lp(str(seq)) || lp(ts) || lp(hash_version)
     || lp(payload_type) || lp(payload_hash) || lp(prev_hash)

entry_hash = lowercase_hex(sha256(frame))
```

The `waxseal-v1` prefix + field count is PAE-style framing (borrowed from DSSE/PASETO)
against format-confusion attacks.

## 4. Schema fingerprint (`hash_version`)

`hash_version` is NEVER a manual string like "v1". It is derived from a **canonical
version descriptor**:

```
descriptor components (ordered):
  algorithm     "sha256"
  encoding      "lp64v1"
  field name 1  "seq"
  field name 2  "ts"
  field name 3  "hash_version"
  field name 4  "payload_type"
  field name 5  "payload_hash"
  field name 6  "prev_hash"

descriptor_bytes = b"waxseal-descriptor-v1\n"
                || u64be(8)                       # component count
                || lp("sha256") || lp("lp64v1")
                || lp("seq") || lp("ts") || lp("hash_version")
                || lp("payload_type") || lp("payload_hash") || lp("prev_hash")

fingerprint = lowercase_hex(sha256(descriptor_bytes))
```

Changing the field set (or algorithm, or encoding) changes the fingerprint automatically.
A verifier holds an **append-only registry** `fingerprint → header schema`. Verification
of a row MUST use the schema its own `hash_version` names.

**Unknown fingerprint → the row is reported "unverifiable by name". It is NOT an error,
NOT tampering, and MUST NOT abort verification of other rows** (RFC 6962 §4.6 principle).
A verifier MUST NOT recompute a row under a schema it was not signed with.

## 5. Chain verification

Walk rows in `seq` order. For each row whose fingerprint is known, check in this order and
report the FIRST break:

1. `seq` contiguity (gap ⇒ reason `seq_gap` — deletion)
2. `prev_hash` equals previous row's `entry_hash` (⇒ `prev_hash_mismatch` — insert/reorder)
3. recomputed `entry_hash` equals stored (⇒ `entry_hash_mismatch` — edit)
4. if payload bytes are available: `sha256(payload)` equals `payload_hash`
   (⇒ `payload_hash_mismatch`)

Unknown-fingerprint rows are collected into `unverifiable`; their stored `entry_hash`
still participates as `prev_hash` input for the next row (the chain remains linked
through them).

Result: `ok` (no break among verifiable rows), `checked` (rows verified before the first
break), `broken_seq`, `reason`, `unverifiable` (seq list), `dropped_writes: int | None`
(`None` = not measured — never conflate with 0).

**Chain integrity ≠ trail completeness**: a write dropped before append leaves no gap.

## 6. Redaction

`payload → Redactor → canonical bytes → payload_hash → store`. The hash is computed on
the redacted payload, so verification is consistent and cleartext never reaches storage.
A degraded/failed redactor MUST be labelled in the stored payload (fail-open is visible),
never silent.

## 7. Storage backends

Any backend storing `(header, entry_hash, payload)` and supporting ordered read works.
Normative requirements:

- Append MUST serialize read-tail + write as one critical section (file lock for JSONL,
  `BEGIN IMMEDIATE` + `UNIQUE(seq)` for SQLite). Two entries with the same `prev_hash`
  is a **fork** — the failure mode this rule exists to prevent.
- Entries are immutable once written. No repair, no rewrite, no in-place migration.
- JSONL reference layout: one JSON object per line:
  `{"header": {...6 fields...}, "entry_hash": "...", "payload_b64": "<base64 of payload bytes>"}`
  written with `\n` line endings, UTF-8, no BOM.

## 8. Golden test vectors (FROZEN once added)

See `tests/vectors/vectors.json`. Existing vectors may never be edited or deleted; the
verification suite fails if any frozen hash changes. That failure means STOP — it is the
tamper alarm for the spec itself.

Vector fields: `descriptor_fingerprint`, per-entry `header` inputs and expected
`entry_hash`, tamper cases with expected `reason`.
