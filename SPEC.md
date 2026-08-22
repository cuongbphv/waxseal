# waxseal SPEC v1

Status: REVIEW — content through section 12 is complete and cross-checked (golden
vectors at tests/vectors/vectors.json, already write-once per CLAUDE.md rule 3);
formal freeze is still planned for v1.0. This file is already treated as append-only
in practice: new sections and new vectors may be added; existing normative text and
existing vectors may never change. REVIEW marks readiness for that v1.0 freeze
decision — it does not change the freeze condition itself.

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

## 9. Checkpoints and external anchoring

A `Checkpoint` pins `(seq, entry_hash, root)`, where `root` is the batch root
(section 10) over every entry hash produced up to and including `seq`. Unlike
the bare tip printed by `waxseal head`, a checkpoint lets a third party who
does not hold a copy of the trail verify that a specific earlier entry was
present in it, closing the whole-trail-rewrite gap a hash chain cannot resist
on its own (section 3 rationale, unchanged).

```
CHECKPOINT_FRAME_PREFIX = b"waxseal-checkpoint-v1\n"

checkpoint_frame(cp) =
    CHECKPOINT_FRAME_PREFIX
 || u64be(3)                              # field count
 || lp(str(cp.seq)) || lp(cp.entry_hash) || lp(cp.root)
```

The frame carries no timestamp: it MUST be exactly reproducible from the
trail's own entry hashes alone. The "when" comes from whatever anchors it (a
block time, an RFC 3161 token, a commit time) — baking a clock reading into
the frame itself would make it depend on something the trail cannot
reproduce.

`checkpoint_for(entry_hashes)` builds a `Checkpoint` for the current tip;
`verify_checkpoint(entry_hashes, checkpoint)` checks one against the CURRENT
trail. It fails closed and never raises, returning `None` on success or one
of:

- `malformed_checkpoint` — `seq` is negative.
- `anchor_beyond_head` — the checkpoint claims a `seq` the trail has not
  reached (the trail was truncated after the checkpoint was taken).
- `anchor_entry_hash_mismatch` — the trail's hash at that `seq` no longer
  matches what was anchored (the tip entry was rewritten).
- `anchor_root_mismatch` — the tip still matches but the batch root over the
  checkpointed prefix does not (an earlier entry was rewritten or reordered
  without breaking the `prev_hash` chain).

**`.anchors` sidecar (local baseline, `FileAnchorSink`)**: one JSON object per
line, O_APPEND, mode 0600, same shape discipline as `.attest`:

```
{"entry_hash": "...", "receipt": null, "root": "...", "seq": N, "sink": "file", "ts": "...", "v": 1}
```

The sidecar is as attacker-writable as the trail it anchors — it is not an
independent witness, only a queue of checkpoints for `waxseal verify
--anchors` to replay and for a real external sink (OpenTimestamps, an RFC 3161
TSA, a pushed git commit, `HTTPAnchorSink` — REMOTE.md section 7) to
publish. Security against a colluding local attacker comes from the RECEIPT an
external sink returns and from copies of that receipt held elsewhere, never
from the sidecar file alone. A duplicate record from a race (two
`anchor_every` triggers landing close together) is harmless: content is
idempotent and every record is checked independently.

`AuditLog(anchor_sink=..., anchor_every=N)` publishes a checkpoint every `N`
entries, best-effort, OUTSIDE the append critical section: a failed anchor
publish is counted (`anchor_failures`) and never blocks or fails a write
(CLAUDE.md rule 6 — fail-open must be labelled).

## 10. Merkle batch roots and consistency proofs (RFC 6962 / RFC 9162)

`batch_root(entry_hashes)` computes an RFC 6962 §2.1 Merkle tree root over the
given entry hashes (leaves are the raw 32 hash bytes decoded from hex, never
their ASCII spelling), with domain-separated leaf/node hashing
(`0x00`/`0x01` prefixes) to block the CVE-2012-2459 second-preimage class
where an inner node is smuggled in as a leaf.

- `membership_proof(entry_hashes, index)` / `verify_membership(...)`: RFC 6962
  §2.1.1/RFC 9162 §2.1.3.2 inclusion proofs — sibling hashes tying one entry to
  the batch root.
- `consistency_proof(entry_hashes, old_size)` / `verify_consistency(...)`: RFC
  9162 §2.1.4 — sibling hashes proving the tree at `old_size` is a PREFIX of
  the current tree, i.e. that a later published head extends an earlier one
  without replaying the whole log.

Both proof-checking functions fail closed and NEVER raise: malformed or
out-of-range input (bad hex, an index/size outside the batch, a
missing/extra/reordered proof element) returns `False`/`None`-equivalent
"not proven", never an exception — a verifier must not be crashable by
attacker-supplied bytes, and "cannot check" must stay distinct from "checked
and false" (CLAUDE.md rule 5). `membership_proof`/`consistency_proof`
themselves (the PROVING side, not verification) raise `IndexError` on an
out-of-range index/size — that request comes from an operator who should be
told the request was invalid, not handed a proof for some other entry by
surprise.

Known-answer vectors for both proof families are cross-checked against an
independent reference implementation before being frozen into
`tests/vectors/`, per this repository's existing golden-vector discipline
(section 8) — new vectors only ever ADD, never edit or delete an existing one.

## 11. Aggregate attestation scheme `fs-hmac-agg-sha256-v1`

An opt-in FssAgg-style (Ma & Tsudik, 2009) extension of the forward-secure
`fs-hmac-sha256-v1` scheme (section on sealing, DESIGN.md §6-§7): instead of
(or alongside) per-entry seals, every seal value folds into ONE running,
KEYED accumulator, so that an attacker who truncates the trail loses the
ability to reproduce the accumulator even if they hold every PUBLIC value the
trail and its sidecars expose.

```
AGG_FRAME_PREFIX = b"waxseal-agg-v1\n"
AGG_GENESIS       = "0" * 64                     # 64 hex zero chars

aggregate_step(epoch_key, prev_agg, value) =
    hex(HMAC-SHA256(
        epoch_key,
        AGG_FRAME_PREFIX || bytes.fromhex(prev_agg) || lp(value)
    ))
```

`epoch_key` is the SAME per-entry epoch key `A_j` that sealed that row — the
key BEFORE it evolves to `A_{j+1}`. Folding under the now-discarded epoch key,
not a plain hash of public values, is the normative property this scheme
exists to provide: a keyless refold from `(prev_agg, value)` alone cannot
reproduce a real fold, because the real fold was HMAC'd under a key nobody
but the writer, at that moment, ever held.

**Normative rule: only the LATEST accumulator value is ever persisted.**
Storing every intermediate `mu_i` would hand a truncating attacker exactly
the `mu_{t'-1}` they would need to splice a forged suffix onto — reopening
the truncation hole this scheme exists to close. The sidecar
(`<trail>.sealagg`) is therefore replace-only (the same atomic single-owner
`os.replace` helper as the epoch keyfile), holding exactly:

```
{"agg": "<hex>", "agg_start": N, "epoch": M}
```

`agg_start` is the row index aggregation began at — aggregation MAY start
mid-trail (an upgrade path for an existing `fs-hmac-sha256-v1` deployment);
rows before `agg_start` are skipped by the fold but still advance the epoch
key, so later folds line up with the same positional-clock rule
`verify_seals` already uses for unrecognized attestation schemes.

`verify_aggregate(attestations, initial_key, *, agg_start, epoch, agg)` fails
closed and never raises, returning `None` on success or one of:

- `malformed_aggregate` — `agg_start` is out of `[0, epoch]`, `agg` is not
  valid hex, or an aggregate-scheme row's value cannot even be folded (an
  attacker-writable sidecar is not obligated to hand back clean bytes; a fold
  that cannot run is a verdict, not a crash).
- `aggregate_epoch_mismatch` — either `epoch` claims more rows than exist (a
  dropped or truncated row), or an aggregate-scheme row sits PAST `epoch` (a
  fold the writer performed but never persisted — a crash between the
  keyfile/attest writes and the `.sealagg` write, section 11's own write
  ordering below).
- `aggregate_mismatch` — the fold over the given rows does not reproduce
  `agg` (a tampered value, a wrong `agg_start`, or a keyless refold attempt).

Rows at or past `epoch` are skipped for folding, but a NON-aggregate-scheme
row past `epoch` is not itself a mismatch: a trail may switch a
`FileAttestor` back to plain `fs-hmac-sha256-v1` after aggregating for a
while, and that scheme's rows never touch `.sealagg` again. Treating the
resulting positional gap as a break would turn an ordinary configuration
change into a false tampering alarm — exactly the incident class this
project exists to make unrepresentable (CLAUDE.md's own "Migration 060"
rationale, one layer down into the sealing subsystem). The writer mirrors
this on the other side: `FileAttestor.attest()` refuses to fold onto a
`.sealagg` whose persisted epoch does not match the entry's own `seq`,
raising rather than silently re-basing onto a sidecar that may have been
tampered with or left stale by a prior crash — the same operator-decision
refusal the epoch keyfile check already makes.

**Honest limits, stated plainly (mirrors section 3/6's residual-risk
discipline):** an attacker who replays an OLD `.sealagg` value alongside a
consistently truncated trail + `.attest` is not detected by this scheme alone
— an old, valid-looking aggregate for a shorter, equally-consistent history
is indistinguishable from a legitimately shorter trail without an external
reference point. This is the same class of residual exposure external
anchoring (section 9) already carries and for the same reason: a purely
internal accumulator has no way to prove "nothing was removed since a
specific external moment" without an external witness. The two mechanisms
are complementary, not redundant — anchoring bounds the window since the
last published checkpoint; the aggregate closes the gap where an attacker
who ALSO controls the row-by-row `.attest` history (not just the keyfile)
would otherwise regenerate a shorter, internally-consistent forgery. An
`fs-hmac-sha256-v1` sidecar written before this scheme existed continues to
verify exactly as it always has (regression, not replacement) — the aggregate
is opt-in per trail via `FileAttestor(scheme=...)`, never retroactive.

## 12. Drop records (`.drops` sidecar)

`dropped_writes` (section 5) reports "chain integrity ≠ trail completeness":
a write that failed before it reached storage leaves no `seq` gap for
`verify` to catch. A `.drops` sidecar, when enabled
(`AuditLog.open(path, record_drops=True)`), gives that count a persistence
layer independent of any one process's in-memory counter.

Format: one JSON object per line, O_APPEND, mode 0600 (same discipline as
`.attest`/`.anchors`):

```
{"payload_type": "<str or null>", "reason": "<exception class name>", "source": "<str>", "ts": "<str>", "v": 1}
```

**Normative rule: a drop record MUST NEVER contain payload content.** At the
moment a write is dropped, the payload has not yet passed through
redact-before-hash (section 6/1) — a drop sidecar that captured payload bytes
would be exactly the cleartext-secrets-on-disk failure redact-before-hash
exists to prevent, just relocated to a different file. `reason` and
`payload_type` are metadata only.

The count this sidecar produces is a **measured minimum**, never an exact
total: the sidecar itself can be absent, deleted, or (on an unwritable disk)
never written to in the first place — and a write catastrophic enough to also
prevent its own drop record from being written cannot bear witness to its own
failure (CLAUDE.md rule 5, one layer down: unmeasured ≠ absent applies to this
sidecar's own existence too). Consequently:

- No sidecar file at all → the count is `None` ("never measured"), reported
  identically to how `dropped_writes` itself reports `None` when
  `measure_drops=False`.
- A sidecar that exists but is empty → the count is `0` ("measured this
  sidecar, found nothing"), a DIFFERENT state from `None` and MUST NOT be
  conflated with it, per CLAUDE.md rule 5.
- A `DropRecorder`'s `record()` method MUST NEVER raise: it is invoked from
  the caller's own best-effort failure path, and a recorder that raised there
  would turn a dropped write into an unhandled exception — worse than the
  drop it was trying to record.
