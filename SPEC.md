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

`waxseal consistency <trail> --old-seq N --old-root HEX` (read-only) runs the
consistency check against a state recorded earlier — the two values printed by
`waxseal checkpoint`, with `old_size = N + 1`. Exit 0 = the current head
extends that state; exit 1 = INCONSISTENT, reported as split-view/rewrite
EVIDENCE naming the root the current prefix actually produces (never a
tampering pronouncement — which state is honest is an operator's decision);
exit 2 = unverifiable (an `--old-seq` beyond the current head, a root that is
not 64 hex characters, an empty trail) — malformed operator input MUST be
screened out before proving, because `verify_consistency` fails closed and a
typo reported as INCONSISTENT would manufacture split-view evidence; exit 3 =
the trail does not exist.

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

## 13. Pinned-head verification (trust-on-first-use)

Sections 9-11 defend a trail against edits by an attacker who cannot rewrite
everything. A remote chain server can. The pin closes the part of that gap a
client can close on its own: the verifier records a `Checkpoint` it computed
itself, keeps it in its OWN trust domain, and refuses to accept a later
history inconsistent with it — SSH `known_hosts` for an audit trail.

State file (JSON, one object, mode 0600):

```
{"chain_id": "<str or null>", "entry_hash": "<hex64>", "pinned_ts": "<str>", "root": "<hex64>", "seq": <int>, "target": "<str>", "v": 1}
```

The checkpoint triple is stored flat, and the section 15 aggregate fields are
deliberately NOT part of a pin. A pin is checked by recomputing the trail's own
entry hashes and comparing; `agg_commit` cannot be recomputed without the seal
key, so a pin carrying one would carry a field the check silently skips — a
stored value that looks verified and is not. `pinned_ts` is informative only and
is not part of any hashed frame.

`v` is the state format version. A file whose `v` this build does not know is
**unverifiable by name** (exit 2), not a break: the pin was written by a newer
waxseal, which is version skew, not evidence of anything (CLAUDE.md rule 5,
the beads-v1.2.2 class).

Reasons, mapped from section 9's checkpoint reasons so the two vocabularies
never merge:

| Checkpoint reason | Pin reason | Meaning |
|---|---|---|
| `anchor_beyond_head` | `pin_beyond_head` | the trail is SHORTER than what was verified before — rollback or truncation |
| `anchor_entry_hash_mismatch` | `pin_mismatch` | history under the pinned seq was rewritten |
| `anchor_root_mismatch` | `pin_mismatch` | same, caught by the batch root |
| `malformed_checkpoint` | `malformed_pin` | the state file is not a checkpoint |
| — | `pin_target_mismatch` | this pin describes a different trail or chain |

Three further values appear in the same `reason` field and are outcomes of the
pin check rather than failures of it: `trust_on_first_use` (no pin existed;
one was recorded), `empty_trail_not_pinned` (nothing to pin yet), and
`pin_version_unknown` (section above). A downstream system keying off
`pin.reason` in `report --json` sees all eight.

Normative rules:

- A pin MUST NOT be advanced on a run that reported a break. Advancing then
  would launder the break into the new baseline. A run that exits 2 — intact,
  with rows this build cannot verify by name — DOES advance the pin: the pin
  records what was served, and refusing to pin any trail containing an unknown
  fingerprint would disable pinning for exactly the forward-compatible case
  this specification is built around. Note what that means: for an
  unverifiable row the pinned hash is the one read from the trail, not one
  this build recomputed. It still detects any later change to that row, which
  is all a pin ever claims.
- A malformed pin file MUST NOT be silently replaced. Re-pinning would give an
  attacker who can corrupt the pin a way to downgrade the verifier back to
  trust-on-first-use, which is precisely the state the pin exists to leave.
- First use MUST be labelled in the output. A verifier that pins silently
  cannot be distinguished, by its operator, from one that checked something.
- The pin file is verifier state, NOT a sidecar of the log. Writing it does
  not violate the CLI's never-writes-to-the-log contract, and its path is
  always given explicitly by the operator.
- A pin stored on the same disk as the trail SHOULD be treated as no pin at
  all against an attacker who holds that disk. The security argument is
  entirely the separation of authority.

## 14. Witness cross-check

A pin catches a server that rewrites history for THIS client. It cannot catch
a server that shows two clients two different consistent histories — a
split-view (fork) attack. Fork consistency (Mazieres and Shasha, SUNDR) says
this is not detectable from inside a single client's view: if the server
controls every response, two clients that never compare notes cannot tell one
history from two. A witness is that comparison, made explicit.

A witness is any party that (a) receives checkpoints as they are published and
(b) will read them back. Wire format is REMOTE.md section 8. Verdicts:

| Status | Meaning | Effect on exit |
|---|---|---|
| `consistent` | every checkpoint the witness holds is a prefix of the local trail | none |
| `inconsistent` | one is not — evidence of a split view or a rewrite | exit 1 |
| `unreachable` | the witness could not be asked | exit 2, and ALWAYS printed |

Normative rules:

- An empty witness MUST report `consistent` with `checked=0` and the reason
  `no_checkpoints_witnessed`. A witness holding nothing has proved nothing;
  reporting `checked=0` as coverage is CLAUDE.md rule 5 again.
- `unreachable` MUST NOT be reported as a pass and MUST NOT be silent. A
  witness that cannot be asked is coverage the run does not have:
  unverifiable-by-witness, exit 2 — the same verdict class as an unknown
  fingerprint, because unverifiable is never tampered. It MUST NOT escalate
  to exit 1, which is reserved for `inconsistent` (evidence, not absence of
  evidence); when both appear in one run, exit 1 wins.
- A witness under the same administrative authority as the chain server
  provides no fork detection at all. This is a deployment requirement, not a
  recommendation the software can enforce.

Honest limits, which no configuration removes:

1. Witnesses colluding with the server. Witnessing narrows trust; it does not
   eliminate it.
2. A client whose entire network path is controlled (an eclipse) sees whatever
   that adversary chooses. This library uses TLS through urllib and does not
   pin certificate authorities.
3. The window after the last witnessed checkpoint is unwitnessed by
   construction.
4. A witness that returns FEWER checkpoints than it holds silently reduces
   coverage. That is why a verdict reports `checked=K` and never "complete".

## 15. Checkpoint frame v2 and the aggregate binding

Section 11's aggregate closes truncation as long as the accumulator on disk is
honest. An attacker holding every local file can replay an older `.sealagg`
over a truncated trail, and every local check agrees. Binding the aggregate
into an ANCHORED checkpoint moves that claim outside the attacker's reach.

What is anchored is a commitment, never the accumulator:

```
AGG_COMMIT_FRAME_PREFIX = "waxseal-aggcommit-v1\n"
agg_commit = SHA-256( PREFIX || u64be(2) || lp(str(epoch)) || lp(agg) )
```

Publishing the accumulator itself would hand a truncating attacker the value
section 11 forbids persisting. The commitment reveals nothing foldable.

Checkpoint frame v2 (used only when BOTH `agg_commit` and `agg_epoch` are
present; a checkpoint with neither produces byte-identical v1 output, so every
existing anchor and vector is unaffected):

```
"waxseal-checkpoint-v2\n" || u64be(5) || lp(str(seq)) || lp(entry_hash) || lp(root) || lp(str(agg_epoch)) || lp(str(agg_commit))
```

The binding lives INSIDE the framed bytes rather than beside them in the
sidecar's JSON because a signing sink (an RFC 3161 TSA, OpenTimestamps, a
signed git commit) attests `SHA-256(checkpoint_frame(cp))` and nothing else. A
JSON side-channel would be unattested by exactly the sinks that matter most.
Setting one of the two fields without the other is an error, not a v1 frame.

`verify_anchored_aggregate` reasons:

| Reason | Meaning |
|---|---|
| `malformed_anchored_aggregate` | the anchored fields are not readable as a commitment |
| `anchored_aggregate_epoch_mismatch` | the anchor describes more folded rows than exist — the replay-plus-truncate case |
| `anchored_aggregate_mismatch` | the recomputed commitment differs |

Rows PAST the anchored epoch are not a failure: an anchor describes a past
state, and a trail is expected to have grown since.

Sidecar records carrying a binding are stamped `"v": 2`. A reader MUST treat a
record version it does not know as unreadable-by-name (exit 2), never as a
failure and never as a crash.

A record whose receipt came from a nonced RFC 3161 request also carries the
request nonce, as an OPTIONAL additive field:

```
{"...": "...", "nonce": "<decimal string>", ...}
```

The field does NOT bump the record version: it is additive, a reader that
predates it keeps reading the record unchanged, and a reader that knows it
MUST treat absence as "no comparison to make" — skipped, never failed
(absence ≠ mismatch). It is a decimal string rather than a bare JSON number
because a 64-bit value is lossy in readers that parse numbers as doubles. A
present-but-unconvertible nonce is malformed sidecar content — this format's
own bytes, so a break (exit 1), not a foreign format. What the stored nonce
buys is section 17's re-verify replay detection.

## 16. Scope statement

Every auditor report carries a fixed, machine-identifiable scope statement:

```
{"scope": {"id": "waxseal-scope-v1", "statement": "..."}}
```

The statement says the output attests hash-chain integrity and completeness
measurements of RECORDED entries only, and does NOT attest that an obligation
was met, that payload content is truthful, or that unrecorded events did not
occur.

Changing the wording MUST produce a NEW `id`. The id is what a downstream
system cites; silently editing the text under a stable id would change the
meaning of every citation already made. The exact text of both forms below is
frozen by `tests/test_scope_statement.py`, so a reword fails the suite rather
than shipping quietly under the old id.

The CLI prints an ABBREVIATED form of the same statement — one trailing line,
because the full paragraph would bury the verdict it qualifies. The two
wordings ship under one id, and the short one MUST NOT assert anything the
long one does not. Only verdict-bearing commands print it, and only once they
have a verdict to qualify: `verify` on exits 0, 1 and 2. Exit 3 (no trail was
read) prints no verdict and therefore no scope line, and `tail`/`inspect`/
`head`/`checkpoint` print data rather than verdicts and never carry it.

## 17. RFC 3161 structural anchoring

An entry's `ts` is asserted by its writer. A Time-Stamp Authority's token is
asserted by a different authority, which is the entire point.

Request: DER `TimeStampReq` (RFC 3161 section 2.4.1) over
`SHA-256(checkpoint_frame(cp))` — the frame, so a v2 binding is timestamped
too. `version` = 1, `messageImprint.hashAlgorithm` = SHA-256
(`2.16.840.1.101.3.4.2.1`) with NULL parameters, `nonce` OPTIONAL (minimal
two's complement, zero-padded when the top bit is set), `certReq` TRUE.
Byte layout is frozen in `tests/vectors/rfc3161.json` and cross-checked
against `openssl ts -query` by `tools/gen_rfc3161_vectors.py`.

Receipt: stored in the `.anchors` record's `receipt` field as
`"rfc3161:" || base64(TimeStampResp DER)`.

Checking is STRUCTURAL ONLY. This library compares status, messageImprint,
digest algorithm and nonce. It does NOT verify the CMS signature or the X.509
chain, and every output line reporting a token MUST say so. Full verification
is delegated:

```
openssl ts -verify -in receipt.tsr -data frame.bin -CAfile tsa-chain.pem
```

`waxseal receipt <trail> [--seq N] --out DIR` produces both inputs from the
stored records: the raw receipt bytes (`.tsr` for `rfc3161:` receipts, `.ots`
for `ots:` receipts) and the checkpoint frame they attest (`.frame`,
recomputed from the record's own checkpoint). It is read-only against the
trail and the sidecar. Exit 0 = wrote at least one receipt; exit 2 = the
sidecar holds no matching receipts (absence — not success, not tampering);
exit 3 = the trail or the sidecar does not exist (nothing read, nothing
created, `--out` included); exit 1 = the sidecar itself is malformed (this
project's own format, so a break rather than a foreign format).

Reason names and their exit classes:

| Reason | Class | Exit |
|---|---|---|
| (none) | the token commits to these exact bytes | 0 |
| `receipt_imprint_mismatch` | checked and false — attests other bytes | 1 |
| `nonce_mismatch` | checked and false — a replayed token | 1 |
| `malformed_token` | not readable by this build | 2 |
| `timestamp_rejected` | the TSA declined | 2 |
| `unsupported_digest_algorithm` | a digest this build does not compare | 2 |
| `unknown_receipt_type` | a receipt type from a newer build | 2 |
| `unreadable_record_version` | a record format from a newer build | 2 |

The request nonce is stored in the anchor record (section 15's optional
`nonce` field), and a verifier reading a stored receipt passes it back as the
expected nonce. With it, re-verify detects cross-request token substitution:
a token that is valid DER, carries the right imprint, but answers a DIFFERENT
request is checked-and-false (`nonce_mismatch`, exit 1) — the same class as
`receipt_imprint_mismatch`, because the token attests something other than
what sits beside it. Without it — every record written before the field
existed — detection is anchor-time-only: `waxseal anchor` refuses to file a
token whose nonce does not match and exits 1, but a later `verify` has
nothing to compare and MUST skip the comparison rather than fail it (absence
≠ mismatch). For those records a verifier learns that the token commits to
these exact bytes, not that this token was the one issued for this request.

Note the deliberate asymmetry with section 12's sidecars: malformed bytes in a
format this project defines are a break (exit 1); unreadable third-party bytes
inside a receipt are unverifiable (exit 2).

A checker MUST NOT raise on any input. Definite lengths only, every TLV
bounds-checked, trailing bytes refused, and no reason string contains the word
"tamper".

Honest limit worth stating plainly: an attacker who rewrites BOTH the record
and its receipt is caught only by the delegated signature verification, never
by the structural check.

## 18. OpenTimestamps anchoring

Submission: POST the raw 32-byte `SHA-256(checkpoint_frame(cp))` to
`<calendar>/digest` with `Accept: application/vnd.opentimestamps.v1`. This
client sets no request `Content-Type` of its own, but the stdlib transport
underneath it leaves urllib's default (`application/x-www-form-urlencoded`)
in place on a POST carrying a body, so that header does reach the wire.
[Unverified] whether any given calendar rejects that header — this has not
been exercised against a live calendar, only against a local server capturing
the request.

Receipt: `"ots:" || base64(calendar response)`. The proof is PENDING — the
Bitcoin attestation does not exist until a block confirms — and this library
neither parses nor upgrades it. A partial reimplementation of a format the
OpenTimestamps project owns would manufacture "malformed" verdicts on valid
proofs, which is the failure class this specification exists to prevent.

A verifier meeting an `ots:` receipt MUST print that it is pending and
unchecked, and MUST NOT change the exit code on account of it. Unlike an
unknown receipt prefix (section 17), this is opacity by design rather than
version skew, and an operator who anchors to a calendar must not be trained to
ignore exit 2. Completing and verifying it is `ots upgrade` / `ots verify`
from the opentimestamps-client.

[Unverified] The commitment semantics of `GET /timestamp/<hex>` on upgrade, and
the recipe for assembling a detached `.ots` file from a raw calendar response,
have not been confirmed against python-opentimestamps and are not specified
here. [Unverified] Which public calendars are currently live also changes over
time; the sink therefore requires an explicit URL and ships no default.
