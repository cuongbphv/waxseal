# waxseal SPEC

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

## 2. lp64 canonical encoding

All hashing inputs are built with **lp64**. There is exactly one canonical encoding.

- A *field value* is either a Unicode string or NULL (absent).
- `enc(value)`:
  - NULL          → the single byte `0x00`
  - string        → `0x01` followed by its UTF-8 bytes
- `lp(value)` = `u64be(len(enc(value))) || enc(value)` where `u64be` is an 8-byte
  big-endian unsigned integer.

The length prefix makes concatenation unambiguous across different field tuples: two
different field lists can never produce the same byte stream. The leading type tag makes
that unambiguity **unconditional** — an absent field and any string whatsoever differ in
their first encoded byte, so there is no side condition to state, no invariant for an
implementation to maintain, and no input `lp` must reject. `lp("")` is the tag alone
(length 1, `0x01`); `lp(NULL)` is length 1, `0x00`; the two can never coincide.

Integers (`seq`) are encoded as their base-10 string with no leading zeros
(`0` for zero) before `lp()`.

Rationale: byte-level control, trivially portable to any language, no dependency on
ECMAScript number serialization (RFC 8785 JCS) and no non-canonical serializers
(protobuf explicitly documents its serialization as non-canonical — never hash it).

> **Historical note.** waxseal 0.1.0-0.1.3 used a different encoding, `lp64v1`, which
> spelled *absent* as the six bytes `b"\x00NULL\x00"`. Those bytes are themselves valid
> UTF-8, so exactly one string — the one that decodes from them — encoded identically to
> *absent*: the encoding chosen to keep "absent" and "empty" apart conflated "absent"
> with one specific *present* value. Injectivity therefore held only under an unstated
> side condition. lp64 replaced it in 0.1.4, before any trail written under lp64v1
> existed outside development, and lp64v1 is not implemented by any current build. An
> implementation of this specification implements lp64 and nothing else.

## 3. Entry hash

```
frame = b"waxseal-lp64\n"
     || u64be(6)                                  # number of header fields
     || lp(str(seq)) || lp(ts) || lp(hash_version)
     || lp(payload_type) || lp(payload_hash) || lp(prev_hash)

entry_hash = lowercase_hex(sha256(frame))
```

The `waxseal-lp64` prefix + field count is PAE-style framing (borrowed from DSSE/PASETO)
against format-confusion attacks.

## 4. Schema fingerprint (`hash_version`)

`hash_version` is NEVER a manual string like "v1". It is derived from a **canonical
version descriptor**:

```
descriptor components (ordered):
  algorithm     "sha256"
  encoding      "lp64"
  field name 1  "seq"
  field name 2  "ts"
  field name 3  "hash_version"
  field name 4  "payload_type"
  field name 5  "payload_hash"
  field name 6  "prev_hash"

descriptor_bytes = b"waxseal-descriptor-v1\n"
                || u64be(8)                       # component count
                || lp("sha256") || lp("lp64")
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

The vectors were re-frozen for 0.1.4 when lp64 replaced lp64v1 (section 2). That was an
explicit owner decision taken while no trail written under the old encoding existed
outside development — it is what this rule exists to prevent by default, and it is not a
precedent. From 0.1.4 the rule reads exactly as written above.

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

### 13.1 Declared expectations (added in 0.1.4)

The state file gained three optional fields. A pin written before they existed omits
all three and parses unchanged — absence is the "not declared" signal, and is never
read as a declaration of the smallest possible value (rule 5).

```
{"chain_id": "<str or null>", "entry_hash": "<hex64>", "pinned_ts": "<str>",
 "root": "<hex64>", "seq": <int>, "target": "<str>", "v": 1,
 "expect_anchor_binding": <bool>,
 "max_anchor_age_s": <int>,
 "declared_topology": {"seal_escrow": <bool>, "anchor_sinks": <int>,
                       "witness": <bool>, "pin_separate": <bool>,
                       "ledger": <bool, optional>}}
```

`expect_anchor_binding` is always written (a plain flag with a real default of
`false`); `max_anchor_age_s` and `declared_topology` are omitted entirely when absent.
`declared_topology`, when present, MUST carry all four ORIGINAL subfields together —
a partial object over those four is `malformed_pin`, never silently defaulted,
because a defaulted field here would be indistinguishable from one the operator
actually declared.

`declared_topology` gained a fifth subfield, `ledger`, in 0.1.5 — genuinely optional,
not required together with the four above. A `declared_topology` written before it
existed, or one that simply never mentions it, omits the key entirely and parses as
`ledger` undeclared: rule 5's `None`, a different claim from a declared-false
`ledger`, never conflated with it. When the key is present it MUST be a boolean;
there is no partial-object case to reject for it, because there is exactly one key
to check, not four. `--declare-topology`'s CLI grammar (`cli.py`) mirrors this
exactly: `ledger=true`/`ledger=false` is an optional fifth token alongside the four
required-together ones, and omitting it parses precisely as it did before this
subfield existed.

This does not contradict the rule above that the section 15 aggregate fields are
deliberately not part of a pin. That rule is about **values**: `agg_commit` cannot be
recomputed without the seal key, so storing one would store a field the check skips.
`expect_anchor_binding` is a **policy** — a boolean the verifier CAN check, by asking
whether any record at or after the pinned seq carries a binding at all. Nothing in the
verifier's own trust domain previously recorded that a trail was supposed to anchor
with one, so an adversary holding the `.anchors` sidecar could present only
version-1-shaped records and strip section 15's replay-plus-truncate protection with
no finding produced. The distinction between an exogenous *value* (uncheckable here)
and an exogenous *policy* (checkable) is what makes the flag sound.

Each check runs only when it was BOTH declared and measured on this run: a run that
did not pass `--anchors` has not observed the sidecar, and "not measured" must never
be reported as "observed nothing" (rule 5). When more than one condition is true at
once, exactly one `reason` surfaces; the order is fixed and is a tiebreak only, since
every outcome below is exit 2:

| Pin reason | Meaning |
|---|---|
| `anchor_policy_downgrade` | `expect_anchor_binding` is set, every readable record at or after the pinned seq lacks an aggregate binding |
| `anchor_binding_unreadable` | same, except some records are in a format this build cannot read — absence among the readable ones is not evidence of absence |
| `anchor_stale` | the newest `.anchors` record is older than `max_anchor_age_s`, or there are no records at all |
| `anchor_timestamp_unparseable` | the newest record exists but its `ts` is not a readable ISO-8601 instant — neither fresh nor stale, unverifiable by name |
| `separation_shortfall` | `declared_topology` claims more independent authorities than this run observed |

All five are **exit 2**, never exit 1. Each reports that corroboration expected by
policy was not observed; none is evidence that the trail itself was altered, and the
chain verdict is reported separately and unchanged. A verifier MUST NOT escalate any
of them to a break.

Only two of `declared_topology`'s four components can be checked against anything:
`anchor_sinks` (distinct external sinks actually recorded in the sidecar, excluding the
local `file` baseline, which is not an independent authority) and `witness` (a witness
this run actually reached that returned `consistent`). `seal_escrow` and `pin_separate`
describe where a key and a file physically live; no artifact in the trail or its
sidecars can corroborate or contradict them, so they never enter the comparison. This
is a permanent limitation of what a verifier can observe, stated rather than papered
over.

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

**Note (0.1.5): the two frame prefixes are parallel SHAPES, not a version
pair.** `waxseal-checkpoint-v1\n` and `waxseal-checkpoint-v2\n` select between
two frame shapes by CONTENT — bare, and aggregate-bound — not between an old
encoding and its replacement. Neither is superseded: a writer holding no
aggregate binding emits the first shape forever. The `v1`/`v2` inside the bytes
is historical naming only, and reading it as an old-then-new pair invites
migrating the "old" shape away — precisely the class of change this document's
frozen material forbids. The implementation therefore names the constants
`CHECKPOINT_FRAME_PREFIX_BARE` and `CHECKPOINT_FRAME_PREFIX_AGG_BOUND`, keeping
the pre-0.1.5 names (`CHECKPOINT_FRAME_PREFIX`, as spelled in section 9, and
`CHECKPOINT_FRAME_PREFIX_V2`) as aliases of the same values. The BYTES above are
frozen: externally issued anchor receipts already contain them, so a change
would orphan evidence that exists.

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

### 17.1 Optional signature verification (`waxseal[rfc3161]`, added in 0.1.5)

Section 17's check is structural and stays structural: it is what a
zero-dependency build can do, and it is what runs when no bundle is named. The
optional `rfc3161` extra adds a second, independent dimension — the CMS
signature and the X.509 chain — engaged only by `--tsa-ca-file <bundle.pem>`
on `verify` or `report`.

The bundle is the operator's. waxseal consults no default trust store: not the
system store, not certifi, not the certificates the token happens to carry. A
default would decide whom the operator trusts without saying so on any line of
output.

The dimension has three states, never two:

| State | Class | Exit |
|---|---|---|
| `signature_valid` | the CMS signature verifies and the signer chains to an anchor in the named bundle | 0 |
| `signature_invalid` | checked and false — the signature does not verify, the signed attributes commit to another TSTInfo, or the signer chains to nobody in the bundle | 1 |
| `signature_unchecked` | the question was never put — the extra is not installed, the bundle is unreadable, or the token's CMS is a shape this build cannot parse | 2 |

`signature_unchecked` MUST NOT be rendered as a pass. An absent extra that
exits 0 reports authenticity nobody established, and every `signature_unchecked`
line therefore names both its cause and its remedy.

Unreadable is unchecked, never invalid — section 17's asymmetry, carried into
the module that CAN say "false". Only a signature that verifiably fails, or a
chain that verifiably does not reach the named anchors, earns exit 1.

Without `--tsa-ca-file` no exit code in section 17's table changes. The run is
not silent about it: it prints one `signature_unchecked` line naming the flag,
the same way a pending OpenTimestamps proof is stated without raising the exit
code.

What a `signature_valid` line does NOT claim, and says so on the line itself:
certificate validity windows, revocation status and the `timeStamping`
extended key usage are not checked. `openssl ts -verify` remains the documented
route and checks more; this extra is a second option for operators who cannot
run it, never a replacement.

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

## 19. Per-append receipt sidecar (`.receipts`) — added in 0.1.5

Anchoring (section 9) bounds a rewrite to the window since the last published
checkpoint; a pin (section 13) is the verifier's own memory. Neither is a
per-append acknowledgment: a record, made at write time by a second authority,
that entry `seq` carried `entry_hash` the moment it was accepted. The receipt
sidecar is that record on the writer's side, paired with the server-side
receipt chain REMOTE.md section 10 defines. Together they shrink the rewrite
window from the anchor cadence to a single entry: an edit to any acknowledged
entry contradicts a stored receipt from the very next append onward, not from
the next checkpoint.

The receipt head chain is computed server-side (REMOTE.md section 10); its
frame is defined here because these are canonical bytes:

```
RECEIPT_FRAME_PREFIX = b"waxseal-receipt-v1\n"
RECEIPT_GENESIS      = "0" * 64          # prev for the first receipt

receipt_head = lowercase_hex(SHA-256(
    RECEIPT_FRAME_PREFIX || u64be(3)
 || lp(str(receipt_seq)) || lp(prev_receipt_head) || lp(entry_hash)))
```

Sidecar `<trail>.receipts`: one JSON object per line, O_APPEND, mode 0600
(same discipline as `.attest`/`.anchors`/`.drops`):

```
{"entry_hash": "<hex64>", "receipt_head": "<hex64>", "receipt_seq": <int>, "seq": <int>, "source": "<str>", "ts": "<str>", "v": 1}
```

`source` labels which server issued the receipt (a base URL or operator
label) — metadata only. A record MUST NEVER contain payload content
(section 12's rule, for section 12's reason).

Writer behavior: a `201` append response carrying receipt fields appends one
record, best-effort — a failed sidecar write MUST NOT fail or retry the append
(the entry is already durable; the miss is labelled, rule 6). A response
without receipt fields appends nothing and is not an error.

Verification, when a verifier is given the sidecar: for every readable record,
the trail's own entry hash at `seq` is compared with the record's
`entry_hash`. The comparison is deterministic — the same footing as a pin
(section 13) — so its failures are breaks, never unverifiable:

| Reason | Class | Exit |
|---|---|---|
| `receipt_mismatch` | the trail's hash at that seq differs from the acknowledged one | 1 |
| `receipt_beyond_head` | the trail is shorter than an acknowledged append — rollback/truncation | 1 |
| `malformed_receipt_record` | a record in a known version this build cannot read (this project's own format — section 17's asymmetry) | 1 |
| `unreadable_record_version` | a `v` from a newer build — unverifiable by name | 2 |

No sidecar at all → reported as `receipts: not recorded`, never a failure and
never conflated with "checked, found nothing" (rule 5; section 12's own
absent-vs-empty rule, one sidecar over).

Honest limits, stated plainly (section 9's sidecar caveat applies verbatim):
the sidecar is as attacker-writable as the trail beside it. An attacker who
rewrites BOTH consistently is caught only against the server's own receipt
chain — read back over REMOTE.md section 10, or compared by a third party —
never by the sidecar alone. What the sidecar alone defeats is the cheaper
attack: a trail edit that does not also curate the sidecar. The one-entry
window claim holds exactly when the server sits under a different
administrative authority than the writer — the same condition every other
mechanism in this specification states and cannot check.

### 19.1 Receipt-frame descriptor fingerprint (added in 0.1.5, waxseal-fg4.9)

`RECEIPT_FRAME_PREFIX` above names the receipt_head frame's SHAPE — the same
role `DESCRIPTOR_PREFIX` plays for the header frame (section 4). It is not,
on its own, an identity a verifier can check a record against: unlike
`hash_version`, nothing in the frame ties a `receipt_head` value to the exact
field set (`receipt_seq`, `prev_receipt_head`, `entry_hash`, in that order)
that produced it. This section closes that gap the same way section 4 closes
it for the header, by deriving a fingerprint from a descriptor of that field
set rather than trusting a hand-written literal to keep meaning the same
thing forever:

```
RECEIPT_DESCRIPTOR_PREFIX = b"waxseal-receipt-descriptor-v1\n"

receipt_fingerprint = lowercase_hex(SHA-256(
    RECEIPT_DESCRIPTOR_PREFIX || u64be(5)
 || lp("sha256") || lp("lp64")
 || lp("receipt_seq") || lp("prev_receipt_head") || lp("entry_hash")))
```

`lp` here is the DESCRIPTOR frame's own length prefix (section 4's `lp`,
restated for this frame rather than shared with it — see
`domain/receipt_fingerprint.py`'s module docstring for why sharing code
between the two would be its own hazard): 8-byte big-endian length followed
by the UTF-8 bytes, untagged. Widening or reordering the three receipt_head
inputs, or changing the algorithm or encoding name, changes
`receipt_fingerprint` automatically — the same migration-060 protection
`hash_version` already gives the header.

The sidecar record gains one field, additive to the shape section 19 above
defines:

```
{"entry_hash": "<hex64>", "receipt_frame_fingerprint": "<hex64>", "receipt_head": "<hex64>", "receipt_seq": <int>, "seq": <int>, "source": "<str>", "ts": "<str>", "v": 1}
```

`receipt_frame_fingerprint` is this build's `receipt_fingerprint` at write
time — never a caller-supplied literal, the same rule `hash_version` follows.
Absent on any record written before this section existed (every receipt
issued under 0.1.5 prior to this append): a verifier treats an absent value
as this build's OWN current `receipt_fingerprint`, so an already-issued
receipt keeps verifying under the identity it always had. CLAUDE.md rule 2
(never change a frozen fingerprint's meaning) applies to `receipt_fingerprint`
values exactly as it applies to `hash_version` values: this is an ADDITIVE
identity layered onto the unchanged receipt_head frame bytes above, never a
reinterpretation of any already-issued receipt.

Verification gains one row, extending section 19's table by the same
asymmetry (section 17) that already separates `malformed_receipt_record` from
`unreadable_record_version` — a record whose declared `receipt_frame_fingerprint`
this build does not recognize is unverifiable by name, never a break, because
this build was never told what that identity means and must not judge the
record's other fields under its own assumptions:

| Reason | Class | Exit |
|---|---|---|
| `unrecognized_receipt_frame_fingerprint` | a `receipt_frame_fingerprint` this build's registry does not recognize | 2 |

This is a SEPARATE axis from `unreadable_record_version` above, not a
replacement for it: `v` names the JSON record's own shape;
`receipt_frame_fingerprint` names the receipt_head hash frame's identity. A
record can be unrecognized on one axis while fully readable on the other, and
the two reasons are never collapsed into each other.

## 20. Sealed segments (`trail.NNNNN.jsonl`) — added in 0.1.5

A hook that appends on every tool dispatch grows one file without bound, and
one file shared by every project a developer touches braids unrelated
histories into a single chain. Rotation fixes the first; per-project routing
fixes the second. Neither is optional and neither has an environment
variable: routing and rotation are on by default.

### 20.1 Layout

A trail lives in a per-project directory under the host's own waxseal home
(`~/.claude/waxseal`, `$CODEX_HOME/waxseal`, `~/.cursor/waxseal`):

```
<host waxseal home>/trails/<slug>/trail.00000.jsonl
                                  trail.00001.jsonl
                                  ...
                                  segments.lock
slug = sanitize(basename(cwd))[:32] + "-" + SHA-256(cwd)[:12]
```

`sanitize` folds to lowercase `[a-z0-9-]`; an empty result is the literal
`unnamed`. The digest is over the LITERAL `cwd` string — never a resolved
path. Resolving is host-dependent (symlinks, case folding), so the same
project would land in two slugs on whichever host disagreed, and a split
trail is indistinguishable from a truncated one. A 48-bit collision merely
MERGES two projects into one trail: weaker privacy separation, never a broken
chain.

Ordinals are zero-padded to five digits, so LEXICOGRAPHIC order over names
equals CHRONOLOGICAL order. Timestamp names are not permitted: clock skew
reverses them, and a verifier walking names would check the bindings
backwards. An ordinal past `99999` is refused rather than widened.

Every sidecar keeps deriving its own path as `<segment file name> + suffix`
(section 9's `.anchors`, section 11's `.attest`/`.sealagg`, section 12's
`.drops`, section 19's `.receipts`), so each segment carries its own
sidecars with no rule of its own.

The pre-0.1.5 shared trail (`<host waxseal home>/trail.jsonl`) is NOT
migrated and NOT force-sealed. Routed appends simply stop arriving, and it
keeps verifying forever under plain `waxseal verify`. A trail named through
`WAXSEAL_TRAIL` keeps its location, and rotation still applies to it: on its
first rotation it is ADOPTED as the base segment, and the successor is
`<its stem>.00000.jsonl`.

### 20.2 Rotation binding

The active segment is the highest ordinal present. Rotation only ever CREATES
a file; nothing is renamed, so every `chain_id` already recorded against a
segment stays true.

A new segment is a NEW chain: `seq` 0, `prev_hash` = 64 zeros (section 1).
Segments are linked ONLY by a binding, never by `prev_hash` across a file
boundary — extending the chain across files would make verifying the newest
segment require every byte of every older one, which is the growth problem
rotation exists to solve.

The binding is the seq-0 entry of every segment that has a predecessor:

```
payload_type = "application/vnd.waxseal.rotation-binding+json"
payload      = {"chain_id": "<slug>/<predecessor identity>",
                "head_hash": "<hex64>",
                "seq": <int>}
```

The triple is exactly the handoff binding of section D3 / `domain/handoff.py`,
reused verbatim including its parser and `binding_holds`. Only the payload
type and the `chain_id` convention are new. Reusing the handoff type is not
permitted: it would make `verify-handoff` report rotation bindings, and the
two carry different obligations — a rotation binding is MANDATORY at seq 0 of
every segment with a predecessor (its absence is a verdict), a handoff
binding is optional wherever it appears.

`seq` and `head_hash` name the CLOSING segment's tail at the moment of
rotation: its last `seq` and its `entry_hash` at that `seq`. The identity in
`chain_id` is the predecessor's file name without the `.jsonl` suffix
(`trail.00000`, or `trail` for an adopted unnumbered base). The slug half
records which project directory the segment lived under at rotation time and
is metadata only — resolution is by identity, so moving or renaming the
directory is not a break.

Rotation is triggered by ONE `stat` of the active segment at open: a
threshold of 16 MiB, a constant in code with no environment variable. By-count
triggering is not permitted (stored entry sizes differ by roughly 100x, so a
count says almost nothing about bytes). Reading the closing segment's tail and
appending the new segment's genesis binding are ONE critical section, held
across BOTH files by `<dir>/segments.lock`, so N racing writers produce
exactly one rotation. A writer publishes one last checkpoint for the segment
it is sealing, best-effort, into that segment's own `.anchors` (section 9's
sidecar, never a chain append); a failure there is labelled and never blocks.

### 20.3 Verification (`waxseal segments <dir>`)

Read-only: it appends nothing, to the trail or to any sidecar. It walks each
stem's segments in ordinal order (an unnumbered base first, as the oldest),
takes each segment's own `verify_chain` verdict (section 5), and checks each
rotation binding against the predecessor's OWN current entry hashes.

A binding that is PRESENT is checked wherever the segment sits, including at
the lowest ordinal in the directory. Exempting the lowest one unconditionally
would make prefix deletion free: remove segments 0 and 1, and segment 2
becomes "the first" and is never asked about the binding it still carries.
Only a segment whose seq 0 is not a binding is exempt, and then only at
position 0.

Per-segment state is `ok`, `broken`, `unverifiable` or `missing`; the
aggregate is the join of them under the severity order of section 5's own
verdicts (`ok` < `unverifiable` < `broken`), never a comparison of exit
codes — 2 is the larger code but the weaker finding.

| Reason | Class | Exit |
|---|---|---|
| `rotation_binding_missing` | a segment with a predecessor whose seq 0 is not a binding | 1 |
| `rotation_binding_mismatch` | the predecessor's hash at that seq differs from the one the binding committed to — deterministic, the same footing as `verify-handoff` | 1 |
| `segment_missing` | a surviving binding names a predecessor that is not present | 1 |
| `rotation_binding_unreadable` | a binding payload this build cannot parse — unverifiable by name | 2 |
| `rotation_binding_unchecked` | the predecessor is present but unreadable, so there was nothing to compare | 2 |
| `segment_unreadable` | a segment's stored lines will not parse at all (a torn write from a crash mid-rotation, an out-of-band edit) | 2 |
| section 5's own reasons, plus `broken_seq` | a break inside one segment's chain, prefixed with the segment name | 1 |

An unknown schema fingerprint inside any segment stays `unverifiable` and
MUST NOT become exit 1 (section 4's rule, unchanged one layer up).

`segment_missing` is a BREAK, not an unverifiable state. A surviving binding
is POSITIVE evidence that the named segment existed, which puts its absence
on the same fail-closed footing as `binding_holds` itself; reporting it as
unverifiable would let deleting a segment downgrade the whole directory from
exit 1 to exit 2, letting an attacker choose their own verdict. A missing
segment is nonetheless never rendered as "tampered": it gets its own state
and its own line, because a legitimate archival move produces exactly the
same evidence, and which of the two happened is an operator's decision, never
this command's.

Exit 3 means nothing was read: no such directory, or a directory holding no
numbered segment. A trail that has never rotated is not a one-segment
directory — `waxseal verify <trail>` is the command for it, and reporting "ok,
all bindings hold" about a directory nothing was checked in would be a verdict
about nothing.

Honest limits, in the same terms as section 19: a rotation binding is as
attacker-writable as the segments around it. An attacker who rewrites a
closing segment AND regenerates every binding downstream of it is caught only
against an external anchor (section 9) or a witness (section 14) that saw the
old head, never by the bindings alone. What the bindings alone defeat is the
cheaper attack: editing or deleting one segment without curating the ones that
name it.

## 21. Ledger layer (added in 0.1.5, Workstream F)

Three ports/contracts, one per question a chain-agnostic reader can ask about a trail:
did the writer anchor on time (liveness), does the world agree with this build about
what a fingerprint means (registry), and is there a stake behind the writer's
signatures (bond). `ports/ledger.py` defines the three as Protocols
(`LedgerReader`/`LedgerSink`/`Signer`/`TransactionSigner`); `adapters/evm.py`'s
`EvmLedgerReader`/`EvmLedgerSink`/`EvmAnchorSink` are the first (and, at this writing,
only) adapter, over stdlib `eth_call` JSON-RPC for reads and an operator-injected
`Signer` for writes — no crypto library enters this process (CLAUDE.md rule 1).

### 21.1 The error contract

A `LedgerReader` method returns `None` ONLY for "the contract answered, and it holds
nothing" (no checkpoint for this trail id, no deadline configured, no descriptor under
this fingerprint) — a MEASURED ABSENCE. It raises `LedgerUnreachable` when it could not
ask at all (a network failure, or a contract answer this build cannot parse); returning
`None` there would render a dead node as a writer that never anchored, which is a false
alarm manufactured out of a network problem. `bond_status` is the one method that never
returns `None`, because `BondStatus` (21.3) already has four values and a `None` there
would be a fifth encoding of one of them.

### 21.2 Checkpoint signing digest and the trail id

A writer's checkpoint is signed off-chain and submitted by any party — the contract
does not need the submitter to be the writer, only the SIGNATURE to be. The 32 bytes a
writer's key signs (F1/F2's digests were reconciled onto this single shape in `fbba32f`,
after the two independently-written halves of the ledger layer signed different bytes
through every green gate until an end-to-end anvil submit caught it):

```
LEDGER_CHECKPOINT_SIG_PREFIX = b"waxseal-ledger-checkpoint-sig-v1\n"

trail_id_for(chain_id) = SHA-256(UTF-8(chain_id))          # 32 bytes

checkpoint_signing_digest(chain_id, cp) = SHA-256(
    LEDGER_CHECKPOINT_SIG_PREFIX
 || u64be(2)                                    # field count
 || lp(hex(trail_id_for(chain_id)))
 || checkpoint_frame(cp))                        # section 9's frame, unchanged
```

The trail is bound INSIDE the digest, keyed by `trail_id_for`, not by the trail's name
directly: the contracts hold `bytes32` mapping keys and cannot hold a name of unbounded
length, so the reduction has to happen somewhere, and it is pinned here rather than
left for each side of the protocol to assume independently. `checkpoint_frame` is
signed DIRECTLY, not through its own hash first: lp64 (section 2) already
length-prefixes every field, so the concatenation above is already injective, and an
extra hash-and-re-hex would only add a second surface for two languages to disagree
about, for a property the encoding already guarantees.

This digest is a SEPARATE mechanism from `checkpoint_frame` alone (section 9): a
checkpoint anchored locally or to an RFC 3161/OpenTimestamps sink is never signed this
way, because those sinks do not need a writer identity recovered from a signature —
only the ledger's `ecrecover`-based contracts do.

### 21.3 The three ternaries

Every on-chain read this section defines is three-valued, never two — the Ternary
Evidence Principle (CLAUDE.md) applied to a chain the client does not control:

| Reading | Values | Domain module |
|---|---|---|
| Liveness | `live` / `delinquent` / `unreachable` | `domain/liveness.py`, `LivenessVerdict` |
| Bond status | `bonded` / `slashed` / `unbonded` / `unreachable` | `domain/bond.py`, `BondStatus` |
| Registry cross-check | `agrees` / `disagrees` / `unreachable` | `domain/registry.py`, `RegistryFinding` |

Bond status carries FOUR values, not three, deliberately: `slashed` names an
ADJUDICATED event (a fraud proof was submitted and accepted); `unbonded` names a writer
that simply never posted a stake. Folding the second into the first would print
"slashed" over a writer nobody ever proved anything against — an adjudication asserted
from an absence, the same collapse CLAUDE.md rule 5 forbids in the other direction.
`unreachable` remains the one value across all three readings that means nothing was
measured.

Each reading maps onto `Verdict` (domain/verdict.py) two DIFFERENT ways, because
`ledger-status` and `verify`/`report` answer different questions (21.6):

- `LivenessVerdict.to_verdict()` / `BondStatus.to_verdict()` (the `ledger-status`
  sense): the bad measured state (`delinquent`, `slashed`, `unbonded`) is a POSITIVELY
  DETECTED finding, `Verdict.BROKEN`.
- `LivenessVerdict.to_verify_verdict()` / `RegistryFinding.to_verdict()` (the
  `verify`/`report` sense): range over `{OK, UNVERIFIABLE}` ONLY — `BROKEN` is not
  spelled in either mapping table, so neither reading can ever contribute a `verify`
  break, by construction. A chain saying "not anchored on time" or "two registries
  disagree" is not a chain saying "the trail was edited"; letting either raise `broken`
  would print "tampered" over a writer whose network was down, or over a conflict this
  process has no standing to adjudicate.

`RegistryFinding`'s status has NO mapping onto `BROKEN` at all: `_REGISTRY_STATUS`'s
entire range is `{OK, UNVERIFIABLE}`, so a registry disagreement structurally cannot
reach `verify` exit 1 through any path, and there is no `to_verdict()` variant that
would let it.

### 21.4 A fourth transport-layer value: `LedgerDisagreement`

`EvmLedgerReader` requires at least TWO RPC endpoints (`MIN_ENDPOINTS = 2`): one
endpoint is one narrative, and an eclipsing adversary does not need to break a chain,
only to be the single voice the client hears. Every read asks every configured
endpoint and resolves three ways:

- every endpoint agrees → the value, returned;
- two or more endpoints answered and DID NOT agree → `LedgerDisagreement` is raised,
  naming every disagreeing pair and what each answered;
- fewer than two endpoints answered → `LedgerUnreachable`, naming every silence.

Disagreement is checked BEFORE the quorum requirement: a measured conflict between two
reachable endpoints outranks a partial silence, because reporting the outage instead
would erase the one observation that distinguishes an eclipse from a mere outage.

`LedgerDisagreement` sits BESIDE `ok`/`broken`/`unverifiable` (section 5), not inside
that vocabulary: it is not a verdict about the trail at all, it is an observation about
the TRANSPORT — two independent, reachable observers reporting different states of the
same contract. It is not itself a not-measured state collapsing into a binary (the
shape the Ternary Evidence Principle names), which is why CLAUDE.md's Named-principle
list documents it here rather than counting it as one more numbered instance there.
Every caller that catches it (the CLI's ledger dimensions, 21.6) maps it onto
`Verdict.UNVERIFIABLE`, reported with both disagreeing answers printed, never resolved
by picking one.

Comparison excludes fields the chain itself does not hold precisely: a checkpoint's
`block_time` is a miner-influenced value with a tolerance of seconds, immaterial
against deadlines measured in hours, so two endpoints differing only in `block_time`
still agree; `chain_id`/`seq`/`entry_hash`/`root` are compared exactly, and any
difference in those IS a disagreement.

### 21.5 The revert as a three-way answer

`AnchoringLiveness.isDelinquent`/`.lastSeen` REVERT with `TrailNotRegistered` for an
unregistered or never-anchored trail, rather than returning `false`/zero: `bool` is
two-valued and the honest answer is three-valued. On the READ path this specific,
recognised revert is a MEASURED ABSENCE (`None`, 21.1) — the node answered,
deterministically, from state, and a second call answers the same. An UNRECOGNISED
revert is different again: the contract answered with something this build cannot
interpret, so nothing was measured, and it degrades to `LedgerUnreachable`, labelled
with the four-byte error selector rather than swallowed silently (CLAUDE.md rule 6). A
genuine network failure carries no selector at all. Three distinguishable outcomes from
one call site, never collapsed into two:

| What happened | Read-path result | Labelled how |
|---|---|---|
| a revert this build recognises (e.g. `TrailNotRegistered`) | measured absence, `None` | — |
| a revert this build does not recognise | `LedgerUnreachable` | the 4-byte selector, in the message |
| the node could not be reached at all | `LedgerUnreachable` | no selector — a genuine silence |

On the WRITE path the same shape inverts: a transaction the contract rejects (any
revert) is the contract answering NO, a POSITIVE rejection — it raises `LedgerError`
(never `LedgerUnreachable`), because the node was reached and it refused the write on
purpose. Estimating gas before sending catches most rejections before broadcasting;
either way, the operator's gas is not spent learning what the estimate already said.

### 21.6 CLI contract

`waxseal ledger-status <trail> --rpc URL [--rpc URL…] --liveness ADDR [--registry ADDR]
[--bond ADDR --writer ADDR] [--trail-id NAME] [--json]` is read-only against the ledger
layer. Exit codes reuse `Verdict.to_exit_code()`, the SAME convention
`reconcile-tickets` (the exogenous-admission-tickets section) already establishes: 0 =
every configured dimension came back clean (live, and registry agrees if `--registry`
was given, and bonded if `--bond` was given); 1 = a POSITIVELY DETECTED finding —
delinquent, slashed, or unbonded; 2 = unreachable, endpoints disagree
(`LedgerDisagreement`), or malformed input — never rendered as "0 findings" (rule 5); 3
= the named trail does not exist (nothing was read). `--trail-id` defaults to the trail
path's own resolved string when omitted.

`verify`/`report` accept the same `--rpc/--liveness/--registry [--trail-id]`, adding a
ledger dimension that can ONLY ever contribute exit 2 (21.3), with reasons
`ledger_delinquent`, `registry_disagreement`, `ledger_unreachable`.

`waxseal registry publish --descriptor-of FP --registry ADDR --rpc URL […]
[--write-rpc URL]` publishes the descriptor this build's own `VersionRegistry` holds
for `FP` — the contract computes `sha256(descriptor)` itself (`FingerprintRegistry.sol`,
append-only, no owner, no update path), so there is no separate fingerprint argument
that could disagree with the bytes sent. `waxseal bond deposit --bond ADDR
--amount-wei WEI […]` posts or tops up the signer's own stake. `waxseal bond prove
<proof.json> --bond ADDR […]` submits a fraud proof — `{"kind": "equivocation", ...}`
(two signed, conflicting checkpoints at one seq, self-contained) or `{"kind":
"non_extension", ...}` (a POSITIVE divergent-leaf challenge, never a mere failing
consistency proof — see `domain/bond.py`'s own module docstring for why the latter
would let anyone empty an honest writer's bond for the price of gas). None of these
three commands appends a chain entry: they write to the ledger layer, the same footing
`anchor` already has, never to the audit trail (CLAUDE.md's CLI contract is unchanged).
Every ledger write prints the chain id, the contract address, and the action before
sending.

`waxseal anchor` accepts `--evm-rpc URL […] --evm-liveness ADDR [--evm-write-rpc URL]
[--evm-trail-id NAME] [--evm-consistency-proof-file PROOF.JSON]`, publishing the SAME
checkpoint `AuditLog.anchor()` already computed to a fourth independently-recording
anchor domain alongside `--tsa-url`/`--ots-calendar` (section 9). The consistency proof
is required by the contract from the SECOND submit for a given trail id onward
(`AnchoringLiveness.submit` gates every submit after the first on an RFC 9162 proof
that the new head extends the recorded one); omitting it after the first submit
surfaces as a labelled `LedgerError` naming the revert, never a silent no-op.

Credentials: `WAXSEAL_EVM_SIGNER_CMD` names an external program answering a three-verb
protocol — `<cmd> address`, `<cmd> sign-digest 0x<hex32>`, `<cmd> sign-tx` (fields as a
JSON object on stdin) — never a private key on argv or in the process table, the same
env-only discipline `WAXSEAL_API_KEY`/`WAXSEAL_WITNESS_API_KEY` already draw.

### 21.7 Scope, stated plainly

None of the above closes coverage, attests any individual entry's honesty, helps
against a writer compromised before it signs, or defends against an eclipse that
controls every RPC endpoint a client is configured to reach. `AnchoringLiveness`
detects that a writer stopped anchoring, never which entry (if any) was altered.
`FingerprintRegistry` removes the poisoned-LOCAL-registry caveat on structural schema
safety; it does not license this build to recompute a row under a fingerprint it merely
agrees is real by NAME (RFC 6962 section 4.6 — unchanged, section 4). `BondedCheckpoints`
prices ONE specific dishonesty — signing two conflicting checkpoints at one position —
expensive once caught; it does not make equivocation impossible, and it does not detect
a writer that is dishonest but never contradicts itself. See
`docs/security/threat-model.md` section 7 for the full doctrine.
