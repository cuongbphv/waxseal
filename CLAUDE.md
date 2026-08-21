# waxseal — Engineering Constitution

waxseal is a tamper-evident, schema-evolution-safe audit hash chain library for AI agent
frameworks. MIT, Python >=3.11, **zero hard runtime dependencies (stdlib only)**.

This file locks the design, the architecture, and the invariants. Rules here are
**bất di bất dịch** (immutable) unless the repository owner explicitly changes this file.
An AI agent working in this repo MUST NOT weaken, delete, or route around any rule below,
and MUST NOT edit the frozen paths listed in "Frozen paths".

## Why this library exists (the two incidents)

1. **"Migration 060" (a prior production system)**: the hashed field set was widened
   without a version identity → every historical row failed verification. A mass false
   tampering alarm.
2. **beads v1.2.2 (08/2026)**: an accidental release migrated schema v53→v65; the reverted
   binary treated the unknown version as a fatal error ("schema version mismatch") and the
   only escape hatch (`BD_IGNORE_SCHEMA_SKEW=1`) disabled safety entirely.

Both are the same failure class: **ordinal version identity + unknown version treated as
error**. waxseal makes that class unrepresentable. Everything below serves that goal.

## Locked design (do not re-litigate)

- **Envelope-based chain.** The chain hashes only the `EntryHeader`
  (`seq, ts, hash_version, payload_type, payload_hash, prev_hash`). Payload is arbitrary
  bytes, stored separately, referenced only by `payload_hash`. Changing payload schema
  never touches the chain.
- **`hash_version` is a schema fingerprint, never a manual string.** It is the SHA-256 of
  the canonical version descriptor (field names + algorithm + encoding rule). Changing the
  field set changes the fingerprint automatically — an agent cannot silently widen the
  tuple (that is exactly migration 060).
- **Unknown fingerprint → "unverifiable by name", NEVER "tampered", NEVER a crash**
  (RFC 6962 §4.6 principle: unrecognized types are opaque, not errors). A verifier MUST NOT
  recompute a row under a tuple it was not signed with — reporting a row intact on a hash
  it cannot reproduce is the one lie a tamper-evidence mechanism must never tell.
- **Canonical encoding = lp64v1**: 8-byte big-endian length prefix per field, UTF-8 values,
  NULL sentinel `b"\x00NULL\x00"` distinct from empty string, PAE-style frame
  (`waxseal-v1` prefix + field count). Defined byte-for-byte in SPEC.md. Never hash a
  serialization you do not control (no protobuf, no repr(), no un-canonicalized JSON).
- **Redact-before-hash.** Redaction runs BEFORE `payload_hash` is computed. Cleartext
  secrets never touch disk. A redaction miss is unrecoverable by design — that is why the
  Redactor runs first, not why it may be skipped.
- **Genesis `prev_hash` = 64 zeros.** Sequences are contiguous from 0.
- **Append-only everywhere**: the log, the version registry, SPEC.md test vectors. No
  in-place migration of entries, ever. Old entries verify under their own fingerprint.
- **Chain integrity ≠ trail completeness.** A dropped write leaves no seq gap, so
  `verify` can still return ok. `dropped_writes: int | None` reports completeness
  separately; `None` means "not measured" and is NEVER the same as `0`.

## Architecture (layer DAG, enforced by tests/architecture/)

```
domain/    pure logic. NO I/O, NO imports from ports/adapters, stdlib only.
ports/     typing.Protocol interfaces only. Imports domain at most.
adapters/  concrete backends (jsonl, sqlite, redactors, atomic). Import domain + ports.
cli.py     thin shell over adapters. Nothing imports cli.
```

- `domain/` must stay importable with zero side effects and zero filesystem access.
- Only `adapters/atomic.py` may call `os.replace` (single-owner rule).
- Public API is the set exported by `src/waxseal/__init__.py` and is frozen by
  `tests/architecture/test_invariants.py` (TestPublicApiFrozen). Additions require
  updating that test in the same commit with rationale; removals/renames are breaking
  changes.

## Immutable rules (bất di bất dịch)

1. **NO new runtime dependencies.** `[project] dependencies` stays `[]`. Heavy things go
   to optional extras, and think twice even then.
2. **Never change a frozen fingerprint's meaning.** The registry is append-only: a new
   field set = a new descriptor = a new fingerprint entry. Editing an existing descriptor
   or verifier for a released fingerprint is forbidden.
3. **Golden test vectors are write-once.** `tests/vectors/` and the vectors in SPEC.md may
   gain new vectors; existing vectors may never be edited or deleted. CI/tests fail if a
   frozen hash changes — that failure means STOP, not "update the vector".
4. **Verify reports, never repairs.** No code path may rewrite, reorder, or "fix" chain
   entries. Which row is the tamper is a decision only an operator can make.
5. **`None` ≠ `0`, unverifiable ≠ tampered, unmeasured ≠ absent.** Applies to
   `dropped_writes`, unknown fingerprints, and any future metric.
6. **Fail-open must be labelled.** If a guard/redactor degrades, the degradation is
   recorded in the output (notice field / warning), never swallowed silently.
7. **Concurrency: read-tail + append is one critical section.** JSONL: file lock around
   both. SQLite: `BEGIN IMMEDIATE` + `UNIQUE(seq)`. Two writers must never both extend the
   same `prev_hash` (fork). A prior production system shipped this bug via a web-server
   threadpool; the concurrency test exists because of it.
8. **Timestamps are injectable** (`now_fn`), monotonic-agnostic; tests never sleep to pass.
9. **Comments carry the incident, not the mechanics.** State the constraint the code can't
   show (which bug, which spec clause), not what the next line does.

## Testing rules (TDD + coverage)

- **TDD is mandatory**: no production code without a failing test first. Bug fix = failing
  repro test first.
- **Coverage floor: 90% line coverage over `src/waxseal`** (`fail_under = 90` in
  pyproject). New modules land WITH their tests in the same commit. The floor may go up,
  never down (ratchet).
- Every behavior class needs a test: happy path, tamper (edit/delete/insert/reorder →
  correct `broken_seq` + reason), unknown fingerprint (→ unverifiable, exit 2, NOT
  tampered), concurrency (N threads, no fork), JSONL↔SQLite parity (same payload → same
  `entry_hash` byte-for-byte), redaction (secret never reaches disk).
- The concurrency test must carry a **falsifiability receipt**: documented proof it fails
  when the lock is removed.
- Golden vectors are cross-checked by an independent script that implements SPEC.md
  prose directly (not by importing waxseal domain code).
- Run: `uv run pytest --cov=waxseal` — all green + coverage floor before any "done" claim.

## Frozen paths (agents MUST NOT edit without explicit owner instruction)

- `SPEC.md` (after v1 freeze)
- `tests/vectors/**`
- `src/waxseal/domain/fingerprint.py` (descriptor canonical form)
- `CLAUDE.md` (this file)
- `LICENSE`

## CLI contract

`waxseal verify <path>`: exit 0 = intact; exit 1 = broken (prints first break: seq +
reason); exit 2 = intact-but-unverifiable-entries-present (prints fingerprints); exit 3 =
trail path does not exist (nothing read, nothing created). `tail`, `inspect`, `head` are
read-only. `waxseal install <target>` writes host shim files only (hook/plugin stubs in
the agent framework's home). The CLI never writes to the log.
