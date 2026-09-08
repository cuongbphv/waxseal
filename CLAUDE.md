# waxseal - Engineering Constitution

waxseal is a tamper-evident, schema-evolution-safe audit hash chain library for AI agent
frameworks. MIT, Python >=3.11, **zero hard runtime dependencies (stdlib only)**.

This file locks the design, the architecture, and the invariants. Rules here are
**bất di bất dịch** (immutable) unless the repository owner explicitly changes this file.
An AI agent working in this repo MUST NOT weaken, delete, or route around any rule below,
and MUST NOT edit the frozen paths listed in "Frozen paths".

## Why this library exists (the two incidents)

1. **"Migration 060" (a prior production system)**: the hashed field set was widened
   without a version identity -> every historical row failed verification. A mass false
   tampering alarm.
2. **beads v1.2.2 (08/2026)**: an accidental release migrated schema v53->v65; the reverted
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
  field set changes the fingerprint automatically - an agent cannot silently widen the
  tuple (that is exactly migration 060).
- **Unknown fingerprint -> "unverifiable by name", NEVER "tampered", NEVER a crash**
  (RFC 6962 §4.6 principle: unrecognized types are opaque, not errors). A verifier MUST NOT
  recompute a row under a tuple it was not signed with - reporting a row intact on a hash
  it cannot reproduce is the one lie a tamper-evidence mechanism must never tell.
- **Canonical encoding = lp64, and there is exactly one**: 8-byte big-endian length prefix
  per field over a tagged payload (`0x00` absent, `0x01` + UTF-8 for a string), PAE-style
  frame (`waxseal-lp64` prefix + field count). The tag makes injectivity unconditional -
  absent and every possible string differ in their first encoded byte, so there is no side
  condition to maintain and no input to reject. Defined byte-for-byte in SPEC.md. Never
  hash a serialization you do not control (no protobuf, no repr(), no un-canonicalized
  JSON). A superseded encoding is not a variant to choose between: `domain/hashing.py`
  implements the current one and nothing else, and a row whose fingerprint no current
  encoder can reproduce is unverifiable by name, never recomputed under a substitute.
- **Redact-before-hash.** Redaction runs BEFORE `payload_hash` is computed. Cleartext
  secrets never touch disk. A redaction miss is unrecoverable by design - that is why the
  Redactor runs first, not why it may be skipped.
- **Genesis `prev_hash` = 64 zeros.** Sequences are contiguous from 0.
- **Append-only everywhere**: the log, the version registry, SPEC.md test vectors. No
  in-place migration of entries, ever. Old entries verify under their own fingerprint.
- **Chain integrity ≠ trail completeness.** A dropped write leaves no seq gap, so
  `verify` can still return ok. `dropped_writes: int | None` reports completeness
  separately; `None` means "not measured" and is NEVER the same as `0`.
- **Tamper-evident is the headline claim; "tamper-proof" is only ever SCOPED**
  (DESIGN.md §11, owner-approved 31/08/2026): the anchored prefix on a finalized
  external ledger, WORM-archived segments - never the live tail, never write-time
  honesty. No output and no doc prints "tamper-proof" without naming its scope.

## Named principle: the Ternary Evidence Principle

**Collapse theorem.** Let `f: {true, false, not-measured} -> {0, 1}` be any reporting
function over a three-valued evidential state. By the pigeonhole principle, either
`f(not-measured) = f(false)` (a false alarm) or `f(not-measured) = f(true)` (false
confidence) - collapsing to two values leaves no third option. "Migration 060" and
"beads v1.2.2" (see the two incidents above) are the same collapse in different
clothing: an unknown/unmeasured state got forced into a binary and came out on the wrong
side.

This codebase already applies the principle, by name or not, in (at least) thirteen places:

1. **Verdict chain**: `ok` / `broken` / `unverifiable` (`domain/verify.py`), now also
   formalized as the `Verdict` type (`src/waxseal/domain/verdict.py`) - a new instance
   that arrived in this same release, not merely a restatement of the old convention.
2. **`dropped_writes: int | None`** - `None` ("not measured") never renders as `0`
   ("measured, zero loss").
3. **`human_oversight.mode`** (`src/waxseal/domain/decision.py`) - `"unrecorded"` is a
   value distinct from `"automated"`, not the absence of one.
4. **`ModelRef.digest = None`** (`src/waxseal/domain/decision.py`) means "unpinned", a
   weaker claim recorded as such rather than guessed at.
5. **Witness verdicts** (`src/waxseal/domain/witnessing.py`) - `unreachable` is distinct
   from both `consistent` and `inconsistent`.
6. **RFC 3161 nonce absence** (`src/waxseal/adapters/rfc3161.py`,
   `src/waxseal/adapters/anchors.py`) - no stored nonce means "nothing to compare",
   skipped, never failed.
7. **Exogenous ticket reconciliation** (`src/waxseal/domain/tickets.py`,
   `reconcile-tickets` in the CLI contract) - exit 2 means "unmeasured: issuer data
   unavailable this run", never rendered as "0 drops detected". Found without being
   told, exactly as the paragraph below used to challenge; recorded here 31/08/2026.
8. **WORM retention on an archived segment** (`src/waxseal/adapters/s3.py`) -
   `worm_locked` / `worm_unlocked` / `worm_unknown`: an Object Lock reply this build
   cannot interpret is unmeasured, never "not locked", so a wrong guess costs an honest
   "could not tell" and never a false guarantee. The first instance where the SUBJECT of
   the question had to become part of the state's identity - S3 protects only the object
   version named in the request, so the same three values asked about a bucket and asked
   about an object version are different claims. `_WORM_LABEL` is keyed on the
   `(subject, state)` PAIR for that reason: keyed on state alone, bucket evidence printed
   the object-level guarantee. A ternary can be correct in every value and still lie in
   its renderer; that renderer never reached `develop`.
9. **Segment archiving** (`src/waxseal/domain/archive.py`) - `archive_stored` /
   `archive_failed` / `archive_not_attempted`. No destination configured is not a failed
   upload: calling it success invents an off-box copy that does not exist, calling it
   failure alarms an operator who never opted in. Distinctive because it is invisible to
   chain integrity - under a mutation that broke archiving entirely, the chain, the
   rotation binding and the new segment all still verified `ok`. A defect no verdict can
   see is why the third value has to be asserted directly, never inferred from one.
10. **RFC 3161 signature checking** (`src/waxseal/adapters/rfc3161_verify.py`) -
    `signature_valid` / `signature_invalid` / `signature_unchecked`, reusing `Verdict`
    rather than growing a parallel three-valued type beside it. The first instance where
    the third value has THREE causes that each need a DIFFERENT fix: once a bundle IS
    named, the `rfc3161` extra is not installed, the bundle could not be read, or the
    token's CMS is a shape this build cannot parse. Every unchecked label therefore names
    its own cause AND its own remedy - install the extra, repoint `--tsa-ca-file`, or fall
    back to `openssl ts -verify` - because "unchecked" with no remedy is only marginally
    better than silence: an operator who cannot tell which of the three they hit can act
    on none of them. Unreadable stays unchecked, never invalid; only a signature that
    verifiably fails, or a signer that verifiably reaches none of the operator's anchors,
    earns `signature_invalid`.
11. **On-chain liveness reading** (`src/waxseal/domain/liveness.py`) - `live` /
    `delinquent` / `unreachable`. An RPC endpoint that did not answer has measured
    nothing about a writer's punctuality: reading that silence as `delinquent` raises an
    alarm about a node outage that was never the writer's fault, and reading it as `live`
    reports a writer that stopped anchoring weeks ago as healthy - the collapse arrived at
    from both directions on the same predicate. `LivenessVerdict` carries two DIFFERENT
    mappings onto `Verdict` on purpose: `to_verdict()` (the `ledger-status` sense, where a
    delinquent reading is a positive detection, exit 1) and `to_verify_verdict()` (the
    `verify`/`report` sense, whose range excludes `BROKEN` by construction, so a chain
    saying "not anchored on time" can never print as "the trail was edited").
12. **Bond status** (`src/waxseal/domain/bond.py`) - FOUR values, not three, and the
    fourth is the point: `bonded` / `slashed` / `unbonded` / `unreachable`. `slashed`
    names an ADJUDICATED event - a fraud proof was submitted and accepted; `unbonded`
    names a writer that simply never posted a stake. Folding the second into the first
    "would print 'slashed' over a writer nobody ever proved anything against - asserting
    an adjudication from an absence, which is the same move CLAUDE.md rule 5 forbids in
    the other direction" (the module's own docstring). The evidential trichotomy stays
    intact around the pair: `unreachable` remains the one value that means nothing was
    measured, and `bonded`/`unbonded` are two distinct KINDS of measured-bad or
    measured-clean, never collapsed into each other for the sake of a shorter enum.
13. **Registry cross-check** (`src/waxseal/domain/registry.py`) - `agrees` / `disagrees`
    / `absent` / `unreachable`, comparing this build's fingerprint against an on-chain
    fingerprint registry. `absent` and `unreachable` were one merged value at first -
    `FingerprintRegistry.sol`'s `lookup()` never reverts, so a caller getting back nothing
    for a fingerprint (a firm, measured "nobody registered this") looked identical to a
    caller that never got an answer at all (nothing measured). Both F3 and F4 hit that
    same collapse independently while building unrelated features on top of it, which is
    the tell that it was load-bearing rather than cosmetic: `RegistryCrossCheck.check()`
    now takes a `reachable` flag the CALLER sets from its own network measurement - the
    domain layer cannot infer reachability from a `None` descriptor, only the caller that
    made the actual RPC call knows which of the two happened. `_REGISTRY_STATUS`'s entire
    range is still `{OK, UNVERIFIABLE}` for all four values - `BROKEN` is not spelled
    anywhere in the table, so no registry reading can produce `verify` exit 1 by
    construction, not by a reviewer's care. Two registries disagreeing about one
    fingerprint are two authorities in conflict; this process has no standing to
    adjudicate which is real, and reporting "tampered" for a conflict it cannot settle
    would be migration 060 with a second registry standing in for the widened field set.
    A fifth, closely related value lives one layer down and is deliberately NOT a
    fourteenth instance here: `LedgerDisagreement` (`ports/ledger.py`), raised when two or
    more RPC endpoints answer and do not agree, is a measured CONFLICT rather than a
    not-measured state, so the collapse theorem's two-values-from-three shape does not
    apply to it the way it applies to instances 11-13 above - it is documented as its own
    transport-layer concept in SPEC.md's Ledger layer section instead of listed here.

Rule 5 below is the SPECIFIC instance of this general principle that the chain-integrity
metric needed. An implementer who has internalized the general principle, not just rule
5's wording, should be able to find a fourteenth place it applies without being told.

## Architecture (layer DAG, enforced by tests/architecture/)

```
domain/        pure logic. NO I/O, NO imports from ports/adapters, stdlib only.
ports/         typing.Protocol interfaces only. Imports domain at most.
adapters/      concrete backends (jsonl, sqlite, redactors, atomic). Import domain + ports.
sources/       ingesters that adapt external evidence into the log. May import domain,
               ports, adapters, and the public AuditLog facade - never cli, never
               backend internals (`log._backend` is off-limits; use `log.entries()`).
integrations/  host-framework glue (hook shims, timer runners). Same import rule as
               sources/. Process/subprocess I/O lives here or in adapters, never domain.
cli.py         thin shell over adapters. Nothing imports cli.
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
   frozen hash changes - that failure means STOP, not "update the vector".
   *Re-frozen once, in 0.1.4, when lp64 replaced lp64v1.* That was an explicit decision by
   the repository owner, taken while waxseal had published releases but no trail written
   under the old encoding existed outside development, so nothing verifiable was orphaned.
   It is recorded here because it is exactly the move this rule forbids by default, and
   recording it is cheaper than someone later inferring the rule is soft. It is not a
   precedent. An agent hitting a frozen-hash failure still STOPS.
4. **Verify reports, never repairs.** No code path may rewrite, reorder, or "fix" chain
   entries. Which row is the tamper is a decision only an operator can make.
5. **`None` ≠ `0`, unverifiable ≠ tampered, unmeasured ≠ absent.** Applies to
   `dropped_writes`, unknown fingerprints, and any future metric. (This is one instance
   of the general Ternary Evidence Principle - see "Named principle" above.)
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
- **Coverage floor: 100% line coverage over `src/waxseal`** (`fail_under = 100` in
  pyproject - ratcheted up from 90 on 2026-08-23). New modules land WITH their tests in
  the same commit. The floor may go up, never down (ratchet).
- Every behavior class needs a test: happy path, tamper (edit/delete/insert/reorder ->
  correct `broken_seq` + reason), unknown fingerprint (-> unverifiable, exit 2, NOT
  tampered), concurrency (N threads, no fork), JSONL↔SQLite parity (same payload -> same
  `entry_hash` byte-for-byte), redaction (secret never reaches disk).
- The concurrency test must carry a **falsifiability receipt**: documented proof it fails
  when the lock is removed.
- Golden vectors are cross-checked by an independent script that implements SPEC.md
  prose directly (not by importing waxseal domain code).
- Run: `uv run pytest --cov=waxseal` - all green + coverage floor before any "done" claim.

## Frozen paths (agents MUST NOT edit without explicit owner instruction)

- `SPEC.md` (after v1 freeze)
- `tests/vectors/**`
- `src/waxseal/domain/fingerprint.py` (descriptor canonical form)
- `CLAUDE.md` (this file)
- `LICENSE`

## CLI contract

`waxseal verify <path|url>`: exit 0 = intact; exit 1 = broken (prints first break: seq +
reason); exit 2 = intact-but-unverifiable (unknown fingerprints, unverifiable anchor
bindings, or an unreachable witness - unverifiable, never tampered); exit 3 = trail path
does not exist (nothing read, nothing created). `tail`, `inspect`, `head`, `report`,
`checkpoint`, `export-proof`, `verify-proof`, `consistency`, `reconcile-tickets`,
`verify-handoff` are read-only against the trail (and, for `verify-handoff`, against the
named origin trail too - no URL/remote support, local path only). `verify-handoff
<delegate-trail> --origin <origin-trail>` (D3: cross-trail handoff binding) checks every
handoff-binding entry recorded on the delegate trail against the origin trail's current
history; exit 0 = nothing to check or every binding holds, exit 1 = at least one binding
no longer holds (a genuinely detected mismatch, never unverifiable - the comparison is
deterministic given the origin's own hashes), exit 3 = the named origin trail does not
exist. `reconcile-tickets` (D2: exogenous admission tickets)
reconciles an operator-supplied `--issued` ticket range against tickets present on the
trail - a missing ticket is a *positively detected* drop, distinct from `dropped_writes`'s
measured minimum; its exit code reuses `Verdict`: 0 = no positively-detected drop, 1 = a
drop WAS positively detected, 2 = unmeasured (issuer data unavailable this run - never
rendered as "0 drops", rule 5). `waxseal cadence` opens no trail at all - only
operator-supplied parameters (`--lam`/`--c`/`--w`/`--rho`/`--delta`/`--t-max` required,
`--M` default 1) - and prints the cost-optimal anchoring cadence from `domain/cadence.py`:
`N*`, the clamped `N_opt`, the clamp bounds, the balance terms, and a recommended band
(never a bare point) around `N_opt`; exit 0 = feasible, exit 1 = infeasible (the anchor
technology, not the cadence, is wrong - `delta > t_max`), exit 2 = an invalid measurement
or a missing required flag. `receipt` is read-only against the trail and its sidecar; it
writes extracted
receipt/frame files only into the operator-named `--out` directory. `verify` and
`report` accept `--tsa-ca-file <bundle.pem>`, engaging the optional `waxseal[rfc3161]`
signature dimension over the RFC 3161 receipts in the `.anchors` sidecar - exit 1 =
`signature_invalid` (checked, and false), exit 2 = `signature_unchecked` (the extra is
absent, the bundle unreadable, or the CMS a shape this build cannot parse), never a
silent 0. waxseal names no default trust anchor: choosing one would decide whom an
operator trusts without saying so on any line of output. Without the flag no SPEC §17
exit code changes and the receipts are checked structurally only, which the run says
out loud rather than passing over in silence. `receipt` is unchanged. `waxseal
segments <dir>` takes the DIRECTORY holding a project's sealed segments, not a trail
file:
read-only over every segment in it, appending nothing. Exit 0/1/2 come from
`Verdict.to_exit_code`, so an unknown fingerprint in one segment never masks a real break
in another; exit 3 = the directory does not exist or holds no segment (an unrotated trail
was not checked here at all - that one is `verify <trail>`). `segment_missing` aggregates
as BROKEN, exit 1 (owner decision, 31/08/2026): a surviving rotation binding is positive
evidence the segment existed. `waxseal preflight <trail>` is read-only against the trail,
its sidecars and - with `--pin` - the pin state file, which it only READS: it is the one
command that names `--pin` and neither writes nor advances it. Exit 0 ALWAYS, because it
reports a reading and not a verdict an operator would then have to reconcile against
`verify`; the single exception is exit 3, the named local trail does not exist. No
URL/remote target. Two spec'd
verifier-state carve-outs, neither of which touches the log: `--pin` writes the pin state
file (SPEC §13 - exit 2 advances the pin because unverifiable ≠ tampered; exit 1 freezes
it), and `anchor` appends to the `.anchors` sidecar. `waxseal ledger-status <trail> --rpc
URL [--rpc URL…] --liveness ADDR [--registry ADDR] [--bond ADDR --writer ADDR]` (0.1.5,
Workstream F) is read-only against the ledger layer, reusing `reconcile-tickets`'s exit
convention exactly: exit 0 = every configured dimension came back clean (live, and
registry agrees if `--registry` was given, and bonded if `--bond` was given); exit 1 = a
POSITIVELY DETECTED finding - delinquent, slashed, or unbonded - the same
"detected, not tampered" sense `reconcile-tickets` gives its own exit 1; exit 2 =
unreachable, two RPC endpoints disagree (`LedgerDisagreement`, naming the pair - a
measured conflict, never a silence), or malformed input, never rendered as "0 findings"
(rule 5); exit 3 = the named trail does not exist. `verify` and `report` accept the same
`--rpc/--liveness/--registry [--trail-id]`: the ledger dimension this adds is
structurally incapable of exit 1 - `LivenessVerdict.to_verify_verdict()` and
`RegistryFinding.to_verdict()` both range over `{OK, UNVERIFIABLE}` only - so
`ledger_delinquent`, `registry_disagreement`, and `ledger_unreachable` all land on exit
2: a chain saying "not anchored on time" is not a chain saying "the trail was edited".
`waxseal registry publish --descriptor-of FP --registry ADDR --rpc URL […]
[--write-rpc URL]` and `waxseal bond deposit --bond ADDR --amount-wei WEI [...]` /
`bond prove <proof.json> --bond ADDR [...]` write to the ledger layer, never to the audit
trail - the same footing `anchor` already has (the CLI still never appends chain
entries); every ledger write prints the chain id, the contract, and the action before
sending. `anchor` additionally accepts `--evm-rpc/--evm-liveness[/--evm-write-rpc/
--evm-trail-id/--evm-consistency-proof-file]`, publishing the SAME checkpoint to a
fourth independently-recording anchor domain alongside `--tsa-url`/`--ots-calendar`.
Credentials come only from env: `WAXSEAL_API_KEY` for the chain server,
`WAXSEAL_WITNESS_API_KEY` for witnesses, `WAXSEAL_EVM_SIGNER_CMD` for the ledger layer's
writes (a three-verb external-signer protocol - `address` / `sign-digest` / `sign-tx` -
never a private key on argv or in a flag) - the server's write credential never crosses
the administrative-authority boundary to a witness, and the ledger layer's signer never
crosses it to either. `waxseal install <target>` writes host shim files only (hook/plugin
stubs in the agent framework's home). The CLI never appends chain entries.
