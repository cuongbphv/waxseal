# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-08-23

Six trust-boundary questions, answered in code where code can answer them and in
prose where it cannot. The theme is the same one the library was founded on: say
what was checked, say what was not, and never let the second read as the first.

### Added

- **Attested time (RFC 3161)** — `Rfc3161AnchorSink` and `waxseal anchor --tsa-url URL`.
  A minimal DER encoder/parser (`waxseal.domain.rfc3161`, stdlib only — no ASN.1 library
  enters the trust path and `dependencies` stays `[]`) builds the TimeStampReq over
  `checkpoint_frame(cp)` and reads the reply, so `ts` stops being a value the writer
  asserted about itself. What the library checks is **structural**: PKI status, message
  imprint, nonce, digest algorithm. The CMS/X.509 signature is **not** verified in-library
  — every docstring, SPEC clause and line of CLI output on this path says so, and full
  verification is delegated to `openssl ts -verify` (recipe in
  `docs/anchoring-external-time.md`). The parser cannot raise on hostile bytes: definite
  lengths only, every TLV bounds-checked, trailing bytes refused. No reason it can produce
  contains the word "tamper" — an unreadable third-party receipt is *unverifiable*
  (exit 2), and only a receipt that demonstrably attests different bytes is *broken*
  (exit 1). Deliberate asymmetry: a malformed `.anchors` record is our own format and
  stays exit 1. Golden vectors live in the new `tests/vectors/rfc3161.json` (write-once
  from birth), cross-checked byte-for-byte against `openssl ts -query` by
  `tools/gen_rfc3161_vectors.py`, which re-implements the RFC prose without importing
  waxseal.

- **OpenTimestamps anchoring** — `OtsAnchorSink` and `waxseal anchor --ots-calendar URL`
  submit the checkpoint digest to a calendar and store the **pending** proof opaquely.
  There is deliberately no proof parser: the serialization belongs to the calendar, and a
  partial re-implementation would invent "malformed" verdicts about bytes waxseal does not
  own. `verify --anchors` prints the pending proof as a labelled note and leaves the exit
  code unchanged — an exit 2 on every healthy verify is how operators learn to ignore exit
  2. Completing the proof is `ots upgrade` / `ots verify` after Bitcoin confirmation, which
  is hours to days later; the library does not poll and does not pretend to. [Unverified]
  the public calendar pool URLs and the detached-`.ots` construction recipe carry that
  label in SPEC §18 and the docs until someone verifies them against
  `python-opentimestamps`.

- **Pinned-head verification (trust-on-first-use)** — `waxseal verify|report --pin
  STATEFILE`. The verifier keeps a `Checkpoint` it computed itself, in its own trust
  domain, and refuses a later history inconsistent with it: SSH `known_hosts` for an audit
  trail. First use is always labelled, never silent. The pin advances only when the whole
  run passed, because advancing after a break would launder the break into the new
  baseline. A corrupted pin file is exit 1 and is **not** re-pinned — silently re-pinning
  would hand an attacker who can overwrite the pin a downgrade back to trust-on-first-use.
  A pin written by a newer waxseal is exit 2, unverifiable by name, not a break (the
  beads-v1.2.2 class). New `waxseal.domain.pinning` (pure) and `adapters.pinstore`
  (0600, via the single `os.replace` owner). SPEC §13.

- **Witness cross-check** — `--witness URL` (repeatable) on `anchor`, `verify` and
  `report`, with the new `WitnessReader` port, `adapters.witness.HTTPWitness`, pure
  `domain.witnessing`, and REMOTE.md §8 for the read-back contract. A pin catches a server
  that rewrites history for *this* client; it cannot catch one that shows two clients two
  different consistent histories. Fork consistency (Mazières & Shasha, SUNDR) says that is
  undetectable from inside one client's view, so the witness is the outside channel. An
  inconsistent witness is exit 1 and names the seq. An unreachable witness prints
  `unreachable — NOT checked` and does **not** change the exit code: it is an absence of
  coverage, and rule 5 forbids spelling that as a pass. The honest residual limits —
  colluding witnesses, an eclipsed client, the window after the last checkpoint, and a
  witness that lies by omission — are enumerated in SPEC §14 and the threat model rather
  than papered over.

- **Checkpoint frame v2 and the aggregate binding** — `Checkpoint` gains optional
  `agg_commit` / `agg_epoch`. With both absent, `checkpoint_frame` returns byte-identical
  v1 bytes, which is what keeps the frozen vectors frozen. With both present it emits the
  v2 frame, so a bytes-signing sink (a TSA, a calendar) witnesses the aggregate commitment
  *inside* what it signs — a JSON side-channel would have missed exactly the sinks that
  matter. The commitment is a hash, never the raw `mu`: SPEC §11 forbids persisting
  intermediate aggregate values because an attacker who truncates the trail could otherwise
  replay an older `.sealagg` and pass. `verify_anchored_aggregate` fails closed and reports
  `anchored_aggregate_epoch_mismatch` for precisely that replay. SPEC §15.

- **Scope statement** — `SCOPE_STATEMENT` / `SCOPE_ID` in `domain.report`, a `scope` object
  in the JSON report, a `## Scope` section in the markdown, and a trailing `scope:` line on
  every `verify` verdict. It states in fixed words that no output of this library asserts
  an obligation was met, that a payload is true, or that an unrecorded event did not
  happen — and that no output should be cited as if it did. Changing the wording means a
  new `SCOPE_ID`, the same append-only discipline the fingerprint registry uses. SPEC §16.

- `AggregateSource` port and `adapters.attest.AggregateReader`: reading an aggregate and
  sealing with one are different privileges, so `waxseal anchor` can now bind the aggregate
  commitment into the checkpoint without ever holding the seal key. Before this, the CLI
  anchoring a sealed trail dropped the binding silently, which is an unlabelled fail-open
  and a rule 6 violation.

- `RecordingAnchorSink` and `AnchorRecord` / `read_anchor_records` in `adapters.anchors`:
  one tolerant reader for the `.anchors` sidecar, version-aware (an unknown `"v"` is
  unverifiable, not a crash), and the seam that keeps a third-party receipt next to the
  checkpoint it belongs to. An external sink that raises leaves the sidecar untouched —
  a record that exists must mean a publication that happened.

- **Threat model** (`docs/security/threat-model{,.vi}.md`) and **external-time anchoring
  guide** (`docs/anchoring-external-time{,.vi}.md`). The threat model argues, rather than
  asserts, why tamper-*proof* is unreachable for pure software on storage the attacker can
  write: every local byte is rewritable, and the only thing software can do is make the
  rewrite *visible* against a copy outside that attacker's reach. It gives the
  detectable-vs-impossible matrix for a Byzantine chain server, the attacker-privilege
  table for forward-secure sealing, why chain integrity is not trail completeness, and how
  to cite waxseal output honestly. The anchoring guide carries the `openssl ts` delegation
  recipe, the OTS upgrade path, and how to write an `AnchorSink` for another chain
  (EVM, Hyperledger, private).

- OpenClaw integration (`waxseal.sources.openclaw` + `waxseal.integrations.openclaw`,
  `waxseal install openclaw`): pages OpenClaw's own audit ledger
  (`openclaw audit --json`) into a waxseal chain. An exporter, not a hook — OpenClaw
  already records tool actions off the hot path, but prunes them (30-day expiry,
  100,000-row cap) and hashes no row, and its docs say so: "It is not a lossless
  compliance archive; if you need one, use an external system". Runs from cron; nothing
  executes on the agent's path (OpenClaw issue #105453 objects to that) and one read path
  covers every runtime (issue #115342's own argument).

  Idempotent: the resume point is the highest ledger `sequence` already on the chain, read
  from the chain rather than a cursor file that could disagree with it. The export is
  newest-first, so the ingest reverses it and appends ascending. A hole in `sequence`
  becomes its own entry (`application/vnd.waxseal.openclaw-ingest-gap+json`) labelled
  `prune_or_drop` — pruning and a dropped write are indistinguishable from outside, so the
  gap names the range, never a cause it cannot establish, and never tampering. A hole left
  by waxseal's own page cap is labelled `page_cap` instead. With `--kind` set, gap
  detection reports `None`, not `()`: absent sequences are then the filter working as
  asked, and unmeasured is not zero.

- AI decision log layer. `DecisionRecord` (`waxseal.domain.decision`) is a decision-shaped
  payload — system id, model name/version/digest, outcome, rationale, policy version,
  confidence, human-oversight mode — with `record_decision`/`iter_decisions`/`commit_input`
  in `waxseal.sources.decisions`. `commit_input` hashes the input **after** redaction, so
  the commitment cannot act as a guess-confirmation oracle for the secrets redaction just
  removed; it refuses a redactor on `bytes` rather than silently claiming to have redacted
  them. `human_oversight=None` means *not recorded* and is counted apart from
  `mode="automated"` everywhere — collapsing them would report an absence of evidence as
  evidence. Optional fields serialize as explicit `null` rather than being omitted, for
  the same reason. `from_payload` ignores unknown extra keys: the beads-v1.2.2 failure
  class applies to payloads too.

- Proof bundles (`waxseal.domain.export`): `build_proof_bundle`/`verify_proof_bundle` plus
  `waxseal export-proof <trail> <seq>` and `waxseal verify-proof <bundle>`. One entry, its
  payload and its RFC 6962 membership path, checkable offline with no trail present — so
  answering a question about one subject does not disclose every other decision. The
  verifier never raises on hostile input and fails closed; an unknown fingerprint makes the
  bundle *unverifiable*, still membership-checked, and never *tampered*. A bundle whose
  format cannot be parsed is refused as unreadable, which is explicitly not a tampering
  verdict.

- Auditor report (`waxseal.domain.report`): `waxseal report <trail> [--json] [--anchors]`,
  exit codes mirroring `verify`. Chain verdict, `dropped_writes` with its source, inventory
  by payload type and schema fingerprint, decisions by type and oversight mode, and each
  sidecar check. A check that was not run prints as *not checked*, never as a pass —
  `CheckSummary(ok=True, reason="no_anchors_recorded")` says an absence of anchors is an
  absence of coverage, not coverage.

- Banking PoC (`examples/banking-poc/`, stdlib-only, not imported by the library): a
  runnable AML-screening simulation with an animated data-flow walkthrough, and a tamper
  walkthrough of eight scenarios that asserts its own expected exit codes and fails the run
  if any scenario stops behaving as documented. Includes the two scenarios where plain
  chain verification correctly reports intact (whole-trail rewrite, tail truncation) and
  the one whose correct answer is exit 2, not tampering. Covered by
  `tests/test_examples_banking_poc.py`, including a falsifiability test that a mislabelled
  scenario fails the run. Bilingual walkthrough in `README.md` / `README.vi.md`.

- Bilingual documentation: `docs/architecture/banking-deployment{,.vi}.md` (four trust
  domains, separation of duties, exit codes as the operational interface, retention/DR),
  `docs/compliance/mapping{,.vi}.md` (EU AI Act Art. 12/19/26(6) and Annex III 5(b),
  NIST AI RMF subcategories, the DORA RTS Art. 12 logging requirements, model-risk
  guidance, SOC 2, and the Vietnam digital-asset pilot — every clause either quoted from a
  retrieved source listed in the document or labelled unverified, with a gap analysis of
  what waxseal does not do), and `docs/paper{,.vi}/outline.md`.

- **`waxseal receipt <trail> --out DIR [--seq N]`** — extracts each stored anchor receipt
  (`.tsr` for RFC 3161, `.ots` for OpenTimestamps) together with the checkpoint frame it
  attests (`.frame`) into an operator-named directory, so `openssl ts -verify` and
  `ots upgrade`/`ots verify` can consume them without hand-written Python. Exit 0 = wrote
  at least one receipt; a sidecar with nothing matching is exit 2 with a label (absence is
  not success and not tampering); a missing trail/sidecar is exit 3 and creates nothing.

- **`waxseal consistency <trail> --old-seq N --old-root HEX`** — wires the RFC 9162
  §2.1.4 consistency-proof primitives (`consistency_proof`/`verify_consistency`, public
  since 0.1.2 but until now consumed by nothing in `src/`) into a read-only command:
  prove the current head extends the earlier state printed by `waxseal checkpoint`.
  Exit 1 prints what diverged as split-view *evidence*, never a repair; malformed input
  and beyond-head seqs are screened to exit 2 first so a typo cannot read as INCONSISTENT.

- **Anchor records may carry the RFC 3161 request nonce** — optional, additive, stored as
  a decimal string, no record-version bump. `Rfc3161AnchorSink` returns
  `SinkReceipt(receipt, nonce)` (a domain type; the `AnchorSink` port's return is now
  honestly `str | SinkReceipt | None`), `RecordingAnchorSink` files it, and
  `verify --anchors` re-checks it — a token replayed from a *different* request over the
  same imprint is now caught at re-verify, not only at anchor time. Records without the
  field keep verifying exactly as before: absence is skipped, never a mismatch.

- **Receipts are no longer silently lost by the library API.** `AuditLog` auto-wraps a
  path-backed `anchor_sink` in `RecordingAnchorSink`, so the README's own
  `AuditLog.open(..., anchor_sink=Rfc3161AnchorSink(url), anchor_every=100)` pattern now
  files every receipt in `<trail>.anchors` instead of discarding the return value.
  Already-recording sinks and `FileAnchorSink` are not double-wrapped; path-less backends
  (memory, remote) are untouched.

- **Golden vectors for the v2 frames** — `tests/vectors/checkpoint.json` (write-once from
  birth) pins `waxseal-checkpoint-v2`, `waxseal-aggcommit-v1`, and the
  no-binding-emits-byte-identical-v1-frame guarantee, cross-checked by
  `tools/gen_checkpoint_vectors.py`, which implements SPEC §2/§6/§15 prose directly and
  imports no waxseal code. Until now these hashed layouts were defined only by the code
  that produced them.

- `tests/architecture/test_layers.py` — no module outside `log.py` may name `._backend`,
  and `sources/`/`integrations/` may not import `waxseal.cli`; plus a dedicated
  `tests/domain/test_canonical.py` freezing `canonical_json`'s byte behavior.

### Changed

- `waxseal.domain.canonical.canonical_json` is now the single owner of payload canonical
  bytes, and `header_to_obj`/`header_from_obj` in `waxseal.domain.header` the single owner
  of header JSON, shared by the storage envelope and proof bundles. Two producers of the
  same bytes are two chances to disagree about them. Golden vectors unchanged, which is
  what makes the extraction safe to have done.

- The CLI reconfigures a console that genuinely cannot encode its output
  (`errors="backslashreplace"`) instead of dying with `UnicodeEncodeError` after the work
  is done. Same failure class as the 0.1.1 Windows install fix: losing a dash is cosmetic,
  losing the verdict is not. A console that can encode the output is left untouched.

- `docs/` was fully gitignored; the Track 4 deliverable subdirectories under it now are
  not. The owner's scratch notes there stay ignored.

- Coverage floor ratcheted from 90% to **100%** line and branch over `src/waxseal`. The
  two platform-conditional lock branches that no single OS can reach carry a pragma naming
  the CI that runs them; nothing else is excluded except `Protocol` bodies, whose shape
  `tests/architecture/test_ports.py` checks instead.

- `tools/gen_vectors.py` pins `newline="\n"`. On Windows it was emitting CRLF, so
  regenerating made a write-once file look edited — and "the vectors changed" is a signal
  that must only ever mean STOP.

- **An unreachable witness now exits 2, not 0.** Unreachable is *unverifiable-by-witness*
  — a script reading only the exit code could not previously distinguish "witnessed" from
  "no witness answered". `inconsistent` stays exit 1 and wins over 2, per the existing
  combine ordering.

- `sources/{decisions,files,openclaw}` read the chain through the public `log.entries()`
  facade instead of reaching into `log._backend` — the facade's own docstring forbade
  exactly that, and the ban is now enforced by an architecture test.

- `waxseal.sources.openclaw.ingest` holds a dedicated `<trail>.ingest.lock` spanning
  resume-read through append, so overlapping timer runs serialize instead of
  double-ingesting the same ledger rows — the module's idempotency claim is now true
  under concurrency, with a measured falsifiability receipt in the test.

- `.anchors` sidecar appends take the same file lock the trail itself uses. Windows
  `O_APPEND` is a non-atomic seek-then-write, and a torn concurrent append parsed as
  `ANCHOR BROKEN: malformed_anchor` (exit 1) — a concurrency accident wearing tampering's
  exit code. Falsifiability receipt: with the lock removed, 6 of 6 runs lost or tore
  records.

- Pin timestamps are injectable (`now_fn`) per the constitution's rule 8; the CLI default
  is unchanged. Pin-advance comments now state the spec'd rule (exit 2 advances because
  unverifiable ≠ tampered; only exit 1 freezes) instead of the stale "clean verdict only".

- `waxseal install <target> --home X` prints a labelled `note:` when the target installs
  nothing to a home directory (langchain, crewai, openai-agents, openclaw) instead of
  silently ignoring the flag.

- `SinkReceipt` moved from `adapters/anchors.py` to `domain/checkpoint.py` (re-imported
  where it was) so the `AnchorSink` port can name its real return type without ports
  importing adapters.

- `CLAUDE.md` (owner-approved amendment): the layer DAG now declares `sources/` and
  `integrations/` with their import rules, the CLI contract lists every shipped command
  with the pin/anchor write carve-outs, and the coverage floor reads 100 to match the
  ratcheted `fail_under`.

### Fixed

- `report --anchors` dropped every caveat that `verify --anchors` printed. A pending
  OpenTimestamps proof and an unchecked aggregate binding both rendered as
  `Anchors: ok (1 checked)` — coverage the report did not have. The notes now live on
  `CheckSummary.notes` rather than on the CLI's printed line, so both commands say the same
  thing and the JSON report carries them as data. `report` is the artifact an auditor still
  has six months later; a caveat only `verify` prints is a caveat that never reaches them.

- `AuditLog.verify_anchored_aggregates` returned `ok=True, reason=None` over a sidecar
  holding records in a format it could not read, while `verify --anchors` reported
  `unreadable_record_version` for the same bytes. Two paths reading one sidecar now give
  one account of it.

- `waxseal anchor` exited 1 with nothing on stderr when the trail was empty or no sink was
  configured. Both reasons are nameable, and a bare non-zero exit is the one outcome an
  operator cannot act on.

- `Checkpoint` now refuses half an aggregate binding at construction instead of at framing.
  The anchor sinks serialize a checkpoint straight to JSON without ever calling
  `checkpoint_frame`, so the old guard let `{"agg_commit": "…", "agg_epoch": null}` — a
  commitment to no stated epoch — reach the wire and the sidecar.

- Nine places across `README{,.vi,.zh}.md`, `REMOTE.md`, `DESIGN.md` and two docs still
  said a dishonest chain server serves a forged rewrite "that no client-side check
  catches". That was true before this release and is now false: `--pin` catches a rewrite
  of history the verifier already confirmed, and `--witness` catches a split-view. The
  claim is narrowed to what chain verification alone cannot do, with the three cases that
  genuinely remain out of reach named (first contact, colluding witnesses, an eclipsed
  client). The same passages also framed RFC 3161 and OpenTimestamps as manual work to do
  with `waxseal head`; both are built-in sinks now. The tamper-*evident*-not-*proof*
  statement is unchanged and stays unchanged — no release makes it false.

- CI ran only `ubuntu-latest`, while `filelock.py`'s Windows lock branch carried
  `# pragma: no cover - exercised on Windows CI`. There was no Windows job: the pragma
  claimed a check nobody performed, which is the exact thing this project exists not to
  ship. The matrix is now `ubuntu-latest` × `windows-latest`, both pragmas name the job
  that actually runs them, and CI additionally runs the two independent vector
  cross-check scripts that CLAUDE.md requires and the workflow never invoked.

- `.gitignore` was still hiding `docs/security/` and `docs/anchoring-external-time*.md`
  under the blanket `docs/*` rule, so three READMEs linked documents that would never have
  been published. A new architecture test walks every relative link in the top-level
  markdown and fails if the target is missing *or* gitignored; deleting the un-ignore line
  reproduces the failure.

### Security

- `urllib_transport` now opens only `http` and `https`, raising `ValueError` before any
  request otherwise. It is the single choke point every network adapter funnels through,
  and urllib's default opener also speaks `file:` and `ftp:` — so a URL arriving from a
  config file, an environment variable or a CI setting made `--tsa-url file:///…` a local
  file read wearing a timestamp reply's clothes. The URL is data; the scheme is a
  capability. No other behaviour changes: an injected transport is untouched, and http/https
  still fail on connection rather than on the guard.

- **`urllib_transport` refuses HTTP redirects.** The stdlib default opener follows 3xx
  and re-sends every header — `Authorization: Bearer <WAXSEAL_API_KEY>` included — to
  whatever host `Location` names, even across an https→http downgrade (the
  curl CVE-2018-1000007 / requests CVE-2018-18074 class). Redirects are not part of the
  REMOTE.md wire contract, so a 3xx now surfaces as a plain non-2xx status every caller
  already rejects. One choke point covers all five network adapters.

- **The chain server's write credential no longer reaches witnesses.** Witness publish
  and read-back authenticate with the new `WAXSEAL_WITNESS_API_KEY`; `WAXSEAL_API_KEY`
  is never attached to a witness request. REMOTE.md §8 requires a witness to be a
  *different administrative authority* than the chain server — handing it the server's
  Bearer write token meant any witness could append forged entries as a trusted writer.
  No fallback between the two variables, by design.

## [0.1.2] - 2026-08-22


### Added

- `RemoteBackend`: an HTTP peer to JSONL/SQLite/S3 speaking a small wire contract
  (`REMOTE.md`) over an injected `Transport` (stdlib `urllib` by default, zero new
  runtime dependencies). `AuditLog.open("http://...")`/`"https://..."` dispatches to
  it automatically; the CLI accepts a URL target for `verify`, `tail`, `inspect`,
  `head`, and `checkpoint` (`anchor` is refused for a URL target — no local sidecar
  location to write to). Credentials are read only from `WAXSEAL_API_KEY`, never
  from argv or the URL itself. The server is a trusted writer, not a
  Byzantine-fault-tolerant peer — `REMOTE.md` states this as the wire contract's
  first normative fact, and independent head anchoring is the documented
  mitigation.
- Merkle consistency proofs (RFC 9162 §2.1.4): `consistency_proof`/
  `verify_consistency` in `domain/anchoring.py`, alongside the existing batch-root
  membership proofs — checking that a later chain head extends an earlier one
  without replaying the whole log.
- `Checkpoint(seq, entry_hash, root)` (`domain/checkpoint.py`) and `waxseal
  checkpoint`: a bytes-only snapshot an external anchor sink can witness.
- Automatic anchoring: `AuditLog(anchor_sink=..., anchor_every=N)` publishes a
  checkpoint every `N` entries, best-effort and outside the append critical
  section. `FileAnchorSink` (local `.anchors` sidecar) and `HTTPAnchorSink`
  (POSTs to an external service over the same `Transport`) both implement the new
  `AnchorSink` port. `waxseal anchor` and `waxseal verify --anchors` are new CLI
  commands.
- `fs-hmac-agg-sha256-v1`: an opt-in FssAgg-style aggregate attestation scheme
  (Ma-Tsudik) that folds every per-entry seal into one KEYED running accumulator
  (`.sealagg`, replace-only, latest value only), closing the gap where an
  untrusted keyfile alone cannot prove a truncated tail was never dropped.
- Drop-count completeness measurement: an optional `.drops` sidecar
  (`record_drops=True`) reports a measured minimum of dropped writes independent
  of the current process, surfaced by `verify`/`inspect` as `dropped_writes >= N`
  — never conflating "not measured" (`None`) with "measured zero" (`0`).
- `s3` and `postgres` optional extras in `pyproject.toml` (pull in a compatible
  injected client for callers who want one; waxseal itself still imports neither).

### Fixed

- `__init__.py`'s public-API docstring referenced a nonexistent
  `test_public_api.py`; corrected to `tests/architecture/test_invariants.py`.

## [0.1.1] - 2026-08-21

### Fixed

- Windows: `waxseal install` wrote hook/plugin shims with the locale codec
  (cp1252), which encoded the shims' em dashes as `0x97`; Python requires
  UTF-8 source, so the installed hermes plugin failed to import with a
  `SyntaxError`. Shims are now written and compared as UTF-8 with `\n`
  newlines on every platform.
- Windows: the Claude Code / Codex / Cursor hook scripts resolved the default
  trail location via `Path.home()`, which ignores `HOME` on Windows
  (`USERPROFILE` wins); a host launching the hook with `HOME` set stranded
  the trail in the wrong profile. `HOME` is now honored first.
- Repository: added `.gitattributes` (LF + `tests/vectors/** -text`) so
  `core.autocrlf=true` checkouts no longer rewrite the golden vector bytes
  and trip the write-once freeze guard with a false "vectors changed".

## [0.1.0] - 2026-08-21

### Added

- Envelope-based SHA-256 audit hash chain: only the fixed `EntryHeader` is chained,
  payloads are referenced by `payload_hash`.
- Automatic schema fingerprints (`hash_version`) with an append-only registry;
  unknown fingerprints report as unverifiable-by-name, never as tampered.
- Storage backends: JSONL, SQLite, in-memory, S3 (injected boto3 client),
  PostgreSQL (injected psycopg connection), each with fork-proof concurrent appends.
- Redact-before-hash: redaction runs before `payload_hash` is computed, so cleartext
  secrets never reach disk.
- Forward-secure sealing (key-evolving HMAC, stdlib only) and injected digital
  signatures via the `.attest` attestation sidecar.
- CLI: `waxseal verify` (exit 0/1/2), `tail`, `inspect`, `head`.
- Integrations for seven agent frameworks and coding tools: Claude Code, Codex CLI,
  Cursor, LangChain/LangGraph, CrewAI, OpenAI Agents SDK, hermes-agent.
- `dropped_writes` completeness reporting, separate from chain integrity
  (`None` = not measured, never conflated with `0`).
