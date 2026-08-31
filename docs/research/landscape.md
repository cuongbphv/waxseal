# waxseal in its landscape

Three projects come up when somebody searches for what waxseal does, or for what
waxseal is *called*. This document records what each one is, where the real
differences sit, and what was decided about each. It is positioning, not a
scorecard. A factual difference between two designs is not a verdict on anyone's
competence.

**How the facts below were checked.** Repository metadata, ChainProof's format
spec and source, and the two README greps were re-checked directly on
2026-08-31 with `gh api` against the public GitHub API, rather than carried over
from the earlier survey of the same day recorded in
[docs/plans/waxseal-0.1.5-contract.md](../plans/waxseal-0.1.5-contract.md)
§ Workstream G. Anything not checked that way carries a label. Star counts move;
they are given with the date of the reading and nothing here rests on them.

---

## 1. vajramatt/chainproof — the closest structural relative

Go, MIT, repository created 2026-08-16, 0 stars (read 2026-08-31). Its own
description is "Local, open-source provenance for any AI agent": a local
provenance ledger with a cockpit TUI and a web explorer, over a local SQLite
file.

The chain structure is the classic one, and it is the same one waxseal uses.
`spec/provenance-v1.md` at HEAD specifies SHA-256 over canonical UTF-8 JSON, a
first `previous_hash` of 64 zeros, zero-based contiguous sequence numbers, and a
verifier that must check genesis, contiguity, the prev-hash links, and every
event hash. That spec is also candid about what a chain does and does not buy,
in terms this repository has no argument with:

> "A valid chain establishes continuity of the recorded bytes. It does not
> establish that the report was truthful or complete."

Three differences from waxseal are substantive rather than cosmetic.

**The hashed event includes the nested payload.** ChainProof's hashed event is
one JSON object of twelve fields, and field 10 is `payload` — an arbitrary JSON
value, hashed in place along with `artifacts` and `extensions`. So the bytes the
chain commits to move whenever the payload's shape moves. waxseal splits those
apart on purpose: the chain hashes only the `EntryHeader`, and the payload
enters it as a single `payload_hash`, which is why a payload schema change never
touches the chain (SPEC.md § 2, CLAUDE.md "Envelope-based chain"). The canonical
form differs too, and the difference is in the side conditions. ChainProof
canonicalises JSON — recursive key sorting, compact output — and states
"Undefined values are rejected", a condition an implementation has to keep
holding. waxseal's lp64 encoding tags each field (`0x00` absent, `0x01` + UTF-8
for a string) under an 8-byte length prefix, so injectivity holds
unconditionally and there is no input class to reject. Hashing a JSON
serialisation is the practice CLAUDE.md rules out for waxseal ("never hash a
serialization you do not control"); that is a constraint on this library, not a
finding about theirs.

**`schema_version` is the ordinal string `1`.** It is field 1 of the hashed
event, typed as a plain string in `internal/proof/types.go`, with no fingerprint
over the field set. This is precisely the version identity waxseal exists to
remove. A hand-written ordinal does not change when the hashed field set
changes, which is how "migration 060" turned a widened field set into a mass
false tampering alarm, and how beads v1.2.2 turned an unrecognised ordinal into
a fatal error. waxseal's `hash_version` is the SHA-256 of the canonical version
descriptor, so widening the tuple changes the identity whether or not anyone
remembers to.

**No external anchoring, seal, witness, or pinned head in v1.** A grep across
all 29 `.go` and `.md` files at HEAD for `rfc 3161`, `tsa`, `opentimestamp`,
`witness`, `forward-secure`, `fssagg`, and `pin` returned one hit, and it is
prose describing the `observed` collection mode ("ChainProof witnessed it
directly"), not a witness protocol. Everything in
[docs/security/threat-model.md](../security/threat-model.md) § 1 about copies
held outside the attacker's reach therefore has no counterpart there yet.

### On the resemblance

The two designs look alike at first glance, and the plain explanation is
convergence: a hash chain over agent events is common knowledge, and both
projects reached for the standard construction on the same problem in the same
few weeks. Further convergence, not evidence of anything more: ChainProof ships
`integrations/openclaw`, waxseal ships `src/waxseal/sources/openclaw.py`, and
both use the word `imported` — though for different things. ChainProof's
`imported` is one of four collection modes labelling how a single event was
obtained; waxseal's imported trail is a whole foreign trail ingested read-only
for verification.

[Inference — basis: the public creation dates (ChainProof 2026-08-16, waxseal
0.1.0 released 2026-08-21) and the depth of the design differences above, which
are architectural rather than incidental] neither project copied the other.

**Decision (repository owner, 31/08/2026): adopt nothing from ChainProof.**
waxseal's own direction is the imported-trail feature landing in 0.1.5
(Workstream I): ingest and verify foreign jsonl/db trails on the self-hosted
server, stored read-only, never extended. Its origin is the owner's own need to
verify foreign trails centrally, and the in-repo precedent predates the survey:
`src/waxseal/sources/openclaw.py` is already an importer.

---

## 2. microsoft/agent-governance-toolkit — a different plane, not a competitor

Python, MIT, repository created 2026-03-02, 6,164 stars (read 2026-08-31; the
0.1.5 plan recorded 6,155 the same day, which is what a live counter does).
Policy enforcement, zero-trust identity, execution sandboxing, and reliability
engineering, with its README claiming coverage of 10/10 of the OWASP Agentic
Top 10, and marked "Public Preview -- production-quality public preview
releases. May have breaking changes before GA."

The difference is the layer, not the quality. AGT is a **control plane**: it
decides whether an action happens. [Unverified — README only, AGT not run and
its source not read] its README describes `govern()` wrapping a tool so that
every call is checked against a YAML policy, logged to an audit trail, and
refused with `GovernanceDenied` when the policy blocks it. waxseal is an
**evidence plane**: it proves the record of what happened has not changed since.
Blocking and proving are different jobs, and a deployment can reasonably want
both.

AGT's README describes its audit log as tamper-evident and lists an audit
specification (`docs/specs/AUDIT-COMPLIANCE-1.0.md`, naming Merkle audit,
compliance mapping, and a Decision BOM) among its documents.
[Unverified — README only, AGT's audit code not read] nothing here compares the
depth of the two audit mechanisms; that spec and the code under it have not been
read, and a comparison drawn from a README would be the kind of claim this
repository's own documentation rules out.

Its framing of the audit problem is worth quoting, because it is the same
question waxseal answers from the other side:

> "**3. Can you prove what happened?** Auditors and regulators need
> tamper-evident records of every decision: what policy was active, what the
> agent requested, and why it was allowed or denied."

**Decision (repository owner, 31/08/2026): build `integrations/agt.py` in
0.1.5** — waxseal as an audit sink behind AGT's governance decisions, following
the library-style pattern of the existing integrations, adding no dependency.
See § Workstream H of the 0.1.5 plan.

---

## 3. degenlegion-com/waxseal-sdk — the same name, a different product

TypeScript, MIT, repository created 2026-06-22, 1 star (read 2026-08-31), with a
service at waxseal.id. It is an Ed25519 identity product: "One Ed25519 keypair.
One 64-character fingerprint. Permanent on-chain record", published as
`@waxseal/verify` and `@waxseal/mcp` on npm, plus an MCP signing and verifying
server for Claude, Cursor, and Windsurf.

It is not a functional competitor, and the check is short: a grep of its README
for `hash chain`, `hash-chain`, `audit trail`, `audit log`, and `tamper`
returned zero hits (read 2026-08-31). The two projects answer different
questions. Theirs is "who is this agent, and did they sign this". waxseal's is
"what happened, and is the record of it intact".

The risk here is name collision, not product overlap. Their README presents
waxseal.id as their own service, and they publish under the npm scope
`@waxseal`: `@waxseal/verify` and `@waxseal/mcp` both answer `200` from the npm
registry, and waxseal.id answers `200` (checked 2026-08-31; a served response is
not proof of who owns either, and no registrar or trademark record was
consulted). They were public first, 2026-06-22 against waxseal's 0.1.0 on
2026-08-21 (CHANGELOG.md). This project holds the PyPI name `waxseal`, at 0.1.4.
Both aim at the AI agent space, so the same name search reaches either one.

Whether to rename or to file a trademark is the repository owner's decision
alone. This document does not propose either, and takes no position. It also
does not use or integrate their service.

### Disambiguation

| You are looking for | You want | Not this |
|---|---|---|
| An audit hash chain: append-only trail, tamper-evident verification, anchoring, ternary verdicts | `waxseal` on **PyPI** (Python), this repository | — |
| Cryptographic identity: Ed25519 keypair, fingerprint, on-chain profile, MCP signing server | **WaxSeal SDK** on npm (`@waxseal/verify`, `@waxseal/mcp`), waxseal.id | this repository |

The same notice, in one sentence, is in [README.md](../../README.md) under
Install, where somebody who installed the wrong package will see it.

---

## What was adopted, in one place

| From | Adopted | Where |
|---|---|---|
| ChainProof | Nothing (owner decision, 31/08/2026) | — |
| ChainProof's existence | No change of direction. The imported-trail feature it might look like a response to is independently sourced: the owner's need, precedent `sources/openclaw.py` | Workstream I, 0.1.5 |
| AGT | Integration as an audit sink, no dependency added | `integrations/agt.py`, Workstream H, 0.1.5 |
| WaxSeal SDK (npm) | Nothing. Disambiguation only | this document, README Install note |

Hedera's public design is treated separately, in
[hedera-lessons.md](hedera-lessons.md).
