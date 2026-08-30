# Paper outline — schema-evolution-safe tamper-evident decision logs for AI agents

*[Tiếng Việt](outline.vi.md)*

Working outline for a systems-security paper built on waxseal. No authors or affiliations
are recorded here; add them at submission time.

**Working title:** *Schema-Evolution-Safe, Tamper-Evident Decision Logs for AI Agents in
Financial Services*

**Alternative framings**, depending on which reviewer community the work is aimed at:

| Framing | Title direction | Best fit |
|---|---|---|
| Failure-class | *Unverifiable Is Not Tampered: Version Identity in Tamper-Evident Logs* | S&P/CCS workshops, DIMVA |
| Systems | *An Evidence Layer for AI Agents: Design and Evaluation* | ACSAC |
| Regulatory | *Verifiable Decision Records for Regulated AI Deployment* | FC / WTSC |

The failure-class framing is the strongest. The core contribution is not a new
cryptographic construction — it is the observation that a widely-repeated deployment bug
class (ordinal version identity + unknown version treated as an error) is **eliminable by
construction**, plus a system that does so and a measurement of what it costs.

---

## Claimed contributions

State these early and keep the paper honest to exactly these four:

1. **A failure class, named and characterised.** Two independent production incidents
   (§1) share one root cause: version identity is *ordinal and manual*, and an unrecognised
   version is treated as an error rather than as an absence of information. We show this
   collapses two distinct verdicts — *this record is wrong* and *I cannot check this
   record* — into one, and that the collapse is what turns a benign rollback into either a
   mass false alarm or a silently-disabled safety mechanism.
2. **A construction that makes the class unrepresentable.** Version identity as a
   *content-derived fingerprint* of the canonical field descriptor, so widening the hashed
   tuple cannot be done silently; combined with a three-valued verification outcome
   (intact / broken / unverifiable-by-name) surfaced all the way to the process exit code.
3. **An evidence layer for AI decision records**, including selective disclosure: a single
   decision plus a membership proof is checkable offline without the rest of the log, and
   without trusting the party that holds it.
4. **An evaluation** covering append/verify cost, the marginal cost of each defence
   (anchoring, forward-secure sealing), and an adversarial case study in which each attack
   class is mapped to the specific mechanism that detects it and the specific trust
   assumption that mechanism requires.

**Explicit non-contributions**, stated in the paper to prevent reviewer over-reading: no
new hash function, no new accumulator, no new proof system, no consensus protocol, no
claim of tamper-*proofing*, and no claim that any regulatory obligation is discharged.

---

## 1. Introduction

Open with the two incidents, because they carry the argument better than any threat model
does.

- **Incident A ("migration 060").** A production system widened the set of fields covered
  by a row hash without changing any version identifier. Every historical row then failed
  verification: the verifier recomputed old rows under the new tuple and, correctly by its
  own logic, found mismatches. The result was a mass false tampering alarm across the
  entire history.
- **Incident B (an issue-tracker tool, v1.2.2, 2026-08).** An accidental release migrated a
  schema from v53 to v65. The reverted binary treated the unknown-but-higher version as a
  fatal error. The only escape hatch was an environment variable that disabled the schema
  safety check entirely — turning a partial-information condition into a binary choice
  between "refuse to run" and "run with no safety at all".

Both are the same bug: **the verifier had no way to say "I cannot check this."** Incident A
answered *tampered* when the honest answer was *unverifiable*; Incident B answered *fatal
error* to the same condition. RFC 6962 §4.6 already tells us the right answer for
unrecognised types — treat them as opaque, not as errors — but the principle is stated for
wire formats and is not, in practice, carried into audit-log verifiers.

Then motivate the AI-agent setting: agent decisions are now the object of record-keeping
duties (EU AI Act Art. 12/19/26(6); DORA's RTS requires logs be protected against tampering
and deletion), the decision schema of a fast-moving agent system changes far more often
than a database schema, and the party operating the agent is usually also the party holding
its log — which is exactly the configuration in which an unforgeable, externally-anchored
record has value.

**Structure of the argument:** the schema churn rate of AI systems makes the failure class
*more* likely, and the evidentiary stakes make it *more* costly. That is why this
combination deserves a paper rather than a bug report.

---

## 2. Background and related work

Organise as four threads, and say plainly what each gives and what it leaves open.

**Hash-chained and forward-secure logging.** Schneier & Kelsey's forward-secure audit logs;
Bellare & Yee's forward-security definitions; Ma & Tsudik's FssAgg aggregate signatures.
*Gives*: detection of truncation and post-compromise rewriting. *Leaves open*: nothing about
schema identity — the field set being hashed is assumed fixed.

**Transparency logs.** Crosby & Wallach's history trees; RFC 6962 (Certificate
Transparency) membership and consistency proofs; RFC 9162 §2.1.4. *Gives*: the proof
machinery this work reuses directly for selective disclosure, plus the §4.6 unrecognised-
types principle this work generalises. *Leaves open*: CT assumes one well-known leaf
format; the schema-evolution problem does not arise there and so is not addressed.

**Content provenance.** C2PA and adjacent media-provenance work. *Gives*: the framing of a
verifiable claim about an artefact's history. *Leaves open*: designed for media assets, not
append-only decision streams, and does not address the verifier-cannot-check case.

**AI accountability and audit.** Model cards, datasheets, algorithmic auditing, and the
regulatory instruments themselves. *Gives*: the requirement. *Leaves open*: these describe
*what* should be recorded and almost never *how the record is made trustworthy against the
party that holds it* — the gap this work fills.

**Position statement for the related-work section:** every primitive used here is
standard. The contribution is the composition and, specifically, the identity and
outcome-space design that the primitives do not themselves supply.

---

## 3. Design

### 3.1 Envelope separation

The chain hashes only a fixed-shape `EntryHeader`
(`seq, ts, hash_version, payload_type, payload_hash, prev_hash`). The payload is arbitrary
bytes referenced solely by `payload_hash`. **Consequence: a payload schema change never
touches the chain.** This is what makes evolution safe in the common case, and it is worth
stating as a design rule rather than an implementation detail.

### 3.2 Version identity as a fingerprint

`hash_version = SHA-256(canonical descriptor)`, where the descriptor is the ordered field
names plus algorithm and encoding rule. Three properties to argue explicitly:

- **Non-forgeable by omission.** Widening the hashed tuple changes the descriptor, hence
  the fingerprint, automatically. Incident A becomes unrepresentable: there is no way to
  change the field set and keep the identifier.
- **Non-ordinal.** There is no "higher" or "lower" fingerprint, so no verifier can conclude
  "this is from the future, therefore fatal". Incident B's premise disappears.
- **Append-only registry.** A new field set is a new entry, never an edit. Old rows verify
  forever under their own fingerprint.

### 3.3 The three-valued outcome

Formalise: `verify` returns one of *intact*, *broken(seq, reason)*, *unverifiable(set of
fingerprints)*. The key soundness property is negative and should be stated as such:

> A verifier never recomputes a record under a field tuple it was not signed with.

Reporting a record intact on a hash it cannot reproduce is the one lie a tamper-evidence
mechanism must never tell; reporting it *tampered* is Incident A. Both are avoided only by
having a third outcome, and the outcome has to survive all the way to the exit code — an
API distinction that collapses at the process boundary is not deployed.

### 3.4 Canonical encoding

The original encoding, lp64v1: 8-byte big-endian length prefix per field, UTF-8 values,
an explicit NULL sentinel
distinct from the empty string, PAE-style framing with a domain-separating prefix and field
count. Argue length-prefixing over delimiters (no in-band ambiguity), and the NULL sentinel
as an instance of the paper's recurring theme: *absent* and *empty* are different claims,
and a canonical encoding that conflates them lets two different records hash identically.

**Then turn the example on itself — this is the strongest passage available.** That
sentinel is `b"\x00NULL\x00"`, which is *itself valid UTF-8*: it decodes to a six-character
string. So the one field value equal to that string encoded identically to *absent*. The
encoding chosen to keep "absent" and "empty" apart conflated "absent" and one specific
*present* value — the very failure the section argues against, in the illustration of the
argument. It was latent (no shipped call site could reach it) and it was still wrong, for
the reason the paper cares about: the encoding is offered as portable, and an independent
implementation written from the prose would have reproduced the ambiguity faithfully.

lp64 fixes it structurally: a type tag *inside* the length-prefixed region (`0x00` for
absent, `0x01` before a string's UTF-8 bytes), so the two differ in their first byte for
every possible input. Injectivity becomes unconditional — no side condition, no invariant
to maintain, no input to reject.

The upgrade is the section's real payload, and it belongs here rather than in §3.3: because
the encoding name is a component of the version descriptor, switching the default *changed
the fingerprint automatically*. There was no migration to write and no released identity to
redefine in place; a binary that predates the change reports the newer rows *unverifiable*,
not *tampered*. Say plainly what it did cost: lp64v1 was removed rather than carried, so
trails written under it are unverifiable by any current build — a price payable only
because none existed outside development, and recorded as a one-off rather than left to
be mistaken for precedent. The schema-evolution mechanism the paper proposes turned
out to be what let the artifact repair its own canonical encoding without a migration. A
design that can safely fix the layer beneath itself is the most convincing evidence that
the design is load-bearing rather than decorative.

### 3.5 Redact-before-hash

Redaction runs before `payload_hash` is computed, so a secret never reaches disk. State the
consequence honestly: a redaction miss is unrecoverable — the cleartext is what would have
been committed. Ordering is the mitigation, not an optional pass.

### 3.6 Decision records and commitments

The `DecisionRecord` field set and its rationale (system identity, model
name/version/digest, outcome, rationale, policy version, confidence, human-oversight mode).
Two design points worth a paragraph each:

- The **input commitment is computed over the redacted input**. A commitment over cleartext
  would let anyone holding the log confirm a guess at a secret by recomputing the hash —
  the log would become a guess-confirmation oracle for the very secrets redaction removed.
- **Unrecorded oversight is a distinct value from automated oversight.** Collapsing them
  reports an absence of evidence as evidence. This is the same three-valued discipline as
  §3.3, applied to a data field, and the paper should draw that line explicitly: it appears
  again in `dropped_writes` (§5.3).

### 3.7 Selective disclosure

A proof bundle = one entry header + payload + membership path + batch root. Verifiable
offline against an independently published root. Argue the disclosure-minimisation
property: answering a question about one subject does not require handing over decisions
about every other subject.

---

## 4. Implementation

Brief. A layered architecture (pure domain / protocol ports / adapters / thin CLI) with the
layering enforced by tests rather than convention; zero runtime dependencies; multiple
backends (file, SQLite, Postgres, S3, remote HTTP) each enforcing read-tail-plus-append as
one critical section by a mechanism native to that store.

Two items deserve more than a mention because they are where the design meets reality:

- **The critical section.** Concurrent writers must never both extend the same `prev_hash`.
  A prior production system shipped exactly this fork bug via a web-server thread pool. The
  concurrency test carries a **falsifiability receipt**: documented evidence that it fails
  when the lock is removed. A concurrency test that has never been shown to fail is not
  evidence of anything.
- **Cross-implementation vectors.** Golden test vectors are write-once and are cross-checked
  by an independent script implementing the specification prose directly, rather than by
  importing the library — otherwise the vectors test the implementation against itself.

---

## 5. Security analysis

### 5.1 Threat model

Adversary tiers, stated so the claims stay bounded:

| Tier | Capability | What still holds |
|---|---|---|
| T1 | read the log | confidentiality of redacted secrets; commitments are not reversible (but see §5.4) |
| T2 | append to the log | cannot forge history; forks are prevented by the critical section |
| T3 | rewrite the log arbitrarily | detected **only** via anchoring and forward-secure seals, and only if those live under another authority |
| T4 | rewrite the log **and** control the anchor destination or hold an early key epoch | **not detectable.** State this plainly |

**waxseal is tamper-evident, not tamper-proof.** The honest claim is that detection
survives T3 *given a separation assumption*, and fails at T4. A paper that does not say
where its guarantees stop invites a reviewer to find the boundary and disbelieve everything
else.

### 5.2 Attack-to-mechanism map

The evaluation case study (§6.3) walks eight concrete attacks. Each row states the attack,
the mechanism that catches it, and — critically — the trust assumption that mechanism
depends on. Whole-trail rewrite is caught by anchoring *only if the anchor domain is
separately administered*; tail truncation is caught by forward-secure seals *only if the
initial key is escrowed off the writing host*. These conditionals are the paper's most
useful contribution to a practitioner.

### 5.3 Integrity is not completeness

A write that never happened leaves no sequence gap and no broken link, so a completeness
failure is invisible to chain verification by construction. `dropped_writes` measures it
separately and reports a **measured minimum**, with `None` meaning *not measured* — never
zero. The drop sidecar itself can be lost, and a disk too broken to record a drop cannot
witness its own failure. This is the third appearance of the paper's recurring theme
(§3.3, §3.6), and the discussion should say so: the design discipline generalises to
*any* metric where absence of measurement could be mistaken for measurement of absence.

### 5.4 Limitations

- Commitments over low-entropy inputs are confirmable by enumeration; commitment is not
  encryption.
- A remote chain server is a *trusted writer*, not Byzantine-fault-tolerant: a dishonest
  server can serve a consistently-forged rewrite that chain verification alone does not
  detect. A pinned head and witness cross-check narrow this to a first-contact client,
  colluding witnesses, or an eclipsed client — they do not remove the trust.
- Timestamps are caller-asserted, not attested; attested time requires an external
  authority.
- Append-only storage is in tension with erasure rights; the mitigation (pseudonymous
  references only) is a constraint on the integrator, not a property of the system.

---

## 6. Evaluation

### 6.1 Cost

Append and verify throughput and latency across backends; the marginal cost of the
forward-secure seal per entry and of a Merkle checkpoint per *N* entries; verification
cost as a function of trail length, and the improvement from incremental verification via
consistency proofs from the last anchored checkpoint. Report distributions, not means —
audit-path tail latency is what an operator actually feels.

### 6.2 Proof bundle size

Bundle size versus batch size, and the disclosure-minimisation ratio (bytes disclosed for
one decision versus bytes in the full trail). The current implementation produces bundles
on the order of 1.7 KB for a batch of six; the interesting curve is logarithmic growth of
the path against linear growth of the trail.

### 6.3 Adversarial case study

The eight-scenario walkthrough from the reference deployment, run as an experiment rather
than a demo: each scenario's expected verdict is asserted, and the harness fails if any
scenario stops behaving as documented. Include the negative controls explicitly — the two
scenarios where plain chain verification *correctly* reports intact, and the scenario where
the correct answer is *unverifiable* rather than *tampered*. A table where every row says
"detected" is a table nobody should believe.

### 6.4 Schema evolution experiment

The measurement that speaks directly to the failure class. Write records under schema
version *A*, evolve to *B*, roll back the binary, and verify. Compare three verifier
designs on identical data:

| Verifier | Result on rolled-back data |
|---|---|
| Ordinal version, unknown = error | refuses to run (Incident B) |
| Recompute under current tuple | reports mass tampering (Incident A) |
| Fingerprint + three-valued outcome | reports intact rows intact, unknown rows unverifiable, exit code distinguishes both from tampering |

This is a small experiment and it is the paper's centrepiece. Everything else is
engineering around it.

---

## 7. Discussion: regulatory context

Short, and deliberately modest — this is a systems paper, not a legal one.

What an integrity layer can and cannot contribute to record-keeping obligations (EU AI Act
Art. 12/19/26(6); the DORA RTS requirement that logs be protected against tampering and
deletion and that logging-system failure be detectable; model-risk-management documentation
expectations). The honest framing: these instruments demand that records be *kept*, and
mostly do not specify that they be *unforgeable against the keeper*. Tamper-evidence is
therefore a stronger posture than most texts require — which is an argument for adopting
it, and an argument against claiming any text mandates it.

Also worth one paragraph: the compliance-artefact trap. A verified log of an ungoverned
system faithfully evidences ungoverned decisions. Integrity is a precondition for
accountability, never a substitute for it.

---

## 8. Limitations and future work

- Trusted time: integrating RFC 3161 timestamping so `ts` becomes attested rather than
  asserted.
- Byzantine chain servers: what a client-side check could detect against a dishonest
  server, and what provably cannot be.
- Privacy-preserving decision logs: whether zero-knowledge membership proofs can remove the
  disclosure that a proof bundle still entails.
- Erasure under append-only: crypto-shredding of payloads while preserving chain integrity,
  and whether the resulting evidence is still worth anything.
- Cross-organisation chains: mutual anchoring between counterparties as a substitute for a
  trusted third party.

---

## Venue candidates

| Venue | Fit | Note |
|---|---|---|
| **ACSAC** | strong | applied-security systems with a deployment story; the case study fits its style |
| **DIMVA** | strong | failure-class framing and detection are squarely in scope |
| **FC — WTSC workshop** | good | financial-services framing; transparency-log lineage is familiar to that audience |
| **IEEE S&P / CCS workshops** (SafeThings, AISec) | good | shortest path if the AI-accountability angle leads |
| **USENIX Security** | stretch | would need a substantially stronger novelty claim than "composition plus identity design" |

**Artefact evaluation.** The implementation is MIT-licensed, dependency-free, and ships
golden vectors plus a runnable adversarial case study — aim for the artefact badge at
whichever venue offers one, and cite the artefact rather than restating its output in the
paper.

---

## Reproducibility checklist

- [ ] All experiments run from the public repository at a tagged commit
- [ ] Synthetic data only; the case study contains no real customer, institution, or model
- [ ] Golden vectors cross-checked by an independent implementation of the spec prose
- [ ] Benchmark harness reports distributions, hardware, and backend versions
- [ ] The schema-evolution experiment (§6.4) is scripted end to end, including the two
      failing baseline verifiers
- [ ] Every regulatory citation verified against a primary source, or labelled unverified
