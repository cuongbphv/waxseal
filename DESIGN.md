# waxseal design rationale

Why waxseal's algorithms look the way they do, grounded in the academic and
standards literature. Sources were verified against primary documents on
2026-08-21; load-bearing quotes are verbatim.

## 1. Hash function: SHA-256 (with agility built in)

**Choice: SHA-256 as the default; the algorithm is part of the schema fingerprint
descriptor, so migrating to SHA-512/256 or SHA3-256 is a new fingerprint, not a
format change.**

- Cryptanalytic status: the best published collision attack on SHA-256 reaches
  **37 of 64 steps** (Zhang, Li, Gao, Wang, "Collision Attacks on SHA-256 up to 37
  Steps with Improved Trail Search", IACR ePrint 2026/232 - "the first such
  advancement in 12 years"); the best practical collision is 31 steps (Li, Liu, Wang,
  Dong, Sun, ASIACRYPT 2024, DOI 10.1007/978-981-96-0941-3_8), and 39-step results are
  semi-free-start only (Li, Liu, Wang, EUROCRYPT 2024, ePrint 2024/349). No collision,
  preimage, or second-preimage attack on full SHA-256 is publicly known.
- NIST position: "Currently there is no need to transition applications from SHA-2 to
  SHA-3" and "NIST encourages application and protocol designers to implement SHA-256
  at a minimum" (NIST Policy on Hash Functions, updated 2024-09-09). SP 800-131A Rev. 3
  (draft, Oct 2024) lists SHA-256 as **acceptable for all hash function applications**
  with no end date; SHA-1 and all 224-bit variants are deprecated through 2030 and
  disallowed after.
- Length extension: SHA-256's one structural weakness breaks secret-prefix MACs
  (H(key‖msg)) - not hash chains over public, length-prefixed, framed bytes, where the
  verifier recomputes every link from the complete known input. An "extended" hash is
  just the hash of a different byte string and fails verification. If waxseal ever
  adds a keyed integrity tag it will use HMAC-SHA-256, never a bare prefix hash.
- Practicalities: SHA-256 is the only candidate with near-universal CPU acceleration
  (Intel SHA-NI, ARMv8 CE), FIPS-validated implementations, stdlib presence in every
  language, and native interop with the transparency-log ecosystem (RFC 6962/9162) and
  TPM PCR-extend. BLAKE3 is faster on large inputs but audit entries are small and
  fsync dominates; SHA3-256 has no mainstream hardware acceleration.

## 2. Linear chain vs Merkle tree: linear now, a documented graduation path

**Choice: a linear chain is the literature-blessed structure for waxseal's use case -
an embedded log whose auditor reads the whole log anyway.**

Crosby & Wallach ("Efficient Data Structures for Tamper-Evident Logging", 18th USENIX
Security Symposium, 2009) state the boundary exactly:

> "Hash chaining schemes, as such, are only feasible with low event volumes or in
> situations where every auditor is already receiving every event."

`waxseal verify` is that situation: full-scan verification by a party holding the
log. Proof-size numbers from the same paper motivate the graduation criteria - in a log
of 80M events a history-tree membership proof is ~3 KB where a hash chain needs ~40M
intermediate hashes (~800 MB).

**Graduate to an RFC 6962/9162-style Merkle tree when any of these appear:**

1. A third party must verify one entry against a published head without downloading
   the log (inclusion proof: O(log n) vs O(n)).
2. You publish signed heads and verifiers must check head H₂ extends H₁ without
   replaying the log (consistency proof - "Merkle consistency proofs prove the
   append-only property of the tree", RFC 9162).
3. Selective disclosure or verifiable deletion is needed (Crosby-Wallach Merkle
   aggregation).

The modern idiom to adopt then is tile-based static logs + signed checkpoints
(Trillian -> Tessera, Let's Encrypt Sunlight / c2sp.org/static-ct-api,
c2sp.org/tlog-checkpoint), not a bespoke tree. A linear chain is exactly a Merkle
tree's leaf sequence: the tree can be retrofitted over existing entries without
changing stored records.

**Criteria 1 and 2 are now implemented, retrofitted over the same stored records
as promised above.** `domain/anchoring.py` computes RFC 6962 `batch_root` and
`membership_proof`/`verify_membership` (criterion 1), plus RFC 9162 §2.1.4
`consistency_proof`/`verify_consistency` (criterion 2 - checking that a later head
extends an earlier one without replaying the log). `domain/checkpoint.py`'s
`Checkpoint(seq, entry_hash, root)` is the bytes-only object an external anchor
witnesses (SPEC §9/§10). Criterion 3 (selective disclosure, verifiable deletion)
remains out of scope.

## 3. Whole-suffix rewrite: anchoring, not more chain

A hash chain is tamper-*evident*, not tamper-*proof*: an attacker with write access
can rewrite the entire suffix after any point. No internal structure fixes this - only
**externalizing the head** does (this is the "split view" problem transparency logs
solve with witness cosigning: "Log clients can verify a quorum of cosignatures to
prevent split-view attacks", c2sp.org/tlog-cosignature).

Minimal-infrastructure ladder for waxseal users, lowest cost first:

1. `waxseal anchor trail.jsonl --ots-calendar <url>` publishes to **OpenTimestamps**
   (free, no registration, verifiable offline against Bitcoin headers: "A timestamp
   proves that some data existed prior to some point in time" - opentimestamps.org);
   `--tsa-url <url>` publishes to an **RFC 3161** TSA ("assertions of proof that a
   datum existed before a particular time"). `waxseal head` still prints
   `{"seq": N, "entry_hash": "..."}` for anyone who would rather commit it to a pushed
   git repo or email it to a third party.
2. Diversify trust roots: any one anchor bounds a suffix rewrite to the window since
   the last anchor; multiple independent anchors force the attacker to compromise all
   of them. `--witness <url>` (repeatable) is the same idea aimed at split-view rather
   than rewrite.
3. Prevention-grade guarantees (Sigsum-style quorums, a witness network operated as
   infrastructure) remain out of scope for an embedded library. What 0.1.3 adds is the
   client half - a pinned head and witness cross-check - not the network.

The residual risk to state plainly: entries written since the last anchor are
rewritable by a write-capable attacker. Anchor frequency is the knob.

**Rung 1 is also automatable, not just a one-shot command.** `AuditLog(anchor_sink=..., anchor_every=N)` publishes a `Checkpoint`
(a batch root, not just the bare tip) to an `AnchorSink` every `N` entries,
best-effort and outside the append critical section - a failed anchor never blocks
a write, it only counts against `anchor_failures` (SPEC §9). `FileAnchorSink` is the
local baseline (a sidecar `waxseal verify --anchors` checks trail history against
between real external events); `HTTPAnchorSink` (§10 below) is a real external
witness. Neither replaces rung 1's own advice: the sink itself should point at
infrastructure the log's own writer does not control.

## 4. Canonicalization: sign the bytes (lp64), not the interpretation

**Choice: waxseal hashes a length-prefixed binary framing (lp64 + PAE-style
prefix) of the header - never a re-serialization of parsed data.**

- The failure class is real: XML Signature wrapping broke 11 of 14 major SAML
  frameworks (Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be",
  USENIX Security 2012) - verify one interpretation, act on another.
- Practitioner consensus: "Canonicalization is a quagnet … it's OK to sign the exact
  byte sequence" (Latacora, "How (not) to sign a JSON object", 2019).
- RFC 8785 JCS is workable but constrained: it requires the I-JSON subset, IEEE-754
  representable numbers ("JSON number data MUST be expressible as IEEE 754
  double-precision values"), performs no Unicode normalization, and its own security
  considerations require parse + validate + verify in strict order. lp64 avoids that
  entire surface and ports to any language with 8 bytes of big-endian length.
- Protobuf is disqualified by its own documentation, titled "Proto Serialization Is
  Not Canonical": "protobuf serialization is not (and cannot be) canonical".
- Certificate Transparency (RFC 6962) hashes TLS-presentation-language structs -
  fixed-order, length-prefixed - which is the same shape as lp64; waxseal's PAE
  prefix (`waxseal-v1` + field count) adds DSSE/PASETO-style domain separation
  against format confusion.

**Revision (0.1.4): lp64 replaced lp64v1 outright.** The original encoding spelled an
absent field as a six-byte sentinel, `b"\x00NULL\x00"`. That sentinel is itself valid
UTF-8, so the one string equal to it encoded identically to "absent": injectivity held
only under an unstated side condition ("no field carries exactly this string"). No
shipped call site could reach it - every header field is a non-null, non-adversarial
string - so the defect was latent, not exploitable. It mattered anyway, because the
encoding is offered as portable and invites independent implementations, which would have
reproduced the same ambiguity. lp64 puts a type tag *inside* the length-prefixed region
(`0x00` for absent, `0x01` before a string's UTF-8), so the two differ in their first byte
for every possible input and injectivity is unconditional - no invariant to maintain, no
input to reject.

The interesting part is what the replacement cost, which is nothing structural. Because
the encoding name is a component of the version descriptor (§3 above), swapping it moved
every fingerprint automatically: there was no migration to write and no released identity
to redefine in place. What it did cost is compatibility - a trail written by 0.1.3 is
*unverifiable* under 0.1.4, reported by name and never as tampering. That was an
acceptable price only because it was paid before any such trail existed outside
development, and the decision is recorded as a one-off in both `CLAUDE.md` and the
CHANGELOG rather than left for someone to rediscover as precedent. Carrying two encodings
forever was the alternative, and it was rejected: a second code path that no writer uses
is a second thing to keep correct, and the doctrine already covers the case it would have
served - a fingerprint no current encoder implements is unverifiable by name, which is a
better answer than a legacy branch nobody exercises.

## 5. Positioning in the AI-agent accountability literature

Activity logging is one of the three visibility measures for AI agents identified in
the peer-reviewed anchor work (Chan et al., "Visibility into AI Agents", ACM FAccT
2024, DOI 10.1145/3630106.3658948), alongside agent identifiers and real-time
monitoring; attribution is a core function of agent infrastructure (Chan et al.,
"Infrastructure for AI Agents", TMLR 2025, arXiv:2501.10114). waxseal supplies the
integrity substrate for those measures: attributable, append-only, tamper-evident
activity logs with schema-evolution safety. For emitting telemetry alongside the
chain, the OpenTelemetry GenAI semantic conventions (`invoke_agent`, `execute_tool`
spans) are the industry pairing.

## 6. Forward integrity, key evolution, and the truncation attack

A keyless hash chain is recomputable by anyone with write access - that is why
section 3 exists. The classic cryptographic answer is **key evolution**: MAC each
entry under an epoch key `A_j`, derive `A_{j+1} = H(A_j)`, and securely delete `A_j`,
so a compromise at time *t* cannot forge anything earlier:

> "We describe a computationally cheap method for making all log entries generated
> prior to the logging machine's compromise impossible for the attacker to read, and
> also impossible to undetectably modify or destroy."
> - Schneier & Kelsey, ACM TISSEC 2(2), 1999

> "An attacker breaking in gets the current key. The desired security property is that
> given the current key Ki it is still not possible to forge MACs relative to any of
> the previous keys K1, …, Ki−1." - Bellare & Yee (CT-RSA 2003; ePrint 2001/035)

Two facts from the literature shape waxseal's position:

- **Truncation is the residual hole even with key evolution.** "The truncation attack
  represents a real danger … there is no single authentication tag protecting the
  integrity of the entire log file" (Ma & Tsudik, "A New Approach to Secure Logging",
  ACM Trans. on Storage 5(1), 2009) - their FssAgg aggregate tag, and its fast
  successor QuickLog2 ("Faster Yet Safer", Hoang, Wu, Yuan, USENIX Security 2022),
  close it; so does external anchoring of `(seq, head hash)`, which waxseal
  already recommends (section 3). Total deletion ("the log never existed") is only
  detectable with an external commitment made at log creation.
- **Key evolution's guarantee depends on secure key deletion and synchronous
  commitment** - Schneier-Kelsey assume the machine "can irretrievably delete
  information held in short-term memory", and KennyLoggings (Paccagnella, Liao, Tian,
  Bates, ACM CCS 2020) showed every earlier system loses events still in memory
  buffers at compromise time unless integrity is committed "upon their occurrence".
  These are kernel/enclave-grade requirements.

**Decision for v1: no key evolution.** It demands key management, secure zeroization,
and often a trusted verifier - all contradicting the zero-dependency, embeddable goal,
and its truncation hole still needs anchoring anyway. waxseal covers the same
practical threats with checkpoint anchoring (rewrite AND truncation bounded by
anchor frequency, at near-zero cost). The fingerprint descriptor gives a keyed scheme
(HMAC per epoch, FssAgg-style aggregate) a clean home as a NEW fingerprint - a later
version added both (`fs-hmac-sha256-v1`, then the FssAgg aggregate below) as opt-in
attestation schemes, never by editing the chain's own header fingerprint; old rows
stay verifiable under their own descriptor.

## 7. The attestation layer: scheme choice and journald's lessons

**Ed25519 as the recommended injected signer.** FIPS 186-5 (Feb 2023) approves EdDSA
("FIPS 186-5 approves the use of EdDSA and specifies additional requirements") and
deterministic ECDSA (RFC 6979); classic randomized ECDSA's nonce is a documented
foot-gun at scale - Breitner & Heninger (Financial Cryptography 2019) computed
"hundreds of Bitcoin private keys and dozens of Ethereum, Ripple, SSH, and HTTPS
private keys" from biased nonces, and the 2013 Android SecureRandom bug leaked wallets
via repeated nonces. Ed25519 needs no per-signature randomness, uses 32/64-byte
keys/signatures, and is what the modern transparency ecosystem converged on (C2SP
signed notes: "Ed25519 signatures are generated according to RFC 8032"). waxseal
defines the signed byte string (the PAE-style seal frame) and stays algorithm-agile -
the signer is injected, `algorithm` names the scheme.

**Per-entry seals + head anchoring, instead of per-entry public-key signatures.**
CT/RFC 9162 signs tree heads, never individual entries; per-entry signatures alone
give no truncation protection (Ma-Tsudik: "there is no single authentication tag
protecting the integrity of the entire log file"). waxseal's split: cheap per-entry
forward-secure HMAC seals for fine-grained attribution, plus `waxseal anchor` external
anchoring as the O(1) checkpoint. Key IDs follow the DSSE rule - "MUST NOT be used
for security decisions; it may only be used to narrow the selection of possible keys".

**Three lessons from systemd-journald FSS** (Dörre & Ottenhues, "Security Analysis of
Forward Secure Log Sealing in Journald", ACNS 2025, ePrint 2023/867 - "one
vulnerability allows to forge arbitrary logs for past entries without the validation
tool noticing"), each mapped to a verifier check waxseal ships:

| journald CVE | Failure | waxseal check |
|---|---|---|
| CVE-2023-31439 | newer keys could seal older entries (one-directional check) | seal seq must equal its position, both directions -> `seal_sequence_mismatch` |
| CVE-2023-31438 | empty epochs left no evidence -> silent truncation | one epoch per entry; keyfile epoch is one-way, cannot roll back -> `keyfile_epoch_mismatch` |
| CVE-2023-31437 | reader consumed unauthenticated index structures | attestations cross-checked against hashes RECOMPUTED from the trail -> `attest_trail_mismatch` |

**Truncation defense without an aggregate tag:** an attacker who chops the tail of
trail + sidecar consistently cannot regress the keyfile - `A_{t'}` is not computable
from `A_t` (one-way evolution), so `epoch == len(attestations)` and
`derive(A_0, epoch) == stored key` fail. This covers the Ma-Tsudik truncation attack
as long as the keyfile itself is trusted; when it must not be, `fs-hmac-agg-sha256-v1`
(SPEC §11) folds every seal into one KEYED running accumulator,
`μ_i = HMAC(A_i, μ_{i-1} ‖ tag_i)` - keyed under the same one-way epoch key, so an
attacker who only holds public values (trail, sidecar, and even the final `μ`) cannot
refold it themselves, closing the "trust the keyfile" assumption the plain scheme
still carries. Only the latest `μ` is ever persisted (`.sealagg`, replace-only):
keeping every intermediate value would hand a truncating attacker exactly the
`μ_{t'-1}` they would need to splice a forged suffix onto.

**Verification semantics precedent**: unknown scheme/key is opaque, never tampering -
C2SP signed note ("Verifiers MUST ignore signatures from unknown keys"), RFC 6962
§4.6, RFC 9162. waxseal's three-way outcome (valid / invalid / unverifiable-by-name)
is that rule transplanted.

**Not adopted**: BLS aggregate signatures (still an IRTF draft, needs pairing
libraries - incompatible with zero dependencies); Ed25519 batch verification (2-2.5×
verifier-side gain but "cofactorless batch verification will exhibit flaky behavior" -
Chalkias, Garillot & Nikolaenko, SSR 2020 - and checkpoint signing keeps signature
volume small anyway).

**Honest zeroization limits**: CPython "does not clear memory … there is no way to
clear immutable structures such as bytes" (pyca/cryptography limitations); "securely
erased … is not easy to guarantee" (Dörre-Ottenhues, citing Gutmann 1996). waxseal's
keyfile is atomically replaced so only the current epoch key exists *in the file*;
memory copies are best-effort, stated plainly.

## 8. Known limitations (measured, not assumed)

- **Chain integrity ≠ trail completeness**: a write dropped before storage leaves no
  gap; waxseal reports `dropped_writes` separately, `None` = unmeasured.
- **Suffix rewrite and tail truncation** are detectable only up to the last external
  anchor (sections 3 and 6). Anchor frequency is the exposure window.
- **Post-compromise writes** carry no guarantee under any scheme (Schneier-Kelsey),
  and events not yet flushed at compromise time are lost unless committed
  synchronously in the write path (KennyLoggings) - out of scope for a userspace
  library, stated here so nobody assumes otherwise.

## 9. The integration observer contract

Every hook/callback integration under `integrations/` (Claude Code, Codex CLI, Cursor,
LangChain, CrewAI, OpenAI Agents SDK, hermes-agent) implements the same observer
contract - the OpenClaw integration is an audit-ledger exporter with no hook, and the
Microsoft AGT integration attaches as an `AuditSink` Protocol to a governance layer
that owns its own logging call, so nothing below applies to either -
derived from how each host actually treats hook failures - verified per host and
pinned to a version in each integration's README:

- **Never veto.** In every hook-based host, some signal from the hook is a control
  signal (exit code 2, a `permission`/`decision` JSON on stdout, a non-None return).
  The audit observer emits none of them: exit 0 always, stdout silent, return None.
  A broken audit disk degrading into a blocked tool call would make operators
  disable auditing - the beads escape-hatch lesson in another costume.
- **Label your own drops.** Hosts differ in how they treat a raising hook: LangChain
  and CrewAI swallow and log (silently, from the trail's perspective), the OpenAI
  Agents SDK propagates and can abort the run, CLI hosts show a notice. All three
  behaviors are wrong for an audit trail, so integrations never raise and never rely
  on the host: every failure path prints a labelled drop and counts it
  (`dropped_writes`) - chain integrity ≠ trail completeness, rule 5/6.
- **Dispatch before execution.** The dispatch entry is written in the pre-hook, so a
  tool call that kills the process (or never returns) is still on the chain. The
  result entry is a second, separate link.
- **Record actions, not the workspace.** Full file contents offered by hooks (e.g. a
  read-file event) are deliberately not stored; huge fields are clipped with a
  visible `…[truncated N chars]` marker, never silently.
- **Transcript vs trail, honestly.** The coding-tool hosts keep their own transcript
  files; a secret leaked there stays there - no hook may rewrite host files (verify
  reports, never repairs). The integration's promise is narrower and keepable: the
  waxseal trail itself never holds cleartext secrets (redact-before-hash), and any
  after-the-fact edit of that trail is detectable.

On redactor scope: the regex families and sensitive key names in
`adapters/redactors.py` are deliberately **non-normative** (SPEC §6 fixes only the
pipeline position: redact -> hash -> store). Patterns err toward matching within a
family but use exact key-name matching rather than substring rules - `tokenizer`
and `authors` must survive, because over-redaction destroys the audit value the
trail exists to provide, and a hash chain makes every redaction permanent.

## 10. Remote backend: CAS instead of a lock, and a trusted-writer server

**Choice: `RemoteBackend` is an HTTP peer to JSONL/SQLite/S3, not a client wrapping
one of them.** It speaks a small wire contract (REMOTE.md) over an injected
`Transport` - stdlib `urllib` by default - so the zero-dependency rule (section 4's
canonicalization discipline extends here too) holds for the client exactly as it
does for `S3Backend`'s injected boto3 client.

**Read-tail + append is still one critical section (CLAUDE.md rule 7) - enforced
server-side, not by a client-held lock.** A file lock or `BEGIN IMMEDIATE`
transaction assumes a single process (or a single database) owns the critical
section; a remote HTTP peer has no such shared primitive to hold across a network
round trip. The wire contract instead makes the server the lock: `POST /entries`
must be an atomic compare-and-swap on `(seq, prev_hash)` against the server's own
current head, answering `409` the instant two writers race for the same slot. The
client's job is only to retry: read the (now-current) head, rebuild the entry
against it, and re-`POST` - the same shape `S3Backend` already uses against
`IfNoneMatch`, capped at the same `_MAX_RACE_RETRIES = 32` so pathological
contention fails loudly instead of looping forever. Two writers never both
extend the same `prev_hash` - the fork this rule exists to prevent - because the
server's CAS check, not a client lock, is the single point that can see both
racers at once.

**Trust model: the server is a trusted writer, not a Byzantine-fault-tolerant
peer.** `verify_chain` runs entirely client-side against whatever the server
returns, so it still catches corruption, truncation, and reordering exactly as it
would for a local file - but a server that is itself dishonest can serve a
consistently-forged full rewrite that `verify_chain` alone cannot distinguish from
the truth, the same whole-suffix-rewrite gap section 3 describes for a local
attacker with write access. This is not a weaker promise made quietly: REMOTE.md
states it as the wire contract's first normative fact, and the mitigation is the
one this document already recommends - anchor the head independently
(`checkpoint_for` + an `AnchorSink` pointed at a service *other than* the chain
server, e.g. `HTTPAnchorSink` against a separate host). A pinned head and a
witness in a separate trust domain narrow it further: the first gives the client
a memory the server does not hold, the second an outside view that a split-view
attack has to fool as well. Neither promotes the server to untrusted-but-checked;
they relocate the trust to whoever holds the pin and operates the witnesses. A chain server and its
anchor witness colluding is out of scope for the same reason a compromised
machine and its own attestation keyfile colluding is (section 6): a witness that
shares the attacker's trust boundary was never a witness.

**Relationship to `FileAttestor`:** attestation sidecars are local-writer
constructs - one host, one keyfile, one epoch clock. A remote chain server is a
different trust boundary; sealing does not travel over the wire contract, and
multiple independent writers attesting against the same remote chain is
undocumented territory this version does not attempt (an `AttestationFailure`
would surface the disagreement loudly rather than silently pick a winner).

## 11. Tamper-evident vs tamper-proof: proof is only ever scoped

Sections 3 and 6 already say the load-bearing part: a hash chain is
tamper-*evident*, and a write-capable attacker can rewrite everything since the
last external reference point. The 0.1.5 release (Workstream J) adds mechanisms
that upgrade specific, named scopes from evidence to something an operator may
reasonably call proof - and fixes the vocabulary so the claim is never made
without its scope.

Two limits survive every mechanism, by construction rather than by budget:

1. **Write-time honesty.** The writer is trusted at the moment of writing; no
   hash prevents recording a lie or omitting an event - the scope statement
   (SPEC §16) exists to say this on every output. Tamper-proof ≠ truth-proof.
2. **The live tail.** Whatever has not yet been externalized - anchored,
   acknowledged, archived - is rewritable by a write-capable attacker.
   Mechanisms shrink this window; none closes it.

What buys scoped proof, and the scope each buys:

| Mechanism | Scope of the "proof" claim |
|---|---|
| finalized-ledger anchoring + bonded checkpoints (contract layer, Workstream F) | the anchored prefix: acknowledged history cannot be re-told without producing a slashable equivocation proof |
| WORM object storage for sealed segments (S3 Object Lock) | archived segments: the storage refuses the overwrite - prevention, not detection. Lock-mode semantics (COMPLIANCE vs GOVERNANCE) confirmed against AWS Object Lock documentation 31/08/2026. [Unverified - the exact S3 error code for "no Object Lock configuration"; `_NOT_CONFIGURED_CODES` is a best-effort allowlist, and a miss degrades to UNKNOWN, never a false lock] |
| per-append receipts (SPEC §19, REMOTE.md §10) | acknowledged entries: the rewrite window shrinks from anchor cadence N to one entry |
| segment archival at rotation | availability: destruction becomes recoverable, not merely detectable - a hash proves a thing existed; only a copy brings it back |

The doctrine tying them together: **no waxseal output prints "tamper-proof"
without naming its scope**, and the library's headline claim remains
tamper-evident. Every row above ends on the condition sections 3, 6, and 10
already state - the mechanism's other half must sit under a different
administrative authority than the writer, which software can state and cannot
check.

## References

- Crosby & Wallach, "Efficient Data Structures for Tamper-Evident Logging", USENIX Security 2009.
- Laurie, Messeri, Stradling, RFC 9162 "Certificate Transparency v2.0", 2021 (Experimental).
- Laurie, Langley, Kasper, RFC 6962 "Certificate Transparency", 2013.
- Li, Liu, Wang, "New Records in Collision Attacks on SHA-2", EUROCRYPT 2024 (ePrint 2024/349).
- Li, Liu, Wang, Dong, Sun, "The First Practical Collision for 31-Step SHA-256", ASIACRYPT 2024.
- Zhang, Li, Gao, Wang, "Collision Attacks on SHA-256 up to 37 Steps…", ePrint 2026/232.
- NIST, "Policy on Hash Functions" (2024); SP 800-131A Rev. 3 (draft, 2024); FIPS 180-4; FIPS 202.
- Bradley, Rundgren, Erdtman, RFC 8785 "JSON Canonicalization Scheme", 2020 (Informational).
- Bormann, Hoffman, RFC 8949 "CBOR" §4.2 deterministic encoding, 2020.
- Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be", USENIX Security 2012.
- Latacora, "How (not) to sign a JSON object", 2019.
- Haber & Stornetta, "How to time-stamp a digital document", J. Cryptology 3, 1991.
- Adams et al., RFC 3161 "Time-Stamp Protocol", 2001; OpenTimestamps (opentimestamps.org).
- Syta et al., "Keeping Authorities 'Honest or Bust' with Decentralized Witness Cosigning", IEEE S&P 2016.
- C2SP specs: tlog-checkpoint, tlog-cosignature, tlog-tiles, static-ct-api; Tessera; Let's Encrypt Sunlight (2024).
- Schneier & Kelsey, "Secure Audit Logs to Support Computer Forensics", ACM TISSEC 2(2), 1999. DOI 10.1145/317087.317089.
- Bellare & Yee, "Forward Integrity for Secure Audit Logs", UCSD TR CS98-580, 1997; "Forward-Security in Private-Key Cryptography", CT-RSA 2003 (ePrint 2001/035).
- Ma & Tsudik, "A New Approach to Secure Logging", ACM Transactions on Storage 5(1), 2009 (ePrint 2008/185).
- Holt, "Logcrypt: Forward Security and Public Verification for Secure Audit Logs", ACSW 2006 (ePrint 2005/002).
- Paccagnella, Liao, Tian, Bates, "Logging to the Danger Zone" (KennyLoggings), ACM CCS 2020. DOI 10.1145/3372297.3417862.
- Hoang, Wu, Yuan, "Faster Yet Safer: Logging System Via Fixed-Key Blockcipher" (QuickLog/QuickLog2), USENIX Security 2022.
- Chan et al., "Visibility into AI Agents", ACM FAccT 2024; "Infrastructure for AI Agents", TMLR 2025.
- OpenTelemetry GenAI semantic conventions.
- NIST FIPS 186-5, "Digital Signature Standard", 2023. DOI 10.6028/NIST.FIPS.186-5.
- Josefsson & Liusvaara, RFC 8032 "EdDSA", 2017; Pornin, RFC 6979 "Deterministic ECDSA/DSA", 2013.
- Breitner & Heninger, "Biased Nonce Sense", Financial Cryptography 2019 (ePrint 2019/023).
- Dörre & Ottenhues, "Security Analysis of Forward Secure Log Sealing in Journald", ACNS 2025 (ePrint 2023/867); CVE-2023-31437/31438/31439.
- Marson & Poettering, "Practical Secure Logging: Seekable Sequential Key Generators", ESORICS 2013 (ePrint 2013/397).
- Chalkias, Garillot, Nikolaenko, "Taming the many EdDSAs", SSR 2020 (ePrint 2020/1244).
- DSSE protocol (secure-systems-lab); C2SP signed-note spec; draft-irtf-cfrg-bls-signature.
- pyca/cryptography "Known security limitations" (memory zeroization); Gutmann, USENIX Security 1996.
