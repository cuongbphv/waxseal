# waxseal threat model

What this library detects, what it cannot, and why. Every claim below is meant
to be checkable against the code and the tests; where something is not
detectable at all, the argument for that is written out rather than asserted.

This document exists because a tamper-evidence tool that overstates itself is
worse than none: it produces a document somebody cites in an audit, and the
citation carries more confidence than the evidence does.

---

## 1. Tamper-evident is not tamper-proof

**Question:** waxseal is only tamper-evident. How do you get to *proof*?

**Answer: you do not, in software alone, and no library that claims otherwise
is telling the truth.**

The argument is short. An attacker with write access to the storage holding the
trail can replace every byte of it. A hash chain does not prevent this: each
`entry_hash` is a pure function of the header, and each `prev_hash` is the
previous `entry_hash`, so recomputing the entire chain from a rewritten row is
mechanical. Sealing raises the cost — a forward-secure HMAC needs the epoch key
— but an attacker who holds the disk holds the keyfile too, and while the key
has *evolved* past old epochs, the attacker can simply start a new chain from
the current key and present it as the whole history.

What software *can* do is make a rewrite **detectable by comparison against a
copy the attacker cannot write**. Everything in waxseal that goes beyond a
plain hash chain exists to create such copies:

| Mechanism | Copy held by | Detects |
|---|---|---|
| Anchoring (SPEC 9) to a local sidecar | the same disk | accidental corruption, honest bugs. Not an attacker. |
| RFC 3161 TSA (SPEC 17) | the TSA | rewrite of anchored history, and asserts the time |
| OpenTimestamps (SPEC 18) | Bitcoin | same, with no trusted third party |
| Witness (SPEC 14) | another host | rewrite *and* split views |
| Pinned head (SPEC 13) | the verifier | rewrite of history this verifier already saw |
| Forward-secure seal (SPEC 11) | the evolving keyfile | insertion and truncation, while the key holder is honest |

Practical "proof" is a *combination*, and the combination is only as strong as
its weakest separation:

1. Anchor to at least two authorities that do not share an operator.
2. Keep the seal key under a different administrative authority than the
   application that writes the trail.
3. Put the storage on write-once media where the platform offers it (S3 Object
   Lock in compliance mode, for instance). waxseal ships no code for this — it
   is a storage configuration, and a library cannot enforce it.
4. Pin, and keep the pin file somewhere the trail's writer cannot reach.

Miss any one of these and the corresponding attack comes back. That is the
honest shape of the answer: not a feature you enable, but a set of separations
you maintain.

---

## 2. Chain integrity is not trail completeness

**Question:** chain integrity is not the completeness of the trail?

**Answer: correct, and the distinction is load-bearing.**

`verify` walks the recorded entries and confirms each one links to the last.
A write that failed *before it reached storage* leaves no gap for that walk to
find: sequence numbers stay contiguous, every `prev_hash` matches, and the
verdict is `ok`. Nothing about a valid chain says the chain is complete.

waxseal reports completeness as a separate, explicitly-measured quantity:

- `dropped_writes: int | None`. `None` means **never measured**. It is not
  `0`, it must never be rendered as `0`, and it must never be omitted from a
  report as if the question had not been asked.
- The `.drops` sidecar (SPEC 12) gives that count a persistence layer
  independent of any one process's memory. Enabled with
  `AuditLog.open(path, record_drops=True)`.
- The count from a sidecar is a **measured minimum**, never a total. A failure
  bad enough to prevent its own drop record cannot bear witness to itself.

What `verify` returning ok does and does not mean:

| It means | It does not mean |
|---|---|
| every recorded entry links to the one before it | every event that happened was recorded |
| no recorded entry was edited, deleted, or reordered | no write was dropped before storage |
| the fingerprints of recorded entries are known to this build | the payloads are truthful |
| the trail is internally consistent | the trail is the whole story |

The only way to bound what is *missing* is to compare against a source outside
the trail — a broker's message count, a database row count, a partner's
records. That comparison is an application-level control. waxseal's job is to
make sure it never *looks* as though the comparison has already been done.

---

## 3. Trustworthy time

**Question:** integrate RFC 3161 so `ts` becomes attested rather than asserted.

An entry's `ts` is written by the process that appended it, from its own clock.
It is an assertion by the writer, and against an attacker who controls the
writer it is worth nothing.

RFC 3161 anchoring (SPEC 17) fixes that for *checkpoints*, not for individual
entries: the TSA stamps `SHA-256(checkpoint_frame(cp))`, which bounds every
entry up to that checkpoint's `seq` to "existed no later than the token's
`genTime`". Combined with the checkpoint before it, an entry is bracketed
between two attested times.

What waxseal checks and what it delegates is spelled out in
[anchoring to external time](../anchoring-external-time.md). In short: the
structural check confirms the token commits to these exact bytes; the CMS
signature is verified by `openssl ts -verify`, never here. Every line of output
that mentions a token says so, because a structural check that reads as
authentication is precisely the overstatement this document exists to prevent.

Residual: a TSA can lie about *time*. It cannot lie about *which digest* it
stamped without invalidating its own signature. Anchor to more than one
authority if the time claim is load-bearing.

---

## 4. A Byzantine chain server

**Question:** against a dishonest server, what can a client-side check detect,
and what is provably impossible?

### Detectable

| Attack | Detected by | Reason reported |
|---|---|---|
| edit an entry | `verify` (hash chain) | `entry_hash_mismatch` / `prev_hash_mismatch` |
| delete or reorder | `verify` (seq walk + chain) | `seq_gap` / `prev_hash_mismatch` |
| roll the trail back | pin (SPEC 13) | `pin_beyond_head` |
| rewrite history the client already saw | pin | `pin_mismatch` |
| rewrite history a witness saw | witness (SPEC 14) | `inconsistent` |
| serve a trail inconsistent with an anchor | `--anchors` | `anchor_root_mismatch` |
| truncate a sealed trail | keyfile epoch (SPEC 11) | `keyfile_epoch_mismatch` |
| replay an old aggregate over a truncated trail | anchored binding (SPEC 15) | `anchored_aggregate_epoch_mismatch` |

### Provably impossible without an external channel

**A split view.** A server that shows client A one history and client B a
different, internally consistent history cannot be caught by either client
alone. This is fork consistency, and the argument is a simulation argument: the
server controls every byte either client receives, so for any check A performs,
the server can compute a response consistent with A's entire past. A's view is
*indistinguishable* from a world where the fork does not exist. No amount of
client-side cryptography changes that, because the missing information is not
cryptographic — it is the fact that B saw something else.

(Mazières and Shasha, *Building Secure File Systems out of Byzantine Storage*,
established this for storage; RFC 6962's gossip requirement is the same result
for certificate transparency.)

The only fix is a channel the server does not mediate. A witness *is* that
channel, made explicit and minimal: the client publishes checkpoints to a
second party and later asks that party what it saw. If the histories diverge,
one of them is a fork.

This narrows the trust; it does not remove it. Explicit residuals:

1. Witnesses colluding with the server see the same forked view and agree.
2. A client whose entire network path is adversarial (an eclipse) reaches the
   attacker's witness, not the real one. waxseal uses TLS through `urllib` and
   does **not** pin certificate authorities.
3. Everything after the last witnessed checkpoint is unwitnessed by
   construction.
4. A witness that returns fewer checkpoints than it holds quietly reduces
   coverage. That is why every verdict reports `checked=K` and never
   "complete".

---

## 5. An attacker who can write

**Question:** an attacker with write access can still rewrite the trail;
anchoring and forward-secure sealing limit that, and only when they sit under a
different administrative authority.

**Answer: exactly right, and the second clause is the whole thing.**

| Attacker holds | Rewrite works? | What stops it |
|---|---|---|
| the trail file only | no | seals: forging one needs the epoch key |
| trail + keyfile | yes, locally | anchors: an external record of the old root |
| trail + keyfile + `.anchors` | yes, locally | external anchor: the TSA / calendar / witness holds its own copy |
| trail + keyfile + `.sealagg` | previously yes (replay + truncate) | the aggregate binding in an anchored checkpoint (SPEC 15) |
| all local files + the anchor sink | yes | nothing this library can offer |
| all local files + every witness | yes | nothing — this is the collusion case |

The row that changed in this release is the fourth. SPEC 11 documented a
residual risk: an attacker who truncates the trail can copy an older
`.sealagg` back into place, and every local check — `verify`,
`verify_attestations`, even the aggregate — agrees, because they all read the
same rewritten files. Binding the aggregate commitment into the anchored
checkpoint moves that claim outside the attacker's reach: the anchor still says
five rows were folded, and the trail now holds two.
(`tests/test_anchored_aggregate_log.py` carries the falsifiability receipt: the
forgery passes `verify()` and `verify_attestations()` and fails only against
the anchor.)

What is committed is a *commitment*,
`sha256(prefix || u64be(2) || lp(epoch) || lp(agg))`, never the accumulator
itself — publishing intermediate accumulators would hand a truncating attacker
exactly the value the scheme forbids persisting.

**The operational requirement, stated plainly:** the seal key, the anchor sink,
and the witness must each be under a *different* administrative authority than
the process that writes the trail. If the same team, the same service account,
or the same compromised host controls both sides, the mechanism records the
attack rather than detecting it. No configuration flag substitutes for this,
and waxseal cannot check it for you.

---

## 6. What no output of this library asserts

**Question:** no output asserts that an obligation was met, and no output
should be cited as if it did.

**Answer: agreed, and it is now written into every output.**

Every report carries a fixed, machine-identifiable scope statement
(`waxseal-scope-v1`, SPEC 16), and `waxseal verify` prints an abbreviated form
of it as a trailing line on every verdict — exit 0, 1, or 2. The full
statement:

> This output attests hash-chain integrity and completeness measurements of
> RECORDED entries only. It does not attest that any obligation was met, that
> payload content is truthful, or that unrecorded events did not occur.

### How to cite waxseal output correctly

**Defensible:**

- "The decision log for period X verified intact: 12,480 entries, no chain
  break, no gap, checked against an RFC 3161 token dated Y."
- "The trail records 340 automated decisions and 12 with human review recorded;
  8 rows record no oversight mode at all."
- "Completeness was measured: at least 3 writes were dropped in period X."
- "Completeness was not measured for period W."

**Not defensible, in each case with the specific reason:**

- ~~"waxseal proves we complied with Article 12."~~ The chain says the record
  is unedited. It says nothing about whether the recorded behaviour satisfies
  anything.
- ~~"verify returned ok, so nothing was missed."~~ Integrity is not
  completeness (section 2).
- ~~"Every decision was human-reviewed."~~ A row with no oversight recorded is
  `oversight_unrecorded`, which is not `automated` and is not `reviewed`.
- ~~"The timestamps are proven."~~ Structural checking is not signature
  verification (section 3).
- ~~"The log is tamper-proof."~~ Section 1.

### For assessors reading a waxseal report

Three questions decide how much the report is worth, and the report answers all
three explicitly:

1. **Was anything anchored outside this system's control, and to whom?** An
   unanchored trail is a self-attestation.
2. **Was completeness measured?** `dropped_writes: null` means the question was
   never asked.
3. **What did the checks that were not performed cover?** A check absent from
   the report was not performed, and absence of a check is never a pass — the
   report labels each one rather than omitting it.
