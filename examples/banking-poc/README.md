# Banking PoC — a verifiable AI decision log

*[Tiếng Việt](README.vi.md)*

A runnable end-to-end demonstration of waxseal used as the **evidence layer under an AI
agent that makes financial decisions**. An AML screening agent decides on payment
instructions; every decision lands on a tamper-evident chain, and an auditor can later
check any single decision without being given the rest of the log.

Everything here is **synthetic**. There is no customer data, no institution, no named
individual, and no real model — the "agent" is a deterministic rule set, so the demo
produces the same decisions on every run and the trail can be reasoned about. What is
being demonstrated is the evidence layer, not the model.

Nothing in this directory is imported by the library. It is stdlib-only, like waxseal
itself, and adds no dependency.

---

## Run it

```bash
python examples/banking-poc/simulate.py --out examples/poc-out     # animated data-flow walkthrough
python examples/banking-poc/simulate.py --out examples/poc-out --no-animation   # CI / piped output
python examples/banking-poc/tamper_demo.py --out examples/poc-out  # the eight scenarios below
```

`--out` is recreated on every run. The animation disables itself automatically when
stdout is not a terminal, and falls back to ASCII glyphs on a console that cannot encode
box drawing (`NO_COLOR=1` or `WAXSEAL_DEMO_PLAIN=1` also force plain output).

Both scripts are covered by `tests/test_examples_banking_poc.py`, which asserts the
claims this page makes. An example that has silently drifted from the library teaches
the wrong thing with a straight face, so this one is tested like code.

---

## What the simulation does

Six synthetic payment instructions are screened. For each one:

| Stage | What happens | Why it is in this order |
|---|---|---|
| `decide` | rule-based agent returns approve / deny / escalate | stands in for a model |
| `redact` | `RegexRedactor` masks secrets in the input | **before** any hash is computed |
| `commit` | `input_commitment = sha256(canonical_json(redacted_input))` | the input is committed, never stored |
| `canon` | decision record → canonical JSON bytes | sorted keys, no whitespace, one owner |
| `hash` | `payload_hash = sha256(payload)` | payload is referenced by hash only |
| `chain` | `EntryHeader` links to `prev_hash` | the chain hashes the header, not the payload |
| `seal` | forward-secure HMAC seal, key evolves | the key that signed entry *n* is gone by *n+1* |

Then a Merkle checkpoint is anchored every 4 entries.

### The redaction claim, made checkable

One transaction carries an operator note containing a credential
(`Bearer sk-live-…`). The run ends by grepping every byte it wrote:

```
Cleartext secret present anywhere in the trail: False
```

The test does the same across the trail *and* every sidecar beside it. The commitment is
computed over the **redacted** input on purpose: a commitment over the cleartext would let
anyone holding the log confirm a guess at the secret by recomputing the hash.

### One decision deliberately records no oversight

One code path leaves `human_oversight` unset. The report must show that as *oversight not
recorded*, counted separately from `automated` — they are different claims, and
collapsing them would report an absence of evidence as evidence
(CLAUDE.md rule 5: `None` ≠ `0`, unmeasured ≠ absent).

### What the run writes

```
examples/poc-out/
  decisions.jsonl           the trail
  decisions.jsonl.anchors   published Merkle roots (a record ABOUT the trail)
  decisions.jsonl.attest    forward-secure seals
  decisions.jsonl.sealkey   current key epoch
  sealkey.escrow            A₀ — see the warning below
```

There is no `.drops` sidecar because nothing was dropped. The report says
`Dropped writes: >= 0 (measured minimum, source: sidecar)` — a **measured minimum**, not a
guarantee of completeness. A sidecar can itself be deleted, and a disk too broken to hold
a drop record cannot bear witness to its own failure.

> **`sealkey.escrow` is a demo artefact.** A₀ is written next to the trail here only
> because a demo has nowhere else to put it. In a real deployment it is the one secret
> that must **not** live on the writing host — it belongs with the verifier. Scenario 6
> below is only caught because the verifier holds a key the attacker did not.

---

## The auditor walkthrough — eight scenarios

`tamper_demo.py` copies the trail once per scenario, attacks the copy, and prints the
command an auditor would run plus its real exit code. **The original trail is never
modified** (a test asserts this). The script asserts each expected outcome itself and
exits non-zero if any scenario deviates — that is the falsifiability receipt for this
table.

| # | Scenario | Detected by | Exit |
|---:|---|---|---:|
| 1 | Edit one decision | chain: `payload_hash` no longer matches | 1 |
| 2 | Delete a decision | chain: `seq_gap` | 1 |
| 3 | Reorder history | chain: `prev_hash_mismatch` | 1 |
| 4 | Insert a decision | chain: `prev_hash_mismatch` | 1 |
| 5 | Rewrite the **whole** trail consistently | anchor — chain alone says `ok` | 1 |
| 6 | Truncate the tail, sidecar and all | forward-secure seal — chain alone says `ok` | 1 |
| 7 | A row from a **newer** software version | nothing — reported *unverifiable*, **not** tampered | 2 |
| 8 | Disclose one decision to an auditor | membership proof (valid bundle exits 0) | 1 |

### Scenarios 1–4: the chain does its own job

Ordinary edits, deletions, reorderings and insertions all break a link. `verify` prints
the first break with its sequence number and reason, and stops there. It reports; it never
repairs. Which row is the tamper is a decision only an operator can make.

### Scenario 5: why anchoring elsewhere matters

An attacker with write access to the trail can edit a row **and recompute every hash after
it**. The chain then re-links perfectly:

```
$ waxseal verify .../05-rewrite/decisions.jsonl
ok (checked=6)
exit 0
```

That is correct behaviour, not a bug: every link genuinely holds. What the attacker could
not rewrite is a root that was already published somewhere else:

```
$ waxseal verify --anchors .../05-rewrite/decisions.jsonl
ANCHOR BROKEN at seq=3: anchor_entry_hash_mismatch
exit 1
```

In this demo the anchor sidecar sits next to the trail, which proves the mechanism but
not the security property — an attacker who can rewrite the trail can delete a sidecar
beside it. **Anchor into a trust domain the writing host does not control.**

### Scenario 6: why the seal key must live elsewhere

Cutting the tail off the trail *and* the seals that covered it leaves a chain and a
sidecar that agree with each other:

```
$ waxseal verify .../06-truncate/decisions.jsonl
ok (checked=3)
exit 0
```

The forward-secure seal catches it, because the key epoch on disk cannot be rolled back to
an earlier one — `A_{j+1} = SHA-256(A_j)` is one-way:

```
$ log.verify_attestations(initial_key=A_0)   # escrowed off-host
ok=False reason=keyfile_epoch_mismatch
```

### Scenario 7: the difference that motivated the library

A row written by a newer build carries a schema fingerprint this build does not recognise.
It is **not** reported as tampering:

```
$ waxseal verify .../07-unknown-schema/decisions.jsonl
ok (checked=5) but 1 unverifiable row(s) at seq=[5]
  — unknown schema fingerprint, NOT evidence of tampering
exit 2
```

Exit 2 is its own verdict. A verifier must not recompute a row under a field tuple it was
not signed with: reporting a row intact on a hash it cannot reproduce is the one lie a
tamper-evidence mechanism must never tell — and calling it *tampered* is the mass false
alarm this library exists to make unrepresentable
(RFC 6962 §4.6: unrecognised types are opaque, not errors).

### Scenario 8: answering one question without disclosing the log

A regulator asks about one customer. Exporting the whole trail would over-disclose every
other customer in it. A proof bundle is one entry plus its Merkle path:

```
$ waxseal export-proof decisions.jsonl 3 > proof-seq3.json
bundle: 1687 bytes, one entry + its Merkle path

$ waxseal verify-proof proof-seq3.json      # the trail is deleted at this point
ok: seq=3 verified against root a00438772c5d… (batch of 6)
exit 0
```

Tamper with the bundle and it fails closed:

```
BROKEN at seq=3: payload_hash_mismatch
exit 1
```

The auditor needs the bundle and the anchored root. They do not need the trail, the other
customers' decisions, or any access to the writing host.

---

## The report an auditor reads

```bash
waxseal report examples/poc-out/decisions.jsonl            # Markdown
waxseal report examples/poc-out/decisions.jsonl --json     # machine-readable
waxseal report examples/poc-out/decisions.jsonl --anchors  # also replay the anchor sidecar
```

It states the chain verdict, completeness (`dropped_writes` with its source), an inventory
by payload type and schema fingerprint, decisions by type and oversight mode, and the
status of each sidecar check. A check that was **not run** is printed as *not checked* —
never as a pass. A report that said "ok" for something it skipped would overstate the
evidence, which is the failure this whole layer is trying to avoid.

---

## What this PoC does **not** show

- **waxseal is tamper-evident, not tamper-proof.** An attacker with write access can
  rewrite the trail. Scenarios 5 and 6 are caught only because a root was anchored, and a
  seal key evolved, outside that attacker's reach.
- **Chain integrity is not trail completeness.** A write that never happened leaves no
  seq gap. `dropped_writes` measures completeness separately, and `None` there means
  *not measured* — never zero.
- **A commitment over a low-entropy input is confirmable.** If an input has few possible
  values, anyone can enumerate them and match the hash. Commitment is not encryption.
- **Nothing here is a compliance verdict.** This layer produces technical evidence that
  can support a record-keeping obligation; it does not establish that any obligation is
  met. Governance, access control, retention enforcement and model documentation are all
  outside it. See [docs/compliance/mapping.md](../../docs/compliance/mapping.md) for the
  honest gap analysis.
