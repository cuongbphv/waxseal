# Anchoring to external time

A hash chain resists edits *behind* its tip. It does not resist an attacker who
rewrites the whole file, because every `prev_hash` downstream of an edit is
recomputable. The only defence against that is a copy of the chain's state held
somewhere the attacker cannot write - which is what anchoring is.

This page covers the two external sinks waxseal ships, how to verify what they
produce with the tools that own those formats, and how to write a sink for a
chain waxseal does not know about.

> Nothing on this page makes a trail tamper-*proof*. It makes a rewrite
> *detectable* by comparison against a party under different administrative
> authority. See [threat model](security/threat-model.md) for what that buys
> and what it does not.

---

## RFC 3161 - a Time-Stamp Authority

A TSA signs a statement of the form "I saw this digest at this time". waxseal
sends it `SHA-256(checkpoint_frame(checkpoint))` - the same bytes every other
sink witnesses, which is why the forward-secure aggregate binding lives inside
the frame rather than beside it.

```bash
waxseal anchor trail.jsonl --tsa-url https://freetsa.org/tsr
```

The token is stored base64-encoded in the `.anchors` record's `receipt` field,
prefixed `rfc3161:`. Nothing is recorded if the TSA is unreachable, declines,
or answers about different bytes.

```bash
waxseal verify trail.jsonl --anchors
# anchors ok (checked=3, latest=seq 240)
#   note: seq=240: attested time (RFC 3161, structural only - signature NOT
#         verified): 2026-08-23T09:22:17+00:00
```

### What "structural only" means

waxseal compares the token's status, its `messageImprint`, its digest
algorithm, and its nonce. It does **not** verify the CMS signature or the TSA's
X.509 chain - that needs path validation and RSA/ECDSA verification, which a
zero-dependency library has no business reimplementing. A homegrown signature
check that is subtly wrong is worse than none, because it reports authenticity
nobody established.

So a passing structural check means *this token is well-formed and commits to
these exact bytes*. It never means *this token is genuine*.

### Delegating full verification to OpenSSL

Extract the token and the exact bytes it was asked to stamp, then let OpenSSL
do the part waxseal declines to do:

```bash
# 1. extract every stored receipt plus the frame it attests
waxseal receipt trail.jsonl --out receipts/
# wrote receipts/seq-240.tsr (RFC 3161 timestamp token, seq=240)
# wrote receipts/seq-240.frame (checkpoint frame the receipt attests, seq=240)

# 2. the verification waxseal delegates
openssl ts -verify -in receipts/seq-240.tsr -data receipts/seq-240.frame \
    -CAfile tsa-chain.pem
```

`--seq N` restricts extraction to records anchored at that seq (duplicate
records there each get a numbered file); exit 3 means the trail or sidecar is
missing (nothing is created, not even `--out`), and exit 2 means the sidecar
holds no matching receipts - absence, not success and not tampering.

`tsa-chain.pem` is the TSA's certificate chain, obtained from the TSA operator
out of band. Verifying against a chain the same attacker could supply proves
nothing.

### Inspecting a token by hand

```bash
openssl ts -reply -in receipts/seq-240.tsr -text
```

### Honest limits

- An attacker who rewrites **both** the anchor record and its receipt is caught
  only by the delegated signature verification above, never by waxseal's
  structural check.
- A TSA is a trusted third party. It can lie about time; it cannot lie about
  *which digest* it stamped without invalidating its own signature.
- A receipt is a few kilobytes. With `anchor_every=1` on a hot trail, the
  `.anchors` sidecar grows accordingly - anchor on a schedule, not per append.

---

## OpenTimestamps - a Bitcoin calendar

OpenTimestamps aggregates digests and folds them into a Bitcoin block. Once
confirmed, the time claim rests on the same authority as the block chain
itself, which is the strongest separation available here.

```bash
waxseal anchor trail.jsonl --ots-calendar https://alice.btc.calendar.opentimestamps.org
```

The calendar returns a **pending** proof, stored with an `ots:` prefix. Pending
means exactly what it says: the calendar has accepted the digest, and the
Bitcoin attestation does not exist until a block confirms - hours to days.

waxseal deliberately ships no OpenTimestamps proof parser. The serialization is
an attestation-op tree the OpenTimestamps project owns; a partial
reimplementation here would manufacture "malformed" verdicts on proofs that are
perfectly valid, which is the exact failure class this library exists to
prevent. So an `ots:` receipt is reported as pending and unchecked, and does
not change the exit code:

```bash
waxseal verify trail.jsonl --anchors
# anchors ok (checked=1, latest=seq 240)
#   note: seq=240: pending OpenTimestamps proof - opaque to this library by
#         design, NOT checked here; complete and verify it with
#         `ots upgrade` / `ots verify`
```

### Completing and verifying a proof

Install the client (`pip install opentimestamps-client`), extract the proof,
then upgrade and verify:

```bash
waxseal receipt trail.jsonl --out receipts/
# wrote receipts/seq-240.ots (pending OpenTimestamps proof, seq=240)
# wrote receipts/seq-240.frame (checkpoint frame the receipt attests, seq=240)

ots upgrade receipts/seq-240.ots     # after the Bitcoin block confirms
ots verify  receipts/seq-240.ots -f receipts/seq-240.frame
```

> **[Unverified]** The exact bytes a calendar returns from `/digest` are treated
> here as a detached `.ots` file. This has not been confirmed against
> `python-opentimestamps`, and the upgrade semantics of
> `GET /timestamp/<hex>` are likewise unconfirmed. Verify both against the
> OpenTimestamps client before relying on this recipe in production.

> **[Unverified]** Which public calendars are live changes over time. waxseal
> ships no default calendar URL for that reason - pass one explicitly, and
> confirm it is current. Calendars commonly cited in OpenTimestamps
> documentation include `alice.btc.calendar.opentimestamps.org`,
> `bob.btc.calendar.opentimestamps.org`, and `finney.calendar.eternitywall.com`.

### Redundancy

One calendar per sink, on purpose. Redundancy in OpenTimestamps means
submitting the same digest to several calendars, which here is several
`waxseal anchor` runs with different `--ots-calendar` values. An aggregating
sink would have to decide what a partial failure means, and that is an
operator's call rather than a library default.

---

## Writing a sink for another chain

An `AnchorSink` is one method (see `src/waxseal/ports/anchor.py`):

```python
class AnchorSink(Protocol):
    name: str
    def anchor(self, checkpoint: Checkpoint) -> str | SinkReceipt | None: ...
```

Three rules, all of them learned the hard way:

1. **Commit to `checkpoint_frame(checkpoint)`, not to a field of it.** The
   frame is the canonical byte encoding, and it is where the aggregate binding
   lives. Anchoring `checkpoint.root` alone silently drops that binding.
2. **Raise on failure. Never return `None` as if it had worked.** `None` means
   "this sink has no receipt to give" - a legitimate state for a sink whose
   evidence lives elsewhere. It must never mean "the publish failed".
3. **Return an opaque receipt with a prefix.** `"<type>:<payload>"`. waxseal
   dispatches on the prefix, and reports a prefix it does not know as
   unverifiable-by-name rather than guessing at the bytes. A sink whose
   request material must be stored beside the receipt for later
   re-verification (an RFC 3161 nonce) returns a
   `waxseal.domain.checkpoint.SinkReceipt` instead of a bare string.

`RecordingAnchorSink` does the sidecar bookkeeping - it publishes first and
records second, so a failed publish leaves no record behind. `AuditLog` wraps
a path-backed trail's sink in it automatically; wrapping explicitly, as below,
is equivalent:

```python
from waxseal import AuditLog
from waxseal.adapters.anchors import RecordingAnchorSink

log = AuditLog.open("trail.jsonl").with_anchor_sink(
    RecordingAnchorSink("trail.jsonl", MyChainSink(...))
)
log.anchor()
```

### EVM contract event

waxseal now ships this natively (0.1.5, Workstream F) - see
`src/waxseal/adapters/evm.py::EvmAnchorSink`. EVM is no longer "a chain
waxseal does not know about"; use the real sink rather than hand-rolling one:

```bash
waxseal anchor trail.jsonl --evm-rpc https://rpc.example \
    --evm-liveness 0xLIVENESS_CONTRACT_ADDRESS
```

Store `sha256(frame)` in a contract's calldata or emit it as an event topic;
the chain id, block number, and transaction hash together are the receipt.
The transaction signer is never a flag or an env var holding a private key:
it is an external process named by `WAXSEAL_EVM_SIGNER_CMD`, a three-verb
protocol (`address` / `sign-digest` / `sign-tx`) - see CLAUDE.md's CLI
contract.

Notes specific to EVM, true whether waxseal's own sink handles this or the
pattern is adapted to an EVM-compatible chain it does not cover: a
transaction that reverts must raise, not return (the shipped sink does this);
a reorg can undo a confirmed anchor, so wait for the confirmation depth your
threat model requires before treating the receipt as evidence
(`EvmLedgerSink`'s `confirm_tag` defaults to `finalized` for exactly this
reason); and the digest is public forever, which is fine - it is a hash of a
hash, and the payloads never leave your storage.

### Hyperledger Fabric

Invoke a chaincode function with the digest as its argument; the receipt is the
channel name plus the transaction ID. Fabric's endorsement policy is what gives
the anchor its separation of authority - an anchor endorsed only by the same
organization that runs the audit trail is not an external witness.

### A private or consortium chain

The same shape applies, and the same question decides whether it is worth
anything: *can the party who can rewrite the trail also rewrite the anchor?* If
yes, the anchor is bookkeeping, not evidence. A private chain operated by the
same team as the application is in that category.

### Publishing to a witness instead

If the other party is willing to hand its checkpoints back, it is a *witness*
rather than an anchor sink, and it buys fork detection on top of rewrite
detection:

```bash
waxseal anchor trail.jsonl --witness https://notary.example/anchors
waxseal verify trail.jsonl --witness https://notary.example/anchors
```

The wire format is REMOTE.md section 8.
