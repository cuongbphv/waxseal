# Lessons read off Hedera's public design

**What this document is not.** waxseal does not use Hedera. It pays none of
their network fees, ships no adapter for them, and does no development on their
behalf. Nothing here is an integration plan and nothing here creates a
dependency on their service. What follows dissects their published design in
order to extract ideas waxseal owns outright and runs on its own
infrastructure.

Reading somebody else's architecture is cheap and legitimate; sending them
traffic is a different decision, and it was not taken.

**What was checked, and how.** Two behaviours of the public mainnet mirror node
were verified directly on 2026-08-31 from this repository with `curl`, sending
no credential of any kind:

```
$ curl -D - https://mainnet-public.mirrornode.hedera.com/api/v1/network/nodes?limit=1
HTTP/2 200
content-type: application/json;charset=UTF-8

$ curl 'https://mainnet-public.mirrornode.hedera.com/api/v1/topics/0.0.3959298/messages?limit=2&order=desc'
HTTP 200
# each message carries: consensus_timestamp, sequence_number,
# running_hash, running_hash_version
```

Two facts follow from those two commands and are stated here as verified: an
unauthenticated public read endpoint returns REST JSON, and each consensus
message it serves carries a running hash together with a contiguous sequence
number. Everything else about Hedera's behaviour below — how the running hash
is constructed, what the consensus timestamp guarantees, what anything costs —
was not verified by command in this session and is labelled accordingly.

---

## 1. The mirror-node pattern → the public read point

**The idea.** A public read surface answers without a credential, and
[Unverified — from the 0.1.5 plan's 31/08/2026 reading of Hedera's public
documentation; this session verified only that the endpoint answers reads with
no credential, not that it can accept no writes] it sits apart from the write
path rather than being the write path with authentication relaxed. A third party
auditing the network does not have to be granted anything by the party that
wrote the data. The verified `curl` above is the credential-free half being
exercised: no key, no account, JSON back.

**Why it is worth taking.** A read permission is a bit somebody can flip. A
separate read surface with no write route on it is a structural fact. The
difference shows up exactly when it matters, which is when the operator of the
write path is the party under question. waxseal's threat model already turns on
this distinction — a copy held under a different administrative authority is the
only thing that makes a rewrite visible
([docs/security/threat-model.md](../security/threat-model.md) § 1) — and an
auditor who must ask the trail's owner for read access is not holding an
independent copy in any useful sense.

**Adopted, and already built.** The self-hosted server (Workstream I, landed in
commit `9162abf`) serves a credential-free public read point at `/public/v1`,
in `server/waxseal_server/api/public.py`, whose module docstring states the
constraint it exists to hold:

> "This is not 'the same data with authentication turned off'. It is a separate
> surface, and a test asserts that every route on it is `GET`."

The routes it exposes are the chain list, a chain's head, its entries, and the
server's own receipt chain (including a verify and a cross-check), plus the
witness view and the scope statement. A third party checks those without being
granted anything, and none of it was left as backlog.

## 2. The per-topic running hash → the server's receipt chain

**The idea.** [Unverified — from the 0.1.5 plan's 31/08/2026 reading of
Hedera's public HCS documentation; the construction itself was not verified by
command] the consensus service binds each message into a service-side running
hash, so the service's own record of the order it accepted messages in is
itself chained. The observable half was verified: the mirror node returns a
`running_hash` and a `running_hash_version` per message, at contiguous sequence
numbers.

**Why it is worth taking.** A witness that merely answers questions can answer
differently later. A witness chained by its own answers cannot re-tell the
history it has already acknowledged without the retelling being visible to
anyone who kept an earlier answer. That lifts witness semantics from "responds
to a query" to "is bound by its responses", and it closes a gap waxseal's
trusted-writer model previously left open on the server side.

**Adopted, and already built.** `server/waxseal_server/domain/receipts.py`
keeps a running hash over the entries the server has acknowledged, in
acknowledgment order, framed per SPEC.md § 19 and specified as a wire contract
in REMOTE.md § 10. Its docstring states the point:

> "It exists so the server is bound by its own answers: it cannot later re-tell
> the history of what it accepted without the retelling being visible to anyone
> who kept a receipt."

The frame reuses `lp` imported from the library rather than restating the
encoding, so the server cannot drift from the bytes the client verifies. This
is a waxseal feature on self-hosted infrastructure. No coin leaves any wallet
for it.

One observation from the verified response, recorded rather than acted on: the
`running_hash_version` field is an ordinal version identifier on the hash
construction, the shape of version identity this repository argues against for
per-row schema identity (CLAUDE.md, "migration 060"). waxseal's receipt frame
carries a fixed literal prefix (`waxseal-receipt-v1`) pinned by SPEC.md § 19
rather than a descriptor fingerprint. Whether the receipt frame should instead
be identified by a fingerprint the way `hash_version` is remains an open
question for the repository owner; this document does not decide it, and the
receipt chain as shipped is a domain-separated frame with a frozen spec, not a
field a verifier selects a code path from.

## 3. The predictable flat-fee model → a case study for `c`, and nothing else

**No code adopted.** [Unverified — from the 0.1.5 plan's 31/08/2026 reading of
Hedera's public documentation; no pricing page was fetched in this session] the
design point of interest is that the per-message fee is predictable and roughly
flat rather than auction-priced, so an operator can state a marginal cost per
anchoring operation in advance instead of estimating a distribution.

That predictability is the only part waxseal borrows, and it borrows it as
arithmetic input rather than as code. `src/waxseal/domain/cadence.py` takes `c`,
the marginal cost per anchor operation, as a required keyword argument with no
default, for the reason its docstring gives: `w`, `rho`, and `c` are
measurements only the operator holds, and inventing a plausible number for any
of them would be inventing a measurement. A flat-fee anchor technology is
therefore the easy case for that model — `c` is a number the operator can read
off a price list — and an auction-priced one is the hard case, where `c` is a
distribution the operator has to summarise before `optimal_cadence` will accept
it. Nothing about this changes the code. It is a worked example of what makes
the `c` parameter easy or hard to supply honestly.

---

## Ideas to features, in one table

| Idea read off their design | Status in waxseal | Where |
|---|---|---|
| Credential-free public read surface, separate from the write path | Built in 0.1.5 | `server/waxseal_server/api/public.py` (`/public/v1`), commit `9162abf` |
| A service chained by its own acknowledgments | Built in 0.1.5 | `server/waxseal_server/domain/receipts.py`, SPEC.md § 19, REMOTE.md § 10 |
| Predictable flat per-operation fee | No code adopted; case study only | `src/waxseal/domain/cadence.py`, parameter `c` |

Neither adopted idea routes any traffic or any money to the design it was read
from.
