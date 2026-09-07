# Deployment options - what to install where, and what leaves the country

*[Tiếng Việt](deploy-options.vi.md)*

Six ways to put waxseal somewhere, and the two questions an operator has to
answer about each: which of the four trust domains does this piece belong to,
and does anything cross a border.

This document does not repeat [`deploy/README.md`](../../deploy/README.md),
which owns the authority mapping for every file under `deploy/`, nor
[deployment.md](deployment.md), which owns the topology and the trust model.
Read those first. This one is the chooser.

---

## 1. The options

| Option | Install | Best for | Domain it usually lands in |
|---|---|---|---|
| `pip` / `uv tool` / `pipx` | `uv tool install waxseal` | a developer machine, a CI runner | application, or verifier |
| `deploy/install.sh` | `curl … \| sh` | a host with no Python packaging story | verifier, anchor client |
| Single-file zipapp | `python3 waxseal-<v>.pyz verify trail.jsonl` | an air-gapped review, a regulator's laptop | verifier |
| Runtime image | `docker run ghcr.io/cuongbphv/waxseal` | a scheduled job, a sealed runtime | verifier, anchor client |
| Compose | `deploy/compose/compose.yaml` | one machine, development | **all four at once - see §3** |
| Helm, two charts | `deploy/helm/waxseal-{server,verifier}` | a cluster | chain, and verifier separately |

Because the runtime dependency list is empty and stays empty, the zipapp is a
complete verifier in one file: nothing is fetched, nothing is installed, and
nothing has to be trusted beyond the `python3` already on the machine. That is the shape an offline review needs,
and it is a direct consequence of an invariant, not a packaging trick.

## 2. Which pieces must never share an authority

Each of these three pairs is a mechanism that keeps working only while the pair
is split, and each fails silently rather than loudly when it is not.

- **A witness and the chain it witnesses.** A witness catches a split view - the
  server showing one history to one reader and another to another. Under the
  same authority as the server, it shows whatever the server shows. Neither Helm
  chart ships a witness for this reason.
- **The pin file and the trail's writer.** A pin catches a rewrite of history a
  verifier already confirmed. A writer that can reach the pin can move it. This
  is why the verifier chart puts the pin on its own claim and the systemd unit
  puts it in the verifier's own state directory, and why neither borrows the
  chain's user.
- **The seal key `A₀` and any writing host.** A forward-secure seal detects a
  suffix rewrite only while the attacker cannot obtain an earlier key epoch.

## 3. Compose is one authority, and says so

The compose overlay is genuinely useful and genuinely not a production
topology: one machine, one operator, one `docker` socket. Everything above about
splitting authorities is unenforceable there, so nothing in it should be read as
evidence about separation. Its own file says this. Use it to develop, to demo,
and to learn the exit codes - then move the verifier somewhere else before you
rely on a detection that needs two authorities to work.

## 4. Where the bytes are, and what crosses a border

Every component here runs on premises. The library reads and writes local
files, the server holds its trails on a local volume, and the verifier reads
over HTTP. Nothing calls home, and there is no telemetry to disable.

There is exactly one class of outbound traffic, and an operator has to be able
to describe it:

| What leaves | Where to | What it is |
|---|---|---|
| A Merkle root, or a hash of one | an RFC 3161 timestamp authority | a request for attested time |
| A Merkle root | an OpenTimestamps calendar | a request for a Bitcoin-anchored proof |
| A checkpoint | a witness | a deposit, so a split view is catchable |
| A checkpoint | an EVM ledger | a transaction, so a delinquent writer is visible |

No payload, no decision record, no personal data, and no identifier from a
payload ever appears in any of them - an anchor carries a root and a sequence
number. But a hash is still data, and a destination is still a destination, so
this is a flow to declare rather than a flow to ignore, and the destination is
one an operator chooses. waxseal names no default timestamp authority and no
default trust anchor: choosing one would decide whom an institution trusts
without saying so on any line of output.

For a deployment that must keep everything within one jurisdiction, all four
sinks have on-shore equivalents in principle - an RFC 3161 authority is a
protocol, not a vendor, and a witness is any host under a different authority
that answers the wire contract. `[Unverified]` Whether a licensed Vietnamese
timestamp authority currently exposes a usable RFC 3161 endpoint was not
checked; treat it as a question to answer during procurement rather than an
assumption to build on. Running with no anchor at all is a supported choice and
an honest one: the report says the anchor check was not run, which is not the
same as saying it passed.

## 5. Verification, whichever option you chose

The exit codes are the interface, and they are the same everywhere:

| Exit | Meaning | Where it should go |
|---:|---|---|
| 0 | intact | nowhere |
| 1 | broken, with the first break's seq and reason | the security function - preserve, do not repair |
| 2 | intact, but rows this build cannot verify by name | release management, not the security function |
| 3 | the trail path does not exist | configuration |

Never wire an automatic remediation to exit 1. waxseal reports and does not
repair, and neither may the runbook: which row is the tamper is a decision only
a person can make, and a repair destroys the evidence a court or a regulator
would need.
