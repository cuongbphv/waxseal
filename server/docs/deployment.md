# Deploying the waxseal server

This is a self-hosted application. "SaaS" here means the source ships so anyone
can run it; waxseal operates no service and holds no data.

## What it is

Three surfaces in one process, deliberately kept apart:

| Surface | Prefix | Credential | Purpose |
|---|---|---|---|
| Chain API | `/v1/chains/...` | an operator API key, or `WAXSEAL_API_KEY` | The write authority. `RemoteBackend` speaks this. |
| Admin | `/v1/operators`, `/v1/keys` | a key with `keys:manage` | Operators and their credentials. |
| Witness | `/v1/witness/...` | `WAXSEAL_WITNESS_API_KEY` | Anchor deposits and read-back for *someone else's* chain. |
| Public read point | `/public/v1/...` | none | Third-party verification without being granted anything. |

The public read point is not "the same data with authentication turned off". It
is a separate surface with no write route on it at all — the read authority is
architecture here, not a permission bit. That shape is borrowed from the
mirror-node pattern (0.1.5 plan, Workstream G4), and a test asserts that no
`/public` route accepts anything but `GET`.

`GET /public/v1/scope` serves the frozen scope statement
(`waxseal-scope-v1`) from the library that owns it. The portal prints it
verbatim beside every verdict, and it is available on a server with no chains at
all: a qualification that disappears when there is nothing to qualify is not a
qualification.

## Quick start

```bash
docker compose -f server/docker-compose.yml up --build
# UI and API on http://127.0.0.1:8000
```

Without Docker:

```bash
cd server/web && npm install && npm run build   # optional; the API runs without it
cd server && uv sync --extra dev
WAXSEAL_SERVER_DATA_DIR=./data uv run python -m waxseal_server
```

If the UI was never built, `/` serves a page that says so and names the build
command, and `GET /v1/meta` reports `"web_ui": "not_built"`. That is a labelled
absence, not a missing page.

## Operators, roles and API keys

The server keeps its own operator records in **PostgreSQL**. Seed them once:

```bash
docker compose -f server/docker-compose.yml exec server \
    waxseal-server-admin seed --email you@example.com
docker compose -f server/docker-compose.yml exec server \
    waxseal-server-admin key-mint --username admin --label laptop
docker compose -f server/docker-compose.yml exec server \
    waxseal-server-admin key-mint --username user-waxseal --label claude-code-hook
```

`seed` creates two accounts and is idempotent, so a deploy script may re-run it:

| Username | Role | For |
|---|---|---|
| `admin` | admin | A person. Manages the server, operators and keys. |
| `user-waxseal` | writer | A machine. What an agent hook appends with. |

`key-mint` is deliberately **not** idempotent: a second mint is a second
credential. Each key's plaintext is printed once and never again — the store
holds only its SHA-256, so this server cannot show you a key twice and cannot
leak every key at once.

### The role table

| Role | Scopes |
|---|---|
| `admin` | `trails:read` `head:read` `entries:append` `verify:run` `proof:export` `import:write` `keys:manage` `public:read` |
| `auditor` | `trails:read` `head:read` `verify:run` `proof:export` `import:write` `public:read` |
| `writer` | `entries:append` `head:read` |
| `viewer` | `trails:read` `public:read` |

Two properties are worth stating because they are enforced, not merely intended:

- **No role can edit an entry.** There is no `entries:edit`, no
  `entries:delete` and no `trails:repair` scope anywhere, so an admin cannot be
  granted one. A test walks every scope of every role and fails if one appears.
- **A writer cannot read the trail it writes to.** That is the point of the
  role: the key lives on a developer's machine or in CI, and leaking it must not
  leak the audit history. It can extend the chain and discover the tail it is
  extending, and nothing else.

### Seeding is what secures a deployment

A server with no `WAXSEAL_API_KEY` and no minted key is **open**, and says so at
`GET /v1/meta` (`"write_auth": "open"`) and in the portal. The moment the first
key exists it stops being open. There is no separate "turn auth on" switch to
forget, because a fail-open that describes itself as secured is the
false-confidence half of the collapse this project exists to prevent.

`WAXSEAL_API_KEY` remains a valid bootstrap credential with admin scopes. It is
not an operator: it has no record and no history, and `GET /v1/whoami` reports
it as `is_operator: false` so the portal never lists it as a person.

## Configuration

Every setting is an environment variable. None is a command-line argument,
because arguments are visible in a process listing (REMOTE.md section 5).

| Variable | Default | Meaning |
|---|---|---|
| `WAXSEAL_SERVER_DATA_DIR` | `/var/lib/waxseal` | Chains, witness records, imports — **files**. |
| `WAXSEAL_SERVER_DATABASE_URL` | unset | PostgreSQL for operators and API keys. Unset means an in-memory store that forgets them on restart. |
| `WAXSEAL_API_KEY` | unset | Bootstrap bearer token, admin scopes. |
| `WAXSEAL_WITNESS_API_KEY` | unset | Bearer token for the witness. Never a chain or operator key. |

### Why the trails are not in PostgreSQL

The database holds this server's own records. A trail stays a JSONL file on the
data volume, and that is a deliberate line rather than an unfinished migration:

- the product's promise is that a third party can verify a trail with the stock
  `waxseal verify` on their own machine. Put the trail in this database and this
  server becomes the only thing that can read it — exactly the trust
  concentration the public read point exists to remove;
- the waxseal library and its CLI know nothing about PostgreSQL, and adding a
  driver to them would break the zero-dependency rule the whole design rests on
  (CLAUDE.md rule 1);
- backing up the data volume gives you files `waxseal verify` reads directly,
  with no server and no database running.

## TLS

Terminate TLS at a reverse proxy (nginx, Caddy, a cloud load balancer) and
forward plain HTTP to port 8000. The compose file binds `127.0.0.1:8000`
precisely so it is not reachable until you have put something in front of it.
This project does not ship a PKI story and will not invent one.

## Data layout

Files, on the data volume:

```
$WAXSEAL_SERVER_DATA_DIR/
  chains/<chain_id>/trail.jsonl      # the chain, one JSON envelope per line
  chains/<chain_id>/receipts.jsonl   # this server's acknowledgment history
  witness/<witness_id>.jsonl         # checkpoints deposited with this witness
  imports/<import_id>/meta.json      # an imported trail's record
  imports/<import_id>/<filename>     # the imported trail, chmod 0400
```

PostgreSQL, two tables:

```
waxseal_operators   username, display_name, email, role, created_at, active
waxseal_api_keys    key_id, username, label, fingerprint, key_sha256,
                    created_at, last_used_at, revoked_at
```

Back up both. `trail.jsonl` is the ordinary waxseal JSONL format, so
`waxseal verify` works directly on a restored copy with no server and no
database running — which is the point of keeping it a file.

## Pointing an agent hook at this server

`WAXSEAL_TRAIL` has always chosen where a hook writes. An `http(s)://` value
makes it a chain server, so no second configuration mechanism is needed:

```sh
#!/bin/sh
# ~/.claude/hooks/waxseal-remote.sh — the credential is NOT in settings.json.
[ -f "$HOME/.config/waxseal/hook.env" ] && { set -a; . "$HOME/.config/waxseal/hook.env"; set +a; }
WAXSEAL_TRAIL="${WAXSEAL_TRAIL:-http://127.0.0.1:8000}" \
WAXSEAL_API_KEY="${WAXSEAL_WRITER_KEY:-}" \
exec "$HOME/.claude/waxseal-venv/bin/python3" "$HOME/.claude/hooks/waxseal_hook.py"
```

Point the `PreToolUse`, `PostToolUse` and `UserPromptSubmit` hooks in
`~/.claude/settings.json` at that script, and keep the key in a `0600` env file
so the hook configuration can be shared and the credential cannot.

Give the hook the **writer** key, not the admin one. A hook runs on a laptop,
and a writer key that leaks lets an attacker append noise to a chain; an admin
key that leaks lets them read every trail on the server and mint more keys.

The chain id is derived from the event's own `cwd`, so each project lands on its
own chain rather than braiding every project into one. Set `WAXSEAL_CHAIN_ID` to
override it. This is the remote-target form of the per-project routing Workstream
B shipped for LOCAL trails in 0.1.5 (`integrations/_trail.py`'s `routed_trail`);
it uses a readable project name rather than that slug because a chain id is read
by people in a portal.

If the server is unreachable the hook exits 0 with a labelled notice on stderr
and the event is lost. That is the observer contract working: a broken audit
path must never veto the developer's tool call. It also means stopping the
container costs you audit coverage, which the notice tells you at the time.

## What the server is trusted for, and what it is not

**The server is a trusted writer.** REMOTE.md section 1 states this as a scope
boundary, and self-hosting does not change it:

- `verify_chain` runs **client-side**. A server that corrupts, truncates or
  reorders entries is caught exactly as a corrupted local file would be. That is
  tamper-evidence, and it is what this server gives you for free.
- What no hash chain catches on its own is a server that forges a whole
  self-consistent rewrite from genesis. A locally writable disk has the same
  blind spot. Narrow it the way the library already documents: pin the head
  somewhere the server cannot reach (SPEC.md section 13), and cross-check
  against a witness under a **different administrative authority** (SPEC.md
  section 14).
- **A witness hosted next to the chain it witnesses proves nothing.** This
  server implements a witness endpoint so you can host one for another team's
  chain, not so a deployment can witness itself. Nothing in the code can enforce
  that; it is a deployment decision and this paragraph is where it is stated.
- The chain's write credential is never accepted at the witness endpoint. This
  one *is* enforced, and a test asserts it: a witness holding the chain key
  could append forged entries to the very chain it exists to cross-check.

**Self-hosting buys separation of authority, not a stronger theorem.** If team A
hosts the server and team B writes to it, the separation degree τ genuinely
rises, and `waxseal report --declare-topology` will say so. If one team holds
both, it does not, and no amount of infrastructure changes that.

**Collusion between server and writer is the last rung of the capability
ladder.** Nothing here addresses it. threat-model.md is the honest account.

## What the server will not do

There is no route that edits, deletes, reorders, repairs or re-signs an entry,
and no button in the UI for one. "Verify reports, never repairs" (CLAUDE.md rule
4) applies to the web surface exactly as it applies to the CLI. A test enumerates
every mutating route in the OpenAPI schema and fails if a third one appears.

Imported trails are somebody else's evidence: the stored copy is `chmod 0400`
and lives in its own namespace, so no chain route can address one and no append
path can reach it.

## Not implemented, and why

Recorded here rather than left for someone to discover, on the same discipline
the conformance ledger uses: written is not shipped.

- **No pin-store endpoint.** The 0.1.5 plan lists one under Workstream I, but no
  waxseal client speaks HTTP to a pin store — `FilePinStore` reads and writes a
  local path the operator chooses, and its own docstring says the pin must live
  where the trail's writer cannot reach. An endpoint with no client is surface
  that looks like a feature and checks nothing, and hosting the pin next to the
  server would defeat the point of a pin. Keep the pin file off this host.
- **No password login, and there will not be one.** Authentication is an API
  key, hashed at rest. A sign-in form over an account store with no password
  column would be a control that admits everyone while looking like one that
  does not.
- **No 2FA and no session history.** The operator table tracks what it can
  actually observe — role, creation, whether a key has ever been used. Columns
  the server cannot fill are absent rather than rendered as em dashes.
- **No longer on this list: the `preflight` and `segments` screens.** Both were
  recorded here as unshipped. Workstream B shipped `segments` and Workstream E
  shipped `preflight`, both in 0.1.5, and because the capability gate is parsed
  from `waxseal --help` each screen started rendering the verifier's own output
  with no server change beyond the argument `segments` is handed (below). The
  entry is kept rather than deleted because the gate did not go away with them:
  a screen still reports `unavailable` whenever the wheel behind this server
  lacks the command (`GET /v1/capabilities` reports it present-and-false),
  which is the ordinary state of an older wheel behind a newer portal.
- **No `.receipts` sidecar on the client side.** That is Workstream J2. This
  server already publishes the head a client would store, so the sidecar lands
  without a server change.

## Reads run the CLI

Every verify/report/inspect surface shells out to `python -m waxseal.cli` and
reports its exit code. The server does not compute verdicts of its own, so there
is only ever one verifier to reconcile. Responses carry the `argv` that produced
them, so an operator can reproduce any verdict on their own machine.

Two consequences worth knowing:

- Commands this build of waxseal does not have report `"status": "unavailable"`
  with a null verdict. They are never run, because argparse also exits 2 and
  that would arrive looking exactly like "unverifiable" — a verdict nobody
  computed. As of 0.1.5 the wheel has every read this server offers, so the path
  is reached only by an older wheel behind a newer server — the case it exists
  for.
- Exit 3 ("nothing was read") is reported as `"absent"`, never as a break. A
  tamper report against a file that does not exist is a false alarm.
- `segments` is handed the DIRECTORY holding the trail, not the trail file: it
  walks a segment group and the rotation bindings between its files (SPEC.md
  section 20). A chain that has not rotated therefore reports `"absent"` with
  "no sealed segments" on stderr — nothing was checked — rather than an `ok` that
  would claim every segment of a trail with none was found intact.

## Receipt chain

If a client's `201` shows `receipt_seq` and `receipt_head`, this server is
maintaining a receipt chain for that `chain_id` (REMOTE.md section 10): a
running hash over what it has acknowledged, in acknowledgment order, framed by
SPEC.md section 19. It is durable on disk, so a restart continues the same chain
rather than starting a new one.

Anyone can check it without a credential:

```
GET /public/v1/chains/<id>/receipts              # the records themselves
GET /public/v1/chains/<id>/receipts/verify       # is the log internally consistent?
GET /public/v1/chains/<id>/receipts/cross-check  # does it still match the trail?
```

All three are published because a receipt chain only a server can evaluate is a
promise rather than evidence. Both verdicts are three-valued: `ok`, `broken`,
and `unverifiable` (a record version this build cannot read). `checked: null`
with `reason: "not_recorded"` means there is no log at all — which is never the
same as a log with nothing wrong in it.

The two answer different questions, and the difference is the point:

- **`verify`** asks whether the acknowledgment log is internally consistent. It
  stays `ok` after an edit to the *trail*, because the log itself was not
  touched. Correct, and useless on its own.
- **`cross-check`** asks whether entry `seq` still carries the hash that was
  acknowledged for it. This is what catches a **self-consistent** local rewrite —
  the kind that recomputes `entry_hash` so plain `verify` passes. The receipt is
  the memory the rewriter does not hold. Reasons are SPEC.md section 19's:
  `receipt_mismatch` and `receipt_beyond_head` (a rollback or truncation).

The honest limit is SPEC.md section 19's too: a server that rewrote **both** the
trail and its own receipt log consistently passes both checks. What they defeat
is the cheaper edit that does not also curate the receipts. Narrowing it further
means reading this server's published head back from somewhere else — a client's
`.receipts` sidecar, or a third party who kept a copy.
