# systemd units - waxseal without Kubernetes

*[Tiếng Việt](README.vi.md)*

Three units, each with a timer, and an `*.env.example` beside each of the three.

| Unit | Runs as | Trail access | Trust domain |
|---|---|---|---|
| `waxseal-verify@.service` | `DynamicUser` (transient) | **read-only** | verifier |
| `waxseal-anchor@.service` | the chain's `waxseal` user | read-write (the `.anchors` sidecar lands beside the trail) | chain -> anchor client |
| `waxseal-openclaw-ingest.service` | the chain's `waxseal` user | read-write (it appends) | application -> chain |

The split in the "Runs as" column is the security argument, not a style
choice. `docs/architecture/deployment.md` section 1: the load-bearing property
of the reference topology is that the domains are different **administrative
authorities**. On one host, a Unix identity is the strongest boundary available,
so the verifier gets one that is not the writer's.

## Install

```sh
sudo install -o root -g root -m 0644 \
  waxseal-verify@.service waxseal-verify@.timer \
  waxseal-anchor@.service waxseal-anchor@.timer \
  waxseal-openclaw-ingest.service waxseal-openclaw-ingest.timer \
  /etc/systemd/system/

sudo install -d -o root -g root -m 0755 /etc/waxseal
sudo install -o root -g root  -m 0640 verify.env.example          /etc/waxseal/verify.env
sudo install -o root -g waxseal -m 0640 anchor.env.example        /etc/waxseal/anchor.env
sudo install -o root -g waxseal -m 0640 openclaw-ingest.env.example /etc/waxseal/openclaw-ingest.env

sudo systemctl daemon-reload
```

Then **edit the three env files** - they ship with every value commented out
and no real credentials, because they are examples in a public repository.

`waxseal-openclaw-ingest.service` also needs its `ExecStart` interpreter path
corrected before it will start. See "The interpreter" below.

## Enable

The instance parameter of the two templated units is the **trail path**,
absolute and escaped. `systemd-escape` is not optional: a path contains `/`,
which is the instance-name separator.

```sh
TRAIL=/var/lib/waxseal/chains/default/trail.jsonl
sudo systemctl enable --now "waxseal-verify@$(systemd-escape "$TRAIL").timer"
sudo systemctl enable --now "waxseal-anchor@$(systemd-escape "$TRAIL").timer"
sudo systemctl enable --now waxseal-openclaw-ingest.timer
```

**Absolute paths only, and never a leading `~`.** `resolve_trail()` in
`src/waxseal/integrations/_trail.py` takes `WAXSEAL_TRAIL` verbatim and
*refuses* a value beginning with a tilde, and its docstring names systemd units
as the reason: no shell runs between a unit file and the process, so the tilde
survives and the writer creates a directory literally called `~` under its cwd.
The same applies to every path in these units and env files.

## Read the timers

```sh
systemctl list-timers 'waxseal-*'

# the last run of one instance
TRAIL=/var/lib/waxseal/chains/default/trail.jsonl
journalctl -u "waxseal-verify@$(systemd-escape "$TRAIL").service" -n 50 --no-pager

# THE EXIT CODE, which is the interface
systemctl show -p ExecMainStatus \
  "waxseal-verify@$(systemd-escape "$TRAIL").service"
```

### Exit codes are the interface

| Exit | Meaning | Where it goes |
|---:|---|---|
| 0 | intact | nowhere |
| 1 | broken - the first break printed with its seq and reason | **the security function.** Preserve. Do not repair. |
| 2 | intact, but carrying rows this build cannot verify by name | **release management**, not the SOC |
| 3 | the trail path does not exist | configuration error: nothing was read, nothing was created |

`SuccessExitStatus` in `waxseal-verify@.service` lists **0 only**. Widening it
to accept 2 would make `systemctl status` green for a state that is neither ok
nor broken, and that flattening of three values into two is the exact failure
this project exists to prevent - it is how "Migration 060" became a mass false
tampering alarm and how beads v1.2.2 turned an unknown schema version into a
fatal error.

Exit 2 is **not a pass**. Alert on it, and route it to whoever owns versions.

**Never wire automatic remediation to exit 1.** waxseal reports; it does not
repair (CLAUDE.md rule 4). No code path may rewrite, reorder or "fix" entries,
and neither may your `OnFailure=` unit. Which row is the tamper is a decision
only an operator can make, and an automation that "restores from backup" has
deleted the only copy of the thing that was detected.

If you add an `OnFailure=` drop-in, make it *notify* - never act:

```ini
# /etc/systemd/system/waxseal-verify@.service.d/notify.conf
[Unit]
OnFailure=waxseal-alert@%i.service
```

and have `waxseal-alert@` read `ExecMainStatus` so it can tell 1 from 2 before
it decides who to wake.

## The pin file, and why `DynamicUser` + `StateDirectory`

`waxseal-verify@.service` writes its pin state to
`/var/lib/waxseal-verifier/pin` - a `StateDirectory` at mode `0700`, owned by
the unit's transient user.

`src/waxseal/adapters/pinstore.py` states the reason in the code. A pin is
**not a sidecar of the trail**: every other file waxseal writes beside a trail
(`.attest`, `.anchors`, `.drops`) describes the log and belongs to whoever owns
it, but "a pin describes what THIS verifier already confirmed, and its entire
value is that it lives somewhere the trail's writer cannot reach." A pin the
writer can edit is a pin the writer can roll back - and then the one thing a
pin catches, a rewrite of history this verifier already confirmed, stops being
caught.

That is also why `waxseal preflight --pin` only *reads* the pin state and the
`--pin` on `verify` is what advances it, and why exit 2 advances the pin
(unverifiable is not tampered, SPEC.md section 13) while exit 1 freezes it.

### The one wrinkle `DynamicUser` creates

A transient user belongs to no group, so a trail at mode `0600` owned by
`waxseal` is unreadable to it and the unit exits non-zero on permissions
rather than producing a verdict. Give the trail a group both sides share, and
add it to the unit as a **read** grant:

```ini
# /etc/systemd/system/waxseal-verify@.service.d/group.conf
[Service]
SupplementaryGroups=waxseal-audit
```

Do **not** solve it by setting `User=waxseal` on the verify unit. Then the
verifier can write both the trail and the pin, and the separation that makes
the pin worth having is gone.

## Why the anchor unit is *not* `DynamicUser`

`waxseal anchor` writes: the `.anchors` sidecar lands **beside** the trail. So
that unit runs as the chain's own user and has the trail directory in
`ReadWritePaths`.

Co-locating the anchor **client** with the chain is the intended topology -
`deployment.md` section 1 draws exactly that arrow. What must answer to a
different authority is the anchor **sink**: the RFC 3161 TSA, the
OpenTimestamps calendar, the witness host. A published root the trail's writer
can rewrite proves nothing, and no unit file can check that the URL you put in
`anchor.env` belongs to somebody else. `adapters/witness.py` says as much in
its own docstring: the deployment is the security argument.

Set the cadence from your own measurements rather than from the `hourly`
placeholder in `waxseal-anchor@.timer`. `waxseal cadence` computes the
cost-optimal interval and returns a **band**, never a bare point; it opens no
trail, so you can run it before anything is deployed.

## The interpreter

`waxseal-openclaw-ingest.service` ships with
`ExecStart=/usr/local/bin/python3 -m waxseal.integrations.openclaw` and that
path is a **placeholder you must correct**:

```sh
# in the environment that actually has waxseal installed
python3 -c 'import sys; print(sys.executable)'
sudo systemctl edit waxseal-openclaw-ingest.service
```

`waxseal install openclaw` prints `sys.executable`, never a bare `python3`, and
`integrations/_install.py` records why in the code: the interpreter on `PATH`
is not necessarily the one that has waxseal, and when it is not, "every hook
event is dropped with a label nobody reads and the trail stays empty while the
hooks look installed." That happened on the repository owner's machine. A unit
file has no `PATH` fallback, so the path is written out - and if it is wrong,
systemd fails the unit with `203/EXEC`, which is loud.

This unit replaces the crontab line `waxseal install openclaw` recommends:

```
*/5 * * * * <interpreter> -m waxseal.integrations.openclaw
```

Nothing here runs on the agent's path. It reads OpenClaw's own ledger after
the fact - OpenClaw keeps one but prunes it (30 days, 100k rows) and hashes no
row, which is what this chains.

Its timer deliberately does **not** set `Persistent=yes`. Catching up a missed
five-minute slot would read rows the next run reads anyway; what a downtime
actually costs is *coverage* - rows OpenClaw pruned while nothing was chaining
them - and no timer setting recovers that. Chain integrity is not trail
completeness: a decision never written leaves no `seq` gap and no broken link,
`dropped_writes` measures completeness separately, and `None` there means *not
measured*, never zero.

## What these units do not do

- **They install no host.** They assume `/usr/local/bin/waxseal`, a `waxseal`
  user for the writing units, and a trail that already exists.
- **They enforce no retention.** waxseal is append-only, so it will not delete
  on its own. Plan chain rotation rather than deletion within a chain.
- **They hold no seal key.** A₀ is escrowed with the verifier and never written
  to a writing host. There is no unit here that puts it on one.
- **They were not run.** These files have never been loaded by a systemd on any
  host: they were written and machine-checked as INI text only. Treat the first
  `systemctl daemon-reload` as the first real test, and
  `systemd-analyze verify` as the cheap way to take it:

  ```sh
  systemd-analyze verify /etc/systemd/system/waxseal-verify@.service
  systemd-analyze security waxseal-openclaw-ingest.service
  ```
