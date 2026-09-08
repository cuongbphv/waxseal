# `deploy/` - what is here, and which authority owns it

*[Tiếng Việt](README.vi.md)*

waxseal's security argument is not a diagram. It is that the four domains of
[`docs/architecture/deployment.md`](../docs/architecture/deployment.md) section
1 are four different **administrative authorities** - four sets of people, not
four boxes. Every detection that survives an attacker with write access
survives because something they needed was under someone else's control.

The index below therefore carries an authority column. Read that column first:
it is what decides whether a given detection still works.

| Path | What it is | Authority it belongs to |
|---|---|---|
| `docker/` | The CLI runtime image | build - used by every domain below |
| `install.sh` | One-line installer for a host | build |
| `compose/compose.yaml` | The server stack plus one on-demand `verify` | **one machine, one authority** - development and single-host only |
| `helm/waxseal-server/` | The chain server: StatefulSet, seed hook, optional anchor **client** | chain |
| `helm/waxseal-verifier/` | `verify` and `report` CronJobs, and the pin file | verifier |
| `helm/tests/` | Value sets and hand-written `helm template` snapshots | build / CI |
| `systemd/waxseal-verify@` | Scheduled verification on a host, `DynamicUser` | verifier |
| `systemd/waxseal-anchor@` | Checkpoint publication, runs as the chain's user | chain -> anchor client |
| `systemd/waxseal-openclaw-ingest` | Chains OpenClaw's ledger every five minutes | application -> chain |

`docker/` and `install.sh` are maintained alongside the rest of `deploy/` but
are not described here; see their own headers.

## The two charts, and why there are two

One chart installing the server and its verifier together would put both under
one Helm release: one namespace, one RBAC boundary, one set of people who can
`helm upgrade`. A verifier that whoever writes the trail can also upgrade is a
self-verifying writer reporting on itself, and the detections that survive an
attacker with write access would stop surviving.

So there are two charts, meant for **two namespaces at the least, two clusters
preferably**:

```sh
helm install waxseal-server deploy/helm/waxseal-server \
  --namespace waxseal-chain --create-namespace

helm install waxseal-verifier deploy/helm/waxseal-verifier \
  --namespace waxseal-audit --create-namespace \
  --set trailUrl=http://waxseal-server.waxseal-chain.svc.cluster.local:8000
```

Neither chart installs a witness. That is deliberate and it is not an omission
to fix later: a witness installed by the same release as the chain answers to
the same authority and **witnesses nothing**. Host a witness for another
team's chain, and let another team host yours.
`src/waxseal/adapters/witness.py` says this in its own docstring, and says that
no code can enforce it - the deployment is the security argument.

## Three things nothing in here can check for you

1. **That the two charts really are under different authorities.** Two
   namespaces one person administers is one authority wearing two names.
2. **That the anchor *sinks* are somebody else's.** The anchor *client* beside
   the chain is the intended topology - `deployment.md` section 1 draws that
   arrow. The TSA, the calendar and the witness URL are what must not be yours.
   A published root the trail's writer can rewrite proves nothing.
3. **That the pin file is out of the writer's reach.** The verifier chart puts
   it on the verifier namespace's own PVC and `waxseal-verify@.service` puts it
   in a `DynamicUser` `StateDirectory`, both for that reason
   (`src/waxseal/adapters/pinstore.py`). Compose has nowhere to put one, which
   is why the compose `verify` service runs without `--pin` and says so.

## Exit codes are the interface

Everything in here that verifies reports through the same four codes, and every
wrapper preserves them rather than collapsing them:

| Exit | Meaning | Where it goes |
|---:|---|---|
| 0 | intact | nowhere |
| 1 | broken - first break printed with its seq and reason | **the security function.** Preserve, do not repair. |
| 2 | intact, but rows this build cannot verify by name | **release management**, not the SOC |
| 3 | the trail path does not exist | configuration error: nothing was read, nothing was created |

Exit 2 exists because of the two incidents in
[`CLAUDE.md`](../CLAUDE.md): a rollback that leaves rows written by a newer
schema must not page anyone as a tampering alarm, and must equally not be
silently recomputed under the wrong field tuple and reported intact. **Exit 2
is not a pass.**

Every CronJob and unit in here echoes `waxseal_command=` and `waxseal_exit=`
so a log query can separate 1 from 2 without reading pod or unit status. If
your alerting collapses them into "job failed", the three-valued verdict this
project is built on has been flattened back to two on the way to the screen -
which is the exact failure it exists to prevent.

**Never wire automatic remediation to exit 1.** waxseal reports; it does not
repair (CLAUDE.md rule 4). Which row is the tamper is a decision only an
operator can make, and a repair destroys the evidence a court or a regulator
would need.

## Status of this directory

Written on a machine with **no `helm`, no `kubectl`, no `kind` and no
`kubeconform`**, and none of them installable there. Consequently:

- no `helm lint` or `helm template` has been run against either chart, and no
  manifest here has been applied to any cluster;
- the snapshots in `helm/tests/snapshots/` were **hand-written** from reading
  the templates. They are a statement of intent, not a recording of output.
  `helm/tests/README.md` says so and says which parts are most likely to need
  regenerating;
- the systemd units have never been loaded by a systemd. `systemd-analyze
  verify` is the cheap first real check;
- what *was* machine-checked is the YAML and JSON: every non-template YAML file
  parses, every `values.schema.json` is valid JSON, and each chart's default
  and test value sets validate against its own schema.

Treat the CI helm job as the first real check on the charts, and the first
`systemctl daemon-reload` as the first real check on the units.

## Read first

- [`docs/architecture/deployment.md`](../docs/architecture/deployment.md) - the
  four trust domains, the separation-of-duties table, and section 4's exit-code
  contract.
- [`docs/architecture/deploy-options.md`](../docs/architecture/deploy-options.md) -
  choosing between the packaging options, and the one class of traffic that
  leaves the premises.
- [`server/docs/deployment.md`](../server/docs/deployment.md) - the operational
  manual: environment variables, the data layout under
  `WAXSEAL_SERVER_DATA_DIR`, why the trails are not in PostgreSQL, why seeding
  is what secures a deployment, and the TLS position.
- [`CLAUDE.md`](../CLAUDE.md) - the invariants none of this may route around.
