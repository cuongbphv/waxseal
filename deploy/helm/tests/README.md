# Chart snapshots - and what they are worth

`snapshots/` holds what `helm template` **should** produce for the three value
sets in `values/`. `values/` holds the inputs.

```sh
# server, chart defaults
helm template waxseal-server ../waxseal-server \
  -f values/server-minimal.yaml > snapshots/server-minimal.yaml

# server, every optional piece on
helm template waxseal-server ../waxseal-server \
  -f values/server-full.yaml > snapshots/server-full.yaml

# the verifier, pointed at a server in another namespace
helm template waxseal-verifier ../waxseal-verifier \
  -f values/verifier.yaml > snapshots/verifier.yaml

# both charts with every image pinned by digest instead of tag
helm template waxseal-server ../waxseal-server \
  -f values/server-digest.yaml > snapshots/server-digest.yaml
helm template waxseal-verifier ../waxseal-verifier \
  -f values/verifier-digest.yaml > snapshots/verifier-digest.yaml
```

The **release names matter**: `waxseal-server` and `waxseal-verifier`. Helm's
fullname helper collapses `<release>-<chart>` to `<release>` when the release
name already contains the chart name, so a different release name changes every
resource name in the output and the diff becomes noise.

## Recorded output since 08/09/2026

Until the 0.1.6 pre-release review every file in `snapshots/` was written by
hand from reading the templates, because no `helm` was installed where the
charts were written; the note here said so, and said the first real render
would replace them. That render happened on 08/09/2026 with Helm v4.2.4:
`helm lint` passed on both charts and the five commands above regenerated every
snapshot. What is in `snapshots/` now is *output*, not intent. `kubeconform`
still runs only in CI (job `helm`), and no manifest has been applied to a
cluster; a `kind` run is still a follow-up.

Two more value sets exist beside the original three: `server-digest.yaml` and
`verifier-digest.yaml` pin every image by `image.digest` instead of tag, so the
rendered reference is `repository@sha256:...`. The digests in them are
placeholders of the right shape, checked by `values.schema.json`'s pattern; a
real one comes from `cosign verify` on the published image.

## What the snapshots are for, and what they are not

They catch an *unintended* change to rendered output: someone edits a helper
and three manifests move. They do not check that the manifests are valid
Kubernetes (that is `kubeconform`), that the charts lint (`helm lint`), or that
anything runs (a `kind` cluster, still a follow-up).

They also cannot check the two properties that actually matter here, because
neither is expressible in a manifest:

- that the two charts are installed under **different administrative
  authorities** - different namespaces at the least, different clusters
  preferably. `docs/architecture/deployment.md` section 1: the load-bearing
  property is that the domains are four different authorities, not four boxes;
- that the anchor **sinks** and any **witness** URL point somewhere the trail's
  writer does not control. `adapters/witness.py` says in its own docstring that
  it cannot enforce this and that the deployment is the security argument.

A green snapshot diff says the templates render what they rendered last time.
It says nothing about either of the above.
