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
```

The **release names matter**: `waxseal-server` and `waxseal-verifier`. Helm's
fullname helper collapses `<release>-<chart>` to `<release>` when the release
name already contains the chart name, so a different release name changes every
resource name in the output and the diff becomes noise.

## These were hand-written. No helm ran.

`helm`, `kubectl`, `kind` and `kubeconform` are not installed on the machine
these charts were written on and could not be installed there. So:

- **no `helm lint` and no `helm template` has ever been run against either
  chart**, and no manifest here has ever been applied to a cluster;
- every file in `snapshots/` was written by hand, from reading the templates -
  it is a statement of *intent*, not a recording of *output*;
- the YAML in `snapshots/` was machine-parsed (`yaml.safe_load_all`) and the
  kind sequence checked, so it is valid YAML carrying the manifests it claims
  to. That is the whole of what was verified.

Three things are the most likely to differ from real output, and all three are
cosmetic rather than semantic:

1. **Document order.** Helm sorts rendered manifests by its install-order kind
   sorter and, within a kind, by template file path; hooks are emitted after
   the ordinary manifests. `snapshots/server-full.yaml` puts the seed Job last
   for that reason. Derived from Helm's documented behaviour, not observed.
2. **Whitespace and key order inside `toYaml` blocks.** `toYaml` marshals maps
   with sorted keys and does not indent sequence items under their key; that is
   what is written here, unverified.
3. **Quoting.** Where a template pipes through `quote` the value is written
   quoted; elsewhere the string is left bare.

**The first CI run may need to regenerate these files, and that is expected.**
Regenerating is the three commands above. A snapshot nobody can trust is worse
than an honest note saying which one this is, so the note stays until a real
`helm template` has replaced the contents at least once - at which point this
section should be edited to say so.

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
