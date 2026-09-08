# waxseal-audit - OpenClaw integration

Tamper-evident external archive for [OpenClaw](https://github.com/openclaw/openclaw)'s
audit ledger. Verified against openclaw/openclaw **@ main, 2026-08-22**. waxseal is on
[PyPI](https://pypi.org/project/waxseal/) (stdlib-only, zero runtime dependencies).

Unlike the other integrations in this repo, this one is **not a hook**. Nothing runs on the
agent's execution path. It reads the ledger OpenClaw already keeps.

## Why an exporter and not a plugin hook

OpenClaw already records what its agents did: `audit_events` in `state/openclaw.sqlite`,
written off the hot path, queryable with `openclaw audit --json`. What it does not do is
keep that record, or prove it was not edited. From `docs/gateway/audit.md`:

> "This ledger supports debugging and operational review. **It is not a lossless
> compliance archive; if you need one, use an external system** fed by OpenTelemetry or
> channel-level tooling."

> "Records live in the shared state database (`state/openclaw.sqlite`) … Queries never
> return records older than **30 days**, and the ledger is capped at **100,000 rows**;
> expired rows are **pruned** during startup, hourly maintenance, and later writes."

> "**Absence of a row proves nothing.** … queue saturation, storage failure, or a bounded
> shutdown timeout can drop records and log one operational warning."

There is no hash on a ledger row and no link between rows (`src/audit/audit-event-store.ts`
has no hash column), so a deleted or edited row leaves nothing behind. This integration is
the external archive the docs point at.

Two things in OpenClaw's own tracker decided the shape:

- [#105453](https://github.com/openclaw/openclaw/issues/105453) objects to audit work on
  the execution path. An exporter adds none.
- [#115342](https://github.com/openclaw/openclaw/issues/115342) argues the capability
  belongs at the **audit layer, not provider hooks**, because hooks exist for some runtimes
  and not others - "a silent gap the moment an agent moves to a runtime without hooks".
  Reading the ledger covers native providers, `claude-cli` and `codex` through one path.

## OpenClaw issues this speaks to

| Issue | State | Ask | What this provides |
|---|---|---|---|
| [#12508](https://github.com/openclaw/openclaw/issues/12508) | open, P2 | Chain integrity + tamper detection + audit logging | A SHA-256 hash chain over the ledger's own records, offline-verifiable with `waxseal verify`. Not the in-core hook-chain checksums the issue proposes - see limits |
| [#115342](https://github.com/openclaw/openclaw/issues/115342) | open, P2 | "payload_hash alone cannot answer *what did this agent just do*" | Nothing on content: the ledger stores no arguments, so neither does this. It answers the adjacent question - *was the record altered afterwards* |
| [#20935](https://github.com/openclaw/openclaw/issues/20935) | open | Audit log for agent memory changes | Whatever the ledger records reaches the chain; memory-change coverage is OpenClaw's to add, not this exporter's |
| [#71712](https://github.com/openclaw/openclaw/issues/71712) | open | Non-forgeable provenance | Append-only chain + optional external anchoring, so a rewrite has to forge the anchor history too |
| [#106710](https://github.com/openclaw/openclaw/issues/106710) | closed | Missing audit trail on plugin lifecycle hooks | Only if the ledger records those events |

**Caveat, stated plainly:** every one of those issues carries
`clawsweeper:needs-maintainer-review` / `needs-product-decision`. No OpenClaw maintainer
has endorsed an external chain, and #12508 asks for integrity **inside core**. This is
offered as the external archive the docs describe - nothing more.

## Install

```bash
pip install waxseal
waxseal install openclaw     # prints the schedule; writes no files
```

Then run it on a timer. Nothing to enable in OpenClaw, no gateway restart, no plugin:

```cron
*/5 * * * * python -m waxseal.integrations.openclaw
```

systemd timer equivalent: a `OnCalendar=*:0/5` unit running the same command.

Requirements: the `openclaw` CLI on `PATH` (set `WAXSEAL_OPENCLAW_BIN` to override) and a
gateway able to answer it - the CLI queries the versioned activity RPC.

Trail location, in order: `$WAXSEAL_TRAIL`, else `$OPENCLAW_HOME/audit/trail.jsonl`, else
`~/.openclaw/audit/trail.jsonl`.

```bash
waxseal verify ~/.openclaw/audit/trail.jsonl   # 0 intact / 1 broken / 2 unverifiable rows
waxseal tail   ~/.openclaw/audit/trail.jsonl
```

Exit codes are cron-alertable. Options: `--kind {agent_run,tool_action,message}`,
`--limit` (≤ 500, OpenClaw's documented page cap), `--max-pages`, `--trail`.

Or use it as a library:

```python
from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.sources.openclaw import ingest

log = AuditLog.open("trail.jsonl", redactor=RegexRedactor(), record_drops=True)
result = ingest(log)  # idempotent; resume point comes from the chain
print(result.ingested, result.last_sequence, result.gaps)
```

## How it behaves

- **Idempotent.** The resume point is the highest ledger `sequence` already on the chain -
  read from the chain, not from a cursor file that could disagree with it. A re-run with no
  new ledger activity appends nothing, and the whole run (resume-read through append) holds
  an ingest lock (`<trail>.ingest.lock`), so two overlapping timer runs cannot both ingest
  the same rows - a run that cannot take the lock backs off with a labelled notice.
- **Order is preserved.** The export is newest-first (`ORDER BY sequence DESC`, and
  `--cursor` means `sequence < cursor`), so the ingest reverses it and appends ascending. A
  chain whose order disagreed with the ledger's would misreport what happened when.
- **Gaps are reported, never judged.** A hole in `sequence` means rows were pruned *or*
  dropped, and from outside the two are indistinguishable - OpenClaw's queue is documented
  best-effort. The hole becomes its own chain entry
  (`application/vnd.waxseal.openclaw-ingest-gap+json`, `cause: "prune_or_drop"`), and
  `waxseal verify` still reports the chain intact. A completeness fact is not a tamper
  verdict. A gap left by waxseal's own `--max-pages` bound is labelled `page_cap` instead,
  so the two are never confused.
- **Filtered exports do not guess.** With `--kind` set, absent sequences are the filter
  working as asked, so gap detection is switched off and reports `None` - not `()`.
  Unmeasured is not zero.
- **Never raises.** A missing binary, a stopped gateway, unparseable output, an unreadable
  trail: all report on stderr and exit 0. One damaged record does not cost its page; the
  loss is counted (`unusable`, `dropped`), never silent.
- **Redaction runs anyway.** The ledger is documented metadata-only, but secrets are
  redacted before hashing regardless. Redact-before-hash is not conditional on trusting
  the source.
- **Nothing on stdout.** stderr carries the summary, so cron mail stays readable.

## What it proves, and what it does not

**Proves:** nothing was altered after ingest. Editing, deleting, reordering or inserting a
row breaks the chain at an exact `seq` with a named reason. Rows written under an older
field set report as *unverifiable*, never as *tampered*, after a rollback - the ledger's
shape has already migrated once ("the earlier run/tool-only ledger"), and that is the
failure class waxseal's version fingerprints exist for.

**Does not prove:**

- **that the ledger was complete when read.** OpenClaw says absence of a row proves
  nothing; an exporter cannot manufacture evidence that was never written.
- **anything about content.** No prompts, tool arguments, results, or command output -
  the ledger deliberately stores none of it, so the chain carries none either. For
  argument-level evidence you need a hook on the runtime itself
  ([integrations/claude-code/](../claude-code/) does that for Claude Code).
- **that a row existed before you ingested it.** The chain starts where you started it.
  Ingest at least as often as the ledger's own retention allows.
- **anything against a compromised host.** waxseal bundles no signature algorithm, and
  this runner configures no anchoring or seals; a rewrite of the whole chain by an
  attacker who owns the disk is detectable only if you anchor the head somewhere else
  (`AuditLog.anchor()` or `anchor_every=N` + an `AnchorSink`).

## Demo

```bash
python integrations/openclaw/e2e_demo.py
```

No OpenClaw needed: a stub serves the real export shape. It shows the backwards export
landing in ascending order, a prune becoming a labelled gap while `verify` still passes,
an idempotent re-run, and an edited row caught with its exact `seq` and reason.
