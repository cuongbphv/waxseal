# OpenClaw integration for waxseal — chain the audit ledger

## Context

waxseal ships integrations for 7 hosts ([integrations/](integrations/)) but not for
**OpenClaw**, the self-hosted agent gateway that runs shell commands, edits files, drives
browsers and schedules cron on the operator's own machine.

Research changed the shape of the work. OpenClaw **already has an audit ledger** —
`src/audit/audit-event-store.ts`, table `audit_events` in `state/openclaw.sqlite`,
`AUDIT_EVENT_SCHEMA_VERSION = 1`, queryable via `openclaw audit --json`. So the gap is not
"add an audit log". The gap is stated in OpenClaw's own docs (`docs/gateway/audit.md`):

> "This ledger supports debugging and operational review. **It is not a lossless
> compliance archive; if you need one, use an external system** …"
> "Queries never return records older than **30 days**, and the ledger is capped at
> **100,000 rows**; expired rows are **pruned** …"
> "**Absence of a row proves nothing** … queue saturation, storage failure, or a bounded
> shutdown timeout can **drop records** and log one operational warning."

The ledger has no per-row hash and no chain link (no `hash` anywhere in
`audit-event-store.ts`), rows are deleted by TTL and row cap, and the docs record a schema
migration from "the earlier run/tool-only ledger" — the exact false-tamper-alarm hazard
`hash_version` fingerprints exist for.

waxseal supplies precisely the missing piece: an append-only, offline-verifiable,
fingerprint-versioned chain outside the system being audited.

### Demand evidence (OpenClaw issue tracker)

| Issue | State | Ask |
|---|---|---|
| [#12508](https://github.com/openclaw/openclaw/issues/12508) | open, P2, `impact:security` | Hook chain integrity, tamper detection, audit log of hook modifications |
| [#115342](https://github.com/openclaw/openclaw/issues/115342) | open, P2, `impact:security` | "payload_hash alone cannot answer *what did this agent just do*"; argues the capability belongs at the **audit layer, not provider hooks** |
| [#20935](https://github.com/openclaw/openclaw/issues/20935) | open, 6c | Audit log for agent memory changes |
| [#71712](https://github.com/openclaw/openclaw/issues/71712) | open | Non-forgeable provenance |
| [#96675](https://github.com/openclaw/openclaw/issues/96675) | open, 7c | Owner-signed gates over actions/evidence |
| [#106710](https://github.com/openclaw/openclaw/issues/106710) | closed | Missing audit trail on plugin lifecycle hooks |
| [#105453](https://github.com/openclaw/openclaw/issues/105453) | open | Audit SQLite writes block the hot path — argues **against** adding work on the execution path |

Honest caveat to carry into the README, not to hide: every one of these is labelled
`clawsweeper:needs-maintainer-review` / `needs-product-decision`. No maintainer has
endorsed an external chain, and #12508 asks for integrity **in core**. This integration is
offered as the external archive the docs point at, and must not claim more.

#105453 and #115342 together are why this is an **exporter**, not a hook: nothing runs on
the execution path, and one read path covers every runtime (native, `claude-cli`, `codex`)
instead of one hook implementation per runtime.

## Design

```
openclaw audit --json --kind … --cursor N        (documented CLI over the versioned
        │                                         activity RPC)
        ▼
waxseal.sources.openclaw.ingest()   ── redact ──►  AuditLog.append(...)   ──►  trail.jsonl
        │                                                                        │
        └─ OpenClaw `sequence` jumped? → labelled notice entry                   ▼
                                                                    waxseal verify (offline)
```

- **Read path**: `subprocess` of `openclaw audit --json --limit 500 --cursor <seq>`, the
  documented contract, rather than opening `openclaw.sqlite` (internal schema, version 9,
  additive tables — brittle across their migrations). The runner is injectable
  (`run_fn`) the way `now_fn` already is, so tests never need the real binary.
- **Paging is newest-first**: the store lists `ORDER BY sequence DESC` and treats
  `--cursor` as `sequence < cursor`
  (`audit-event-store.ts` L664–L723). So collect pages backwards until reaching the
  last-ingested sequence, then **append in ascending `sequence` order** — chain order must
  match the ledger's own order.
- **Resume point comes from the chain itself**, not a side-car cursor file: scan entries
  for the highest ingested `sequence`, the same technique
  [`sources/files.py:36`](src/waxseal/sources/files.py#L36) uses for `current_matches_last`.
  One source of truth; a separate cursor file could disagree with the chain. Returns
  `None` when nothing was ever ingested — `None` is not `0` (rule 5).
- **Idempotent**: only `sequence > last_ingested` is appended, so a re-run adds nothing.
- **Gaps are reported, never judged.** If the oldest fetched `sequence` exceeds
  `last_ingested + 1`, rows vanished before waxseal saw them — pruning (TTL/row cap) and
  a dropped write are indistinguishable from outside. Emit a notice entry
  (`kind: "ingest_gap"`, `missing_after`, `missing_before`, `cause: "unmeasured"`). It is
  a completeness fact, never `tampered` (rules 4, 5).
- **Bounded work**: `max_pages` caps a first run against a 100k-row ledger.
  Hitting the cap sets `truncated=True` and prints what was left — no silent caps (rule 6).
- **Fail-open, labelled**: missing binary, gateway down, non-zero exit, unparseable JSON →
  record a drop through [`FileDropRecorder`](src/waxseal/adapters/drops.py), print one
  `[waxseal-audit]` line, return a result object. Never raise into a cron job.
- **Redact anyway**: the ledger claims metadata-only, but `RegexRedactor` runs before
  hashing regardless. Redact-before-hash is not conditional on trusting the source.
- The chain's own `ts` comes from the injectable `now_fn`; OpenClaw's `occurredAt`
  (epoch ms) is preserved inside the payload.

### Why no CLI subcommand

CLAUDE.md's CLI contract: "**The CLI never writes to the log.**" So there is no
`waxseal ingest`. The runner ships as `python -m waxseal.integrations.openclaw`
(integrations are the write side), run one-shot from cron or a systemd timer.

## Files

### New

- `src/waxseal/sources/openclaw.py` — the reusable ingest. Public surface:
  `OPENCLAW_AUDIT_PAYLOAD_TYPE`, `INGEST_GAP_PAYLOAD_TYPE`,
  `last_ingested_sequence(log) -> int | None`,
  `ingest(log, *, kinds=…, limit=500, max_pages=…, run_fn=…) -> IngestResult`.
  `IngestResult` carries `ingested`, `last_sequence`, `gaps`, `truncated`, `notice`.
  Docstring records the verified OpenClaw revision plus the `file:line` refs for cursor
  semantics and retention, as every other integration does
  ([claude_code.py:9](src/waxseal/integrations/claude_code.py#L9)).
- `src/waxseal/integrations/openclaw.py` — thin runner: resolve trail
  (`WAXSEAL_TRAIL`, else `OPENCLAW_HOME`, else `HOME`-before-`Path.home()` — the Windows
  `ntpath`/`USERPROFILE` trap, [claude_code.py:59](src/waxseal/integrations/claude_code.py#L59))
  → `<openclaw home>/audit/trail.jsonl`; call `ingest`; print the summary; `main()` returns
  0 on every path so a timer never flaps.
- `integrations/openclaw/README.md` — shape of
  [integrations/hermes/README.md](integrations/hermes/README.md): verified-against
  revision, the issue table above **with the maintainer-review caveat**, the two quoted doc
  lines that justify the design, install/cron instructions, and an explicit
  "what it proves / what it does not" (it proves nothing was altered **after ingest**; it
  cannot prove the ledger was complete when read, and it carries no tool arguments or
  results because the ledger deliberately stores none).
- `integrations/openclaw/e2e_demo.py` — like the other demos: fake `openclaw audit`
  output → ingest → `verify` ok → tamper one row → exact `broken_seq` + reason.

### Changed

- `src/waxseal/integrations/_install.py` — add `openclaw` to `TARGETS`; it installs no
  host file, so it prints the runner + a cron/systemd-timer snippet, reusing the existing
  "attaches in your own code — nothing to install" branch shape (`_LIBRARY_USAGE`).
- `tests/integrations/test_package.py` — add `waxseal.integrations.openclaw` and
  `waxseal.sources.openclaw` to `STDLIB_ONLY_MODULES`.
- `CHANGELOG.md`; integration tables in `README.md`, `README.vi.md`, `README.zh.md`.

No `pyproject.toml` change: pure-Python modules under the existing
`packages = ["src/waxseal"]`, and no new dependency (rule 1).

## Tests (TDD — failing test first; floor stays 90%)

`tests/test_sources_openclaw.py` — drives `ingest` with an injected `run_fn`:
1. One page → one entry per record, `payload_type` correct, `verify` ok.
2. Multi-page via `nextCursor` → entries land in **ascending** `sequence` order despite
   the newest-first API.
3. Re-run after ingest → `ingested == 0`, chain unchanged (idempotency).
4. `last_ingested_sequence` on an empty/foreign trail → `None`, not `0`.
5. Ledger pruned below the resume point → one `ingest_gap` notice entry with
   `cause: "unmeasured"`, `verify` still ok, nothing reported as tampered.
6. `max_pages` reached → `truncated is True` and the shortfall is in `notice`.
7. Secret-looking value in a field → `***REDACTED***` on disk, cleartext bytes absent from
   the whole file.
8. Runner failures — binary missing, non-zero exit, malformed JSON, JSON that is not an
   object/list → no exception, drop recorded, result labels the degradation.
9. Tamper an ingested row → `verify` returns the exact `broken_seq` + reason.

`tests/integrations/test_openclaw_runner.py`
10. `main()` returns 0 with no `openclaw` binary on PATH; trail path resolution honours
    `WAXSEAL_TRAIL` and `OPENCLAW_HOME`; one real-`subprocess` pass against a stub
    `openclaw` script on PATH (proves the default `run_fn`, not just the injected one).

`tests/test_cli_install.py`
11. `waxseal install openclaw` prints the runner/cron guidance and writes nothing.

## Verification

```
uv run pytest --cov=waxseal            # all green, coverage floor >= 90
uv run python integrations/openclaw/e2e_demo.py
uv run waxseal install openclaw
```

Manual, against a real gateway: `openclaw audit --json --limit 5` to confirm the CLI
answers, then `python -m waxseal.integrations.openclaw`, then
`waxseal verify ~/.openclaw/audit/trail.jsonl` (exit 0) and
`waxseal tail ~/.openclaw/audit/trail.jsonl` (expect `tool.action.started` /
`tool.action.finished` pairs). Re-run the ingest and confirm `ingested 0`.

## Out of scope (and why)

- **Plugin/internal hooks + JS sidecar.** Would add content-level capture (redacted tool
  args) that the ledger deliberately omits — the open ask in #115342 — but puts work on the
  execution path that #105453 objects to, and requires JS in a Python-only repo. Revisit
  only if an operator needs argument-level evidence.
- Direct reads of `state/openclaw.sqlite`; publishing to npm/ClawHub; a waxseal server;
  any code path that could block or alter OpenClaw's work.

## Sources

- [openclaw/openclaw](https://github.com/openclaw/openclaw) — `src/audit/audit-event-store.ts`, `src/audit/audit-event-types.ts`
- [Audit history](https://docs.openclaw.ai/gateway/audit) · [`openclaw audit` CLI](https://docs.openclaw.ai/cli/audit)
- [Plugin hooks](https://docs.openclaw.ai/plugins/hooks) · [Internal hooks](https://docs.openclaw.ai/automation/hooks) (surveyed, then ruled out above)
- [openclaw.ai](https://openclaw.ai/)
