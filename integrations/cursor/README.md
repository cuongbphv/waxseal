# waxseal-audit — Cursor integration

Tamper-evident audit trail for Cursor's Agent Hooks. Verified against
https://cursor.com/docs/hooks (2026-08-21; hooks shipped in Cursor 1.7).

Shell commands, MCP tool calls, file edits, prompts, and stop events are appended
to a hash chain at `~/.cursor/waxseal/trails/<slug>/trail.00000.jsonl` (override the location with
`WAXSEAL_TRAIL`). Secrets are redacted **before** hashing and storage — including
a key the agent writes into a file, which arrives here inside the
`afterFileEdit` diff.

Trails are **routed per project** (SPEC.md section 20): the project key is the
hook event's `cwd`, so two projects never braid their histories into one file.
The active segment is rolled over into a new sealed segment once it passes
16 MiB, and the segments are linked by a rotation binding at each new
segment's `seq` 0 — never by `prev_hash` across a file boundary.

```bash
waxseal segments ~/.cursor/waxseal/trails/<slug>          # every segment + its binding
waxseal verify   ~/.cursor/waxseal/trails/<slug>/trail.00000.jsonl   # one segment
```

`waxseal segments` exits 0 intact / 1 broken / 2 unverifiable-present / 3
nothing read. `WAXSEAL_TRAIL` still overrides the LOCATION, and is not a
rotation off-switch: a trail named through it rotates too, and on its first
rotation it is adopted as the base segment. A pre-0.1.5
`~/.cursor/waxseal/trail.jsonl` is neither migrated nor sealed — it stops receiving
appends and keeps verifying with plain `waxseal verify`.

Cursor sends `cwd` on the shell events and `workspace_roots` on the others, so
the first workspace root is the project key when there is no `cwd`.

## Install

```bash
pip install waxseal
waxseal install cursor    # writes ~/.cursor/hooks/waxseal_hook.py and prints the config below
```

Then add to `~/.cursor/hooks.json` (or a project's `.cursor/hooks.json`):

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{ "command": "python3 ~/.cursor/hooks/waxseal_hook.py" }],
    "afterShellExecution":  [{ "command": "python3 ~/.cursor/hooks/waxseal_hook.py" }],
    "beforeMCPExecution":   [{ "command": "python3 ~/.cursor/hooks/waxseal_hook.py" }],
    "afterFileEdit":        [{ "command": "python3 ~/.cursor/hooks/waxseal_hook.py" }],
    "beforeSubmitPrompt":   [{ "command": "python3 ~/.cursor/hooks/waxseal_hook.py" }],
    "stop":                 [{ "command": "python3 ~/.cursor/hooks/waxseal_hook.py" }]
  }
}
```

## Verify anytime

```bash
waxseal verify ~/.cursor/waxseal/trails/<slug>/trail.00000.jsonl
# exit 0 intact / 1 broken (prints first bad seq) / 2 unverifiable rows present
```

## Design notes

- **Exit 0 + empty stdout on every path.** Exit code 2 is a deny; `before*` events
  parse stdout for permission/continue decisions, and even printing an explicit
  "allow" could override a real policy hook. The audit observer never speaks there.
  Failures degrade to a labelled stderr notice (chain integrity ≠ trail
  completeness).
- `beforeReadFile`'s full file content is deliberately NOT recorded — the trail
  records actions, not a copy of the workspace.
- **Redact-before-hash**: cleartext keys never touch this trail.
- Large shell outputs are clipped with a visible `…[truncated N chars]` marker.

## End-to-end demo

`e2e_demo.py` drives the shipped hook exactly the way the host runs it (a
subprocess per event, JSON on stdin) and replays 4 attack/failure scenarios
(edit, delete, schema skew, secret leakage):

```bash
python e2e_demo.py   # needs only waxseal installed
```
