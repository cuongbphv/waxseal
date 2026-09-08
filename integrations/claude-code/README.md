# waxseal-audit - Claude Code integration

Tamper-evident audit trail for [Claude Code](https://code.claude.com) via its hooks
system. Verified against the official hooks reference
(code.claude.com/docs/en/hooks, 2026-08).

Every tool dispatch (PreToolUse), tool result (PostToolUse), user prompt
(UserPromptSubmit), and session lifecycle event is appended to a hash chain at
`~/.claude/waxseal/trails/<slug>/trail.00000.jsonl` (override the location with
`WAXSEAL_TRAIL`). Secrets - API keys, git tokens, JWTs, private keys - are
redacted **before** hashing and storage.

Trails are **routed per project** (SPEC.md section 20): the project key is the
hook event's `cwd`, so two projects never braid their histories into one file.
The active segment is rolled over into a new sealed segment once it passes
16 MiB, and the segments are linked by a rotation binding at each new
segment's `seq` 0 - never by `prev_hash` across a file boundary.

```bash
waxseal segments ~/.claude/waxseal/trails/<slug>          # every segment + its binding
waxseal verify   ~/.claude/waxseal/trails/<slug>/trail.00000.jsonl   # one segment
```

`waxseal segments` exits 0 intact / 1 broken / 2 unverifiable-present / 3
nothing read. `WAXSEAL_TRAIL` still overrides the LOCATION, and is not a
rotation off-switch: a trail named through it rotates too, and on its first
rotation it is adopted as the base segment. A pre-0.1.5
`~/.claude/waxseal/trail.jsonl` is neither migrated nor sealed - it stops receiving
appends and keeps verifying with plain `waxseal verify`.

## Why this exists

The incident class: the agent leaks a key into a command or the user pastes one into
the chat; the key is now in a transcript file that cannot be safely edited. Be precise
about what this hook does and does not fix:

- **It does not scrub Claude Code's own transcript** (`~/.claude/projects/**/*.jsonl`).
  That file is written by Claude Code itself; no hook can rewrite it.
- **It gives you a parallel audit trail where the leak never lands in cleartext**:
  every action is recorded with secrets already redacted, and the chain proves the
  record has not been edited after the fact - including by an agent trying to cover
  its tracks.

## Install

```bash
pip install waxseal          # in a Python >= 3.11 the hook can run under
waxseal install claude-code    # writes ~/.claude/hooks/waxseal_hook.py and prints the config below
```

Then add to `~/.claude/settings.json` (or a project's `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse":       [{ "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/waxseal_hook.py" }] }],
    "PostToolUse":      [{ "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/waxseal_hook.py" }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/waxseal_hook.py" }] }]
  }
}
```

## Verify anytime

```bash
waxseal verify ~/.claude/waxseal/trails/<slug>/trail.00000.jsonl
# exit 0 intact / 1 broken (prints first bad seq) / 2 unverifiable rows present
waxseal tail ~/.claude/waxseal/trails/<slug>/trail.00000.jsonl -n 20
```

## Design notes (why the hook behaves the way it does)

- **Exit 0 on every path, including its own failures.** Exit 2 BLOCKS the tool call
  (PreToolUse) or the prompt (UserPromptSubmit) - a broken audit disk must never veto
  the user's work. Failures degrade to a labelled stderr notice and a counted dropped
  write (chain integrity ≠ trail completeness).
- **Never writes to stdout.** On UserPromptSubmit, exit-0 stdout is injected into
  model context; elsewhere it is parsed for decision JSON. An audit observer stays
  silent there.
- **Redact-before-hash.** The hash commits to the redacted payload, so verification
  passes while cleartext never touches this trail.
- Large tool outputs are clipped with a visible `…[truncated N chars]` marker, never
  silently.
- Tamper-*evident*, not tamper-*proof*: anchor the head elsewhere
  (`waxseal head`) if you need protection against full-suffix rewrites.

## End-to-end demo

`e2e_demo.py` drives the shipped hook exactly the way the host runs it (a
subprocess per event, JSON on stdin) and replays 4 attack/failure scenarios
(edit, delete, schema skew, secret leakage):

```bash
python e2e_demo.py   # needs only waxseal installed
```
