# waxseal-audit — Codex CLI integration

Tamper-evident audit trail for OpenAI Codex CLI via its lifecycle hooks system.
Verified against the openai/codex source at rust-v0.149.0 (2026-08-21) — the hooks
schema lives in `codex-rs/hooks/src/schema.rs`.

Every tool dispatch (PreToolUse), tool result (PostToolUse), and user prompt
(UserPromptSubmit) is appended to a hash chain at
`$CODEX_HOME/waxseal/trail.jsonl` (default `~/.codex/waxseal/trail.jsonl`,
override with `WAXSEAL_TRAIL`). Secrets are redacted **before** hashing and
storage.

> Do not confuse this with the legacy `notify` config: `notify` fires one
> `agent-turn-complete` event per turn with no tool data — too weak for auditing.
> The hooks below are per tool call, with `tool_input` (including the shell
> command) and `tool_response` on stdin.

## Install

```bash
pip install waxseal
waxseal install codex    # writes ~/.codex/hooks/waxseal_hook.py and prints the config below
```

Then add to `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse":       [{ "hooks": [{ "type": "command", "command": "python3 ~/.codex/hooks/waxseal_hook.py" }] }],
    "PostToolUse":      [{ "hooks": [{ "type": "command", "command": "python3 ~/.codex/hooks/waxseal_hook.py" }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "python3 ~/.codex/hooks/waxseal_hook.py" }] }]
  }
}
```

(or the equivalent `[[hooks.PreToolUse]]` tables in `config.toml`). Codex requires a
one-time trust approval for non-managed command hooks via the `/hooks` command.

## Verify anytime

```bash
waxseal verify ~/.codex/waxseal/trail.jsonl
# exit 0 intact / 1 broken (prints first bad seq) / 2 unverifiable rows present
```

## Design notes

- **Exit 0 on every path.** Exit code 2 blocks the tool call, and stdout is parsed
  as decision JSON (`decision`, `continue`, `updatedInput`) — the audit hook stays
  silent on stdout and never vetoes work. Failures degrade to a labelled stderr
  notice (chain integrity ≠ trail completeness).
- **Redact-before-hash**: cleartext keys never touch this trail; verification still
  passes because the hash commits to the redacted payload.
- Large tool responses are clipped with a visible `…[truncated N chars]` marker.
- A killed or skipped hook is a missing record with no seq gap — that is exactly
  why `dropped_writes` is reported separately from chain integrity.

## End-to-end demo

`e2e_demo.py` drives the shipped hook exactly the way the host runs it (a
subprocess per event, JSON on stdin) and replays 4 attack/failure scenarios
(edit, delete, schema skew, secret leakage):

```bash
python e2e_demo.py   # needs only waxseal installed
```
