# waxseal-audit — hermes-agent integration

Tamper-evident audit trail for [hermes-agent](https://github.com/NousResearch/hermes-agent),
addressing issue #487 (action-focused, chain-linked audit log). Verified against
hermes-agent **v2026.8.18** source. waxseal is on
[PyPI](https://pypi.org/project/waxseal/) (stdlib-only, zero runtime dependencies).

## hermes-agent issues this addresses

Built for [#487](https://github.com/NousResearch/hermes-agent/issues/487), closed
2026-05-05 with the maintainer direction: no core changes — the plugin hooks are the
integration seam. The same need recurs in open issues:

| Issue | Ask | What this integration provides |
|---|---|---|
| [#1155](https://github.com/NousResearch/hermes-agent/issues/1155) | Structured, persistent audit log of every tool call (redacted args, per-session correlation, cron-monitorable) | Two chained JSONL entries per tool call (`dispatch` + `result`) carrying `session_id`/`task_id`/`tool_call_id`/`turn_id`; secrets redacted before hashing; `waxseal verify` exit codes are cron-alertable |
| [#5041](https://github.com/NousResearch/hermes-agent/issues/5041) | Cryptographic audit trail for tool calls | SHA-256 hash chain over a canonical byte encoding, offline verification — without wrapping the hermes process (no Node, no MCP gateway). No signatures/policy engine (see limits below) |
| [#26201](https://github.com/NousResearch/hermes-agent/issues/26201) | Hash-chain tamper protection with a JSONL backend | The chain layer, including schema-version fingerprints: rows written by a newer schema report "unverifiable", never "tampered", after a rollback |

The plugin's default is the plain hash chain. At the library level waxseal also has
opt-in forward-secure HMAC sealing (`.attest` sidecar: evolving epoch key, detects
truncate-and-rewrite) and a `Signer` protocol for injected digital signatures — but it
bundles **no** signature algorithm and no automatic external anchoring; see
"What it guarantees (and what it does not)" below.

hermes-agent has two extension systems, and they cover different ground:

| | **Plugin** (`plugin/`) | **Legacy gateway hook** (`HOOK.yaml` + `handler.py`) |
|---|---|---|
| Mechanism | `~/.hermes/plugins/` + `register(ctx)` (`hermes_cli/plugins.py`) | `~/.hermes/hooks/` + `handle(event_type, context)` (`gateway/hooks.py`) |
| Fires on | `pre_tool_call` / `post_tool_call` — every tool dispatch in `model_tools.handle_function_call` | `session:*`, `agent:*`, `command:*`, `gateway:startup` |
| Surfaces | CLI, gateway, batch — anything dispatching tools | **gateway process only** |
| Granularity | per tool call: name, args, result, status, duration, `tool_call_id` | per lifecycle event / loop iteration (`agent:step` carries `iteration` + previous tools, not args at dispatch) |
| What #487 asked for | ✅ this | context only |

Both write to the same chain (`<hermes home>/audit/trail.jsonl`); waxseal's
locked append keeps concurrent writers fork-free. Install the plugin; add the
gateway hook if you also want session/gateway lifecycle context.

## Install — plugin (recommended)

Everything comes from PyPI — no checkout, no file copying:

```bash
pip install waxseal                   # in the environment running hermes
waxseal install hermes                # writes ~/.hermes/plugins/waxseal-audit/
hermes plugins enable waxseal-audit   # standalone plugins are opt-in
```

The installed files are thin shims importing `waxseal.integrations.hermes`,
so `pip install -U waxseal` upgrades the hook without re-running install.
(No pip? The same two files can be copied from this directory:
`plugin/plugin.yaml` and `plugin/__init__.py`.)

Every tool call then produces two chained entries: `phase: dispatch`
(before execution — an attempt that kills the process is still recorded) and
`phase: result` (status, duration, error, clipped result).

## Install — legacy gateway hook (optional, lifecycle context)

```bash
waxseal install hermes-gateway        # writes ~/.hermes/hooks/waxseal-audit/
```

The gateway discovers it on next startup (`[hooks] Loaded hook 'waxseal-audit' ...`).
Note: these events fire **only in the gateway process** — CLI runs won't emit them.

## Verify anytime

```bash
waxseal verify ~/.hermes/audit/trail.jsonl
# exit 0 intact / 1 broken / 2 unverifiable rows present (unknown newer schema
#   — e.g. after a version rollback; NOT evidence of tampering)
waxseal tail  ~/.hermes/audit/trail.jsonl -n 20
```

## What it guarantees (and what it does not)

- Any edit, deletion, insertion, or reordering of past entries is detected
  with the exact breaking sequence number.
- Secrets in tool args/results are redacted **before** hashing and storage
  (#487's stated risk); large results are clipped with a visible
  `…[truncated N chars]` marker, never silently.
- Rows written by a newer waxseal schema stay readable after a rollback:
  they are reported "unverifiable by name", never as tampering, never a crash.
- Neither integration can block the pipeline: every failure path degrades to
  a counted, printed dropped write (chain integrity ≠ trail completeness).
  The plugin's `pre_tool_call` always returns `None` — hermes parses dict
  returns as block/approve directives, and an audit observer must never veto
  a tool call.
- Tamper-*evident*, not tamper-*proof*: an attacker with write access can
  rewrite the whole trail suffix. Anchor the latest `entry_hash` elsewhere
  (`waxseal head`, periodic off-host copy) if you need stronger guarantees.

## End-to-end demo

`e2e_demo.py` drives the REAL `gateway.hooks.HookRegistry` from an installed
hermes-agent and replays 4 attack/failure scenarios (edit, delete, schema
skew, secret leakage):

```bash
python e2e_demo.py   # needs hermes-agent + waxseal installed
```
