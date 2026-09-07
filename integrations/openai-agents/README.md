# waxseal-audit - OpenAI Agents SDK integration

Tamper-evident audit trail as a RunHooks implementation for the OpenAI Agents SDK
(pip `openai-agents`, import `agents`). Verified against the official docs
(openai.github.io/openai-agents-python, /ref/lifecycle, 2026-08-21).

Tool calls (dispatch + result), agent start/end, and handoffs are appended to a
hash chain (default `~/.waxseal/openai-agents-trail.jsonl`). Secrets are
redacted **before** hashing and storage.

## Install

```bash
pip install waxseal openai-agents
# no file to copy - the hooks ship in the wheel:
#   from waxseal.integrations.openai_agents import WaxsealRunHooks
```

Attach per run:

```python
from agents import Runner
from waxseal_hooks import WaxsealRunHooks

audit = WaxsealRunHooks("~/.waxseal/openai-agents-trail.jsonl")
result = await Runner.run(agent, "input", hooks=audit)
```

## Verify anytime

```bash
waxseal verify ~/.waxseal/openai-agents-trail.jsonl
# exit 0 intact / 1 broken (prints first bad seq) / 2 unverifiable rows present
```

## Design notes

- The SDK awaits hooks inline and does not promise to swallow exceptions - a raise
  inside a hook can abort the user's run. Every failure path here degrades to a
  labelled, counted dropped write on stderr (chain integrity ≠ trail completeness).
- Tool *input* is not a hook parameter: for function tools it is read from the
  ToolContext (`tool_name`, `tool_call_id`, `tool_arguments`); other tool families
  pass a plain context and those fields are recorded as absent, with `tool.name`
  as the fallback - absent is never faked as empty.
- **Redact-before-hash**: cleartext keys in tool arguments never touch this trail.
- Dispatch is recorded in `on_tool_start`, before execution - an attempt that
  kills the process is still on the chain.

## End-to-end demo

`e2e_demo.py` exercises the hooks with REAL SDK objects - a real `Agent`, a
real `@function_tool`, and a real `ToolContext` (the context Runner passes to
function-tool hooks) - then replays 4 attack/failure scenarios (edit, delete,
schema skew, secret leakage). A full `Runner.run` needs a model provider and
API key, so the demo awaits the hook coroutines directly with the same objects
Runner would pass:

```bash
python e2e_demo.py   # needs waxseal + openai-agents installed
```
