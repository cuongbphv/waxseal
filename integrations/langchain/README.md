# waxseal-audit - LangChain / LangGraph integration

Tamper-evident audit trail as a LangChain callback handler. Verified against
langchain-core 1.6.0 (installed source, 2026-08-21).

Tool dispatches, results, errors, and agent decisions are appended to a hash chain
(default `~/.waxseal/langchain-trail.jsonl`). Secrets are redacted **before**
hashing and storage.

## Install

```bash
pip install waxseal langchain-core
# no file to copy - the handler ships in the wheel:
#   from waxseal.integrations.langchain import WaxsealCallbackHandler
```

Attach at invoke time so the handler inherits down to tool runs (constructor-scoped
callbacks do not propagate to children):

```python
from waxseal_handler import WaxsealCallbackHandler

audit = WaxsealCallbackHandler("~/.waxseal/langchain-trail.jsonl")
agent.invoke(input, config={"callbacks": [audit]})     # also works for LangGraph graphs
```

## Verify anytime

```bash
waxseal verify ~/.waxseal/langchain-trail.jsonl
# exit 0 intact / 1 broken (prints first bad seq) / 2 unverifiable rows present
```

## Design notes

- **`raise_error` stays False**: LangChain's callback manager re-raises handler
  exceptions only when that flag is set, and a broken audit disk must never abort
  the user's run. But LangChain's default swallow is *silent* - so every failure
  path here labels its own dropped write on stderr and counts it
  (chain integrity ≠ trail completeness).
- `on_tool_end`'s `output` is `Any` in langchain-core ≥ 1.x (it was `str` in old
  versions); structured ToolMessage outputs are recorded, sanitized and clipped.
- **Redact-before-hash**: cleartext keys never touch this trail.
- Dispatch is recorded in `on_tool_start`, before execution - an attempt that
  kills the process is still on the chain.

## End-to-end demo

`e2e_demo.py` drives the handler through the REAL langchain-core callback
manager (a real `@tool` invoked with `config={"callbacks": [...]}`, no LLM or
API key needed) and replays 4 attack/failure scenarios (edit, delete, schema
skew, secret leakage):

```bash
python e2e_demo.py   # needs waxseal + langchain-core installed
```
