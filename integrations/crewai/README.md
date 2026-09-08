# waxseal-audit - CrewAI integration

Tamper-evident audit trail as a CrewAI event listener. Verified against
crewai 1.15.17 (PyPI wheel source, 2026-08-21).

Tool usage (started / finished / error), task lifecycle, and crew kickoff events
are appended to a hash chain (default `~/.waxseal/crewai-trail.jsonl`). Secrets
are redacted **before** hashing and storage.

## Install

```bash
pip install waxseal crewai
# no file to copy - the listener ships in the wheel:
#   from waxseal.integrations.crewai import WaxsealEventListener
```

Instantiate once at your entry point (crew.py / main.py / flow.py) and keep the
reference alive - CrewAI's event bus is a global singleton and
`BaseEventListener.__init__` registers on it, so **construction is the
registration**:

```python
from waxseal_listener import WaxsealEventListener

audit = WaxsealEventListener("~/.waxseal/crewai-trail.jsonl")
# ... build and kickoff your crew as usual
```

> Note: this imports from `crewai.events` (crewai ≥ 1.0). The pre-1.0
> `crewai.utilities.events` path no longer exists.

## Verify anytime

```bash
waxseal verify ~/.waxseal/crewai-trail.jsonl
# exit 0 intact / 1 broken (prints first bad seq) / 2 unverifiable rows present
```

## Design notes

- CrewAI's bus wraps handlers in try/except and only prints failures - a raise
  inside a listener is a **silently** dropped audit record. Every failure path
  here instead degrades to a labelled, counted dropped write on stderr
  (chain integrity ≠ trail completeness).
- Events carry live agent/task/crew objects; those are deliberately not recorded -
  the trail keeps the curated audit fields (tool_name, tool_args, agent_role,
  task_id, output, error, …), sanitized and clipped.
- **Redact-before-hash**: cleartext keys in tool args never touch this trail.

## End-to-end demo

`e2e_demo.py` registers the listener on the REAL global CrewAI event bus and
emits real tool/task/crew events through it (no LLM or API key needed), then
replays 4 attack/failure scenarios (edit, delete, schema skew, secret
leakage):

```bash
python e2e_demo.py   # needs waxseal + crewai installed
```
