"""waxseal-audit OpenAI Agents SDK hooks shim — the logic lives in
waxseal.integrations.openai_agents (shipped in the wheel). Import from there
directly; this file exists so older copy-this-file instructions keep working."""

from waxseal.integrations.openai_agents import WaxsealRunHooks  # noqa: F401
