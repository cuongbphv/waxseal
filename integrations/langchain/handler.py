"""waxseal-audit LangChain handler shim — the logic lives in
waxseal.integrations.langchain (shipped in the wheel). Import from there
directly; this file exists so older copy-this-file instructions keep working."""

from waxseal.integrations.langchain import WaxsealCallbackHandler  # noqa: F401
