"""Audit hooks for agent frameworks, shipped in the wheel.

Import the submodule for your host directly (e.g.
``from waxseal.integrations.langchain import WaxsealCallbackHandler``).
This package must stay side-effect free and must never be imported by
``waxseal/__init__.py``: the langchain/crewai/openai_agents modules import
their host framework at module level, and a user who never asked for that
host must never pay for — or crash on — it.
"""
