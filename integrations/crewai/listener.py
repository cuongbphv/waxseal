"""waxseal-audit CrewAI listener shim — the logic lives in
waxseal.integrations.crewai (shipped in the wheel). Import from there
directly; this file exists so older copy-this-file instructions keep working."""

from waxseal.integrations.crewai import WaxsealEventListener  # noqa: F401
