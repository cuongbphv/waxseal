"""waxseal-audit hermes gateway hook shim — the logic lives in
waxseal.integrations.hermes_gateway (shipped in the wheel). Prefer `waxseal
install hermes-gateway`, which writes this same shim."""

from waxseal.integrations.hermes_gateway import handle  # noqa: F401
