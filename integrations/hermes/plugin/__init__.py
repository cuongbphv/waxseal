"""waxseal-audit hermes plugin shim — the logic lives in
waxseal.integrations.hermes (shipped in the wheel). Prefer `waxseal install
hermes`, which writes this same shim; upgrade with `pip install -U waxseal`."""

from waxseal.integrations.hermes import (  # noqa: F401
    on_post_tool_call,
    on_pre_tool_call,
    register,
)
