#!/usr/bin/env python3
"""waxseal-audit hook shim — the logic lives in waxseal.integrations.cursor
(shipped in the wheel). Prefer `waxseal install cursor`, which writes this
same shim; upgrade behavior with `pip install -U waxseal`."""

import sys

try:
    from waxseal.integrations.cursor import main
except Exception as e:
    # Exit 0 even here: a missing waxseal must never veto the host's work,
    # and the degradation is labelled on stderr, never silent.
    print(f"[waxseal-audit] waxseal not importable (entry dropped): {e}", file=sys.stderr)
    sys.exit(0)

sys.exit(main())
