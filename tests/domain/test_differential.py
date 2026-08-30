"""Seeded differential check: an independent SPEC reimplementation vs.
``domain/hashing.py`` over randomised ``EntryHeader``-shaped inputs.

Paper eval protocol item 1 (docs/paper/conformance.md section 4) asks for a
randomised differential sweep of 10**6 headers between the real
implementation and a reimplementation of SPEC.md prose that does not import
waxseal. ``tools/gen_vectors.py`` already IS that independent reimplementation
— it derives ``lp()`` and the header frame straight from SPEC.md sections 2-3
without touching ``waxseal.domain`` — but until now it only ran against the
fixed, frozen vector set (``tests/vectors/vectors.json``). This file reuses
that same independent implementation (imported by file path below, since
``tools/`` ships no ``__init__.py`` and is not a package) and drives it with
random headers instead.

Two-tier plan (bead waxseal-jsk, owner decision 2026-08-29): running the
paper's 10**6 iterations on every push/PR, across the CI matrix of 2 OSes x 4
Python versions (.github/workflows/ci.yml), is not the right cost to pay on
every commit. So:

  - DEFAULT_N below is what runs in the normal `pytest` suite, on every push
    and PR. It is a REDUCED bound from the paper's 10**6 — chosen to finish
    in well under a second per job while still being a real, seeded,
    reproducible differential sweep, not a token gesture. A silently lowered
    bound is exactly the "capped bound presented as the paper's bound" this
    project's engineering constitution forbids (CLAUDE.md, "fail-open must be
    labelled" / Ternary Evidence Principle) — hence this whole comment block,
    the print statement in the test below, and the conformance ledger row.
  - .github/workflows/differential-nightly.yml runs this SAME test function,
    same seed, with ``WAXSEAL_DIFFERENTIAL_N=1000000`` on a weekly schedule,
    delivering the paper's number in full without paying its cost on every
    push. Benchmarked locally at ~32s per 10**6 iterations (pure Python, no
    hashing shortcuts) — comfortably inside a CI job's time budget even on a
    slower runner.

Both tiers call the identical harness with a different N sourced from
``WAXSEAL_DIFFERENTIAL_N`` — one test function, not two divergent
implementations.
"""

from __future__ import annotations

import importlib.util
import os
import random
from pathlib import Path
from types import ModuleType

from waxseal.domain.hashing import compute_entry_hash
from waxseal.domain.header import EntryHeader

# The paper's number. Never edit this constant to make a shrunken run look
# like the real one — REDUCED_N below is where the honest, labelled cap lives.
PAPER_N = 1_000_000

# What runs on every `pytest` invocation (CI push/PR) unless overridden.
# Reduced from PAPER_N by 500x: see the module docstring for why that is a
# labelled reduction, not a silent one.
REDUCED_N = 2_000

SEED = 0xA5A5_1234  # fixed -> reproducible across local runs and CI

_TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def _load_gen_vectors() -> ModuleType:
    """Load tools/gen_vectors.py by path (tools/ has no __init__.py -- it
    ships as standalone scripts, run directly by CI, not as a package)."""
    spec = importlib.util.spec_from_file_location(
        "waxseal_differential_gen_vectors", _TOOLS_DIR / "gen_vectors.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen_vectors = _load_gen_vectors()


def _random_scalar_char(rng: random.Random) -> str:
    """One random valid Unicode scalar value, excluding the surrogate range
    (U+D800-U+DFFF has no UTF-8 form; a lone surrogate reaching ``str.encode``
    is a known, separately-tracked gap -- see docs/paper/conformance.md gap
    G4 -- and isn't what this differential sweep is measuring)."""
    codepoint = rng.randrange(0x110000 - 0x800)
    if codepoint >= 0xD800:
        codepoint += 0x800
    return chr(codepoint)


def _random_text(rng: random.Random, max_len: int = 48) -> str:
    length = rng.randrange(max_len + 1)
    return "".join(_random_scalar_char(rng) for _ in range(length))


def _random_header_dict(rng: random.Random) -> dict[str, object]:
    """One random EntryHeader-shaped dict: same six SPEC fields, arbitrary
    (including empty, non-ASCII, and non-hex-shaped) values -- the encoding
    frame is generic over field content, so this exercises it independent of
    any assumption that hash_version/payload_hash "look like" a sha256 hex
    digest."""
    return {
        "seq": rng.randrange(2**63),
        "ts": _random_text(rng),
        "hash_version": _random_text(rng),
        "payload_type": _random_text(rng),
        "payload_hash": _random_text(rng),
        "prev_hash": _random_text(rng),
    }


def _resolve_n() -> int:
    """WAXSEAL_DIFFERENTIAL_N overrides the default -- the scheduled nightly
    workflow sets it to PAPER_N; the normal test suite leaves it unset and
    gets REDUCED_N."""
    raw = os.environ.get("WAXSEAL_DIFFERENTIAL_N")
    return int(raw) if raw else REDUCED_N


def test_differential_reimplementation_matches_hashing() -> None:
    n = _resolve_n()
    # Explicitly logged per bead waxseal-jsk: a reduced N must never be a
    # silent cap. `pytest -s` (or CI's captured-output-on-failure) surfaces
    # this line.
    reduced_note = " (REDUCED from the paper's 10**6 -- see module docstring)"
    print(
        f"waxseal-jsk differential sweep: N={n}, seed={SEED:#x}"
        f"{reduced_note if n < PAPER_N else ' (== paper bound, scheduled run)'}"
    )
    rng = random.Random(SEED)
    for i in range(n):
        header_dict = _random_header_dict(rng)
        header = EntryHeader(**header_dict)  # type: ignore[arg-type]
        independent = gen_vectors.entry_hash(header_dict)
        real = compute_entry_hash(header)
        assert independent == real, (
            f"divergence at iteration {i}/{n} (seed={SEED:#x}): "
            f"independent={independent!r} real={real!r} header={header_dict!r}"
        )
