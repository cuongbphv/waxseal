# Runs the exact commands .github/workflows/ci.yml runs, in a clean container —
# a `docker build` that reaches the final stage IS the 100%-pass proof, not a
# side claim about it (CLAUDE.md: "all green + coverage floor before any
# 'done' claim").
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim

WORKDIR /app

# Whole tree, not a cherry-picked subset: tests reach for repo-root files
# outside src/tests (integrations/ shim sources, SPEC.md, README*.md) the
# same way `actions/checkout` gives ci.yml the full checkout — a partial
# COPY list silently diverges from what CI actually verifies.
COPY . .

# --frozen: fail on a stale/missing uv.lock rather than silently re-resolving —
# the lock committed to the repo is the one under test.
RUN uv sync --extra dev --frozen

# Same three commands as ci.yml, same order. A failure here fails the build.
RUN uv run --extra dev pytest --cov=waxseal
RUN uv run --extra dev mypy
RUN uv run --extra dev ruff check .
