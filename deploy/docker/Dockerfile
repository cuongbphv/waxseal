# The waxseal CLI as a runtime image → ghcr.io/cuongbphv/waxseal
#
# Build context is the REPOSITORY ROOT, not deploy/docker/ — the wheel is built
# from this tree, so the image and the library it verifies with are the same
# commit. Same reason server/Dockerfile does it.
#
#   docker build -f deploy/docker/Dockerfile -t ghcr.io/cuongbphv/waxseal:dev .
#
# Not to be confused with the repository-root `Dockerfile`, which is the CI
# proof (`pytest --cov` + `mypy` + `ruff` in a clean container) and has no
# ENTRYPOINT on purpose. This file is the only runtime image of the CLI.

# ---- stage 1: the wheel ------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS build

WORKDIR /src

# Only what the wheel target needs (pyproject's packages = ["src/waxseal"],
# readme = README.md). Not the whole tree: a wheel built from a narrow copy
# list cannot pick up a stray file, and the layer stays stable across every
# commit that touches tests, docs or server/.
COPY pyproject.toml README.md ./
COPY src ./src

RUN uv build --wheel --out-dir /wheels

# ---- stage 2: the runtime ----------------------------------------------------
FROM python:3.13-slim AS runtime

# Optional extras, off by default. The default image is therefore stdlib-only:
# `cryptography` (the rfc3161 extra) and `boto3` (s3) stay OUT of it, so the
# image an operator gets without asking carries the same zero-dependency
# surface CLAUDE.md rule 1 pins for the wheel. An operator who wants the
# RFC 3161 signature dimension (`--tsa-ca-file`) or the S3 archive backend
# names it and accepts the dependency:
#
#   docker build -f deploy/docker/Dockerfile --build-arg EXTRAS=rfc3161 .
#   docker build -f deploy/docker/Dockerfile --build-arg EXTRAS=rfc3161,s3 .
ARG EXTRAS=""

ARG VERSION="0.0.0.dev0"
ARG REVISION="unknown"

LABEL org.opencontainers.image.title="waxseal" \
      org.opencontainers.image.description="Tamper-evident, schema-evolution-safe audit hash chain for AI agent frameworks." \
      org.opencontainers.image.source="https://github.com/cuongbphv/waxseal" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Deliberately NOT setting WAXSEAL_TRAIL. Every CLI verb takes the trail as a
# positional argument; that variable aims the agent-framework HOOKS, and a
# default baked into an image would point every `waxseal install`-ed writer in
# a container at a path the image author chose. src/waxseal/integrations/
# _trail.py owns that precedence chain, and it is not this image's to pre-empt.

COPY --from=build /wheels/*.whl /tmp/

# --no-deps in the no-extras case is honest rather than a shortcut: the wheel
# declares no dependencies, so there is nothing for pip to resolve and nothing
# it could quietly skip. With EXTRAS named, deps are exactly the point, so the
# flag comes off — an extra installed --no-deps would give the operator the
# import site and not the library behind it, which is the failure the extras'
# guarded ImportErrors already report as `signature_unchecked`/`worm_unknown`.
#
# Rejected: distroless (gcr.io/distroless/python3). It pins an older Python
# than this base and ships no shell, so an operator debugging a trail inside
# the container has no `ls` to find it with. The wheel is pure Python and needs
# no build toolchain, so slim already carries no compiler — distroless would
# buy a smaller attack surface and little else. Worth revisiting as a second,
# explicitly-tagged image; it is a follow-up, not a mistake made here.
RUN set -eu; \
    whl="$(ls /tmp/waxseal-*.whl)"; \
    if [ -z "$EXTRAS" ]; then \
      pip install --no-cache-dir --no-deps "$whl"; \
    else \
      pip install --no-cache-dir "${whl}[${EXTRAS}]"; \
    fi; \
    rm -f /tmp/waxseal-*.whl

# uid 10001 matches server/Dockerfile so a volume shared between the server and
# a CLI sidecar (an `anchor` CronJob beside the chain, say) has one owner and
# needs no chown dance between them.
RUN useradd --system --uid 10001 waxseal \
 && mkdir -p /data \
 && chown waxseal:waxseal /data
USER 10001

# Runs correctly under `docker run --read-only`: nothing outside /data and an
# operator-mounted `--pin` path is ever written. PYTHONDONTWRITEBYTECODE keeps
# the interpreter from trying to drop __pycache__ into site-packages, which is
# the one thing a read-only rootfs would otherwise turn into a warning nobody
# reads.
WORKDIR /data
VOLUME ["/data"]

# The verbs are the interface (docs/architecture/deployment.md §4 — "Exit codes
# are the interface"): 0 intact, 1 broken, 2 intact-but-unverifiable, 3 the path
# does not exist. ENTRYPOINT keeps those codes coming from waxseal itself rather
# than from a shell wrapper that would flatten them.
ENTRYPOINT ["waxseal"]
CMD ["--help"]
