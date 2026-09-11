# waxseal self-hosted server: the wheel, the server app, and the built web UI.
#
# Build context is the REPOSITORY ROOT, not server/ — the image installs waxseal
# from source in this tree rather than from PyPI, so the server and the library
# it verifies with are always the same commit. A published wheel and a server
# built from a different commit is exactly the drift the CLI-as-contract split
# exists to avoid.
#
#   docker build -f server/Dockerfile -t waxseal-server .

# ---- stage 1: the web UI -----------------------------------------------------
FROM node:24-alpine AS web
WORKDIR /src
COPY server/web/package.json server/web/package-lock.json* server/web/
RUN cd server/web && npm ci
COPY server/web server/web
# Vite's outDir is ../waxseal_server/static, so this writes to
# /src/server/waxseal_server/static.
RUN cd server/web && npm run build

# ---- stage 2: the server's dependency set, FROM THE LOCK ----------------------
# `pip install ./server` resolved FastAPI/uvicorn/psycopg from the floors in
# pyproject at build time, so the image shipped a dependency set nobody had
# audited: CI's pip-audit runs against server/uv.lock, and the two only agreed
# by luck. Export the lock (with hashes) here and install exactly that below.
# `waxseal` is a path source (`..`) installed from this tree in the runtime
# stage, so it is left out of the export.
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS lock
WORKDIR /app
COPY pyproject.toml ./
COPY server/pyproject.toml server/uv.lock ./server/
RUN cd server && uv export --frozen --no-dev --no-emit-project --no-emit-package waxseal \
      --format requirements-txt -o /requirements.txt

# ---- stage 3: the runtime ----------------------------------------------------
FROM python:3.14-slim AS runtime

# The server shells out to `python -m waxseal.cli` for every read; it needs no
# compiler, no git, and no shell utilities beyond what the base image carries.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WAXSEAL_SERVER_DATA_DIR=/var/lib/waxseal

WORKDIR /app

# The library first: zero runtime dependencies, so this layer is tiny and stable.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Then the application, which is allowed its own dependencies (FastAPI, uvicorn)
# because it is never packaged into the waxseal wheel. The dependencies come
# from the lock export (hash-checked); the application itself with --no-deps,
# so pip cannot widen the set behind the lock's back.
COPY --from=lock /requirements.txt /tmp/server-requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/server-requirements.txt \
 && rm /tmp/server-requirements.txt
COPY server/pyproject.toml server/README.md ./server/
COPY server/waxseal_server ./server/waxseal_server
COPY --from=web /src/server/waxseal_server/static ./server/waxseal_server/static
RUN pip install --no-cache-dir --no-deps ./server

# Runs unprivileged. The data volume is the only writable path it needs, and an
# imported trail is chmod'd read-only the moment it lands.
RUN useradd --system --create-home --uid 10001 waxseal \
 && mkdir -p /var/lib/waxseal \
 && chown -R waxseal:waxseal /var/lib/waxseal
USER waxseal

VOLUME ["/var/lib/waxseal"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

CMD ["python", "-m", "waxseal_server"]
