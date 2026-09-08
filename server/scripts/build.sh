#!/usr/bin/env bash
# Build everything: backend deps, frontend bundle, and optionally the image.
#
#   ./scripts/build.sh              backend + frontend
#   ./scripts/build.sh --docker     also build the Docker image
#   ./scripts/build.sh --check      also run tests, coverage, mypy and typecheck
#   ./scripts/build.sh --frontend   frontend only
#   ./scripts/build.sh --backend    backend only
#
# The frontend build writes into `waxseal_server/static`, which is where the
# FastAPI app mounts it. That directory is gitignored: it is a build artifact,
# and the Docker image builds its own copy in a separate stage rather than
# copying whatever happened to be on the developer's disk.

# shellcheck source=_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

DO_BACKEND=1 DO_FRONTEND=1 DO_DOCKER=0 DO_CHECK=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker)   DO_DOCKER=1 ;;
    --check)    DO_CHECK=1 ;;
    --frontend) DO_BACKEND=0 ;;
    --backend)  DO_FRONTEND=0 ;;
    -h|--help)  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)          die "unknown flag $1 (try --help)" ;;
  esac
  shift
done

if (( DO_BACKEND )); then
  step "Backend dependencies"
  need uv "install from https://docs.astral.sh/uv/"
  # `--extra dev` so the check step below has pytest and mypy without a second
  # resolve. The wheel's own dependency list stays empty (CLAUDE.md rule 1);
  # this is the SERVER's stack, which is a separate distribution.
  ( cd "$SERVER_DIR" && uv sync --extra dev )
  info "venv: $SERVER_DIR/.venv"
fi

if (( DO_FRONTEND )); then
  step "Frontend bundle"
  need npm
  # `npm ci` when there is a lockfile: it installs exactly what is pinned, so a
  # build here and a build in the Docker stage cannot resolve differently.
  if [[ -f "$WEB_DIR/package-lock.json" ]]; then
    ( cd "$WEB_DIR" && npm ci --no-audit --no-fund )
  else
    ( cd "$WEB_DIR" && npm install --no-audit --no-fund )
  fi
  ( cd "$WEB_DIR" && npm run build )
  index="$SERVER_DIR/waxseal_server/static/index.html"
  [[ -f "$index" ]] || die "the build produced no $index"
  info "bundle: $SERVER_DIR/waxseal_server/static"
fi

if (( DO_CHECK )); then
  step "Checks"
  py="$(server_python)"
  info "pytest + coverage floor"
  ( cd "$SERVER_DIR" && $py -m pytest --cov=waxseal_server -q )
  info "mypy (strict)"
  ( cd "$SERVER_DIR" && $py -m mypy )
  info "vue-tsc"
  ( cd "$WEB_DIR" && npx vue-tsc --noEmit )
fi

if (( DO_DOCKER )); then
  step "Docker image"
  need docker
  # Built from the repository root so the image installs waxseal from THIS tree.
  # A server verifying with a different commit's library is a server whose
  # verdicts belong to code nobody reviewed together.
  ( cd "$REPO_ROOT" && docker compose -f server/docker-compose.yml build )
fi

step "Done"
