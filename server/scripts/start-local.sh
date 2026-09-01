#!/usr/bin/env bash
# Run the server on this machine, no Docker.
#
#   ./scripts/start-local.sh                     port 8000, data in ./.local-data
#   ./scripts/start-local.sh --port 8080
#   ./scripts/start-local.sh --data /tmp/wx
#   ./scripts/start-local.sh --demo              seed a demo chain first
#   ./scripts/start-local.sh --reload            reload on source change
#
# NO DATABASE by default, and it says so: the operator and settings stores fall
# back to memory and forget everything on restart. That is a dev convenience,
# never a deployment — `GET /v1/settings` reports which backend is in use so a
# setting that vanished has its reason on screen.
#
# Credentials come only from the environment (REMOTE.md section 5): export
# WAXSEAL_API_KEY before running if you want the server closed. Unset means OPEN
# and the portal says so, because a fail-open that describes itself as secured is
# the failure this project exists to prevent.

source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

PORT=8000
DATA_DIR="$SERVER_DIR/.local-data"
DEMO=0
RELOAD=()  # expanded with ${a[@]+...} below: bash 3.2 + set -u

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)   PORT="${2:?--port needs a value}"; shift ;;
    --data)   DATA_DIR="${2:?--data needs a value}"; shift ;;
    --demo)   DEMO=1 ;;
    --reload) RELOAD=(--reload --reload-dir "$SERVER_DIR/waxseal_server") ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag $1 (try --help)" ;;
  esac
  shift
done

py="$(server_python)"

if [[ ! -f "$SERVER_DIR/waxseal_server/static/index.html" ]]; then
  info "no frontend bundle — serving the API only."
  info "run ./scripts/build.sh --frontend to build the portal."
fi

mkdir -p "$DATA_DIR"

if (( DEMO )); then
  step "Demo chain"
  "$SERVER_DIR/scripts/seed-demo.sh" --data "$DATA_DIR"
fi

step "Starting on http://127.0.0.1:$PORT"
info "data dir: $DATA_DIR"
info "operator + settings store: memory (no WAXSEAL_SERVER_DATABASE_URL)"
[[ -n "${WAXSEAL_API_KEY:-}" ]] && info "write auth: bearer required" \
                                || info "write auth: OPEN (WAXSEAL_API_KEY unset)"

cd "$SERVER_DIR"
# `--factory` so uvicorn builds the app itself, which is what `--reload`
# requires. `__main__.build` reads the same environment the container path reads,
# so a local run cannot be exercising a differently-configured app.
WAXSEAL_SERVER_DATA_DIR="$DATA_DIR" exec $py -m uvicorn \
  --factory waxseal_server.__main__:build \
  --host 127.0.0.1 --port "$PORT" ${RELOAD[@]+"${RELOAD[@]}"}
