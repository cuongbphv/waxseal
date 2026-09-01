#!/usr/bin/env bash
# Bring the whole stack up in Docker: PostgreSQL, the server, the portal.
#
#   ./scripts/start-docker.sh              build and start, then seed operators
#   ./scripts/start-docker.sh --no-build   start without rebuilding
#   ./scripts/start-docker.sh --down       stop and remove the containers
#   ./scripts/start-docker.sh --logs       follow the server log
#
# ALWAYS REBUILDS BY DEFAULT, and that is deliberate. The image bakes the built
# frontend in at build time, so a container started without a rebuild serves
# whatever bundle the last build produced — which is how an edited screen appears
# to change nothing. `--no-build` is there when you know you want that.
#
# Credentials still come only from the environment. Export WAXSEAL_API_KEY and
# WAXSEAL_WITNESS_API_KEY before running to close the two authorities; leave them
# unset and the server is OPEN and says so at GET /v1/meta. They must be
# DIFFERENT values: a witness holding the chain's write key could append forged
# entries to the very chain it exists to cross-check (REMOTE.md section 8).

source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

COMPOSE=(docker compose -f "$SERVER_DIR/docker-compose.yml")
BUILD=(--build)  # expanded with ${a[@]+...} below: bash 3.2 + set -u
ACTION=up

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build) BUILD=() ;;
    --down)     ACTION=down ;;
    --logs)     ACTION=logs ;;
    -h|--help)  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag $1 (try --help)" ;;
  esac
  shift
done

need docker

if [[ -n "${WAXSEAL_API_KEY:-}" && "${WAXSEAL_API_KEY:-}" == "${WAXSEAL_WITNESS_API_KEY:-}" ]]; then
  die "WAXSEAL_API_KEY and WAXSEAL_WITNESS_API_KEY must differ — a witness holding
       the chain's write credential could append to the chain it cross-checks
       (REMOTE.md section 8)"
fi

case "$ACTION" in
  down)
    step "Stopping"
    "${COMPOSE[@]}" down
    exit 0 ;;
  logs)
    exec "${COMPOSE[@]}" logs -f server ;;
esac

step "Starting the stack"
cd "$REPO_ROOT"
"${COMPOSE[@]}" up -d ${BUILD[@]+"${BUILD[@]}"}

step "Waiting for the server"
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null http://127.0.0.1:8000/health 2>/dev/null; then
    info "healthy"
    break
  fi
  sleep 1
done
curl -fsS -o /dev/null http://127.0.0.1:8000/health 2>/dev/null \
  || die "server did not become healthy — ./scripts/start-docker.sh --logs"

step "Seeding operators"
# Idempotent: re-running reports "already exists" and exits 0, so this is safe
# on every start rather than a step somebody has to remember once.
"${COMPOSE[@]}" exec -T server waxseal-server-admin seed || true

step "Ready"
info "portal:      http://127.0.0.1:8000/"
info "public read: http://127.0.0.1:8000/public/v1/chains"
info "openapi:     http://127.0.0.1:8000/docs"
[[ -n "${WAXSEAL_API_KEY:-}" ]] && info "write auth:  bearer required" \
                                || info "write auth:  OPEN (WAXSEAL_API_KEY unset)"
