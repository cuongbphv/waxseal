#!/usr/bin/env bash
# Capture a screenshot of every screen, for the docs.
#
#   ./scripts/screenshots.sh                    both languages, desktop + phone
#   ./scripts/screenshots.sh --lang vi          one language only
#   ./scripts/screenshots.sh --out docs/shots
#
# Frames land in <out>/<lang>/, one directory per language, because the portal is
# bilingual and each deployment doc embeds its own set. One server serves both
# runs: the language is a client-side toggle, so photographing it twice needs no
# second deployment.
#
# It starts its OWN server on a scratch port with its own demo data, so it never
# photographs whatever happens to be in a real deployment. That is the point: a
# screenshot is the easiest way for a real trail to leave a building.
#
# NEUTRAL PATHS, and this is not cosmetic. Every command output the portal shows
# carries its `argv`, which begins with the interpreter that ran it — so a
# screenshot taken from a checkout renders the developer's home directory, and
# the data dir on the Settings screen renders it again. Both are pinned under
# /tmp/waxseal-demo here: `sys.executable` reports the symlink it was invoked
# through, so the published frames read as a deployment rather than as somebody's
# laptop.

# shellcheck source=_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

OUT="$SERVER_DIR/docs/screenshots"
LANGS=(vi en)
PORT=8951

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)  OUT="${2:?--out needs a value}"; shift ;;
    --lang)
      case "${2:?--lang needs a value}" in
        vi|en) LANGS=("$2") ;;
        both)  LANGS=(vi en) ;;
        *) die "--lang takes vi, en or both" ;;
      esac
      shift ;;
    --port) PORT="${2:?--port needs a value}"; shift ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag $1" ;;
  esac
  shift
done

need npx
need node
[[ -f "$SERVER_DIR/waxseal_server/static/index.html" ]] \
  || die "no frontend bundle — run ./scripts/build.sh --frontend first"

# A fixed, neutral root rather than mktemp: the path is visible in the frames.
DEMO_ROOT=/tmp/waxseal-demo
WORK="$DEMO_ROOT/data"
RUNTIME="$DEMO_ROOT/runtime"
cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$DEMO_ROOT"
}
trap cleanup EXIT
rm -rf "$DEMO_ROOT"
mkdir -p "$WORK"

step "Demo data"
"$SERVER_DIR/scripts/seed-demo.sh" --data "$WORK" >/dev/null
info "$WORK"

step "Server on port $PORT"
py="$(server_python)"
# The WHOLE venv is symlinked, not just the interpreter: a venv resolves its
# prefix from the `pyvenv.cfg` beside `bin/`, so a lone symlinked binary finds no
# site-packages. Through the directory symlink the layout is intact and
# `sys.executable` still reports the neutral path.
[[ "$py" == *" "* ]] && die "screenshots need a real venv, not 'uv run' — run ./scripts/build.sh"
ln -sfn "$SERVER_DIR/.venv" "$RUNTIME"
py="$RUNTIME/bin/python"
( cd "$SERVER_DIR" && WAXSEAL_SERVER_DATA_DIR="$WORK" $py -m uvicorn \
    --factory waxseal_server.__main__:build --host 127.0.0.1 --port "$PORT" \
    --log-level error ) &
SERVER_PID=$!
for _ in $(seq 1 40); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/health" 2>/dev/null && break
  sleep 0.5
done
curl -fsS -o /dev/null "http://127.0.0.1:$PORT/health" 2>/dev/null \
  || die "the screenshot server did not start"

step "Capturing ${LANGS[*]}"
# playwright installed into the scratch dir, so this script adds no dependency
# to server/web and cannot change what the app builds against.
( cd "$DEMO_ROOT" && npm install --silent --no-audit --no-fund playwright@1.62.1 >/dev/null 2>&1 )
# The driver is COPIED next to that node_modules rather than run in place.
# NODE_PATH does not apply to ESM: an `import 'playwright'` resolves by walking
# up from the FILE's directory, not from the working directory, so a script left
# in scripts/ would never find the scratch install.
cp "$SERVER_DIR/scripts/screenshots.mjs" "$DEMO_ROOT/driver.mjs"
for lang in "${LANGS[@]}"; do
  info "language: $lang -> $OUT/$lang"
  mkdir -p "$OUT/$lang"
  node "$DEMO_ROOT/driver.mjs" "http://127.0.0.1:$PORT" "$OUT/$lang" "$lang"
done

step "Done"
info "$OUT"
