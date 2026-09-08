#!/usr/bin/env bash
# Shared plumbing. Sourced, never run.
#
# `set -euo pipefail` in every script, so a failed step stops the run instead of
# letting the next one report success over it. A build script that keeps going
# after a failed test is a build script that ships a red build.

set -euo pipefail

SERVER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Read by the scripts that source this file, not here; shellcheck checks this
# file on its own in CI and cannot see those readers.
# shellcheck disable=SC2034
REPO_ROOT="$(cd "$SERVER_DIR/.." && pwd)"
# shellcheck disable=SC2034
WEB_DIR="$SERVER_DIR/web"

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'; RESET=$'\033[0m'
else
  BOLD=''; DIM=''; RED=''; GREEN=''; RESET=''
fi

step() { printf '\n%s==>%s %s%s%s\n' "$GREEN" "$RESET" "$BOLD" "$*" "$RESET"; }
info() { printf '    %s%s%s\n' "$DIM" "$*" "$RESET"; }
die()  { printf '\n%serror:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is not on PATH${2:+ — $2}"
}

# The interpreter that can import waxseal, never a bare `python3`.
# `runtime/cli.py` uses sys.executable for the same reason: an interpreter found
# on PATH is not necessarily the one with the library installed, and that exact
# mistake is in this release's history.
server_python() {
  if [[ -x "$SERVER_DIR/.venv/bin/python" ]]; then
    printf '%s' "$SERVER_DIR/.venv/bin/python"
  elif command -v uv >/dev/null 2>&1; then
    printf '%s' "uv run --project $SERVER_DIR python"
  else
    die "no server venv at $SERVER_DIR/.venv and no uv — run scripts/build.sh first"
  fi
}
