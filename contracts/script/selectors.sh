#!/usr/bin/env bash
# Freeze and check the contracts' four-byte function selectors.
#
# Two jobs, one file.
#
# 1. APPEND-ONLY RECEIPT for FingerprintRegistry. `register` is the only
#    function that writes, and the whole guarantee rests on there being no
#    second one. That is a property of the ABI, not of any single test, so the
#    ABI is frozen here: adding `update`, `revoke` or `pause` changes this file
#    and turns CI red instead of landing quietly.
#
# 2. THE CROSS-CHECK PYTHON CANNOT DO ITSELF. Selectors are keccak256 of the
#    signature and Python's stdlib has no keccak256, so `domain/abi.py`
#    (workstream F1) carries them as frozen constants. Constants nobody
#    compares against the compiler are constants that drift. This file is what
#    they get compared against.
#
# Usage:
#   contracts/script/selectors.sh          write contracts/abi/selectors.json
#   contracts/script/selectors.sh --check  exit 1 if the committed file differs
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
out="$root/abi/selectors.json"
contracts=(FingerprintRegistry AnchoringLiveness BondedCheckpoints)

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

{
  echo "{"
  for i in "${!contracts[@]}"; do
    name="${contracts[$i]}"
    printf '  "%s": ' "$name"
    # `forge inspect ... methodIdentifiers` is the compiler's own answer, not a
    # hand-maintained list -- which is the only reason freezing it proves
    # anything.
    (cd "$root" && forge inspect "$name" methodIdentifiers --json) | python3 -c '
import json, sys
data = json.load(sys.stdin)
print(json.dumps(dict(sorted(data.items())), indent=2).replace("\n", "\n  "), end="")
'
    if [ "$i" -lt $((${#contracts[@]} - 1)) ]; then echo ","; else echo; fi
  done
  echo "}"
} > "$tmp"

if [ "${1:-}" = "--check" ]; then
  if ! diff -u "$out" "$tmp"; then
    echo "selectors.json is out of date with the compiled ABI." >&2
    echo "A changed selector set means a changed contract API. If that was" >&2
    echo "deliberate, regenerate; if it was not, this is the check working." >&2
    exit 1
  fi
  echo "selectors.json matches forge inspect for: ${contracts[*]}"
else
  mkdir -p "$(dirname "$out")"
  cp "$tmp" "$out"
  echo "wrote $out"
fi
