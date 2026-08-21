"""End-to-end demo: WaxsealCallbackHandler driven by the REAL langchain-core
callback machinery (a real @tool invoked with config={"callbacks": [...]} —
the exact attach point users employ), then four attack/failure scenarios
against the produced trail.

Requires langchain-core and waxseal installed. Run:  python e2e_demo.py
(No LLM or API key needed: tool invocation drives the same CallbackManager
path an agent run does.)

Scenarios:
  1. Real tool runs (success + failure) are audited -> verify exit 0
  2. Attacker rewrites a past action (hide an exfil command) -> verify exit 1
  3. Attacker deletes an entry                                -> exit 1 (seq_gap)
  4. Schema skew (the beads-v1.2.2 class): rows written by a NEWER schema are
     read by this binary -> exit 2 "unverifiable", NOT a false tampering alarm
  5. Secret in tool input is redacted before disk
"""

from __future__ import annotations

import base64
import contextlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from handler import WaxsealCallbackHandler  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

PASS = "PASS"
FAIL = "FAIL"
results: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((PASS if ok else FAIL, name))
    print(f"  [{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail else ""))


def run_verify(trail: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "waxseal.cli", "verify", str(trail)],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout.strip()


@tool
def run_shell(command: str) -> str:
    """Pretend to run a shell command."""
    return f"ran: {command}"


@tool
def flaky_api(query: str) -> str:
    """A tool that always fails, to exercise on_tool_error."""
    raise TimeoutError("upstream API did not answer in 30s")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="langchain-e2e-"))
    trail = tmp / "trail.jsonl"
    audit = WaxsealCallbackHandler(trail)
    cfg = {"callbacks": [audit]}

    # --- drive the REAL callback manager ------------------------------------
    run_shell.invoke(
        {"command": "export GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a"}, config=cfg
    )
    run_shell.invoke({"command": "kubectl apply -f deploy.yaml"}, config=cfg)
    # The raise propagates to the caller; on_tool_error already fired inside
    # the manager before it does.
    with contextlib.suppress(Exception):
        flaky_api.invoke({"query": "status"}, config=cfg)

    print("\nScenario 1 — audited tool runs verify clean")
    code, out = run_verify(trail)
    check("handler wrote a verifiable chain (exit 0)", code == 0, out)
    decoded_lines = [
        json.loads(base64.b64decode(json.loads(line)["payload_b64"]))
        for line in trail.read_text().splitlines()
    ]
    phases = [p["phase"] for p in decoded_lines]
    check("dispatch + result recorded for successful runs",
          phases.count("dispatch") == 3 and phases.count("result") == 2, str(phases))
    check("tool failure recorded via on_tool_error", "error" in phases)

    print("\nScenario 5 — secret in tool input never reaches disk")
    decoded = json.dumps(decoded_lines).encode()
    check("GitHub token absent from decoded payloads",
          b"ghp_16C7e42F292c6912E7710c838347Ae178B4a" not in decoded)
    check("redaction marker present in decoded payloads", b"***REDACTED***" in decoded)

    print("\nScenario 2 — attacker rewrites a past action")
    lines = trail.read_text().splitlines()
    idx = phases.index("dispatch", 1)  # the kubectl dispatch (second dispatch)
    obj = json.loads(lines[idx])
    payload = json.loads(base64.b64decode(obj["payload_b64"]))
    payload["input_str"] = "{'command': 'ls'}"  # hide what really ran
    obj["payload_b64"] = base64.b64encode(json.dumps(payload).encode()).decode()
    tampered = tmp / "tampered.jsonl"
    tampered.write_text("\n".join(lines[:idx] + [json.dumps(obj)] + lines[idx + 1:]) + "\n")
    code, out = run_verify(tampered)
    check("edit detected (exit 1)", code == 1, out)
    check(f"break located at seq={idx}", f"seq={idx}" in out)

    print("\nScenario 3 — attacker deletes an entry")
    deleted = tmp / "deleted.jsonl"
    deleted.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    code, out = run_verify(deleted)
    check("deletion detected (exit 1)", code == 1, out)
    check("reason is seq_gap", "seq_gap" in out)

    print("\nScenario 4 — schema skew (beads-v1.2.2 class): newer writer, older verifier")
    from waxseal.domain.fingerprint import HEADER_V1_FIELDS, fingerprint_for
    from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
    from waxseal.domain.header import EntryHeader

    last = json.loads(lines[-1])
    new_payload = b'{"phase":"dispatch","written_by":"waxseal vNEXT"}'
    header = EntryHeader(
        seq=last["header"]["seq"] + 1,
        ts="2026-08-21T07:00:00+00:00",
        hash_version=fingerprint_for((*HEADER_V1_FIELDS, "agent_id")),
        payload_type="application/vnd.langchain.tool-event+json",
        payload_hash=compute_payload_hash(new_payload),
        prev_hash=last["entry_hash"],
    )
    future = tmp / "future.jsonl"
    future.write_text("\n".join(lines + [json.dumps({
        "header": {
            "seq": header.seq, "ts": header.ts, "hash_version": header.hash_version,
            "payload_type": header.payload_type, "payload_hash": header.payload_hash,
            "prev_hash": header.prev_hash,
        },
        "entry_hash": compute_entry_hash(header),
        "payload_b64": base64.b64encode(new_payload).decode(),
    })]) + "\n")
    code, out = run_verify(future)
    check("unknown schema -> exit 2, not broken", code == 2, out)
    check("reported unverifiable, NOT tampering", "NOT evidence of tampering" in out)

    print()
    failed = [name for status, name in results if status == FAIL]
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
