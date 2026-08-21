"""End-to-end demo: the waxseal-audit hook driven exactly the way Codex CLI
drives it (a subprocess per event, snake_case JSON on stdin — that IS the
hook contract boundary, verified against openai/codex rust-v0.149.0), then
four attack/failure scenarios against the produced trail.

Requires only waxseal installed. Run:  python e2e_demo.py

Scenarios:
  1. An agent session is audited through real subprocess dispatch -> exit 0,
     and the hook stays observe-only (exit 0 + empty stdout on every event —
     stdout would be parsed as decision JSON, exit 2 would block the tool)
  2. Attacker rewrites a past action (hide an exfil command) -> verify exit 1
  3. Attacker deletes an entry                                -> exit 1 (seq_gap)
  4. Schema skew (the beads-v1.2.2 class): rows written by a NEWER schema are
     read by this binary -> exit 2 "unverifiable", NOT a false tampering alarm
  5. Secrets (agent-leaked in a command AND user-pasted in a prompt) are
     redacted before disk
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HOOK = Path(__file__).parent / "hook.py"

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


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="codex-e2e-"))
    trail = tmp / "trail.jsonl"
    env = {**os.environ, "WAXSEAL_TRAIL": str(trail)}

    def fire(event: dict) -> None:
        proc = subprocess.run(
            [sys.executable, str(HOOK)],
            input=json.dumps(event), capture_output=True, text=True, env=env,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == "", proc.stdout

    leaked = "export GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a"
    common = {"session_id": "s1", "turn_id": "turn-1", "cwd": "/work/project",
              "model": "some-model", "permission_mode": "default"}
    fire({**common, "hook_event_name": "SessionStart"})
    fire({**common, "hook_event_name": "PreToolUse", "tool_name": "shell", "tool_use_id": "c1",
          "tool_input": {"command": leaked}})
    fire({**common, "hook_event_name": "PostToolUse", "tool_name": "shell", "tool_use_id": "c1",
          "tool_input": {"command": "export GITHUB_TOKEN=..."}, "tool_response": {"output": "ok"}})
    fire({**common, "hook_event_name": "PreToolUse", "tool_name": "shell", "tool_use_id": "c2",
          "tool_input": {"command": "kubectl apply -f deploy.yaml"}})
    fire({**common, "hook_event_name": "UserPromptSubmit",
          "prompt": "here is my key sk-usersecret1234567890abcdef please fix the deploy"})

    print("\nScenario 1 — audited session verifies clean (hook stayed observe-only)")
    code, out = run_verify(trail)
    check("hook wrote a verifiable chain (exit 0)", code == 0, out)

    print("\nScenario 5 — secrets never reach disk")
    decoded = b"\n".join(
        base64.b64decode(json.loads(line)["payload_b64"])
        for line in trail.read_text().splitlines()
    )
    check("agent-leaked GitHub token absent from decoded payloads",
          b"ghp_16C7e42F292c6912E7710c838347Ae178B4a" not in decoded)
    check("user-pasted API key absent from decoded payloads",
          b"sk-usersecret1234567890abcdef" not in decoded)
    check("redaction marker present in decoded payloads", b"***REDACTED***" in decoded)

    print("\nScenario 2 — attacker rewrites a past action")
    lines = trail.read_text().splitlines()
    obj = json.loads(lines[3])  # the kubectl dispatch
    payload = json.loads(base64.b64decode(obj["payload_b64"]))
    payload["tool_input"] = {"command": "ls"}  # hide what really ran
    obj["payload_b64"] = base64.b64encode(json.dumps(payload).encode()).decode()
    tampered = tmp / "tampered.jsonl"
    tampered.write_text("\n".join(lines[:3] + [json.dumps(obj)] + lines[4:]) + "\n")
    code, out = run_verify(tampered)
    check("edit detected (exit 1)", code == 1, out)
    check("break located at seq=3", "seq=3" in out)

    print("\nScenario 3 — attacker deletes an entry")
    deleted = tmp / "deleted.jsonl"
    deleted.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    code, out = run_verify(deleted)
    check("deletion detected (exit 1)", code == 1, out)
    check("reason is seq_gap", "seq_gap" in out)

    print("\nScenario 4 — schema skew (beads-v1.2.2 class): newer writer, older verifier")
    from waxseal.domain.fingerprint import HEADER_V1_FIELDS, fingerprint_for
    from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
    from waxseal.domain.header import EntryHeader

    last = json.loads(lines[-1])
    new_payload = b'{"event":"PreToolUse","written_by":"waxseal vNEXT"}'
    header = EntryHeader(
        seq=last["header"]["seq"] + 1,
        ts="2026-08-21T07:00:00+00:00",
        hash_version=fingerprint_for((*HEADER_V1_FIELDS, "agent_id")),
        payload_type="application/vnd.codex.hook-event+json",
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
