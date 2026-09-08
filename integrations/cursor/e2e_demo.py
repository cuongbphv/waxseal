"""End-to-end demo: the waxseal-audit hook driven exactly the way Cursor
drives Agent Hooks (a subprocess per event, JSON on stdin, decision JSON
expected on stdout — that IS the hook contract boundary, verified against
cursor.com/docs/hooks), then four attack/failure scenarios against the
produced trail.

Requires only waxseal installed. Run:  python e2e_demo.py

Scenarios:
  1. An agent session is audited through real subprocess dispatch -> exit 0,
     and the hook stays observe-only (exit 0 + empty stdout — printed JSON
     could veto or override a real policy hook; exit 2 is a deny)
  2. Attacker rewrites a past action (hide an exfil command) -> verify exit 1
  3. Attacker deletes an entry                                -> exit 1 (seq_gap)
  4. Schema skew (the beads-v1.2.2 class): rows written by a NEWER schema are
     read by this binary -> exit 2 "unverifiable", NOT a false tampering alarm
  5. Secrets (leaked in a shell command, written into a file edit, pasted in
     a prompt) are redacted before disk
  6. The mirror of 4: ordinary rows read by an OUT-OF-DATE verifier, which
     must report them unverifiable rather than tampered
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
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout.strip()


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="cursor-e2e-"))
    trail = tmp / "trail.jsonl"
    env = {**os.environ, "WAXSEAL_TRAIL": str(trail)}

    def fire(event: dict) -> None:
        proc = subprocess.run(
            [sys.executable, str(HOOK)],
            input=json.dumps(event),
            capture_output=True,
            text=True,
            env=env,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == "", proc.stdout

    common = {
        "conversation_id": "conv-1",
        "generation_id": "gen-1",
        "model": "some-model",
        "workspace_roots": ["/work/project"],
    }
    fire(
        {
            **common,
            "hook_event_name": "beforeShellExecution",
            "cwd": "/work/project",
            "command": "export GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a",
        }
    )
    fire(
        {
            **common,
            "hook_event_name": "afterShellExecution",
            "command": "export GITHUB_TOKEN=...",
            "output": "ok",
            "duration": 12,
        }
    )
    fire(
        {
            **common,
            "hook_event_name": "beforeShellExecution",
            "cwd": "/work/project",
            "command": "kubectl apply -f deploy.yaml",
        }
    )
    written_key = "OPENAI_API_KEY=sk-fileedit1234567890abcdef"
    fire(
        {
            **common,
            "hook_event_name": "afterFileEdit",
            "file_path": "/work/project/.env",
            "edits": [{"old_string": "", "new_string": written_key}],
        }
    )
    # Literal split: GitHub push protection blocks the contiguous glpat- fixture.
    gitlab_pat = "glpat-" + "Xk2fjPq81mNbV4wZs7Ay"
    fire(
        {
            **common,
            "hook_event_name": "beforeSubmitPrompt",
            "prompt": f"deploy with token {gitlab_pat} please",
        }
    )

    print("\nScenario 1 — audited session verifies clean (hook stayed observe-only)")
    code, out = run_verify(trail)
    check("hook wrote a verifiable chain (exit 0)", code == 0, out)

    print("\nScenario 5 — secrets never reach disk")
    decoded = b"\n".join(
        base64.b64decode(json.loads(line)["payload_b64"]) for line in trail.read_text().splitlines()
    )
    check(
        "shell-leaked GitHub token absent from decoded payloads",
        b"ghp_16C7e42F292c6912E7710c838347Ae178B4a" not in decoded,
    )
    check(
        "key written into a file edit absent from decoded payloads",
        b"sk-fileedit1234567890abcdef" not in decoded,
    )
    check(
        "user-pasted GitLab token absent from decoded payloads", gitlab_pat.encode() not in decoded
    )
    check("redaction marker present in decoded payloads", b"***REDACTED***" in decoded)

    print("\nScenario 2 — attacker rewrites a past action")
    lines = trail.read_text().splitlines()
    obj = json.loads(lines[2])  # the kubectl dispatch
    payload = json.loads(base64.b64decode(obj["payload_b64"]))
    payload["command"] = "ls"  # hide what really ran
    obj["payload_b64"] = base64.b64encode(json.dumps(payload).encode()).decode()
    tampered = tmp / "tampered.jsonl"
    tampered.write_text("\n".join(lines[:2] + [json.dumps(obj)] + lines[3:]) + "\n")
    code, out = run_verify(tampered)
    check("edit detected (exit 1)", code == 1, out)
    check("break located at seq=2", "seq=2" in out)

    print("\nScenario 3 — attacker deletes an entry")
    deleted = tmp / "deleted.jsonl"
    deleted.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    code, out = run_verify(deleted)
    check("deletion detected (exit 1)", code == 1, out)
    check("reason is seq_gap", "seq_gap" in out)

    print("\nScenario 4 — schema skew (beads-v1.2.2 class): newer writer, older verifier")
    from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint_for
    from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
    from waxseal.domain.header import EntryHeader

    last = json.loads(lines[-1])
    new_payload = b'{"event":"beforeShellExecution","written_by":"waxseal vNEXT"}'
    header = EntryHeader(
        seq=last["header"]["seq"] + 1,
        ts="2026-08-21T07:00:00+00:00",
        hash_version=fingerprint_for((*HEADER_FIELDS, "agent_id")),
        payload_type="application/vnd.cursor.hook-event+json",
        payload_hash=compute_payload_hash(new_payload),
        prev_hash=last["entry_hash"],
    )
    future = tmp / "future.jsonl"
    future.write_text(
        "\n".join(
            lines
            + [
                json.dumps(
                    {
                        "header": {
                            "seq": header.seq,
                            "ts": header.ts,
                            "hash_version": header.hash_version,
                            "payload_type": header.payload_type,
                            "payload_hash": header.payload_hash,
                            "prev_hash": header.prev_hash,
                        },
                        "entry_hash": compute_entry_hash(header),
                        "payload_b64": base64.b64encode(new_payload).decode(),
                    }
                )
            ]
        )
        + "\n"
    )
    code, out = run_verify(future)
    check("unknown schema -> exit 2, not broken", code == 2, out)
    check("reported unverifiable, NOT tampering", "NOT evidence of tampering" in out)

    print("\nScenario 6 — a verifier that does not recognise the schema")
    from waxseal.adapters.jsonl import JSONLBackend
    from waxseal.domain.fingerprint import fingerprint
    from waxseal.domain.registry import VersionRegistry
    from waxseal.domain.verify import verify_chain

    # Scenario 4 forges a row from a FUTURE schema. This is the mirror image,
    # and the commoner case in practice: the rows are ordinary and it is the
    # VERIFIER that is out of date -- a rolled-back binary reading a trail
    # written by a build it predates. It must say so, not cry tampering.
    written = list(JSONLBackend(trail).entries())
    check(
        "the hook stamped every row with the derived schema fingerprint",
        bool(written) and all(e.header.hash_version == fingerprint() for e in written),
        f"hash_version={fingerprint()[:12]}...",
    )

    class OutdatedVerifier(VersionRegistry):
        """A build predating this schema: it recognises no fingerprint at all.

        Overriding encoder_for is enough -- recomputable() is defined in terms
        of it, so the two can never disagree about what this build can verify.
        """

        def encoder_for(self, fingerprint_: str):
            return None

    rolled_back = verify_chain(written, OutdatedVerifier())
    check(
        "it reports them unverifiable, NOT tampered",
        rolled_back.ok
        and rolled_back.broken_seq is None
        and len(rolled_back.unverifiable) == len(written),
        f"unverifiable={list(rolled_back.unverifiable)} broken_seq={rolled_back.broken_seq}",
    )

    print()
    failed = [name for status, name in results if status == FAIL]
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
