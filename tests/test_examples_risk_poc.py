"""The risk PoC is documentation that runs, so it is tested like code.

Its whole value to a reviewer is the claim "each of these attacks produces
exactly this verdict". An example that has quietly drifted from the library
is worse than no example — it teaches the wrong thing with a straight face.

These tests do not cover presentation (colours, spinners, box drawing); they
cover the evidence claims the walkthrough makes.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

POC = Path(__file__).parents[1] / "examples" / "risk-poc"


def load_module(name: str) -> ModuleType:
    """Import a script from examples/ (which is not a package).

    Registered in sys.modules before execution: @dataclass resolves its
    annotations via sys.modules[cls.__module__], so an unregistered module
    makes every dataclass in the script fail to build. Cached on the same
    key so repeated calls return one module object, which keeps monkeypatch
    on module globals meaningful across a test.
    """
    if name in sys.modules:
        return sys.modules[name]
    if str(POC) not in sys.path:
        sys.path.insert(0, str(POC))
    spec = importlib.util.spec_from_file_location(name, POC / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def simulate() -> ModuleType:
    return load_module("simulate")


@pytest.fixture(scope="module")
def tamper() -> ModuleType:
    return load_module("tamper_demo")


@pytest.fixture
def poc_dir(tmp_path: Path, simulate: ModuleType) -> Path:
    out = tmp_path / "poc"
    assert simulate.run(out, animate=False) == 0
    return out


class TestSimulate:
    def test_the_run_produces_an_intact_verifiable_trail(self, poc_dir: Path) -> None:
        from waxseal import AuditLog

        result = AuditLog.open(poc_dir / "decisions.jsonl").verify()
        assert result.ok
        assert result.checked == len(load_module("simulate").transactions())

    def test_the_secret_in_the_operator_note_never_reaches_disk(self, poc_dir: Path) -> None:
        # The redact-before-hash claim, checked against every byte the run
        # wrote — not just the trail, but the sidecars beside it.
        secret = b"sk-live-9f2ab7c41de85630"
        for path in poc_dir.rglob("*"):
            if path.is_file():
                assert secret not in path.read_bytes(), path

    def test_every_decision_carries_a_committed_input(self, poc_dir: Path) -> None:
        from waxseal import AuditLog
        from waxseal.sources.decisions import iter_decisions

        log = AuditLog.open(poc_dir / "decisions.jsonl")
        records = [record for _, record in iter_decisions(log)]
        assert records and all(r is not None for r in records)
        assert all(len(r.input_commitment) == 64 for r in records)  # type: ignore[union-attr]

    def test_one_decision_deliberately_records_no_oversight(self, poc_dir: Path) -> None:
        # rule 5 has to be demonstrable, not just described: the run includes
        # a path where nobody recorded whether a human was involved, and the
        # report must say that rather than calling it automated.
        from waxseal import AuditLog
        from waxseal.domain.report import build_report

        log = AuditLog.open(poc_dir / "decisions.jsonl")
        entries = list(log._backend.entries())
        report = build_report(log.verify(), entries)
        assert report.oversight_unrecorded == 1
        assert "automated" in dict(report.by_oversight_mode)

    def test_attestations_verify_under_the_escrowed_key(self, poc_dir: Path) -> None:
        from waxseal import AuditLog
        from waxseal.adapters.attest import FileAttestor

        trail = poc_dir / "decisions.jsonl"
        key = (poc_dir / "sealkey.escrow").read_bytes()
        log = AuditLog.open(trail, attestor=FileAttestor(trail, initial_key=key))
        assert log.verify_attestations(initial_key=key).ok

    def test_a_checkpoint_was_anchored(self, poc_dir: Path) -> None:
        from waxseal.adapters.anchors import FileAnchorSink

        assert list(FileAnchorSink(poc_dir / "decisions.jsonl").records())

    def test_the_run_is_reproducible(self, tmp_path: Path, simulate: ModuleType) -> None:
        # Same inputs, same decisions — only the timestamps differ. A demo
        # whose verdicts moved between runs could not be reasoned about.
        outcomes = []
        for i in range(2):
            out = tmp_path / f"run{i}"
            simulate.run(out, animate=False)
            outcomes.append(
                [
                    json.loads(__import__("base64").b64decode(json.loads(line)["payload_b64"]))[
                        "outcome"
                    ]
                    for line in (out / "decisions.jsonl").read_text(encoding="utf-8").splitlines()
                ]
            )
        assert outcomes[0] == outcomes[1]

    def test_animation_is_never_required_for_the_result(
        self, tmp_path: Path, simulate: ModuleType
    ) -> None:
        # The animator is presentation only: turning it on must not change a
        # single byte of the evidence it narrates.
        plain, fancy = tmp_path / "plain", tmp_path / "fancy"
        simulate.run(plain, animate=False)
        simulate.run(fancy, animate=True)

        def payloads(d: Path) -> list[str]:
            return [
                json.loads(line)["payload_b64"]
                for line in (d / "decisions.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        assert payloads(plain) == payloads(fancy)


class TestTamperWalkthrough:
    def test_every_scenario_behaves_as_the_walkthrough_documents(
        self, poc_dir: Path, tamper: ModuleType
    ) -> None:
        # The demo asserts its own expectations and exits non-zero if any
        # scenario deviates; this is the falsifiability receipt for the
        # claims the README makes to a reviewer.
        assert tamper.run(poc_dir) == 0

    def test_the_original_trail_is_never_modified(self, poc_dir: Path, tamper: ModuleType) -> None:
        trail = poc_dir / "decisions.jsonl"
        before = trail.read_bytes()
        tamper.run(poc_dir)
        assert trail.read_bytes() == before

    def test_it_refuses_to_run_without_a_trail(self, tmp_path: Path, tamper: ModuleType) -> None:
        assert tamper.run(tmp_path / "nothing-here") == 3

    def test_a_scenario_that_stopped_being_caught_fails_the_run(
        self, poc_dir: Path, tamper: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Falsifiability: prove the walkthrough would actually notice. With
        # one scenario's expectation flipped to "not caught", the run fails.
        original = tamper.scenario_edit

        def mislabelled(src: Path, work: Path) -> object:
            outcome = original(src, work)
            return type(outcome)(
                name=outcome.name,
                expected=0,
                actual=outcome.actual,
                caught_by=outcome.caught_by,
            )

        monkeypatch.setattr(tamper, "SCENARIOS", [mislabelled, *tamper.SCENARIOS[1:]])
        assert tamper.run(poc_dir) == 1


class TestAnimator:
    def test_it_disables_itself_when_output_is_not_a_terminal(self) -> None:
        # Under pytest stdout is captured, so this is the real piped case:
        # redraw escapes written into a pipe are unreadable noise.
        animate = load_module("_animate")
        assert animate.supports_ansi() is False

    def test_plain_mode_still_prints_every_stage(self, capsys: pytest.CaptureFixture[str]) -> None:
        animate = load_module("_animate")
        animator = animate.FlowAnimator(enabled=False)
        animator.play("t", [animate.Stage("decide", "x"), animate.Stage("hash", "y")])
        out = capsys.readouterr().out
        assert "decide" in out and "hash" in out
        assert "\033[" not in out

    def test_glyphs_fall_back_to_ascii_on_a_narrow_console(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        animate = load_module("_animate")

        class NarrowStdout:
            encoding = "cp1252"

        monkeypatch.setattr(animate.sys, "stdout", NarrowStdout())
        assert animate.glyphs() is animate.ASCII

    def test_glyphs_use_box_drawing_when_the_console_can_encode_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        animate = load_module("_animate")

        class WideStdout:
            encoding = "utf-8"

        monkeypatch.setattr(animate.sys, "stdout", WideStdout())
        assert animate.glyphs() is animate.UNICODE

    def test_no_color_env_var_is_honoured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        animate = load_module("_animate")
        monkeypatch.setenv("NO_COLOR", "1")
        assert animate.supports_ansi() is False

    def test_draw_chain_on_an_empty_trail_prints_nothing(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        animate = load_module("_animate")
        animate.draw_chain([], enabled=False)
        assert capsys.readouterr().out == ""

    def test_draw_chain_names_the_head(self, capsys: pytest.CaptureFixture[str]) -> None:
        animate = load_module("_animate")
        animate.draw_chain(["a" * 64, "b" * 64], enabled=False)
        assert "b" * 12 in capsys.readouterr().out
