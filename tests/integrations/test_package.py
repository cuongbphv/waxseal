"""The integrations ship inside the wheel (waxseal.integrations.*) so
`pip install waxseal` is enough — no source checkout to copy hook files from.

Two properties keep this compatible with the zero-dependency rule:
- importing `waxseal` must never import the integrations subpackage (a user
  who never asked for langchain must never pay for, or crash on, it);
- the host-framework-free modules must import cleanly in an environment where
  no agent framework is installed at all (this test environment).
"""

import importlib
import subprocess
import sys

# Modules that depend only on stdlib + waxseal; the langchain/crewai/
# openai_agents modules import their host at module level and are exercised
# with sys.modules stubs in their own test files.
STDLIB_ONLY_MODULES = [
    "waxseal.integrations",
    "waxseal.integrations.claude_code",
    "waxseal.integrations.codex",
    "waxseal.integrations.cursor",
    "waxseal.integrations.hermes",
    "waxseal.integrations.hermes_gateway",
    "waxseal.integrations.openclaw",
    "waxseal.sources.openclaw",
]


class TestPackageShape:
    def test_stdlib_only_modules_import_without_any_host_framework(self) -> None:
        for name in STDLIB_ONLY_MODULES:
            importlib.import_module(name)

    def test_importing_waxseal_does_not_import_integrations(self) -> None:
        # Run in a fresh interpreter: this process has already imported both.
        code = (
            "import sys; import waxseal; "
            "bad = [m for m in sys.modules if m.startswith('waxseal.integrations')]; "
            "sys.exit(1 if bad else 0)"
        )
        proc = subprocess.run([sys.executable, "-c", code])
        assert proc.returncode == 0

    def test_no_module_builds_a_urllib_opener_at_import(self) -> None:
        """`build_opener` instantiates HTTPSHandler, which creates an SSL
        context. As a module-level side effect (`adapters/remote.py`'s old
        eager `_OPENER`) it ran on every hook import — and on windows/3.14
        CI, whose newer bundled OpenSSL refuses to initialize inside the
        hook tests' minimal env, it crashed the interpreter with SSLError
        0xa080024 BEFORE any hook's fail-open existed: a module-level crash
        is upstream of every try (5 tests, the 0.1.5 MR's fifth masked
        class). The opener must be built on first request, never at import.
        """
        code = (
            "import urllib.request\n"
            "def boom(*a, **k):\n"
            "    raise AssertionError('urllib opener built at import time')\n"
            "urllib.request.build_opener = boom\n"
            + "".join(f"import {name}\n" for name in STDLIB_ONLY_MODULES)
            + "import waxseal.adapters.remote\n"
            "import waxseal\n"
            "print('no-opener-at-import')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
        )
        assert proc.returncode == 0, proc.stderr
        assert "no-opener-at-import" in proc.stdout

    def test_repo_manifests_match_the_package_constants(self) -> None:
        # The curl-install path serves integrations/hermes/*.yaml from the
        # repo while `waxseal install` writes the package constants — the
        # two must be byte-identical or the install paths diverge.
        from pathlib import Path

        from waxseal.integrations import hermes, hermes_gateway

        repo = Path(__file__).parent.parent.parent / "integrations" / "hermes"
        assert (repo / "plugin" / "plugin.yaml").read_text(
            encoding="utf-8"
        ) == hermes.PLUGIN_MANIFEST
        assert (repo / "HOOK.yaml").read_text(encoding="utf-8") == hermes_gateway.HOOK_MANIFEST

    def test_hook_entry_points_exist(self) -> None:
        # The shims `waxseal install` writes call exactly these names.
        from waxseal.integrations import claude_code, codex, cursor, hermes, hermes_gateway

        assert callable(claude_code.main)
        assert callable(codex.main)
        assert callable(cursor.main)
        assert callable(hermes.register)
        assert callable(hermes_gateway.handle)
