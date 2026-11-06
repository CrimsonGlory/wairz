"""CI canary for scripts/merge-dependabot-prs.py identity pins.

The cron merger squash-merges green PRs whose GitHub ``user`` matches the
official github.com/apps/dependabot bot. Running the script's ``--self-test``
here means a pin drift (wrong login, lookalike account, unsigned commit,
right-login/wrong-id impersonation) fails Backend Tests rather than silently
auto-merging the wrong author.

Rule #46: ``--self-test`` includes the impersonation canary (official login
with a non-49699333 id must be rejected) and a lookalike battery
(dependabot, dependabot-bot, dependabot-preview[bot], github-actions[bot]).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
# Repo checkout: backend/tests -> <repo>/scripts
# CI container:  /app/tests -> /app/scripts (docker cp in backend-tests.yml)
_SCRIPT_DIRS = (
    _HERE.parents[2] / "scripts",
    _HERE.parents[1] / "scripts",
)


def _script(name: str) -> Path:
    tried: list[Path] = []
    for directory in _SCRIPT_DIRS:
        path = directory / name
        tried.append(path)
        if path.is_file():
            return path
    raise FileNotFoundError(f"{name} not found (tried {', '.join(str(p) for p in tried)})")


def _run_self_test(script: Path) -> None:
    proc = subprocess.run(  # noqa: ASYNC221 — sync CLI harness; this test is not async
        [sys.executable, str(script), "--self-test"],
        cwd=str(script.parent.parent),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "self-test ok" in proc.stdout


def test_merge_dependabot_prs_self_test() -> None:
    _run_self_test(_script("merge-dependabot-prs.py"))


def test_fix_github_security_and_quality_self_test() -> None:
    _run_self_test(_script("fix-github-security-and-quality.py"))
