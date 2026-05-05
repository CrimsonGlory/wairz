"""CLAUDE.md Rule #35b + audit-2026-05-04 F-A-06 / F-D-03 / F-D-08:
every direct ``Finding(...)`` construction outside ``FindingService.create()``
MUST explicitly carry ``confidence`` and ``firmware_id``.

Background — commit ``7dc21fe`` (2026-05-04, Rule #35b base case) fixed
``FindingService.create()`` to forward ``data.confidence.value`` to the
``Finding(...)`` constructor.  Five additional code paths constructed
``Finding(...)`` directly and dropped both fields to NULL on persist.
The audit campaign 2026-05-04 confirmed the bug across 3 streams (A, D, G).

This test parses every backend ``.py`` file, extracts each
``Finding(...)`` constructor invocation (excluding ``finding_service.py``
which is the authoritative single-owner), and asserts both
``confidence=`` and ``firmware_id=`` keyword arguments are present in the
call's keyword set.

Why structural rather than runtime: each scanner path invokes Docker
containers (mobsfscan, grype, cwe_checker), real binaries, or NVD HTTP
calls — driving them through pytest is heavyweight.  The structural
gate locks the Rule #35b discipline in: future direct ``Finding(...)``
constructors will fail this test until they explicitly forward both
fields.  Companion to the live-canary precedent in
``unpack_audit_findings`` C3 (commit ``7dc21fe``) — that one tested
runtime persistence; this one tests authoring discipline.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest


_BACKEND = Path(__file__).parent.parent
_APP = _BACKEND / "app"

# `finding_service.py` is the authoritative owner of `Finding(...)` —
# its single direct construction is the canonical one and ALWAYS
# propagates confidence + firmware_id from FindingCreate.  Excluded here.
_OWNER_FILES: frozenset[Path] = frozenset({
    _APP / "services" / "finding_service.py",
})


def _iter_finding_constructions() -> list[tuple[Path, int, set[str]]]:
    """Walk every .py under app/ and collect (path, line, kwargs)
    tuples for each direct call to ``Finding(...)``.

    A "direct call" is `Call(func=Name(id='Finding'))`.  Excludes
    `Finding.something(...)` method calls (those don't construct).
    """
    out: list[tuple[Path, int, set[str]]] = []
    for path in _APP.rglob("*.py"):
        if path in _OWNER_FILES or "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Match `Finding(` exactly — bare name, not `something.Finding`.
            if not (isinstance(func, ast.Name) and func.id == "Finding"):
                continue
            kwargs = {kw.arg for kw in node.keywords if kw.arg is not None}
            out.append((path, node.lineno, kwargs))
    return out


def test_every_direct_finding_construction_carries_confidence_and_firmware_id():
    sites = _iter_finding_constructions()

    # The audit identified 5 bypass paths.  This number is allowed to
    # rise as new scanners ship — the gate is "every site MUST pass",
    # not "exactly N sites".
    assert len(sites) >= 1, (
        f"no `Finding(...)` constructions found under {_APP} — did the "
        f"AST walker break or did the model get renamed?"
    )

    failures: list[str] = []
    for path, lineno, kwargs in sites:
        rel = os.path.relpath(path, _BACKEND)
        missing = []
        if "confidence" not in kwargs:
            missing.append("confidence=")
        if "firmware_id" not in kwargs:
            missing.append("firmware_id=")
        if missing:
            failures.append(
                f"{rel}:{lineno} — missing {', '.join(missing)} "
                f"(present kwargs: {sorted(kwargs)})"
            )

    if failures:
        pytest.fail(
            f"Direct `Finding(...)` constructions outside finding_service.py "
            f"MUST explicitly carry confidence + firmware_id (Rule #35b / "
            f"audit-2026-05-04):\n  - "
            + "\n  - ".join(failures)
            + "\n\nResolution: either add the missing kwarg(s) to the call "
            "(use `confidence=None` explicitly when the source data has no "
            "confidence signal), OR route the construction through "
            "`FindingService.create()` which forwards both fields from "
            "`FindingCreate`."
        )


def test_finding_service_create_signature_propagates_both_fields():
    """Sanity check that the canonical owner's Finding(...) call
    explicitly references both fields — guards against a future
    refactor accidentally dropping them in finding_service.py."""
    src = (_APP / "services" / "finding_service.py").read_text()
    assert "confidence=" in src, (
        "finding_service.py no longer references `confidence=` in its "
        "Finding(...) construction — the canonical owner regressed; "
        "every consumer is now broken"
    )
    assert "firmware_id=" in src, (
        "finding_service.py no longer references `firmware_id=` in its "
        "Finding(...) construction — same regression class"
    )
