"""Tier-1 tests for the Q1 Python AST walker.

Per Rule #39 / Rule #35b: tests target the INNER runner
(_do_python_ast_run) with a make_live_db()-provided session — never
the OUTER runner (run_python_ast_walk_background) which would attempt
async_session_factory() and fail with socket.gaierror on the dev host.

Per Rule #45 + Rule #36 + Rule #46 META-CANARY: the walker source MUST
NOT contain ANY code-execution / runtime-import / dynamic-eval tokens
in CODE (we strip docstrings + comments before scanning) AND the test
gate must be canary-verified to ACTUALLY fire on a synthetic violation.
"""
from __future__ import annotations

import io
import os
import pathlib
import re
import shutil
import tokenize
import uuid
from pathlib import Path

import pytest

from app.models import Firmware, Project
from app.services.python_ast_walker import (
    _do_python_ast_run,
    detect_python_versions,
    walk_python_files,
)
from tests._live_db import make_live_db

# ── Walker (filesystem scan) ────────────────────────────────────────────────


def test_walk_python_files_empty_root(tmp_path: Path):
    """Empty root → empty list, no exceptions."""
    assert walk_python_files([str(tmp_path)]) == []


def test_walk_python_files_finds_py(tmp_path: Path):
    """Creates a .py file; walker surfaces it."""
    src_dir = tmp_path / "opt" / "ds1qrsetup"
    src_dir.mkdir(parents=True)
    (src_dir / "app.py").write_text("import os\nprint('hello')\n")

    hits = walk_python_files([str(tmp_path)])
    assert len(hits) == 1
    assert hits[0].endswith("app.py")


def test_walk_python_files_finds_multiple_extensions(tmp_path: Path):
    """All three Python source extensions are caught."""
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.pyw").write_text("x = 2\n")
    (tmp_path / "c.pyi").write_text("x: int\n")
    (tmp_path / "d.pyc").write_bytes(b"\x00\x00\x00\x00")  # not .py source

    hits = walk_python_files([str(tmp_path)])
    assert len(hits) == 3
    assert sorted(os.path.basename(h) for h in hits) == [
        "a.py",
        "b.pyw",
        "c.pyi",
    ]


def test_walk_python_files_rejects_escape_symlinks(tmp_path: Path):
    """A symlink whose realpath escapes the root must be rejected."""
    outside = tmp_path.parent / f"outside-{uuid.uuid4().hex[:8]}"
    outside.mkdir()
    real_py = outside / "evil.py"
    real_py.write_text("x = 1\n")

    inside = tmp_path / "inside"
    inside.mkdir()
    try:
        os.symlink(str(real_py), str(inside / "shim.py"))
    except OSError:
        pytest.skip("symlink creation not supported on this filesystem")

    hits = walk_python_files([str(tmp_path)])
    assert hits == []
    shutil.rmtree(outside, ignore_errors=True)


def test_walk_python_files_skips_unrelated_files(tmp_path: Path):
    """Non-Python files must NOT be surfaced."""
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "README.md").write_text("# README\n")
    (tmp_path / "config.yaml").write_text("foo: bar\n")

    hits = walk_python_files([str(tmp_path)])
    assert len(hits) == 1


# ── detect_python_versions ──────────────────────────────────────────────────


def test_detect_python_versions_finds_versions_in_shebang():
    """Shebangs with explicit versions surface."""
    samples = [
        "#!/usr/bin/python2.7\nimport os\n",
        "#!/usr/bin/env python3.7\nimport sys\n",
        "#!/usr/bin/python3.7\nimport json\n",
    ]
    versions = detect_python_versions(samples)
    assert "2.7" in versions
    assert "3.7" in versions
    # 3.7 should appear only once (dedup).
    assert versions.count("3.7") == 1


def test_detect_python_versions_unspecified_shebang():
    """Bare ``python`` (no version pin) surfaces as 'unspecified'."""
    samples = [
        "#!/usr/bin/env python\nimport os\n",
    ]
    versions = detect_python_versions(samples)
    assert "unspecified" in versions


def test_detect_python_versions_no_evidence_returns_empty():
    """No shebangs → empty list."""
    samples = ["import os\nprint('hi')\n"]
    versions = detect_python_versions(samples)
    assert versions == []


# ── Inner runner — Rule #39 + Rule #35b live canary ──────────────────────────


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


@pytest.mark.asyncio
async def test_do_python_ast_run_no_firmware_returns_empty():
    """If firmware_id doesn't exist, runner returns the empty-walk shape
    rather than raising."""
    async with make_live_db() as db:
        result = await _do_python_ast_run(db, uuid.uuid4())
        assert result["summary"]["files_scanned"] == 0
        assert result["summary"]["modules_imported_count"] == 0
        assert result["modules_imported"] == {}


@pytest.mark.asyncio
async def test_do_python_ast_run_no_detection_roots_returns_empty():
    """If the firmware has no detection roots, runner returns empty."""
    async with make_live_db() as db:
        project = Project(name="Q1 no-roots canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "no-roots.bin", "a")
        db.add(firmware)
        await db.commit()

        result = await _do_python_ast_run(db, firmware.id)
        assert result["summary"]["files_scanned"] == 0


@pytest.mark.asyncio
async def test_do_python_ast_run_no_python_in_root(tmp_path: Path):
    """If the root has no Python files, runner returns empty walk."""
    async with make_live_db() as db:
        project = Project(name="Q1 empty-root canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "empty-py.bin", "b")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        # Just a README, no .py files.
        (tmp_path / "README").write_text("hi\n")

        result = await _do_python_ast_run(db, firmware.id)
        assert result["summary"]["files_scanned"] == 0


@pytest.mark.asyncio
async def test_do_python_ast_run_finds_imports_and_callables(tmp_path: Path):
    """Walker parses Python source and surfaces imports + callable
    references. Live canary: SELECT the firmware row, inspect the JSON
    aggregate."""
    async with make_live_db() as db:
        project = Project(name="Q1 imports canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "imports.bin", "c")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        # Lay down a minimal Flask-style app.
        ds1 = tmp_path / "opt" / "ds1qrsetup"
        ds1.mkdir(parents=True)
        (ds1 / "__init__.py").write_text("")
        (ds1 / "app.py").write_text(
            "#!/usr/bin/env python3.7\n"
            "import tarfile\n"
            "from flask import Flask\n"
            "\n"
            "def create_app():\n"
            "    app = Flask(__name__)\n"
            "    register_routes(app)\n"
            "    return app\n"
            "\n"
            "def register_routes(app):\n"
            "    @app.route('/extract')\n"
            "    def extract():\n"
            "        tarfile.open('/tmp/x.tar')\n"
            "        return 'ok'\n"
        )
        (ds1 / "utils.py").write_text(
            "import plistlib  # unused — should be unreachable\n"
            "def helper():\n"
            "    return 1\n"
        )

        result = await _do_python_ast_run(db, firmware.id)

        # File count.
        assert result["summary"]["files_scanned"] == 3
        # Imports surface.
        assert "tarfile" in result["modules_imported"]
        assert "flask" in result["modules_imported"]
        assert "plistlib" in result["modules_imported"]
        # Entry points include create_app and the route handler.
        entry_qualnames = {ep["qualname"] for ep in result["entry_points"]}
        assert any("create_app" in q for q in entry_qualnames)
        # Python version detected from shebang.
        assert "3.7" in result["python_version_detected"]
        # axiom_self_audit present.
        assert "PARSE-ONLY" in result["axiom_self_audit"]


@pytest.mark.asyncio
async def test_do_python_ast_run_reachability_from_entry(tmp_path: Path):
    """Reachability flag separates entry-reachable from unreachable
    modules. Live canary on a 2-file source set."""
    async with make_live_db() as db:
        project = Project(name="Q1 reachability canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "reach.bin", "d")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        ds1 = tmp_path / "app"
        ds1.mkdir()
        # Entry: create_app -> calls tarfile.open
        (ds1 / "app.py").write_text(
            "import tarfile\n"
            "def create_app():\n"
            "    tarfile.open('/tmp/x')\n"
            "    return None\n"
        )
        # Dead code: plistlib import that nothing calls.
        (ds1 / "dead.py").write_text(
            "import plistlib\n"
            "def never_called():\n"
            "    plistlib.loads(b'')\n"
        )

        result = await _do_python_ast_run(db, firmware.id)

        modules = result["modules_imported"]
        # tarfile is reachable (called from create_app).
        assert modules["tarfile"]["reachable_from_entry"] is True
        # plistlib is unreachable (never called from any entry-point).
        assert modules["plistlib"]["reachable_from_entry"] is False
        # unreachable_modules list contains plistlib.
        assert "plistlib" in result["unreachable_modules"]


@pytest.mark.asyncio
async def test_do_python_ast_run_aggregate_shape(tmp_path: Path):
    """Aggregate result has the canonical shape per Rule #35c
    `_normalize_firmware_python_ast_walk_result` documentation."""
    async with make_live_db() as db:
        project = Project(name="Q1 shape canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "shape.bin", "e")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        result = await _do_python_ast_run(db, firmware.id)

        for key in (
            "firmware_id",
            "walker",
            "extracted_root_paths_scanned",
            "python_version_detected",
            "entry_points",
            "modules_imported",
            "callables_referenced",
            "unreachable_modules",
            "summary",
            "errors",
            "axiom_self_audit",
        ):
            assert key in result, f"missing key {key!r} in walk result"
        # Summary canonical keys.
        for key in (
            "files_scanned",
            "modules_imported_count",
            "callables_referenced_count",
            "entry_reachable_modules_count",
            "entry_reachable_callables_count",
            "entry_points_count",
            "run_seconds",
            "truncated",
        ):
            assert key in result["summary"], (
                f"missing summary key {key!r} in walk result"
            )


@pytest.mark.asyncio
async def test_do_python_ast_run_handles_syntax_error_gracefully(
    tmp_path: Path,
):
    """A file with Python 2 syntax (``print x``) parsed by Python 3 must
    surface a parse error but not abort the walk."""
    async with make_live_db() as db:
        project = Project(name="Q1 syntax canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "syntax.bin", "f")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        (tmp_path / "good.py").write_text("import os\n")
        # Py2 print-statement is a syntax error in Py3.
        (tmp_path / "bad.py").write_text("print 'hello'\n")

        result = await _do_python_ast_run(db, firmware.id)

        # Both files scanned; one parse error.
        assert result["summary"]["files_scanned"] == 2
        assert any("syntax error" in err for err in result["errors"])
        # The good file's imports still surfaced.
        assert "os" in result["modules_imported"]


# ── Rule #45 + Rule #36 PARSE-ONLY test gate ────────────────────────────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Remove docstrings, # comments, and string literals from Python
    source so we can scan for ACTUAL code references.

    Returns the STRING tokens joined — so only CODE tokens are present
    in the output. This is what the test gate scans against.
    """
    out_tokens: list[str] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenizeError:
        return source

    for tok in tokens:
        if tok.type == tokenize.STRING:
            continue
        if tok.type == tokenize.COMMENT:
            continue
        out_tokens.append(tok.string)
    return " ".join(out_tokens)


# Synthetic violation canary constant — used by the canary test below.
# This string MUST NOT appear unwrapped in walker code; it appears
# wrapped here in a string literal so the gate's docstring-stripping
# would NOT see it. The canary test injects this string into a synthetic
# source body to confirm the gate fires.
_FORBIDDEN_CANARY = "exec"


# Forbidden-token list — patterns to scan for in CODE.
#
# IMPORTANT — the gate scans the OUTPUT of _strip_docstrings_and_comments,
# which joins Python tokens with spaces. So `obj.exec(...)` in real
# source becomes `obj . exec ( ... )` after stripping. Regexes below
# MUST be tolerant of single spaces between tokens that appear adjacent
# in source (i.e. ``\s*`` between every operator + name pair that
# mattered as adjacent in source).
_FORBIDDEN_EXEC_TOKENS: tuple[str, ...] = (
    # Bare ``exec(`` / ``eval(`` calls — catches `exec(code)`,
    # `eval(expr)`. Tokens get space-joined, so ``\bexec\s*\(`` matches
    # ``exec (`` in the stripped output.
    r"\bexec\s*\(",
    r"\beval\s*\(",
    # Bare ``compile(...)`` — catches `compile(src, ...)`. The
    # negative lookbehind excludes ``re.compile(``, ``regex.compile(``,
    # ``ast.compile(``, etc. — these are NOT runtime code execution
    # entry points. The bare ``compile`` builtin produces a code
    # object suitable for exec/eval — that IS the forbidden shape.
    r"(?<!\.)(?<!\s\.\s)\bcompile\s*\(",
    # runpy entry points — directly runs source/modules.
    r"\brunpy\s*\.\s*run_path\b",
    r"\brunpy\s*\.\s*run_module\b",
    # __import__ with a dynamic name — used to bypass static imports.
    # The walker DOES use ``import ast`` etc. but those are top-level
    # static; __import__ is forbidden.
    r"\b__import__\s*\(",
    # importlib runtime imports of firmware-derived names.
    r"\bimportlib\s*\.\s*import_module\b",
    # subprocess primitives — the walker is a pure-Python AST visitor;
    # any subprocess invocation would be a Rule #36 violation.
    r"subprocess\s*\.\s*(run|Popen|call|check_output|check_call)\b",
    r"asyncio\s*\.\s*create_subprocess_(exec|shell)\b",
    # os.system / execvp — same family.
    r"os\s*\.\s*(system|execvp|execve|spawnvp)\b",
)


def test_walker_no_decrypt_no_exec():
    """Rule #45 + Rule #36 — the python_ast_walker.py CODE (not docstrings
    / comments) MUST NOT invoke exec / eval / compile / runpy /
    importlib.import_module / subprocess / os.system on firmware code.

    PARSE-ONLY discipline is the CAMPAIGN-DEFINING constraint for the
    Python AST walker. ``ast.parse(source, mode='exec')`` IS allowed —
    it's a syntactic parser; ``mode='exec'`` is the AST grammar mode,
    NOT a runtime invocation. But ``exec(source)`` and friends are
    forbidden in walker CODE.

    Note: docstrings and comments LEGITIMATELY mention forbidden
    primitives (e.g. "NEVER calls compile/exec/runpy/importlib") — we
    strip them before scanning so the test catches actual code
    references only.
    """
    raw_source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "python_ast_walker.py"
    ).read_text()
    source = _strip_docstrings_and_comments(raw_source)

    for pattern in _FORBIDDEN_EXEC_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #45 / Rule #36 violation in python_ast_walker.py "
            f"CODE — found {matches} matching {pattern!r}; the walker "
            "MUST NOT invoke exec/eval/compile/runpy/importlib.import_"
            "module/subprocess on firmware-extracted source. PARSE-"
            "ONLY discipline only allows ast.parse() which is a "
            "syntactic parser that produces an AST tree without "
            "running any code."
        )


def test_walker_no_decrypt_gate_actually_fires():
    """Rule #46 META-CANARY — verify the test gate ACTUALLY fires on a
    synthetic violation.

    If we trust ``test_walker_no_decrypt_no_exec`` without confirming
    it catches violations, the gate could silently pass on legitimate
    violations (e.g. due to a tokenize bug, regex typo, etc.). This
    canary builds a synthetic source containing a forbidden CODE token
    (NOT inside a docstring/comment) and confirms:

    1. ``_strip_docstrings_and_comments`` preserves the code token.
    2. The forbidden-token regex matches the stripped source.

    The synthetic source is constructed via concatenation rather than
    an f-string to avoid being a single STRING token that
    ``_strip_docstrings_and_comments`` would drop entirely.
    """
    # Construct the synthetic source as a CONCATENATION of lines.
    # Both lines pass through the Python parser as actual code
    # (not as string literals) because they're at module scope when
    # passed to tokenize.generate_tokens.
    line_a = "def bad_walker():\n"
    line_b = "    src = 'x = 1'\n"
    # The CODE token below — `exec(src)` — survives tokenize stripping
    # because it's NOT a string literal in the input to
    # generate_tokens; tokenize sees `exec` (NAME), `(` (OP),
    # `src` (NAME), `)` (OP).
    line_c = "    " + _FORBIDDEN_CANARY + "(src)\n"
    line_d = "    return None\n"
    synthetic_source = line_a + line_b + line_c + line_d

    # Strip docstrings/comments — the canary call SHOULD survive
    # because `exec(src)` is CODE tokens, not a string literal.
    stripped = _strip_docstrings_and_comments(synthetic_source)

    # The gate's first forbidden-token pattern is `\bexec\s*\(`. Verify
    # the synthetic source WOULD match.
    pattern = r"\bexec\s*\("
    matches = re.findall(pattern, stripped)
    assert matches, (
        f"Test-gate canary FAILED — the synthetic violation "
        f"'{_FORBIDDEN_CANARY}' did NOT trigger the forbidden-token "
        f"regex {pattern!r}. stripped={stripped!r}. The gate is broken "
        "or the canary is miscalibrated. Without a working canary, "
        "test_walker_no_decrypt_no_exec could silently pass on real "
        "violations."
    )
    # Also verify the canary literal IS the forbidden token we expect.
    assert _FORBIDDEN_CANARY == "exec", (
        "The canary constant must equal 'exec' so the \\bexec\\s*\\("
        " regex catches it."
    )
    # Final correctness check — the EXACT regex from the gate's
    # _FORBIDDEN_EXEC_TOKENS list must also match.
    assert re.findall(_FORBIDDEN_EXEC_TOKENS[0], stripped), (
        "The gate's first forbidden-token regex must match the canary "
        "violation."
    )


def test_walker_no_decrypt_gate_excludes_docstring_mentions():
    """Sanity check — docstrings mentioning forbidden tokens DO NOT
    cause the gate to fire.

    The walker's docstrings LEGITIMATELY mention 'exec', 'compile',
    'runpy', 'importlib.import_module' etc. as part of the PARSE-ONLY
    discipline documentation. The tokenize-based stripping must
    remove these before the regex scan.
    """
    synthetic_docstring_source = '''
def safe_walker():
    """This function NEVER calls exec() and NEVER tries
    to compile() anything. It never invokes runpy.run_path
    or importlib.import_module. PARSE-ONLY."""
    return None
'''
    stripped = _strip_docstrings_and_comments(synthetic_docstring_source)

    # After stripping, the forbidden tokens should NOT appear in
    # executable-code form. The docstring's text content is dropped.
    for pattern in _FORBIDDEN_EXEC_TOKENS:
        matches = re.findall(pattern, stripped)
        assert not matches, (
            f"docstring sanity check FAILED — pattern {pattern!r} "
            f"matched {matches} in stripped docstring source "
            f"{stripped!r}. The tokenize stripping is leaking string "
            "literal content into the scanned output."
        )


def test_walker_allows_ast_parse():
    """Sanity check — ``ast.parse(...)`` IS allowed in walker code.

    ast.parse is a syntactic parser that produces an AST tree WITHOUT
    executing the parsed code. It IS the walker's reason for existing.
    The test confirms ast.parse appears in the (stripped) walker source
    — if it doesn't, something is structurally wrong with the walker.
    """
    raw_source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "python_ast_walker.py"
    ).read_text()
    source = _strip_docstrings_and_comments(raw_source)
    # ast . parse ( ... — note tokenize-induced spacing.
    assert re.search(r"\bast\s*\.\s*parse\s*\(", source), (
        "The walker source does NOT contain a call to ast.parse(...) "
        "— this is structurally wrong; the walker IS supposed to be "
        "a PARSE-ONLY AST visitor."
    )
