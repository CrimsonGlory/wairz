"""Q1 Python AST walker — static AST + import-graph reachability analysis.

Walks every Python source file in a firmware extraction, parses each
via :func:`ast.parse` (PARSE-ONLY — see Rule #45 + Rule #36 discipline
below), builds module-import + callable-reference graphs, identifies
entry-points (Flask/FastAPI route handlers, ``create_app`` factories,
``__main__`` blocks), and computes reachability of every (module,
callable) pair from the rooted entry-point set.

**Purpose.** For DS1 (Yocto-deployed ds1qrsetup Flask service at
``/opt/ds1qrsetup/``) and similar Python-on-firmware images, the
cve-assessment-framework (Round-9.1 §12 EG-8A.3-5) consumes the JSONB
aggregate to narrow Python CVE applicability via deployed-script grep
precedent. Example: 13 Round-20.2 Python EXPL CVEs (plistlib /
tarfile / multiprocessing.forkserver / etc.) expect this walker's
``modules_imported`` + ``callables_referenced`` reachability flags to
filter false-positives.

**Rule #39 inner/outer/safe runner triplet:**

- :func:`_do_python_ast_run` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every ``.py`` file in detection roots, parses each via
  :func:`ast.parse`, builds the import + call graphs, computes
  reachability, returns aggregate dict UNSTAMPED.
- :func:`run_python_ast_walk_background` — OUTER state-machine wrapper.
  Owns Rule #33 .a status transitions via ``async_session_factory()``.
- :func:`auto_python_ast_walk_firmware_safe` — UNPACK-POST-DETECTION
  hook. Runs the inner orchestrator but does NOT mutate
  ``python_ast_walk_status``.

**Rule #45 + Rule #36 PARSE-ONLY discipline.** ``ast.parse(source,
mode='exec')`` is a SYNTACTIC parser that produces an AST tree without
ever executing user code. wairz NEVER calls:

- ``compile()`` + ``exec()`` on the parsed source
- ``runpy.run_path()`` / ``runpy.run_module()``
- ``importlib.import_module(<firmware-derived-name>)``
- ``__import__()`` with a runtime-resolved name
- ``eval()`` / ``exec()`` of any string from firmware data

The walker IS allowed to ``import ast``, ``import os``, ``import
tokenize`` — these are wairz's OWN dependencies, not firmware code.
The PARSE-ONLY gate enforced in ``tests/test_python_ast_walker.py``
scans the walker source for forbidden-token combinations after
stripping docstrings + comments (Rule #46 META-CANARY).

**Rule #44 — cross-firmware MCP tool.** Companion file
``app/ai/tools/python_ast.py`` ships
``lookup_python_ast_across_firmwares`` to aggregate by module / callable
across the firmware corpus. Adding the same vulnerable callable across
multiple firmwares is a supply-chain signal.

**Rule #5 minimum-hop discipline.** ``ast.parse`` is CPU-bound; the
walker wraps file-reading + parsing in a single ``run_in_executor``
hop per file, not one hop per AST visit.
"""
from __future__ import annotations

import ast
import asyncio
import datetime as _dt
import logging
import os
import re
import time
import traceback
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_python_ast_walk_result,
)

logger = logging.getLogger(__name__)


# ── Runner tunables ──────────────────────────────────────────────────────────

# Per-walk wall-clock soft cap. Walker is bounded by file count + AST
# parse depth; healthy ds1qrsetup walks in <2s. Corrupted Python or
# massive ML stacks could send the parser into long iteration.
_DEFAULT_PER_WALK_TIMEOUT_SECONDS: float = 300.0

# Cap on Python files scanned per walk. Real Yocto firmwares typically
# carry 500-3000 .py files (Flask + dependencies); cap at 25k to keep
# aggregate size bounded for pathological corpora.
_DEFAULT_MAX_FILES_PER_WALK: int = 25_000

# Cap on bytes per .py file. Generated SQLAlchemy migrations or vendored
# ML model definitions can exceed 1 MB; the parser still works but the
# aggregate value-add drops. Files larger than this cap are recorded
# with a parse_skipped status.
_DEFAULT_MAX_FILE_BYTES: int = 2 * 1024 * 1024  # 2 MB

# Canonical Python source extensions. ``.pyw`` is the Windows GUI
# variant; ``.pyi`` is a stub file (still valid Python AST). ``.pyc`` /
# ``.pyo`` are compiled bytecode — NOT scanned (would require marshal
# decoding; out of scope for a PARSE-ONLY AST walker).
_PYTHON_SOURCE_EXTS: frozenset[str] = frozenset({".py", ".pyw", ".pyi"})

# Python-runtime-version shebang heuristic patterns. Detect:
#   #!/usr/bin/env python2.7
#   #!/usr/bin/python3.7
#   #!/usr/bin/python (no version pin → "unspecified")
# Word boundaries (\b) prevent "python" matching inside "pythonista";
# the [^\n]*? prefix non-greedily skips over /usr/bin/env / interpreter
# paths between #! and the literal "python" name.
_PYTHON_SHEBANG_RE = re.compile(
    r"^#![^\n]*?\bpython(?P<version>\d(?:\.\d+)?)?\b", re.MULTILINE
)

# Canonical entry-point detection patterns. Walker matches a function /
# class definition against this set to classify it as a "root".
_ENTRY_POINT_PATTERNS: tuple[tuple[str, str], ...] = (
    # Flask app factory pattern: def create_app(...): ...
    ("create_app", "flask_factory"),
    # Common Flask handler-registration entry points.
    ("register_routes", "flask_routes"),
    ("register_blueprints", "flask_blueprints"),
    # FastAPI app instantiation pattern.
    ("main", "main_entry"),
)

# Decorator names that mark a function as a route handler (entry point).
# Detection inspects ``@<name>.<method>(...)`` and ``@<name>(...)`` AST
# shapes.
_ROUTE_DECORATOR_METHODS: frozenset[str] = frozenset({
    "route",  # Flask: @app.route(...)
    "get", "post", "put", "delete", "patch",  # FastAPI: @app.get(...)
    "options", "head",  # HTTP method routes
    "websocket",  # FastAPI websocket
    "include_router",  # FastAPI sub-router
    "before_request", "after_request",  # Flask request hooks
    "errorhandler",  # Flask error handlers
})


# ── Filesystem scan ──────────────────────────────────────────────────────────


def walk_python_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return every Python source path.

    Mirrors the SRUM / EVTX / Prefetch walker shape: case-insensitive
    extension match + sandbox check that rejects symlinks pointing
    outside the root tree (Rule #1 spirit).

    Sync I/O — wrap in run_in_executor for async callers (Rule #5).
    Defensive against missing roots / permission errors.
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if not os.path.isdir(real_root):
            continue
        # noqa: ASYNC240 — bounded loop over <= 3 detection roots
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for name in filenames:
                lower = name.lower()
                ext = os.path.splitext(lower)[1]
                if ext not in _PYTHON_SOURCE_EXTS:
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                try:
                    if not os.path.isfile(real_full):
                        continue
                except OSError:
                    continue
                hits.append(real_full)
    return hits


async def _walk_python_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_python_files` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_python_files, roots)


# ── Path helpers ─────────────────────────────────────────────────────────────


def _relativize_path(full_path: str, roots: list[str]) -> str:
    """Compute path relative to whichever detection root contains it."""
    try:
        real_full = os.path.realpath(full_path)
    except OSError:
        return os.path.basename(full_path)
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if real_full == real_root or real_full.startswith(real_root + os.sep):
            return real_full[len(real_root) + 1:] if real_full != real_root else "."
    return os.path.basename(full_path)


def _module_qualname(rel_path: str) -> str:
    """Derive a Python module qualified name from a relative path.

    Example:
        ds1qrsetup/app/routes.py → ds1qrsetup.app.routes
        ds1qrsetup/__init__.py → ds1qrsetup
    """
    # Drop the source extension.
    no_ext, _ = os.path.splitext(rel_path)
    parts = [p for p in no_ext.split(os.sep) if p]
    # Drop trailing __init__ segments — they ARE the package, not a
    # submodule.
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) if parts else os.path.basename(rel_path)


# ── Python version detection ─────────────────────────────────────────────────


def detect_python_versions(source_samples: list[str]) -> list[str]:
    """Detect Python interpreter versions referenced in firmware.

    Inspects shebang lines + interpreter-name string heuristics across
    a sample of files. Returns the unique version strings sorted.

    Falls back to the empty list if no version evidence is found —
    caller surfaces this as ``python_version_detected: []`` in the
    aggregate (operator-actionable signal that no shebangs landed).
    """
    versions: set[str] = set()
    for source in source_samples:
        # Read at most the first ~1KB; shebang must be the first line.
        prefix = source[:1024] if source else ""
        for match in _PYTHON_SHEBANG_RE.finditer(prefix):
            v = match.group("version")
            if v:
                versions.add(v)
            else:
                # Bare "python" — no version pin.
                versions.add("unspecified")
    return sorted(versions)


# ── AST visitor — single-file graph builder ──────────────────────────────────


class _PythonAstVisitor(ast.NodeVisitor):
    """Walk a single Python file's AST and collect import + call edges.

    PARSE-ONLY discipline — never invokes the parsed code; the visitor
    is a pure tree walker.
    """

    def __init__(self, *, rel_path: str, module_qualname: str) -> None:
        self.rel_path = rel_path
        self.module_qualname = module_qualname
        # Modules imported by this file (e.g. {"tarfile", "os.path"}).
        self.imported_modules: set[str] = set()
        # Per-import-statement source positions.
        # {module_name: [(rel_path, line)]}
        self.import_sites: dict[str, list[tuple[str, int]]] = {}
        # Aliases for ``import X as Y`` / ``from X import Y as Z``.
        # {alias_name: full_qualname}
        self.aliases: dict[str, str] = {}
        # Callables referenced (str of qualified target name).
        # {"tarfile.open": [(rel_path, line)], ...}
        self.callable_sites: dict[str, list[tuple[str, int]]] = {}
        # Functions / classes defined in this file (their qualnames).
        self.defined_functions: list[str] = []
        # Local function-name → list of called callables (for call-graph
        # reachability). Key is qualname like "module.func"; value is
        # list of resolved qualnames called from inside it.
        self.calls_from: dict[str, list[str]] = {}
        # Entry-point function names defined in this file (qualname →
        # type tag).
        self.entry_points: list[tuple[str, str]] = []
        # Tracks the current enclosing function qualname (for call-graph
        # building during recursion).
        self._enclosing_qualname: list[str] = []

    # ── Import statements ────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        """``import X`` / ``import X as Y`` / ``import X.Y.Z``."""
        for alias in node.names:
            module = alias.name
            self.imported_modules.add(module)
            self.import_sites.setdefault(module, []).append(
                (self.rel_path, node.lineno)
            )
            local_name = alias.asname or module.split(".")[0]
            self.aliases[local_name] = module
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """``from X import Y`` / ``from X.Y import Z as W``."""
        module = node.module or ""
        if module:
            self.imported_modules.add(module)
            self.import_sites.setdefault(module, []).append(
                (self.rel_path, node.lineno)
            )
        for alias in node.names:
            if alias.name == "*":
                continue
            qualname = f"{module}.{alias.name}" if module else alias.name
            local_name = alias.asname or alias.name
            self.aliases[local_name] = qualname
        self.generic_visit(node)

    # ── Function / class definitions ─────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """``def foo(...): ...`` — record definition + detect entry-points."""
        self._handle_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """``async def foo(...): ...``."""
        self._handle_function(node)

    def _handle_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        qualname = (
            f"{self.module_qualname}.{node.name}"
            if self.module_qualname
            else node.name
        )
        self.defined_functions.append(qualname)

        # Entry-point classification by name.
        for pattern_name, pattern_type in _ENTRY_POINT_PATTERNS:
            if node.name == pattern_name:
                self.entry_points.append((qualname, pattern_type))
                break

        # Entry-point classification by decorator (route handlers).
        for decorator in node.decorator_list:
            tag = self._classify_route_decorator(decorator)
            if tag is not None:
                self.entry_points.append((qualname, tag))
                break

        # Recurse into the body, tracking the enclosing qualname so
        # nested calls land in the right call-graph bucket.
        self._enclosing_qualname.append(qualname)
        try:
            self.generic_visit(node)
        finally:
            self._enclosing_qualname.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualname = (
            f"{self.module_qualname}.{node.name}"
            if self.module_qualname
            else node.name
        )
        # Treat classes like functions for enclosing-context tracking.
        self._enclosing_qualname.append(qualname)
        try:
            self.generic_visit(node)
        finally:
            self._enclosing_qualname.pop()

    def _classify_route_decorator(
        self, decorator: ast.expr
    ) -> str | None:
        """Classify a decorator expression as a route handler if applicable.

        Matches both ``@app.route(...)`` and ``@router.get(...)`` AST
        shapes. Returns a string tag like "flask_route" /
        "fastapi_get" / None if the decorator is not a route.
        """
        # ``@app.route(...)`` / ``@app.get(...)`` — a Call whose func
        # is an Attribute on a Name.
        func = decorator
        if isinstance(decorator, ast.Call):
            func = decorator.func
        if isinstance(func, ast.Attribute):
            attr = func.attr
            if attr in _ROUTE_DECORATOR_METHODS:
                # Build a tag like "flask_route" / "fastapi_get".
                if attr == "route":
                    return "flask_route"
                return f"fastapi_{attr}"
        if isinstance(func, ast.Name) and func.id in _ROUTE_DECORATOR_METHODS:
            # Bare ``@route(...)`` — less common; still a route.
            return f"route_{func.id}"
        return None

    # ── Call expressions ─────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        """Record callable references for reachability analysis."""
        target = self._resolve_call_target(node.func)
        if target is not None:
            self.callable_sites.setdefault(target, []).append(
                (self.rel_path, node.lineno)
            )
            # Record in the call graph for reachability propagation.
            if self._enclosing_qualname:
                caller = self._enclosing_qualname[-1]
                self.calls_from.setdefault(caller, []).append(target)
        self.generic_visit(node)

    def _resolve_call_target(self, func: ast.expr) -> str | None:
        """Resolve a call's func expression to a qualified-name string.

        Handles:
        - ``foo(...)`` → resolves "foo" via self.aliases (so
          ``from tarfile import open; open(...)`` → "tarfile.open").
        - ``mod.foo(...)`` → resolves "mod" via self.aliases, joins
          with attribute name (so ``import tarfile; tarfile.open(...)``
          → "tarfile.open").
        - ``a.b.c.foo(...)`` → walks the Attribute chain.
        - Anything else → returns None (lambda calls, indexed calls,
          dynamic attribute access).
        """
        if isinstance(func, ast.Name):
            return self.aliases.get(func.id, func.id)
        if isinstance(func, ast.Attribute):
            chain: list[str] = []
            cur: ast.expr = func
            while isinstance(cur, ast.Attribute):
                chain.append(cur.attr)
                cur = cur.value
            chain.reverse()
            if isinstance(cur, ast.Name):
                # Resolve the head against self.aliases.
                head = self.aliases.get(cur.id, cur.id)
                return f"{head}." + ".".join(chain)
            return None
        return None

    # ── __main__ block detection ─────────────────────────────────────────

    def visit_If(self, node: ast.If) -> None:
        """Detect ``if __name__ == '__main__':`` blocks as entry points."""
        test = node.test
        # Pattern: __name__ == "__main__"  (Compare with Eq + str literal).
        if isinstance(test, ast.Compare) and len(test.comparators) == 1:
            left = test.left
            right = test.comparators[0]
            is_main_check = (
                isinstance(left, ast.Name) and left.id == "__name__"
                and isinstance(right, ast.Constant) and right.value == "__main__"
            )
            if is_main_check:
                self.entry_points.append(
                    (f"{self.module_qualname}.__main__", "main_block")
                )
        self.generic_visit(node)


# ── Per-file AST parse + visit ───────────────────────────────────────────────


def _parse_and_visit_file(
    path: str,
    rel_path: str,
    *,
    max_bytes: int = _DEFAULT_MAX_FILE_BYTES,
) -> tuple[_PythonAstVisitor | None, str | None, str | None]:
    """Read + parse + visit a single Python source file.

    Returns ``(visitor, source_text, error_str)``:
    - On success: ``(visitor, source_text, None)``
    - On read/parse error: ``(None, None, error_str)``
    - On skip (oversized): ``(None, source_prefix, None)`` — source_prefix
      is used for shebang detection even when the full parse skipped.

    PARSE-ONLY: ``ast.parse(source, mode='exec')`` does NOT execute the
    parsed code. Per Rule #45 + Rule #36 — see module docstring.
    """
    try:
        file_size = os.path.getsize(path)
    except OSError as exc:
        return None, None, f"stat failed: {type(exc).__name__}: {exc}"

    if file_size > max_bytes:
        # Read just the first 1 KB for shebang detection.
        try:
            with open(path, "rb") as fh:
                head = fh.read(1024)
            source_prefix = head.decode("utf-8", errors="replace")
        except OSError:
            source_prefix = ""
        return None, source_prefix, None

    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return None, None, f"read failed: {type(exc).__name__}: {exc}"

    # Decode tolerantly — firmware sources sometimes carry latin-1 or
    # mixed encodings.
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            source = raw.decode("latin-1")
        except UnicodeDecodeError as exc:
            return None, None, f"decode failed: {exc}"

    # **PARSE-ONLY** — ast.parse produces a tree; it never runs the code.
    try:
        tree = ast.parse(source, filename=rel_path, mode="exec")
    except SyntaxError as exc:
        # Common for Python 2 sources parsed by Python 3 (``print`` as
        # statement, ``except X, e:`` legacy syntax). Record as error,
        # surface in aggregate.
        return None, source, f"syntax error: {exc.msg} (line {exc.lineno})"
    except (ValueError, RecursionError) as exc:
        return None, source, f"parse failed: {type(exc).__name__}: {exc}"

    module_qualname = _module_qualname(rel_path)
    visitor = _PythonAstVisitor(
        rel_path=rel_path, module_qualname=module_qualname
    )
    try:
        visitor.visit(tree)
    except RecursionError as exc:
        return None, source, f"visit failed: {exc}"

    return visitor, source, None


def _walk_python_files_sync(
    paths: list[str],
    roots: list[str],
    max_files: int,
    max_bytes: int,
) -> dict[str, Any]:
    """Sync helper that iterates `paths`, parses each, and aggregates.

    Runs in a thread pool via run_in_executor (Rule #5 — CPU-bound).
    """
    # Aggregate state.
    modules_imported: dict[str, dict[str, Any]] = {}
    callables_referenced: dict[str, dict[str, Any]] = {}
    entry_points: list[dict[str, Any]] = []
    files_scanned: int = 0
    parse_errors: list[str] = []
    source_samples: list[str] = []
    # Module qualnames defined in this firmware (file basename
    # canonicalisation). Used to mark "local" modules vs stdlib/external.
    local_modules: set[str] = set()
    # Call graph: caller-qualname → list[callee-qualname]
    call_graph: dict[str, list[str]] = {}
    # Maps callable qualname → list of source positions.
    callable_call_sites: dict[str, list[str]] = {}
    # Set of entry-point qualnames (for BFS roots).
    entry_qualnames: set[str] = set()

    truncated = False
    for path in paths:
        if files_scanned >= max_files:
            truncated = True
            break
        rel_path = _relativize_path(path, roots)
        visitor, source, error = _parse_and_visit_file(
            path, rel_path, max_bytes=max_bytes
        )
        files_scanned += 1
        if source is not None and len(source_samples) < 200:
            # Cap sample retention so the aggregate stays small in
            # memory; 200 shebangs is more than enough to detect
            # python_version.
            source_samples.append(source[:1024])
        if error is not None:
            parse_errors.append(f"{rel_path}: {error}")
            continue
        if visitor is None:
            # Oversized file — already-recorded source_prefix for shebang.
            continue

        # Local module qualname accounting.
        if visitor.module_qualname:
            local_modules.add(visitor.module_qualname)

        # Merge imports.
        for module in visitor.imported_modules:
            slot = modules_imported.setdefault(
                module, {"imported_from": [], "reachable_from_entry": False}
            )
            for rp, lineno in visitor.import_sites.get(module, []):
                slot["imported_from"].append(f"{rp}:{lineno}")

        # Merge callable references.
        for target, sites in visitor.callable_sites.items():
            slot = callables_referenced.setdefault(
                target, {"called_from": [], "reachable_from_entry": False}
            )
            for rp, lineno in sites:
                slot["called_from"].append(f"{rp}:{lineno}")
            callable_call_sites.setdefault(target, []).extend(
                f"{rp}:{lineno}" for rp, lineno in sites
            )

        # Merge call graph.
        for caller, callees in visitor.calls_from.items():
            call_graph.setdefault(caller, []).extend(callees)

        # Merge entry points.
        for qualname, ep_type in visitor.entry_points:
            entry_points.append({
                "file": rel_path,
                "entry_function": qualname.rsplit(".", 1)[-1],
                "qualname": qualname,
                "type": ep_type,
            })
            entry_qualnames.add(qualname)

    # ── Reachability analysis ────────────────────────────────────────────
    #
    # BFS over the call graph starting from every entry-point qualname.
    # Any callable transitively reached gets reachable_from_entry=True;
    # the module hosting it gets reachable=True as well.
    reachable_callables: set[str] = set()
    queue: list[str] = list(entry_qualnames)
    visited: set[str] = set()
    while queue:
        cur = queue.pop()
        if cur in visited:
            continue
        visited.add(cur)
        reachable_callables.add(cur)
        for callee in call_graph.get(cur, []):
            reachable_callables.add(callee)
            if callee in call_graph and callee not in visited:
                queue.append(callee)

    # Mark modules reachable when they host a reachable callable OR a
    # called-target whose head segment maps to an imported module.
    reachable_modules: set[str] = set()
    for callable_qualname in reachable_callables:
        # The module of a callable qualname is the prefix up to the last
        # dot — e.g. "tarfile.open" → "tarfile"; "ds1qrsetup.app.routes.handler"
        # → "ds1qrsetup.app.routes" (which is a LOCAL module; we also
        # mark the head "tarfile" as imported-and-reached if it appears).
        if "." in callable_qualname:
            module_part = callable_qualname.rsplit(".", 1)[0]
            reachable_modules.add(module_part)
            # Walk up the module hierarchy so "tarfile" is reached when
            # "tarfile.TarFile.extractall" is reached.
            parts = module_part.split(".")
            for i in range(1, len(parts) + 1):
                reachable_modules.add(".".join(parts[:i]))

    # Stamp reachability flags onto the aggregated dicts.
    for module, slot in modules_imported.items():
        if module in reachable_modules:
            slot["reachable_from_entry"] = True
        # Walk up: if "tarfile.open" was reached but the slot key is
        # "tarfile", we still want the module to count as reached.
        else:
            parts = module.split(".")
            for i in range(1, len(parts) + 1):
                if ".".join(parts[:i]) in reachable_modules:
                    slot["reachable_from_entry"] = True
                    break
    for callable_qualname, slot in callables_referenced.items():
        if callable_qualname in reachable_callables:
            slot["reachable_from_entry"] = True

    # Unreachable-module list — imported BUT never reached from entry.
    unreachable_modules = sorted(
        m for m, slot in modules_imported.items()
        if not slot.get("reachable_from_entry")
    )

    # Python version detection.
    python_versions = detect_python_versions(source_samples)

    # Summary aggregates.
    entry_reachable_modules_count = sum(
        1 for slot in modules_imported.values()
        if slot.get("reachable_from_entry")
    )
    entry_reachable_callables_count = sum(
        1 for slot in callables_referenced.values()
        if slot.get("reachable_from_entry")
    )

    return {
        "modules_imported": modules_imported,
        "callables_referenced": callables_referenced,
        "entry_points": entry_points,
        "files_scanned": files_scanned,
        "parse_errors": parse_errors,
        "python_version_detected": python_versions,
        "unreachable_modules": unreachable_modules,
        "summary": {
            "files_scanned": files_scanned,
            "modules_imported_count": len(modules_imported),
            "callables_referenced_count": len(callables_referenced),
            "entry_reachable_modules_count": entry_reachable_modules_count,
            "entry_reachable_callables_count": entry_reachable_callables_count,
            "entry_points_count": len(entry_points),
            "truncated": truncated,
        },
    }


# ── Inner orchestrator (accepts a db; reusable in tier-1 live canaries) ──────


async def _do_python_ast_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_files: int = _DEFAULT_MAX_FILES_PER_WALK,
    max_bytes: int = _DEFAULT_MAX_FILE_BYTES,
) -> dict[str, Any]:
    """Run the Python AST walk against ``firmware_id``'s extracted tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for Python source files.
    3. Run :func:`_walk_python_files_sync` in a thread-pool executor
       (Rule #5 — ``ast.parse`` is CPU-bound; one hop per walk).
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) drive the FULL walk against a real test
    DB without DNS resolution issues from ``async_session_factory()``.
    """
    started = time.monotonic()

    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        return _empty_walk_result(0.0, str(firmware_id))

    roots = await get_detection_roots(firmware, db=db)
    if not roots:
        return _empty_walk_result(
            time.monotonic() - started, str(firmware_id)
        )

    py_paths = await _walk_python_files_async(roots)
    if not py_paths:
        result = _empty_walk_result(
            time.monotonic() - started, str(firmware_id)
        )
        result["extracted_root_paths_scanned"] = [
            _relativize_path(r, roots) or r for r in roots
        ]
        return result

    # Rule #5 — one executor hop for the whole walk.
    loop = asyncio.get_running_loop()
    walked = await loop.run_in_executor(
        None,
        _walk_python_files_sync,
        py_paths,
        roots,
        max_files,
        max_bytes,
    )

    run_seconds = round(time.monotonic() - started, 3)
    walked["summary"]["run_seconds"] = run_seconds

    return {
        "firmware_id": str(firmware_id),
        "walker": "python_ast_walker",
        "extracted_root_paths_scanned": [
            _relativize_path(r, roots) or r for r in roots
        ],
        "python_version_detected": walked["python_version_detected"],
        "entry_points": walked["entry_points"],
        "modules_imported": walked["modules_imported"],
        "callables_referenced": walked["callables_referenced"],
        "unreachable_modules": walked["unreachable_modules"],
        "summary": walked["summary"],
        "errors": walked["parse_errors"],
        "axiom_self_audit": (
            "PARSE-ONLY discipline: ast.parse(mode='exec') only — "
            "wairz never calls compile/exec/runpy/importlib on "
            "firmware-extracted source. Rule #45 + Rule #36."
        ),
    }


def _empty_walk_result(run_seconds: float, firmware_id: str) -> dict[str, Any]:
    return {
        "firmware_id": firmware_id,
        "walker": "python_ast_walker",
        "extracted_root_paths_scanned": [],
        "python_version_detected": [],
        "entry_points": [],
        "modules_imported": {},
        "callables_referenced": {},
        "unreachable_modules": [],
        "summary": {
            "files_scanned": 0,
            "modules_imported_count": 0,
            "callables_referenced_count": 0,
            "entry_reachable_modules_count": 0,
            "entry_reachable_callables_count": 0,
            "entry_points_count": 0,
            "run_seconds": round(run_seconds, 3),
            "truncated": False,
        },
        "errors": [],
        "axiom_self_audit": (
            "PARSE-ONLY discipline: ast.parse(mode='exec') only — "
            "wairz never calls compile/exec/runpy/importlib on "
            "firmware-extracted source. Rule #45 + Rule #36."
        ),
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_python_ast_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the Python AST walk.

    Owns AsyncSession via :func:`async_session_factory`; outer guard
    catches escapes; failure persistence on a fresh session. Mirrors
    γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B shape exactly.
    """
    try:
        async with async_session_factory() as db:
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is None:
                logger.warning(
                    "python_ast_walk: firmware %s not found", firmware_id
                )
                return

            row.python_ast_walk_status = "running"
            row.python_ast_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_python_ast_run(db, firmware_id)
                row.python_ast_walk_status = "completed"
                row.python_ast_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.python_ast_walk_result = (
                    _stamp_firmware_python_ast_walk_result(result)
                )
                await db.commit()
                logger.info(
                    "python_ast_walk: firmware %s completed in %.2fs "
                    "(%d files, %d modules, %d callables, %d entry-points)",
                    firmware_id,
                    result["summary"]["run_seconds"],
                    result["summary"]["files_scanned"],
                    result["summary"]["modules_imported_count"],
                    result["summary"]["callables_referenced_count"],
                    result["summary"]["entry_points_count"],
                )
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(
                        type(exc), exc, exc.__traceback__
                    )
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.python_ast_walk_status = "failed"
                        fail_row.python_ast_walk_finished_at = _dt.datetime.now(
                            _dt.UTC
                        )
                        fail_row.python_ast_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "python_ast_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "python_ast_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_python_ast_walk_firmware_safe(
    firmware_id: uuid.UUID,
) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes.

    Per Rule #39 .safe contract:
    - Owns its own AsyncSession.
    - Swallows exceptions silently.
    - Stamps the JSONB result so operators see last-known-result.
    - Does NOT mutate ``python_ast_walk_status`` — leaves it ``idle``
      so an operator-triggered re-walk via ``trigger_python_ast_walk``
      MCP tool succeeds without 409 conflict.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_python_ast_run(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.python_ast_walk_result = (
                    _stamp_firmware_python_ast_walk_result(result)
                )
                await db.commit()
            logger.info(
                "python_ast_walk auto: firmware %s walked %d files in "
                "%.2fs (%d entry-points, %d reachable modules)",
                firmware_id,
                result["summary"]["files_scanned"],
                result["summary"]["run_seconds"],
                result["summary"]["entry_points_count"],
                result["summary"]["entry_reachable_modules_count"],
            )
    except Exception:
        logger.warning(
            "python_ast_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_python_ast_run",
    "auto_python_ast_walk_firmware_safe",
    "detect_python_versions",
    "run_python_ast_walk_background",
    "walk_python_files",
]
