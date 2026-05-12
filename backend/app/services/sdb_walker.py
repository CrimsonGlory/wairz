"""Phase θ.D — Windows Application Compatibility Shim Database walker.

Walks `.sdb` files in a firmware capture's detection roots; parses
each file via the vendored python_sdb clean-room parser (θ.D.A);
extracts APP / SHIM / PATCH entries; classifies each by shim_class
(RedirectEXE / InjectDll / GetCommandLineW / RedirectShortcut /
Custom / Patch / Other) AND sdb_kind (microsoft / custom / unknown);
and persists a per-entry ``WindowsSdbEntry`` row for downstream
finding-emit hooks (θ.D.E). Closes the θ campaign as the 5th of 5
walker streams (θ.A BCD + θ.B WMI + θ.C ESP + θ.E MBR/VBR + θ.D SDB).

**Rule #39 inner/outer/safe runner triplet** (γ.4 + δ.5 + ε.1.b.3 +
ζ.2.B + ζ.3.B + η.B.C + η.C.C + η.A.C + θ.A.C + θ.B.D + θ.C.C +
θ.E.C + θ.D.D = Rule-of-Thirteen):

- :func:`_do_sdb_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every `.sdb` candidate under detection roots,
  parses bytes via python_sdb, classifies each TAG_SHIM / TAG_PATCH,
  persists per-entry ``WindowsSdbEntry`` rows, returns aggregate
  dict UNSTAMPED.
- :func:`run_sdb_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer guard
  catches escapes; failure persistence on a fresh session.
- :func:`auto_sdb_walk_firmware_safe` — UNPACK-POST-DETECTION
  hook. Runs the inner orchestrator + emit hook but does NOT mutate
  ``sdb_walk_status`` (leaves ``idle`` so manual re-trigger works
  without 409 conflict).

**Rule #36 no-execute discipline.** `.sdb` files describe shim
instructions that Windows loads + executes via AppHelp / sdbinst
infrastructure on every application launch. The walker parses bytes
via the vendored python_sdb (no execution); NO codepath:

- Invokes ``sdbinst.exe`` / ``AppHelp.dll`` / ``Mscoree.dll`` /
  any process-spawn primitive against the `.sdb` files.
- Loads the .sdb into a shim execution context.
- Transfers control to the parsed shim's DLL or executable
  reference.

The shim entries surface as DATA in
``WindowsSdbEntry.shim_payload`` + Finding evidence; operator
review only. The test gate
``tests/test_sdb_walker.py::test_sdb_no_shim_execution`` asserts
this discipline programmatically.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare
``firmware.extracted_path``) so multi-archive Windows extracts
surface every `.sdb` candidate (full partition image, partial
AppPatch directory extract, etc.).

**Performance.** Parsing one `.sdb` is sub-second (typical files are
50 KB – 5 MB; sysmain.sdb is the largest commonly seen). The full
walker on a typical Windows extract scans 5-50 `.sdb` files —
single-digit seconds wall-time per firmware. We cap at 500 persisted
entries per firmware (``_DEFAULT_MAX_ENTRIES_PER_FIRMWARE``)
defensive against attacker-planted multi-megabyte shim dumps.

**Cross-firmware fingerprint.** ``WindowsSdbEntry.fingerprint_sha256``
is SHA256 of ``(file_path_lower + "|" + file_sha256 + "|" +
shim_class + "|" + shim_name)`` — same fingerprint across
firmware ⇒ same shim was planted. Surfaces via the θ.D.F
``lookup_sdb_shim`` MCP tool for cross-corpus shim hunt.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_sdb_entry import WindowsSdbEntry
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_sdb_walk_result,
    _stamp_windows_sdb_entries_anomaly_flags,
    _stamp_windows_sdb_entries_shim_payload,
)
from third_party.python_sdb import (
    InvalidSDBFileError,
    ParsedSDB,
    SDBApp,
    SDBPatch,
    SDBShim,
    parse_sdb,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum SDB entries persisted per firmware. A typical Windows
# extract has 5-50 `.sdb` files × 1-50 shims each — 500 covers
# attacker-DoS / vendor-bloated cases.
_DEFAULT_MAX_ENTRIES_PER_FIRMWARE: int = 500

# Cap on `.sdb` file size to attempt. Real shim databases are 50 KB
# – 5 MB; sysmain.sdb tops out around 5 MB. 64 MiB is the hard
# safety bound (also enforced inside parse_sdb).
_DEFAULT_MAX_FILE_BYTES: int = 64 * 1024 * 1024

# Minimum `.sdb` size — must be at least the header size.
_MIN_FILE_BYTES: int = 12


# ── `.sdb` file extension allow-list ────────────────────────────────────────

# Extensions we'll attempt to parse. `.sdb` is the only canonical
# extension; `.sdbx` is hypothetical compressed variant — wairz
# walker is conservative and only scans `.sdb`.
_SDB_EXTENSIONS: tuple[str, ...] = (".sdb",)


# ── Known-bad shim primitive names (Rule #19 inline) ────────────────────────
#
# These are the canonical T1546.011 attacker primitives — direct
# code-execution / process-replacement / argument-injection shim
# names. A SHIM whose name matches one of these is a HIGH-confidence
# triage candidate (the classifier in θ.D.E uses these for emit
# tier mapping).
#
# Reference: Microsoft Application Compatibility Toolkit (ACT) and
# the AppHelp DLL implementation; pre-installed shim names are
# publicly documented in the Windows SDK.

_KNOWN_BAD_SHIM_NAMES: dict[str, str] = {
    # Direct DLL injection — the most common attacker primitive.
    "InjectDll": "InjectDll",
    # EXE replacement — replaces the executed binary entirely.
    "RedirectEXE": "RedirectEXE",
    # Command-line hook — argument-injection / spoofing.
    "GetCommandLineW": "GetCommandLineW",
    "GetCommandLineA": "GetCommandLineW",  # ANSI variant; same class
    # Shortcut hijack — redirects shortcut-target resolution.
    "RedirectShortcut": "RedirectShortcut",
}


# ── SDB-kind classification ─────────────────────────────────────────────────


def classify_sdb_kind(file_path: str) -> str:
    """Classify an `.sdb` file by its location within the Windows
    AppPatch directory hierarchy.

    Returns one of: 'microsoft', 'custom', 'unknown'. Pure function.

    - 'custom': file lives under ``Windows/AppPatch/Custom/`` or
      ``Windows/AppPatch/Custom64/`` (attacker / per-app shim
      installation location for T1546.011).
    - 'microsoft': file lives DIRECTLY under ``Windows/AppPatch/``
      (legitimate Microsoft-shipped: sysmain.sdb, apphelp.sdb,
      drvmain.sdb, mshtmlmedia.sdb, etc.).
    - 'unknown': file has a `.sdb` extension but lives in a non-
      standard location (still suspicious — `.sdb` outside the
      AppPatch hierarchy is anomalous).
    """
    norm = file_path.replace("\\", "/").lower()
    # Custom directory check first (more specific).
    if "windows/apppatch/custom/" in norm or (
        "windows/apppatch/custom64/" in norm
    ):
        return "custom"
    # Microsoft directory check.
    if "windows/apppatch/" in norm:
        # Make sure it's not under Custom/ which we already handled.
        return "microsoft"
    return "unknown"


def classify_shim_class(shim_name: str) -> str:
    """Classify a SHIM by its name into the 7-state shim_class enum.

    Returns one of the canonical shim_class values matching
    ``SdbShimClass`` in ``app/schemas/firmware.py``. Pure function.
    """
    if not shim_name:
        return "Other"
    if shim_name in _KNOWN_BAD_SHIM_NAMES:
        return _KNOWN_BAD_SHIM_NAMES[shim_name]
    return "Custom"


# ── Anomaly classification ──────────────────────────────────────────────────


def _is_dll_outside_appdir(dll_path: str, app_exe: str) -> bool:
    """Heuristic — return True if ``dll_path`` is not in an
    expected location (system32, syswow64, the application's own
    directory, or under Windows/).

    Conservative: a relative path or a path containing /Temp/,
    /Users/Public/, /ProgramData/ raises the flag.
    """
    if not dll_path:
        return False
    norm = dll_path.replace("\\", "/").lower()
    # Trusted Windows locations.
    if any(s in norm for s in (
        "system32/", "syswow64/", "windows/winsxs/",
    )):
        return False
    # Untrusted-shape locations.
    if any(s in norm for s in (
        "/temp/", "/tmp/", "/users/public/", "/programdata/",
    )):
        return True
    # Relative DLL paths (no slash) are typically loaded from the
    # application's own directory — not suspicious in themselves.
    if "/" not in norm and "\\" not in dll_path:
        return False
    return True


def build_anomaly_flags(
    *,
    sdb_kind: str,
    shim_class: str,
    shim_name: str,
    module: str,
    command_line: str,
    app_exe: str,
) -> dict:
    """Construct the anomaly_flags payload for one shim entry.

    Pure function. Heuristic detection inputs for the θ.D.E
    classifier:

    - is_custom_path: sdb_kind == 'custom' (the .sdb itself lives in
      Custom/ — strong signal regardless of shim contents).
    - has_inject_dll: shim_class == 'InjectDll'.
    - has_redirect_exe: shim_class == 'RedirectEXE'.
    - has_get_command_line: shim_class == 'GetCommandLineW'.
    - has_redirect_shortcut: shim_class == 'RedirectShortcut'.
    - has_dll_outside_appdir: shim's module/DLL filename resolves
      to a non-system, non-application location (heuristic above).
    - has_command_line: shim carries a TAG_COMMAND_LINE (most
      legitimate shims don't; argument-injection / process-replace
      tradecraft does).
    """
    return {
        "is_custom_path": sdb_kind == "custom",
        "has_inject_dll": shim_class == "InjectDll",
        "has_redirect_exe": shim_class == "RedirectEXE",
        "has_get_command_line": shim_class == "GetCommandLineW",
        "has_redirect_shortcut": shim_class == "RedirectShortcut",
        "has_dll_outside_appdir": _is_dll_outside_appdir(module, app_exe),
        "has_command_line": bool(command_line),
    }


def compute_entry_fingerprint(
    *,
    file_path: str,
    file_sha256: str,
    shim_class: str,
    shim_name: str,
) -> str:
    """Compute SHA256(file_path_lower + "|" + file_sha256 + "|" +
    shim_class + "|" + shim_name). Same fingerprint across firmware
    ⇒ same shim was planted."""
    payload = (
        f"{file_path.lower()}|{file_sha256}|"
        f"{shim_class}|{shim_name}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── `.sdb` file enumeration ──────────────────────────────────────────────────


def walk_sdb_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return candidate `.sdb` file
    paths.

    Returns files with the ``.sdb`` extension whose size is between
    the minimum header bytes and the max-file-bytes cap. Sync I/O —
    wrap in ``run_in_executor`` for async callers (Rule #5).

    Defensive against missing roots, permission errors — every error
    path is swallowed at the per-root / per-file level so one
    corrupted detection root doesn't abort the entire walk.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots` — NEVER ``firmware.extracted_path``
    alone.
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
        except OSError:
            continue
        if not os.path.isdir(real_root):  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            continue
        for dirpath, _dirnames, filenames in os.walk(  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            real_root, followlinks=False
        ):
            for name in filenames:
                lower = name.lower()
                if not any(
                    lower.endswith(ext) for ext in _SDB_EXTENSIONS
                ):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math + one realpath per candidate
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                try:
                    size = os.path.getsize(real_full)  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
                except OSError:
                    continue
                if size < _MIN_FILE_BYTES or size > _DEFAULT_MAX_FILE_BYTES:
                    continue
                hits.append(real_full)
    return hits


# ── Per-file walk ────────────────────────────────────────────────────────────


def _read_sdb_bytes(path: str) -> bytes | None:
    """Read the full `.sdb` file. Defensive against I/O errors → None."""
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _build_shim_row(
    *,
    firmware_id: uuid.UUID,
    file_path: str,
    file_sha256: str,
    sdb_kind: str,
    app: SDBApp | None,
    shim: SDBShim,
) -> WindowsSdbEntry:
    """Construct one WindowsSdbEntry row from a SHIM entry.

    Pure function — same inputs always produce the same row content
    (modulo the row's auto-generated id + created_at).
    """
    shim_class = classify_shim_class(shim.name)
    app_name = app.app_name or app.name if app is not None else None
    app_exe = (
        app.exes[0]
        if app is not None and app.exes else None
    )
    payload = _stamp_windows_sdb_entries_shim_payload({
        "kind": "shim",
        "shim_name": shim.name,
        "module": shim.module,
        "command_line": shim.command_line,
        "description": shim.description,
    })
    anomaly = _stamp_windows_sdb_entries_anomaly_flags(
        build_anomaly_flags(
            sdb_kind=sdb_kind,
            shim_class=shim_class,
            shim_name=shim.name,
            module=shim.module,
            command_line=shim.command_line,
            app_exe=app_exe or "",
        )
    )
    fingerprint = compute_entry_fingerprint(
        file_path=file_path,
        file_sha256=file_sha256,
        shim_class=shim_class,
        shim_name=shim.name,
    )
    return WindowsSdbEntry(
        firmware_id=firmware_id,
        file_path=file_path[:2048],
        file_sha256=file_sha256,
        sdb_kind=sdb_kind,
        app_name=(app_name or None)[:512] if app_name else None,
        app_exe=(app_exe or None)[:512] if app_exe else None,
        shim_class=shim_class,
        shim_payload=payload,
        anomaly_flags=anomaly,
        fingerprint_sha256=fingerprint,
    )


def _build_patch_row(
    *,
    firmware_id: uuid.UUID,
    file_path: str,
    file_sha256: str,
    sdb_kind: str,
    app: SDBApp | None,
    patch: SDBPatch,
) -> WindowsSdbEntry:
    """Construct one WindowsSdbEntry row from a PATCH entry."""
    app_name = app.app_name or app.name if app is not None else None
    app_exe = (
        app.exes[0]
        if app is not None and app.exes else None
    )
    payload = _stamp_windows_sdb_entries_shim_payload({
        "kind": "patch",
        "patch_name": patch.name,
        "patch_bits_hex": patch.patch_bits_hex,
        "patch_bits_size": patch.patch_bits_size,
    })
    anomaly = _stamp_windows_sdb_entries_anomaly_flags(
        build_anomaly_flags(
            sdb_kind=sdb_kind,
            shim_class="Patch",
            shim_name=patch.name,
            module="",
            command_line="",
            app_exe=app_exe or "",
        )
    )
    fingerprint = compute_entry_fingerprint(
        file_path=file_path,
        file_sha256=file_sha256,
        shim_class="Patch",
        shim_name=patch.name,
    )
    return WindowsSdbEntry(
        firmware_id=firmware_id,
        file_path=file_path[:2048],
        file_sha256=file_sha256,
        sdb_kind=sdb_kind,
        app_name=(app_name or None)[:512] if app_name else None,
        app_exe=(app_exe or None)[:512] if app_exe else None,
        shim_class="Patch",
        shim_payload=payload,
        anomaly_flags=anomaly,
        fingerprint_sha256=fingerprint,
    )


def _walk_one_sdb(
    sdb_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
) -> tuple[list[WindowsSdbEntry], dict[str, Any]]:
    """Parse one `.sdb` file: enumerate APPs + nested SHIMs/PATCHEs +
    orphan SHIMs/PATCHEs.

    Returns ``(entries, per_file_aggregate)``. ``entries`` is a list
    of SQLAlchemy ORM instances ready for ``db.add()``; the aggregate
    summary tells the caller what shim classes were found + the
    associated counters.

    Defensive boundary:
    - I/O error → status="error".
    - Invalid magic / truncated header → status="parse_error".
    - Empty parse (no APPs and no orphans) → status="empty".
    """
    aggregate: dict[str, Any] = {
        "path": relative_source,
        "status": "ok",
        "sdb_kind": classify_sdb_kind(relative_source),
        "apps_found": 0,
        "shims_persisted": 0,
        "patches_persisted": 0,
        "inject_dll_count": 0,
        "redirect_exe_count": 0,
        "error": None,
    }
    entries: list[WindowsSdbEntry] = []

    raw = _read_sdb_bytes(sdb_path)
    if raw is None:
        aggregate["status"] = "error"
        aggregate["error"] = "I/O read failed"
        return entries, aggregate

    file_sha256 = hashlib.sha256(raw).hexdigest()

    try:
        parsed: ParsedSDB = parse_sdb(raw)
    except InvalidSDBFileError as exc:
        aggregate["status"] = "parse_error"
        aggregate["error"] = (
            f"InvalidSDBFileError: {str(exc)[:200]}"
        )
        return entries, aggregate

    sdb_kind = aggregate["sdb_kind"]
    aggregate["apps_found"] = len(parsed.apps)

    # Walk each APP's nested entries.
    for app in parsed.apps:
        for shim in app.shims:
            row = _build_shim_row(
                firmware_id=firmware_id,
                file_path=relative_source,
                file_sha256=file_sha256,
                sdb_kind=sdb_kind,
                app=app,
                shim=shim,
            )
            entries.append(row)
            aggregate["shims_persisted"] += 1
            if row.shim_class == "InjectDll":
                aggregate["inject_dll_count"] += 1
            elif row.shim_class == "RedirectEXE":
                aggregate["redirect_exe_count"] += 1
        for patch in app.patches:
            row = _build_patch_row(
                firmware_id=firmware_id,
                file_path=relative_source,
                file_sha256=file_sha256,
                sdb_kind=sdb_kind,
                app=app,
                patch=patch,
            )
            entries.append(row)
            aggregate["patches_persisted"] += 1

    # Walk orphan SHIMs / PATCHEs (uncommon but legitimate for
    # Library-only shims).
    for shim in parsed.orphan_shims:
        row = _build_shim_row(
            firmware_id=firmware_id,
            file_path=relative_source,
            file_sha256=file_sha256,
            sdb_kind=sdb_kind,
            app=None,
            shim=shim,
        )
        entries.append(row)
        aggregate["shims_persisted"] += 1
        if row.shim_class == "InjectDll":
            aggregate["inject_dll_count"] += 1
        elif row.shim_class == "RedirectEXE":
            aggregate["redirect_exe_count"] += 1

    for patch in parsed.orphan_patches:
        row = _build_patch_row(
            firmware_id=firmware_id,
            file_path=relative_source,
            file_sha256=file_sha256,
            sdb_kind=sdb_kind,
            app=None,
            patch=patch,
        )
        entries.append(row)
        aggregate["patches_persisted"] += 1

    if not entries:
        aggregate["status"] = "empty"

    return entries, aggregate


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "files_scanned": 0,
        "entries_persisted": 0,
        "shim_count": 0,
        "patch_count": 0,
        "custom_path_count": 0,
        "inject_dll_count": 0,
        "redirect_exe_count": 0,
        "get_command_line_count": 0,
        "redirect_shortcut_count": 0,
        "anomaly_count": 0,
        "errors": [],
        "per_file": [],
    }


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
            return (
                real_full[len(real_root) + 1 :]
                if real_full != real_root
                else "."
            )
    return os.path.basename(full_path)


async def _walk_sdb_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_sdb_files` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_sdb_files, roots)


async def _walk_one_sdb_async(
    sdb_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
) -> tuple[list[WindowsSdbEntry], dict[str, Any]]:
    """Async wrapper around :func:`_walk_one_sdb` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_sdb(
            sdb_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ─────────────────────────


async def _do_sdb_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_entries: int = _DEFAULT_MAX_ENTRIES_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every `.sdb` candidate in ``firmware_id``'s extracted
    tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for `.sdb` files (extension allow-list +
       size gate).
    3. For each candidate: read bytes; parse via python_sdb;
       enumerate APPs + nested SHIMs/PATCHes + orphans; classify;
       bulk-add WindowsSdbEntry rows.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1
    live canary tests (Rule #35b) can drive the FULL walk against
    a real test DB without DNS resolution issues from
    ``async_session_factory()``.
    """
    started = time.monotonic()

    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        return _empty_walk_result(0.0)

    roots = await get_detection_roots(firmware, db=db)
    if not roots:
        return _empty_walk_result(time.monotonic() - started)

    sdb_paths = await _walk_sdb_files_async(roots)
    if not sdb_paths:
        return _empty_walk_result(time.monotonic() - started)

    files_scanned = 0
    entries_persisted = 0
    shim_count = 0
    patch_count = 0
    custom_path_count = 0
    inject_dll_count = 0
    redirect_exe_count = 0
    get_command_line_count = 0
    redirect_shortcut_count = 0
    anomaly_count = 0
    errors: list[str] = []
    per_file: list[dict[str, Any]] = []

    persist_budget = max_entries

    for sdb_path in sdb_paths:
        if persist_budget <= 0:
            files_scanned += 1
            continue

        relative = _relativize_path(sdb_path, roots)
        try:
            entries, agg = await _walk_one_sdb_async(
                sdb_path,
                firmware_id=firmware_id,
                relative_source=relative,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = (
                f"walk failed for {sdb_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_file.append({
                "path": relative,
                "status": "error",
                "sdb_kind": classify_sdb_kind(relative),
                "apps_found": 0,
                "shims_persisted": 0,
                "patches_persisted": 0,
                "inject_dll_count": 0,
                "redirect_exe_count": 0,
                "error": err,
            })
            files_scanned += 1
            continue

        files_scanned += 1

        for entry in entries:
            if persist_budget <= 0:
                break
            db.add(entry)
            await db.flush()
            entries_persisted += 1
            persist_budget -= 1

            if entry.shim_class == "Patch":
                patch_count += 1
            else:
                shim_count += 1

            if entry.sdb_kind == "custom":
                custom_path_count += 1
            if entry.shim_class == "InjectDll":
                inject_dll_count += 1
            elif entry.shim_class == "RedirectEXE":
                redirect_exe_count += 1
            elif entry.shim_class == "GetCommandLineW":
                get_command_line_count += 1
            elif entry.shim_class == "RedirectShortcut":
                redirect_shortcut_count += 1

            if isinstance(entry.anomaly_flags, dict):
                # An anomaly counts if ANY attacker-tradecraft flag
                # is True (custom path OR known-bad shim primitive
                # OR DLL outside appdir).
                anomaly_keys = (
                    "is_custom_path",
                    "has_inject_dll",
                    "has_redirect_exe",
                    "has_get_command_line",
                    "has_redirect_shortcut",
                    "has_dll_outside_appdir",
                )
                if any(
                    entry.anomaly_flags.get(k) for k in anomaly_keys
                ):
                    anomaly_count += 1

        per_file.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "files_scanned": files_scanned,
        "entries_persisted": entries_persisted,
        "shim_count": shim_count,
        "patch_count": patch_count,
        "custom_path_count": custom_path_count,
        "inject_dll_count": inject_dll_count,
        "redirect_exe_count": redirect_exe_count,
        "get_command_line_count": get_command_line_count,
        "redirect_shortcut_count": redirect_shortcut_count,
        "anomaly_count": anomaly_count,
        "errors": errors,
        "per_file": per_file,
    }


# ── Outer wrapper (Rule #33 .a state machine) ───────────────────────────────


async def run_sdb_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the SDB shim walk.

    Owns its own AsyncSession via :func:`async_session_factory`;
    outer guard catches anything that escapes; failure persistence
    on a fresh session because the inner one rolled back. Mirrors
    the θ.E.C / θ.C.C precedent.

    Status transitions: idle → running → completed | failed. The
    queued state belongs to the trigger router (idempotent POST +
    409-on-conflict per Rule #33 .a).
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
                    "sdb_walk: firmware %s not found", firmware_id
                )
                return

            row.sdb_walk_status = "running"
            row.sdb_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_sdb_walk(db, firmware_id)
                row.sdb_walk_status = "completed"
                row.sdb_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.sdb_walk_result = (
                    _stamp_firmware_sdb_walk_result(result)
                )
                project_id = row.project_id
                await db.commit()

                # θ.D.E — emit windows_sdb_* Finding rows alongside
                # the status transition. Lazy import per Rule #30
                # to avoid sdb_walker ↔ finding_service circular at
                # module load.
                if result["entries_persisted"] > 0:
                    try:
                        from app.services.finding_service import (
                            FindingService,
                        )

                        service = FindingService(db=db)
                        emitted = (
                            await service.emit_sdb_findings_from_walk(
                                project_id, firmware_id
                            )
                        )
                        await db.commit()
                        logger.info(
                            "sdb_walk: firmware %s emitted "
                            "%d Finding rows",
                            firmware_id,
                            len(emitted),
                        )
                    except Exception:
                        await db.rollback()
                        logger.warning(
                            "sdb_walk: firmware %s Finding emit "
                            "failed",
                            firmware_id,
                            exc_info=True,
                        )

                logger.info(
                    "sdb_walk: firmware %s completed in %.2fs (%d "
                    "files, %d entries persisted, %d shims, %d "
                    "patches, %d custom, %d InjectDll, %d "
                    "RedirectEXE, %d anomaly)",
                    firmware_id,
                    result["run_seconds"],
                    result["files_scanned"],
                    result["entries_persisted"],
                    result["shim_count"],
                    result["patch_count"],
                    result["custom_path_count"],
                    result["inject_dll_count"],
                    result["redirect_exe_count"],
                    result["anomaly_count"],
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
                            select(Firmware).where(
                                Firmware.id == firmware_id
                            )
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.sdb_walk_status = "failed"
                        fail_row.sdb_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.sdb_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "sdb_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "sdb_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_sdb_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as θ.E.C
    auto_mbr_vbr_walk_firmware_safe wrapper.

    Distinct from :func:`run_sdb_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-
    triggered walks. The auto-walk-on-unpack flow runs the SAME
    orchestrator (``_do_sdb_walk``) but DOES NOT transition the
    status column — it stays ``idle`` until an operator explicitly
    triggers a re-walk via the trigger MCP tool, which resets and
    runs again.

    Wired to FindingService.emit_sdb_findings_from_walk in θ.D.E
    so auto-walks produce both the per-entry landing-zone rows AND
    the shim Finding rows in a single pass.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_sdb_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            project_id: uuid.UUID | None = None
            if row is not None:
                row.sdb_walk_result = (
                    _stamp_firmware_sdb_walk_result(result)
                )
                project_id = row.project_id
                await db.commit()

            # θ.D.E — emit windows_sdb_* Finding rows.
            if (
                project_id is not None
                and result["entries_persisted"] > 0
            ):
                try:
                    from app.services.finding_service import FindingService

                    service = FindingService(db=db)
                    emitted = (
                        await service.emit_sdb_findings_from_walk(
                            project_id, firmware_id
                        )
                    )
                    await db.commit()
                    logger.info(
                        "sdb_walk auto: firmware %s emitted "
                        "%d Finding rows",
                        firmware_id,
                        len(emitted),
                    )
                except Exception:
                    # Emit failure must NOT roll back the walk-result
                    # persistence — leave the windows_sdb_entries rows
                    # + sdb_walk_result aggregate in place even if the
                    # downstream Finding emit raises. Operators can
                    # re-run via trigger MCP tool.
                    await db.rollback()
                    logger.warning(
                        "sdb_walk auto: firmware %s Finding "
                        "emit failed",
                        firmware_id,
                        exc_info=True,
                    )

            logger.info(
                "sdb_walk auto: firmware %s walked %d files "
                "in %.2fs",
                firmware_id,
                result["files_scanned"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "sdb_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_sdb_walk",
    "auto_sdb_walk_firmware_safe",
    "build_anomaly_flags",
    "classify_sdb_kind",
    "classify_shim_class",
    "compute_entry_fingerprint",
    "run_sdb_walk_background",
    "walk_sdb_files",
]
