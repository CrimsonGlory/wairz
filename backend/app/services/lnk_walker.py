"""Phase η.C — Windows Shell Link (.lnk) walker.

Reads on-disk Windows shortcut (LNK / MS-SHLLINK) binary files from
extracted Windows installations (typically under user-profile +
system shortcut locations) and surfaces persistence-candidate
metadata as ``WindowsLnkRecord`` rows for downstream finding-emit
hooks (η.C.D).

**Rule #39 inner/outer/safe runner triplet** (γ.4 + δ.5 + ε.1.b.3 +
ζ.2.B + ζ.3.B + η.B.C + η.C.C = Rule-of-Seven):

- :func:`_do_lnk_run` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every ``.lnk`` file in detection roots, parses
  each via ``LnkParse3.lnk_file(fhandle=...)``, persists per-LNK
  ``WindowsLnkRecord`` rows, returns aggregate dict UNSTAMPED.
- :func:`run_lnk_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer
  guard catches escapes; failure persistence on a fresh session.
- :func:`auto_lnk_walk_firmware_safe` — UNPACK-POST-DETECTION hook.
  Runs the inner orchestrator but does NOT mutate
  ``lnk_walk_status`` (leaves ``idle`` so manual re-trigger works
  without 409).

**Rule #36 no-execute discipline.** ``LnkParse3.lnk_file(fhandle=...)``
PARSES the LNK binary AS DATA (LnkParse3 is a pure-Python parser
that decodes ShellLinkHeader / LinkInfo / StringData / ExtraData
blocks). The parsed ``target_path`` / ``arguments`` are surfaced
for operator review, NEVER invoked. wairz does NOT shell out to
``cscript`` / ``wscript`` / ``Start-Process`` / ``cmd /c`` on the
resolved target.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare
``firmware.extracted_path``) so scatter-zip / multi-archive
Windows extracts surface their user-profile LNK directories.

**Rule #19 evidence-first probe.** :func:`is_lnkparse3_available`
exposes a graceful-degrade probe so consumers can surface a
clear "library not installed" message rather than an opaque
ImportError. The library is in pyproject.toml; the probe protects
against container-level dep skew (e.g. when the worker image is
rebuilt LATER than the backend, briefly producing a window where
the dep isn't resolvable).
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import io
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
from app.models.windows_lnk_record import WindowsLnkRecord
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_lnk_walk_result,
    _stamp_windows_lnk_records_target_metadata,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum LNK files walked per firmware. A healthy Windows user
# profile averages 30-100 LNKs in Recent docs alone; cap at 5000 so
# a malformed/inflated extraction (e.g. attacker-planted LNK spam)
# doesn't blow up DB row count. Operators wanting more re-walk via
# the MCP tool against a specific path.
_DEFAULT_MAX_LNK_PER_FIRMWARE: int = 5000

# Cap on file size to parse. Real-world LNKs are typically 1-10 KB.
# Files larger than 1 MB are not legitimate shortcuts (LNK spec has
# practical upper bound around the StringData section + ExtraData
# blocks). Defensive against attacker-DoS oversize files.
_DEFAULT_MAX_FILE_BYTES: int = 1 * 1024 * 1024

# Conservative location filter — only walk under known shortcut
# locations to keep the walk bounded. Each pattern is matched
# case-insensitively against the directory path.
_LNK_LOCATION_HINTS: tuple[str, ...] = (
    "recent",      # \Users\<u>\AppData\Roaming\Microsoft\Windows\Recent\
    "start menu",  # \Users\<u>\AppData\Roaming\Microsoft\Windows\Start Menu\
    "startmenu",   # alt without space
    "desktop",     # \Users\<u>\Desktop\
    "programs",    # \Users\<u>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\
    "users",       # any \Users\<u>\... fallback hit
    "programdata", # \ProgramData\Microsoft\Windows\Start Menu\
    "office",      # Office automation / pinning shortcuts
    "quick launch",
    "sendto",
)


# ── T1547.009 Shortcut-Modification heuristics ───────────────────────────────

# Encoded-PowerShell argument shape detection (Qakbot / cobalt-strike
# pattern). When ANY of these regex patterns match the LNK's
# arguments, the η.C.D classifier upgrades the finding to HIGH
# confidence. Mirrors the η.B scheduled_task_walker patterns; uses
# the (?:^|[^A-Za-z0-9]) lookaround for hyphenated short forms (η.B
# regex bug remediation).
_ENCODED_POWERSHELL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-EncodedCommand\b", re.IGNORECASE),
    re.compile(
        r"(?:^|[^A-Za-z0-9])-enc(?:od|odedcomm|edcommand)?(?:[^A-Za-z0-9]|$)",
        re.IGNORECASE,
    ),
    re.compile(r"\bFromBase64String\b", re.IGNORECASE),
    re.compile(r"\bInvoke-Expression\b", re.IGNORECASE),
    re.compile(r"\[char\[\]\]\(", re.IGNORECASE),
    re.compile(r"\bDownloadString\(", re.IGNORECASE),
    re.compile(r"(?:^|[^A-Za-z0-9])IEX(?:[^A-Za-z0-9]|$)"),
)

# Known-Microsoft target-path prefixes. A LNK target_path starting
# with these is treated as a system / Microsoft binary and DOES NOT
# contribute to the non-Microsoft-MEDIUM emit. Anything else is a
# candidate-MEDIUM. Case-insensitive prefix match.
_MICROSOFT_TARGET_PREFIXES: tuple[str, ...] = (
    "c:\\windows\\",
    "%windir%\\",
    "%systemroot%\\",
    "c:\\program files\\windows ",
    "c:\\program files (x86)\\windows ",
    "c:\\program files\\common files\\microsoft ",
    "c:\\program files (x86)\\common files\\microsoft ",
    "c:\\program files\\microsoft ",
    "c:\\program files (x86)\\microsoft ",
    "c:\\programdata\\microsoft\\",
)

# Common cmd.exe / cscript.exe / wscript.exe / powershell.exe
# normalized target binary names. T1547.009 flags LNKs whose
# target resolves to one of these AND whose arguments carry an
# encoded-PS pattern → HIGH confidence.
_SCRIPT_HOST_BINARIES: frozenset[str] = frozenset({
    "cmd.exe",
    "cscript.exe",
    "wscript.exe",
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
})


def is_arguments_encoded_powershell(arguments: str | None) -> bool:
    """Return True iff the LNK arguments match a known encoded-PS pattern.

    Pure function — pattern-only check. No side effects.
    """
    if not arguments:
        return False
    return any(pat.search(arguments) for pat in _ENCODED_POWERSHELL_PATTERNS)


def is_microsoft_target(target_path: str | None) -> bool:
    """Return True iff the LNK target_path matches a Microsoft-shipped
    binary prefix.

    Comparison is case-insensitive against the canonical prefix list.
    Returns False for None or unrecognised paths.
    """
    if not target_path:
        return False
    lower = target_path.lower().replace("/", "\\")
    return any(lower.startswith(prefix) for prefix in _MICROSOFT_TARGET_PREFIXES)


def target_basename_normalized(target_path: str | None) -> str | None:
    """Return the lowercased basename of target_path, NULL when absent.

    Helper for script-host detection — extracts the .exe name
    from a full path with case + slash normalization.
    """
    if not target_path:
        return None
    normalized = target_path.replace("/", "\\")
    return normalized.rsplit("\\", 1)[-1].lower()


def is_script_host_target(target_path: str | None) -> bool:
    """Return True iff target_path resolves to a known script-host
    binary (cmd / powershell / cscript / wscript / mshta /
    regsvr32 / rundll32)."""
    base = target_basename_normalized(target_path)
    return base in _SCRIPT_HOST_BINARIES


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_lnkparse3_available() -> bool:
    """Return True iff ``LnkParse3`` is importable in this process.

    Mirrors the regipy / python-evtx / windowsprefetch / defusedxml
    graceful-degrade probes used by γ.4 / ε.1.b / ζ.2.B / η.B.C.
    Probe runs in <1 ms after first call (Python's import cache).
    """
    try:
        import LnkParse3  # noqa: F401 — import-only probe
    except ImportError:
        return False
    return True


# ── Parser ──────────────────────────────────────────────────────────────────


LNKPARSE3_UNAVAILABLE: dict[str, Any] = {
    "status": "unavailable",
    "reason": "LnkParse3 not installed — see backend/pyproject.toml",
    "data": None,
}


def _jsonify(value: Any) -> Any:
    """Recursively coerce ``value`` to JSON-serializable types.

    LnkParse3's ``.get_json()`` returns Python datetime objects for
    header MAC times and bytes for some ExtraData blocks. PostgreSQL
    JSONB requires str / int / float / bool / None / list / dict;
    asyncpg's JSON encoder rejects datetime / bytes / UUID / etc.

    Strategy: recurse into list / dict / tuple values. Datetime
    becomes ISO-8601 string; bytes becomes hex string; UUID becomes
    str; other unknown types fall back to ``repr(value)`` (defensive
    — never raises, never blocks JSONB write).
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=_dt.UTC)
        return value.isoformat()
    if isinstance(value, _dt.date):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.hex()
        except (UnicodeDecodeError, AttributeError):
            return repr(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonify(v) for v in value]
    # Fallback for unknown types (rare — defensive boundary).
    return repr(value)


def _resolve_target_path(parsed_json: dict[str, Any]) -> str | None:
    """Resolve target_path from LnkParse3's parsed JSON.

    Preference order:
      1. link_info.local_base_path  (most common; resolved drive letter)
      2. data.relative_path         (LNK-relative path, e.g. ..\\..\\X.exe)
      3. None                       (target unresolvable; rare)
    """
    link_info = parsed_json.get("link_info") or {}
    if isinstance(link_info, dict):
        lbp = link_info.get("local_base_path")
        if isinstance(lbp, str) and lbp:
            return lbp
    data = parsed_json.get("data") or {}
    if isinstance(data, dict):
        rp = data.get("relative_path")
        if isinstance(rp, str) and rp:
            return rp
    return None


def _coerce_datetime(value: Any) -> _dt.datetime | None:
    """Coerce a value (datetime / ISO-8601 string / None) to a tz-aware
    UTC datetime.

    LnkParse3 may return either a Python datetime object or an
    ISO-8601 string for header MAC times depending on version.
    Defensive — returns None on any parse failure.
    """
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=_dt.UTC)
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            parsed = _dt.datetime.fromisoformat(s)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=_dt.UTC)
            return parsed
        except (ValueError, TypeError):
            return None
    return None


def parse_lnk_file(
    path: str, *, max_bytes: int = _DEFAULT_MAX_FILE_BYTES
) -> dict[str, Any]:
    """Parse a single Windows Shell Link file and return a structured summary.

    Returns a dict with keys:
    - ``status``: "ok" | "unavailable" | "error" | "skipped".
    - ``data``: parsed LNK fields when status="ok"; None otherwise.
    - ``error``: present only when status="error" (truncated to 500 chars).
    - ``raw_json``: full LnkParse3 .get_json() output when status="ok".

    **Defensive against missing dep** — returns
    :data:`LNKPARSE3_UNAVAILABLE` shape if the library isn't importable.

    **Defensive against malformed input** — wraps the parse in a
    try/except. Truncated / corrupted LNK files surface a structured
    error instead of crashing the caller.

    **Defensive against attacker-DoS oversize files** — files larger
    than ``max_bytes`` (default 1 MB) are skipped with status="skipped".

    Rule #36 reminder: ``path`` is read AS DATA via
    ``LnkParse3.lnk_file(fhandle=...)``; no process spawn.
    """
    if not is_lnkparse3_available():
        return LNKPARSE3_UNAVAILABLE

    try:
        size = os.path.getsize(path)  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
    except OSError as exc:
        return {
            "status": "error",
            "data": None,
            "error": f"stat failed: {type(exc).__name__}: {str(exc)[:200]}",
        }
    if size > max_bytes:
        return {
            "status": "skipped",
            "data": None,
            "reason": (
                f"file size {size} exceeds max {max_bytes} (attacker-DoS "
                f"protection); operator can re-walk individual file via MCP tool"
            ),
        }
    if size < 76:  # ShellLinkHeader is 76 bytes minimum
        return {
            "status": "error",
            "data": None,
            "error": (
                f"file size {size} below 76-byte minimum "
                f"ShellLinkHeader — not a valid LNK"
            ),
        }

    # Lazy import per Rule #30 — LnkParse3 is light but keeps cold-
    # import bounded for non-η.C code paths.
    from LnkParse3 import lnk_file

    try:
        with open(path, "rb") as f:
            blob = f.read()
        # LnkParse3 expects a file-handle-like object.
        parsed = lnk_file(fhandle=io.BytesIO(blob))
        raw_json = parsed.get_json()
    except (OSError, ValueError, KeyError, IndexError) as exc:
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        return {"status": "error", "data": None, "error": msg}
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        return {
            "status": "error",
            "data": None,
            "error": f"{type(exc).__name__}: {msg}",
        }

    if not isinstance(raw_json, dict):
        return {
            "status": "error",
            "data": None,
            "error": (
                f"LnkParse3.get_json() returned non-dict "
                f"({type(raw_json).__name__}); not a valid LNK"
            ),
        }

    header = raw_json.get("header") or {}
    data_block = raw_json.get("data") or {}
    if not isinstance(header, dict):
        header = {}
    if not isinstance(data_block, dict):
        data_block = {}

    target_path = _resolve_target_path(raw_json)
    working_directory = data_block.get("working_directory") or None
    arguments = data_block.get("command_line_arguments") or None
    description = data_block.get("description") or None
    icon_location = data_block.get("icon_location") or None
    show_command = header.get("windowstyle") or None
    hotkey = header.get("hotkey") or None

    creation_time = _coerce_datetime(header.get("creation_time"))
    accessed_time = _coerce_datetime(header.get("accessed_time"))
    modified_time = _coerce_datetime(header.get("modified_time"))

    return {
        "status": "ok",
        "raw_json": raw_json,
        "data": {
            "target_path": target_path,
            "working_directory": working_directory,
            "arguments": arguments,
            "description": description,
            "icon_location": icon_location,
            "show_command": show_command,
            "hotkey": hotkey,
            "creation_time": creation_time,
            "accessed_time": accessed_time,
            "modified_time": modified_time,
        },
    }


# ── Walker ──────────────────────────────────────────────────────────────────


def walk_lnk_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return ``.lnk`` file paths.

    Conservative location filter — only walks under directories whose
    path contains a known shortcut-location hint (Recent / Start
    Menu / Desktop / Programs / Users / ProgramData). Mirrors the
    EVTX / Prefetch / SRUM / scheduled_task walker shape: case-
    insensitive matching + sandbox check that rejects symlinks
    pointing outside the root tree (Rule #1 spirit).

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
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
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if not os.path.isdir(real_root):
            continue
        for dirpath, _dirnames, filenames in os.walk(  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            root, followlinks=False
        ):
            # Filter directories to known shortcut locations to keep
            # the walk bounded — LNKs are exclusively under user-
            # profile + system shortcut areas on canonical Windows
            # extracts.
            dirpath_lower = dirpath.lower()
            if not any(hint in dirpath_lower for hint in _LNK_LOCATION_HINTS):
                continue
            for name in filenames:
                # Match .lnk extension case-insensitively.
                if not name.lower().endswith(".lnk"):
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


async def _walk_lnk_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_lnk_files` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_lnk_files, roots)


async def _parse_lnk_file_async(path: str) -> dict[str, Any]:
    """Async wrapper around :func:`parse_lnk_file` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, parse_lnk_file, path)


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "lnk_count": 0,
        "by_status": {"ok": 0, "error": 0, "unavailable": 0, "skipped": 0},
        "unique_targets": 0,
        "non_microsoft_target_count": 0,
        "encoded_powershell_count": 0,
        "errors": [],
        "per_file": [],
    }


def _relativize_path(full_path: str, roots: list[str]) -> str:
    """Compute path relative to whichever detection root contains it.

    Matches the WindowsLnkRecord.source_path discipline. Returns
    the basename if no root matches.
    """
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


def _build_record(
    firmware_id: uuid.UUID,
    source_path: str,
    parsed: dict[str, Any],
) -> WindowsLnkRecord | None:
    """Construct a WindowsLnkRecord from a parse_lnk_file result.

    Returns None on structural defensive failures (parsed_data not a
    dict). Otherwise always returns a row, even when most fields are
    absent (the minimal record carries source_path + lnk_filename only).
    """
    parsed_data = parsed.get("data")
    raw_json = parsed.get("raw_json")
    if not isinstance(parsed_data, dict):
        return None

    lnk_filename = os.path.basename(source_path) or "(unnamed.lnk)"

    target_path = parsed_data.get("target_path")
    working_directory = parsed_data.get("working_directory")
    arguments = parsed_data.get("arguments")
    description = parsed_data.get("description")
    icon_location = parsed_data.get("icon_location")
    show_command = parsed_data.get("show_command")
    hotkey = parsed_data.get("hotkey")

    target_metadata = (
        _stamp_windows_lnk_records_target_metadata(_jsonify(raw_json))
        if isinstance(raw_json, dict)
        else None
    )

    return WindowsLnkRecord(
        firmware_id=firmware_id,
        source_path=source_path[:2048],
        lnk_filename=lnk_filename[:512],
        target_path=(target_path[:2048] if target_path else None),
        working_directory=(
            working_directory[:2048] if working_directory else None
        ),
        # arguments is Text — no length truncation needed (encoded
        # PowerShell args can exceed 8 KB after Base64 expansion).
        arguments=arguments,
        description=(description[:1024] if description else None),
        icon_location=(
            icon_location[:2048] if icon_location else None
        ),
        show_command=(show_command[:64] if show_command else None),
        hotkey=(hotkey[:128] if hotkey else None),
        creation_time=parsed_data.get("creation_time"),
        accessed_time=parsed_data.get("accessed_time"),
        modified_time=parsed_data.get("modified_time"),
        target_metadata=target_metadata,
    )


# ── Inner orchestrator (accepts a db; reusable in tier-1 live canaries) ──────


async def _do_lnk_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_lnk: int = _DEFAULT_MAX_LNK_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every ``.lnk`` file in ``firmware_id``'s extracted tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for LNK files under any user-profile / system
       shortcut location (Recent / Start Menu / Desktop / etc.).
    3. For each file: parse via LnkParse3 (run_in_executor for
       Rule #5 sync I/O), bulk-insert WindowsLnkRecord rows.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real
    test DB without DNS resolution issues from
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

    lnk_paths = await _walk_lnk_files_async(roots)
    if not lnk_paths:
        return _empty_walk_result(time.monotonic() - started)

    # Bound per Rule #19 evidence-first — Win10/11 user profile
    # averages 30-100 LNKs in Recent docs alone; 5000 cap protects
    # against attacker-planted LNK spam without blocking legitimate
    # forensic walks.
    if len(lnk_paths) > max_lnk:
        logger.warning(
            "lnk_walk: firmware %s exceeded max_lnk=%d "
            "(found %d); truncating",
            firmware_id,
            max_lnk,
            len(lnk_paths),
        )
        lnk_paths = lnk_paths[:max_lnk]

    by_status: dict[str, int] = {
        "ok": 0,
        "error": 0,
        "unavailable": 0,
        "skipped": 0,
    }
    unique_targets: set[str] = set()
    non_microsoft_target_count = 0
    encoded_powershell_count = 0
    errors: list[str] = []
    per_file: list[dict[str, Any]] = []

    for lnk_path in lnk_paths:
        relpath = _relativize_path(lnk_path, roots)
        try:
            parsed = await _parse_lnk_file_async(lnk_path)
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = (
                f"parse failed for {lnk_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            by_status["error"] += 1
            per_file.append(
                {
                    "path": relpath,
                    "status": "error",
                    "target_path": None,
                    "lnk_filename": os.path.basename(relpath),
                    "error": err,
                }
            )
            continue

        status = parsed.get("status", "error")
        by_status[status] = by_status.get(status, 0) + 1

        if status == "ok":
            data = parsed.get("data") or {}
            record = _build_record(firmware_id, relpath, parsed)
            if record is not None:
                db.add(record)
                await db.flush()
                if record.target_path:
                    unique_targets.add(record.target_path)
                    if not is_microsoft_target(record.target_path):
                        non_microsoft_target_count += 1
                if is_arguments_encoded_powershell(record.arguments):
                    encoded_powershell_count += 1
            per_file.append(
                {
                    "path": relpath,
                    "status": "ok",
                    "target_path": data.get("target_path"),
                    "lnk_filename": os.path.basename(relpath),
                    "error": None,
                }
            )
        else:
            per_file.append(
                {
                    "path": relpath,
                    "status": status,
                    "target_path": None,
                    "lnk_filename": os.path.basename(relpath),
                    "error": parsed.get("error") or parsed.get("reason"),
                }
            )

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "lnk_count": len(lnk_paths),
        "by_status": by_status,
        "unique_targets": len(unique_targets),
        "non_microsoft_target_count": non_microsoft_target_count,
        "encoded_powershell_count": encoded_powershell_count,
        "errors": errors,
        "per_file": per_file,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_lnk_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the LNK walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back. Mirrors the
    γ.4 registry_hive_walker / ε.1.b.3 evtx_service / ζ.2.B
    prefetch_walker / ζ.3.B srum_walker / η.B.C scheduled_task_walker
    shape.

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
                    "lnk_walk: firmware %s not found", firmware_id
                )
                return

            row.lnk_walk_status = "running"
            row.lnk_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_lnk_run(db, firmware_id)
                row.lnk_walk_status = "completed"
                row.lnk_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.lnk_walk_result = (
                    _stamp_firmware_lnk_walk_result(result)
                )
                await db.commit()
                logger.info(
                    "lnk_walk: firmware %s completed in %.2fs (%d "
                    "LNKs, %d unique targets, %d non-Microsoft "
                    "targets, %d encoded-PS args)",
                    firmware_id,
                    result["run_seconds"],
                    result["lnk_count"],
                    result["unique_targets"],
                    result["non_microsoft_target_count"],
                    result["encoded_powershell_count"],
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
                        fail_row.lnk_walk_status = "failed"
                        fail_row.lnk_walk_finished_at = _dt.datetime.now(
                            _dt.UTC
                        )
                        fail_row.lnk_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "lnk_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception("lnk_walk: unrecoverable for %s", firmware_id)


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_lnk_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as ζ.2.B / ζ.3.B / η.B.C
    auto_walk_firmware_safe.

    Distinct from :func:`run_lnk_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-
    triggered walks. The auto-walk-on-unpack flow runs the SAME
    orchestrator (``_do_lnk_run``) but DOES NOT transition the
    status column — it stays ``idle`` until an operator explicitly
    triggers a re-walk via the trigger MCP tool, which resets and
    runs again.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_lnk_run(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.lnk_walk_result = _stamp_firmware_lnk_walk_result(result)
                await db.commit()
            logger.info(
                "lnk_walk auto: firmware %s walked %d LNKs in %.2fs",
                firmware_id,
                result["lnk_count"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "lnk_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "LNKPARSE3_UNAVAILABLE",
    "_do_lnk_run",
    "auto_lnk_walk_firmware_safe",
    "is_arguments_encoded_powershell",
    "is_lnkparse3_available",
    "is_microsoft_target",
    "is_script_host_target",
    "parse_lnk_file",
    "run_lnk_walk_background",
    "target_basename_normalized",
    "walk_lnk_files",
]
