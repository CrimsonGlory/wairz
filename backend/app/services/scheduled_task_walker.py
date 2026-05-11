"""Phase η.B — Windows Scheduled Task XML walker.

Reads on-disk Scheduled Task XML files from extracted Windows
installations (typically under ``\\Windows\\System32\\Tasks\\`` and
its recursive subdirectory tree) and surfaces persistence-candidate
metadata as ``WindowsScheduledTask`` rows for downstream
finding-emit hooks (η.B.D).

**Rule #39 inner/outer/safe runner triplet** (γ.4 + δ.5 + ε.1.b.3 +
ζ.2.B + ζ.3.B + η.B.C = Rule-of-Six):

- :func:`_do_scheduled_task_run` — INNER orchestrator. Accepts
  caller-owned ``db``. Walks every ``.xml`` task file in detection
  roots, parses each via ``defusedxml.ElementTree.fromstring``,
  persists per-task ``WindowsScheduledTask`` rows, returns aggregate
  dict UNSTAMPED.
- :func:`run_scheduled_task_walk_background` — OUTER state-machine
  wrapper. Owns the Rule #33 .a status transitions
  (idle → running → completed | failed) via ``async_session_factory()``.
  Outer guard catches escapes; failure persistence on a fresh session.
- :func:`auto_walk_firmware_safe` — UNPACK-POST-DETECTION hook. Runs
  the inner orchestrator but does NOT mutate
  ``scheduled_task_walk_status`` (leaves ``idle`` so manual
  re-trigger works without 409).

**Rule #36 no-execute discipline.** ``defusedxml.ElementTree.fromstring``
PARSES task XML AS DATA (defusedxml is a hardened pure-Python parser
that disables XXE / billion-laughs / external-entity expansion). The
parsed Action's <Command>/<Arguments> are surfaced for operator
review, NEVER invoked. wairz does NOT shell out to ``schtasks
/create``, ``Register-ScheduledTask``, ``Start-Process``, or any
Windows-side scheduling primitive on the parsed Command.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare ``firmware.extracted_path``)
so scatter-zip / multi-archive Windows extracts surface their Tasks
directories.

**Rule #19 evidence-first probe.** :func:`is_defusedxml_available`
exposes a graceful-degrade probe so consumers can surface a clear
"library not installed" message rather than an opaque ImportError.
The library is in pyproject.toml; the probe protects against
container-level dep skew.

**Per intake D2 (defusedxml swap pattern from Phase Lint.B.3
baseline).** The Tasks XML files are extracted from a firmware tree
we control via the unpack pipeline; the parsed content is treated
as untrusted DATA per Rule #36. defusedxml hardens against XML
attacks (XXE / DoS) that a malicious firmware could carry.
"""
from __future__ import annotations

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
from app.models.windows_scheduled_task import WindowsScheduledTask
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_scheduled_task_walk_result,
    _stamp_windows_scheduled_tasks_actions,
    _stamp_windows_scheduled_tasks_principal,
    _stamp_windows_scheduled_tasks_settings,
    _stamp_windows_scheduled_tasks_triggers,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum task XMLs walked per firmware. Real Win11 ships ~150-200
# tasks under \Microsoft\Windows\; cap at 5000 so a malformed/inflated
# extraction (e.g. attacker-planted task spam) doesn't blow up DB row
# count. Operators wanting more re-walk via the MCP tool against a
# specific path.
_DEFAULT_MAX_TASKS_PER_FIRMWARE: int = 5000

# Per-file wall-clock soft cap. defusedxml is fast on healthy XMLs but
# a degenerate input (e.g. deeply-nested element tree) could send the
# parser into long iteration. Soft-cap at 30 seconds per file.
_DEFAULT_PER_FILE_TIMEOUT_SECONDS: float = 30.0

# Cap on file size to parse (XML files >5 MB are not legitimate task
# definitions; they're either malformed or attacker-planted DoS
# vectors).
_DEFAULT_MAX_FILE_BYTES: int = 5 * 1024 * 1024

# Tasks XML namespace (Windows 2004+ schema; covers Vista through Win11).
_TASK_NAMESPACE: str = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_NS: dict[str, str] = {"t": _TASK_NAMESPACE}


# ── Trigger / Action classification helpers ──────────────────────────────────

# Encoded-PowerShell action shape detection (Qakbot pattern).
# When ANY of these regex patterns match an Action's Command +
# Arguments, the η.B.D classifier emits HIGH confidence persistence
# finding. The patterns are deliberately conservative — only flagging
# shapes that survived a 2024-2025 Mandiant/CrowdStrike adversary-
# tradecraft review (cited in scout-2-persona-refresh.md).
_ENCODED_POWERSHELL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-EncodedCommand\b", re.IGNORECASE),
    # `-enc` and friends — `\b` does NOT match between `-` and `e` (both
    # are non-word→word transitions, but `-` is non-word and `e` is word
    # so `\b` MATCHES at that boundary; however on the trailing side we
    # need either word→non-word or end-of-string). Use a non-word
    # lookbehind / lookahead pattern instead of `\b` for hyphenated
    # short forms.
    re.compile(r"(?:^|[^A-Za-z0-9])-enc(?:od|odedcomm|edcommand)?(?:[^A-Za-z0-9]|$)", re.IGNORECASE),
    re.compile(r"\bFromBase64String\b", re.IGNORECASE),
    re.compile(r"\bInvoke-Expression\b", re.IGNORECASE),
    re.compile(r"\b\[char\[\]\]\(", re.IGNORECASE),
    re.compile(r"\bDownloadString\(", re.IGNORECASE),
    re.compile(r"\bIEX\b", re.IGNORECASE),
)

# System-author prefix list. Author values starting with these strings
# are treated as system-shipped tasks and DO NOT contribute to the
# privilege-escalation-MEDIUM emit. Anything else with
# RunLevel=HighestAvailable is candidate-MEDIUM.
_SYSTEM_AUTHOR_PREFIXES: tuple[str, ...] = (
    "Microsoft Corporation",
    "Microsoft Corp",
    "Microsoft",
    "Microsoft Windows",
    "$(@%SystemRoot%",  # localised Microsoft author resource ref
    "$(@%ProgramFiles%",
)


def is_action_encoded_powershell(
    command: str | None, arguments: str | None
) -> bool:
    """Return True iff the Action shape matches Qakbot encoded-PS pattern.

    Pure function — pattern-only check across command + arguments
    concatenated. No side effects.
    """
    blob = " ".join(filter(None, (command, arguments)))
    if not blob:
        return False
    return any(pat.search(blob) for pat in _ENCODED_POWERSHELL_PATTERNS)


def is_system_author(author: str | None) -> bool:
    """Return True iff the Author value matches a known system prefix."""
    if not author:
        return False
    return any(
        author.startswith(prefix) for prefix in _SYSTEM_AUTHOR_PREFIXES
    )


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_defusedxml_available() -> bool:
    """Return True iff ``defusedxml`` is importable in this process.

    Mirrors the regipy / python-evtx / windowsprefetch graceful-degrade
    probes used by γ.4 / ε.1.b / ζ.2.B. Probe runs in <1 ms after
    first call (Python's import cache).
    """
    try:
        import defusedxml.ElementTree  # noqa: F401 — import-only probe
    except ImportError:
        return False
    return True


# ── Parser ──────────────────────────────────────────────────────────────────


DEFUSEDXML_UNAVAILABLE: dict[str, Any] = {
    "status": "unavailable",
    "reason": "defusedxml not installed — see backend/pyproject.toml",
    "data": None,
}


def _strip_ns(tag: str) -> str:
    """Strip the XML namespace prefix from an ElementTree tag.

    ElementTree wraps namespaced tags as ``{namespace}LocalName``; we
    want just the local name for shape comparisons.
    """
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _parse_iso_datetime(text: str | None) -> _dt.datetime | None:
    """Parse a Windows-task-XML timestamp string (ISO-8601 naive form).

    Tasks XML uses "2019-09-15T22:35:08" (no timezone). We render as
    UTC for storage consistency.
    """
    if not text:
        return None
    try:
        # Strip trailing fractional seconds beyond microsecond precision
        # if present.
        cleaned = text.strip()
        # Some tasks include 'Z' or '+00:00' suffix; tolerate both.
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        parsed = _dt.datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.UTC)
        return parsed
    except (ValueError, TypeError):
        return None


def _extract_triggers(root: Any) -> list[dict[str, Any]]:
    """Extract triggers from a parsed task root element.

    Returns list of dicts with shape:
        {"type": str, "enabled": bool, "start_boundary": str | None,
         "end_boundary": str | None, "details": dict}

    Defensive — empty list when <Triggers> is absent or malformed.
    """
    triggers_block = root.find("t:Triggers", _NS)
    if triggers_block is None:
        return []
    out: list[dict[str, Any]] = []
    for trigger in list(triggers_block):
        ttype = _strip_ns(trigger.tag)
        enabled_el = trigger.find("t:Enabled", _NS)
        # Default per Tasks XML spec: triggers are enabled unless
        # <Enabled>false</Enabled> is set.
        enabled = True
        if enabled_el is not None and enabled_el.text:
            enabled = enabled_el.text.strip().lower() != "false"
        start_el = trigger.find("t:StartBoundary", _NS)
        end_el = trigger.find("t:EndBoundary", _NS)

        # Capture any nested element names (e.g. ScheduleByWeek /
        # ScheduleByDay subkeys for CalendarTrigger) into details for
        # operator triage.
        details: dict[str, Any] = {}
        for child in list(trigger):
            local = _strip_ns(child.tag)
            if local in ("Enabled", "StartBoundary", "EndBoundary"):
                continue
            if local in details:
                continue
            # Capture the local tag name — actual nested-element values
            # too verbose for the JSONB column. The full XML is on disk
            # at source_path for deep inspection.
            details[local] = True
        out.append(
            {
                "type": ttype,
                "enabled": enabled,
                "start_boundary": (
                    start_el.text if start_el is not None else None
                ),
                "end_boundary": (
                    end_el.text if end_el is not None else None
                ),
                "details": details,
            }
        )
    return out


def _extract_actions(root: Any) -> list[dict[str, Any]]:
    """Extract actions from a parsed task root element.

    Returns list of dicts with shape:
        {"type": str, "command": str | None, "arguments": str | None,
         "working_directory": str | None, "class_id": str | None,
         "details": dict}

    Defensive — empty list when <Actions> is absent or malformed.
    Per Rule #36, command/arguments are surfaced AS DATA — never
    invoked.
    """
    actions_block = root.find("t:Actions", _NS)
    if actions_block is None:
        return []
    out: list[dict[str, Any]] = []
    for action in list(actions_block):
        atype = _strip_ns(action.tag)
        cmd_el = action.find("t:Command", _NS)
        args_el = action.find("t:Arguments", _NS)
        wd_el = action.find("t:WorkingDirectory", _NS)
        class_el = action.find("t:ClassId", _NS)
        details: dict[str, Any] = {}
        for child in list(action):
            local = _strip_ns(child.tag)
            if local in (
                "Command",
                "Arguments",
                "WorkingDirectory",
                "ClassId",
            ):
                continue
            if local in details:
                continue
            details[local] = True
        out.append(
            {
                "type": atype,
                "command": cmd_el.text if cmd_el is not None else None,
                "arguments": args_el.text if args_el is not None else None,
                "working_directory": (
                    wd_el.text if wd_el is not None else None
                ),
                "class_id": (
                    class_el.text if class_el is not None else None
                ),
                "details": details,
            }
        )
    return out


def _extract_principal(root: Any) -> tuple[
    dict[str, Any], str | None, str | None
]:
    """Extract the first <Principal> from a parsed task root element.

    Returns (principal_dict, run_level, run_as_user) tuple. The
    secondary returns extract the typed columns the model surfaces
    directly for indexed lookup.
    """
    principal_el = root.find("t:Principals/t:Principal", _NS)
    if principal_el is None:
        return {}, None, None
    out: dict[str, Any] = {}
    user_id_el = principal_el.find("t:UserId", _NS)
    group_id_el = principal_el.find("t:GroupId", _NS)
    run_level_el = principal_el.find("t:RunLevel", _NS)
    logon_type_el = principal_el.find("t:LogonType", _NS)
    proc_token_el = principal_el.find("t:ProcessTokenSidType", _NS)

    out["id"] = principal_el.attrib.get("id")
    if user_id_el is not None:
        out["user_id"] = user_id_el.text
    if group_id_el is not None:
        out["group_id"] = group_id_el.text
    if run_level_el is not None:
        out["run_level"] = run_level_el.text
    if logon_type_el is not None:
        out["logon_type"] = logon_type_el.text
    if proc_token_el is not None:
        out["process_token_sid_type"] = proc_token_el.text

    run_level: str | None = (
        run_level_el.text if run_level_el is not None else None
    )
    # Resolve RunAs identifier — UserId takes precedence, fall back to
    # GroupId, fall back to the principal's id attribute.
    run_as_user: str | None = (
        (user_id_el.text if user_id_el is not None else None)
        or (group_id_el.text if group_id_el is not None else None)
        or principal_el.attrib.get("id")
    )
    return out, run_level, run_as_user


def _extract_settings(root: Any) -> dict[str, Any]:
    """Extract <Settings> block as a flat dict.

    Each immediate child element becomes a top-level key. Boolean
    string values ("true"/"false") are coerced to Python bool. All
    other values pass through as strings. Nested elements are
    captured by tag-name only (their values aren't surfaced — too
    verbose for JSONB).
    """
    settings_el = root.find("t:Settings", _NS)
    if settings_el is None:
        return {}
    out: dict[str, Any] = {}
    for child in list(settings_el):
        local = _strip_ns(child.tag)
        text = child.text
        if text is None:
            # Element with nested children — capture as marker.
            out[local] = True
            continue
        text_stripped = text.strip()
        if text_stripped.lower() == "true":
            out[local] = True
        elif text_stripped.lower() == "false":
            out[local] = False
        else:
            out[local] = text_stripped
    return out


def parse_scheduled_task_xml(
    path: str, *, max_bytes: int = _DEFAULT_MAX_FILE_BYTES
) -> dict[str, Any]:
    """Parse a single Scheduled Task XML file and return a structured summary.

    Returns a dict with keys:
    - ``status``: "ok" | "unavailable" | "error" | "skipped".
    - ``data``: parsed Task fields when status="ok"; None otherwise.
    - ``error``: present only when status="error" (truncated to 500 chars).

    **Defensive against missing dep** — returns
    :data:`DEFUSEDXML_UNAVAILABLE` shape if the library isn't importable.

    **Defensive against malformed input** — wraps the parse in a
    try/except. Truncated / corrupted XML files surface a structured
    error instead of crashing the caller.

    **Defensive against attacker-DoS oversize files** — files larger
    than ``max_bytes`` (default 5 MB) are skipped with status="skipped".

    Rule #36 reminder: ``path`` is read AS DATA via
    ``defusedxml.ElementTree.fromstring``; no process spawn.
    """
    if not is_defusedxml_available():
        return DEFUSEDXML_UNAVAILABLE

    try:
        size = os.path.getsize(path)
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

    # Lazy import per Rule #30 — defusedxml is light but keeps cold-
    # import bounded for non-η.B code paths.
    import defusedxml.ElementTree as ET

    try:
        with open(path, "rb") as f:
            blob = f.read()
        root = ET.fromstring(blob)
    except (OSError, ET.ParseError, ValueError) as exc:
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

    # Verify the root tag is a Task element (defusedxml accepts any
    # well-formed XML; we want to reject non-Task XML files).
    if _strip_ns(root.tag) != "Task":
        return {
            "status": "error",
            "data": None,
            "error": f"root tag {_strip_ns(root.tag)!r} is not 'Task'",
        }

    # Extract registration info.
    reg_uri_el = root.find("t:RegistrationInfo/t:URI", _NS)
    reg_author_el = root.find("t:RegistrationInfo/t:Author", _NS)
    reg_date_el = root.find("t:RegistrationInfo/t:Date", _NS)

    task_uri = reg_uri_el.text if reg_uri_el is not None else None
    author = reg_author_el.text if reg_author_el is not None else None
    registration_date = _parse_iso_datetime(
        reg_date_el.text if reg_date_el is not None else None
    )

    triggers = _extract_triggers(root)
    actions = _extract_actions(root)
    principal, run_level, run_as_user = _extract_principal(root)
    settings = _extract_settings(root)

    return {
        "status": "ok",
        "data": {
            "task_uri": task_uri,
            "author": author,
            "registration_date": registration_date,
            "run_level": run_level,
            "run_as_user": run_as_user,
            "triggers": triggers,
            "actions": actions,
            "principal": principal,
            "settings": settings,
        },
    }


# ── Walker ──────────────────────────────────────────────────────────────────


def walk_scheduled_task_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return Scheduled Task XML file paths.

    Tasks live under ``\\Windows\\System32\\Tasks\\`` (recursive — Win10/11
    organise Microsoft tasks under a deep subdirectory tree). Many
    task files have NO extension (the legacy convention). Some carry
    `.xml` (third-party convention or copied-out backups). We accept
    both: any regular file under a path containing ``Tasks`` (case-
    insensitive) AND whose first 256 bytes look like XML.

    Mirrors the EVTX / Prefetch / SRUM walker shape: case-insensitive
    matching + sandbox check that rejects symlinks pointing outside
    the root tree (Rule #1 spirit).

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Defensive against missing roots, permission errors, short reads —
    every error path is swallowed at the per-root / per-file level so
    one corrupted detection root doesn't abort the entire walk.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots` — NEVER ``firmware.extracted_path`` alone.
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
            # Skip directories outside any \Tasks\ subtree to keep the
            # walk bounded — Tasks are exclusively under
            # \Windows\System32\Tasks\ on canonical Windows extracts.
            if "tasks" not in dirpath.lower():
                continue
            for name in filenames:
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
                # Quick sniff — first 256 bytes should look like XML
                # (BOM / "<?xml" / "<Task" prefix). Tasks XML uses
                # UTF-16-LE BOM + "<?xml" prolog; we tolerate both.
                try:
                    with open(real_full, "rb") as f:
                        head = f.read(256)
                except OSError:
                    continue
                if not head:
                    continue
                # UTF-16-LE BOM (FF FE) or UTF-8 BOM (EF BB BF) or raw
                # ASCII. Both legitimate Task encodings produce an XML
                # prolog within the first 256 bytes.
                head_lower = head.lower()
                if (
                    b"<?xml" in head_lower
                    or b"<task" in head_lower
                    or head.startswith(b"\xff\xfe")
                    or head.startswith(b"\xef\xbb\xbf")
                ):
                    hits.append(real_full)
    return hits


async def _walk_scheduled_task_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_scheduled_task_files` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_scheduled_task_files, roots)


async def _parse_scheduled_task_xml_async(path: str) -> dict[str, Any]:
    """Async wrapper around :func:`parse_scheduled_task_xml` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, parse_scheduled_task_xml, path)


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "task_count": 0,
        "by_status": {"ok": 0, "error": 0, "unavailable": 0, "skipped": 0},
        "unique_authors": 0,
        "highest_available_count": 0,
        "encoded_powershell_count": 0,
        "errors": [],
        "per_file": [],
    }


def _relativize_path(full_path: str, roots: list[str]) -> str:
    """Compute path relative to whichever detection root contains it.

    Matches the WindowsScheduledTask.source_path discipline. Returns
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


def _derive_task_name(task_uri: str | None, source_path: str) -> str:
    """Derive a task_name from URI (preferred) or source_path (fallback).

    Tasks XML <URI> uses backslash-separated form (Windows convention).
    Source path uses forward slashes after relativization. Both yield
    the basename via simple split + last segment.
    """
    if task_uri:
        return task_uri.rsplit("\\", 1)[-1].strip()
    return os.path.basename(source_path).strip() or "(unnamed)"


def _build_record(
    firmware_id: uuid.UUID,
    source_path: str,
    parsed_data: dict[str, Any],
) -> WindowsScheduledTask | None:
    """Construct a WindowsScheduledTask from a parse result.

    Always returns a row — even when most fields are absent (the
    minimal record carries source_path + task_name only). Returns
    None only on the structural assertion that the parse_data is a
    dict (defensive against caller misuse).
    """
    if not isinstance(parsed_data, dict):
        return None
    task_uri = parsed_data.get("task_uri")
    task_name = _derive_task_name(task_uri, source_path)

    return WindowsScheduledTask(
        firmware_id=firmware_id,
        source_path=source_path[:2048],
        task_uri=(task_uri[:2048] if task_uri else None),
        task_name=task_name[:512],
        author=(
            parsed_data.get("author")[:512]
            if parsed_data.get("author")
            else None
        ),
        registration_date=parsed_data.get("registration_date"),
        run_level=(
            parsed_data.get("run_level")[:64]
            if parsed_data.get("run_level")
            else None
        ),
        run_as_user=(
            parsed_data.get("run_as_user")[:512]
            if parsed_data.get("run_as_user")
            else None
        ),
        triggers=_stamp_windows_scheduled_tasks_triggers(
            parsed_data.get("triggers") or []
        ),
        actions=_stamp_windows_scheduled_tasks_actions(
            parsed_data.get("actions") or []
        ),
        principal=_stamp_windows_scheduled_tasks_principal(
            dict(parsed_data.get("principal") or {})
        ),
        settings=_stamp_windows_scheduled_tasks_settings(
            dict(parsed_data.get("settings") or {})
        ),
    )


# ── Inner orchestrator (accepts a db; reusable in tier-1 live canaries) ──────


async def _do_scheduled_task_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_tasks: int = _DEFAULT_MAX_TASKS_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every Scheduled Task XML in ``firmware_id``'s extracted tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for task XML files under any \\Tasks\\ subtree.
    3. For each file: parse via defusedxml (run_in_executor for
       Rule #5 sync I/O), bulk-insert WindowsScheduledTask rows.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real test
    DB without DNS resolution issues from ``async_session_factory()``.
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

    task_paths = await _walk_scheduled_task_files_async(roots)
    if not task_paths:
        return _empty_walk_result(time.monotonic() - started)

    # Bound per Rule #19 evidence-first — Win11 ships 150-200 tasks; a
    # 5000 cap protects against attacker-planted task spam without
    # blocking legitimate forensic walks.
    if len(task_paths) > max_tasks:
        logger.warning(
            "scheduled_task_walk: firmware %s exceeded max_tasks=%d "
            "(found %d); truncating",
            firmware_id,
            max_tasks,
            len(task_paths),
        )
        task_paths = task_paths[:max_tasks]

    by_status: dict[str, int] = {
        "ok": 0,
        "error": 0,
        "unavailable": 0,
        "skipped": 0,
    }
    authors: set[str] = set()
    highest_available_count = 0
    encoded_powershell_count = 0
    errors: list[str] = []
    per_file: list[dict[str, Any]] = []

    for task_path in task_paths:
        relpath = _relativize_path(task_path, roots)
        try:
            parsed = await _parse_scheduled_task_xml_async(task_path)
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = (
                f"parse failed for {task_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            by_status["error"] += 1
            per_file.append(
                {
                    "path": relpath,
                    "status": "error",
                    "task_uri": None,
                    "author": None,
                    "error": err,
                }
            )
            continue

        status = parsed.get("status", "error")
        by_status[status] = by_status.get(status, 0) + 1

        if status == "ok":
            data = parsed.get("data") or {}
            record = _build_record(firmware_id, relpath, data)
            if record is not None:
                db.add(record)
                await db.flush()
                if record.author:
                    authors.add(record.author)
                if record.run_level == "HighestAvailable":
                    highest_available_count += 1
                # Encoded-PS detection across all actions in this task.
                for act in data.get("actions") or []:
                    if is_action_encoded_powershell(
                        act.get("command"), act.get("arguments")
                    ):
                        encoded_powershell_count += 1
                        break  # one match per task is enough
            per_file.append(
                {
                    "path": relpath,
                    "status": "ok",
                    "task_uri": data.get("task_uri"),
                    "author": data.get("author"),
                    "error": None,
                }
            )
        else:
            per_file.append(
                {
                    "path": relpath,
                    "status": status,
                    "task_uri": None,
                    "author": None,
                    "error": parsed.get("error") or parsed.get("reason"),
                }
            )

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "task_count": len(task_paths),
        "by_status": by_status,
        "unique_authors": len(authors),
        "highest_available_count": highest_available_count,
        "encoded_powershell_count": encoded_powershell_count,
        "errors": errors,
        "per_file": per_file,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_scheduled_task_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the Scheduled Task XML walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back. Mirrors the γ.4
    registry_hive_walker / ε.1.b.3 evtx_service / ζ.2.B
    prefetch_walker / ζ.3.B srum_walker shape.

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
                    "scheduled_task_walk: firmware %s not found",
                    firmware_id,
                )
                return

            row.scheduled_task_walk_status = "running"
            row.scheduled_task_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_scheduled_task_run(db, firmware_id)
                row.scheduled_task_walk_status = "completed"
                row.scheduled_task_walk_finished_at = _dt.datetime.now(
                    _dt.UTC
                )
                row.scheduled_task_walk_result = (
                    _stamp_firmware_scheduled_task_walk_result(result)
                )
                await db.commit()
                logger.info(
                    "scheduled_task_walk: firmware %s completed in "
                    "%.2fs (%d task XMLs, %d unique authors, %d "
                    "RunLevel=HighestAvailable, %d encoded-PS actions)",
                    firmware_id,
                    result["run_seconds"],
                    result["task_count"],
                    result["unique_authors"],
                    result["highest_available_count"],
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
                        fail_row.scheduled_task_walk_status = "failed"
                        fail_row.scheduled_task_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.scheduled_task_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "scheduled_task_walk: firmware %s failed",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "scheduled_task_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_scheduled_task_walk_firmware_safe(
    firmware_id: uuid.UUID,
) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as ζ.2.B / ζ.3.B
    auto_walk_firmware_safe.

    Distinct from :func:`run_scheduled_task_walk_background`: the
    background runner transitions the firmware status column through
    queued → running → completed/failed and is for explicit operator-
    triggered walks. The auto-walk-on-unpack flow runs the SAME
    orchestrator (``_do_scheduled_task_run``) but DOES NOT transition
    the status column — it stays ``idle`` until an operator
    explicitly triggers a re-walk via the trigger MCP tool, which
    resets and runs again.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_scheduled_task_run(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.scheduled_task_walk_result = (
                    _stamp_firmware_scheduled_task_walk_result(result)
                )
                await db.commit()
            logger.info(
                "scheduled_task_walk auto: firmware %s walked %d task "
                "XMLs in %.2fs",
                firmware_id,
                result["task_count"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "scheduled_task_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "DEFUSEDXML_UNAVAILABLE",
    "_do_scheduled_task_run",
    "auto_scheduled_task_walk_firmware_safe",
    "is_action_encoded_powershell",
    "is_defusedxml_available",
    "is_system_author",
    "parse_scheduled_task_xml",
    "run_scheduled_task_walk_background",
    "walk_scheduled_task_files",
]
