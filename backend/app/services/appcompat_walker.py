"""Phase κ.B.C — Windows AppCompat / Shimcache execution-evidence walker.

Walks Windows SYSTEM registry hives under detection roots (per Rule
#16), reads the ``ControlSet00X\\Control\\Session Manager\\AppCompatCache
\\AppCompatCache`` REG_BINARY value, parses it via a clean-room
pure-Python ``struct``-based parser (targeting Win10/11 + Server 2016+
format), classifies per-entry anomalies, and persists per-entry rows
into ``windows_appcompat_entries``.

**AppCompatCache is execution evidence.** The Application Compatibility
Engine records EVERY executable the system has seen, regardless of
whether it actually ran. Forensic gold for T1106 / T1059 / LotL hunts.
Healthy estates rarely have user-writable paths in AppCompat; an exec
under ``\\Users\\Public\\`` or ``\\Windows\\Temp\\`` means SOMEONE ran
the binary or it triggered AppCompat by being loaded as a DLL.

**Rule #19 evidence-first OSS-library probe** (ran 2026-05-12T21:00Z):

- ``regipy.registry.RegistryHive`` already in tree (used by
  ``registry_hive_walker.py``). API: ``RegistryHive(path)`` →
  ``.get_control_sets("\\Control\\Session Manager\\AppCompatCache")``
  returns list of full key paths; ``.get_key(<path>).get_value(...)``
  returns the value record.
- AppCompatCache binary format reference: Eric Zimmerman's
  ``AppCompatCacheParser`` C# (MIT) + Mandiant ShimCacheParser archives
  (~2013 + 2015 follow-up). Decision: clean-room pure-Python
  ``struct``-based parser. Smaller surface (~200 LOC over a
  well-documented format), no new dep, no foreign-license concern.

**Win10/11 + Server 2016+ format:**

- Header at offset 0x30 (some builds use offset 0x34 — we probe both):
  4-byte magic ``"10ts"``.
- Per-entry:
  - 4-byte signature ``"10ts"`` (used for re-sync on stream corruption)
  - 4-byte entry data length (LE, doesn't include the signature+length
    fields themselves)
  - 2-byte path length in bytes (LE)
  - UTF-16LE path (variable, ``path_length`` bytes)
  - 8-byte last_modified FILETIME (Windows FILETIME, 100-ns since 1601-01-01)
  - 4-byte data_size (LE; we IGNORE the data payload itself — only
    metadata interests us)
  - additional bytes per build (we resync via the next ``"10ts"``
    signature rather than trusting variable trailing fields).

Older formats (Win7, Win8.0, Win8.1, Server 2008/2012) use a different
layout — we GRACEFULLY DEGRADE: return parse_error=True for the
ControlSet and continue. Most firmware in the wild is Win10/11+;
older-format support can be added later when needed.

**Rule #39 inner/outer/safe runner triplet:**

- :func:`_do_appcompat_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks SYSTEM hives under detection roots, parses each
  ControlSet's AppCompatCache binary value via the pure-Python parser,
  persists per-entry ``WindowsAppCompatEntry`` rows, returns aggregate
  dict UNSTAMPED. Tier-1 tests call this directly via ``make_live_db()``.
- :func:`run_appcompat_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions via ``async_session_factory()``.
  Outer guard catches escapes; failure persistence on a fresh session.
- :func:`auto_appcompat_walk_firmware_safe` — UNPACK-POST-DETECTION hook.
  Runs the inner orchestrator but does NOT mutate
  ``appcompat_walk_status`` — leaves ``idle`` so manual re-trigger
  via the trigger MCP tool works without 409 conflict.

**Rule #36 no-execute discipline.** The walker is a pure-Python
``struct`` parser that decodes AppCompatCache bytes AS DATA. The walker
NEVER:

- Invokes ``rundll32`` / ``cscript`` / ``wmic`` / ``wine`` / ``mono``.
- Spawns ANY subprocess via ``subprocess`` / ``os.system`` / ``asyncio.
  create_subprocess_*``.
- Calls Windows APIs for AppCompat replay.

Test gate ``test_appcompat_walker_no_execute`` tokenizes this source
for forbidden invocation tokens (``subprocess``, ``os.system``,
``wine``, ``mono``, ``rundll32``, ``cscript``, ``wmic``).

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare ``firmware.extracted_path``)
so multi-rootfs Windows firmware (VHDX / NTFS / FAT32 / system images)
surfaces every SYSTEM hive candidate (typically one per Windows
installation; mirrored backup in RegBack/ also picked up).

**Performance.** Each SYSTEM hive walk is ~50-200 ms (regipy hive open +
read one REG_BINARY value); the pure-Python parser decodes ~500-1000
entries per hive in ~10 ms. Total per-firmware: <1 s.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os
import struct
import time
import traceback
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_appcompat_entries import WindowsAppCompatEntry
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_appcompat_walk_result,
    _stamp_windows_appcompat_entries_anomaly_flags,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum AppCompat entries persisted per firmware. Real Windows AppCompat
# caps at 1024 entries (older builds) or unlimited (Win10/11 — Server
# 2019+ can have 10000+). Cap at 50000 defensive against attacker-planted
# blobs.
_DEFAULT_MAX_ENTRIES_PER_FIRMWARE: int = 50_000

# Maximum SYSTEM hive size we'll attempt to read. A pathological hive
# could be 1 GB+; protect the synchronous walker.
_DEFAULT_MAX_HIVE_BYTES: int = 256 * 1024 * 1024  # 256 MiB

# Maximum REG_BINARY value size for AppCompatCache. Real-world values
# are 100 KB-2 MB; cap at 16 MiB defensive.
_DEFAULT_MAX_REG_VALUE_BYTES: int = 16 * 1024 * 1024  # 16 MiB

# Maximum per-entry path length (UTF-16LE bytes). Real paths are 100-300
# bytes; cap at 4096 bytes defensive against malformed entries.
_DEFAULT_MAX_PATH_BYTES: int = 4096

# Per-entry signature for Win10/11 + Server 2016+ format. Used for
# resync on stream corruption.
_ENTRY_SIGNATURE: bytes = b"10ts"

# Header magic offsets to probe. Win10/11 typically uses 0x30; some
# Server builds use 0x34.
_HEADER_MAGIC_OFFSETS: tuple[int, ...] = (0x30, 0x34)

# Windows FILETIME epoch — 1601-01-01 UTC. FILETIME is 100-ns intervals
# since this epoch. Used for FILETIME → datetime conversion.
_FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.UTC)

# FILETIME tick: 100 ns. 10,000,000 ticks per second.
_FILETIME_TICKS_PER_SECOND: int = 10_000_000


# ── Anomaly classifier path heuristics ───────────────────────────────────────

# Canonical adversary-staging directories. Path-match is case-insensitive
# substring match against the file_path (Windows paths come in mixed
# case, often with ``\\??\\`` device prefix). Each fragment is the
# literal directory prefix WITH a trailing single backslash so the
# substring check below catches both ``\users\public\evil.exe`` and
# ``\users\public\dir\nested.exe`` shapes.
_SUSPICIOUS_PATH_FRAGMENTS: tuple[str, ...] = (
    "\\users\\public\\",
    "\\windows\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\programdata\\microsoft\\windows\\caches\\",
    "c:\\temp\\",
    "\\users\\default\\appdata\\",
)

# Extensions considered "expected" in AppCompat — anything else triggers
# unusual_extension. Lowercase, includes the leading dot.
_EXPECTED_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".scr", ".com", ".msi", ".cpl", ".sys",
})

# Extensions that indicate possible extension-hiding (T1036 Masquerading).
# A path ending in these but otherwise looking like an executable shape
# raises temp_execution.
_TEMP_EXTENSIONS: frozenset[str] = frozenset({".tmp", ".dat"})


# ── Pure helpers (sync, executor-safe) ───────────────────────────────────────


def _filetime_to_datetime(filetime: int) -> _dt.datetime | None:
    """Convert a Windows FILETIME (100-ns ticks since 1601-01-01) to a UTC
    datetime.

    Returns None on zero / negative / out-of-range FILETIME (Win10 builds
    sometimes zero this field; we surface the row but with NULL ts).
    Defensive: never raises.
    """
    if filetime <= 0:
        return None
    try:
        seconds = filetime // _FILETIME_TICKS_PER_SECOND
        microseconds = (filetime % _FILETIME_TICKS_PER_SECOND) // 10
        # FILETIME max = ~year 30828; clamp to datetime.max (year 9999).
        delta = _dt.timedelta(seconds=seconds, microseconds=microseconds)
        try:
            return _FILETIME_EPOCH + delta
        except OverflowError:
            return None
    except (ValueError, OverflowError, ArithmeticError):
        return None


def _classify_path(file_path: str | None) -> dict[str, bool]:
    """Pure function — same path always produces the same flag dict.

    Returns a dict with keys ``suspicious_path``, ``temp_execution``,
    ``unusual_extension``. Caller adds ``parse_error`` separately when
    needed.
    """
    flags = {
        "suspicious_path": False,
        "temp_execution": False,
        "unusual_extension": False,
    }
    if not file_path:
        return flags

    lower = file_path.lower()

    # suspicious_path — substring against canonical staging directories.
    for fragment in _SUSPICIOUS_PATH_FRAGMENTS:
        if fragment in lower:
            flags["suspicious_path"] = True
            break

    # Extract extension for the other two checks.
    _, ext = os.path.splitext(lower)
    if ext:
        if ext in _TEMP_EXTENSIONS:
            flags["temp_execution"] = True
        elif ext not in _EXPECTED_EXTENSIONS:
            flags["unusual_extension"] = True
    else:
        # No extension AND non-empty path is itself unusual (real
        # executables almost always have an extension).
        flags["unusual_extension"] = True

    return flags


def build_anomaly_flags(
    *,
    file_path: str | None,
    parse_error: bool,
) -> dict[str, Any]:
    """Construct the anomaly_flags payload for one entry.

    Pure function — same inputs always produce the same output. Caller
    stamps the schema_version via
    ``_stamp_windows_appcompat_entries_anomaly_flags``.
    """
    path_flags = _classify_path(file_path)
    return {
        "suspicious_path": path_flags["suspicious_path"],
        "temp_execution": path_flags["temp_execution"],
        "unusual_extension": path_flags["unusual_extension"],
        "parse_error": bool(parse_error),
    }


# ── AppCompatCache binary parser (PARSE-ONLY — Rule #36) ─────────────────────
#
# Win10/11 + Server 2016+ format:
#   Header offset (0x30 or 0x34 depending on build):
#     - 4-byte magic "10ts"
#   Per-entry:
#     - 4-byte signature "10ts" (entry marker; used for resync)
#     - 4-byte entry data length (LE, excluding signature+length itself)
#     - 2-byte path length in bytes (LE)
#     - <path_length> bytes UTF-16LE path
#     - 8-byte FILETIME (LE, 100-ns since 1601-01-01)
#     - 4-byte data_size (LE, points to extra data we IGNORE)
#     - <data_size> trailing bytes (IGNORED — only metadata interests us)
#
# We resync on the next "10ts" signature rather than trusting entry
# data length, since some builds have variable-shape trailers.
#
# PARSE-ONLY: we extract path + FILETIME and IGNORE any payload bytes.


def _find_header_magic(blob: bytes) -> int | None:
    """Locate the AppCompatCache header magic ``"10ts"``.

    Returns the offset of the FIRST entry signature (i.e. the offset
    where iteration should START), or None if no Win10/11+ magic is
    found at the canonical offsets.
    """
    for header_offset in _HEADER_MAGIC_OFFSETS:
        if header_offset + 4 <= len(blob):
            if blob[header_offset:header_offset + 4] == _ENTRY_SIGNATURE:
                # Per Mandiant + Zimmerman: after the header magic at
                # offset N, entries start at N+4 (right after the magic).
                return header_offset + 4
    return None


def _parse_appcompat_cache_binary(
    blob: bytes,
    *,
    max_entries: int = _DEFAULT_MAX_ENTRIES_PER_FIRMWARE,
    max_path_bytes: int = _DEFAULT_MAX_PATH_BYTES,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse an AppCompatCache REG_BINARY value.

    Returns ``(entries, errors)`` where entries is a list of dicts
    ``{"file_path": str | None, "filetime": int, "entry_size": int}``
    and errors is a list of per-entry parse error messages.

    PARSE-ONLY: the parser reads bytes, unpacks structs, and emits
    metadata records. No payload bytes are interpreted as executable
    code; no spawn primitives are called. Defensive: bounds-checked;
    never raises.

    Returns empty entries + a single error if no Win10/11+ magic is
    found (older formats degrade-no-emit per κ.B intake spec).
    """
    entries: list[dict[str, Any]] = []
    errors: list[str] = []

    if len(blob) < 0x38:
        errors.append(
            f"blob too short ({len(blob)} bytes < minimum 56-byte header)"
        )
        return entries, errors

    cursor = _find_header_magic(blob)
    if cursor is None:
        errors.append(
            "AppCompatCache header magic '10ts' not found at offset 0x30 "
            "or 0x34 — likely older Win7/Win8 format which this parser "
            "does not support; gracefully degrading"
        )
        return entries, errors

    entry_idx = 0
    while cursor < len(blob) and entry_idx < max_entries:
        # Look for entry signature (4 bytes "10ts"). If not present at
        # cursor, scan forward to find next sig (resync).
        if cursor + 4 > len(blob):
            break
        if blob[cursor:cursor + 4] != _ENTRY_SIGNATURE:
            # Scan forward for next sig.
            next_sig = blob.find(_ENTRY_SIGNATURE, cursor)
            if next_sig < 0:
                break
            errors.append(
                f"resync from offset {cursor} to {next_sig} "
                f"(skipped {next_sig - cursor} bytes)"
            )
            cursor = next_sig

        # Past sig: parse entry header.
        # Layout: sig(4) + entry_data_length(4) + path_length(2) + path + ts(8) + data_size(4)
        if cursor + 4 + 4 + 2 > len(blob):
            errors.append(
                f"entry {entry_idx} truncated at offset {cursor} "
                "(need 10-byte header)"
            )
            break
        try:
            entry_data_length = struct.unpack_from(
                "<I", blob, cursor + 4
            )[0]
            path_length = struct.unpack_from("<H", blob, cursor + 8)[0]
        except struct.error as exc:
            errors.append(
                f"entry {entry_idx} header unpack: {exc}"
            )
            break

        # Sanity bounds.
        if path_length > max_path_bytes:
            errors.append(
                f"entry {entry_idx} path_length {path_length} exceeds "
                f"{max_path_bytes} cap; clamping"
            )
            path_length = max_path_bytes

        # Compute entry total bounds (sig+len = 8 bytes header, then
        # data of length entry_data_length follows).
        entry_total = 8 + entry_data_length
        if cursor + entry_total > len(blob):
            errors.append(
                f"entry {entry_idx} entry_data_length {entry_data_length} "
                f"exceeds remaining blob ({len(blob) - cursor - 8})"
            )
            break

        path_offset = cursor + 10  # after sig(4) + data_len(4) + path_len(2)
        path_end = path_offset + path_length
        if path_end > len(blob):
            errors.append(
                f"entry {entry_idx} path bytes truncated"
            )
            break

        # Decode path as UTF-16LE.
        file_path: str | None = None
        try:
            raw_path = blob[path_offset:path_end]
            decoded = raw_path.decode("utf-16-le", errors="ignore")
            # Strip trailing NULs and control chars.
            cleaned = decoded.rstrip("\x00").strip()
            # Some entries store the \??\ device prefix; preserve as-is.
            if cleaned:
                file_path = cleaned[:1024]
        except (UnicodeDecodeError, ValueError) as exc:
            errors.append(
                f"entry {entry_idx} path decode: {exc}"
            )

        # FILETIME at path_end (8 bytes LE).
        filetime = 0
        if path_end + 8 <= len(blob):
            try:
                filetime = struct.unpack_from("<Q", blob, path_end)[0]
            except struct.error:
                pass

        entries.append({
            "file_path": file_path,
            "filetime": filetime,
            "entry_size": entry_total,
        })

        # Advance cursor by entry_total (sig+len header + entry data).
        # If entry_data_length is suspect (zero / tiny), force resync.
        if entry_data_length < 14:  # minimum: path_length(2) + filetime(8) + data_size(4)
            # Scan to next sig instead.
            next_sig = blob.find(_ENTRY_SIGNATURE, cursor + 4)
            if next_sig < 0:
                break
            cursor = next_sig
        else:
            cursor += entry_total

        entry_idx += 1

    return entries, errors


# ── Hive-finder helpers ──────────────────────────────────────────────────────


# Filenames we treat as SYSTEM hives. AppCompat only lives in SYSTEM.
_SYSTEM_HIVE_BASENAMES: frozenset[str] = frozenset({"SYSTEM"})

# Regf magic — same as registry_hive_walker.
_REGF_MAGIC: bytes = b"regf"


def _is_system_hive(path: str) -> bool:
    """True iff the file at ``path`` is a SYSTEM-named regf-magic hive."""
    try:
        if not os.path.isfile(path):
            return False
        basename = os.path.basename(path).upper()
        if basename not in _SYSTEM_HIVE_BASENAMES:
            return False
        with open(path, "rb") as fh:
            return fh.read(4) == _REGF_MAGIC
    except OSError:
        return False


def scan_for_system_hives(roots: list[str]) -> list[str]:
    """Walk every detection root and return absolute paths of SYSTEM
    hives.

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Skips symlinks pointing outside the root tree (Rule #1 spirit).
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for name in filenames:
                if name.upper() not in _SYSTEM_HIVE_BASENAMES:
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                if _is_system_hive(real_full):
                    hits.append(real_full)
    return hits


def _control_set_ordinal_from_path(key_path: str) -> int | None:
    """Extract the integer ControlSetNNN ordinal from a key path.

    ``\\ControlSet001\\Control\\Session Manager\\AppCompatCache`` → 1.
    Returns None when the path doesn't match the expected shape.
    """
    parts = [p for p in key_path.split("\\") if p]
    for part in parts:
        if part.upper().startswith("CONTROLSET") and len(part) > 10:
            try:
                return int(part[10:])
            except ValueError:
                continue
    return None


# ── Per-hive walker ──────────────────────────────────────────────────────────


def _walk_one_hive_sync(
    hive_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_entries: int,
    persisted_so_far: int,
) -> tuple[list[WindowsAppCompatEntry], dict[str, Any]]:
    """Open one SYSTEM hive and parse its AppCompatCache value.

    SYNC I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Defensive: returns partial rows on any error.
    """
    aggregate: dict[str, Any] = {
        "path": relative_source,
        "status": "ok",
        "control_sets_seen": 0,
        "entries_parsed": 0,
        "entries_persisted": 0,
        "entries_capped": 0,
        "parse_errors": 0,
        "suspicious_path_count": 0,
        "temp_execution_count": 0,
        "unusual_extension_count": 0,
        "anomaly_total": 0,
        "error": None,
    }

    try:
        size = os.path.getsize(hive_path)
    except OSError as exc:
        aggregate["status"] = "error"
        aggregate["error"] = (
            f"stat failed: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return [], aggregate

    if size > _DEFAULT_MAX_HIVE_BYTES:
        aggregate["status"] = "skipped"
        aggregate["error"] = (
            f"hive size {size} exceeds max {_DEFAULT_MAX_HIVE_BYTES}"
        )
        return [], aggregate

    # Lazy import — regipy cold-import is ~200 ms (Rule #30 legitimate
    # reason: import-time cost; matches registry_hive_walker.py pattern).
    try:
        from regipy.exceptions import (  # noqa: F401 — used via except
            RegipyException,
            RegistryKeyNotFoundException,
        )
        from regipy.registry import RegistryHive
    except ImportError as exc:
        aggregate["status"] = "unavailable"
        aggregate["error"] = f"regipy import: {exc}"
        return [], aggregate

    rows: list[WindowsAppCompatEntry] = []
    persist_budget = max_entries - persisted_so_far

    try:
        hive = RegistryHive(hive_path)
    except Exception as exc:  # noqa: BLE001
        aggregate["status"] = "error"
        aggregate["error"] = (
            f"hive open: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return rows, aggregate

    # Find AppCompatCache key paths under all ControlSets.
    try:
        cs_paths = hive.get_control_sets(
            r"\Control\Session Manager\AppCompatCache"
        )
    except Exception as exc:  # noqa: BLE001
        aggregate["status"] = "error"
        aggregate["error"] = (
            f"get_control_sets: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return rows, aggregate

    for cs_path in cs_paths:
        aggregate["control_sets_seen"] += 1
        cs_ordinal = _control_set_ordinal_from_path(cs_path)

        try:
            key = hive.get_key(cs_path)
        except Exception as exc:  # noqa: BLE001
            aggregate["parse_errors"] += 1
            aggregate["error"] = (
                f"get_key({cs_path}): {type(exc).__name__}: {str(exc)[:120]}"
            )
            continue

        try:
            # Read the REG_BINARY value named "AppCompatCache".
            value_record = key.get_value(
                "AppCompatCache", as_json=False, raise_on_missing=False
            )
        except Exception as exc:  # noqa: BLE001
            aggregate["parse_errors"] += 1
            continue

        if value_record is None:
            continue

        # The value bytes — regipy returns bytes for REG_BINARY.
        if isinstance(value_record, (bytes, bytearray)):
            value_bytes = bytes(value_record)
        else:
            # Some regipy versions wrap value in a record dict.
            value_bytes = b""
            for attr_name in ("value", "data"):
                v = getattr(value_record, attr_name, None)
                if isinstance(v, (bytes, bytearray)):
                    value_bytes = bytes(v)
                    break
            if not value_bytes and isinstance(value_record, dict):
                v = value_record.get("value") or value_record.get("data")
                if isinstance(v, (bytes, bytearray)):
                    value_bytes = bytes(v)
            if not value_bytes:
                aggregate["parse_errors"] += 1
                continue

        if len(value_bytes) > _DEFAULT_MAX_REG_VALUE_BYTES:
            aggregate["parse_errors"] += 1
            continue

        # Parse the binary.
        parsed_entries, parser_errors = _parse_appcompat_cache_binary(
            value_bytes,
            max_entries=max_entries,
        )
        if parser_errors:
            aggregate["parse_errors"] += len(parser_errors)

        for position, entry in enumerate(parsed_entries):
            aggregate["entries_parsed"] += 1

            if persist_budget <= 0:
                aggregate["entries_capped"] += 1
                continue

            file_path = entry.get("file_path")
            filetime = entry.get("filetime", 0)
            entry_size = entry.get("entry_size", 0)

            last_modified_ts = _filetime_to_datetime(filetime)

            # Classify anomalies.
            parse_error_text: str | None = None
            if not file_path:
                parse_error_text = "entry has no parseable path"

            anomaly = build_anomaly_flags(
                file_path=file_path,
                parse_error=parse_error_text is not None,
            )
            if anomaly["suspicious_path"]:
                aggregate["suspicious_path_count"] += 1
            if anomaly["temp_execution"]:
                aggregate["temp_execution_count"] += 1
            if anomaly["unusual_extension"]:
                aggregate["unusual_extension_count"] += 1
            if any(
                v for k, v in anomaly.items()
                if isinstance(v, bool) and k != "parse_error"
            ):
                aggregate["anomaly_total"] += 1

            row = WindowsAppCompatEntry(
                firmware_id=firmware_id,
                file_path=file_path,
                insertion_position=position,
                last_modified_ts=last_modified_ts,
                anomaly_flags=_stamp_windows_appcompat_entries_anomaly_flags(
                    dict(anomaly)
                ),
                source_hive_path=relative_source[:512],
                control_set=cs_ordinal,
                schema_version=1,
                parse_error=parse_error_text,
                entry_size_bytes=entry_size,
            )
            rows.append(row)
            persist_budget -= 1
            aggregate["entries_persisted"] += 1

    return rows, aggregate


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "hives_scanned": 0,
        "entries_persisted": 0,
        "entries_capped": 0,
        "parse_errors": 0,
        "suspicious_path_count": 0,
        "temp_execution_count": 0,
        "unusual_extension_count": 0,
        "anomaly_total": 0,
        "errors": [],
        "per_hive": [],
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
                real_full[len(real_root) + 1:]
                if real_full != real_root
                else "."
            )
    return os.path.basename(full_path)


async def _scan_for_system_hives_async(roots: list[str]) -> list[str]:
    """Async wrapper around scan_for_system_hives (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, scan_for_system_hives, roots)


async def _walk_one_hive_async(
    hive_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_entries: int,
    persisted_so_far: int,
) -> tuple[list[WindowsAppCompatEntry], dict[str, Any]]:
    """Async wrapper around _walk_one_hive_sync (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_hive_sync(
            hive_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
            max_entries=max_entries,
            persisted_so_far=persisted_so_far,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ──────────────────────────


async def _do_appcompat_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_entries: int = _DEFAULT_MAX_ENTRIES_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every SYSTEM hive under ``firmware_id``'s detection roots,
    parse the AppCompatCache REG_BINARY value, classify anomalies, and
    persist per-entry rows.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for SYSTEM hives (filename + regf magic).
    3. For each hive: open via regipy, read AppCompatCache value for
       each ControlSet, parse the binary, build rows.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real test
    DB without DNS resolution issues from ``async_session_factory()``.

    Rule #36 reminder: NEVER invokes any extracted binary; surfaces
    paths as DATA only.
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

    hive_paths = await _scan_for_system_hives_async(roots)
    if not hive_paths:
        return _empty_walk_result(time.monotonic() - started)

    hives_scanned = 0
    entries_persisted = 0
    entries_capped = 0
    parse_errors = 0
    suspicious_path_count = 0
    temp_execution_count = 0
    unusual_extension_count = 0
    anomaly_total = 0
    errors: list[str] = []
    per_hive: list[dict] = []

    for hive_path in hive_paths:
        relative = _relativize_path(hive_path, roots)
        try:
            rows, agg = await _walk_one_hive_async(
                hive_path,
                firmware_id=firmware_id,
                relative_source=relative,
                max_entries=max_entries,
                persisted_so_far=entries_persisted,
            )
        except Exception as exc:  # noqa: BLE001
            err = (
                f"walk failed for {hive_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_hive.append({
                "path": relative,
                "status": "error",
                "control_sets_seen": 0,
                "entries_parsed": 0,
                "entries_persisted": 0,
                "entries_capped": 0,
                "parse_errors": 0,
                "suspicious_path_count": 0,
                "temp_execution_count": 0,
                "unusual_extension_count": 0,
                "anomaly_total": 0,
                "error": err,
            })
            continue

        hives_scanned += 1
        entries_persisted += agg["entries_persisted"]
        entries_capped += agg["entries_capped"]
        parse_errors += agg["parse_errors"]
        suspicious_path_count += agg["suspicious_path_count"]
        temp_execution_count += agg["temp_execution_count"]
        unusual_extension_count += agg["unusual_extension_count"]
        anomaly_total += agg["anomaly_total"]
        per_hive.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

        for row in rows:
            db.add(row)
        if rows:
            await db.flush()

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "hives_scanned": hives_scanned,
        "entries_persisted": entries_persisted,
        "entries_capped": entries_capped,
        "parse_errors": parse_errors,
        "suspicious_path_count": suspicious_path_count,
        "temp_execution_count": temp_execution_count,
        "unusual_extension_count": unusual_extension_count,
        "anomaly_total": anomaly_total,
        "errors": errors,
        "per_hive": per_hive,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_appcompat_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the AppCompat walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a fresh
    session because the inner one rolled back.
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
                    "appcompat_walk: firmware %s not found", firmware_id
                )
                return

            row.appcompat_walk_status = "running"
            row.appcompat_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_appcompat_walk(db, firmware_id)
                row.appcompat_walk_status = "completed"
                row.appcompat_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.appcompat_walk_result = (
                    _stamp_firmware_appcompat_walk_result(result)
                )
                await db.commit()

                logger.info(
                    "appcompat_walk: firmware %s completed in %.2fs "
                    "(%d hives, %d entries persisted, %d anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["hives_scanned"],
                    result["entries_persisted"],
                    result["anomaly_total"],
                )
            except Exception as exc:  # noqa: BLE001
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
                        fail_row.appcompat_walk_status = "failed"
                        fail_row.appcompat_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.appcompat_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "appcompat_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "appcompat_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_appcompat_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point — runs the inner orchestrator but
    does NOT mutate ``appcompat_walk_status`` so a manual re-trigger
    via the trigger MCP tool still works without 409 conflict.

    Distinct from :func:`run_appcompat_walk_background`: the background
    runner (a) transitions the firmware status column through queued →
    running → completed/failed; (b) is intended for explicit operator-
    triggered walks via the trigger MCP tool. The auto-walk-on-unpack
    flow runs the SAME orchestrator (``_do_appcompat_walk``) but DOES
    NOT transition the status column.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_appcompat_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.appcompat_walk_result = (
                    _stamp_firmware_appcompat_walk_result(result)
                )
                await db.commit()

            logger.info(
                "appcompat_walk auto: firmware %s walked %d hives / "
                "%d entries persisted in %.2fs",
                firmware_id,
                result["hives_scanned"],
                result["entries_persisted"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "appcompat_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_appcompat_walk",
    "_parse_appcompat_cache_binary",
    "auto_appcompat_walk_firmware_safe",
    "build_anomaly_flags",
    "run_appcompat_walk_background",
    "scan_for_system_hives",
]
