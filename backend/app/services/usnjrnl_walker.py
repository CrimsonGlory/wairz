"""Phase κ.E — Windows NTFS $UsnJrnl:$J change-log walker (TENTH κ-era walker).

Reads raw NTFS images (``.dd`` / ``.raw`` / ``.ntfs`` / ``.img`` /
``.bin`` candidates under each detection root) extracted from firmware
captures, opens each via ``dissect.ntfs.NTFS``, locates the
``$Extend/$UsnJrnl`` MFT record's ``$J`` ADS, and iterates USN records
via ``dissect.ntfs.usnjrnl.UsnJrnl.records()`` to surface T1070.004
(File Deletion) anti-forensics evidence as ``WindowsUsnJrnlEntry``
rows for downstream finding-emit hooks (κ.E.D).

**Rule #39 inner/outer/safe runner triplet** (γ.4 + δ.5 + ε.1.b.3 +
ζ.2.B + ζ.3.B + η.A.C + η.B.C + η.C.C + κ.B.C + κ.D.C + κ.E.C —
Rule-of-Eleven):

- :func:`_do_usnjrnl_run` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every raw NTFS image candidate under detection roots,
  opens each via ``with open(path, "rb") as fh: NTFS(fh)``, locates
  the ``$Extend/$UsnJrnl:$J`` ADS, iterates ``UsnJrnl.records()`` for
  every USN_RECORD_V2/V3, decodes reason flags via the wire bitmask,
  classifies per-record + cross-record anomalies, persists per-record
  ``WindowsUsnJrnlEntry`` rows, returns aggregate dict UNSTAMPED.
- :func:`run_usnjrnl_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running → completed
  | failed) via ``async_session_factory()``. Outer guard catches
  escapes; failure persistence on a fresh session.
- :func:`auto_usnjrnl_walk_firmware_safe` — UNPACK-POST-DETECTION hook.
  Runs the inner orchestrator but does NOT mutate
  ``usnjrnl_walk_status`` (leaves ``idle`` so manual re-trigger works
  without 409).

**Rule #36 no-execute discipline.** ``dissect.ntfs`` is a pure-Python
parser that decodes NTFS structures AS DATA. The walker NEVER:

- Mounts the raw image via ``ntfs-3g`` / ``mount`` / ``losetup`` /
  ``qemu-system``.
- Invokes any file referenced by the USN journal entries (filenames
  are surfaced as DATA for operator review).
- Executes any binary on the parsed volume.
- Spawns sub-processes against extracted artefacts.

Test gate ``test_usnjrnl_walker.py::test_walker_no_execute`` plus a
canary test confirms the gate ACTUALLY fires on synthetic violations.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare ``firmware.extracted_path``)
so scatter-zip / multi-archive Windows extracts surface their raw NTFS
image candidates.

**Rule #19 evidence-first probe.** :func:`is_dissect_ntfs_available`
exposes a graceful-degrade probe so consumers can surface a clear
"library not installed" message rather than an opaque ImportError.
Mirrors the η.A MFT walker's ``DISSECT_NTFS_UNAVAILABLE`` pattern.

**Performance**. dissect.ntfs is pure-Python; the $J ADS can be tens-
to-hundreds of megabytes on busy hosts. We cap persisted rows at 5000
per firmware (``_DEFAULT_MAX_RECORDS_PER_FIRMWARE``) — same envelope
as the η.A MFT walker — to keep DB sizes manageable. Operators
wanting full-volume coverage re-walk via the MCP tool against a
specific image.

**Anomaly classifiers** (κ.E.D — 3 finding sources):

- ``windows_usnjrnl_file_deletion`` MEDIUM — ``FILE_DELETE`` reason
  on an executable-extension filename.
- ``windows_usnjrnl_temp_create_delete_pair`` HIGH — same file (matched
  by ``parent_file_reference_number + file_name``) emits both
  ``FILE_CREATE`` AND ``FILE_DELETE`` within 5 minutes AND the parent
  directory looks like a temp / staging path. Staged-payload anti-
  forensics.
- ``windows_usnjrnl_renamed_executable`` MEDIUM — ``RENAME_OLD_NAME``
  + ``RENAME_NEW_NAME`` pair with an extension change. T1036
  Masquerading.

Per the κ.C postmortem lesson, the "is-temp-path" predicate uses
EXPLICIT shell-boundary character groups (``[\\\\/]``) rather than
``\\b`` since ``\\b`` has subtle behaviour around ``/`` and ``\\``.
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
from collections.abc import Iterable, Iterator
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_usnjrnl_entries import WindowsUsnJrnlEntry
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_usnjrnl_walk_result,
    _stamp_windows_usnjrnl_reason_flags,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum USN records persisted per firmware. The $J ADS can hold
# hundreds of thousands of records on busy hosts; for forensic triage
# we cap at 5000 (same envelope as η.A's MFT cap). Operators wanting
# fuller coverage re-walk via the MCP tool against a specific image.
_DEFAULT_MAX_RECORDS_PER_FIRMWARE: int = 5000

# Cap on raw NTFS image size to attempt. Mirrors η.A — 16 GiB. Larger
# images are skipped with status="skipped" rather than walked, to
# protect the in-process synchronous walker.
_DEFAULT_MAX_IMAGE_BYTES: int = 16 * 1024 * 1024 * 1024  # 16 GiB

# Cap on per-image record iteration. Defense against attacker-planted
# pathologically-large $J streams. 1_000_000 records is well above any
# realistic per-image total in a forensic firmware capture.
_DEFAULT_MAX_RECORDS_PER_IMAGE: int = 1_000_000

# Filename extensions / suffixes that mark a candidate raw NTFS image.
_RAW_IMAGE_EXTENSIONS: tuple[str, ...] = (
    ".dd",
    ".raw",
    ".ntfs",
    ".img",
    ".bin",
)

# Executable-extension set used by the file_deletion classifier.
_EXECUTABLE_EXTENSIONS: tuple[str, ...] = (
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
    ".vbs",
    ".scr",
    ".com",
    ".cmd",
    ".js",
    ".cpl",
    ".msi",
)

# Temp / staging path tokens for the temp_create_delete_pair classifier.
# Use EXPLICIT shell-boundary character groups (``[\\\\/]``) per the κ.C
# postmortem lesson — ``\\b`` has subtle behaviour around ``/`` and ``\\``.
_TEMP_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:[\\/]|^)Temp(?:[\\/]|$)", re.IGNORECASE),
    re.compile(
        r"(?:[\\/]|^)AppData[\\/]Local[\\/]Temp(?:[\\/]|$)", re.IGNORECASE
    ),
    re.compile(r"(?:[\\/]|^)ProgramData(?:[\\/]|$)", re.IGNORECASE),
    re.compile(
        r"(?:[\\/]|^)Users[\\/]Public[\\/]Downloads(?:[\\/]|$)",
        re.IGNORECASE,
    ),
    re.compile(r"(?:[\\/]|^)Windows[\\/]Temp(?:[\\/]|$)", re.IGNORECASE),
    re.compile(r"(?:[\\/]|^)Public[\\/]Downloads(?:[\\/]|$)", re.IGNORECASE),
)

# Window for the temp_create_delete_pair classifier — same file
# CREATE + DELETE within this many seconds.
_CREATE_DELETE_WINDOW_SECONDS: int = 5 * 60

# Reason bitmask flag values — local copies of dissect.ntfs USN_REASON
# bits (the parser exposes them via the cstruct flag enum; we keep
# explicit local constants for readability + to avoid coupling the
# decoder to dissect-internal constant names).
USN_REASON_FILE_CREATE: int = 0x00000100
USN_REASON_FILE_DELETE: int = 0x00000200
USN_REASON_RENAME_OLD_NAME: int = 0x00001000
USN_REASON_RENAME_NEW_NAME: int = 0x00002000


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_dissect_ntfs_available() -> bool:
    """Return True iff ``dissect.ntfs`` is importable in this process.

    Mirrors the η.A MFT walker probe — pure-Python parser with a
    sub-millisecond import cache hit after first call.
    """
    try:
        import dissect.ntfs  # noqa: F401 — import-only probe
        import dissect.ntfs.usnjrnl  # noqa: F401 — UsnJrnl import-only probe
    except ImportError:
        return False
    return True


DISSECT_NTFS_UNAVAILABLE: dict[str, Any] = {
    "status": "unavailable",
    "reason": "dissect.ntfs not installed — see backend/pyproject.toml",
    "records": 0,
}


# ── NTFS image candidate enumeration ─────────────────────────────────────────


def walk_raw_ntfs_images(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return candidate raw NTFS image paths.

    Selects files whose basename matches any of ``_RAW_IMAGE_EXTENSIONS``
    (case-insensitive). The magic-check (first bytes ``'NTFS    '`` at
    sector offset 3) is deferred to :func:`looks_like_ntfs`.

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Defensive against missing roots, permission errors.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots`.
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
            root, followlinks=False
        ):
            for name in filenames:
                lower = name.lower()
                if not any(lower.endswith(ext) for ext in _RAW_IMAGE_EXTENSIONS):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math; one realpath per candidate
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                try:
                    if not os.path.isfile(real_full):  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
                        continue
                except OSError:
                    continue
                hits.append(real_full)
    return hits


def looks_like_ntfs(path: str) -> bool:
    """Return True iff the file at ``path`` has an NTFS boot sector
    signature (``'NTFS    '`` at byte offset 3 of sector 0).
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return False
    return len(head) >= 11 and head[3:11] == b"NTFS    "


# ── Reason-flag decoder ──────────────────────────────────────────────────────


def decode_reason_flags(raw: int) -> dict[str, Any]:
    """Decode a USN_REASON DWORD bitmask into the canonical bool dict.

    Mirrors the ``_decode_usn_reason_bitmask`` helper in
    ``app.services.jsonb_normalizers`` so this module can build payloads
    directly (the normalizer is the read-site coercion partner; this
    function is the write-site builder).
    """
    raw_int = int(raw) & 0xFFFFFFFF
    return {
        "data_overwrite": bool(raw_int & 0x00000001),
        "data_extend": bool(raw_int & 0x00000002),
        "data_truncation": bool(raw_int & 0x00000004),
        "named_data_overwrite": bool(raw_int & 0x00000010),
        "named_data_extend": bool(raw_int & 0x00000020),
        "named_data_truncation": bool(raw_int & 0x00000040),
        "file_create": bool(raw_int & USN_REASON_FILE_CREATE),
        "file_delete": bool(raw_int & USN_REASON_FILE_DELETE),
        "ea_change": bool(raw_int & 0x00000400),
        "security_change": bool(raw_int & 0x00000800),
        "rename_old_name": bool(raw_int & USN_REASON_RENAME_OLD_NAME),
        "rename_new_name": bool(raw_int & USN_REASON_RENAME_NEW_NAME),
        "indexable_change": bool(raw_int & 0x00004000),
        "basic_info_change": bool(raw_int & 0x00008000),
        "hard_link_change": bool(raw_int & 0x00010000),
        "compression_change": bool(raw_int & 0x00020000),
        "encryption_change": bool(raw_int & 0x00040000),
        "object_id_change": bool(raw_int & 0x00080000),
        "reparse_point_change": bool(raw_int & 0x00100000),
        "stream_change": bool(raw_int & 0x00200000),
        "transacted_change": bool(raw_int & 0x00400000),
        "integrity_change": bool(raw_int & 0x00800000),
        "close": bool(raw_int & 0x80000000),
        "_raw": raw_int,
    }


# ── Anomaly classifiers (pure functions) ─────────────────────────────────────


def has_executable_extension(name: str | None) -> bool:
    """Return True iff ``name`` ends in a recognised executable extension.

    Case-insensitive match against ``_EXECUTABLE_EXTENSIONS``. Defensive
    against ``None`` / empty.
    """
    if not name:
        return False
    lower = name.lower()
    return any(lower.endswith(ext) for ext in _EXECUTABLE_EXTENSIONS)


def looks_like_temp_path(path: str | None) -> bool:
    """Return True iff ``path`` matches one of the canonical temp /
    staging path patterns.

    Uses EXPLICIT shell-boundary character groups (``[\\\\/]``) per the
    κ.C postmortem lesson. The patterns match `Temp/`, `/Temp`,
    `AppData/Local/Temp/`, `ProgramData/`, `Public/Downloads/`,
    `Windows/Temp/`, case-insensitively.
    """
    if not path:
        return False
    return any(p.search(path) for p in _TEMP_PATH_PATTERNS)


def extension_changed(old_name: str | None, new_name: str | None) -> bool:
    """Return True iff the case-insensitive extensions of ``old_name``
    and ``new_name`` differ.

    Defensive against missing names. Returns False if either is empty.
    """
    if not old_name or not new_name:
        return False
    _, old_ext = os.path.splitext(old_name)
    _, new_ext = os.path.splitext(new_name)
    return old_ext.lower() != new_ext.lower()


# ── USN record extraction helpers ────────────────────────────────────────────


def _safe_attr(record: Any, attr: str, default: Any = None) -> Any:
    """Pull ``attr`` from a parsed UsnRecord defensively."""
    try:
        return getattr(record, attr, default)
    except Exception:  # noqa: BLE001 — defensive boundary
        return default


def _safe_segment_reference(reference: Any) -> int | None:
    """Compute the 64-bit segment number from an MFT_SEGMENT_REFERENCE.

    The wire structure has SegmentNumberLowPart (DWORD) + SegmentNumberHighPart
    (WORD or 32-bit depending on version) + SequenceNumber. We assemble the
    low + high parts into the full segment number. dissect.ntfs exposes
    ``util.segment_reference`` for V2/V3 records; for FILE_ID_128 (V3/V4)
    references we treat the leading 8 bytes as the segment number to
    keep a consistent representation.
    """
    if reference is None:
        return None
    # Try dissect.ntfs's helper for V2 references first.
    try:
        from dissect.ntfs.util import segment_reference

        return int(segment_reference(reference))
    except Exception:  # noqa: BLE001 — defensive boundary
        pass
    # FILE_ID_128 fallback — take the leading 8 bytes as the segment.
    try:
        identifier = getattr(reference, "Identifier", None)
        if identifier is not None:
            return int.from_bytes(bytes(identifier[:8]), "little")
    except Exception:  # noqa: BLE001 — defensive boundary
        pass
    return None


def _safe_timestamp(record: Any) -> _dt.datetime | None:
    """Return the record's timestamp as a UTC datetime, or None on failure."""
    try:
        ts = record.timestamp
    except Exception:  # noqa: BLE001 — defensive boundary
        return None
    if ts is None:
        return None
    if isinstance(ts, _dt.datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=_dt.UTC)
        return ts
    return None


def _safe_filename(record: Any) -> str | None:
    """Return the record's filename, defensively."""
    try:
        fn = record.filename
    except Exception:  # noqa: BLE001 — defensive boundary
        return None
    if isinstance(fn, str) and fn:
        return fn
    return None


# ── Per-image walk ───────────────────────────────────────────────────────────


def _open_usnjrnl(fs: Any) -> Any | None:
    """Locate the ``$Extend/$UsnJrnl`` MFT record and open its ``$J`` ADS.

    Returns a :class:`dissect.ntfs.usnjrnl.UsnJrnl` instance ready for
    ``records()`` iteration, or None when the volume has no $UsnJrnl
    (Windows without USN journaling enabled — rare but possible).

    Defensive against missing $Extend entry / missing $J ADS / corrupt
    runlist.
    """
    try:
        from dissect.ntfs.usnjrnl import UsnJrnl
    except ImportError:
        return None

    try:
        # Navigate to $Extend/$UsnJrnl. dissect.ntfs exposes the MFT
        # record by full path; the ADS is named '$J' on the record.
        record = fs.mft.get("$Extend/$UsnJrnl")
    except Exception:  # noqa: BLE001 — defensive boundary
        return None

    if record is None:
        return None

    # Open the $J ADS data stream. ``open()`` returns a BinaryIO that
    # reads the ADS bytes; the UsnJrnl parser then walks records.
    try:
        stream = record.open("$J")
    except Exception:  # noqa: BLE001 — defensive boundary
        return None

    if stream is None:
        return None

    try:
        return UsnJrnl(stream, ntfs=fs)
    except Exception:  # noqa: BLE001 — defensive boundary
        return None


def _iter_records_safe(jrnl: Any) -> Iterator[Any]:
    """Iterate ``UsnJrnl.records()`` swallowing per-record corruption."""
    try:
        iterator = jrnl.records()
    except Exception:  # noqa: BLE001 — defensive boundary
        return iter([])

    def _generator() -> Iterator[Any]:
        while True:
            try:
                record = next(iterator)
            except StopIteration:
                return
            except Exception:  # noqa: BLE001 — defensive boundary
                continue
            yield record

    return _generator()


def _walk_one_image(
    image_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_records: int,
    started_count: int,
    max_image_bytes: int = _DEFAULT_MAX_IMAGE_BYTES,
    max_records_per_image: int = _DEFAULT_MAX_RECORDS_PER_IMAGE,
) -> tuple[list[WindowsUsnJrnlEntry], dict]:
    """Open one raw NTFS image, locate $UsnJrnl:$J, walk records.

    Returns ``(rows_to_persist, per_image_aggregate)``. The rows are
    SQLAlchemy ORM instances ready for ``db.add()``; the aggregate
    tells the caller how many records were walked + filtered.

    Defensive boundary:
    - file size > max_image_bytes → status="skipped"
    - not NTFS → status="not_ntfs"
    - no $UsnJrnl → status="no_journal"
    - parser raises → status="error" with first 500 chars of error
    """
    aggregate: dict = {
        "path": relative_source,
        "status": "ok",
        "records_walked": 0,
        "records_persisted": 0,
        "file_deletion_count": 0,
        "temp_create_delete_pair_count": 0,
        "renamed_executable_count": 0,
        "parse_errors": 0,
        "error": None,
    }

    try:
        size = os.path.getsize(image_path)  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
    except OSError as exc:
        aggregate["status"] = "error"
        aggregate["error"] = (
            f"stat failed: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return [], aggregate

    if size > max_image_bytes:
        aggregate["status"] = "skipped"
        aggregate["error"] = (
            f"image size {size} exceeds max {max_image_bytes} "
            "(attacker-DoS / runaway-walk protection)"
        )
        return [], aggregate

    if not looks_like_ntfs(image_path):
        aggregate["status"] = "not_ntfs"
        aggregate["error"] = "NTFS boot sector signature not found"
        return [], aggregate

    try:
        from dissect.ntfs import NTFS
    except ImportError:
        aggregate["status"] = "unavailable"
        aggregate["error"] = "dissect.ntfs not importable"
        return [], aggregate

    rows: list[WindowsUsnJrnlEntry] = []
    persist_budget = max_records - started_count

    # In-memory bookkeeping for cross-record classifiers.
    # Map (parent_ref, filename_lower) → list of (reason_dict, timestamp)
    # so we can detect CREATE+DELETE pairs within a window.
    create_delete_buckets: dict[
        tuple[int, str], list[tuple[dict, _dt.datetime | None]]
    ] = {}
    # Map parent_ref → (old_name, old_timestamp) so we can pair
    # RENAME_OLD_NAME + RENAME_NEW_NAME records (same parent ref,
    # consecutive in the journal).
    pending_rename_old: tuple[int, str, _dt.datetime | None] | None = None

    try:
        with open(image_path, "rb") as fh:
            fs = NTFS(fh=fh)
            jrnl = _open_usnjrnl(fs)
            if jrnl is None:
                aggregate["status"] = "no_journal"
                aggregate["error"] = (
                    "$UsnJrnl:$J not present on volume (USN journaling "
                    "may not be enabled)"
                )
                return [], aggregate

            records_iterated = 0
            for record in _iter_records_safe(jrnl):
                records_iterated += 1
                if records_iterated > max_records_per_image:
                    aggregate["error"] = (
                        f"per-image record cap {max_records_per_image} "
                        "reached; stopped iteration"
                    )
                    break

                aggregate["records_walked"] += 1

                # Pull raw record fields defensively.
                raw_reason = _safe_attr(record, "Reason", 0) or 0
                try:
                    raw_reason_int = int(raw_reason) & 0xFFFFFFFF
                except Exception:  # noqa: BLE001 — defensive boundary
                    raw_reason_int = 0
                reason_flags = decode_reason_flags(raw_reason_int)

                usn_value = _safe_attr(record, "Usn", None)
                try:
                    usn_int = int(usn_value) if usn_value is not None else None
                except Exception:  # noqa: BLE001 — defensive boundary
                    usn_int = None

                file_ref = _safe_segment_reference(
                    _safe_attr(record, "FileReferenceNumber", None)
                )
                parent_ref = _safe_segment_reference(
                    _safe_attr(record, "ParentFileReferenceNumber", None)
                )

                filename = _safe_filename(record)
                timestamp = _safe_timestamp(record)

                raw_source = _safe_attr(record, "SourceInfo", 0) or 0
                try:
                    source_info_int = int(raw_source) & 0xFFFFFFFF
                except Exception:  # noqa: BLE001 — defensive boundary
                    source_info_int = 0

                raw_security = _safe_attr(record, "SecurityId", 0) or 0
                try:
                    security_id_int = int(raw_security) & 0xFFFFFFFF
                except Exception:  # noqa: BLE001 — defensive boundary
                    security_id_int = 0

                schema_version_int = 2
                try:
                    schema_version_int = int(
                        _safe_attr(record, "MajorVersion", 2) or 2
                    )
                except Exception:  # noqa: BLE001 — defensive boundary
                    pass

                # Cross-record classifiers — bookkeeping only; the
                # finding emit fires in κ.E.D.
                if (
                    parent_ref is not None
                    and filename is not None
                    and (
                        reason_flags["file_create"]
                        or reason_flags["file_delete"]
                    )
                ):
                    key = (parent_ref, filename.lower())
                    bucket = create_delete_buckets.setdefault(key, [])
                    bucket.append((reason_flags, timestamp))

                if reason_flags["rename_old_name"]:
                    pending_rename_old = (
                        parent_ref or 0,
                        filename or "",
                        timestamp,
                    )
                elif reason_flags["rename_new_name"] and pending_rename_old:
                    old_parent, old_name, _old_ts = pending_rename_old
                    if (
                        old_parent == (parent_ref or 0)
                        and extension_changed(old_name, filename)
                    ):
                        aggregate["renamed_executable_count"] += 1
                    pending_rename_old = None

                # Per-record classifier: file_deletion on exe-extension.
                if (
                    reason_flags["file_delete"]
                    and has_executable_extension(filename)
                ):
                    aggregate["file_deletion_count"] += 1

                if persist_budget <= 0:
                    # Continue iterating for aggregate counters but stop
                    # persisting rows.
                    continue

                truncated_filename = (
                    filename[:512] if filename else None
                )

                stamped_reason = _stamp_windows_usnjrnl_reason_flags(
                    dict(reason_flags)
                )

                row = WindowsUsnJrnlEntry(
                    firmware_id=firmware_id,
                    source_file_path=relative_source[:1024],
                    usn=usn_int,
                    file_reference_number=file_ref,
                    parent_file_reference_number=parent_ref,
                    file_name=truncated_filename,
                    reason_flags=stamped_reason,
                    source_info=source_info_int,
                    security_id=security_id_int,
                    timestamp=timestamp,
                    schema_version=schema_version_int,
                )
                rows.append(row)
                persist_budget -= 1
                aggregate["records_persisted"] += 1

            # Post-iteration: count cross-record CREATE+DELETE pairs that
            # fall within the temporal window AND have a temp-path parent.
            # We need the parent's path — best-effort lookup against the
            # MFT for the parent segment.
            for (parent_ref, filename_lower), bucket in (
                create_delete_buckets.items()
            ):
                if len(bucket) < 2:
                    continue
                has_create = any(
                    flags["file_create"] for flags, _ in bucket
                )
                has_delete = any(
                    flags["file_delete"] for flags, _ in bucket
                )
                if not (has_create and has_delete):
                    continue

                # Find the earliest CREATE + latest DELETE; check window.
                create_times = [
                    ts for flags, ts in bucket
                    if flags["file_create"] and ts is not None
                ]
                delete_times = [
                    ts for flags, ts in bucket
                    if flags["file_delete"] and ts is not None
                ]
                if not (create_times and delete_times):
                    # Missing timestamps — count anyway since both
                    # events are present for the same file.
                    pass
                else:
                    delta = abs(
                        (max(delete_times) - min(create_times)).total_seconds()
                    )
                    if delta > _CREATE_DELETE_WINDOW_SECONDS:
                        continue

                # Check the parent directory looks like a temp path.
                parent_path = _resolve_parent_path(fs, parent_ref)
                if not looks_like_temp_path(parent_path):
                    continue

                aggregate["temp_create_delete_pair_count"] += 1
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        aggregate["status"] = "error"
        aggregate["error"] = f"{type(exc).__name__}: {msg}"
        return rows, aggregate

    return rows, aggregate


def _resolve_parent_path(fs: Any, parent_ref: int | None) -> str | None:
    """Return the parent directory's full path via the MFT, defensively."""
    if parent_ref is None:
        return None
    try:
        record = fs.mft(parent_ref)
        if record is None:
            return None
        return record.full_path()
    except Exception:  # noqa: BLE001 — defensive boundary
        return None


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "images_scanned": 0,
        "records_walked": 0,
        "records_persisted": 0,
        "records_capped": 0,
        "parse_errors": 0,
        "file_deletion_count": 0,
        "temp_create_delete_pair_count": 0,
        "renamed_executable_count": 0,
        "anomaly_total": 0,
        "errors": [],
        "per_image": [],
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


async def _walk_raw_ntfs_images_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_raw_ntfs_images` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_raw_ntfs_images, roots)


async def _walk_one_image_async(
    image_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_records: int,
    started_count: int,
) -> tuple[list[WindowsUsnJrnlEntry], dict]:
    """Async wrapper around :func:`_walk_one_image` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_image(
            image_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
            max_records=max_records,
            started_count=started_count,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ──────────────────────────


async def _do_usnjrnl_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_records: int = _DEFAULT_MAX_RECORDS_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every $UsnJrnl:$J on raw NTFS images under ``firmware_id``'s
    detection roots, decode reason flags, classify anomalies, persist
    per-record rows.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for raw NTFS image candidates.
    3. For each candidate: NTFS magic check, open via dissect.ntfs, locate
       $UsnJrnl:$J ADS, iterate records, decode reason flags, persist
       rows + classifier bookkeeping.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) drive the FULL walk against a real test DB
    without DNS resolution issues from ``async_session_factory()``.
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

    image_paths = await _walk_raw_ntfs_images_async(roots)
    if not image_paths:
        return _empty_walk_result(time.monotonic() - started)

    images_scanned = 0
    records_walked = 0
    records_persisted = 0
    records_capped = 0
    parse_errors = 0
    file_deletion_count = 0
    temp_create_delete_pair_count = 0
    renamed_executable_count = 0
    errors: list[str] = []
    per_image: list[dict] = []

    for image_path in image_paths:
        relative = _relativize_path(image_path, roots)
        try:
            rows, agg = await _walk_one_image_async(
                image_path,
                firmware_id=firmware_id,
                relative_source=relative,
                max_records=max_records,
                started_count=records_persisted,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = (
                f"walk failed for {image_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_image.append({
                "path": relative,
                "status": "error",
                "records_walked": 0,
                "records_persisted": 0,
                "file_deletion_count": 0,
                "temp_create_delete_pair_count": 0,
                "renamed_executable_count": 0,
                "parse_errors": 0,
                "error": err,
            })
            continue

        images_scanned += 1
        records_walked += agg["records_walked"]
        records_persisted += agg["records_persisted"]
        file_deletion_count += agg["file_deletion_count"]
        temp_create_delete_pair_count += agg["temp_create_delete_pair_count"]
        renamed_executable_count += agg["renamed_executable_count"]
        parse_errors += agg["parse_errors"]
        records_capped += max(
            0, agg["records_walked"] - agg["records_persisted"]
        )
        per_image.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

        for row in rows:
            db.add(row)
        if rows:
            await db.flush()

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "images_scanned": images_scanned,
        "records_walked": records_walked,
        "records_persisted": records_persisted,
        "records_capped": records_capped,
        "parse_errors": parse_errors,
        "file_deletion_count": file_deletion_count,
        "temp_create_delete_pair_count": temp_create_delete_pair_count,
        "renamed_executable_count": renamed_executable_count,
        "anomaly_total": (
            file_deletion_count
            + temp_create_delete_pair_count
            + renamed_executable_count
        ),
        "errors": errors,
        "per_image": per_image,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_usnjrnl_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the $UsnJrnl:$J walk.

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
                    "usnjrnl_walk: firmware %s not found", firmware_id
                )
                return

            row.usnjrnl_walk_status = "running"
            row.usnjrnl_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_usnjrnl_walk(db, firmware_id)
                row.usnjrnl_walk_status = "completed"
                row.usnjrnl_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.usnjrnl_walk_result = (
                    _stamp_firmware_usnjrnl_walk_result(result)
                )
                await db.commit()

                logger.info(
                    "usnjrnl_walk: firmware %s completed in %.2fs "
                    "(%d images, %d records walked, %d persisted, "
                    "%d anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["images_scanned"],
                    result["records_walked"],
                    result["records_persisted"],
                    result["anomaly_total"],
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
                        fail_row.usnjrnl_walk_status = "failed"
                        fail_row.usnjrnl_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.usnjrnl_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "usnjrnl_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "usnjrnl_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ─────────────────────────────────────────────────


async def auto_usnjrnl_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point — runs the inner orchestrator but
    does NOT mutate ``usnjrnl_walk_status`` so a manual re-trigger via
    the trigger MCP tool still works without 409 conflict.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_usnjrnl_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.usnjrnl_walk_result = (
                    _stamp_firmware_usnjrnl_walk_result(result)
                )
                await db.commit()

            logger.info(
                "usnjrnl_walk auto: firmware %s walked %d images / "
                "%d records in %.2fs",
                firmware_id,
                result["images_scanned"],
                result["records_walked"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "usnjrnl_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "DISSECT_NTFS_UNAVAILABLE",
    "USN_REASON_FILE_CREATE",
    "USN_REASON_FILE_DELETE",
    "USN_REASON_RENAME_NEW_NAME",
    "USN_REASON_RENAME_OLD_NAME",
    "_do_usnjrnl_walk",
    "auto_usnjrnl_walk_firmware_safe",
    "decode_reason_flags",
    "extension_changed",
    "has_executable_extension",
    "is_dissect_ntfs_available",
    "looks_like_ntfs",
    "looks_like_temp_path",
    "run_usnjrnl_walk_background",
    "walk_raw_ntfs_images",
]
