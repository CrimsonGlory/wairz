"""Phase η.A — Windows NTFS $MFT walker.

Reads raw NTFS images (``.dd`` / ``.raw`` / ``.ntfs`` candidates under
each detection root) extracted from firmware captures (typically VHDX
images converted to raw via the α.2.7 qemu-img pipeline, or raw
partitions surfaced via β.7) and walks the Master File Table via
``dissect.ntfs.NTFS(fh).mft.segments()`` to surface persistence-,
hidden-content-, and anti-forensics-candidate metadata as
``WindowsMftRecord`` rows for downstream finding-emit hooks (η.A.D).

**Rule #39 inner/outer/safe runner triplet** (γ.4 + δ.5 + ε.1.b.3 +
ζ.2.B + ζ.3.B + η.B.C + η.C.C + η.A.C = Rule-of-Eight):

- :func:`_do_mft_run` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every raw NTFS image candidate under detection
  roots, opens each via ``with open(path, "rb") as fh: NTFS(fh)``,
  iterates ``fs.mft.segments()`` for both allocated + deleted-but-
  unreaped records, persists per-record ``WindowsMftRecord`` rows,
  returns aggregate dict UNSTAMPED.
- :func:`run_mft_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer
  guard catches escapes; failure persistence on a fresh session.
- :func:`auto_mft_walk_firmware_safe` — UNPACK-POST-DETECTION hook.
  Runs the inner orchestrator but does NOT mutate
  ``mft_walk_status`` (leaves ``idle`` so manual re-trigger works
  without 409).

**Rule #36 no-execute discipline.** ``dissect.ntfs`` is a pure-Python
parser that decodes NTFS structures (boot sector, $MFT, $LogFile,
$Bitmap, attribute records, runlists) AS DATA. The walker NEVER:

- Mounts the raw image via ``ntfs-3g`` / ``mount`` / ``losetup`` /
  ``qemu-system``.
- Reads attacker-controlled $DATA primary stream content beyond
  the file-size header (file_size is metadata; we don't open
  the stream).
- Reads named ADS stream CONTENT — we only enumerate the per-record
  ADS roster (name + size). A future η.A.X "ADS sample" extension
  could read up to N bytes for evidence trails but is not done here.
- Executes any binary on the parsed volume.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare
``firmware.extracted_path``) so scatter-zip / multi-archive Windows
extracts surface their raw NTFS image candidates.

**Rule #19 evidence-first probe.** :func:`is_dissect_ntfs_available`
exposes a graceful-degrade probe so consumers can surface a clear
"library not installed" message rather than an opaque ImportError.
The library is in pyproject.toml; the probe protects against
container-level dep skew (e.g. when the worker image is rebuilt
LATER than the backend, briefly producing a window where the dep
isn't resolvable). Mirrors the LnkParse3 / regipy / python-evtx
/ windowsprefetch probes used by ε.1.b / ζ.2.B / η.B.C / η.C.C.

**Performance**. dissect.ntfs is pure-Python and cold-imports in
~150 ms on the dev box. A modern Win10 install has ~150k MFT
segments — iteration runs ~2s/100k segments on the host venv.
Total wall-time per image is dominated by segment count, not
detection-root depth. We cap at 5000 persisted rows per firmware
(``_DEFAULT_MAX_RECORDS_PER_FIRMWARE``) for the same reason the LNK
walker caps at 5000 LNKs: defensive against attacker-planted
artifacts that would inflate the DB row count without forensic value.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable, Iterator
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_mft_record import WindowsMftRecord
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_mft_walk_result,
    _stamp_windows_mft_records_ads_streams,
    _stamp_windows_mft_records_target_metadata,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum MFT records persisted per firmware. A healthy Win10 install
# has ~150k segments; for forensic triage we don't need to persist
# every single one — operators want the records that matter
# (ADS-bearing / timestomp-candidates / specific filename matches).
# Cap at 5000 — same envelope as η.C's LNK cap. Operators wanting
# more re-walk via the MCP tool against a specific image.
_DEFAULT_MAX_RECORDS_PER_FIRMWARE: int = 5000

# Cap on raw NTFS image size to attempt. A whole-disk image can exceed
# 100 GB which would take minutes to walk; the cap protects the
# in-process synchronous walker from runaway. Operators wanting
# whole-disk walks can re-walk specific images via the MCP tool;
# defaults to 16 GB so single-partition images of typical Windows
# installs (40-60 GB) which we'd typically convert to raw are
# excluded — but partition-stripped NTFS images and forensic-target
# subsets fit comfortably. Configurable via ``max_image_bytes``
# kwarg on :func:`_do_mft_run` for explicit operator overrides.
_DEFAULT_MAX_IMAGE_BYTES: int = 16 * 1024 * 1024 * 1024  # 16 GiB

# Cap on named ADS streams to persist per record. Real-world records
# have 0-1 streams (Zone.Identifier on MOTW-tagged downloads); a
# pathological file with 50+ ADS is either an attacker-DoS artifact
# or a forensic curiosity that already implicates the file.
_DEFAULT_MAX_ADS_PER_RECORD: int = 50

# Threshold below which we consider an ADS stream a benign tag (NOT a
# hidden-content candidate). Zone.Identifier carries ~100 bytes of
# "URL came from Internet Zone" metadata; anything larger than this
# starts looking like a payload. The η.A.D classifier branches on
# this threshold to suppress LOW-noise tag emits.
_ADS_BENIGN_TAG_SIZE: int = 1024  # 1 KB

# Filename extensions / suffixes that mark a candidate raw NTFS
# image. The walker scans each detection root for files matching
# these patterns and attempts a magic-check via the NTFS boot sector
# signature.
_RAW_IMAGE_EXTENSIONS: tuple[str, ...] = (
    ".dd",
    ".raw",
    ".ntfs",
    ".img",
    ".bin",
)


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_dissect_ntfs_available() -> bool:
    """Return True iff ``dissect.ntfs`` is importable in this process.

    Mirrors the regipy / python-evtx / windowsprefetch / LnkParse3
    graceful-degrade probes used by γ.4 / ε.1.b / ζ.2.B / η.B.C / η.C.C.
    Probe runs in <1 ms after first call (Python's import cache).
    """
    try:
        import dissect.ntfs  # noqa: F401 — import-only probe
    except ImportError:
        return False
    return True


DISSECT_NTFS_UNAVAILABLE: dict[str, Any] = {
    "status": "unavailable",
    "reason": "dissect.ntfs not installed — see backend/pyproject.toml",
    "records": 0,
}


# ── Image candidate enumeration ──────────────────────────────────────────────


def walk_raw_ntfs_images(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return candidate raw NTFS image
    paths.

    Selects files whose basename matches any of ``_RAW_IMAGE_EXTENSIONS``
    (case-insensitive). The magic-check (first 4 bytes ``'NTFS'`` at
    sector offset 3) is deferred to the parser; this function only
    enumerates candidates by extension so the I/O is bounded.

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

    Defensive against unreadable files (OSError) → False.
    Cheap — reads only the first 16 bytes.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return False
    # NTFS boot sector: jump (3 bytes) + OEM ID "NTFS    " (8 bytes).
    return len(head) >= 11 and head[3:11] == b"NTFS    "


# ── Record extraction helpers ────────────────────────────────────────────────


def _safe_attribute_value(
    attribute_collection: Any, attr_name: str
) -> Any:
    """Pull ``attr_name`` from an AttributeCollection via its
    __getattr__ proxy. Defensive — returns None on any access error
    (collection empty / attribute missing on the underlying type)."""
    try:
        return getattr(attribute_collection, attr_name, None)
    except Exception:  # noqa: BLE001 — defensive boundary
        return None


def _extract_si_timestamps(record: Any) -> dict[str, int | None]:
    """Pull the $STD_INFO ns-precision timestamps from a MftRecord.

    Returns a dict with the 4 keys (creation / modification / change /
    access); values are None when the attribute is missing or the
    accessor raises.
    """
    try:
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
    except ImportError:
        return {
            "creation_ns": None,
            "modification_ns": None,
            "change_ns": None,
            "access_ns": None,
        }

    try:
        si = record.attributes[ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION]
    except Exception:  # noqa: BLE001 — defensive boundary
        si = None

    if not si:
        return {
            "creation_ns": None,
            "modification_ns": None,
            "change_ns": None,
            "access_ns": None,
        }

    return {
        "creation_ns": _safe_attribute_value(si, "creation_time_ns"),
        "modification_ns": _safe_attribute_value(
            si, "last_modification_time_ns"
        ),
        "change_ns": _safe_attribute_value(si, "last_change_time_ns"),
        "access_ns": _safe_attribute_value(si, "last_access_time_ns"),
    }


def _extract_fn_timestamps(record: Any) -> dict[str, int | None]:
    """Pull the $FILE_NAME ns-precision timestamps from a MftRecord.

    Returns a dict with the 4 keys. NTFS keeps an independent
    timestamp tuple in $FN; the kernel writes them on create/rename
    but NOT on every $SI write. timestomp.exe / SetMACE rewrite $SI
    only → η.A.D detection compares the two tuples.
    """
    try:
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
    except ImportError:
        return {
            "creation_ns": None,
            "modification_ns": None,
            "change_ns": None,
            "access_ns": None,
        }

    try:
        fn = record.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]
    except Exception:  # noqa: BLE001 — defensive boundary
        fn = None

    if not fn:
        return {
            "creation_ns": None,
            "modification_ns": None,
            "change_ns": None,
            "access_ns": None,
        }

    return {
        "creation_ns": _safe_attribute_value(fn, "creation_time_ns"),
        "modification_ns": _safe_attribute_value(
            fn, "last_modification_time_ns"
        ),
        "change_ns": _safe_attribute_value(fn, "last_change_time_ns"),
        "access_ns": _safe_attribute_value(fn, "last_access_time_ns"),
    }


def _extract_data_summary(
    record: Any, max_ads: int = _DEFAULT_MAX_ADS_PER_RECORD
) -> tuple[int | None, list[dict]]:
    """Return ``(primary_file_size, named_ads_streams)`` for a record.

    primary_file_size: the size of the unnamed $DATA stream (the
    "real" file contents). None when no $DATA attribute is present.
    named_ads_streams: list[{"name": str, "size": int, "data_size": int|None}]
    capped at ``max_ads`` entries. Empty list when the record has no
    named ADS streams (the common case).
    """
    try:
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
    except ImportError:
        return None, []

    try:
        data_attrs = record.attributes[ATTRIBUTE_TYPE_CODE.DATA]
    except Exception:  # noqa: BLE001 — defensive boundary
        return None, []

    if not data_attrs:
        return None, []

    primary_size: int | None = None
    ads: list[dict] = []

    for attr in data_attrs:
        try:
            name = attr.header.name or ""
            size_value = getattr(attr.header, "size", 0) or 0
            allocated = getattr(attr.header, "allocated_size", None)
        except Exception:  # noqa: BLE001 — defensive boundary
            continue

        if not name:
            # Primary unnamed $DATA stream — defines the file's size.
            if primary_size is None:
                primary_size = int(size_value)
        else:
            if len(ads) < max_ads:
                ads.append({
                    "name": str(name),
                    "size": int(size_value),
                    "data_size": (
                        int(allocated) if allocated is not None else None
                    ),
                })

    return primary_size, ads


def _safe_full_path(record: Any) -> str | None:
    """Return the volume-local full path for a record, or None on
    orphan / lookup failure.

    record.full_path() can raise on orphaned records (parent segment
    pointer dangling). Defensive — swallow the exception.
    """
    try:
        path = record.full_path()
        if isinstance(path, str) and path:
            return path
    except Exception:  # noqa: BLE001 — defensive boundary
        pass
    return None


def _safe_filename(record: Any) -> str | None:
    """Return the basename of the record, or None on lookup failure."""
    try:
        name = record.filename
        if isinstance(name, str) and name:
            return name
    except Exception:  # noqa: BLE001 — defensive boundary
        pass
    return None


def _safe_is_directory(record: Any) -> bool:
    """Return True iff the record is a directory (defensive boundary)."""
    try:
        return bool(record.is_dir())
    except Exception:  # noqa: BLE001 — defensive boundary
        return False


def _safe_is_reparse_point(record: Any) -> bool:
    """Return True iff the record carries a reparse-point attribute."""
    try:
        return bool(record.is_reparse_point())
    except Exception:  # noqa: BLE001 — defensive boundary
        return False


def _safe_in_use(record: Any) -> bool:
    """Return True iff the FILE_RECORD_SEGMENT_IN_USE flag is set.

    Allocated records pass; deleted-but-unreaped records return False.
    Defensive — returns False on any header-access failure (record is
    a corrupt slot).
    """
    try:
        from dissect.ntfs.c_ntfs import FILE_RECORD_SEGMENT_IN_USE
        flags = int(record.header.Flags)
    except Exception:  # noqa: BLE001 — defensive boundary
        return False
    return bool(flags & FILE_RECORD_SEGMENT_IN_USE)


def _safe_attribute_flags(record: Any) -> int:
    """Return the raw header.Flags value (0 on access failure)."""
    try:
        return int(record.header.Flags)
    except Exception:  # noqa: BLE001 — defensive boundary
        return 0


def _safe_sequence_number(record: Any) -> int | None:
    """Return the header.SequenceNumber, or None on access failure."""
    try:
        return int(record.header.SequenceNumber)
    except Exception:  # noqa: BLE001 — defensive boundary
        return None


def _build_target_metadata(record: Any) -> dict:
    """Construct the target_metadata JSONB payload from a record's
    header fields. Returns a dict ready for the
    ``_stamp_windows_mft_records_target_metadata`` writer."""
    return {
        "reparse_point": _safe_is_reparse_point(record),
        "attribute_flags": _safe_attribute_flags(record),
        "sequence_number": _safe_sequence_number(record),
    }


# ── Per-image walk ───────────────────────────────────────────────────────────


def _iter_segments_safe(fs: Any) -> Iterator[Any]:
    """Iterate ``fs.mft.segments()`` swallowing per-record corruption.

    dissect.ntfs raises ``BrokenMftError`` on malformed segment headers
    and EOF on truncated images; defensive wrapper continues past
    individual bad records.
    """
    try:
        from dissect.ntfs.exceptions import Error
    except ImportError:
        return iter([])

    try:
        iterator = fs.mft.segments()
    except Exception:  # noqa: BLE001 — defensive boundary
        return iter([])

    def _generator() -> Iterator[Any]:
        while True:
            try:
                record = next(iterator)
            except StopIteration:
                return
            except (Error, EOFError):
                continue
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
) -> tuple[list[WindowsMftRecord], dict]:
    """Open one raw NTFS image and walk its MFT.

    Returns ``(records_to_persist, per_image_aggregate)``. The records
    are SQLAlchemy ORM instances ready for ``db.add()``; the aggregate
    summary tells the caller how many records were walked + how many
    were filtered out for the persist cap.

    Defensive boundary:
    - file size > max_image_bytes → status="skipped"
    - file doesn't pass the NTFS magic check → status="not_ntfs"
    - parser raises → status="error" with first 500 chars of error
    """
    aggregate: dict = {
        "path": relative_source,
        "status": "ok",
        "records_walked": 0,
        "records_persisted": 0,
        "ads_streams_seen": 0,
        "timestomp_candidates": 0,
        "ads_hidden_candidates": 0,
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
            f"(attacker-DoS / runaway-walk protection); operator can "
            f"re-walk via MCP tool"
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

    records: list[WindowsMftRecord] = []
    image_segment_count: int | None = None
    persist_budget = max_records - started_count

    try:
        with open(image_path, "rb") as fh:
            fs = NTFS(fh=fh)
            # Cheaply count the total segments for the image-context
            # field. fs.mft._record_count is internal; fall back to
            # iteration count if unavailable.
            try:
                image_segment_count = int(getattr(fs.mft, "_record_count", 0)) or None
            except Exception:  # noqa: BLE001 — defensive boundary
                image_segment_count = None

            for record in _iter_segments_safe(fs):
                aggregate["records_walked"] += 1

                if persist_budget <= 0:
                    # Still iterating for the aggregate counters but
                    # not persisting more rows (5000-per-firmware cap).
                    continue

                # Distinguish file from directory; the η.A.D ADS-hidden
                # and timestomp emits target FILES, not directories,
                # but persist directories too for forensic context.
                in_use = _safe_in_use(record)
                is_directory = _safe_is_directory(record)

                # Skip if not a file AND not a directory AND not a
                # reparse point — empty / unused slot records carry
                # no forensic value.
                if not (is_directory or _safe_is_reparse_point(record)):
                    try:
                        if not record.is_file():
                            continue
                    except Exception:  # noqa: BLE001 — defensive boundary
                        continue

                si = _extract_si_timestamps(record)
                fn = _extract_fn_timestamps(record)
                file_size, ads_streams = _extract_data_summary(record)

                # Update aggregate counters
                aggregate["ads_streams_seen"] += len(ads_streams)
                for stream in ads_streams:
                    if int(stream.get("size") or 0) > _ADS_BENIGN_TAG_SIZE:
                        aggregate["ads_hidden_candidates"] += 1
                if (
                    si["modification_ns"] is not None
                    and fn["modification_ns"] is not None
                    and si["modification_ns"] < fn["modification_ns"]
                ):
                    aggregate["timestomp_candidates"] += 1

                # Build the ORM row
                full_path = _safe_full_path(record)
                filename = _safe_filename(record)
                segment_number = (
                    int(record.segment)
                    if record.segment is not None
                    else aggregate["records_walked"] - 1
                )

                stamped_ads = (
                    _stamp_windows_mft_records_ads_streams(ads_streams)
                    if ads_streams
                    else []
                )
                stamped_meta = _stamp_windows_mft_records_target_metadata(
                    _build_target_metadata(record)
                )

                # Truncate string columns defensively
                truncated_full = (
                    full_path[:4096] if full_path else None
                )
                truncated_filename = (
                    filename[:512] if filename else None
                )

                row = WindowsMftRecord(
                    firmware_id=firmware_id,
                    source_path=relative_source[:2048],
                    segment_number=segment_number,
                    in_use=in_use,
                    is_directory=is_directory,
                    full_path=truncated_full,
                    filename=truncated_filename,
                    file_size=file_size,
                    si_creation_ns=si["creation_ns"],
                    si_last_modification_ns=si["modification_ns"],
                    si_last_change_ns=si["change_ns"],
                    si_last_access_ns=si["access_ns"],
                    fn_creation_ns=fn["creation_ns"],
                    fn_last_modification_ns=fn["modification_ns"],
                    fn_last_change_ns=fn["change_ns"],
                    fn_last_access_ns=fn["access_ns"],
                    ads_streams=stamped_ads,
                    target_metadata=stamped_meta,
                    image_segment_count=image_segment_count,
                )
                records.append(row)
                persist_budget -= 1
                aggregate["records_persisted"] += 1
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        aggregate["status"] = "error"
        aggregate["error"] = f"{type(exc).__name__}: {msg}"
        return records, aggregate

    return records, aggregate


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "images_scanned": 0,
        "records_walked": 0,
        "records_persisted": 0,
        "ads_streams_seen": 0,
        "timestomp_candidates": 0,
        "ads_hidden_candidates": 0,
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
                real_full[len(real_root) + 1 :]
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
) -> tuple[list[WindowsMftRecord], dict]:
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


# ── Inner orchestrator (accepts a db; reusable in tier-1 live canaries) ──────


async def _do_mft_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_records: int = _DEFAULT_MAX_RECORDS_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every raw NTFS image candidate in ``firmware_id``'s
    extracted tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for raw image candidates (``.dd`` / ``.raw`` /
       ``.ntfs`` / ``.img`` / ``.bin``).
    3. For each candidate: pre-flight NTFS magic check, open via
       dissect.ntfs (run_in_executor for Rule #5 sync I/O), iterate
       fs.mft.segments(), construct + bulk-add WindowsMftRecord rows.
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

    image_paths = await _walk_raw_ntfs_images_async(roots)
    if not image_paths:
        return _empty_walk_result(time.monotonic() - started)

    images_scanned = 0
    records_walked = 0
    records_persisted = 0
    ads_streams_seen = 0
    timestomp_candidates = 0
    ads_hidden_candidates = 0
    errors: list[str] = []
    per_image: list[dict] = []

    for image_path in image_paths:
        relative = _relativize_path(image_path, roots)
        try:
            records, agg = await _walk_one_image_async(
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
                "ads_streams_seen": 0,
                "timestomp_candidates": 0,
                "ads_hidden_candidates": 0,
                "error": err,
            })
            continue

        images_scanned += 1
        records_walked += agg["records_walked"]
        records_persisted += agg["records_persisted"]
        ads_streams_seen += agg["ads_streams_seen"]
        timestomp_candidates += agg["timestomp_candidates"]
        ads_hidden_candidates += agg["ads_hidden_candidates"]
        per_image.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

        for row in records:
            db.add(row)
        if records:
            await db.flush()

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "images_scanned": images_scanned,
        "records_walked": records_walked,
        "records_persisted": records_persisted,
        "ads_streams_seen": ads_streams_seen,
        "timestomp_candidates": timestomp_candidates,
        "ads_hidden_candidates": ads_hidden_candidates,
        "errors": errors,
        "per_image": per_image,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_mft_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the MFT walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back. Mirrors the
    γ.4 registry_hive_walker / ε.1.b.3 evtx_service / ζ.2.B
    prefetch_walker / ζ.3.B srum_walker / η.B.C scheduled_task_walker
    / η.C.C lnk_walker shape.

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
                    "mft_walk: firmware %s not found", firmware_id
                )
                return

            row.mft_walk_status = "running"
            row.mft_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_mft_run(db, firmware_id)
                row.mft_walk_status = "completed"
                row.mft_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.mft_walk_result = (
                    _stamp_firmware_mft_walk_result(result)
                )
                await db.commit()
                logger.info(
                    "mft_walk: firmware %s completed in %.2fs (%d "
                    "images, %d records walked, %d persisted, %d ADS, "
                    "%d timestomp, %d ADS-hidden)",
                    firmware_id,
                    result["run_seconds"],
                    result["images_scanned"],
                    result["records_walked"],
                    result["records_persisted"],
                    result["ads_streams_seen"],
                    result["timestomp_candidates"],
                    result["ads_hidden_candidates"],
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
                        fail_row.mft_walk_status = "failed"
                        fail_row.mft_walk_finished_at = _dt.datetime.now(
                            _dt.UTC
                        )
                        fail_row.mft_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "mft_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "mft_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_mft_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as ζ.2.B / ζ.3.B / η.B.C /
    η.C.C auto_walk_firmware_safe.

    Distinct from :func:`run_mft_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-
    triggered walks. The auto-walk-on-unpack flow runs the SAME
    orchestrator (``_do_mft_run``) but DOES NOT transition the
    status column — it stays ``idle`` until an operator explicitly
    triggers a re-walk via the trigger MCP tool, which resets and
    runs again.

    Wired into FindingService.emit_mft_findings_from_walk in η.A.E so
    that auto-walks produce both the per-record landing zone rows AND
    the persistence Finding rows in a single pass.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_mft_run(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.mft_walk_result = _stamp_firmware_mft_walk_result(
                    result
                )
                await db.commit()
            logger.info(
                "mft_walk auto: firmware %s walked %d images / %d "
                "records in %.2fs",
                firmware_id,
                result["images_scanned"],
                result["records_walked"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "mft_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "DISSECT_NTFS_UNAVAILABLE",
    "_do_mft_run",
    "auto_mft_walk_firmware_safe",
    "is_dissect_ntfs_available",
    "looks_like_ntfs",
    "run_mft_walk_background",
    "walk_raw_ntfs_images",
]
