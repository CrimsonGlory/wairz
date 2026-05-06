from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import stat as _stat
import time
import uuid
from collections import deque
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.services.firmware_paths import get_detection_roots
from app.services.hardware_firmware.classifier import classify
from app.services.hardware_firmware.parsers import ParsedBlob, get_parser
from app.services.jsonb_normalizers import (
    _normalize_firmware_device_metadata,
    _stamp_firmware_device_metadata,
)

logger = logging.getLogger(__name__)

_MIN_FILE_SIZE = 512
_MAX_FILE_SIZE = 128 * 1024 * 1024  # 128 MB
_MAX_CANDIDATES = 10_000
_MAGIC_READ_BYTES = 64
_HASH_CHUNK = 1 * 1024 * 1024
_SLOW_WALK_SECONDS = 45
_DETECTION_SOURCE = "phase1_classifier"


def _detect_partition(extracted_path: str, blob_path: str) -> str | None:
    """Return the top-level directory under extracted_path, or None."""
    try:
        rel = os.path.relpath(blob_path, extracted_path)
    except ValueError:
        return None
    if rel.startswith(".."):
        return None
    parts = rel.split(os.sep, 1)
    if not parts or not parts[0] or parts[0] == ".":
        return None
    top = parts[0]
    # Only return top-level partition-shaped names; ignore files directly at root.
    if len(parts) < 2:
        return None
    return top


def _read_magic_and_hash(path: str, size: int) -> tuple[bytes, str] | None:
    """Open with O_NOFOLLOW, read magic bytes, stream sha256; None on error."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except (OSError, PermissionError):
        # Fallback: realpath guard + normal open (should rarely hit)
        try:
            real = os.path.realpath(path)
            if os.path.islink(path) or real != os.path.abspath(path):
                return None
            fd = os.open(real, os.O_RDONLY)
        except (OSError, PermissionError):
            return None
    try:
        with os.fdopen(fd, "rb", closefd=True) as f:
            magic = f.read(_MAGIC_READ_BYTES)
            hasher = hashlib.sha256()
            hasher.update(magic)
            remaining = size - len(magic)
            while remaining > 0:
                chunk = f.read(min(_HASH_CHUNK, remaining))
                if not chunk:
                    break
                hasher.update(chunk)
                remaining -= len(chunk)
            return magic, hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def _walk_and_classify(extracted_path: str) -> list[dict]:
    """Walk the extracted tree, classify candidates, return row dicts."""
    rows: list[dict] = []
    if not extracted_path or not os.path.isdir(extracted_path):
        return rows

    candidates_seen = 0
    queue: deque[str] = deque([extracted_path])
    capped = False
    start = time.monotonic()

    while queue and not capped:
        dir_path = queue.popleft()
        try:
            it = os.scandir(dir_path)
        except (OSError, PermissionError):
            continue
        with it:
            for entry in it:
                try:
                    if entry.is_symlink():
                        continue
                    # Skip sockets / fifos / block / char devices
                    try:
                        mode = entry.stat(follow_symlinks=False).st_mode
                    except (OSError, PermissionError):
                        continue
                    if _stat.S_ISDIR(mode):
                        queue.append(entry.path)
                        continue
                    if not _stat.S_ISREG(mode):
                        continue

                    size = entry.stat(follow_symlinks=False).st_size
                    if size < _MIN_FILE_SIZE or size > _MAX_FILE_SIZE:
                        continue

                    candidates_seen += 1
                    if candidates_seen > _MAX_CANDIDATES:
                        capped = True
                        break

                    read = _read_magic_and_hash(entry.path, size)
                    if read is None:
                        continue
                    magic, sha256 = read

                    cls = classify(entry.path, magic, size)
                    if cls is None:
                        continue

                    # Invoke per-format parser (sync I/O is fine — we're
                    # already in run_in_executor).  Parsers must never
                    # raise; catch defensively in case one does.
                    parser = get_parser(cls.format)
                    parsed: ParsedBlob
                    if parser is None:
                        parsed = ParsedBlob()
                    else:
                        try:
                            parsed = parser.parse(entry.path, magic, size)
                        except Exception:  # noqa: BLE001
                            logger.debug(
                                "Parser %s raised on %s",
                                cls.format,
                                entry.path,
                                exc_info=True,
                            )
                            parsed = ParsedBlob(metadata={"error": "parser raised"})

                    partition = _detect_partition(extracted_path, entry.path)
                    rows.append({
                        "blob_path": entry.path,
                        "partition": partition,
                        "blob_sha256": sha256,
                        "file_size": size,
                        "category": cls.category,
                        "vendor": cls.vendor if cls.vendor != "unknown" else None,
                        "format": cls.format,
                        "detection_source": _DETECTION_SOURCE,
                        "detection_confidence": cls.confidence,
                        "version": parsed.version,
                        "signed": parsed.signed,
                        "signature_algorithm": parsed.signature_algorithm,
                        "cert_subject": parsed.cert_subject,
                        "chipset_target": parsed.chipset_target,
                        "metadata": parsed.metadata or {},
                    })
                except (OSError, PermissionError):
                    continue

    elapsed = time.monotonic() - start
    if capped:
        logger.warning(
            "Hardware firmware detector: candidate cap reached (%d), walk truncated",
            _MAX_CANDIDATES,
        )
    if elapsed > _SLOW_WALK_SECONDS:
        logger.warning(
            "Hardware firmware detector: slow walk (%.1fs, %d candidates, %d classified)",
            elapsed,
            candidates_seen,
            len(rows),
        )
    else:
        logger.info(
            "Hardware firmware detector: walk done in %.1fs (%d candidates, %d classified)",
            elapsed,
            candidates_seen,
            len(rows),
        )
    return rows


async def detect_hardware_firmware(
    firmware_id: uuid.UUID,
    db: AsyncSession,
    *,
    walk_roots: list[str] | None = None,
) -> int:
    """Walk extracted firmware, classify candidate blobs, persist rows; return count.

    Parameters
    ----------
    firmware_id:
        The Firmware row to attribute blobs to.
    db:
        Active async session; caller owns the transaction.
    walk_roots:
        Optional explicit list of detection-root directories to walk. When
        ``None``, the firmware row is fetched and
        ``app.services.firmware_paths.get_detection_roots`` resolves the
        roots (honoring the JSONB cache and walking scatter siblings /
        partition containers). Providing ``walk_roots`` is useful for
        tests and backfill scripts that want explicit control.

    Multi-root walks dedupe across roots via the existing
    ``uq_hwfw_firmware_sha256`` unique constraint
    ``(firmware_id, blob_sha256)`` — identical blobs in two partition
    dirs collapse to one row.
    """
    # Track whether the caller supplied walk_roots explicitly — backfill and
    # test paths pass them in; live detection leaves them None. Used below to
    # decide whether to stamp the Phase 5 observability audit.
    walk_roots_supplied = walk_roots is not None

    # Resolve walk_roots from the Firmware row when not supplied.
    if walk_roots is None:
        result = await db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
        firmware = result.scalar_one_or_none()
        if firmware is None:
            logger.warning(
                "Hardware firmware detector: firmware_id=%s not found",
                firmware_id,
            )
            return 0
        walk_roots = await get_detection_roots(firmware, db=db)

    # Filter to only existing directories (defensive — cache staleness).
    # ``os.path.isdir`` is a blocking stat(); offload to a thread so we
    # don't stall the event loop on network-backed filesystems.
    def _existing_dirs(paths: list[str]) -> list[str]:
        return [p for p in paths if p and os.path.isdir(p)]

    walk_roots = await asyncio.to_thread(_existing_dirs, walk_roots or [])
    if not walk_roots:
        logger.info(
            "Hardware firmware detector: no detection roots for firmware_id=%s",
            firmware_id,
        )
        await _stamp_detection_audit(
            db, firmware_id, walk_roots=[], count=0,
            supplied=walk_roots_supplied,
        )
        return 0

    logger.info(
        "Hardware firmware detector: walking %d root(s) for firmware_id=%s",
        len(walk_roots),
        firmware_id,
    )

    loop = asyncio.get_event_loop()
    rows: list[dict] = []
    # Sequential walk per root — sharing an AsyncSession across gather'd
    # coroutines is forbidden (CLAUDE.md rule 7). The per-root work itself
    # is pure sync I/O in a thread executor.
    for root in walk_roots:
        root_rows = await loop.run_in_executor(None, _walk_and_classify, root)
        logger.info(
            "Hardware firmware detector: root=%s yielded %d candidate(s)",
            root,
            len(root_rows),
        )
        rows.extend(root_rows)

    if not rows:
        logger.info("Hardware firmware detector: no candidates classified")
        await _stamp_detection_audit(
            db, firmware_id, walk_roots=walk_roots, count=0,
            supplied=walk_roots_supplied,
        )
        return 0

    # In-memory dedupe across roots by SHA-256 (belt-and-braces; the DB
    # unique constraint would reject dupes anyway, but this keeps the
    # values list lean for large multi-partition containers).
    seen_sha: set[str] = set()
    values: list[dict] = []
    for row in rows:
        sha = row["blob_sha256"]
        if sha in seen_sha:
            continue
        seen_sha.add(sha)
        version = row.get("version")
        sig_algo = row.get("signature_algorithm")
        chipset = row.get("chipset_target")
        values.append({
            "firmware_id": firmware_id,
            "blob_path": row["blob_path"][:1024],
            "partition": row["partition"][:64] if row["partition"] else None,
            "blob_sha256": sha,
            "file_size": row["file_size"],
            "category": row["category"],
            "vendor": row["vendor"],
            "format": row["format"],
            "detection_source": row["detection_source"],
            "detection_confidence": row["detection_confidence"],
            "version": version[:128] if version else None,
            "signed": row.get("signed") or "unknown",
            "signature_algorithm": sig_algo[:64] if sig_algo else None,
            "cert_subject": row.get("cert_subject"),
            "chipset_target": chipset[:64] if chipset else None,
            # ORM attribute is metadata_; DB column is "metadata".
            # postgresql.insert(<MappedClass>).values() resolves attribute
            # names, not column names — use "metadata_" or it collides with
            # Base.metadata (MetaData object) and raises AttributeError.
            "metadata_": row.get("metadata") or {},
        })

    # Chunk bulk insert — asyncpg caps bind parameters at 32767 per statement.
    # Keep comfortably under the limit (16 columns × 1000 rows = 16K params).
    _CHUNK_ROWS = 1000
    for i in range(0, len(values), _CHUNK_ROWS):
        chunk = values[i:i + _CHUNK_ROWS]
        stmt = insert(HardwareFirmwareBlob).values(chunk)
        # Unique per (firmware_id, blob_sha256) — idempotent upsert.
        stmt = stmt.on_conflict_do_nothing(constraint="uq_hwfw_firmware_sha256")
        await db.execute(stmt)
    await db.flush()

    logger.info(
        "Hardware firmware detector: persisted %d blob row(s) for firmware_id=%s",
        len(values),
        firmware_id,
    )

    # Phase 5 observability: stamp a detection audit on the firmware row so
    # we can surface orphan-rate regressions without re-walking disk.
    await _stamp_detection_audit(
        db, firmware_id, walk_roots=walk_roots, count=len(values),
        supplied=walk_roots_supplied,
    )

    return len(values)


# ---------------------------------------------------------------------------
# Phase 5 observability helper
# ---------------------------------------------------------------------------

_AUDIT_FILE_CAP = 50_000


def _count_files_on_disk(walk_roots: list[str]) -> int:
    """Sync best-effort file count across ``walk_roots``.

    Bails past ``_AUDIT_FILE_CAP`` so a huge tree doesn't dominate the
    post-detection wall-clock. Kept sync so it can run in the thread
    executor; see ``_stamp_detection_audit`` for the async wrapper.
    """
    total = 0
    for root in walk_roots:
        try:
            for _dirpath, _dirnames, filenames in os.walk(root):
                total += len(filenames)
                if total > _AUDIT_FILE_CAP:
                    return total
        except OSError:
            continue
    return total


async def _stamp_detection_audit(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    walk_roots: list[str],
    count: int,
    supplied: bool,
) -> None:
    """Write ``device_metadata['detection_audit']`` for Phase 5 observability.

    Runs on every live detection AND every explicit-walk (test / backfill)
    invocation. The backfill script additionally stamps
    ``last_backfill_at`` + ``orphans_pre_backfill`` — both paths coexist.

    Failures here are swallowed — observability must never break detection.
    """
    try:
        file_total = await asyncio.to_thread(_count_files_on_disk, walk_roots)
        orphan_ratio = (
            round((file_total - count) / file_total, 3) if file_total else 0.0
        )
        audit_update = {
            "roots_count": len(walk_roots),
            "blobs_detected": count,
            "files_on_disk": file_total,
            "orphan_ratio": orphan_ratio,
            "last_detection_at": datetime.now(UTC).isoformat(),
            "walk_source": "explicit" if supplied else "resolver",
        }
        fw_row = await db.get(Firmware, firmware_id)
        if fw_row is None:
            return
        existing = dict(_normalize_firmware_device_metadata(fw_row.device_metadata))
        merged_audit = dict(existing.get("detection_audit") or {})
        merged_audit.update(audit_update)
        existing["detection_audit"] = merged_audit
        fw_row.device_metadata = _stamp_firmware_device_metadata(existing)
        await db.flush()
    except Exception:  # noqa: BLE001
        logger.exception("detection_audit stamp failed")
