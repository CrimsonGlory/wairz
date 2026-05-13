import asyncio
import hashlib
import logging
import os
import re
import shutil
import tarfile
import traceback
import uuid
import zipfile
from datetime import UTC, datetime

import aiofiles
from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import async_session_factory
from app.models.firmware import Firmware
from app.services.firmware_paths import populate_detection_roots
from app.services.format_detection import (
    DetectedFormat,
    detect_format,
)
from app.services.jsonb_normalizers import _stamp_firmware_device_metadata
from app.workers.safe_extract import safe_extract_zip
from app.workers.unpack import (
    _run_hardware_firmware_detection_safe,
    detect_architecture,
    detect_kernel,
    detect_os_info,
    find_filesystem_root,
)
from app.workers.unpack_common import (
    _recursive_extract_nested,
    diagnose_failed_archives,
    widen_read_perms,
)
from app.workers.unpack_linux import _firmware_tar_filter

logger = logging.getLogger(__name__)


def _rmtree_if_isdir_sync(path: str) -> None:
    """Synchronous helper: isdir + rmtree in one hop.

    Combines two blocking filesystem calls so a single executor hop covers
    both (Rule #5 minimum-hop discipline). ignore_errors mirrors the
    pre-existing rmtree call semantics.
    """
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)


def _sanitize_filename(name: str) -> str:
    """Sanitize a user-supplied filename to prevent path traversal and OS issues.

    Strips directory components, replaces unsafe characters, and limits length.
    """
    # Take only the basename (strip any path components / traversal)
    name = os.path.basename(name)
    # Replace anything that isn't alphanumeric, dot, hyphen, or underscore
    name = re.sub(r"[^\w.\-]", "_", name)
    # Collapse consecutive underscores
    name = re.sub(r"__+", "_", name)
    # Strip leading dots (no hidden files / no "..") and leading underscores
    name = name.lstrip("._")
    # Limit to 200 chars to stay within filesystem limits
    name = name[:200]
    return name or "firmware.bin"


def _zip_contains_rootfs(zip_path: str) -> bool:
    """Check if a ZIP archive contains a Linux root filesystem.

    Looks for standard Linux top-level directories (etc/, usr/, bin/, lib/,
    sbin/) either at the archive root or one level deep (when the ZIP has a
    single wrapper directory).  If 3+ of these markers are found, we treat
    the ZIP as a rootfs archive.
    """
    rootfs_markers = {"etc", "usr", "bin", "lib", "sbin"}

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = [
            info.filename for info in zf.infolist()
            if not info.filename.startswith(".")
            and not info.filename.startswith("__")
        ]

        # Collect top-level directory names
        top_level_dirs: set[str] = set()
        for name in names:
            parts = name.strip("/").split("/")
            if len(parts) >= 1:
                top_level_dirs.add(parts[0])

        # Case 1: rootfs directories directly at the archive root
        if len(rootfs_markers & top_level_dirs) >= 3:
            return True

        # Case 2: single wrapper directory containing rootfs directories
        #   e.g., rootfs/etc/, rootfs/usr/, rootfs/bin/
        if len(top_level_dirs) == 1:
            wrapper = next(iter(top_level_dirs))
            second_level_dirs: set[str] = set()
            for name in names:
                parts = name.strip("/").split("/")
                if len(parts) >= 2 and parts[0] == wrapper:
                    second_level_dirs.add(parts[1])
            if len(rootfs_markers & second_level_dirs) >= 3:
                return True

    return False


def _is_android_firmware_zip(zip_path: str) -> bool:
    """Check if a ZIP archive contains Android firmware.

    Detects Android OTA/factory ZIPs by looking for payload.bin (A/B OTA),
    META-INF Android updater files, or 2+ known Android partition images.
    When detected, the ZIP is kept intact so classify_firmware() returns
    "android_ota" and _extract_android_ota() handles full extraction.
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = {os.path.basename(n) if "/" not in n else n for n in zf.namelist()}
        basenames = {os.path.basename(n) for n in zf.namelist()}

        if "payload.bin" in basenames:
            return True

        android_meta = {
            "META-INF/com/google/android/updater-script",
            "META-INF/com/google/android/update-binary",
            "META-INF/com/android/metadata",
        }
        if names & android_meta:
            return True

        android_partitions = {
            "system.img", "boot.img", "vendor.img", "super.img",
            "recovery.img", "vbmeta.img", "dtbo.img", "product.img",
            "system_ext.img", "odm.img",
        }
        if len(basenames & android_partitions) >= 2:
            return True

    return False


def _extract_firmware_from_zip(zip_path: str, output_dir: str) -> str | None:
    """Extract all files from a ZIP archive, returning the primary firmware path.

    Extracts the full contents of the ZIP into a 'zip_contents' subdirectory
    (preserving internal directory structure) so that all companion files
    (FPGA bitstreams, adapter firmware, manifests, config data) are retained
    for browsing and analysis.

    The largest file is identified as the primary firmware image and its path
    is returned for the analysis pipeline.  Returns None if the archive
    contains no extractable files.
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        candidates = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            basename = os.path.basename(info.filename)
            # Skip hidden files, macOS resource forks, etc.
            if not basename or basename.startswith(".") or basename.startswith("__"):
                continue
            candidates.append(info)

        if not candidates:
            return None

        # Create a subdirectory for the full ZIP contents
        extract_dir = os.path.join(output_dir, "zip_contents")
        os.makedirs(extract_dir, exist_ok=True)
        real_extract_dir = os.path.realpath(extract_dir)

        # Extract all files with ZIP slip prevention
        for info in zf.infolist():
            target_path = os.path.realpath(
                os.path.join(extract_dir, info.filename)
            )
            if not (
                target_path.startswith(real_extract_dir + os.sep)
                or target_path == real_extract_dir
            ):
                # Path traversal attempt — skip this entry
                logger.warning(
                    "Skipping ZIP entry with path traversal: %s", info.filename
                )
                continue

            if info.is_dir():
                os.makedirs(target_path, exist_ok=True)
            else:
                # Ensure parent directory exists
                parent = os.path.dirname(target_path)
                os.makedirs(parent, exist_ok=True)
                # Extract in chunks to avoid loading entire file into memory
                with zf.open(info) as src, open(target_path, "wb") as dst:
                    while chunk := src.read(8192):
                        dst.write(chunk)

        # Identify the largest file as the primary firmware target
        best = max(candidates, key=lambda i: i.file_size)
        primary_path = os.path.realpath(
            os.path.join(extract_dir, best.filename)
        )

        # Verify the primary file was actually extracted (not skipped by
        # ZIP slip prevention)
        if not os.path.isfile(primary_path):
            # Fall back to the largest file that was actually extracted
            for fallback in sorted(
                candidates, key=lambda i: i.file_size, reverse=True
            ):
                fb_path = os.path.realpath(
                    os.path.join(extract_dir, fallback.filename)
                )
                if os.path.isfile(fb_path):
                    primary_path = fb_path
                    break
            else:
                return None

        return primary_path


# `_firmware_tar_filter` is imported from `app.workers.unpack_linux` (line 40);
# the previous local redefinition here was a Phase Lint.B.2 (2026-05-10) F811
# cleanup — the imported version is the authoritative implementation, with
# stricter `_tarfile.AbsolutePathError` semantics + hard-link target
# validation that the local copy lacked.


def _extract_archive(archive_path: str, output_dir: str) -> None:
    """Extract a tar, tar.gz, or zip archive with path traversal prevention."""
    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as tf:
            tf.extractall(output_dir, filter=_firmware_tar_filter)
    elif zipfile.is_zipfile(archive_path):
        settings = get_settings()
        max_bytes = settings.max_extraction_size_mb * 1024 * 1024
        safe_extract_zip(archive_path, output_dir, max_size=max_bytes)
    else:
        raise ValueError(
            "Unsupported archive format. Please upload a .tar.gz, .tar, or .zip file."
        )


def _check_storage_available(storage_root: str, required_bytes: int) -> None:
    """Raise HTTP 507 if ``storage_root`` can't absorb another ``required_bytes``.

    Applies a 1.5x safety margin — an incoming 2 GB upload needs ~3 GB free.
    The margin covers temporary extraction artefacts and the unpack
    pipeline's own working space (unblob copies each container before
    recursing, etc.). ``shutil.disk_usage`` operates on the volume the
    path resolves to, so this works against both bind-mounted and named
    Docker volumes.

    The guard is cheap (< 1 ms) and runs before the UploadFile stream is
    consumed, so rejected uploads don't burn bandwidth.
    """
    from fastapi import HTTPException

    try:
        free = shutil.disk_usage(storage_root).free
    except OSError as exc:
        logger.warning(
            "storage-quota check: disk_usage(%s) failed: %s — allowing upload",
            storage_root, exc,
        )
        return

    needed = int(required_bytes * 1.5)
    if free < needed:
        free_mb = free // (1024 * 1024)
        needed_mb = needed // (1024 * 1024)
        raise HTTPException(
            507,  # Insufficient Storage (RFC 4918)
            (
                f"Not enough disk space on {storage_root} to accept upload. "
                f"{free_mb} MB free, need {needed_mb} MB (upload size x1.5 safety "
                f"margin). Delete old firmware or expand the volume."
            ),
        )


class FirmwareService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.settings = get_settings()

    async def upload_bytes_only(
        self,
        project_id: uuid.UUID,
        file: UploadFile,
        version_label: str | None = None,
    ) -> Firmware:
        """Stream the upload to disk, dedup, persist Firmware row in 'detecting'.

        Rule #33 (a-d) ack-only path. After this returns, the caller spawns
        ``_run_upload_post_processing_background(firmware.id)`` via
        ``asyncio.create_task`` to do the slow work (format detect, archive
        extract, filesystem-root detect, arch/endian/OS detect) without
        holding the request connection idle.

        The streaming SHA-256 + bytes-to-disk loop stays inline because:
        (i) bytes can't be processed before they're on disk; (ii) the loop
        runs at IO speed (network upload-bound, not CPU-bound), so any time
        spent here is wall-time the user is already waiting for; (iii) the
        dedup check needs the final hash, which is the natural place to
        return the 202 ack.

        Returns the persisted Firmware row in ``upload_stage='detecting'``.
        """
        from fastapi import HTTPException

        # Storage-quota pre-flight (infra-volumes V1).
        probable_size = file.size if file.size is not None else (
            self.settings.max_upload_size_mb * 1024 * 1024
        )
        _check_storage_available(self.settings.storage_root, probable_size)

        firmware_id = uuid.uuid4()
        firmware_dir = os.path.join(
            self.settings.storage_root,
            "projects",
            str(project_id),
            "firmware",
            str(firmware_id),
        )
        os.makedirs(firmware_dir, exist_ok=True)

        raw_filename = file.filename or "firmware.bin"
        filename = _sanitize_filename(raw_filename)
        storage_path = os.path.join(firmware_dir, filename)
        sha256_hash = hashlib.sha256()
        file_size = 0
        max_bytes = self.settings.max_upload_size_mb * 1024 * 1024

        async with aiofiles.open(storage_path, "wb") as out_file:
            while chunk := await file.read(8192):
                sha256_hash.update(chunk)
                await out_file.write(chunk)
                file_size += len(chunk)
                if file_size > max_bytes:
                    try:
                        os.remove(storage_path)
                    except OSError:
                        pass
                    raise HTTPException(
                        413,
                        f"Upload exceeds MAX_UPLOAD_SIZE_MB "
                        f"({self.settings.max_upload_size_mb} MB limit).",
                    )

        sha256_hex = sha256_hash.hexdigest()
        existing_id = (
            await self.db.execute(
                select(Firmware.id).where(
                    Firmware.project_id == project_id,
                    Firmware.sha256 == sha256_hex,
                )
            )
        ).scalar_one_or_none()
        if existing_id is not None:
            try:
                os.remove(storage_path)
            except OSError:
                pass
            try:
                os.rmdir(firmware_dir)
            except OSError:
                pass
            raise HTTPException(
                status_code=409,
                detail=(
                    f"This firmware is already in the project "
                    f"(firmware_id={existing_id}). Open the existing entry "
                    "or upload to a different project."
                ),
            )

        firmware = Firmware(
            id=firmware_id,
            project_id=project_id,
            original_filename=raw_filename,
            sha256=sha256_hex,
            file_size=file_size,
            storage_path=storage_path,
            version_label=version_label,
            upload_stage="detecting",
            upload_stage_started_at=datetime.now(UTC),
        )
        self.db.add(firmware)
        # Commit so the background task's fresh AsyncSession observes the
        # row (Rule #33 reference shape — the inner task uses
        # async_session_factory(), not the request-scoped self.db).
        await self.db.commit()
        return firmware

    async def upload(
        self,
        project_id: uuid.UUID,
        file: UploadFile,
        version_label: str | None = None,
    ) -> Firmware:
        """Legacy synchronous upload — bytes + post-processing in one request.

        Retained for tests and any internal callers that want the old
        "wait until everything is done" semantics. Equivalent to calling
        ``upload_bytes_only`` followed by the post-processing pipeline
        running inline against the same session.

        The production HTTP endpoint no longer calls this; it uses
        ``upload_bytes_only`` + ``_run_upload_post_processing_background``.
        """
        firmware = await self.upload_bytes_only(
            project_id, file, version_label=version_label
        )
        await _post_process_inline(self.db, firmware)
        # Refresh + flush so the caller sees the populated fields without
        # an extra round-trip.
        await self.db.flush()
        return firmware


    async def upload_rootfs(
        self,
        firmware: Firmware,
        file: UploadFile,
    ) -> Firmware:
        """Extract a user-supplied rootfs archive into the firmware's extracted dir.

        Accepts .tar.gz, .tar, or .zip archives containing the filesystem root.
        Runs architecture and OS detection on the extracted contents.
        """
        firmware_dir = os.path.dirname(firmware.storage_path)
        extraction_dir = os.path.join(firmware_dir, "extracted")
        os.makedirs(extraction_dir, exist_ok=True)

        # Save archive to a temp file
        raw_filename = file.filename or "rootfs.tar.gz"
        archive_path = os.path.join(firmware_dir, _sanitize_filename(raw_filename))
        async with aiofiles.open(archive_path, "wb") as out:
            while chunk := await file.read(8192):
                await out.write(chunk)

        # Extract the archive (sync I/O — run in executor to avoid blocking)
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, _extract_archive, archive_path, extraction_dir)
        finally:
            os.remove(archive_path)

        # Find the filesystem root (sync I/O — run in executor)
        fs_root = await loop.run_in_executor(None, find_filesystem_root, extraction_dir)
        if not fs_root:
            raise ValueError(
                "Could not locate a filesystem root in the archive. "
                "Ensure it contains a Linux root filesystem (with etc/, bin/ or usr/)."
            )

        firmware.extracted_path = fs_root
        arch, endian = await loop.run_in_executor(None, detect_architecture, fs_root)
        firmware.architecture = arch
        firmware.endianness = endian
        firmware.os_info = await loop.run_in_executor(None, detect_os_info, fs_root)
        firmware.kernel_path = await loop.run_in_executor(None, detect_kernel, extraction_dir, fs_root)
        firmware.unpack_log = "Filesystem provided via manual rootfs upload."

        await self.db.flush()
        return firmware

    async def get_by_project(self, project_id: uuid.UUID) -> Firmware | None:
        """Get the first firmware for a project (backward compat)."""
        result = await self.db.execute(
            select(Firmware)
            .where(Firmware.project_id == project_id)
            .order_by(Firmware.created_at)
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, firmware_id: uuid.UUID) -> Firmware | None:
        """Get a specific firmware by its ID."""
        result = await self.db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
        return result.scalar_one_or_none()

    async def list_by_project(self, project_id: uuid.UUID) -> list[Firmware]:
        """List all firmware for a project, ordered by creation time."""
        result = await self.db.execute(
            select(Firmware)
            .where(Firmware.project_id == project_id)
            .order_by(Firmware.created_at)
        )
        return list(result.scalars().all())

    async def delete(self, firmware: Firmware) -> None:
        """Delete a firmware record and its files on disk."""
        # Remove files from disk
        loop = asyncio.get_running_loop()
        if firmware.storage_path:
            # The firmware directory is the parent of the storage_path
            firmware_dir = os.path.dirname(firmware.storage_path)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
            await loop.run_in_executor(None, _rmtree_if_isdir_sync, firmware_dir)
        elif firmware.extracted_path:
            # Fallback: remove extracted path's parent
            parent = os.path.dirname(firmware.extracted_path)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
            await loop.run_in_executor(None, _rmtree_if_isdir_sync, parent)

        await self.db.delete(firmware)
        await self.db.flush()


# ---------------------------------------------------------------------------
# Upload post-processing pipeline (Rule #29 + Rule #33)
# ---------------------------------------------------------------------------
#
# After ``upload_bytes_only`` returns the 202 ack, the router fires
# ``_run_upload_post_processing_background`` via asyncio.create_task to
# run the slow CPU-bound work (format detect → archive extract →
# filesystem-root detect → arch/endian/OS detect) on its own AsyncSession.
# The same work is reachable inline via ``_post_process_inline`` for the
# legacy ``FirmwareService.upload`` callable that some tests + scripts
# still want.
#
# The two share an underlying ``_post_process_pipeline`` so the extraction
# logic — preserved verbatim from the pre-refactor synchronous body —
# only lives in one place.


async def _post_process_pipeline(
    db: AsyncSession,
    firmware: Firmware,
    *,
    update_stage: bool,
) -> None:
    """Run the post-write extraction + analysis pipeline on a firmware row.

    Mutates the row in place and flushes. When ``update_stage`` is True
    (background runner path), transitions the row through ``detecting``
    → ``extracting`` → ``analyzing`` → ``ready`` and commits at each
    boundary so the frontend's polling endpoint sees progress. When
    False (legacy inline path), leaves ``upload_stage`` alone — the
    caller is responsible for any final flush.
    """
    settings = get_settings()
    storage_path = firmware.storage_path
    raw_filename = firmware.original_filename or "firmware.bin"
    firmware_dir = os.path.dirname(storage_path) if storage_path else None

    # ── Stage: detecting (format detection) ──────────────────────────
    if update_stage:
        firmware.upload_stage = "detecting"
        await db.commit()

    try:
        detected = detect_format(storage_path) if storage_path else DetectedFormat.UNKNOWN
        firmware.detected_format = detected.value
    except Exception:
        logger.warning("format-detect failed for %s", storage_path, exc_info=True)
        firmware.detected_format = DetectedFormat.UNKNOWN.value

    if update_stage:
        await db.commit()

    # ── Stage: extracting ────────────────────────────────────────────
    if update_stage:
        firmware.upload_stage = "extracting"
        await db.commit()

    extraction_diagnostics: dict = {}
    extracted_via_shortcut = False
    loop = asyncio.get_running_loop()

    # Tarball shortcut (.tar.gz / .tar / .tgz / .tar.bz2 / .tar.xz)
    is_tar = raw_filename.lower().endswith((".tar.gz", ".tar", ".tgz", ".tar.bz2", ".tar.xz"))
    if is_tar and firmware_dir and storage_path:
        try:
            if tarfile.is_tarfile(storage_path):
                extraction_dir = os.path.join(firmware_dir, "extracted")
                os.makedirs(extraction_dir, exist_ok=True)

                def _extract_tar():
                    with tarfile.open(storage_path) as tf:
                        tf.extractall(extraction_dir, filter=_firmware_tar_filter)

                await loop.run_in_executor(None, _extract_tar)
                await loop.run_in_executor(None, widen_read_perms, extraction_dir)
                fs_root = await loop.run_in_executor(
                    None, find_filesystem_root, extraction_dir
                )
                if fs_root:
                    firmware.extracted_path = fs_root
                    firmware.unpack_log = "Tarball detected; extracted directly as rootfs."
                    extracted_via_shortcut = True
        except Exception:
            logger.debug("Tarball device-dump detection failed", exc_info=True)

    # ZIP shortcut (Android OTA kept intact, rootfs ZIPs extracted directly,
    # generic ZIPs extract to zip_contents/ for browsing).
    if not extracted_via_shortcut and storage_path and firmware_dir:
        is_zip = False
        try:
            is_zip = (
                raw_filename.lower().endswith(".zip")
                and zipfile.is_zipfile(storage_path)
            )
        except (zipfile.BadZipFile, OSError):
            pass

        if is_zip:
            try:
                is_android = _is_android_firmware_zip(storage_path)
            except (zipfile.BadZipFile, OSError, EOFError):
                is_android = False
            try:
                is_rootfs = (
                    not is_android and _zip_contains_rootfs(storage_path)
                )
            except (zipfile.BadZipFile, OSError, EOFError):
                is_rootfs = False

            if is_rootfs:
                extraction_dir = os.path.join(firmware_dir, "extracted")
                os.makedirs(extraction_dir, exist_ok=True)
                await loop.run_in_executor(
                    None, _extract_archive, storage_path, extraction_dir
                )
                # Rootfs ZIP: original archive is no longer needed;
                # extracted/ is the durable artefact.
                try:
                    os.remove(storage_path)
                except OSError:
                    pass
                await loop.run_in_executor(None, widen_read_perms, extraction_dir)
                fs_root = await loop.run_in_executor(
                    None, find_filesystem_root, extraction_dir
                )
                if fs_root:
                    firmware.extracted_path = fs_root
                    firmware.unpack_log = (
                        "Rootfs ZIP detected; extracted directly without binwalk."
                    )
                    extracted_via_shortcut = True
            elif not is_android:
                # Generic ZIP: extract to zip_contents/ for the file
                # explorer (preserves original zip on disk for later
                # /unpack reprocessing).
                try:
                    await loop.run_in_executor(
                        None,
                        _extract_firmware_from_zip,
                        storage_path,
                        firmware_dir,
                    )
                    zip_root = os.path.join(firmware_dir, "zip_contents")  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                    if await loop.run_in_executor(None, os.path.isdir, zip_root):
                        await loop.run_in_executor(
                            None,
                            _recursive_extract_nested,
                            zip_root,
                            3,
                        )
                        await loop.run_in_executor(
                            None, widen_read_perms, zip_root
                        )
                        try:
                            extraction_diagnostics = await loop.run_in_executor(
                                None,
                                diagnose_failed_archives,
                                [zip_root],
                            )
                        except Exception:
                            logger.warning(
                                "Archive diagnostic scan failed",
                                exc_info=True,
                            )
                        # Walker-bridge fix: surface the zip_contents/
                        # directory as the firmware's extracted_path so
                        # downstream consumers (populate_detection_roots,
                        # _run_hardware_firmware_detection_safe, and the
                        # 22-walker registry it iterates via
                        # walker_registry.WALKER_AUTO_TRIGGERS) can find
                        # work to do. Before this assignment, generic-ZIP
                        # firmware (Windows boot CDs / multi-file medical
                        # firmware bundles / etc.) extracted successfully
                        # but extracted_path stayed NULL — so detection
                        # never fired and every *_walk_status column
                        # remained 'idle'. Tar + rootfs-ZIP shortcuts
                        # above already set extracted_path; this brings
                        # the generic-ZIP path in line.
                        firmware.extracted_path = zip_root
                except (zipfile.BadZipFile, EOFError, OSError) as exc:
                    logger.warning(
                        "Generic ZIP extraction failed (%s); raw zip preserved on disk",
                        exc,
                    )

    # Stamp extraction_diagnostics on device_metadata if any failures
    # were diagnosed (mirrors the legacy upload behaviour).
    if extraction_diagnostics:
        firmware.device_metadata = _stamp_firmware_device_metadata(
            {"extraction_diagnostics": extraction_diagnostics}
        )

    # ── Stage: analyzing (arch / endian / OS / kernel detection) ─────
    if update_stage:
        firmware.upload_stage = "analyzing"
        await db.commit()

    if firmware.extracted_path:
        fs_root = firmware.extracted_path
        extraction_dir = os.path.dirname(fs_root) if fs_root else None
        try:
            arch, endian = await loop.run_in_executor(
                None, detect_architecture, fs_root
            )
            firmware.architecture = arch
            firmware.endianness = endian
            firmware.os_info = await loop.run_in_executor(
                None, detect_os_info, fs_root
            )
            if extraction_dir:
                firmware.kernel_path = await loop.run_in_executor(
                    None, detect_kernel, extraction_dir, fs_root
                )
            await loop.run_in_executor(None, populate_detection_roots, firmware)
        except Exception:
            logger.warning(
                "Post-extraction analysis failed for firmware %s",
                firmware.id,
                exc_info=True,
            )

    # ── Stage: ready (terminal) ──────────────────────────────────────
    if update_stage:
        firmware.upload_stage = "ready"
        firmware.upload_stage_finished_at = datetime.now(UTC)
        await db.commit()

        # Fire HW detection post-commit if extraction succeeded.
        # The HW detection runner itself dispatches the walker
        # auto-trigger registry (see app.workers.walker_registry +
        # _run_hardware_firmware_detection_safe), so this single
        # create_task covers BOTH HW-blob discovery AND every walker
        # registered in WALKER_AUTO_TRIGGERS.
        if firmware.extracted_path:
            asyncio.create_task(
                _run_hardware_firmware_detection_safe(
                    firmware.id, firmware.extracted_path,
                ),
            )


async def _fire_walker_auto_triggers(firmware_id: uuid.UUID) -> None:
    """Dispatch every walker safe-runner in WALKER_AUTO_TRIGGERS sequentially.

    Thin orchestrator that iterates ``walker_registry.get_walker_auto_triggers()``
    and invokes each ``auto_*_walk_firmware_safe(firmware_id)`` with an
    outer try/except so one walker's crash doesn't block the rest. Each
    safe-runner owns its own ``async_session_factory()`` session and is
    fire-and-forget per Rule #39.

    Sequential rather than ``asyncio.gather`` per Rule #7 — even though
    each safe-runner owns its own AsyncSession, the worker container's
    PostgreSQL pool is finite and a 22-way gather would starve other
    requests. Sequential matches the shape
    ``_run_hardware_firmware_detection_safe`` uses (one walker at a
    time after detection + graph build).

    Used by the Shape A walker-bridge: ``_post_process_pipeline`` calls
    ``_run_hardware_firmware_detection_safe`` which calls this helper.
    Also called directly by tests (Rule #35b live canary against the
    full walker chain) and by any future operator-triggered "fire all
    walkers" maintenance endpoint.
    """
    from app.workers.walker_registry import get_walker_auto_triggers

    for safe_runner in get_walker_auto_triggers():
        try:
            await safe_runner(firmware_id)
        except Exception:
            logger.warning(
                "walker auto-trigger %s failed for firmware %s",
                getattr(safe_runner, "__qualname__", repr(safe_runner)),
                firmware_id,
                exc_info=True,
            )


async def _post_process_inline(
    db: AsyncSession,
    firmware: Firmware,
) -> None:
    """Run the post-write pipeline against the request-scoped session.

    Used by the legacy ``FirmwareService.upload`` callable. Does NOT
    touch ``upload_stage`` (the legacy callers don't observe it) and
    flushes once at the end so the caller can return the populated row.
    """
    await _post_process_pipeline(db, firmware, update_stage=False)
    await db.flush()


async def _run_upload_post_processing_background(firmware_id: uuid.UUID) -> None:
    """Detached post-processing runner for the Rule #33 202+polling path.

    Owns its own AsyncSession so the FastAPI request that returned the
    202 ack can close cleanly. Mirrors ``_run_vuln_scan_background`` in
    ``routers/sbom.py`` and ``_run_unpack_background`` in
    ``routers/firmware.py``.

    State machine:
    - On entry: row is in ``upload_stage='detecting'`` (set by
      ``upload_bytes_only`` before commit).
    - On clean return: row is in ``upload_stage='ready'`` with
      ``extracted_path`` / ``architecture`` / ``os_info`` / ``detected_format``
      populated as available.
    - On exception: row is in ``upload_stage='failed'`` with a 2 KB
      traceback summary on ``upload_stage_error``. The fail-write uses
      a fresh AsyncSession because the outer one rolled back — same
      shape as the canonical Rule #33 reference.
    """
    try:
        async with async_session_factory() as db:
            try:
                row = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one_or_none()
                if row is None:
                    logger.warning(
                        "upload-post-processing: firmware %s vanished before run",
                        firmware_id,
                    )
                    return
                await _post_process_pipeline(db, row, update_stage=True)
                logger.info(
                    "upload-post-processing: firmware %s ready (format=%s)",
                    firmware_id,
                    row.detected_format,
                )
            except Exception as exc:
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.upload_stage = "failed"
                        fail_row.upload_stage_error = err
                        fail_row.upload_stage_finished_at = datetime.now(UTC)
                        await fail_db.commit()
                logger.exception(
                    "upload-post-processing: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "upload-post-processing: unrecoverable error for firmware %s",
            firmware_id,
        )
