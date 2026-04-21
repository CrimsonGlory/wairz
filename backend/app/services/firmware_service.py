import asyncio
import hashlib
import logging
import os
import re
import shutil
import tarfile
import uuid
import zipfile

import aiofiles
from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.firmware import Firmware

logger = logging.getLogger(__name__)


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


def _firmware_tar_filter(member, dest_path):
    """Tar filter for firmware archives — allows absolute symlinks.

    Python 3.12's filter="data" rejects symlinks to absolute paths,
    but firmware rootfs archives legitimately use them. This filter
    allows symlinks while still preventing path traversal and
    rejecting device nodes.
    """
    name = member.name.lstrip("/")
    if name != member.name:
        member = member.replace(name=name, deep=False)
    resolved = os.path.realpath(os.path.join(dest_path, name))
    real_dest = os.path.realpath(dest_path)
    if not resolved.startswith(real_dest + os.sep) and resolved != real_dest:
        raise ValueError(f"Path traversal detected in archive: {member.name}")
    if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
        return None
    return member


def _extract_archive(archive_path: str, output_dir: str) -> None:
    """Extract a tar, tar.gz, or zip archive with path traversal prevention."""
    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as tf:
            tf.extractall(output_dir, filter=_firmware_tar_filter)
    elif zipfile.is_zipfile(archive_path):
        from app.workers.safe_extract import safe_extract_zip
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

    async def upload(
        self,
        project_id: uuid.UUID,
        file: UploadFile,
        version_label: str | None = None,
    ) -> Firmware:
        # Storage-quota pre-flight (infra-volumes V1). Reject with 507 before
        # consuming the upload stream if the volume can't absorb the file.
        # ``file.size`` is trustworthy for multipart uploads — FastAPI reads
        # it from the Content-Length on the part boundary. Fall back to the
        # MAX_UPLOAD_SIZE ceiling when size is unavailable.
        probable_size = file.size if file.size is not None else (
            self.settings.max_upload_size_mb * 1024 * 1024
        )
        _check_storage_available(self.settings.storage_root, probable_size)

        # Generate a firmware ID upfront for per-firmware storage directory
        firmware_id = uuid.uuid4()

        # Per-firmware storage: projects/{pid}/firmware/{fid}/
        firmware_dir = os.path.join(
            self.settings.storage_root,
            "projects",
            str(project_id),
            "firmware",
            str(firmware_id),
        )
        os.makedirs(firmware_dir, exist_ok=True)

        # Stream file to disk while computing SHA256.
        # Enforce MAX_UPLOAD_SIZE_MB mid-transfer so oversized uploads abort
        # before filling the disk (B.1.c).
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
                    # Clean up the partial file before raising
                    try:
                        os.remove(storage_path)
                    except OSError:
                        pass
                    from fastapi import HTTPException
                    raise HTTPException(
                        413,
                        f"Upload exceeds MAX_UPLOAD_SIZE_MB "
                        f"({self.settings.max_upload_size_mb} MB limit).",
                    )

        # Tarball detection: .tar.gz, .tar, .tgz files containing a rootfs
        # are extracted directly (same path as rootfs ZIPs). This supports
        # ADB device dumps (e.g., `adb pull /system` → system.tar.gz).
        is_tar = raw_filename.lower().endswith((".tar.gz", ".tar", ".tgz", ".tar.bz2", ".tar.xz"))
        if is_tar:
            import tarfile
            try:
                if tarfile.is_tarfile(storage_path):
                    from app.workers.unpack import (
                        detect_architecture,
                        detect_kernel,
                        detect_os_info,
                        find_filesystem_root,
                    )

                    extraction_dir = os.path.join(firmware_dir, "extracted")
                    os.makedirs(extraction_dir, exist_ok=True)

                    def _extract_tar():
                        with tarfile.open(storage_path) as tf:
                            from app.workers.unpack_linux import _firmware_tar_filter
                            tf.extractall(extraction_dir, filter=_firmware_tar_filter)

                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, _extract_tar)

                    fs_root = await loop.run_in_executor(
                        None, find_filesystem_root, extraction_dir
                    )
                    if fs_root:
                        firmware = Firmware(
                            id=firmware_id,
                            project_id=project_id,
                            original_filename=raw_filename,
                            sha256=sha256_hash.hexdigest(),
                            file_size=file_size,
                            storage_path=storage_path,
                            extracted_path=fs_root,
                            version_label=version_label,
                            unpack_log="Tarball detected; extracted directly as rootfs.",
                        )
                        arch, endian = await loop.run_in_executor(
                            None, detect_architecture, fs_root
                        )
                        firmware.architecture = arch
                        firmware.endianness = endian
                        firmware.os_info = await loop.run_in_executor(
                            None, detect_os_info, fs_root
                        )
                        firmware.kernel_path = await loop.run_in_executor(
                            None, detect_kernel, extraction_dir, fs_root
                        )
                        # Check for getprop.txt (ADB device dump metadata)
                        for getprop_name in ("getprop.txt", "device_properties.txt"):
                            getprop_path = os.path.join(extraction_dir, getprop_name)
                            if not os.path.isfile(getprop_path):
                                getprop_path = os.path.join(fs_root, getprop_name)
                            if os.path.isfile(getprop_path):
                                try:
                                    with open(getprop_path) as gf:
                                        getprop = gf.read(8192)
                                    if not firmware.os_info:
                                        firmware.os_info = getprop
                                    firmware.unpack_log += f"\nParsed {getprop_name} for device metadata."
                                except Exception:
                                    logger.debug("Failed to parse %s", getprop_name, exc_info=True)
                                break
                        # Rule #16: populate detection_roots so downstream
                        # walkers (hardware-firmware, SBOM, MCP file tree)
                        # don't have to re-derive them from extracted_path.
                        # Safe + synchronous — already wrapped for walk I/O.
                        from app.services.firmware_paths import (
                            _compute_roots_sync,
                            _persist_roots,
                        )
                        roots = await loop.run_in_executor(
                            None, _compute_roots_sync, fs_root
                        )
                        _persist_roots(firmware, roots)
                        self.db.add(firmware)
                        await self.db.flush()
                        return firmware
            except Exception:
                logger.debug("Tarball device-dump detection failed", exc_info=True)

        # If the uploaded file is a ZIP (by extension), extract the firmware from inside it.
        # We check the extension rather than zipfile.is_zipfile() alone because firmware
        # binaries can contain embedded zip data that triggers false positives.
        is_zip = False
        try:
            is_zip = raw_filename.lower().endswith(".zip") and zipfile.is_zipfile(storage_path)
        except (zipfile.BadZipFile, OSError):
            pass  # Corrupted or unreadable — treat as non-ZIP firmware

        extraction_diagnostics: dict = {}
        if is_zip:
            try:
                is_android = _is_android_firmware_zip(storage_path)
            except (zipfile.BadZipFile, OSError, EOFError):
                is_android = False
            try:
                is_rootfs = not is_android and _zip_contains_rootfs(storage_path)
            except (zipfile.BadZipFile, OSError, EOFError):
                is_rootfs = False

            if is_android:
                pass  # Keep ZIP intact for the unpack pipeline's _extract_android_ota()
            elif is_rootfs:
                # The ZIP contains a Linux root filesystem — extract the entire
                # archive directly instead of pulling a single file for binwalk.
                # This mirrors the "Upload Rootfs" path so the user doesn't need
                # to fall back to manual rootfs upload.
                from app.workers.unpack import (
                    detect_architecture,
                    detect_kernel,
                    detect_os_info,
                    find_filesystem_root,
                )

                extraction_dir = os.path.join(firmware_dir, "extracted")
                os.makedirs(extraction_dir, exist_ok=True)

                loop = asyncio.get_running_loop()
                await loop.run_in_executor(
                    None, _extract_archive, storage_path, extraction_dir
                )
                os.remove(storage_path)

                fs_root = await loop.run_in_executor(
                    None, find_filesystem_root, extraction_dir
                )
                if not fs_root:
                    raise ValueError(
                        "ZIP appears to contain a rootfs but no filesystem root "
                        "was found after extraction."
                    )

                firmware = Firmware(
                    id=firmware_id,
                    project_id=project_id,
                    original_filename=raw_filename,
                    sha256=sha256_hash.hexdigest(),
                    file_size=file_size,
                    storage_path=storage_path,
                    extracted_path=fs_root,
                    version_label=version_label,
                    unpack_log="Rootfs ZIP detected; extracted directly without binwalk.",
                )
                arch, endian = await loop.run_in_executor(
                    None, detect_architecture, fs_root
                )
                firmware.architecture = arch
                firmware.endianness = endian
                firmware.os_info = await loop.run_in_executor(
                    None, detect_os_info, fs_root
                )
                firmware.kernel_path = await loop.run_in_executor(
                    None, detect_kernel, extraction_dir, fs_root
                )
                # Rule #16: populate detection_roots so downstream walkers
                # don't have to re-derive them from extracted_path.
                from app.services.firmware_paths import (
                    _compute_roots_sync,
                    _persist_roots,
                )
                roots = await loop.run_in_executor(
                    None, _compute_roots_sync, fs_root
                )
                _persist_roots(firmware, roots)
                self.db.add(firmware)
                await self.db.flush()
                return firmware

            else:
                try:
                    extracted = _extract_firmware_from_zip(storage_path, firmware_dir)
                except (zipfile.BadZipFile, EOFError, OSError) as exc:
                    logger.warning("ZIP extraction failed (%s), treating as raw firmware", exc)
                    extracted = None
                if extracted:
                    # Preserve the original zip on disk so POST /unpack can
                    # reprocess the whole archive end-to-end (needed for
                    # the vendor-AES auto-decrypt pipeline in Stage 2 to
                    # see the recovery rootfs + encrypted payloads side-
                    # by-side). The zip path used to delete the original
                    # here and re-point storage_path at a single inner
                    # file, which starved /unpack of context and diverged
                    # from the .7z/.tar paths. See intake:
                    # zip-upload-breaks-vendor-aes-autodecrypt.md.
                    zip_file_path = storage_path
                    # ``storage_path`` now points at the picked inner file
                    # so the nested-extract walk + diagnostic scan below
                    # can locate ``zip_contents/`` via dirname(); we
                    # restore it to the zip path when constructing the
                    # Firmware row so /unpack reprocesses the whole zip.
                    storage_path = extracted
                    # Extraction-integrity fix: multi-file firmware ZIPs
                    # (medical device / embedded Linux patterns) pack many
                    # sibling archives (rootfs_partition.tar.xz,
                    # zImage-restore.tar.xz, boot_partition.tar.xz, etc.)
                    # alongside MCU .bin files. Unblob later runs against
                    # just the largest file (``extracted``), leaving the
                    # siblings inaccessible to detection. Recursively
                    # expand any tar/zip/lz4 archive in the zip_contents
                    # tree in-place so their contents are visible to
                    # Phase 2's get_detection_roots.
                    try:
                        from app.workers.unpack_common import (
                            _recursive_extract_nested,
                        )
                        zip_loop = asyncio.get_running_loop()
                        # storage_path = firmware-dir/zip_contents/<arbitrary-path>/<file>
                        # Find the zip_contents dir by walking up until its basename matches.
                        cursor = os.path.dirname(storage_path)
                        zip_root: str | None = None
                        for _ in range(8):
                            if os.path.basename(cursor) == "zip_contents":
                                zip_root = cursor
                                break
                            parent = os.path.dirname(cursor)
                            if parent == cursor:
                                break
                            cursor = parent
                        if zip_root and os.path.isdir(zip_root):
                            nested = await zip_loop.run_in_executor(
                                None,
                                _recursive_extract_nested,
                                zip_root,
                                3,
                            )
                            if nested:
                                logger.info(
                                    "Expanded %d nested archive(s) in %s",
                                    len(nested),
                                    zip_root,
                                )
                    except Exception:
                        logger.warning(
                            "Nested extraction of zip_contents failed",
                            exc_info=True,
                        )
                    # Diagnose archive-named files that failed to extract
                    # (vendor-encrypted / signed containers). Surfaced in
                    # device_metadata so the UI can flag partial extraction.
                    try:
                        from app.workers.unpack_common import (
                            diagnose_failed_archives,
                        )
                        if zip_root and os.path.isdir(zip_root):
                            extraction_diagnostics = await zip_loop.run_in_executor(
                                None,
                                diagnose_failed_archives,
                                [zip_root],
                            )
                    except Exception:
                        logger.warning(
                            "Archive diagnostic scan failed",
                            exc_info=True,
                        )
                    # Hash/size of the original zip are already captured
                    # from the upload stream above; no recompute needed.
                    # Restore storage_path to the zip so Firmware.storage_path
                    # points at the whole upload artefact, not an inner file.
                    storage_path = zip_file_path

        firmware = Firmware(
            id=firmware_id,
            project_id=project_id,
            original_filename=raw_filename,
            sha256=sha256_hash.hexdigest(),
            file_size=file_size,
            storage_path=storage_path,
            version_label=version_label,
            device_metadata=(
                {"extraction_diagnostics": extraction_diagnostics}
                if extraction_diagnostics
                else None
            ),
        )
        self.db.add(firmware)
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
        from app.workers.unpack import (
            detect_architecture,
            detect_kernel,
            detect_os_info,
            find_filesystem_root,
        )

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
        if firmware.storage_path:
            # The firmware directory is the parent of the storage_path
            firmware_dir = os.path.dirname(firmware.storage_path)
            if os.path.isdir(firmware_dir):
                shutil.rmtree(firmware_dir, ignore_errors=True)
        elif firmware.extracted_path:
            # Fallback: remove extracted path's parent
            parent = os.path.dirname(firmware.extracted_path)
            if os.path.isdir(parent):
                shutil.rmtree(parent, ignore_errors=True)

        await self.db.delete(firmware)
        await self.db.flush()
