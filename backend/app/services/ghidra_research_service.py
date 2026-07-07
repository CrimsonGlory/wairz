import asyncio
import hashlib
import logging
import mimetypes
import os
import shutil
import traceback
import uuid
from datetime import UTC, datetime

import aiofiles
from fastapi import UploadFile
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import async_session_factory
from app.models.ghidra_research import GhidraResearchFile
from app.schemas.ghidra_research import (
    ALLOWED_EXTENSIONS,
    BINARY_EXTENSIONS,
    FILE_CATEGORY_MAP,
    MAX_GZF_SIZE_MB,
    MAX_SCRIPT_SIZE_MB,
    TEXT_EXTENSIONS,
)

logger = logging.getLogger(__name__)


class GhidraResearchService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def upload(
        self,
        project_id: uuid.UUID,
        file: UploadFile,
        description: str | None = None,
    ) -> GhidraResearchFile:
        original_filename = file.filename or "file"
        ext = os.path.splitext(original_filename)[1].lower()
        max_mb = MAX_GZF_SIZE_MB if ext in BINARY_EXTENSIONS else MAX_SCRIPT_SIZE_MB
        max_bytes = max_mb * 1024 * 1024

        hasher = hashlib.sha256()
        chunks: list[bytes] = []
        total_size = 0

        while True:
            chunk = await file.read(64 * 1024)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > max_bytes:
                raise ValueError(f"File exceeds maximum size of {max_mb}MB")
            hasher.update(chunk)
            chunks.append(chunk)

        sha256 = hasher.hexdigest()
        content_type = file.content_type or mimetypes.guess_type(original_filename)[0] or "application/octet-stream"
        file_category = FILE_CATEGORY_MAP.get(ext, "python_script")

        settings = get_settings()
        file_id = uuid.uuid4()
        safe_filename = original_filename.replace("/", "_").replace("\\", "_")
        storage_dir = os.path.join(
            settings.storage_root, "projects", str(project_id), "ghidra_research"
        )
        os.makedirs(storage_dir, exist_ok=True)
        storage_path = os.path.join(storage_dir, f"{file_id}_{safe_filename}")

        async with aiofiles.open(storage_path, "wb") as f:
            for chunk in chunks:
                await f.write(chunk)

        record = GhidraResearchFile(
            id=file_id,
            project_id=project_id,
            original_filename=original_filename,
            file_category=file_category,
            description=description,
            content_type=content_type,
            file_size=total_size,
            sha256=sha256,
            storage_path=storage_path,
            import_status="idle",
        )
        self.db.add(record)
        await self.db.flush()
        return record

    async def register_local_file(
        self,
        project_id: uuid.UUID,
        local_path: str,
        original_filename: str,
        description: str | None = None,
    ) -> GhidraResearchFile:
        """Register an already-on-disk file as a new GhidraResearchFile.

        Mirrors upload(), but the source is a local path (e.g. an archive
        just produced by export_ghidra_archive) rather than an UploadFile
        streamed from an HTTP request. Copies the file into the project's
        ghidra_research storage dir so it is served identically to an
        uploaded file (list/download/delete all go through the same rows).
        """
        ext = os.path.splitext(original_filename)[1].lower()
        content_type = mimetypes.guess_type(original_filename)[0] or "application/octet-stream"
        file_category = FILE_CATEGORY_MAP.get(ext, "python_script")

        hasher = hashlib.sha256()
        total_size = 0
        async with aiofiles.open(local_path, "rb") as src:
            while True:
                chunk = await src.read(64 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
                total_size += len(chunk)
        sha256 = hasher.hexdigest()

        settings = get_settings()
        file_id = uuid.uuid4()
        safe_filename = original_filename.replace("/", "_").replace("\\", "_")
        storage_dir = os.path.join(
            settings.storage_root, "projects", str(project_id), "ghidra_research"
        )
        os.makedirs(storage_dir, exist_ok=True)
        storage_path = os.path.join(storage_dir, f"{file_id}_{safe_filename}")

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, shutil.copyfile, local_path, storage_path)

        record = GhidraResearchFile(
            id=file_id,
            project_id=project_id,
            original_filename=original_filename,
            file_category=file_category,
            description=description,
            content_type=content_type,
            file_size=total_size,
            sha256=sha256,
            storage_path=storage_path,
            import_status="idle",
        )
        self.db.add(record)
        await self.db.flush()
        return record

    @staticmethod
    def _name_filter(name_contains: str | None):
        """Case-insensitive substring filter over filename OR description.

        Returns a SQLAlchemy predicate, or None when no filter is requested.
        """
        if not name_contains:
            return None
        pattern = f"%{name_contains}%"
        return or_(
            GhidraResearchFile.original_filename.ilike(pattern),
            GhidraResearchFile.description.ilike(pattern),
        )

    async def list_by_project(
        self,
        project_id: uuid.UUID,
        *,
        limit: int = 100,
        offset: int = 0,
        name_contains: str | None = None,
    ) -> list[GhidraResearchFile]:
        stmt = (
            select(GhidraResearchFile)
            .where(GhidraResearchFile.project_id == project_id)
        )
        name_filter = self._name_filter(name_contains)
        if name_filter is not None:
            stmt = stmt.where(name_filter)
        stmt = (
            stmt.order_by(GhidraResearchFile.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def count_by_project(
        self, project_id: uuid.UUID, *, name_contains: str | None = None,
    ) -> int:
        """Total research files for a project after applying the name filter.

        Used by the MCP listing tool to report the true total so callers can
        tell when a page is truncated.
        """
        stmt = (
            select(func.count())
            .select_from(GhidraResearchFile)
            .where(GhidraResearchFile.project_id == project_id)
        )
        name_filter = self._name_filter(name_contains)
        if name_filter is not None:
            stmt = stmt.where(name_filter)
        result = await self.db.execute(stmt)
        return int(result.scalar_one())

    async def get(self, file_id: uuid.UUID) -> GhidraResearchFile | None:
        result = await self.db.execute(
            select(GhidraResearchFile).where(GhidraResearchFile.id == file_id)
        )
        return result.scalar_one_or_none()

    async def update_description(
        self, file_id: uuid.UUID, description: str | None
    ) -> GhidraResearchFile | None:
        record = await self.get(file_id)
        if record is None:
            return None
        record.description = description
        await self.db.flush()
        return record

    async def delete(self, file_id: uuid.UUID) -> bool:
        record = await self.get(file_id)
        if record is None:
            return False
        if record.storage_path:
            storage_path = record.storage_path

            def _unlink_if_exists() -> None:
                if os.path.exists(storage_path):
                    os.remove(storage_path)

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _unlink_if_exists)
        await self.db.delete(record)
        await self.db.flush()
        return True

    async def update_script_content(
        self,
        file_id: uuid.UUID,
        content: str,
    ) -> GhidraResearchFile | None:
        record = await self.get(file_id)
        if record is None:
            return None
        ext = os.path.splitext(record.original_filename)[1].lower()
        if ext not in TEXT_EXTENSIONS:
            raise ValueError(f"Cannot edit binary files with extension '{ext}'")

        content_bytes = content.encode("utf-8")
        record.sha256 = hashlib.sha256(content_bytes).hexdigest()
        record.file_size = len(content_bytes)

        async with aiofiles.open(record.storage_path, "w", encoding="utf-8") as f:
            await f.write(content)

        await self.db.flush()
        return record

    async def resolve_gzf_path(self, project_id: uuid.UUID, name_or_path: str) -> str:
        """Resolve a .gzf filename/path to its real on-disk storage path.

        GhidraResearchFile archives live under storage_root/.../ghidra_research/,
        outside the firmware sandbox tree that FileService/context.resolve_path()
        validates against — so binary.py tools and run_ghidra_headless's GZF
        process mode both need this lookup instead of the normal sandboxed
        resolution. Matches by original_filename, basename, or stored
        storage_path, mirroring the matching shape already used in
        ghidra_research.py's resolve_firmware_path handler.

        Raises FileNotFoundError (never returns None) so callers can let it
        propagate to ToolRegistry.execute()'s generic exception handler,
        which turns it into a clean error string for the MCP client.
        """
        basename = os.path.basename(name_or_path)
        result = await self.db.execute(
            select(GhidraResearchFile).where(
                GhidraResearchFile.project_id == project_id,
                GhidraResearchFile.original_filename.ilike("%.gzf"),
            )
        )
        records = list(result.scalars().all())
        for record in records:
            if (
                record.original_filename == basename
                or record.original_filename == name_or_path
                or record.storage_path == name_or_path
                or os.path.basename(record.storage_path) == basename
            ):
                if not os.path.exists(record.storage_path):  # noqa: ASYNC240 — pre-flight stat, no walk
                    raise FileNotFoundError(
                        f"GZF archive '{record.original_filename}' is registered but "
                        f"missing on disk: {record.storage_path}"
                    )
                return record.storage_path
        raise FileNotFoundError(
            f"No .gzf archive named '{name_or_path}' found in this project's Ghidra "
            "research files. Use list_ghidra_research_files to see available archives."
        )

    @staticmethod
    def read_text_content(record: GhidraResearchFile) -> str:
        path = record.storage_path
        if not os.path.exists(path):  # noqa: ASYNC240 — pre-flight stat before read; single check, no walk
            return "[Error: file not found on disk]"
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as exc:
            return f"[Error reading file: {exc}]"


# ---------------------------------------------------------------------------
# Rule #39 inner/outer/safe triplet for Ghidra archive import
# ---------------------------------------------------------------------------

async def _do_ghidra_import_run(db: AsyncSession, file_id: uuid.UUID) -> dict:
    """INNER: run Ghidra headless on the .gzf archive, return raw result dict."""
    from app.services.ghidra_service import run_ghidra_subprocess

    result = await db.execute(
        select(GhidraResearchFile).where(GhidraResearchFile.id == file_id)
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise ValueError(f"GhidraResearchFile {file_id} not found")

    if not os.path.exists(record.storage_path):  # noqa: ASYNC240 — pre-flight existence check before subprocess; single stat, no loop
        raise FileNotFoundError(f"Archive file not on disk: {record.storage_path}")

    # Ghidra headless accepts .gzf directly via -import, same as a raw binary.
    # AnalyzeBinary.java extracts the pre-annotated functions, decompilations,
    # and researcher comments from the archived project.
    settings = get_settings()
    timeout = settings.ghidra_timeout * 2  # archives may have pre-analyzed state

    raw_output = await run_ghidra_subprocess(
        binary_path=record.storage_path,
        script_name="AnalyzeBinary.java",
        timeout=timeout,
    )

    # Parse the JSON output between markers
    import json
    start_marker = "===ANALYSIS_START==="
    end_marker = "===ANALYSIS_END==="
    start_idx = raw_output.find(start_marker)
    end_idx = raw_output.find(end_marker)
    if start_idx == -1 or end_idx == -1:
        return {"raw_output": raw_output[:4000], "parsed": False}

    json_str = raw_output[start_idx + len(start_marker):end_idx].strip()
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return {"raw_output": json_str[:4000], "parsed": False}


async def run_ghidra_import_background(file_id: uuid.UUID) -> None:
    """OUTER: state-machine wrapper (idle→queued→running→completed|failed)."""
    try:
        async with async_session_factory() as db:
            result = await db.execute(
                select(GhidraResearchFile).where(GhidraResearchFile.id == file_id)
            )
            record = result.scalar_one_or_none()
            if record is None:
                return
            record.import_status = "running"
            await db.commit()
            try:
                import_result = await _do_ghidra_import_run(db, file_id)
                async with async_session_factory() as done_db:
                    done_result = await done_db.execute(
                        select(GhidraResearchFile).where(GhidraResearchFile.id == file_id)
                    )
                    done_record = done_result.scalar_one_or_none()
                    if done_record is not None:
                        done_record.import_status = "completed"
                        done_record.import_result = import_result
                        done_record.import_error = None
                        await done_db.commit()
            except Exception as exc:
                err = "\n".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-2000:]
                async with async_session_factory() as fail_db:
                    fail_result = await fail_db.execute(
                        select(GhidraResearchFile).where(GhidraResearchFile.id == file_id)
                    )
                    fail_record = fail_result.scalar_one_or_none()
                    if fail_record is not None:
                        fail_record.import_status = "failed"
                        fail_record.import_error = err
                        await fail_db.commit()
                logger.exception("Ghidra archive import failed for file %s", file_id)
    except Exception:
        logger.exception("Unrecoverable error in run_ghidra_import_background for file %s", file_id)
