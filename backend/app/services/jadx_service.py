"""JADX-based APK/DEX decompilation service with caching.

Runs JADX to decompile Android APK or DEX files into Java source code.
Results are cached in the ``analysis_cache`` table (keyed by SHA256) via
:mod:`app.services._cache` to avoid expensive re-decompilation.  Follows
the same caching and concurrency patterns as ghidra_service.py.

All methods are async.  The actual JADX CLI invocation is done via
``asyncio.create_subprocess_exec()`` with configurable timeout.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.services import _cache
from app.utils.hashing import compute_file_sha256

logger = logging.getLogger(__name__)

# Maximum number of source files to include in cached result to keep
# JSONB size reasonable.  Individual files can still be fetched on demand.
_MAX_CACHED_SOURCE_FILES = 2000

# Maximum size (bytes) per individual source file to cache
_MAX_SOURCE_FILE_SIZE = 256 * 1024  # 256 KB


def _find_jadx_binary() -> str:
    """Locate the jadx binary, checking settings first then PATH."""
    settings = get_settings()
    configured = settings.jadx_path

    if os.path.isfile(configured) and os.access(configured, os.X_OK):
        return configured

    # Fallback: check PATH
    from shutil import which

    found = which("jadx")
    if found:
        return found

    raise FileNotFoundError(
        f"JADX not found at '{configured}' and not on PATH. "
        "Install JADX or set JADX_PATH in .env."
    )


async def run_jadx_subprocess(
    apk_path: str,
    output_dir: str,
    *,
    timeout: int | None = None,  # noqa: ASYNC109 — caller-supplied per-invocation timeout passed to asyncio.wait_for
    extra_args: list[str] | None = None,
) -> tuple[str, str, int]:
    """Run the JADX CLI on an APK/DEX file and return (stdout, stderr, returncode).

    Parameters
    ----------
    apk_path:
        Path to the APK or DEX file to decompile.
    output_dir:
        Directory where JADX will write decompiled Java sources.
    timeout:
        Max seconds to wait (defaults to settings.jadx_timeout).
    extra_args:
        Additional CLI arguments passed to jadx.

    Returns
    -------
    tuple of (stdout_text, stderr_text, return_code)

    Raises
    ------
    FileNotFoundError
        If JADX binary is not found.
    TimeoutError
        If decompilation exceeds the timeout.
    """
    settings = get_settings()
    jadx_bin = _find_jadx_binary()
    effective_timeout = timeout or settings.jadx_timeout

    cmd = [
        jadx_bin,
        "--output-dir", output_dir,
        "--threads-count", str(settings.jadx_threads),
        "--deobf",                  # apply deobfuscation
        "--deobf-min", "3",         # min name length before deobfuscation
        "--show-bad-code",          # show decompiler failures as comments
        "--no-imports",             # inline imports for standalone readability
        "--quiet",                  # reduce noise
    ]

    if extra_args:
        cmd.extend(extra_args)

    cmd.append(apk_path)

    # Set JAVA_OPTS for memory limit
    env = os.environ.copy()
    env["JAVA_OPTS"] = f"-Xmx{settings.jadx_max_memory}"

    logger.info(
        "Running JADX on %s (timeout=%ds, memory=%s)",
        os.path.basename(apk_path),
        effective_timeout,
        settings.jadx_max_memory,
    )

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            f"JADX binary not found at {jadx_bin}. "
            "Install JADX or set JADX_PATH in .env."
        )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=effective_timeout,
        )
    except TimeoutError:
        process.kill()
        await process.wait()
        raise TimeoutError(
            f"JADX decompilation timed out after {effective_timeout}s "
            f"for {os.path.basename(apk_path)}"
        )

    stdout_text = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr.decode("utf-8", errors="replace")

    if process.returncode != 0:
        logger.warning(
            "JADX exited with code %d for %s: %s",
            process.returncode,
            os.path.basename(apk_path),
            stderr_text[-500:],
        )

    return stdout_text, stderr_text, process.returncode


def _collect_decompiled_sources(output_dir: str) -> dict[str, Any]:
    """Walk the JADX output directory and collect decompiled Java source files.

    Returns a dict with:
        - ``sources``: dict mapping relative path → source code string
        - ``source_tree``: list of relative paths (for directory listing)
        - ``stats``: summary statistics
    """
    sources: dict[str, str] = {}
    source_tree: list[str] = []
    total_files = 0
    skipped_too_large = 0
    skipped_max_files = 0
    total_bytes = 0

    sources_dir = os.path.join(output_dir, "sources")
    resources_dir = os.path.join(output_dir, "resources")

    # Collect Java source files
    if os.path.isdir(sources_dir):
        for root, _dirs, files in os.walk(sources_dir):
            for fname in sorted(files):
                if not fname.endswith((".java", ".kt")):
                    continue

                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, sources_dir)
                total_files += 1
                source_tree.append(rel_path)

                if len(sources) >= _MAX_CACHED_SOURCE_FILES:
                    skipped_max_files += 1
                    continue

                try:
                    file_size = os.path.getsize(full_path)
                except OSError:
                    continue

                if file_size > _MAX_SOURCE_FILE_SIZE:
                    skipped_too_large += 1
                    continue

                try:
                    with open(full_path, encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    sources[rel_path] = content
                    total_bytes += len(content)
                except OSError as exc:
                    logger.warning("Failed to read decompiled source %s: %s", rel_path, exc)

    # Collect resource file listing (don't read contents)
    resource_tree: list[str] = []
    if os.path.isdir(resources_dir):
        for root, _dirs, files in os.walk(resources_dir):
            for fname in sorted(files):
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, resources_dir)
                resource_tree.append(rel_path)

    return {
        "sources": sources,
        "source_tree": sorted(source_tree),
        "resource_tree": sorted(resource_tree),
        "stats": {
            "total_source_files": total_files,
            "cached_source_files": len(sources),
            "skipped_too_large": skipped_too_large,
            "skipped_max_files": skipped_max_files,
            "total_cached_bytes": total_bytes,
            "total_resource_files": len(resource_tree),
        },
    }


class JadxDecompilationCache:
    """Cache for JADX decompilation results.

    Decompiles an APK once, stores all Java source files in the
    analysis_cache table, and serves subsequent queries from DB.

    Includes a concurrency guard: if two requests hit the same APK
    simultaneously, only one runs JADX and the other waits.
    """

    def __init__(self) -> None:
        self._decompile_locks: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    async def _get_apk_sha256(self, apk_path: str) -> str:
        """Compute SHA256 of the APK in a thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, compute_file_sha256, apk_path)

    async def _is_decompilation_complete(
        self,
        firmware_id: uuid.UUID,
        apk_sha256: str,
        db: AsyncSession,
    ) -> bool:
        """Check if JADX decompilation has been completed for this APK."""
        return await _cache.exists_cached(
            db,
            firmware_id,
            "jadx_decompilation",
            binary_sha256=apk_sha256,
        )

    async def _get_cached(
        self,
        firmware_id: uuid.UUID,
        apk_sha256: str,
        operation: str,
        db: AsyncSession,
    ) -> dict | None:
        """Retrieve a cached result by operation key."""
        return await _cache.get_cached(
            db, firmware_id, operation, binary_sha256=apk_sha256,
        )

    async def _store_cached(
        self,
        firmware_id: uuid.UUID,
        apk_path: str,
        apk_sha256: str,
        operation: str,
        result_data: dict,
        db: AsyncSession,
    ) -> None:
        """Store a result in the cache (delete-then-insert upsert)."""
        await _cache.store_cached(
            db,
            firmware_id,
            operation,
            result_data,
            binary_sha256=apk_sha256,
            binary_path=apk_path,
        )

    async def _run_decompilation(
        self,
        apk_path: str,
        firmware_id: uuid.UUID,
        apk_sha256: str,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Run JADX decompilation and store results in cache."""
        with tempfile.TemporaryDirectory(prefix="jadx_") as output_dir:
            stdout_text, stderr_text, returncode = await run_jadx_subprocess(
                apk_path, output_dir,
            )

            # Collect decompiled sources from the output directory
            # (runs file I/O in executor to avoid blocking event loop)
            loop = asyncio.get_running_loop()
            collected = await loop.run_in_executor(
                None, _collect_decompiled_sources, output_dir,
            )

        stats = collected["stats"]

        if stats["total_source_files"] == 0 and returncode != 0:
            raise RuntimeError(
                f"JADX decompilation failed (exit code {returncode}): "
                f"{stderr_text[-500:]}"
            )

        # Store the source tree listing (lightweight, always cached)
        await self._store_cached(
            firmware_id, apk_path, apk_sha256,
            "jadx_source_tree",
            {
                "source_tree": collected["source_tree"],
                "resource_tree": collected["resource_tree"],
                "stats": stats,
            },
            db,
        )

        # Store individual source files as separate cache entries
        # (allows per-file retrieval without loading everything)
        for rel_path, source_code in collected["sources"].items():
            await self._store_cached(
                firmware_id, apk_path, apk_sha256,
                f"jadx_source:{rel_path}",
                {"source": source_code, "path": rel_path},
                db,
            )

        # Store all sources as a single blob for SAST scanning
        # (mobsfscan needs all sources at once)
        await self._store_cached(
            firmware_id, apk_path, apk_sha256,
            "jadx_all_sources",
            {"sources": collected["sources"]},
            db,
        )

        # Store sentinel marking decompilation as complete
        sentinel_data = {
            "status": "complete",
            "stats": stats,
            "jadx_returncode": returncode,
        }
        await self._store_cached(
            firmware_id, apk_path, apk_sha256,
            "jadx_decompilation",
            sentinel_data,
            db,
        )

        logger.info(
            "JADX decompilation complete for %s: %d source files (%d cached, %d bytes)",
            os.path.basename(apk_path),
            stats["total_source_files"],
            stats["cached_source_files"],
            stats["total_cached_bytes"],
        )

        return sentinel_data

    async def ensure_decompilation(
        self,
        apk_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> str:
        """Ensure JADX decompilation has been run for this APK.

        Returns the APK's SHA256 hash.  Uses a concurrency guard so only
        one JADX process runs per APK.

        Parameters
        ----------
        apk_path:
            Absolute path to the APK file.
        firmware_id:
            UUID of the parent firmware (for cache association).
        db:
            Async SQLAlchemy session.

        Returns
        -------
        str — the SHA256 hash of the APK file.

        Raises
        ------
        FileNotFoundError
            If the APK file does not exist.
        TimeoutError
            If JADX exceeds the configured timeout.
        RuntimeError
            If JADX fails to produce any output.
        """
        loop = asyncio.get_running_loop()
        if not await loop.run_in_executor(None, os.path.isfile, apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")

        apk_sha256 = await self._get_apk_sha256(apk_path)

        # Fast path: already decompiled
        if await self._is_decompilation_complete(firmware_id, apk_sha256, db):
            return apk_sha256

        # Concurrency guard
        should_decompile = False
        async with self._lock:
            event = self._decompile_locks.get(apk_sha256)
            if event is not None:
                pass  # Another coroutine is already decompiling — wait
            else:
                event = asyncio.Event()
                self._decompile_locks[apk_sha256] = event
                should_decompile = True

        if not should_decompile:
            await event.wait()
            return apk_sha256

        # We're responsible for running the decompilation
        try:
            if not await self._is_decompilation_complete(firmware_id, apk_sha256, db):
                await self._run_decompilation(
                    apk_path, firmware_id, apk_sha256, db,
                )
        finally:
            async with self._lock:
                self._decompile_locks.pop(apk_sha256, None)
            event.set()

        return apk_sha256

    async def get_source_tree(
        self,
        apk_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Get the decompiled source file tree for an APK.

        Returns a dict with ``source_tree``, ``resource_tree``, and ``stats``.
        Triggers decompilation if not already cached.
        """
        apk_sha256 = await self.ensure_decompilation(apk_path, firmware_id, db)

        cached = await self._get_cached(
            firmware_id, apk_sha256, "jadx_source_tree", db,
        )
        return cached or {"source_tree": [], "resource_tree": [], "stats": {}}

    async def get_source_file(
        self,
        apk_path: str,
        source_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> str | None:
        """Get decompiled source code for a specific Java/Kotlin file.

        Parameters
        ----------
        apk_path:
            Path to the APK file.
        source_path:
            Relative path within the decompiled source tree
            (e.g. ``com/example/MainActivity.java``).
        firmware_id:
            UUID of the parent firmware.
        db:
            Async SQLAlchemy session.

        Returns
        -------
        The decompiled source code, or None if the file was not found.
        """
        apk_sha256 = await self.ensure_decompilation(apk_path, firmware_id, db)

        cached = await self._get_cached(
            firmware_id, apk_sha256, f"jadx_source:{source_path}", db,
        )
        if cached:
            return cached.get("source")
        return None

    async def get_all_sources(
        self,
        apk_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> dict[str, str]:
        """Get all decompiled sources as a dict of path → source code.

        Used by downstream SAST tools (e.g. mobsfscan) that need the
        full source tree.  Triggers decompilation if not cached.
        """
        apk_sha256 = await self.ensure_decompilation(apk_path, firmware_id, db)

        cached = await self._get_cached(
            firmware_id, apk_sha256, "jadx_all_sources", db,
        )
        if cached:
            return cached.get("sources", {})
        return {}

    async def get_decompilation_status(
        self,
        apk_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> dict[str, Any] | None:
        """Check if decompilation is complete and return stats.

        Returns None if decompilation has not been run yet.
        Does NOT trigger decompilation.
        """
        loop = asyncio.get_running_loop()
        if not await loop.run_in_executor(None, os.path.isfile, apk_path):
            return None

        apk_sha256 = await self._get_apk_sha256(apk_path)
        return await self._get_cached(
            firmware_id, apk_sha256, "jadx_decompilation", db,
        )

    async def write_sources_to_disk(
        self,
        apk_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
        target_dir: str,
    ) -> str:
        """Write all cached decompiled sources to a directory on disk.

        Useful for downstream tools that need filesystem access to the
        decompiled source tree (e.g. mobsfscan, semgrep).

        Parameters
        ----------
        target_dir:
            Directory to write sources into.  Will be created if needed.

        Returns
        -------
        Path to the sources directory (``target_dir``).
        """
        sources = await self.get_all_sources(apk_path, firmware_id, db)

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, _write_sources_sync, sources, target_dir,
        )

        return target_dir


def _write_sources_sync(sources: dict[str, str], target_dir: str) -> None:
    """Synchronous helper: write source files to disk."""
    os.makedirs(target_dir, exist_ok=True)
    for rel_path, content in sources.items():
        full_path = os.path.join(target_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_jadx_cache = JadxDecompilationCache()


def get_jadx_cache() -> JadxDecompilationCache:
    """Get the module-level JadxDecompilationCache singleton."""
    return _jadx_cache
