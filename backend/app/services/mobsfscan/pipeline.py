"""End-to-end mobsfscan orchestration pipeline.

This module is the **orchestration** layer of the mobsfscan pipeline.
:class:`MobsfScanPipeline` glues together:

1. JADX decompilation (lazy, cached via :mod:`app.services.jadx_service`)
2. :mod:`app.services._cache` lookup (analysis_cache table keyed by APK SHA-256)
3. :func:`~app.services.mobsfscan.parser.run_mobsfscan` CLI invocation
4. :func:`~app.services.mobsfscan.normalization.normalize_mobsfscan_findings`
   post-processing (severity overrides, priv-app bump, dedup, min-severity filter)
5. :func:`~app.services.mobsfscan.normalization.persist_mobsfscan_findings`
   persistence to the ``findings`` table
6. :func:`~app.services.mobsfscan.normalization.format_mobsfscan_text`
   human-readable output formatting

A per-APK-SHA-256 concurrency guard prevents duplicate scans of the
same binary (matching the jadx_service pattern).

The module exposes the singleton :data:`_pipeline` via
:func:`get_mobsfscan_pipeline` so MCP tools and REST handlers share state.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.services import _cache
from app.services.jadx_service import get_jadx_cache
from app.services.mobsfscan.normalization import (
    NormalizedFinding,
    format_mobsfscan_text,
    normalize_mobsfscan_findings,
    persist_mobsfscan_findings,
)
from app.services.mobsfscan.parser import (
    MobsfScanFinding,
    MobsfScanResult,
    run_mobsfscan,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.utils.firmware_context import FirmwareContext

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Orchestration dataclass — full pipeline result
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MobsfScanPipelineResult:
    """Complete result of the mobsfscan orchestration pipeline.

    Aggregates scan results, normalized findings, persistence counts,
    and formatted text output — everything downstream consumers need.
    """

    scan_result: MobsfScanResult
    normalized: list[NormalizedFinding]
    persisted_count: int = 0
    cached: bool = False  # True if result was served from the analysis_cache table
    text_output: str = ""
    # Phase timing (milliseconds)
    total_elapsed_ms: int = 0  # wall-clock time for the entire pipeline
    jadx_elapsed_ms: int = 0  # time spent in JADX decompilation
    mobsfscan_elapsed_ms: int = 0  # time spent in mobsfscan scanning

    @property
    def summary(self) -> dict[str, Any]:
        """Compact summary dict for API responses and MCP tool output."""
        return {
            **self.scan_result.summary,
            "normalized_findings": len(self.normalized),
            "persisted_count": self.persisted_count,
            "cached": self.cached,
            "total_elapsed_ms": self.total_elapsed_ms,
            "jadx_elapsed_ms": self.jadx_elapsed_ms,
            "mobsfscan_elapsed_ms": self.mobsfscan_elapsed_ms,
        }


# ---------------------------------------------------------------------------
# MobsfScanPipeline — end-to-end orchestration
# ---------------------------------------------------------------------------

#: ``analysis_cache.operation`` key for cached mobsfscan results.
_CACHE_OP = "mobsfscan_scan"

#: Total pipeline budget (seconds).  The 3-minute cap is shared across
#: JADX decompilation + mobsfscan scanning.  After JADX completes, the
#: remaining budget is passed to mobsfscan as its timeout.
_PIPELINE_BUDGET_SECONDS: int = 600


def _sources_ready_sync(source_dir: str) -> bool:
    """Synchronous helper: source_dir exists AND is non-empty.

    Combines two stat-family calls (isdir + listdir) into one executor hop
    so a single ``loop.run_in_executor`` call is sufficient (Rule #5).
    """
    return os.path.isdir(source_dir) and bool(os.listdir(source_dir))


class MobsfScanPipeline:
    """Orchestrates the full mobsfscan SAST scanning pipeline.

    Responsibilities:

    1. Accept either a **JADX output directory** (already decompiled) or
       an **APK path** (triggers lazy decompilation via jadx_service).
    2. If sources live in the ``analysis_cache`` table (JSONB),
       materialise them to a temporary directory for mobsfscan CLI
       consumption.
    3. Invoke ``run_mobsfscan()`` with configurable timeout.
    4. Parse + normalise findings with firmware-context severity adjustments.
    5. Cache raw scan results in the ``analysis_cache`` table (keyed by
       APK SHA-256).
    6. Persist normalised findings to the ``findings`` table via ``flush()``.
    7. Return a :class:`MobsfScanPipelineResult` with everything bundled.

    The pipeline includes a concurrency guard so only one scan per APK
    SHA-256 runs at a time (matching the jadx_service pattern).
    """

    def __init__(self) -> None:
        self._scan_locks: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Cache helpers (thin wrappers over app.services._cache)
    # ------------------------------------------------------------------

    async def _get_cached_result(
        self,
        firmware_id: uuid.UUID,
        apk_sha256: str,
        db: AsyncSession,
    ) -> dict | None:
        """Retrieve a previously cached mobsfscan result."""
        return await _cache.get_cached(
            db, firmware_id, _CACHE_OP, binary_sha256=apk_sha256,
        )

    async def _store_cached_result(
        self,
        firmware_id: uuid.UUID,
        apk_path: str,
        apk_sha256: str,
        result_data: dict,
        db: AsyncSession,
    ) -> None:
        """Store a mobsfscan result (delete-then-insert upsert)."""
        await _cache.store_cached(
            db,
            firmware_id,
            _CACHE_OP,
            result_data,
            binary_sha256=apk_sha256,
            binary_path=apk_path,
        )

    # ------------------------------------------------------------------
    # Rebuild helpers — reconstruct dataclasses from cached dicts
    # ------------------------------------------------------------------

    @staticmethod
    def _rebuild_scan_result(cached: dict) -> MobsfScanResult:
        """Reconstruct a :class:`MobsfScanResult` from cached JSONB data."""
        findings: list[MobsfScanFinding] = []
        for fd in cached.get("findings", []):
            findings.append(
                MobsfScanFinding(
                    rule_id=fd.get("rule_id", ""),
                    title=fd.get("title", ""),
                    description=fd.get("description", ""),
                    severity=fd.get("severity", "INFO"),
                    section=fd.get("section", ""),
                    file_path=fd.get("file_path", ""),
                    line_number=fd.get("line_number", 0),
                    match_string=fd.get("match_string", ""),
                    cwe=fd.get("cwe", ""),
                    owasp_mobile=fd.get("owasp_mobile", ""),
                    masvs=fd.get("masvs", ""),
                    metadata=fd.get("metadata", {}),
                )
            )
        return MobsfScanResult(
            success=cached.get("success", True),
            findings=findings,
            raw_json=cached.get("raw_json"),
            scan_duration_ms=cached.get("scan_duration_ms", 0),
            files_scanned=cached.get("files_scanned", 0),
            suppressed_rule_count=cached.get("suppressed_rule_count", 0),
            suppressed_path_count=cached.get("suppressed_path_count", 0),
        )

    @staticmethod
    def _serialize_scan_result(result: MobsfScanResult) -> dict:
        """Serialise a :class:`MobsfScanResult` to a dict for JSONB storage."""
        serialised_findings = []
        for f in result.findings:
            serialised_findings.append({
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "section": f.section,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "match_string": f.match_string[:1000],  # cap for JSONB
                "cwe": f.cwe,
                "owasp_mobile": f.owasp_mobile,
                "masvs": f.masvs,
                "metadata": f.metadata,
            })
        return {
            "success": result.success,
            "findings": serialised_findings,
            "raw_json": None,  # raw_json can be huge; omit from cache
            "scan_duration_ms": result.scan_duration_ms,
            "files_scanned": result.files_scanned,
            "error": result.error,
            "suppressed_rule_count": result.suppressed_rule_count,
            "suppressed_path_count": result.suppressed_path_count,
        }

    # ------------------------------------------------------------------
    # Source materialisation
    # ------------------------------------------------------------------

    @staticmethod
    async def _materialise_sources_from_cache(
        apk_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
        target_dir: str,
    ) -> str:
        """Write cached JADX sources to disk for mobsfscan consumption.

        Uses :meth:`JadxDecompilationCache.write_sources_to_disk`.
        """
        cache = get_jadx_cache()
        return await cache.write_sources_to_disk(
            apk_path, firmware_id, db, target_dir,
        )

    @staticmethod
    async def _ensure_decompilation(
        apk_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> str:
        """Ensure JADX has decompiled the APK; returns the SHA-256 hash."""
        cache = get_jadx_cache()
        return await cache.ensure_decompilation(apk_path, firmware_id, db)

    # ------------------------------------------------------------------
    # Public API — scan_apk (full pipeline from APK path)
    # ------------------------------------------------------------------

    async def scan_apk(
        self,
        *,
        apk_path: str,
        firmware_id: uuid.UUID,
        project_id: uuid.UUID,
        db: AsyncSession,
        apk_rel_path: str = "",
        timeout: int | None = None,  # noqa: ASYNC109 — caller-supplied per-scan override; falls through to _PIPELINE_BUDGET_SECONDS
        min_severity: str = "info",
        persist: bool = True,
        use_cache: bool = True,
        fw_ctx: FirmwareContext | None = None,
    ) -> MobsfScanPipelineResult:
        """Run the full jadx → mobsfscan pipeline against an APK.

        This is the primary entry point for MCP tools and REST endpoints.
        The pipeline runs sequentially with a shared timeout budget
        (default ``_PIPELINE_BUDGET_SECONDS`` = 180 s / 3 minutes):

        1. **JADX decompilation** (lazy, cached) — consumes part of the budget.
        2. Check the ``analysis_cache`` table for prior mobsfscan results.
        3. **mobsfscan SAST scan** — gets the *remaining* budget as its timeout.
        4. Cache scan results in the ``analysis_cache`` table.
        5. Normalise findings with firmware-context severity adjustments.
        6. Optionally persist findings to the ``findings`` table.
        7. Format human-readable text output.

        Total elapsed time and per-phase timing are recorded on the
        returned :class:`MobsfScanPipelineResult`.

        Parameters
        ----------
        apk_path:
            Absolute path to the APK file.
        firmware_id:
            UUID of the firmware the APK belongs to.
        project_id:
            UUID of the project (for finding persistence).
        db:
            Async SQLAlchemy session.
        apk_rel_path:
            Relative path of the APK within firmware extraction root.
            Used for priv-app severity bump and display.
        timeout:
            Total pipeline budget in seconds.  Defaults to
            ``_PIPELINE_BUDGET_SECONDS`` (180 s).  The budget is shared:
            after JADX finishes, the remainder is given to mobsfscan.
        min_severity:
            Minimum severity threshold for normalised findings.
        persist:
            Whether to write findings to the ``findings`` table.
        use_cache:
            Whether to check/store the ``analysis_cache`` table.  Set
            ``False`` to force a rescan.
        fw_ctx:
            Optional :class:`FirmwareContext` for enriching finding
            descriptions with device/firmware metadata.

        Returns
        -------
        MobsfScanPipelineResult
            Complete pipeline result with scan data, findings, timing,
            and formatted text.

        Raises
        ------
        FileNotFoundError
            If the APK path does not exist.
        RuntimeError
            If mobsfscan is not installed or JADX decompilation fails.
        TimeoutError
            If the total pipeline budget is exhausted.
        """
        loop = asyncio.get_running_loop()
        if not await loop.run_in_executor(None, os.path.isfile, apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")

        budget = timeout or _PIPELINE_BUDGET_SECONDS
        pipeline_t0 = time.monotonic()

        # ------------------------------------------------------------------
        # Phase 1: JADX decompilation (lazy, cached, concurrency-guarded)
        # ------------------------------------------------------------------
        jadx_t0 = time.monotonic()
        try:
            apk_sha256 = await asyncio.wait_for(
                self._ensure_decompilation(apk_path, firmware_id, db),
                timeout=budget,
            )
        except TimeoutError:
            elapsed_ms = int((time.monotonic() - pipeline_t0) * 1000)
            logger.error(
                "Pipeline budget exhausted during JADX decompilation for %s "
                "(%ds budget)",
                os.path.basename(apk_path),
                budget,
            )
            raise TimeoutError(
                f"Pipeline budget ({budget}s) exhausted during JADX "
                f"decompilation of {os.path.basename(apk_path)} "
                f"after {elapsed_ms}ms"
            )
        jadx_elapsed_ms = int((time.monotonic() - jadx_t0) * 1000)

        # ------------------------------------------------------------------
        # Check remaining budget
        # ------------------------------------------------------------------
        elapsed_so_far = time.monotonic() - pipeline_t0
        remaining_budget = max(budget - elapsed_so_far, 0)

        if remaining_budget < 5:
            # Less than 5 s left — not enough for a meaningful scan
            total_ms = int((time.monotonic() - pipeline_t0) * 1000)
            logger.warning(
                "Only %.1fs remaining after JADX — skipping mobsfscan for %s",
                remaining_budget,
                os.path.basename(apk_path),
            )
            empty_result = MobsfScanResult(
                success=False,
                error=(
                    f"Pipeline budget exhausted: JADX took {jadx_elapsed_ms}ms, "
                    f"only {remaining_budget:.1f}s remaining (need ≥5s for scan)"
                ),
                scan_duration_ms=0,
            )
            return MobsfScanPipelineResult(
                scan_result=empty_result,
                normalized=[],
                total_elapsed_ms=total_ms,
                jadx_elapsed_ms=jadx_elapsed_ms,
                mobsfscan_elapsed_ms=0,
            )

        # ------------------------------------------------------------------
        # Phase 1.5: Check cache (fast, no budget concern)
        # ------------------------------------------------------------------
        if use_cache:
            cached_data = await self._get_cached_result(
                firmware_id, apk_sha256, db,
            )
            if cached_data is not None:
                logger.info(
                    "mobsfscan cache hit for %s (sha256=%s)",
                    os.path.basename(apk_path),
                    apk_sha256[:12],
                )
                scan_result = self._rebuild_scan_result(cached_data)
                normalized = normalize_mobsfscan_findings(
                    scan_result,
                    apk_rel_path=apk_rel_path,
                    min_severity=min_severity,
                )
                persisted = 0
                if persist and normalized:
                    persisted = await persist_mobsfscan_findings(
                        db, project_id, firmware_id, normalized,
                        fw_ctx=fw_ctx,
                    )
                total_ms = int((time.monotonic() - pipeline_t0) * 1000)
                text = format_mobsfscan_text(
                    scan_result, normalized, apk_rel_path,
                    jadx_elapsed_ms=jadx_elapsed_ms,
                    total_elapsed_ms=total_ms,
                )
                return MobsfScanPipelineResult(
                    scan_result=scan_result,
                    normalized=normalized,
                    persisted_count=persisted,
                    cached=True,
                    text_output=text,
                    total_elapsed_ms=total_ms,
                    jadx_elapsed_ms=jadx_elapsed_ms,
                    mobsfscan_elapsed_ms=scan_result.scan_duration_ms,
                )

        # ------------------------------------------------------------------
        # Phase 2: mobsfscan SAST scan (gets remaining budget)
        # ------------------------------------------------------------------
        mobsfscan_timeout = int(remaining_budget)
        logger.info(
            "Running mobsfscan with %ds remaining budget (JADX took %dms)",
            mobsfscan_timeout,
            jadx_elapsed_ms,
        )

        mobsfscan_t0 = time.monotonic()
        scan_result = await self._run_with_guard(
            apk_path=apk_path,
            apk_sha256=apk_sha256,
            firmware_id=firmware_id,
            db=db,
            timeout=mobsfscan_timeout,
        )
        mobsfscan_elapsed_ms = int((time.monotonic() - mobsfscan_t0) * 1000)

        # ------------------------------------------------------------------
        # Post-scan: cache, normalise, persist, format
        # ------------------------------------------------------------------
        if use_cache and scan_result.success:
            await self._store_cached_result(
                firmware_id,
                apk_path,
                apk_sha256,
                self._serialize_scan_result(scan_result),
                db,
            )

        normalized = normalize_mobsfscan_findings(
            scan_result,
            apk_rel_path=apk_rel_path,
            min_severity=min_severity,
        )

        persisted = 0
        if persist and normalized:
            persisted = await persist_mobsfscan_findings(
                db, project_id, firmware_id, normalized,
                fw_ctx=fw_ctx,
            )

        total_elapsed_ms = int((time.monotonic() - pipeline_t0) * 1000)
        text = format_mobsfscan_text(
            scan_result, normalized, apk_rel_path,
            jadx_elapsed_ms=jadx_elapsed_ms,
            total_elapsed_ms=total_elapsed_ms,
        )

        return MobsfScanPipelineResult(
            scan_result=scan_result,
            normalized=normalized,
            persisted_count=persisted,
            cached=False,
            text_output=text,
            total_elapsed_ms=total_elapsed_ms,
            jadx_elapsed_ms=jadx_elapsed_ms,
            mobsfscan_elapsed_ms=mobsfscan_elapsed_ms,
        )

    # ------------------------------------------------------------------
    # Public API — scan_source_dir (from pre-existing JADX output)
    # ------------------------------------------------------------------

    async def scan_source_dir(
        self,
        *,
        source_dir: str,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID | None = None,
        db: AsyncSession,
        apk_rel_path: str = "",
        timeout: int | None = None,  # noqa: ASYNC109 — caller-supplied per-scan override; falls through to _PIPELINE_BUDGET_SECONDS
        min_severity: str = "info",
        persist: bool = True,
    ) -> MobsfScanPipelineResult:
        """Run mobsfscan against a pre-existing JADX output directory.

        Use this when decompiled sources are already on disk (e.g. an
        extracted firmware that shipped with Java source, or a directory
        prepared by the caller).  No caching or decompilation is performed.

        Parameters
        ----------
        source_dir:
            Absolute path to the directory containing Java/Kotlin sources.
        project_id:
            UUID of the project for finding persistence.
        firmware_id:
            UUID of the firmware (nullable for standalone APKs).
        db:
            Async SQLAlchemy session.
        apk_rel_path:
            Display path for findings.
        timeout:
            Mobsfscan timeout in seconds.
        min_severity:
            Minimum severity for normalised findings.
        persist:
            Whether to write findings to the ``findings`` table.

        Returns
        -------
        MobsfScanPipelineResult

        Raises
        ------
        FileNotFoundError
            If *source_dir* does not exist.
        RuntimeError
            If mobsfscan is not installed.
        """
        scan_result = await run_mobsfscan(source_dir, timeout=timeout)

        normalized = normalize_mobsfscan_findings(
            scan_result,
            apk_rel_path=apk_rel_path,
            min_severity=min_severity,
        )

        persisted = 0
        if persist and normalized:
            persisted = await persist_mobsfscan_findings(
                db, project_id, firmware_id, normalized,
            )

        text = format_mobsfscan_text(scan_result, normalized, apk_rel_path)

        return MobsfScanPipelineResult(
            scan_result=scan_result,
            normalized=normalized,
            persisted_count=persisted,
            cached=False,
            text_output=text,
        )

    # ------------------------------------------------------------------
    # Internal — concurrency-guarded scan execution
    # ------------------------------------------------------------------

    async def _run_with_guard(
        self,
        *,
        apk_path: str,
        apk_sha256: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
        timeout: int | None,  # noqa: ASYNC109 — caller-supplied timeout threaded through from scan_apk
    ) -> MobsfScanResult:
        """Execute mobsfscan with a per-APK concurrency guard.

        If another coroutine is already scanning the same APK (by SHA-256),
        this coroutine waits for it to finish and then reads from cache.
        """
        should_scan = False
        async with self._lock:
            event = self._scan_locks.get(apk_sha256)
            if event is not None:
                pass  # Another coroutine is scanning — we'll wait
            else:
                event = asyncio.Event()
                self._scan_locks[apk_sha256] = event
                should_scan = True

        if not should_scan:
            # Wait for the other coroutine to finish, then try cache
            await event.wait()
            cached = await self._get_cached_result(firmware_id, apk_sha256, db)
            if cached is not None:
                return self._rebuild_scan_result(cached)
            # Fallthrough: cache miss after wait (shouldn't happen, but
            # be defensive — just run the scan ourselves)

        try:
            return await self._execute_scan(
                apk_path=apk_path,
                firmware_id=firmware_id,
                db=db,
                timeout=timeout,
            )
        finally:
            if should_scan:
                async with self._lock:
                    self._scan_locks.pop(apk_sha256, None)
                event.set()

    async def _execute_scan(
        self,
        *,
        apk_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
        timeout: int | None,  # noqa: ASYNC109 — caller-supplied timeout threaded through from scan_apk
    ) -> MobsfScanResult:
        """Materialise cached sources to a temp dir and run mobsfscan."""
        with tempfile.TemporaryDirectory(prefix="mobsfscan_") as tmp_dir:
            source_dir = os.path.join(tmp_dir, "sources")

            # Write decompiled sources from the analysis_cache table to disk
            await self._materialise_sources_from_cache(
                apk_path, firmware_id, db, source_dir,
            )

            # Verify sources were written
            loop = asyncio.get_running_loop()
            sources_ready = await loop.run_in_executor(
                None, _sources_ready_sync, source_dir,
            )
            if not sources_ready:
                return MobsfScanResult(
                    success=True,  # Not an error — resource-only APKs have no code
                    error=(
                        "No decompiled sources found — this APK contains no "
                        "DEX bytecode (resource-only package). SAST analysis "
                        "is not applicable."
                    ),
                )

            return await run_mobsfscan(source_dir, timeout=timeout)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_pipeline = MobsfScanPipeline()


def get_mobsfscan_pipeline() -> MobsfScanPipeline:
    """Get the module-level MobsfScanPipeline singleton."""
    return _pipeline
