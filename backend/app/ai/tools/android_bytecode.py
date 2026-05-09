"""Phase 2a: Android APK bytecode analysis MCP tool.

Provides an MCP tool for scanning APK DEX bytecode for insecure API
usage patterns using Androguard's analysis framework. Results are
cached in the ``analysis_cache`` table (SHA256-keyed) via
:mod:`app.services._cache`, and findings persisted to the project
findings database via flush().
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from typing import TYPE_CHECKING

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.ai.tools._android_helpers import check_androguard, find_apk

if TYPE_CHECKING:
    from app.utils.firmware_context import FirmwareContext

logger = logging.getLogger(__name__)


def register_android_bytecode_tools(registry: ToolRegistry) -> None:
    """Register Phase 2a bytecode analysis tools."""

    registry.register(
        name="scan_apk_bytecode",
        description=(
            "Phase 2a: Scan APK DEX bytecode for insecure API usage patterns. "
            "Detects: insecure crypto (ECB, DES, static keys/IVs), cleartext HTTP, "
            "disabled certificate validation, world-readable/writable files, "
            "Runtime.exec, insecure WebView settings, SQL injection vectors, "
            "insecure random, clipboard data leaks, and more (~30 patterns). "
            "Results are cached by APK hash. Completes under 30s per APK."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "app_name": {
                    "type": "string",
                    "description": (
                        "App directory name (e.g. 'Settings', 'Chrome') — "
                        "searched in standard Android app directories"
                    ),
                },
                "path": {
                    "type": "string",
                    "description": "Direct firmware path to the APK file (e.g. /system/app/Settings/Settings.apk)",
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Minimum severity to include in output (default: low)",
                },
                "min_confidence": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": (
                        "Minimum confidence threshold to include findings (default: low). "
                        "Use 'medium' or 'high' to suppress noisy low-confidence matches "
                        "like reflection usage, logging, and Base64 encoding."
                    ),
                },
            },
        },
        handler=_handle_scan_apk_bytecode,
    )


# ---------------------------------------------------------------------------
# Helpers (shared via _android_helpers.py)
# ---------------------------------------------------------------------------


def _compute_file_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _get_apk_firmware_location(apk_path: str, extracted_root: str) -> str | None:
    """Get the firmware-relative location of an APK for context-aware severity."""
    try:
        return "/" + os.path.relpath(apk_path, extracted_root)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Tool handler
# ---------------------------------------------------------------------------


async def _handle_scan_apk_bytecode(input: dict, context: ToolContext) -> str:
    """Scan APK bytecode for insecure API patterns with caching."""
    err = check_androguard()
    if err:
        return err

    try:
        apk_path = find_apk(context, input.get("app_name"), input.get("path"))
    except ValueError as exc:
        return str(exc)

    min_severity = input.get("min_severity", "low")
    severity_order = ["info", "low", "medium", "high", "critical"]
    if min_severity not in severity_order:
        min_severity = "low"
    min_idx = severity_order.index(min_severity)

    # Confidence threshold filtering
    from app.services.bytecode_analysis_service import CONFIDENCE_ORDER
    min_confidence = input.get("min_confidence", "low")
    if min_confidence not in CONFIDENCE_ORDER:
        min_confidence = "low"
    min_conf_idx = CONFIDENCE_ORDER.index(min_confidence)

    # Check cache first (SHA256-based dedup)
    loop = asyncio.get_event_loop()
    apk_sha256 = await loop.run_in_executor(None, _compute_file_sha256, apk_path)

    cached_result = None
    if context.db and context.firmware_id:
        cached_result = await _get_cached_bytecode_result(
            context, apk_sha256
        )

    if cached_result is not None:
        result = cached_result
        result["from_cache"] = True
        logger.info(
            "Bytecode scan cache hit for %s (sha256=%s)",
            os.path.basename(apk_path),
            apk_sha256[:12],
        )
    else:
        # Run bytecode analysis in executor (CPU-bound)
        apk_location = _get_apk_firmware_location(
            apk_path, context.extracted_path
        )

        from app.services.bytecode_analysis_service import BytecodeAnalysisService

        svc = BytecodeAnalysisService()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: svc.scan_apk(
                    apk_path,
                    apk_location=apk_location,
                    timeout=30.0,
                ),
            )
        except Exception as exc:
            return f"Error during bytecode analysis: {exc}"

        result["from_cache"] = False

        # Cache the result
        if context.db and context.firmware_id:
            try:
                await _cache_bytecode_result(
                    context, apk_path, apk_sha256, result
                )
            except Exception as exc:
                logger.warning("Failed to cache bytecode result: %s", exc)

    # Resolve firmware context for finding enrichment
    fw_ctx = None
    if context.db and context.firmware_id:
        try:
            from app.utils.firmware_context import get_firmware_context

            fw_ctx = await get_firmware_context(
                context.db, context.firmware_id,
                apk_path=apk_path,
                extracted_root=context.extracted_path,
            )
        except Exception as exc:
            logger.debug("Failed to resolve firmware context: %s", exc)

    # Persist findings to project findings database via flush()
    if context.db and result.get("findings"):
        try:
            await _persist_bytecode_findings(
                context, result, apk_path, min_idx, severity_order,
                min_conf_idx=min_conf_idx,
                fw_ctx=fw_ctx,
            )
        except Exception as exc:
            logger.warning("Failed to persist bytecode findings: %s", exc)

    # Format output with severity + confidence filter
    return _format_bytecode_scan(
        result, apk_path, context.extracted_path,
        min_idx, severity_order,
        min_conf_idx=min_conf_idx,
        fw_ctx=fw_ctx,
    )


# ---------------------------------------------------------------------------
# Cache helpers (thin wrappers over app.services._cache)
# ---------------------------------------------------------------------------


async def _get_cached_bytecode_result(
    context: ToolContext,
    apk_sha256: str,
) -> dict | None:
    """Check the bytecode_scan cache for existing results."""
    from app.services import _cache

    return await _cache.get_cached(
        context.db,
        context.firmware_id,
        "bytecode_scan",
        binary_sha256=apk_sha256,
    )


async def _cache_bytecode_result(
    context: ToolContext,
    apk_path: str,
    apk_sha256: str,
    result: dict,
) -> None:
    """Store bytecode scan results (delete-then-insert upsert)."""
    from app.services import _cache

    rel_path = os.path.relpath(apk_path, context.extracted_path)
    await _cache.store_cached(
        context.db,
        context.firmware_id,
        "bytecode_scan",
        result,
        binary_sha256=apk_sha256,
        binary_path=rel_path,
    )


# ---------------------------------------------------------------------------
# Finding persistence
# ---------------------------------------------------------------------------


async def _persist_bytecode_findings(
    context: ToolContext,
    result: dict,
    apk_path: str,
    min_severity_idx: int,
    severity_order: list[str],
    *,
    min_conf_idx: int = 0,
    fw_ctx: FirmwareContext | None = None,
) -> None:
    """Write bytecode findings to the Finding table via flush().

    When *fw_ctx* is provided, finding descriptions and evidence are
    enriched with firmware metadata (device model, Android version, etc.).
    Findings below *min_conf_idx* confidence threshold are skipped.
    """
    from app.models.finding import Finding
    from app.services.bytecode_analysis_service import CONFIDENCE_ORDER

    rel_path = os.path.relpath(apk_path, context.extracted_path)
    package = result.get("package", "unknown")

    for f in result["findings"]:
        sev = f.get("severity", "medium")
        sev_idx = severity_order.index(sev) if sev in severity_order else 2
        if sev_idx < min_severity_idx:
            continue

        # Apply confidence threshold
        conf = f.get("confidence", "high")
        conf_idx = CONFIDENCE_ORDER.index(conf) if conf in CONFIDENCE_ORDER else 2
        if conf_idx < min_conf_idx:
            continue

        # Build evidence from locations
        evidence_parts = [f"Package: {package}"]
        for loc in f.get("locations", [])[:5]:
            if "caller_class" in loc:
                evidence_parts.append(
                    f"  Called from: {loc['caller_class']}.{loc.get('caller_method', '?')} -> {loc.get('target', '?')}"
                )
            elif "string_value" in loc:
                evidence_parts.append(f"  String: {loc['string_value']}")
            elif "using_class" in loc:
                evidence_parts.append(
                    f"  Used in: {loc['using_class']}.{loc.get('using_method', '?')}"
                )
        total = f.get("total_occurrences", 0)
        if total > 5:
            evidence_parts.append(f"  ... and {total - 5} more occurrences")

        description = f["description"]
        evidence = "\n".join(evidence_parts)

        # Enrich with firmware context when available
        if fw_ctx:
            from app.utils.firmware_context import enrich_description, enrich_evidence
            description = enrich_description(description, fw_ctx)
            evidence = enrich_evidence(evidence, fw_ctx)

        finding = Finding(
            project_id=context.project_id,
            firmware_id=context.firmware_id,
            title=f"[{f['pattern_id']}] {f['title']}",
            severity=sev,
            confidence=conf,
            description=description,
            evidence=evidence,
            file_path=rel_path,
            cwe_ids=f.get("cwe_ids") or None,
            source="apk-bytecode-scan",
        )
        context.db.add(finding)

    await context.db.flush()


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------


def _format_bytecode_scan(
    result: dict,
    apk_path: str,
    extracted_root: str,
    min_severity_idx: int,
    severity_order: list[str],
    *,
    min_conf_idx: int = 0,
    fw_ctx: FirmwareContext | None = None,
) -> str:
    """Format bytecode scan results into readable MCP tool output."""
    from app.services.bytecode_analysis_service import CONFIDENCE_ORDER

    package = result.get("package", "unknown")
    rel_path = os.path.relpath(apk_path, extracted_root)
    from_cache = result.get("from_cache", False)
    elapsed = result.get("elapsed_seconds", 0)

    lines = [
        f"APK Bytecode Security Scan: {package}",
        f"File: {rel_path}",
        f"DEX files: {result.get('dex_count', 'N/A')}",
        f"Elapsed: {elapsed}s{' (cached)' if from_cache else ''}",
    ]

    # Include firmware context summary if available
    if fw_ctx and not fw_ctx.is_empty:
        ctx_summary = fw_ctx.summary_line()
        if ctx_summary:
            lines.append(f"Firmware: {ctx_summary}")

    lines.append("")

    # Error case
    if result.get("error"):
        lines.append(f"Error: {result['error']}")
        return "\n".join(lines)

    # Summary
    summary = result.get("summary", {})
    total = summary.get("total_findings", 0)
    by_severity = summary.get("by_severity", {})
    by_category = summary.get("by_category", {})
    by_confidence = summary.get("by_confidence", {})

    lines.append(f"Total findings: {total}")
    if by_severity:
        sev_parts = []
        for s in reversed(severity_order):
            cnt = by_severity.get(s, 0)
            if cnt:
                sev_parts.append(f"{s.upper()}: {cnt}")
        lines.append(f"By severity: {', '.join(sev_parts)}")
    if by_confidence:
        conf_parts = []
        for c in reversed(CONFIDENCE_ORDER):
            cnt = by_confidence.get(c, 0)
            if cnt:
                conf_parts.append(f"{c}: {cnt}")
        lines.append(f"By confidence: {', '.join(conf_parts)}")
    if by_category:
        cat_parts = [f"{k}: {v}" for k, v in sorted(by_category.items())]
        lines.append(f"By category: {', '.join(cat_parts)}")
    lines.append("")

    # Findings (filtered by min_severity AND min_confidence)
    findings = result.get("findings", [])
    filtered = []
    suppressed_by_confidence = 0
    for f in findings:
        sev = f.get("severity", "medium")
        sev_idx = severity_order.index(sev) if sev in severity_order else 2
        if sev_idx < min_severity_idx:
            continue
        conf = f.get("confidence", "high")
        conf_idx = CONFIDENCE_ORDER.index(conf) if conf in CONFIDENCE_ORDER else 2
        if conf_idx < min_conf_idx:
            suppressed_by_confidence += 1
            continue
        filtered.append(f)

    if not filtered:
        if total > 0:
            parts = []
            if min_severity_idx > 0:
                parts.append(
                    f"severity threshold '{severity_order[min_severity_idx]}'"
                )
            if min_conf_idx > 0:
                parts.append(
                    f"confidence threshold '{CONFIDENCE_ORDER[min_conf_idx]}'"
                )
            threshold_desc = " and ".join(parts) if parts else "filters"
            lines.append(
                f"All {total} findings are below the {threshold_desc}. "
                "Use min_severity='info' and min_confidence='low' to see all."
            )
        else:
            lines.append("No insecure API patterns detected in bytecode.")
        return "\n".join(lines)

    if suppressed_by_confidence > 0:
        lines.append(
            f"({suppressed_by_confidence} low-confidence finding(s) suppressed — "
            f"use min_confidence='low' to include)"
        )
        lines.append("")

    # Sort by severity (critical first), then by confidence (high first)
    filtered.sort(
        key=lambda f: (
            severity_order.index(f.get("severity", "medium"))
            if f.get("severity", "medium") in severity_order
            else 2,
            CONFIDENCE_ORDER.index(f.get("confidence", "high"))
            if f.get("confidence", "high") in CONFIDENCE_ORDER
            else 2,
        ),
        reverse=True,
    )

    for f in filtered:
        sev = f.get("severity", "medium").upper()
        conf = f.get("confidence", "high")
        conf_tag = f" [confidence:{conf}]" if conf != "high" else ""
        lines.append(f"[{sev}] {f['title']} ({f.get('pattern_id', '?')}){conf_tag}")
        lines.append(f"  {f.get('description', '')}")
        cwe = f.get("cwe_ids", [])
        if cwe:
            lines.append(f"  CWE: {', '.join(cwe)}")
        locs = f.get("locations", [])
        total_occ = f.get("total_occurrences", len(locs))
        if locs:
            for loc in locs[:5]:
                if "caller_class" in loc:
                    lines.append(
                        f"    -> {loc['caller_class']}.{loc.get('caller_method', '?')}"
                    )
                elif "string_value" in loc:
                    lines.append(f"    -> \"{loc['string_value']}\"")
                elif "using_class" in loc:
                    lines.append(
                        f"    -> {loc['using_class']}.{loc.get('using_method', '?')}"
                    )
                elif "target" in loc:
                    lines.append(f"    -> {loc['target']}")
            if total_occ > 5:
                lines.append(f"    ... {total_occ - 5} more occurrence(s)")
        elif total_occ:
            lines.append(f"    {total_occ} occurrence(s)")
        lines.append("")

    return "\n".join(lines)
