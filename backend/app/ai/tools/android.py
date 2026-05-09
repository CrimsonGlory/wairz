"""Android APK analysis AI tools.

Tools for deep analysis of Android APK files found in firmware using
Androguard: permissions, components, signatures, and security checks.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.ai.tools._android_helpers import (
    check_androguard,
    find_apk,
    is_priv_app_path,
)

if TYPE_CHECKING:
    from app.utils.firmware_context import FirmwareContext

logger = logging.getLogger(__name__)


def register_android_tools(registry: ToolRegistry) -> None:
    """Register all Android APK analysis tools with the given registry."""

    registry.register(
        name="analyze_apk",
        description=(
            "Deep-analyse an Android APK file found in the firmware. "
            "Returns package name, SDK versions, permissions, activities, "
            "services, receivers, providers, and signature info. "
            "Accepts an app name (looked up in system/app, system/priv-app, etc.) "
            "or a direct path to the APK file."
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
            },
        },
        handler=_handle_analyze_apk,
    )

    registry.register(
        name="list_apk_permissions",
        description=(
            "List permissions declared by an Android APK with risk levels "
            "(dangerous, signature, normal). Useful for quick security "
            "assessment of an app's permission footprint."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "app_name": {
                    "type": "string",
                    "description": "App directory name (e.g. 'Settings')",
                },
                "path": {
                    "type": "string",
                    "description": "Direct firmware path to the APK file",
                },
            },
        },
        handler=_handle_list_apk_permissions,
    )

    registry.register(
        name="check_apk_signatures",
        description=(
            "Verify APK signing certificates and check for security issues: "
            "unsigned APKs, debug/test certificates, weak signature algorithms. "
            "Important for assessing firmware supply chain integrity."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "app_name": {
                    "type": "string",
                    "description": "App directory name (e.g. 'Settings')",
                },
                "path": {
                    "type": "string",
                    "description": "Direct firmware path to the APK file",
                },
            },
        },
        handler=_handle_check_apk_signatures,
    )

    registry.register(
        name="scan_apk_manifest",
        description=(
            "Run manifest-level security checks on an Android APK. "
            "Detects insecure manifest flags: debuggable, allowBackup, "
            "usesCleartextTraffic, testOnly, and outdated minSdkVersion. "
            "Automatically detects firmware context (priv-app, platform signing) "
            "to adjust severity. Returns findings AND persists them to the "
            "project findings database."
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
            },
        },
        handler=_handle_scan_apk_manifest,
    )


# ---------------------------------------------------------------------------
# Helpers (shared via _android_helpers.py)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_analyze_apk(input: dict, context: ToolContext) -> str:
    """Analyse an APK and return a formatted summary."""
    err = check_androguard()
    if err:
        return err

    try:
        apk_path = find_apk(context, input.get("app_name"), input.get("path"))
    except ValueError as exc:
        return str(exc)

    from app.services.androguard_service import AndroguardService

    svc = AndroguardService()
    loop = asyncio.get_event_loop()
    try:
        info = await loop.run_in_executor(None, svc.analyze_apk, apk_path)
    except Exception as exc:
        return f"Error analysing APK: {exc}"

    return _format_apk_analysis(info)


async def _handle_list_apk_permissions(input: dict, context: ToolContext) -> str:
    """List APK permissions with risk levels."""
    err = check_androguard()
    if err:
        return err

    try:
        apk_path = find_apk(context, input.get("app_name"), input.get("path"))
    except ValueError as exc:
        return str(exc)

    from app.services.androguard_service import AndroguardService

    svc = AndroguardService()
    loop = asyncio.get_event_loop()
    try:
        perms = await loop.run_in_executor(
            None, svc.get_permissions_with_risk, apk_path
        )
    except Exception as exc:
        return f"Error extracting permissions: {exc}"

    if not perms:
        return "This APK declares no permissions."

    dangerous = [p for p in perms if p["risk"] == "dangerous"]
    signature = [p for p in perms if p["risk"] == "signature"]
    normal = [p for p in perms if p["risk"] == "normal"]

    lines = [f"Permissions for APK ({len(perms)} total):\n"]

    if dangerous:
        lines.append(f"DANGEROUS ({len(dangerous)}):")
        for p in dangerous:
            lines.append(f"  - {p['permission']}")

    if signature:
        lines.append(f"\nSIGNATURE ({len(signature)}):")
        for p in signature:
            lines.append(f"  - {p['permission']}")

    if normal:
        lines.append(f"\nNORMAL ({len(normal)}):")
        for p in normal:
            lines.append(f"  - {p['permission']}")

    if dangerous:
        lines.append(
            f"\n{len(dangerous)} dangerous permission(s) require runtime "
            "user consent and have privacy/security implications."
        )
    if signature:
        lines.append(
            f"{len(signature)} signature-level permission(s) require "
            "platform signing key — elevated system privileges."
        )

    return "\n".join(lines)


async def _handle_check_apk_signatures(
    input: dict, context: ToolContext
) -> str:
    """Check APK signatures for security issues."""
    err = check_androguard()
    if err:
        return err

    try:
        apk_path = find_apk(context, input.get("app_name"), input.get("path"))
    except ValueError as exc:
        return str(exc)

    from app.services.androguard_service import AndroguardService

    svc = AndroguardService()
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, svc.check_signatures, apk_path)
    except Exception as exc:
        return f"Error checking signatures: {exc}"

    return _format_signature_check(result)


async def _handle_scan_apk_manifest(input: dict, context: ToolContext) -> str:
    """Run manifest security checks on an APK and persist findings."""
    err = check_androguard()
    if err:
        return err

    try:
        apk_path = find_apk(context, input.get("app_name"), input.get("path"))
    except ValueError as exc:
        return str(exc)

    # Detect firmware context for severity adjustment
    is_priv_app = is_priv_app_path(apk_path, context.extracted_path)

    from app.services.androguard_service import AndroguardService

    svc = AndroguardService()
    loop = asyncio.get_event_loop()

    # Detect platform signing via manifest heuristics (declared permissions
    # with signature/signatureOrSystem protectionLevel, requested platform-
    # signature permissions, or system shared UID).  This is more accurate
    # than the previous "not debug-signed AND in priv-app" heuristic which
    # could false-positive on third-party APKs placed in priv-app by OEMs.
    is_platform_signed = False
    try:
        is_platform_signed = await loop.run_in_executor(
            None, svc.check_platform_signed, apk_path
        )
    except Exception:
        pass

    try:
        result = await loop.run_in_executor(
            None,
            lambda: svc.scan_manifest_security(
                apk_path,
                is_priv_app=is_priv_app,
                is_platform_signed=is_platform_signed,
            ),
        )
    except Exception as exc:
        return f"Error scanning APK manifest: {exc}"

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

    # Persist findings to the project findings database via flush()
    persisted_count = 0
    persist_error = False
    if context.db and result.get("findings"):
        try:
            persisted_count = await _persist_manifest_findings(
                context, result, apk_path, fw_ctx=fw_ctx
            )
        except Exception as exc:
            logger.warning(
                "Failed to persist manifest findings: %s", exc
            )
            persist_error = True

    return _format_manifest_scan(
        result, apk_path, context.extracted_path,
        persisted_count=persisted_count,
        total_findings=len(result.get("findings", [])),
        persist_error=persist_error,
        has_db=context.db is not None,
        fw_ctx=fw_ctx,
    )




async def _persist_manifest_findings(
    context: ToolContext,
    result: dict,
    apk_path: str,
    *,
    fw_ctx: FirmwareContext | None = None,
) -> int:
    """Write manifest findings to the Finding table via flush().

    Returns the number of *new* findings persisted (skips duplicates).
    Deduplication is keyed on (project_id, source, file_path, title).

    When *fw_ctx* is provided, finding descriptions and evidence are
    enriched with firmware metadata (device model, Android version, etc.).
    """
    from sqlalchemy import select

    from app.models.finding import Finding

    rel_path = os.path.relpath(apk_path, context.extracted_path)

    # Fetch existing finding titles for this APK to avoid duplicates on re-scan
    existing_stmt = (
        select(Finding.title)
        .where(
            Finding.project_id == context.project_id,
            Finding.source == "apk-manifest-scan",
            Finding.file_path == rel_path,
        )
    )
    existing_result = await context.db.execute(existing_stmt)
    existing_titles: set[str] = {row[0] for row in existing_result}

    new_count = 0
    for f in result["findings"]:
        title = f"[{f['check_id']}] {f['title']}"
        if title in existing_titles:
            continue  # Skip duplicate

        description = f["description"]
        evidence = f["evidence"]

        # Enrich with firmware context when available
        if fw_ctx:
            from app.utils.firmware_context import enrich_description, enrich_evidence
            description = enrich_description(description, fw_ctx)
            evidence = enrich_evidence(evidence, fw_ctx)

        finding = Finding(
            project_id=context.project_id,
            firmware_id=context.firmware_id,
            title=title,
            severity=f["severity"],
            confidence=f.get("confidence", "high"),
            description=description,
            evidence=evidence,
            file_path=rel_path,
            cwe_ids=f.get("cwe_ids") or None,
            source="apk-manifest-scan",
        )
        context.db.add(finding)
        new_count += 1

    if new_count:
        await context.db.flush()

    return new_count


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


def _format_apk_analysis(info: dict) -> str:
    """Format the full APK analysis dict into readable text."""
    lines = [
        f"APK Analysis: {info['package']}\n",
        f"Package:         {info['package']}",
        f"Version name:    {info.get('version_name') or 'N/A'}",
        f"Version code:    {info.get('version_code') or 'N/A'}",
        f"Min SDK:         {info.get('min_sdk') or 'N/A'}",
        f"Target SDK:      {info.get('target_sdk') or 'N/A'}",
        f"Main activity:   {info.get('main_activity') or 'N/A'}",
        f"Signed:          {info.get('is_signed', False)}",
    ]

    # Permissions summary
    perms = info.get("permissions", [])
    from app.services.androguard_service import classify_permission

    dangerous = [p for p in perms if classify_permission(p) == "dangerous"]
    lines.append(f"\nPermissions: {len(perms)} total, {len(dangerous)} dangerous")
    if dangerous:
        lines.append("Dangerous permissions:")
        for p in dangerous[:15]:
            lines.append(f"  - {p}")
        if len(dangerous) > 15:
            lines.append(f"  ... and {len(dangerous) - 15} more")

    # Components
    for label, key in [
        ("Activities", "activities"),
        ("Services", "services"),
        ("Receivers", "receivers"),
        ("Providers", "providers"),
    ]:
        items = info.get(key, [])
        if items:
            lines.append(f"\n{label} ({len(items)}):")
            for item in items[:50]:
                lines.append(f"  - {item}")
            if len(items) > 50:
                lines.append(f"  ... and {len(items) - 50} more")

    # Signatures
    sigs = info.get("signatures", [])
    if sigs:
        lines.append(f"\nSignatures ({len(sigs)}):")
        for sig in sigs:
            debug_tag = " [DEBUG CERT]" if sig.get("is_debug") else ""
            lines.append(f"  Issuer:    {sig.get('issuer', 'N/A')}{debug_tag}")
            lines.append(f"  Subject:   {sig.get('subject', 'N/A')}")
            lines.append(f"  Algorithm: {sig.get('algorithm', 'N/A')}")
            lines.append(f"  Serial:    {sig.get('serial', 'N/A')}")
            if sig.get("not_before"):
                lines.append(f"  Validity:  {sig['not_before']} — {sig.get('not_after', 'N/A')}")

    return "\n".join(lines)


def _format_signature_check(result: dict) -> str:
    """Format signature check results."""
    lines = [
        f"Signature check: {result['package']}\n",
        f"Signed: {result['is_signed']}",
    ]

    sigs = result.get("signatures", [])
    if sigs:
        lines.append(f"\nCertificates ({len(sigs)}):")
        for sig in sigs:
            debug_tag = " [DEBUG]" if sig.get("is_debug") else ""
            lines.append(f"  Subject:   {sig.get('subject', 'N/A')}{debug_tag}")
            lines.append(f"  Issuer:    {sig.get('issuer', 'N/A')}")
            lines.append(f"  Algorithm: {sig.get('algorithm', 'N/A')}")
            lines.append(f"  Serial:    {sig.get('serial', 'N/A')}")
            if sig.get("not_before"):
                lines.append(f"  Validity:  {sig['not_before']} — {sig.get('not_after', 'N/A')}")

    warnings = result.get("warnings", [])
    if warnings:
        lines.append(f"\nSECURITY WARNINGS ({len(warnings)}):")
        for w in warnings:
            lines.append(f"  !! {w}")
    else:
        lines.append("\nNo security warnings — signatures look clean.")

    return "\n".join(lines)


def _format_manifest_scan(
    result: dict,
    apk_path: str,
    extracted_root: str,
    *,
    persisted_count: int = 0,
    total_findings: int = 0,
    persist_error: bool = False,
    has_db: bool = True,
    fw_ctx: FirmwareContext | None = None,
) -> str:
    """Format manifest security scan results into readable text.

    The text output serves as the AI-assistant-facing return value while
    findings are separately persisted to the database.  The persistence
    status footer tells the assistant whether findings were saved.
    """
    rel_path = os.path.relpath(apk_path, extracted_root)
    findings = result.get("findings", [])
    summary = result.get("summary", {})
    pkg = result.get("package", "unknown")

    lines = [
        f"Manifest Security Scan: {pkg}",
        f"APK: {rel_path}",
        f"Total findings: {len(findings)}",
    ]

    # Include firmware context summary if available
    if fw_ctx and not fw_ctx.is_empty:
        ctx_summary = fw_ctx.summary_line()
        if ctx_summary:
            lines.append(f"Firmware: {ctx_summary}")

    # Suppression info
    suppressed_count = result.get("suppressed_count", 0)
    if suppressed_count:
        reasons = result.get("suppression_reasons", [])
        lines.append(
            f"Suppressed: {suppressed_count} finding(s) via permission "
            f"allowlisting ({'; '.join(reasons)})"
        )

    if result.get("is_debug_signed"):
        lines.append("Signing: debug/test certificate detected")
    if result.get("severity_bumped"):
        lines.append("Severity adjustment: +1 bump (privileged system APK)")
    if result.get("severity_reduced"):
        reduced = result.get("reduced_check_ids", [])
        lines.append(
            f"Severity reduction: -1 for platform-signed system component "
            f"({len(reduced)} check(s): {', '.join(reduced)})"
        )

    if summary:
        severity_order = ["critical", "high", "medium", "low", "info"]
        parts = []
        for sev in severity_order:
            count = summary.get(sev, 0)
            if count:
                parts.append(f"{count} {sev}")
        if parts:
            lines.append(f"Severity: {', '.join(parts)}")

    confidence_summary = result.get("confidence_summary", {})
    if confidence_summary:
        conf_order = ["high", "medium", "low"]
        conf_parts = []
        for conf in conf_order:
            count = confidence_summary.get(conf, 0)
            if count:
                conf_parts.append(f"{count} {conf}")
        if conf_parts:
            lines.append(f"Confidence: {', '.join(conf_parts)}")

    lines.append("")

    if not findings:
        lines.append("No manifest security issues detected.")
        return "\n".join(lines)

    for f in findings:
        sev_upper = f["severity"].upper()
        confidence = f.get("confidence", "high")
        lines.append(f"[{sev_upper}] {f['check_id']}: {f['title']} (confidence: {confidence})")
        lines.append(f"  {f['description']}")
        if f.get("evidence"):
            lines.append(f"  Evidence: {f['evidence']}")
        if f.get("cwe_ids"):
            lines.append(f"  CWE: {', '.join(f['cwe_ids'])}")
        lines.append("")

    # Persistence status footer — tells the AI assistant what happened
    if persist_error:
        lines.append(
            "WARNING: Failed to save findings to the database. "
            "The scan results above are still valid."
        )
    elif not has_db:
        lines.append(
            "Note: No database session available — findings were not "
            "persisted. Run within an MCP context to auto-save findings."
        )
    elif persisted_count == total_findings:
        lines.append(
            f"All {persisted_count} finding(s) saved to the project "
            "findings database (source: apk-manifest-scan)."
        )
    elif persisted_count == 0:
        lines.append(
            f"All {total_findings} finding(s) already existed in the "
            "project findings database (duplicate scan skipped)."
        )
    else:
        already = total_findings - persisted_count
        lines.append(
            f"{persisted_count} new finding(s) saved to the project "
            f"findings database; {already} already existed "
            "(source: apk-manifest-scan)."
        )
    return "\n".join(lines)
