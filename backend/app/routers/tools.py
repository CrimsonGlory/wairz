"""MCP-to-REST bridge — exposes MCP tools via HTTP for the web UI.

Provides a generic endpoint that can execute any whitelisted MCP tool
through the existing ToolRegistry, without needing per-tool REST routes.

Rate limiting: not yet implemented. Consider adding slowapi or a Redis-based
limiter before exposing this to untrusted clients. Current assumption is that
the UI is used by authenticated local users only.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import create_tool_registry
from app.ai.tool_registry import ToolContext, ToolRegistry
from app.database import get_db
from app.models.firmware import Firmware
from app.routers.deps import resolve_firmware
from app.schemas.tools import (
    ToolInfo,
    ToolListResponse,
    ToolRunRequest,
    ToolRunResponse,
)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/tools",
    tags=["tools"],
)

# ---------------------------------------------------------------------------
# Whitelist: only read-only / analysis tools are allowed through REST.
# Dangerous tools (emulation start/stop, fuzzing start/stop, UART, document
# writes, etc.) are blocked by default.
# ---------------------------------------------------------------------------

ALLOWED_TOOLS: set[str] = {
    # Filesystem (read-only)
    "list_directory",
    "read_file",
    "file_info",
    "search_files",
    "find_files_by_type",
    "get_component_map",
    "get_firmware_metadata",
    "extract_bootloader_env",
    # Strings (read-only)
    "extract_strings",
    "search_strings",
    "find_crypto_material",
    "find_hardcoded_credentials",
    "find_hardcoded_ips",
    # Binary analysis (read-only)
    "detect_rtos",
    "analyze_binary_format",
    "analyze_raw_binary",
    "list_functions",
    "disassemble_function",
    "decompile_function",
    "list_imports",
    "list_exports",
    "xrefs_to",
    "xrefs_from",
    "get_binary_info",
    "check_binary_protections",
    "check_all_binary_protections",
    "find_string_refs",
    "resolve_import",
    "find_callers",
    "search_binary_content",
    "get_stack_layout",
    "get_global_layout",
    "trace_dataflow",
    "cross_binary_dataflow",
    "detect_capabilities",
    "list_binary_capabilities",
    # Security analysis (read-only)
    "check_known_cves",
    "analyze_config_security",
    "check_setuid_binaries",
    "analyze_init_scripts",
    "check_filesystem_permissions",
    "analyze_certificate",
    "check_kernel_hardening",
    "scan_with_yara",
    "extract_kernel_config",
    "check_kernel_config",
    "analyze_selinux_policy",
    "check_selinux_enforcement",
    "check_compliance",
    "scan_scripts",
    "shellcheck_scan",
    "bandit_scan",
    "check_secure_boot",
    "detect_network_dependencies",
    "detect_update_mechanisms",
    "analyze_update_config",
    # SBOM (read-only)
    "generate_sbom",
    "get_sbom_components",
    "check_component_cves",
    "run_vulnerability_scan",
    "list_vulnerabilities_for_assessment",
    "export_sbom",
    "assess_vulnerabilities",
    # Comparison (read-only)
    "list_firmware_versions",
    "diff_firmware",
    "diff_binary",
    "diff_decompilation",
    # Reporting (read-only queries)
    "list_findings",
    "read_project_instructions",
    "list_project_documents",
    "read_project_document",
    "read_scratchpad",
    # Android (read-only + security scan)
    "analyze_apk",
    "list_apk_permissions",
    "check_apk_signatures",
    "scan_apk_manifest",
    "scan_apk_bytecode",
    "scan_apk_sast",
    # UEFI (read-only)
    "list_firmware_volumes",
    "list_uefi_modules",
    "extract_nvram_variables",
    "identify_uefi_module",
    "read_uefi_module",
    # Network analysis (read-only)
    "analyze_network_traffic",
    "get_protocol_breakdown",
    "identify_insecure_protocols",
    "get_dns_queries",
    "get_network_conversations",
    # Emulation (status queries only)
    "check_emulation_status",
    "get_emulation_logs",
    "list_emulation_presets",
    # Fuzzing (status/analysis only)
    "analyze_fuzzing_target",
    "check_fuzzing_status",
    "triage_fuzzing_crash",
    "diagnose_fuzzing_campaign",
    # VulHunt (read-only)
    "vulhunt_scan_binary",
    "vulhunt_scan_firmware",
    "vulhunt_check_available",
    # cwe_checker (read-only analysis)
    "cwe_check_status",
    "cwe_check_binary",
    "cwe_check_firmware",
    # CRA compliance (read-only analysis + reporting)
    "create_cra_assessment",
    "auto_populate_cra",
    "update_cra_requirement",
    "export_cra_checklist",
    "generate_article14_notification",
    # Threat intelligence (read-only scanning)
    "scan_with_clamav",
    "scan_firmware_clamav",
    "check_virustotal",
    "scan_firmware_virustotal",
    "check_malwarebazaar_hash",
    "check_threatfox_ioc",
    "check_urlhaus_url",
    "enrich_firmware_threat_intel",
    "check_known_good_hash",
    "scan_firmware_known_good",
}


def _get_registry() -> ToolRegistry:
    """Build the full tool registry (cached at module level after first call)."""
    global _registry_cache
    if _registry_cache is None:
        _registry_cache = create_tool_registry()
    return _registry_cache


_registry_cache: ToolRegistry | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=ToolListResponse)
async def list_tools(project_id: uuid.UUID):
    """List all MCP tools available via the REST bridge.

    Returns the tool name, description, and JSON Schema for the input
    of every whitelisted tool. Dangerous tools (emulation control, UART,
    fuzzing control) are excluded.
    """
    registry = _get_registry()
    tools: list[ToolInfo] = []
    for defn in registry.get_anthropic_tools():
        if defn["name"] in ALLOWED_TOOLS:
            tools.append(
                ToolInfo(
                    name=defn["name"],
                    description=defn["description"],
                    input_schema=defn["input_schema"],
                )
            )
    tools.sort(key=lambda t: t.name)
    return ToolListResponse(tools=tools, count=len(tools))


@router.post("/run", response_model=ToolRunResponse)
async def run_tool(
    project_id: uuid.UUID,
    body: ToolRunRequest,
    firmware: Firmware = Depends(resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Execute an MCP tool via REST and return its text output.

    This is the generic bridge endpoint. It accepts any whitelisted tool
    name plus the tool's input dict, constructs a ToolContext from the
    resolved firmware, and delegates to the existing ToolRegistry.

    The response ``output`` field contains the same text string that the
    MCP tool would return to Claude (max 30 KB, auto-truncated).
    """
    if body.tool_name not in ALLOWED_TOOLS:
        raise HTTPException(
            status_code=403,
            detail=f"Tool '{body.tool_name}' is not allowed via REST. "
            f"Only read-only analysis tools are exposed.",
        )

    registry = _get_registry()

    # Phase 3b: pass full detection_roots list so tools that iterate
    # sibling partition dirs (scatter zips, raw-image dirs) see them all.
    try:
        from app.services.firmware_paths import get_detection_roots
        detection_roots = await get_detection_roots(firmware, db=db)
    except Exception:
        detection_roots = [firmware.extracted_path] if firmware.extracted_path else []

    context = ToolContext(
        project_id=firmware.project_id,
        firmware_id=firmware.id,
        extracted_path=firmware.extracted_path,
        db=db,
        extraction_dir=firmware.extraction_dir,
        detection_roots=list(detection_roots),
    )

    result = await registry.execute(body.tool_name, body.input, context, truncate=False)

    # The registry returns "Error: ..." or "Error executing ..." on failure
    is_error = result.startswith("Error:")  or result.startswith("Error executing ")
    if is_error:
        return ToolRunResponse(tool=body.tool_name, output=result, success=False)

    return ToolRunResponse(tool=body.tool_name, output=result, success=True)
