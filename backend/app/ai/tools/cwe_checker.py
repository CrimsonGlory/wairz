"""MCP tools for cwe_checker binary CWE detection.

Tools:
  - cwe_check_binary: Run cwe_checker on a single ELF binary
  - cwe_check_firmware: Batch check top-N binaries from attack surface map
  - cwe_check_status: Check if cwe_checker Docker image is available
"""

import os

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.attack_surface import AttackSurfaceEntry
from app.services.cwe_checker_service import (
    CweCheckResult,
    check_image_available,
    run_cwe_checker,
    run_cwe_checker_batch,
)
from app.utils.truncation import truncate_output


def _format_result(result: CweCheckResult) -> str:
    """Format a single CweCheckResult for MCP output."""
    lines = [f"## {result.binary_name}"]

    if result.error:
        lines.append(f"Error: {result.error}")
        return "\n".join(lines)

    if result.from_cache:
        lines.append("(cached result)")

    if not result.warnings:
        lines.append("No CWE warnings found.")
    else:
        lines.append(f"**{len(result.warnings)} CWE warning(s) found:**\n")

        # Group by CWE ID
        by_cwe: dict[str, list] = {}
        for w in result.warnings:
            by_cwe.setdefault(w.cwe_id, []).append(w)

        for cwe_id, warnings in sorted(by_cwe.items()):
            lines.append(f"### {cwe_id} ({len(warnings)} occurrence{'s' if len(warnings) > 1 else ''})")
            lines.append(f"  {warnings[0].name}")
            for w in warnings[:50]:
                sym = w.symbols[0] if w.symbols else "unknown"
                lines.append(f"  - {sym} @ {w.address}: {w.description[:120]}")
            if len(warnings) > 50:
                lines.append(f"  ... and {len(warnings) - 50} more")
            lines.append("")

    if result.elapsed_seconds > 0:
        lines.append(f"Analysis time: {result.elapsed_seconds:.1f}s")

    return "\n".join(lines)


async def _handle_cwe_check_status(input: dict, context: ToolContext) -> str:
    """Check if cwe_checker Docker image is available."""
    available, message = await check_image_available()
    if available:
        return (
            f"cwe_checker is available ({message}).\n\n"
            "Supported CWE checks: CWE-78 (OS Command Injection), "
            "CWE-119 (Buffer Overflow), CWE-125 (Out-of-bounds Read), "
            "CWE-134 (Format String), CWE-190 (Integer Overflow), "
            "CWE-215 (Debug Info Exposure), CWE-243 (chroot without chdir), "
            "CWE-332 (Weak PRNG), CWE-337 (Predictable Seed), "
            "CWE-367 (TOCTOU), CWE-415 (Double Free), CWE-416 (Use After Free), "
            "CWE-426 (Untrusted Search Path), CWE-467 (sizeof on Pointer), "
            "CWE-476 (NULL Pointer Deref), CWE-560 (Permissive umask), "
            "CWE-676 (Dangerous Functions), CWE-782 (Exposed IOCTL), "
            "CWE-787 (Out-of-bounds Write), CWE-789 (Uncontrolled Memory Alloc)\n\n"
            "Supported architectures: x86, ARM, MIPS, PPC"
        )
    return f"cwe_checker is NOT available: {message}"


async def _handle_cwe_check_binary(input: dict, context: ToolContext) -> str:
    """Run cwe_checker on a single binary."""
    path = input.get("path", "")
    if not path:
        return "Error: 'path' is required (relative path within firmware filesystem)"

    resolved = context.resolve_path(path)
    if not os.path.isfile(resolved):
        return f"Error: file not found: {path}"

    timeout = input.get("timeout", 600)
    checks = input.get("checks")

    result = await run_cwe_checker(
        binary_path=resolved,
        firmware_id=context.firmware_id,
        db=context.db,
        timeout=timeout,
        checks=checks,
    )

    output = _format_result(result)

    # Auto-generate findings for high-severity CWEs
    if result.warnings and not result.error:
        await _generate_findings(result, context)

    return truncate_output(output)


async def _handle_cwe_check_firmware(input: dict, context: ToolContext) -> str:
    """Batch check top-N binaries from the attack surface map."""
    top_n = input.get("top_n", 20)
    min_score = input.get("min_score", 0)
    timeout = input.get("timeout", 600)

    # Query attack surface entries sorted by score
    result = await context.db.execute(
        select(AttackSurfaceEntry)
        .where(
            AttackSurfaceEntry.project_id == context.project_id,
            AttackSurfaceEntry.firmware_id == context.firmware_id,
            AttackSurfaceEntry.attack_surface_score >= min_score,
        )
        .order_by(AttackSurfaceEntry.attack_surface_score.desc())
        .limit(top_n)
    )
    entries = result.scalars().all()

    if not entries:
        return (
            "No attack surface entries found. Run `detect_input_vectors` first "
            "to score binaries, then re-run this tool."
        )

    # Resolve paths
    binary_paths = []
    for entry in entries:
        full_path = os.path.join(
            context.extracted_path or "", entry.binary_path.lstrip("/")
        )
        if os.path.isfile(full_path):
            binary_paths.append(full_path)

    if not binary_paths:
        return "Error: none of the attack surface binaries could be found on disk."

    lines = [
        f"Running cwe_checker on top {len(binary_paths)} binaries "
        f"(by attack surface score, min_score={min_score})...\n"
    ]

    results = await run_cwe_checker_batch(
        binary_paths=binary_paths,
        firmware_id=context.firmware_id,
        db=context.db,
        timeout=timeout,
        max_concurrent=1,  # cwe_checker is heavy, run one at a time
    )

    total_warnings = 0
    binaries_with_warnings = 0

    for r in results:
        lines.append(_format_result(r))
        lines.append("---")
        if r.warnings:
            total_warnings += len(r.warnings)
            binaries_with_warnings += 1
            # Auto-generate findings
            if not r.error:
                await _generate_findings(r, context)

    # Summary
    lines.insert(1, f"\n**Summary:** {total_warnings} CWE warnings across "
                    f"{binaries_with_warnings}/{len(results)} binaries\n")

    return truncate_output("\n".join(lines))


# CWE severity mapping for auto-findings
_CWE_SEVERITY = {
    "CWE-78": "high",      # OS Command Injection
    "CWE-119": "high",     # Buffer Overflow
    "CWE-125": "medium",   # Out-of-bounds Read
    "CWE-134": "high",     # Format String
    "CWE-190": "medium",   # Integer Overflow
    "CWE-215": "low",      # Debug Info
    "CWE-243": "medium",   # chroot without chdir
    "CWE-332": "medium",   # Weak PRNG
    "CWE-337": "medium",   # Predictable Seed
    "CWE-367": "medium",   # TOCTOU
    "CWE-415": "high",     # Double Free
    "CWE-416": "high",     # Use After Free
    "CWE-426": "medium",   # Untrusted Search Path
    "CWE-467": "low",      # sizeof on Pointer
    "CWE-476": "medium",   # NULL Pointer Deref
    "CWE-560": "low",      # Permissive umask
    "CWE-676": "medium",   # Dangerous Functions
    "CWE-782": "medium",   # Exposed IOCTL
    "CWE-787": "high",     # Out-of-bounds Write
    "CWE-789": "medium",   # Uncontrolled Memory Alloc
}


async def _generate_findings(result: CweCheckResult, context: ToolContext) -> None:
    """Auto-generate findings for cwe_checker warnings."""
    from app.models.finding import Finding

    if not result.warnings:
        return

    # Group warnings by CWE ID
    by_cwe: dict[str, list] = {}
    for w in result.warnings:
        by_cwe.setdefault(w.cwe_id, []).append(w)

    for cwe_id, warnings in by_cwe.items():
        severity = _CWE_SEVERITY.get(cwe_id, "medium")
        cwe_name = warnings[0].name

        # Build evidence
        evidence_lines = [
            f"cwe_checker detected {len(warnings)} instance(s) of {cwe_id} "
            f"in `{result.binary_name}`:\n"
        ]
        for w in warnings[:20]:
            sym = w.symbols[0] if w.symbols else "unknown"
            evidence_lines.append(f"- {sym} @ {w.address}")

        # Rule #35b / audit-2026-05-04 F-D-08: confidence + firmware_id
        # MUST be explicit on every Finding() construction outside
        # FindingService.create() to prevent silent NULL persistence.
        # Confidence: cwe_checker uses BAP-derived static analysis on
        # ELF binaries — semantic-level reasoning, lower false positives
        # than regex matchers but not as authoritative as CVE matches.
        # "medium" reflects the static-analysis matcher class.
        finding = Finding(
            project_id=context.project_id,
            firmware_id=context.firmware_id,
            confidence="medium",
            title=f"{cwe_id}: {cwe_name} in {result.binary_name}",
            description=warnings[0].description,
            severity=severity,
            source="cwe_checker",
            file_path=result.binary_path,
            evidence="\n".join(evidence_lines),
            cwe_ids=[cwe_id],
        )
        context.db.add(finding)

    await context.db.flush()


def register_cwe_checker_tools(registry: ToolRegistry) -> None:
    """Register cwe_checker MCP tools."""

    registry.register(
        name="cwe_check_status",
        description=(
            "Check if the cwe_checker Docker image is available for binary CWE analysis. "
            "Returns supported CWE checks and architectures."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_cwe_check_status,
    )

    registry.register(
        name="cwe_check_binary",
        description=(
            "Run cwe_checker static analysis on a single ELF binary to detect CWE violations. "
            "Checks 17+ CWEs including buffer overflows (CWE-119), use-after-free (CWE-416), "
            "format strings (CWE-134), command injection (CWE-78), and more. "
            "Results are cached by binary SHA-256. Requires the cwe_checker Docker image."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the ELF binary (relative to firmware root)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max analysis time in seconds (default 600)",
                    "default": 600,
                },
                "checks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional: specific CWE checks to run (e.g., ['CWE676', 'CWE119']). Omit for all.",
                },
            },
            "required": ["path"],
        },
        handler=_handle_cwe_check_binary,
    )

    registry.register(
        name="cwe_check_firmware",
        description=(
            "Run cwe_checker on the top-N highest-scoring binaries from the attack surface map. "
            "Automatically selects the most attack-surface-exposed binaries (network listeners, "
            "CGI handlers, setuid binaries) and runs CWE analysis on each. "
            "Requires: (1) attack surface scan (detect_input_vectors) completed, "
            "(2) cwe_checker Docker image available."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "top_n": {
                    "type": "integer",
                    "description": "Number of top-scoring binaries to check (default 20)",
                    "default": 20,
                },
                "min_score": {
                    "type": "integer",
                    "description": "Minimum attack surface score to include (default 0)",
                    "default": 0,
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max analysis time per binary in seconds (default 600)",
                    "default": 600,
                },
            },
        },
        handler=_handle_cwe_check_firmware,
    )
