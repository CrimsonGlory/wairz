"""Attack surface analysis MCP tools.

Provides tools for detecting input vectors and analyzing individual binary
attack surfaces within extracted firmware.
"""

import asyncio
import logging

from sqlalchemy import delete, select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.attack_surface import AttackSurfaceEntry
from app.models.finding import Finding
from app.services.jsonb_normalizers import (
    _normalize_attack_surface_entries_dangerous_imports,
    _normalize_attack_surface_entries_input_categories,
    _stamp_attack_surface_entries_score_breakdown,
)

logger = logging.getLogger(__name__)


async def _handle_detect_input_vectors(input: dict, context: ToolContext) -> str:
    """Scan firmware for ELF binaries and rank them by attack surface score.

    Returns cached results unless rescan=True.
    """
    min_score = input.get("min_score", 0)
    max_results = input.get("max_results", 50)
    rescan = input.get("rescan", False)
    path_filter = input.get("path")

    # Check for cached results
    if not rescan:
        stmt = (
            select(AttackSurfaceEntry)
            .where(
                AttackSurfaceEntry.project_id == context.project_id,
                AttackSurfaceEntry.firmware_id == context.firmware_id,
            )
            .order_by(AttackSurfaceEntry.attack_surface_score.desc())
        )
        result = await context.db.execute(stmt)
        cached = result.scalars().all()
        if cached:
            filtered = [e for e in cached if e.attack_surface_score >= min_score]
            return _format_table(filtered[:max_results], len(cached))

    # Run the scan (CPU-bound, run in executor)
    from app.services.attack_surface_service import scan_attack_surface

    loop = asyncio.get_running_loop()
    scan_results = await loop.run_in_executor(
        None,
        scan_attack_surface,
        context.extracted_path,
        path_filter,
    )

    if not scan_results:
        return "No ELF binaries found in the firmware filesystem."

    # Clear old entries for this firmware
    await context.db.execute(
        delete(AttackSurfaceEntry).where(
            AttackSurfaceEntry.project_id == context.project_id,
            AttackSurfaceEntry.firmware_id == context.firmware_id,
        )
    )

    # Persist results and auto-findings
    entries = []
    for r in scan_results:
        entry = AttackSurfaceEntry(
            project_id=context.project_id,
            firmware_id=context.firmware_id,
            binary_path=r.path,
            binary_name=r.name,
            architecture=r.architecture,
            file_size=r.file_size,
            attack_surface_score=r.score,
            score_breakdown=_stamp_attack_surface_entries_score_breakdown(dict(r.breakdown)),
            is_setuid=r.is_setuid,
            is_network_listener=r.is_network_listener,
            is_cgi_handler=r.is_cgi_handler,
            has_dangerous_imports=r.has_dangerous_imports,
            dangerous_imports=_normalize_attack_surface_entries_dangerous_imports(r.dangerous_imports),
            input_categories=_normalize_attack_surface_entries_input_categories(r.input_categories),
            auto_findings_generated=bool(r.findings),
        )
        context.db.add(entry)
        entries.append(entry)

        # Create findings — Rule #35b explicit confidence (heuristic
        # listening-port + service-banner inference; "medium" reflects
        # the matcher class — not a CVE-DB or magic-byte gate).
        for finding_data in r.findings:
            finding = Finding(
                project_id=context.project_id,
                firmware_id=context.firmware_id,
                confidence="medium",
                title=finding_data["title"],
                severity=finding_data["severity"],
                description=finding_data["description"],
                file_path=finding_data.get("file_path"),
                cwe_ids=finding_data.get("cwe_ids"),
                source="attack_surface",
            )
            context.db.add(finding)

    await context.db.flush()

    # Filter and format
    filtered = [e for e in entries if e.attack_surface_score >= min_score]
    return _format_table(filtered[:max_results], len(entries))


def _format_table(entries: list, total: int) -> str:
    """Format entries as a readable table."""
    lines = [
        f"Attack Surface Analysis: {total} ELF binaries scanned",
        "",
    ]

    if not entries:
        lines.append("No binaries match the score filter.")
        return "\n".join(lines)

    # Summary counts
    critical = sum(1 for e in entries if e.attack_surface_score >= 75)
    high = sum(1 for e in entries if 50 <= e.attack_surface_score < 75)
    medium = sum(1 for e in entries if 25 <= e.attack_surface_score < 50)
    low = sum(1 for e in entries if e.attack_surface_score < 25)
    lines.append(f"Critical({critical}) High({high}) Medium({medium}) Low({low})")
    lines.append("")

    # Table header
    lines.append(f"{'Score':>5} | {'Badge':<8} | {'Binary':<20} | {'Categories':<30} | {'Key Imports'}")
    lines.append("-" * 100)

    for e in entries:
        score = e.attack_surface_score if isinstance(e.attack_surface_score, int) else e.attack_surface_score
        if score >= 75:
            badge = "CRITICAL"
        elif score >= 50:
            badge = "HIGH"
        elif score >= 25:
            badge = "MEDIUM"
        else:
            badge = "LOW"

        name = e.binary_name if isinstance(e, AttackSurfaceEntry) else e.binary_name
        categories = _normalize_attack_surface_entries_input_categories(e.input_categories)
        cats = ", ".join(categories[:3]) if categories else "-"

        dangerous = _normalize_attack_surface_entries_dangerous_imports(e.dangerous_imports)
        imports_str = ", ".join(dangerous[:4]) if dangerous else "-"

        lines.append(f"{score:>5} | {badge:<8} | {name:<20} | {cats:<30} | {imports_str}")

    if len(entries) < total:
        lines.append(f"\n(Showing {len(entries)} of {total} binaries)")

    return "\n".join(lines)


def _analyze_binary_sync(resolved: str, real_root: str) -> dict:
    """Synchronous binary attack-surface analysis.

    Performs ELF magic check, stat(), ELF import parsing, init-script
    enumeration, and protection probes. All filesystem/ELF I/O lives here so
    the async handler can offload via run_in_executor (Rule #5).

    Returns a dict with either {"error": "..."} on failure, or the full
    signals + score + categories aggregate ready for formatting.
    """
    import os
    import stat as stat_mod

    from app.services.attack_surface_service import (
        CGI_PATH_PATTERNS,
        KNOWN_NETWORK_DAEMONS,
        BinarySignals,
        _classify_categories,
        _collect_init_script_binaries,
        _get_binary_protections,
        _get_elf_imports,
        _rel,
        _score_binary,
    )

    if not os.path.isfile(resolved):
        return {"error": "not_found"}

    # Verify it's ELF
    try:
        with open(resolved, "rb") as f:
            magic = f.read(4)
        if magic != b"\x7fELF":
            return {"error": "not_elf"}
    except OSError as exc:
        return {"error": f"read_failed:{exc}"}

    rel_path = _rel(resolved, real_root)
    name = os.path.basename(resolved)

    signals = BinarySignals(path=rel_path, name=name)

    # File size and permissions
    try:
        st = os.stat(resolved)
        signals.file_size = st.st_size
        signals.is_setuid = bool(st.st_mode & stat_mod.S_ISUID)
        signals.is_setgid = bool(st.st_mode & stat_mod.S_ISGID)
    except OSError:
        pass

    # ELF imports
    imports, arch, has_debug = _get_elf_imports(resolved)
    signals.imported_symbols = imports
    signals.architecture = arch
    signals.has_debug_info = has_debug

    # CGI path check
    for pattern in CGI_PATH_PATTERNS:
        if pattern in rel_path:
            signals.is_cgi = True
            break

    # Known daemon
    if name in KNOWN_NETWORK_DAEMONS:
        signals.is_known_daemon = True

    # Init script check
    init_binaries = _collect_init_script_binaries(real_root)
    if name in init_binaries:
        signals.in_init_scripts = True

    # Protections
    prots = _get_binary_protections(resolved)
    if "error" not in prots:
        signals.nx = bool(prots.get("nx", False))
        signals.canary = bool(prots.get("canary", False))
        signals.pie = bool(prots.get("pie", False))
        signals.relro = str(prots.get("relro", "none"))

    score, breakdown = _score_binary(signals)
    categories = _classify_categories(signals)

    return {
        "rel_path": rel_path,
        "name": name,
        "signals": signals,
        "score": score,
        "breakdown": breakdown,
        "categories": categories,
        "imports": imports,
    }


async def _handle_analyze_binary_attack_surface(input: dict, context: ToolContext) -> str:
    """Deep-dive analysis of a single binary's attack surface."""
    import os

    from app.services.attack_surface_service import (
        DANGEROUS_FUNCTIONS,
        NETWORK_FUNCTIONS,
    )

    path = input.get("path")
    if not path:
        return "Error: 'path' is required"

    resolved = context.resolve_path(path)
    real_root = os.path.realpath(context.extracted_path)

    # Rule #5 — ELF parse + filesystem walks (init-scripts) are sync I/O;
    # offload to executor so 10K+ file rootfs scans don't stall the loop.
    loop = asyncio.get_running_loop()
    aggregate = await loop.run_in_executor(
        None, _analyze_binary_sync, resolved, real_root
    )

    err = aggregate.get("error")
    if err == "not_found":
        return f"Error: File not found: {path}"
    if err == "not_elf":
        return f"Error: {path} is not an ELF binary"
    if err and err.startswith("read_failed:"):
        return f"Error reading file: {err.split(':', 1)[1]}"

    rel_path = aggregate["rel_path"]
    name = aggregate["name"]
    signals = aggregate["signals"]
    score = aggregate["score"]
    breakdown = aggregate["breakdown"]
    categories = aggregate["categories"]
    imports = aggregate["imports"]

    # Format output
    net_imports = sorted(signals.imported_symbols & NETWORK_FUNCTIONS)
    dangerous_imports = sorted(signals.imported_symbols & DANGEROUS_FUNCTIONS)

    lines = [
        f"=== Attack Surface Analysis: {name} ===",
        f"Path: {rel_path}",
        f"Architecture: {signals.architecture or 'unknown'}",
        f"File size: {signals.file_size or 0:,} bytes",
        "",
        f"SCORE: {score}/100",
        "",
        "--- Score Breakdown ---",
        f"  Network score:      {breakdown['network_score']} (imports: {', '.join(net_imports) or 'none'})",
        f"  CGI score:          {breakdown['cgi_score']} ({'CGI path detected' if signals.is_cgi else 'not CGI'})",
        f"  Setuid score:       {breakdown['setuid_score']} ({'setuid' if signals.is_setuid else 'setgid' if signals.is_setgid else 'normal'})",
        f"  Dangerous score:    {breakdown['dangerous_score']} (imports: {', '.join(dangerous_imports) or 'none'})",
        f"  Known daemon bonus: {breakdown['known_daemon_bonus']} ({'yes' if signals.is_known_daemon else 'no'})",
        f"  Raw score:          {breakdown['raw_score']}",
        f"  Privilege mult:     {breakdown['privilege_multiplier']}x",
        "",
        "--- Flags ---",
        f"  Setuid/setgid:    {'YES' if signals.is_setuid or signals.is_setgid else 'no'}",
        f"  Network listener: {'YES' if net_imports or signals.is_known_daemon else 'no'}",
        f"  CGI handler:      {'YES' if signals.is_cgi else 'no'}",
        f"  Known daemon:     {'YES' if signals.is_known_daemon else 'no'}",
        f"  In init scripts:  {'YES' if signals.in_init_scripts else 'no'}",
        f"  Debug symbols:    {'YES' if signals.has_debug_info else 'no'}",
        "",
        "--- Binary Protections ---",
        f"  NX (DEP):      {'enabled' if signals.nx else 'DISABLED'}",
        f"  Stack canary:  {'enabled' if signals.canary else 'DISABLED'}",
        f"  PIE (ASLR):    {'enabled' if signals.pie else 'DISABLED'}",
        f"  RELRO:         {signals.relro}",
        "",
        f"Categories: {', '.join(categories) or 'none'}",
    ]

    # All imported symbols summary
    if imports:
        lines.append("")
        lines.append(f"--- All imported symbols ({len(imports)} total) ---")
        for sym in sorted(imports)[:100]:
            marker = ""
            if sym in NETWORK_FUNCTIONS:
                marker = " [NETWORK]"
            elif sym in DANGEROUS_FUNCTIONS:
                marker = " [DANGEROUS]"
            lines.append(f"  {sym}{marker}")
        if len(imports) > 100:
            lines.append(f"  ... and {len(imports) - 100} more")

    return "\n".join(lines)


def register_attack_surface_tools(registry: ToolRegistry) -> None:
    """Register attack surface analysis tools."""
    registry.register(
        name="detect_input_vectors",
        description=(
            "Scan all ELF binaries in the firmware and rank them by attack surface "
            "score (0-100). Identifies network listeners, CGI handlers, setuid binaries, "
            "and dangerous function imports. Generates security findings automatically. "
            "Results are cached — set rescan=true to re-analyze."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Optional sub-path to limit scanning to (e.g. '/usr/bin')",
                },
                "min_score": {
                    "type": "integer",
                    "description": "Minimum attack surface score to include (default 0)",
                    "default": 0,
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default 50)",
                    "default": 50,
                },
                "rescan": {
                    "type": "boolean",
                    "description": "Force a fresh scan even if cached results exist",
                    "default": False,
                },
            },
            "required": [],
        },
        handler=_handle_detect_input_vectors,
    )

    registry.register(
        name="analyze_binary_attack_surface",
        description=(
            "Deep-dive analysis of a single binary's attack surface. Shows score "
            "breakdown, all categorized imports, setuid status, init script references, "
            "and binary protection status (NX, ASLR, canary, RELRO)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem",
                },
            },
            "required": ["path"],
        },
        handler=_handle_analyze_binary_attack_surface,
    )
