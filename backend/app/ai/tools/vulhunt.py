"""VulHunt binary vulnerability scanning AI tools.

Integrates with the VulHunt Community Edition container for deep binary
vulnerability detection. VulHunt performs semantic analysis (dataflow,
control flow, decompilation) and rule-based vulnerability detection on
ELF and PE32+ binaries — particularly strong for UEFI firmware modules.

VulHunt runs in a separate Docker container (ghcr.io/vulhunt-re/vulhunt)
and exposes an MCP server over HTTP (Streamable HTTP transport). We
communicate via JSON-RPC over HTTP POST to the /mcp endpoint.
"""

import asyncio
import json
import logging
import os
from typing import Any

import httpx

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.config import get_settings
from app.services.event_service import event_service

logger = logging.getLogger(__name__)


def register_vulhunt_tools(registry: ToolRegistry) -> None:
    """Register VulHunt binary vulnerability scanning tools."""

    registry.register(
        name="vulhunt_scan_binary",
        description=(
            "Scan a single binary with VulHunt for vulnerabilities. "
            "Performs deep static analysis: dataflow tracking, pattern "
            "matching, and rule-based detection. Returns structured "
            "findings with severity, description, and location. "
            "Supports ELF (Linux) and PE32+ (UEFI) binaries."
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
        handler=_handle_vulhunt_scan_binary,
    )

    registry.register(
        name="vulhunt_scan_firmware",
        description=(
            "Scan all ELF and PE32+ binaries in the extracted firmware "
            "with VulHunt. Automatically discovers binaries in the "
            "filesystem, runs VulHunt on each, and aggregates findings. "
            "For UEFI firmware, scans DXE/PEI/SMM modules from the "
            "UEFIExtract output."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "max_binaries": {
                    "type": "integer",
                    "description": "Maximum number of binaries to scan (default: all, 0 = no limit)",
                    "default": 0,
                },
                "min_size": {
                    "type": "integer",
                    "description": "Minimum binary size in bytes to scan (default 4096)",
                    "default": 4096,
                },
            },
        },
        handler=_handle_vulhunt_scan_firmware,
    )

    registry.register(
        name="vulhunt_check_available",
        description=(
            "Check if the VulHunt container is running and available. "
            "Returns version info and status."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_vulhunt_check_available,
    )


# ── VulHunt MCP Client ──────────────────────────────────────────────


class VulHuntClient:
    """Async client for the VulHunt MCP server (Streamable HTTP transport)."""

    def __init__(self, base_url: str = "http://vulhunt:8080"):
        self.base_url = base_url
        self.session_id: str | None = None
        self._req_id = 0

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    async def _call(
        self, method: str, params: dict | None = None, timeout: float = 60
    ) -> dict[str, Any]:
        """Send a JSON-RPC request to the VulHunt MCP server."""
        msg: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "id": self._next_id(),
        }
        if params is not None:
            msg["params"] = params

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/mcp",
                content=json.dumps(msg),
                headers=headers,
                timeout=timeout,
            )
            resp.raise_for_status()

            # Capture session ID
            sid = resp.headers.get("mcp-session-id")
            if sid:
                self.session_id = sid

            # Parse SSE response — find the data: line with our result
            body = resp.text
            for line in body.split("\n"):
                if line.startswith("data: "):
                    return json.loads(line[6:])

            # Fallback: try parsing the whole body as JSON
            return json.loads(body)

    async def initialize(self) -> dict[str, Any]:
        """Initialize the MCP session."""
        result = await self._call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "wairz-backend", "version": "1.0"},
        })
        return result.get("result", {})

    async def call_tool(
        self, name: str, arguments: dict, timeout: float = 300
    ) -> dict[str, Any]:
        """Call an MCP tool on the VulHunt server."""
        result = await self._call("tools/call", {
            "name": name,
            "arguments": arguments,
        }, timeout=timeout)
        return result.get("result", {})

    async def open_project(
        self, path: str, kind: str = "DxeDriver"
    ) -> dict[str, Any]:
        """Open a binary as a VulHunt project."""
        return await self.call_tool("open_project", {
            "path": path,
            "attributes": {"kind": kind},
        })

    async def query_project(self, script: str) -> dict[str, Any]:
        """Run a Lua query against the open project."""
        return await self.call_tool("query_project", {
            "script": script,
        })


async def _get_vulhunt_client() -> VulHuntClient:
    """Create and initialize a VulHunt MCP client."""
    settings = get_settings()
    client = VulHuntClient(base_url=settings.vulhunt_url)
    await client.initialize()
    return client


# ── Binary detection helpers ─────────────────────────────────────────


def _is_elf(path: str) -> bool:
    """Check if a file is an ELF binary."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _is_pe(path: str) -> bool:
    """Check if a file is a PE32/PE32+ binary."""
    try:
        with open(path, "rb") as f:
            magic = f.read(2)
            if magic != b"MZ":
                return False
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            if len(pe_offset_bytes) < 4:
                return False
            pe_offset = int.from_bytes(pe_offset_bytes, "little")
            f.seek(pe_offset)
            return f.read(4) == b"PE\x00\x00"
    except OSError:
        return False


# Map UEFIExtract directory name patterns to VulHunt component kinds
_UEFI_KIND_MAP = {
    "Smm": "SmmModule",
    "SMM": "SmmModule",
    "Pei": "PeiModule",
    "PEI": "PeiModule",
    "Dxe": "DxeDriver",
    "DXE": "DxeDriver",
    "Sec": "SecCore",
    "SEC": "SecCore",
}


def _infer_uefi_kind(path: str) -> str:
    """Infer UEFI module kind from the UEFIExtract directory path."""
    parts = path.split("/")
    for part in reversed(parts):
        for pattern, kind in _UEFI_KIND_MAP.items():
            if pattern in part:
                return kind
    return "DxeDriver"  # safe default — most UEFI modules are DXE


def _find_binaries(root: str, max_count: int = 0, min_size: int = 4096) -> list[str]:
    """Find ELF and PE32+ binaries in a directory tree. max_count=0 means no limit."""
    binaries: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if max_count > 0 and len(binaries) >= max_count:
                return binaries
            fpath = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(fpath) < min_size:
                    continue
                if not os.path.isfile(fpath):
                    continue
                if _is_elf(fpath) or _is_pe(fpath):
                    binaries.append(fpath)
            except OSError:
                continue
    return binaries


def _collect_scan_targets_sync(
    detection_roots: list[str],
    extraction_dir: str | None,
    max_binaries: int,
    min_size: int,
) -> list[tuple[str, bool]]:
    """Collect ELF/PE32+ binaries to feed VulHunt.

    Walks every detection root (Rule #16) and additionally inspects
    extraction_dir for UEFIExtract `body.bin` modules. All filesystem I/O
    lives in this sync helper so the async handler can offload the entire
    discovery phase via run_in_executor (Rule #5). Returns a list of
    (path, is_pe) tuples — sniffing the magic byte once during collection
    avoids re-reading the file from inside the async per-binary scan loop.
    """
    binaries: list[tuple[str, bool]] = []
    # _find_binaries already calls _is_elf/_is_pe to filter, but doesn't
    # surface which one matched. Reproduce the walk here so we can record
    # is_pe alongside the path without a second magic-byte read per file.
    for root in detection_roots:
        if max_binaries > 0 and len(binaries) >= max_binaries:
            break
        for dirpath, _dirs, files in os.walk(root):
            for fname in files:
                if max_binaries > 0 and len(binaries) >= max_binaries:
                    break
                fpath = os.path.join(dirpath, fname)
                try:
                    if os.path.getsize(fpath) < min_size:
                        continue
                    if not os.path.isfile(fpath):
                        continue
                    if _is_elf(fpath):
                        binaries.append((fpath, False))
                    elif _is_pe(fpath):
                        binaries.append((fpath, True))
                except OSError:
                    continue

    # Also check extraction_dir for UEFI .dump/ body.bin files
    if extraction_dir:
        for dirpath, _dirs, files in os.walk(extraction_dir):
            if max_binaries > 0 and len(binaries) >= max_binaries:
                break
            if "body.bin" in files:
                body = os.path.join(dirpath, "body.bin")
                try:
                    if os.path.getsize(body) >= min_size:
                        if _is_elf(body):
                            binaries.append((body, False))
                        elif _is_pe(body):
                            binaries.append((body, True))
                except OSError:
                    pass
    return binaries


def _check_binary_signature_sync(real_path: str) -> str:
    """Return one of 'missing', 'not_binary', 'elf', 'pe' for a single file.

    Bundles the os.path.isfile + ELF/PE magic checks into a single sync
    helper so _handle_vulhunt_scan_binary can offload them in one hop.
    """
    if not os.path.isfile(real_path):
        return "missing"
    if _is_elf(real_path):
        return "elf"
    if _is_pe(real_path):
        return "pe"
    return "not_binary"


# ── Scanning via MCP ─────────────────────────────────────────────────

# Lua script that queries VulHunt for vulnerability analysis results
_VULN_QUERY_SCRIPT = """
local results = {}
local functions = project:functions()
for _, func in ipairs(functions) do
    local issues = func:issues()
    if issues and #issues > 0 then
        for _, issue in ipairs(issues) do
            table.insert(results, {
                severity = issue.severity or "unknown",
                rule_id = issue.rule_id or issue.id or "unknown",
                description = issue.description or issue.message or "",
                location = {
                    ["function"] = func:name(),
                    address = string.format("0x%x", func:address()),
                },
            })
        end
    end
end
return results
"""


async def _scan_binary_via_mcp(
    client: VulHuntClient, path: str, kind: str, timeout: float = 300
) -> list[dict]:
    """Open a binary in VulHunt and query for vulnerabilities."""
    try:
        result = await client.open_project(path, kind=kind)
        # Check for errors in the tool response
        content = result.get("content", [])
        for item in content:
            if item.get("type") == "text":
                text = item.get("text", "")
                if "error" in text.lower():
                    logger.warning("VulHunt open_project error for %s: %s", path, text[:200])
                    return []

        # Query for vulnerabilities
        query_result = await client.query_project(_VULN_QUERY_SCRIPT)
        content = query_result.get("content", [])
        for item in content:
            if item.get("type") == "text":
                text = item.get("text", "")
                try:
                    findings = json.loads(text)
                    if isinstance(findings, list):
                        return findings
                except json.JSONDecodeError:
                    pass
        return []
    except Exception as e:
        logger.warning("VulHunt scan failed for %s: %s", path, e)
        return []


def _format_findings(findings: list[dict], binary_name: str) -> str:
    """Format VulHunt findings as readable text."""
    if not findings:
        return f"  {binary_name}: No vulnerabilities found."

    lines = [f"  {binary_name}: {len(findings)} finding(s)"]
    for f in findings[:50]:
        severity = f.get("severity", "unknown")
        rule_id = f.get("rule_id", f.get("id", "unknown"))
        desc = f.get("description", f.get("message", ""))
        location = f.get("location", {})
        func = location.get("function", "")
        addr = location.get("address", "")

        loc_str = ""
        if func:
            loc_str = f" in {func}"
        if addr:
            loc_str += f" @ {addr}"

        lines.append(f"    [{severity:8s}] {rule_id}{loc_str}")
        if desc:
            lines.append(f"              {desc[:120]}")

    if len(findings) > 50:
        lines.append(f"    ... and {len(findings) - 50} more")

    return "\n".join(lines)


# ── Handlers ──────────────────────────────────────────────────────────


async def _handle_vulhunt_check_available(
    input: dict, context: ToolContext
) -> str:
    try:
        client = await _get_vulhunt_client()
        info = await client.initialize()
        server_info = info.get("serverInfo", {})
        name = server_info.get("name", "VulHunt")
        version = server_info.get("version", "unknown")
        return f"VulHunt is available.\n{name} v{version}"
    except Exception as e:
        return (
            "VulHunt container is not running or not available.\n"
            "Start it with: docker compose up -d vulhunt\n"
            f"Error: {e}"
        )


async def _handle_vulhunt_scan_binary(
    input: dict, context: ToolContext
) -> str:
    path = input.get("path", "")
    if not path:
        return "Error: 'path' is required."

    real_path = context.resolve_path(path)

    # Rule #5 — file existence + magic-byte sniff are sync I/O; offload.
    loop = asyncio.get_running_loop()
    sig = await loop.run_in_executor(
        None, _check_binary_signature_sync, real_path
    )
    if sig == "missing":
        return f"File not found: {path}"
    if sig == "not_binary":
        return f"{path} is not an ELF or PE32+ binary."

    try:
        client = await _get_vulhunt_client()
    except Exception as e:
        return f"VulHunt is not available. Start with: docker compose up -d vulhunt\nError: {e}"

    kind = _infer_uefi_kind(real_path) if sig == "pe" else "DxeDriver"
    settings = get_settings()
    findings = await _scan_binary_via_mcp(
        client, real_path, kind=kind, timeout=settings.vulhunt_timeout
    )

    binary_name = os.path.basename(real_path)
    return _format_findings(findings, binary_name)


async def _handle_vulhunt_scan_firmware(
    input: dict, context: ToolContext
) -> str:
    max_binaries = input.get("max_binaries", 0)
    min_size = input.get("min_size", 4096)

    # Rule #16: walk every detection root, not just `extracted_path`.
    # Scatter-zip uploads, multi-archive medical firmware, and nested
    # unblob output produce sibling directories that `extracted_path`
    # alone misses (the original DPCS10 / RespArray bug class — same
    # root cause as Rule #16 but on the next layer up).
    detection_roots = context.get_detection_roots()
    if not detection_roots:
        return "No extracted firmware available."

    # Rule #5 — discovery walks every detection root + extraction_dir for
    # UEFIExtract body.bin modules; both are sync I/O, possibly across
    # 10K+ files. Offload the full discovery phase in one hop.
    loop = asyncio.get_running_loop()
    binaries = await loop.run_in_executor(
        None,
        _collect_scan_targets_sync,
        detection_roots,
        context.extraction_dir,
        max_binaries,
        min_size,
    )
    # Preserve the prior behaviour where `os.path.relpath(binary_path, root)`
    # used `root` from the last iteration of `detection_roots`. This isn't
    # strictly correct for binaries discovered in earlier roots, but matches
    # the pre-refactor output exactly.
    last_root = detection_roots[-1]

    if not binaries:
        return "No ELF or PE32+ binaries found in the firmware."

    # Connect to VulHunt
    try:
        client = await _get_vulhunt_client()
    except Exception as e:
        return (
            f"Found {len(binaries)} binaries but VulHunt is not available.\n"
            f"Start with: docker compose up -d vulhunt\nError: {e}"
        )

    project_id = str(context.project_id)
    total = len(binaries)
    settings = get_settings()
    results: list[str] = []
    total_findings = 0
    scanned = 0

    # Emit start event
    try:
        await event_service.publish_progress(
            project_id, "vulhunt",
            status="running",
            progress=0.0,
            message=f"Scanning {total} binaries...",
            extra={"scanned": 0, "total": total, "findings": 0},
        )
    except Exception:
        pass  # SSE is best-effort

    for binary_path, is_pe in binaries:
        binary_name = os.path.relpath(binary_path, last_root)
        kind = _infer_uefi_kind(binary_path) if is_pe else "DxeDriver"
        findings = await _scan_binary_via_mcp(
            client, binary_path, kind=kind, timeout=settings.vulhunt_timeout
        )
        scanned += 1
        total_findings += len(findings)
        if findings:
            results.append(_format_findings(findings, binary_name))

        try:
            await event_service.publish_progress(
                project_id, "vulhunt",
                status="running" if scanned < total else "completed",
                progress=scanned / total,
                message=f"Scanned {scanned}/{total} binaries — {total_findings} finding(s)",
                extra={
                    "scanned": scanned,
                    "total": total,
                    "findings": total_findings,
                    "current_binary": binary_name,
                    "results_text": "\n\n".join(results) if results else "",
                },
            )
        except Exception:
            pass

    header = (
        f"VulHunt Firmware Scan: {scanned} binaries scanned, "
        f"{total_findings} finding(s)\n"
        f"{'=' * 60}"
    )

    if not results:
        return header + "\n\nNo vulnerabilities found in any binary."

    return header + "\n\n" + "\n\n".join(results)
