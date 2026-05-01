"""MCP tools for the firmware carving sandbox.

Exposes ``run_shell``: a single command-execution tool that runs in an
isolated, network-less Docker container with the standard reverse-engineering
toolset (binwalk, dd, xxd, file, strings, readelf, python3 + cryptography,
unsquashfs, jefferson, ubi_reader, mkimage, etc.) plus access to the raw
firmware blob and a writable carved-output directory.

Design rationale (see WAIRZ_CARVING_BRIEFING.md):
  - Auto-extracting every vendor envelope is brittle; instead, give the agent
    primitives and let it carve manually as the analysis dictates.
  - One shell tool composes via pipes and the agent already knows the toolset.
  - Outputs land under /carved/ which maps to /_carved/ in the project's
    virtual filesystem — automatically visible to read_file, extract_strings,
    decompile_function, etc.
"""

from __future__ import annotations

import logging

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.services.carving_service import CarvingError, CarvingService

logger = logging.getLogger(__name__)

# Cap each side of the output independently so a flood of stderr can't
# entirely shadow the stdout the agent actually wants to see. The overall
# tool reply is further truncated by ToolRegistry.execute → truncate_output.
_PER_STREAM_CAP_BYTES = 12_000


def _cap(stream: str, cap: int) -> str:
    if len(stream) <= cap:
        return stream
    head = stream[: cap - 80]
    return f"{head}\n…[truncated {len(stream) - len(head)} bytes]"


async def _handle_run_shell(input: dict, context: ToolContext) -> str:
    command = input.get("command")
    if not isinstance(command, str) or not command.strip():
        return "Error: 'command' is required and must be a non-empty string."

    timeout = input.get("timeout")
    if timeout is not None:
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            return "Error: 'timeout' must be an integer (seconds)."

    service = CarvingService(context.db)
    try:
        result = await service.run_command(
            project_id=context.project_id,
            firmware_id=context.firmware_id,
            command=command,
            timeout=timeout,
        )
    except CarvingError as exc:
        return f"Error: {exc}"
    except Exception as exc:
        logger.exception("run_shell failed")
        return f"Error: unexpected failure invoking carving sandbox: {exc}"

    parts: list[str] = []
    if result.timed_out:
        parts.append(
            f"[command timed out after the configured limit; partial output below]"
        )
    parts.append(f"exit_code: {result.exit_code}")
    if result.stdout:
        parts.append("stdout:")
        parts.append(_cap(result.stdout, _PER_STREAM_CAP_BYTES))
    else:
        parts.append("stdout: (empty)")
    if result.stderr:
        parts.append("stderr:")
        parts.append(_cap(result.stderr, _PER_STREAM_CAP_BYTES))
    return "\n".join(parts)


def register_carving_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="run_shell",
        description=(
            "Run a shell command in the firmware carving sandbox — an isolated, "
            "network-less Docker container with read-only access to the raw "
            "firmware image and read-write access to a per-firmware carved/ "
            "directory.\n"
            "\n"
            "Mounts inside the sandbox:\n"
            "  /image/firmware.bin  — original uploaded blob (RO)\n"
            "  /extracted/          — unpacked filesystem tree (RO, if extracted)\n"
            "  /carved/             — your output directory (RW); contents appear "
            "in the project filesystem at /_carved/ and are visible to all other "
            "wairz tools (read_file, extract_strings, decompile_function, …).\n"
            "  /tmp/                — tmpfs scratch (256 MiB)\n"
            "\n"
            "Toolset preinstalled: binwalk, dd, xxd, hexdump, file, strings, grep, "
            "readelf, objdump, python3 with cryptography + pycryptodome, lz4, "
            "xz, zstd, unsquashfs, jefferson, ubi_reader, mtd-utils, mkimage, "
            "p7zip, jq, bsdtar, cpio.\n"
            "\n"
            "Sandbox: no network, all capabilities dropped, read-only root, "
            "non-root user, 1 GiB memory cap. Working directory is /carved/.\n"
            "\n"
            "Example: dd if=/image/firmware.bin of=/carved/manifest.bin bs=1 "
            "skip=0 count=832\n"
            "\n"
            "Default timeout: 60 s. Max: 600 s. The container persists across "
            "calls within the project session; carved files persist forever."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": (
                        "Shell command to run. Passed to bash -c so pipelines, "
                        "redirects, and multi-statement scripts are supported."
                    ),
                },
                "timeout": {
                    "type": "integer",
                    "description": "Wall-clock timeout in seconds (default 60, max 600).",
                },
            },
            "required": ["command"],
        },
        handler=_handle_run_shell,
    )
