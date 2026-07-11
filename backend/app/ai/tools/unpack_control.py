"""MCP tools for manual unpack control.

When the auto-unpacker can't get a firmware emulation-ready on its own — most
often an app-only OTA that ships a kernel + ``/app`` partition but no base
rootfs (the busybox/init root lives on a separate flash partition not in the
image) — these tools let the agent fix it like a researcher would:

  1. Investigate / carve / assemble in the sandbox with ``run_shell`` (binwalk,
     unsquashfs, cpio, dd, python+crypto …). Output lands at ``/_carved/...``;
     ``/extracted`` is writable for in-place fixes.
  2. Make the result authoritative with the tools here:
       - ``set_firmware_arch``  → unblocks the emulation architecture gate
       - ``set_rootfs``         → the filesystem root emulation/analysis uses
       - ``set_kernel``         → the kernel image emulation boots
       - ``redetect``           → re-run detection over the current extraction

Typical app-only-OTA recipe the agent can run end to end::

    run_shell: cp -a /extracted/squashfs-root /carved/root          # start from /app
    run_shell: # ...drop in a busybox/init/loader, fix symlinks & perms...
    set_rootfs: /_carved/root
    set_firmware_arch: arm little
    start_emulation ...
"""

from __future__ import annotations

import logging

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.services.unpack_control_service import (
    UnpackControlError,
    UnpackControlService,
)

logger = logging.getLogger(__name__)


async def _load_firmware(context: ToolContext) -> Firmware | None:
    result = await context.db.execute(
        select(Firmware).where(
            Firmware.id == context.firmware_id,
            Firmware.project_id == context.project_id,
        )
    )
    return result.scalar_one_or_none()


def _summary(firmware: Firmware) -> str:
    return (
        f"  architecture: {firmware.architecture or 'unknown'}\n"
        f"  endianness:   {firmware.endianness or 'unknown'}\n"
        f"  rootfs:       {firmware.extracted_path or '(none)'}\n"
        f"  kernel:       {firmware.kernel_path or '(none)'}"
    )


async def _handle_set_firmware_arch(input: dict, context: ToolContext) -> str:
    architecture = input.get("architecture")
    endianness = input.get("endianness")
    if not isinstance(architecture, str) or not architecture.strip():
        return "Error: 'architecture' is required (e.g. 'arm', 'mipsel', 'aarch64')."

    firmware = await _load_firmware(context)
    if firmware is None:
        return "Error: no active firmware to update."

    try:
        await UnpackControlService(context.db).set_architecture(
            firmware, architecture, endianness
        )
    except UnpackControlError as exc:
        return f"Error: {exc}"

    return (
        "Architecture set. The emulation architecture gate will now pass.\n"
        + _summary(firmware)
    )


async def _handle_set_rootfs(input: dict, context: ToolContext) -> str:
    path = input.get("path")
    if not isinstance(path, str) or not path.strip():
        return (
            "Error: 'path' is required — a virtual firmware path to the "
            "directory to use as the root (e.g. '/_carved/root', '/rootfs', "
            "'/squashfs-root-0')."
        )

    firmware = await _load_firmware(context)
    if firmware is None:
        return "Error: no active firmware to update."

    try:
        await UnpackControlService(context.db).set_rootfs(firmware, path)
    except UnpackControlError as exc:
        return f"Error: {exc}"

    return (
        f"Rootfs set to '{path}'. Filesystem tools and emulation now use this "
        f"directory as the root (surfaced at /rootfs).\n" + _summary(firmware)
    )


async def _handle_set_kernel(input: dict, context: ToolContext) -> str:
    path = input.get("path")
    if not isinstance(path, str) or not path.strip():
        return (
            "Error: 'path' is required — a virtual firmware path to the kernel "
            "image file (e.g. '/_carved/uImage', '/37FC')."
        )

    firmware = await _load_firmware(context)
    if firmware is None:
        return "Error: no active firmware to update."

    try:
        await UnpackControlService(context.db).set_kernel(firmware, path)
    except UnpackControlError as exc:
        return f"Error: {exc}"

    return f"Kernel set to '{path}'.\n" + _summary(firmware)


async def _handle_redetect(input: dict, context: ToolContext) -> str:
    targets = input.get("targets")
    if targets is not None and not isinstance(targets, list):
        return "Error: 'targets' must be a list of: rootfs, arch, kernel."

    firmware = await _load_firmware(context)
    if firmware is None:
        return "Error: no active firmware to update."

    try:
        _fw, report = await UnpackControlService(context.db).redetect(
            firmware, targets
        )
    except UnpackControlError as exc:
        return f"Error: {exc}"

    lines = ["Re-detection complete."]
    for key in ("rootfs", "arch", "kernel"):
        if key in report:
            lines.append(f"  {key}: {report[key] if report[key] else 'not found'}")
    lines.append("Current state:")
    lines.append(_summary(firmware))
    return "\n".join(lines)


def register_unpack_control_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="set_firmware_arch",
        description=(
            "Manually set the firmware's CPU architecture and endianness when "
            "auto-detection returned 'unknown'. Unblocks the emulation "
            "architecture gate. Use when file_info/get_binary_info on an "
            "extracted ELF, or the uImage header, clearly shows the arch but "
            "the project still reports 'unknown'. architecture is one of: arm, "
            "aarch64, mips, mipsel, x86, x86_64, ppc, ppc64, sh, sparc, riscv."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "architecture": {
                    "type": "string",
                    "description": "Canonical arch name, e.g. 'arm', 'mipsel', 'aarch64'.",
                },
                "endianness": {
                    "type": "string",
                    "enum": ["little", "big"],
                    "description": "Optional; inferred for mipsel, else left unchanged.",
                },
            },
            "required": ["architecture"],
        },
        handler=_handle_set_firmware_arch,
    )

    registry.register(
        name="set_rootfs",
        description=(
            "Designate a directory as the filesystem root used by emulation and "
            "the file tools (surfaced as /rootfs). Use when the unpacker picked "
            "the wrong filesystem, or after you carved/assembled a workable root "
            "in the sandbox (e.g. copied /extracted/squashfs-root to /carved and "
            "fixed it up). 'path' is a virtual firmware path such as "
            "'/_carved/root', '/rootfs', or '/squashfs-root-0'."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Virtual path to the directory to use as the root.",
                },
            },
            "required": ["path"],
        },
        handler=_handle_set_rootfs,
    )

    registry.register(
        name="set_kernel",
        description=(
            "Designate a file as the kernel image emulation should boot (system "
            "mode). Use after you identify/extract the right kernel (e.g. a "
            "decompressed vmlinux or a uImage) in the sandbox. 'path' is a "
            "virtual firmware path such as '/_carved/uImage'."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Virtual path to the kernel image file.",
                },
            },
            "required": ["path"],
        },
        handler=_handle_set_kernel,
    )

    registry.register(
        name="redetect",
        description=(
            "Re-run unpack detection (filesystem root, architecture, kernel) "
            "over the firmware's existing extraction without re-uploading. "
            "Architecture detection now also fingerprints ELFs anywhere in the "
            "tree and falls back to the uImage header. Optionally limit to "
            "specific targets."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["rootfs", "arch", "kernel"]},
                    "description": "Which fields to refresh; defaults to all three.",
                },
            },
        },
        handler=_handle_redetect,
    )
