"""RTOS-specific MCP tools.

These tools are tagged ``applies_to=("rtos",)`` and operate on the raw
firmware blob (``context.storage_path``) rather than an unpacked rootfs.
ELF/.axf images get rich analysis via pyelftools; raw .bin images
degrade gracefully to byte-level heuristics where possible.
"""

import os
import struct

from elftools.elf.elffile import ELFFile

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.services.rtos_detection_service import detect_firmware_kind


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _open_elf(path: str):
    """Open *path* as an ELFFile if its magic matches; else (None, None)."""
    try:
        fh = open(path, "rb")
    except OSError:
        return None, None
    if fh.read(4) != b"\x7fELF":
        fh.close()
        return None, None
    fh.seek(0)
    try:
        return ELFFile(fh), fh
    except Exception:
        fh.close()
        return None, None


def _storage_path(context: ToolContext) -> str | None:
    p = context.storage_path
    if not p or not os.path.isfile(p):
        return None
    return p


def _seg_perms(flags: int) -> str:
    return (
        ("R" if flags & 4 else "-")
        + ("W" if flags & 2 else "-")
        + ("X" if flags & 1 else "-")
    )


def _build_symtab(elf) -> dict[int, str]:
    """Map function-symbol address (thumb bit cleared) to name."""
    out: dict[int, str] = {}
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        return out
    for sym in symtab.iter_symbols():
        addr = sym["st_value"]
        name = sym.name or ""
        if not name or not addr:
            continue
        out.setdefault(addr & ~1, name)
    return out


# ---------------------------------------------------------------------------
# detect_rtos_kernel
# ---------------------------------------------------------------------------


async def _handle_detect_rtos_kernel(input: dict, context: ToolContext) -> str:
    path = _storage_path(context)
    if path is None:
        return "Error: firmware blob is unavailable (storage_path missing)."
    detection = detect_firmware_kind(path, None, None)
    lines = [
        f"Kind: {detection.kind}",
        f"Flavor: {detection.flavor or '(none)'}",
        f"Notes: {detection.notes}",
    ]
    elf, fh = _open_elf(path)
    if elf is not None:
        try:
            lines.append(f"ELF machine: {elf.header.e_machine}")
            lines.append(
                f"ELF endianness: {'little' if elf.little_endian else 'big'}"
            )
            lines.append(f"ELF entry: 0x{elf.header.e_entry:08x}")
        finally:
            fh.close()
    else:
        try:
            lines.append(f"Image size: {os.path.getsize(path)} bytes (raw, non-ELF)")
        except OSError:
            pass
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# enumerate_rtos_tasks
# ---------------------------------------------------------------------------


_TASK_NAME_HINTS = ("Task", "Thread", "task", "thread")
_FREERTOS_INFRA_PREFIX = ("vTask", "xTask", "uxTask", "prv", "xQueue", "xSemaphore")


async def _handle_enumerate_rtos_tasks(input: dict, context: ToolContext) -> str:
    path = _storage_path(context)
    if path is None:
        return "Error: firmware blob is unavailable."
    elf, fh = _open_elf(path)
    if elf is None:
        return (
            "enumerate_rtos_tasks requires an ELF image (.axf/.elf). "
            "This firmware is a raw binary — task enumeration is not supported "
            "without symbol metadata."
        )
    try:
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return (
                "ELF has no .symtab — image is stripped. Cannot enumerate "
                "tasks symbolically. Try analyze_vector_table for execution "
                "entry points instead."
            )
        candidates: list[tuple[int, int, str]] = []
        infrastructure: list[tuple[int, int, str]] = []
        for sym in symtab.iter_symbols():
            if sym["st_info"]["type"] != "STT_FUNC":
                continue
            name = sym.name or ""
            if not name:
                continue
            addr = sym["st_value"] & ~1
            size = sym["st_size"]
            if any(name.startswith(p) for p in _FREERTOS_INFRA_PREFIX):
                infrastructure.append((addr, size, name))
            elif any(h in name for h in _TASK_NAME_HINTS):
                candidates.append((addr, size, name))

        lines = [f"Likely task entry-point functions ({len(candidates)}):"]
        if not candidates:
            lines.append("  (no matches; binary may use non-standard naming)")
        for addr, size, name in sorted(candidates)[:80]:
            lines.append(f"  0x{addr:08x}  size={size:>5}  {name}")
        lines.append("")
        lines.append(
            f"FreeRTOS / kernel infrastructure functions "
            f"({len(infrastructure)}):"
        )
        for addr, size, name in sorted(infrastructure)[:60]:
            lines.append(f"  0x{addr:08x}  size={size:>5}  {name}")
        return "\n".join(lines)
    finally:
        fh.close()


# ---------------------------------------------------------------------------
# analyze_vector_table
# ---------------------------------------------------------------------------


# ARM Cortex-M built-in exceptions (index 0 is the initial SP, not a handler).
_CORTEX_M_CORE = [
    "Initial_SP", "Reset", "NMI", "HardFault",
    "MemManage", "BusFault", "UsageFault", "Reserved",
    "Reserved", "Reserved", "Reserved", "SVCall",
    "DebugMon", "Reserved", "PendSV", "SysTick",
]


async def _handle_analyze_vector_table(input: dict, context: ToolContext) -> str:
    path = _storage_path(context)
    if path is None:
        return "Error: firmware blob is unavailable."
    count = max(16, min(int(input.get("count", 32) or 32), 256))

    elf, fh = _open_elf(path)
    blob: bytes | None = None
    section_name = ""
    base_addr = 0
    base_known = False
    sym_at: dict[int, str] = {}
    try:
        if elf is not None:
            for cand in (".isr_vector", ".vectors", ".vector_table"):
                sec = elf.get_section_by_name(cand)
                if sec is not None:
                    blob = sec.data()
                    section_name = cand
                    base_addr = sec["sh_addr"]
                    base_known = True
                    break
            if blob is None:
                # Fall back to the first executable LOAD segment — in most
                # Cortex-M firmware the vector table sits at the start of
                # flash, which is the first LOAD segment.
                for seg in elf.iter_segments():
                    if seg["p_type"] == "PT_LOAD" and seg["p_flags"] & 1:
                        blob = bytes(seg.data())
                        section_name = "(first executable LOAD segment)"
                        base_addr = seg["p_vaddr"]
                        base_known = True
                        break
            sym_at = _build_symtab(elf)
        else:
            with open(path, "rb") as raw:
                blob = raw.read(count * 4)
            section_name = "(raw image, file offset 0)"
    finally:
        if fh is not None:
            fh.close()

    if blob is None or len(blob) < 8:
        return "Could not locate a vector-table region in this image."

    n = min(count, len(blob) // 4)
    words = struct.unpack_from("<" + "I" * n, blob)

    lines = [
        f"Vector table source: {section_name}",
        (
            f"Base address: 0x{base_addr:08x}"
            if base_known
            else "Base address: (raw — load address unknown)"
        ),
        f"Entries: {n}",
        "",
        f"  {'#':>3}  {'addr':>10}  {'value':>10}  exception              handler",
    ]
    for i, w in enumerate(words):
        if i < len(_CORTEX_M_CORE):
            label = _CORTEX_M_CORE[i]
        else:
            label = f"IRQ{i - 16}"
        # Handlers carry the thumb bit; stripping it is what hits .symtab.
        target = w if i == 0 else (w & ~1)
        sym = sym_at.get(target, "")
        addr = base_addr + i * 4
        lines.append(
            f"  {i:>3}  0x{addr:08x}  0x{w:08x}  {label:<22} {sym}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# recover_base_address
# ---------------------------------------------------------------------------


async def _handle_recover_base_address(input: dict, context: ToolContext) -> str:
    path = _storage_path(context)
    if path is None:
        return "Error: firmware blob is unavailable."

    elf, fh = _open_elf(path)
    if elf is not None:
        try:
            lines = [
                f"ELF machine: {elf.header.e_machine}",
                f"ELF entry point: 0x{elf.header.e_entry:08x}",
                "",
                "LOAD segments:",
            ]
            any_seg = False
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                any_seg = True
                lines.append(
                    f"  vaddr=0x{seg['p_vaddr']:08x}  paddr=0x{seg['p_paddr']:08x}  "
                    f"filesz=0x{seg['p_filesz']:08x}  memsz=0x{seg['p_memsz']:08x}  "
                    f"perms={_seg_perms(seg['p_flags'])}"
                )
            if not any_seg:
                lines.append("  (none — relocatable object?)")
            return "\n".join(lines)
        finally:
            fh.close()

    # Raw .bin: infer from the Cortex-M reset vector
    try:
        with open(path, "rb") as raw:
            head = raw.read(8)
    except OSError as exc:
        return f"Error reading image: {exc}"
    if len(head) < 8:
        return "Image too small to recover a base address."
    initial_sp, reset_handler = struct.unpack("<II", head)
    target = reset_handler & ~1
    lines = [
        "Raw binary — best-effort base recovery from Cortex-M reset vector:",
        f"  Initial SP:    0x{initial_sp:08x}  "
        f"(typical RAM regions: 0x20000000+, 0x10000000+)",
        f"  Reset handler: 0x{reset_handler:08x}  "
        f"(target 0x{target:08x}, "
        f"thumb bit {'set' if reset_handler & 1 else 'CLEAR — suspicious!'})",
    ]
    if 0x08000000 <= target <= 0x080FFFFF:
        lines.append("  Likely flash base: 0x08000000 (STM32 family)")
    elif target < 0x00200000:
        lines.append(
            "  Likely flash base: 0x00000000 (generic Cortex-M alias / Nordic)"
        )
    elif 0x10000000 <= target <= 0x1FFFFFFF:
        lines.append("  Likely flash base: 0x10000000 (NXP / nRF52)")
    else:
        lines.append(
            "  Flash base: ambiguous — provide the load offset manually."
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# analyze_memory_map
# ---------------------------------------------------------------------------


# ELF section flag bits we care about
_SHF_WRITE = 0x1
_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4


async def _handle_analyze_memory_map(input: dict, context: ToolContext) -> str:
    path = _storage_path(context)
    if path is None:
        return "Error: firmware blob is unavailable."
    elf, fh = _open_elf(path)
    if elf is None:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = -1
        return (
            f"Raw binary, {size} bytes. No segment metadata available without "
            "an ELF — call recover_base_address for a load-address estimate."
        )

    try:
        lines = ["LOAD segments:"]
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            lines.append(
                f"  vaddr=0x{seg['p_vaddr']:08x}  paddr=0x{seg['p_paddr']:08x}  "
                f"filesz=0x{seg['p_filesz']:08x}  memsz=0x{seg['p_memsz']:08x}  "
                f"perms={_seg_perms(seg['p_flags'])}"
            )

        flash_rows: list[tuple[int, str]] = []
        ram_rows: list[tuple[int, str]] = []
        rodata_rows: list[tuple[int, str]] = []

        for sec in elf.iter_sections():
            if sec["sh_size"] == 0:
                continue
            name = sec.name or "(unnamed)"
            if name.startswith(".debug") or name.startswith(".comment"):
                continue
            flags = sec["sh_flags"]
            if not (flags & _SHF_ALLOC):
                continue
            write = bool(flags & _SHF_WRITE)
            execinstr = bool(flags & _SHF_EXECINSTR)
            row = (
                f"  {name:<22} addr=0x{sec['sh_addr']:08x}  "
                f"size=0x{sec['sh_size']:08x}  "
                f"perms={_seg_perms((4 if flags & _SHF_ALLOC else 0) | (2 if write else 0) | (1 if execinstr else 0))}"
            )
            key = sec["sh_addr"]
            if write:
                ram_rows.append((key, row))
            elif execinstr:
                flash_rows.append((key, row))
            else:
                rodata_rows.append((key, row))

        if flash_rows:
            lines.append("")
            lines.append("Flash (executable) sections:")
            for _, row in sorted(flash_rows):
                lines.append(row)
        if rodata_rows:
            lines.append("")
            lines.append("Read-only data sections:")
            for _, row in sorted(rodata_rows):
                lines.append(row)
        if ram_rows:
            lines.append("")
            lines.append("RAM (writable) sections:")
            for _, row in sorted(ram_rows):
                lines.append(row)
        return "\n".join(lines)
    finally:
        fh.close()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_rtos_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="detect_rtos_kernel",
        description=(
            "Re-run RTOS detection against the firmware blob and return the "
            "resulting kind (linux/rtos/unknown), flavor "
            "(freertos/zephyr/baremetal-cortexm), the matching evidence, and "
            "ELF metadata when available. Useful for verifying the "
            "auto-detected classification."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_detect_rtos_kernel,
        applies_to=("rtos",),
    )
    registry.register(
        name="enumerate_rtos_tasks",
        description=(
            "List likely RTOS task entry-point functions and FreeRTOS / "
            "kernel infrastructure symbols by scanning the ELF .symtab. "
            "Requires an unstripped ELF (.axf/.elf); raw .bin images are "
            "rejected."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_enumerate_rtos_tasks,
        applies_to=("rtos",),
    )
    registry.register(
        name="analyze_vector_table",
        description=(
            "Parse the ARM Cortex-M vector table from the firmware. Prefers "
            "the .isr_vector / .vectors / .vector_table section, falling back "
            "to the first executable LOAD segment for ELFs or file offset 0 "
            "for raw .bin. Each entry is rendered with its standard exception "
            "name and (when known) the resolved handler symbol."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "count": {
                    "type": "integer",
                    "minimum": 16,
                    "maximum": 256,
                    "description": "Number of vector-table entries to display (default 32, max 256).",
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_analyze_vector_table,
        applies_to=("rtos",),
    )
    registry.register(
        name="recover_base_address",
        description=(
            "Recover the firmware load address. For ELF images returns each "
            "LOAD segment's vaddr/paddr/perms. For raw .bin images, infers a "
            "likely flash base from the Cortex-M reset vector (initial SP + "
            "reset handler)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_recover_base_address,
        applies_to=("rtos",),
    )
    registry.register(
        name="analyze_memory_map",
        description=(
            "Show the firmware's memory layout: ELF program-header LOAD "
            "segments and notable allocated sections, classified into flash "
            "(executable / read-only) vs RAM (writable). Useful for setting "
            "up Ghidra/IDA loaders or QEMU memory maps."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_analyze_memory_map,
        applies_to=("rtos",),
    )
