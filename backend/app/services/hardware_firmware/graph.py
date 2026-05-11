"""Driver <-> firmware dependency graph builder.

Resolves references between kernel modules (.ko) / vmlinux and the firmware
blobs they load via ``request_firmware()``, matching on filename.  Uses
metadata already extracted by Phase 2 parsers (kmod ``firmware_deps``, DTB
``firmware_names``).  Additionally scans vmlinux for hardcoded firmware
paths.

Write-side behavior:

* Populates ``HardwareFirmwareBlob.driver_references`` with the raw list of
  requested firmware names per .ko driver (unresolved or not).
* Creates ``Finding`` rows (source=``hardware_firmware_graph``) for every
  distinct unresolved firmware-name reference.  Idempotent: second run
  against the same firmware does not create duplicate findings.

Read-side behavior:

* Returns a flat list of ``DriverFirmwareEdge`` objects that the overlay
  endpoint and the ``list_firmware_drivers`` MCP tool collapse per-driver.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.services.jsonb_normalizers import _normalize_hardware_firmware_blobs_metadata

logger = logging.getLogger(__name__)

# Extensions typical of firmware names referenced by drivers.
_FW_EXT_PATTERN = re.compile(
    rb"([A-Za-z0-9_\-/.]+?\.(?:bin|fw|mbn|hex|ucode|nvm|ncd|hcd|clm_blob|elf|bx))\b",
    re.IGNORECASE,
)

# Only scan vmlinux first 32 MB for firmware paths.  Decompressed kernel
# images very rarely exceed ~50 MB; capping reads bounds I/O and regex cost.
_VMLINUX_SCAN_BYTES = 32 * 1024 * 1024

# Maximum distinct firmware strings we will record from a single vmlinux scan.
_VMLINUX_MAX_REFS = 500


@dataclass
class DriverFirmwareEdge:
    """One reference: driver (ko or vmlinux) -> firmware blob.

    ``firmware_blob_path`` is ``None`` when the requested firmware is not
    present in the extracted image (i.e. unresolved).
    """

    driver_path: str
    firmware_name: str
    firmware_blob_path: str | None
    source: str  # "kmod_modinfo" | "vmlinux_strings" | "dtb_firmware_name"


@dataclass
class GraphResult:
    edges: list[DriverFirmwareEdge]
    unresolved_count: int
    kmod_drivers: int
    dtb_sources: int


async def build_driver_firmware_graph(
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> GraphResult:
    """Build driver <-> firmware graph for one firmware.

    - Reads Phase 2 parser metadata for ``.ko`` ``firmware_deps`` and DTB
      ``firmware_names``.
    - Optionally scans vmlinux for embedded firmware paths.
    - Writes ``driver_references`` back to each driver's
      ``HardwareFirmwareBlob`` row.
    - Creates ``Finding`` rows for unresolved references (dedup by title).
    - Returns an edge list suitable for the overlay API / MCP tool.
    """
    stmt = select(HardwareFirmwareBlob).where(
        HardwareFirmwareBlob.firmware_id == firmware_id,
    )
    result = await db.execute(stmt)
    blobs = list(result.scalars().all())

    if not blobs:
        return GraphResult(edges=[], unresolved_count=0, kmod_drivers=0, dtb_sources=0)

    # Build filename index: basename(blob.blob_path) -> [blobs].  Multiple
    # blobs may share a basename (e.g. same firmware under system/ and
    # vendor/ partitions), so we keep a list rather than a single hit.
    fw_by_name: dict[str, list[HardwareFirmwareBlob]] = {}
    for blob in blobs:
        base = os.path.basename(blob.blob_path)
        fw_by_name.setdefault(base, []).append(blob)

    edges: list[DriverFirmwareEdge] = []

    # ----- Kmod drivers -----
    kmod_drivers = 0
    for blob in blobs:
        if blob.format != "ko":
            continue
        fw_deps = _normalize_hardware_firmware_blobs_metadata(blob.metadata_).get("firmware_deps") or []
        if not fw_deps:
            continue
        kmod_drivers += 1
        refs: list[str] = []
        for dep in fw_deps:
            match_blobs = _resolve_firmware_name(dep, fw_by_name)
            refs.append(dep)
            if match_blobs:
                for m in match_blobs:
                    edges.append(
                        DriverFirmwareEdge(
                            driver_path=blob.blob_path,
                            firmware_name=dep,
                            firmware_blob_path=m.blob_path,
                            source="kmod_modinfo",
                        )
                    )
            else:
                edges.append(
                    DriverFirmwareEdge(
                        driver_path=blob.blob_path,
                        firmware_name=dep,
                        firmware_blob_path=None,
                        source="kmod_modinfo",
                    )
                )
        # Mutate in-place; the session tracks the attribute change and will
        # flush it back to the row.
        blob.driver_references = refs

    # ----- DTB firmware-name references -----
    dtb_sources = 0
    for blob in blobs:
        if blob.format not in ("dtb", "dtbo"):
            continue
        fw_names = _normalize_hardware_firmware_blobs_metadata(blob.metadata_).get("firmware_names") or []
        if not fw_names:
            continue
        dtb_sources += 1
        for name in fw_names:
            match_blobs = _resolve_firmware_name(name, fw_by_name)
            if match_blobs:
                for m in match_blobs:
                    edges.append(
                        DriverFirmwareEdge(
                            driver_path=blob.blob_path,
                            firmware_name=name,
                            firmware_blob_path=m.blob_path,
                            source="dtb_firmware_name",
                        )
                    )
            else:
                edges.append(
                    DriverFirmwareEdge(
                        driver_path=blob.blob_path,
                        firmware_name=name,
                        firmware_blob_path=None,
                        source="dtb_firmware_name",
                    )
                )

    # ----- vmlinux string scan (best-effort) -----
    fw_stmt = select(Firmware).where(Firmware.id == firmware_id)
    fw_row = (await db.execute(fw_stmt)).scalar_one_or_none()

    loop = asyncio.get_event_loop()
    kernel_is_file = bool(
        fw_row and fw_row.kernel_path and await loop.run_in_executor(
            None, os.path.isfile, fw_row.kernel_path,
        )
    )
    if kernel_is_file:
        vmlinux_refs = await loop.run_in_executor(
            None, _scan_vmlinux_firmware_strings, fw_row.kernel_path,
        )
        # Record a stable "vmlinux" driver path. Prefer the firmware-root
        # relative path so the overlay matches component-map ids; fall
        # back to the absolute path. Phase 3b: iterate every detection
        # root so a kernel image sitting in a sibling partition dir (e.g.
        # scatter-zip ``boot/`` partition, raw ``kernel.img``) still gets
        # a stable relative path instead of an absolute one.
        from app.services.firmware_paths import get_detection_roots

        detection_roots = await get_detection_roots(fw_row, db=db)
        vmlinux_path = await loop.run_in_executor(
            None, _resolve_vmlinux_relative_path, fw_row.kernel_path, list(detection_roots),
        )

        for ref in vmlinux_refs:
            match_blobs = _resolve_firmware_name(ref, fw_by_name)
            if match_blobs:
                for m in match_blobs:
                    edges.append(
                        DriverFirmwareEdge(
                            driver_path=vmlinux_path,
                            firmware_name=ref,
                            firmware_blob_path=m.blob_path,
                            source="vmlinux_strings",
                        )
                    )
            else:
                edges.append(
                    DriverFirmwareEdge(
                        driver_path=vmlinux_path,
                        firmware_name=ref,
                        firmware_blob_path=None,
                        source="vmlinux_strings",
                    )
                )

    # ----- Missing-firmware findings (dedup by firmware name) -----
    unresolved_names: dict[str, list[str]] = {}
    for e in edges:
        if e.firmware_blob_path is None:
            unresolved_names.setdefault(e.firmware_name, []).append(e.driver_path)

    if unresolved_names and fw_row is not None:
        await _write_missing_firmware_findings(
            db, fw_row.project_id, firmware_id, unresolved_names,
        )

    await db.flush()

    logger.info(
        "HW firmware graph: %d kmod drivers, %d DTB sources, %d edges, %d unresolved",
        kmod_drivers,
        dtb_sources,
        len(edges),
        len(unresolved_names),
    )
    return GraphResult(
        edges=edges,
        unresolved_count=len(unresolved_names),
        kmod_drivers=kmod_drivers,
        dtb_sources=dtb_sources,
    )


def _resolve_firmware_name(
    name: str, fw_by_name: dict[str, list[HardwareFirmwareBlob]],
) -> list[HardwareFirmwareBlob]:
    """Match a firmware reference to blob rows by basename (case-insensitive)."""
    if not name:
        return []
    base = os.path.basename(name.strip().strip("/"))
    if not base:
        return []
    hit = fw_by_name.get(base)
    if hit:
        return hit
    lb = base.lower()
    for k, v in fw_by_name.items():
        if k.lower() == lb:
            return v
    return []


def _scan_vmlinux_firmware_strings(path: str) -> list[str]:
    """Scan vmlinux for embedded firmware-path strings.

    Sync: call via ``run_in_executor``.  Reads at most ``_VMLINUX_SCAN_BYTES``.
    Filters obvious debug/source/Windows paths and caps distinct results.
    """
    seen: set[str] = set()
    try:
        with open(path, "rb") as f:
            data = f.read(_VMLINUX_SCAN_BYTES)
    except OSError:
        return []
    for m in _FW_EXT_PATTERN.finditer(data):
        try:
            s = m.group(1).decode("ascii", errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        # Reject paths that look like debug/source trees or stray references.
        if ".." in s or s.startswith("/proc/") or s.startswith("C:") or len(s) > 128:
            continue
        # Reject names that are just an extension (e.g. '.bin') with nothing in front.
        if s.startswith("."):
            continue
        seen.add(s)
        if len(seen) >= _VMLINUX_MAX_REFS:
            break
    return sorted(seen)


def _resolve_vmlinux_relative_path(kernel_path: str, detection_roots: list[str]) -> str:
    """Resolve a stable absolute or root-relative vmlinux path.

    Sync: call via ``run_in_executor``. ``os.path.realpath`` walks symlinks
    (real I/O) so this must not run on the event loop. Returns either
    ``"/<rel>"`` when the kernel is a descendant of one of the detection
    roots, or the original ``kernel_path`` otherwise.
    """
    kernel_real = os.path.realpath(kernel_path)
    for root in detection_roots:
        try:
            root_real = os.path.realpath(root)
            rel = os.path.relpath(kernel_real, root_real)  # pure-string after realpath
        except ValueError:
            continue
        # Accept only a descendant path (no ``..`` escape).
        if not rel.startswith(".."):
            return "/" + rel
    return kernel_path


async def _write_missing_firmware_findings(
    db: AsyncSession,
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    unresolved: dict[str, list[str]],
) -> None:
    """Create a ``Finding`` per unresolved firmware name.

    Idempotent: skip names that already have a finding for this firmware
    with source=``hardware_firmware_graph``.
    """
    existing_stmt = select(Finding.title).where(
        Finding.firmware_id == firmware_id,
        Finding.source == "hardware_firmware_graph",
    )
    existing_titles = {row[0] for row in (await db.execute(existing_stmt)).all()}

    for fw_name, driver_paths in unresolved.items():
        title = f"Missing firmware: {fw_name}"
        if title in existing_titles:
            continue
        preview = driver_paths[:5]
        drivers_str = ", ".join(preview)
        if len(driver_paths) > 5:
            drivers_str += f" (+{len(driver_paths) - 5} more)"
        desc = (
            f"Driver(s) request firmware `{fw_name}` via .modinfo / DTB / vmlinux "
            "strings but no matching blob was found in the extracted firmware. "
            "This may indicate an incomplete extraction, a tampered image, or a "
            "driver referencing firmware stored on a different partition."
        )
        # Rule #35b explicit confidence — driver→firmware-blob graph
        # analysis is deterministic (a driver's .modinfo string explicitly
        # names the firmware blob; either the file exists or it doesn't),
        # so "high" reflects the matcher certainty.  Severity remains
        # "medium" (impact: missing blob may or may not be exploitable).
        finding = Finding(
            project_id=project_id,
            firmware_id=firmware_id,
            confidence="high",
            title=title,
            severity="medium",
            description=desc,
            evidence=f"Requested by: {drivers_str}",
            source="hardware_firmware_graph",
            status="open",
        )
        db.add(finding)
