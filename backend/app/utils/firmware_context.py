"""Firmware-aware context enrichment for APK security findings.

Extracts contextual metadata from the firmware/project (device type,
Android version, firmware origin, security posture) and uses it to
augment finding descriptions so that security analysts understand
the risk in the context of the specific device/firmware.

This module provides:
- ``FirmwareContext``: dataclass with resolved metadata
- ``get_firmware_context()``: async helper to build context from DB
- ``build_firmware_context_from_fs()``: sync helper for filesystem-only context
- ``enrich_description()``: augments a finding description with context
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from app.services.jsonb_normalizers import _normalize_firmware_device_metadata

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FirmwareContext:
    """Resolved firmware metadata for finding enrichment.

    All fields are optional — enrichment degrades gracefully when
    metadata is unavailable.
    """

    # Device identity
    device_model: str | None = None
    manufacturer: str | None = None
    chipset: str | None = None

    # Android / OS info
    android_version: str | None = None
    api_level: int | None = None
    security_patch: str | None = None
    build_fingerprint: str | None = None
    os_info: str | None = None

    # Firmware provenance
    firmware_filename: str | None = None
    architecture: str | None = None

    # Security posture
    bootloader_state: str | None = None
    security_posture: dict[str, str] = field(default_factory=dict)

    # APK location context
    is_priv_app: bool = False
    is_system_app: bool = False
    is_vendor_app: bool = False
    partition: str | None = None  # "system", "vendor", "product", etc.

    @property
    def is_empty(self) -> bool:
        """True if no meaningful metadata was resolved."""
        return (
            self.device_model is None
            and self.manufacturer is None
            and self.android_version is None
            and self.api_level is None
            and self.firmware_filename is None
            and self.os_info is None
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict (omitting None values)."""
        d: dict[str, Any] = {}
        for fld in (
            "device_model", "manufacturer", "chipset",
            "android_version", "api_level", "security_patch",
            "build_fingerprint", "os_info", "firmware_filename",
            "architecture", "bootloader_state",
            "is_priv_app", "is_system_app", "is_vendor_app",
            "partition",
        ):
            val = getattr(self, fld)
            if val is not None and val is not False:
                d[fld] = val
        if self.security_posture:
            d["security_posture"] = self.security_posture
        return d

    def summary_line(self) -> str:
        """One-line summary for inclusion in finding text output."""
        parts: list[str] = []
        if self.manufacturer and self.device_model:
            parts.append(f"{self.manufacturer} {self.device_model}")
        elif self.device_model:
            parts.append(self.device_model)
        if self.android_version:
            api_str = f" (API {self.api_level})" if self.api_level else ""
            parts.append(f"Android {self.android_version}{api_str}")
        if self.security_patch:
            parts.append(f"patch {self.security_patch}")
        if self.architecture:
            parts.append(self.architecture)
        if self.partition:
            parts.append(f"/{self.partition}")
        return " | ".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Firmware context from database (async — use in MCP/REST handlers)
# ---------------------------------------------------------------------------


async def get_firmware_context(
    db: Any,  # AsyncSession
    firmware_id: Any,
    apk_path: str | None = None,
    extracted_root: str | None = None,
) -> FirmwareContext:
    """Build a FirmwareContext from the Firmware DB record + APK location.

    Parameters
    ----------
    db : AsyncSession
        Active database session.
    firmware_id : UUID
        Firmware record to look up.
    apk_path : str, optional
        Absolute path to the APK (for location-based context).
    extracted_root : str, optional
        Firmware extraction root (for relative path computation).
    """
    from sqlalchemy import select
    from app.models.firmware import Firmware

    stmt = select(Firmware).where(Firmware.id == firmware_id)
    result = await db.execute(stmt)
    firmware = result.scalar_one_or_none()

    if not firmware:
        # Degrade gracefully — still provide APK location context
        return _apk_location_context(apk_path, extracted_root)

    dm = _normalize_firmware_device_metadata(firmware.device_metadata)

    # If device_metadata is empty, try parsing build.prop from FS
    if not dm and firmware.extracted_path and os.path.isdir(firmware.extracted_path):
        dm = _parse_build_prop_from_fs(firmware.extracted_path)

    apk_ctx = _apk_location_context(apk_path, extracted_root or firmware.extracted_path)

    return FirmwareContext(
        device_model=dm.get("device_model"),
        manufacturer=dm.get("manufacturer"),
        chipset=dm.get("chipset"),
        android_version=dm.get("android_version"),
        api_level=dm.get("api_level"),
        security_patch=dm.get("security_patch"),
        build_fingerprint=dm.get("build_fingerprint"),
        os_info=firmware.os_info,
        firmware_filename=firmware.original_filename,
        architecture=firmware.architecture,
        bootloader_state=dm.get("bootloader_state"),
        security_posture=dm.get("security_posture") or {},
        is_priv_app=apk_ctx.is_priv_app,
        is_system_app=apk_ctx.is_system_app,
        is_vendor_app=apk_ctx.is_vendor_app,
        partition=apk_ctx.partition,
    )


def build_firmware_context_from_firmware(
    firmware: Any,  # Firmware ORM model
    apk_path: str | None = None,
) -> FirmwareContext:
    """Build a FirmwareContext from a loaded Firmware ORM object.

    Useful in REST endpoint handlers that already have the Firmware loaded.
    """
    dm = _normalize_firmware_device_metadata(firmware.device_metadata)

    # If device_metadata is empty, try parsing build.prop from FS
    if not dm and firmware.extracted_path and os.path.isdir(firmware.extracted_path):
        dm = _parse_build_prop_from_fs(firmware.extracted_path)

    apk_ctx = _apk_location_context(apk_path, firmware.extracted_path)

    return FirmwareContext(
        device_model=dm.get("device_model"),
        manufacturer=dm.get("manufacturer"),
        chipset=dm.get("chipset"),
        android_version=dm.get("android_version"),
        api_level=dm.get("api_level"),
        security_patch=dm.get("security_patch"),
        build_fingerprint=dm.get("build_fingerprint"),
        os_info=firmware.os_info,
        firmware_filename=firmware.original_filename,
        architecture=firmware.architecture,
        bootloader_state=dm.get("bootloader_state"),
        security_posture=dm.get("security_posture") or {},
        is_priv_app=apk_ctx.is_priv_app,
        is_system_app=apk_ctx.is_system_app,
        is_vendor_app=apk_ctx.is_vendor_app,
        partition=apk_ctx.partition,
    )


# ---------------------------------------------------------------------------
# Description enrichment
# ---------------------------------------------------------------------------


def enrich_description(
    base_description: str,
    ctx: FirmwareContext,
    *,
    include_risk_note: bool = True,
) -> str:
    """Augment a finding description with firmware context metadata.

    Appends a structured context block to the description so analysts
    can quickly see the device/firmware environment.

    Parameters
    ----------
    base_description : str
        Original finding description.
    ctx : FirmwareContext
        Resolved firmware context.
    include_risk_note : bool
        If True, adds a risk-impact note for priv-app/vendor contexts.
    """
    if ctx.is_empty and not ctx.is_priv_app and not ctx.partition:
        return base_description

    parts: list[str] = [base_description.rstrip()]

    # Build context block
    context_lines: list[str] = []

    if ctx.device_model or ctx.manufacturer:
        device = ""
        if ctx.manufacturer:
            device = ctx.manufacturer
        if ctx.device_model:
            device = f"{device} {ctx.device_model}".strip()
        context_lines.append(f"Device: {device}")

    if ctx.android_version:
        api_str = f" (API {ctx.api_level})" if ctx.api_level else ""
        context_lines.append(f"Android: {ctx.android_version}{api_str}")

    if ctx.security_patch:
        context_lines.append(f"Security patch: {ctx.security_patch}")

    if ctx.architecture:
        context_lines.append(f"Architecture: {ctx.architecture}")

    if ctx.partition:
        context_lines.append(f"Partition: /{ctx.partition}")

    if ctx.firmware_filename:
        context_lines.append(f"Firmware: {ctx.firmware_filename}")

    if ctx.bootloader_state and ctx.bootloader_state != "unknown":
        context_lines.append(f"Bootloader: {ctx.bootloader_state}")

    if context_lines:
        parts.append("\n[Firmware Context]")
        for line in context_lines:
            parts.append(f"  {line}")

    # Risk impact note for privileged/system contexts
    if include_risk_note:
        risk_note = _build_risk_note(ctx)
        if risk_note:
            parts.append(f"\n[Risk Impact] {risk_note}")

    return "\n".join(parts)


def enrich_evidence(
    base_evidence: str,
    ctx: FirmwareContext,
) -> str:
    """Augment finding evidence with a compact firmware context tag.

    Lighter than enrich_description — adds a single line summary
    suitable for the evidence field.
    """
    summary = ctx.summary_line()
    if not summary:
        return base_evidence

    if base_evidence:
        return f"{base_evidence}\nFirmware context: {summary}"
    return f"Firmware context: {summary}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


_BUILD_PROP_LOCATIONS = [
    "system/build.prop",
    "system/system/build.prop",
    "vendor/build.prop",
    "product/build.prop",
]


def _parse_build_prop_from_fs(extracted_root: str) -> dict:
    """Try to parse build.prop from extracted firmware filesystem.

    Returns a device_metadata-compatible dict, or empty dict on failure.
    """
    from app.utils.getprop import extract_device_metadata, parse_build_prop

    for rel_path in _BUILD_PROP_LOCATIONS:
        bp_path = os.path.join(extracted_root, rel_path)
        if os.path.isfile(bp_path):
            try:
                with open(bp_path, "r", errors="replace") as f:
                    text = f.read(256 * 1024)  # Cap at 256KB
                props = parse_build_prop(text)
                if props:
                    return extract_device_metadata(props)
            except (OSError, UnicodeDecodeError) as exc:
                logger.debug("Failed to parse %s: %s", bp_path, exc)
    return {}


def _apk_location_context(
    apk_path: str | None,
    extracted_root: str | None,
) -> FirmwareContext:
    """Derive APK location context (partition, priv-app, etc.)."""
    if not apk_path or not extracted_root:
        return FirmwareContext()

    try:
        rel = os.path.relpath(apk_path, extracted_root)
    except ValueError:
        return FirmwareContext()

    parts = rel.replace("\\", "/").split("/")

    is_priv_app = "priv-app" in parts
    is_system_app = False
    is_vendor_app = False
    partition = None

    # Detect partition from path prefix
    if parts:
        first = parts[0].lower()
        if first in ("system", "system_ext"):
            is_system_app = True
            partition = first
        elif first == "vendor":
            is_vendor_app = True
            partition = "vendor"
        elif first == "product":
            partition = "product"
        elif first == "odm":
            partition = "odm"

    return FirmwareContext(
        is_priv_app=is_priv_app,
        is_system_app=is_system_app,
        is_vendor_app=is_vendor_app,
        partition=partition,
    )


def _build_risk_note(ctx: FirmwareContext) -> str:
    """Build a risk-impact note for the given firmware context."""
    notes: list[str] = []

    if ctx.is_priv_app:
        notes.append(
            "This is a privileged system app (priv-app) with elevated "
            "permissions — vulnerabilities have wider blast radius."
        )
    elif ctx.is_system_app and not ctx.is_priv_app:
        notes.append(
            "This is a pre-installed system app — users cannot easily "
            "uninstall or update it independently."
        )
    elif ctx.is_vendor_app:
        notes.append(
            "This is a vendor-bundled app — it may have access to "
            "proprietary hardware interfaces and persist across factory resets."
        )

    if ctx.api_level is not None and ctx.api_level < 24:
        notes.append(
            f"Running on API level {ctx.api_level} (Android "
            f"{ctx.android_version or '?'}) which lacks modern security "
            "defaults (network security config, background restrictions)."
        )

    if ctx.security_posture.get("ro_debuggable") == "1":
        notes.append(
            "Firmware has ro.debuggable=1 indicating a debug/engineering "
            "build — additional attack surface exposed."
        )

    if ctx.bootloader_state == "unlocked":
        notes.append(
            "Device bootloader is unlocked — custom code can be flashed, "
            "reducing trust in firmware integrity."
        )

    return " ".join(notes)
