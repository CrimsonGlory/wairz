"""Windows driver MCP tools — Phase γ.6.

Surfaces the Phase γ.5 driver-extractor verdicts to the MCP layer:

- ``list_drivers`` — list every WindowsDriver row for the active firmware
  (compact summary: class_guid + manufacturer + signing_tier).
- ``get_driver_info`` — full per-driver record (INF metadata, PnP IDs,
  CAT signer info, paths to INF/CAT/SYS).
- ``list_signed_drivers`` — filter to drivers with catalog_signed=True
  (operator's "what's actually signed" view).
- ``get_signing_tier`` — return the histogram of drivers by Persona-E
  #13 capability badge (whql / attestation / cross_signed / unsigned /
  unknown).
- ``scan_inf_imports`` — extract every PnP hardware ID + compatible ID
  across the driver matrix (operator's "what hardware is supported"
  rollup view).
- ``diff_driver_matrix`` — diff two firmware images' driver matrices
  by class_guid + PnP ID overlap.

Sandbox discipline (Rule #1): the few tools that read disk paths
resolve them via ``context.resolve_path()``.

Rule #36 no-execute discipline: every tool reads driver data via
persisted WindowsDriver rows or via signify (for on-demand re-classify);
nothing in this module invokes rundll32 / .inf install / cscript.

Output truncation (Rule #29): tool outputs ≤ 30 KB; large dumps emit
a tail-truncation marker.
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.windows_driver import WindowsDriver
from app.services.jsonb_normalizers import (
    _normalize_windows_drivers_inf_metadata,
)

logger = logging.getLogger(__name__)


# ── 30 KB output cap (Rule #29) ─────────────────────────────────────────────
_OUTPUT_CAP_BYTES = 30 * 1024


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    if len(text) <= cap:
        return text
    keep = cap - 80
    return text[:keep] + f"\n... [truncated; {len(text) - keep} more bytes]\n"


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    return str(obj)


def _dump_json(payload: Any) -> str:
    return _truncate(json.dumps(payload, indent=2, default=_json_default))


# ── Helpers ──────────────────────────────────────────────────────────────────


async def _load_firmware_drivers(
    context: ToolContext,
) -> list[tuple[WindowsDriver, HardwareFirmwareBlob]]:
    """Load every (driver, blob) pair for the active firmware."""
    stmt = (
        select(WindowsDriver, HardwareFirmwareBlob)
        .join(
            HardwareFirmwareBlob,
            WindowsDriver.blob_id == HardwareFirmwareBlob.id,
        )
        .where(HardwareFirmwareBlob.firmware_id == context.firmware_id)
        .order_by(WindowsDriver.driver_path)
    )
    rows = (await context.db.execute(stmt)).all()
    return [(driver, blob) for driver, blob in rows]


async def _load_driver_by_path(
    context: ToolContext, driver_path: str,
) -> tuple[WindowsDriver, HardwareFirmwareBlob] | None:
    stmt = (
        select(WindowsDriver, HardwareFirmwareBlob)
        .join(
            HardwareFirmwareBlob,
            WindowsDriver.blob_id == HardwareFirmwareBlob.id,
        )
        .where(
            HardwareFirmwareBlob.firmware_id == context.firmware_id,
            WindowsDriver.driver_path == driver_path,
        )
    )
    row = (await context.db.execute(stmt)).first()
    if row is None:
        return None
    return row[0], row[1]


def _driver_summary(driver: WindowsDriver) -> dict[str, Any]:
    """Compact per-driver shape for list_drivers / list_signed_drivers."""
    return {
        "id": driver.id,
        "driver_path": driver.driver_path,
        "manufacturer": driver.manufacturer,
        "driver_provider": driver.driver_provider,
        "driver_version": driver.driver_version,
        "inf_class": driver.inf_class,
        "class_guid": driver.class_guid,
        "signing_tier": driver.signing_tier,
        "catalog_signed": driver.catalog_signed,
        "pnp_id_count": len(driver.pnp_ids or []),
    }


def _driver_full(driver: WindowsDriver, blob: HardwareFirmwareBlob) -> dict[str, Any]:
    """Full per-driver shape for get_driver_info — includes inf_metadata."""
    return {
        "id": driver.id,
        "blob_path": blob.blob_path,
        "blob_id": blob.id,
        "driver_path": driver.driver_path,
        "inf_path": driver.inf_path,
        "cat_path": driver.cat_path,
        "sys_path": driver.sys_path,
        "manufacturer": driver.manufacturer,
        "driver_provider": driver.driver_provider,
        "driver_version": driver.driver_version,
        "driver_name": driver.driver_name,
        "inf_class": driver.inf_class,
        "class_guid": driver.class_guid,
        "pnp_ids": driver.pnp_ids or [],
        "catalog_signed": driver.catalog_signed,
        "catalog_signer_subject": driver.catalog_signer_subject,
        "catalog_signer_issuer": driver.catalog_signer_issuer,
        "signing_tier": driver.signing_tier,
        "inf_metadata": _normalize_windows_drivers_inf_metadata(driver.inf_metadata),
    }


# ── Handlers ─────────────────────────────────────────────────────────────────


async def _handle_list_drivers(input: dict, context: ToolContext) -> str:
    """List every driver-package extracted for the active firmware.

    Optional ``class_guid_filter`` and ``manufacturer_filter`` for
    slicing the matrix view.
    """
    class_guid_filter = input.get("class_guid_filter")
    mfg_filter = input.get("manufacturer_filter")

    rows = await _load_firmware_drivers(context)
    payload = []
    for driver, _blob in rows:
        if class_guid_filter and driver.class_guid != class_guid_filter:
            continue
        if mfg_filter and (
            driver.manufacturer is None
            or mfg_filter.lower() not in driver.manufacturer.lower()
        ):
            continue
        payload.append(_driver_summary(driver))
    return _dump_json(
        {
            "firmware_id": context.firmware_id,
            "drivers": payload,
            "total_count": len(payload),
        }
    )


async def _handle_get_driver_info(input: dict, context: ToolContext) -> str:
    """Return the full WindowsDriver record by driver_path."""
    driver_path = input.get("driver_path")
    if not driver_path:
        return "Error: 'driver_path' parameter required"
    loaded = await _load_driver_by_path(context, driver_path)
    if loaded is None:
        return f"Error: no driver at driver_path={driver_path!r} for active firmware"
    driver, blob = loaded
    return _dump_json(_driver_full(driver, blob))


async def _handle_list_signed_drivers(input: dict, context: ToolContext) -> str:  # noqa: ARG001
    """Filter to drivers with catalog_signed=True. Returns the same
    summary shape as list_drivers."""
    rows = await _load_firmware_drivers(context)
    payload = [
        _driver_summary(driver)
        for driver, _blob in rows
        if driver.catalog_signed
    ]
    return _dump_json(
        {
            "firmware_id": context.firmware_id,
            "signed_drivers": payload,
            "signed_count": len(payload),
            "total_drivers": len(rows),
        }
    )


async def _handle_get_signing_tier(input: dict, context: ToolContext) -> str:  # noqa: ARG001
    """Return the histogram of drivers by Persona-E #13 capability
    badge. Always returns all 5 buckets pre-seeded to 0 so the
    operator gets a complete histogram."""
    rows = await _load_firmware_drivers(context)
    histogram: dict[str, int] = {
        "whql": 0,
        "attestation": 0,
        "cross_signed": 0,
        "unsigned": 0,
        "unknown": 0,
    }
    for driver, _blob in rows:
        tier = driver.signing_tier or "unknown"
        histogram[tier] = histogram.get(tier, 0) + 1
    return _dump_json(
        {
            "firmware_id": context.firmware_id,
            "by_signing_tier": histogram,
            "total_drivers": len(rows),
        }
    )


async def _handle_scan_inf_imports(input: dict, context: ToolContext) -> str:  # noqa: ARG001
    """Extract every PnP hardware ID + compatible ID across the driver
    matrix. Returns a flat list of {pnp_id, driver_path, manufacturer,
    inf_class} entries — operator's "what hardware is supported"
    rollup view per Persona-E #13."""
    rows = await _load_firmware_drivers(context)
    entries: list[dict[str, Any]] = []
    pnp_seen: set[str] = set()
    for driver, _blob in rows:
        for pnp_id in driver.pnp_ids or []:
            entries.append(
                {
                    "pnp_id": pnp_id,
                    "driver_path": driver.driver_path,
                    "manufacturer": driver.manufacturer,
                    "inf_class": driver.inf_class,
                    "class_guid": driver.class_guid,
                }
            )
            pnp_seen.add(pnp_id)
    return _dump_json(
        {
            "firmware_id": context.firmware_id,
            "entries": entries,
            "unique_pnp_count": len(pnp_seen),
            "total_entries": len(entries),
        }
    )


async def _handle_diff_driver_matrix(input: dict, context: ToolContext) -> str:
    """Diff two firmwares' driver matrices by class_guid + PnP ID
    overlap.

    The 'rhs_firmware_id' parameter names a different firmware in the
    same project; the diff returns lhs_only, rhs_only, and common
    (matching driver_path AND class_guid).
    """
    rhs_firmware_id_str = input.get("rhs_firmware_id")
    if not rhs_firmware_id_str:
        return "Error: 'rhs_firmware_id' parameter required (firmware UUID to compare against)"
    try:
        rhs_firmware_id = uuid.UUID(rhs_firmware_id_str)
    except ValueError:
        return f"Error: rhs_firmware_id={rhs_firmware_id_str!r} is not a valid UUID"

    lhs_rows = await _load_firmware_drivers(context)

    rhs_stmt = (
        select(WindowsDriver, HardwareFirmwareBlob)
        .join(
            HardwareFirmwareBlob,
            WindowsDriver.blob_id == HardwareFirmwareBlob.id,
        )
        .where(HardwareFirmwareBlob.firmware_id == rhs_firmware_id)
        .order_by(WindowsDriver.driver_path)
    )
    rhs_rows_raw = (await context.db.execute(rhs_stmt)).all()
    rhs_rows = [(d, b) for d, b in rhs_rows_raw]

    lhs_keys = {(d.driver_path, d.class_guid) for d, _b in lhs_rows}
    rhs_keys = {(d.driver_path, d.class_guid) for d, _b in rhs_rows}

    def _summarise(rows, keys: set) -> list[dict[str, Any]]:
        return [_driver_summary(d) for d, _b in rows if (d.driver_path, d.class_guid) in keys]

    lhs_only_keys = lhs_keys - rhs_keys
    rhs_only_keys = rhs_keys - lhs_keys
    common_keys = lhs_keys & rhs_keys

    return _dump_json(
        {
            "lhs_firmware_id": context.firmware_id,
            "rhs_firmware_id": rhs_firmware_id_str,
            "lhs_only": _summarise(lhs_rows, lhs_only_keys),
            "rhs_only": _summarise(rhs_rows, rhs_only_keys),
            "common": _summarise(lhs_rows, common_keys),
            "summary": {
                "lhs_total": len(lhs_rows),
                "rhs_total": len(rhs_rows),
                "lhs_only_count": len(lhs_only_keys),
                "rhs_only_count": len(rhs_only_keys),
                "common_count": len(common_keys),
            },
        }
    )


# ── Registration ─────────────────────────────────────────────────────────────


def register_windows_driver_tools(registry: ToolRegistry) -> None:
    """Register all Phase γ.6 Windows driver MCP tools."""

    registry.register(
        name="list_drivers",
        description=(
            "List every Windows driver-package extracted for the active "
            "firmware. Returns compact rows (driver_path, manufacturer, "
            "driver_version, inf_class, class_guid, signing_tier per "
            "Persona-E #13, catalog_signed). Optional class_guid_filter "
            "+ manufacturer_filter for matrix-view slicing."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "class_guid_filter": {
                    "type": "string",
                    "description": "Optional: filter to one ClassGuid (e.g. '{4d36e968-e325-11ce-bfc1-08002be10318}' for Display class)",
                },
                "manufacturer_filter": {
                    "type": "string",
                    "description": "Optional: case-insensitive substring match on manufacturer",
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_list_drivers,
    )

    registry.register(
        name="get_driver_info",
        description=(
            "Return the full WindowsDriver record for one driver-package: "
            "INF/CAT/SYS paths, parsed inf_metadata (Version block + "
            "Manufacturer block + Models + Strings), all PnP hardware "
            "IDs, CAT signer subject + issuer, signing_tier classification."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "driver_path": {
                    "type": "string",
                    "description": "Anchor path of the driver (matches WindowsDriver.driver_path; typically the INF path)",
                },
            },
            "required": ["driver_path"],
            "additionalProperties": False,
        },
        handler=_handle_get_driver_info,
    )

    registry.register(
        name="list_signed_drivers",
        description=(
            "Filter to drivers with catalog_signed=True. Returns the "
            "same compact summary shape as list_drivers. Useful for "
            "the 'what fraction of this firmware's drivers carry a "
            "valid CAT signature' triage view."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_list_signed_drivers,
    )

    registry.register(
        name="get_signing_tier_histogram",
        description=(
            "Return the histogram of drivers by Persona-E #13 capability "
            "badge: whql (Microsoft WHQL-certified), attestation (vendor-"
            "signed via Microsoft attestation root), cross_signed (legacy "
            "vendor cert with MS cross-cert anchor), unsigned (no CAT or "
            "CAT failed validation), unknown (signed but fits no pattern). "
            "All 5 buckets always present, pre-seeded to 0."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_get_signing_tier,
    )

    registry.register(
        name="scan_inf_imports",
        description=(
            "Extract every PnP hardware ID + compatible ID across the "
            "driver matrix for the active firmware. Returns flat list "
            "of {pnp_id, driver_path, manufacturer, inf_class, "
            "class_guid} — answers 'what hardware does this firmware "
            "support drivers for' per Persona-E #13."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_scan_inf_imports,
    )

    registry.register(
        name="diff_driver_matrix",
        description=(
            "Diff two firmware images' driver matrices by (driver_path, "
            "class_guid) overlap. Returns lhs_only (drivers in this "
            "firmware but not the rhs), rhs_only, and common (driver "
            "rows present in both). Useful for comparing pre/post-"
            "update firmware revisions or two devices in the same "
            "project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rhs_firmware_id": {
                    "type": "string",
                    "description": "UUID of the firmware to compare against (the right side of the diff)",
                },
            },
            "required": ["rhs_firmware_id"],
            "additionalProperties": False,
        },
        handler=_handle_diff_driver_matrix,
    )
