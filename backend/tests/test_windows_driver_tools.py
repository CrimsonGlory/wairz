"""Phase γ.6 — windows_driver MCP tool tests.

Tests every handler in ``app.ai.tools.windows_driver`` via stubbed
ToolContext + the live SQLite session from ``tests._live_db.make_live_db``.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.windows_driver import (
    _handle_diff_driver_matrix,
    _handle_get_driver_info,
    _handle_get_signing_tier,
    _handle_list_drivers,
    _handle_list_signed_drivers,
    _handle_scan_inf_imports,
    register_windows_driver_tools,
)
from app.models import (
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsDriver,
)
from app.services.jsonb_normalizers import (
    _stamp_windows_drivers_inf_metadata,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    extracted_path: str
    db: object
    firmware_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def resolve_path(self, p: str) -> str:
        return p


# ── Fixture builders ────────────────────────────────────────────────────────


async def _seed_firmware_with_drivers(db) -> tuple[Firmware, list[WindowsDriver]]:
    """Seed a Project + Firmware + 2 HardwareFirmwareBlob (driver_package)
    + 2 WindowsDriver rows (one whql Display + one unsigned Net)."""
    project = Project(name="γ.6-driver-test")
    db.add(project)
    await db.flush()

    fw = Firmware(
        project_id=project.id,
        sha256="0" * 64,
        extracted_path="/tmp/test-extracted",
    )
    db.add(fw)
    await db.flush()

    igd_blob = HardwareFirmwareBlob(
        firmware_id=fw.id,
        blob_path="Windows/INF/igdkmd.inf",
        blob_sha256="a" * 64,
        file_size=1024,
        category="driver_package",
        format="windows_inf",
        detection_source="driver_extractor",
    )
    netvendor_blob = HardwareFirmwareBlob(
        firmware_id=fw.id,
        blob_path="Windows/INF/netvendor.inf",
        blob_sha256="b" * 64,
        file_size=1024,
        category="driver_package",
        format="windows_inf",
        detection_source="driver_extractor",
    )
    db.add_all([igd_blob, netvendor_blob])
    await db.flush()

    igd_metadata = _stamp_windows_drivers_inf_metadata({
        "version_block": {
            "Class": "Display",
            "ClassGuid": "{4d36e968-e325-11ce-bfc1-08002be10318}",
            "Provider": "Intel Corporation",
            "DriverVer": "01/15/2024,31.0.101.5333",
            "CatalogFile": "igdkmd.cat",
        },
        "manufacturer_block": [
            {"name": "Intel Corporation", "section": "IntelGfx", "decorations": []},
        ],
        "models": [
            {
                "manufacturer": "Intel Corporation",
                "device_description": "Intel(R) UHD Graphics 770",
                "install_section": "iIGDX",
                "hardware_id": "PCI\\VEN_8086&DEV_4680",
                "compatible_ids": [],
            },
        ],
        "strings": {},
        "errors": [],
    })

    igd_driver = WindowsDriver(
        blob_id=igd_blob.id,
        driver_path="Windows/INF/igdkmd.inf",
        inf_path="Windows/INF/igdkmd.inf",
        cat_path="Windows/INF/igdkmd.cat",
        sys_path="Windows/INF/igdkmd.sys",
        inf_class="Display",
        class_guid="{4d36e968-e325-11ce-bfc1-08002be10318}",
        driver_provider="Intel Corporation",
        driver_version="01/15/2024,31.0.101.5333",
        driver_name="Intel Corporation",
        manufacturer="Intel Corporation",
        pnp_ids=["PCI\\VEN_8086&DEV_4680"],
        catalog_signed=True,
        catalog_signer_subject="CN=Microsoft Windows Hardware Compatibility Publisher",
        catalog_signer_issuer="CN=Microsoft Root Certificate Authority",
        signing_tier="whql",
        inf_metadata=igd_metadata,
    )
    netvendor_driver = WindowsDriver(
        blob_id=netvendor_blob.id,
        driver_path="Windows/INF/netvendor.inf",
        inf_path="Windows/INF/netvendor.inf",
        cat_path=None,
        sys_path=None,
        inf_class="Net",
        class_guid="{4d36e972-e325-11ce-bfc1-08002be10318}",
        driver_provider="No-Name Vendor",
        driver_version="01/01/2010,1.0.0.0",
        driver_name="No-Name Vendor",
        manufacturer="No-Name Vendor",
        pnp_ids=["USB\\VID_FFFF&PID_DEAD"],
        catalog_signed=False,
        signing_tier="unsigned",
        inf_metadata=None,
    )
    db.add_all([igd_driver, netvendor_driver])
    await db.flush()
    return fw, [igd_driver, netvendor_driver]


# ── list_drivers ────────────────────────────────────────────────────────────


async def test_list_drivers_returns_summary_rows(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_drivers(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)

        out = await _handle_list_drivers({}, ctx)
        payload = json.loads(out)
        assert payload["total_count"] == 2
        # Each summary carries class_guid + signing_tier per Persona-E #13.
        tiers = sorted(d["signing_tier"] for d in payload["drivers"])
        assert tiers == ["unsigned", "whql"]


async def test_list_drivers_filters_by_class_guid(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_drivers(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_list_drivers(
            {"class_guid_filter": "{4d36e968-e325-11ce-bfc1-08002be10318}"}, ctx
        )
        payload = json.loads(out)
        assert payload["total_count"] == 1
        assert payload["drivers"][0]["inf_class"] == "Display"


async def test_list_drivers_filters_by_manufacturer(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_drivers(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_list_drivers({"manufacturer_filter": "intel"}, ctx)
        payload = json.loads(out)
        assert payload["total_count"] == 1
        assert payload["drivers"][0]["manufacturer"] == "Intel Corporation"


# ── get_driver_info ─────────────────────────────────────────────────────────


async def test_get_driver_info_returns_full_record(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_drivers(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_get_driver_info(
            {"driver_path": "Windows/INF/igdkmd.inf"}, ctx
        )
        payload = json.loads(out)
        assert payload["inf_class"] == "Display"
        assert payload["catalog_signed"] is True
        assert payload["signing_tier"] == "whql"
        assert payload["pnp_ids"] == ["PCI\\VEN_8086&DEV_4680"]
        # inf_metadata round-trips via the normalizer.
        assert payload["inf_metadata"]["schema_version"] == 1
        assert (
            payload["inf_metadata"]["version_block"]["Class"]
            == "Display"
        )


async def test_get_driver_info_unknown_driver_errors(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_drivers(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_get_driver_info({"driver_path": "no/such.inf"}, ctx)
        assert "Error" in out


# ── list_signed_drivers ─────────────────────────────────────────────────────


async def test_list_signed_drivers_filters_to_catalog_signed_true(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_drivers(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_list_signed_drivers({}, ctx)
        payload = json.loads(out)
        assert payload["signed_count"] == 1
        assert payload["total_drivers"] == 2
        assert payload["signed_drivers"][0]["signing_tier"] == "whql"


# ── get_signing_tier histogram ──────────────────────────────────────────────


async def test_get_signing_tier_returns_full_histogram(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_drivers(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_get_signing_tier({}, ctx)
        payload = json.loads(out)
        # All 5 buckets always present.
        assert set(payload["by_signing_tier"]) == {
            "whql", "attestation", "cross_signed", "unsigned", "unknown",
        }
        assert payload["by_signing_tier"]["whql"] == 1
        assert payload["by_signing_tier"]["unsigned"] == 1
        assert payload["by_signing_tier"]["attestation"] == 0
        assert payload["total_drivers"] == 2


# ── scan_inf_imports ────────────────────────────────────────────────────────


async def test_scan_inf_imports_returns_pnp_id_aggregate(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_drivers(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_scan_inf_imports({}, ctx)
        payload = json.loads(out)
        assert payload["unique_pnp_count"] == 2
        assert payload["total_entries"] == 2
        pnp_ids = sorted(e["pnp_id"] for e in payload["entries"])
        assert pnp_ids == [
            "PCI\\VEN_8086&DEV_4680",
            "USB\\VID_FFFF&PID_DEAD",
        ]


# ── diff_driver_matrix ──────────────────────────────────────────────────────


async def test_diff_driver_matrix_against_other_firmware(tmp_path) -> None:
    """Set up two firmwares in the same project + diff their driver
    matrices."""
    async with make_live_db() as db:
        # First firmware (lhs context).
        fw_a, _ = await _seed_firmware_with_drivers(db)
        # Second firmware (rhs target) — share igdkmd, drop netvendor,
        # add a new realtek driver.
        fw_b = Firmware(project_id=fw_a.project_id, sha256="1" * 64)
        db.add(fw_b)
        await db.flush()

        igd_blob_b = HardwareFirmwareBlob(
            firmware_id=fw_b.id,
            blob_path="Windows/INF/igdkmd.inf",
            blob_sha256="c" * 64,
            file_size=1024,
            category="driver_package",
            format="windows_inf",
            detection_source="driver_extractor",
        )
        rtk_blob = HardwareFirmwareBlob(
            firmware_id=fw_b.id,
            blob_path="Windows/INF/realtek.inf",
            blob_sha256="d" * 64,
            file_size=1024,
            category="driver_package",
            format="windows_inf",
            detection_source="driver_extractor",
        )
        db.add_all([igd_blob_b, rtk_blob])
        await db.flush()

        db.add_all([
            WindowsDriver(
                blob_id=igd_blob_b.id,
                driver_path="Windows/INF/igdkmd.inf",
                class_guid="{4d36e968-e325-11ce-bfc1-08002be10318}",
                inf_class="Display",
                catalog_signed=True,
                signing_tier="whql",
            ),
            WindowsDriver(
                blob_id=rtk_blob.id,
                driver_path="Windows/INF/realtek.inf",
                class_guid="{4d36e968-e325-11ce-bfc1-08002be10318}",
                inf_class="Display",
                catalog_signed=True,
                signing_tier="attestation",
            ),
        ])
        await db.commit()

        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw_a.id)
        out = await _handle_diff_driver_matrix(
            {"rhs_firmware_id": str(fw_b.id)}, ctx
        )
        payload = json.loads(out)
        # Common: igdkmd.inf is in both with same class_guid.
        assert payload["summary"]["common_count"] == 1
        # lhs_only: netvendor.inf
        assert payload["summary"]["lhs_only_count"] == 1
        # rhs_only: realtek.inf
        assert payload["summary"]["rhs_only_count"] == 1


async def test_diff_driver_matrix_invalid_uuid_errors(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_drivers(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_diff_driver_matrix({"rhs_firmware_id": "not-uuid"}, ctx)
        assert "Error" in out
        assert "valid UUID" in out


async def test_diff_driver_matrix_requires_param(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_drivers(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_diff_driver_matrix({}, ctx)
        assert "Error" in out


# ── Registration smoke ──────────────────────────────────────────────────────


def test_register_adds_six_tools() -> None:
    reg = ToolRegistry()
    register_windows_driver_tools(reg)
    names = {t["name"] for t in reg.get_anthropic_tools()}
    assert names == {
        "list_drivers",
        "get_driver_info",
        "list_signed_drivers",
        "get_signing_tier_histogram",
        "scan_inf_imports",
        "diff_driver_matrix",
    }
