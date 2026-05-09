"""Phase γ.8 — registry + driver finding-emitter tests.

Two layers:

1. Pure classifier tests — ``classify_registry_persistence_findings``
   and ``classify_driver_findings`` exercised against synthetic
   parsed_tree / driver-state inputs. Covers the Persona-E #13 severity
   map (Session Manager BootExecute critical → Run medium →
   CurrentControlSet\\Services low) and the driver tier classifier
   (unsigned/unknown signing_tier + INF parse errors + no-PnP-IDs).

2. Live canary (Rule #35b) — full end-to-end via
   tests._live_db.make_live_db: seed Project + Firmware + Hardware blobs
   + WindowsRegistryExtract + WindowsDriver rows, run
   ``FindingService.emit_registry_findings_from_walk`` /
   ``emit_driver_findings_from_extract``, SELECT the persisted Finding
   rows and verify every field the classifier sets.
"""
from __future__ import annotations

from app.models import (
    Finding,
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsDriver,
    WindowsRegistryExtract,
)
from app.schemas.finding import Severity
from app.services.finding_service import (
    _SOURCE_DRIVER_IMPORTS,
    _SOURCE_INF,
    _SOURCE_REGISTRY_PERSISTENCE,
    FindingService,
    classify_driver_findings,
    classify_registry_persistence_findings,
)
from app.services.jsonb_normalizers import (
    _stamp_windows_drivers_inf_metadata,
    _stamp_windows_registry_extracts_parsed_tree,
)
from tests._live_db import make_live_db

# ── classify_registry_persistence_findings ──────────────────────────────────


def _parsed_tree_with(subkeys: list[dict]) -> dict:
    return _stamp_windows_registry_extracts_parsed_tree({
        "hive_type": "SOFTWARE",
        "walk_complete": True,
        "depth_limit": 5,
        "key_count": len(subkeys),
        "value_count": sum(len(s.get("values", [])) for s in subkeys),
        "truncated": False,
        "errors": [],
        "subkeys": subkeys,
    })


def test_classify_registry_run_key_with_value_emits_medium() -> None:
    parsed = _parsed_tree_with([
        {
            "path": "\\Microsoft\\Windows\\CurrentVersion\\Run",
            "values": [
                {"name": "OneDrive", "type": "REG_SZ", "data": "C:\\OneDrive.exe"},
            ],
        },
    ])
    drafts = classify_registry_persistence_findings(
        hive_path="Windows/System32/config/SOFTWARE",
        hive_type="SOFTWARE",
        parsed_tree=parsed,
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == _SOURCE_REGISTRY_PERSISTENCE
    assert d.severity == Severity.medium
    assert "Run / RunOnce" in d.title
    assert "OneDrive" in d.evidence


def test_classify_registry_session_manager_boot_execute_emits_critical() -> None:
    parsed = _parsed_tree_with([
        {
            "path": "\\ControlSet001\\Control\\Session Manager\\BootExecute",
            "values": [
                {"name": "BootExecute", "type": "REG_MULTI_SZ", "data": "autocheck autochk *"},
            ],
        },
    ])
    drafts = classify_registry_persistence_findings(
        hive_path="Windows/System32/config/SYSTEM",
        hive_type="SYSTEM",
        parsed_tree=parsed,
    )
    assert len(drafts) == 1
    assert drafts[0].severity == Severity.critical
    assert "BootExecute" in drafts[0].title


def test_classify_registry_image_file_execution_options_emits_high() -> None:
    parsed = _parsed_tree_with([
        {
            "path": "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
            "values": [
                {"name": "Debugger", "type": "REG_SZ", "data": "C:\\evil.exe"},
            ],
        },
    ])
    drafts = classify_registry_persistence_findings(
        hive_path="Windows/System32/config/SOFTWARE",
        hive_type="SOFTWARE",
        parsed_tree=parsed,
    )
    assert len(drafts) == 1
    assert drafts[0].severity == Severity.high
    assert "Image File Execution Options" in drafts[0].title


def test_classify_registry_empty_run_key_emits_nothing() -> None:
    """A Run key with no values is the default Windows shape — not a
    finding (the classifier skips empty-values entries to avoid noise)."""
    parsed = _parsed_tree_with([
        {
            "path": "\\Microsoft\\Windows\\CurrentVersion\\Run",
            "values": [],
        },
    ])
    drafts = classify_registry_persistence_findings(
        hive_path="x",
        hive_type="SOFTWARE",
        parsed_tree=parsed,
    )
    assert drafts == []


def test_classify_registry_unrelated_subkey_emits_nothing() -> None:
    parsed = _parsed_tree_with([
        {
            "path": "\\Microsoft\\Some\\Unrelated\\Key",
            "values": [{"name": "Foo", "type": "REG_SZ", "data": "bar"}],
        },
    ])
    drafts = classify_registry_persistence_findings(
        hive_path="x",
        hive_type="SOFTWARE",
        parsed_tree=parsed,
    )
    assert drafts == []


def test_classify_registry_none_parsed_tree_returns_empty() -> None:
    """Defensive — None parsed_tree (row exists but no walk) returns []."""
    drafts = classify_registry_persistence_findings(
        hive_path="x",
        hive_type="SOFTWARE",
        parsed_tree=None,
    )
    assert drafts == []


def test_classify_registry_wrong_type_parsed_tree_returns_empty() -> None:
    """Defensive — wrong-typed parsed_tree returns []."""
    drafts = classify_registry_persistence_findings(
        hive_path="x", hive_type="SOFTWARE", parsed_tree="not a dict"
    )
    assert drafts == []


def test_classify_registry_services_emits_low() -> None:
    parsed = _parsed_tree_with([
        {
            "path": "\\CurrentControlSet\\Services\\spooler",
            "values": [{"name": "ImagePath", "type": "REG_EXPAND_SZ", "data": "%SystemRoot%\\System32\\spoolsv.exe"}],
        },
    ])
    drafts = classify_registry_persistence_findings(
        hive_path="x",
        hive_type="SYSTEM",
        parsed_tree=parsed,
    )
    assert len(drafts) == 1
    assert drafts[0].severity == Severity.low


# ── classify_driver_findings ────────────────────────────────────────────────


def test_classify_driver_unsigned_emits_inf_finding() -> None:
    drafts = classify_driver_findings(
        driver_path="Windows/INF/no-name.inf",
        signing_tier="unsigned",
        catalog_signed=False,
        pnp_ids=["PCI\\VEN_FFFF&DEV_DEAD"],
        inf_metadata=None,
        manufacturer="No-Name Vendor",
        inf_class="Display",
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == _SOURCE_INF
    assert d.severity == Severity.medium
    assert "UNSIGNED" in d.description


def test_classify_driver_unknown_emits_low_inf_finding() -> None:
    drafts = classify_driver_findings(
        driver_path="Windows/INF/weird.inf",
        signing_tier="unknown",
        catalog_signed=True,
        pnp_ids=["PCI\\VEN_AAAA&DEV_BBBB"],
        inf_metadata=None,
        manufacturer="Some Vendor",
        inf_class="System",
    )
    assert len(drafts) == 1
    assert drafts[0].source == _SOURCE_INF
    assert drafts[0].severity == Severity.low


def test_classify_driver_no_pnp_ids_emits_imports_finding() -> None:
    drafts = classify_driver_findings(
        driver_path="Windows/INF/filter.inf",
        signing_tier="whql",  # signed, but no PnP IDs is the anomaly
        catalog_signed=True,
        pnp_ids=[],
        inf_metadata=None,
        manufacturer="Microsoft",
        inf_class="System",
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == _SOURCE_DRIVER_IMPORTS
    assert d.severity == Severity.low
    assert "no Plug-and-Play" in d.description


def test_classify_driver_unsigned_AND_no_pnp_emits_two_findings() -> None:
    """Unsigned + no PnP IDs → both signal channels fire (one
    windows_inf finding + one windows_driver_imports finding)."""
    drafts = classify_driver_findings(
        driver_path="Windows/INF/sus.inf",
        signing_tier="unsigned",
        catalog_signed=False,
        pnp_ids=[],
        inf_metadata=None,
        manufacturer="Sus Vendor",
        inf_class="System",
    )
    sources = sorted(d.source for d in drafts)
    assert sources == [_SOURCE_DRIVER_IMPORTS, _SOURCE_INF]


def test_classify_driver_inf_parse_errors_emits_low_finding() -> None:
    """When INF metadata has parse errors but signing_tier is OK,
    the errors signal triggers a low-severity windows_inf finding."""
    drafts = classify_driver_findings(
        driver_path="Windows/INF/broken.inf",
        signing_tier="whql",
        catalog_signed=True,
        pnp_ids=["PCI\\VEN_8086&DEV_4680"],
        inf_metadata={
            "version_block": {},
            "manufacturer_block": [],
            "models": [],
            "strings": {},
            "errors": ["[Models] section section-name resolution failed"],
        },
        manufacturer=None,
        inf_class=None,
    )
    inf_drafts = [d for d in drafts if d.source == _SOURCE_INF]
    assert len(inf_drafts) == 1
    assert inf_drafts[0].severity == Severity.low
    assert "1 error" in inf_drafts[0].description


def test_classify_driver_whql_with_pnp_no_errors_emits_nothing() -> None:
    """WHQL-signed driver with PnP IDs and no INF errors is the
    happy-path — no findings."""
    drafts = classify_driver_findings(
        driver_path="Windows/INF/intel.inf",
        signing_tier="whql",
        catalog_signed=True,
        pnp_ids=["PCI\\VEN_8086&DEV_4680"],
        inf_metadata={"errors": []},
        manufacturer="Intel Corporation",
        inf_class="Display",
    )
    assert drafts == []


# ── Live canary — emit_registry_findings_from_walk (Rule #35b) ──────────────


async def _seed_firmware_with_persistence_hive(db) -> tuple[Project, Firmware]:
    project = Project(name="γ.8-test")
    db.add(project)
    await db.flush()
    fw = Firmware(project_id=project.id, sha256="0" * 64)
    db.add(fw)
    await db.flush()

    blob = HardwareFirmwareBlob(
        firmware_id=fw.id,
        blob_path="Windows/System32/config/SOFTWARE",
        blob_sha256="a" * 64,
        file_size=1024,
        category="registry_hive",
        format="regf_hive",
        detection_source="registry_hive_walker",
    )
    db.add(blob)
    await db.flush()

    parsed = _stamp_windows_registry_extracts_parsed_tree({
        "hive_type": "SOFTWARE",
        "walk_complete": True,
        "depth_limit": 5,
        "key_count": 1,
        "value_count": 1,
        "truncated": False,
        "errors": [],
        "subkeys": [
            {
                "path": "\\Microsoft\\Windows\\CurrentVersion\\Run",
                "values": [
                    {"name": "OneDrive", "type": "REG_SZ", "data": "C:\\OneDrive.exe"},
                ],
            },
        ],
    })
    extract = WindowsRegistryExtract(
        blob_id=blob.id,
        hive_path="Windows/System32/config/SOFTWARE",
        hive_type="SOFTWARE",
        key_count=1,
        value_count=1,
        walk_status="completed",
        parsed_tree=parsed,
    )
    db.add(extract)
    await db.flush()
    return project, fw


async def test_emit_registry_findings_persists_finding_row() -> None:
    """End-to-end: seed extract → emit findings → SELECT persisted
    Finding row to verify every field the classifier explicitly sets
    (value-flow verification per Rule #35b)."""
    async with make_live_db() as db:
        project, fw = await _seed_firmware_with_persistence_hive(db)
        await db.commit()

        service = FindingService(db)
        emitted = await service.emit_registry_findings_from_walk(project.id, fw.id)
        await db.commit()

        assert len(emitted) == 1
        f = emitted[0]
        assert f.source == "windows_registry_persistence"
        assert f.severity == "medium"
        assert "Run" in f.title
        # SELECT verification.
        from sqlalchemy import select as _sel
        rows = (
            await db.execute(
                _sel(Finding).where(
                    Finding.firmware_id == fw.id,
                    Finding.source == "windows_registry_persistence",
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        r = rows[0]
        assert r.confidence == "medium"
        assert r.file_path == "Windows/System32/config/SOFTWARE"


async def test_emit_registry_findings_no_extracts_returns_empty() -> None:
    """Firmware with no walked extracts → no findings emitted."""
    async with make_live_db() as db:
        project = Project(name="empty")
        db.add(project)
        await db.flush()
        fw = Firmware(project_id=project.id, sha256="0" * 64)
        db.add(fw)
        await db.flush()
        await db.commit()

        service = FindingService(db)
        emitted = await service.emit_registry_findings_from_walk(project.id, fw.id)
        await db.commit()
        assert emitted == []


# ── Live canary — emit_driver_findings_from_extract (Rule #35b) ─────────────


async def _seed_firmware_with_unsigned_driver(db) -> tuple[Project, Firmware]:
    project = Project(name="γ.8-driver")
    db.add(project)
    await db.flush()
    fw = Firmware(project_id=project.id, sha256="0" * 64)
    db.add(fw)
    await db.flush()

    blob = HardwareFirmwareBlob(
        firmware_id=fw.id,
        blob_path="Windows/INF/no-name.inf",
        blob_sha256="b" * 64,
        file_size=1024,
        category="driver_package",
        format="windows_inf",
        detection_source="driver_extractor",
    )
    db.add(blob)
    await db.flush()

    inf_metadata = _stamp_windows_drivers_inf_metadata({
        "version_block": {"Class": "Display", "ClassGuid": None,
                          "Provider": "No-Name Vendor",
                          "DriverVer": None, "CatalogFile": None},
        "manufacturer_block": [],
        "models": [],
        "strings": {},
        "errors": [],
    })
    driver = WindowsDriver(
        blob_id=blob.id,
        driver_path="Windows/INF/no-name.inf",
        inf_path="Windows/INF/no-name.inf",
        cat_path=None,
        sys_path=None,
        inf_class="Display",
        class_guid=None,
        driver_provider="No-Name Vendor",
        driver_version=None,
        driver_name="No-Name Vendor",
        manufacturer="No-Name Vendor",
        pnp_ids=["PCI\\VEN_FFFF&DEV_DEAD"],
        catalog_signed=False,
        signing_tier="unsigned",
        inf_metadata=inf_metadata,
    )
    db.add(driver)
    await db.flush()
    return project, fw


async def test_emit_driver_findings_persists_finding_row() -> None:
    """End-to-end: seed unsigned driver → emit findings → SELECT
    persisted Finding row."""
    async with make_live_db() as db:
        project, fw = await _seed_firmware_with_unsigned_driver(db)
        await db.commit()

        service = FindingService(db)
        emitted = await service.emit_driver_findings_from_extract(project.id, fw.id)
        await db.commit()

        # Unsigned driver with PnP IDs → 1 windows_inf finding.
        assert len(emitted) == 1
        f = emitted[0]
        assert f.source == "windows_inf"
        assert f.severity == "medium"
        assert "no-name.inf" in f.title

        from sqlalchemy import select as _sel
        rows = (
            await db.execute(
                _sel(Finding).where(
                    Finding.firmware_id == fw.id,
                    Finding.source == "windows_inf",
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        r = rows[0]
        assert r.file_path == "Windows/INF/no-name.inf"
        assert r.confidence == "medium"


async def test_emit_driver_findings_no_drivers_returns_empty() -> None:
    """Firmware with no drivers → no findings emitted."""
    async with make_live_db() as db:
        project = Project(name="empty")
        db.add(project)
        await db.flush()
        fw = Firmware(project_id=project.id, sha256="0" * 64)
        db.add(fw)
        await db.flush()
        await db.commit()

        service = FindingService(db)
        emitted = await service.emit_driver_findings_from_extract(project.id, fw.id)
        await db.commit()
        assert emitted == []
