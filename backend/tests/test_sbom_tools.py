"""Contract tests for the ``app.ai.tools.sbom`` MCP tool handlers.

increase-coverage skill run: app/ai/tools/sbom.py sat at 7% coverage
(435 stmts / 406 miss) with no dedicated MCP-handler test file — only the
service, router, and status-alignment suites exercised the SBOM surface.
This file drives every handler through a ``_StubContext`` + ``make_live_db``
(Rule #35b), mocking NVD / Dependency-Track / SbomService at their service
boundaries so no live network or filesystem walk is required.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.sbom import (
    _SBOM_EXPORT_MAX_BYTES,
    _handle_assess_vulnerabilities,
    _handle_check_component_cves,
    _handle_export_sbom,
    _handle_generate_sbom,
    _handle_get_sbom_components,
    _handle_list_vulnerabilities_for_assessment,
    _handle_push_to_dependency_track,
    _handle_run_vulnerability_scan,
    _handle_set_vulnerability_status,
    _sbom_truncation_marker,
    register_sbom_tools,
)
from app.models import Firmware, Project
from app.models.sbom import SbomComponent, SbomVulnerability
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub for SBOM handlers (db / firmware / project)."""

    db: AsyncSession
    firmware_id: uuid.UUID
    project_id: uuid.UUID | None = None
    extracted_path: str | None = "/tmp/extract"
    detection_roots: list[str] = field(default_factory=list)


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


async def _seed(
    db: AsyncSession,
    *,
    extracted_path: str | None = "/tmp/extract",
    os_info: str | dict | None = None,
    original_filename: str = "test-fw.bin",
    sha256: str | None = None,
) -> tuple[Project, Firmware]:
    project = Project(id=uuid.uuid4(), name="sbom-tools-test", status="ready")
    db.add(project)
    await db.flush()

    if isinstance(os_info, dict):
        os_info = json.dumps(os_info)

    firmware = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256=sha256 or ("b" * 64),
        extracted_path=extracted_path,
        extraction_dir=extracted_path,
        original_filename=original_filename,
        os_info=os_info,
    )
    db.add(firmware)
    await db.flush()
    return project, firmware


def _component(firmware_id: uuid.UUID, **overrides) -> SbomComponent:
    defaults = dict(
        id=uuid.uuid4(),
        firmware_id=firmware_id,
        name="busybox",
        version="1.33.1",
        type="application",
        cpe="cpe:2.3:a:busybox:busybox:1.33.1:*:*:*:*:*:*:*",
        purl="pkg:generic/busybox@1.33.1",
        supplier=None,
        detection_source="package_manager",
        detection_confidence="high",
        file_paths=["/bin/busybox", "/bin/ls"],
        metadata_={},
    )
    defaults.update(overrides)
    return SbomComponent(**defaults)


def _vuln(firmware_id: uuid.UUID, component_id: uuid.UUID | None = None, **overrides) -> SbomVulnerability:
    defaults = dict(
        id=uuid.uuid4(),
        firmware_id=firmware_id,
        component_id=component_id,
        cve_id="CVE-2021-42374",
        cvss_score=7.5,
        severity="high",
        description="A vulnerability in busybox.",
        resolution_status="open",
    )
    defaults.update(overrides)
    return SbomVulnerability(**defaults)


# ---------------------------------------------------------------------------
# register_sbom_tools
# ---------------------------------------------------------------------------


def test_register_sbom_tools_registers_all_nine():
    registry = ToolRegistry()
    register_sbom_tools(registry)
    names = set(registry._tools.keys())
    assert names == {
        "generate_sbom",
        "get_sbom_components",
        "check_component_cves",
        "run_vulnerability_scan",
        "list_vulnerabilities_for_assessment",
        "export_sbom",
        "push_to_dependency_track",
        "assess_vulnerabilities",
        "set_vulnerability_status",
    }


# ---------------------------------------------------------------------------
# _sbom_truncation_marker
# ---------------------------------------------------------------------------


def test_sbom_truncation_marker_is_valid_json():
    marker = _sbom_truncation_marker(
        "cyclonedx-json", 50_000, str(uuid.uuid4()), str(uuid.uuid4()),
    )
    data = json.loads(marker)
    assert data["status"] == "truncated"
    assert data["format"] == "cyclonedx-json"
    assert data["original_size_bytes"] == 50_000
    assert data["limit_bytes"] == _SBOM_EXPORT_MAX_BYTES
    assert "/sbom/export?format=cyclonedx-json" in data["rest_endpoint"]


# ---------------------------------------------------------------------------
# _handle_generate_sbom
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_sbom_returns_cached_when_components_exist(live_db):
    project, firmware = await _seed(live_db)
    live_db.add(_component(firmware.id))
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_generate_sbom({}, ctx)
    assert "SBOM generated (cached)" in result
    assert "1 components identified" in result
    assert "busybox 1.33.1" in result
    assert "have CPE identifiers" in result


@pytest.mark.asyncio
async def test_generate_sbom_force_rescan_clears_and_regenerates(live_db):
    project, firmware = await _seed(live_db)
    live_db.add(_component(firmware.id, name="oldpkg", version="0.1"))
    await live_db.flush()

    generated = [
        {
            "name": "openssl",
            "version": "1.1.1k",
            "type": "library",
            "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
            "purl": None,
            "supplier": None,
            "detection_source": "binary_strings",
            "detection_confidence": "medium",
            "file_paths": ["/usr/lib/libssl.so"],
            "metadata": {},
        }
    ]
    mock_svc = MagicMock()
    mock_svc.generate_sbom.return_value = generated

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with (
        patch("app.ai.tools.sbom.SbomService", return_value=mock_svc),
        patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=["/tmp/extract"]),
        ),
    ):
        result = await _handle_generate_sbom({"force_rescan": True}, ctx)

    assert "SBOM generated:" in result
    assert "(cached)" not in result
    assert "openssl" in result

    rows = (
        await live_db.execute(
            select(SbomComponent).where(SbomComponent.firmware_id == firmware.id)
        )
    ).scalars().all()
    names = {r.name for r in rows}
    assert "openssl" in names
    assert "oldpkg" not in names  # force_rescan deleted prior rows


@pytest.mark.asyncio
async def test_generate_sbom_injects_rtos_from_os_info(live_db):
    os_info = {
        "rtos": {"name": "FreeRTOS", "version": "10.4.3", "confidence": "high"},
        "companion_components": [
            {"name": "lwIP", "version": "2.1.2", "confidence": "medium"},
        ],
        "format": "elf",
    }
    project, firmware = await _seed(live_db, os_info=os_info)

    mock_svc = MagicMock()
    mock_svc.generate_sbom.return_value = []

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with (
        patch("app.ai.tools.sbom.SbomService", return_value=mock_svc),
        patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=["/tmp/extract"]),
        ),
    ):
        result = await _handle_generate_sbom({}, ctx)

    assert "FreeRTOS" in result or "components identified" in result
    rows = (
        await live_db.execute(
            select(SbomComponent).where(SbomComponent.firmware_id == firmware.id)
        )
    ).scalars().all()
    names = {r.name for r in rows}
    assert "FreeRTOS" in names
    assert "lwIP" in names
    freertos = next(r for r in rows if r.name == "FreeRTOS")
    assert freertos.type == "operating-system"
    assert freertos.detection_source == "rtos_detection"
    assert freertos.cpe is not None and "freertos" in freertos.cpe


@pytest.mark.asyncio
async def test_generate_sbom_ucos_supplier_and_service_fallback(live_db):
    """Micrium supplier for uC/OS; SbomService falls back when firmware row missing."""
    os_info = {
        "rtos": {"name": "uC/OS-II", "version": "2.92", "confidence": "high"},
        "companion_components": [],
    }
    # Seed then point context at a non-existent firmware_id so pre_fw is None
    # but we still need a valid FK for component insert — use real firmware
    # with empty generate, then re-run path via force and missing pre lookup
    # is covered separately. Here cover ucos supplier on real firmware.
    project, firmware = await _seed(live_db, os_info=os_info)
    mock_svc = MagicMock()
    mock_svc.generate_sbom.return_value = []

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with (
        patch("app.ai.tools.sbom.SbomService", return_value=mock_svc) as svc_cls,
        patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=["/tmp/extract"]),
        ),
    ):
        await _handle_generate_sbom({}, ctx)
        # Firmware row exists → SbomService constructed with firmware=
        assert svc_cls.called
        call_kwargs = svc_cls.call_args
        assert call_kwargs.kwargs.get("firmware") is not None or (
            call_kwargs.args and call_kwargs.args[0] is not None
        )

    rows = (
        await live_db.execute(
            select(SbomComponent).where(SbomComponent.firmware_id == firmware.id)
        )
    ).scalars().all()
    ucos = next(r for r in rows if "uC" in r.name or "uc" in r.name.lower())
    assert ucos.supplier == "Micrium"


@pytest.mark.asyncio
async def test_generate_sbom_generation_error(live_db):
    project, firmware = await _seed(live_db)
    mock_svc = MagicMock()
    mock_svc.generate_sbom.side_effect = RuntimeError("disk full")

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with (
        patch("app.ai.tools.sbom.SbomService", return_value=mock_svc),
        patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=["/tmp/extract"]),
        ),
    ):
        result = await _handle_generate_sbom({}, ctx)
    assert result == "Error generating SBOM: disk full"


@pytest.mark.asyncio
async def test_generate_sbom_when_firmware_row_missing_uses_path(live_db):
    """SbomService(extracted_path) path when firmware SELECT returns None."""
    project = Project(id=uuid.uuid4(), name="orphan-project", status="ready")
    live_db.add(project)
    await live_db.flush()

    # No Firmware row for this id → pre_fw is None → path-only constructor.
    # SQLite live DB typically does not enforce FKs, so component inserts land.
    missing_fw_id = uuid.uuid4()
    mock_svc = MagicMock()
    mock_svc.generate_sbom.return_value = [
        {
            "name": "dropbear",
            "version": "2020.81",
            "type": "application",
            "cpe": None,
            "purl": None,
            "supplier": None,
            "detection_source": "binary",
            "detection_confidence": "low",
            "file_paths": None,
            "metadata": {},
        }
    ]

    ctx = _StubContext(
        db=live_db,
        firmware_id=missing_fw_id,
        project_id=project.id,
        extracted_path="/tmp/extract",
    )
    with patch("app.ai.tools.sbom.SbomService") as svc_cls:
        svc_cls.return_value = mock_svc
        result = await _handle_generate_sbom({}, ctx)

    # Path-only constructor: SbomService(extracted_path) positional arg
    svc_cls.assert_called_once_with("/tmp/extract")
    assert "SBOM generated" in result
    assert "dropbear" in result

# ---------------------------------------------------------------------------
# _handle_get_sbom_components
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_sbom_components_empty(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_get_sbom_components({}, ctx)
    assert "No SBOM components found" in result
    assert "Run generate_sbom first" in result


@pytest.mark.asyncio
async def test_get_sbom_components_with_filters_and_paths(live_db):
    project, firmware = await _seed(live_db)
    live_db.add(
        _component(
            firmware.id,
            name="busybox",
            type="application",
            file_paths=[f"/bin/f{i}" for i in range(20)],
        )
    )
    live_db.add(
        _component(
            firmware.id,
            name="libssl",
            version="1.1.1",
            type="library",
            cpe=None,
            purl=None,
            file_paths=None,
        )
    )
    live_db.add(
        _component(
            firmware.id,
            name="linux",
            version=None,
            type="operating-system",
            cpe=None,
            purl=None,
            file_paths=[],
        )
    )
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    all_result = await _handle_get_sbom_components({}, ctx)
    assert "Found 3 component(s)" in all_result
    assert "busybox" in all_result
    assert "(+5 more)" in all_result  # 20 paths → 15 shown + 5 more
    assert "unknown version" in all_result

    filtered = await _handle_get_sbom_components(
        {"type": "library", "name_filter": "ssl"}, ctx,
    )
    assert "Found 1 component(s)" in filtered
    assert "libssl" in filtered
    assert "busybox" not in filtered

    empty_filter = await _handle_get_sbom_components(
        {"type": "application", "name_filter": "zzzz"}, ctx,
    )
    assert "No SBOM components found" in empty_filter
    assert "type=application" in empty_filter
    assert "name contains 'zzzz'" in empty_filter


# ---------------------------------------------------------------------------
# _handle_check_component_cves
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_component_cves_no_cpe(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_check_component_cves(
        {"component_name": "totally-unknown-pkg-xyz", "version": "1.0"}, ctx,
    )
    assert "Cannot look up CVEs" in result
    assert "no CPE identifier" in result


@pytest.mark.asyncio
async def test_check_component_cves_from_vendor_map_no_cves(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    with (
        patch("app.config.get_settings", return_value=SimpleNamespace(nvd_api_key=None)),
        patch(
            "app.services.vulnerability_service._search_nvd",
            return_value=[],
        ),
    ):
        result = await _handle_check_component_cves(
            {"component_name": "openssl", "version": "1.1.1k"}, ctx,
        )
    assert "No known CVEs found for openssl 1.1.1k" in result
    assert "cpe:2.3:a:openssl:openssl:1.1.1k" in result


@pytest.mark.asyncio
async def test_check_component_cves_from_sbom_component_with_scores(live_db):
    project, firmware = await _seed(live_db)
    live_db.add(_component(firmware.id, name="busybox", version="1.33.1"))
    await live_db.flush()

    desc_en = SimpleNamespace(lang="en", value="A" * 250)
    desc_fr = SimpleNamespace(lang="fr", value="ignored")
    cves = [
        SimpleNamespace(id="CVE-CRITICAL", score=["cvssV3", 9.8], descriptions=[desc_fr, desc_en]),
        SimpleNamespace(id="CVE-HIGH", score=["cvssV3", 7.5], descriptions=[desc_en]),
        SimpleNamespace(id="CVE-MED", score=["cvssV3", 5.0], descriptions=[]),
        SimpleNamespace(id="CVE-LOW", score=["cvssV3", 2.0], descriptions=[]),
        SimpleNamespace(id="CVE-NOSCORE", score=None, descriptions=[]),
    ]

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with (
        patch("app.config.get_settings", return_value=SimpleNamespace(nvd_api_key="k")),
        patch(
            "app.services.vulnerability_service._search_nvd",
            return_value=cves,
        ),
    ):
        result = await _handle_check_component_cves(
            {"component_name": "busybox", "version": "1.33.1"}, ctx,
        )

    assert "Found 5 CVE(s)" in result
    assert "[CRITICAL] CVE-CRITICAL (CVSS 9.8)" in result
    assert "[HIGH] CVE-HIGH" in result
    assert "[MEDIUM] CVE-MED" in result
    assert "[LOW] CVE-LOW" in result
    assert "AAA" in result  # truncated description prefix


@pytest.mark.asyncio
async def test_check_component_cves_nvd_error_and_more_than_50(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    with (
        patch("app.config.get_settings", return_value=SimpleNamespace(nvd_api_key=None)),
        patch(
            "app.services.vulnerability_service._search_nvd",
            side_effect=RuntimeError("rate limited"),
        ),
    ):
        err = await _handle_check_component_cves(
            {"component_name": "openssl", "version": "1.0.0"}, ctx,
        )
    assert "Error querying NVD for openssl 1.0.0" in err
    assert "rate limited" in err

    many = [
        SimpleNamespace(id=f"CVE-2020-{i:04d}", score=["cvssV3", 4.0], descriptions=[])
        for i in range(55)
    ]
    with (
        patch("app.config.get_settings", return_value=SimpleNamespace(nvd_api_key=None)),
        patch(
            "app.services.vulnerability_service._search_nvd",
            return_value=many,
        ),
    ):
        result = await _handle_check_component_cves(
            {"component_name": "openssl", "version": "1.0.0"}, ctx,
        )
    assert "Found 55 CVE(s)" in result
    assert "... and 5 more CVEs" in result


# ---------------------------------------------------------------------------
# _handle_run_vulnerability_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_vulnerability_scan_requires_sbom(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_run_vulnerability_scan({}, ctx)
    assert "No SBOM generated yet" in result


@pytest.mark.asyncio
async def test_run_vulnerability_scan_success_and_error(live_db):
    project, firmware = await _seed(live_db)
    live_db.add(_component(firmware.id))
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    summary = {
        "status": "completed",
        "total_components_scanned": 3,
        "total_vulnerabilities_found": 5,
        "findings_created": 2,
        "vulns_by_severity": {"critical": 1, "high": 2, "medium": 2, "low": 0},
    }
    with patch(
        "app.ai.tools.sbom.VulnerabilityService.scan_components",
        new=AsyncMock(return_value=summary),
    ):
        result = await _handle_run_vulnerability_scan({}, ctx)
    assert "Vulnerability scan complete" in result
    assert "Components scanned (with CPE): 3" in result
    assert "CRITICAL: 1" in result
    assert "2 security finding(s) auto-created" in result
    assert "list_vulnerabilities_for_assessment" in result

    cached = {
        **summary,
        "status": "cached",
        "findings_created": 0,
        "total_vulnerabilities_found": 0,
        "vulns_by_severity": {},
    }
    with patch(
        "app.ai.tools.sbom.VulnerabilityService.scan_components",
        new=AsyncMock(return_value=cached),
    ):
        result = await _handle_run_vulnerability_scan({"force_rescan": True}, ctx)
    assert "(cached results)" in result

    no_findings = {
        "status": "completed",
        "total_components_scanned": 1,
        "total_vulnerabilities_found": 0,
        "findings_created": 0,
        "vulns_by_severity": {},
    }
    with patch(
        "app.ai.tools.sbom.VulnerabilityService.scan_components",
        new=AsyncMock(return_value=no_findings),
    ):
        result = await _handle_run_vulnerability_scan({}, ctx)
    assert "No findings auto-created" in result

    with patch(
        "app.ai.tools.sbom.VulnerabilityService.scan_components",
        new=AsyncMock(side_effect=RuntimeError("nvd down")),
    ):
        result = await _handle_run_vulnerability_scan({}, ctx)
    assert result == "Vulnerability scan error: nvd down"


# ---------------------------------------------------------------------------
# _handle_list_vulnerabilities_for_assessment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_vulnerabilities_empty_and_populated(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    empty = await _handle_list_vulnerabilities_for_assessment({}, ctx)
    assert "No vulnerabilities found" in empty
    assert "status=open" in empty
    assert "unassessed only" in empty

    comp = _component(firmware.id)
    live_db.add(comp)
    await live_db.flush()

    long_desc = "X" * 200
    v1 = _vuln(
        firmware.id, comp.id,
        cve_id="CVE-2021-0001",
        cvss_score=9.0,
        severity="critical",
        description=long_desc,
    )
    v2 = _vuln(
        firmware.id, comp.id,
        cve_id="CVE-2021-0002",
        cvss_score=4.0,
        severity="medium",
        description="short",
        adjusted_severity="low",  # assessed — excluded by default
    )
    v3 = _vuln(
        firmware.id,
        component_id=None,  # blob-pipeline style
        cve_id="CVE-2021-0003",
        cvss_score=8.0,
        severity="high",
        description=None,
    )
    live_db.add_all([v1, v2, v3])
    await live_db.flush()

    result = await _handle_list_vulnerabilities_for_assessment({}, ctx)
    assert "CVE-2021-0001" in result
    assert "CVE-2021-0003" in result
    assert "CVE-2021-0002" not in result  # assessed filtered out
    assert "..." in result  # long description truncated
    assert str(v1.id) in result
    assert "busybox" in result
    assert "(unattributed)" in result  # blob-pipeline without blob_path

    # severity + unassessed_only=false
    all_open = await _handle_list_vulnerabilities_for_assessment(
        {"unassessed_only": False, "severity_filter": "medium"}, ctx,
    )
    assert "CVE-2021-0002" in all_open
    assert "CVE-2021-0001" not in all_open


@pytest.mark.asyncio
async def test_list_vulnerabilities_pagination(live_db):
    project, firmware = await _seed(live_db)
    comp = _component(firmware.id)
    live_db.add(comp)
    await live_db.flush()
    for i in range(3):
        live_db.add(
            _vuln(
                firmware.id, comp.id,
                cve_id=f"CVE-2022-{i:04d}",
                cvss_score=float(9 - i),
                severity="high",
            )
        )
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    page1 = await _handle_list_vulnerabilities_for_assessment(
        {"limit": 2, "offset": 0, "unassessed_only": False}, ctx,
    )
    assert "1-2 of 3" in page1
    assert "1 more" in page1
    assert "offset=2" in page1

    page2 = await _handle_list_vulnerabilities_for_assessment(
        {"limit": 2, "offset": 2, "unassessed_only": False}, ctx,
    )
    assert "3-3 of 3" in page2


# ---------------------------------------------------------------------------
# _handle_export_sbom
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_sbom_no_components(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_export_sbom({}, ctx)
    assert result == "No SBOM generated yet. Run generate_sbom first."


@pytest.mark.asyncio
async def test_export_sbom_cyclonedx_default(live_db):
    project, firmware = await _seed(live_db)
    live_db.add(
        _component(
            firmware.id,
            name="busybox",
            version="1.33.1",
            purl="pkg:generic/busybox@1.33.1",
            cpe="cpe:2.3:a:busybox:busybox:1.33.1:*:*:*:*:*:*:*",
        )
    )
    live_db.add(
        _component(
            firmware.id,
            name="noversion",
            version=None,
            purl=None,
            cpe=None,
            type="library",
        )
    )
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_export_sbom({}, ctx)
    data = json.loads(result)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.7"
    assert len(data["components"]) == 2
    names = {c["name"] for c in data["components"]}
    assert names == {"busybox", "noversion"}
    bb = next(c for c in data["components"] if c["name"] == "busybox")
    assert bb["version"] == "1.33.1"
    assert bb["purl"].startswith("pkg:")
    assert "cpe" in bb


@pytest.mark.asyncio
async def test_export_sbom_spdx_json(live_db):
    project, firmware = await _seed(live_db)
    live_db.add(_component(firmware.id, supplier="BusyBox Project"))
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_export_sbom({"format": "spdx-json"}, ctx)
    data = json.loads(result)
    assert data["spdxVersion"] == "SPDX-2.3"
    assert "packages" in data


@pytest.mark.asyncio
async def test_export_sbom_vex_summary(live_db):
    project, firmware = await _seed(live_db)
    comp = _component(firmware.id)
    live_db.add(comp)
    await live_db.flush()
    live_db.add(
        _vuln(
            firmware.id, comp.id,
            cve_id="CVE-2023-1",
            cvss_score=9.1,
            severity="critical",
            adjusted_severity=None,
            resolution_status="open",
        )
    )
    live_db.add(
        _vuln(
            firmware.id, comp.id,
            cve_id="CVE-2023-2",
            cvss_score=3.0,
            severity="low",
            adjusted_cvss_score=1.0,
            adjusted_severity="low",
            resolution_status="false_positive",
        )
    )
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_export_sbom({"format": "cyclonedx-vex-json"}, ctx)
    data = json.loads(result)
    assert data["format"].startswith("CycloneDX VEX")
    assert data["total_components"] == 1
    assert data["total_vulnerabilities"] == 2
    assert "by_severity" in data
    assert "by_state" in data
    assert len(data["top_vulnerabilities"]) == 2


@pytest.mark.asyncio
async def test_export_sbom_truncation_marker_for_large_output(live_db):
    project, firmware = await _seed(live_db)
    # Create enough components that pretty-printed CycloneDX exceeds 30 KB
    live_db.add_all([
        _component(
            firmware.id,
            name=f"component-with-a-very-long-name-{i:04d}",
            version=f"1.0.{i}",
            cpe=f"cpe:2.3:a:vendor:product{i}:1.0.{i}:*:*:*:*:*:*:*",
            purl=f"pkg:generic/component-with-a-very-long-name-{i:04d}@1.0.{i}",
        )
        for i in range(800)
    ])
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_export_sbom({"format": "cyclonedx-json"}, ctx)
    data = json.loads(result)
    assert data["status"] == "truncated"
    assert data["format"] == "cyclonedx-json"
    assert data["original_size_bytes"] > _SBOM_EXPORT_MAX_BYTES


# ---------------------------------------------------------------------------
# _handle_push_to_dependency_track
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_push_to_dt_not_configured(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    mock_svc = MagicMock()
    mock_svc.is_configured = False
    with patch(
        "app.services.dependency_track_service.DependencyTrackService",
        return_value=mock_svc,
    ):
        result = await _handle_push_to_dependency_track({}, ctx)
    assert "Dependency-Track not configured" in result


@pytest.mark.asyncio
async def test_push_to_dt_no_sbom(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    mock_svc = MagicMock()
    mock_svc.is_configured = True
    with patch(
        "app.services.dependency_track_service.DependencyTrackService",
        return_value=mock_svc,
    ):
        result = await _handle_push_to_dependency_track({}, ctx)
    assert "No SBOM generated yet" in result


@pytest.mark.asyncio
async def test_push_to_dt_success_and_failure(live_db):
    project, firmware = await _seed(
        live_db, original_filename="router.bin", sha256="c" * 64,
    )
    live_db.add(_component(firmware.id, version=None, purl=None, cpe=None))
    live_db.add(
        _component(
            firmware.id,
            name="openssl",
            version="1.1.1",
            purl="pkg:generic/openssl@1.1.1",
            cpe="cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
        )
    )
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    mock_svc = MagicMock()
    mock_svc.is_configured = True
    mock_svc.push_sbom = AsyncMock(return_value={"token": "abc123"})

    with patch(
        "app.services.dependency_track_service.DependencyTrackService",
        return_value=mock_svc,
    ):
        result = await _handle_push_to_dependency_track({}, ctx)
    assert "SBOM pushed to Dependency-Track successfully" in result
    assert "abc123" in result
    call_kwargs = mock_svc.push_sbom.await_args.kwargs
    assert call_kwargs["project_name"] == "router.bin"
    assert call_kwargs["project_version"] == ("c" * 12)
    assert call_kwargs["sbom_json"]["bomFormat"] == "CycloneDX"

    mock_svc.push_sbom = AsyncMock(side_effect=RuntimeError("401 unauthorized"))
    with patch(
        "app.services.dependency_track_service.DependencyTrackService",
        return_value=mock_svc,
    ):
        err = await _handle_push_to_dependency_track(
            {"project_name": "custom", "project_version": "9.9"}, ctx,
        )
    assert "Failed to push to Dependency-Track: 401 unauthorized" in err


# ---------------------------------------------------------------------------
# _handle_assess_vulnerabilities
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_vulnerabilities_validation(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    assert await _handle_assess_vulnerabilities({}, ctx) == "No assessments provided."
    assert (
        await _handle_assess_vulnerabilities({"assessments": []}, ctx)
        == "No assessments provided."
    )
    too_many = [
        {"vulnerability_id": str(uuid.uuid4()), "rationale": "x"}
        for _ in range(51)
    ]
    assert (
        await _handle_assess_vulnerabilities({"assessments": too_many}, ctx)
        == "Maximum 50 assessments per call."
    )


@pytest.mark.asyncio
async def test_assess_vulnerabilities_updates_and_not_found(live_db):
    project, firmware = await _seed(live_db)
    comp = _component(firmware.id)
    live_db.add(comp)
    await live_db.flush()

    v_open = _vuln(
        firmware.id, comp.id,
        cve_id="CVE-ASSESS-1",
        severity="high",
        resolution_status="open",
    )
    v_resolve = _vuln(
        firmware.id, comp.id,
        cve_id="CVE-ASSESS-2",
        severity="critical",
        resolution_status="open",
    )
    live_db.add_all([v_open, v_resolve])
    await live_db.flush()

    missing_id = uuid.uuid4()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_assess_vulnerabilities(
        {
            "assessments": [
                {
                    "vulnerability_id": str(v_open.id),
                    "adjusted_severity": "medium",
                    "adjusted_cvss_score": 5.5,
                    "rationale": "not reachable over WAN",
                },
                {
                    "vulnerability_id": str(v_resolve.id),
                    "adjusted_severity": "critical",
                    "resolution_status": "resolved",
                    "rationale": "patched in this build",
                },
                {
                    "vulnerability_id": str(missing_id),
                    "rationale": "ghost",
                },
                {
                    "vulnerability_id": "not-a-uuid",
                    "rationale": "bad id",
                },
                {
                    # empty vulnerability_id skipped in collection
                    "rationale": "no id",
                },
            ],
        },
        ctx,
    )

    assert "Assessed 2 vulnerability(ies)" in result
    # missing UUID + invalid UUID + empty vulnerability_id all count as not found
    assert "3 not found" in result
    assert "CVE-ASSESS-1: high -> medium [open]" in result
    assert "CVE-ASSESS-2: critical (unchanged) [resolved]" in result
    assert "NOT FOUND" in result

    await live_db.refresh(v_open)
    await live_db.refresh(v_resolve)
    assert v_open.adjusted_severity == "medium"
    assert float(v_open.adjusted_cvss_score) == 5.5
    assert v_open.adjustment_rationale == "not reachable over WAN"
    assert v_resolve.resolution_status == "resolved"
    assert v_resolve.resolved_by == "ai"
    assert v_resolve.resolved_at is not None


@pytest.mark.asyncio
async def test_assess_vulnerabilities_reopen_clears_resolved(live_db):
    project, firmware = await _seed(live_db)
    comp = _component(firmware.id)
    live_db.add(comp)
    await live_db.flush()
    from datetime import UTC, datetime

    v = _vuln(
        firmware.id, comp.id,
        cve_id="CVE-REOPEN",
        severity="medium",
        resolution_status="ignored",
        resolved_by="ai",
        resolved_at=datetime.now(UTC),
    )
    live_db.add(v)
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_assess_vulnerabilities(
        {
            "assessments": [
                {
                    "vulnerability_id": str(v.id),
                    "resolution_status": "open",
                    "rationale": "re-open for re-triage",
                },
            ],
        },
        ctx,
    )
    assert "CVE-REOPEN" in result
    await live_db.refresh(v)
    assert v.resolution_status == "open"
    assert v.resolved_by is None
    assert v.resolved_at is None


# ---------------------------------------------------------------------------
# _handle_set_vulnerability_status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_vulnerability_status_invalid_id_and_status(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    bad_id = await _handle_set_vulnerability_status(
        {
            "vulnerability_id": "nope",
            "status": "not_affected",
            "justification": "x",
        },
        ctx,
    )
    assert "Invalid vulnerability_id" in bad_id

    bad_status = await _handle_set_vulnerability_status(
        {
            "vulnerability_id": str(uuid.uuid4()),
            "status": "bogus",
            "justification": "x",
        },
        ctx,
    )
    assert "Invalid VEX status" in bad_status


@pytest.mark.asyncio
async def test_set_vulnerability_status_not_found(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_set_vulnerability_status(
        {
            "vulnerability_id": str(uuid.uuid4()),
            "status": "fixed",
            "justification": "patched",
        },
        ctx,
    )
    assert "not found in this firmware" in result


@pytest.mark.asyncio
async def test_set_vulnerability_status_all_vex_mappings(live_db):
    project, firmware = await _seed(live_db)
    comp = _component(firmware.id)
    live_db.add(comp)
    await live_db.flush()

    v_na = _vuln(firmware.id, comp.id, cve_id="CVE-NA", resolution_status="open")
    v_aff = _vuln(
        firmware.id, comp.id, cve_id="CVE-AFF", severity="high", resolution_status="open",
    )
    v_fix = _vuln(firmware.id, comp.id, cve_id="CVE-FIX", resolution_status="open")
    v_inv = _vuln(
        firmware.id, comp.id,
        cve_id="CVE-INV",
        resolution_status="resolved",
        resolved_by="user",
    )
    live_db.add_all([v_na, v_aff, v_fix, v_inv])
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    r1 = await _handle_set_vulnerability_status(
        {
            "vulnerability_id": str(v_na.id),
            "status": "not_affected",
            "justification": "code_not_reachable",
        },
        ctx,
    )
    assert "VEX state: not_affected" in r1
    assert "false_positive" in r1
    await live_db.refresh(v_na)
    assert v_na.resolution_status == "false_positive"
    assert v_na.resolved_by == "ai"
    assert v_na.resolution_justification == "code_not_reachable"

    r2 = await _handle_set_vulnerability_status(
        {
            "vulnerability_id": str(v_aff.id),
            "status": "affected",
            "justification": "confirmed exploitable",
        },
        ctx,
    )
    assert "VEX state: affected" in r2
    await live_db.refresh(v_aff)
    assert v_aff.resolution_status == "open"
    assert v_aff.adjusted_severity == "high"  # copied from severity
    assert v_aff.resolved_by is None

    r3 = await _handle_set_vulnerability_status(
        {
            "vulnerability_id": str(v_fix.id),
            "status": "fixed",
            "justification": "vendor patch applied",
        },
        ctx,
    )
    assert "fixed" in r3
    await live_db.refresh(v_fix)
    assert v_fix.resolution_status == "resolved"
    assert v_fix.resolved_by == "ai"
    assert v_fix.resolved_at is not None

    r4 = await _handle_set_vulnerability_status(
        {
            "vulnerability_id": str(v_inv.id),
            "status": "under_investigation",
            "justification": "rechecking",
        },
        ctx,
    )
    assert "under_investigation" in r4
    await live_db.refresh(v_inv)
    assert v_inv.resolution_status == "open"
    assert v_inv.resolved_by is None
    assert v_inv.resolved_at is None


# ---------------------------------------------------------------------------
# Live canary: assess → SELECT persisted columns (Rule #35b)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_sbom_tolerates_malformed_os_info(live_db):
    """RTOS injection swallows JSON/parse errors (lines 394-395)."""
    project, firmware = await _seed(live_db, os_info="{not-valid-json")
    mock_svc = MagicMock()
    mock_svc.generate_sbom.return_value = [
        {
            "name": "only",
            "version": "1",
            "type": "library",
            "cpe": None,
            "purl": None,
            "supplier": None,
            "detection_source": "binary",
            "detection_confidence": "low",
            "file_paths": None,
            "metadata": {},
        }
    ]
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with (
        patch("app.ai.tools.sbom.SbomService", return_value=mock_svc),
        patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=["/tmp/extract"]),
        ),
    ):
        result = await _handle_generate_sbom({}, ctx)
    assert "SBOM generated" in result
    assert "only" in result


@pytest.mark.asyncio
async def test_list_vulnerabilities_empty_with_no_filters(live_db):
    """Empty result with all filters off hits the bare 'No vulnerabilities' branch."""
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_list_vulnerabilities_for_assessment(
        {"status_filter": "", "unassessed_only": False}, ctx,
    )
    assert result == "No vulnerabilities found."


@pytest.mark.asyncio
async def test_list_vulnerabilities_empty_with_severity_filter(live_db):
    """Empty result with severity_filter alone (line 753)."""
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_list_vulnerabilities_for_assessment(
        {
            "status_filter": "",
            "severity_filter": "critical",
            "unassessed_only": False,
        },
        ctx,
    )
    assert "No vulnerabilities found" in result
    assert "severity=critical" in result

@pytest.mark.asyncio
async def test_export_spdx_and_vex_truncation(live_db):
    """Force SPDX / VEX paths through the 30 KB truncation marker."""
    project, firmware = await _seed(live_db)
    live_db.add(_component(firmware.id))
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    with patch("app.ai.tools.sbom._SBOM_EXPORT_MAX_BYTES", 10):
        spdx = await _handle_export_sbom({"format": "spdx-json"}, ctx)
        vex = await _handle_export_sbom({"format": "cyclonedx-vex-json"}, ctx)

    spdx_data = json.loads(spdx)
    assert spdx_data["status"] == "truncated"
    assert spdx_data["format"] == "spdx-json"

    vex_data = json.loads(vex)
    assert vex_data["status"] == "truncated"
    assert vex_data["format"] == "cyclonedx-vex-json"


@pytest.mark.asyncio
async def test_assess_live_canary_persists_fields(live_db):
    """Rule #35b: value-flow canary through real ORM round-trip."""
    project, firmware = await _seed(live_db)
    comp = _component(firmware.id, name="openssl", version="1.0.2")
    live_db.add(comp)
    await live_db.flush()
    vuln = _vuln(
        firmware.id, comp.id,
        cve_id="CVE-CANARY-9999",
        severity="critical",
        cvss_score=9.8,
    )
    live_db.add(vuln)
    await live_db.flush()
    vuln_id = vuln.id

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    await _handle_assess_vulnerabilities(
        {
            "assessments": [
                {
                    "vulnerability_id": str(vuln_id),
                    "adjusted_severity": "low",
                    "adjusted_cvss_score": 2.1,
                    "resolution_status": "false_positive",
                    "rationale": "feature disabled at compile time",
                },
            ],
        },
        ctx,
    )

    row = (
        await live_db.execute(
            select(SbomVulnerability).where(SbomVulnerability.id == vuln_id)
        )
    ).scalar_one()
    assert row.adjusted_severity == "low"
    assert float(row.adjusted_cvss_score) == 2.1
    assert row.resolution_status == "false_positive"
    assert row.resolved_by == "ai"
    assert row.resolved_at is not None
    assert row.adjustment_rationale == "feature disabled at compile time"
    assert row.resolution_justification == "feature disabled at compile time"
    # NVD originals untouched
    assert row.severity == "critical"
    assert float(row.cvss_score) == 9.8
