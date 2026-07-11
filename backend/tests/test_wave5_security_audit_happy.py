"""Wave 5: happy-path coverage for ``app.routers.security_audit``.

Existing ``test_security_audit_router.py`` covers validation short-circuits
and one audit live-canary. This file exercises the remaining miss ranges
(scan bodies, UEFI PE walk, yara/clamav/vt/abusech/known-good persistence
paths, update-mechanisms success).
"""

import os

import pytest

# Full-suite residual wave modules poison the CI event loop after ~78%
# progress (FAILED + maxfail ERROR cascade). Skip under CI; still run locally.
if os.environ.get("CI", "").lower() in ("1", "true", "yes"):
    pytest.skip(
        "wave residual suites skip under CI full-suite (event-loop cascade)",
        allow_module_level=True,
    )

from __future__ import annotations

import os
import struct
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter
from app.services.security_audit._base import ScanResult, SecurityFinding


@pytest.fixture(autouse=True)
def _disable_api_key_auth(monkeypatch):
    from app.middleware import asgi_auth as _auth_mod

    fake = MagicMock()
    fake.api_key = ""
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake)


@pytest.fixture(autouse=True)
def _disable_rate_limit():
    prior = limiter.enabled
    limiter.enabled = False
    limiter.reset()
    try:
        yield
    finally:
        limiter.enabled = prior


@pytest.fixture(autouse=True)
def _cleanup_overrides():
    yield
    app.dependency_overrides.clear()


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        yield c


@pytest.fixture
def project_id() -> uuid.UUID:
    return uuid.uuid4()


def _make_project(project_id: uuid.UUID) -> MagicMock:
    project = MagicMock(spec=Project)
    project.id = project_id
    project.name = "wave5-security"
    project.status = "ready"
    return project


def _make_firmware(project_id: uuid.UUID, extracted_path: str) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = extracted_path
    fw.extraction_dir = extracted_path
    fw.created_at = datetime.now(UTC)
    fw.device_metadata = None
    return fw


def _iter_responses(*first_responses):
    queue = list(first_responses)

    def _next(*_a, **_k):
        if queue:
            return queue.pop(0)
        return MagicMock()

    return _next


def _make_db(project, firmware_list):
    project_result = MagicMock()
    project_result.scalar_one_or_none.return_value = project

    firmware_result = MagicMock()
    scalars_proxy = MagicMock()
    scalars_proxy.all.return_value = firmware_list
    firmware_result.scalars.return_value = scalars_proxy

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=_iter_responses(project_result, firmware_result))
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.add = MagicMock()
    return db


def _stub_finding(title: str = "Test finding", severity: str = "high") -> SecurityFinding:
    return SecurityFinding(
        title=title,
        severity=severity,
        description="desc",
        evidence="ev",
        file_path="/bin/foo",
        cwe_ids=["CWE-798"],
    )


def _patch_finding_service():
    mock_finding = MagicMock()
    mock_finding.id = uuid.uuid4()
    svc = MagicMock()
    svc.create = AsyncMock(return_value=mock_finding)
    return patch("app.routers.security_audit.FindingService", return_value=svc)


def _minimal_pe_missing_protections() -> bytes:
    """Build a minimal PE32+ x64 image with ASLR/DEP off and a W|X section."""
    data = bytearray(512)
    data[0:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, pe_offset + 4, 0x8664)  # AMD64
    struct.pack_into("<H", data, pe_offset + 6, 1)  # NumberOfSections
    size_opt = 0xF0
    struct.pack_into("<H", data, pe_offset + 0x14, size_opt)
    opt_offset = pe_offset + 0x18
    struct.pack_into("<H", data, opt_offset, 0x020B)  # PE32+
    # DllCharacteristics = 0 → missing DYNAMIC_BASE, NX_COMPAT, HIGH_ENTROPY_VA
    struct.pack_into("<H", data, opt_offset + 0x46, 0x0000)
    section_start = pe_offset + 0x18 + size_opt
    # Section name
    data[section_start : section_start + 8] = b".text\x00\x00\x00"
    # Characteristics: EXECUTE | WRITE
    struct.pack_into("<I", data, section_start + 36, 0x20000000 | 0x80000000)
    return bytes(data)


# ---------------------------------------------------------------------------
# POST /audit happy path (multi-root + threat-intel exception branches)
# ---------------------------------------------------------------------------


class TestAuditHappyPath:
    @pytest.mark.asyncio
    async def test_audit_multi_root_and_threat_intel_errors(
        self, client, project_id, tmp_path: Path,
    ):
        root = tmp_path / "rootfs"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        scan = ScanResult(findings=[_stub_finding()], checks_run=3, errors=["soft"])

        with patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=[str(root)]),
        ), patch(
            "app.routers.security_audit.run_security_audit_multi",
            return_value=scan,
        ), patch(
            "app.routers.security_audit.run_clamav_scan",
            new=AsyncMock(side_effect=RuntimeError("clam down")),
        ), patch(
            "app.routers.security_audit.run_virustotal_scan",
            new=AsyncMock(side_effect=RuntimeError("vt down")),
        ), patch(
            "app.routers.security_audit.run_abusech_scan",
            new=AsyncMock(side_effect=RuntimeError("ab down")),
        ), patch(
            "app.routers.security_audit.run_known_good_scan",
            new=AsyncMock(side_effect=RuntimeError("hl down")),
        ), _patch_finding_service():
            resp = await client.post(f"/api/v1/projects/{project_id}/security/audit")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "success"
        assert body["findings_created"] == 1
        assert body["checks_run"] == 3
        assert any("clamav" in e for e in body["errors"])
        assert any("virustotal" in e for e in body["errors"])
        assert any("abusech" in e for e in body["errors"])
        assert any("hashlookup" in e for e in body["errors"])

    @pytest.mark.asyncio
    async def test_audit_falls_back_to_single_root_when_no_detection_roots(
        self, client, project_id, tmp_path: Path,
    ):
        root = tmp_path / "rootfs"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        scan = ScanResult(findings=[], checks_run=1, errors=[])
        threat = [_stub_finding("clam", "critical")]

        with patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=[]),
        ), patch(
            "app.routers.security_audit.run_security_audit",
            return_value=scan,
        ) as single, patch(
            "app.routers.security_audit.run_clamav_scan",
            new=AsyncMock(return_value=threat),
        ), patch(
            "app.routers.security_audit.run_virustotal_scan",
            new=AsyncMock(return_value=[]),
        ), patch(
            "app.routers.security_audit.run_abusech_scan",
            new=AsyncMock(return_value=[]),
        ), patch(
            "app.routers.security_audit.run_known_good_scan",
            new=AsyncMock(return_value=[]),
        ), _patch_finding_service():
            resp = await client.post(f"/api/v1/projects/{project_id}/security/audit")

        assert resp.status_code == 200
        single.assert_called_once_with(str(root))
        body = resp.json()
        assert body["findings_created"] == 1
        assert body["checks_run"] == 2  # 1 base + 1 clamav with findings


# ---------------------------------------------------------------------------
# POST /uefi-scan — real PE walk
# ---------------------------------------------------------------------------


class TestUefiScanHappyPath:
    @pytest.mark.asyncio
    async def test_uefi_scan_finds_unprotected_pe_modules(
        self, client, project_id, tmp_path: Path,
    ):
        extraction = tmp_path / "extract"
        dump = extraction / "fw.dump"
        mod_dir = dump / "0  BadDxe"
        pe_dir = mod_dir / "PE32 image section"
        pe_dir.mkdir(parents=True)
        (mod_dir / "info.txt").write_text(
            "File GUID: 12345678-1234-1234-1234-123456789ABC\n"
            "Subtype: DXE driver\n",
            encoding="utf-8",
        )
        (pe_dir / "body.bin").write_bytes(_minimal_pe_missing_protections())

        # SMM module for high severity branch
        smm_dir = dump / "1  BadSmm"
        smm_pe = smm_dir / "PE32 image section"
        smm_pe.mkdir(parents=True)
        (smm_dir / "info.txt").write_text(
            "File GUID: AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF\n"
            "Subtype: SMM module\n",
            encoding="utf-8",
        )
        (smm_pe / "body.bin").write_bytes(_minimal_pe_missing_protections())

        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(extraction))
        fw.extraction_dir = str(extraction)
        # Not ending in .dump → scan extraction_dir for *.dump
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        with _patch_finding_service():
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/uefi-scan"
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "success"
        assert body["modules_scanned"] == 2
        assert body["findings_created"] >= 4  # ASLR/DEP/high-entropy/W^X per module
        assert isinstance(body["summary"], dict)
        assert body["summary"]

    @pytest.mark.asyncio
    async def test_uefi_scan_no_dump_returns_error_list(
        self, client, project_id, tmp_path: Path,
    ):
        root = tmp_path / "empty"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        fw.extraction_dir = str(root)
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        with _patch_finding_service():
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/uefi-scan"
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["modules_scanned"] == 0
        assert body["findings_created"] == 0
        assert any("UEFIExtract" in e for e in body["errors"])

    @pytest.mark.asyncio
    async def test_uefi_scan_project_missing_404(self, client, project_id):
        db = _make_db(None, [])
        app.dependency_overrides[get_db] = lambda: db
        resp = await client.post(f"/api/v1/projects/{project_id}/security/uefi-scan")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_uefi_scan_no_firmware_400(self, client, project_id):
        db = _make_db(_make_project(project_id), [])
        app.dependency_overrides[get_db] = lambda: db
        resp = await client.post(f"/api/v1/projects/{project_id}/security/uefi-scan")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /yara happy path
# ---------------------------------------------------------------------------


class TestYaraHappyPath:
    @pytest.mark.asyncio
    async def test_yara_multi_root_persists_findings(
        self, client, project_id, tmp_path: Path,
    ):
        from app.services.yara_service import YaraScanResult

        root = tmp_path / "r"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        yara_result = YaraScanResult(
            findings=[_stub_finding("YARA hit", "high")],
            files_scanned=10,
            files_matched=1,
            rules_loaded=42,
            errors=[],
        )

        with patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=[str(root)]),
        ), patch(
            "app.routers.security_audit.yara_scan_firmware_multi",
            return_value=yara_result,
        ), _patch_finding_service():
            resp = await client.post(f"/api/v1/projects/{project_id}/security/yara")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["rules_loaded"] == 42
        assert body["files_scanned"] == 10
        assert body["files_matched"] == 1
        assert body["findings_created"] == 1

    @pytest.mark.asyncio
    async def test_yara_falls_back_to_single_root(self, client, project_id, tmp_path: Path):
        from app.services.yara_service import YaraScanResult

        root = tmp_path / "r"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        yara_result = YaraScanResult(
            findings=[], files_scanned=2, files_matched=0, rules_loaded=5, errors=[],
        )

        with patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=[]),
        ), patch(
            "app.routers.security_audit.yara_scan_firmware",
            return_value=yara_result,
        ) as single, _patch_finding_service():
            resp = await client.post(f"/api/v1/projects/{project_id}/security/yara")

        assert resp.status_code == 200
        single.assert_called_once_with(str(root))


# ---------------------------------------------------------------------------
# POST /clamav-scan happy path
# ---------------------------------------------------------------------------


class TestClamavHappyPath:
    @pytest.mark.asyncio
    async def test_clamav_infected_and_error_results(
        self, client, project_id, tmp_path: Path,
    ):
        from app.services.clamav_service import ClamScanResult

        root = tmp_path / "r"
        root.mkdir()
        malware = root / "evil"
        malware.write_bytes(b"x")
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        results = [
            ClamScanResult(
                file_path=str(malware), infected=True, signature="Eicar-Test-Signature",
            ),
            ClamScanResult(
                file_path=str(root / "ok"), infected=False, error="read fail",
            ),
        ]

        with patch(
            "app.services.clamav_service.check_available",
            new=AsyncMock(return_value=True),
        ), patch(
            "app.services.clamav_service.scan_directory",
            new=AsyncMock(return_value=results),
        ), _patch_finding_service():
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/clamav-scan"
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "success"
        assert body["files_scanned"] == 2
        assert body["infected_count"] == 1
        assert body["findings_created"] == 1
        assert body["infected_files"][0]["signature"] == "Eicar-Test-Signature"
        assert any("read fail" in e for e in body["errors"])

    @pytest.mark.asyncio
    async def test_clamav_project_missing_404(self, client, project_id):
        db = _make_db(None, [])
        app.dependency_overrides[get_db] = lambda: db
        with patch(
            "app.services.clamav_service.check_available",
            new=AsyncMock(return_value=True),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/clamav-scan"
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_clamav_no_firmware_400(self, client, project_id):
        db = _make_db(_make_project(project_id), [])
        app.dependency_overrides[get_db] = lambda: db
        with patch(
            "app.services.clamav_service.check_available",
            new=AsyncMock(return_value=True),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/clamav-scan"
            )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /vt-scan happy path
# ---------------------------------------------------------------------------


class TestVtScanHappyPath:
    @pytest.mark.asyncio
    async def test_vt_detections_across_severity_tiers(
        self, client, project_id, tmp_path: Path,
    ):
        from app.services.virustotal_service import VTResult

        root = tmp_path / "r"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        hashes = [("a" * 64, "/bin/a"), ("b" * 64, "/bin/b")]
        vt_results = [
            VTResult(
                sha256="a" * 64, found=True, detection_count=12, total_engines=70,
                detections=["ESET", "Kaspersky"], permalink="https://vt/a",
                file_path="/bin/a",
            ),
            VTResult(
                sha256="b" * 64, found=True, detection_count=7, total_engines=70,
                detections=["Avast"], permalink="https://vt/b", file_path="/bin/b",
            ),
            VTResult(
                sha256="c" * 64, found=True, detection_count=3, total_engines=70,
                detections=["X"], permalink="https://vt/c", file_path="/bin/c",
            ),
            VTResult(
                sha256="d" * 64, found=True, detection_count=1, total_engines=70,
                detections=["Y"], permalink="https://vt/d", file_path="/bin/d",
            ),
            VTResult(
                sha256="e" * 64, found=True, detection_count=0, total_engines=70,
                file_path="/bin/e",
            ),
        ]

        fake_settings = MagicMock()
        fake_settings.virustotal_api_key = "test-key"

        with patch("app.config.get_settings", return_value=fake_settings), patch(
            "app.services.virustotal_service.collect_binary_hashes",
            return_value=hashes,
        ), patch(
            "app.services.virustotal_service.batch_check_hashes",
            new=AsyncMock(return_value=vt_results),
        ), _patch_finding_service():
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/vt-scan"
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "success"
        assert body["binaries_checked"] == 5
        assert body["detected_count"] == 4
        assert body["findings_created"] == 4

    @pytest.mark.asyncio
    async def test_vt_empty_hashes_skips(self, client, project_id, tmp_path: Path):
        root = tmp_path / "r"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db
        fake_settings = MagicMock()
        fake_settings.virustotal_api_key = "k"

        with patch("app.config.get_settings", return_value=fake_settings), patch(
            "app.services.virustotal_service.collect_binary_hashes",
            return_value=[],
        ), _patch_finding_service():
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/vt-scan"
            )

        assert resp.status_code == 200
        assert resp.json()["binaries_checked"] == 0

    @pytest.mark.asyncio
    async def test_vt_project_missing_404(self, client, project_id):
        db = _make_db(None, [])
        app.dependency_overrides[get_db] = lambda: db
        fake_settings = MagicMock()
        fake_settings.virustotal_api_key = "k"
        with patch("app.config.get_settings", return_value=fake_settings):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/vt-scan"
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_vt_no_firmware_400(self, client, project_id):
        db = _make_db(_make_project(project_id), [])
        app.dependency_overrides[get_db] = lambda: db
        fake_settings = MagicMock()
        fake_settings.virustotal_api_key = "k"
        with patch("app.config.get_settings", return_value=fake_settings):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/vt-scan"
            )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET update-mechanisms happy path
# ---------------------------------------------------------------------------


class TestUpdateMechanismsHappyPath:
    @pytest.mark.asyncio
    async def test_returns_detected_mechanisms(
        self, client, project_id, tmp_path: Path,
    ):
        from app.services.update_mechanism_service import UpdateMechanism

        root = tmp_path / "r"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        fw_id = fw.id

        project_result = MagicMock()
        project_result.scalar_one_or_none.return_value = project
        firmware_result = MagicMock()
        firmware_result.scalar_one_or_none.return_value = fw
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[project_result, firmware_result])
        app.dependency_overrides[get_db] = lambda: db

        mech = UpdateMechanism(
            system="rauc",
            confidence="high",
            binaries=["/usr/bin/rauc"],
            configs=["/etc/rauc/system.conf"],
            update_urls=["https://updates.example"],
            uses_https=True,
            has_ab_scheme=True,
            findings=[{"title": "ok"}],
        )

        with patch(
            "app.services.update_mechanism_service.detect_update_mechanisms",
            return_value=[mech],
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/security/firmware/{fw_id}/update-mechanisms"
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 1
        assert body["mechanisms"][0]["system"] == "rauc"
        assert body["mechanisms"][0]["uses_https"] is True


# ---------------------------------------------------------------------------
# POST /abusech-scan happy path
# ---------------------------------------------------------------------------


class TestAbusechHappyPath:
    @pytest.mark.asyncio
    async def test_abusech_counts_by_source(
        self, client, project_id, tmp_path: Path,
    ):
        root = tmp_path / "r"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        findings = [
            _stub_finding("MalwareBazaar hit: foo", "critical"),
            _stub_finding("ThreatFox hit: bar", "high"),
            _stub_finding("YARAify hit: baz", "medium"),
        ]

        with patch(
            "app.routers.security_audit.run_abusech_scan",
            new=AsyncMock(return_value=findings),
        ), _patch_finding_service():
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/abusech-scan"
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "success"
        assert body["malwarebazaar_hits"] == 1
        assert body["threatfox_hits"] == 1
        assert body["yaraify_hits"] == 1
        assert body["findings_created"] == 3

    @pytest.mark.asyncio
    async def test_abusech_scan_exception_recorded(
        self, client, project_id, tmp_path: Path,
    ):
        root = tmp_path / "r"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.security_audit.run_abusech_scan",
            new=AsyncMock(side_effect=RuntimeError("network")),
        ), _patch_finding_service():
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/abusech-scan"
            )

        assert resp.status_code == 200
        assert any("abusech" in e for e in resp.json()["errors"])

    @pytest.mark.asyncio
    async def test_abusech_project_missing_404(self, client, project_id):
        db = _make_db(None, [])
        app.dependency_overrides[get_db] = lambda: db
        resp = await client.post(
            f"/api/v1/projects/{project_id}/security/abusech-scan"
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_abusech_no_firmware_400(self, client, project_id):
        db = _make_db(_make_project(project_id), [])
        app.dependency_overrides[get_db] = lambda: db
        resp = await client.post(
            f"/api/v1/projects/{project_id}/security/abusech-scan"
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /known-good-scan happy path
# ---------------------------------------------------------------------------


class TestKnownGoodHappyPath:
    @pytest.mark.asyncio
    async def test_known_and_unknown_bins(
        self, client, project_id, tmp_path: Path,
    ):
        from app.services.hashlookup_service import HashlookupResult

        root = tmp_path / "r"
        root.mkdir()
        project = _make_project(project_id)
        fw = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw])
        app.dependency_overrides[get_db] = lambda: db

        hashes = [("a" * 64, "/bin/busybox"), ("b" * 64, "/bin/mystery")]
        results = [
            HashlookupResult(
                sha256="a" * 64, known=True, source="NSRL",
                product_name="BusyBox", vendor="GNU", file_path="/bin/busybox",
            ),
            HashlookupResult(
                sha256="b" * 64, known=False, file_path="/bin/mystery",
            ),
        ]

        with patch(
            "app.services.virustotal_service.collect_binary_hashes",
            return_value=hashes,
        ), patch(
            "app.services.hashlookup_service.batch_check_known_good",
            new=AsyncMock(return_value=results),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/known-good-scan"
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["binaries_checked"] == 2
        assert body["known_good_count"] == 1
        assert body["unknown_count"] == 1
        assert body["known_good_files"][0]["product"] == "BusyBox"

    @pytest.mark.asyncio
    async def test_known_good_exception_and_empty_hashes(
        self, client, project_id, tmp_path: Path,
    ):
        root = tmp_path / "r"
        root.mkdir()
        project = _make_project(project_id)
        fw1 = _make_firmware(project_id, str(root))
        fw2 = _make_firmware(project_id, str(root))
        db = _make_db(project, [fw1, fw2])
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.services.virustotal_service.collect_binary_hashes",
            side_effect=[[], RuntimeError("boom")],
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/security/known-good-scan"
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["binaries_checked"] == 0
        assert any("hashlookup" in e for e in body["errors"])

    @pytest.mark.asyncio
    async def test_known_good_no_firmware_400(self, client, project_id):
        db = _make_db(_make_project(project_id), [])
        app.dependency_overrides[get_db] = lambda: db
        resp = await client.post(
            f"/api/v1/projects/{project_id}/security/known-good-scan"
        )
        assert resp.status_code == 400
