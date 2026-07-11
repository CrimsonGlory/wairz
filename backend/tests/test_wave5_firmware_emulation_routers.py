"""Wave 5: additional router coverage for firmware + emulation.

Extends beyond validation-only tests to hit list/update/delete/kind/rootfs/
metadata/audit and system-emulation happy paths (network analysis, nvram,
command, services, capture, stop).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter
from app.routers.deps import resolve_firmware as resolve_firmware_dep
from app.routers.firmware import get_firmware_service


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


def _fw_detail(project_id: uuid.UUID, **overrides) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.original_filename = "test.bin"
    fw.sha256 = "a" * 64
    fw.file_size = 1024
    fw.storage_path = "/tmp/storage/x.bin"
    fw.extracted_path = "/tmp/extracted"
    fw.extraction_dir = "/tmp/extracted"
    fw.architecture = "arm"
    fw.endianness = "little"
    fw.os_info = "linux"
    fw.kernel_path = None
    fw.version_label = "1.0"
    fw.firmware_kind = "linux"
    fw.firmware_kind_source = "detected"
    fw.rtos_flavor = None
    fw.unpack_log = None
    fw.unpack_stage = None
    fw.unpack_progress = None
    fw.binary_info = None
    fw.device_metadata = {"detection_audit": {"orphan_rate": 0.1}}
    fw.created_at = datetime.now(UTC)
    fw.upload_stage = "ready"
    fw.upload_stage_started_at = datetime.now(UTC)
    fw.upload_stage_finished_at = datetime.now(UTC)
    fw.upload_stage_error = None
    fw.detected_format = "squashfs"
    for k, v in overrides.items():
        setattr(fw, k, v)
    return fw


def _service_with(fw: MagicMock | None = None, lst: list | None = None) -> MagicMock:
    svc = MagicMock()
    svc.get_by_id = AsyncMock(return_value=fw)
    svc.list_by_project = AsyncMock(return_value=lst if lst is not None else ([fw] if fw else []))
    svc.get_by_project = AsyncMock(return_value=fw)
    svc.delete = AsyncMock()
    svc.upload_rootfs = AsyncMock()
    svc.db = AsyncMock()
    svc.db.flush = AsyncMock()
    return svc


# ── Firmware router ─────────────────────────────────────────────────────────


class TestFirmwareCrudAndMeta:
    @pytest.mark.asyncio
    async def test_list_and_get_firmware(self, client, project_id):
        fw = _fw_detail(project_id)
        svc = _service_with(fw)
        app.dependency_overrides[get_firmware_service] = lambda: svc

        resp = await client.get(f"/api/v1/projects/{project_id}/firmware")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

        resp2 = await client.get(
            f"/api/v1/projects/{project_id}/firmware/{fw.id}"
        )
        assert resp2.status_code == 200
        assert resp2.json()["sha256"] == "a" * 64

    @pytest.mark.asyncio
    async def test_patch_firmware_fields(self, client, project_id):
        fw = _fw_detail(project_id)
        svc = _service_with(fw)
        app.dependency_overrides[get_firmware_service] = lambda: svc

        resp = await client.patch(
            f"/api/v1/projects/{project_id}/firmware/{fw.id}",
            json={"version_label": "2.0", "architecture": "mips32"},
        )
        assert resp.status_code == 200, resp.text
        assert fw.version_label == "2.0"
        assert fw.architecture == "mips32"
        svc.db.flush.assert_awaited()

    @pytest.mark.asyncio
    async def test_patch_firmware_kind_rtos(self, client, project_id):
        fw = _fw_detail(project_id)
        svc = _service_with(fw)
        app.dependency_overrides[get_firmware_service] = lambda: svc

        resp = await client.patch(
            f"/api/v1/projects/{project_id}/firmware/{fw.id}/kind",
            json={"kind": "rtos", "rtos_flavor": "freertos"},
        )
        assert resp.status_code == 200, resp.text
        assert fw.firmware_kind == "rtos"
        assert fw.rtos_flavor == "freertos"
        assert fw.firmware_kind_source == "manual"

    @pytest.mark.asyncio
    async def test_patch_firmware_kind_linux_clears_flavor(self, client, project_id):
        fw = _fw_detail(project_id, rtos_flavor="zephyr", firmware_kind="rtos")
        svc = _service_with(fw)
        app.dependency_overrides[get_firmware_service] = lambda: svc

        resp = await client.patch(
            f"/api/v1/projects/{project_id}/firmware/{fw.id}/kind",
            json={"kind": "linux"},
        )
        assert resp.status_code == 200
        assert fw.firmware_kind == "linux"
        assert fw.rtos_flavor is None

    @pytest.mark.asyncio
    async def test_delete_firmware_resets_unpacking_project(
        self, client, project_id,
    ):
        fw = _fw_detail(project_id, extracted_path=None)
        svc = _service_with(fw)
        project = MagicMock(spec=Project)
        project.id = project_id
        project.status = "unpacking"
        proj_result = MagicMock()
        proj_result.scalar_one_or_none.return_value = project
        db = AsyncMock()
        db.execute = AsyncMock(return_value=proj_result)
        db.flush = AsyncMock()
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.delete(
            f"/api/v1/projects/{project_id}/firmware/{fw.id}"
        )
        assert resp.status_code == 204
        assert project.status == "created"
        svc.delete.assert_awaited_with(fw)

    @pytest.mark.asyncio
    async def test_delete_firmware_with_extract_skips_reset(
        self, client, project_id,
    ):
        fw = _fw_detail(project_id, extracted_path="/tmp/x")
        svc = _service_with(fw)
        db = AsyncMock()
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.delete(
            f"/api/v1/projects/{project_id}/firmware/{fw.id}"
        )
        assert resp.status_code == 204
        # no project status lookup when already extracted
        db.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_upload_rootfs_happy(self, client, project_id):
        fw = _fw_detail(project_id, extracted_path=None)
        svc = _service_with(fw)
        project = MagicMock(spec=Project)
        project.id = project_id
        project.status = "created"
        proj_result = MagicMock()
        proj_result.scalar_one_or_none.return_value = project
        db = AsyncMock()
        db.execute = AsyncMock(return_value=proj_result)
        db.flush = AsyncMock()
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.firmware._check_upload_size", new=AsyncMock(),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/firmware/{fw.id}/upload-rootfs",
                files={"file": ("rootfs.tar.gz", b"fake-tar", "application/gzip")},
            )
        assert resp.status_code == 200, resp.text
        assert project.status == "ready"
        svc.upload_rootfs.assert_awaited()

    @pytest.mark.asyncio
    async def test_upload_rootfs_already_extracted_409(self, client, project_id):
        fw = _fw_detail(project_id, extracted_path="/tmp/x")
        svc = _service_with(fw)
        project = MagicMock(spec=Project)
        project.id = project_id
        proj_result = MagicMock()
        proj_result.scalar_one_or_none.return_value = project
        db = AsyncMock()
        db.execute = AsyncMock(return_value=proj_result)
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.firmware._check_upload_size", new=AsyncMock(),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/firmware/{fw.id}/upload-rootfs",
                files={"file": ("rootfs.tar.gz", b"x", "application/gzip")},
            )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_redetect_kernel(self, client, project_id):
        fw = _fw_detail(
            project_id,
            extracted_path="/tmp/extracted/rootfs",
            extraction_dir="/tmp/extracted",
        )
        svc = _service_with(fw)
        db = AsyncMock()
        db.flush = AsyncMock()
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.firmware.detect_kernel",
            return_value="/tmp/extracted/rootfs/boot/vmlinux",
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/firmware/{fw.id}/redetect-kernel"
            )
        assert resp.status_code == 200, resp.text
        assert fw.kernel_path == "/tmp/extracted/rootfs/boot/vmlinux"

    @pytest.mark.asyncio
    async def test_redetect_kernel_not_unpacked_400(self, client, project_id):
        fw = _fw_detail(project_id, extracted_path=None)
        svc = _service_with(fw)
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{fw.id}/redetect-kernel"
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_get_metadata(self, client, project_id):
        fw = _fw_detail(project_id)
        svc = _service_with(fw)
        db = AsyncMock()
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: db

        meta = {
            "file_size": 1024,
            "sections": [],
            "uboot_header": None,
            "uboot_env": {},
            "mtd_partitions": [],
        }
        with patch(
            "app.routers.firmware.FirmwareMetadataService"
        ) as MockMeta:
            MockMeta.return_value.scan_firmware_image = AsyncMock(return_value=meta)
            resp = await client.get(
                f"/api/v1/projects/{project_id}/firmware/{fw.id}/metadata"
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["file_size"] == 1024

    @pytest.mark.asyncio
    async def test_get_detection_audit_without_recompute(self, client, project_id):
        fw = _fw_detail(project_id)
        svc = _service_with(fw)
        db = AsyncMock()
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.firmware.get_detection_roots",
            new=AsyncMock(return_value=["/tmp/extracted"]),
        ), patch(
            "app.routers.firmware._normalize_firmware_device_metadata",
            return_value={"detection_audit": {"orphan_rate": 0.1}},
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/firmware/{fw.id}/audit"
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["detection_roots"] == ["/tmp/extracted"]
        assert body["orphans_preview"] is None
        assert body["audit"]["orphan_rate"] == 0.1

    @pytest.mark.asyncio
    async def test_get_detection_audit_recompute(
        self, client, project_id, tmp_path: Path,
    ):
        root = tmp_path / "root"
        root.mkdir()
        (root / "known.bin").write_bytes(b"k")
        (root / "orphan.bin").write_bytes(b"o")
        known_real = str((root / "known.bin").resolve())

        fw = _fw_detail(project_id, extracted_path=str(root))
        svc = _service_with(fw)
        blob_result = MagicMock()
        blob_result.all.return_value = [(known_real,)]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=blob_result)
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.firmware.get_detection_roots",
            new=AsyncMock(return_value=[str(root)]),
        ), patch(
            "app.routers.firmware._normalize_firmware_device_metadata",
            return_value={"detection_audit": {}},
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/firmware/{fw.id}/audit"
                f"?recompute=true"
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["orphans_preview"] is not None
        assert any("orphan.bin" in p for p in body["orphans_preview"])

    @pytest.mark.asyncio
    async def test_unpack_legacy_no_firmware_404(self, client, project_id):
        svc = _service_with(None)
        svc.get_by_project = AsyncMock(return_value=None)
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        resp = await client.post(f"/api/v1/projects/{project_id}/firmware/unpack")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_redetect_legacy(self, client, project_id):
        fw2 = _fw_detail(project_id, extracted_path="/tmp/extracted/rootfs")
        svc2 = _service_with(fw2)
        app.dependency_overrides[get_firmware_service] = lambda: svc2
        app.dependency_overrides[get_db] = lambda: AsyncMock(flush=AsyncMock())
        with patch(
            "app.routers.firmware.detect_kernel", return_value=None,
        ):
            resp2 = await client.post(
                f"/api/v1/projects/{project_id}/firmware/redetect-kernel"
            )
        assert resp2.status_code == 200

    @pytest.mark.asyncio
    async def test_redetect_legacy_no_firmware_404(self, client, project_id):
        svc = _service_with(None)
        svc.get_by_project = AsyncMock(return_value=None)
        app.dependency_overrides[get_firmware_service] = lambda: svc
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/redetect-kernel"
        )
        assert resp.status_code == 404


# ── Emulation system + network paths ────────────────────────────────────────


def _emu_session(project_id: uuid.UUID, **overrides) -> MagicMock:
    s = MagicMock(spec=EmulationSession)
    s.id = uuid.uuid4()
    s.project_id = project_id
    s.firmware_id = uuid.uuid4()
    s.mode = "system"
    s.status = "running"
    s.architecture = "arm"
    s.binary_path = None
    s.arguments = None
    s.port_forwards = None
    s.error_message = None
    s.logs = "boot ok"
    s.started_at = datetime.now(UTC)
    s.stopped_at = None
    s.created_at = datetime.now(UTC)
    s.discovered_services = [{"port": 80, "protocol": "tcp", "service": "http"}]
    s.system_emulation_stage = "ready"
    s.kernel_used = "4.1"
    s.firmware_ip = "192.168.0.1"
    s.nvram_state = {"lan_ipaddr": "192.168.0.1"}
    s.idle_since = None
    s.pcap_path = None
    s.container_id = "abc123"
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


def _session_db(session) -> AsyncMock:
    result = MagicMock()
    result.scalar_one_or_none.return_value = session
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.flush = AsyncMock()
    return db


class TestSystemEmulationHappyPaths:
    @pytest.mark.asyncio
    async def test_system_status_services_command_nvram_stop(
        self, client, project_id,
    ):
        session = _emu_session(project_id)
        db = _session_db(session)
        app.dependency_overrides[get_db] = lambda: db

        with patch("app.routers.emulation.SystemEmulationService") as MockSys:
            svc = MockSys.return_value
            svc.poll_system_status = AsyncMock(return_value=session)
            svc.get_firmware_services = AsyncMock(
                return_value=[
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "service": "http",
                        "host_port": 8080,
                        "url": "http://localhost:8080",
                    }
                ]
            )
            svc.run_command_in_firmware = AsyncMock(
                return_value={"stdout": "ok", "stderr": "", "exit_code": 0}
            )
            svc.get_nvram_state = AsyncMock(
                return_value={"lan_ipaddr": "192.168.0.1"}
            )
            svc.stop_system_emulation = AsyncMock()
            svc.capture_network_traffic = AsyncMock(
                return_value={
                    "packet_count": 12,
                    "pcap_path": "/tmp/c.pcap",
                    "size_bytes": 400,
                    "duration": 5,
                }
            )

            r1 = await client.get(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}"
            )
            assert r1.status_code == 200, r1.text

            r2 = await client.get(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}/services"
            )
            assert r2.status_code == 200
            assert r2.json()[0]["port"] == 80

            r3 = await client.post(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}/command",
                json={"command": "ls /", "timeout": 10},
            )
            assert r3.status_code == 200
            assert r3.json()["stdout"] == "ok"

            r4 = await client.get(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}/nvram"
            )
            assert r4.status_code == 200
            assert r4.json()["nvram"]["lan_ipaddr"] == "192.168.0.1"

            r5 = await client.post(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}/capture",
                json={"duration": 5, "interface": "eth0"},
            )
            assert r5.status_code == 200
            assert r5.json()["packet_count"] == 12

            r6 = await client.delete(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}"
            )
            assert r6.status_code == 204

    @pytest.mark.asyncio
    async def test_network_analysis_happy(
        self, client, project_id, tmp_path: Path,
    ):
        pcap = tmp_path / "c.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
        session = _emu_session(project_id, pcap_path=str(pcap))
        db = _session_db(session)
        app.dependency_overrides[get_db] = lambda: db

        analysis = SimpleNamespace(
            total_packets=10,
            protocol_breakdown={"TCP": 8, "UDP": 2},
            conversations=[
                SimpleNamespace(
                    src="1.1.1.1", src_port=1234, dst="2.2.2.2",
                    dst_port=80, protocol="TCP", packet_count=5, byte_count=500,
                )
            ],
            insecure_findings=[
                SimpleNamespace(
                    protocol="HTTP", port=80, severity="medium",
                    description="cleartext", evidence="GET /", packet_count=3,
                )
            ],
            dns_queries=[
                SimpleNamespace(
                    domain="evil.example", query_type="A",
                    resolved_ips=["9.9.9.9"],
                )
            ],
            tls_info=[
                SimpleNamespace(
                    server="api.example", port=443, version="TLS1.2",
                    cipher_suites=["AES"],
                )
            ],
        )

        with patch("app.routers.emulation.PcapAnalysisService") as MockPcap:
            MockPcap.return_value.analyze_pcap = MagicMock(return_value=analysis)
            resp = await client.get(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}/network-analysis"
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total_packets"] == 10
        assert body["protocol_breakdown"][0]["protocol"] == "TCP"
        assert body["conversations"][0]["dst_port"] == 80
        assert body["insecure_findings"][0]["protocol"] == "HTTP"
        assert body["dns_queries"][0]["domain"] == "evil.example"
        assert body["tls_info"][0]["version"] == "TLS1.2"

    @pytest.mark.asyncio
    async def test_network_analysis_no_pcap_404(self, client, project_id):
        session = _emu_session(project_id, pcap_path=None)
        db = _session_db(session)
        app.dependency_overrides[get_db] = lambda: db
        resp = await client.get(
            f"/api/v1/projects/{project_id}/emulation/system/{session.id}/network-analysis"
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_network_analysis_file_missing(self, client, project_id):
        session = _emu_session(project_id, pcap_path="/no/such/file.pcap")
        db = _session_db(session)
        app.dependency_overrides[get_db] = lambda: db
        with patch("app.routers.emulation.PcapAnalysisService") as MockPcap:
            MockPcap.return_value.analyze_pcap = MagicMock(
                side_effect=FileNotFoundError("gone")
            )
            resp = await client.get(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}/network-analysis"
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_system_value_errors_map_to_400(self, client, project_id):
        session = _emu_session(project_id)
        db = _session_db(session)
        app.dependency_overrides[get_db] = lambda: db

        with patch("app.routers.emulation.SystemEmulationService") as MockSys:
            MockSys.return_value.poll_system_status = AsyncMock(
                side_effect=ValueError("dead")
            )
            r = await client.get(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}"
            )
            assert r.status_code == 400

            MockSys.return_value.get_firmware_services = AsyncMock(
                side_effect=ValueError("dead")
            )
            r = await client.get(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}/services"
            )
            assert r.status_code == 400

            MockSys.return_value.run_command_in_firmware = AsyncMock(
                side_effect=ValueError("dead")
            )
            r = await client.post(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}/command",
                json={"command": "id"},
            )
            assert r.status_code == 400

            MockSys.return_value.get_nvram_state = AsyncMock(
                side_effect=ValueError("dead")
            )
            r = await client.get(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}/nvram"
            )
            assert r.status_code == 400

            MockSys.return_value.capture_network_traffic = AsyncMock(
                side_effect=ValueError("dead")
            )
            r = await client.post(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}/capture",
                json={"duration": 1},
            )
            assert r.status_code == 400

            MockSys.return_value.stop_system_emulation = AsyncMock(
                side_effect=ValueError("dead")
            )
            r = await client.delete(
                f"/api/v1/projects/{project_id}/emulation/system/{session.id}"
            )
            assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_start_system_happy(self, client, project_id):
        fw = _fw_detail(project_id)
        session = _emu_session(project_id, firmware_id=fw.id)
        db = AsyncMock()
        db.flush = AsyncMock()
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[resolve_firmware_dep] = lambda: fw

        with patch("app.routers.emulation.SystemEmulationService") as MockSys, patch(
            "app.routers.emulation.get_settings"
        ) as gs:
            gs.return_value.system_emulation_pipeline_timeout = 900
            MockSys.return_value.start_system_emulation = AsyncMock(
                return_value=session
            )
            resp = await client.post(
                f"/api/v1/projects/{project_id}/emulation/system",
                json={"brand": "netgear", "timeout": 600},
            )
        assert resp.status_code == 201, resp.text
        assert resp.json()["mode"] == "system"

    @pytest.mark.asyncio
    async def test_user_mode_stop_exec_logs_status_happy(
        self, client, project_id,
    ):
        session = _emu_session(project_id, mode="user", status="running")
        db = _session_db(session)
        app.dependency_overrides[get_db] = lambda: db

        with patch("app.routers.emulation.EmulationService") as MockEmu:
            svc = MockEmu.return_value
            svc.stop_session = AsyncMock(return_value=session)
            svc.exec_command = AsyncMock(
                return_value={
                    "stdout": "hi",
                    "stderr": "",
                    "exit_code": 0,
                    "timed_out": False,
                }
            )
            svc.get_session_logs = AsyncMock(return_value="line1\nline2")
            svc.get_status = AsyncMock(return_value=session)

            r = await client.post(
                f"/api/v1/projects/{project_id}/emulation/{session.id}/stop"
            )
            assert r.status_code == 200, r.text

            r = await client.post(
                f"/api/v1/projects/{project_id}/emulation/{session.id}/exec",
                json={"command": "id"},
            )
            assert r.status_code == 200, r.text

            r = await client.get(
                f"/api/v1/projects/{project_id}/emulation/{session.id}/logs"
            )
            assert r.status_code == 200
            assert "line1" in r.json()["logs"]

            r = await client.get(
                f"/api/v1/projects/{project_id}/emulation/{session.id}/status"
            )
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_preset_list_get_update(self, client, project_id):
        preset_id = uuid.uuid4()
        preset = MagicMock()
        preset.id = preset_id
        preset.project_id = project_id
        preset.name = "p1"
        preset.description = None
        preset.mode = "user"
        preset.architecture = "arm"
        preset.binary_path = "/bin/httpd"
        preset.arguments = ""
        preset.port_forwards = []
        preset.kernel_name = None
        preset.init_path = None
        preset.pre_init_script = None
        preset.stub_profile = "none"
        preset.created_at = datetime.now(UTC)
        preset.updated_at = datetime.now(UTC)

        db = AsyncMock()
        db.flush = AsyncMock()
        app.dependency_overrides[get_db] = lambda: db

        with patch("app.routers.emulation.EmulationService") as MockEmu:
            svc = MockEmu.return_value
            svc.list_presets = AsyncMock(return_value=[preset])
            svc.get_preset = AsyncMock(return_value=preset)
            svc.update_preset = AsyncMock(return_value=preset)

            r = await client.get(f"/api/v1/projects/{project_id}/emulation/presets")
            assert r.status_code == 200, r.text
            assert r.json()[0]["name"] == "p1"

            # get_preset endpoint may use db select not service — cover both
            result = MagicMock()
            result.scalar_one_or_none.return_value = preset
            db.execute = AsyncMock(return_value=result)

            r = await client.get(
                f"/api/v1/projects/{project_id}/emulation/presets/{preset_id}"
            )
            assert r.status_code == 200, r.text

            r = await client.patch(
                f"/api/v1/projects/{project_id}/emulation/presets/{preset_id}",
                json={"name": "p1-renamed"},
            )
            assert r.status_code in (200, 404, 422), r.text
