"""Tests for the ExportService — project archive generation.

Tests the JSON serialization helpers, ZIP construction logic, and DB loaders
using mocked sessions. Also tests filesystem helper methods with real files.
"""

import base64
import io
import json
import os
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.export_service import (
    ARCHIVE_VERSION,
    ExportService,
    _dumps,
    _json_serial,
    _write_file_to_zip,
)

# ---------------------------------------------------------------------------
# JSON serialization helpers
# ---------------------------------------------------------------------------

class TestJsonSerial:
    def test_datetime_serialized(self):
        dt = datetime(2024, 6, 15, 12, 30, 0, tzinfo=UTC)
        result = _json_serial(dt)
        assert "2024-06-15" in result
        assert "12:30" in result

    def test_uuid_serialized(self):
        uid = uuid.UUID("12345678-1234-5678-1234-567812345678")
        result = _json_serial(uid)
        assert result == "12345678-1234-5678-1234-567812345678"

    def test_bytes_serialized_as_base64(self):
        data = b"hello world"
        result = _json_serial(data)
        decoded = base64.b64decode(result)
        assert decoded == data

    def test_unsupported_type_raises(self):
        with pytest.raises(TypeError, match="not serializable"):
            _json_serial(set([1, 2, 3]))

    def test_dumps_uses_serial(self):
        obj = {"id": uuid.uuid4(), "ts": datetime.now(UTC)}
        result = _dumps(obj)
        parsed = json.loads(result)
        assert isinstance(parsed["id"], str)
        assert isinstance(parsed["ts"], str)

    def test_dumps_indented(self):
        result = _dumps({"key": "value"})
        assert "\n" in result  # pretty-printed


# ---------------------------------------------------------------------------
# _write_file_to_zip — timestamp clamping
# ---------------------------------------------------------------------------

class TestWriteFileToZip:
    def test_normal_file_added(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("hello")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            _write_file_to_zip(zf, str(f), "test.txt")

        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            assert zf.read("test.txt") == b"hello"

    def test_recent_timestamp_preserved(self, tmp_path: Path):
        """Files with timestamps after 1980 are added normally."""
        f = tmp_path / "recent.txt"
        f.write_text("from 2024")
        # Set modification time to a known date
        import time
        ts = time.mktime((2024, 6, 15, 12, 0, 0, 0, 0, -1))
        os.utime(str(f), (ts, ts))

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            _write_file_to_zip(zf, str(f), "recent.txt")

        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            info = zf.getinfo("recent.txt")
            assert info.date_time[0] == 2024

    def test_binary_content_preserved(self, tmp_path: Path):
        f = tmp_path / "binary.bin"
        data = bytes(range(256))
        f.write_bytes(data)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            _write_file_to_zip(zf, str(f), "binary.bin")

        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            assert zf.read("binary.bin") == data


# ---------------------------------------------------------------------------
# ExportService — internal methods
# ---------------------------------------------------------------------------

def _make_mock_project():
    p = MagicMock()
    p.id = uuid.uuid4()
    p.name = "Test Project"
    p.description = "A test"
    p.status = "active"
    p.created_at = datetime(2024, 1, 1, tzinfo=UTC)
    p.updated_at = datetime(2024, 1, 2, tzinfo=UTC)
    return p


def _make_mock_firmware(project_id, tmp_path=None):
    fw = MagicMock()
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.original_filename = "firmware.bin"
    fw.sha256 = "abc123" * 10 + "abcd"
    fw.file_size = 1024
    fw.architecture = "mips"
    fw.endianness = "big"
    fw.os_info = "Linux 5.4"
    fw.kernel_path = "/vmlinux"
    fw.version_label = "v1.0"
    fw.unpack_log = "Success"
    fw.created_at = datetime(2024, 1, 1, tzinfo=UTC)
    if tmp_path:
        storage = tmp_path / "firmware.bin"
        storage.write_bytes(b"\x7fELF" + b"\x00" * 100)
        fw.storage_path = str(storage)
        extracted = tmp_path / "extracted"
        extracted.mkdir()
        (extracted / "etc").mkdir()
        (extracted / "etc" / "passwd").write_text("root::")
        fw.extracted_path = str(extracted)
    else:
        fw.storage_path = "/nonexistent/firmware.bin"
        fw.extracted_path = None
    return fw


def _make_mock_finding(project_id):
    f = MagicMock()
    f.id = uuid.uuid4()
    f.project_id = project_id
    f.title = "XSS in admin panel"
    f.severity = "high"
    f.description = "Reflected XSS"
    f.evidence = "<script>alert(1)</script>"
    f.file_path = "/usr/bin/httpd"
    f.line_number = 50
    f.cve_ids = ["CVE-2024-0001"]
    f.cwe_ids = ["CWE-79"]
    f.status = "open"
    f.source = "manual"
    f.created_at = datetime(2024, 1, 1, tzinfo=UTC)
    f.updated_at = datetime(2024, 1, 1, tzinfo=UTC)
    return f


class TestExportServiceLoadProject:
    @pytest.mark.asyncio
    async def test_load_project_success(self):
        db = AsyncMock()
        project = _make_mock_project()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = project
        db.execute = AsyncMock(return_value=mock_result)

        svc = ExportService(db)
        result = await svc._load_project(project.id)

        assert result["name"] == "Test Project"
        assert result["id"] == str(project.id)

    @pytest.mark.asyncio
    async def test_load_project_not_found(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)

        svc = ExportService(db)
        with pytest.raises(ValueError, match="not found"):
            await svc._load_project(uuid.uuid4())


class TestExportServiceLoadFindings:
    @pytest.mark.asyncio
    async def test_load_findings_returns_dicts(self):
        db = AsyncMock()
        pid = uuid.uuid4()
        finding = _make_mock_finding(pid)
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [finding]
        db.execute = AsyncMock(return_value=mock_result)

        svc = ExportService(db)
        result = await svc._load_findings(pid)

        assert len(result) == 1
        assert result[0]["title"] == "XSS in admin panel"
        assert result[0]["severity"] == "high"
        assert result[0]["cve_ids"] == ["CVE-2024-0001"]

    @pytest.mark.asyncio
    async def test_load_findings_empty(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=mock_result)

        svc = ExportService(db)
        result = await svc._load_findings(uuid.uuid4())
        assert result == []


class TestExportServiceHelpers:
    def test_firmware_to_dict(self):
        db = AsyncMock()
        svc = ExportService(db)
        fw = _make_mock_firmware(uuid.uuid4())
        result = svc._firmware_to_dict(fw)

        assert result["original_filename"] == "firmware.bin"
        assert result["architecture"] == "mips"
        assert result["endianness"] == "big"
        assert result["version_label"] == "v1.0"

    def test_get_extracted_root_from_extracted_path(self, tmp_path: Path):
        db = AsyncMock()
        svc = ExportService(db)

        extracted = tmp_path / "extracted"
        extracted.mkdir()

        fw = MagicMock()
        fw.extracted_path = str(extracted)
        fw.storage_path = None

        assert svc._get_extracted_root(fw) == str(extracted)

    def test_get_extracted_root_from_storage_path(self, tmp_path: Path):
        db = AsyncMock()
        svc = ExportService(db)

        # Create _extracted dir next to storage path
        fw_dir = tmp_path / "firmware_dir"
        fw_dir.mkdir()
        (fw_dir / "_extracted").mkdir()

        fw = MagicMock()
        fw.extracted_path = None
        fw.storage_path = str(fw_dir / "firmware.bin")

        result = svc._get_extracted_root(fw)
        assert result == str(fw_dir / "_extracted")

    def test_get_extracted_root_none(self):
        db = AsyncMock()
        svc = ExportService(db)

        fw = MagicMock()
        fw.extracted_path = None
        fw.storage_path = None

        assert svc._get_extracted_root(fw) is None

    def test_add_extracted_fs_adds_files(self, tmp_path: Path):
        db = AsyncMock()
        svc = ExportService(db)

        # Build a minimal filesystem
        root = tmp_path / "rootfs"
        root.mkdir()
        (root / "etc").mkdir()
        (root / "etc" / "passwd").write_text("root::")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            svc._add_extracted_fs(zf, str(root), "firmware/extracted")

        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()
            assert any("etc/passwd" in n for n in names)
            assert any("permissions.json" in n for n in names)

    def test_add_extracted_fs_handles_symlinks(self, tmp_path: Path):
        db = AsyncMock()
        svc = ExportService(db)

        root = tmp_path / "rootfs"
        root.mkdir()
        (root / "target.txt").write_text("data")
        (root / "link.txt").symlink_to(str(root / "target.txt"))

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            svc._add_extracted_fs(zf, str(root), "fw/extracted")

        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()
            assert any(".symlink" in n for n in names)


class TestExportServiceFull:
    """Integration-style test for export_project with fully mocked DB."""

    @pytest.mark.asyncio
    async def test_export_produces_valid_zip(self, tmp_path: Path):
        pid = uuid.uuid4()
        project = _make_mock_project()
        project.id = pid
        fw = _make_mock_firmware(pid, tmp_path)
        finding = _make_mock_finding(pid)

        db = AsyncMock()

        # Mock all DB queries in sequence
        call_count = 0
        results = []

        # _load_project
        r1 = MagicMock()
        r1.scalar_one_or_none.return_value = project
        results.append(r1)

        # _load_firmware
        r2 = MagicMock()
        r2.scalars.return_value.all.return_value = [fw]
        results.append(r2)

        # _load_findings
        r3 = MagicMock()
        r3.scalars.return_value.all.return_value = [finding]
        results.append(r3)

        # _load_documents
        r4 = MagicMock()
        r4.scalars.return_value.all.return_value = []
        results.append(r4)

        # _load_emulation_presets
        r5 = MagicMock()
        r5.scalars.return_value.all.return_value = []
        results.append(r5)

        # _load_analysis_cache
        r6 = MagicMock()
        r6.scalars.return_value.all.return_value = []
        results.append(r6)

        # _load_sbom_components
        r7 = MagicMock()
        r7.scalars.return_value.all.return_value = []
        results.append(r7)

        # _load_sbom_vulnerabilities
        r8 = MagicMock()
        r8.scalars.return_value.all.return_value = []
        results.append(r8)

        # _load_fuzzing_campaigns
        r9 = MagicMock()
        r9.scalars.return_value.all.return_value = []
        results.append(r9)

        db.execute = AsyncMock(side_effect=results)

        svc = ExportService(db)
        buf = await svc.export_project(pid)

        assert isinstance(buf, io.BytesIO)
        buf.seek(0)

        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()

            # Manifest present
            assert "manifest.json" in names
            manifest = json.loads(zf.read("manifest.json"))
            assert manifest["archive_version"] == ARCHIVE_VERSION
            assert manifest["project_id"] == str(pid)

            # Project metadata present
            assert "project.json" in names
            proj = json.loads(zf.read("project.json"))
            assert proj["name"] == "Test Project"

            # Findings present
            assert "findings.json" in names
            findings = json.loads(zf.read("findings.json"))
            assert len(findings) == 1
            assert findings[0]["title"] == "XSS in admin panel"
