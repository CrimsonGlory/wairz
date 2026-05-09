"""Tests for the FindingService — CRUD operations on security findings.

Uses a mock AsyncSession since FindingService is purely DB-driven. Tests cover
create, list (with filters), get, update, and delete operations.
"""

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.schemas.finding import (
    FindingCreate,
    FindingStatus,
    FindingUpdate,
    Severity,
)
from app.services.finding_service import FindingService


def _make_finding(**overrides):
    """Build a mock Finding ORM object with sensible defaults."""
    defaults = {
        "id": uuid.uuid4(),
        "project_id": uuid.uuid4(),
        "firmware_id": None,
        "conversation_id": None,
        "title": "Hardcoded credential in /etc/config",
        "severity": "high",
        "description": "Found API key",
        "evidence": "api_key = AKIA...",
        "file_path": "/etc/config",
        "line_number": 42,
        "cve_ids": None,
        "cwe_ids": ["CWE-798"],
        "confidence": "high",
        "status": "open",
        "source": "manual",
        "component_id": None,
        "created_at": datetime(2024, 1, 1),
        "updated_at": datetime(2024, 1, 1),
    }
    defaults.update(overrides)
    finding = MagicMock()
    for k, v in defaults.items():
        setattr(finding, k, v)
    return finding


def _make_db_session():
    """Create a mock AsyncSession with standard stubs."""
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.delete = AsyncMock()
    db.refresh = AsyncMock()
    return db


class TestFindingServiceCreate:
    """Tests for FindingService.create()."""

    @pytest.mark.asyncio
    async def test_create_minimal(self):
        db = _make_db_session()
        svc = FindingService(db)
        project_id = uuid.uuid4()
        data = FindingCreate(title="Test finding", severity=Severity.medium)

        result = await svc.create(project_id, data)

        db.add.assert_called_once()
        db.flush.assert_awaited_once()
        added = db.add.call_args[0][0]
        assert added.title == "Test finding"
        assert added.severity == "medium"
        assert added.project_id == project_id
        assert added.source == "manual"

    @pytest.mark.asyncio
    async def test_create_full_fields(self):
        db = _make_db_session()
        svc = FindingService(db)
        project_id = uuid.uuid4()
        firmware_id = uuid.uuid4()
        data = FindingCreate(
            title="SQL injection in httpd",
            severity=Severity.critical,
            description="Unsanitized user input in /cgi-bin/admin",
            evidence="GET /cgi-bin/admin?id=1' OR 1=1--",
            file_path="/usr/bin/httpd",
            line_number=100,
            cve_ids=["CVE-2024-1234"],
            cwe_ids=["CWE-89"],
            firmware_id=firmware_id,
            source="apk_sast",
        )

        result = await svc.create(project_id, data)

        added = db.add.call_args[0][0]
        assert added.severity == "critical"
        assert added.cve_ids == ["CVE-2024-1234"]
        assert added.firmware_id == firmware_id
        assert added.source == "apk_sast"

    @pytest.mark.asyncio
    async def test_create_with_all_severities(self):
        """Verify each severity enum value maps correctly to a string."""
        db = _make_db_session()
        svc = FindingService(db)
        pid = uuid.uuid4()
        for sev in Severity:
            data = FindingCreate(title=f"{sev.value} finding", severity=sev)
            await svc.create(pid, data)
            added = db.add.call_args[0][0]
            assert added.severity == sev.value


class TestFindingServiceList:
    """Tests for FindingService.list_by_project()."""

    @pytest.mark.asyncio
    async def test_list_no_filters(self):
        db = _make_db_session()
        findings = [_make_finding(), _make_finding()]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = findings
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.list_by_project(uuid.uuid4())
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_list_with_severity_filter(self):
        db = _make_db_session()
        finding = _make_finding(severity="critical")
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [finding]
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.list_by_project(uuid.uuid4(), severity="critical")
        assert len(result) == 1
        assert result[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_list_with_status_filter(self):
        db = _make_db_session()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.list_by_project(uuid.uuid4(), status="confirmed")
        assert result == []

    @pytest.mark.asyncio
    async def test_list_with_source_filter(self):
        db = _make_db_session()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [_make_finding(source="apk_manifest")]
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.list_by_project(uuid.uuid4(), source="apk_manifest")
        assert len(result) == 1
        assert result[0].source == "apk_manifest"

    @pytest.mark.asyncio
    async def test_list_with_firmware_filter(self):
        db = _make_db_session()
        fw_id = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [_make_finding(firmware_id=fw_id)]
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.list_by_project(uuid.uuid4(), firmware_id=fw_id)
        assert result[0].firmware_id == fw_id

    @pytest.mark.asyncio
    async def test_list_with_limit_and_offset(self):
        db = _make_db_session()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [_make_finding()]
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.list_by_project(uuid.uuid4(), limit=10, offset=5)
        assert len(result) == 1
        # Verify execute was called (query construction succeeded)
        db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_list_empty_project(self):
        db = _make_db_session()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.list_by_project(uuid.uuid4())
        assert result == []


class TestFindingServiceGet:
    """Tests for FindingService.get()."""

    @pytest.mark.asyncio
    async def test_get_existing(self):
        db = _make_db_session()
        finding = _make_finding()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = finding
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.get(finding.id)
        assert result is finding

    @pytest.mark.asyncio
    async def test_get_nonexistent(self):
        db = _make_db_session()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.get(uuid.uuid4())
        assert result is None


class TestFindingServiceUpdate:
    """Tests for FindingService.update()."""

    @pytest.mark.asyncio
    async def test_update_title(self):
        db = _make_db_session()
        finding = _make_finding(title="Old title")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = finding
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        data = FindingUpdate(title="New title")
        result = await svc.update(finding.id, data)

        assert finding.title == "New title"
        db.flush.assert_awaited_once()
        db.refresh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_severity_enum(self):
        db = _make_db_session()
        finding = _make_finding(severity="medium")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = finding
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        data = FindingUpdate(severity=Severity.critical)
        result = await svc.update(finding.id, data)

        # Enum value should be converted to string
        assert finding.severity == "critical"

    @pytest.mark.asyncio
    async def test_update_status(self):
        db = _make_db_session()
        finding = _make_finding(status="open")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = finding
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        data = FindingUpdate(status=FindingStatus.false_positive)
        result = await svc.update(finding.id, data)

        assert finding.status == "false_positive"

    @pytest.mark.asyncio
    async def test_update_nonexistent(self):
        db = _make_db_session()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        data = FindingUpdate(title="Won't happen")
        result = await svc.update(uuid.uuid4(), data)
        assert result is None

    @pytest.mark.asyncio
    async def test_update_partial_only_sets_provided_fields(self):
        db = _make_db_session()
        finding = _make_finding(title="Original", description="Keep this")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = finding
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        # Only update severity, not title or description
        data = FindingUpdate(severity=Severity.low)
        await svc.update(finding.id, data)

        # Title and description should remain unchanged
        assert finding.title == "Original"
        assert finding.description == "Keep this"
        assert finding.severity == "low"


class TestFindingServiceDelete:
    """Tests for FindingService.delete()."""

    @pytest.mark.asyncio
    async def test_delete_existing(self):
        db = _make_db_session()
        finding = _make_finding()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = finding
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.delete(finding.id)

        assert result is True
        db.delete.assert_awaited_once_with(finding)
        db.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self):
        db = _make_db_session()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)

        svc = FindingService(db)
        result = await svc.delete(uuid.uuid4())

        assert result is False
        db.delete.assert_not_awaited()
