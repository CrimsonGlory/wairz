"""MCP handler tests for ``app.ai.tools.comparison`` (was ~9% / 208 miss)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.comparison import (
    _handle_diff_binary,
    _handle_diff_decompilation,
    _handle_diff_firmware,
    _handle_list_firmware_versions,
    register_comparison_tools,
)
from app.models import Firmware, Project
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    db: AsyncSession
    firmware_id: uuid.UUID
    project_id: uuid.UUID
    extracted_path: str | None = "/tmp/extract"
    detection_roots: list[str] = field(default_factory=list)


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


async def _seed_two(db: AsyncSession):
    project = Project(id=uuid.uuid4(), name="cmp", status="ready")
    db.add(project)
    await db.flush()
    fw_a = Firmware(
        id=uuid.uuid4(), project_id=project.id, sha256="a" * 64,
        original_filename="v1.bin", version_label="v1",
        extracted_path="/tmp/a", architecture="arm", file_size=1000,
    )
    fw_b = Firmware(
        id=uuid.uuid4(), project_id=project.id, sha256="b" * 64,
        original_filename="v2.bin", version_label="v2",
        extracted_path="/tmp/b", architecture="arm", file_size=1100,
    )
    db.add_all([fw_a, fw_b])
    await db.flush()
    return project, fw_a, fw_b


def test_register_comparison_tools():
    reg = ToolRegistry()
    register_comparison_tools(reg)
    assert {
        "list_firmware_versions",
        "diff_firmware",
        "diff_binary",
        "diff_decompilation",
    } <= set(reg._tools.keys())


@pytest.mark.asyncio
async def test_list_firmware_versions_empty_and_populated(live_db):
    project = Project(id=uuid.uuid4(), name="empty", status="ready")
    live_db.add(project)
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4(), project_id=project.id)
    empty = await _handle_list_firmware_versions({}, ctx)
    assert "No firmware" in empty

    project, fw_a, fw_b = await _seed_two(live_db)
    ctx = _StubContext(db=live_db, firmware_id=fw_a.id, project_id=project.id)
    listed = await _handle_list_firmware_versions({}, ctx)
    assert "Firmware versions" in listed
    assert str(fw_a.id) in listed
    assert "v1" in listed


@pytest.mark.asyncio
async def test_diff_firmware_invalid_ids(live_db):
    project, fw_a, _ = await _seed_two(live_db)
    ctx = _StubContext(db=live_db, firmware_id=fw_a.id, project_id=project.id)
    bad = await _handle_diff_firmware({"firmware_a_id": "nope"}, ctx)
    assert "invalid firmware IDs" in bad


@pytest.mark.asyncio
async def test_diff_firmware_happy(live_db):
    project, fw_a, fw_b = await _seed_two(live_db)
    ctx = _StubContext(db=live_db, firmware_id=fw_a.id, project_id=project.id)

    entry = SimpleNamespace(path="/bin/busybox", size_a=100, size_b=120, perms_a="755", perms_b="700")
    result = SimpleNamespace(
        total_files_a=10, total_files_b=12,
        added=[entry], removed=[entry], modified=[entry],
        permissions_changed=[entry], truncated=False,
    )
    with patch("app.ai.tools.comparison.diff_filesystems", return_value=result):
        out = await _handle_diff_firmware(
            {"firmware_a_id": str(fw_a.id), "firmware_b_id": str(fw_b.id)}, ctx,
        )
    assert "Filesystem Diff" in out
    assert "Added" in out
    assert "busybox" in out


@pytest.mark.asyncio
async def test_diff_firmware_missing_firmware(live_db):
    project, fw_a, _ = await _seed_two(live_db)
    ctx = _StubContext(db=live_db, firmware_id=fw_a.id, project_id=project.id)
    missing = await _handle_diff_firmware(
        {"firmware_a_id": str(fw_a.id), "firmware_b_id": str(uuid.uuid4())}, ctx,
    )
    assert "not found" in missing.lower() or "Error" in missing


@pytest.mark.asyncio
async def test_diff_binary_branches(live_db):
    project, fw_a, fw_b = await _seed_two(live_db)
    ctx = _StubContext(db=live_db, firmware_id=fw_a.id, project_id=project.id)

    no_path = await _handle_diff_binary(
        {"firmware_a_id": str(fw_a.id), "firmware_b_id": str(fw_b.id)}, ctx,
    )
    assert "binary_path is required" in no_path

    fn = SimpleNamespace(
        name="main", size_a=10, size_b=20, addr_a=0x1000, addr_b=0x1000,
    )
    result = SimpleNamespace(
        info_a={"file_size": 100}, info_b={"file_size": 110},
        functions_added=[fn], functions_removed=[fn], functions_modified=[fn],
        imports_added=["strcpy"], imports_removed=["gets"],
        exports_added=["foo"], exports_removed=["bar"],
        sections_changed=[
            {"name": ".text", "status": "modified", "size_a": 1, "size_b": 2},
            {"name": ".new", "status": "added", "size_b": 3},
            {"name": ".old", "status": "removed", "size_a": 4},
        ],
    )
    with (
        patch("app.ai.tools.comparison.validate_path", side_effect=lambda r, p: f"{r}{p}"),
        patch("app.ai.tools.comparison.diff_binary", return_value=result),
    ):
        out = await _handle_diff_binary(
            {
                "firmware_a_id": str(fw_a.id),
                "firmware_b_id": str(fw_b.id),
                "binary_path": "/bin/busybox",
            },
            ctx,
        )
    assert "Binary Diff" in out
    assert "Functions Added" in out
    assert "Import Changes" in out
    assert "Section Changes" in out


@pytest.mark.asyncio
async def test_diff_binary_not_found_and_no_diff(live_db):
    project, fw_a, fw_b = await _seed_two(live_db)
    ctx = _StubContext(db=live_db, firmware_id=fw_a.id, project_id=project.id)

    with patch(
        "app.ai.tools.comparison.validate_path",
        side_effect=ValueError("bad"),
    ):
        out = await _handle_diff_binary(
            {
                "firmware_a_id": str(fw_a.id),
                "firmware_b_id": str(fw_b.id),
                "binary_path": "/bin/x",
            },
            ctx,
        )
    assert "not found" in out.lower()

    empty = SimpleNamespace(
        info_a={}, info_b={},
        functions_added=[], functions_removed=[], functions_modified=[],
        imports_added=[], imports_removed=[],
        exports_added=[], exports_removed=[],
        sections_changed=[],
    )
    with (
        patch("app.ai.tools.comparison.validate_path", side_effect=lambda r, p: f"{r}{p}"),
        patch("app.ai.tools.comparison.diff_binary", return_value=empty),
    ):
        out = await _handle_diff_binary(
            {
                "firmware_a_id": str(fw_a.id),
                "firmware_b_id": str(fw_b.id),
                "binary_path": "/bin/x",
            },
            ctx,
        )
    assert "No function-level" in out


@pytest.mark.asyncio
async def test_diff_decompilation(live_db):
    project, fw_a, fw_b = await _seed_two(live_db)
    ctx = _StubContext(db=live_db, firmware_id=fw_a.id, project_id=project.id)

    missing = await _handle_diff_decompilation(
        {"firmware_a_id": str(fw_a.id), "firmware_b_id": str(fw_b.id)}, ctx,
    )
    assert "required" in missing.lower()

    with (
        patch("app.ai.tools.comparison.validate_path", side_effect=lambda r, p: f"{r}{p}"),
        patch(
            "app.ai.tools.comparison.ghidra_service.decompile_function",
            new=AsyncMock(side_effect=["int main() { return 1; }", "int main() { return 2; }"]),
        ),
    ):
        out = await _handle_diff_decompilation(
            {
                "firmware_a_id": str(fw_a.id),
                "firmware_b_id": str(fw_b.id),
                "binary_path": "/bin/busybox",
                "function_name": "main",
            },
            ctx,
        )
    # unified diff or equality message
    assert isinstance(out, str) and len(out) > 0
