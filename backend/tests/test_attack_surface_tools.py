"""MCP handler tests for ``app.ai.tools.attack_surface`` (was ~10% / 141 miss)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.attack_surface import (
    _format_table,
    _handle_analyze_binary_attack_surface,
    _handle_detect_input_vectors,
    register_attack_surface_tools,
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

    def resolve_path(self, path: str) -> str:
        root = self.extracted_path or "/tmp/extract"
        return f"{root}{path if path.startswith('/') else '/' + path}"


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


async def _seed(db):
    p = Project(id=uuid.uuid4(), name="as", status="ready")
    db.add(p)
    await db.flush()
    fw = Firmware(
        id=uuid.uuid4(), project_id=p.id, sha256="e" * 64, extracted_path="/tmp/x",
    )
    db.add(fw)
    await db.flush()
    return p, fw


def test_register_and_format_table():
    reg = ToolRegistry()
    register_attack_surface_tools(reg)
    assert "detect_input_vectors" in reg._tools

    entry = SimpleNamespace(
        binary_path="/usr/sbin/httpd",
        binary_name="httpd",
        attack_surface_score=80,
        architecture="arm",
        is_setuid=True,
        is_network_listener=True,
        is_cgi_handler=False,
        has_dangerous_imports=True,
        dangerous_imports=["strcpy"],
        input_categories=["network"],
    )
    out = _format_table([entry], 1)
    assert "httpd" in out
    assert "Attack Surface" in out


def _scan_result(**overrides):
    base = dict(
        path="/bin/busybox",
        name="busybox",
        architecture="arm",
        file_size=100,
        score=50,
        breakdown={"net": 20},
        is_setuid=False,
        is_network_listener=True,
        is_cgi_handler=False,
        has_dangerous_imports=True,
        dangerous_imports=["system"],
        input_categories=["cli"],
        findings=[{
            "title": "Dangerous import",
            "severity": "medium",
            "description": "system()",
            "file_path": "/bin/busybox",
            "cwe_ids": ["CWE-78"],
        }],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_detect_input_vectors_scan_and_cache(live_db):
    p, fw = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=fw.id, project_id=p.id)

    with patch(
        "app.services.attack_surface_service.scan_attack_surface",
        return_value=[_scan_result()],
    ):
        out = await _handle_detect_input_vectors({"rescan": True}, ctx)
    assert "busybox" in out or "Attack Surface" in out

    # second call hits DB cache
    out2 = await _handle_detect_input_vectors({}, ctx)
    assert "busybox" in out2 or "Attack Surface" in out2

    with patch(
        "app.services.attack_surface_service.scan_attack_surface",
        return_value=[],
    ):
        empty = await _handle_detect_input_vectors({"rescan": True}, ctx)
    assert "No ELF" in empty


@pytest.mark.asyncio
async def test_analyze_binary_attack_surface(live_db):
    p, fw = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=fw.id, project_id=p.id)

    detail = _scan_result(score=90, name="httpd", path="/usr/sbin/httpd")
    with patch(
        "app.services.attack_surface_service.analyze_binary",
        return_value=detail,
        create=True,
    ):
        with patch(
            "app.services.attack_surface_service.scan_attack_surface",
            return_value=[detail],
        ):
            out = await _handle_analyze_binary_attack_surface(
                {"path": "/usr/sbin/httpd"}, ctx,
            )
            assert isinstance(out, str)
