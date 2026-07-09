"""MCP handler tests for ``app.ai.tools.report_writer`` (was ~18% / 72 miss)."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.report_writer import (
    _handle_report_render,
    _handle_report_start,
    _handle_report_write_section,
    register_report_writer_tools,
)


@dataclass
class _StubContext:
    db: object
    firmware_id: object
    project_id: object
    extracted_path: str | None = "/tmp/x"

    def __post_init__(self):
        if self.firmware_id is None:
            self.firmware_id = uuid.uuid4()
        if self.project_id is None:
            self.project_id = uuid.uuid4()


def test_register_report_writer():
    reg = ToolRegistry()
    register_report_writer_tools(reg)
    assert {"report_start", "report_write_section", "report_render"} <= set(reg._tools)


@pytest.mark.asyncio
async def test_report_start_unknown_template_and_success():
    db = MagicMock()
    db.commit = AsyncMock()
    ctx = _StubContext(db=db, firmware_id=uuid.uuid4(), project_id=uuid.uuid4())

    from app.services.report_template_service import TemplateNotFoundError

    with patch(
        "app.ai.tools.report_writer.get_template",
        side_effect=TemplateNotFoundError("x"),
    ):
        with patch("app.ai.tools.report_writer.list_templates", return_value=[]):
            out = await _handle_report_start({"template_id": "nope"}, ctx)
    assert "unknown template" in out.lower() or "Error" in out

    section_t = SimpleNamespace(
        slug="risk_summary", title="Risk", required=True, order=1,
        max_words=500, guidance="write risks",
    )
    template = SimpleNamespace(id="default", name="Default", sections=[section_t])
    report = SimpleNamespace(
        id=uuid.uuid4(), status="draft", template_id="default",
        title="R1", findings=[], sections=[],
    )
    svc = MagicMock()
    svc.get_or_create_active_draft = AsyncMock(return_value=report)
    with (
        patch("app.ai.tools.report_writer.get_template", return_value=template),
        patch("app.ai.tools.report_writer.ReportAuthoringService", return_value=svc),
    ):
        out = await _handle_report_start({}, ctx)
    data = json.loads(out)
    assert data["report_id"] == str(report.id)
    assert data["sections"][0]["slug"] == "risk_summary"


@pytest.mark.asyncio
async def test_report_write_section():
    db = MagicMock()
    db.commit = AsyncMock()
    ctx = _StubContext(db=db, firmware_id=uuid.uuid4(), project_id=uuid.uuid4())

    assert "slug is required" in await _handle_report_write_section({}, ctx)

    report = SimpleNamespace(id=uuid.uuid4())
    section = SimpleNamespace(slug="risk_summary")
    svc = MagicMock()
    svc.get_or_create_active_draft = AsyncMock(return_value=report)
    svc.upsert_section = AsyncMock(return_value=section)
    with patch("app.ai.tools.report_writer.ReportAuthoringService", return_value=svc):
        out = await _handle_report_write_section(
            {"slug": "risk_summary", "content_md": "hello world"}, ctx,
        )
    assert "updated" in out and "2 words" in out


@pytest.mark.asyncio
async def test_report_render_cached_and_fresh(tmp_path):
    db = MagicMock()
    db.commit = AsyncMock()
    # execute returns project/firmware/cache queries
    project = SimpleNamespace(id=uuid.uuid4(), name="P")
    firmware = SimpleNamespace(id=uuid.uuid4(), original_filename="fw.bin")

    async def fake_execute(stmt):
        m = MagicMock()
        # alternate responses
        if not hasattr(fake_execute, "n"):
            fake_execute.n = 0
        fake_execute.n += 1
        if fake_execute.n == 1:
            m.scalar_one.return_value = project
            m.scalar_one_or_none.return_value = project
        elif fake_execute.n == 2:
            m.scalar_one_or_none.return_value = firmware
        else:
            m.scalar_one_or_none.return_value = None
        return m

    db.execute = fake_execute
    db.add = MagicMock()
    ctx = _StubContext(db=db, firmware_id=firmware.id, project_id=project.id)

    section = SimpleNamespace(slug="s", order_index=1, content_md="hi")
    report = SimpleNamespace(
        id=uuid.uuid4(), template_id="default", sections=[section], findings=[],
    )
    template = SimpleNamespace(id="default", name="Default", sections=[])
    svc = MagicMock()
    svc.get_or_create_active_draft = AsyncMock(return_value=report)
    svc.get = AsyncMock(return_value=report)
    svc.included_findings = AsyncMock(return_value=[])

    with (
        patch("app.ai.tools.report_writer.ReportAuthoringService", return_value=svc),
        patch("app.ai.tools.report_writer.get_template", return_value=template),
        patch("app.ai.tools.report_writer.compute_content_hash", return_value="abc123"),
        patch("app.ai.tools.report_writer.render_pdf_bytes", return_value=b"%PDF-1.4"),
        patch("app.ai.tools.report_writer.artifact_path", return_value=tmp_path / "r.pdf"),
        patch("app.ai.tools.report_writer.write_artifact", return_value=None),
    ):
        out = await _handle_report_render({}, ctx)
    data = json.loads(out)
    assert data["format"] == "pdf"
    assert data["content_hash"] == "abc123"
    assert data["cached"] is False
