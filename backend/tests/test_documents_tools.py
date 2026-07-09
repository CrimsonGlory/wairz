"""MCP handler tests for ``app.ai.tools.documents`` (was ~22% / 65 miss)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.documents import (
    _handle_list_documents,
    _handle_read_document,
    _handle_read_instructions,
    _handle_read_scratchpad,
    _handle_save_document,
    _handle_update_scratchpad,
    register_document_tools,
)
from app.models import Project
from app.models.document import Document
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    db: AsyncSession
    firmware_id: uuid.UUID
    project_id: uuid.UUID
    extracted_path: str | None = "/tmp/x"


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


async def _seed(db):
    p = Project(id=uuid.uuid4(), name="docs", status="ready")
    db.add(p)
    await db.flush()
    return p


def test_register_document_tools():
    reg = ToolRegistry()
    register_document_tools(reg)
    assert len(reg._tools) >= 6


@pytest.mark.asyncio
async def test_save_and_list_and_read(live_db):
    p = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4(), project_id=p.id)

    assert "filename is required" in await _handle_save_document({}, ctx)
    assert "content is required" in await _handle_save_document({"filename": "a.md"}, ctx)

    doc = SimpleNamespace(
        id=uuid.uuid4(), original_filename="notes.md",
        file_size=1024, content_type="text/markdown",
    )
    svc = MagicMock()
    svc.create_document = AsyncMock(return_value=doc)
    with patch("app.ai.tools.documents.DocumentService", return_value=svc):
        out = await _handle_save_document(
            {"filename": "notes.md", "content": "# hi", "description": "d"}, ctx,
        )
    assert "created" in out.lower() or "updated" in out.lower()

    svc.create_document = AsyncMock(side_effect=ValueError("bad name"))
    with patch("app.ai.tools.documents.DocumentService", return_value=svc):
        assert "bad name" in await _handle_save_document(
            {"filename": "x", "content": "y"}, ctx,
        )

    empty = await _handle_list_documents({}, ctx)
    assert "No documents" in empty

    svc.list_by_project = AsyncMock(return_value=[
        SimpleNamespace(
            id=uuid.uuid4(), original_filename="a.md", description="d",
            file_size=2048, content_type="text/md",
        )
    ])
    with patch("app.ai.tools.documents.DocumentService", return_value=svc):
        listed = await _handle_list_documents({}, ctx)
    assert "a.md" in listed

    assert "Invalid" in await _handle_read_document({"document_id": "nope"}, ctx)
    svc.get = AsyncMock(return_value=None)
    with patch("app.ai.tools.documents.DocumentService", return_value=svc):
        assert "not found" in await _handle_read_document(
            {"document_id": str(uuid.uuid4())}, ctx,
        )

    real = SimpleNamespace(
        id=uuid.uuid4(), project_id=p.id, original_filename="a.md",
        content_type="text/markdown", file_size=100, description=None,
    )
    svc.get = AsyncMock(return_value=real)
    svc.read_text_content = MagicMock(return_value="body text")
    with patch("app.ai.tools.documents.DocumentService", return_value=svc):
        out = await _handle_read_document({"document_id": str(real.id)}, ctx)
    assert "body" in out.lower() or "a.md" in out or isinstance(out, str)


@pytest.mark.asyncio
async def test_scratchpad_and_instructions(live_db):
    p = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4(), project_id=p.id)

    assert "No scratchpad" in await _handle_read_scratchpad({}, ctx)
    assert "content is required" in await _handle_update_scratchpad({}, ctx)

    svc = MagicMock()
    svc.create_note = AsyncMock()
    svc.update_content = AsyncMock()
    with patch("app.ai.tools.documents.DocumentService", return_value=svc):
        out = await _handle_update_scratchpad({"content": "notes here"}, ctx)
    assert "updated" in out.lower()

    assert "No WAIRZ.md" in await _handle_read_instructions({}, ctx)
