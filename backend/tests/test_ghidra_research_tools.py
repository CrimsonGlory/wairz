"""Tests for the Ghidra-log persistence/list/read MCP tools.

Covers the 2026-06-22 process-violation fix: previously there was no
durable, sanctioned way to retrieve full Ghidra run output once the MCP
response was truncated, which led a worker to bypass the truncation limit
by reading the wairz Docker container's overlay filesystem directly. These
tools (list_ghidra_logs / read_ghidra_log) plus the higher 100KB ceiling
for Ghidra output are the sanctioned replacement.
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

from app.ai.tools import ghidra_research as gr


@pytest.fixture
def _fake_settings(tmp_path, monkeypatch):
    fake_settings = MagicMock()
    fake_settings.storage_root = str(tmp_path)
    monkeypatch.setattr(gr, "get_settings", lambda: fake_settings)
    return fake_settings


class _FakeContext:
    def __init__(self, project_id: uuid.UUID):
        self.project_id = project_id


def test_ghidra_output_max_kb_is_100():
    """Pin the Ghidra-specific ceiling (Rule #46-style size-lock)."""
    assert gr.GHIDRA_OUTPUT_MAX_KB == 100


@pytest.mark.asyncio
async def test_persist_list_read_log_roundtrip(_fake_settings):
    project_id = uuid.uuid4()
    body = "line one\n" * 2000 + "TAIL_MARKER\n"  # well under 100KB
    filename = gr._persist_ghidra_log(project_id, "MyScript.py", body)
    assert filename
    assert filename.endswith(".log")

    ctx = _FakeContext(project_id)

    listing = await gr._handle_list_ghidra_logs({}, ctx)
    assert filename in listing
    assert "Found 1 Ghidra log(s)" in listing

    full = await gr._handle_read_ghidra_log({"filename": filename}, ctx)
    assert full == body

    tail = await gr._handle_read_ghidra_log({"filename": filename, "tail": True}, ctx)
    assert "TAIL_MARKER" in tail


@pytest.mark.asyncio
async def test_read_ghidra_log_rejects_path_traversal(_fake_settings):
    """Canary: a synthetic traversal attempt must be rejected, not served."""
    project_id = uuid.uuid4()
    ctx = _FakeContext(project_id)
    result = await gr._handle_read_ghidra_log(
        {"filename": "../../../../etc/passwd"}, ctx
    )
    assert result.startswith("Error: Invalid filename")


@pytest.mark.asyncio
async def test_read_ghidra_log_missing_file_returns_error(_fake_settings):
    project_id = uuid.uuid4()
    ctx = _FakeContext(project_id)
    result = await gr._handle_read_ghidra_log({"filename": "does-not-exist.log"}, ctx)
    assert "not found" in result


@pytest.mark.asyncio
async def test_list_ghidra_logs_empty_project(_fake_settings):
    project_id = uuid.uuid4()
    ctx = _FakeContext(project_id)
    result = await gr._handle_list_ghidra_logs({}, ctx)
    assert "No Ghidra logs persisted yet" in result


@pytest.mark.asyncio
async def test_read_ghidra_log_truncates_long_content_by_default(_fake_settings):
    project_id = uuid.uuid4()
    # Exceed the 100KB ceiling so the default (head) read must truncate.
    body = "x" * (150 * 1024)
    filename = gr._persist_ghidra_log(project_id, "Big.py", body)

    ctx = _FakeContext(project_id)
    result = await gr._handle_read_ghidra_log({"filename": filename}, ctx)
    assert len(result.encode("utf-8")) < len(body.encode("utf-8"))
    assert "truncated" in result


@pytest.mark.asyncio
async def test_read_ghidra_log_tail_returns_end_of_long_content(_fake_settings):
    project_id = uuid.uuid4()
    body = ("a" * (150 * 1024)) + "END_MARKER"
    filename = gr._persist_ghidra_log(project_id, "Big.py", body)

    ctx = _FakeContext(project_id)
    result = await gr._handle_read_ghidra_log(
        {"filename": filename, "tail": True}, ctx
    )
    assert "END_MARKER" in result
