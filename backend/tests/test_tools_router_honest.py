"""Honest absolute coverage for app/routers/tools.py (list_tools + run_tool)."""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException


class TestToolsRouterHonest:
    def test_get_registry_caches(self):
        from app.routers import tools as tr

        tr._registry_cache = None
        fake = MagicMock()
        with patch.object(tr, "create_tool_registry", return_value=fake) as crt:
            a = tr._get_registry()
            b = tr._get_registry()
            assert a is b is fake
            crt.assert_called_once()
        tr._registry_cache = None

    @pytest.mark.asyncio
    async def test_list_tools(self):
        from app.routers import tools as tr

        reg = MagicMock()
        reg.get_anthropic_tools.return_value = [
            {
                "name": "list_directory",
                "description": "list",
                "input_schema": {"type": "object"},
            },
            {
                "name": "emulate_start",  # not in ALLOWED_TOOLS
                "description": "emu",
                "input_schema": {},
            },
            {
                "name": "read_file",
                "description": "read",
                "input_schema": {"type": "object", "properties": {}},
            },
        ]
        with patch.object(tr, "_get_registry", return_value=reg):
            out = await tr.list_tools(uuid.uuid4())
        assert out.count >= 1
        names = {t.name for t in out.tools}
        assert "list_directory" in names
        assert "read_file" in names
        assert "emulate_start" not in names

    @pytest.mark.asyncio
    async def test_run_tool_forbidden_and_ok_and_error(self):
        from app.routers import tools as tr
        from app.schemas.tools import ToolRunRequest

        pid = uuid.uuid4()
        fw = SimpleNamespace(
            id=uuid.uuid4(),
            project_id=pid,
            extracted_path="/data/fw",
            extraction_dir="/data",
        )
        db = AsyncMock()

        # forbidden tool
        body = ToolRunRequest(tool_name="emulate_start", input={})
        with pytest.raises(HTTPException) as ei:
            await tr.run_tool(pid, body, fw, db)
        assert ei.value.status_code == 403

        reg = MagicMock()
        reg.execute = AsyncMock(
            side_effect=["Error: boom", "ok content", "Error executing X"]
        )

        allowed = next(iter(tr.ALLOWED_TOOLS))
        body_ok = ToolRunRequest(tool_name=allowed, input={"path": "/"})

        with (
            patch.object(tr, "_get_registry", return_value=reg),
            patch(
                "app.services.firmware_paths.get_detection_roots",
                new=AsyncMock(return_value=["/data/fw"]),
            ),
        ):
            err = await tr.run_tool(pid, body_ok, fw, db)
            assert err.success is False
            ok = await tr.run_tool(pid, body_ok, fw, db)
            assert ok.success is True
            err2 = await tr.run_tool(pid, body_ok, fw, db)
            assert err2.success is False

        # get_detection_roots failure fallback
        with (
            patch.object(tr, "_get_registry", return_value=reg),
            patch(
                "app.services.firmware_paths.get_detection_roots",
                new=AsyncMock(side_effect=RuntimeError("no roots")),
            ),
        ):
            reg.execute = AsyncMock(return_value="fine")
            out = await tr.run_tool(pid, body_ok, fw, db)
            assert out.success is True

        # no extracted_path fallback
        fw2 = SimpleNamespace(
            id=fw.id,
            project_id=pid,
            extracted_path=None,
            extraction_dir=None,
        )
        with (
            patch.object(tr, "_get_registry", return_value=reg),
            patch(
                "app.services.firmware_paths.get_detection_roots",
                new=AsyncMock(side_effect=RuntimeError("x")),
            ),
        ):
            reg.execute = AsyncMock(return_value="fine")
            out = await tr.run_tool(pid, body_ok, fw2, db)
            assert out.success is True
