"""HTTP-layer tests for ``app.routers.tools``.

Phase 2 Wave 2 file 2 of 5 — backfills router-level tests for the
MCP-to-REST bridge (263 LOC, 2 endpoints + ALLOWED_TOOLS whitelist) per
intake audit-test-coverage-routers-services-2026-05-04.

The router exposes a generic dispatcher that can execute any whitelisted
MCP tool through the existing ToolRegistry. Tests verify both the
dispatch surface AND the ALLOWED_TOOLS security boundary (a regression
that drops a dangerous tool into the whitelist would silently expose
it to unauthenticated REST callers).

Coverage targets:

* ``GET /``        — returns ToolListResponse with whitelisted tools
  only; non-allowed tools excluded; result sorted by name.
* ``POST /run``    — non-whitelisted tool returns 403; happy-path returns
  ToolRunResponse(success=True); error-string ("Error:" prefix) yields
  ToolRunResponse(success=False); ToolContext constructed with
  firmware_id, extracted_path, detection_roots from the resolved row.
* ``ALLOWED_TOOLS`` constant — pin the minimum membership so a regression
  that removes ``read_file`` (or adds ``start_emulation``) is caught by
  CI rather than shipping silently.
* **Rule #35b live-canary** — POST /run dispatches to a custom registry
  whose handler captures the ToolContext; assert ``context.firmware_id``,
  ``context.project_id``, ``context.extracted_path``, and
  ``context.detection_roots`` all equal the seeded firmware row's values.
  Mock-only tests would assert ``mock_registry.execute.assert_called_once_with(...)``
  and pass even if the router silently passed firmware.id=uuid.uuid4()
  (unrelated UUID) to the context — the F-A-06-shape regression this
  canary backstops.

Per Rule #30: ``create_tool_registry`` and ``ToolContext`` are MODULE-imported
at the top of tools.py (lines 16-17) — the consumer-module patch path
works for both. ``get_detection_roots`` is LAZY-imported inside the run_tool
endpoint (line 242) — patch the SOURCE module
``app.services.firmware_paths.get_detection_roots`` per Rule #30.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.database import get_db
from app.main import app
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter
from app.routers.deps import resolve_firmware as resolve_firmware_dep
from app.routers.tools import ALLOWED_TOOLS
from tests._live_db import make_live_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


def _make_firmware(
    project_id: uuid.UUID, extracted_path: str = "/tmp/x",
) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = extracted_path
    fw.extraction_dir = extracted_path
    fw.device_metadata = None
    return fw


# ===========================================================================
# ALLOWED_TOOLS whitelist — pin minimum membership
# ===========================================================================


class TestAllowedToolsConstant:
    """Pin ALLOWED_TOOLS so a regression that adds a dangerous tool
    (start_emulation, fuzzing_start, write_file, etc.) or accidentally
    drops a load-bearing read tool (read_file, list_directory) is caught."""

    def test_dangerous_tools_are_excluded(self):
        """The whitelist intentionally excludes mutating / control tools."""
        forbidden = {
            "start_emulation",
            "stop_emulation",
            "start_fuzzing_campaign",
            "stop_fuzzing_campaign",
            "uart_connect",
            "uart_send_command",
            "save_code_cleanup",
            "create_finding",
            "update_finding",
        }
        assert forbidden.isdisjoint(ALLOWED_TOOLS), (
            f"dangerous tools leaked into whitelist: "
            f"{forbidden & ALLOWED_TOOLS}"
        )

    def test_core_read_tools_present(self):
        """If any of these go missing the web-UI tool browser breaks."""
        required = {
            "list_directory", "read_file", "search_files",
            "list_functions", "decompile_function",
            "generate_sbom", "list_findings",
            "scan_apk_manifest", "scan_apk_bytecode",
        }
        missing = required - ALLOWED_TOOLS
        assert not missing, f"required tools missing from whitelist: {missing}"


# ===========================================================================
# GET / — list whitelisted tools
# ===========================================================================


class TestListTools:
    @pytest.mark.asyncio
    async def test_returns_only_whitelisted_tools_sorted(
        self, client, project_id,
    ):
        """The list endpoint reads from create_tool_registry() and filters
        by ALLOWED_TOOLS. Patch the registry to return a known set with a
        mix of allowed and disallowed tools — assert filter + sort."""
        fake_registry = MagicMock()
        fake_registry.get_anthropic_tools = MagicMock(return_value=[
            {"name": "read_file", "description": "read", "input_schema": {}},
            {"name": "start_emulation", "description": "danger", "input_schema": {}},
            {"name": "list_directory", "description": "list", "input_schema": {}},
            {"name": "uart_send_command", "description": "danger", "input_schema": {}},
        ])
        with patch(
            "app.routers.tools._get_registry",
            return_value=fake_registry,
        ):
            resp = await client.get(f"/api/v1/projects/{project_id}/tools")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        # Only the two read-only tools should pass the whitelist.
        assert body["count"] == 2
        # Sorted by name.
        assert [t["name"] for t in body["tools"]] == [
            "list_directory", "read_file",
        ]


# ===========================================================================
# POST /run — whitelist boundary + dispatch
# ===========================================================================


class TestRunToolWhitelist:
    @pytest.mark.asyncio
    async def test_dangerous_tool_returns_403(self, client, project_id):
        firmware = _make_firmware(project_id)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        resp = await client.post(
            f"/api/v1/projects/{project_id}/tools/run",
            json={"tool_name": "start_emulation", "input": {}},
        )
        assert resp.status_code == 403
        assert "not allowed via REST" in resp.json()["detail"]


class TestRunToolDispatch:
    @pytest.mark.asyncio
    async def test_happy_path_returns_success_response(
        self, client, project_id,
    ):
        firmware = _make_firmware(project_id)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        fake_registry = MagicMock()
        fake_registry.execute = AsyncMock(return_value="output text\n")

        with patch(
            "app.routers.tools._get_registry",
            return_value=fake_registry,
        ), patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=[firmware.extracted_path]),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/tools/run",
                json={"tool_name": "read_file", "input": {"path": "/etc/passwd"}},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["tool"] == "read_file"
        assert body["output"] == "output text\n"
        assert body["success"] is True

    @pytest.mark.asyncio
    async def test_error_string_yields_success_false(self, client, project_id):
        firmware = _make_firmware(project_id)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        fake_registry = MagicMock()
        # Registry returns "Error: ..." or "Error executing ..." on failure.
        fake_registry.execute = AsyncMock(
            return_value="Error executing read_file: file not found",
        )

        with patch(
            "app.routers.tools._get_registry",
            return_value=fake_registry,
        ), patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=[firmware.extracted_path]),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/tools/run",
                json={"tool_name": "read_file", "input": {"path": "/missing"}},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["success"] is False
        assert body["output"].startswith("Error executing")

    @pytest.mark.asyncio
    async def test_detection_roots_fallback_when_helper_raises(
        self, client, project_id,
    ):
        """If get_detection_roots raises, the router falls back to
        ``[firmware.extracted_path]``. The fallback must NOT 500 the request."""
        firmware = _make_firmware(project_id, extracted_path="/tmp/extract")
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        captured: dict = {}

        async def _capture(name, input, context, *, truncate=True):
            captured["roots"] = list(context.detection_roots)
            return "ok"

        fake_registry = MagicMock()
        fake_registry.execute = _capture

        with patch(
            "app.routers.tools._get_registry",
            return_value=fake_registry,
        ), patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(side_effect=RuntimeError("db error")),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/tools/run",
                json={"tool_name": "read_file", "input": {}},
            )
        assert resp.status_code == 200, resp.text
        # Fallback path: exactly the extracted_path, nothing more.
        assert captured["roots"] == ["/tmp/extract"]


# ===========================================================================
# Rule #35b LIVE-CANARY — ToolContext built from real firmware row
# ===========================================================================


class TestRunToolLiveCanaryContext:
    """Rule #35b: the value-flow contract here is that the router
    constructs a ToolContext whose firmware_id, project_id, extracted_path,
    and detection_roots equal the resolved firmware row's actual values.
    A mock-only test would assert ``execute.assert_called_once_with(...)``
    and pass even if the router silently passed ``uuid.uuid4()`` as
    firmware_id (the F-A-06 confidence-bypass shape applied to the
    context-construction layer). This canary instead seeds a real
    Firmware row and intercepts execute() with a context-capturing handler.
    """

    @pytest.mark.asyncio
    async def test_context_carries_real_firmware_values(self, tmp_path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            extracted = tmp_path / "rootfs"
            extracted.mkdir()
            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="j" * 64,
                extracted_path=str(extracted),
                extraction_dir=str(extracted),
            )
            db.add(firmware)
            await db.flush()

            # Real registry shape with one tool that captures its context
            # for inspection. A plain assert in the handler would also work,
            # but capturing lets us inspect every field at once.
            registry = ToolRegistry()
            captured: dict = {}

            async def _capture_handler(tool_input, context: ToolContext) -> str:
                captured["project_id"] = context.project_id
                captured["firmware_id"] = context.firmware_id
                captured["extracted_path"] = context.extracted_path
                captured["detection_roots"] = list(context.detection_roots)
                captured["extraction_dir"] = context.extraction_dir
                return "ok"

            registry.register(
                name="read_file",  # in ALLOWED_TOOLS so the whitelist passes
                description="capture",
                input_schema={"type": "object"},
                handler=_capture_handler,
            )

            extra_root = tmp_path / "scatter"
            extra_root.mkdir()

            # Override get_db so the run_tool endpoint uses our live db.
            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: db

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c:
                with patch(
                    "app.routers.tools._get_registry",
                    return_value=registry,
                ), patch(
                    "app.services.firmware_paths.get_detection_roots",
                    new=AsyncMock(return_value=[str(extracted), str(extra_root)]),
                ):
                    resp = await c.post(
                        f"/api/v1/projects/{pid}/tools/run",
                        json={"tool_name": "read_file", "input": {"path": "/"}},
                    )

            assert resp.status_code == 200, resp.text
            assert resp.json()["success"] is True

            # The ToolContext that landed inside the handler must reflect
            # the real firmware row — not a fabricated UUID, not the
            # path of some other firmware.
            assert captured["project_id"] == pid
            assert captured["firmware_id"] == firmware.id, (
                "Rule #35b: firmware_id must round-trip from the resolved row "
                "into the ToolContext"
            )
            assert captured["extracted_path"] == str(extracted)
            assert captured["extraction_dir"] == str(extracted)
            assert captured["detection_roots"] == [str(extracted), str(extra_root)]

            # And the seed row really is in the DB.
            persisted = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware.id),
                )
            ).scalar_one()
            assert persisted.project_id == pid
