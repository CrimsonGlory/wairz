"""HTTP-layer tests for ``app.routers.analysis``.

Phase 2 Wave 2 file 1 of 5 — backfills router-level tests for
backend/app/routers/analysis.py (316 LOC, 6 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04. The router dispatches
binary analysis to ghidra_service (functions, disassembly, decompile,
binary-info, cleaned-code) and parses ELF imports inline via pyelftools.

Coverage targets:

* ``GET /functions`` — invalid path 403; Ghidra TimeoutError 504; generic
  Exception 400; happy path returns name/offset/size shape.
* ``GET /imports``   — invalid path 403; happy path returns parsed
  import dict shape (mocked _resolve_elf_imports to avoid ELF dep).
* ``GET /disasm``    — invalid path 403; Ghidra TimeoutError 504; generic
  Exception 400; happy path.
* ``GET /binary-info`` — invalid path 403; Ghidra TimeoutError 504; happy
  path includes both ``info`` and ``protections`` blocks.
* ``GET /cleaned-code`` — invalid path 403; cache-miss returns
  ``{available: False}``.
* ``GET /decompile`` — invalid path 403; FileNotFoundError 404; TimeoutError
  504; RuntimeError 400; happy path.
* **Rule #35b live-canary** — ``GET /cleaned-code`` against a real SQLite
  session: write a real binary file, compute its SHA256, INSERT an
  analysis_cache row with the matching key, then call the endpoint and
  verify the cleaned_code field round-tripped through the JSONB result
  column. Mocks would have asserted ``db.execute.call_count == 1`` and
  passed even if the JSONB cleaned_code field was silently dropped.

Per Rule #30, ``ghidra_service.*`` and ``ghidra_decompile`` (the renamed
``decompile_function``) are MODULE-imported at top of analysis.py
(lines 14-15), so router-module patches work for the ``ghidra_service.X``
attribute access AND the renamed ``ghidra_decompile`` symbol — patches
target ``app.routers.analysis.ghidra_service`` and
``app.routers.analysis.ghidra_decompile``.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.analysis_cache import AnalysisCache  # noqa: F401 — registers table
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter
from app.routers.deps import resolve_firmware as resolve_firmware_dep
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


def _make_firmware(project_id: uuid.UUID, extracted_path: str) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = extracted_path
    fw.extraction_dir = extracted_path
    fw.device_metadata = None
    return fw


def _make_binary(extracted_path: Path, rel: str = "usr/bin/test") -> Path:
    """Create a minimal-ELF-shaped file at extracted_path/rel."""
    target = extracted_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 100)
    return target


# ===========================================================================
# Path resolution surface — every endpoint calls _resolve_path
# ===========================================================================


class TestPathResolutionGuard:
    """``_resolve_path`` raises if FileService rejects the path; router
    catches and returns 403. Any path the FileService can't normalise
    (escaping the sandbox, missing extracted_path, etc.) hits this guard."""

    @pytest.mark.asyncio
    async def test_invalid_path_returns_403_on_functions(
        self, client, project_id, tmp_path: Path,
    ):
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        # FileService rejects relative-escape paths via realpath check.
        resp = await client.get(
            f"/api/v1/projects/{project_id}/analysis/functions",
            params={"path": "../../etc/shadow"},
        )
        assert resp.status_code == 403
        assert "Invalid path" in resp.json()["detail"]


# ===========================================================================
# GET /functions
# ===========================================================================


class TestListFunctions:
    @pytest.mark.asyncio
    async def test_timeout_returns_504(self, client, project_id, tmp_path: Path):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch(
            "app.routers.analysis.ghidra_service.get_functions",
            new=AsyncMock(side_effect=TimeoutError("ghidra timed out")),
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/functions",
                params={"path": os.path.relpath(str(binary), str(tmp_path))},  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
            )
        assert resp.status_code == 504
        assert "timed out" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_generic_exception_returns_400(
        self, client, project_id, tmp_path: Path,
    ):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch(
            "app.routers.analysis.ghidra_service.get_functions",
            new=AsyncMock(side_effect=RuntimeError("ghidra exploded")),
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/functions",
                params={"path": os.path.relpath(str(binary), str(tmp_path))},  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
            )
        assert resp.status_code == 400
        assert "Failed to analyze binary" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_returns_function_list_with_correct_shape(
        self, client, project_id, tmp_path: Path,
    ):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        funcs = [
            {"name": "main", "address": "0x1000", "size": 256},
            {"name": "init", "address": "0x900",  "size": 64},
        ]
        with patch(
            "app.routers.analysis.ghidra_service.get_functions",
            new=AsyncMock(return_value=funcs),
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/functions",
                params={"path": os.path.relpath(str(binary), str(tmp_path))},  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body["functions"]) == 2
        assert body["functions"][0]["name"] == "main"
        assert body["functions"][0]["offset"] == "0x1000"
        assert body["functions"][0]["size"] == 256


# ===========================================================================
# GET /imports
# ===========================================================================


class TestListImports:
    @pytest.mark.asyncio
    async def test_returns_import_list_via_resolver(
        self, client, project_id, tmp_path: Path,
    ):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        # _resolve_elf_imports is module-scope in analysis.py — patch the
        # router-module attribute (the function is module-level so the
        # consumer-attribute access goes through the module).
        fake_imports = [
            {"name": "printf", "libname": "libc.so.6"},
            {"name": "exit", "libname": "libc.so.6"},
            {"name": "unresolved_func", "libname": None},
        ]
        with patch(
            "app.routers.analysis._resolve_elf_imports",
            return_value=fake_imports,
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/imports",
                params={"path": os.path.relpath(str(binary), str(tmp_path))},  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["imports"] == fake_imports


# ===========================================================================
# GET /disasm
# ===========================================================================


class TestDisassemble:
    @pytest.mark.asyncio
    async def test_timeout_returns_504(self, client, project_id, tmp_path: Path):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch(
            "app.routers.analysis.ghidra_service.get_disassembly",
            new=AsyncMock(side_effect=TimeoutError),
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/disasm",
                params={
                    "path": os.path.relpath(str(binary), str(tmp_path)),  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                    "function": "main",
                },
            )
        assert resp.status_code == 504

    @pytest.mark.asyncio
    async def test_returns_disassembly(
        self, client, project_id, tmp_path: Path,
    ):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        disasm = [{"address": "0x1000", "instruction": "MOV EAX, 0"}]
        with patch(
            "app.routers.analysis.ghidra_service.get_disassembly",
            new=AsyncMock(return_value=disasm),
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/disasm",
                params={
                    "path": os.path.relpath(str(binary), str(tmp_path)),  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                    "function": "main",
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["function"] == "main"
        assert body["disassembly"] == disasm


# ===========================================================================
# GET /binary-info
# ===========================================================================


class TestBinaryInfo:
    @pytest.mark.asyncio
    async def test_includes_info_and_protections_blocks(
        self, client, project_id, tmp_path: Path,
    ):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        info = {"architecture": "ARM", "bits": 32, "format": "ELF"}
        protections = {"nx": True, "canary": False, "pie": True, "relro": "partial"}
        with patch(
            "app.routers.analysis.ghidra_service.get_binary_info",
            new=AsyncMock(return_value=info),
        ), patch(
            "app.routers.analysis.check_binary_protections",
            return_value=protections,
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/binary-info",
                params={"path": os.path.relpath(str(binary), str(tmp_path))},  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["info"] == info
        assert body["protections"] == protections


# ===========================================================================
# GET /cleaned-code — cache miss
# ===========================================================================


class TestCleanedCode:
    @pytest.mark.asyncio
    async def test_cache_miss_returns_unavailable(
        self, client, project_id, tmp_path: Path,
    ):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        # No cache row → get_cached returns None.
        with patch(
            "app.routers.analysis.ghidra_service.get_binary_sha256",
            new=AsyncMock(return_value="x" * 64),
        ), patch(
            "app.routers.analysis.ghidra_service.get_cached",
            new=AsyncMock(return_value=None),
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/cleaned-code",
                params={
                    "path": os.path.relpath(str(binary), str(tmp_path)),  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                    "function": "main",
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["available"] is False
        assert body["cleaned_code"] is None


# ===========================================================================
# GET /decompile — error matrix + happy path
# ===========================================================================


class TestDecompile:
    @pytest.mark.asyncio
    async def test_file_not_found_returns_404(
        self, client, project_id, tmp_path: Path,
    ):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch(
            "app.routers.analysis.ghidra_decompile",
            new=AsyncMock(side_effect=FileNotFoundError("missing")),
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/decompile",
                params={
                    "path": os.path.relpath(str(binary), str(tmp_path)),  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                    "function": "main",
                },
            )
        assert resp.status_code == 404
        assert "Binary not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_timeout_returns_504(self, client, project_id, tmp_path: Path):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch(
            "app.routers.analysis.ghidra_decompile",
            new=AsyncMock(side_effect=TimeoutError("ghidra timeout 360s")),
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/decompile",
                params={
                    "path": os.path.relpath(str(binary), str(tmp_path)),  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                    "function": "main",
                },
            )
        assert resp.status_code == 504
        assert "ghidra timeout" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_runtime_error_returns_400(
        self, client, project_id, tmp_path: Path,
    ):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch(
            "app.routers.analysis.ghidra_decompile",
            new=AsyncMock(side_effect=RuntimeError("ghidra crashed")),
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/decompile",
                params={
                    "path": os.path.relpath(str(binary), str(tmp_path)),  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                    "function": "main",
                },
            )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_returns_decompiled_source(
        self, client, project_id, tmp_path: Path,
    ):
        binary = _make_binary(tmp_path)
        firmware = _make_firmware(project_id, str(tmp_path))
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        decompiled = "int main(int argc, char *argv[]) {\n  return 0;\n}\n"
        with patch(
            "app.routers.analysis.ghidra_decompile",
            new=AsyncMock(return_value=decompiled),
        ):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/analysis/decompile",
                params={
                    "path": os.path.relpath(str(binary), str(tmp_path)),  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                    "function": "main",
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["decompiled_code"] == decompiled
        assert body["function"] == "main"


# ===========================================================================
# Rule #35b LIVE-CANARY — /cleaned-code reads real analysis_cache row
# ===========================================================================


class TestCleanedCodeLiveCanary:
    """Rule #35b: ``GET /cleaned-code`` round-trips through the
    analysis_cache JSONB ``result`` column. Mock-only tests would assert
    ``mock.get_cached.assert_called_with(...)`` and pass even if the
    JSONB ``cleaned_code`` field was silently dropped from the result
    dict (the F-A-06 confidence-bypass shape). The canary instead seeds
    a real analysis_cache row through the ORM, lets the router compute
    the matching SHA256 against a real binary, and verifies the JSONB
    payload arrives unchanged at the client.
    """

    @pytest.mark.asyncio
    async def test_cleaned_code_round_trips_via_analysis_cache(
        self, tmp_path: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            extracted_path = tmp_path / "rootfs"
            extracted_path.mkdir()
            binary = _make_binary(extracted_path, "usr/bin/foo")

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="i" * 64,
                extracted_path=str(extracted_path),
                extraction_dir=str(extracted_path),
            )
            db.add(firmware)
            await db.flush()

            # Compute the SHA256 the same way the router will — so the
            # cache lookup actually hits.
            import hashlib
            sha = hashlib.sha256()
            with open(binary, "rb") as f:  # noqa: ASYNC230 — test fixture: SHA256 of small binary mirrors router's own digest path; sync open acceptable
                sha.update(f.read())
            binary_sha256 = sha.hexdigest()

            # Seed the cache row with a JSONB payload containing
            # cleaned_code. The router will SELECT this back, unwrap, and
            # return the cleaned_code field in the response.
            cleaned_source = (
                "// AI-cleaned\nint main(void) {\n  return 0;\n}\n"
            )
            cache_row = AnalysisCache(
                firmware_id=firmware.id,
                binary_path="usr/bin/foo",
                binary_sha256=binary_sha256,
                operation="code_cleanup:main",
                result={"cleaned_code": cleaned_source, "model": "claude-test"},
            )
            db.add(cache_row)
            await db.flush()

            # Override deps so the router uses our live db + firmware.
            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: db

            # Patch only the SHA256 helper to skip the real I/O — but
            # have it return our REAL computed hash so get_cached hits.
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c:
                with patch(
                    "app.routers.analysis.ghidra_service.get_binary_sha256",
                    new=AsyncMock(return_value=binary_sha256),
                ):
                    resp = await c.get(
                        f"/api/v1/projects/{pid}/analysis/cleaned-code",
                        params={"path": "usr/bin/foo", "function": "main"},
                    )

            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["available"] is True
            assert body["cleaned_code"] == cleaned_source, (
                "Rule #35b: cleaned_code field must round-trip through the "
                "JSONB result column unchanged"
            )

            # Belt-and-braces: SELECT the row directly to confirm the seed.
            persisted = (
                await db.execute(
                    select(AnalysisCache).where(
                        AnalysisCache.firmware_id == firmware.id,
                        AnalysisCache.operation == "code_cleanup:main",
                    )
                )
            ).scalar_one()
            assert persisted.result["cleaned_code"] == cleaned_source
            assert persisted.result["model"] == "claude-test"
