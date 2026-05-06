"""HTTP-layer tests for ``app.routers.apk_scan``.

The apk_scan router has 5 endpoints — manifest scan, bytecode scan, SAST
scan, source-list, source-file — all under
``/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/...``. It
fetches firmware via its own ``_get_firmware`` helper (NOT the shared
``resolve_firmware`` dependency), so test setup mocks ``get_db`` and seeds
the firmware row through ``db.execute``.

Coverage targets (per intake audit-test-coverage-routers-services-2026-05-04
Phase 2):

* Validation surface — ``min_severity``/``min_confidence`` invalid values
  return 400; missing firmware row → 404; un-extracted firmware → 400;
  APK path that doesn't resolve → 404.
* ``POST /manifest`` — happy path with stubbed AndroguardService; cache-hit
  path (returns ``from_cache=True``).
* ``POST /bytecode`` — happy path with stubbed BytecodeAnalysisService.
* ``POST /sast`` — mobsfscan-not-installed 503 short-circuit.
* ``GET /source/list`` + ``GET /source`` — happy path + missing-source 404.
* **Rule #35b live-canary** — ``POST /manifest`` against a real SQLite
  session. Stubs AndroguardService + _cache to known outputs, then
  ``SELECT``s the persisted ``Finding`` rows and asserts every field the
  router sets on the ``Finding(...)`` constructor in
  ``_persist_rest_manifest_findings`` (lines 440-451) round-tripped — the
  exact value-flow contract that mocks structurally cannot verify.

Per Rule #30, this router is rich in lazy-imported symbols (AndroguardService,
BytecodeAnalysisService, _cache, mobsfscan, JadxDecompilationCache,
firmware_context). Patches must hit the SOURCE module, not the router.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter

from tests._live_db import make_live_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_api_key_auth(monkeypatch):
    from app.middleware import asgi_auth as _auth_mod
    fake_settings = MagicMock()
    fake_settings.api_key = ""
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake_settings)


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


@pytest.fixture
def firmware_id() -> uuid.UUID:
    return uuid.uuid4()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _firmware_row(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    extracted_path: str,
) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = firmware_id
    fw.project_id = project_id
    fw.extracted_path = extracted_path
    fw.extraction_dir = extracted_path
    fw.original_filename = "test-firmware.zip"
    fw.device_metadata = None
    fw.os_info = None
    fw.created_at = datetime.now(timezone.utc)
    return fw


def _firmware_db_mock(firmware: MagicMock | None) -> AsyncMock:
    """AsyncMock db.execute returning ``firmware`` from scalar_one_or_none."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = firmware
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.add = MagicMock()
    db.commit = AsyncMock()
    return db


def _make_apk_file(parent: Path, rel_path: str = "system/app/Settings.apk") -> tuple[Path, str]:
    """Create a non-empty .apk file at ``parent/rel_path``. Return (parent, rel_path)."""
    target = parent / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"PK\x03\x04" + b"x" * 100)  # minimal zip-magic prefix
    return parent, rel_path


# ===========================================================================
# Validation surface — invalid min_severity / min_confidence / missing inputs
# ===========================================================================


class TestValidationSurface:
    @pytest.mark.asyncio
    async def test_invalid_min_severity_on_manifest_returns_400(
        self, client, project_id, firmware_id,
    ):
        # min_severity validated BEFORE the firmware lookup, so no DB
        # mocking required — the handler raises 400 immediately.
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/manifest",
            params={"apk_path": "system/app/X.apk", "min_severity": "bogus"},
        )
        assert resp.status_code == 400
        assert "Invalid min_severity" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_invalid_min_confidence_on_bytecode_returns_400(
        self, client, project_id, firmware_id,
    ):
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/bytecode",
            params={"apk_path": "system/app/X.apk", "min_confidence": "bogus"},
        )
        assert resp.status_code == 400
        assert "Invalid min_confidence" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_missing_firmware_returns_404(
        self, client, project_id, firmware_id,
    ):
        db = _firmware_db_mock(firmware=None)
        app.dependency_overrides[get_db] = lambda: db
        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/manifest",
            params={"apk_path": "system/app/X.apk"},
        )
        assert resp.status_code == 404
        assert "Firmware not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_unextracted_firmware_returns_400(
        self, client, project_id, firmware_id, tmp_path: Path,
    ):
        firmware = _firmware_row(project_id, firmware_id, extracted_path="")
        # extracted_path falsy → handler raises 400 BEFORE the apk_path resolve.
        db = _firmware_db_mock(firmware)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/manifest",
            params={"apk_path": "system/app/X.apk"},
        )
        assert resp.status_code == 400
        assert "not yet extracted" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_apk_path_unresolvable_returns_404(
        self, client, project_id, firmware_id, tmp_path: Path,
    ):
        # Real extracted dir, but the requested apk_path doesn't exist —
        # _find_apk_in_firmware raises 404.
        extracted_path = tmp_path / "extract"
        extracted_path.mkdir()
        firmware = _firmware_row(project_id, firmware_id, str(extracted_path))
        db = _firmware_db_mock(firmware)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/manifest",
            params={"apk_path": "system/app/Missing.apk"},
        )
        assert resp.status_code == 404
        assert "APK not found" in resp.json()["detail"]


# ===========================================================================
# POST /manifest — happy path + cache hit
# ===========================================================================


class TestManifestScanHappyPath:
    @pytest.mark.asyncio
    async def test_returns_response_with_manifest_findings(
        self, client, project_id, firmware_id, tmp_path: Path,
    ):
        extracted_path, rel_apk = _make_apk_file(tmp_path / "extract")
        firmware = _firmware_row(project_id, firmware_id, str(extracted_path))
        db = _firmware_db_mock(firmware)
        app.dependency_overrides[get_db] = lambda: db

        scan_result = {
            "package": "com.test.settings",
            "findings": [
                {
                    "check_id": "M1",
                    "title": "Debuggable",
                    "description": "android:debuggable=true",
                    "severity": "high",
                    "evidence": "AndroidManifest.xml line 42",
                    "cwe_ids": ["CWE-489"],
                    "confidence": "high",
                },
            ],
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "confidence_summary": {"high": 1, "medium": 0, "low": 0},
            "is_priv_app": False,
            "is_platform_signed": False,
            "is_debug_signed": False,
            "severity_reduced": False,
            "reduced_check_ids": [],
            "suppressed_findings": [],
            "suppressed_count": 0,
            "suppression_reasons": [],
            "elapsed_ms": 100,
            "total_findings": 1,
        }

        # Lazy-imported helpers per Rule #30: patch SOURCE modules.
        with patch(
            "app.services._cache.get_cached", new=AsyncMock(return_value=None),
        ), patch(
            "app.services._cache.store_cached", new=AsyncMock(return_value=None),
        ), patch(
            "app.services.androguard_service.AndroguardService",
        ) as svc_cls:
            svc_inst = MagicMock()
            svc_inst.check_platform_signed = MagicMock(return_value=False)
            svc_inst.scan_manifest_security = MagicMock(return_value=scan_result)
            svc_cls.return_value = svc_inst

            resp = await client.post(
                f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/manifest",
                params={"apk_path": rel_apk, "persist_findings": False},
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["package"] == "com.test.settings"
        assert body["from_cache"] is False
        assert len(body["findings"]) == 1
        assert body["findings"][0]["check_id"] == "M1"
        assert body["findings"][0]["severity"] == "high"
        assert body["summary"]["high"] == 1

    @pytest.mark.asyncio
    async def test_cache_hit_returns_from_cache_true(
        self, client, project_id, firmware_id, tmp_path: Path,
    ):
        extracted_path, rel_apk = _make_apk_file(tmp_path / "extract")
        firmware = _firmware_row(project_id, firmware_id, str(extracted_path))
        db = _firmware_db_mock(firmware)
        app.dependency_overrides[get_db] = lambda: db

        cached_result = {
            "package": "com.cached.app",
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "confidence_summary": {"high": 0, "medium": 0, "low": 0},
            "is_priv_app": False,
            "is_platform_signed": False,
            "is_debug_signed": False,
            "severity_reduced": False,
            "reduced_check_ids": [],
            "suppressed_findings": [],
            "suppressed_count": 0,
            "suppression_reasons": [],
            "elapsed_ms": 50,
            "total_findings": 0,
        }
        with patch(
            "app.services._cache.get_cached", new=AsyncMock(return_value=cached_result),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/manifest",
                params={"apk_path": rel_apk, "persist_findings": False},
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["from_cache"] is True
        assert body["package"] == "com.cached.app"


# ===========================================================================
# POST /bytecode — happy path
# ===========================================================================


class TestBytecodeScanHappyPath:
    @pytest.mark.asyncio
    async def test_returns_bytecode_response(
        self, client, project_id, firmware_id, tmp_path: Path,
    ):
        extracted_path, rel_apk = _make_apk_file(tmp_path / "extract")
        firmware = _firmware_row(project_id, firmware_id, str(extracted_path))
        db = _firmware_db_mock(firmware)
        app.dependency_overrides[get_db] = lambda: db

        bytecode_result = {
            "apk_location": "/" + rel_apk,
            "package": "com.test.app",
            "findings": [
                {
                    "pattern_id": "B1",
                    "title": "ECB Mode",
                    "description": "Cipher.getInstance(\"AES/ECB/NoPadding\")",
                    "severity": "high",
                    "category": "crypto",
                    "confidence": "high",
                    "cwe_ids": ["CWE-327"],
                    "locations": [{"class": "com.test.Crypto", "method": "encrypt"}],
                    "total_occurrences": 1,
                },
            ],
            "summary": {
                "total_findings": 1,
                "by_severity": {"high": 1},
                "by_category": {"crypto": 1},
                "by_confidence": {"high": 1},
            },
            "elapsed_ms": 1500,
        }

        with patch(
            "app.services._cache.get_cached", new=AsyncMock(return_value=None),
        ), patch(
            "app.services._cache.store_cached", new=AsyncMock(return_value=None),
        ), patch(
            "app.services.bytecode_analysis_service.BytecodeAnalysisService",
        ) as svc_cls:
            svc_inst = MagicMock()
            svc_inst.scan_apk = MagicMock(return_value=bytecode_result)
            svc_cls.return_value = svc_inst

            resp = await client.post(
                f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/bytecode",
                params={"apk_path": rel_apk},
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["from_cache"] is False
        assert len(body["findings"]) == 1
        assert body["findings"][0]["pattern_id"] == "B1"
        assert body["summary"]["by_category"] == {"crypto": 1}


# ===========================================================================
# POST /sast — mobsfscan unavailable short-circuit
# ===========================================================================


class TestSastScanUnavailable:
    @pytest.mark.asyncio
    async def test_mobsfscan_not_installed_returns_503(
        self, client, project_id, firmware_id,
    ):
        """``mobsfscan_available`` is lazy-imported inside the endpoint
        body (apk_scan.py:675); patch the SOURCE module per Rule #30.

        Patching ``app.routers.apk_scan.mobsfscan_available`` would be a
        silent no-op because the symbol was never bound at module scope.
        """
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch(
            "app.services.mobsfscan.mobsfscan_available",
            return_value=False,
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/sast",
                params={"apk_path": "system/app/X.apk"},
            )
        assert resp.status_code == 503
        assert "mobsfscan not installed" in resp.json()["detail"]


# ===========================================================================
# Source viewer endpoints
# ===========================================================================


class TestSourceList:
    @pytest.mark.asyncio
    async def test_returns_sorted_file_list(
        self, client, project_id, firmware_id, tmp_path: Path,
    ):
        extracted_path, rel_apk = _make_apk_file(tmp_path / "extract")
        firmware = _firmware_row(project_id, firmware_id, str(extracted_path))
        db = _firmware_db_mock(firmware)
        app.dependency_overrides[get_db] = lambda: db

        sources = {
            "com/foo/B.java": "class B {}",
            "com/foo/A.java": "class A {}",
        }
        with patch(
            "app.services.jadx_service.JadxDecompilationCache",
        ) as svc_cls:
            svc_inst = MagicMock()
            svc_inst.get_all_sources = AsyncMock(return_value=sources)
            svc_cls.return_value = svc_inst

            resp = await client.get(
                f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/source/list",
                params={"apk_path": rel_apk},
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["files"] == ["com/foo/A.java", "com/foo/B.java"]
        assert body["total"] == 2


class TestSourceFile:
    @pytest.mark.asyncio
    async def test_missing_source_returns_404(
        self, client, project_id, firmware_id, tmp_path: Path,
    ):
        extracted_path, rel_apk = _make_apk_file(tmp_path / "extract")
        firmware = _firmware_row(project_id, firmware_id, str(extracted_path))
        db = _firmware_db_mock(firmware)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.services.jadx_service.JadxDecompilationCache",
        ) as svc_cls:
            svc_inst = MagicMock()
            svc_inst.get_source_file = AsyncMock(return_value=None)
            svc_cls.return_value = svc_inst

            resp = await client.get(
                f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/source",
                params={"apk_path": rel_apk, "file_path": "com/Missing.java"},
            )

        assert resp.status_code == 404
        assert "not found in decompiled output" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_returns_source_with_line_count(
        self, client, project_id, firmware_id, tmp_path: Path,
    ):
        extracted_path, rel_apk = _make_apk_file(tmp_path / "extract")
        firmware = _firmware_row(project_id, firmware_id, str(extracted_path))
        db = _firmware_db_mock(firmware)
        app.dependency_overrides[get_db] = lambda: db

        source_text = "public class A {\n  void m() {}\n}\n"
        with patch(
            "app.services.jadx_service.JadxDecompilationCache",
        ) as svc_cls:
            svc_inst = MagicMock()
            svc_inst.get_source_file = AsyncMock(return_value=source_text)
            svc_cls.return_value = svc_inst

            resp = await client.get(
                f"/api/v1/projects/{project_id}/firmware/{firmware_id}/apk-scan/source",
                params={"apk_path": rel_apk, "file_path": "com/A.java"},
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["source"] == source_text
        assert body["line_count"] == source_text.count("\n") + 1
        assert body["path"] == "com/A.java"


# ===========================================================================
# Rule #35b LIVE-CANARY — POST /manifest persists Finding rows
# ===========================================================================


class TestApkScanManifestPersistenceLiveCanary:
    """Rule #35b: ``_persist_rest_manifest_findings`` constructor mapping.

    A mock-only test would assert ``db.add.call_count == 1`` and pass while
    the constructor silently dropped ``confidence`` (the F-A-06 shape this
    backstop exists to catch). This canary instead seeds a real SQLite
    session, writes a real APK file under a real extraction dir, runs
    ``POST /manifest`` with stubbed AndroguardService output, then
    ``SELECT``s the persisted ``Finding`` rows and asserts every field
    set on lines 440-451 of apk_scan.py round-tripped through the DB layer.
    """

    @pytest.mark.asyncio
    async def test_manifest_persists_findings_with_correct_fields(
        self, client, tmp_path: Path,
    ):
        # Real extraction dir + real APK file (the router computes SHA256
        # over the actual file bytes).
        extracted_path = tmp_path / "extract"
        rel_apk = "system/priv-app/Settings/Settings.apk"
        target = extracted_path / rel_apk
        target.parent.mkdir(parents=True)
        target.write_bytes(b"PK\x03\x04" + b"a" * 1024)

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="apk-canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="e" * 64,
                extracted_path=str(extracted_path),
                extraction_dir=str(extracted_path),
            )
            db.add(firmware)
            await db.flush()

            app.dependency_overrides[get_db] = lambda: db

            scan_result = {
                "package": "com.android.settings",
                "findings": [
                    {
                        "check_id": "M14",
                        "title": "Cleartext Traffic",
                        "description": "android:usesCleartextTraffic=true",
                        "severity": "medium",
                        "evidence": "AndroidManifest.xml: usesCleartextTraffic",
                        "cwe_ids": ["CWE-319"],
                        "confidence": "high",
                    },
                    {
                        "check_id": "M3",
                        "title": "Allow Backup",
                        "description": "android:allowBackup=true",
                        "severity": "low",
                        "evidence": "AndroidManifest.xml: allowBackup",
                        "cwe_ids": ["CWE-200"],
                        "confidence": "medium",
                    },
                ],
                "summary": {"critical": 0, "high": 0, "medium": 1, "low": 1, "info": 0},
                "confidence_summary": {"high": 1, "medium": 1, "low": 0},
                "is_priv_app": True,
                "is_platform_signed": False,
                "is_debug_signed": False,
                "severity_reduced": False,
                "reduced_check_ids": [],
                "suppressed_findings": [],
                "suppressed_count": 0,
                "suppression_reasons": [],
                "elapsed_ms": 200,
                "total_findings": 2,
            }

            # Per Rule #30: AndroguardService + _cache are lazy-imported
            # inside the endpoint body — patches must hit the SOURCE module.
            # The cache writer is patched out so we don't hit analysis_cache;
            # the live canary is on the Finding persistence path.
            with patch(
                "app.services._cache.get_cached", new=AsyncMock(return_value=None),
            ), patch(
                "app.services._cache.store_cached", new=AsyncMock(return_value=None),
            ), patch(
                "app.services.androguard_service.AndroguardService",
            ) as svc_cls:
                svc_inst = MagicMock()
                svc_inst.check_platform_signed = MagicMock(return_value=False)
                svc_inst.scan_manifest_security = MagicMock(return_value=scan_result)
                svc_cls.return_value = svc_inst

                resp = await client.post(
                    f"/api/v1/projects/{pid}/firmware/{firmware.id}/apk-scan/manifest",
                    params={"apk_path": rel_apk, "persist_findings": True},
                )

            assert resp.status_code == 200, resp.text

            # Real SELECT — the canary that mocks cannot fake. Two
            # AndroguardService findings → two Finding rows persisted.
            persisted = (
                await db.execute(
                    select(Finding).where(Finding.project_id == pid)
                )
            ).scalars().all()
            assert len(persisted) == 2, (
                f"expected exactly 2 persisted Finding rows, got {len(persisted)}"
            )

            # Title-keyed access (lexicographic ordering on "[M14]" vs "[M3]"
            # is brittle — character-by-character comparison sorts the
            # two-digit check_id BEFORE the one-digit one).
            by_title = {f.title: f for f in persisted}

            # Allow Backup — title is "[<check_id>] <title>" per router line 443.
            allow = by_title["[M3] Allow Backup"]
            assert allow.severity == "low"
            assert allow.confidence == "medium", (
                "Rule #35b: confidence must round-trip — F-A-06 shape: "
                "the constructor would silently drop this if removed"
            )
            assert allow.source == "apk-manifest-scan"
            assert allow.firmware_id == firmware.id
            assert allow.cwe_ids == ["CWE-200"]
            assert allow.file_path == os.path.relpath(str(target), str(extracted_path))

            # Cleartext Traffic — high-confidence row covers the other branch.
            ct = by_title["[M14] Cleartext Traffic"]
            assert ct.severity == "medium"
            assert ct.confidence == "high"
            assert ct.cwe_ids == ["CWE-319"]
            assert "android:usesCleartextTraffic=true" in ct.description
