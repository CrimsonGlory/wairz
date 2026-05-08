"""Tests for the hardware-firmware router's new endpoints.

Covers:

* ``GET .../{blob_id}/download`` — happy path, missing blob (404), path
  escaping the firmware sandbox (403).
* ``GET .../cve-aggregate`` — severity breakdown fields populated.
* ``GET .../cves`` — CVE-centric aggregation returns one row per
  distinct CVE with affected blobs + formats rolled up.

These tests exercise the sandbox logic + schema contracts without
needing real firmware on disk — fixtures build a tmp tree and patch the
``resolve_firmware`` dependency so we can control what the router sees.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import get_settings
from app.database import get_db
from app.main import app
from app.routers.deps import resolve_firmware as resolve_firmware_dep


def _make_firmware(project_id: uuid.UUID, extraction_dir: str) -> MagicMock:
    """Build a Firmware-shaped mock row for the dependency override."""
    fw = MagicMock()
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extraction_dir = extraction_dir
    fw.extracted_path = extraction_dir
    return fw


def _make_blob(firmware_id: uuid.UUID, blob_path: str) -> MagicMock:
    blob = MagicMock()
    blob.id = uuid.uuid4()
    blob.firmware_id = firmware_id
    blob.blob_path = blob_path
    blob.partition = None
    blob.blob_sha256 = "a" * 64
    blob.file_size = 1234
    blob.category = "tee"
    blob.vendor = "MediaTek"
    blob.format = "mtk_atf"
    blob.version = "v1.3"
    blob.signed = "signed"
    blob.signature_algorithm = None
    blob.cert_subject = None
    blob.chipset_target = None
    blob.driver_references = None
    blob.sbom_component_id = None
    blob.metadata_ = {}
    blob.detection_source = "magic"
    blob.detection_confidence = "high"
    blob.created_at = datetime.now(timezone.utc)
    return blob


@pytest.fixture
async def client():
    # Pre-attach X-API-Key so the APIKeyASGIMiddleware gate in
    # app/middleware/asgi_auth.py doesn't return 401 on every request.
    # get_settings() is @lru_cache'd and reads API_KEY from the container
    # env; tests that want to exercise the auth middleware itself should
    # use a different fixture.
    api_key = get_settings().api_key or ""
    headers = {"X-API-Key": api_key} if api_key else {}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=headers,
    ) as c:
        yield c


@pytest.fixture
def project_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture(autouse=True)
def cleanup_overrides():
    """Reset dependency overrides after each test so they don't leak."""
    yield
    app.dependency_overrides.clear()


class TestDownloadBlob:
    """``GET .../{blob_id}/download`` sandbox enforcement."""

    @pytest.mark.asyncio
    async def test_happy_path_streams_file(
        self, client, project_id, tmp_path: Path,
    ):
        """Blob path inside the firmware extraction_dir → 200 + file bytes."""
        extraction_dir = tmp_path / "extract"
        extraction_dir.mkdir()
        target = extraction_dir / "gz.img"
        target.write_bytes(b"GENIEZONE\x00\x01" * 100)

        firmware = _make_firmware(project_id, str(extraction_dir))
        blob = _make_blob(firmware.id, str(target))

        result = MagicMock()
        result.scalar_one_or_none.return_value = blob
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/{blob.id}/download"
        )
        assert resp.status_code == 200, resp.text
        assert resp.content == target.read_bytes()
        assert "attachment" in resp.headers.get("content-disposition", "").lower()
        assert "gz.img" in resp.headers.get("content-disposition", "")

    @pytest.mark.asyncio
    async def test_missing_blob_returns_404(self, client, project_id, tmp_path: Path):
        firmware = _make_firmware(project_id, str(tmp_path))
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/{uuid.uuid4()}/download"
        )
        assert resp.status_code == 404
        assert "Blob not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_path_escaping_sandbox_returns_403(
        self, client, project_id, tmp_path: Path,
    ):
        """Blob path outside extraction_dir → 403 even if file exists."""
        extraction_dir = tmp_path / "extract"
        extraction_dir.mkdir()
        outside = tmp_path / "outside.bin"
        outside.write_bytes(b"escape")

        firmware = _make_firmware(project_id, str(extraction_dir))
        blob = _make_blob(firmware.id, str(outside))

        result = MagicMock()
        result.scalar_one_or_none.return_value = blob
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/{blob.id}/download"
        )
        assert resp.status_code == 403
        assert "sandbox" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_symlink_to_outside_is_rejected(
        self, client, project_id, tmp_path: Path,
    ):
        """A symlink INSIDE extraction_dir that points OUTSIDE it must also
        be rejected — realpath collapses the link before the prefix check."""
        extraction_dir = tmp_path / "extract"
        extraction_dir.mkdir()
        outside = tmp_path / "secret.txt"
        outside.write_bytes(b"secret")
        link = extraction_dir / "looks-legit.img"
        os.symlink(str(outside), str(link))

        firmware = _make_firmware(project_id, str(extraction_dir))
        blob = _make_blob(firmware.id, str(link))

        result = MagicMock()
        result.scalar_one_or_none.return_value = blob
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/{blob.id}/download"
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_file_on_disk_returns_404(
        self, client, project_id, tmp_path: Path,
    ):
        """Blob row exists but its file was deleted → 404 (not a 200 with empty body)."""
        extraction_dir = tmp_path / "extract"
        extraction_dir.mkdir()
        phantom = extraction_dir / "vanished.img"
        # Intentionally do NOT create the file.

        firmware = _make_firmware(project_id, str(extraction_dir))
        blob = _make_blob(firmware.id, str(phantom))

        result = MagicMock()
        result.scalar_one_or_none.return_value = blob
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/{blob.id}/download"
        )
        assert resp.status_code == 404
        assert "missing" in resp.json()["detail"].lower()


class TestCveAggregateSeverity:
    """``GET .../cve-aggregate`` returns severity breakdown fields."""

    @pytest.mark.asyncio
    async def test_response_schema_includes_severity_breakdown(
        self, client, project_id, tmp_path: Path,
    ):
        firmware = _make_firmware(project_id, str(tmp_path))

        # No vulns in the DB → aggregate returns zero across the board.
        result = MagicMock()
        result.all.return_value = []
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/cve-aggregate"
        )
        assert resp.status_code == 200
        body = resp.json()
        for key in (
            "hw_firmware_cves",
            "kernel_cves",
            "advisory_count",
            "hw_severity_critical",
            "hw_severity_high",
            "hw_severity_medium",
            "hw_severity_low",
        ):
            assert key in body, f"aggregate missing '{key}' field"
            assert body[key] == 0


class TestListCves:
    """``GET .../cves`` returns the CVE-centric aggregation payload."""

    @pytest.mark.asyncio
    async def test_empty_firmware_returns_empty_list(
        self, client, project_id, tmp_path: Path,
    ):
        firmware = _make_firmware(project_id, str(tmp_path))
        result = MagicMock()
        result.all.return_value = []
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/cves"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"cves": [], "total": 0}


# ── Phase β.11 — pe-signatures REST endpoint tests ───────────────────────────
#
# Mock-only tests for: invalid chain_status filter (400), invalid pagination
# bounds (400), 404 on missing signature, response-schema-shape sanity. The
# Rule #35b live canary lives at the end of this section — it seeds a real
# WindowsPESignature row through the live-DB fixture, hits the router via
# the AsyncClient, and SELECTs back to confirm the value-flow contract.


class TestListPeSignaturesValidation:
    """``GET .../pe-signatures`` validates query parameters."""

    @pytest.mark.asyncio
    async def test_invalid_chain_status_returns_400(
        self, client, project_id, tmp_path: Path,
    ):
        firmware = _make_firmware(project_id, str(tmp_path))
        db = AsyncMock()
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/pe-signatures",
            params={"chain_status": "bogus"},
        )
        assert resp.status_code == 400
        assert "chain_status" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_negative_offset_returns_400(
        self, client, project_id, tmp_path: Path,
    ):
        firmware = _make_firmware(project_id, str(tmp_path))
        db = AsyncMock()
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/pe-signatures",
            params={"offset": -1},
        )
        assert resp.status_code == 400
        assert "offset" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_limit_out_of_range_returns_400(
        self, client, project_id, tmp_path: Path,
    ):
        firmware = _make_firmware(project_id, str(tmp_path))
        db = AsyncMock()
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/pe-signatures",
            params={"limit": 0},
        )
        assert resp.status_code == 400
        assert "limit" in resp.json()["detail"]

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/pe-signatures",
            params={"limit": 1000},
        )
        assert resp.status_code == 400
        assert "limit" in resp.json()["detail"]


class TestGetPeSignature:
    """``GET .../pe-signatures/{id}`` enforces firmware-scoped lookup."""

    @pytest.mark.asyncio
    async def test_missing_signature_returns_404(
        self, client, project_id, tmp_path: Path,
    ):
        firmware = _make_firmware(project_id, str(tmp_path))
        result = MagicMock()
        result.first.return_value = None  # JOIN returned no rows
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/"
            f"pe-signatures/{uuid.uuid4()}"
        )
        assert resp.status_code == 404
        assert "PE signature not found" in resp.json()["detail"]


class TestPeSignaturesLiveCanary:
    """Rule #35b live canary: real ORM round-trip + SELECT-back.

    Mocks structurally cannot catch value-flow bugs (audit-2026-05-04
    F-G-03 + every β-phase postmortem since). This test seeds a real
    Project + Firmware + HardwareFirmwareBlob + WindowsPESignature row
    through the live-DB fixture, hits the new router endpoints via the
    AsyncClient, and asserts that every column the router surfaces
    matches what the constructor explicitly set.
    """

    @pytest.mark.asyncio
    async def test_list_and_get_pe_signature_round_trip(
        self, client, project_id,
    ):
        from datetime import UTC

        from app.models import (
            Firmware,
            HardwareFirmwareBlob,
            Project,
            WindowsPESignature,
        )
        from tests._live_db import make_live_db

        async with make_live_db() as db:
            project = Project(name="β11-live", description="pe-sig router canary")
            db.add(project)
            await db.flush()
            fw = Firmware(
                project_id=project.id,
                original_filename="windows.cab",
                file_size=4096,
                sha256="d" * 64,
                extracted_path="/tmp/live-canary",
            )
            db.add(fw)
            await db.flush()

            blob = HardwareFirmwareBlob(
                firmware_id=fw.id,
                blob_path="/tmp/live-canary/vendor.sys",
                blob_sha256="a" * 64,
                file_size=2048,
                category="other",
                format="raw_bin",
                detection_source="test",
            )
            db.add(blob)
            await db.flush()

            sig = WindowsPESignature(
                blob_id=blob.id,
                signed=True,
                chain_status="revoked",
                signer_subject="CN=AcmeRevoked",
                signer_issuer="CN=AcmeRoot",
                leaf_serial="DEADBEEF",
                sig_hash_algo="sha256",
                tsa_authority="CN=AcmeTSA",
                signed_at=datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC),
                chain_json={"verification_result": "OK"},
                dbx_revoked=True,
                dbx_revocation_kb="KB5025885",
                rich_header_json={"hash_md5": "abc"},
                arch_view={"primary": "arm64x", "secondary": "amd64"},
            )
            db.add(sig)
            await db.commit()

            # Override the resolved firmware to point at the live row,
            # and the get_db dependency to use the live session.
            async def _override_db():
                yield db

            app.dependency_overrides[resolve_firmware_dep] = lambda: fw
            app.dependency_overrides[get_db] = _override_db

            # ── List endpoint ───────────────────────────────────────
            resp = await client.get(
                f"/api/v1/projects/{project_id}/hardware-firmware/pe-signatures",
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["total"] == 1
            assert body["offset"] == 0
            assert body["limit"] == 50
            assert len(body["signatures"]) == 1

            row = body["signatures"][0]
            # Value-flow checks: every field the router surfaces matches
            # the explicit constructor argument.
            assert row["id"] == str(sig.id)
            assert row["blob_id"] == str(blob.id)
            assert row["blob_path"] == "/tmp/live-canary/vendor.sys"
            assert row["signed"] is True
            assert row["chain_status"] == "revoked"
            assert row["signer_subject"] == "CN=AcmeRevoked"
            assert row["signer_issuer"] == "CN=AcmeRoot"
            assert row["leaf_serial"] == "DEADBEEF"
            assert row["sig_hash_algo"] == "sha256"
            assert row["tsa_authority"] == "CN=AcmeTSA"
            assert row["dbx_revoked"] is True
            assert row["dbx_revocation_kb"] == "KB5025885"
            # Presence flags — JSONB payloads NOT in summary response.
            assert row["arch_view_present"] is True
            assert row["rich_header_present"] is True
            assert "arch_view" not in row
            assert "rich_header_json" not in row
            assert "chain_json" not in row

            # ── Detail endpoint ─────────────────────────────────────
            resp = await client.get(
                f"/api/v1/projects/{project_id}/hardware-firmware/"
                f"pe-signatures/{sig.id}",
            )
            assert resp.status_code == 200, resp.text
            detail = resp.json()
            # Detail surfaces the heavy JSONB payloads.
            assert detail["chain_json"] == {"verification_result": "OK"}
            assert detail["arch_view"] == {
                "primary": "arm64x", "secondary": "amd64",
            }
            assert detail["rich_header_json"] == {"hash_md5": "abc"}
            assert detail["dbx_revoked"] is True
            assert detail["chain_status"] == "revoked"
            assert detail["leaf_serial"] == "DEADBEEF"

            # ── chain_status filter ────────────────────────────────
            resp = await client.get(
                f"/api/v1/projects/{project_id}/hardware-firmware/pe-signatures",
                params={"chain_status": "valid_now"},  # doesn't match
            )
            assert resp.status_code == 200
            assert resp.json()["total"] == 0
            assert resp.json()["signatures"] == []

            resp = await client.get(
                f"/api/v1/projects/{project_id}/hardware-firmware/pe-signatures",
                params={"chain_status": "revoked"},  # matches
            )
            assert resp.status_code == 200
            assert resp.json()["total"] == 1

            # ── dbx_revoked_only filter ────────────────────────────
            resp = await client.get(
                f"/api/v1/projects/{project_id}/hardware-firmware/pe-signatures",
                params={"dbx_revoked_only": "true"},
            )
            assert resp.status_code == 200
            assert resp.json()["total"] == 1

    @pytest.mark.asyncio
    async def test_get_signature_belonging_to_other_firmware_returns_404(
        self, client, project_id,
    ):
        """A row from firmware B must NOT be retrievable when firmware A
        is the resolved scope — the JOIN in the get endpoint enforces
        per-firmware isolation."""
        from app.models import (
            Firmware,
            HardwareFirmwareBlob,
            Project,
            WindowsPESignature,
        )
        from tests._live_db import make_live_db

        async with make_live_db() as db:
            project = Project(name="β11-iso", description="firmware isolation")
            db.add(project)
            await db.flush()
            fw_a = Firmware(
                project_id=project.id,
                original_filename="a.cab",
                file_size=1,
                sha256="a" * 64,
                extracted_path="/tmp/a",
            )
            fw_b = Firmware(
                project_id=project.id,
                original_filename="b.cab",
                file_size=1,
                sha256="b" * 64,
                extracted_path="/tmp/b",
            )
            db.add_all([fw_a, fw_b])
            await db.flush()

            blob_b = HardwareFirmwareBlob(
                firmware_id=fw_b.id,
                blob_path="/tmp/b/foo.sys",
                blob_sha256="b" * 64,
                file_size=1,
                category="other",
                format="raw_bin",
                detection_source="test",
            )
            db.add(blob_b)
            await db.flush()
            sig_b = WindowsPESignature(
                blob_id=blob_b.id,
                signed=False,
                chain_status="unknown",
                dbx_revoked=False,
            )
            db.add(sig_b)
            await db.commit()

            async def _override_db():
                yield db

            # Resolve to fw_a; ask for sig_b's id → must 404.
            app.dependency_overrides[resolve_firmware_dep] = lambda: fw_a
            app.dependency_overrides[get_db] = _override_db

            resp = await client.get(
                f"/api/v1/projects/{project_id}/hardware-firmware/"
                f"pe-signatures/{sig_b.id}",
            )
            assert resp.status_code == 404
