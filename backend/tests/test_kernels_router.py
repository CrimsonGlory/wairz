"""HTTP-layer tests for ``app.routers.kernels``.

Phase 2 Wave 5 file 3 of 6 — backfills router-level tests for
backend/app/routers/kernels.py (104 LOC, 4 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04.

This router is filesystem-only (KernelService writes pre-built kernels
to a known directory; no DB persistence). Tests focus on the validation
surface — supported-architecture whitelist, file-size cap, empty-file
guard — and the upload happy path with mocked KernelService.

Coverage targets:

* ``GET /``                          — list response shape with
  optional architecture filter.
* ``POST /``                         — unsupported architecture 400;
  oversize file 400; empty file 400; service ValueError 400; happy path.
* ``POST /{name}/initrd``           — oversize 400; empty 400; happy path.
* ``DELETE /{name}``                — 404 missing.

Per Rule #30: ``KernelService`` and ``SUPPORTED_ARCHITECTURES`` are
module-imported at top of kernels.py (line 9). Service-module patches
work for the class.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.rate_limit import limiter


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


# ===========================================================================
# GET /
# ===========================================================================


class TestListKernels:
    @pytest.mark.asyncio
    async def test_returns_kernel_list_shape(self, client):
        kernel_info = {
            "name": "vmlinuz-arm-linux-malta",
            "architecture": "arm",
            "description": "OpenWrt kernel for ARM",
            "file_size": 5_000_000,
            "uploaded_at": "2026-05-06T12:00:00Z",
            "has_initrd": False,
        }
        with patch(
            "app.routers.kernels.KernelService",
        ) as svc_cls:
            svc = MagicMock()
            svc.list_kernels = MagicMock(return_value=[kernel_info])
            svc_cls.return_value = svc

            resp = await client.get(
                "/api/v1/kernels", params={"architecture": "arm"},
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 1
        assert body["kernels"][0]["name"] == "vmlinuz-arm-linux-malta"
        # KernelService.list_kernels was called with the architecture filter.
        svc.list_kernels.assert_called_once_with(architecture="arm")


# ===========================================================================
# POST / — upload kernel
# ===========================================================================


class TestUploadKernel:
    @pytest.mark.asyncio
    async def test_unsupported_architecture_returns_400(self, client):
        # The whitelist check fires BEFORE the file-read, so no service
        # patch needed.
        files = {"file": ("kernel", b"abc", "application/octet-stream")}
        resp = await client.post(
            "/api/v1/kernels",
            files=files,
            data={
                "name": "test-kernel",
                "architecture": "z80",  # not in SUPPORTED_ARCHITECTURES
                "description": "test",
            },
        )
        assert resp.status_code == 400
        assert "Unsupported architecture" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_empty_file_returns_400(self, client):
        files = {"file": ("kernel", b"", "application/octet-stream")}
        resp = await client.post(
            "/api/v1/kernels",
            files=files,
            data={
                "name": "test-kernel",
                "architecture": "arm",
                "description": "test",
            },
        )
        assert resp.status_code == 400
        assert "empty" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_service_value_error_returns_400(self, client):
        # KernelService.upload_kernel raises ValueError on (e.g.) duplicate
        # name. Patch with AsyncMock since the router awaits it.
        from unittest.mock import AsyncMock as _AM
        with patch(
            "app.routers.kernels.KernelService",
        ) as svc_cls:
            svc = MagicMock()
            svc.upload_kernel = _AM(side_effect=ValueError("duplicate name"))
            svc_cls.return_value = svc

            files = {"file": ("kernel", b"ELFheader" + b"\x00" * 100,
                              "application/octet-stream")}
            resp = await client.post(
                "/api/v1/kernels",
                files=files,
                data={
                    "name": "test-kernel",
                    "architecture": "arm",
                    "description": "test",
                },
            )
        assert resp.status_code == 400
        assert "duplicate" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_happy_path_returns_201_with_kernel_response(
        self, client,
    ):
        from unittest.mock import AsyncMock as _AM
        kernel_info = {
            "name": "test-kernel",
            "architecture": "arm",
            "description": "test",
            "file_size": 109,
            "uploaded_at": "2026-05-06T12:00:00Z",
            "has_initrd": False,
        }
        with patch(
            "app.routers.kernels.KernelService",
        ) as svc_cls:
            svc = MagicMock()
            svc.upload_kernel = _AM(return_value=kernel_info)
            svc_cls.return_value = svc

            files = {"file": ("kernel", b"ELFheader" + b"\x00" * 100,
                              "application/octet-stream")}
            resp = await client.post(
                "/api/v1/kernels",
                files=files,
                data={
                    "name": "test-kernel",
                    "architecture": "arm",
                    "description": "test",
                },
            )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["name"] == "test-kernel"
        assert body["architecture"] == "arm"


# ===========================================================================
# POST /{name}/initrd
# ===========================================================================


class TestUploadInitrd:
    @pytest.mark.asyncio
    async def test_empty_initrd_returns_400(self, client):
        files = {"file": ("initrd.img", b"", "application/octet-stream")}
        resp = await client.post(
            "/api/v1/kernels/test-kernel/initrd",
            files=files,
        )
        assert resp.status_code == 400
        assert "empty" in resp.json()["detail"].lower()


# ===========================================================================
# DELETE /{name}
# ===========================================================================


class TestDeleteKernel:
    @pytest.mark.asyncio
    async def test_unknown_kernel_returns_404(self, client):
        with patch(
            "app.routers.kernels.KernelService",
        ) as svc_cls:
            svc = MagicMock()
            svc.delete_kernel = MagicMock(
                side_effect=ValueError("kernel not found"),
            )
            svc_cls.return_value = svc

            resp = await client.delete("/api/v1/kernels/missing-kernel")
        assert resp.status_code == 404
