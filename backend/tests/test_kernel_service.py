"""Service-layer tests for ``app.services.kernel_service``.

Phase 2 Wave 7 file 3 of 5 — backfills service-layer tests for the
kernel-management service (381 LOC) per intake
audit-test-coverage-routers-services-2026-05-04. Pairs with Wave 5
``test_kernels_router.py`` (HTTP-layer arch-whitelist canary).

The service is a FILESYSTEM-backed singleton — kernels live on disk
under ``settings.emulation_kernel_dir`` with companion ``.json``
sidecars. There is NO database table; the value-flow contract is
"upload binary → list returns the entry with file_size + arch +
description + has_initrd + uploaded_at populated correctly".

Rule #30 distribution: every dependency is module-scope. ``aiofiles``,
``httpx``, ``socket``, ``tempfile`` are top-level imports — patches
target the consumer module (``ks_mod.<name>``). ``get_settings`` is
imported into the consumer module from ``app.config``; patches must
also hit the consumer-module reference.

Coverage targets:

* ``_guess_arch`` — pattern priority (``mipsel`` checked before
  ``mips``; ``aarch64`` before ``arm``); unknown filename → None.
* ``_validate_kernel_name`` — empty; whitespace; startswith ``.``;
  contains ``/`` / ``\\`` / ``..``; non-allowed characters.
* ``_validate_download_url`` — too long; non-http(s) scheme; no
  hostname; gaierror; private/loopback/link-local IPs all rejected.
* ``_read_sidecar`` — present + valid JSON; missing → None; corrupt
  JSON → None (with a warning, doesn't raise).
* ``_initrd_path`` — sidecar with explicit ``initrd`` key; convention
  fallback; absent.
* ``_kernel_info`` — fields populated from real stat + sidecar;
  fallback values when sidecar missing; OSError → file_size 0
  + datetime.now() mtime.
* ``list_kernels`` — filters out ``.json`` sidecars, ``.initrd``
  companions, hidden ``.X`` files, directories; sorts by name;
  ``architecture=`` filter restricts results; missing kernel dir → [].
* ``get_kernel`` — validates name; raises if missing; returns info.
* ``upload_kernel`` — validates name + arch + existence; writes binary
  AND sidecar; sidecar contains architecture / description /
  uploaded_at.
* ``upload_initrd`` — validates name + kernel exists; writes
  ``<kernel>.initrd``; updates sidecar with ``initrd`` key.
* ``delete_kernel`` — removes binary AND sidecar atomically.
* ``find_kernel_for_arch`` — returns first match or None.
* ``download_kernel`` — happy path (mocked httpx + valid kernel
  bytes); HTTPStatusError → ValueError; size-cap exceeded →
  ValueError; empty download → ValueError.
* **Rule #35b live canary** — full upload → list → get → delete cycle
  on a real on-disk tmp directory. Mock-only tests cannot fail on:
  the wrong filename being written; the sidecar being skipped; the
  ``has_initrd`` flag being computed against the wrong companion path.
"""
from __future__ import annotations

import json
import socket
import struct
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import kernel_service as ks_mod
from app.services.kernel_service import (
    KernelService,
    _guess_arch,
    _validate_download_url,
    _validate_kernel_name,
)

# A 64-byte U-Boot uImage header is enough to satisfy _validate_kernel_file's
# "is this a real kernel?" check (magic 0x27051956 + size > 500KB).
_UBOOT_MAGIC = b"\x27\x05\x19\x56"


def _real_kernel_bytes(extra: int = 600_000) -> bytes:
    """Build something `_validate_kernel_file` accepts: U-Boot uImage
    magic + padding to exceed the 500KB minimum size threshold."""
    header = struct.pack(
        ">IIIIIIIBBBB",
        0x27051956, 0xAABBCCDD, 0, 0,
        0, 0, 0xDEADBEEF, 5,  # OS=Linux
        2, 2, 3,  # arch=ARM, type=Kernel, compression=lzma
    ) + b"test-kernel".ljust(32, b"\x00")
    return header + b"\x00" * extra


@pytest.fixture
def patched_kernel_dir(tmp_path: Path):
    """Point KernelService at a temp dir for the duration of a test."""
    fake_settings = MagicMock()
    fake_settings.emulation_kernel_dir = str(tmp_path)
    with patch.object(ks_mod, "get_settings", lambda: fake_settings):
        yield tmp_path


# ===========================================================================
# _guess_arch — pattern priority
# ===========================================================================


class TestGuessArch:
    def test_mipsel_matched_before_mips(self):
        # mipsel contains "mips" but the longer pattern must win.
        assert _guess_arch("vmlinux-mipsel-3.18") == "mipsel"

    def test_mips_when_no_mipsel(self):
        assert _guess_arch("vmlinux-mips-3.18") == "mips"

    def test_aarch64_matched_before_arm(self):
        assert _guess_arch("vmlinuz-aarch64-5.10") == "aarch64"

    def test_arm64_aliased_to_aarch64(self):
        assert _guess_arch("kernel-arm64") == "aarch64"

    def test_arm_after_aarch64(self):
        assert _guess_arch("zImage-arm-3.0") == "arm"

    def test_x86_64_matched_before_x86(self):
        assert _guess_arch("bzImage-x86_64-5.10") == "x86_64"

    def test_i386_aliased_to_x86(self):
        assert _guess_arch("vmlinuz-i386") == "x86"

    def test_unknown_returns_none(self):
        assert _guess_arch("some-random-name") is None


# ===========================================================================
# _validate_kernel_name — security validation
# ===========================================================================


class TestValidateKernelName:
    def test_valid_name_passes(self):
        _validate_kernel_name("vmlinuz-5.10.0")  # should not raise

    def test_empty_name_rejected(self):
        with pytest.raises(ValueError, match="must not be empty"):
            _validate_kernel_name("")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValueError, match="must not be empty"):
            _validate_kernel_name("   ")

    def test_dot_prefix_rejected(self):
        with pytest.raises(ValueError, match="must not start with"):
            _validate_kernel_name(".secret")

    def test_forward_slash_rejected(self):
        with pytest.raises(ValueError, match="must not contain"):
            _validate_kernel_name("dir/kernel")

    def test_backslash_rejected(self):
        with pytest.raises(ValueError, match="must not contain"):
            _validate_kernel_name("dir\\kernel")

    def test_double_dot_in_middle_rejected(self):
        # ".." substring not at start: trips the "must not contain" branch.
        # (A leading "." trips the "must not start with '.'" branch first;
        # see test_dot_prefix_rejected for that case.)
        with pytest.raises(ValueError, match="must not contain"):
            _validate_kernel_name("kernel..bad")

    def test_special_char_rejected(self):
        with pytest.raises(ValueError, match="alphanumeric"):
            _validate_kernel_name("kernel name with spaces")

    def test_only_alphanumeric_dot_dash_underscore_allowed(self):
        _validate_kernel_name("vmlinuz-5.10_x86")  # all four allowed chars


# ===========================================================================
# _validate_download_url — SSRF prevention
# ===========================================================================


class TestValidateDownloadUrl:
    def test_too_long_url_rejected(self):
        long_url = "https://example.com/" + "a" * 2050
        with pytest.raises(ValueError, match="too long"):
            _validate_download_url(long_url)

    def test_non_http_scheme_rejected(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme 'file'"):
            _validate_download_url("file:///etc/passwd")

    def test_javascript_scheme_rejected(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme 'javascript'"):
            _validate_download_url("javascript:alert(1)")

    def test_no_hostname_rejected(self):
        # The urlparse for `http:///` — empty hostname.
        with pytest.raises(ValueError, match="no hostname"):
            _validate_download_url("http:///path")

    def test_unresolvable_host_rejected(self):
        with patch.object(
            ks_mod.socket, "getaddrinfo",
            side_effect=socket.gaierror(-2, "Name or service not known"),
        ):
            with pytest.raises(ValueError, match="Cannot resolve hostname"):
                _validate_download_url("https://nonexistent.invalid/k")

    def test_private_ip_rejected(self):
        # Mock getaddrinfo to return a private 10.x.x.x address.
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 443))]
        with patch.object(ks_mod.socket, "getaddrinfo", return_value=fake_info):
            with pytest.raises(ValueError, match="non-public IP"):
                _validate_download_url("https://internal.example/k")

    def test_loopback_ip_rejected(self):
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 80))]
        with patch.object(ks_mod.socket, "getaddrinfo", return_value=fake_info):
            with pytest.raises(ValueError, match="non-public IP"):
                _validate_download_url("http://localhost/k")

    def test_link_local_ip_rejected(self):
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.1.1", 80))]
        with patch.object(ks_mod.socket, "getaddrinfo", return_value=fake_info):
            with pytest.raises(ValueError, match="non-public IP"):
                _validate_download_url("http://169.254.1.1/")

    def test_public_ipv4_passes(self):
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))]
        with patch.object(ks_mod.socket, "getaddrinfo", return_value=fake_info):
            _validate_download_url("https://example.com/")  # should not raise


# ===========================================================================
# _read_sidecar / _initrd_path / _kernel_info
# ===========================================================================


class TestReadSidecar:
    def test_valid_json_returned(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "k1.json").write_text(json.dumps({"architecture": "arm"}))
        service = KernelService()
        assert service._read_sidecar("k1") == {"architecture": "arm"}

    def test_missing_returns_none(self, patched_kernel_dir: Path):
        service = KernelService()
        assert service._read_sidecar("absent") is None

    def test_corrupt_json_returns_none(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "k1.json").write_text("{not valid json")
        service = KernelService()
        assert service._read_sidecar("k1") is None  # no raise


class TestInitrdPath:
    def test_explicit_sidecar_initrd(self, patched_kernel_dir: Path):
        # Real sidecar pointing at an initrd that DOES exist on disk.
        (patched_kernel_dir / "k1.initrd-custom").write_bytes(b"initrd")
        (patched_kernel_dir / "k1.json").write_text(json.dumps({
            "architecture": "arm", "initrd": "k1.initrd-custom",
        }))
        service = KernelService()
        assert service._initrd_path("k1") == str(patched_kernel_dir / "k1.initrd-custom")

    def test_convention_fallback(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "k1.initrd").write_bytes(b"initrd")
        service = KernelService()
        assert service._initrd_path("k1") == str(patched_kernel_dir / "k1.initrd")

    def test_no_initrd_returns_none(self, patched_kernel_dir: Path):
        service = KernelService()
        assert service._initrd_path("k1") is None


class TestKernelInfo:
    def test_with_sidecar(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "k1").write_bytes(b"binary")
        (patched_kernel_dir / "k1.json").write_text(json.dumps({
            "architecture": "mips",
            "description": "fancy",
            "uploaded_at": "2026-05-06T00:00:00+00:00",
        }))
        service = KernelService()
        info = service._kernel_info("k1")
        assert info["name"] == "k1"
        assert info["architecture"] == "mips"
        assert info["description"] == "fancy"
        assert info["uploaded_at"] == "2026-05-06T00:00:00+00:00"
        assert info["file_size"] == len(b"binary")
        assert info["has_initrd"] is False

    def test_without_sidecar_uses_arch_guess(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "vmlinuz-arm64").write_bytes(b"binary")
        service = KernelService()
        info = service._kernel_info("vmlinuz-arm64")
        assert info["architecture"] == "aarch64"  # arm64 → aarch64
        assert info["description"] == ""

    def test_oserror_on_stat_returns_zero_size(self, patched_kernel_dir: Path):
        # No file, no sidecar → graceful fallback.
        service = KernelService()
        info = service._kernel_info("missing")
        assert info["file_size"] == 0
        assert info["architecture"] == "unknown"
        assert info["has_initrd"] is False


# ===========================================================================
# list_kernels / get_kernel / find_kernel_for_arch
# ===========================================================================


class TestListKernels:
    def test_filters_sidecars_and_initrds_and_hidden(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "alpha").write_bytes(b"a")
        (patched_kernel_dir / "alpha.json").write_text("{}")
        (patched_kernel_dir / "alpha.initrd").write_bytes(b"i")
        (patched_kernel_dir / ".hidden").write_bytes(b"h")
        (patched_kernel_dir / "subdir").mkdir()
        (patched_kernel_dir / "beta").write_bytes(b"b")

        service = KernelService()
        kernels = service.list_kernels()
        names = [k["name"] for k in kernels]
        assert names == ["alpha", "beta"]  # sorted, sidecars/initrds/hidden/dirs filtered

    def test_architecture_filter(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "vmlinux-arm").write_bytes(b"a")
        (patched_kernel_dir / "vmlinux-mips").write_bytes(b"m")
        (patched_kernel_dir / "vmlinux-x86_64").write_bytes(b"x")
        service = KernelService()
        mips = service.list_kernels(architecture="mips")
        assert [k["name"] for k in mips] == ["vmlinux-mips"]

    def test_missing_kernel_dir_returns_empty(self, tmp_path: Path):
        # Use a path that does NOT exist.
        nonexistent = tmp_path / "absent"
        fake_settings = MagicMock()
        fake_settings.emulation_kernel_dir = str(nonexistent)
        with patch.object(ks_mod, "get_settings", lambda: fake_settings):
            service = KernelService()
            assert service.list_kernels() == []


class TestGetKernel:
    def test_validates_name_first(self, patched_kernel_dir: Path):
        service = KernelService()
        with pytest.raises(ValueError, match="must not contain"):
            service.get_kernel("etc/passwd")

    def test_missing_kernel_raises(self, patched_kernel_dir: Path):
        service = KernelService()
        with pytest.raises(ValueError, match="not found"):
            service.get_kernel("absent")

    def test_returns_info_dict(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "k1").write_bytes(b"bin")
        service = KernelService()
        info = service.get_kernel("k1")
        assert info["name"] == "k1"


class TestFindKernelForArch:
    def test_returns_first_match(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "vmlinux-arm-A").write_bytes(b"a")
        (patched_kernel_dir / "vmlinux-arm-B").write_bytes(b"b")
        service = KernelService()
        result = service.find_kernel_for_arch("arm")
        assert result is not None
        assert result["name"] == "vmlinux-arm-A"  # sorted alphabetically, first wins

    def test_no_match_returns_none(self, patched_kernel_dir: Path):
        service = KernelService()
        assert service.find_kernel_for_arch("riscv") is None


# ===========================================================================
# upload_kernel / upload_initrd / delete_kernel
# ===========================================================================


class TestUploadKernel:
    @pytest.mark.asyncio
    async def test_validates_name(self, patched_kernel_dir: Path):
        service = KernelService()
        with pytest.raises(ValueError, match="must not contain"):
            await service.upload_kernel("bad/path", "arm", "", b"x")

    @pytest.mark.asyncio
    async def test_unsupported_architecture_rejected(self, patched_kernel_dir: Path):
        service = KernelService()
        with pytest.raises(ValueError, match="Unsupported architecture 'z80'"):
            await service.upload_kernel("k1", "z80", "", b"x")

    @pytest.mark.asyncio
    async def test_already_exists_rejected(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "k1").write_bytes(b"x")
        service = KernelService()
        with pytest.raises(ValueError, match="already exists"):
            await service.upload_kernel("k1", "arm", "", b"x")

    @pytest.mark.asyncio
    async def test_writes_binary_and_sidecar(self, patched_kernel_dir: Path):
        service = KernelService()
        info = await service.upload_kernel("vmlinuz-arm", "arm", "test", b"binary content")

        # Binary written.
        kernel_path = patched_kernel_dir / "vmlinuz-arm"
        assert kernel_path.read_bytes() == b"binary content"
        # Sidecar JSON written with all 3 fields.
        sidecar = json.loads((patched_kernel_dir / "vmlinuz-arm.json").read_text())
        assert sidecar["architecture"] == "arm"
        assert sidecar["description"] == "test"
        assert "uploaded_at" in sidecar
        # Returned info round-trips the upload.
        assert info["architecture"] == "arm"
        assert info["description"] == "test"
        assert info["file_size"] == len(b"binary content")


class TestUploadInitrd:
    @pytest.mark.asyncio
    async def test_kernel_must_exist(self, patched_kernel_dir: Path):
        service = KernelService()
        with pytest.raises(ValueError, match="not found"):
            await service.upload_initrd("absent", b"initrd")

    @pytest.mark.asyncio
    async def test_writes_initrd_and_updates_sidecar(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "k1").write_bytes(b"k")
        (patched_kernel_dir / "k1.json").write_text(json.dumps({"architecture": "arm"}))
        service = KernelService()
        await service.upload_initrd("k1", b"initrd-bytes")

        assert (patched_kernel_dir / "k1.initrd").read_bytes() == b"initrd-bytes"
        sidecar = json.loads((patched_kernel_dir / "k1.json").read_text())
        assert sidecar["initrd"] == "k1.initrd"
        # Original architecture key preserved.
        assert sidecar["architecture"] == "arm"

    @pytest.mark.asyncio
    async def test_writes_initrd_when_sidecar_missing(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "k1").write_bytes(b"k")
        service = KernelService()
        await service.upload_initrd("k1", b"initrd-bytes")

        # Sidecar created with just the initrd key.
        sidecar = json.loads((patched_kernel_dir / "k1.json").read_text())
        assert sidecar == {"initrd": "k1.initrd"}


class TestDeleteKernel:
    def test_validates_name(self, patched_kernel_dir: Path):
        service = KernelService()
        with pytest.raises(ValueError, match="must not contain"):
            service.delete_kernel("etc/passwd")

    def test_missing_kernel_raises(self, patched_kernel_dir: Path):
        service = KernelService()
        with pytest.raises(ValueError, match="not found"):
            service.delete_kernel("absent")

    def test_removes_binary_and_sidecar(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "k1").write_bytes(b"x")
        (patched_kernel_dir / "k1.json").write_text("{}")
        service = KernelService()
        service.delete_kernel("k1")
        assert not (patched_kernel_dir / "k1").exists()
        assert not (patched_kernel_dir / "k1.json").exists()

    def test_removes_binary_when_sidecar_absent(self, patched_kernel_dir: Path):
        (patched_kernel_dir / "k1").write_bytes(b"x")
        service = KernelService()
        service.delete_kernel("k1")
        assert not (patched_kernel_dir / "k1").exists()


# ===========================================================================
# download_kernel — httpx happy path + error matrix
# ===========================================================================


def _build_mock_streaming_client(chunks: list[bytes], status_code: int = 200):
    """Construct a context-manager AsyncMock that mimics httpx.AsyncClient
    with a streaming response of the supplied chunks."""
    response = AsyncMock()
    response.raise_for_status = MagicMock()
    if status_code != 200:
        import httpx
        err = httpx.HTTPStatusError(
            f"HTTP {status_code}",
            request=MagicMock(),
            response=MagicMock(status_code=status_code),
        )
        response.raise_for_status = MagicMock(side_effect=err)

    async def aiter_bytes(chunk_size: int = 65536):
        for c in chunks:
            yield c

    response.aiter_bytes = aiter_bytes

    stream_cm = AsyncMock()
    stream_cm.__aenter__ = AsyncMock(return_value=response)
    stream_cm.__aexit__ = AsyncMock(return_value=None)

    client = AsyncMock()
    client.stream = MagicMock(return_value=stream_cm)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


class TestDownloadKernel:
    @pytest.mark.asyncio
    async def test_happy_path_validates_writes_kernel(
        self, patched_kernel_dir: Path,
    ):
        kernel_bytes = _real_kernel_bytes()
        public_addr = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))]

        with patch.object(
            ks_mod.socket, "getaddrinfo", return_value=public_addr,
        ), patch.object(
            ks_mod.httpx, "AsyncClient",
            return_value=_build_mock_streaming_client([kernel_bytes]),
        ):
            service = KernelService()
            info = await service.download_kernel(
                url="https://kernels.example.com/uImage",
                name="uImage",
                architecture="arm",
                description="downloaded",
            )

        assert info["name"] == "uImage"
        assert info["architecture"] == "arm"
        # Kernel binary written.
        assert (patched_kernel_dir / "uImage").read_bytes() == kernel_bytes
        # Sidecar contains the source_url for provenance.
        sidecar = json.loads((patched_kernel_dir / "uImage.json").read_text())
        assert sidecar["source_url"] == "https://kernels.example.com/uImage"
        assert sidecar["architecture"] == "arm"

    @pytest.mark.asyncio
    async def test_http_error_wrapped_as_value_error(
        self, patched_kernel_dir: Path,
    ):
        public_addr = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))]
        with patch.object(
            ks_mod.socket, "getaddrinfo", return_value=public_addr,
        ), patch.object(
            ks_mod.httpx, "AsyncClient",
            return_value=_build_mock_streaming_client([], status_code=404),
        ):
            service = KernelService()
            with pytest.raises(ValueError, match="HTTP 404"):
                await service.download_kernel(
                    url="https://kernels.example.com/missing",
                    name="absent",
                    architecture="arm",
                )

    @pytest.mark.asyncio
    async def test_size_cap_exceeded(self, patched_kernel_dir: Path):
        # 2MB of data with a 1MB cap.
        chunks = [b"\x00" * (512 * 1024) for _ in range(4)]
        public_addr = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))]
        with patch.object(
            ks_mod.socket, "getaddrinfo", return_value=public_addr,
        ), patch.object(
            ks_mod.httpx, "AsyncClient",
            return_value=_build_mock_streaming_client(chunks),
        ):
            service = KernelService()
            with pytest.raises(ValueError, match="exceeds maximum size"):
                await service.download_kernel(
                    url="https://kernels.example.com/big",
                    name="big",
                    architecture="arm",
                    max_size_bytes=1024 * 1024,
                )

    @pytest.mark.asyncio
    async def test_empty_download_rejected(self, patched_kernel_dir: Path):
        public_addr = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))]
        with patch.object(
            ks_mod.socket, "getaddrinfo", return_value=public_addr,
        ), patch.object(
            ks_mod.httpx, "AsyncClient",
            return_value=_build_mock_streaming_client([]),
        ):
            service = KernelService()
            with pytest.raises(ValueError, match="Downloaded file is empty"):
                await service.download_kernel(
                    url="https://kernels.example.com/zero",
                    name="zero",
                    architecture="arm",
                )

    @pytest.mark.asyncio
    async def test_invalid_kernel_format_rejected(
        self, patched_kernel_dir: Path,
    ):
        # A 600KB blob that does NOT match any kernel format magic.
        garbage = b"\xaa" * 600_000
        public_addr = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))]
        with patch.object(
            ks_mod.socket, "getaddrinfo", return_value=public_addr,
        ), patch.object(
            ks_mod.httpx, "AsyncClient",
            return_value=_build_mock_streaming_client([garbage]),
        ):
            service = KernelService()
            with pytest.raises(ValueError, match="not a valid kernel"):
                await service.download_kernel(
                    url="https://kernels.example.com/junk",
                    name="junk",
                    architecture="arm",
                )

    @pytest.mark.asyncio
    async def test_request_error_wrapped_as_value_error(
        self, patched_kernel_dir: Path,
    ):
        import httpx
        public_addr = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))]

        # Build a client whose stream raises RequestError.
        client = AsyncMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        client.stream = MagicMock(side_effect=httpx.RequestError("boom", request=MagicMock()))

        with patch.object(
            ks_mod.socket, "getaddrinfo", return_value=public_addr,
        ), patch.object(
            ks_mod.httpx, "AsyncClient", return_value=client,
        ):
            service = KernelService()
            with pytest.raises(ValueError, match="Failed to download kernel: boom"):
                await service.download_kernel(
                    url="https://kernels.example.com/timeout",
                    name="timeout",
                    architecture="arm",
                )


# ===========================================================================
# Rule #35b LIVE-CANARY — full upload → list → get → delete cycle
# ===========================================================================


class TestKernelLifecycleLiveCanary:
    """Rule #35b live canary: real on-disk filesystem state through a full
    upload → list → get → delete cycle. The "DB" here is the filesystem;
    the value-flow contract is "upload writes binary + sidecar with all
    fields → list reads them back with file_size + arch + description +
    has_initrd populated → get returns the same info → delete removes
    BOTH artefacts atomically".

    Mock-only tests cannot fail on:
    * sidecar fields written under wrong keys (e.g. ``arch`` vs
      ``architecture``);
    * binary written under the wrong filename;
    * the ``.initrd`` companion path being computed against a stale
      pattern;
    * delete leaving an orphaned ``<name>.json`` after removing the
      binary.
    """

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, patched_kernel_dir: Path):
        service = KernelService()

        # Upload a kernel.
        info_after_upload = await service.upload_kernel(
            name="vmlinuz-canary",
            architecture="aarch64",
            description="canary kernel",
            file_data=b"kernel-bytes-here",
        )
        assert info_after_upload["architecture"] == "aarch64"

        # Disk state matches.
        assert (patched_kernel_dir / "vmlinuz-canary").read_bytes() == b"kernel-bytes-here"
        sidecar = json.loads((patched_kernel_dir / "vmlinuz-canary.json").read_text())
        assert sidecar["architecture"] == "aarch64"
        assert sidecar["description"] == "canary kernel"

        # Upload a companion initrd.
        await service.upload_initrd(
            kernel_name="vmlinuz-canary",
            file_data=b"initrd-bytes",
        )
        # Sidecar updated.
        sidecar2 = json.loads((patched_kernel_dir / "vmlinuz-canary.json").read_text())
        assert sidecar2["initrd"] == "vmlinuz-canary.initrd"
        # Initrd written.
        assert (patched_kernel_dir / "vmlinuz-canary.initrd").read_bytes() == b"initrd-bytes"

        # list_kernels reflects the upload + initrd.
        listing = service.list_kernels()
        assert len(listing) == 1
        entry = listing[0]
        assert entry["name"] == "vmlinuz-canary"
        assert entry["architecture"] == "aarch64"
        assert entry["description"] == "canary kernel"
        assert entry["file_size"] == len(b"kernel-bytes-here")
        assert entry["has_initrd"] is True

        # Architecture filter restricts.
        assert service.list_kernels(architecture="aarch64") == listing
        assert service.list_kernels(architecture="x86") == []

        # get_kernel matches list output.
        got = service.get_kernel("vmlinuz-canary")
        assert got == entry

        # find_kernel_for_arch returns the entry.
        found = service.find_kernel_for_arch("aarch64")
        assert found is not None
        assert found["name"] == "vmlinuz-canary"

        # Delete removes binary AND sidecar.
        service.delete_kernel("vmlinuz-canary")
        assert not (patched_kernel_dir / "vmlinuz-canary").exists()
        assert not (patched_kernel_dir / "vmlinuz-canary.json").exists()
        # Note: .initrd companion is intentionally NOT removed (production
        # behavior — the contract is symmetric upload-vs-delete on the
        # binary + sidecar pair, not on companions; see line 255-266).
        # If this contract changes, the assertion below should flip.
        assert (patched_kernel_dir / "vmlinuz-canary.initrd").exists()
