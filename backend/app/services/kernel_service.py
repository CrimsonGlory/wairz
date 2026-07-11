"""Service for managing pre-built Linux kernels for system-mode emulation.

Kernels are a global resource (not per-project). The filesystem is the source
of truth -- no database table needed. JSON sidecar files store metadata
alongside each kernel binary.
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import tempfile
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import aiofiles
import httpx

from app.config import get_settings
from app.services.emulation_constants import _validate_kernel_file
from app.utils.log_sanitize import sanitize_for_log

logger = logging.getLogger(__name__)

SUPPORTED_ARCHITECTURES = {"arm", "aarch64", "mips", "mipsel", "x86", "x86_64"}

# Patterns for guessing architecture from filename (order matters: check
# more-specific names first to avoid "mips" matching "mipsel").
_ARCH_PATTERNS: list[tuple[str, str]] = [
    ("mipsel", "mipsel"),
    ("mips", "mips"),
    ("aarch64", "aarch64"),
    ("arm64", "aarch64"),
    ("arm", "arm"),
    ("x86_64", "x86_64"),
    ("x86", "x86"),
    ("i386", "x86"),
]


def _guess_arch(filename: str) -> str | None:
    """Heuristic: guess architecture from a kernel filename."""
    lower = filename.lower()
    for pattern, arch in _ARCH_PATTERNS:
        if pattern in lower:
            return arch
    return None


def _validate_kernel_name(name: str) -> None:
    """Raise ValueError if name contains disallowed characters."""
    if not name or not name.strip():
        raise ValueError("Kernel name must not be empty")
    if name.startswith("."):
        raise ValueError("Kernel name must not start with '.'")
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError("Kernel name must not contain '/', '\\', or '..'")
    if not re.match(r"^[a-zA-Z0-9._-]+$", name):
        raise ValueError(
            "Kernel name may only contain alphanumeric characters, "
            "hyphens, underscores, and dots"
        )


def _validate_download_url(url: str) -> None:
    """Validate a URL for safe downloading (SSRF prevention).

    Rejects private/loopback/link-local IPs, non-HTTP(S) schemes,
    and malformed URLs.
    """
    if len(url) > 2048:
        raise ValueError("URL too long (max 2048 characters)")

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Unsupported URL scheme '{parsed.scheme}' — only http and https are allowed"
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")

    # Resolve hostname and check all returned IPs
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname '{hostname}': {exc}") from exc

    if not addr_infos:
        raise ValueError(f"Hostname '{hostname}' did not resolve to any address")

    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError(
                f"URL resolves to non-public IP address ({ip_str}) — "
                "downloads from private/loopback/link-local networks are blocked"
            )


class KernelService:
    """Manages pre-built Linux kernels on the local filesystem."""

    def __init__(self) -> None:
        self._kernel_dir = get_settings().emulation_kernel_dir

    def _kernel_path(self, name: str) -> str:
        return os.path.join(self._kernel_dir, name)

    def _sidecar_path(self, name: str) -> str:
        return os.path.join(self._kernel_dir, f"{name}.json")

    def _read_sidecar(self, name: str) -> dict | None:
        path = self._sidecar_path(name)
        if not os.path.isfile(path):
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to read sidecar for kernel %s", sanitize_for_log(name))
            return None

    def _initrd_path(self, kernel_name: str) -> str | None:
        """Return the path to a kernel's companion initrd, if it exists.

        Checks the sidecar JSON for an explicit 'initrd' field, then
        falls back to the convention: <kernel_name>.initrd
        """
        sidecar = self._read_sidecar(kernel_name)
        if sidecar and sidecar.get("initrd"):
            initrd_name = sidecar["initrd"]
            path = os.path.join(self._kernel_dir, initrd_name)
            if os.path.isfile(path):
                return path

        # Convention fallback
        path = os.path.join(self._kernel_dir, f"{kernel_name}.initrd")
        if os.path.isfile(path):
            return path

        return None

    def _dtb_path(self, kernel_name: str) -> str | None:
        """Return the path to a kernel's companion device-tree blob, if any.

        Checks the sidecar JSON for an explicit 'dtb' field, then falls back to
        the convention: <kernel_name>.dtb. DT-only kernels (e.g. the bundled
        dhruvvyas90 buster RPi kernel) need a matching dtb passed via -dtb or
        they fail with "invalid dtb and unrecognized/unsupported machine ID".
        """
        sidecar = self._read_sidecar(kernel_name)
        if sidecar and sidecar.get("dtb"):
            path = os.path.join(self._kernel_dir, sidecar["dtb"])
            if os.path.isfile(path):
                return path

        # Convention fallback
        path = os.path.join(self._kernel_dir, f"{kernel_name}.dtb")
        if os.path.isfile(path):
            return path

        return None

    def _kernel_info(self, name: str) -> dict:
        """Build kernel info dict for a single kernel."""
        kernel_path = self._kernel_path(name)
        sidecar = self._read_sidecar(name)

        try:
            stat = os.stat(kernel_path)
            file_size = stat.st_size
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat()
        except OSError:
            file_size = 0
            mtime = datetime.now(UTC).isoformat()

        if sidecar:
            architecture = sidecar.get("architecture", _guess_arch(name) or "unknown")
            description = sidecar.get("description", "")
            uploaded_at = sidecar.get("uploaded_at", mtime)
        else:
            architecture = _guess_arch(name) or "unknown"
            description = ""
            uploaded_at = mtime

        # Check for companion initrd / device-tree blob
        has_initrd = self._initrd_path(name) is not None
        has_dtb = self._dtb_path(name) is not None

        return {
            "name": name,
            "architecture": architecture,
            "description": description,
            "file_size": file_size,
            "uploaded_at": uploaded_at,
            "has_initrd": has_initrd,
            "has_dtb": has_dtb,
            # Optional QEMU board this kernel targets (e.g. "virt",
            # "versatilepb"); used to steer board selection (feedback #5).
            "machine": (sidecar or {}).get("machine"),
        }

    def list_kernels(self, architecture: str | None = None) -> list[dict]:
        """List all available kernels, optionally filtered by architecture."""
        if not os.path.isdir(self._kernel_dir):
            return []

        kernels = []
        for entry in os.scandir(self._kernel_dir):
            # Skip sidecar JSON files, initrd companions, hidden files, directories
            if entry.name.startswith("."):
                continue
            if entry.name.endswith(".json"):
                continue
            if entry.name.endswith((".initrd", ".dtb")):
                continue
            if not entry.is_file():
                continue

            info = self._kernel_info(entry.name)

            if architecture and info["architecture"] != architecture:
                continue

            kernels.append(info)

        kernels.sort(key=lambda k: k["name"])
        return kernels

    async def upload_kernel(
        self,
        name: str,
        architecture: str,
        description: str,
        file_data: bytes,
    ) -> dict:
        """Write a kernel binary + sidecar JSON."""
        _validate_kernel_name(name)

        if architecture not in SUPPORTED_ARCHITECTURES:
            raise ValueError(
                f"Unsupported architecture '{architecture}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_ARCHITECTURES))}"
            )

        kernel_path = self._kernel_path(name)
        loop = asyncio.get_running_loop()
        if await loop.run_in_executor(None, os.path.exists, kernel_path):
            raise ValueError(f"Kernel '{name}' already exists")

        await loop.run_in_executor(
            None, lambda: os.makedirs(self._kernel_dir, exist_ok=True),
        )

        # Write binary
        async with aiofiles.open(kernel_path, "wb") as f:
            await f.write(file_data)

        # Write sidecar metadata
        sidecar = {
            "architecture": architecture,
            "description": description,
            "uploaded_at": datetime.now(UTC).isoformat(),
        }
        async with aiofiles.open(self._sidecar_path(name), "w") as f:
            await f.write(json.dumps(sidecar, indent=2))

        return self._kernel_info(name)

    def delete_kernel(self, name: str) -> None:
        """Delete a kernel binary and its sidecar."""
        _validate_kernel_name(name)
        kernel_path = self._kernel_path(name)
        if not os.path.isfile(kernel_path):
            raise ValueError(f"Kernel '{name}' not found")

        os.remove(kernel_path)

        sidecar_path = self._sidecar_path(name)
        if os.path.isfile(sidecar_path):
            os.remove(sidecar_path)

    def find_kernel_for_arch(
        self, architecture: str, prefer_machine: str | None = None
    ) -> dict | None:
        """Return a kernel matching the given architecture, or None.

        When ``prefer_machine`` is set (e.g. "virt" for an ARMv7/hard-float
        userland that can't run on the ARMv5/v6 versatilepb board), a kernel
        whose sidecar declares that machine wins over the alphabetical first
        match. This is how an armhf image is steered to the armvirt kernel
        instead of a Raspberry-Pi/versatile one (feedback #5).
        """
        kernels = self.list_kernels(architecture=architecture)
        if not kernels:
            return None
        if prefer_machine:
            for k in kernels:
                if (k.get("machine") or "").lower() == prefer_machine.lower():
                    return k
        return kernels[0]

    def get_kernel_meta(self, name: str) -> dict:
        """Return the board/boot hints a kernel's sidecar declares, or {}.

        Recognised keys: ``machine``, ``cpu``, ``drive_interface``,
        ``root_dev``, ``mem`` (and ``console``). These let a kernel describe
        the QEMU machine it was built for so the emulation service can pick
        matching board defaults without the agent specifying them. Unknown
        kernels (e.g. firmware-extracted) simply return {}.
        """
        try:
            _validate_kernel_name(name)
        except ValueError:
            return {}
        sidecar = self._read_sidecar(name)
        if not sidecar:
            return {}
        meta: dict = {}
        for key in ("machine", "cpu", "drive_interface", "root_dev", "console"):
            val = sidecar.get(key)
            if val:
                meta[key] = val
        if isinstance(sidecar.get("mem"), int):
            meta["mem"] = sidecar["mem"]
        return meta

    async def upload_initrd(
        self,
        kernel_name: str,
        file_data: bytes,
    ) -> dict:
        """Upload an initrd/initramfs to pair with an existing kernel."""
        _validate_kernel_name(kernel_name)
        kernel_path = self._kernel_path(kernel_name)
        loop = asyncio.get_running_loop()
        if not await loop.run_in_executor(None, os.path.isfile, kernel_path):
            raise ValueError(f"Kernel '{kernel_name}' not found")

        initrd_name = f"{kernel_name}.initrd"
        initrd_path = os.path.join(self._kernel_dir, initrd_name)

        async with aiofiles.open(initrd_path, "wb") as f:
            await f.write(file_data)

        # Update sidecar to reference the initrd. The existence check +
        # JSON read is a single sync helper offloaded via run_in_executor
        # (Rule #5) — same shape as Phase C's `_extract_boot_img_sync`.
        sidecar_path = self._sidecar_path(kernel_name)

        def _load_sidecar_sync(path: str) -> dict:
            if not os.path.isfile(path):
                return {}
            try:
                with open(path) as fh:
                    return json.load(fh)
            except (json.JSONDecodeError, OSError):
                return {}

        sidecar = await loop.run_in_executor(None, _load_sidecar_sync, sidecar_path)
        sidecar["initrd"] = initrd_name
        async with aiofiles.open(sidecar_path, "w") as f:
            await f.write(json.dumps(sidecar, indent=2))

        logger.info("Uploaded initrd %s for kernel %s (%s bytes)",
                     sanitize_for_log(initrd_name), sanitize_for_log(kernel_name), sanitize_for_log(len(file_data)))
        return self._kernel_info(kernel_name)

    async def download_kernel(
        self,
        url: str,
        name: str,
        architecture: str,
        description: str = "",
        max_size_bytes: int = 100 * 1024 * 1024,
        timeout_seconds: int = 120,
    ) -> dict:
        """Download a kernel from a URL, validate it, and install it.

        Includes SSRF prevention (blocks private/loopback IPs) and kernel
        format validation before saving.

        Returns the kernel info dict on success, raises ValueError on failure.
        """
        # --- URL validation ---
        _validate_download_url(url)

        # --- Download with streaming ---
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="kernel_dl_")
        os.close(tmp_fd)
        try:
            downloaded = await self._stream_download(
                url, tmp_path, max_size_bytes, timeout_seconds
            )
            if downloaded == 0:
                raise ValueError("Downloaded file is empty")

            # --- Validate kernel format ---
            is_valid, reason = _validate_kernel_file(tmp_path)
            if not is_valid:
                raise ValueError(f"Downloaded file is not a valid kernel: {reason}")

            # --- Read validated file and install via upload_kernel ---
            async with aiofiles.open(tmp_path, "rb") as f:
                file_data = await f.read()

            result = await self.upload_kernel(name, architecture, description, file_data)

            # Add download source to sidecar metadata. Single sync helper
            # offloaded via run_in_executor for the isfile+open pair (Rule #5).
            sidecar_path = self._sidecar_path(name)
            loop = asyncio.get_running_loop()

            def _read_sidecar_sync(path: str) -> dict | None:
                if not os.path.isfile(path):
                    return None
                with open(path) as fh:
                    return json.load(fh)

            sidecar = await loop.run_in_executor(
                None, _read_sidecar_sync, sidecar_path,
            )
            if sidecar is not None:
                sidecar["source_url"] = url
                async with aiofiles.open(sidecar_path, "w") as f:
                    await f.write(json.dumps(sidecar, indent=2))

            return result
        finally:
            cleanup_loop = asyncio.get_running_loop()

            def _cleanup_tmp_sync(path: str) -> None:
                if os.path.exists(path):
                    os.unlink(path)

            await cleanup_loop.run_in_executor(None, _cleanup_tmp_sync, tmp_path)

    async def _stream_download(
        self,
        url: str,
        dest_path: str,
        max_size_bytes: int,
        timeout_seconds: int,
    ) -> int:
        """Stream a URL to ``dest_path``, returning bytes written.

        Follows redirects MANUALLY so every hop — including cross-host
        redirects to regional mirrors (e.g. downloads.openwrt.org → a country
        mirror) — is re-validated against the SSRF policy before we connect to
        it. httpx's built-in follow_redirects would skip that re-check, and
        some mirrors 404 a request without a normal User-Agent.
        """
        headers = {"User-Agent": "wairz-kernel-downloader/1.0"}
        current = url
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=httpx.Timeout(timeout_seconds, connect=30.0),
                headers=headers,
            ) as client:
                for _hop in range(10):
                    _validate_download_url(current)
                    async with client.stream("GET", current) as response:
                        if response.is_redirect:
                            location = response.headers.get("location")
                            if not location:
                                raise ValueError(
                                    f"HTTP {response.status_code} redirect with no "
                                    f"Location header from {current}"
                                )
                            current = urljoin(current, location)
                            continue
                        response.raise_for_status()
                        downloaded = 0
                        async with aiofiles.open(dest_path, "wb") as f:
                            async for chunk in response.aiter_bytes(chunk_size=65536):
                                downloaded += len(chunk)
                                if downloaded > max_size_bytes:
                                    raise ValueError(
                                        f"Download exceeds maximum size "
                                        f"({max_size_bytes // (1024*1024)}MB)"
                                    )
                                await f.write(chunk)
                        return downloaded
                raise ValueError(f"Too many redirects downloading from {url}")
        except httpx.HTTPStatusError as exc:
            raise ValueError(
                f"HTTP {exc.response.status_code} downloading from {current}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValueError(f"Failed to download: {exc}") from exc
