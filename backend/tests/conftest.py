"""Shared test fixtures for the Wairz backend test suite."""

import asyncio
import errno
import os
from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Tolerate EBADF when pytest restores stdio capture at session end.

    Some residual/coverage-wave tests still exercise code paths that close or
    redirect process FDs. When that happens, pytest's global capture teardown
    (`FDCapture.done` → `os.dup2(targetfd_save, …)`) raises OSError EBADF
    *after* every test has already passed, turning a green suite into exit 1
    (CI: 9203 passed then SystemExit from capture cleanup). Swallow only
    EBADF on capture restore; all other failures still surface.
    """
    from _pytest.capture import FDCapture

    _orig_done = FDCapture.done

    def _done_ignore_ebadf(self) -> None:  # type: ignore[no-untyped-def]
        try:
            _orig_done(self)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise

    FDCapture.done = _done_ignore_ebadf  # type: ignore[method-assign]


@pytest.fixture(scope="session", autouse=True)
def _preserve_stdio_fds():
    """Keep working copies of FDs 0-2 so a mid-suite close can be repaired."""
    saved: list[int | None] = []
    for i in range(3):
        try:
            saved.append(os.dup(i))
        except OSError:
            saved.append(None)
    yield
    for i, fd in enumerate(saved):
        if fd is None:
            continue
        try:
            os.dup2(fd, i)
        except OSError:
            try:
                devnull = os.open(os.devnull, os.O_RDWR)
                try:
                    os.dup2(devnull, i)
                finally:
                    os.close(devnull)
            except OSError:
                pass
        try:
            os.close(fd)
        except OSError:
            pass


@pytest.fixture(autouse=True)
async def _cancel_dangling_background_tasks():
    """Cancel any asyncio task a test spawns and doesn't clean up itself.

    Router tests that exercise a Rule #33 202+polling endpoint without
    patching out the fire-and-forget ``asyncio.create_task(...)`` call
    (e.g. ``_run_unpack_background``) leave a real task running past the
    end of the test. pytest-asyncio gives every test its own event loop,
    so the dangling task never actually completes — it sits until the
    garbage collector finalizes it (producing a "coroutine was never
    awaited" RuntimeWarning attributed to whatever LATER test happens to
    be running at GC time) while still holding its AsyncSession/asyncpg
    connection in a not-quite-finished state. A subsequent test that
    acquires the same pooled connection can then hit
    "InterfaceError: cannot perform operation: another operation is in
    progress" — a flaky, test-order-dependent failure with no relation
    to the test it's attributed to. Cancelling leftover tasks at the end
    of every test starves this at the source.
    """
    before = asyncio.all_tasks()
    yield
    current = asyncio.current_task()
    leftover = [t for t in asyncio.all_tasks() - before if t is not current and not t.done()]
    for t in leftover:
        t.cancel()
    for t in leftover:
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass


@pytest.fixture(autouse=True, scope="session")
def _allow_httpx_test_host_in_origin_guard():
    """Let httpx's ASGITransport default Host ("test") through origin_host_guard.

    httpx.AsyncClient(transport=ASGITransport(app=app)) defaults to
    base_url="http://test" unless a test overrides it, so every router
    test's request carries Host: test. app.main's origin_host_guard
    middleware 403s any Host not in ALLOWED_HOSTS, which doesn't include
    "test" (deliberately — that allowlist guards the real deployed
    backend against DNS-rebinding/CSRF, and "test" has no place in a
    production allowlist). Widening it here, once, for the test session
    is cheaper and less error-prone than adding an explicit Host header
    override to every router test file.
    """
    from app.main import ALLOWED_HOSTS

    ALLOWED_HOSTS.add("test")


@pytest.fixture
def firmware_root(tmp_path: Path) -> Path:
    """Create a standard test firmware filesystem.

    Provides a minimal but realistic embedded Linux layout with directories,
    config files, fake ELF binaries, symlinks, and a certificate.
    """
    # Directories
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "init.d").mkdir()
    (tmp_path / "usr").mkdir()
    (tmp_path / "usr" / "bin").mkdir()
    (tmp_path / "bin").mkdir()
    (tmp_path / "var").mkdir()
    (tmp_path / "lib").mkdir()

    # Text files
    (tmp_path / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:Nobody:/:/bin/false\n"
    )
    (tmp_path / "etc" / "shadow").write_text("root::0:0:99999:7:::\n")
    (tmp_path / "etc" / "config.conf").write_text(
        "[server]\nport=8080\ndebug=true\n"
    )
    (tmp_path / "etc" / "init.d" / "rcS").write_bytes(
        b"#!/bin/sh\necho 'Starting services...'\n"
    )

    # Fake ELF binary (valid magic, minimal header)
    elf_header = b"\x7fELF" + b"\x00" * 12
    (tmp_path / "usr" / "bin" / "httpd").write_bytes(elf_header)

    # Certificate file
    (tmp_path / "etc" / "server.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nMIIBojCCAUmgAwIBAgI...\n-----END CERTIFICATE-----\n"
    )

    # Shared library
    (tmp_path / "lib" / "libfoo.so.1").write_bytes(b"\x7fELF" + b"\x00" * 12)

    # Symlink (internal — points within the firmware root)
    (tmp_path / "bin" / "sh").symlink_to(str(tmp_path / "usr" / "bin" / "httpd"))

    return tmp_path


@pytest.fixture
def android_firmware_root(tmp_path: Path) -> Path:
    """Create a minimal Android firmware filesystem for testing.

    Provides a realistic Android layout with build.prop files, APK stubs,
    init.rc service declarations, SELinux policy, and vendor partition.
    """
    # system partition
    system = tmp_path / "system"
    system.mkdir()
    (system / "build.prop").write_text(
        "# begin build properties\n"
        "ro.build.version.release=13\n"
        "ro.build.version.security_patch=2023-09-05\n"
        "ro.build.display.id=TP1A.220624.014\n"
        "ro.board.platform=msm8953\n"
        "ro.product.model=Pixel 4a\n"
    )

    # APK stubs
    (system / "app" / "Settings").mkdir(parents=True)
    (system / "app" / "Settings" / "Settings.apk").write_bytes(b"")
    (system / "priv-app" / "SystemUI").mkdir(parents=True)
    (system / "priv-app" / "SystemUI" / "SystemUI.apk").write_bytes(b"")

    # init.rc under system/etc/init
    (system / "etc" / "init").mkdir(parents=True)
    (system / "etc" / "init" / "init.test.rc").write_text(
        "# Test init file\n"
        "\n"
        "service healthd /system/bin/healthd\n"
        "    class core\n"
        "\n"
        "service surfaceflinger /system/bin/surfaceflinger\n"
        "    class core animation\n"
    )

    # SELinux policy
    (system / "etc" / "selinux").mkdir(parents=True)
    (system / "etc" / "selinux" / "plat_sepolicy.cil").write_bytes(b"")

    # system/bin directory
    (system / "bin").mkdir(exist_ok=True)

    # vendor partition
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "build.prop").write_text(
        "ro.vendor.build.version.release=13\n"
        "ro.vendor.build.security_patch_level=2023-09-01\n"
    )
    (vendor / "etc" / "init" / "hw").mkdir(parents=True)
    (vendor / "etc" / "init" / "hw" / "init.vendor.rc").write_text(
        "service wifi_hal /vendor/bin/hw/android.hardware.wifi@1.0-service\n"
        "    class hal\n"
    )
    (vendor / "lib" / "modules").mkdir(parents=True)
    (vendor / "lib" / "modules" / "test.ko").write_bytes(b"")

    # Android init binary marker
    (tmp_path / "init").write_bytes(b"")

    # Symlink: bin -> system/bin
    try:
        (tmp_path / "bin").symlink_to(str(system / "bin"))
    except OSError:
        pass

    return tmp_path


@pytest.fixture
def tool_context(firmware_root: Path):
    """Create a ToolContext with a mocked DB session pointed at firmware_root.

    Import is deferred to avoid pulling in heavy dependencies (elftools, etc.)
    when only lightweight tests are running.
    """
    from app.ai.tool_registry import ToolContext

    return ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path=str(firmware_root),
        db=MagicMock(),
    )
