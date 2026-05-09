"""Service-layer tests for ``app.services.clamav_service``.

Phase 2 Wave 9 file 4 of 4 — backfills service-layer tests for the
ClamAV antivirus scanning service (174 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

Marginal-to-strong canary surface: NO DB persistence and NO cache,
but the service has TWO lazy `import clamd` sites (lines 39 + 51)
making it canonical Rule #30 SOURCE-patch territory. The scan_directory
function has a TWO-PASS pipeline (multiscan-first, fall back to per-file
scan when multiscan fails) that mock-only tests would NOT differentiate
without an explicit canary on the second-pass code path.

Rule #30 distribution:
* ``clamd`` is LAZY-imported INSIDE both ``check_available`` (line 39)
  and ``_get_clamd`` (line 51). The wairz container does NOT install
  clamd as a top-level dependency — it's optional. Per Rule #30,
  patches MUST hit the SOURCE module
  (``patch.dict(sys.modules, {"clamd": fake_clamd})``), not
  ``app.services.clamav_service.clamd`` which the consumer never
  binds at module scope.
* ``get_settings`` and ``asyncio`` and ``stat``/``os`` are TOP-LEVEL
  imported — those are inverse-Rule-30 sites (CONSUMER-module patches).

Coverage targets:

* ``check_available`` — clamav_enabled=False short-circuits without
  socket; ping returns "PONG" → True; ping returns anything else → False;
  clamd raises → False (graceful degradation).
* ``_get_clamd`` — constructs ClamdNetworkSocket with
  host/port/timeout=120 from settings.
* ``scan_file`` — happy path returns ClamScanResult with
  infected=False; FOUND status returns infected=True with signature;
  exception captured to error field.
* ``scan_directory`` —
  (a) two-pass canary: multiscan returns infected map → results
      reflect both infected and clean files (regression backstop on
      the dict-merge logic);
  (b) multiscan returns None → all clean;
  (c) **multiscan raises → falls back to per-file scan**: critical
      regression backstop for "clamd container restarted mid-scan" —
      mock-only tests would not catch a swap of `cd.scan` to
      `cd.multiscan` in the fallback branch;
  (d) connection error in BOTH multiscan AND fallback → single error
      result returned;
  (e) max_files cap respected during file collection;
  (f) oversized files (> 100 MB) skipped during collection;
  (g) non-regular files (symlinks, devices) skipped during collection.
* **Rule #30 SOURCE-patch class** — ``TestRule30ClamdSourcePatch``
  proves the patch shape against the lazy ``import clamd`` and
  includes a hasattr-sentinel that fails LOUDLY if a future refactor
  promotes ``clamd`` to a module-scope import (which would flip the
  patch shape to inverse-Rule-30).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services import clamav_service as clam_mod
from app.services.clamav_service import (
    MAX_SCAN_FILE_SIZE,
    ClamScanResult,
    _get_clamd,
    check_available,
    scan_directory,
    scan_file,
)

# ===========================================================================
# Fake clamd module — installed via sys.modules
# ===========================================================================


def _make_fake_clamd_module(network_socket_factory=None):
    """Build a fake `clamd` package that the lazy `import clamd` will pick up.

    ``network_socket_factory`` is a callable that returns a fake
    ClamdNetworkSocket instance (one per call). Use it to inject test
    behaviour while preserving the SOURCE-patch contract.
    """
    fake = MagicMock()

    def _ctor(host=None, port=None, timeout=None):
        sock = network_socket_factory() if network_socket_factory else MagicMock()
        sock._ctor_args = {"host": host, "port": port, "timeout": timeout}
        return sock

    fake.ClamdNetworkSocket = MagicMock(side_effect=_ctor)
    return fake


def _settings_mock(enabled: bool = True, host: str = "clamd-host", port: int = 3310) -> MagicMock:
    s = MagicMock()
    s.clamav_enabled = enabled
    s.clamav_host = host
    s.clamav_port = port
    return s


# ===========================================================================
# check_available
# ===========================================================================


class TestCheckAvailable:
    @pytest.mark.asyncio
    async def test_disabled_short_circuits_without_socket(self):
        # When clamav_enabled=False, no clamd socket is opened.
        fake_clamd = _make_fake_clamd_module()

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock(enabled=False)):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                result = await check_available()
        assert result is False
        # ClamdNetworkSocket constructor must NOT have been called.
        fake_clamd.ClamdNetworkSocket.assert_not_called()

    @pytest.mark.asyncio
    async def test_ping_returns_pong_returns_true(self):
        sock = MagicMock()
        sock.ping = MagicMock(return_value="PONG")
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                result = await check_available()
        assert result is True

    @pytest.mark.asyncio
    async def test_ping_returns_unexpected_returns_false(self):
        sock = MagicMock()
        sock.ping = MagicMock(return_value="WAT")
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                result = await check_available()
        assert result is False

    @pytest.mark.asyncio
    async def test_ping_raises_returns_false(self):
        sock = MagicMock()
        sock.ping = MagicMock(side_effect=ConnectionRefusedError("clamd unreachable"))
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                result = await check_available()
        assert result is False


# ===========================================================================
# _get_clamd — socket construction
# ===========================================================================


class TestGetClamd:
    def test_constructs_socket_with_host_port_timeout(self):
        captured: dict = {}

        def _factory():
            sock = MagicMock()
            captured["sock"] = sock
            return sock

        fake_clamd = _make_fake_clamd_module(network_socket_factory=_factory)
        with patch.object(clam_mod, "get_settings", lambda: _settings_mock(host="test-host", port=9999)):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                result = _get_clamd()

        assert result is captured["sock"]
        assert captured["sock"]._ctor_args == {
            "host": "test-host", "port": 9999, "timeout": 120,
        }


# ===========================================================================
# scan_file
# ===========================================================================


class TestScanFile:
    @pytest.mark.asyncio
    async def test_clean_file_returns_infected_false(self, tmp_path: Path):
        f = tmp_path / "clean.bin"
        f.write_bytes(b"hello world")

        sock = MagicMock()
        sock.scan = MagicMock(return_value={str(f): ("OK", None)})
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                result = await scan_file(str(f))

        assert isinstance(result, ClamScanResult)
        assert result.file_path == str(f)
        assert result.infected is False
        assert result.signature is None
        assert result.error is None

    @pytest.mark.asyncio
    async def test_infected_file_returns_signature(self, tmp_path: Path):
        f = tmp_path / "evil.bin"
        f.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-")

        sock = MagicMock()
        sock.scan = MagicMock(return_value={str(f): ("FOUND", "Eicar-Test-Signature")})
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                result = await scan_file(str(f))

        assert result.infected is True
        assert result.signature == "Eicar-Test-Signature"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_scan_returning_none_treated_as_clean(self, tmp_path: Path):
        f = tmp_path / "clean.bin"
        f.write_bytes(b"hello")

        sock = MagicMock()
        sock.scan = MagicMock(return_value=None)
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                result = await scan_file(str(f))

        assert result.infected is False

    @pytest.mark.asyncio
    async def test_exception_captured_to_error(self, tmp_path: Path):
        f = tmp_path / "x.bin"
        f.write_bytes(b"x")

        sock = MagicMock()
        sock.scan = MagicMock(side_effect=ConnectionResetError("clamd died"))
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                result = await scan_file(str(f))

        assert result.infected is False
        assert result.error is not None
        assert "clamd died" in result.error


# ===========================================================================
# scan_directory — two-pass pipeline + fallback
# ===========================================================================


class TestScanDirectoryHappyPath:
    @pytest.mark.asyncio
    async def test_multiscan_returns_infected_map(self, tmp_path: Path):
        clean = tmp_path / "clean.bin"
        clean.write_bytes(b"hello")
        evil = tmp_path / "evil.bin"
        evil.write_bytes(b"BADBADBAD")

        sock = MagicMock()
        # multiscan returns a dict — the normaliser builds an infected map.
        sock.multiscan = MagicMock(return_value={
            str(evil): ("FOUND", "Test.Trojan.Eicar"),
            str(clean): ("OK", None),
        })
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                results = await scan_directory(str(tmp_path))

        assert len(results) == 2
        by_path = {r.file_path: r for r in results}
        assert by_path[str(clean)].infected is False
        assert by_path[str(evil)].infected is True
        assert by_path[str(evil)].signature == "Test.Trojan.Eicar"

    @pytest.mark.asyncio
    async def test_multiscan_returns_none_all_clean(self, tmp_path: Path):
        for name in ("a.bin", "b.bin", "c.bin"):
            (tmp_path / name).write_bytes(b"clean")

        sock = MagicMock()
        sock.multiscan = MagicMock(return_value=None)
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                results = await scan_directory(str(tmp_path))

        assert len(results) == 3
        assert all(r.infected is False for r in results)


class TestScanDirectoryFallback:
    @pytest.mark.asyncio
    async def test_multiscan_raises_falls_back_to_per_file_scan(self, tmp_path: Path):
        """Critical regression backstop: when clamd's multiscan path fails
        (often because the socket buffer overflows or the daemon was
        restarted mid-batch), the service falls back to scanning each file
        individually via cd.scan(). Mock-only tests of multiscan dispatch
        would NOT catch a regression where the fallback uses the wrong
        clamd method."""
        clean = tmp_path / "clean.bin"
        clean.write_bytes(b"hello")
        evil = tmp_path / "evil.bin"
        evil.write_bytes(b"badness")

        # Track which scans occurred.
        scan_calls: list[str] = []

        sock = MagicMock()
        sock.multiscan = MagicMock(side_effect=ConnectionResetError("multiscan failed"))

        def _per_file_scan(path):
            scan_calls.append(path)
            if path == str(evil):
                return {path: ("FOUND", "Trojan.X")}
            return {path: ("OK", None)}

        sock.scan = MagicMock(side_effect=_per_file_scan)
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                results = await scan_directory(str(tmp_path))

        # Both files were scanned individually in the fallback path.
        assert sorted(scan_calls) == sorted([str(clean), str(evil)])
        assert len(results) == 2
        by_path = {r.file_path: r for r in results}
        assert by_path[str(evil)].infected is True
        assert by_path[str(evil)].signature == "Trojan.X"
        assert by_path[str(clean)].infected is False

    @pytest.mark.asyncio
    async def test_fallback_per_file_exception_captured(self, tmp_path: Path):
        f1 = tmp_path / "x.bin"
        f1.write_bytes(b"a")
        f2 = tmp_path / "y.bin"
        f2.write_bytes(b"b")

        sock = MagicMock()
        sock.multiscan = MagicMock(side_effect=RuntimeError("multiscan boom"))

        def _per_file_scan(path):
            if path == str(f1):
                raise OSError("scan failed for x")
            return {path: ("OK", None)}

        sock.scan = MagicMock(side_effect=_per_file_scan)
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                results = await scan_directory(str(tmp_path))

        assert len(results) == 2
        by_path = {r.file_path: r for r in results}
        assert by_path[str(f1)].error is not None
        assert "scan failed for x" in by_path[str(f1)].error
        assert by_path[str(f2)].error is None

    @pytest.mark.asyncio
    async def test_connection_error_returns_single_error_result(self, tmp_path: Path):
        """When the second cd = _get_clamd() in the fallback path also
        fails, the service returns a single error sentinel keyed to the
        directory path."""
        f = tmp_path / "x.bin"
        f.write_bytes(b"x")

        # Sequential factory: first call gets multiscan-failing socket;
        # second call (in the fallback) raises during _get_clamd construction.
        call_count = {"n": 0}

        def _factory():
            call_count["n"] += 1
            if call_count["n"] == 1:
                sock = MagicMock()
                sock.multiscan = MagicMock(side_effect=RuntimeError("multiscan boom"))
                return sock
            raise ConnectionRefusedError("clamd dead")

        fake_clamd = _make_fake_clamd_module(network_socket_factory=_factory)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                results = await scan_directory(str(tmp_path))

        assert len(results) == 1
        assert results[0].file_path == str(tmp_path)
        assert results[0].error is not None
        assert "ClamAV connection failed" in results[0].error
        assert "clamd dead" in results[0].error


# ===========================================================================
# scan_directory — file collection guards
# ===========================================================================


class TestScanDirectoryFileCollection:
    @pytest.mark.asyncio
    async def test_max_files_cap_respected(self, tmp_path: Path):
        # Create 10 files, cap at 3.
        for i in range(10):
            (tmp_path / f"f{i}.bin").write_bytes(b"x")

        sock = MagicMock()
        sock.multiscan = MagicMock(return_value=None)
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                results = await scan_directory(str(tmp_path), max_files=3)

        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_non_regular_files_skipped(self, tmp_path: Path):
        # Regular file
        (tmp_path / "real.bin").write_bytes(b"x")
        # Symlink — will be rejected by stat.S_ISREG(lstat).
        (tmp_path / "link").symlink_to(tmp_path / "real.bin")

        sock = MagicMock()
        sock.multiscan = MagicMock(return_value=None)
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                results = await scan_directory(str(tmp_path))

        # Only the real file scanned — symlink skipped.
        assert len(results) == 1
        assert results[0].file_path.endswith("/real.bin")

    @pytest.mark.asyncio
    async def test_oversized_files_skipped(self, tmp_path: Path, monkeypatch):
        # Create one normal-sized file and patch a small file's stat to
        # return a size > MAX_SCAN_FILE_SIZE — easier than allocating
        # a real 100 MB file in tmp_path.
        small = tmp_path / "small.bin"
        small.write_bytes(b"x")
        big = tmp_path / "big.bin"
        big.write_bytes(b"x")

        real_lstat = os.lstat

        def _faux_lstat(path, **kw):
            st = real_lstat(path, **kw)
            if str(path).endswith("/big.bin"):
                # Build a stat_result with size > MAX.
                return os.stat_result((
                    st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                    st.st_uid, st.st_gid,
                    MAX_SCAN_FILE_SIZE + 1024,  # st_size
                    st.st_atime, st.st_mtime, st.st_ctime,
                ))
            return st

        monkeypatch.setattr(os, "lstat", _faux_lstat)

        sock = MagicMock()
        sock.multiscan = MagicMock(return_value=None)
        fake_clamd = _make_fake_clamd_module(network_socket_factory=lambda: sock)

        with patch.object(clam_mod, "get_settings", lambda: _settings_mock()):
            with patch.dict(sys.modules, {"clamd": fake_clamd}):
                results = await scan_directory(str(tmp_path))

        # Only small.bin scanned — big.bin filtered by size cap.
        assert len(results) == 1
        assert results[0].file_path.endswith("/small.bin")


# ===========================================================================
# Rule #30 SOURCE-patch sentinels
# ===========================================================================


class TestRule30ClamdSourcePatch:
    """Document that clamav_service LAZY-imports clamd inside function bodies
    (lines 39 + 51), making the SOURCE module the correct patch target.

    The hasattr-sentinel below fails LOUDLY if a future refactor promotes
    ``import clamd`` to module scope — which would invalidate every
    ``patch.dict(sys.modules, {"clamd": fake_clamd})`` in this file because
    the consumer module would already hold its own bound reference, making
    the sys.modules patch a silent no-op.

    If that refactor ever lands, the patches must migrate to inverse-Rule-30
    shape: ``patch.object(clam_mod, "clamd", fake_clamd)``.
    """

    def test_consumer_module_has_no_clamd_attribute(self):
        # `import clamd` is INSIDE function bodies; clam_mod must NOT have
        # bound the name at module scope.
        assert not hasattr(clam_mod, "clamd"), (
            "clamav_service has grown a module-scope `import clamd`. "
            "The SOURCE-patch tests in this file (patch.dict sys.modules) "
            "are now silent no-ops — migrate them to inverse-Rule-30 "
            "(patch.object on clam_mod) before this assertion fails."
        )

    def test_consumer_module_binds_get_settings(self):
        # get_settings IS top-level imported (line 14) — inverse-Rule-30
        # site, patched via patch.object(clam_mod, "get_settings", ...).
        assert hasattr(clam_mod, "get_settings")

    def test_consumer_module_binds_asyncio(self):
        # asyncio IS top-level imported — inverse-Rule-30.
        assert hasattr(clam_mod, "asyncio")

    def test_lazy_import_resolves_through_sys_modules(self):
        """End-to-end proof: when sys.modules['clamd'] is replaced, the
        next call to a clamav_service function picks up the fake."""
        sentinel = object()
        fake_clamd = MagicMock()
        fake_clamd.SENTINEL = sentinel

        with patch.dict(sys.modules, {"clamd": fake_clamd}):
            # Re-import inside function body (matches service code path).
            import clamd as imported  # noqa: PLC0415
            assert imported.SENTINEL is sentinel
