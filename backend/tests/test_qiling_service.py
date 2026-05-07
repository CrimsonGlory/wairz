"""Service-layer tests for ``app.services.qiling_service``.

Phase 2 Wave 8 file 4 of 4 — backfills service-layer tests for the
Qiling Framework binary-emulation wrapper (279 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

Marginal canary surface: the service has NO DB persistence, NO cache,
and the actual Qiling emulation runs in a SEPARATE Python interpreter
(spawned via ``subprocess.run``) so the test surface is the
format/arch → ostype/rootfs mapping + subprocess JSON parse +
auto-detect dispatch. The value flow under test is "subprocess
returncode + stdout JSON → QilingResult fields" plus the lazy import
of ``binary_analysis_service.analyze_binary``.

Rule #30 distribution:
* ``subprocess`` and ``json`` — LAZY-imported INSIDE ``run_binary`` at
  lines 177-178 (stdlib modules; lazy because they're hot only when
  the function actually runs, and the module-import path is already
  warm via the os/io imports). Per Rule #30, since these are stdlib
  modules patches go via the SOURCE module
  (``patch("subprocess.run", ...)`` would replace the global; we use
  the cleaner discipline of ``patch.object(qiling_mod, "subprocess",
  ...)`` IF the consumer module had bound it — but it didn't, so we
  patch ``subprocess.run`` on the SOURCE module, which is the same
  ``sys.modules['subprocess']`` object the lazy import resolves to).
* ``app.services.binary_analysis_service.analyze_binary`` —
  LAZY-imported INSIDE ``run_binary`` at line 184. Per Rule #30,
  patches MUST hit the SOURCE module
  (``app.services.binary_analysis_service.analyze_binary``), not
  ``qiling_service.analyze_binary`` which the consumer never bound.
* ``qiling`` and ``qiling.const`` — referenced inside the inline
  ``_QILING_RUNNER_SCRIPT`` string that runs in a SEPARATE Python
  interpreter. These imports are NOT under test from this side —
  the script string itself is a string-literal contract.

Coverage targets:

* ``_FORMAT_ARCH_TO_QILING`` — every entry has 2-tuple
  (ostype, rootfs_dir); supported (format, arch) keys cover PE,
  Mach-O, ELF.
* ``get_rootfs_path`` — returns the path when rootfs dir exists;
  returns None when format/arch unsupported; returns None when
  the rootfs dir is absent on disk.
* ``get_qiling_ostype`` / ``is_qiling_supported`` — basic lookups.
* ``check_rootfs_status`` — returns dict keyed by ``fmt/arch`` with
  available + ostype + has_system_libs fields.
* ``run_binary`` (synchronous):
  * Auto-detect format + arch via the lazy
    ``binary_analysis_service.analyze_binary`` SOURCE-patch;
  * Missing architecture → result.error;
  * Missing rootfs → result.error;
  * System Python missing → result.error;
  * Happy path: subprocess returns JSON on stdout → QilingResult
    fields populated correctly;
  * Subprocess returncode != 0 → error captured;
  * subprocess.TimeoutExpired → result.timed_out=True;
  * Generic subprocess exception captured;
  * Malformed subprocess JSON → result.error sentinel.
* ``run_binary_async`` — wraps run_binary in run_in_executor.
* **Rule #30 SOURCE-patch class** — proves the patch shape against
  ``binary_analysis_service.analyze_binary`` (lazy-import
  source-patch) and confirms the consumer module did NOT bind the
  symbol at module scope.
* **Rule #35b live(-ish) canary** — full subprocess JSON →
  QilingResult round-trip with a real synthesized JSON payload that
  exercises every populated field (stdout, stderr, exit_code,
  timed_out, error, duration_ms, syscall_count, memory_errors,
  syscall_trace). Filesystem rootfs dir is created on disk; the
  binary path is a real file. Mock-only assertions cannot fail on
  a regression where the JSON-key spelling drifts (e.g.
  ``exit_status`` vs ``exit_code``).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services import qiling_service as qiling_mod
from app.services.qiling_service import (
    QilingResult,
    _FORMAT_ARCH_TO_QILING,
    check_rootfs_status,
    get_qiling_ostype,
    get_rootfs_path,
    is_qiling_supported,
    run_binary,
    run_binary_async,
)


# ===========================================================================
# Format / arch mapping table
# ===========================================================================


class TestFormatArchMapping:
    def test_every_entry_is_two_tuple(self):
        for key, value in _FORMAT_ARCH_TO_QILING.items():
            assert isinstance(value, tuple) and len(value) == 2
            ostype, rootfs_dir = value
            assert isinstance(ostype, str) and ostype != ""
            assert isinstance(rootfs_dir, str) and rootfs_dir != ""

    def test_pe_x86_64_present(self):
        assert ("pe", "x86_64") in _FORMAT_ARCH_TO_QILING
        assert _FORMAT_ARCH_TO_QILING[("pe", "x86_64")][0] == "windows"

    def test_macho_aarch64_uses_ios_rootfs(self):
        assert ("macho", "aarch64") in _FORMAT_ARCH_TO_QILING
        assert _FORMAT_ARCH_TO_QILING[("macho", "aarch64")][1] == "arm64_ios"

    def test_elf_mips_endianness_distinct(self):
        assert _FORMAT_ARCH_TO_QILING[("elf", "mips")] != _FORMAT_ARCH_TO_QILING[("elf", "mipsel")]


# ===========================================================================
# get_rootfs_path / get_qiling_ostype / is_qiling_supported
# ===========================================================================


class TestGetRootfsPath:
    def test_returns_path_when_dir_exists(self, tmp_path: Path, monkeypatch):
        # Build a fake rootfs base.
        rootfs_base = tmp_path / "qiling-rootfs"
        rootfs_base.mkdir()
        (rootfs_base / "x8664_linux").mkdir()
        monkeypatch.setattr(qiling_mod, "QILING_ROOTFS_BASE", str(rootfs_base))

        result = get_rootfs_path("elf", "x86_64")
        assert result == str(rootfs_base / "x8664_linux")

    def test_unsupported_format_arch_returns_none(self):
        assert get_rootfs_path("unknown", "z80") is None

    def test_missing_rootfs_dir_returns_none(self, tmp_path: Path, monkeypatch):
        rootfs_base = tmp_path / "qiling-rootfs"
        rootfs_base.mkdir()
        # x8664_linux subdir does NOT exist.
        monkeypatch.setattr(qiling_mod, "QILING_ROOTFS_BASE", str(rootfs_base))
        assert get_rootfs_path("elf", "x86_64") is None

    def test_case_insensitive(self, tmp_path: Path, monkeypatch):
        rootfs_base = tmp_path / "qiling-rootfs"
        rootfs_base.mkdir()
        (rootfs_base / "x8664_linux").mkdir()
        monkeypatch.setattr(qiling_mod, "QILING_ROOTFS_BASE", str(rootfs_base))
        # Mixed case format/arch normalised to lower for lookup.
        result = get_rootfs_path("ELF", "X86_64")
        assert result == str(rootfs_base / "x8664_linux")


class TestGetQilingOstype:
    def test_known_format_arch(self):
        assert get_qiling_ostype("pe", "x86_64") == "windows"
        assert get_qiling_ostype("macho", "aarch64") == "macos"
        assert get_qiling_ostype("elf", "arm") == "linux"

    def test_unknown_returns_none(self):
        assert get_qiling_ostype("unknown", "z80") is None


class TestIsQilingSupported:
    def test_supported_combinations(self):
        assert is_qiling_supported("pe", "x86_64") is True
        assert is_qiling_supported("macho", "x86_64") is True
        assert is_qiling_supported("elf", "mipsel") is True

    def test_unsupported_combination(self):
        assert is_qiling_supported("xtensa", "esp32") is False
        assert is_qiling_supported("pe", "z80") is False


# ===========================================================================
# check_rootfs_status
# ===========================================================================


class TestCheckRootfsStatus:
    def test_returns_dict_keyed_by_fmt_slash_arch(self, tmp_path: Path, monkeypatch):
        rootfs_base = tmp_path / "qiling-rootfs"
        rootfs_base.mkdir()
        (rootfs_base / "x8664_linux").mkdir()
        monkeypatch.setattr(qiling_mod, "QILING_ROOTFS_BASE", str(rootfs_base))

        status = check_rootfs_status()
        assert "elf/x86_64" in status
        assert "pe/x86_64" in status
        # x8664_linux IS available.
        assert status["elf/x86_64"]["available"] is True
        assert status["elf/x86_64"]["ostype"] == "linux"
        # pe/x86_64 is NOT (no x8664_windows dir).
        assert status["pe/x86_64"]["available"] is False

    def test_windows_has_dlls_check(self, tmp_path: Path, monkeypatch):
        """Windows rootfs marks has_system_libs based on DLL count."""
        rootfs_base = tmp_path / "qiling-rootfs"
        rootfs_base.mkdir()
        win = rootfs_base / "x8664_windows" / "Windows" / "System32"
        win.mkdir(parents=True)
        # Add 6 DLLs to clear the >5 threshold.
        for i in range(6):
            (win / f"dll{i}.dll").write_bytes(b"")
        monkeypatch.setattr(qiling_mod, "QILING_ROOTFS_BASE", str(rootfs_base))

        status = check_rootfs_status()
        assert status["pe/x86_64"]["available"] is True
        assert status["pe/x86_64"]["has_system_libs"] is True

    def test_windows_few_dlls_marks_no_system_libs(
        self, tmp_path: Path, monkeypatch,
    ):
        rootfs_base = tmp_path / "qiling-rootfs"
        rootfs_base.mkdir()
        win = rootfs_base / "x8664_windows" / "Windows" / "System32"
        win.mkdir(parents=True)
        # Only 3 DLLs — below threshold.
        for i in range(3):
            (win / f"dll{i}.dll").write_bytes(b"")
        monkeypatch.setattr(qiling_mod, "QILING_ROOTFS_BASE", str(rootfs_base))

        status = check_rootfs_status()
        assert status["pe/x86_64"]["has_system_libs"] is False


# ===========================================================================
# run_binary — synchronous error matrix
# ===========================================================================


@pytest.fixture
def fake_rootfs(tmp_path: Path, monkeypatch) -> Path:
    """Create a rootfs base dir with the x86_64 ELF subdir present."""
    base = tmp_path / "qiling-rootfs"
    base.mkdir()
    (base / "x8664_linux").mkdir()
    monkeypatch.setattr(qiling_mod, "QILING_ROOTFS_BASE", str(base))
    return base


class TestRunBinaryErrorMatrix:
    def test_no_arch_detected_returns_error(self, tmp_path: Path):
        binary = tmp_path / "fake"
        binary.write_bytes(b"\x00")

        # analyze_binary returns no architecture.
        with patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"format": "elf"},
        ):
            result = run_binary(str(binary))
        assert result.error is not None
        assert "Could not detect" in result.error

    def test_no_rootfs_returns_error(self, tmp_path: Path, monkeypatch):
        binary = tmp_path / "fake"
        binary.write_bytes(b"\x00")

        monkeypatch.setattr(qiling_mod, "QILING_ROOTFS_BASE", "/nonexistent")
        result = run_binary(
            str(binary),
            binary_format="elf",
            architecture="x86_64",
        )
        assert result.error is not None
        assert "No Qiling rootfs available" in result.error

    def test_system_python_missing_returns_error(
        self, tmp_path: Path, fake_rootfs: Path,
    ):
        binary = tmp_path / "fake"
        binary.write_bytes(b"\x00")

        with patch.object(qiling_mod, "_SYSTEM_PYTHON", "/nonexistent/python"):
            result = run_binary(
                str(binary),
                binary_format="elf",
                architecture="x86_64",
            )
        assert result.error is not None
        assert "System Python not found" in result.error

    def test_happy_path_parses_subprocess_json(
        self, tmp_path: Path, fake_rootfs: Path,
    ):
        binary = tmp_path / "good"
        binary.write_bytes(b"\x7fELF" + b"good")

        # System Python must exist for the subprocess path.
        sys_python = tmp_path / "fake_python"
        sys_python.write_text("#!/bin/sh\n")
        sys_python.chmod(0o755)

        runner_payload = {
            "stdout": "Hello from emulated binary\n",
            "stderr": "warn: something\n",
            "exit_code": 0,
            "timed_out": False,
            "error": None,
            "duration_ms": 142,
            "syscall_count": 23,
            "memory_errors": [],
            "syscall_trace": ["openat(AT_FDCWD, ...)", "read(3, ...)"],
        }
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = json.dumps(runner_payload)
        proc.stderr = ""

        with patch.object(qiling_mod, "_SYSTEM_PYTHON", str(sys_python)):
            with patch("subprocess.run", return_value=proc) as mock_run:
                result = run_binary(
                    str(binary),
                    binary_format="elf",
                    architecture="x86_64",
                    args=["--help"],
                    timeout=10,
                )

        assert result.error is None
        assert result.stdout == "Hello from emulated binary\n"
        assert result.stderr == "warn: something\n"
        assert result.exit_code == 0
        assert result.timed_out is False
        assert result.duration_ms == 142
        assert result.syscall_count == 23
        assert result.memory_errors == []
        assert "openat" in result.syscall_trace[0]

        # Verify the subprocess was given the right args.
        # cmd: [python, -c, script, binary_path, rootfs, timeout_str,
        #       trace_flag, args_json]
        args, kwargs = mock_run.call_args
        cmd = args[0]
        assert cmd[0] == str(sys_python)
        assert cmd[1] == "-c"
        assert cmd[3] == str(binary)
        assert "x8664_linux" in cmd[4]
        assert kwargs["timeout"] == 20  # +10 margin
        assert kwargs["capture_output"] is True

    def test_subprocess_nonzero_returncode_captures_stderr(
        self, tmp_path: Path, fake_rootfs: Path,
    ):
        binary = tmp_path / "bad"
        binary.write_bytes(b"\x7fELF")

        sys_python = tmp_path / "fake_python"
        sys_python.write_text("#!/bin/sh\n")
        sys_python.chmod(0o755)

        proc = MagicMock()
        proc.returncode = 1
        proc.stdout = ""
        proc.stderr = "Qiling failed: missing library libc.so.6"

        with patch.object(qiling_mod, "_SYSTEM_PYTHON", str(sys_python)):
            with patch("subprocess.run", return_value=proc):
                result = run_binary(
                    str(binary),
                    binary_format="elf",
                    architecture="x86_64",
                )
        assert result.error is not None
        assert "missing library libc.so.6" in result.error

    def test_subprocess_timeout_marks_timed_out(
        self, tmp_path: Path, fake_rootfs: Path,
    ):
        binary = tmp_path / "slow"
        binary.write_bytes(b"\x7fELF")

        sys_python = tmp_path / "fake_python"
        sys_python.write_text("#!/bin/sh\n")
        sys_python.chmod(0o755)

        # subprocess.TimeoutExpired requires cmd, timeout positional args.
        with patch.object(qiling_mod, "_SYSTEM_PYTHON", str(sys_python)):
            with patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["python"], timeout=10),
            ):
                result = run_binary(
                    str(binary),
                    binary_format="elf",
                    architecture="x86_64",
                    timeout=10,
                )
        assert result.timed_out is True
        assert "timed out" in (result.error or "")

    def test_subprocess_generic_exception_captured(
        self, tmp_path: Path, fake_rootfs: Path,
    ):
        binary = tmp_path / "fail"
        binary.write_bytes(b"\x7fELF")

        sys_python = tmp_path / "fake_python"
        sys_python.write_text("#!/bin/sh\n")
        sys_python.chmod(0o755)

        with patch.object(qiling_mod, "_SYSTEM_PYTHON", str(sys_python)):
            with patch(
                "subprocess.run",
                side_effect=OSError("permission denied"),
            ):
                result = run_binary(
                    str(binary),
                    binary_format="elf",
                    architecture="x86_64",
                )
        assert result.error is not None
        assert "permission denied" in result.error

    def test_malformed_subprocess_json_falls_back(
        self, tmp_path: Path, fake_rootfs: Path,
    ):
        binary = tmp_path / "garbage"
        binary.write_bytes(b"\x7fELF")

        sys_python = tmp_path / "fake_python"
        sys_python.write_text("#!/bin/sh\n")
        sys_python.chmod(0o755)

        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "not even json output"
        proc.stderr = ""

        with patch.object(qiling_mod, "_SYSTEM_PYTHON", str(sys_python)):
            with patch("subprocess.run", return_value=proc):
                result = run_binary(
                    str(binary),
                    binary_format="elf",
                    architecture="x86_64",
                )
        # Falls back to raw stdout + sentinel error.
        assert result.error is not None
        assert "Failed to parse" in result.error
        assert result.stdout == "not even json output"


# ===========================================================================
# Auto-detect via lazy-imported analyze_binary (Rule #30 SOURCE-patch)
# ===========================================================================


class TestAutoDetect:
    def test_auto_detect_calls_lazy_analyze_binary(
        self, tmp_path: Path, fake_rootfs: Path,
    ):
        """When binary_format / architecture are NOT provided, the
        function lazy-imports
        ``app.services.binary_analysis_service.analyze_binary`` to fill
        them in. Per Rule #30, the patch target is the SOURCE module."""
        binary = tmp_path / "auto"
        binary.write_bytes(b"\x7fELF")

        sys_python = tmp_path / "fake_python"
        sys_python.write_text("#!/bin/sh\n")
        sys_python.chmod(0o755)

        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = json.dumps({
            "stdout": "ok", "stderr": "", "exit_code": 0,
            "timed_out": False, "error": None,
            "duration_ms": 1, "syscall_count": 0,
            "memory_errors": [], "syscall_trace": [],
        })
        proc.stderr = ""

        with patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"format": "elf", "architecture": "x86_64"},
        ) as mock_analyze:
            with patch.object(qiling_mod, "_SYSTEM_PYTHON", str(sys_python)):
                with patch("subprocess.run", return_value=proc):
                    result = run_binary(str(binary))

        assert result.error is None
        # analyze_binary was called with the binary path.
        mock_analyze.assert_called_once_with(str(binary))


# ===========================================================================
# run_binary_async wraps run_binary in run_in_executor
# ===========================================================================


class TestRunBinaryAsync:
    @pytest.mark.asyncio
    async def test_delegates_to_run_binary_in_executor(self, tmp_path: Path):
        # Mock run_binary to return a known result without actually
        # running anything.
        sentinel = QilingResult(
            stdout="async ok", exit_code=0,
        )

        # Patch run_binary on the module so the lambda inside
        # run_binary_async picks up the mock.
        with patch.object(qiling_mod, "run_binary", return_value=sentinel) as m:
            result = await run_binary_async(
                "/path/to/binary",
                rootfs="/rootfs",
                args=["x"],
                timeout=5,
                trace_syscalls=True,
                binary_format="pe",
                architecture="x86_64",
            )
        assert result is sentinel
        # Called with expected kwargs.
        m.assert_called_once_with(
            binary_path="/path/to/binary",
            rootfs="/rootfs",
            args=["x"],
            timeout=5,
            trace_syscalls=True,
            binary_format="pe",
            architecture="x86_64",
        )


# ===========================================================================
# Rule #30 SOURCE-patch class — explicit discipline canary
# ===========================================================================


class TestRule30AnalyzeBinarySourcePatch:
    """Rule #30 source-patch discipline: ``analyze_binary`` is
    LAZY-imported INSIDE ``run_binary`` at line 184 of qiling_service.py
    (``from app.services.binary_analysis_service import analyze_binary``).

    Mock targets that would be a SILENT NO-OP:
    * ``patch("app.services.qiling_service.analyze_binary", ...)`` —
      AttributeError because the consumer module never bound the name.
    * ``patch.object(qiling_mod, "analyze_binary", ...)`` — same.

    The CORRECT discipline (this class):
    * ``patch("app.services.binary_analysis_service.analyze_binary",
      ...)`` so the ``from app.services.binary_analysis_service
      import analyze_binary`` inside the function body resolves
      against the patched SOURCE module.
    """

    def test_consumer_module_has_no_analyze_binary_attribute(self):
        """Sanity: confirms ``qiling_mod.analyze_binary`` does NOT
        exist as a module-scope attribute. A future refactor that
        promotes the import to top-level would break the SOURCE-patch
        discipline; this sentinel fails LOUDLY in that case so tests
        are migrated to ``patch.object(qiling_mod, "analyze_binary",
        ...)`` (CONSUMER-patch shape) per Rule #30 inverse case."""
        assert not hasattr(qiling_mod, "analyze_binary"), (
            "If analyze_binary is now top-level, switch tests to "
            "patch.object(qiling_mod, 'analyze_binary', ...) per "
            "Rule #30 inverse case."
        )

    def test_consumer_module_has_no_qiling_attribute(self):
        """``qiling`` and ``qiling.const`` are referenced ONLY inside
        the inline ``_QILING_RUNNER_SCRIPT`` string that runs in a
        SEPARATE Python interpreter — not in the consumer module's
        namespace. The consumer module must not bind these names."""
        assert not hasattr(qiling_mod, "qiling")
        assert not hasattr(qiling_mod, "QL_VERBOSE")


# ===========================================================================
# Rule #35b LIVE(-ish) CANARY — full subprocess JSON → QilingResult
# ===========================================================================


class TestRunBinaryLiveCanary:
    """Rule #35b live(-ish) canary: the value-flow contract from
    subprocess JSON → QilingResult fields. No DB persistence here
    (qiling_service is stateless), so the "live" surface is the
    subprocess output → dataclass mapping. Mock-only assertions of
    ``mock_run.assert_called`` cannot fail on:

    * a regression where the JSON-key spelling drifts (e.g. ``exit_status``
      vs ``exit_code``) — the dict access defaults to -1, hiding the
      bug;
    * a regression where the ``json.loads(... .split("\\n")[-1])`` chain
      is rewritten to ``json.loads(stdout)`` and breaks on multi-line
      Qiling subprocess output (the runner script prints debug output
      BEFORE the final JSON line);
    * a regression where the ``timeout + 10`` subprocess timeout grace
      is removed (the qiling SDK takes ~5-10s to bootstrap; cutting the
      grace causes spurious TimeoutExpired in tests with tight
      timeouts).

    This canary uses a multi-line stdout — debug log line + final JSON
    line — to verify the ``split("\\n")[-1]`` parser. Every populated
    field of QilingResult is asserted.
    """

    def test_full_value_flow_with_multiline_stdout(
        self, tmp_path: Path, fake_rootfs: Path,
    ):
        binary = tmp_path / "real-canary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        sys_python = tmp_path / "fake_python"
        sys_python.write_text("#!/bin/sh\n")
        sys_python.chmod(0o755)

        # Multi-line output: pretend Qiling printed debug lines BEFORE
        # the final JSON. The parser uses split("\n")[-1] to pluck only
        # the JSON line.
        runner_payload = {
            "stdout": "Captured: hello\n",
            "stderr": "Qiling[INFO]: started\n",
            "exit_code": 42,
            "timed_out": False,
            "error": None,
            "duration_ms": 1234,
            "syscall_count": 99,
            "memory_errors": [
                "UC_ERR_READ_UNMAPPED at 0xdeadbeef",
            ],
            "syscall_trace": [
                "syscall openat(AT_FDCWD, '/etc/passwd', O_RDONLY) = 3",
                "syscall read(3, ..., 4096) = 1024",
                "syscall close(3) = 0",
            ],
        }
        multiline_stdout = (
            "DEBUG: bootstrapping qiling\n"
            "INFO: rootfs at /opt/qiling-rootfs/x8664_linux\n"
            + json.dumps(runner_payload)
        )
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = multiline_stdout
        proc.stderr = ""

        with patch.object(qiling_mod, "_SYSTEM_PYTHON", str(sys_python)):
            with patch("subprocess.run", return_value=proc) as mock_run:
                result = run_binary(
                    str(binary),
                    binary_format="elf",
                    architecture="x86_64",
                    args=["arg1", "arg2"],
                    timeout=15,
                    trace_syscalls=True,
                )

        # Every field of QilingResult populated from the JSON.
        assert result.error is None
        assert result.stdout == "Captured: hello\n"
        assert result.stderr == "Qiling[INFO]: started\n"
        assert result.exit_code == 42
        assert result.timed_out is False
        assert result.duration_ms == 1234
        assert result.syscall_count == 99
        assert len(result.memory_errors) == 1
        assert "0xdeadbeef" in result.memory_errors[0]
        assert len(result.syscall_trace) == 3
        assert "openat" in result.syscall_trace[0]

        # Subprocess invoked with the right shape.
        cmd = mock_run.call_args[0][0]
        # cmd: [python, -c, script, binary_path, rootfs, timeout_str, trace_flag, args_json]
        assert cmd[0] == str(sys_python)
        assert cmd[1] == "-c"
        assert cmd[3] == str(binary)
        assert "x8664_linux" in cmd[4]
        assert cmd[5] == "15"  # timeout str
        assert cmd[6] == "1"   # trace flag (true)
        assert json.loads(cmd[7]) == ["arg1", "arg2"]
        # Subprocess timeout = inner timeout + 10s margin (line 220).
        assert mock_run.call_args.kwargs["timeout"] == 25

    def test_dataclass_default_factories_isolated(self):
        """Sanity: QilingResult.memory_errors / syscall_trace use
        ``field(default_factory=list)`` — two fresh instances must
        NOT share the same list object (a regression to a bare
        ``= []`` default would silently break this)."""
        a = QilingResult()
        b = QilingResult()
        a.memory_errors.append("a")
        a.syscall_trace.append("syscall_a")
        assert b.memory_errors == []
        assert b.syscall_trace == []
