"""Service for Qiling-based binary emulation (PE and Mach-O).

Qiling Framework is a Python binary emulation engine that can run Windows PE
and macOS Mach-O binaries without QEMU or native OS support. It runs inside
the backend process (no Docker container needed) using Unicorn engine for
CPU emulation and its own OS/library stubs.

This service provides:
- Format/arch to Qiling ostype/archtype mapping
- Synchronous emulation execution (run in executor for async)
- Output capture (stdout, stderr, syscall traces)
- Timeout enforcement
- Rootfs resolution and validation
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Default Qiling rootfs base path (set during Docker build)
QILING_ROOTFS_BASE = os.environ.get("QILING_ROOTFS_BASE", "/opt/qiling-rootfs")

# Map (format, architecture) -> (Qiling ostype string, rootfs subdirectory)
_FORMAT_ARCH_TO_QILING: dict[tuple[str, str], tuple[str, str]] = {
    # PE (Windows)
    ("pe", "x86"): ("windows", "x86_windows"),
    ("pe", "x86_64"): ("windows", "x8664_windows"),
    ("pe", "arm"): ("windows", "arm_windows"),
    # Mach-O (macOS/iOS — ARM64 Mach-O uses iOS rootfs since no ARM64 macOS rootfs exists)
    ("macho", "x86_64"): ("macos", "x8664_macos"),
    ("macho", "x86"): ("macos", "x86_macos"),
    ("macho", "aarch64"): ("macos", "arm64_ios"),
    # Linux ELF (for completeness, though QEMU is preferred for Linux)
    ("elf", "x86"): ("linux", "x86_linux"),
    ("elf", "x86_64"): ("linux", "x8664_linux"),
    ("elf", "arm"): ("linux", "arm_linux"),
    ("elf", "aarch64"): ("linux", "arm64_linux"),
    ("elf", "mips"): ("linux", "mips32_linux"),
    ("elf", "mipsel"): ("linux", "mips32el_linux"),
}

# Thread pool for running Qiling emulation (synchronous)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="qiling")


@dataclass
class QilingResult:
    """Result of a Qiling emulation run."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    error: str | None = None
    duration_ms: int = 0
    syscall_count: int = 0
    memory_errors: list[str] = field(default_factory=list)
    syscall_trace: list[str] = field(default_factory=list)


def get_rootfs_path(binary_format: str, architecture: str) -> str | None:
    """Resolve the Qiling rootfs path for a given binary format and architecture.

    Returns the absolute path to the rootfs directory, or None if not available.
    """
    key = (binary_format.lower(), architecture.lower())
    mapping = _FORMAT_ARCH_TO_QILING.get(key)
    if not mapping:
        return None

    _, rootfs_dir = mapping
    rootfs_path = os.path.join(QILING_ROOTFS_BASE, rootfs_dir)

    if os.path.isdir(rootfs_path):
        return rootfs_path
    return None


def get_qiling_ostype(binary_format: str, architecture: str) -> str | None:
    """Get the Qiling ostype string for a given binary format and architecture."""
    key = (binary_format.lower(), architecture.lower())
    mapping = _FORMAT_ARCH_TO_QILING.get(key)
    if mapping:
        return mapping[0]
    return None


def is_qiling_supported(binary_format: str, architecture: str) -> bool:
    """Check if Qiling can emulate binaries of this format and architecture."""
    key = (binary_format.lower(), architecture.lower())
    return key in _FORMAT_ARCH_TO_QILING


def check_rootfs_status() -> dict[str, Any]:
    """Check which Qiling rootfs templates are available.

    Returns a dict mapping format/arch combos to their status.
    """
    status: dict[str, Any] = {}
    for (fmt, arch), (ostype, rootfs_dir) in _FORMAT_ARCH_TO_QILING.items():
        rootfs_path = os.path.join(QILING_ROOTFS_BASE, rootfs_dir)
        exists = os.path.isdir(rootfs_path)
        key = f"{fmt}/{arch}"

        # For Windows, check if DLLs are present (licensing requirement)
        has_dlls = True
        if ostype == "windows" and exists:
            sys32 = os.path.join(rootfs_path, "Windows", "System32")
            has_dlls = os.path.isdir(sys32) and len(os.listdir(sys32)) > 5

        status[key] = {
            "available": exists,
            "rootfs_path": rootfs_path,
            "ostype": ostype,
            "has_system_libs": has_dlls if ostype == "windows" else exists,
        }
    return status


# System Python path where Qiling is installed (separate from uv venv to
# avoid dependency conflicts with the project's packages).
_SYSTEM_PYTHON = "/usr/local/bin/python3"

# Inline script that the subprocess runs. Kept minimal to avoid quoting issues.
_QILING_RUNNER_SCRIPT = '''
import sys, json, time, io
binary_path, rootfs, timeout_s, trace = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4] == "1"
args = json.loads(sys.argv[5]) if len(sys.argv) > 5 else []
result = {"stdout": "", "stderr": "", "exit_code": -1, "timed_out": False, "error": None,
          "duration_ms": 0, "syscall_count": 0, "memory_errors": [], "syscall_trace": []}
start = time.monotonic()
try:
    from qiling import Qiling
    from qiling.const import QL_VERBOSE
    argv = [binary_path] + args
    ql = Qiling(argv, rootfs, verbose=QL_VERBOSE.DEBUG if trace else QL_VERBOSE.OFF)
    stdout_cap, stderr_cap = io.StringIO(), io.StringIO()
    ql.os.stdout, ql.os.stderr = stdout_cap, stderr_cap
    ql.run(timeout=timeout_s * 1000000)
    result["exit_code"] = getattr(ql.os, "exit_code", 0) or 0
    result["stdout"] = stdout_cap.getvalue()
    result["stderr"] = stderr_cap.getvalue()
except Exception as e:
    result["error"] = f"{type(e).__name__}: {e}"
    if "unicorn" in str(e).lower() or "UcError" in type(e).__name__:
        result["memory_errors"].append(str(e))
result["duration_ms"] = int((time.monotonic() - start) * 1000)
print(json.dumps(result))
'''


def run_binary(
    binary_path: str,
    rootfs: str | None = None,
    args: list[str] | None = None,
    timeout: int = 30,
    trace_syscalls: bool = False,
    binary_format: str | None = None,
    architecture: str | None = None,
) -> QilingResult:
    """Run a binary through Qiling emulation via subprocess.

    Qiling is installed system-wide (separate from the uv venv) to avoid
    dependency conflicts. This function spawns a subprocess using the system
    Python to run the emulation.

    This function is SYNCHRONOUS. Call via run_binary_async() for async code.
    """
    import json
    import subprocess

    result = QilingResult()

    # Auto-detect format and architecture if not provided
    if not binary_format or not architecture:
        from app.services.binary_analysis_service import analyze_binary
        info = analyze_binary(binary_path)
        binary_format = binary_format or info.get("format", "unknown")
        architecture = architecture or info.get("architecture")

    if not architecture:
        result.error = "Could not detect binary architecture"
        return result

    # Resolve rootfs
    if not rootfs:
        rootfs = get_rootfs_path(binary_format or "", architecture)

    if not rootfs or not os.path.isdir(rootfs):
        result.error = (
            f"No Qiling rootfs available for {binary_format}/{architecture}. "
            f"Expected at: {rootfs or 'N/A'}. "
            "Rootfs templates should be at /opt/qiling-rootfs/."
        )
        return result

    # Check that system Python has qiling
    if not os.path.isfile(_SYSTEM_PYTHON):
        result.error = f"System Python not found at {_SYSTEM_PYTHON}"
        return result

    try:
        proc = subprocess.run(
            [
                _SYSTEM_PYTHON, "-c", _QILING_RUNNER_SCRIPT,
                binary_path, rootfs, str(timeout),
                "1" if trace_syscalls else "0",
                json.dumps(args or []),
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 10,  # extra margin for subprocess overhead
        )

        # Parse JSON result from subprocess stdout
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout.strip().split("\n")[-1])
                result.stdout = data.get("stdout", "")
                result.stderr = data.get("stderr", "")
                result.exit_code = data.get("exit_code", -1)
                result.timed_out = data.get("timed_out", False)
                result.error = data.get("error")
                result.duration_ms = data.get("duration_ms", 0)
                result.syscall_count = data.get("syscall_count", 0)
                result.memory_errors = data.get("memory_errors", [])
                result.syscall_trace = data.get("syscall_trace", [])
            except json.JSONDecodeError:
                result.stdout = proc.stdout
                result.stderr = proc.stderr
                result.error = "Failed to parse Qiling subprocess output"
        else:
            result.error = proc.stderr.strip() or f"Qiling subprocess exited with code {proc.returncode}"
            result.stdout = proc.stdout

    except subprocess.TimeoutExpired:
        result.timed_out = True
        result.error = f"Qiling emulation timed out after {timeout}s"
    except Exception as exc:
        result.error = f"Failed to start Qiling subprocess: {exc}"

    return result


async def run_binary_async(
    binary_path: str,
    rootfs: str | None = None,
    args: list[str] | None = None,
    timeout: int = 30,
    trace_syscalls: bool = False,
    binary_format: str | None = None,
    architecture: str | None = None,
) -> QilingResult:
    """Async wrapper around run_binary().

    Runs Qiling emulation in a thread pool to avoid blocking the event loop.
    """
    import asyncio
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor,
        lambda: run_binary(
            binary_path=binary_path,
            rootfs=rootfs,
            args=args,
            timeout=timeout,
            trace_syscalls=trace_syscalls,
            binary_format=binary_format,
            architecture=architecture,
        ),
    )
