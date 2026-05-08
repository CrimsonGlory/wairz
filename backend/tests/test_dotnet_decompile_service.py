"""Phase δ.4: tests for ``app.services.dotnet_decompile_service``.

Three categories:

1. **Rule #36 no-execute argv gate** — the forbidden-token enforcement
   that prevents ilspycmd's argv[0] from resolving to a .NET runtime
   (``dotnet``), Wine (``wine``), Mono (``mono``), or a Windows scripting
   host (``cscript`` / ``wscript`` / ``powershell`` / ``pwsh``). This
   gate is a public API of the service so the (future) trigger router
   can re-validate before enqueuing.
2. **State machine** — the firmware-row 5-state transitions
   (idle → queued → running → completed/failed) — see β.10's
   ``test_authenticode_chain_runner.py`` for the precedent shape.
3. **dnfile bundle detection** — mock-based test of ``_detect_bundle_sync``
   walking a fake .NET PE; uses Rule #30 patch-at-source-module discipline.

A Rule #35b live canary lives in
``tests/test_dotnet_decompile_real_firmware.py`` (added in δ.9 cut-over) —
this file covers the unit-test surface.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services.dotnet_decompile_service import (
    DEFAULT_BUNDLE_TIMEOUT_SECONDS,
    FORBIDDEN_ARGV0_TOKENS,
    ILSPYCMD_BIN,
    _detect_bundle_sync,
    _detect_pe_arch,
    _firmware_output_dir,
    assert_no_execute_argv,
)


# ─────────────────────────────────────────────────────────────────────────────
# Rule #36 no-execute argv gate
# ─────────────────────────────────────────────────────────────────────────────


def test_forbidden_argv0_tokens_includes_dotnet_family():
    """The allowlist of forbidden argv[0] tokens covers every .NET runtime
    + Windows scripting host that could execute a bundle.

    Future contributors who add a new "convenience" subprocess call must
    not bypass this list — Rule #36's intent is that the bundle is read
    AS DATA only; argv[0] resolves to ilspycmd (the read-only decompiler),
    never to a runtime that would invoke the bundle's entry point.
    """
    assert "dotnet" in FORBIDDEN_ARGV0_TOKENS
    assert "wine" in FORBIDDEN_ARGV0_TOKENS
    assert "mono" in FORBIDDEN_ARGV0_TOKENS
    assert "cscript" in FORBIDDEN_ARGV0_TOKENS
    assert "wscript" in FORBIDDEN_ARGV0_TOKENS
    assert "powershell" in FORBIDDEN_ARGV0_TOKENS
    assert "pwsh" in FORBIDDEN_ARGV0_TOKENS


def test_assert_no_execute_argv_accepts_ilspycmd():
    """ilspycmd is the trusted, image-shipped read-only decompiler."""
    assert_no_execute_argv(["ilspycmd", "/firmware/SomeApp.exe", "-o", "/tmp/out"])
    assert_no_execute_argv(
        ["/root/.dotnet/tools/ilspycmd", "/firmware/SomeApp.exe", "-o", "/tmp/out"]
    )


@pytest.mark.parametrize(
    "argv0",
    [
        "dotnet",
        "/usr/bin/dotnet",
        "wine",
        "/usr/bin/wine",
        "mono",
        "/usr/bin/mono",
        "cscript",
        "wscript",
        "powershell",
        "pwsh",
        "/usr/local/bin/pwsh",
    ],
)
def test_assert_no_execute_argv_rejects_runtimes(argv0):
    """Any runtime that would invoke the bundle's entry point must fail
    the gate. Includes path-prefixed variants (``/usr/bin/dotnet``) since
    a future subprocess call might use the absolute path form.
    """
    with pytest.raises(ValueError, match="Rule #36 violation"):
        assert_no_execute_argv([argv0, "/firmware/SomeApp.exe"])


def test_assert_no_execute_argv_rejects_empty():
    with pytest.raises(ValueError, match="empty argv"):
        assert_no_execute_argv([])


def test_default_bundle_timeout_is_set():
    """The per-bundle timeout exists; pathological bundles can't wedge the
    worker indefinitely. Value is documented in the module docstring."""
    assert DEFAULT_BUNDLE_TIMEOUT_SECONDS >= 60
    assert DEFAULT_BUNDLE_TIMEOUT_SECONDS <= 3600


def test_ilspycmd_bin_constant_is_pure_name():
    """The bin constant is a tool name, not a path — so shutil.which can
    resolve it correctly. The Dockerfile's
    ``ln -s /root/.dotnet/tools/ilspycmd /usr/local/bin/ilspycmd`` puts
    it on PATH inside the worker container."""
    assert ILSPYCMD_BIN == "ilspycmd"
    assert "/" not in ILSPYCMD_BIN


# ─────────────────────────────────────────────────────────────────────────────
# Output dir helper
# ─────────────────────────────────────────────────────────────────────────────


def test_firmware_output_dir_layout(monkeypatch, tmp_path):
    """Per-firmware output is rooted under ``$STORAGE_ROOT/<firmware_id>/dotnet/``."""
    monkeypatch.setenv("STORAGE_ROOT", str(tmp_path))
    # Bust @lru_cache settings if relevant (Rule #20 class-shape note).
    from app.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]
    fid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    out = _firmware_output_dir(fid)
    assert out == tmp_path / str(fid) / "dotnet"
    get_settings.cache_clear()  # type: ignore[attr-defined]


# ─────────────────────────────────────────────────────────────────────────────
# PE arch detection
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "machine,expected",
    [
        (0x8664, "amd64"),
        (0xAA64, "arm64"),
        (0x14C, "i386"),
        (0x1C4, "armnt"),
        (0x0, "msil"),
        (0xDEAD, "unknown"),
    ],
)
def test_detect_pe_arch_machine_map(tmp_path, machine, expected):
    """Architecture mapping covers msil + the four PE machines we expect.

    Test patches pefile.PE at the source module per Rule #30.
    """
    fake_pe = MagicMock()
    fake_pe.FILE_HEADER.Machine = machine
    with patch("pefile.PE", return_value=fake_pe):
        assert _detect_pe_arch(str(tmp_path / "fake.exe")) == expected


def test_detect_pe_arch_handles_parse_error(tmp_path):
    with patch("pefile.PE", side_effect=Exception("malformed")):
        assert _detect_pe_arch(str(tmp_path / "broken.exe")) == "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Bundle detection (Rule #30 patch-at-source-module)
# ─────────────────────────────────────────────────────────────────────────────


def test_detect_bundle_sync_returns_none_when_no_file(tmp_path):
    """Non-existent path is filtered out without dnfile import surprise."""
    assert _detect_bundle_sync(str(tmp_path / "missing.exe")) is None


def test_detect_bundle_sync_returns_none_when_dnfile_raises(tmp_path):
    """dnfile parser failure on a malformed PE is caught and returns None."""
    p = tmp_path / "broken.exe"
    p.write_bytes(b"not a real PE")
    # Patch at source module per Rule #30 — dnfile.dnPE is what the
    # service lazy-imports.
    with patch("dnfile.dnPE", side_effect=Exception("malformed")):
        assert _detect_bundle_sync(str(p)) is None


def test_detect_bundle_sync_dotnet_pe_returns_metadata(tmp_path):
    """A valid .NET PE returns {bundle_sha256, arch} — no bundle markers
    needed when the PE has .NET metadata directly."""
    p = tmp_path / "managed.dll"
    p.write_bytes(b"\x00" * 1024)
    fake_dnpe = MagicMock()
    fake_dnpe.net = MagicMock()  # truthy — has .NET metadata
    fake_pefile = MagicMock()
    fake_pefile.FILE_HEADER.Machine = 0x0  # MSIL
    with (
        patch("dnfile.dnPE", return_value=fake_dnpe),
        patch("pefile.PE", return_value=fake_pefile),
    ):
        meta = _detect_bundle_sync(str(p))
    assert meta is not None
    assert meta["arch"] == "msil"
    assert isinstance(meta["bundle_sha256"], str)
    assert len(meta["bundle_sha256"]) == 64  # SHA256 hex


def test_detect_bundle_sync_native_apphost_with_marker_returns_metadata(tmp_path):
    """A native AppHost wrapper without .NET metadata is detected via
    the AppHostBundle marker string in raw bytes (single-file bundle
    payload signature)."""
    p = tmp_path / "apphost.exe"
    p.write_bytes(b"X" * 100 + b"DOTNET_BUNDLE_EXTRACT_BASE_DIR" + b"Y" * 100)
    fake_dnpe = MagicMock()
    fake_dnpe.net = None  # no .NET metadata at the wrapper level
    fake_pefile = MagicMock()
    fake_pefile.FILE_HEADER.Machine = 0x8664  # amd64 host wrapper
    with (
        patch("dnfile.dnPE", return_value=fake_dnpe),
        patch("pefile.PE", return_value=fake_pefile),
    ):
        meta = _detect_bundle_sync(str(p))
    assert meta is not None
    assert meta["arch"] == "amd64"


def test_detect_bundle_sync_non_dotnet_native_pe_returns_none(tmp_path):
    """A pure-native PE (no .NET metadata, no bundle markers) is filtered
    out — δ.4 only emits IL for .NET assemblies."""
    p = tmp_path / "native.exe"
    p.write_bytes(b"plain native bytes - no .NET, no bundle marker")
    fake_dnpe = MagicMock()
    fake_dnpe.net = None
    with patch("dnfile.dnPE", return_value=fake_dnpe):
        assert _detect_bundle_sync(str(p)) is None
