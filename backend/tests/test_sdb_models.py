"""Tests for the Phase θ.D.B WindowsSdbEntry ORM model.

Per CLAUDE.md Rule #35b live canaries: round-trip via the real ORM
+ ``make_live_db`` SQLite shim to confirm column shapes + index
declarations match the alembic migration intent.

Covers:
- ORM round-trip — create, persist, SELECT, inspect every column.
- JSONB columns (shim_payload, anomaly_flags) — Rule #35c stamped
  envelopes persist end-to-end.
- Defensive shapes: NULL app_name, NULL app_exe, NULL fingerprint,
  custom-path InjectDll variant, microsoft-path benign variant.
- Idempotency + idempotent re-stamp of normaliser envelope.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsSdbEntry
from app.services.jsonb_normalizers import (
    FIRMWARE_SDB_WALK_RESULT_SCHEMA_VERSION,
    WINDOWS_SDB_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION,
    WINDOWS_SDB_ENTRIES_SHIM_PAYLOAD_SCHEMA_VERSION,
    _normalize_firmware_sdb_walk_result,
    _normalize_windows_sdb_entries_anomaly_flags,
    _normalize_windows_sdb_entries_shim_payload,
    _stamp_firmware_sdb_walk_result,
    _stamp_windows_sdb_entries_anomaly_flags,
    _stamp_windows_sdb_entries_shim_payload,
)
from tests._live_db import make_live_db


def _make_firmware(
    project_id: uuid.UUID, name: str, sha_seed: str
) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── ORM round-trip live canaries ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sdb_entry_persists_inject_dll_custom_shim():
    """Rule #35b live canary — round-trip an attacker-shape InjectDll
    custom shim and confirm every column persists with the expected
    shape."""
    async with make_live_db() as db:
        project = Project(name="θ.D.B InjectDll canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "windows.img", "i")
        db.add(firmware)
        await db.flush()

        shim_payload = _stamp_windows_sdb_entries_shim_payload({
            "kind": "shim",
            "shim_name": "InjectDll",
            "module": "C:/Temp/attacker.dll",
            "command_line": "",
            "description": "Inject malicious DLL",
        })
        anomaly = _stamp_windows_sdb_entries_anomaly_flags({
            "is_custom_path": True,
            "has_inject_dll": True,
            "has_redirect_exe": False,
            "has_get_command_line": False,
            "has_redirect_shortcut": False,
            "has_dll_outside_appdir": True,
            "has_command_line": False,
        })

        entry = WindowsSdbEntry(
            firmware_id=firmware.id,
            file_path="Windows/AppPatch/Custom/myapp.sdb",
            file_sha256="a" * 64,
            sdb_kind="custom",
            app_name="EvilApp",
            app_exe="myapp.exe",
            shim_class="InjectDll",
            shim_payload=shim_payload,
            anomaly_flags=anomaly,
            fingerprint_sha256="b" * 64,
        )
        db.add(entry)
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsSdbEntry).where(
                    WindowsSdbEntry.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        r = rows[0]
        assert r.file_path == "Windows/AppPatch/Custom/myapp.sdb"
        assert r.file_sha256 == "a" * 64
        assert r.sdb_kind == "custom"
        assert r.app_name == "EvilApp"
        assert r.app_exe == "myapp.exe"
        assert r.shim_class == "InjectDll"
        assert r.fingerprint_sha256 == "b" * 64

        assert isinstance(r.shim_payload, dict)
        assert r.shim_payload["kind"] == "shim"
        assert r.shim_payload["shim_name"] == "InjectDll"
        assert r.shim_payload["module"] == "C:/Temp/attacker.dll"
        assert r.shim_payload["schema_version"] == (
            WINDOWS_SDB_ENTRIES_SHIM_PAYLOAD_SCHEMA_VERSION
        )

        assert isinstance(r.anomaly_flags, dict)
        assert r.anomaly_flags["is_custom_path"] is True
        assert r.anomaly_flags["has_inject_dll"] is True
        assert r.anomaly_flags["has_dll_outside_appdir"] is True
        assert r.anomaly_flags["schema_version"] == (
            WINDOWS_SDB_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
        )


@pytest.mark.asyncio
async def test_sdb_entry_persists_microsoft_benign_shim():
    """Microsoft-path benign Custom shim — sdb_kind=microsoft,
    is_custom_path=False, no attacker flags raised."""
    async with make_live_db() as db:
        project = Project(name="θ.D.B benign-MS canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "windows.img", "m")
        db.add(firmware)
        await db.flush()

        entry = WindowsSdbEntry(
            firmware_id=firmware.id,
            file_path="Windows/AppPatch/sysmain.sdb",
            file_sha256="c" * 64,
            sdb_kind="microsoft",
            app_name="LegacyApp",
            app_exe="legacy.exe",
            shim_class="Custom",
            shim_payload=_stamp_windows_sdb_entries_shim_payload({
                "kind": "shim",
                "shim_name": "VersionLie",
                "module": "",
                "command_line": "",
                "description": "Lie about Windows version",
            }),
            anomaly_flags=_stamp_windows_sdb_entries_anomaly_flags({
                "is_custom_path": False,
                "has_inject_dll": False,
                "has_redirect_exe": False,
                "has_get_command_line": False,
                "has_redirect_shortcut": False,
                "has_dll_outside_appdir": False,
                "has_command_line": False,
            }),
            fingerprint_sha256="d" * 64,
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsSdbEntry).where(
                    WindowsSdbEntry.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.sdb_kind == "microsoft"
        assert r.shim_class == "Custom"
        assert r.anomaly_flags["is_custom_path"] is False
        assert r.anomaly_flags["has_inject_dll"] is False


@pytest.mark.asyncio
async def test_sdb_entry_supports_null_optional_fields():
    """app_name + app_exe + fingerprint_sha256 are nullable — defensive
    shape for .sdb files without TAG_APP_NAME / TAG_EXE."""
    async with make_live_db() as db:
        project = Project(name="θ.D.B null-fields canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "windows.img", "n")
        db.add(firmware)
        await db.flush()

        entry = WindowsSdbEntry(
            firmware_id=firmware.id,
            file_path="Windows/AppPatch/Custom/orphan.sdb",
            file_sha256="e" * 64,
            sdb_kind="custom",
            app_name=None,
            app_exe=None,
            shim_class="Other",
            shim_payload=None,
            anomaly_flags=None,
            fingerprint_sha256=None,
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsSdbEntry).where(
                    WindowsSdbEntry.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.app_name is None
        assert r.app_exe is None
        assert r.shim_payload is None
        assert r.anomaly_flags is None
        assert r.fingerprint_sha256 is None


@pytest.mark.asyncio
async def test_sdb_entry_persists_patch_class_with_hex_blob():
    """TAG_PATCH entry — shim_class=Patch, shim_payload carries
    patch_bits_hex of the raw TAG_PATCH_BITS bytes."""
    async with make_live_db() as db:
        project = Project(name="θ.D.B patch canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "windows.img", "p")
        db.add(firmware)
        await db.flush()

        entry = WindowsSdbEntry(
            firmware_id=firmware.id,
            file_path="Windows/AppPatch/Custom/patched.sdb",
            file_sha256="f" * 64,
            sdb_kind="custom",
            app_name="PatchedApp",
            app_exe="patched.exe",
            shim_class="Patch",
            shim_payload=_stamp_windows_sdb_entries_shim_payload({
                "kind": "patch",
                "patch_name": "BadPatch",
                "patch_bits_hex": "deadbeefcafe",
                "patch_bits_size": 6,
            }),
            anomaly_flags=_stamp_windows_sdb_entries_anomaly_flags({
                "is_custom_path": True,
                "has_inject_dll": False,
                "has_redirect_exe": False,
                "has_get_command_line": False,
                "has_redirect_shortcut": False,
                "has_dll_outside_appdir": False,
                "has_command_line": False,
            }),
            fingerprint_sha256="0" * 64,
        )
        db.add(entry)
        await db.commit()

        r = (
            await db.execute(
                select(WindowsSdbEntry).where(
                    WindowsSdbEntry.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.shim_class == "Patch"
        assert r.shim_payload["kind"] == "patch"
        assert r.shim_payload["patch_bits_hex"] == "deadbeefcafe"
        assert r.shim_payload["patch_bits_size"] == 6


@pytest.mark.asyncio
async def test_sdb_entry_multiple_per_firmware_persist_independently():
    """Multiple SDB entries per firmware persist independently —
    canonical shape (one .sdb file may carry multiple shims, each
    with its own row)."""
    async with make_live_db() as db:
        project = Project(name="θ.D.B multi-entry canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "windows.img", "c")
        db.add(firmware)
        await db.flush()

        for i, shim_class in enumerate([
            "InjectDll", "RedirectEXE", "GetCommandLineW", "Custom"
        ]):
            entry = WindowsSdbEntry(
                firmware_id=firmware.id,
                file_path="Windows/AppPatch/Custom/multi.sdb",
                file_sha256="2" * 64,
                sdb_kind="custom",
                app_name="EvilApp",
                app_exe="evil.exe",
                shim_class=shim_class,
                fingerprint_sha256=f"{i}" * 64,
            )
            db.add(entry)
        await db.commit()

        rows = (
            await db.execute(
                select(WindowsSdbEntry).where(
                    WindowsSdbEntry.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 4
        assert {r.shim_class for r in rows} == {
            "InjectDll", "RedirectEXE", "GetCommandLineW", "Custom"
        }


# ── JSONB normaliser idempotency tests (Rule #35c) ──────────────────────────


def test_normalize_shim_payload_canonical_passthrough():
    """Canonical dict passes through unchanged (idempotent)."""
    canonical = {
        "schema_version": 1,
        "kind": "shim",
        "shim_name": "InjectDll",
        "module": "x.dll",
        "command_line": "",
        "description": "",
    }
    assert _normalize_windows_sdb_entries_shim_payload(canonical) == canonical


def test_normalize_shim_payload_defensive_none_to_empty_dict():
    """None / non-dict inputs → empty dict (defensive boundary)."""
    assert _normalize_windows_sdb_entries_shim_payload(None) == {}
    assert _normalize_windows_sdb_entries_shim_payload("string") == {}
    assert _normalize_windows_sdb_entries_shim_payload([1, 2, 3]) == {}
    assert _normalize_windows_sdb_entries_shim_payload(123) == {}


def test_stamp_shim_payload_inline_stamps_version():
    """Stamp writer adds the schema_version key inline."""
    payload = {"kind": "shim", "shim_name": "X"}
    stamped = _stamp_windows_sdb_entries_shim_payload(payload)
    assert stamped["schema_version"] == (
        WINDOWS_SDB_ENTRIES_SHIM_PAYLOAD_SCHEMA_VERSION
    )
    assert stamped["kind"] == "shim"


def test_stamp_shim_payload_is_idempotent():
    """Re-stamping a previously-stamped payload is a no-op."""
    payload = {"kind": "shim", "shim_name": "X"}
    once = _stamp_windows_sdb_entries_shim_payload(dict(payload))
    twice = _stamp_windows_sdb_entries_shim_payload(once)
    assert once == twice


def test_normalize_anomaly_flags_canonical_passthrough():
    """Canonical anomaly flags dict passes through unchanged."""
    canonical = {
        "schema_version": 1,
        "is_custom_path": True,
        "has_inject_dll": True,
        "has_redirect_exe": False,
        "has_get_command_line": False,
        "has_redirect_shortcut": False,
        "has_dll_outside_appdir": True,
        "has_command_line": False,
    }
    assert (
        _normalize_windows_sdb_entries_anomaly_flags(canonical) == canonical
    )


def test_normalize_anomaly_flags_defensive_none_to_empty_dict():
    """None / non-dict inputs → empty dict."""
    assert _normalize_windows_sdb_entries_anomaly_flags(None) == {}
    assert _normalize_windows_sdb_entries_anomaly_flags("nope") == {}


def test_stamp_anomaly_flags_inline_stamps_version():
    """Stamp writer adds schema_version inline."""
    payload = {"is_custom_path": True}
    stamped = _stamp_windows_sdb_entries_anomaly_flags(payload)
    assert stamped["schema_version"] == (
        WINDOWS_SDB_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    assert stamped["is_custom_path"] is True


def test_stamp_anomaly_flags_is_idempotent():
    """Re-stamping a previously-stamped payload is a no-op."""
    payload = {"is_custom_path": True}
    once = _stamp_windows_sdb_entries_anomaly_flags(dict(payload))
    twice = _stamp_windows_sdb_entries_anomaly_flags(once)
    assert once == twice


# ── firmware.sdb_walk_result normaliser tests (Rule #35c) ──────────────────


def test_normalize_firmware_sdb_walk_result_canonical_passthrough():
    """Canonical dict passes through unchanged (idempotent)."""
    canonical = {
        "schema_version": 1,
        "run_seconds": 0.123,
        "files_scanned": 1,
        "entries_persisted": 2,
        "shim_count": 1,
        "patch_count": 1,
        "custom_path_count": 1,
        "inject_dll_count": 1,
        "redirect_exe_count": 0,
        "get_command_line_count": 0,
        "redirect_shortcut_count": 0,
        "anomaly_count": 1,
        "errors": [],
        "per_file": [],
    }
    assert _normalize_firmware_sdb_walk_result(canonical) == canonical


def test_normalize_firmware_sdb_walk_result_defensive_none_preserved():
    """None / non-dict inputs → None (semantic 'no completed run')."""
    assert _normalize_firmware_sdb_walk_result(None) is None
    assert _normalize_firmware_sdb_walk_result("string") is None
    assert _normalize_firmware_sdb_walk_result([]) is None


def test_stamp_firmware_sdb_walk_result_inline_stamps_version():
    payload = {"files_scanned": 5}
    stamped = _stamp_firmware_sdb_walk_result(payload)
    assert stamped["schema_version"] == (
        FIRMWARE_SDB_WALK_RESULT_SCHEMA_VERSION
    )
    assert stamped["files_scanned"] == 5


def test_stamp_firmware_sdb_walk_result_is_idempotent():
    payload = {"files_scanned": 5}
    once = _stamp_firmware_sdb_walk_result(dict(payload))
    twice = _stamp_firmware_sdb_walk_result(once)
    assert once == twice
