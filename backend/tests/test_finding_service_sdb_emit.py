"""Tests for the Phase θ.D.E SDB-finding classifier + emit hook.

Tier 1 — pure-function classifier tests covering the tier-mapping
decision tree:

- microsoft-path → 0 drafts (no auto-emit by location).
- unknown-path → 0 drafts (operator review only).
- custom-path + InjectDll → HIGH windows_sdb_inject_dll.
- custom-path + RedirectEXE → HIGH windows_sdb_redirect_exe.
- custom-path + GetCommandLineW → MEDIUM windows_sdb_custom_shim.
- custom-path + RedirectShortcut → MEDIUM windows_sdb_custom_shim.
- custom-path + Custom + has_command_line → MEDIUM custom_shim.
- custom-path + Custom (no command_line) → LOW custom_shim.
- custom-path + Patch → LOW custom_shim (baseline).

Tier 2 — Rule #35b live canaries via make_live_db: round-trip the
emit hook against a fixture WindowsSdbEntry row and confirm Finding
rows persist with the correct source / severity / confidence /
file_path mapping.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import Finding, Firmware, Project, WindowsSdbEntry
from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    FindingService,
    classify_sdb_findings,
)
from app.services.jsonb_normalizers import (
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


def _make_anomaly_flags(**overrides) -> dict:
    base = {
        "is_custom_path": False,
        "has_inject_dll": False,
        "has_redirect_exe": False,
        "has_get_command_line": False,
        "has_redirect_shortcut": False,
        "has_dll_outside_appdir": False,
        "has_command_line": False,
    }
    base.update(overrides)
    return base


# ── classify_sdb_findings tier-mapping tests ────────────────────────────────


def test_classify_sdb_microsoft_path_zero_drafts():
    """Microsoft-path shims do NOT emit — benign by location."""
    drafts = classify_sdb_findings(
        file_path="Windows/AppPatch/sysmain.sdb",
        file_sha256="a" * 64,
        sdb_kind="microsoft",
        app_name="LegacyApp",
        app_exe="legacy.exe",
        shim_class="Custom",
        shim_payload={"shim_name": "VersionLie"},
        anomaly_flags=_make_anomaly_flags(),
    )
    assert drafts == []


def test_classify_sdb_unknown_path_zero_drafts():
    """Unknown-path shims do NOT emit — operator review only."""
    drafts = classify_sdb_findings(
        file_path="Temp/random.sdb",
        file_sha256="a" * 64,
        sdb_kind="unknown",
        app_name=None,
        app_exe=None,
        shim_class="InjectDll",  # Even InjectDll outside AppPatch — no emit.
        shim_payload={"shim_name": "InjectDll", "module": "evil.dll"},
        anomaly_flags=_make_anomaly_flags(has_inject_dll=True),
    )
    assert drafts == []


def test_classify_sdb_inject_dll_custom_path_high():
    """custom-path + InjectDll → HIGH windows_sdb_inject_dll."""
    drafts = classify_sdb_findings(
        file_path="Windows/AppPatch/Custom/myapp.sdb",
        file_sha256="a" * 64,
        sdb_kind="custom",
        app_name="EvilApp",
        app_exe="myapp.exe",
        shim_class="InjectDll",
        shim_payload={
            "shim_name": "InjectDll",
            "module": "C:/Temp/attacker.dll",
            "command_line": "",
            "description": "",
        },
        anomaly_flags=_make_anomaly_flags(
            is_custom_path=True,
            has_inject_dll=True,
            has_dll_outside_appdir=True,
        ),
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_sdb_inject_dll"
    assert d.severity == Severity.high
    assert d.confidence == Confidence.high
    assert "InjectDll" in d.title
    assert "attacker.dll" in d.evidence


def test_classify_sdb_redirect_exe_custom_path_high():
    """custom-path + RedirectEXE → HIGH windows_sdb_redirect_exe."""
    drafts = classify_sdb_findings(
        file_path="Windows/AppPatch/Custom/notepad.sdb",
        file_sha256="b" * 64,
        sdb_kind="custom",
        app_name="NotepadFix",
        app_exe="notepad.exe",
        shim_class="RedirectEXE",
        shim_payload={
            "shim_name": "RedirectEXE",
            "module": "redirect.dll",
            "command_line": "calc.exe",
            "description": "",
        },
        anomaly_flags=_make_anomaly_flags(
            is_custom_path=True,
            has_redirect_exe=True,
            has_command_line=True,
        ),
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_sdb_redirect_exe"
    assert d.severity == Severity.high
    assert d.confidence == Confidence.high
    assert "RedirectEXE" in d.title
    assert "calc.exe" in d.title or "calc.exe" in d.evidence


def test_classify_sdb_get_command_line_custom_path_medium():
    """custom-path + GetCommandLineW → MEDIUM windows_sdb_custom_shim."""
    drafts = classify_sdb_findings(
        file_path="Windows/AppPatch/Custom/argv.sdb",
        file_sha256="c" * 64,
        sdb_kind="custom",
        app_name="ArgvApp",
        app_exe="argv.exe",
        shim_class="GetCommandLineW",
        shim_payload={
            "shim_name": "GetCommandLineW",
            "module": "",
            "command_line": "--inject-args",
            "description": "",
        },
        anomaly_flags=_make_anomaly_flags(
            is_custom_path=True,
            has_get_command_line=True,
            has_command_line=True,
        ),
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_sdb_custom_shim"
    assert d.severity == Severity.medium
    assert d.confidence == Confidence.medium


def test_classify_sdb_redirect_shortcut_custom_path_medium():
    """custom-path + RedirectShortcut → MEDIUM windows_sdb_custom_shim."""
    drafts = classify_sdb_findings(
        file_path="Windows/AppPatch/Custom/shortcut.sdb",
        file_sha256="d" * 64,
        sdb_kind="custom",
        app_name="ShortcutApp",
        app_exe="shortcut.exe",
        shim_class="RedirectShortcut",
        shim_payload={"shim_name": "RedirectShortcut"},
        anomaly_flags=_make_anomaly_flags(
            is_custom_path=True,
            has_redirect_shortcut=True,
        ),
    )
    assert len(drafts) == 1
    assert drafts[0].source == "windows_sdb_custom_shim"
    assert drafts[0].severity == Severity.medium
    assert drafts[0].confidence == Confidence.medium


def test_classify_sdb_custom_with_command_line_medium():
    """custom-path + Custom + has_command_line → MEDIUM custom_shim
    (LOLBin argument-injection candidate)."""
    drafts = classify_sdb_findings(
        file_path="Windows/AppPatch/Custom/exotic.sdb",
        file_sha256="e" * 64,
        sdb_kind="custom",
        app_name="ExoticApp",
        app_exe="exotic.exe",
        shim_class="Custom",
        shim_payload={
            "shim_name": "ExoticShim",
            "module": "",
            "command_line": "powershell -enc Foo",
            "description": "",
        },
        anomaly_flags=_make_anomaly_flags(
            is_custom_path=True,
            has_command_line=True,
        ),
    )
    assert len(drafts) == 1
    assert drafts[0].source == "windows_sdb_custom_shim"
    assert drafts[0].severity == Severity.medium
    assert drafts[0].confidence == Confidence.medium


def test_classify_sdb_custom_baseline_low():
    """custom-path + Custom (no command_line) → LOW custom_shim."""
    drafts = classify_sdb_findings(
        file_path="Windows/AppPatch/Custom/baseline.sdb",
        file_sha256="f" * 64,
        sdb_kind="custom",
        app_name="BaselineApp",
        app_exe="baseline.exe",
        shim_class="Custom",
        shim_payload={"shim_name": "MyShim"},
        anomaly_flags=_make_anomaly_flags(is_custom_path=True),
    )
    assert len(drafts) == 1
    assert drafts[0].source == "windows_sdb_custom_shim"
    assert drafts[0].severity == Severity.low
    assert drafts[0].confidence == Confidence.low


def test_classify_sdb_patch_custom_path_low():
    """custom-path + Patch → LOW windows_sdb_custom_shim (baseline)."""
    drafts = classify_sdb_findings(
        file_path="Windows/AppPatch/Custom/patched.sdb",
        file_sha256="0" * 64,
        sdb_kind="custom",
        app_name="PatchedApp",
        app_exe="patched.exe",
        shim_class="Patch",
        shim_payload={
            "patch_name": "BadPatch",
            "patch_bits_hex": "deadbeef",
            "patch_bits_size": 4,
        },
        anomaly_flags=_make_anomaly_flags(is_custom_path=True),
    )
    assert len(drafts) == 1
    assert drafts[0].source == "windows_sdb_custom_shim"
    assert drafts[0].confidence == Confidence.low


def test_classify_sdb_other_class_custom_path_low():
    """custom-path + Other (unknown shim) → LOW custom_shim."""
    drafts = classify_sdb_findings(
        file_path="Windows/AppPatch/Custom/orphan.sdb",
        file_sha256="1" * 64,
        sdb_kind="custom",
        app_name=None,
        app_exe=None,
        shim_class="Other",
        shim_payload={},
        anomaly_flags=_make_anomaly_flags(is_custom_path=True),
    )
    assert len(drafts) == 1
    assert drafts[0].source == "windows_sdb_custom_shim"
    assert drafts[0].confidence == Confidence.low


# ── emit_sdb_findings_from_walk Rule #35b live canaries ────────────────────


@pytest.mark.asyncio
async def test_emit_sdb_high_inject_dll_persists_finding():
    """Rule #35b live canary — InjectDll attacker entry emits a HIGH
    windows_sdb_inject_dll Finding row."""
    async with make_live_db() as db:
        project = Project(name="θ.D.E InjectDll emit canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "windows.zip", "i")
        db.add(firmware)
        await db.flush()

        entry = WindowsSdbEntry(
            firmware_id=firmware.id,
            file_path="Windows/AppPatch/Custom/myapp.sdb",
            file_sha256="a" * 64,
            sdb_kind="custom",
            app_name="EvilApp",
            app_exe="myapp.exe",
            shim_class="InjectDll",
            shim_payload=_stamp_windows_sdb_entries_shim_payload({
                "kind": "shim",
                "shim_name": "InjectDll",
                "module": "C:/Temp/attacker.dll",
                "command_line": "",
                "description": "",
            }),
            anomaly_flags=_stamp_windows_sdb_entries_anomaly_flags(
                _make_anomaly_flags(
                    is_custom_path=True,
                    has_inject_dll=True,
                    has_dll_outside_appdir=True,
                )
            ),
            fingerprint_sha256="b" * 64,
        )
        db.add(entry)
        await db.flush()

        service = FindingService(db=db)
        emitted = await service.emit_sdb_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert len(emitted) == 1
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        assert len(rows) == 1
        f = rows[0]
        assert f.source == "windows_sdb_inject_dll"
        assert f.severity == "high"
        assert f.confidence == "high"
        assert f.file_path == "Windows/AppPatch/Custom/myapp.sdb"


@pytest.mark.asyncio
async def test_emit_sdb_microsoft_path_emits_nothing():
    """microsoft-path entries do NOT emit Finding rows."""
    async with make_live_db() as db:
        project = Project(name="θ.D.E MS no-emit canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "windows.zip", "m")
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
                "shim_name": "VersionLie"
            }),
            anomaly_flags=_stamp_windows_sdb_entries_anomaly_flags(
                _make_anomaly_flags()
            ),
        )
        db.add(entry)
        await db.flush()

        service = FindingService(db=db)
        emitted = await service.emit_sdb_findings_from_walk(
            project.id, firmware.id
        )

        assert emitted == []
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        assert rows == []


@pytest.mark.asyncio
async def test_emit_sdb_mixed_rows_emit_only_matching():
    """Three entries — microsoft, custom InjectDll, custom Patch
    baseline — only 2 of 3 emit Findings."""
    async with make_live_db() as db:
        project = Project(name="θ.D.E mixed canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "windows.zip", "x")
        db.add(firmware)
        await db.flush()

        # 1. MS-path → no emit.
        db.add(WindowsSdbEntry(
            firmware_id=firmware.id,
            file_path="Windows/AppPatch/sysmain.sdb",
            file_sha256="1" * 64,
            sdb_kind="microsoft",
            shim_class="Custom",
            shim_payload=_stamp_windows_sdb_entries_shim_payload({}),
            anomaly_flags=_stamp_windows_sdb_entries_anomaly_flags(
                _make_anomaly_flags()
            ),
        ))
        # 2. Custom InjectDll → HIGH emit.
        db.add(WindowsSdbEntry(
            firmware_id=firmware.id,
            file_path="Windows/AppPatch/Custom/inj.sdb",
            file_sha256="2" * 64,
            sdb_kind="custom",
            app_name="A1",
            app_exe="a1.exe",
            shim_class="InjectDll",
            shim_payload=_stamp_windows_sdb_entries_shim_payload({
                "shim_name": "InjectDll",
                "module": "attacker.dll",
            }),
            anomaly_flags=_stamp_windows_sdb_entries_anomaly_flags(
                _make_anomaly_flags(
                    is_custom_path=True, has_inject_dll=True
                )
            ),
        ))
        # 3. Custom Patch baseline → LOW emit.
        db.add(WindowsSdbEntry(
            firmware_id=firmware.id,
            file_path="Windows/AppPatch/Custom/patch.sdb",
            file_sha256="3" * 64,
            sdb_kind="custom",
            app_name="A2",
            app_exe="a2.exe",
            shim_class="Patch",
            shim_payload=_stamp_windows_sdb_entries_shim_payload({
                "patch_name": "P", "patch_bits_hex": "ab", "patch_bits_size": 1,
            }),
            anomaly_flags=_stamp_windows_sdb_entries_anomaly_flags(
                _make_anomaly_flags(is_custom_path=True)
            ),
        ))
        await db.flush()

        service = FindingService(db=db)
        emitted = await service.emit_sdb_findings_from_walk(
            project.id, firmware.id
        )
        await db.commit()

        assert len(emitted) == 2
        sources = {f.source for f in emitted}
        assert sources == {
            "windows_sdb_inject_dll",
            "windows_sdb_custom_shim",
        }


@pytest.mark.asyncio
async def test_emit_sdb_no_entries_returns_empty_list():
    """No entries → empty list, no Finding rows persisted."""
    async with make_live_db() as db:
        project = Project(name="θ.D.E empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "windows.zip", "e")
        db.add(firmware)
        await db.flush()

        service = FindingService(db=db)
        emitted = await service.emit_sdb_findings_from_walk(
            project.id, firmware.id
        )
        assert emitted == []


# ── Cross-stack alignment test (Rule #25 single-slice #2) ──────────────────


def test_finding_source_alignment_includes_sdb_sources():
    """Confirm the new windows_sdb_* sources appear in BOTH the
    DB CHECK allowlist (via the in-tree alembic migration) AND the
    frontend FindingSource union — the alignment test will fire
    structurally if either drifts."""
    from pathlib import Path

    backend_dir = Path(__file__).parent.parent
    repo_root = backend_dir.parent

    # DB allowlist via the latest extend-source migration.
    migration_path = (
        backend_dir
        / "alembic"
        / "versions"
        / "cd1e2f3a4b5c_extend_findings_source_sdb.py"
    )
    migration_text = migration_path.read_text()
    assert "windows_sdb_inject_dll" in migration_text
    assert "windows_sdb_redirect_exe" in migration_text
    assert "windows_sdb_custom_shim" in migration_text

    # Frontend FindingSource union.
    types_path = repo_root / "frontend" / "src" / "types" / "index.ts"
    types_text = types_path.read_text()
    assert "'windows_sdb_inject_dll'" in types_text
    assert "'windows_sdb_redirect_exe'" in types_text
    assert "'windows_sdb_custom_shim'" in types_text

    # Frontend FINDING_SOURCE_CONFIG.
    config_path = (
        repo_root / "frontend" / "src" / "constants" / "statusConfig.ts"
    )
    config_text = config_path.read_text()
    assert "windows_sdb_inject_dll:" in config_text
    assert "windows_sdb_redirect_exe:" in config_text
    assert "windows_sdb_custom_shim:" in config_text
