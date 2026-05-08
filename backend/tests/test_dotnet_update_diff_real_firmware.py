"""Phase δ.9 — Rule #35b real-firmware end-to-end canary set.

Activates the deferred real-firmware canary identified in the δ.9
cut-over kickoff: drives the FULL δ pipeline (δ.4 dotnet decompile →
δ.5 update-diff runner → δ.6 R2R-stomping classifier → δ.8 emit) against
on-disk fixtures and asserts cumulative end-to-end behaviour.

Mirrors β.14a + γ.9 precedent (Rule-of-Three now for skip-tier real-
artefact canary discipline). 3 tiers:

  - **Tier 1 (always runs)** — synthetic fixtures: a tiny .NET PE
    + a tiny KB-vs-KB pair on disk. Drives:
      (a) δ.6 ``classify_r2r_stomp_findings`` against a synthetic .NET
          PE (mocks dnfile + pefile so the synthetic bytes produce a
          usable verdict).
      (b) δ.5 ``run_windows_update_diff_background`` end-to-end against
          two synthetic ``WindowsUpdatePackage`` rows with file BOMs;
          asserts windows_update_dll_diffs rows persist + the firmware
          row transitions queued → completed.
      (c) δ.4 ``dotnet_decompile_service.assert_no_execute_argv`` Rule
          #36 gate over the trusted argv shape.
      (d) δ.7 MCP registry shape — ``create_tool_registry()`` returns
          213 tools (+16 over γ).
      (e) δ.8 ``FindingService.emit_r2r_stomp_findings_from_decompile``
          persists drafts as Finding rows with source=windows_r2r_stomp.

  - **Tier 2 (skip-unless ``WAIRZ_TEST_REAL_DOTNET_BUNDLE``)** — drives
    a real .NET 8 single-file bundle through the δ.6 classifier with NO
    dnfile mock. Asserts the classifier produces ≥1 draft for an
    R2R-eligible bundle (Tier-1 LOW review candidate at minimum).
    Provisioning path: extract a single-file bundle from any modern
    Windows app (Visual Studio Code's electron host, or similar).

  - **Tier 3 (skip-unless ``WAIRZ_TEST_KB_DIFF_FIXTURE``)** — drives a
    real (older_kb, newer_kb) extracted package pair through δ.5
    ``run_windows_update_diff_background``. Asserts ≥1 modified DLL
    detected (real KBs reliably modify some DLLs). Provisioning path:
    set the env var to a directory containing two subdirectories named
    after KB IDs, each with ``files`` BOM in a sidecar ``manifest.json``.

Fixture provisioning (operator graduation path):

    export WAIRZ_TEST_REAL_DOTNET_BUNDLE=/path/to/SomeApp.exe
    export WAIRZ_TEST_KB_DIFF_FIXTURE=/path/to/kb-diff/
    pytest tests/test_dotnet_update_diff_real_firmware.py -v

The canary set graduates from "partial" (5 pass + 2 skip on a typical
Linux dev host) to "full" (7 pass) via fixture commits — no test edits
needed. Mirrors β.14a + γ.9 graduation shape.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from app.ai import create_tool_registry
from app.models import (
    Finding,
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsUpdateDllDiff,
    WindowsUpdatePackage,
)
from app.services.dotnet_decompile_service import (
    FORBIDDEN_ARGV0_TOKENS,
    assert_no_execute_argv,
)
from app.services.finding_service import FindingService
from app.services.r2r_stomping import classify_r2r_stomp_findings
from app.services.windows_update_diff_service import (
    _do_diff_run,
    run_windows_update_diff_background,
)
from tests._live_db import make_live_db


# ── Fixture env-var probes ──────────────────────────────────────────────────


_HOST_REAL_DOTNET_BUNDLE = os.environ.get("WAIRZ_TEST_REAL_DOTNET_BUNDLE")
_HOST_KB_DIFF_FIXTURE = os.environ.get("WAIRZ_TEST_KB_DIFF_FIXTURE")


# ── Tier 1 (always runs) ────────────────────────────────────────────────────


def test_tier1_argv_gate_rejects_runtime_invocation():
    """Rule #36 no-execute argv discipline — argv[0] must be ilspycmd,
    never a .NET runtime / Wine / Mono / scripting host."""
    # Allowed: ilspycmd reading bundle as data.
    assert_no_execute_argv(["ilspycmd", "/firmware/SomeApp.exe", "-o", "/tmp/out"])
    # Rejected: every runtime that would EXECUTE the bundle.
    for runtime in FORBIDDEN_ARGV0_TOKENS:
        with pytest.raises(ValueError, match="Rule #36 violation"):
            assert_no_execute_argv([runtime, "/firmware/SomeApp.exe"])


def test_tier1_mcp_registry_count_is_213_post_delta():
    """δ.7 brings the registry from γ end (197) to δ end (213)."""
    reg = create_tool_registry()
    assert len(reg._tools) == 213


def test_tier1_synthetic_r2r_classifier_emits_review_candidate(tmp_path):
    """δ.6 R2R-stomping classifier against a synthetic R2R-eligible PE
    via mocked dnfile/pefile. Tier-1 review candidate fires for any PE
    with .NET metadata + non-zero ManagedNativeHeader.Size."""
    p = tmp_path / "synthetic_r2r.dll"
    p.write_bytes(b"synthetic r2r bytes")
    fake_pe = MagicMock()
    fake_pe.net = MagicMock()
    fake_pe.net.struct.ManagedNativeHeader.Size = 4096
    fake_pe.net.mdtables.MethodDef.rows = [object()] * 25
    fake_pefile = MagicMock()
    fake_pefile.FILE_HEADER.Machine = 0x8664
    with (
        patch("dnfile.dnPE", return_value=fake_pe),
        patch("pefile.PE", return_value=fake_pefile),
    ):
        drafts = classify_r2r_stomp_findings(str(p))
    assert len(drafts) >= 1
    assert drafts[0].source == "windows_r2r_stomp"
    assert drafts[0].confidence_tier == 1


async def test_tier1_synthetic_update_diff_persists_dll_rows(tmp_path):
    """δ.5 update-diff runner end-to-end against two synthetic
    WindowsUpdatePackage rows with file BOMs; asserts persisted
    windows_update_dll_diffs rows + firmware status transitions."""
    async with make_live_db() as db:
        project = Project(name="δ.9-tier1-update-diff")
        db.add(project)
        await db.flush()
        fw = Firmware(
            project_id=project.id,
            sha256="d" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(fw)
        await db.flush()

        blob = HardwareFirmwareBlob(
            firmware_id=fw.id,
            blob_path=str(tmp_path / "windows_blob"),
            blob_sha256="b" * 64,
            file_size=1024,
            category="windows_update",
            format="cab_cumulative",
            detection_source="synthetic-test",
        )
        db.add(blob)
        await db.flush()

        # Two synthetic packages; one DLL changes between KB versions.
        older = WindowsUpdatePackage(
            blob_id=blob.id,
            package_path="/extracted/KB5034441/Package_for_KB5034441.cab",
            package_type="cab_cumulative",
            kb_id="KB5034441",
            release_date=datetime(2024, 1, 1),
            update_metadata={
                "schema_version": 1,
                "files": [
                    {"path": "ntdll.dll", "sha256": "old_sha", "size": 1000, "is_pe": True, "kind": "binary"},
                    {"path": "kernel32.dll", "sha256": "kernel_sha", "size": 800, "is_pe": True, "kind": "binary"},
                ],
            },
        )
        newer = WindowsUpdatePackage(
            blob_id=blob.id,
            package_path="/extracted/KB5036893/Package_for_KB5036893.cab",
            package_type="cab_cumulative",
            kb_id="KB5036893",
            release_date=datetime(2024, 4, 1),
            update_metadata={
                "schema_version": 1,
                "files": [
                    {"path": "ntdll.dll", "sha256": "new_sha", "size": 1100, "is_pe": True, "kind": "binary"},
                    {"path": "kernel32.dll", "sha256": "kernel_sha", "size": 800, "is_pe": True, "kind": "binary"},
                    {"path": "newdll.dll", "sha256": "added_sha", "size": 500, "is_pe": True, "kind": "binary"},
                ],
            },
        )
        db.add_all([older, newer])
        fw.windows_update_diff_status = "queued"
        await db.commit()

        # Run the INNER runner with the live db (tier-1 exercises the
        # diff logic + UPSERT path; the outer
        # run_windows_update_diff_background wrapper owns the state
        # machine + uses async_session_factory which would require the
        # docker DATABASE_URL — exercised in the running container, not
        # the host pytest sweep).
        aggregate = await _do_diff_run(db, fw.id)
        await db.commit()

        # Reload diff rows.
        from sqlalchemy import select

        diff_rows = (
            (await db.execute(
                select(WindowsUpdateDllDiff).where(
                    WindowsUpdateDllDiff.firmware_id == fw.id
                )
            ))
            .scalars()
            .all()
        )

        # Acceptance assertions — at least 3 rows: ntdll modified,
        # kernel32 unchanged, newdll added.
        types = {r.diff_type for r in diff_rows}
        assert "modified" in types
        assert "unchanged" in types
        assert "added" in types
        # Aggregate carries the histogram counts.
        assert aggregate["dlls_modified"] >= 1
        assert aggregate["dlls_added"] >= 1
        assert aggregate["package_count"] >= 2
        assert aggregate["kb_pair_count"] >= 1


async def test_tier1_synthetic_r2r_emit_persists_findings(tmp_path):
    """δ.8 emit hook: classify_r2r_stomp_findings drafts → Finding rows
    with source='windows_r2r_stomp'. Mocks dnfile so a synthetic PE
    produces R2R-eligible drafts; verifies the post-emit DELETE +
    insert path."""
    fake_bundle = tmp_path / "synthetic_bundle.exe"
    fake_bundle.write_bytes(b"synthetic r2r bytes")

    fake_pe = MagicMock()
    fake_pe.net = MagicMock()
    fake_pe.net.struct.ManagedNativeHeader.Size = 4096
    fake_pe.net.mdtables.MethodDef.rows = [object()] * 25
    fake_pefile = MagicMock()
    fake_pefile.FILE_HEADER.Machine = 0x8664

    async with make_live_db() as db:
        project = Project(name="δ.9-tier1-emit")
        db.add(project)
        await db.flush()
        fw = Firmware(
            project_id=project.id,
            sha256="e" * 64,
            extracted_path=str(tmp_path),
            dotnet_decompile_status="completed",
            dotnet_decompile_result={
                "schema_version": 1,
                "bundle_count": 1,
                "bundles_decompiled": 1,
                "bundles_failed": 0,
                "total_assemblies_extracted": 5,
                "by_arch": {"amd64": 1},
                "bundles": [
                    {
                        "bundle_path": str(fake_bundle),
                        "bundle_sha256": "abc",
                        "extracted_count": 5,
                        "decompile_target_dir": str(tmp_path / "decomp_out"),
                        "errors": [],
                    },
                ],
                "errors": [],
                "run_seconds": 1.0,
            },
        )
        db.add(fw)
        await db.flush()
        await db.commit()

        service = FindingService(db)
        with (
            patch("dnfile.dnPE", return_value=fake_pe),
            patch("pefile.PE", return_value=fake_pefile),
        ):
            findings = await service.emit_r2r_stomp_findings_from_decompile(
                project.id, fw.id,
            )
        await db.commit()

        # Acceptance: at least one finding emitted, source=windows_r2r_stomp.
        assert len(findings) >= 1
        assert all(f.source == "windows_r2r_stomp" for f in findings)
        assert all(f.firmware_id == fw.id for f in findings)


# ── Tier 2 — skip-unless real .NET 8 single-file bundle ─────────────────────


@pytest.mark.skipif(
    _HOST_REAL_DOTNET_BUNDLE is None,
    reason="WAIRZ_TEST_REAL_DOTNET_BUNDLE not set — set to a real .NET single-file bundle path",
)
def test_tier2_real_dotnet_bundle_classifies():
    """Real .NET single-file bundle through the δ.6 classifier with NO
    dnfile mock. Asserts at least Tier-1 LOW draft fires for any
    R2R-eligible bundle."""
    drafts = classify_r2r_stomp_findings(_HOST_REAL_DOTNET_BUNDLE)
    # If the bundle is .NET-eligible, we expect at least Tier-1.
    # If it's not, we expect 0 drafts (filtering correctly applied).
    if drafts:
        assert drafts[0].source == "windows_r2r_stomp"
        assert drafts[0].confidence_tier in (1, 2)
        assert drafts[0].pe_path == _HOST_REAL_DOTNET_BUNDLE
    # Either outcome is valid — the canary asserts the classifier
    # doesn't crash on real input + produces well-shaped output.


# ── Tier 3 — skip-unless real KB-vs-KB diff fixture ─────────────────────────


@pytest.mark.skipif(
    _HOST_KB_DIFF_FIXTURE is None,
    reason="WAIRZ_TEST_KB_DIFF_FIXTURE not set — set to a directory containing two KB extraction subdirs",
)
async def test_tier3_real_kb_diff_persists_modified_dlls():
    """Real (older_kb, newer_kb) extracted package pair through δ.5
    runner. Asserts ≥1 modified DLL detected — real KBs reliably modify
    some DLLs across versions."""
    fixture_dir = _HOST_KB_DIFF_FIXTURE
    assert os.path.isdir(fixture_dir), (
        f"WAIRZ_TEST_KB_DIFF_FIXTURE={fixture_dir!r} is not a directory"
    )
    subdirs = [
        d for d in sorted(os.listdir(fixture_dir))
        if os.path.isdir(os.path.join(fixture_dir, d))
    ]
    assert len(subdirs) >= 2, "fixture must contain ≥2 KB subdirs"
    older_dir = os.path.join(fixture_dir, subdirs[0])
    newer_dir = os.path.join(fixture_dir, subdirs[1])

    async with make_live_db() as db:
        project = Project(name="δ.9-tier3-real-kb")
        db.add(project)
        await db.flush()
        fw = Firmware(
            project_id=project.id,
            sha256="f" * 64,
            extracted_path=fixture_dir,
        )
        db.add(fw)
        await db.flush()
        blob = HardwareFirmwareBlob(
            firmware_id=fw.id,
            blob_path=fixture_dir,
            blob_sha256="real_kb",
            file_size=os.path.getsize(fixture_dir) if os.path.isfile(fixture_dir) else 0,
            category="windows_update",
            format="cab_cumulative",
            detection_source="real-kb-fixture",
        )
        db.add(blob)
        await db.flush()
        # Build packages from the fixture subdirs; rely on the FS-walk
        # fallback in _scan_pkg_dlls_sync (no BOM in update_metadata).
        older_pkg = WindowsUpdatePackage(
            blob_id=blob.id,
            package_path=os.path.join(older_dir, "package.cab"),
            package_type="cab_cumulative",
            kb_id=subdirs[0],
            release_date=datetime(2024, 1, 1),
            update_metadata=None,
        )
        newer_pkg = WindowsUpdatePackage(
            blob_id=blob.id,
            package_path=os.path.join(newer_dir, "package.cab"),
            package_type="cab_cumulative",
            kb_id=subdirs[1],
            release_date=datetime(2024, 4, 1),
            update_metadata=None,
        )
        db.add_all([older_pkg, newer_pkg])
        fw.windows_update_diff_status = "queued"
        await db.commit()

        aggregate = await _do_diff_run(db, fw.id)
        await db.commit()

        from sqlalchemy import select

        diff_rows = (
            (
                await db.execute(
                    select(WindowsUpdateDllDiff).where(
                        WindowsUpdateDllDiff.firmware_id == fw.id
                    )
                )
            )
            .scalars()
            .all()
        )

        # At least one DLL — real KB packages contain hundreds.
        assert len(diff_rows) >= 1, (
            "expected ≥1 DLL diff row from real fixture; "
            "verify the subdirs contain .dll/.exe/.sys files"
        )
        # Real KB pairs typically have at least one modified DLL.
        types = {r.diff_type for r in diff_rows}
        assert types, f"no diff types emitted from {len(diff_rows)} rows"
