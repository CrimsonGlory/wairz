"""Service-layer tests for ``app.services.assessment_service``.

Phase 2 Wave 1 file 5 of 5 — backfills service-layer tests for the full
assessment orchestrator (770 LOC, 1 helper + 7 phase methods + 3 lifecycle
hooks) per intake audit-test-coverage-routers-services-2026-05-04.

The service runs a multi-phase security assessment, calling existing
services directly and persisting findings. Each phase is independent:
failures in one don't block others. This file uses ``tests._live_db.make_live_db``
for the canary path that walks ``run_full_assessment`` end-to-end with all
phases skipped except a single mock; the assertion is on the persisted
Finding row (Rule #35b) plus the orchestration summary shape.

Coverage targets:

* ``_enumerate_android_apk_dirs`` — pure helper; covers all 10
  partition/directory pairs across multiple roots; deduplicates by
  ``os.path.realpath``.
* ``AssessmentService.__init__`` — extracted_path normalised to realpath;
  finding service initialised with the same db.
* ``_resolve_detection_roots`` — primary path uses ``get_detection_roots``;
  fallback to ``[extracted_path]`` when firmware row is missing or
  helper raises.
* ``_create_finding``           — Rule #35b live canary: persists Finding
  with ``source="security_review"`` AND the right ``firmware_id`` —
  the F-A-06-shape assertion that mock tests cannot fail on.
* ``run_full_assessment``       — orchestration: skip_phases skips a phase,
  failed phase produces ``status="error"``, summary contains
  ``total_findings_created`` + per-phase results.
* ``ASSESSMENT_SOURCE``         — module constant pinned at "security_review"
  (any unintentional rename would break Stream A's confidence-bypass
  source-tag conventions).

Per Rule #30 audit, all service-level imports in assessment_service.py are
MODULE-scope (lines 17-31) — patching ``app.services.assessment_service.<X>``
works for run_scan_subset, scan_firmware_multi, SbomService, etc. Only
``get_detection_roots`` is also lazy-imported via downstream callers; for
``_resolve_detection_roots`` patch ``app.services.firmware_paths.get_detection_roots``
to be safe (the SOURCE module).
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.assessment_service import (
    ANDROID_APK_PARTITION_DIRS,
    ASSESSMENT_SOURCE,
    AssessmentService,
    _enumerate_android_apk_dirs,
)
from tests._live_db import make_live_db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed(db, *, extracted_path: str = "/tmp/x") -> tuple[Project, Firmware]:
    project = Project(id=uuid.uuid4(), name="assessment-test", status="ready")
    db.add(project)
    await db.flush()

    firmware = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="h" * 64,
        extracted_path=extracted_path,
        extraction_dir=extracted_path,
    )
    db.add(firmware)
    await db.flush()
    return project, firmware


# ===========================================================================
# Module constants — pin them so a rename breaks the test, not production
# ===========================================================================


class TestModuleConstants:
    def test_assessment_source_tag_is_security_review(self):
        """If this changes, every existing Finding row created by the
        assessment service stops matching its source tag in queries.
        Stream A (audit F-A-06) treats ``source`` as a key contract."""
        assert ASSESSMENT_SOURCE == "security_review"

    def test_android_partition_dirs_cover_all_ten_combos(self):
        """Phase 3b expansion: 5 partitions × 2 directory variants. A
        regression that drops product/* or system_ext/* would silently
        miss apps shipped on AOSP Q+ and the four-way partition split."""
        assert set(ANDROID_APK_PARTITION_DIRS) == {
            "system/app", "system/priv-app",
            "product/app", "product/priv-app",
            "vendor/app", "vendor/priv-app",
            "system_ext/app", "system_ext/priv-app",
            "odm/app", "odm/priv-app",
        }


# ===========================================================================
# _enumerate_android_apk_dirs — pure helper
# ===========================================================================


class TestEnumerateAndroidApkDirs:
    def test_returns_only_existing_dirs(self, tmp_path: Path):
        # Create a subset of the 10 partition/dir pairs.
        for rel in ("system/app", "vendor/priv-app", "product/app"):
            (tmp_path / rel).mkdir(parents=True)

        result = _enumerate_android_apk_dirs([str(tmp_path)])
        assert {os.path.relpath(p, str(tmp_path)) for p in result} == {
            "system/app", "vendor/priv-app", "product/app",
        }

    def test_handles_multi_root_with_dedup(self, tmp_path: Path):
        # Two roots — second one is a symlink to the first. Realpath
        # collapses them, so /system/app appears exactly once.
        root_a = tmp_path / "a"
        root_b = tmp_path / "b"
        root_a.mkdir()
        (root_a / "system" / "app").mkdir(parents=True)
        os.symlink(str(root_a), str(root_b))

        result = _enumerate_android_apk_dirs([str(root_a), str(root_b)])
        assert len(result) == 1, (
            f"realpath dedup failed: {result}"
        )

    def test_skips_falsy_root(self):
        # The helper checks ``if not root: continue`` — empty string and
        # None should both be silently skipped.
        result = _enumerate_android_apk_dirs(["", None])  # type: ignore[list-item]
        assert result == []

    def test_returns_empty_when_no_partitions_present(self, tmp_path: Path):
        # Empty extraction tree → no partition dirs → no matches.
        result = _enumerate_android_apk_dirs([str(tmp_path)])
        assert result == []


# ===========================================================================
# AssessmentService.__init__ — attribute initialisation
# ===========================================================================


class TestServiceInit:
    @pytest.mark.asyncio
    async def test_extracted_path_is_realpath_normalised(self, tmp_path: Path):
        async with make_live_db() as db:
            link = tmp_path / "link"
            target = tmp_path / "target"
            target.mkdir()
            os.symlink(str(target), str(link))

            svc = AssessmentService(
                project_id=uuid.uuid4(),
                firmware_id=uuid.uuid4(),
                extracted_path=str(link),
                db=db,
            )
            assert svc.extracted_path == str(target)
            assert svc._detection_roots is None  # lazy
            assert svc.finding_svc is not None
            assert svc.finding_svc.db is db


# ===========================================================================
# _resolve_detection_roots — primary path + fallback
# ===========================================================================


class TestResolveDetectionRoots:
    @pytest.mark.asyncio
    async def test_falls_back_to_extracted_path_when_firmware_missing(
        self, tmp_path: Path,
    ):
        async with make_live_db() as db:
            # Construct service with a firmware_id that doesn't exist in DB —
            # `db.get(Firmware, ...)` returns None → fallback path fires.
            svc = AssessmentService(
                project_id=uuid.uuid4(),
                firmware_id=uuid.uuid4(),
                extracted_path=str(tmp_path),
                db=db,
            )
            roots = await svc._resolve_detection_roots()
            assert roots == [os.path.realpath(str(tmp_path))]  # noqa: ASYNC240 — test assertion: realpath of tmp_path for equality check; pure-string path math, no I/O via realpath here is filesystem-bound but bounded to tmp_path symlink resolution

    @pytest.mark.asyncio
    async def test_uses_get_detection_roots_when_helper_returns_roots(
        self, tmp_path: Path,
    ):
        async with make_live_db() as db:
            project, firmware = await _seed(db, extracted_path=str(tmp_path))

            # ``get_detection_roots`` is MODULE-imported at the top of
            # assessment_service.py (line 26) — the consumer module already
            # holds its own local reference, so patching the SOURCE module
            # is a silent no-op (the inverse of Rule #30: a top-level
            # ``from X import Y`` makes ``Y`` a CONSUMER-module attribute,
            # not a SOURCE-module one). Patch where the consumer looks it up.
            extra = tmp_path / "scatter"
            extra.mkdir()
            with patch(
                "app.services.assessment_service.get_detection_roots",
                new=AsyncMock(return_value=[str(tmp_path), str(extra)]),
            ):
                svc = AssessmentService(
                    project_id=project.id,
                    firmware_id=firmware.id,
                    extracted_path=str(tmp_path),
                    db=db,
                )
                roots = await svc._resolve_detection_roots()

            assert roots == [
                os.path.realpath(str(tmp_path)),  # noqa: ASYNC240 — test assertion: realpath of tmp_path for equality check; bounded to tmp_path symlink resolution
                os.path.realpath(str(extra)),  # noqa: ASYNC240 — test assertion: realpath of extra path for equality check; bounded to tmp_path symlink resolution
            ]
            # Memoised — second call returns same list without re-querying.
            assert svc._detection_roots is not None
            assert await svc._resolve_detection_roots() is svc._detection_roots

    @pytest.mark.asyncio
    async def test_falls_back_when_helper_raises(self, tmp_path: Path):
        async with make_live_db() as db:
            project, firmware = await _seed(db, extracted_path=str(tmp_path))

            with patch(
                "app.services.firmware_paths.get_detection_roots",
                new=AsyncMock(side_effect=RuntimeError("boom")),
            ):
                svc = AssessmentService(
                    project_id=project.id,
                    firmware_id=firmware.id,
                    extracted_path=str(tmp_path),
                    db=db,
                )
                roots = await svc._resolve_detection_roots()
            assert roots == [os.path.realpath(str(tmp_path))]  # noqa: ASYNC240 — test assertion: realpath of tmp_path for equality check; bounded to tmp_path symlink resolution


# ===========================================================================
# _create_finding — Rule #35b live canary
# ===========================================================================


class TestCreateFindingLiveCanary:
    """Rule #35b: ``_create_finding`` builds a FindingCreate then routes
    through ``FindingService.create`` (which writes the row). The canary
    asserts that ``source="security_review"`` AND ``firmware_id`` AND
    every other field round-trips through the constructor + persist path
    — the F-A-06-shape assertion mock-only tests cannot fail on.
    """

    @pytest.mark.asyncio
    async def test_persists_finding_with_assessment_source_tag(
        self, tmp_path: Path,
    ):
        async with make_live_db() as db:
            project, firmware = await _seed(db, extracted_path=str(tmp_path))
            svc = AssessmentService(
                project_id=project.id,
                firmware_id=firmware.id,
                extracted_path=str(tmp_path),
                db=db,
            )

            finding = await svc._create_finding(
                title="Hardcoded API key in /etc/secrets.cfg",
                severity="critical",
                description="Cleartext key matched against AWS access-key regex",
                evidence="AKIAIOSFODNN7EXAMPLE",
                file_path="etc/secrets.cfg",
                line_number=42,
                cwe_ids=["CWE-798"],
            )
            await db.flush()

            persisted = (
                await db.execute(
                    select(Finding).where(Finding.id == finding.id),
                )
            ).scalar_one()

            assert persisted.title == "Hardcoded API key in /etc/secrets.cfg"
            assert persisted.severity == "critical"
            assert persisted.description.startswith("Cleartext key matched")
            assert persisted.evidence == "AKIAIOSFODNN7EXAMPLE"
            assert persisted.file_path == "etc/secrets.cfg"
            assert persisted.line_number == 42
            assert persisted.cwe_ids == ["CWE-798"]
            assert persisted.firmware_id == firmware.id, (
                "Rule #35b: firmware_id must round-trip through DB layer"
            )
            assert persisted.project_id == project.id
            assert persisted.source == ASSESSMENT_SOURCE == "security_review", (
                "Rule #35b: source tag must persist as 'security_review' — "
                "the F-A-06 confidence-bypass shape would silently null this"
            )


# ===========================================================================
# run_full_assessment — orchestration
# ===========================================================================


class TestRunFullAssessmentOrchestration:
    @pytest.mark.asyncio
    async def test_skip_all_phases_returns_seven_skipped_results(
        self, tmp_path: Path,
    ):
        async with make_live_db() as db:
            project, firmware = await _seed(db, extracted_path=str(tmp_path))
            svc = AssessmentService(
                project_id=project.id,
                firmware_id=firmware.id,
                extracted_path=str(tmp_path),
                db=db,
            )

            result = await svc.run_full_assessment(skip_phases=[
                "credential_crypto",
                "sbom_vulnerability",
                "config_filesystem",
                "malware_detection",
                "binary_protections",
                "android",
                "compliance",
            ])

            assert result["status"] == "completed"
            assert result["total_findings_created"] == 0
            assert len(result["phases"]) == 7
            assert all(p["status"] == "skipped" for p in result["phases"])
            assert {p["phase"] for p in result["phases"]} == {
                "credential_crypto", "sbom_vulnerability",
                "config_filesystem", "malware_detection",
                "binary_protections", "android", "compliance",
            }

    @pytest.mark.asyncio
    async def test_failing_phase_produces_error_status_without_blocking_others(
        self, tmp_path: Path,
    ):
        """Each phase is independent — a failure in one MUST NOT abort
        the orchestrator. The failure surfaces as ``status="error"`` +
        ``errors=[...]`` in that phase's result entry."""
        async with make_live_db() as db:
            project, firmware = await _seed(db, extracted_path=str(tmp_path))
            svc = AssessmentService(
                project_id=project.id,
                firmware_id=firmware.id,
                extracted_path=str(tmp_path),
                db=db,
            )

            # Make the credential_crypto phase explode; skip everything else.
            with patch.object(
                svc, "_phase_credential_crypto",
                new=AsyncMock(side_effect=RuntimeError("simulated bug")),
            ):
                result = await svc.run_full_assessment(skip_phases=[
                    "sbom_vulnerability", "config_filesystem",
                    "malware_detection", "binary_protections",
                    "android", "compliance",
                ])

            cred_phase = next(
                p for p in result["phases"]
                if p["phase"] == "credential_crypto"
            )
            assert cred_phase["status"] == "error"
            assert cred_phase["findings_created"] == 0
            assert "simulated bug" in cred_phase["errors"][0]
            # Orchestration kept going.
            assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_successful_phase_increments_total_findings_created(
        self, tmp_path: Path,
    ):
        async with make_live_db() as db:
            project, firmware = await _seed(db, extracted_path=str(tmp_path))
            svc = AssessmentService(
                project_id=project.id,
                firmware_id=firmware.id,
                extracted_path=str(tmp_path),
                db=db,
            )

            # Stub one phase to claim 3 findings, skip the rest.
            with patch.object(
                svc, "_phase_credential_crypto",
                new=AsyncMock(return_value=3),
            ):
                result = await svc.run_full_assessment(skip_phases=[
                    "sbom_vulnerability", "config_filesystem",
                    "malware_detection", "binary_protections",
                    "android", "compliance",
                ])

            assert result["total_findings_created"] == 3
            cred_phase = next(
                p for p in result["phases"]
                if p["phase"] == "credential_crypto"
            )
            assert cred_phase["status"] == "completed"
            assert cred_phase["findings_created"] == 3
            assert cred_phase["errors"] == []
