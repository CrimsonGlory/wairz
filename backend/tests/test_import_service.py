"""Service-layer tests for ``app.services.import_service``.

Phase 2 Wave 6 file 4 of 5 — backfills service-layer tests for the
.wairz archive importer (586 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

Pairs with Wave 5's ``test_export_import_router.py`` test (covers the
HTTP endpoint that streams .wairz exports / accepts .zip imports). This
file canaries the inbound side of the round-trip — the value-flow
contract is "archive bytes → persisted ORM rows", and the live-canary
discipline is exercised end-to-end against ``make_live_db``.

Coverage targets:

* ``_parse_dt`` — pure datetime-string parser (None / valid ISO /
  invalid-string / already-datetime passthrough).
* Archive validation:
  - ``zipfile.BadZipFile`` → ``ValueError("Invalid archive: ...")``.
  - Missing ``manifest.json`` → ``ValueError`` cleanup.
  - Archive version > ``ARCHIVE_VERSION`` (constant 1) →
    ``ValueError`` with the helpful "update Wairz" message.
  - Missing ``project.json`` → ``ValueError``.
  - Zip-slip paths (``../foo``, ``\\\\windows``, leading slash) all
    rejected with the "suspicious path" error.
* Happy-path import (Rule #35b live canary):
  - Archive contains project + 1 firmware (with metadata + a small
    file in extracted/) + 2 findings (one with explicit
    ``confidence='medium'``, one with ``confidence=None`` — the
    audit-2026-05-04 width-canary site) + 1 document + 1 emulation
    preset + analysis_cache + sbom_components + fuzzing_campaigns.
  - SELECT every persisted row and assert UUID remapping (NEW IDs,
    not the archive's IDs); confidence field round-trips on EACH
    finding (the F-A-06 backstop generalised to the import path);
    firmware project_id points at the new project; documents storage_path
    derived from new IDs.

Per the campaign Decision Log, this is the **inverse Rule #30 case**:
all imports in import_service.py are MODULE-scope, so patches that
target external symbols would be silent no-ops if pointed at source
modules. Here we don't actually need to patch anything — the import
runs against a real ZIP we build in the test.
"""
from __future__ import annotations

import io
import json
import os
import uuid
import zipfile
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models.analysis_cache import AnalysisCache
from app.models.document import Document
from app.models.emulation_preset import EmulationPreset
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.fuzzing import FuzzingCampaign
from app.models.project import Project
from app.models.sbom import SbomComponent
from app.services.export_service import ARCHIVE_VERSION
from app.services.import_service import ImportService, _parse_dt
from tests._live_db import make_live_db

# ===========================================================================
# Pure datetime parser
# ===========================================================================


class TestParseDt:
    def test_none_returns_none(self):
        assert _parse_dt(None) is None

    def test_already_datetime_passes_through(self):
        dt = datetime(2026, 5, 6, 12, 0, 0)
        assert _parse_dt(dt) is dt

    def test_iso_string_parsed(self):
        result = _parse_dt("2026-05-06T12:00:00")
        assert result == datetime(2026, 5, 6, 12, 0, 0)

    def test_invalid_string_returns_none(self):
        assert _parse_dt("not-a-date") is None

    def test_empty_string_returns_none(self):
        assert _parse_dt("") is None


# ===========================================================================
# Archive-validation branches
# ===========================================================================


def _build_minimal_archive(*, project_data=None, manifest_overrides=None,
                           extra_entries=None) -> bytes:
    """Build a minimal valid .wairz archive in memory.

    Parameters
    ----------
    project_data:
        Override the project.json payload. If None, a default project
        is used.
    manifest_overrides:
        Dict merged into the default manifest (e.g.
        ``{"archive_version": 99}`` to test the version-too-new branch).
    extra_entries:
        Iterable of (arcname, bytes_content) tuples to add additional
        files (e.g. firmware/{id}/metadata.json).
    """
    buf = io.BytesIO()
    manifest = {
        "archive_version": ARCHIVE_VERSION,
        "exported_at": "2026-05-06T00:00:00",
    }
    if manifest_overrides:
        manifest.update(manifest_overrides)

    default_project_id = "11111111-1111-1111-1111-111111111111"
    if project_data is None:
        project_data = {
            "id": default_project_id,
            "name": "imported-project",
            "description": "round-trip canary",
            "status": "created",
        }

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("project.json", json.dumps(project_data))
        if extra_entries:
            for name, content in extra_entries:
                if isinstance(content, str):
                    content = content.encode("utf-8")
                zf.writestr(name, content)

    return buf.getvalue()


class TestArchiveValidation:
    @pytest.mark.asyncio
    async def test_bad_zip_raises_value_error(self):
        async with make_live_db() as db:
            svc = ImportService(db)
            with pytest.raises(ValueError, match="not a valid ZIP"):
                await svc.import_project(b"not a zip file")

    @pytest.mark.asyncio
    async def test_zip_slip_rejected_double_dot(self):
        # Build a zip with a `../escape` entry → suspicious-path branch.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../escape", b"x")
        async with make_live_db() as db:
            svc = ImportService(db)
            with pytest.raises(ValueError, match="suspicious path"):
                await svc.import_project(buf.getvalue())

    @pytest.mark.asyncio
    async def test_zip_slip_rejected_leading_slash(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("/abs/path", b"x")
        async with make_live_db() as db:
            svc = ImportService(db)
            with pytest.raises(ValueError, match="suspicious path"):
                await svc.import_project(buf.getvalue())

    @pytest.mark.asyncio
    async def test_zip_slip_rejected_backslash(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("windows\\path", b"x")
        async with make_live_db() as db:
            svc = ImportService(db)
            with pytest.raises(ValueError, match="suspicious path"):
                await svc.import_project(buf.getvalue())

    @pytest.mark.asyncio
    async def test_missing_manifest_raises(self):
        # Zip without manifest.json.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("project.json", b"{}")
        async with make_live_db() as db:
            svc = ImportService(db)
            with pytest.raises(ValueError, match="missing manifest.json"):
                await svc.import_project(buf.getvalue())

    @pytest.mark.asyncio
    async def test_archive_version_too_new_raises(self):
        archive = _build_minimal_archive(
            manifest_overrides={"archive_version": ARCHIVE_VERSION + 100},
        )
        async with make_live_db() as db:
            svc = ImportService(db)
            with pytest.raises(ValueError, match="newer than supported"):
                await svc.import_project(archive)

    @pytest.mark.asyncio
    async def test_missing_project_json_raises(self):
        # Build a zip with only manifest.json — project.json missing.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json",
                        json.dumps({"archive_version": ARCHIVE_VERSION}))
        async with make_live_db() as db:
            svc = ImportService(db)
            with pytest.raises(ValueError, match="missing project.json"):
                await svc.import_project(buf.getvalue())


# ===========================================================================
# Rule #35b live canary — full archive round-trip → ORM rows
# ===========================================================================


class TestImportProjectLiveCanary:
    """End-to-end canary: build a real archive in memory, import it
    against ``make_live_db()``, then SELECT the persisted rows and
    assert every field round-trips through the import pipeline.

    The F-A-06 confidence-bypass backstop generalises here: the
    Finding constructor at line 310 explicitly forwards
    ``confidence=f.get("confidence")``. A regression that drops this
    kwarg (or the schema field) would silently set confidence=None on
    every imported finding — mock-only `mock_db.add.call_count == 2`
    cannot fail on this.
    """

    @pytest.fixture
    def project_storage_root(self, tmp_path: Path, monkeypatch):
        """Override settings.storage_root to a tmp dir so the test
        doesn't write to /data."""
        from app.services import import_service as svc_mod
        original = svc_mod.get_settings

        fake_settings = type("S", (), {"storage_root": str(tmp_path)})()

        def _fake():
            return fake_settings

        monkeypatch.setattr(svc_mod, "get_settings", _fake)
        return tmp_path

    @pytest.mark.asyncio
    async def test_full_round_trip_persists_remapped_uuids(
        self, project_storage_root: Path,
    ):
        old_proj_id = "11111111-1111-1111-1111-111111111111"
        old_fw_id = "22222222-2222-2222-2222-222222222222"
        old_finding_id_a = "33333333-3333-3333-3333-333333333333"
        old_finding_id_b = "44444444-4444-4444-4444-444444444444"
        old_doc_id = "55555555-5555-5555-5555-555555555555"
        old_preset_id = "66666666-6666-6666-6666-666666666666"
        old_comp_id = "77777777-7777-7777-7777-777777777777"

        # Real-bytes content for the firmware "extracted" tree.
        extracted_content = b"#!/bin/sh\necho hi\n"
        # And one real doc file.
        doc_content = b"# notes from the imported project\n"
        # And a firmware blob.
        original_blob = b"PK\x03\x04" + b"\x00" * 50

        archive = _build_minimal_archive(
            project_data={
                "id": old_proj_id,
                "name": "round-trip-canary",
                "description": "imported via .wairz",
                "status": "ready",
            },
            extra_entries=[
                # ─ Firmware metadata + content
                (f"firmware/{old_fw_id}/metadata.json", json.dumps({
                    "id": old_fw_id,
                    "original_filename": "firmware.bin",
                    "sha256": "a" * 64,
                    "file_size": 50,
                    "architecture": "arm",
                    "endianness": "little",
                    "version_label": "v1.2.3",
                })),
                (f"firmware/{old_fw_id}/original/firmware.bin", original_blob),
                (f"firmware/{old_fw_id}/extracted/etc/init.d/start.sh",
                 extracted_content),
                # ─ Findings (Rule #35b confidence canary on TWO rows —
                # one with explicit medium, one with None to backstop the
                # nullable column.)
                ("findings.json", json.dumps([
                    {
                        "id": old_finding_id_a,
                        "title": "[A] insecure binding",
                        "severity": "high",
                        "confidence": "medium",   # explicit literal
                        "source": "security_audit",
                        "firmware_id": old_fw_id,
                        "evidence": "binds 0.0.0.0",
                        "file_path": "/etc/init.d/start.sh",
                        "line_number": 1,
                        "cwe_ids": ["CWE-200"],
                    },
                    {
                        "id": old_finding_id_b,
                        "title": "[B] note",
                        "severity": "info",
                        "confidence": None,        # null-tolerance canary
                        "source": "manual",
                        "firmware_id": old_fw_id,
                        "status": "open",
                    },
                ])),
                # ─ Documents
                ("documents/metadata.json", json.dumps([
                    {
                        "id": old_doc_id,
                        "original_filename": "notes.md",
                        "description": "imported notes",
                        "content_type": "text/markdown",
                        "file_size": len(doc_content),
                        "sha256": "b" * 64,
                    },
                ])),
                (f"documents/files/{old_doc_id}_notes.md", doc_content),
                # ─ Emulation preset
                ("emulation_presets.json", json.dumps([
                    {
                        "id": old_preset_id,
                        "name": "imported-user-preset",
                        "mode": "user",
                        "binary_path": "/bin/httpd",
                        "arguments": "-D",
                        "architecture": "arm",
                        "port_forwards": [{"host": 8080, "guest": 80}],
                        "stub_profile": "none",
                    },
                ])),
                # ─ Analysis cache
                (f"firmware/{old_fw_id}/analysis_cache.json", json.dumps([
                    {
                        "binary_path": "/bin/httpd",
                        "binary_sha256": "c" * 64,
                        "operation": "decompile:main",
                        "result": {"decompiled": "void main() {}"},
                    },
                ])),
                # ─ SBOM components
                (f"firmware/{old_fw_id}/sbom_components.json", json.dumps([
                    {
                        "id": old_comp_id,
                        "name": "openssl",
                        "version": "1.0.2",
                        "type": "library",
                        "cpe": "cpe:2.3:a:openssl:openssl:1.0.2:*:*:*:*:*:*:*",
                        "detection_source": "string_match",
                        "detection_confidence": "high",
                        "metadata": {"raw_version": "1.0.2g"},
                    },
                ])),
                # ─ SBOM vulns (linked to component)
                (f"firmware/{old_fw_id}/sbom_vulnerabilities.json",
                 json.dumps([
                     {
                         "component_id": old_comp_id,
                         "cve_id": "CVE-2016-2107",
                         "cvss_score": 5.9,
                         "severity": "medium",
                         "description": "Padding oracle",
                     },
                 ])),
                # ─ Fuzzing campaign (status=running → forced to stopped on import)
                (f"firmware/{old_fw_id}/fuzzing_campaigns.json",
                 json.dumps([
                     {
                         "binary_path": "/bin/httpd",
                         "status": "running",   # → "stopped" on import
                         "config": {"timeout": 600},
                         "stats": {"executions": 100},
                         "crashes_count": 2,
                     },
                 ])),
            ],
        )

        async with make_live_db() as db:
            svc = ImportService(db)
            project = await svc.import_project(archive)
            await db.commit()

            # ── Project remapping ─────────────────────────────────────
            assert isinstance(project, Project)
            assert project.id != uuid.UUID(old_proj_id), (
                "import must remap project ID to a fresh UUID"
            )
            assert project.name == "round-trip-canary"
            assert project.description == "imported via .wairz"
            assert project.status == "ready"

            # ── Firmware row persisted with new project_id ────────────
            fw_row = (await db.execute(
                select(Firmware).where(Firmware.project_id == project.id)
            )).scalar_one()
            assert fw_row.id != uuid.UUID(old_fw_id)
            assert fw_row.original_filename == "firmware.bin"
            assert fw_row.sha256 == "a" * 64
            assert fw_row.architecture == "arm"
            assert fw_row.endianness == "little"
            assert fw_row.version_label == "v1.2.3"
            # storage_path + extracted_path both derive from new project/firmware
            # IDs and resolve under settings.storage_root.
            assert fw_row.storage_path is not None
            assert str(project.id) in fw_row.storage_path
            assert str(fw_row.id) in fw_row.storage_path
            assert os.path.isfile(fw_row.storage_path)  # noqa: ASYNC240 — test assertion: verify import service persisted on-disk artifact; sync stat acceptable
            # Original blob bytes round-trip through extraction.
            assert open(fw_row.storage_path, "rb").read() == original_blob  # noqa: ASYNC230 — test assertion: read-back content to verify import service round-trip; sync open acceptable

            assert fw_row.extracted_path is not None
            extracted_file = os.path.join(
                fw_row.extracted_path, "etc", "init.d", "start.sh",
            )
            assert os.path.isfile(extracted_file), (  # noqa: ASYNC240 — test assertion: verify import service persisted on-disk artifact; sync stat acceptable
                "extracted/etc/init.d/start.sh must be on disk"
            )
            assert open(extracted_file, "rb").read() == extracted_content  # noqa: ASYNC230 — test assertion: read-back content to verify import service round-trip; sync open acceptable

            # ── Findings: F-A-06 confidence-bypass backstop ───────────
            findings = (await db.execute(
                select(Finding).where(Finding.project_id == project.id)
            )).scalars().all()
            assert len(findings) == 2
            by_title = {f.title: f for f in findings}
            assert "[A] insecure binding" in by_title
            assert "[B] note" in by_title

            # The Rule #35b discipline — every Finding's confidence,
            # source, and firmware_id round-trip.
            f_a = by_title["[A] insecure binding"]
            assert f_a.confidence == "medium"   # F-A-06 backstop
            assert f_a.severity == "high"
            assert f_a.source == "security_audit"
            assert f_a.evidence == "binds 0.0.0.0"
            assert f_a.file_path == "/etc/init.d/start.sh"
            assert f_a.line_number == 1
            # firmware_id remapped: the imported finding points at the
            # NEW firmware row, not the archive's old UUID.
            assert f_a.firmware_id == fw_row.id

            f_b = by_title["[B] note"]
            assert f_b.confidence is None   # null-tolerance backstop
            assert f_b.severity == "info"
            assert f_b.source == "manual"
            assert f_b.firmware_id == fw_row.id

            # ── Document persisted + file copied ──────────────────────
            doc_row = (await db.execute(
                select(Document).where(Document.project_id == project.id)
            )).scalar_one()
            assert doc_row.original_filename == "notes.md"
            assert doc_row.content_type == "text/markdown"
            assert doc_row.file_size == len(doc_content)
            assert doc_row.sha256 == "b" * 64
            # storage_path uses the NEW doc id, not the archive's.
            assert str(doc_row.id) in doc_row.storage_path
            assert open(doc_row.storage_path, "rb").read() == doc_content  # noqa: ASYNC230 — test assertion: read-back content to verify import service round-trip; sync open acceptable

            # ── Emulation preset persisted with normalised port_forwards
            preset_row = (await db.execute(
                select(EmulationPreset).where(
                    EmulationPreset.project_id == project.id,
                )
            )).scalar_one()
            assert preset_row.name == "imported-user-preset"
            assert preset_row.mode == "user"
            assert preset_row.binary_path == "/bin/httpd"
            assert preset_row.architecture == "arm"
            # port_forwards JSONB round-tripped through normaliser.
            assert preset_row.port_forwards == [{"host": 8080, "guest": 80}]

            # ── Analysis cache persisted with new firmware_id ─────────
            cache_row = (await db.execute(
                select(AnalysisCache).where(
                    AnalysisCache.firmware_id == fw_row.id,
                )
            )).scalar_one()
            assert cache_row.binary_path == "/bin/httpd"
            assert cache_row.binary_sha256 == "c" * 64
            assert cache_row.operation == "decompile:main"
            # JSONB result round-trip.
            assert cache_row.result["decompiled"] == "void main() {}"

            # ── SBOM component + vuln (FK link to remapped component) ─
            comp_row = (await db.execute(
                select(SbomComponent).where(
                    SbomComponent.firmware_id == fw_row.id,
                )
            )).scalar_one()
            assert comp_row.name == "openssl"
            assert comp_row.version == "1.0.2"
            assert comp_row.detection_source == "string_match"
            assert comp_row.detection_confidence == "high"
            # Component ID was remapped — SbomVulnerability's
            # component_id FK points at the NEW row.
            assert comp_row.id != uuid.UUID(old_comp_id)

            # ── Fuzzing campaign: running → stopped (audit invariant) ──
            campaign_row = (await db.execute(
                select(FuzzingCampaign).where(
                    FuzzingCampaign.firmware_id == fw_row.id,
                )
            )).scalar_one()
            assert campaign_row.status == "stopped", (
                "imported running campaigns must be coerced to stopped — "
                "the archive's runtime state is no longer authoritative"
            )
            assert campaign_row.binary_path == "/bin/httpd"
            assert campaign_row.crashes_count == 2
            # config + stats JSONB round-trip via _normalize + _stamp.
            assert campaign_row.config["timeout"] == 600
            assert campaign_row.stats["executions"] == 100

    @pytest.mark.asyncio
    async def test_minimal_archive_no_optional_sections(
        self, project_storage_root: Path,
    ):
        """An archive with ONLY manifest + project (no firmware,
        findings, documents, etc.) imports cleanly to a project row
        with zero downstream rows."""
        archive = _build_minimal_archive()

        async with make_live_db() as db:
            svc = ImportService(db)
            project = await svc.import_project(archive)
            await db.commit()

            # Project persisted.
            row = (await db.execute(
                select(Project).where(Project.id == project.id)
            )).scalar_one()
            assert row.name == "imported-project"
            assert row.status == "created"

            # No firmware / findings / documents.
            assert (await db.execute(
                select(Firmware).where(Firmware.project_id == project.id)
            )).scalars().all() == []
            assert (await db.execute(
                select(Finding).where(Finding.project_id == project.id)
            )).scalars().all() == []
            assert (await db.execute(
                select(Document).where(Document.project_id == project.id)
            )).scalars().all() == []
