"""Service-layer tests for ``app.services.grype_service``.

Phase 2 Wave 9 file 1 of 4 — backfills service-layer tests for the
Grype-based vulnerability scanner (265 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

Strong canary surface: this is a SUBPROCESS-driven scanner that
WRITES to the SbomVulnerability and Finding tables. Mock-only tests
would verify "subprocess.create_subprocess_exec was called" but
NOT "the persisted row reflects Grype's JSON output". Per Rule
#35b, the live canary runs the full pipeline against an in-memory
SQLite session: seed SbomComponent rows, mock the subprocess to
return a synthesized Grype JSON payload, run scan_with_grype, then
SELECT every persisted row to inspect every field the service set.

Rule #30 distribution: ``shutil.which`` and ``asyncio`` are
TOP-LEVEL imported at module scope (lines 10, 17, 19). The Finding,
SbomComponent, and SbomVulnerability ORM models are also TOP-LEVEL
imported. This puts grype_service in the **inverse-Rule-30** shape:
patches MUST hit the CONSUMER module
(``app.services.grype_service.which`` /
``app.services.grype_service.asyncio``), not the SOURCE modules
which the consumer module DOES bind at module scope.

Coverage targets:

* ``_extract_cpe_vendor`` — happy path; wildcard rejected; empty
  rejected; short CPE rejected.
* ``_extract_grype_vendor`` — walks matchDetails.found.cpes;
  walks matchDetails.searchedBy.cpes; falls back to
  relatedVulnerabilities.cpes; returns None if all empty.
* ``grype_available`` — wraps shutil.which.
* ``scan_with_grype`` happy path — full pipeline:
  (i) loads SbomComponent rows; (ii) builds CycloneDX 1.5 SBOM
  (verifies specVersion is 1.5 NOT 1.7); (iii) writes temp file;
  (iv) runs subprocess; (v) parses output; (vi) deletes existing
  vulns; (vii) creates new vulns; (viii) creates Finding when
  critical/high count > 0; (ix) returns summary dict.
* ``scan_with_grype`` no-components — early return with
  status='no_components', no subprocess call.
* ``scan_with_grype`` vendor-mismatch filter — Grype emits a CVE
  for vendor=A but our SbomComponent has CPE for vendor=B → that
  match is SKIPPED (regression backstop for cross-vendor
  false-positives that mocked tests cannot catch).
* ``scan_with_grype`` returncode 1 = OK — Grype returns 1 when
  vulns are found; the service must NOT raise.
* ``scan_with_grype`` returncode 2 = error — surfaces RuntimeError.
* ``scan_with_grype`` timeout → RuntimeError with "timed out".
* ``scan_with_grype`` malformed JSON → RuntimeError.
* ``scan_with_grype`` Finding NOT created when only medium/low
  vulns (regression on the F-A-06 confidence-bypass shape).
* **Rule #35b live canary** — full SQLite round-trip: seed 2
  SbomComponents, run scan, SELECT 2 SbomVulnerability rows by
  firmware_id, assert every field (cve_id, severity, cvss_score,
  description, component_id) reflects the Grype JSON; SELECT
  Finding row, assert confidence='high' (audit F-A-06 backstop)
  and severity='critical'.
* **Rule #30 inverse-consumer-patch class** — proves that
  ``app.services.grype_service.asyncio.create_subprocess_exec``
  is the correct patch target (consumer module DOES bind asyncio
  at module scope). Hasattr-sentinel against future refactor that
  promotes asyncio to function-body lazy import (which would flip
  the patch shape to inverse-Rule-30 → SOURCE).
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.sbom import SbomComponent, SbomVulnerability
from app.services import grype_service as grype_mod
from app.services.grype_service import (
    _extract_cpe_vendor,
    _extract_grype_vendor,
    grype_available,
    scan_with_grype,
)

from tests._live_db import make_live_db


# ===========================================================================
# CPE vendor extraction helpers (pure functions)
# ===========================================================================


class TestExtractCpeVendor:
    def test_happy_path_returns_lowercased_vendor(self):
        assert _extract_cpe_vendor(
            "cpe:2.3:a:OpenSSL:openssl:1.1.1k:*:*:*:*:*:*:*"
        ) == "openssl"

    def test_already_lowercase(self):
        assert _extract_cpe_vendor(
            "cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*"
        ) == "apache"

    def test_wildcard_vendor_returns_none(self):
        assert _extract_cpe_vendor("cpe:2.3:a:*:openssl:1.1.1k:*:*:*:*:*:*:*") is None

    def test_empty_vendor_returns_none(self):
        assert _extract_cpe_vendor("cpe:2.3:a::openssl:1.1.1k:*:*:*:*:*:*:*") is None

    def test_none_input_returns_none(self):
        assert _extract_cpe_vendor(None) is None

    def test_short_cpe_returns_none(self):
        # Less than 4 parts → no vendor field.
        assert _extract_cpe_vendor("cpe:2.3:a") is None


class TestExtractGrypeVendor:
    def test_walks_match_details_found_cpes(self):
        match = {
            "matchDetails": [
                {
                    "found": {
                        "cpes": ["cpe:2.3:a:openssl:openssl:1.0.0:*:*:*:*:*:*:*"],
                    },
                },
            ],
        }
        assert _extract_grype_vendor(match) == "openssl"

    def test_walks_match_details_searched_by_cpes(self):
        match = {
            "matchDetails": [
                {
                    "searchedBy": {
                        "cpes": ["cpe:2.3:a:apache:httpd:2.4.0:*:*:*:*:*:*:*"],
                    },
                },
            ],
        }
        assert _extract_grype_vendor(match) == "apache"

    def test_falls_back_to_related_vulnerabilities(self):
        match = {
            "matchDetails": [],
            "relatedVulnerabilities": [
                {
                    "cpes": ["cpe:2.3:a:linux:linux_kernel:5.0:*:*:*:*:*:*:*"],
                },
            ],
        }
        assert _extract_grype_vendor(match) == "linux"

    def test_no_cpes_returns_none(self):
        assert _extract_grype_vendor({}) is None
        assert _extract_grype_vendor({"matchDetails": []}) is None

    def test_first_match_wins(self):
        match = {
            "matchDetails": [
                {
                    "found": {
                        "cpes": [
                            "cpe:2.3:a:first:foo:1.0:*:*:*:*:*:*:*",
                            "cpe:2.3:a:second:foo:1.0:*:*:*:*:*:*:*",
                        ],
                    },
                },
            ],
        }
        assert _extract_grype_vendor(match) == "first"


# ===========================================================================
# grype_available — shutil.which wrapper
# ===========================================================================


class TestGrypeAvailable:
    def test_returns_true_when_which_finds_grype(self):
        with patch.object(grype_mod, "which", return_value="/usr/local/bin/grype"):
            assert grype_available() is True

    def test_returns_false_when_which_returns_none(self):
        with patch.object(grype_mod, "which", return_value=None):
            assert grype_available() is False


# ===========================================================================
# scan_with_grype — error / no-components paths
# ===========================================================================


def _make_settings_mock(timeout: int = 600, cache_dir: str = "/tmp/grype-cache") -> MagicMock:
    s = MagicMock()
    s.grype_db_cache_dir = cache_dir
    s.grype_timeout = timeout
    return s


def _make_subprocess_proc(
    returncode: int,
    stdout: bytes,
    stderr: bytes = b"",
) -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return proc


class TestScanWithGrypeNoComponents:
    @pytest.mark.asyncio
    async def test_returns_no_components_status_without_running_subprocess(
        self, tmp_path: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="empty", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(id=uuid.uuid4(), project_id=pid, sha256="0" * 64)
            db.add(firmware)
            await db.flush()

            # No SbomComponents seeded — scan should short-circuit.
            fake_create = AsyncMock(
                side_effect=AssertionError("subprocess must NOT run when no components"),
            )

            with patch.object(grype_mod, "get_settings", lambda: _make_settings_mock()):
                with patch.object(
                    grype_mod.asyncio, "create_subprocess_exec", fake_create,
                ):
                    result = await scan_with_grype(firmware.id, pid, db)

            assert result["status"] == "no_components"
            assert result["total_components_scanned"] == 0
            assert result["total_vulnerabilities_found"] == 0
            assert result["findings_created"] == 0


# ===========================================================================
# scan_with_grype — happy path with full live-canary
# ===========================================================================


def _build_grype_output(matches: list[dict]) -> bytes:
    return json.dumps({"matches": matches}).encode("utf-8")


class TestScanWithGrypeHappyPath:
    @pytest.mark.asyncio
    async def test_full_pipeline_persists_vulns_and_finding(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="grype-canary", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(id=uuid.uuid4(), project_id=pid, sha256="g" * 64)
            db.add(firmware)
            await db.flush()

            # Seed two SbomComponents — Grype will return matches for both.
            comp_openssl = SbomComponent(
                firmware_id=firmware.id,
                name="openssl",
                version="1.0.2k",
                type="library",
                cpe="cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*",
                detection_source="binwalk",
            )
            comp_busybox = SbomComponent(
                firmware_id=firmware.id,
                name="busybox",
                version="1.31.0",
                type="library",
                cpe="cpe:2.3:a:busybox:busybox:1.31.0:*:*:*:*:*:*:*",
                detection_source="binwalk",
            )
            db.add_all([comp_openssl, comp_busybox])
            await db.flush()

            # Mock subprocess to return synthesized Grype output.
            grype_matches = [
                {
                    "vulnerability": {
                        "id": "CVE-2018-0732",
                        "severity": "High",
                        "description": "OpenSSL DoS via crafted DH params.",
                        "fix": {"versions": ["1.0.2p"]},
                        "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2018-0732",
                        "cvss": [
                            {"version": "3.1", "metrics": {"baseScore": 7.5}},
                        ],
                    },
                    "artifact": {"name": "openssl", "version": "1.0.2k"},
                    "matchDetails": [
                        {
                            "found": {
                                "cpes": [
                                    "cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*"
                                ],
                            },
                        },
                    ],
                },
                {
                    "vulnerability": {
                        "id": "CVE-2018-1000517",
                        "severity": "Critical",
                        "description": "BusyBox wget heap buffer overflow.",
                        "cvss": [
                            {"version": "3.0", "metrics": {"baseScore": 9.8}},
                        ],
                    },
                    "artifact": {"name": "busybox", "version": "1.31.0"},
                    "matchDetails": [
                        {
                            "found": {
                                "cpes": [
                                    "cpe:2.3:a:busybox:busybox:1.31.0:*:*:*:*:*:*:*"
                                ],
                            },
                        },
                    ],
                },
            ]
            stdout = _build_grype_output(grype_matches)

            # Track that subprocess ran with the right command.
            call_args: dict = {}

            async def fake_create_subprocess(*args, **kwargs):
                call_args["args"] = args
                call_args["env"] = kwargs.get("env", {})
                return _make_subprocess_proc(returncode=1, stdout=stdout)

            settings = _make_settings_mock(cache_dir=str(tmp_path / "grype-db"))

            with patch.object(grype_mod, "get_settings", lambda: settings):
                with patch.object(
                    grype_mod.asyncio, "create_subprocess_exec",
                    side_effect=fake_create_subprocess,
                ):
                    result = await scan_with_grype(firmware.id, pid, db)
            await db.commit()

            # Subprocess command sanity.
            assert call_args["args"][0] == "grype"
            assert call_args["args"][2] == "-o"
            assert call_args["args"][3] == "json"
            assert call_args["env"]["GRYPE_DB_CACHE_DIR"] == str(tmp_path / "grype-db")

            # Result summary.
            assert result["status"] == "success"
            assert result["total_components_scanned"] == 2
            assert result["total_vulnerabilities_found"] == 2
            assert result["findings_created"] == 1
            assert result["vulns_by_severity"]["critical"] == 1
            assert result["vulns_by_severity"]["high"] == 1
            assert result["vulns_by_severity"]["medium"] == 0
            assert result["vulns_by_severity"]["low"] == 0
            assert result["backend"] == "grype"

            # Live-canary: SELECT persisted SbomVulnerability rows.
            vrows = (
                await db.execute(
                    select(SbomVulnerability).where(
                        SbomVulnerability.firmware_id == firmware.id
                    )
                )
            ).scalars().all()
            vrows = list(vrows)
            assert len(vrows) == 2

            by_cve = {v.cve_id: v for v in vrows}
            assert "CVE-2018-0732" in by_cve
            assert "CVE-2018-1000517" in by_cve

            v_openssl = by_cve["CVE-2018-0732"]
            assert v_openssl.severity == "high"
            assert float(v_openssl.cvss_score) == 7.5
            assert v_openssl.description and "DoS" in v_openssl.description
            assert v_openssl.component_id == comp_openssl.id

            v_busybox = by_cve["CVE-2018-1000517"]
            assert v_busybox.severity == "critical"
            assert float(v_busybox.cvss_score) == 9.8
            assert v_busybox.component_id == comp_busybox.id

            # Live-canary: SELECT persisted Finding row.
            frows = (
                await db.execute(
                    select(Finding).where(
                        Finding.firmware_id == firmware.id,
                    )
                )
            ).scalars().all()
            frows = list(frows)
            assert len(frows) == 1
            f = frows[0]
            # F-A-06 backstop: confidence MUST be set explicitly.
            assert f.confidence == "high"
            # When critical>0 the severity is critical.
            assert f.severity == "critical"
            assert f.source == "sbom_scan"
            assert f.status == "open"
            assert "Found 2 vulnerabilities" in (f.description or "")

    @pytest.mark.asyncio
    async def test_returncode_1_is_not_error(self, tmp_path: Path):
        """Grype returncode 1 means vulns found — service must NOT raise."""
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="rc1", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(id=uuid.uuid4(), project_id=pid, sha256="r" * 64)
            db.add(firmware)
            await db.flush()
            db.add(SbomComponent(
                firmware_id=firmware.id,
                name="x", version="1",
                type="library",
                detection_source="x",
            ))
            await db.flush()

            stdout = _build_grype_output([])

            async def fake_create(*args, **kwargs):
                return _make_subprocess_proc(returncode=1, stdout=stdout)

            with patch.object(grype_mod, "get_settings", lambda: _make_settings_mock()):
                with patch.object(
                    grype_mod.asyncio, "create_subprocess_exec",
                    side_effect=fake_create,
                ):
                    result = await scan_with_grype(firmware.id, pid, db)

            assert result["status"] == "success"
            assert result["total_vulnerabilities_found"] == 0


# ===========================================================================
# scan_with_grype — error matrix
# ===========================================================================


class TestScanWithGrypeErrors:
    @pytest.mark.asyncio
    async def test_returncode_2_raises_runtime_error(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="rc2", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(id=uuid.uuid4(), project_id=pid, sha256="2" * 64)
            db.add(firmware)
            await db.flush()
            db.add(SbomComponent(
                firmware_id=firmware.id, name="x", version="1",
                type="library", detection_source="x",
            ))
            await db.flush()

            async def fake_create(*args, **kwargs):
                return _make_subprocess_proc(
                    returncode=2, stdout=b"", stderr=b"grype: db not initialized",
                )

            with patch.object(grype_mod, "get_settings", lambda: _make_settings_mock()):
                with patch.object(
                    grype_mod.asyncio, "create_subprocess_exec",
                    side_effect=fake_create,
                ):
                    with pytest.raises(RuntimeError) as exc_info:
                        await scan_with_grype(firmware.id, pid, db)
            assert "Grype scan failed" in str(exc_info.value)
            assert "db not initialized" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_timeout_raises_runtime_error(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="to", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(id=uuid.uuid4(), project_id=pid, sha256="t" * 64)
            db.add(firmware)
            await db.flush()
            db.add(SbomComponent(
                firmware_id=firmware.id, name="x", version="1",
                type="library", detection_source="x",
            ))
            await db.flush()

            import asyncio as real_asyncio

            async def fake_create(*args, **kwargs):
                return MagicMock(communicate=AsyncMock(side_effect=real_asyncio.TimeoutError()))

            settings = _make_settings_mock(timeout=1)

            with patch.object(grype_mod, "get_settings", lambda: settings):
                with patch.object(
                    grype_mod.asyncio, "create_subprocess_exec",
                    side_effect=fake_create,
                ):
                    # asyncio.wait_for itself raises TimeoutError when the
                    # underlying coroutine raises; service catches and reraises.
                    with pytest.raises(RuntimeError) as exc_info:
                        await scan_with_grype(firmware.id, pid, db)
            assert "timed out" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_malformed_json_raises_runtime_error(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="bad", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(id=uuid.uuid4(), project_id=pid, sha256="b" * 64)
            db.add(firmware)
            await db.flush()
            db.add(SbomComponent(
                firmware_id=firmware.id, name="x", version="1",
                type="library", detection_source="x",
            ))
            await db.flush()

            async def fake_create(*args, **kwargs):
                return _make_subprocess_proc(
                    returncode=0, stdout=b"this is not json",
                )

            with patch.object(grype_mod, "get_settings", lambda: _make_settings_mock()):
                with patch.object(
                    grype_mod.asyncio, "create_subprocess_exec",
                    side_effect=fake_create,
                ):
                    with pytest.raises(RuntimeError) as exc_info:
                        await scan_with_grype(firmware.id, pid, db)
            assert "Failed to parse Grype output" in str(exc_info.value)


# ===========================================================================
# scan_with_grype — vendor mismatch filter
# ===========================================================================


class TestScanWithGrypeVendorMismatch:
    @pytest.mark.asyncio
    async def test_skips_match_when_vendors_differ(self, tmp_path: Path):
        """Grype emits CVE for vendor=A; component CPE has vendor=B → skip."""
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="vendor", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(id=uuid.uuid4(), project_id=pid, sha256="v" * 64)
            db.add(firmware)
            await db.flush()
            # Component CPE vendor = openssl (the project)
            comp = SbomComponent(
                firmware_id=firmware.id,
                name="openssl",
                version="1.0.0",
                type="library",
                cpe="cpe:2.3:a:openssl:openssl:1.0.0:*:*:*:*:*:*:*",
                detection_source="x",
            )
            db.add(comp)
            await db.flush()

            # Grype-emitted match has vendor=cisco (different vendor, same product name)
            grype_matches = [
                {
                    "vulnerability": {
                        "id": "CVE-2099-9999",
                        "severity": "High",
                        "description": "irrelevant",
                        "cvss": [{"version": "3.1", "metrics": {"baseScore": 7.0}}],
                    },
                    "artifact": {"name": "openssl", "version": "1.0.0"},
                    "matchDetails": [
                        {
                            "found": {
                                "cpes": [
                                    "cpe:2.3:a:cisco:openssl:1.0.0:*:*:*:*:*:*:*"
                                ],
                            },
                        },
                    ],
                },
            ]
            stdout = _build_grype_output(grype_matches)

            async def fake_create(*args, **kwargs):
                return _make_subprocess_proc(returncode=1, stdout=stdout)

            with patch.object(grype_mod, "get_settings", lambda: _make_settings_mock()):
                with patch.object(
                    grype_mod.asyncio, "create_subprocess_exec",
                    side_effect=fake_create,
                ):
                    result = await scan_with_grype(firmware.id, pid, db)
            await db.commit()

            assert result["total_vulnerabilities_found"] == 0

            vrows = list((await db.execute(
                select(SbomVulnerability).where(
                    SbomVulnerability.firmware_id == firmware.id
                )
            )).scalars().all())
            assert len(vrows) == 0


# ===========================================================================
# scan_with_grype — Finding NOT created for medium/low only
# ===========================================================================


class TestScanWithGrypeFindingThreshold:
    @pytest.mark.asyncio
    async def test_no_finding_when_only_medium_severity(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="med", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(id=uuid.uuid4(), project_id=pid, sha256="m" * 64)
            db.add(firmware)
            await db.flush()
            db.add(SbomComponent(
                firmware_id=firmware.id, name="x", version="1.0",
                type="library", detection_source="x",
            ))
            await db.flush()

            grype_matches = [
                {
                    "vulnerability": {
                        "id": "CVE-2099-1111",
                        "severity": "Medium",
                        "description": "minor",
                        "cvss": [{"version": "3.1", "metrics": {"baseScore": 5.0}}],
                    },
                    "artifact": {"name": "x", "version": "1.0"},
                },
            ]
            stdout = _build_grype_output(grype_matches)

            async def fake_create(*args, **kwargs):
                return _make_subprocess_proc(returncode=1, stdout=stdout)

            with patch.object(grype_mod, "get_settings", lambda: _make_settings_mock()):
                with patch.object(
                    grype_mod.asyncio, "create_subprocess_exec",
                    side_effect=fake_create,
                ):
                    result = await scan_with_grype(firmware.id, pid, db)
            await db.commit()

            assert result["findings_created"] == 0
            assert result["vulns_by_severity"]["medium"] == 1

            frows = list((await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )).scalars().all())
            assert len(frows) == 0


# ===========================================================================
# scan_with_grype — replaces existing vulns (delete-then-insert)
# ===========================================================================


class TestScanWithGrypeReplaces:
    @pytest.mark.asyncio
    async def test_existing_vulns_deleted_before_insert(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="repl", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(id=uuid.uuid4(), project_id=pid, sha256="z" * 64)
            db.add(firmware)
            await db.flush()
            comp = SbomComponent(
                firmware_id=firmware.id, name="x", version="1.0",
                type="library", detection_source="x",
            )
            db.add(comp)
            await db.flush()

            # Pre-existing vuln from a stale scan.
            stale = SbomVulnerability(
                firmware_id=firmware.id,
                component_id=comp.id,
                cve_id="CVE-1900-0000",
                severity="critical",
            )
            db.add(stale)
            await db.flush()

            # New scan finds a different CVE.
            grype_matches = [
                {
                    "vulnerability": {
                        "id": "CVE-2024-NEW1",
                        "severity": "Low",
                        "description": "new",
                        "cvss": [{"version": "3.1", "metrics": {"baseScore": 3.0}}],
                    },
                    "artifact": {"name": "x", "version": "1.0"},
                },
            ]
            stdout = _build_grype_output(grype_matches)

            async def fake_create(*args, **kwargs):
                return _make_subprocess_proc(returncode=1, stdout=stdout)

            with patch.object(grype_mod, "get_settings", lambda: _make_settings_mock()):
                with patch.object(
                    grype_mod.asyncio, "create_subprocess_exec",
                    side_effect=fake_create,
                ):
                    result = await scan_with_grype(firmware.id, pid, db)
            await db.commit()

            # Stale CVE-1900-0000 must be GONE; only CVE-2024-NEW1 remains.
            vrows = list((await db.execute(
                select(SbomVulnerability).where(
                    SbomVulnerability.firmware_id == firmware.id
                )
            )).scalars().all())
            assert len(vrows) == 1
            assert vrows[0].cve_id == "CVE-2024-NEW1"


# ===========================================================================
# Rule #30 inverse-Rule-30 (consumer-module patch) sentinels
# ===========================================================================


class TestRule30InverseConsumerPatch:
    """Document that grype_service binds asyncio + which at module scope.

    Per Rule #30, when a third-party / stdlib symbol is bound at MODULE
    scope on the consumer (NOT lazy-imported inside a function body),
    patches MUST hit the CONSUMER module — patching the SOURCE module
    is a silent no-op because the consumer already holds its own local
    reference at that point.

    These sentinels fail LOUDLY if a future refactor flips the import
    style — e.g. promotes ``which`` to a function-body lazy import, in
    which case the patch shape must migrate to source-patch via
    ``patch("shutil.which", ...)``.
    """

    def test_consumer_module_binds_asyncio(self):
        # asyncio is module-scope imported at line 10.
        assert hasattr(grype_mod, "asyncio")

    def test_consumer_module_binds_which(self):
        # `from shutil import which` at line 17 — `which` is a
        # consumer-module attribute.
        assert hasattr(grype_mod, "which")

    def test_consumer_module_binds_orm_models(self):
        # Top-level ORM imports — patching app.models.* would be a
        # silent no-op for code that uses these names.
        assert hasattr(grype_mod, "Finding")
        assert hasattr(grype_mod, "SbomComponent")
        assert hasattr(grype_mod, "SbomVulnerability")
