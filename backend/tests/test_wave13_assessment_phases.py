"""Wave 13: AssessmentService phase bodies (credential/sbom/config/malware/
binary/android/semgrep) — largest residual clusters in assessment_service.py.
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.security_audit._base import SecurityFinding


def _svc(tmp_path: Path):
    from app.services.assessment_service import AssessmentService

    db = AsyncMock()
    db.flush = AsyncMock()
    db.get = AsyncMock(return_value=None)
    db.scalar = AsyncMock(return_value=0)
    db.add = MagicMock()
    svc = AssessmentService(
        project_id=uuid.uuid4(),
        firmware_id=uuid.uuid4(),
        extracted_path=str(tmp_path),
        db=db,
    )
    svc._detection_roots = [str(tmp_path)]
    svc._create_finding = AsyncMock(return_value=MagicMock())
    return svc


def _sf(title="t", severity="medium", **kw):
    return SecurityFinding(
        title=title,
        severity=severity,
        description=kw.get("description", "d"),
        evidence=kw.get("evidence", "e"),
        file_path=kw.get("file_path", "/etc/x"),
        line_number=kw.get("line_number", 1),
        cwe_ids=kw.get("cwe_ids", ["CWE-1"]),
    )


class TestAssessmentCredentialConfigPhases:
    @pytest.mark.asyncio
    async def test_credential_and_config_with_findings(self, tmp_path: Path):
        root = tmp_path / "root"
        root.mkdir()
        svc = _svc(root)
        findings = [_sf("cred"), _sf("shadow", severity="high")]

        def fake_scan(r, scanners, out):
            out.extend(findings)

        with patch(
            "app.services.assessment_service.run_scan_subset", side_effect=fake_scan
        ):
            n1 = await svc._phase_credential_crypto()
            n2 = await svc._phase_config_filesystem()
        assert n1 == 2
        assert n2 == 2
        assert svc._create_finding.await_count == 4


class TestAssessmentSbomPhase:
    @pytest.mark.asyncio
    async def test_sbom_generates_and_scans(self, tmp_path: Path):
        root = tmp_path / "r"
        root.mkdir()
        svc = _svc(root)
        svc.db.scalar = AsyncMock(return_value=0)
        fw = MagicMock()
        svc.db.get = AsyncMock(return_value=fw)

        comps = [
            {
                "name": "busybox",
                "version": "1.36",
                "type": "application",
                "cpe": None,
                "purl": "pkg:generic/busybox@1.36",
                "supplier": None,
                "detection_source": "path",
                "detection_confidence": 0.9,
                "file_paths": ["/bin/busybox"],
                "metadata": {},
            }
        ]
        fake_sbom = MagicMock()
        fake_sbom.generate_sbom = MagicMock(return_value=comps)
        fake_vuln = MagicMock()
        fake_vuln.scan_components = AsyncMock(
            return_value={"findings_created": 3}
        )

        with patch(
            "app.services.assessment_service.SbomService", return_value=fake_sbom
        ), patch(
            "app.services.assessment_service.VulnerabilityService",
            return_value=fake_vuln,
        ):
            n = await svc._phase_sbom_vulnerability()
        assert n == 3
        assert svc.db.add.call_count == 1
        svc.db.flush.assert_awaited()

    @pytest.mark.asyncio
    async def test_sbom_existing_skips_generate(self, tmp_path: Path):
        root = tmp_path / "r"
        root.mkdir()
        svc = _svc(root)
        svc.db.scalar = AsyncMock(return_value=5)
        fake_vuln = MagicMock()
        fake_vuln.scan_components = AsyncMock(
            return_value={"findings_created": 1}
        )
        with patch(
            "app.services.assessment_service.VulnerabilityService",
            return_value=fake_vuln,
        ):
            n = await svc._phase_sbom_vulnerability()
        assert n == 1

    @pytest.mark.asyncio
    async def test_sbom_no_fw_row_uses_path_ctor(self, tmp_path: Path):
        root = tmp_path / "r"
        root.mkdir()
        svc = _svc(root)
        svc.db.scalar = AsyncMock(return_value=0)
        svc.db.get = AsyncMock(return_value=None)
        fake_sbom = MagicMock()
        fake_sbom.generate_sbom = MagicMock(return_value=[])
        fake_vuln = MagicMock()
        fake_vuln.scan_components = AsyncMock(
            return_value={"findings_created": 0}
        )
        with patch(
            "app.services.assessment_service.SbomService", return_value=fake_sbom
        ) as sbom_cls, patch(
            "app.services.assessment_service.VulnerabilityService",
            return_value=fake_vuln,
        ):
            n = await svc._phase_sbom_vulnerability()
        assert n == 0
        # constructed with extracted path string
        assert sbom_cls.called


class TestAssessmentMalwareSemgrep:
    @pytest.mark.asyncio
    async def test_yara_findings_and_errors(self, tmp_path: Path):
        root = tmp_path / "r"
        root.mkdir()
        (root / "etc").mkdir()
        svc = _svc(root)
        yara = SimpleNamespace(
            findings=[_sf("yara-hit", severity="high")],
            errors=["rule-x failed"],
        )
        with patch(
            "app.services.assessment_service.scan_firmware_multi", return_value=yara
        ), patch.object(
            svc, "_run_semgrep", new=AsyncMock(return_value=2)
        ):
            n = await svc._phase_malware_detection()
        assert n == 3  # 1 yara + 2 semgrep
        assert svc._create_finding.await_count == 1

    @pytest.mark.asyncio
    async def test_yara_import_error_and_generic(self, tmp_path: Path):
        root = tmp_path / "r"
        root.mkdir()
        svc = _svc(root)
        with patch(
            "app.services.assessment_service.scan_firmware_multi",
            side_effect=ImportError("no yara"),
        ), patch.object(svc, "_run_semgrep", new=AsyncMock(return_value=0)):
            n = await svc._phase_malware_detection()
        assert n == 0

        with patch(
            "app.services.assessment_service.scan_firmware_multi",
            side_effect=RuntimeError("boom"),
        ), patch.object(
            svc, "_run_semgrep", new=AsyncMock(side_effect=RuntimeError("sg"))
        ):
            n2 = await svc._phase_malware_detection()
        assert n2 == 0

    @pytest.mark.asyncio
    async def test_semgrep_full_happy_path(self, tmp_path: Path):
        root = tmp_path / "r"
        (root / "etc").mkdir(parents=True)
        (root / "usr" / "bin").mkdir(parents=True)
        (root / "www").mkdir(parents=True)
        svc = _svc(root)
        payload = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.os-system",
                    "extra": {
                        "message": "os.system",
                        "severity": "ERROR",
                        "lines": "os.system(x)",
                    },
                    "path": str(root / "etc" / "x.sh"),
                    "start": {"line": 3},
                },
                {
                    "check_id": "a.b.info",
                    "extra": {"message": "info", "severity": "INFO", "lines": ""},
                    "path": str(root / "www" / "i.js"),
                    "start": {"line": 1},
                },
                {
                    "check_id": "a.b.warn",
                    "extra": {
                        "message": "warn",
                        "severity": "WARNING",
                        "lines": "x",
                    },
                    "path": "/outside/file",
                    "start": {"line": 9},
                },
            ]
        }

        class Proc:
            async def communicate(self):
                return json.dumps(payload).encode(), b""

        with patch("shutil.which", return_value="/usr/bin/semgrep"), patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=Proc()),
        ):
            n = await svc._run_semgrep()
        assert n == 3
        assert svc._create_finding.await_count == 3

    @pytest.mark.asyncio
    async def test_semgrep_missing_not_installed_and_timeout(self, tmp_path: Path):
        root = tmp_path / "r"
        root.mkdir()
        svc = _svc(root)
        with patch("shutil.which", return_value=None):
            assert await svc._run_semgrep() == 0

        (root / "etc").mkdir()
        svc2 = _svc(root)

        class Boom:
            async def communicate(self):
                raise TimeoutError("slow")

        with patch("shutil.which", return_value="/usr/bin/semgrep"), patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=Boom()),
        ):
            assert await svc2._run_semgrep() == 0

    @pytest.mark.asyncio
    async def test_semgrep_empty_stdout_and_bad_json(self, tmp_path: Path):
        root = tmp_path / "r"
        (root / "opt").mkdir(parents=True)
        svc = _svc(root)

        class Empty:
            async def communicate(self):
                return b"", b""

        class Bad:
            async def communicate(self):
                return b"not-json{", b""

        with patch("shutil.which", return_value="/usr/bin/semgrep"), patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=Empty()),
        ):
            assert await svc._run_semgrep() == 0

        with patch("shutil.which", return_value="/usr/bin/semgrep"), patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=Bad()),
        ):
            assert await svc._run_semgrep() == 0


class TestAssessmentBinaryProtections:
    @pytest.mark.asyncio
    async def test_poorly_protected_summary(self, tmp_path: Path):
        root = tmp_path / "r"
        root.mkdir()
        svc = _svc(root)
        results = [
            {
                "path": f"/bin/b{i}",
                "score": 0.5 if i < 15 else 1.0,
                "nx": False,
                "canary": False,
                "pie": False,
                "relro": "none",
            }
            for i in range(25)
        ]
        # one well protected
        results.append(
            {
                "path": "/bin/good",
                "score": 5.0,
                "nx": True,
                "canary": True,
                "pie": True,
                "relro": "full",
            }
        )
        with patch(
            "app.services.assessment_service._scan_all_binary_protections",
            return_value=results,
        ):
            n = await svc._phase_binary_protections()
        assert n == 1
        call_kw = svc._create_finding.await_args.kwargs
        assert "Weak binary protections" in call_kw["title"]
        assert "no-NX" in call_kw["evidence"]

    @pytest.mark.asyncio
    async def test_binary_empty_or_all_good(self, tmp_path: Path):
        root = tmp_path / "r"
        root.mkdir()
        svc = _svc(root)
        with patch(
            "app.services.assessment_service._scan_all_binary_protections",
            return_value=[],
        ):
            assert await svc._phase_binary_protections() == 0
        good = [{"path": "/bin/x", "score": 4.0, "nx": True, "canary": True, "pie": True, "relro": "full"}]
        with patch(
            "app.services.assessment_service._scan_all_binary_protections",
            return_value=good,
        ):
            assert await svc._phase_binary_protections() == 0


class TestAssessmentAndroidPhase:
    @pytest.mark.asyncio
    async def test_android_selinux_and_apks(self, tmp_path: Path):
        root = tmp_path / "r"
        sys_app = root / "system" / "app" / "Foo"
        sys_app.mkdir(parents=True)
        (root / "system" / "build.prop").write_text("ro.build=1\n")
        apk = sys_app / "Foo.apk"
        apk.write_bytes(b"PK\x03\x04" + b"\x00" * 20)
        priv = root / "system" / "priv-app" / "Bar"
        priv.mkdir(parents=True)
        (priv / "Bar.apk").write_bytes(b"PK\x03\x04" + b"\x00" * 10)
        svc = _svc(root)

        class Selinux:
            def analyze_policy(self):
                return {
                    "has_selinux": True,
                    "permissive_domains": ["unconfined_t", "shell_t"],
                    "enforcement": {"mode": "permissive"},
                }

        class ApkSvc:
            def analyze_apk(self, path):
                return {"dangerous_permissions": ["CAMERA", "SMS"]}

        with patch(
            "app.services.assessment_service.SELinuxService", return_value=Selinux()
        ), patch(
            "app.services.assessment_service.AndroguardService", return_value=ApkSvc()
        ):
            n = await svc._phase_android()
        # permissive domains + global permissive + dangerous apks
        assert n >= 2
        assert svc._create_finding.await_count >= 2

    @pytest.mark.asyncio
    async def test_android_no_selinux_and_import_error(self, tmp_path: Path):
        root = tmp_path / "r"
        (root / "system" / "app").mkdir(parents=True)
        (root / "system" / "build.prop").write_text("x=1\n")
        svc = _svc(root)

        class Selinux:
            def analyze_policy(self):
                return {"has_selinux": False}

        with patch(
            "app.services.assessment_service.SELinuxService", return_value=Selinux()
        ), patch(
            "app.services.assessment_service.AndroguardService",
            side_effect=ImportError("no androguard"),
        ):
            n = await svc._phase_android()
        assert n == 1

    @pytest.mark.asyncio
    async def test_android_not_android_returns_zero(self, tmp_path: Path):
        root = tmp_path / "plain"
        root.mkdir()
        svc = _svc(root)
        assert await svc._phase_android() == 0

    @pytest.mark.asyncio
    async def test_android_selinux_exception(self, tmp_path: Path):
        root = tmp_path / "r"
        root.mkdir()
        (root / "build.prop").write_text("x=1\n")
        svc = _svc(root)
        with patch(
            "app.services.assessment_service.SELinuxService",
            side_effect=RuntimeError("selinux boom"),
        ), patch(
            "app.services.assessment_service.AndroguardService",
            side_effect=RuntimeError("apk boom"),
        ):
            n = await svc._phase_android()
        assert n == 0
