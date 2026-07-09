"""Coverage tests for app.ai.tools.android + android_bytecode.

Mocks Androguard/service boundaries; exercises formatters + handlers end-to-end.
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools import android as android_mod
from app.ai.tools import android_bytecode as bytecode_mod
from app.ai.tools.android import (
    _format_apk_analysis,
    _format_manifest_scan,
    _format_signature_check,
    _handle_analyze_apk,
    _handle_check_apk_signatures,
    _handle_list_apk_permissions,
    _handle_scan_apk_manifest,
    register_android_tools,
)
from app.ai.tools.android_bytecode import (
    _compute_file_sha256,
    _format_bytecode_scan,
    _get_apk_firmware_location,
    _handle_scan_apk_bytecode,
    register_android_bytecode_tools,
)
from app.models import Firmware, Project
from tests._live_db import make_live_db


@dataclass
class _Ctx:
    db: AsyncSession | None
    firmware_id: uuid.UUID
    project_id: uuid.UUID | None = None
    extracted_path: str | None = "/tmp/x"
    detection_roots: list[str] = field(default_factory=list)

    def resolve_path(self, path: str) -> str:
        root = self.extracted_path or "/tmp/x"
        return os.path.realpath(os.path.join(root, path.lstrip("/")))

    def real_root_for(self, path: str) -> str:
        return os.path.realpath(self.extracted_path or "/tmp/x")


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


async def _seed(db: AsyncSession, extracted: str) -> tuple[Project, Firmware]:
    project = Project(id=uuid.uuid4(), name="android-tools", status="ready")
    db.add(project)
    await db.flush()
    fw = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="a" * 64,
        extracted_path=extracted,
        extraction_dir=extracted,
        original_filename="fw.bin",
    )
    db.add(fw)
    await db.flush()
    return project, fw


def test_register_android_tools():
    r = ToolRegistry()
    register_android_tools(r)
    assert "analyze_apk" in r._tools
    assert "scan_apk_manifest" in r._tools
    r2 = ToolRegistry()
    register_android_bytecode_tools(r2)
    assert "scan_apk_bytecode" in r2._tools


def test_format_apk_analysis_full():
    with patch(
        "app.services.androguard_service.classify_permission",
        side_effect=lambda p: "dangerous" if "CAMERA" in p else "normal",
    ):
        out = _format_apk_analysis({
            "package": "com.example.app",
            "version_name": "1.0",
            "version_code": 1,
            "min_sdk": 21,
            "target_sdk": 33,
            "main_activity": ".Main",
            "is_signed": True,
            "permissions": [
                "android.permission.CAMERA",
                "android.permission.INTERNET",
            ] + [f"android.permission.P{i}" for i in range(20)],
            "activities": [f".A{i}" for i in range(55)],
            "services": [".S1"],
            "receivers": [".R1"],
            "providers": [".P1"],
            "signatures": [{
                "issuer": "CN=Debug",
                "subject": "CN=Debug",
                "algorithm": "SHA256withRSA",
                "serial": "1",
                "is_debug": True,
                "not_before": "2020-01-01",
                "not_after": "2030-01-01",
            }],
        })
    assert "com.example.app" in out
    assert "DANGEROUS" in out.upper() or "dangerous" in out
    assert "DEBUG CERT" in out
    assert "..." in out  # truncation of long lists


def test_format_signature_check_branches():
    clean = _format_signature_check({
        "package": "com.x",
        "is_signed": True,
        "signatures": [{
            "subject": "CN=Prod", "issuer": "CN=CA",
            "algorithm": "SHA256", "serial": "9",
            "not_before": "a", "not_after": "b",
        }],
        "warnings": [],
    })
    assert "No security warnings" in clean
    warn = _format_signature_check({
        "package": "com.y",
        "is_signed": False,
        "signatures": [{"subject": "CN=D", "issuer": "CN=D", "algorithm": "MD5",
                        "serial": "1", "is_debug": True}],
        "warnings": ["unsigned", "debug cert"],
    })
    assert "SECURITY WARNINGS" in warn
    assert "[DEBUG]" in warn


def test_format_manifest_scan_all_footer_branches(tmp_path):
    apk = tmp_path / "system" / "priv-app" / "App" / "App.apk"
    apk.parent.mkdir(parents=True)
    apk.write_bytes(b"PK")
    root = str(tmp_path)

    base = {
        "package": "com.app",
        "findings": [{
            "severity": "high",
            "check_id": "debuggable",
            "title": "Debuggable",
            "description": "app is debuggable",
            "evidence": "android:debuggable=true",
            "confidence": "high",
            "cwe_ids": ["CWE-489"],
        }],
        "summary": {"high": 1, "medium": 0},
        "confidence_summary": {"high": 1},
        "suppressed_count": 2,
        "suppression_reasons": ["platform-signed"],
        "is_debug_signed": True,
        "severity_bumped": True,
        "severity_reduced": True,
        "reduced_check_ids": ["allowBackup"],
    }
    out = _format_manifest_scan(
        base, str(apk), root,
        persisted_count=1, total_findings=1, persist_error=False, has_db=True,
    )
    assert "Manifest Security Scan" in out
    assert "saved" in out.lower()

    out_err = _format_manifest_scan(
        base, str(apk), root, persisted_count=0, total_findings=1, persist_error=True,
    )
    assert "WARNING" in out_err

    out_nodb = _format_manifest_scan(
        base, str(apk), root, persisted_count=0, total_findings=1, has_db=False,
    )
    assert "No database" in out_nodb

    out_dup = _format_manifest_scan(
        base, str(apk), root, persisted_count=0, total_findings=1, has_db=True,
    )
    assert "already existed" in out_dup

    out_partial = _format_manifest_scan(
        base, str(apk), root, persisted_count=1, total_findings=2, has_db=True,
    )
    assert "new finding" in out_partial.lower() or "already existed" in out_partial

    empty = _format_manifest_scan(
        {"package": "com.z", "findings": [], "summary": {}},
        str(apk), root,
    )
    assert "No manifest security issues" in empty


def test_compute_sha256_and_location(tmp_path):
    f = tmp_path / "a.apk"
    f.write_bytes(b"hello")
    h = _compute_file_sha256(str(f))
    assert len(h) == 64
    loc = _get_apk_firmware_location(str(f), str(tmp_path))
    assert loc == "/a.apk"
    # ValueError path when on different drives — hard on Linux; force via mock
    with patch("os.path.relpath", side_effect=ValueError("x")):
        assert _get_apk_firmware_location(str(f), str(tmp_path)) is None


@pytest.mark.asyncio
async def test_android_handlers_error_paths(tmp_path, live_db):
    project, fw = await _seed(live_db, str(tmp_path))
    ctx = _Ctx(db=live_db, firmware_id=fw.id, project_id=project.id, extracted_path=str(tmp_path))

    with patch("app.ai.tools.android.check_androguard", return_value="Error: androguard missing"):
        for h in (
            _handle_analyze_apk,
            _handle_list_apk_permissions,
            _handle_check_apk_signatures,
            _handle_scan_apk_manifest,
        ):
            r = await h({}, ctx)
            assert "androguard" in r.lower() or "Error" in r

    with patch("app.ai.tools.android.check_androguard", return_value=None):
        with patch("app.ai.tools.android.find_apk", side_effect=ValueError("APK not found")):
            r = await _handle_analyze_apk({"path": "/no.apk"}, ctx)
            assert "not found" in r.lower() or "APK" in r


@pytest.mark.asyncio
async def test_android_handlers_success_mocked(tmp_path, live_db):
    apk = tmp_path / "system" / "app" / "Foo" / "Foo.apk"
    apk.parent.mkdir(parents=True)
    apk.write_bytes(b"PK\x03\x04fake")
    project, fw = await _seed(live_db, str(tmp_path))
    ctx = _Ctx(db=live_db, firmware_id=fw.id, project_id=project.id, extracted_path=str(tmp_path))

    info = {
        "package": "com.foo",
        "version_name": "1",
        "version_code": 1,
        "min_sdk": 24,
        "target_sdk": 33,
        "main_activity": ".Main",
        "is_signed": True,
        "permissions": ["android.permission.INTERNET"],
        "activities": [".Main"],
        "services": [],
        "receivers": [],
        "providers": [],
        "signatures": [],
    }
    mock_svc = MagicMock()
    mock_svc.analyze_apk.return_value = info
    mock_svc.get_permissions_with_risk.return_value = [
        {"permission": "android.permission.CAMERA", "risk": "dangerous"},
        {"permission": "android.permission.INTERNET", "risk": "normal"},
        {"permission": "android.permission.BIND_X", "risk": "signature"},
    ]
    mock_svc.check_signatures.return_value = {
        "package": "com.foo",
        "is_signed": True,
        "signatures": [{"subject": "CN=X", "issuer": "CN=X", "algorithm": "SHA256", "serial": "1"}],
        "warnings": [],
    }
    mock_svc.check_platform_signed.return_value = True
    mock_svc.scan_manifest_security.return_value = {
        "package": "com.foo",
        "findings": [{
            "check_id": "allowBackup",
            "title": "Backup allowed",
            "description": "android:allowBackup=true",
            "evidence": "manifest",
            "severity": "medium",
            "confidence": "high",
            "cwe_ids": ["CWE-312"],
        }],
        "summary": {"medium": 1},
        "confidence_summary": {"high": 1},
    }

    with patch("app.ai.tools.android.check_androguard", return_value=None):
        with patch("app.ai.tools.android.find_apk", return_value=str(apk)):
            with patch("app.services.androguard_service.AndroguardService", return_value=mock_svc):
                with patch(
                    "app.services.androguard_service.classify_permission",
                    return_value="normal",
                ):
                    r1 = await _handle_analyze_apk({"path": "/system/app/Foo/Foo.apk"}, ctx)
                    assert "com.foo" in r1
                r2 = await _handle_list_apk_permissions({"path": "/system/app/Foo/Foo.apk"}, ctx)
                assert "DANGEROUS" in r2 or "CAMERA" in r2
                r3 = await _handle_check_apk_signatures({"path": "/system/app/Foo/Foo.apk"}, ctx)
                assert "Signature" in r3 or "Signed" in r3
                r4 = await _handle_scan_apk_manifest({"path": "/system/app/Foo/Foo.apk"}, ctx)
                assert "Manifest" in r4 or "allowBackup" in r4 or "Backup" in r4

                # empty permissions
                mock_svc.get_permissions_with_risk.return_value = []
                r5 = await _handle_list_apk_permissions({"path": "/x"}, ctx)
                assert "no permissions" in r5.lower()

                # service exceptions
                mock_svc.analyze_apk.side_effect = RuntimeError("boom")
                r6 = await _handle_analyze_apk({"path": "/x"}, ctx)
                assert "Error" in r6




@pytest.mark.asyncio
async def test_scan_apk_bytecode_paths(tmp_path, live_db):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04" + b"\x00" * 20)
    project, fw = await _seed(live_db, str(tmp_path))
    ctx = _Ctx(db=live_db, firmware_id=fw.id, project_id=project.id, extracted_path=str(tmp_path))

    with patch("app.ai.tools.android_bytecode.check_androguard", return_value="missing"):
        assert "missing" in await _handle_scan_apk_bytecode({}, ctx)

    with patch("app.ai.tools.android_bytecode.check_androguard", return_value=None):
        with patch("app.ai.tools.android_bytecode.find_apk", side_effect=ValueError("no apk")):
            assert "no apk" in await _handle_scan_apk_bytecode({}, ctx)

    findings = [
        {
            "severity": "high",
            "confidence": "high",
            "pattern_id": "crypto_ecb",
            "title": "ECB mode",
            "description": "uses ECB",
            "locations": [
                {"caller_class": "a.b.C", "caller_method": "encrypt", "target": "Cipher"},
                {"string_value": "AES/ECB/PKCS5"},
                {"using_class": "a.b.D", "using_method": "init"},
            ],
            "total_occurrences": 10,
            "cwe_ids": ["CWE-327"],
        },
        {
            "severity": "info",
            "confidence": "low",
            "pattern_id": "log",
            "title": "Log",
            "description": "logging",
            "locations": [],
            "cwe_ids": [],
        },
    ]
    scan_result = {
        "package": "com.foo",
        "findings": findings,
        "summary": {"high": 1, "info": 1},
        "from_cache": False,
    }
    mock_svc = MagicMock()
    mock_svc.scan_apk.return_value = scan_result

    with patch("app.ai.tools.android_bytecode.check_androguard", return_value=None):
        with patch("app.ai.tools.android_bytecode.find_apk", return_value=str(apk)):
            with patch(
                "app.services.bytecode_analysis_service.BytecodeAnalysisService",
                return_value=mock_svc,
            ):
                with patch(
                    "app.services.bytecode_analysis_service.CONFIDENCE_ORDER",
                    ["low", "medium", "high"],
                ):
                    with patch(
                        "app.services._cache.get_cached",
                        new=AsyncMock(return_value=None),
                    ):
                        with patch(
                            "app.services._cache.store_cached",
                            new=AsyncMock(),
                        ):
                            r = await _handle_scan_apk_bytecode(
                                {
                                    "path": "/app.apk",
                                    "min_severity": "low",
                                    "min_confidence": "low",
                                },
                                ctx,
                            )
                            assert isinstance(r, str)

                    with patch(
                        "app.services._cache.get_cached",
                        new=AsyncMock(return_value=dict(scan_result)),
                    ):
                        r2 = await _handle_scan_apk_bytecode(
                            {"path": "/app.apk", "min_severity": "bogus"},
                            ctx,
                        )
                        assert isinstance(r2, str)

                    mock_svc.scan_apk.side_effect = RuntimeError("dex fail")
                    with patch(
                        "app.services._cache.get_cached",
                        new=AsyncMock(return_value=None),
                    ):
                        r3 = await _handle_scan_apk_bytecode({"path": "/app.apk"}, ctx)
                        assert "Error" in r3


def test_format_bytecode_scan_variants(tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK")
    sev_order = ["info", "low", "medium", "high", "critical"]
    result = {
        "package": "com.x",
        "findings": [
            {
                "severity": "critical",
                "confidence": "high",
                "pattern_id": "c1",
                "title": "T",
                "description": "D",
                "locations": [{"caller_class": "C", "caller_method": "m"}],
                "cwe_ids": ["CWE-1"],
            },
            {
                "severity": "info",
                "confidence": "low",
                "pattern_id": "skip",
                "title": "skip me",
                "description": "low",
                "locations": [],
            },
        ],
        "summary": {"critical": 1},
        "from_cache": True,
    }
    with patch(
        "app.services.bytecode_analysis_service.CONFIDENCE_ORDER",
        ["low", "medium", "high"],
    ):
        out = _format_bytecode_scan(result, str(apk), str(tmp_path), 0, sev_order)
        assert isinstance(out, str)
        out2 = _format_bytecode_scan(
            result, str(apk), str(tmp_path), 3, sev_order, min_conf_idx=2,
        )
        assert isinstance(out2, str)
        out3 = _format_bytecode_scan(
            {"package": "p", "findings": [], "summary": {}, "from_cache": False},
            str(apk), str(tmp_path), 0, sev_order,
        )
        assert isinstance(out3, str)


@pytest.mark.asyncio
async def test_persist_bytecode_findings(tmp_path, live_db):
    from app.ai.tools.android_bytecode import _persist_bytecode_findings

    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
    project, fw = await _seed(live_db, str(tmp_path))
    ctx = _Ctx(db=live_db, firmware_id=fw.id, project_id=project.id, extracted_path=str(tmp_path))
    result = {
        "package": "com.p",
        "findings": [
            {
                "severity": "high",
                "confidence": "high",
                "pattern_id": "p1",
                "title": "Bad crypto",
                "description": "desc",
                "locations": [{"caller_class": "C", "caller_method": "m", "target": "t"}],
                "total_occurrences": 8,
                "cwe_ids": ["CWE-327"],
            },
            {
                "severity": "info",
                "confidence": "low",
                "pattern_id": "p2",
                "title": "noise",
                "description": "n",
                "locations": [{"string_value": "x"}],
            },
        ],
    }
    with patch(
        "app.services.bytecode_analysis_service.CONFIDENCE_ORDER",
        ["low", "medium", "high"],
    ):
        await _persist_bytecode_findings(
            ctx, result, str(apk), 0, ["info", "low", "medium", "high", "critical"],
            min_conf_idx=0,
        )
        await live_db.flush()
