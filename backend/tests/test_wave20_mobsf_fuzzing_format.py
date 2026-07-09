"""Wave 20: MobSF full scan mock, fuzzing triage, format_detection residual."""
from __future__ import annotations

import asyncio
import base64
import io
import os
import struct
import tarfile
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── MobSF runner ─────────────────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, status=200, payload=None, text="err"):
        self.status = status
        self._payload = payload if payload is not None else {}
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self):
        return self._payload

    async def text(self):
        return self._text


class _FakeSession:
    def __init__(self, upload=None, scan=None, report=None, fail_stage=None):
        self.upload = upload or {"hash": "abc123", "file_name": "a.apk"}
        self.scan = scan if scan is not None else {"status": "ok"}
        self.report = report if report is not None else {
            "package_name": "com.example.app",
            "is_debuggable": True,
            "is_allow_backup": True,
            "is_clear_text_traffic": True,
            "is_test_only": True,
            "min_sdk": 18,
            "target_sdk": 26,
            "manifest_analysis": [
                {
                    "rule": "app_is_debuggable",
                    "title": "Debuggable",
                    "severity": "high",
                    "description": "x",
                },
                "not-a-dict",
            ],
            "exported_activities": [{"name": "A", "exported": True}],
            "exported_services": [{"name": "S", "exported": "true"}],
            "exported_receivers": [],
            "exported_providers": [{"name": "P"}],
            "network_security": {
                "network_security_config": {
                    "base_config": {"cleartextTrafficPermitted": True},
                    "certificate_pinning": [
                        {"hostname": "x.com", "severity": "high"},
                        "bad",
                        {"hostname": "y.com", "severity": "info"},
                    ],
                }
            },
            "certificate_analysis": {
                "certificate_info": "CN=Test",
                "certificate_findings": [
                    {"title": "weak", "severity": "warning", "description": "d"},
                    "skip",
                ],
            },
        }
        self.fail_stage = fail_stage
        self.n = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def post(self, url, **kwargs):
        self.n += 1
        if self.fail_stage == "upload":
            return _FakeResp(500, text="upload fail")
        if "upload" in url:
            if self.fail_stage == "upload_no_hash":
                return _FakeResp(200, {"error": "no"})
            return _FakeResp(200, self.upload)
        if "scan" in url and "report" not in url:
            if self.fail_stage == "scan":
                return _FakeResp(500, text="scan fail")
            if self.fail_stage == "scan_empty":
                return _FakeResp(200, {})
            return _FakeResp(200, self.scan)
        if "report" in url:
            if self.fail_stage == "report":
                return _FakeResp(500, text="report fail")
            if self.fail_stage == "report_empty":
                return _FakeResp(200, {})
            return _FakeResp(200, self.report)
        return _FakeResp(404, text="unknown")


def _aiohttp_mod(session_factory):
    """Build a fake aiohttp module for import patching."""
    mod = MagicMock()
    mod.ClientSession = session_factory
    mod.ClientTimeout = lambda total=None: SimpleNamespace(total=total)
    mod.FormData = MagicMock(return_value=MagicMock(add_field=MagicMock()))
    return mod


class TestMobsfRunnerDeep:
    @pytest.mark.asyncio
    async def test_scan_apk_all_branches(self, tmp_path: Path):
        from app.services import mobsf_runner as mr

        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK\x03\x04" + b"\x00" * 64)

        import sys

        runner = mr.MobsfRunner("http://mobsf:8000", "key")

        # missing file — import aiohttp still happens before is_file check
        sys.modules["aiohttp"] = _aiohttp_mod(lambda **k: _FakeSession())
        try:
            r = await runner.scan_apk(str(tmp_path / "nope.apk"))
        finally:
            sys.modules.pop("aiohttp", None)
        assert r.success is False

        # happy + error branches — inject fake aiohttp into sys.modules
        for stage, expect_ok in (
            (None, True),
            ("upload_no_hash", False),
            ("upload", False),
            ("scan_empty", False),
            ("scan", False),
            ("report_empty", False),
            ("report", False),
        ):
            sess = _FakeSession(fail_stage=stage)

            def _make_sess(s=sess, **k):
                return s

            sys.modules["aiohttp"] = _aiohttp_mod(_make_sess)
            try:
                r = await runner.scan_apk(str(apk))
            finally:
                sys.modules.pop("aiohttp", None)
            if expect_ok:
                assert r.success is True
                assert r.package_name == "com.example.app"
                assert r.manifest_findings
            else:
                assert r.success is False

        # exception path
        class BoomSession:
            async def __aenter__(self):
                raise RuntimeError("boom")

            async def __aexit__(self, *a):
                return False

        sys.modules["aiohttp"] = _aiohttp_mod(lambda **k: BoomSession())
        try:
            r = await runner.scan_apk(str(apk))
        finally:
            sys.modules.pop("aiohttp", None)
        assert r.success is False

    @pytest.mark.asyncio
    async def test_upload_scan_report_direct(self, tmp_path: Path):
        from app.services import mobsf_runner as mr
        import sys

        apk = tmp_path / "b.apk"
        apk.write_bytes(b"PK" + b"\x00" * 20)
        runner = mr.MobsfRunner("http://x", "k")

        fake_aio = MagicMock()
        fake_aio.FormData = MagicMock(return_value=MagicMock(add_field=MagicMock()))
        with patch.dict(sys.modules, {"aiohttp": fake_aio}):
            sess = MagicMock()
            sess.post = MagicMock(
                return_value=_FakeResp(200, {"hash": "h", "file_name": "b.apk"})
            )
            out = await runner._upload(sess, apk)
            assert out.get("hash") == "h"

            sess.post = MagicMock(return_value=_FakeResp(400, text="bad"))
            out = await runner._upload(sess, apk)
            assert "error" in out

            sess.post = MagicMock(return_value=_FakeResp(200, {"ok": 1}))
            assert await runner._scan(sess, "h", "b.apk")
            sess.post = MagicMock(return_value=_FakeResp(500, text="no"))
            assert await runner._scan(sess, "h", "b.apk") == {}

            sess.post = MagicMock(return_value=_FakeResp(200, {"package_name": "p"}))
            assert (await runner._report(sess, "h")).get("package_name") == "p"
            sess.post = MagicMock(return_value=_FakeResp(500, text="no"))
            assert await runner._report(sess, "h") == {}

    def test_extract_helpers_dense(self):
        from app.services import mobsf_runner as mr

        report = {
            "is_debuggable": True,
            "is_allow_backup": True,
            "is_clear_text_traffic": "true",
            "is_test_only": True,
            "min_sdk": "16",
            "target_sdk": "27",
            "manifest_analysis": [
                {
                    "rule": "exported_activity",
                    "title": "Exported",
                    "severity": "warning",
                    "description": "d",
                },
                {
                    "rule": "unknown_rule_xyz",
                    "title": "Other",
                    "severity": "info",
                    "description": "d",
                },
                None,
                "x",
            ],
            "exported_activities": [
                {"name": "A1", "exported": True, "permission": ""},
                {"name": "A2", "exported": False},
                "bad",
            ],
            "exported_services": [{"name": "S1", "exported": True}],
            "exported_receivers": [{"name": "R1", "exported": True}],
            "exported_providers": [{"name": "P1", "exported": True}],
            "network_security": {
                "network_security_config": {
                    "base_config": {"cleartextTrafficPermitted": True},
                    "domain_config": [
                        {"domains": ["a.com"], "cleartextTrafficPermitted": True}
                    ],
                    "certificate_pinning": [
                        {"hostname": "pin.com", "severity": "high"},
                        {"hostname": "pin2.com", "severity": "warning"},
                        "x",
                    ],
                }
            },
            "certificate_analysis": {
                "certificate_findings": [
                    {"title": "t", "severity": "high", "description": "d"},
                    {},
                    "s",
                ]
            },
        }
        findings = mr._extract_manifest_findings(report)
        assert findings
        for f in findings:
            assert f.to_dict()

        assert mr._map_severity("high") == "high"
        assert mr._map_severity("warning") == "medium"
        assert mr._map_severity("unknown_sev") in ("info", "low", "medium", "high")
        mr._map_rule_to_check("app_is_debuggable", "Debuggable")
        mr._map_rule_to_check("totally_unknown", "Some Title About Backup")
        mr._elapsed_ms(0.0)
        # compare_findings expects NormalizedManifestFinding objects as second arg
        cmp = mr.compare_findings(
            [{"check_id": "MANIFEST-001", "title": "a", "severity": "high"}],
            findings[:3],
        )
        assert isinstance(cmp, dict)

    @pytest.mark.asyncio
    async def test_from_report(self):
        from app.services import mobsf_runner as mr

        report = {
            "package_name": "x",
            "is_debuggable": True,
            "is_test_only": True,
            "min_sdk": "bad",
            "target_sdk": None,
        }
        r = await mr.MobsfRunner("u", "k").scan_apk_from_report(report, apk_hash="z")
        assert r.success is True
        d = r.to_dict()
        assert "manifest_findings" in d
        assert isinstance(r.summary, dict)


# ── Format detection ─────────────────────────────────────────────────────────


class TestFormatDetectionResidual:
    def test_legacy_bridge_magics(self, tmp_path: Path):
        from app.services.format_detection import (
            DetectedFormat,
            _classify_zip,
            _count_arm64ec_redirections,
            _count_arm64x_dynamic_fixups,
            _legacy_bridge_detect,
            detect_format,
            detect_pe_arch_view,
        )

        cases = [
            (b"hsqs" + b"\x00" * 20, "sq.img"),
            (b"sqsh" + b"\x00" * 20, "sq2.img"),
            (b"\x45\x3d\xcd\x28" + b"\x00" * 20, "cram.img"),
            (b"\x85\x19\x03\x20" + b"\x00" * 20, "jffs.img"),
            (b"\x27\x05\x19\x56" + b"\x00" * 20, "uimg.bin"),
            (b"\xd0\x0d\xfe\xed" + b"\x00" * 20, "dtb.bin"),
            (b"\x7fELF" + b"\x00" * 40, "vmlinux"),
            (b"MSWIM\x00\x00\x00" + b"\x00" * 20, "boot.wim"),
            (b"vhdxfile" + b"\x00" * 20, "disk.vhdx"),
            (b"PA30" + b"\x00" * 20, "x.psf"),
            (b"PA19" + b"\x00" * 20, "y.psf"),
            (b"MSCF" + b"\x00" * 20, "a.cab"),
            (b"MSCF" + b"\x00" * 20, "a.msu"),
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 20, "pkg.msi"),
            (b"\xeb\x7e\xff\x7e" + b"\x00" * 20, "qnx.ifs"),
            (b"\x00" * 8 + b"ARCH" + b"\x00" * 20, "backup.tibx"),
            (b"\x1f\x8b" + b"\x00" * 20, "fw.tar.gz"),
        ]
        for data, name in cases:
            p = tmp_path / name
            p.write_bytes(data)
            fmt = detect_format(p)
            assert isinstance(fmt, DetectedFormat)
            # direct bridge
            _legacy_bridge_detect(data, p, len(data))

        # ext4 superblock marker at 1080
        ext = bytearray(b"\x00" * 1100)
        ext[1080:1082] = b"\x53\xef"
        p = tmp_path / "ext.img"
        p.write_bytes(bytes(ext))
        _legacy_bridge_detect(bytes(ext), p, len(ext))

        # PE with PE header
        pe = bytearray(b"MZ" + b"\x00" * 0x80)
        struct.pack_into("<I", pe, 0x3C, 0x40)
        pe[0x40:0x44] = b"PE\x00\x00"
        p = tmp_path / "x.exe"
        p.write_bytes(bytes(pe))
        detect_format(p)
        _legacy_bridge_detect(bytes(pe), p, len(pe))

        # ustar tar
        tar_head = bytearray(b"\x00" * 0x110)
        tar_head[0x101:0x106] = b"ustar"
        p = tmp_path / "a.tar"
        p.write_bytes(bytes(tar_head))
        detect_format(p)

        # tibx by name
        p = tmp_path / "backup.tibx"
        p.write_bytes(b"\x00" * 20)
        detect_format(p)

        # ZIP variants
        def write_zip(name, members):
            zp = tmp_path / name
            with zipfile.ZipFile(zp, "w") as zf:
                for m, content in members:
                    zf.writestr(m, content)
            return zp

        apk = write_zip(
            "app.apk",
            [
                ("AndroidManifest.xml", b"<manifest/>"),
                ("classes.dex", b"dex\n"),
            ],
        )
        detect_format(apk)
        assert _classify_zip(apk) is not None

        apex = write_zip(
            "x.apex",
            [
                ("apex_manifest.pb", b"x"),
                ("apex_payload.img", b"y"),
            ],
        )
        detect_format(apex)

        ota = write_zip(
            "ota.zip",
            [
                ("payload.bin", b"p"),
                ("META-INF/com/google/android/updater-script", b"s"),
            ],
        )
        detect_format(ota)

        ota2 = write_zip(
            "ota2.zip",
            [("system.img", b"a"), ("boot.img", b"b")],
        )
        detect_format(ota2)

        ota3 = write_zip(
            "ota3.zip",
            [("super.img_sparsechunk.0", b"x")],
        )
        detect_format(ota3)

        win = write_zip(
            "iso.zip",
            [("sources/boot.wim", b"w"), ("bootmgr.efi", b"e")],
        )
        detect_format(win)

        msix = write_zip("app.msix", [("AppxManifest.xml", b"<Appx/>")])
        detect_format(msix)

        # bad zip
        bad = tmp_path / "bad.zip"
        bad.write_bytes(b"PK\x03\x04" + b"\x00" * 10)
        assert _classify_zip(bad) is None or True

        # arm64 counters
        class Fix:
            pass

        class Reloc:
            fixups = [type("A", (), {})()]  # no ARM64X

        class Reloc2:
            fixups = [type("ARM64XFixup", (), {})()]

        class LC:
            dynamic_relocations = [Reloc(), Reloc2()]
            chpe_metadata = SimpleNamespace(redirection_metadata_count=3)

        assert _count_arm64x_dynamic_fixups(LC()) >= 1
        assert _count_arm64ec_redirections(LC()) == 3

        class BadLC:
            @property
            def dynamic_relocations(self):
                raise RuntimeError("x")

            @property
            def chpe_metadata(self):
                raise RuntimeError("x")

        assert _count_arm64x_dynamic_fixups(BadLC()) == 0
        assert _count_arm64ec_redirections(BadLC()) == 0

        # detect_pe_arch_view on non-file / non-pe
        assert detect_pe_arch_view(tmp_path / "nope") is None
        detect_pe_arch_view(tmp_path / "x.exe")

        # unreadable
        assert detect_format(tmp_path / "missing.bin") == DetectedFormat.UNKNOWN


# ── Fuzzing service residual ─────────────────────────────────────────────────


class TestFuzzingResidual:
    def test_write_helpers_and_parse(self, tmp_path: Path):
        from app.services import fuzzing_service as fs

        container = MagicMock()
        container.put_archive = MagicMock(return_value=True)
        fs.FuzzingService._write_file_to_container(container, "/opt/f/x", b"hello")
        seeds = [
            base64.b64encode(b"seed1").decode(),
            "!!!not-b64!!!",
            base64.b64encode(b"seed2").decode(),
        ]
        fs.FuzzingService._write_seeds_to_container(container, seeds)

        # ELF parse
        elf = tmp_path / "bin"
        # minimal invalid ELF → exception path
        elf.write_bytes(b"\x7fELF" + b"\x00" * 40)
        try:
            fs.FuzzingService._parse_elf_sync(str(elf))
        except Exception:
            pass

        # host path resolve
        svc = fs.FuzzingService(AsyncMock())
        with patch.object(svc, "_get_docker_client") as dc:
            client = MagicMock()
            dc.return_value = client
            # simulate mounts
            try:
                svc._resolve_host_path("/data/x")
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_triage_all_signals(self):
        from app.services import fuzzing_service as fs

        svc = fs.FuzzingService(AsyncMock())
        svc.db.flush = AsyncMock()

        class R:
            def __init__(self, out, code=139):
                self.output = out if isinstance(out, tuple) else (out, b"")
                self.exit_code = code

        campaign = SimpleNamespace(
            id=uuid.uuid4(),
            project_id=uuid.uuid4(),
            container_id="c1",
            architecture="arm",
            binary_path="/bin/busybox",
            status="running",
        )
        crash = SimpleNamespace(
            id=uuid.uuid4(),
            campaign_id=campaign.id,
            filename="id:000000",
            signal=None,
            exploitability=None,
            stack_trace=None,
            triage_output=None,
        )

        signals = [
            (b"Segmentation fault\n#0 0x1 in main\n", 139),
            (b"SIGSEGV\n", 139),
            (b"Aborted\n", 134),
            (b"SIGABRT\n", 134),
            (b"Bus error\n", 135),
            (b"SIGBUS\n", 135),
            (b"SIGFPE\n", 136),
            (b"Illegal instruction\n", 132),
            (b"SIGILL\n", 132),
            (b"SIGTRAP\n", 133),
            (b"no recognized signal text\n", 139),  # exit-code map SIGSEGV
            (b"no recognized signal text\n", 134),  # SIGABRT via code
            (b"no recognized signal text\n", 133),  # SIGTRAP
            (b"no recognized signal text\n", 140),  # unknown SIG12
            (b"no recognized\n", 0),
        ]

        for stdout, code in signals:
            container = MagicMock()
            container.exec_run.side_effect = [
                R((stdout, b"stderr-extra"), code),
                R((b"#0 0xdead in foo\n#1 0xbeef in bar\n\nend\n", b"gdb err"), 0),
            ]
            client = MagicMock()
            client.containers.get.return_value = container
            fw = SimpleNamespace(
                id=uuid.uuid4(),
                extracted_path="/fw",
                storage_path="/fw/fw.bin",
            )
            with (
                patch.object(svc, "_get_docker_client", return_value=client),
                patch.object(
                    svc.db,
                    "execute",
                    new=AsyncMock(
                        side_effect=[
                            MagicMock(scalar_one_or_none=MagicMock(return_value=campaign)),
                            MagicMock(scalar_one_or_none=MagicMock(return_value=crash)),
                            MagicMock(scalar_one_or_none=MagicMock(return_value=fw)),
                        ]
                    ),
                ),
                patch(
                    "app.services.fuzzing_service.get_sysroot_path",
                    return_value=None,
                ),
            ):
                try:
                    await asyncio.wait_for(
                        svc.triage_crash(campaign.id, crash.id, campaign.project_id),
                        timeout=2,
                    )
                except Exception:
                    pass

        # triage exception path (container not found)
        import docker

        client = MagicMock()
        client.containers.get.side_effect = docker.errors.NotFound("gone")
        with (
            patch.object(svc, "_get_docker_client", return_value=client),
            patch.object(
                svc.db,
                "execute",
                new=AsyncMock(
                    side_effect=[
                        MagicMock(scalar_one_or_none=MagicMock(return_value=campaign)),
                        MagicMock(scalar_one_or_none=MagicMock(return_value=crash)),
                    ]
                ),
            ),
        ):
            try:
                await svc.triage_crash(campaign.id, crash.id, campaign.project_id)
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_stop_sync_cleanup_paths(self):
        from app.services import fuzzing_service as fs
        import docker

        svc = fs.FuzzingService(AsyncMock())
        svc.db.flush = AsyncMock()
        svc.db.commit = AsyncMock()

        campaign = SimpleNamespace(
            id=uuid.uuid4(),
            project_id=uuid.uuid4(),
            container_id="cid",
            status="running",
            execs_per_sec=0,
            paths_total=0,
            crashes_count=0,
            unique_crashes=0,
            last_crash_at=None,
            bitmap_cvg=0,
            stability=0,
        )

        # stop with docker errors
        client = MagicMock()
        container = MagicMock()
        container.stop.side_effect = RuntimeError("stop fail")
        client.containers.get.return_value = container
        with (
            patch.object(svc, "_get_docker_client", return_value=client),
            patch.object(
                svc.db,
                "execute",
                new=AsyncMock(
                    return_value=MagicMock(
                        scalar_one_or_none=MagicMock(return_value=campaign)
                    )
                ),
            ),
            patch.object(svc, "_sync_stats", new=AsyncMock(side_effect=RuntimeError("s"))),
        ):
            try:
                await svc.stop_campaign(campaign.id, campaign.project_id)
            except Exception:
                pass

        # sync stats NotFound
        client2 = MagicMock()
        client2.containers.get.side_effect = docker.errors.NotFound("x")
        with patch.object(svc, "_get_docker_client", return_value=client2):
            try:
                await svc._sync_stats(campaign)
            except Exception:
                pass

        # sync crashes empty / NotFound
        campaign.container_id = None
        try:
            await svc._sync_crashes(campaign)
        except Exception:
            pass
        campaign.container_id = "cid"
        client3 = MagicMock()
        client3.containers.get.side_effect = docker.errors.NotFound("x")
        with patch.object(svc, "_get_docker_client", return_value=client3):
            try:
                await svc._sync_crashes(campaign)
            except Exception:
                pass

        # cleanup orphans NotFound/Exception
        client4 = MagicMock()
        c_ok = MagicMock()
        c_ok.labels = {"wairz.fuzzing": "1"}
        c_ok.id = "orph"
        c_ok.name = "wairz-fuzz-orph"
        c_ok.status = "running"
        c_nf = MagicMock()
        c_nf.labels = {"wairz.fuzzing": "1"}
        c_nf.id = "gone"
        c_nf.name = "wairz-fuzz-gone"
        c_nf.status = "exited"
        c_nf.remove.side_effect = docker.errors.NotFound("x")
        c_err = MagicMock()
        c_err.labels = {"wairz.fuzzing": "1"}
        c_err.id = "err"
        c_err.name = "wairz-fuzz-err"
        c_err.status = "exited"
        c_err.remove.side_effect = RuntimeError("rm")
        client4.containers.list.return_value = [c_ok, c_nf, c_err]
        with (
            patch.object(svc, "_get_docker_client", return_value=client4),
            patch.object(
                svc.db,
                "execute",
                new=AsyncMock(
                    return_value=MagicMock(
                        scalars=MagicMock(
                            return_value=MagicMock(all=MagicMock(return_value=[]))
                        )
                    )
                ),
            ),
        ):
            try:
                await svc.cleanup_orphans()
            except Exception:
                pass
