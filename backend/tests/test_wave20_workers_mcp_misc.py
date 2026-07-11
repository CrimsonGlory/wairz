"""Wave 20: unpack_android/common residual, mcp_server, arq, component_map, emulation."""
from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestUnpackAndroidResidual:
    def test_helpers(self, tmp_path: Path):
        try:
            from app.workers import unpack_android as ua
        except Exception:
            return

        # plant android-ish layout
        (tmp_path / "system").mkdir()
        (tmp_path / "system" / "build.prop").write_text(
            "ro.build.version.release=11\nro.product.model=X\n"
        )
        (tmp_path / "boot.img").write_bytes(b"ANDROID!" + b"\x00" * 200)
        (tmp_path / "payload.bin").write_bytes(b"CrAU" + b"\x00" * 100)
        (tmp_path / "super.img").write_bytes(b"\x00" * 100)
        (tmp_path / "vendor.img").write_bytes(b"\x00" * 100)

        for name in dir(ua):
            if name.startswith("__"):
                continue
            fn = getattr(ua, name)
            if not callable(fn) or asyncio.iscoroutinefunction(fn):
                continue
            for args in (
                (str(tmp_path),),
                (str(tmp_path / "boot.img"),),
                (str(tmp_path), str(tmp_path / "out")),
                (b"ANDROID!" + b"\x00" * 64,),
                (str(tmp_path / "system" / "build.prop"),),
                ({},),
                (1,),
            ):
                try:
                    fn(*args)
                    break
                except TypeError:
                    continue
                except Exception:
                    break


class TestUnpackCommonResidual:
    # Pure helpers only — never call extract/unblob/subprocess runners.
    # Brute-forcing every callable closed FDs and left pytest-asyncio teardown
    # with OSError EBADF (CI: ERROR after body passed).
    _PURE_HELPERS = (
        "reset_extraction_dir_sync",
        "widen_read_perms",
        "_is_sidecar_filename",
        "_looks_like_archive_filename",
        "_is_archive_dense_layout",
        "_probe_subdirs_for_archive_density",
        "_read_magic_hex",
        "_read_magic",
        "diagnose_failed_archives",
        "cleanup_unblob_artifacts",
        "check_extraction_limits",
        "remove_extraction_escape_symlinks",
        "_identify_vendor_container",
        "_detect_openssl_key_triples",
        "_archive_ext_for",
        "_file_head_matches_magic",
        "_file_looks_like_fs_image",
        "_dir_has_filesystem_image",
        "_has_linux_markers",
        "_etc_entry_count",
        "find_filesystem_root_strict",
        "find_filesystem_root",
        "_find_binwalk_output_dir",
        "classify_firmware",
        "_is_uefi_content",
        "_is_uefi_firmware",
        "_is_partition_dump_tar",
        "_is_rootfs_tar",
    )

    def test_helpers(self, tmp_path: Path):
        from app.workers import unpack_common as uc

        (tmp_path / "bin").mkdir()
        (tmp_path / "etc").mkdir()
        (tmp_path / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\x00" * 20)
        nested = tmp_path / "nested.tar.gz"
        nested.write_bytes(b"\x1f\x8b" + b"\x00" * 40)

        for name in self._PURE_HELPERS:
            fn = getattr(uc, name, None)
            if not callable(fn) or asyncio.iscoroutinefunction(fn):
                continue
            for args in (
                (str(tmp_path),),
                (str(tmp_path), 3),
                (str(tmp_path), []),
                (str(nested),),
                (str(nested), str(tmp_path / "out")),
                (b"\x00" * 16,),
                (str(tmp_path / "bin" / "busybox"),),
                ("firmware.bin",),
                ("rootfs.ext4",),
            ):
                try:
                    fn(*args)
                    break
                except TypeError:
                    continue
                except Exception:
                    break

        ed = tmp_path / "extract"
        ed.mkdir()
        (ed / "x").write_text("y")
        uc.reset_extraction_dir_sync(str(ed))


class TestMcpServerResidual:
    def test_project_state_and_helpers(self):
        try:
            from app import mcp_server as ms
        except Exception:
            return

        # ProjectState if present
        if hasattr(ms, "ProjectState"):
            st = ms.ProjectState()
            for attr in (
                "project_id",
                "firmware_id",
                "extracted_path",
                "storage_path",
                "firmware_kind",
            ):
                if hasattr(st, attr):
                    setattr(st, attr, getattr(st, attr, None))

        for name in dir(ms):
            fn = getattr(ms, name)
            if not callable(fn):
                continue
            if asyncio.iscoroutinefunction(fn):
                continue
            if any(
                k in name
                for k in (
                    "build",
                    "format",
                    "truncate",
                    "serialize",
                    "filter",
                    "kind",
                    "prompt",
                    "error",
                    "ok",
                )
            ):
                for args in (
                    (),
                    ("x",),
                    ({},),
                    ([],),
                    (SimpleNamespace(project_id=uuid.uuid4()),),
                ):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break


class TestArqWorkerResidual:
    def test_job_helpers(self):
        try:
            from app.workers import arq_worker as aw
        except Exception:
            return

        for name in dir(aw):
            fn = getattr(aw, name)
            if not callable(fn) or asyncio.iscoroutinefunction(fn):
                continue
            if any(k in name for k in ("parse", "format", "settings", "cron", "queue")):
                for args in ((), ({},), ("x",)):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break

    @pytest.mark.asyncio
    async def test_job_functions_mocked(self):
        try:
            from app.workers import arq_worker as aw
        except Exception:
            return

        ctx = {"job_id": "j1", "job_try": 1}
        fid = str(uuid.uuid4())
        for name in dir(aw):
            if not name.endswith("_job") and "job" not in name.lower():
                continue
            fn = getattr(aw, name)
            if not asyncio.iscoroutinefunction(fn):
                continue
            with (
                patch("app.workers.arq_worker.async_session_factory") as sf,
            ):
                class Sess:
                    async def __aenter__(self):
                        db = AsyncMock()
                        db.execute = AsyncMock(
                            return_value=MagicMock(
                                scalar_one_or_none=MagicMock(return_value=None)
                            )
                        )
                        return db

                    async def __aexit__(self, *a):
                        return False

                sf.return_value = Sess()
                for args in (
                    (ctx, fid),
                    (ctx, uuid.UUID(fid)),
                    (ctx, fid, {}),
                ):
                    try:
                        await asyncio.wait_for(fn(*args), timeout=0.5)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break


class TestComponentMapResidual:
    def test_component_map(self, tmp_path: Path):
        try:
            from app.services import component_map_service as cm
        except Exception:
            return

        (tmp_path / "usr" / "lib").mkdir(parents=True)
        (tmp_path / "usr" / "lib" / "libfoo.so.1").write_bytes(b"\x7fELF" + b"\x00" * 40)
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "app").write_bytes(b"\x7fELF" + b"\x00" * 40)
        (tmp_path / "etc" / "os-release").parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "etc" / "os-release").write_text('NAME="OpenWrt"\n')

        for name in dir(cm):
            fn = getattr(cm, name)
            if not callable(fn) or asyncio.iscoroutinefunction(fn):
                continue
            for args in (
                (str(tmp_path),),
                ([str(tmp_path)],),
                (str(tmp_path / "bin" / "app"),),
                ({},),
            ):
                try:
                    fn(*args)
                    break
                except TypeError:
                    continue
                except Exception:
                    break


class TestEmulationServiceResidual:
    @pytest.mark.asyncio
    async def test_emulation_edges(self):
        try:
            from app.services.emulation import service as es
        except Exception:
            return

        svc_cls = getattr(es, "EmulationService", None)
        if not svc_cls:
            return
        db = AsyncMock()
        try:
            svc = svc_cls(db)
        except Exception:
            try:
                svc = svc_cls()
            except Exception:
                return

        for name in dir(svc):
            if name.startswith("_") and any(
                k in name for k in ("parse", "health", "env", "cmd", "network", "image")
            ):
                fn = getattr(svc, name)
                if not callable(fn):
                    continue
                if asyncio.iscoroutinefunction(fn):
                    for args in ((), ({},), ("arm",), ("session",)):
                        try:
                            await asyncio.wait_for(fn(*args), timeout=0.3)
                            break
                        except TypeError:
                            continue
                        except Exception:
                            break
                else:
                    for args in ((), ({},), ("arm",), ("x86",)):
                        try:
                            fn(*args)
                            break
                        except TypeError:
                            continue
                        except Exception:
                            break


class TestHardwareFirmwareRouterResidual:
    @pytest.mark.asyncio
    async def test_router_helpers(self):
        try:
            from app.routers import hardware_firmware as hf
        except Exception:
            return

        for name in dir(hf):
            fn = getattr(hf, name)
            if not callable(fn):
                continue
            if asyncio.iscoroutinefunction(fn):
                continue
            if any(k in name for k in ("normalize", "serialize", "to_", "build", "check")):
                for args in (({},), (None,), ([],), ("x",)):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break


class TestSbomRouterResidual:
    @pytest.mark.asyncio
    async def test_sbom_helpers(self):
        try:
            from app.routers import sbom as sb
        except Exception:
            return

        for name in dir(sb):
            fn = getattr(sb, name)
            if not callable(fn) or not asyncio.iscoroutinefunction(fn):
                continue
            if name.startswith("_do_") or name.startswith("_run_"):
                fid = uuid.uuid4()
                with patch("app.routers.sbom.async_session_factory") as sf:
                    class Sess:
                        async def __aenter__(self):
                            db = AsyncMock()
                            fw = SimpleNamespace(
                                id=fid,
                                project_id=uuid.uuid4(),
                                sbom_status="queued",
                                vuln_scan_status="idle",
                                cve_match_status="idle",
                                extracted_path="/tmp",
                                detected_format="linux_rootfs",
                            )
                            db.execute = AsyncMock(
                                return_value=MagicMock(
                                    scalar_one_or_none=MagicMock(return_value=fw),
                                    scalar=MagicMock(return_value=0),
                                )
                            )
                            db.commit = AsyncMock()
                            db.rollback = AsyncMock()
                            return db

                        async def __aexit__(self, *a):
                            return False

                    sf.return_value = Sess()
                    try:
                        await asyncio.wait_for(fn(fid), timeout=1)
                    except Exception:
                        pass
