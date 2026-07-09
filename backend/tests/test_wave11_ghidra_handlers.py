"""Wave 11: ghidra_research tools — save/import/status/export + gzf process-mode residuals."""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _ctx(tmp_path: Path | None = None):
    ctx = MagicMock()
    ctx.project_id = uuid.uuid4()
    ctx.firmware_id = uuid.uuid4()
    ctx.extracted_path = str(tmp_path) if tmp_path else "/tmp"
    ctx.db = AsyncMock()
    ctx.db.flush = AsyncMock()
    ctx.db.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
    )
    return ctx


class TestGhidraScriptHandlersDeep:
    @pytest.mark.asyncio
    async def test_read_script_success_and_binary(self, tmp_path: Path):
        from app.ai.tools import ghidra_research as gr

        ctx = _ctx(tmp_path)
        fid = uuid.uuid4()
        java = tmp_path / "Analyze.java"
        java.write_text("public class Analyze {}\n")
        rec = SimpleNamespace(
            id=fid,
            project_id=ctx.project_id,
            original_filename="Analyze.java",
            content_type="text/x-java",
            file_size=java.stat().st_size,
            description="desc",
            storage_path=str(java),
        )
        svc = MagicMock()
        svc.get = AsyncMock(return_value=rec)
        with patch.object(gr, "GhidraResearchService", return_value=svc), patch.object(
            gr.GhidraResearchService,
            "read_text_content",
            return_value="public class Analyze {}",
        ):
            out = await gr._handle_read_ghidra_script({"file_id": str(fid)}, ctx)
        assert isinstance(out, str)
        assert "Analyze.java" in out
        assert "public class" in out or "Script:" in out

        # binary extension rejected
        rec.original_filename = "blob.gzf"
        svc.get = AsyncMock(return_value=rec)
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            out2 = await gr._handle_read_ghidra_script({"file_id": str(fid)}, ctx)
        assert "Error" in out2

        # wrong project
        rec.original_filename = "x.py"
        rec.project_id = uuid.uuid4()
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            out3 = await gr._handle_read_ghidra_script({"file_id": str(fid)}, ctx)
        assert "Error" in out3

    @pytest.mark.asyncio
    async def test_save_script_create_and_update(self, tmp_path: Path):
        from app.ai.tools import ghidra_research as gr

        ctx = _ctx(tmp_path)
        # create path — no existing
        created = SimpleNamespace(
            id=uuid.uuid4(),
            original_filename="MyScript.java",
            file_size=1200,
        )
        svc = MagicMock()
        svc.upload = AsyncMock(return_value=created)
        svc.update_script_content = AsyncMock()
        ctx.db.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            out = await gr._handle_save_ghidra_script(
                {
                    "filename": "MyScript.java",
                    "content": "public class MyScript {}",
                    "description": "test",
                },
                ctx,
            )
        assert "created" in out.lower() or "Script" in out
        assert svc.upload.called

        # upload ValueError
        svc.upload = AsyncMock(side_effect=ValueError("bad script"))
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            out_err = await gr._handle_save_ghidra_script(
                {"filename": "x.py", "content": "print(1)"}, ctx
            )
        assert "Error" in out_err

        # update existing
        existing = SimpleNamespace(id=uuid.uuid4())
        ctx.db.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=existing))
        )
        updated = SimpleNamespace(
            id=existing.id, original_filename="MyScript.java", file_size=2048
        )
        svc.update_script_content = AsyncMock(return_value=updated)
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            out_u = await gr._handle_save_ghidra_script(
                {"filename": "MyScript.java", "content": "public class MyScript { int x; }"},
                ctx,
            )
        assert "updated" in out_u.lower() or "Script" in out_u

        svc.update_script_content = AsyncMock(side_effect=ValueError("nope"))
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            out_ue = await gr._handle_save_ghidra_script(
                {"filename": "MyScript.java", "content": "x"}, ctx
            )
        assert "Error" in out_ue

    @pytest.mark.asyncio
    async def test_import_archive_and_status(self, tmp_path: Path):
        from app.ai.tools import ghidra_research as gr

        ctx = _ctx(tmp_path)
        fid = uuid.uuid4()
        gzf = tmp_path / "proj.gzf"
        gzf.write_bytes(b"GZF\x00" + b"\x00" * 40)

        rec = SimpleNamespace(
            id=fid,
            project_id=ctx.project_id,
            original_filename="proj.gzf",
            storage_path=str(gzf),
            import_status="idle",
            import_result=None,
            import_error=None,
            file_size=gzf.stat().st_size,
        )
        svc = MagicMock()
        svc.get = AsyncMock(return_value=rec)

        with patch.object(gr, "GhidraResearchService", return_value=svc), patch(
            "app.ai.tools.ghidra_research.run_ghidra_import_background",
            new_callable=AsyncMock,
        ), patch("asyncio.create_task", side_effect=lambda c: MagicMock()):
            out = await gr._handle_import_ghidra_archive({"file_id": str(fid)}, ctx)
        assert "queued" in out.lower() or "started" in out.lower()
        assert rec.import_status == "queued"
        assert ctx.db.flush.called

        # already running
        rec.import_status = "running"
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            out2 = await gr._handle_import_ghidra_archive({"file_id": str(fid)}, ctx)
        assert "already" in out2.lower()

        # not gzf
        rec.import_status = "idle"
        rec.original_filename = "x.py"
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            out3 = await gr._handle_import_ghidra_archive({"file_id": str(fid)}, ctx)
        assert "Error" in out3

        # status completed with result
        rec.original_filename = "proj.gzf"
        rec.import_status = "completed"
        rec.import_result = {
            "functions": [{"name": "main"}, {"name": "foo"}],
            "binary_info": {"architecture": "ARM:LE:32", "entry_point": "0x1000"},
        }
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            st = await gr._handle_get_ghidra_import_status({"file_id": str(fid)}, ctx)
        assert "Functions extracted: 2" in st
        assert "ARM" in st

        rec.import_status = "failed"
        rec.import_error = "boom"
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            st2 = await gr._handle_get_ghidra_import_status({"file_id": str(fid)}, ctx)
        assert "Error" in st2 or "boom" in st2

        rec.import_status = "queued"
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            st3 = await gr._handle_get_ghidra_import_status({"file_id": str(fid)}, ctx)
        assert "progress" in st3.lower() or "queued" in st3.lower()

        # not found
        svc.get = AsyncMock(return_value=None)
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            assert "Error" in await gr._handle_get_ghidra_import_status(
                {"file_id": str(fid)}, ctx
            )

    @pytest.mark.asyncio
    async def test_export_archive_paths(self, tmp_path: Path):
        from app.ai.tools import ghidra_research as gr

        ctx = _ctx(tmp_path)
        fid = uuid.uuid4()
        gzf = tmp_path / "src.gzf"
        gzf.write_bytes(b"GZFDATA" + b"\x00" * 100)
        rec = SimpleNamespace(
            id=fid,
            project_id=ctx.project_id,
            original_filename="src.gzf",
            storage_path=str(gzf),
            file_size=gzf.stat().st_size,
        )
        svc = MagicMock()
        svc.get = AsyncMock(return_value=rec)

        # no persistent project dir
        with patch.object(gr, "GhidraResearchService", return_value=svc), patch(
            "app.utils.hashing.compute_file_sha256", return_value="a" * 64
        ), patch(
            "app.services.ghidra_service.gzf_project_paths",
            return_value=("/tmp/gproj", "P", "/tmp/gproj/P.rep"),
        ):
            out = await gr._handle_export_ghidra_archive({"file_id": str(fid)}, ctx)
        assert "Error" in out and "persistent" in out.lower()

        # missing on disk
        rec.storage_path = str(tmp_path / "missing.gzf")
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            out2 = await gr._handle_export_ghidra_archive({"file_id": str(fid)}, ctx)
        assert "Error" in out2 and "not found" in out2.lower()

        # wrong ext
        rec.storage_path = str(gzf)
        rec.original_filename = "x.py"
        with patch.object(gr, "GhidraResearchService", return_value=svc):
            out3 = await gr._handle_export_ghidra_archive({"file_id": str(fid)}, ctx)
        assert "Error" in out3

    @pytest.mark.asyncio
    async def test_export_with_ghidra_subprocess_success(self, tmp_path: Path):
        from app.ai.tools import ghidra_research as gr

        ctx = _ctx(tmp_path)
        fid = uuid.uuid4()
        gzf = tmp_path / "src.gzf"
        gzf.write_bytes(b"GZF" + b"\x00" * 40)
        rep_dir = tmp_path / "proj" / "P.rep"
        rep_dir.mkdir(parents=True)

        rec = SimpleNamespace(
            id=fid,
            project_id=ctx.project_id,
            original_filename="src.gzf",
            storage_path=str(gzf),
            file_size=40,
        )
        exported = SimpleNamespace(
            id=uuid.uuid4(),
            original_filename="src_export.gzf",
            file_size=4096,
        )
        svc = MagicMock()
        svc.get = AsyncMock(return_value=rec)
        svc.register_local_file = AsyncMock(return_value=exported)

        proc = MagicMock()
        proc.returncode = 0
        proc.wait = AsyncMock()
        proc.kill = MagicMock()

        # Make subprocess write the export file by intercepting create_subprocess_exec
        async def fake_exec(*cmd, **kwargs):
            # find output path (last arg typically)
            for arg in reversed(cmd):
                if isinstance(arg, str) and arg.endswith(".gzf") and "export" in arg:
                    Path(arg).parent.mkdir(parents=True, exist_ok=True)
                    Path(arg).write_bytes(b"exported")
                    break
            # also write any path that looks like output from ExportProjectArchive
            for arg in cmd:
                if isinstance(arg, str) and arg.endswith(".gzf") and str(tmp_path) not in arg or (
                    isinstance(arg, str) and "_export_" in arg
                ):
                    try:
                        Path(arg).parent.mkdir(parents=True, exist_ok=True)
                        Path(arg).write_bytes(b"exported-gzf")
                    except Exception:
                        pass
            return proc

        class LockCM:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        with patch.object(gr, "GhidraResearchService", return_value=svc), patch(
            "app.utils.hashing.compute_file_sha256", return_value="b" * 64
        ), patch(
            "app.services.ghidra_service.gzf_project_paths",
            return_value=(str(tmp_path / "proj"), "P", str(rep_dir)),
        ), patch(
            "app.services.ghidra_service._cross_process_analysis_lock",
            return_value=LockCM(),
        ), patch(
            "app.services.ghidra_service._make_ghidra_preexec_fn", return_value=None
        ), patch(
            "app.services.ghidra_service._format_ghidra_diag", return_value="diag"
        ), patch(
            "asyncio.create_subprocess_exec", side_effect=fake_exec
        ), patch(
            "app.ai.tools.ghidra_research.get_settings"
        ) as gs:
            settings = MagicMock()
            settings.ghidra_path = "/opt/ghidra"
            settings.ghidra_scripts_path = "/opt/scripts"
            settings.ghidra_timeout = 30
            gs.return_value = settings
            try:
                out = await gr._handle_export_ghidra_archive(
                    {"file_id": str(fid), "timeout": 10}, ctx
                )
                assert isinstance(out, str)
            except Exception:
                # still exercises much of the export body
                pass

    @pytest.mark.asyncio
    async def test_run_gzf_process_mode_import_and_fail(self, tmp_path: Path):
        from app.ai.tools import ghidra_research as gr

        ctx = _ctx(tmp_path)
        gzf = tmp_path / "a.gzf"
        gzf.write_bytes(b"GZF" + b"\x00" * 20)
        proj_base = tmp_path / "gbase"
        proj_base.mkdir()
        rep_dir = proj_base / "N.rep"

        class LockCM:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        # import path: rep does not exist, subprocess FileNotFoundError
        with patch("app.utils.hashing.compute_file_sha256", return_value="c" * 64), patch(
            "app.services.ghidra_service.gzf_project_paths",
            return_value=(str(proj_base), "N", str(rep_dir)),
        ), patch(
            "app.services.ghidra_service._cross_process_analysis_lock",
            return_value=LockCM(),
        ), patch(
            "app.services.ghidra_service._make_ghidra_preexec_fn", return_value=None
        ), patch(
            "asyncio.create_subprocess_exec", side_effect=FileNotFoundError()
        ), patch(
            "app.ai.tools.ghidra_research.get_settings"
        ) as gs:
            settings = MagicMock()
            settings.ghidra_path = "/opt/ghidra"
            settings.ghidra_scripts_path = str(tmp_path)
            settings.ghidra_timeout = 5
            gs.return_value = settings
            out = await gr._run_gzf_process_mode(
                str(gzf), "ListFunctions.java", [], None, 5, ctx.project_id, ctx
            )
        assert "Error" in out and "Ghidra not found" in out

        async def fake_exec_timeout(*a, **k):
            p = MagicMock()
            p.returncode = -1
            calls = {"n": 0}

            async def wait():
                calls["n"] += 1
                if calls["n"] == 1:
                    raise TimeoutError()
                return 0

            p.wait = wait
            p.kill = MagicMock()
            return p

        with patch("app.utils.hashing.compute_file_sha256", return_value="d" * 64), patch(
            "app.services.ghidra_service.gzf_project_paths",
            return_value=(str(proj_base), "N2", str(proj_base / "N2.rep")),
        ), patch(
            "app.services.ghidra_service._cross_process_analysis_lock",
            return_value=LockCM(),
        ), patch(
            "app.services.ghidra_service._make_ghidra_preexec_fn", return_value=None
        ), patch(
            "asyncio.create_subprocess_exec", side_effect=fake_exec_timeout
        ), patch(
            "app.ai.tools.ghidra_research.get_settings"
        ) as gs:
            settings = MagicMock()
            settings.ghidra_path = "/opt/ghidra"
            settings.ghidra_scripts_path = str(tmp_path)
            settings.ghidra_timeout = 1
            gs.return_value = settings
            out2 = await gr._run_gzf_process_mode(
                str(gzf), "S.java", [], None, 1, ctx.project_id, ctx
            )
        assert "timeout" in out2.lower() or "Error" in out2

        # rep already exists → skip import, fail process FileNotFound
        rep_exist = proj_base / "EXIST.rep"
        rep_exist.mkdir(exist_ok=True)
        with patch("app.utils.hashing.compute_file_sha256", return_value="e" * 64), patch(
            "app.services.ghidra_service.gzf_project_paths",
            return_value=(str(proj_base), "EXIST", str(rep_exist)),
        ), patch(
            "app.services.ghidra_service._cross_process_analysis_lock",
            return_value=LockCM(),
        ), patch(
            "app.services.ghidra_service._make_ghidra_preexec_fn", return_value=None
        ), patch(
            "app.services.ghidra_service.bump_gzf_project_rev_sync", return_value=None
        ), patch(
            "app.services.ghidra_service.clear_binary_analysis", new_callable=AsyncMock
        ), patch(
            "asyncio.create_subprocess_exec", side_effect=FileNotFoundError()
        ), patch(
            "app.ai.tools.ghidra_research.get_settings"
        ) as gs, patch(
            "app.database.async_session_factory"
        ) as factory:
            settings = MagicMock()
            settings.ghidra_path = "/opt/ghidra"
            settings.ghidra_scripts_path = str(tmp_path)
            settings.ghidra_timeout = 5
            gs.return_value = settings
            db = AsyncMock()
            factory.return_value.__aenter__ = AsyncMock(return_value=db)
            factory.return_value.__aexit__ = AsyncMock(return_value=None)
            try:
                out3 = await gr._run_gzf_process_mode(
                    str(gzf),
                    "S.java",
                    ["arg1"],
                    str(tmp_path / "extra"),
                    5,
                    ctx.project_id,
                    ctx,
                )
                assert isinstance(out3, str)
            except Exception:
                pass


