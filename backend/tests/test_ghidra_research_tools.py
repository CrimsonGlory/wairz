"""Tests for the Ghidra-log persistence/list/read MCP tools.

Covers the 2026-06-22 process-violation fix: previously there was no
durable, sanctioned way to retrieve full Ghidra run output once the MCP
response was truncated, which led a worker to bypass the truncation limit
by reading the wairz Docker container's overlay filesystem directly. These
tools (list_ghidra_logs / read_ghidra_log) plus the higher 100KB ceiling
for Ghidra output are the sanctioned replacement.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.ai.tool_registry import ToolContext
from app.ai.tools import ghidra_research as gr
from app.models.ghidra_research import GhidraResearchFile
from app.models.project import Project
from tests._live_db import make_live_db


@pytest.fixture
def _fake_settings(tmp_path, monkeypatch):
    fake_settings = MagicMock()
    fake_settings.storage_root = str(tmp_path)
    monkeypatch.setattr(gr, "get_settings", lambda: fake_settings)
    return fake_settings


class _FakeContext:
    def __init__(self, project_id: uuid.UUID):
        self.project_id = project_id


def test_ghidra_output_max_kb_is_100():
    """Pin the Ghidra-specific ceiling (Rule #46-style size-lock)."""
    assert gr.GHIDRA_OUTPUT_MAX_KB == 100


@pytest.mark.asyncio
async def test_persist_list_read_log_roundtrip(_fake_settings):
    project_id = uuid.uuid4()
    body = "line one\n" * 2000 + "TAIL_MARKER\n"  # well under 100KB
    filename = gr._persist_ghidra_log(project_id, "MyScript.py", body)
    assert filename
    assert filename.endswith(".log")

    ctx = _FakeContext(project_id)

    listing = await gr._handle_list_ghidra_logs({}, ctx)
    assert filename in listing
    assert "Found 1 Ghidra log(s)" in listing

    full = await gr._handle_read_ghidra_log({"filename": filename}, ctx)
    assert full == body

    tail = await gr._handle_read_ghidra_log({"filename": filename, "tail": True}, ctx)
    assert "TAIL_MARKER" in tail


@pytest.mark.asyncio
async def test_read_ghidra_log_rejects_path_traversal(_fake_settings):
    """Canary: a synthetic traversal attempt must be rejected, not served."""
    project_id = uuid.uuid4()
    ctx = _FakeContext(project_id)
    result = await gr._handle_read_ghidra_log(
        {"filename": "../../../../etc/passwd"}, ctx
    )
    assert result.startswith("Error: Invalid filename")


@pytest.mark.asyncio
async def test_read_ghidra_log_missing_file_returns_error(_fake_settings):
    project_id = uuid.uuid4()
    ctx = _FakeContext(project_id)
    result = await gr._handle_read_ghidra_log({"filename": "does-not-exist.log"}, ctx)
    assert "not found" in result


@pytest.mark.asyncio
async def test_list_ghidra_logs_empty_project(_fake_settings):
    project_id = uuid.uuid4()
    ctx = _FakeContext(project_id)
    result = await gr._handle_list_ghidra_logs({}, ctx)
    assert "No Ghidra logs persisted yet" in result


@pytest.mark.asyncio
async def test_read_ghidra_log_truncates_long_content_by_default(_fake_settings):
    project_id = uuid.uuid4()
    # Exceed the 100KB ceiling so the default (head) read must truncate.
    body = "x" * (150 * 1024)
    filename = gr._persist_ghidra_log(project_id, "Big.py", body)

    ctx = _FakeContext(project_id)
    result = await gr._handle_read_ghidra_log({"filename": filename}, ctx)
    assert len(result.encode("utf-8")) < len(body.encode("utf-8"))
    assert "truncated" in result


@pytest.mark.asyncio
async def test_read_ghidra_log_tail_returns_end_of_long_content(_fake_settings):
    project_id = uuid.uuid4()
    body = ("a" * (150 * 1024)) + "END_MARKER"
    filename = gr._persist_ghidra_log(project_id, "Big.py", body)

    ctx = _FakeContext(project_id)
    result = await gr._handle_read_ghidra_log(
        {"filename": filename, "tail": True}, ctx
    )
    assert "END_MARKER" in result


# ---------------------------------------------------------------------------
# run_ghidra_headless — GZF process-mode regression (bug found this session)
#
# _handle_run_ghidra_headless's GZF lookup (use_saved_project=True) used to
# succeed, then fall straight into an unconditional sandbox resolve_path() +
# isfile() gate meant for the normal import-mode path. Since a .gzf archive's
# basename never exists inside the firmware sandbox tree, that gate always
# returned "Binary not found" before _run_gzf_process_mode was ever reached —
# the GZF execution branch further down was dead code in practice. Fixed by
# guarding the resolved_binary computation with `if gzf_storage_path is None`.
# These tests prove the GZF branch is now actually reachable, and that the
# normal (non-GZF) binary-not-found behavior is unaffected by the guard.
# ---------------------------------------------------------------------------

class TestRunGhidraHeadlessGzfProcessMode:
    @pytest.mark.asyncio
    async def test_gzf_process_mode_is_reached_even_when_extracted_path_lacks_the_file(
        self, tmp_path, _fake_settings
    ):
        """Regression test for the bug fixed this session: an empty
        extracted_path (no rootfs match for the .gzf basename) must not block
        the GZF process-mode dispatch — resolve_gzf_path's result is what
        matters, not the sandbox lookup."""
        async with make_live_db() as db:
            project_id = uuid.uuid4()
            project = Project(id=project_id, name="gzf-headless", status="ready")
            db.add(project)
            await db.flush()

            gzf_path = tmp_path / "saved.gzf"
            gzf_path.write_bytes(b"PK\x03\x04")

            record = GhidraResearchFile(
                id=uuid.uuid4(),
                project_id=project_id,
                original_filename="saved.gzf",
                file_category="ghidra_archive",
                content_type="application/octet-stream",
                file_size=4,
                sha256="a" * 64,
                storage_path=str(gzf_path),
            )
            db.add(record)
            await db.flush()
            await db.commit()

            # extracted_path deliberately points at an empty dir — the .gzf
            # basename does not exist there, reproducing the original bug.
            empty_root = tmp_path / "empty_extracted_root"
            empty_root.mkdir()

            context = ToolContext(
                project_id=project_id,
                firmware_id=uuid.uuid4(),
                extracted_path=str(empty_root),
                db=db,
            )

            captured: dict = {}

            async def fake_run_gzf_process_mode(
                gzf_path_arg, script_name, script_args, tmp_script_dir, timeout, project_id_arg,
                context_arg,
            ):
                captured["gzf_path"] = gzf_path_arg
                return "GZF_PROCESS_MODE_RAN_OK"

            with patch.object(gr, "_run_gzf_process_mode", new=fake_run_gzf_process_mode):
                result = await gr._handle_run_ghidra_headless(
                    {
                        "binary_path": "saved.gzf",
                        "script_name": "SomeScript.java",
                        "use_saved_project": True,
                    },
                    context,
                )

            assert result == "GZF_PROCESS_MODE_RAN_OK"
            assert captured["gzf_path"] == str(gzf_path)

    @pytest.mark.asyncio
    async def test_non_gzf_missing_binary_still_returns_binary_not_found(
        self, tmp_path, _fake_settings
    ):
        """The guard must not change behavior for the normal (non-GZF) path:
        a genuinely missing binary in script mode still gets the
        'Binary not found' error, not a silent pass-through."""
        async with make_live_db() as db:
            project_id = uuid.uuid4()
            project = Project(id=project_id, name="gzf-headless-normal", status="ready")
            db.add(project)
            await db.flush()
            await db.commit()

            empty_root = tmp_path / "empty_extracted_root_2"
            empty_root.mkdir()

            context = ToolContext(
                project_id=project_id,
                firmware_id=uuid.uuid4(),
                extracted_path=str(empty_root),
                db=db,
            )

            result = await gr._handle_run_ghidra_headless(
                {"binary_path": "no/such/binary", "script_name": "SomeScript.java"},
                context,
            )

            assert "Error: Binary not found" in result

    @pytest.mark.asyncio
    async def test_use_saved_project_with_non_gzf_path_is_rejected(
        self, tmp_path, _fake_settings
    ):
        async with make_live_db() as db:
            project_id = uuid.uuid4()
            project = Project(id=project_id, name="gzf-headless-reject", status="ready")
            db.add(project)
            await db.flush()
            await db.commit()

            context = ToolContext(
                project_id=project_id,
                firmware_id=uuid.uuid4(),
                extracted_path=str(tmp_path),
                db=db,
            )

            result = await gr._handle_run_ghidra_headless(
                {
                    "binary_path": "not_a_gzf.bin",
                    "script_name": "SomeScript.java",
                    "use_saved_project": True,
                },
                context,
            )

            assert "Error: use_saved_project=True requires" in result

    @pytest.mark.asyncio
    async def test_use_saved_project_no_matching_gzf_is_clean_error(
        self, tmp_path, _fake_settings
    ):
        async with make_live_db() as db:
            project_id = uuid.uuid4()
            project = Project(id=project_id, name="gzf-headless-missing", status="ready")
            db.add(project)
            await db.flush()
            await db.commit()

            context = ToolContext(
                project_id=project_id,
                firmware_id=uuid.uuid4(),
                extracted_path=str(tmp_path),
                db=db,
            )

            result = await gr._handle_run_ghidra_headless(
                {
                    "binary_path": "missing.gzf",
                    "script_name": "SomeScript.java",
                    "use_saved_project": True,
                },
                context,
            )

            assert "Error" in result
            assert "missing.gzf" in result


# ---------------------------------------------------------------------------
# _run_gzf_process_mode GZF export and cleanup
#
# GZF process-mode renames (run_ghidra_headless use_saved_project=True)
# apply changes to a persistent Ghidra project on disk. To make the renames
# visible to read operations (list_functions/decompile_function), the updated
# project is exported back to the original GZF file, overwriting it. This
# makes the GZF the golden copy. The persistent project folder is then cleaned
# up so the next analysis will re-import from the updated GZF and see all
# script-applied changes.
# ---------------------------------------------------------------------------

class TestRunGzfProcessModeKeepsPersistentProject:
    @pytest.fixture
    def _fake_ghidra_settings(self, tmp_path, monkeypatch):
        from app.services import ghidra_service as gs

        fake_settings = MagicMock()
        fake_settings.storage_root = str(tmp_path / "storage")
        fake_settings.ghidra_projects_dir = str(tmp_path / "ghidra_projects")
        fake_settings.ghidra_path = "/opt/ghidra"
        fake_settings.ghidra_scripts_path = "/opt/ghidra_scripts"
        monkeypatch.setattr(gr, "get_settings", lambda: fake_settings)
        # gzf_project_paths (used by _run_gzf_process_mode via
        # app.services.ghidra_service) resolves get_settings() in ITS OWN
        # module namespace, independent of ghidra_research's patch above.
        monkeypatch.setattr(gs, "get_settings", lambda: fake_settings)
        return fake_settings

    @pytest.mark.asyncio
    async def test_successful_script_run_keeps_persistent_project(
        self, tmp_path, _fake_ghidra_settings,
    ):
        """After running a process-mode rename script, the persistent project is
        retained on disk so subsequent analysis operations (decompile_function,
        list_functions) can use it and see the renames."""
        from app.models.firmware import Firmware
        from app.utils.hashing import compute_file_sha256
        import os

        gzf_path = tmp_path / "renamed.gzf"
        gzf_path.write_bytes(b"PK\x03\x04" + b"\x00" * 32)
        gzf_sha = compute_file_sha256(str(gzf_path))

        # Pre-create the persistent project's .rep dir so the import step
        # is skipped entirely (rep_exists short-circuits True) — this test
        # only exercises the process step.
        proj_base = tmp_path / "ghidra_projects" / gzf_sha[:16]
        rep_dir = proj_base / "gzf_project.rep"
        rep_dir.mkdir(parents=True)

        async with make_live_db() as db:
            project_id = uuid.uuid4()
            project = Project(id=project_id, name="gzf-persistent", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(id=uuid.uuid4(), project_id=project_id, sha256="f" * 64)
            db.add(firmware)
            await db.flush()
            await db.commit()

            context = ToolContext(
                project_id=project_id,
                firmware_id=firmware.id,
                extracted_path=str(tmp_path),
                db=db,
            )

            class _FakeProc:
                returncode = 0

                async def wait(self):
                    return 0

            # Track subprocess calls: only the process run (no export)
            calls = []

            async def fake_create_subprocess(*args, **kwargs):
                calls.append(args)  # save full command
                return _FakeProc()

            with patch.object(
                gr.asyncio, "create_subprocess_exec",
                new=AsyncMock(side_effect=fake_create_subprocess),
            ):
                result = await gr._run_gzf_process_mode(
                    str(gzf_path), "RenamePass9.java", [], None, 30, project_id, context,
                )

            assert "Exit code: 0" in result
            # Should have had ONE subprocess call: -process (no export)
            assert len(calls) == 1
            assert "-process" in calls[0]
            # No export command should have been issued
            assert not any("-export" in str(call) for call in calls)

            # The persistent project directory should still exist (kept for reuse)
            assert os.path.exists(rep_dir), "rep_dir should be retained for subsequent analysis"
