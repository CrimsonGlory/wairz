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
                gzf_path_arg, script_name, script_args, tmp_script_dir, timeout, project_id_arg,  # noqa: ASYNC109 -- caller-supplied timeout per Rule #29 contract
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
        import os

        from app.models.firmware import Firmware
        from app.utils.hashing import compute_file_sha256

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
            assert os.path.exists(rep_dir), "rep_dir should be retained for subsequent analysis"  # noqa: ASYNC240 -- single bounded stat/open call, not a hot loop


class TestListGhidraResearchFilesFilterAndPaging:
    """The >100-file listing fix: name_contains filter + limit/offset paging +
    true-total header (wairz_requested_changes 2026-06-29 casualty:
    RomRegionBreakdown.java undiscoverable past the first 100 rows)."""

    @staticmethod
    def _mk_record(project_id: uuid.UUID, name: str) -> GhidraResearchFile:
        return GhidraResearchFile(
            id=uuid.uuid4(),
            project_id=project_id,
            original_filename=name,
            file_category="script",
            content_type="text/x-java-source",
            file_size=1024,
            sha256=uuid.uuid4().hex + uuid.uuid4().hex,
            storage_path=f"/tmp/{name}",
        )

    @pytest.mark.asyncio
    async def test_name_contains_finds_file_past_the_first_100(self):
        async with make_live_db() as db:
            project_id = uuid.uuid4()
            db.add(Project(id=project_id, name="rtl8761bu", status="ready"))
            await db.flush()

            # 120 filler scripts, then the target — created LAST so it sorts
            # first by created_at desc; but assert on the filter, not order.
            for i in range(120):
                db.add(self._mk_record(project_id, f"RenamePass{i}.java"))
            db.add(self._mk_record(project_id, "RomRegionBreakdown.java"))
            await db.commit()

            context = ToolContext(
                project_id=project_id, firmware_id=uuid.uuid4(),
                extracted_path=None, db=db,
            )

            result = await gr._handle_list_ghidra_research_files(
                {"name_contains": "RomRegionBreakdown"}, context,
            )
            assert "RomRegionBreakdown.java" in result
            assert "Found 1 of 1 research file(s)" in result
            # None of the filler scripts leaked in
            assert "RenamePass" not in result

    @pytest.mark.asyncio
    async def test_name_contains_is_case_insensitive(self):
        async with make_live_db() as db:
            project_id = uuid.uuid4()
            db.add(Project(id=project_id, name="ci", status="ready"))
            await db.flush()
            db.add(self._mk_record(project_id, "RomRegionBreakdown.java"))
            await db.commit()

            context = ToolContext(
                project_id=project_id, firmware_id=uuid.uuid4(),
                extracted_path=None, db=db,
            )
            result = await gr._handle_list_ghidra_research_files(
                {"name_contains": "romregion"}, context,
            )
            assert "RomRegionBreakdown.java" in result

    @pytest.mark.asyncio
    async def test_no_arg_caps_at_100_but_reports_true_total(self):
        async with make_live_db() as db:
            project_id = uuid.uuid4()
            db.add(Project(id=project_id, name="capped", status="ready"))
            await db.flush()
            for i in range(150):
                db.add(self._mk_record(project_id, f"Script{i}.java"))
            await db.commit()

            context = ToolContext(
                project_id=project_id, firmware_id=uuid.uuid4(),
                extracted_path=None, db=db,
            )
            result = await gr._handle_list_ghidra_research_files({}, context)
            assert "Found 100 of 150 research file(s)" in result
            # Exactly 100 rendered list items ("- ...")
            assert result.count("\n- ") == 100

    @pytest.mark.asyncio
    async def test_offset_pages_through_the_set(self):
        async with make_live_db() as db:
            project_id = uuid.uuid4()
            db.add(Project(id=project_id, name="paged", status="ready"))
            await db.flush()
            for i in range(150):
                db.add(self._mk_record(project_id, f"Script{i}.java"))
            await db.commit()

            context = ToolContext(
                project_id=project_id, firmware_id=uuid.uuid4(),
                extracted_path=None, db=db,
            )
            page2 = await gr._handle_list_ghidra_research_files(
                {"offset": 100, "limit": 100}, context,
            )
            assert "Found 50 of 150 research file(s)" in page2
            assert page2.count("\n- ") == 50

    @pytest.mark.asyncio
    async def test_name_contains_no_match_returns_clear_message(self):
        async with make_live_db() as db:
            project_id = uuid.uuid4()
            db.add(Project(id=project_id, name="nomatch", status="ready"))
            await db.flush()
            db.add(self._mk_record(project_id, "Script0.java"))
            await db.commit()

            context = ToolContext(
                project_id=project_id, firmware_id=uuid.uuid4(),
                extracted_path=None, db=db,
            )
            result = await gr._handle_list_ghidra_research_files(
                {"name_contains": "DoesNotExist"}, context,
            )
            assert "No Ghidra research files match" in result
            assert "DoesNotExist" in result

    @pytest.mark.asyncio
    async def test_bad_limit_is_rejected(self):
        context = ToolContext(
            project_id=uuid.uuid4(), firmware_id=uuid.uuid4(),
            extracted_path=None, db=AsyncMock(),
        )
        result = await gr._handle_list_ghidra_research_files({"limit": "abc"}, context)
        assert "Error" in result and "limit" in result


class TestScriptFileIdTempDirPermissions:
    """script_file_id + use_saved_project=True writes the script to a mkdtemp
    dir (0o700, owned by the caller). In the worker/root container the GZF
    process step drops to the 'wairz' user, which then can't traverse the
    root-owned temp dir — analyzeHeadless reported "Script not found:
    /tmp/ghidra_script_*/<name>.java". The dir/script must be widened so the
    de-privileged Ghidra process can read the script (wairz_requested_changes
    2026-06-29 pre-existing bug)."""

    @pytest.mark.asyncio
    async def test_tmp_script_dir_and_file_are_world_readable(
        self, tmp_path, _fake_settings,
    ):
        import os
        import stat

        async with make_live_db() as db:
            project_id = uuid.uuid4()
            db.add(Project(id=project_id, name="gzf-scriptid", status="ready"))
            await db.flush()

            gzf_path = tmp_path / "saved.gzf"
            gzf_path.write_bytes(b"PK\x03\x04")
            db.add(GhidraResearchFile(
                id=uuid.uuid4(), project_id=project_id,
                original_filename="saved.gzf", file_category="ghidra_archive",
                content_type="application/octet-stream", file_size=4,
                sha256="a" * 64, storage_path=str(gzf_path),
            ))

            script_path = tmp_path / "RomRegionBreakdown.java"
            script_path.write_text("// analysis script\n")
            script_id = uuid.uuid4()
            db.add(GhidraResearchFile(
                id=script_id, project_id=project_id,
                original_filename="RomRegionBreakdown.java", file_category="script",
                content_type="text/x-java-source", file_size=20,
                sha256="b" * 64, storage_path=str(script_path),
            ))
            await db.commit()

            context = ToolContext(
                project_id=project_id, firmware_id=uuid.uuid4(),
                extracted_path=str(tmp_path / "empty"), db=db,
            )
            (tmp_path / "empty").mkdir()

            captured: dict = {}

            async def fake_run_gzf_process_mode(
                gzf_path_arg, script_name, script_args, tmp_script_dir,
                timeout, project_id_arg, context_arg,  # noqa: ASYNC109 -- caller-supplied timeout per Rule #29 contract
            ):
                # Inspect the temp dir + script at the moment the process step
                # would run (before the finally-block rmtree).
                dest = os.path.join(tmp_script_dir, script_name)
                captured["dir_mode"] = stat.S_IMODE(os.stat(tmp_script_dir).st_mode)
                captured["file_mode"] = stat.S_IMODE(os.stat(dest).st_mode)
                captured["script_name"] = script_name
                return "OK"

            with patch.object(gr, "_run_gzf_process_mode", new=fake_run_gzf_process_mode):
                result = await gr._handle_run_ghidra_headless(
                    {
                        "binary_path": "saved.gzf",
                        "script_file_id": str(script_id),
                        "use_saved_project": True,
                    },
                    context,
                )

            assert result == "OK"
            assert captured["script_name"] == "RomRegionBreakdown.java"
            # Dir must be traversable (o+x) and script readable (o+r) by the
            # dropped-to 'wairz' user.
            assert captured["dir_mode"] & stat.S_IXOTH, "temp dir not world-traversable"
            assert captured["dir_mode"] & stat.S_IROTH, "temp dir not world-readable"
            assert captured["file_mode"] & stat.S_IROTH, "script not world-readable"


class TestResolveFirmwarePathBeyond100:
    """_handle_resolve_firmware_path matches an input against the FULL research
    file set. The default 100-row cap on list_by_project would make a .gzf past
    the first 100 unmatchable — the same >100 casualty class as the listing
    tool. Fetch is now sized by the true count."""

    @pytest.mark.asyncio
    async def test_gzf_past_first_100_is_matched(self, tmp_path, _fake_settings):
        from datetime import UTC, datetime, timedelta

        async with make_live_db() as db:
            project_id = uuid.uuid4()
            db.add(Project(id=project_id, name="resolve-101", status="ready"))
            await db.flush()

            # Bury the target .gzf at position 131 in created_at-desc order by
            # giving it the OLDEST explicit timestamp and the 130 fillers newer
            # ones. Explicit timestamps make the ordering deterministic — the
            # server_default func.now() ties at second-resolution for rows in
            # one transaction, which would make "position >100" flaky. Under the
            # old 100-row cap the target is off the fetched page and unmatchable.
            base = datetime(2026, 1, 1, tzinfo=UTC)
            gzf_path = tmp_path / "target.gzf"
            gzf_path.write_bytes(b"PK\x03\x04")
            db.add(GhidraResearchFile(
                id=uuid.uuid4(), project_id=project_id,
                original_filename="target.gzf", file_category="ghidra_archive",
                content_type="application/octet-stream", file_size=4,
                sha256="c" * 64, storage_path=str(gzf_path),
                created_at=base,
            ))
            for i in range(130):
                db.add(GhidraResearchFile(
                    id=uuid.uuid4(), project_id=project_id,
                    original_filename=f"RenamePass{i}.java", file_category="script",
                    content_type="text/x-java-source", file_size=10,
                    sha256=uuid.uuid4().hex + uuid.uuid4().hex,
                    storage_path=f"/tmp/RenamePass{i}.java",
                    created_at=base + timedelta(seconds=i + 1),
                ))
            await db.commit()

            context = ToolContext(
                project_id=project_id, firmware_id=uuid.uuid4(),
                extracted_path=str(tmp_path / "empty"), db=db,
            )
            (tmp_path / "empty").mkdir()

            # Stub the gzf project-dir derivation so we don't need real Ghidra
            # (real sha256 over the 4-byte file is fine; only the project-path
            # resolution needs settings the fake doesn't provide).
            with patch(
                "app.services.ghidra_service.gzf_project_paths",
                return_value=(str(tmp_path / "proj"), "gzf_project", str(tmp_path / "proj" / "gzf_project.rep")),
            ):
                result = await gr._handle_resolve_firmware_path(
                    {"binary_path": "target.gzf"}, context,
                )

            # The target .gzf (position >100) must be recognised, not reported
            # as an unresolvable path.
            assert "Cannot resolve" not in result
            assert "target.gzf" in result
