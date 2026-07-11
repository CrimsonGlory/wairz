"""Service-layer tests for ``app.services.ghidra_service``.

Phase 1 of audit-test-coverage-routers-services-2026-05-04 — the
service is 685 LOC and previously had no test importing it. The
critical paths to lock in:

* ``_parse_analysis_output`` / ``_parse_decompile_output`` —
  marker-based JSON extraction from raw Ghidra stdout (resilient to
  ``INFO  AnalyzeBinary.java>`` log prefixes).
* ``_map_architecture`` — Ghidra processor names → wairz short names
  (drift here misroutes downstream tools by architecture).
* ``_build_analyze_command`` — analyzeHeadless invocation shape
  (drift breaks every Ghidra run silently — ``run_ghidra_subprocess``
  swallows non-zero exit codes when output markers are present).
* ``run_ghidra_subprocess`` — timeout enforcement + missing-binary
  ``FileNotFoundError`` translation.
* **Rule #35b LIVE-CANARY** — exercises the full cache round-trip
  for ``decompile_function``: stubs the Ghidra subprocess to return a
  marker-wrapped payload, calls the service against a real SQLite
  session, then SELECTs the ``analysis_cache`` row to verify the
  decompiled code, the JSONB ``result`` shape, and the
  ``binary_sha256`` lookup key all round-tripped through the DB
  layer. A second canary call against the SAME (binary, function)
  must hit the cache (no second subprocess call) — the cache-hit
  contract from ``_get_cached`` (line 645).
"""
from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.analysis_cache import AnalysisCache
from app.models.firmware import Firmware
from app.models.project import Project
from app.services import ghidra_service
from app.services.ghidra_service import (
    _build_analyze_command,
    _map_architecture,
    _parse_analysis_output,
    _parse_decompile_output,
    decompile_function,
    get_cached,
    resolve_binary_import_params,
    run_ghidra_subprocess,
    store_cached,
)
from tests._live_db import make_live_db

# ---------------------------------------------------------------------------
# Pure-function tests — output parsing
# ---------------------------------------------------------------------------

class TestParseAnalysisOutput:
    def test_extracts_json_between_markers(self):
        raw = (
            "Ghidra startup chatter\n"
            "===ANALYSIS_START===\n"
            'INFO  AnalyzeBinary.java> {"functions": [{"name": "main"}]} (GhidraScript)\n'
            "===ANALYSIS_END===\n"
            "Ghidra shutdown\n"
        )
        result = _parse_analysis_output(raw)
        assert result == {"functions": [{"name": "main"}]}

    def test_handles_log_prefix_around_json(self):
        """Ghidra wraps println() output with INFO + class-name prefixes —
        the parser must extract the outermost {...} regardless."""
        raw = (
            "===ANALYSIS_START===\n"
            "INFO  AnalyzeBinary.java> SOME_NOISE_BEFORE\n"
            'INFO  AnalyzeBinary.java> {"key": "value", "nested": {"x": 1}} (GhidraScript)\n'
            "===ANALYSIS_END===\n"
        )
        result = _parse_analysis_output(raw)
        assert result == {"key": "value", "nested": {"x": 1}}

    def test_returns_none_when_markers_missing(self):
        assert _parse_analysis_output("no markers here") is None
        assert _parse_analysis_output("===ANALYSIS_START===\nbut no end") is None

    def test_returns_none_when_content_empty(self):
        raw = "===ANALYSIS_START===\n===ANALYSIS_END===\n"
        assert _parse_analysis_output(raw) is None

    def test_returns_none_when_no_json_object(self):
        raw = "===ANALYSIS_START===\njust text, no braces===ANALYSIS_END==="
        assert _parse_analysis_output(raw) is None

    def test_returns_none_on_invalid_json(self):
        raw = "===ANALYSIS_START==={invalid: json===ANALYSIS_END==="
        assert _parse_analysis_output(raw) is None


class TestParseDecompileOutput:
    def test_extracts_decompiled_code(self):
        raw = (
            "===DECOMPILE_START===\n"
            "void main() {\n"
            "    printf(\"hello\");\n"
            "}\n"
            "===DECOMPILE_END===\n"
        )
        result = _parse_decompile_output(raw)
        assert result is not None
        assert "void main()" in result
        assert "printf" in result

    def test_returns_none_when_markers_missing(self):
        assert _parse_decompile_output("no markers") is None

    def test_returns_none_when_content_empty(self):
        assert _parse_decompile_output("===DECOMPILE_START======DECOMPILE_END===") is None


# ---------------------------------------------------------------------------
# Architecture mapping
# ---------------------------------------------------------------------------

class TestMapArchitecture:
    @pytest.mark.parametrize("ghidra,expected", [
        ("ARM", "arm"),
        ("ARM:LE:32:v8", "arm"),
        ("AARCH64", "aarch64"),
        ("AARCH64:LE:64:v8A", "aarch64"),
        ("MIPS", "mips"),
        ("MIPS:BE:32:default", "mips"),
        ("x86", "x86"),
        ("x86:LE:64:default", "x86"),
        ("x86-64", "x86"),
        ("PowerPC", "ppc"),
        ("PowerPC:BE:32:default", "ppc"),
        ("sparc", "sparc"),
    ])
    def test_known_architectures_mapped(self, ghidra, expected):
        assert _map_architecture(ghidra) == expected

    def test_unknown_architecture_returns_lowercased(self):
        assert _map_architecture("RISCV") == "riscv"
        assert _map_architecture("Z80") == "z80"


# ---------------------------------------------------------------------------
# resolve_binary_import_params — .gzf short-circuit
#
# A saved Ghidra project archive already carries its own baked-in
# processor/loader/base-address state from when it was first imported.
# Without the extension check, a bare-metal firmware's rtos_flavor would
# force BinaryLoader override params onto a .gzf import and corrupt that
# state. The check must fire BEFORE the magic-byte read (a .gzf is a ZIP
# container, not a known ELF/PE/Mach-O format, so without the short-circuit
# it would fall through to the rtos_flavor DB lookup below).
# ---------------------------------------------------------------------------

class TestResolveBinaryImportParamsGzfShortCircuit:
    @pytest.mark.asyncio
    async def test_gzf_extension_returns_none_without_db_lookup(self):
        # No async_session_factory patch needed — the .gzf check returns
        # before any DB access, so a real (unmocked) firmware_id is safe.
        result = await resolve_binary_import_params(
            "/data/research/saved_project.gzf", uuid.uuid4(),
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_gzf_extension_match_is_case_insensitive(self):
        result = await resolve_binary_import_params(
            "/data/research/SAVED_PROJECT.GZF", uuid.uuid4(),
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_raw_binary_with_baremetal_flavor_still_gets_params(self, tmp_path: Path):
        """Contrast case: a non-.gzf raw blob for the SAME flavor that would
        produce params if it weren't a .gzf — proves the short-circuit is
        extension-specific, not a blanket bypass of the flavor lookup."""
        raw_path = tmp_path / "firmware.bin"
        raw_path.write_bytes(b"\x00" * 64)  # unknown-format magic

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="gzf-shortcircuit", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="c" * 64,
                rtos_flavor="baremetal-cortexm",
            )
            db.add(firmware)
            await db.flush()
            await db.commit()

            @asynccontextmanager
            async def _fake_factory():
                yield db

            with patch(
                "app.services.ghidra_service.async_session_factory",
                _fake_factory,
            ):
                result = await resolve_binary_import_params(str(raw_path), firmware.id)

        assert result == {
            "processor": "ARM:LE:32:Cortex",
            "loader": "BinaryLoader",
            "base_addr": 0,
        }


# ---------------------------------------------------------------------------
# Analyze-command builder
# ---------------------------------------------------------------------------

class TestBuildAnalyzeCommand:
    def test_minimum_command_shape(self):
        cmd = _build_analyze_command(
            binary_path="/firmware/etc/init.d/rcS",
            script_name="AnalyzeBinary.java",
            project_dir="/tmp/ghidra_xyz",
        )
        # analyzeHeadless path is settings.ghidra_path + /support/analyzeHeadless
        assert cmd[0].endswith("/support/analyzeHeadless")
        assert "/tmp/ghidra_xyz" in cmd
        # -import + binary path are paired
        idx = cmd.index("-import")
        assert cmd[idx + 1] == "/firmware/etc/init.d/rcS"
        # -postScript + script name are paired
        idx = cmd.index("-postScript")
        assert cmd[idx + 1] == "AnalyzeBinary.java"
        # Cleanup flag tail
        assert "-deleteProject" not in cmd  # persistent project store keeps the project

    def test_script_args_appended_after_postscript(self):
        cmd = _build_analyze_command(
            binary_path="/bin/foo",
            script_name="DecompileFunction.java",
            project_dir="/tmp/p",
            script_args=["main"],
        )
        # Script args come AFTER -postScript script_name (no -deleteProject:
        # persistent Ghidra project store keeps the project on disk).
        post_idx = cmd.index("-postScript")
        assert cmd[post_idx + 1] == "DecompileFunction.java"
        assert "main" in cmd[post_idx + 2 :]
        assert "-deleteProject" not in cmd

    def test_extra_script_path_uses_single_combined_scriptpath_flag(self):
        """Regression for the 2026-06-22 stale-script bug, corrected same day.

        Verified empirically against the bundled Ghidra 12.1.2_PUBLIC: passing
        -scriptPath as two SEPARATE CLI arguments does not accumulate —
        analyzeHeadless keeps only the LAST occurrence and silently drops the
        first. A research script's temp directory and the bundled scripts
        dir must be joined into ONE -scriptPath flag using Ghidra's own
        ';'-delimited list syntax, or the temp dir is never searched at all.
        """
        cmd = _build_analyze_command(
            binary_path="/bin/foo",
            script_name="MyResearch.py",
            project_dir="/tmp/p",
            extra_script_path="/tmp/ghidra_script_abc123",
        )
        script_path_indices = [i for i, v in enumerate(cmd) if v == "-scriptPath"]
        assert len(script_path_indices) == 1
        (idx,) = script_path_indices
        parts = cmd[idx + 1].split(";")
        assert "/tmp/ghidra_script_abc123" in parts
        assert len(parts) == 2  # extra dir + bundled scripts_path, nothing else

    def test_extra_script_path_makes_postscript_an_absolute_path(self):
        """Bare-name collision resolution across -scriptPath directories is
        alphabetical-last-wins (verified empirically), NOT first-match —
        relying on it is fragile in either direction. -postScript must be
        the absolute path to the saved script so the exact file runs
        regardless of what else shares its basename.
        """
        cmd = _build_analyze_command(
            binary_path="/bin/foo",
            script_name="MyResearch.py",
            project_dir="/tmp/p",
            extra_script_path="/tmp/ghidra_script_abc123",
        )
        idx = cmd.index("-postScript")
        assert cmd[idx + 1] == "/tmp/ghidra_script_abc123/MyResearch.py"

    def test_no_extra_script_path_omits_combined_scriptpath_and_uses_bare_name(self):
        cmd = _build_analyze_command(
            binary_path="/bin/foo",
            script_name="AnalyzeBinary.java",
            project_dir="/tmp/p",
        )
        assert cmd.count("-scriptPath") == 1
        idx = cmd.index("-postScript")
        assert cmd[idx + 1] == "AnalyzeBinary.java"


# ---------------------------------------------------------------------------
# run_ghidra_subprocess — timeout + missing-binary handling
# ---------------------------------------------------------------------------

class TestRunGhidraSubprocess:
    @pytest.mark.asyncio
    async def test_missing_ghidra_raises_runtime_error_with_helpful_message(
        self, tmp_path,
    ):
        # Force a binary path that does not exist.
        binary = tmp_path / "fakebin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 12)

        async def _raise_fnf(*args, **kwargs):
            raise FileNotFoundError(f"No such file or directory: {args[0]!r}")

        with patch.object(
            ghidra_service.asyncio,
            "create_subprocess_exec",
            new=AsyncMock(side_effect=_raise_fnf),
        ):
            with pytest.raises(RuntimeError) as exc_info:
                await run_ghidra_subprocess(str(binary), "AnalyzeBinary.java")
            assert "Ghidra not found" in str(exc_info.value)
            assert "GHIDRA_PATH" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_timeout_kills_process_and_raises(self, tmp_path):
        binary = tmp_path / "fakebin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 12)

        # Build a fake Process object that hangs forever and tracks kill().
        # run_ghidra_subprocess captures stdout/stderr to tempfiles and waits
        # via asyncio.wait_for(process.wait(), ...) — NOT communicate() — so
        # wait() is what must hang until the timeout fires. After kill(), the
        # follow-up `await process.wait()` must return promptly.
        class _FakeProc:
            def __init__(self):
                self._killed = False
                self.returncode = None

            def kill(self):
                self._killed = True
                self.returncode = -9

            async def wait(self):
                if self._killed:
                    return self.returncode
                # Hang until cancelled by wait_for's timeout.
                await asyncio.sleep(3600)
                return 0

        fake_proc = _FakeProc()

        async def _return_fake(*args, **kwargs):
            return fake_proc

        # Force a tiny timeout so the test doesn't actually take the full
        # configured GHIDRA_TIMEOUT (300s).
        fake_settings = MagicMock()
        fake_settings.ghidra_timeout = 0.05
        fake_settings.ghidra_path = "/opt/ghidra"
        fake_settings.ghidra_scripts_path = "/scripts"

        with patch.object(
            ghidra_service.asyncio,
            "create_subprocess_exec",
            new=AsyncMock(side_effect=_return_fake),
        ), patch.object(
            ghidra_service, "get_settings", lambda: fake_settings,
        ):
            with pytest.raises(TimeoutError) as exc_info:
                await run_ghidra_subprocess(str(binary), "AnalyzeBinary.java")
            assert "timed out" in str(exc_info.value)

        assert fake_proc._killed, (
            "ghidra_service.run_ghidra_subprocess must call process.kill() "
            "before raising TimeoutError so the orphan analyzeHeadless does "
            "not pin a CPU after the timeout"
        )


# ---------------------------------------------------------------------------
# Rule #35b LIVE-CANARY — cache round-trip + cache-hit contract
# ---------------------------------------------------------------------------

class TestGhidraServiceCacheLiveCanary:
    """End-to-end cache round-trip on a real SQLite session.

    Two paths:

    1. ``store_cached`` + ``get_cached`` direct round-trip — proves
       the JSONB ``result`` column round-trips through the DB
       (Rule #35b: insert, then SELECT, verify the dict matches —
       not just ``mock_db.add.call_count == 1``).

    2. ``decompile_function`` with a stubbed Ghidra subprocess that
       returns a marker-wrapped payload — proves the cache-MISS path
       calls Ghidra, persists the result, and the cache-HIT path on
       the SECOND call returns the stored value WITHOUT a second
       subprocess invocation (the canonical Rule #29-aligned ms-cache
       contract — Ghidra runs are 30-120s; a missed cache HIT
       silently regresses the user-visible timeout).
    """

    @pytest.mark.asyncio
    async def test_store_then_get_round_trip(self):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="ghidra-cache", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="i" * 64,
            )
            db.add(firmware)
            await db.flush()

            # Direct round-trip via the public API — exercises both
            # store_cached + get_cached, which are the cache-layer
            # contract every other ghidra_service caller depends on.
            payload = {
                "decompiled_code": "void main() { return 0; }",
                "metadata": {"function_count": 1},
            }
            await store_cached(
                firmware_id=firmware.id,
                binary_path="/bin/init",
                binary_sha256="b" * 64,
                operation="decompile:main",
                result_data=payload,
                db=db,
            )
            await db.commit()

            # Real SELECT — the canary that mocks cannot fake.
            row = (
                await db.execute(
                    select(AnalysisCache).where(
                        AnalysisCache.firmware_id == firmware.id,
                        AnalysisCache.operation == "decompile:main",
                    )
                )
            ).scalar_one()
            assert row.binary_sha256 == "b" * 64
            assert row.binary_path == "/bin/init"
            # The stamp helper adds a _schema_version key — strip it
            # before payload comparison.
            stored = dict(row.result)
            stored.pop("_schema_version", None)
            assert stored == payload

            # Public get_cached returns the dict (with the schema_version
            # NORMALISED back out — it's a write-side stamp, not a
            # caller concern).
            fetched = await get_cached(
                firmware_id=firmware.id,
                binary_sha256="b" * 64,
                operation="decompile:main",
                db=db,
            )
            assert fetched is not None
            assert fetched.get("decompiled_code") == payload["decompiled_code"]

    @pytest.mark.asyncio
    async def test_decompile_function_caches_after_first_subprocess_call(
        self, tmp_path: Path,
    ):
        # Need a real binary file for ensure_analysis's os.path.isfile guard.
        binary = tmp_path / "init"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="ghidra-cache-hit", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="j" * 64,
            )
            db.add(firmware)
            await db.flush()
            await db.commit()

            # Marker-wrapped payload that _parse_decompile_output will
            # extract.
            decompile_payload = (
                "===DECOMPILE_START===\n"
                "int main(int argc, char **argv) {\n"
                "    return 42;\n"
                "}\n"
                "===DECOMPILE_END===\n"
            )

            call_count = 0

            async def fake_subprocess(binary_path, script_name, script_args=None, **kwargs):
                nonlocal call_count
                call_count += 1
                return decompile_payload

            with patch.object(
                ghidra_service, "run_ghidra_subprocess",
                new=fake_subprocess,
            ):
                # First call: cache MISS → subprocess called once,
                # result persisted.
                code1 = await decompile_function(
                    binary_path=str(binary),
                    function_name="main",
                    firmware_id=firmware.id,
                    db=db,
                )
                await db.commit()
                assert "return 42" in code1
                assert call_count == 1, (
                    f"first decompile_function call should invoke Ghidra "
                    f"subprocess exactly once, got {call_count}"
                )

                # Second call against the same (binary_sha256, function) —
                # MUST be a cache HIT (no second subprocess invocation).
                # This is the load-bearing performance contract: Ghidra
                # runs are 30-120s per call (Rule #29).
                code2 = await decompile_function(
                    binary_path=str(binary),
                    function_name="main",
                    firmware_id=firmware.id,
                    db=db,
                )
                assert code2 == code1
                assert call_count == 1, (
                    f"Rule #29 cache-hit regression: second decompile_function "
                    f"call against the same (binary_sha256, function) must hit "
                    f"the cache, not invoke Ghidra. Got {call_count} subprocess "
                    f"calls — was the cache miss-key wrong?"
                )

            # Real SELECT — the persisted cache row carries the right
            # operation key + binary_sha256 lookup index.
            row = (
                await db.execute(
                    select(AnalysisCache).where(
                        AnalysisCache.firmware_id == firmware.id,
                        AnalysisCache.operation == "decompile:main",
                    )
                )
            ).scalar_one()
            # binary_sha256 was computed by _get_binary_sha256 on the
            # tmp file — verify it's a 64-char hex digest.
            assert row.binary_sha256 is not None
            assert len(row.binary_sha256) == 64
            assert row.binary_path == str(binary)


# ---------------------------------------------------------------------------
# GZF process-mode read-path routing — 2026-06-26 fix
#
# ensure_analysis/decompile_function/batch_decompile_functions used to
# always -import a FRESH, pristine copy of a .gzf for AnalyzeBinary.java /
# DecompileFunction.java, completely blind to a persistent GZF process-mode
# project (run_ghidra_headless use_saved_project=True) that may already
# carry script-applied renames for the SAME archive. These tests pin the
# routing contract: when gzf_project_paths' rep_dir exists for a .gzf's own
# sha256, the read path must request -process mode (is_gzf_process_mode set)
# instead of a fresh -import (ghidra_import_params forced to None, since a
# restored project already carries its own processor/loader state).
#
# The cache-invalidation mechanism is a MONOTONIC rev counter, not a
# consume-once dirty flag: every rename bumps the rev; ensure_analysis
# rebuilds whenever the on-disk rev diverges from the rev stamped in the
# cached sentinel, so renames stay visible to list_functions / find_callers
# across any number of renames and any stale cache rebuild.
# ---------------------------------------------------------------------------

import json as _json

from app.services.ghidra_service import (
    _proj_base_from_process_target,
    _read_gzf_rev_sync,
    batch_decompile_functions,
    bump_gzf_project_rev_sync,
    get_functions,
    gzf_project_rev,
    resolve_gzf_process_target,
)


def _settings_with_projects_dir(projects_dir: str) -> MagicMock:
    s = MagicMock()
    s.ghidra_projects_dir = projects_dir
    s.ghidra_path = "/opt/ghidra"
    s.ghidra_scripts_path = "/scripts"
    s.ghidra_timeout = 300
    return s


async def _make_persistent_gzf(tmp_path: Path, projects_dir: Path) -> tuple[str, str, str]:
    """Create a .gzf file + its persistent process-mode project on disk.

    Returns (gzf_path, gzf_sha256, proj_base). get_settings must be patched to
    point ghidra_projects_dir at `projects_dir` for the helpers to find it.
    """
    gzf = tmp_path / "rom.gzf"
    gzf.write_bytes(b"PK\x03\x04" + b"\x00" * 200)  # zip magic; content is arbitrary
    sha = await ghidra_service.get_binary_sha256(str(gzf))
    proj_base = projects_dir / sha[:16]
    rep_dir = proj_base / "gzf_project.rep"
    rep_dir.mkdir(parents=True)  # simulate a restored persistent project
    return str(gzf), sha, str(proj_base)


def _analyze_output(func_names: list[str]) -> str:
    payload = {
        "functions": [
            {"name": n, "address": "0x80050000", "size": 256} for n in func_names
        ],
        "imports": [],
        "exports": [],
        "binary_info": {},
        "xrefs": {},
        "disassembly": {},
        "decompilation": {},
    }
    return (
        "INFO  AnalyzeBinary.java> ===ANALYSIS_START===\n"
        + _json.dumps(payload)
        + "\n===ANALYSIS_END===\n"
    )


class TestGzfRevCounter:
    """Monotonic, atomic rev counter — the durable invalidation signal."""

    def test_rev_starts_at_zero_when_absent(self, tmp_path: Path):
        assert _read_gzf_rev_sync(str(tmp_path)) == 0

    def test_bump_is_monotonic_and_atomic(self, tmp_path: Path):
        base = str(tmp_path / "proj")  # does not exist yet — bump must mkdir
        assert bump_gzf_project_rev_sync(base) == 1
        assert bump_gzf_project_rev_sync(base) == 2
        assert bump_gzf_project_rev_sync(base) == 3
        assert _read_gzf_rev_sync(base) == 3
        # No leftover temp files from the atomic tmp+replace write.
        leftovers = [p for p in os.listdir(base) if p.startswith(".rev-")]
        assert leftovers == []

    def test_garbage_rev_file_reads_as_zero(self, tmp_path: Path):
        (tmp_path / "_wairz_rev").write_text("not-an-int")
        assert _read_gzf_rev_sync(str(tmp_path)) == 0

    @pytest.mark.asyncio
    async def test_async_wrapper_matches_sync(self, tmp_path: Path):
        base = str(tmp_path)
        bump_gzf_project_rev_sync(base)
        assert await gzf_project_rev(base) == 1


class TestProjBaseFromProcessTarget:
    def test_round_trips_with_resolve(self):
        target = "PROJECT_PROCESS_MODE:/data/ghidra/abcdef0123456789:gzf_project"
        assert _proj_base_from_process_target(target) == "/data/ghidra/abcdef0123456789"

    def test_returns_none_for_plain_path(self):
        assert _proj_base_from_process_target("/firmware/rom.gzf") is None


class TestResolveGzfProcessTarget:
    """The single routing helper that both bugs traced back to."""

    @pytest.mark.asyncio
    async def test_non_gzf_passes_through(self, tmp_path: Path):
        target, is_proc = await resolve_gzf_process_target("/firmware/init", "a" * 64)
        assert target == "/firmware/init"
        assert is_proc is False

    @pytest.mark.asyncio
    async def test_gzf_without_project_passes_through(self, tmp_path: Path):
        projects = tmp_path / "projects"
        projects.mkdir()
        with patch.object(
            ghidra_service, "get_settings",
            lambda: _settings_with_projects_dir(str(projects)),
        ):
            target, is_proc = await resolve_gzf_process_target(
                "/firmware/rom.gzf", "b" * 64,
            )
        assert target == "/firmware/rom.gzf"
        assert is_proc is False

    @pytest.mark.asyncio
    async def test_gzf_with_project_routes_process_mode(self, tmp_path: Path):
        projects = tmp_path / "projects"
        projects.mkdir()
        with patch.object(
            ghidra_service, "get_settings",
            lambda: _settings_with_projects_dir(str(projects)),
        ):
            gzf_path, sha, proj_base = await _make_persistent_gzf(tmp_path, projects)
            target, is_proc = await resolve_gzf_process_target(gzf_path, sha)
        assert is_proc is True
        assert target == f"PROJECT_PROCESS_MODE:{proj_base}:gzf_project"
        # Routing helper output must parse back to the same proj_base.
        assert _proj_base_from_process_target(target) == proj_base


class TestGzfRevInvalidationLiveCanary:
    """Rule #35b: a rename (rev bump) durably invalidates the analysis cache
    so get_functions re-analyzes the persistent project and returns the NEW
    name — the exact contract the consume-once dirty flag failed to hold."""

    @pytest.mark.asyncio
    async def test_rev_mismatch_rebuilds_with_renamed_function(self, tmp_path: Path):
        from app.services.ghidra_service import store_cached as _store

        projects = tmp_path / "projects"
        projects.mkdir()

        async with make_live_db() as db:
            @asynccontextmanager
            async def _reuse_db():
                # All of ensure_analysis's internal async_session_factory()
                # blocks must hit the SAME in-memory DB as the test session.
                yield db

            pid = uuid.uuid4()
            db.add(Project(id=pid, name="gzf-rev", status="ready"))
            await db.flush()
            fw = Firmware(id=uuid.uuid4(), project_id=pid, sha256="k" * 64)
            db.add(fw)
            await db.flush()
            await db.commit()

            with patch.object(
                ghidra_service, "get_settings",
                lambda: _settings_with_projects_dir(str(projects)),
            ):
                gzf_path, sha, proj_base = await _make_persistent_gzf(tmp_path, projects)

                # A rename already happened: disk rev is 1, but the cache was
                # built at rev 0 with the OLD function name.
                bump_gzf_project_rev_sync(proj_base)
                await _store(
                    fw.id, gzf_path, sha, "functions",
                    {"functions": [{"name": "FUN_80050000", "address": "0x80050000", "size": 256}]},
                    db,
                )
                await _store(
                    fw.id, gzf_path, sha, "ghidra_full_analysis",
                    {"status": "complete", "function_count": 1,
                     "decompiled_count": 0, "gzf_rev": 0},
                    db,
                )
                await db.commit()

                captured: dict = {}

                async def fake_subprocess(binary_path, script_name, **kwargs):
                    captured["target"] = binary_path
                    captured["is_gzf_process_mode"] = kwargs.get("is_gzf_process_mode")
                    return _analyze_output(["release_connection_record"])

                with patch.object(
                    ghidra_service, "run_ghidra_subprocess", new=fake_subprocess,
                ), patch.object(
                    ghidra_service, "async_session_factory", _reuse_db,
                ):
                    funcs = await get_functions(gzf_path, fw.id, db)
                    await db.commit()

            names = {f["name"] for f in funcs}
            assert "release_connection_record" in names, (
                "rev mismatch must clear the stale cache and re-analyze the "
                f"persistent project; got {names}"
            )
            assert "FUN_80050000" not in names, "stale pre-rename name still served"
            assert captured["is_gzf_process_mode"] is True
            assert captured["target"].startswith("PROJECT_PROCESS_MODE:")

            # The rebuilt sentinel must carry the on-disk rev so the NEXT read
            # is a fast-path cache hit (rev now matches).
            sentinel = await get_cached(fw.id, sha, "ghidra_full_analysis", db)
            assert sentinel is not None
            assert sentinel.get("gzf_rev") == 1


class TestBatchDecompileProcessModeRouting:
    """Bug 2: batch_decompile_functions must route a GZF-with-project through
    -process mode (target + is_gzf_process_mode + params None), identical to
    decompile_function — previously it ran the pristine archive and reported
    'not found' for names decompile_function resolved fine."""

    @pytest.mark.asyncio
    async def test_batch_routes_process_mode(self, tmp_path: Path):
        projects = tmp_path / "projects"
        projects.mkdir()

        async with make_live_db() as db:
            pid = uuid.uuid4()
            db.add(Project(id=pid, name="gzf-batch", status="ready"))
            await db.flush()
            fw = Firmware(id=uuid.uuid4(), project_id=pid, sha256="m" * 64)
            db.add(fw)
            await db.flush()
            await db.commit()

            with patch.object(
                ghidra_service, "get_settings",
                lambda: _settings_with_projects_dir(str(projects)),
            ):
                gzf_path, sha, proj_base = await _make_persistent_gzf(tmp_path, projects)

                captured: dict = {}

                async def fake_subprocess(binary_path, script_name, **kwargs):
                    captured["target"] = binary_path
                    captured["is_gzf_process_mode"] = kwargs.get("is_gzf_process_mode")
                    captured["import_params"] = kwargs.get("ghidra_import_params")
                    return (
                        "===DECOMPILE_START===\n"
                        "// Function: release_connection_record\n"
                        "// Address: 0x80050000\n"
                        "\n"
                        "void release_connection_record(void) { return; }\n"
                        "===DECOMPILE_END===\n"
                        "===BATCH_SUMMARY===\n"
                        "// Requested: 1\n// Success: 1\n// Failed: 0\n"
                        "===BATCH_SUMMARY_END===\n"
                    )

                with patch.object(
                    ghidra_service, "run_ghidra_subprocess", new=fake_subprocess,
                ):
                    results = await batch_decompile_functions(
                        gzf_path, ["release_connection_record"], fw.id, db,
                    )

            assert results.get("release_connection_record")
            assert "release_connection_record" in results["release_connection_record"]
            assert captured["is_gzf_process_mode"] is True
            assert captured["target"].startswith("PROJECT_PROCESS_MODE:")
            assert captured["import_params"] is None
