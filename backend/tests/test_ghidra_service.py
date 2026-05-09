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
import uuid
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
        assert cmd[-1] == "-deleteProject"

    def test_script_args_appended_before_delete_project(self):
        cmd = _build_analyze_command(
            binary_path="/bin/foo",
            script_name="DecompileFunction.java",
            project_dir="/tmp/p",
            script_args=["main"],
        )
        # Script args come AFTER -postScript script_name and BEFORE -deleteProject
        post_idx = cmd.index("-postScript")
        del_idx = cmd.index("-deleteProject")
        assert "main" in cmd[post_idx + 2:del_idx]
        assert cmd[-1] == "-deleteProject"


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
        class _FakeProc:
            def __init__(self):
                self._killed = False

            async def communicate(self):
                # Hang until cancelled by wait_for's timeout
                await asyncio.sleep(3600)

            def kill(self):
                self._killed = True

            async def wait(self):
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

            async def fake_subprocess(binary_path, script_name, script_args=None):
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
