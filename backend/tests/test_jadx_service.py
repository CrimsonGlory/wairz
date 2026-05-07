"""Service-layer tests for ``app.services.jadx_service``.

Phase 2 Wave 6 file 3 of 5 — backfills service-layer tests for the
JADX decompilation wrapper (592 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

JADX is invoked as a CLI subprocess via ``asyncio.create_subprocess_exec``,
NOT a Python import — so Rule #30 here applies to the SUBPROCESS, not
the import shape:

* ``shutil.which`` IS lazy-imported inside ``_find_jadx_binary`` (line 46).
  Per Rule #30, patches MUST hit the SOURCE module:
  ``patch("shutil.which", ...)``.
* ``asyncio.create_subprocess_exec`` is referenced through the module's
  ``asyncio`` import (top-level, line 14). Patch the consumer module:
  ``patch.object(jadx_service.asyncio, "create_subprocess_exec", ...)``
  — same shape as ``test_ghidra_service.py``'s subprocess discipline.

Coverage targets:

* ``_find_jadx_binary`` — settings.jadx_path (configured + executable)
  short-circuits; PATH fallback via lazy-imported ``shutil.which``;
  FileNotFoundError when both fail.
* ``run_jadx_subprocess`` — happy path (returncode 0); FileNotFoundError
  on missing binary; TimeoutError kills process + raises.
* ``_collect_decompiled_sources`` — walks output dir, caps source count,
  skips oversized files, builds source_tree + resource_tree, computes
  stats correctly. Empty output dir produces empty result.
* ``_write_sources_sync`` — writes nested paths to disk.
* ``JadxDecompilationCache.ensure_decompilation`` — missing-APK guard
  (FileNotFoundError); cache MISS triggers _run_decompilation; cache HIT
  short-circuits and does NOT re-invoke JADX (the load-bearing
  performance contract — JADX runs are 30-300s).
* ``get_decompilation_status`` — returns None when APK missing; returns
  cached sentinel dict when complete.
* **Rule #35b live canary** — cache round-trip on a real SQLite session:
  first ``ensure_decompilation`` call invokes the (stubbed) subprocess
  + persists 4 cache rows (sentinel + source_tree + per-file +
  all_sources); second call hits the cache and does NOT invoke
  subprocess again. SELECT the persisted analysis_cache rows and
  verify binary_sha256 / operation / result JSONB shape.
"""
from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.analysis_cache import AnalysisCache
from app.models.firmware import Firmware
from app.models.project import Project
from app.services import jadx_service
from app.services.jadx_service import (
    JadxDecompilationCache,
    _collect_decompiled_sources,
    _find_jadx_binary,
    _MAX_CACHED_SOURCE_FILES,
    _MAX_SOURCE_FILE_SIZE,
    _write_sources_sync,
    get_jadx_cache,
    run_jadx_subprocess,
)

from tests._live_db import make_live_db


# ===========================================================================
# _find_jadx_binary — Rule #30 SOURCE-patch on lazy-imported shutil.which
# ===========================================================================


class TestFindJadxBinary:
    def test_configured_path_used_when_executable(self, tmp_path: Path):
        """When settings.jadx_path is a real executable, that's returned
        WITHOUT consulting PATH."""
        jadx_bin = tmp_path / "jadx"
        jadx_bin.write_text("#!/bin/sh\necho fake\n")
        os.chmod(str(jadx_bin), 0o755)

        fake_settings = MagicMock()
        fake_settings.jadx_path = str(jadx_bin)

        with patch.object(jadx_service, "get_settings", lambda: fake_settings):
            assert _find_jadx_binary() == str(jadx_bin)

    def test_path_fallback_via_shutil_which(self, tmp_path: Path):
        """When settings.jadx_path is missing, ``shutil.which`` is
        lazy-imported and consulted. Per Rule #30, patches MUST target
        the SOURCE module — NOT app.services.jadx_service."""
        fake_settings = MagicMock()
        fake_settings.jadx_path = str(tmp_path / "missing")

        # Patch the SOURCE module — `from shutil import which` inside
        # the function rebinds against shutil.which at call time.
        with patch.object(jadx_service, "get_settings", lambda: fake_settings):
            with patch("shutil.which", return_value="/usr/local/bin/jadx"):
                assert _find_jadx_binary() == "/usr/local/bin/jadx"

    def test_raises_file_not_found_when_neither_works(self, tmp_path: Path):
        fake_settings = MagicMock()
        fake_settings.jadx_path = str(tmp_path / "absent")

        with patch.object(jadx_service, "get_settings", lambda: fake_settings):
            with patch("shutil.which", return_value=None):
                with pytest.raises(FileNotFoundError, match="JADX not found"):
                    _find_jadx_binary()

    def test_configured_path_not_executable_falls_back(self, tmp_path: Path):
        """A path that exists but lacks the executable bit must trigger
        the PATH fallback, not be silently used."""
        non_exec = tmp_path / "jadx"
        non_exec.write_text("#!/bin/sh\n")
        # No chmod +x → os.access(..., os.X_OK) returns False.

        fake_settings = MagicMock()
        fake_settings.jadx_path = str(non_exec)

        with patch.object(jadx_service, "get_settings", lambda: fake_settings):
            with patch("shutil.which", return_value="/from/path/jadx"):
                assert _find_jadx_binary() == "/from/path/jadx"


# ===========================================================================
# run_jadx_subprocess — happy / missing / timeout paths
# ===========================================================================


class TestRunJadxSubprocess:
    @pytest.mark.asyncio
    async def test_happy_path_returns_decoded_stdout_stderr_returncode(
        self, tmp_path: Path,
    ):
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK\x03\x04")

        # Build a fake Process that completes successfully.
        fake_proc = MagicMock()
        fake_proc.communicate = AsyncMock(
            return_value=(b"jadx output\n", b"warnings\n"),
        )
        fake_proc.returncode = 0

        async def _return_fake(*args, **kwargs):
            return fake_proc

        fake_settings = MagicMock()
        fake_settings.jadx_path = "/opt/jadx/bin/jadx"
        fake_settings.jadx_timeout = 60
        fake_settings.jadx_threads = 4
        fake_settings.jadx_max_memory = "1g"

        with patch.object(jadx_service, "_find_jadx_binary",
                          return_value="/opt/jadx/bin/jadx"):
            with patch.object(jadx_service, "get_settings",
                              lambda: fake_settings):
                with patch.object(
                    jadx_service.asyncio,
                    "create_subprocess_exec",
                    new=AsyncMock(side_effect=_return_fake),
                ):
                    stdout, stderr, rc = await run_jadx_subprocess(
                        str(apk), str(tmp_path / "out"),
                    )

        assert stdout == "jadx output\n"
        assert stderr == "warnings\n"
        assert rc == 0

    @pytest.mark.asyncio
    async def test_missing_jadx_raises_file_not_found(self, tmp_path: Path):
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK\x03\x04")

        async def _raise_fnf(*args, **kwargs):
            raise FileNotFoundError("nope")

        fake_settings = MagicMock()
        fake_settings.jadx_path = "/opt/jadx/bin/jadx"
        fake_settings.jadx_timeout = 60
        fake_settings.jadx_threads = 4
        fake_settings.jadx_max_memory = "1g"

        with patch.object(jadx_service, "_find_jadx_binary",
                          return_value="/opt/jadx/bin/jadx"):
            with patch.object(jadx_service, "get_settings",
                              lambda: fake_settings):
                with patch.object(
                    jadx_service.asyncio,
                    "create_subprocess_exec",
                    new=AsyncMock(side_effect=_raise_fnf),
                ):
                    with pytest.raises(FileNotFoundError, match="JADX binary not found"):
                        await run_jadx_subprocess(
                            str(apk), str(tmp_path / "out"),
                        )

    @pytest.mark.asyncio
    async def test_timeout_kills_process_and_raises(self, tmp_path: Path):
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK\x03\x04")

        class _FakeProc:
            def __init__(self):
                self._killed = False

            async def communicate(self):
                await asyncio.sleep(3600)  # hang until cancelled

            def kill(self):
                self._killed = True

            async def wait(self):
                return 0

        fake_proc = _FakeProc()

        async def _return_fake(*args, **kwargs):
            return fake_proc

        fake_settings = MagicMock()
        fake_settings.jadx_path = "/opt/jadx/bin/jadx"
        fake_settings.jadx_timeout = 0.05  # tiny so the test is fast
        fake_settings.jadx_threads = 4
        fake_settings.jadx_max_memory = "1g"

        with patch.object(jadx_service, "_find_jadx_binary",
                          return_value="/opt/jadx/bin/jadx"):
            with patch.object(jadx_service, "get_settings",
                              lambda: fake_settings):
                with patch.object(
                    jadx_service.asyncio,
                    "create_subprocess_exec",
                    new=AsyncMock(side_effect=_return_fake),
                ):
                    with pytest.raises(TimeoutError, match="timed out"):
                        await run_jadx_subprocess(
                            str(apk), str(tmp_path / "out"),
                        )

        assert fake_proc._killed, (
            "TimeoutError path must call process.kill() so the orphan "
            "JADX subprocess does not pin a CPU after the timeout"
        )


# ===========================================================================
# _collect_decompiled_sources — output-dir walk + caps
# ===========================================================================


class TestCollectDecompiledSources:
    def test_empty_output_dir(self, tmp_path: Path):
        result = _collect_decompiled_sources(str(tmp_path))
        assert result["sources"] == {}
        assert result["source_tree"] == []
        assert result["resource_tree"] == []
        assert result["stats"]["total_source_files"] == 0
        assert result["stats"]["cached_source_files"] == 0
        assert result["stats"]["total_cached_bytes"] == 0

    def test_collects_java_and_kotlin_sources(self, tmp_path: Path):
        sources = tmp_path / "sources"
        (sources / "com" / "example").mkdir(parents=True)
        (sources / "com" / "example" / "Main.java").write_text("class Main {}")
        (sources / "com" / "example" / "Util.kt").write_text("class Util")
        (sources / "skip.txt").write_text("not java")  # ignored
        result = _collect_decompiled_sources(str(tmp_path))

        # Both java + kotlin collected; .txt skipped.
        assert "com/example/Main.java" in result["sources"]
        assert "com/example/Util.kt" in result["sources"]
        assert result["sources"]["com/example/Main.java"] == "class Main {}"
        assert result["stats"]["total_source_files"] == 2
        assert result["stats"]["cached_source_files"] == 2
        assert "com/example/Main.java" in result["source_tree"]

    def test_skips_oversized_files(self, tmp_path: Path):
        sources = tmp_path / "sources"
        sources.mkdir()
        # Write a file larger than _MAX_SOURCE_FILE_SIZE.
        big = sources / "Big.java"
        big.write_text("X" * (_MAX_SOURCE_FILE_SIZE + 1))
        small = sources / "Small.java"
        small.write_text("class Small {}")
        result = _collect_decompiled_sources(str(tmp_path))

        # total counts BOTH files (they're both .java); cached counts ONLY
        # the small one; skipped_too_large counts the big one.
        assert result["stats"]["total_source_files"] == 2
        assert result["stats"]["cached_source_files"] == 1
        assert result["stats"]["skipped_too_large"] == 1
        assert "Big.java" not in result["sources"]
        assert "Small.java" in result["sources"]

    def test_collects_resource_tree_listing(self, tmp_path: Path):
        resources = tmp_path / "resources"
        (resources / "AndroidManifest.xml").parent.mkdir(parents=True)
        (resources / "AndroidManifest.xml").write_text("<manifest/>")
        (resources / "res" / "layout").mkdir(parents=True)
        (resources / "res" / "layout" / "main.xml").write_text("<x/>")
        result = _collect_decompiled_sources(str(tmp_path))

        # Resource tree contains relative paths but NO content.
        assert "AndroidManifest.xml" in result["resource_tree"]
        assert "res/layout/main.xml" in result["resource_tree"]
        assert result["stats"]["total_resource_files"] == 2

    def test_skips_at_max_files_cap(self, tmp_path: Path, monkeypatch):
        """When the source count exceeds the cap, the excess goes into
        ``skipped_max_files`` and source_tree but not ``sources``."""
        sources = tmp_path / "sources"
        sources.mkdir()
        # Use a tiny cap via monkeypatch so we don't have to write 2000
        # files.
        monkeypatch.setattr(
            jadx_service, "_MAX_CACHED_SOURCE_FILES", 2,
        )
        for i in range(5):
            (sources / f"F{i}.java").write_text("class F{};")
        result = _collect_decompiled_sources(str(tmp_path))
        assert result["stats"]["total_source_files"] == 5
        assert result["stats"]["cached_source_files"] == 2
        assert result["stats"]["skipped_max_files"] == 3


class TestWriteSourcesSync:
    def test_writes_nested_paths_to_disk(self, tmp_path: Path):
        sources = {
            "com/example/Main.java": "class Main {}",
            "com/example/util/Util.java": "class Util {}",
            "Top.java": "class Top {}",
        }
        target = tmp_path / "out"
        _write_sources_sync(sources, str(target))

        assert (target / "com" / "example" / "Main.java").read_text() == "class Main {}"
        assert (target / "com" / "example" / "util" / "Util.java").read_text() == "class Util {}"
        assert (target / "Top.java").read_text() == "class Top {}"


# ===========================================================================
# JadxDecompilationCache.ensure_decompilation — missing-APK + cache hit/miss
# ===========================================================================


class TestEnsureDecompilationGuards:
    @pytest.mark.asyncio
    async def test_missing_apk_raises_file_not_found(self, tmp_path: Path):
        cache = JadxDecompilationCache()
        async with make_live_db() as db:
            with pytest.raises(FileNotFoundError, match="APK not found"):
                await cache.ensure_decompilation(
                    apk_path=str(tmp_path / "absent.apk"),
                    firmware_id=uuid.uuid4(),
                    db=db,
                )


class TestGetDecompilationStatus:
    @pytest.mark.asyncio
    async def test_missing_apk_returns_none(self, tmp_path: Path):
        cache = JadxDecompilationCache()
        async with make_live_db() as db:
            result = await cache.get_decompilation_status(
                apk_path=str(tmp_path / "missing.apk"),
                firmware_id=uuid.uuid4(),
                db=db,
            )
        assert result is None


# ===========================================================================
# Module singleton
# ===========================================================================


class TestModuleSingleton:
    def test_get_jadx_cache_returns_singleton(self):
        # Two calls return the SAME instance (load-bearing for the
        # concurrency lock — a fresh instance per request would defeat
        # the per-APK guard).
        a = get_jadx_cache()
        b = get_jadx_cache()
        assert a is b


# ===========================================================================
# Rule #35b LIVE-CANARY — cache round-trip + cache-hit contract
# ===========================================================================


class TestEnsureDecompilationLiveCanary:
    """Rule #35b live canary: real SQLite session + real
    analysis_cache rows + the cache-MISS / cache-HIT performance
    contract.

    Mirrors test_ghidra_service.py::test_decompile_function_caches_after_first_subprocess_call —
    JADX runs are 30-300s per APK; a missed cache HIT silently regresses
    user-visible UI timeout. The discipline catches a regression where
    the cache key becomes inconsistent (e.g. binary_sha256 omitted, or
    a typo in the operation key) — mock tests of
    ``mock_subprocess.assert_called_once`` cannot fail on this.
    """

    @pytest.mark.asyncio
    async def test_cache_miss_triggers_subprocess_then_hit_short_circuits(
        self, tmp_path: Path,
    ):
        # Real APK file on disk for the os.path.isfile guard.
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

        # Build a fake JADX output directory that
        # ``_collect_decompiled_sources`` will walk.
        async def fake_run_jadx(apk_path, output_dir, **kwargs):
            sources_dir = os.path.join(output_dir, "sources")
            os.makedirs(sources_dir, exist_ok=True)
            with open(os.path.join(sources_dir, "Main.java"), "w") as f:
                f.write("public class Main { public static void main() {} }")
            return ("jadx ok\n", "", 0)

        call_count = 0

        async def counting_run_jadx(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return await fake_run_jadx(*args, **kwargs)

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="jadx-canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="j" * 64,
            )
            db.add(firmware)
            await db.flush()
            await db.commit()

            cache = JadxDecompilationCache()

            with patch.object(
                jadx_service, "run_jadx_subprocess",
                new=counting_run_jadx,
            ):
                # First call: cache MISS → subprocess runs, 4+ rows persist.
                sha1 = await cache.ensure_decompilation(
                    apk_path=str(apk),
                    firmware_id=firmware.id,
                    db=db,
                )
                await db.commit()
                assert call_count == 1, (
                    f"first ensure_decompilation must invoke JADX, got "
                    f"{call_count}"
                )
                # The returned hash is the APK file's SHA256 (64 hex chars).
                assert isinstance(sha1, str)
                assert len(sha1) == 64

                # Cache rows persisted: sentinel + source_tree + per-file
                # source(s) + all_sources blob.
                rows = (await db.execute(
                    select(AnalysisCache).where(
                        AnalysisCache.firmware_id == firmware.id,
                    )
                )).scalars().all()
                ops = {r.operation for r in rows}
                assert "jadx_decompilation" in ops, "sentinel missing"
                assert "jadx_source_tree" in ops, "source_tree missing"
                assert "jadx_all_sources" in ops, "all_sources blob missing"
                # At least one per-file source row.
                assert any(o.startswith("jadx_source:") for o in ops)

                # binary_sha256 lookup key + binary_path round-trip.
                sentinel_row = next(r for r in rows
                                    if r.operation == "jadx_decompilation")
                assert sentinel_row.binary_sha256 == sha1
                assert sentinel_row.binary_path == str(apk)

                # Sentinel result JSONB shape.
                sent_payload = dict(sentinel_row.result)
                sent_payload.pop("_schema_version", None)
                assert sent_payload["status"] == "complete"
                assert sent_payload["jadx_returncode"] == 0
                assert "stats" in sent_payload
                assert sent_payload["stats"]["total_source_files"] == 1

                # Second call against the SAME APK — MUST be a cache HIT
                # (no second subprocess invocation). This is the
                # load-bearing performance contract Rule #29 backstops.
                sha2 = await cache.ensure_decompilation(
                    apk_path=str(apk),
                    firmware_id=firmware.id,
                    db=db,
                )
                assert sha2 == sha1
                assert call_count == 1, (
                    f"Rule #29 cache-hit regression: second "
                    f"ensure_decompilation against the same APK must hit "
                    f"the cache, not invoke JADX. Got {call_count} "
                    f"subprocess calls — was the binary_sha256 lookup "
                    f"key wrong?"
                )

    @pytest.mark.asyncio
    async def test_get_source_tree_returns_cached_when_complete(
        self, tmp_path: Path,
    ):
        """After ensure_decompilation completes, get_source_tree returns
        the cached source_tree entry directly (no second subprocess
        invocation)."""
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

        call_count = 0

        async def fake_run_jadx(apk_path, output_dir, **kwargs):
            nonlocal call_count
            call_count += 1
            sources_dir = os.path.join(output_dir, "sources")
            os.makedirs(sources_dir, exist_ok=True)
            with open(os.path.join(sources_dir, "App.java"), "w") as f:
                f.write("public class App {}")
            return ("ok", "", 0)

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="jadx-tree", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="t" * 64,
            )
            db.add(firmware)
            await db.flush()
            await db.commit()

            cache = JadxDecompilationCache()

            with patch.object(
                jadx_service, "run_jadx_subprocess",
                new=fake_run_jadx,
            ):
                tree1 = await cache.get_source_tree(
                    apk_path=str(apk),
                    firmware_id=firmware.id,
                    db=db,
                )
                await db.commit()
                # source_tree contains the single Java file we wrote.
                assert "App.java" in tree1["source_tree"]
                assert tree1["stats"]["total_source_files"] == 1
                assert call_count == 1

                # Second call → cache hit, identical result, no JADX.
                tree2 = await cache.get_source_tree(
                    apk_path=str(apk),
                    firmware_id=firmware.id,
                    db=db,
                )
                # Strip _schema_version stamps before comparing
                # (write-side stamp, not a caller concern).
                t1_clean = {k: v for k, v in tree1.items()
                            if k != "_schema_version"}
                t2_clean = {k: v for k, v in tree2.items()
                            if k != "_schema_version"}
                assert t2_clean == t1_clean
                assert call_count == 1
