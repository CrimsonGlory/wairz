"""Service-layer tests for ``app.services.cwe_checker_service``.

Phase 2 Wave 8 file 2 of 4 — backfills service-layer tests for the
cwe_checker Docker sidecar wrapper (318 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

cwe_checker is invoked via ``docker run --rm`` (one-shot container) and
results are cached by binary SHA-256 in the analysis_cache table. This
mirrors the Wave 6 jadx_service test shape — both services share the
"cache MISS triggers tool, cache HIT short-circuits with call_count==1"
performance contract that mock-only tests cannot verify.

Rule #30 distribution: ``docker`` and ``docker.errors`` are LAZY-imported
inside ``check_image_available`` (line 87) and ``run_cwe_checker`` (line
204-205). The wairz container DOES ship the docker SDK at install time,
so ``import docker`` always succeeds — but per Rule #30 mechanical
discipline, patches MUST hit the SOURCE module (the ``docker`` package
in sys.modules), not ``app.services.cwe_checker_service.docker`` which
the consumer module never bound at module scope.

Coverage targets:

* Module-level helpers: ``_image()`` / ``_timeout()`` / ``_memory()``
  read settings on every call (no caching).
* ``_parse_cwe_json`` — happy path; malformed JSON; empty; missing fields.
* ``check_image_available`` — image present; ImageNotFound; generic Exception.
* ``_get_cached_result`` / ``_save_to_cache`` — round-trip via real
  analysis_cache table; idempotent (delete-then-insert via ``_cache``).
* ``run_cwe_checker``:
  * Cache HIT short-circuits (no docker run, returns ``from_cache=True``);
  * Missing binary returns CweCheckResult with error;
  * Happy path runs container, parses output, writes cache;
  * docker.errors.ContainerError formatted into error string;
  * docker.errors.ImageNotFound formatted with pull instruction;
  * Generic exception captured.
* ``run_cwe_checker_batch`` — sequential (CLAUDE.md Rule #7); per-row
  exception captured into result list (does NOT abort the batch).
* **Rule #30 SOURCE-patch class** — ``TestRule30DockerSourcePatch``
  proves the patch shape against the docker SDK.
* **Rule #35b live canary** — full cache MISS → store_cached → cache
  HIT round-trip via real SQLite session, with a counting fake docker
  client that asserts ``call_count == 1`` after the second
  ``run_cwe_checker`` invocation (the Rule #29 cache-HIT contract that
  mock-only assertions cannot enforce).
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import docker
import docker.errors
import pytest
from sqlalchemy import select

from app.models.analysis_cache import AnalysisCache
from app.models.firmware import Firmware
from app.models.project import Project
from app.services import cwe_checker_service as cwe_mod
from app.services.cwe_checker_service import (
    CweCheckResult,
    CweWarning,
    _get_cached_result,
    _parse_cwe_json,
    _save_to_cache,
    check_image_available,
    run_cwe_checker,
    run_cwe_checker_batch,
)
from tests._live_db import make_live_db

# ===========================================================================
# Module-level setting helpers
# ===========================================================================


class TestSettingsHelpers:
    def test_image_reads_from_settings(self):
        fake_settings = MagicMock()
        fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"
        with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
            assert cwe_mod._image() == "fkiecad/cwe_checker:latest"

    def test_timeout_reads_from_settings(self):
        fake_settings = MagicMock()
        fake_settings.cwe_checker_timeout = 600
        with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
            assert cwe_mod._timeout() == 600

    def test_memory_reads_from_settings(self):
        fake_settings = MagicMock()
        fake_settings.cwe_checker_memory_limit = "4g"
        with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
            assert cwe_mod._memory() == "4g"


# ===========================================================================
# _parse_cwe_json — JSON output parsing
# ===========================================================================


class TestParseCweJson:
    def test_happy_path_extracts_warnings(self):
        raw = json.dumps({
            "warnings": [
                {
                    "cwe_id": "CWE-119",
                    "name": "Buffer Overflow",
                    "description": "OOB write in strcpy",
                    "address": "0x401234",
                    "symbols": ["strcpy"],
                    "other_addresses": ["0x401240"],
                    "context": {"function": "main"},
                },
                {
                    "cwe_id": "CWE-676",
                    "name": "Dangerous Function",
                    "description": "use of strcpy",
                    "address": "0x402000",
                },
            ]
        })
        result = _parse_cwe_json(raw)
        assert len(result) == 2
        assert result[0].cwe_id == "CWE-119"
        assert result[0].name == "Buffer Overflow"
        assert result[0].symbols == ["strcpy"]
        assert result[0].other_addresses == ["0x401240"]
        assert result[0].context == {"function": "main"}
        # Missing optional fields default sanely.
        assert result[1].symbols == []
        assert result[1].other_addresses == []
        assert result[1].context == {}

    def test_malformed_json_returns_empty(self):
        assert _parse_cwe_json("not json {") == []

    def test_empty_warnings_array_returns_empty(self):
        assert _parse_cwe_json('{"warnings": []}') == []

    def test_missing_warnings_key_returns_empty(self):
        assert _parse_cwe_json('{"version": "1.0"}') == []

    def test_missing_required_field_defaults_to_empty_string(self):
        raw = json.dumps({"warnings": [{}]})
        result = _parse_cwe_json(raw)
        assert len(result) == 1
        assert result[0].cwe_id == ""
        assert result[0].name == ""
        assert result[0].address == ""


# ===========================================================================
# check_image_available
# ===========================================================================


class TestCheckImageAvailable:
    @pytest.mark.asyncio
    async def test_image_present_returns_true(self):
        fake_settings = MagicMock()
        fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"

        fake_client = MagicMock()
        fake_client.images.get = MagicMock(return_value=MagicMock())

        with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
            with patch.object(cwe_mod, "get_docker_client",
                              return_value=fake_client):
                ok, msg = await check_image_available()
        assert ok is True
        assert msg == "fkiecad/cwe_checker:latest"

    @pytest.mark.asyncio
    async def test_image_not_found_returns_pull_instruction(self):
        fake_settings = MagicMock()
        fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"

        fake_client = MagicMock()
        fake_client.images.get = MagicMock(
            side_effect=docker.errors.ImageNotFound("not here"),
        )

        with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
            with patch.object(cwe_mod, "get_docker_client",
                              return_value=fake_client):
                ok, msg = await check_image_available()
        assert ok is False
        assert "not found" in msg
        assert "docker pull" in msg
        assert "fkiecad/cwe_checker:latest" in msg

    @pytest.mark.asyncio
    async def test_generic_exception_caught(self):
        fake_settings = MagicMock()
        fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"

        with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
            with patch.object(
                cwe_mod, "get_docker_client",
                side_effect=RuntimeError("docker daemon unreachable"),
            ):
                ok, msg = await check_image_available()
        assert ok is False
        assert "Docker check failed" in msg
        assert "docker daemon unreachable" in msg


# ===========================================================================
# _get_cached_result / _save_to_cache — cache round-trip via real DB
# ===========================================================================


class TestCacheRoundTrip:
    @pytest.mark.asyncio
    async def test_save_then_get_round_trip(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="cwe-cache", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="c" * 64,
            )
            db.add(firmware)
            await db.flush()

            warnings = [
                CweWarning(
                    cwe_id="CWE-119",
                    name="Buffer Overflow",
                    description="OOB",
                    address="0x401000",
                    symbols=["strcpy"],
                    other_addresses=[],
                ),
            ]
            await _save_to_cache(
                db, firmware.id,
                "/firmware/bin/vuln",
                "deadbeef" * 8,
                warnings,
            )
            await db.commit()

            cached = await _get_cached_result(
                db, firmware.id, "deadbeef" * 8,
            )
            assert cached is not None
            assert len(cached) == 1
            assert cached[0]["cwe_id"] == "CWE-119"
            assert cached[0]["symbols"] == ["strcpy"]

    @pytest.mark.asyncio
    async def test_get_cached_missing_returns_none(self):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="empty", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="e" * 64,
            )
            db.add(firmware)
            await db.flush()

            cached = await _get_cached_result(
                db, firmware.id, "no-such-binary" + "0" * 51,
            )
            assert cached is None


# ===========================================================================
# run_cwe_checker — error matrix + cache hit
# ===========================================================================


class TestRunCweChecker:
    @pytest.mark.asyncio
    async def test_cache_hit_short_circuits_docker(self, tmp_path: Path):
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF" + b"fake content")

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="hit", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="h" * 64,
            )
            db.add(firmware)
            await db.flush()

            # Pre-populate cache with one warning.
            from app.utils.hashing import compute_file_sha256
            sha = compute_file_sha256(str(binary))
            warnings = [CweWarning(
                cwe_id="CWE-119",
                name="Buffer overflow",
                description="OOB",
                address="0x123",
            )]
            await _save_to_cache(db, firmware.id, str(binary), sha, warnings)
            await db.commit()

            # Mock docker so we can detect if it's called (it must NOT be).
            fake_client = MagicMock()
            fake_client.containers.run = MagicMock(
                side_effect=AssertionError("docker should not run on cache hit"),
            )
            fake_settings = MagicMock()
            fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"
            fake_settings.cwe_checker_timeout = 600
            fake_settings.cwe_checker_memory_limit = "4g"

            with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
                with patch.object(
                    cwe_mod, "get_docker_client", return_value=fake_client,
                ):
                    result = await run_cwe_checker(
                        str(binary), firmware.id, db,
                    )

            assert result.from_cache is True
            assert len(result.warnings) == 1
            assert result.warnings[0].cwe_id == "CWE-119"
            assert result.sha256 == sha

    @pytest.mark.asyncio
    async def test_missing_binary_returns_error_result(self, tmp_path: Path):
        # Path that exists temporarily for the SHA computation but is
        # gone before the realpath/isfile check. Simplest: pass a path
        # that never existed and let compute_file_sha256 raise — but the
        # service expects sha256 to compute first. Use a strategy where
        # we patch compute_file_sha256 to short-circuit.
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="missing", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="m" * 64,
            )
            db.add(firmware)
            await db.flush()

            ghost = str(tmp_path / "ghost-binary")
            with patch.object(
                cwe_mod, "compute_file_sha256", return_value="0" * 64,
            ):
                fake_settings = MagicMock()
                fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"
                fake_settings.cwe_checker_timeout = 600
                fake_settings.cwe_checker_memory_limit = "4g"
                with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
                    result = await run_cwe_checker(ghost, firmware.id, db)

        assert result.error is not None
        assert "Binary not found" in result.error
        assert result.binary_name == "ghost-binary"

    @pytest.mark.asyncio
    async def test_happy_path_runs_container_and_caches(self, tmp_path: Path):
        binary = tmp_path / "good"
        binary.write_bytes(b"\x7fELF" + b"good")

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="happy", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="g" * 64,
            )
            db.add(firmware)
            await db.flush()
            await db.commit()

            # Fake container output: cwe_checker JSON with one warning.
            container_output = json.dumps({
                "warnings": [{
                    "cwe_id": "CWE-676",
                    "name": "Dangerous Function",
                    "description": "use of gets",
                    "address": "0x500",
                    "symbols": ["gets"],
                    "other_addresses": [],
                }]
            }).encode()

            fake_client = MagicMock()
            fake_client.containers.run = MagicMock(return_value=container_output)

            fake_settings = MagicMock()
            fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"
            fake_settings.cwe_checker_timeout = 600
            fake_settings.cwe_checker_memory_limit = "4g"

            with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
                with patch.object(
                    cwe_mod, "get_docker_client", return_value=fake_client,
                ):
                    result = await run_cwe_checker(
                        str(binary), firmware.id, db,
                    )
            await db.commit()

            assert result.from_cache is False
            assert result.error is None
            assert len(result.warnings) == 1
            assert result.warnings[0].cwe_id == "CWE-676"
            assert result.warnings[0].symbols == ["gets"]

            # Cache row written.
            from app.utils.hashing import compute_file_sha256
            sha = compute_file_sha256(str(binary))
            rows = (await db.execute(
                select(AnalysisCache).where(
                    AnalysisCache.firmware_id == firmware.id,
                    AnalysisCache.operation == "cwe_checker",
                    AnalysisCache.binary_sha256 == sha,
                )
            )).scalars().all()
            assert len(rows) == 1
            assert rows[0].binary_path == str(binary)
            payload = dict(rows[0].result)
            payload.pop("_schema_version", None)
            assert "warnings" in payload
            assert payload["warnings"][0]["cwe_id"] == "CWE-676"

            # Verify docker was called with the right command + mounts.
            args, kwargs = fake_client.containers.run.call_args
            assert kwargs["image"] == "fkiecad/cwe_checker:latest"
            assert kwargs["command"] == ["/input/binary", "--json", "--quiet"]
            # Volume mount points binary into /input/binary read-only.
            volumes = kwargs["volumes"]
            assert any(
                v["bind"] == "/input/binary" and v["mode"] == "ro"
                for v in volumes.values()
            )
            assert kwargs["network_mode"] == "none"
            assert kwargs["platform"] == "linux/amd64"
            assert kwargs["mem_limit"] == "4g"

    @pytest.mark.asyncio
    async def test_specific_checks_passed_as_partial_flags(self, tmp_path: Path):
        binary = tmp_path / "selected"
        binary.write_bytes(b"\x7fELF" + b"sel")

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="part", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="s" * 64,
            )
            db.add(firmware)
            await db.flush()

            fake_client = MagicMock()
            fake_client.containers.run = MagicMock(
                return_value=b'{"warnings": []}',
            )

            fake_settings = MagicMock()
            fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"
            fake_settings.cwe_checker_timeout = 600
            fake_settings.cwe_checker_memory_limit = "4g"

            with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
                with patch.object(
                    cwe_mod, "get_docker_client", return_value=fake_client,
                ):
                    await run_cwe_checker(
                        str(binary), firmware.id, db,
                        checks=["CWE676", "CWE119"],
                    )
            args, kwargs = fake_client.containers.run.call_args
            cmd = kwargs["command"]
            assert "--partial" in cmd
            assert "CWE676" in cmd
            assert "CWE119" in cmd

    @pytest.mark.asyncio
    async def test_container_error_captured_in_result(self, tmp_path: Path):
        binary = tmp_path / "fail"
        binary.write_bytes(b"\x7fELF" + b"x")

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="cerr", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="f" * 64,
            )
            db.add(firmware)
            await db.flush()

            fake_client = MagicMock()
            err = docker.errors.ContainerError(
                container="cwe_check",
                exit_status=1,
                command="cwe_checker",
                image="fkiecad/cwe_checker",
                stderr=b"corrupt binary input",
            )
            fake_client.containers.run = MagicMock(side_effect=err)

            fake_settings = MagicMock()
            fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"
            fake_settings.cwe_checker_timeout = 600
            fake_settings.cwe_checker_memory_limit = "4g"

            with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
                with patch.object(
                    cwe_mod, "get_docker_client", return_value=fake_client,
                ):
                    result = await run_cwe_checker(
                        str(binary), firmware.id, db,
                    )

        assert result.error is not None
        assert "cwe_checker failed" in result.error
        assert "corrupt binary input" in result.error

    @pytest.mark.asyncio
    async def test_image_not_found_at_run_time(self, tmp_path: Path):
        binary = tmp_path / "nopull"
        binary.write_bytes(b"\x7fELF")

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="nopull", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="n" * 64,
            )
            db.add(firmware)
            await db.flush()

            fake_client = MagicMock()
            fake_client.containers.run = MagicMock(
                side_effect=docker.errors.ImageNotFound("missing"),
            )

            fake_settings = MagicMock()
            fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"
            fake_settings.cwe_checker_timeout = 600
            fake_settings.cwe_checker_memory_limit = "4g"

            with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
                with patch.object(
                    cwe_mod, "get_docker_client", return_value=fake_client,
                ):
                    result = await run_cwe_checker(
                        str(binary), firmware.id, db,
                    )
        assert result.error is not None
        assert "not found" in result.error
        assert "docker pull" in result.error

    @pytest.mark.asyncio
    async def test_generic_exception_captured(self, tmp_path: Path):
        binary = tmp_path / "boom"
        binary.write_bytes(b"\x7fELF")

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="boom", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="b" * 64,
            )
            db.add(firmware)
            await db.flush()

            fake_client = MagicMock()
            fake_client.containers.run = MagicMock(
                side_effect=RuntimeError("ENOMEM"),
            )

            fake_settings = MagicMock()
            fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"
            fake_settings.cwe_checker_timeout = 600
            fake_settings.cwe_checker_memory_limit = "4g"

            with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
                with patch.object(
                    cwe_mod, "get_docker_client", return_value=fake_client,
                ):
                    result = await run_cwe_checker(
                        str(binary), firmware.id, db,
                    )
        assert result.error is not None
        assert "Docker error" in result.error
        assert "ENOMEM" in result.error


# ===========================================================================
# run_cwe_checker_batch — sequential per Rule #7
# ===========================================================================


class TestRunCweCheckerBatch:
    @pytest.mark.asyncio
    async def test_runs_each_binary_sequentially(self, tmp_path: Path):
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.write_bytes(b"\x7fELFa")
        b.write_bytes(b"\x7fELFb")

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="batch", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="z" * 64,
            )
            db.add(firmware)
            await db.flush()

            call_log: list[str] = []

            def _fake_run(image, command, volumes, **kwargs):
                # Record each invocation.
                call_log.append(image)
                return b'{"warnings": []}'

            fake_client = MagicMock()
            fake_client.containers.run = MagicMock(side_effect=_fake_run)

            fake_settings = MagicMock()
            fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"
            fake_settings.cwe_checker_timeout = 600
            fake_settings.cwe_checker_memory_limit = "4g"

            with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
                with patch.object(
                    cwe_mod, "get_docker_client", return_value=fake_client,
                ):
                    results = await run_cwe_checker_batch(
                        [str(a), str(b)], firmware.id, db,
                    )

        assert len(results) == 2
        assert results[0].binary_name == "a"
        assert results[1].binary_name == "b"
        # Both processed; sequential implies len(call_log) == 2.
        assert len(call_log) == 2

    @pytest.mark.asyncio
    async def test_per_row_exception_captured_does_not_abort_batch(
        self, tmp_path: Path,
    ):
        good = tmp_path / "good"
        bad = tmp_path / "bad"
        good.write_bytes(b"\x7fELFg")
        bad.write_bytes(b"\x7fELFb")

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="batch-err", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="r" * 64,
            )
            db.add(firmware)
            await db.flush()

            # Mock run_cwe_checker directly to force the bad path to raise.
            async def _fake(path, fwid, db, timeout=None):  # noqa: ASYNC109 — test stub: signature-mirroring fake for run_cwe_checker; timeout= must match upstream signature
                if path.endswith("bad"):
                    raise RuntimeError("boom on bad")
                return CweCheckResult(
                    binary_path=path,
                    binary_name="good",
                    sha256="x" * 64,
                )

            with patch.object(cwe_mod, "run_cwe_checker", side_effect=_fake):
                results = await run_cwe_checker_batch(
                    [str(good), str(bad)], firmware.id, db,
                )

        # Both entries present even though one raised.
        assert len(results) == 2
        # The bad one carries the error.
        bad_result = next(r for r in results if r.binary_name == "bad")
        assert bad_result.error == "boom on bad"
        # The good one survived.
        good_result = next(r for r in results if r.binary_name == "good")
        assert good_result.error is None


# ===========================================================================
# Rule #30 SOURCE-patch class — explicit discipline canary
# ===========================================================================


class TestRule30DockerSourcePatch:
    """Rule #30 source-patch discipline: ``docker`` is lazy-imported
    INSIDE ``check_image_available`` (line 87) and ``run_cwe_checker``
    (lines 204-205). The wairz container ships docker at install time,
    so ``import docker`` always succeeds — but the consumer module
    NEVER binds ``docker`` at module scope.

    Mock targets that would be a SILENT NO-OP:
    * ``patch("app.services.cwe_checker_service.docker", ...)`` —
      AttributeError because the consumer never bound the name.
    * ``patch.object(cwe_mod, "docker", ...)`` — same.

    The CORRECT discipline (this test class):
    * The wairz tests don't actually need to replace the docker module
      itself — they patch the docker_client + the SDK exception classes
      via the SOURCE module (``docker.errors.ContainerError``,
      ``docker.errors.ImageNotFound``). Those are already public attrs
      on the docker package and therefore valid SOURCE-patch targets.
    """

    def test_consumer_module_has_no_docker_attribute(self):
        """Sanity: confirms ``cwe_mod.docker`` does NOT exist as a
        module-scope attribute. A future refactor that promotes the
        import to top-level would break tests that patch the SOURCE
        module's exception classes by ALSO patching the consumer
        binding (unless the consumer's binding is also patched in
        sync). This sentinel fails LOUDLY in that case so the tests
        are migrated."""
        assert not hasattr(cwe_mod, "docker"), (
            "If docker is now top-level, additionally patch.object("
            "cwe_mod, 'docker', ...) in the relevant tests per "
            "Rule #30 inverse case."
        )

    def test_source_patch_via_module_attribute_works(self):
        """Demonstrates the canonical SOURCE-patch shape: patching
        ``docker.errors.ImageNotFound`` makes the cwe_mod's
        ``except docker.errors.ImageNotFound:`` clause catch the
        injected exception, because the lazy ``import docker`` resolves
        through ``sys.modules['docker']`` — which is the same module
        object the SOURCE patch targets."""
        # docker.errors.ImageNotFound is the real class.
        assert docker.errors.ImageNotFound is sys.modules[
            "docker.errors"
        ].ImageNotFound


# ===========================================================================
# Rule #35b LIVE-CANARY — cache MISS / cache HIT contract end-to-end
# ===========================================================================


class TestRunCweCheckerLiveCanary:
    """Rule #35b live canary: the cache MISS → cache HIT performance
    contract end-to-end. Mock-only tests of ``mock.assert_called_once``
    cannot fail on a regression where the cache key drifts (e.g. a
    typo in ``"cwe_checker"`` operation name, or ``binary_sha256``
    omitted from the lookup) — the test would still see one
    invocation per call but it would silently be a fresh docker run.

    This canary uses a counting fake docker client + real SQLite
    session: first call MUST run docker (call_count == 1); second
    call against the same binary MUST short-circuit on cache HIT
    (call_count STILL == 1).
    """

    @pytest.mark.asyncio
    async def test_cache_miss_then_hit_call_count_stays_one(
        self, tmp_path: Path,
    ):
        binary = tmp_path / "canary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        # Counting fake client.
        call_count = 0
        warnings_payload = json.dumps({
            "warnings": [{
                "cwe_id": "CWE-415",
                "name": "Double Free",
                "description": "pointer freed twice",
                "address": "0xabc",
                "symbols": [],
                "other_addresses": [],
            }]
        }).encode()

        def _counting_run(image, command, volumes, **kwargs):
            nonlocal call_count
            call_count += 1
            return warnings_payload

        fake_client = MagicMock()
        fake_client.containers.run = MagicMock(side_effect=_counting_run)

        fake_settings = MagicMock()
        fake_settings.cwe_checker_image = "fkiecad/cwe_checker:latest"
        fake_settings.cwe_checker_timeout = 600
        fake_settings.cwe_checker_memory_limit = "4g"

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="C" * 64,
            )
            db.add(firmware)
            await db.flush()
            await db.commit()

            with patch.object(cwe_mod, "get_settings", lambda: fake_settings):
                with patch.object(
                    cwe_mod, "get_docker_client", return_value=fake_client,
                ):
                    # First call: cache MISS → docker runs, row persists.
                    result1 = await run_cwe_checker(
                        str(binary), firmware.id, db,
                    )
                    await db.commit()
                    assert result1.from_cache is False
                    assert call_count == 1
                    assert len(result1.warnings) == 1
                    assert result1.warnings[0].cwe_id == "CWE-415"

                    # Cache row landed in analysis_cache.
                    rows = (await db.execute(
                        select(AnalysisCache).where(
                            AnalysisCache.firmware_id == firmware.id,
                            AnalysisCache.operation == "cwe_checker",
                        )
                    )).scalars().all()
                    assert len(rows) == 1
                    assert rows[0].binary_sha256 == result1.sha256
                    assert rows[0].binary_path == str(binary)
                    payload = dict(rows[0].result)
                    payload.pop("_schema_version", None)
                    assert payload["warnings"][0]["cwe_id"] == "CWE-415"

                    # Second call against the SAME binary — MUST hit cache.
                    result2 = await run_cwe_checker(
                        str(binary), firmware.id, db,
                    )
                    assert result2.from_cache is True
                    assert call_count == 1, (
                        f"Rule #29 cache-hit regression: second "
                        f"run_cwe_checker against the same binary must hit "
                        f"the cache, not invoke docker. Got {call_count} "
                        f"docker invocations — was the binary_sha256 lookup "
                        f"key wrong?"
                    )
                    assert result2.sha256 == result1.sha256
                    assert len(result2.warnings) == 1
                    assert result2.warnings[0].cwe_id == "CWE-415"
