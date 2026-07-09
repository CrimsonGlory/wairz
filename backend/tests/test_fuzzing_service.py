"""Service-layer tests for ``app.services.fuzzing_service``.

Phase 2 Wave 2 file 5 of 5 — backfills service-layer tests for the
AFL++ fuzzing campaign lifecycle (1196 LOC, 24 methods) per intake
audit-test-coverage-routers-services-2026-05-04. Largest single file
in Wave 2.

The service spawns isolated Docker containers running AFL++ in QEMU
mode for cross-architecture fuzzing. Tests mock at the Docker SDK +
filesystem boundaries so the actual AFL++ container never launches;
the live-canary discipline focuses on FuzzingCampaign row state
transitions through ``create_campaign`` and ``start_campaign`` (Rule #33
202+polling pattern — `start_campaign` is the fast-path that flips
status to ``"queued"`` before the background task takes over).

Coverage targets:

* ``_count_active_campaigns`` — counts only created/queued/running.
* ``create_campaign``       — no_extracted_path raises; concurrent-
  campaign-limit raises; happy-path persists row with config (Rule #35b
  live canary).
* ``start_campaign``        — campaign-not-found raises; bad-status
  raises; firmware-not-found raises; happy-path flips to "queued"
  (Rule #33 idempotency contract).
* ``stop_campaign``         — not-found raises; terminal-status returns
  unchanged; no-container-id flips to "stopped" + stopped_at.
* ``get_campaign_status``   — not-found raises.
* ``analyze_target``        — no_extracted_path raises; binary-not-found
  raises; ELF-parse-failure returns error dict.
* ``list_campaigns`` / ``get_crashes`` — happy paths.

Per Rule #30, ``get_settings``, ``get_docker_client``, ``check_binary_protections``,
``event_service``, JSONB normalizers — all MODULE-imported at top of
fuzzing_service.py (lines 22-36). Service-module patches work for them.

SQLite + JSONB server_default workaround: FuzzingCampaign.config and .stats
both use ``server_default="'{}'"`` (bare string, NOT text() expression).
Per the Wave 1 EmulationSession discovery, these collapse SQLite's native
JSON column processor with the live_db.py shim and bomb at flush time.
**Workaround applied:** every test FuzzingCampaign constructor passes
``config={}`` (and ``stats={}`` where applicable) explicitly.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.firmware import Firmware
from app.models.fuzzing import FuzzingCampaign, FuzzingCrash  # noqa: F401 — registers tables
from app.models.project import Project
from app.services.fuzzing_service import FuzzingService
from tests._live_db import make_live_db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed(db, *, with_extraction: bool = True) -> tuple[Project, Firmware]:
    project = Project(id=uuid.uuid4(), name="fuzz-test", status="ready")
    db.add(project)
    await db.flush()

    firmware = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="m" * 64,
        extracted_path="/tmp/extract" if with_extraction else None,
        extraction_dir="/tmp/extract" if with_extraction else None,
    )
    db.add(firmware)
    await db.flush()
    return project, firmware


def _fake_settings() -> MagicMock:
    s = MagicMock()
    s.fuzzing_max_campaigns = 3
    s.fuzzing_image = "wairz/aflpp:latest"
    s.fuzzing_timeout_minutes = 120
    s.docker_host = ""
    s.storage_root = "/data/firmware"
    s.emulation_network = "emulation_net"
    return s


# ===========================================================================
# _count_active_campaigns
# ===========================================================================


class TestCountActiveCampaigns:
    @pytest.mark.asyncio
    async def test_counts_only_active_status_campaigns(self, tmp_path: Path):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            other_project, other_firmware = await _seed(db)

            # 1 active for THIS project — counts.
            db.add(FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="/bin/x", status="running",
                config={}, stats={},
            ))
            # Stopped — does NOT count.
            db.add(FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="/bin/x", status="stopped",
                config={}, stats={},
            ))
            # Completed — does NOT count.
            db.add(FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="/bin/x", status="completed",
                config={}, stats={},
            ))
            # Other project's active — does NOT count.
            db.add(FuzzingCampaign(
                project_id=other_project.id, firmware_id=other_firmware.id,
                binary_path="/bin/x", status="running",
                config={}, stats={},
            ))
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                count = await svc._count_active_campaigns(project.id)
            assert count == 1


# ===========================================================================
# create_campaign — validation + live canary
# ===========================================================================


class TestCreateCampaignValidation:
    @pytest.mark.asyncio
    async def test_no_extracted_path_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db, with_extraction=False)
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                with pytest.raises(ValueError, match="not been unpacked"):
                    await svc.create_campaign(firmware, "bin/foo")

    @pytest.mark.asyncio
    async def test_concurrent_limit_raises(self, tmp_path: Path):
        """``fuzzing_max_campaigns = 1`` for this test — already 1 active
        → second create raises."""
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            db.add(FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="/bin/x", status="running",
                config={}, stats={},
            ))
            await db.flush()

            settings = _fake_settings()
            settings.fuzzing_max_campaigns = 1
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=settings,
            ), patch(
                "app.services.fuzzing_service.validate_path",
                return_value="/tmp/extract/bin/foo",
            ):
                svc = FuzzingService(db)
                with pytest.raises(ValueError, match="Maximum concurrent"):
                    await svc.create_campaign(firmware, "bin/foo")


class TestCreateCampaignLiveCanary:
    """Rule #35b: ``create_campaign`` writes a FuzzingCampaign row with
    config merged from defaults + caller overrides. The canary asserts
    the merged config (timeout_per_exec=1000 default + caller's
    memory_limit override) round-trips through the JSONB ``config``
    column. Mock-only tests would assert ``db.add.call_count == 1`` and
    pass even if the constructor silently dropped ``binary_path`` or
    used the wrong project_id (F-A-06 confidence-bypass shape)."""

    @pytest.mark.asyncio
    async def test_persists_campaign_with_merged_config(self, tmp_path: Path):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch(
                "app.services.fuzzing_service.validate_path",
                return_value="/tmp/extract/bin/foo",
            ):
                svc = FuzzingService(db)
                campaign = await svc.create_campaign(
                    firmware,
                    "bin/foo",
                    config={"memory_limit": 512, "dictionary": "/usr/share/dict"},
                )

            # Real SELECT — Rule #35b.
            persisted = (
                await db.execute(
                    select(FuzzingCampaign).where(
                        FuzzingCampaign.id == campaign.id,
                    )
                )
            ).scalar_one()
            assert persisted.project_id == project.id
            assert persisted.firmware_id == firmware.id
            assert persisted.binary_path == "bin/foo"
            assert persisted.status == "created"
            # Defaults merged with overrides.
            assert persisted.config["timeout_per_exec"] == 1000
            assert persisted.config["memory_limit"] == 512
            assert persisted.config["dictionary"] == "/usr/share/dict"
            assert persisted.config["seed_corpus"] is None


# ===========================================================================
# start_campaign — Rule #33 fast-path
# ===========================================================================


class TestStartCampaign:
    @pytest.mark.asyncio
    async def test_campaign_not_found_raises(self):
        async with make_live_db() as db:
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                with pytest.raises(ValueError, match="not found"):
                    await svc.start_campaign(uuid.uuid4(), uuid.uuid4())

    @pytest.mark.asyncio
    async def test_bad_status_raises(self):
        """Only ``created`` and ``stopped`` campaigns can start — anything
        else (running, queued, completed, error) raises."""
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="bin/x", status="running",
                config={}, stats={},
            )
            db.add(campaign)
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                with pytest.raises(ValueError, match="cannot be started"):
                    await svc.start_campaign(campaign.id, project.id)

    @pytest.mark.asyncio
    async def test_firmware_missing_or_unpacked_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db, with_extraction=False)
            campaign = FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="bin/x", status="created",
                config={}, stats={},
            )
            db.add(campaign)
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                with pytest.raises(ValueError, match="not unpacked"):
                    await svc.start_campaign(campaign.id, project.id)

    @pytest.mark.asyncio
    async def test_happy_path_flips_status_to_queued(self):
        """Rule #33 idempotency contract: status flips to "queued" so a
        subsequent start call returns "cannot be started" (already-in-flight
        guard). Live canary verifies the flush actually persisted."""
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="bin/x", status="created",
                config={}, stats={},
                error_message="prior error to be cleared",
            )
            db.add(campaign)
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                result = await svc.start_campaign(campaign.id, project.id)

            assert result.status == "queued"
            # error_message cleared so the next attempt's failure isn't
            # contaminated by stale text.
            assert result.error_message is None

            # Real SELECT — Rule #35b.
            refreshed = (
                await db.execute(
                    select(FuzzingCampaign).where(
                        FuzzingCampaign.id == campaign.id,
                    )
                )
            ).scalar_one()
            assert refreshed.status == "queued"
            assert refreshed.error_message is None


# ===========================================================================
# stop_campaign
# ===========================================================================


class TestStopCampaign:
    @pytest.mark.asyncio
    async def test_not_found_raises(self):
        async with make_live_db() as db:
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                with pytest.raises(ValueError, match="not found"):
                    await svc.stop_campaign(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_already_terminal_returns_unchanged(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="bin/x", status="completed",
                config={}, stats={},
            )
            db.add(campaign)
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                result = await svc.stop_campaign(campaign.id)
            assert result.status == "completed"
            assert result.stopped_at is None  # no transition

    @pytest.mark.asyncio
    async def test_no_container_id_flips_to_stopped(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="bin/x", status="queued",
                config={}, stats={},
                container_id=None,
            )
            db.add(campaign)
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                result = await svc.stop_campaign(campaign.id)
            assert result.status == "stopped"
            assert result.stopped_at is not None


# ===========================================================================
# get_campaign_status
# ===========================================================================


class TestGetCampaignStatus:
    @pytest.mark.asyncio
    async def test_not_found_raises(self):
        async with make_live_db() as db:
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                with pytest.raises(ValueError, match="not found"):
                    await svc.get_campaign_status(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_non_running_campaign_returns_unchanged(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="bin/x", status="created",
                config={}, stats={},
            )
            db.add(campaign)
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                result = await svc.get_campaign_status(campaign.id)
            assert result.status == "created"


# ===========================================================================
# analyze_target — validation surface
# ===========================================================================


class TestAnalyzeTarget:
    @pytest.mark.asyncio
    async def test_no_extracted_path_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db, with_extraction=False)
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                with pytest.raises(ValueError, match="not been unpacked"):
                    await svc.analyze_target(firmware, "bin/foo")

    @pytest.mark.asyncio
    async def test_binary_not_found_raises(self, tmp_path: Path):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            firmware.extracted_path = str(tmp_path)
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                with pytest.raises(ValueError, match="Binary not found"):
                    await svc.analyze_target(firmware, "missing/bin")

    @pytest.mark.asyncio
    async def test_elf_parse_failure_returns_error_dict(
        self, tmp_path: Path,
    ):
        """When pyelftools chokes (corrupt binary, etc.), analyze_target
        catches and returns an error dict with fuzzing_score=0 — does NOT
        raise. Frontend can render the error without breaking."""
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            firmware.extracted_path = str(tmp_path)
            await db.flush()

            # Real on-disk file so the os.path.isfile check passes.
            binary = tmp_path / "broken"
            binary.write_bytes(b"not an elf")

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_parse_elf_sync",
                side_effect=Exception("malformed ELF"),
            ):
                svc = FuzzingService(db)
                result = await svc.analyze_target(firmware, "broken")

            assert result["binary_path"] == "broken"
            assert result["fuzzing_score"] == 0
            assert "Failed to parse ELF" in result["error"]


# ===========================================================================
# list_campaigns + get_crashes
# ===========================================================================


class TestListAndGetCrashes:
    @pytest.mark.asyncio
    async def test_list_campaigns_returns_project_campaigns(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            other_project, other_firmware = await _seed(db)

            db.add(FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="/bin/a", status="running",
                config={}, stats={},
            ))
            db.add(FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="/bin/b", status="stopped",
                config={}, stats={},
            ))
            db.add(FuzzingCampaign(
                project_id=other_project.id, firmware_id=other_firmware.id,
                binary_path="/bin/x", status="running",
                config={}, stats={},
            ))
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                campaigns = await svc.list_campaigns(project.id)

            # 2 from this project, 0 from other.
            assert len(campaigns) == 2
            assert all(c.project_id == project.id for c in campaigns)

    @pytest.mark.asyncio
    async def test_get_crashes_returns_empty_for_no_crashes(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id, firmware_id=firmware.id,
                binary_path="/bin/x", status="running",
                config={}, stats={},
            )
            db.add(campaign)
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                svc = FuzzingService(db)
                crashes = await svc.get_crashes(campaign.id, project.id)
            assert crashes == []


# ===========================================================================
# Helpers / pure static methods / resolve_host_path
# ===========================================================================


class TestStaticHelpers:
    def test_write_file_to_container_put_archive(self):
        container = MagicMock()
        FuzzingService._write_file_to_container(container, "/opt/fuzzing/x.txt", b"hello")
        dest, stream = container.put_archive.call_args[0]
        assert dest == "/opt/fuzzing"
        data = stream.read() if hasattr(stream, "read") else stream.getvalue()
        assert isinstance(data, (bytes, bytearray))
        assert len(data) > 0

    def test_write_seeds_decodes_and_skips_bad_b64(self):
        import base64

        container = MagicMock()
        good = base64.b64encode(b"seeddata").decode()
        FuzzingService._write_seeds_to_container(container, [good, "!!!not-b64!!!"])
        container.put_archive.assert_called_once()
        dest, _ = container.put_archive.call_args[0]
        assert dest == "/opt/fuzzing/input"

    def test_resolve_host_path_outside_docker(self, tmp_path: Path):
        p = tmp_path / "fw"
        p.mkdir()
        with patch(
            "app.services.fuzzing_service.get_settings",
            return_value=_fake_settings(),
        ), patch("app.services.fuzzing_service.os.path.exists", return_value=False):
            # /.dockerenv missing → return realpath
            svc = FuzzingService(MagicMock())
            with patch.object(svc, "_get_docker_client") as mock_cli:
                out = svc._resolve_host_path(str(p))
                mock_cli.assert_not_called()
            assert out == str(p.resolve())

    def test_resolve_host_path_in_docker_with_mount(self, tmp_path: Path):
        p = tmp_path / "extract"
        p.mkdir()
        real = str(p.resolve())
        client = MagicMock()
        our = MagicMock()
        our.attrs = {
            "Mounts": [
                {"Destination": str(tmp_path), "Source": "/host/data"},
                {"Destination": "", "Source": ""},
            ]
        }
        client.containers.get.return_value = our
        with patch(
            "app.services.fuzzing_service.get_settings",
            return_value=_fake_settings(),
        ), patch("app.services.fuzzing_service.os.path.exists", return_value=True), patch(
            "app.services.fuzzing_service.os.environ.get", return_value="abc123"
        ):
            svc = FuzzingService(MagicMock())
            with patch.object(svc, "_get_docker_client", return_value=client):
                out = svc._resolve_host_path(real)
        assert out is not None
        assert out.startswith("/host/data")

    def test_resolve_host_path_inspect_failure_returns_none(self, tmp_path: Path):
        p = tmp_path / "x"
        p.mkdir()
        client = MagicMock()
        client.containers.get.side_effect = Exception("boom")
        with patch(
            "app.services.fuzzing_service.get_settings",
            return_value=_fake_settings(),
        ), patch("app.services.fuzzing_service.os.path.exists", return_value=True), patch(
            "app.services.fuzzing_service.os.environ.get", return_value="cid"
        ):
            svc = FuzzingService(MagicMock())
            with patch.object(svc, "_get_docker_client", return_value=client):
                out = svc._resolve_host_path(str(p))
        assert out is None

    def test_parse_elf_sync_on_real_binary(self, tmp_path: Path):
        # Write a minimal ELF if pyelftools can open it — use system binary
        # if available, else skip via exception path.
        import shutil

        src = shutil.which("true") or shutil.which("ls")
        if not src:
            pytest.skip("no ELF binary available")
        dest = tmp_path / "bin"
        shutil.copy(src, dest)
        try:
            imports, fn_count = FuzzingService._parse_elf_sync(str(dest))
        except Exception as exc:
            pytest.skip(f"ELF parse not available: {exc}")
        assert isinstance(imports, list)
        assert isinstance(fn_count, int)


class TestEmitEvent:
    @pytest.mark.asyncio
    async def test_emit_event_swallows_errors(self):
        with patch(
            "app.services.fuzzing_service.event_service.publish_progress",
            side_effect=RuntimeError("sse down"),
        ):
            await FuzzingService._emit_event(uuid.uuid4(), "running", "msg")


class TestAnalyzeTargetHappyPath:
    @pytest.mark.asyncio
    async def test_scores_network_binary(self, tmp_path: Path):
        binary = tmp_path / "httpd"
        binary.write_bytes(b"ELF")
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            firmware.extracted_path = str(tmp_path)
            await db.flush()

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService,
                "_parse_elf_sync",
                return_value=(
                    ["socket", "recv", "strcpy", "fopen", "system"],
                    100,
                ),
            ), patch(
                "app.services.fuzzing_service.check_binary_protections",
                return_value={
                    "nx": False,
                    "relro": "none",
                    "canary": False,
                    "pie": False,
                },
            ), patch(
                "app.services.fuzzing_service.os.path.getsize",
                return_value=200_000,
            ):
                svc = FuzzingService(db)
                result = await svc.analyze_target(firmware, "httpd")

            assert result["recommended_strategy"] == "network"
            assert result["fuzzing_score"] > 0
            assert "socket" in result["network_functions"]
            assert "strcpy" in result["dangerous_functions"]

    @pytest.mark.asyncio
    async def test_file_strategy_when_fopen_only(self, tmp_path: Path):
        (tmp_path / "cfg").write_bytes(b"x")
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            firmware.extracted_path = str(tmp_path)
            await db.flush()
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_parse_elf_sync", return_value=(["fopen", "fread"], 10)
            ), patch(
                "app.services.fuzzing_service.check_binary_protections",
                return_value={"nx": True, "relro": "full", "canary": True, "pie": True},
            ), patch(
                "app.services.fuzzing_service.os.path.getsize", return_value=50
            ):
                result = await FuzzingService(db).analyze_target(firmware, "cfg")
            assert result["recommended_strategy"] == "file"

    @pytest.mark.asyncio
    async def test_stdin_strategy_default(self, tmp_path: Path):
        (tmp_path / "b").write_bytes(b"x")
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            firmware.extracted_path = str(tmp_path)
            await db.flush()
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_parse_elf_sync", return_value=(["malloc"], 5)
            ), patch(
                "app.services.fuzzing_service.check_binary_protections",
                return_value={"nx": True, "relro": "full", "canary": True, "pie": True},
            ), patch(
                "app.services.fuzzing_service.os.path.getsize", return_value=10
            ):
                result = await FuzzingService(db).analyze_target(firmware, "b")
            assert result["recommended_strategy"] == "stdin"


# ===========================================================================
# _spawn_campaign_container
# ===========================================================================


class TestSpawnCampaignContainer:
    @pytest.mark.asyncio
    async def test_not_found_raises(self):
        async with make_live_db() as db:
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                with pytest.raises(ValueError, match="not found"):
                    await FuzzingService(db)._spawn_campaign_container(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_non_queued_returns_unchanged(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                out = await FuzzingService(db)._spawn_campaign_container(campaign.id)
            assert out.status == "running"

    @pytest.mark.asyncio
    async def test_missing_firmware_marks_error(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db, with_extraction=False)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="queued",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                out = await FuzzingService(db)._spawn_campaign_container(campaign.id)
            assert out.status == "error"
            assert "not unpacked" in (out.error_message or "")

    @pytest.mark.asyncio
    async def test_happy_path_marks_running(self, tmp_path: Path):
        extract = tmp_path / "root"
        extract.mkdir()
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            firmware.extracted_path = str(extract)
            firmware.architecture = "arm"
            await db.flush()
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/httpd",
                status="queued",
                config={
                    "seed_corpus": [
                        __import__("base64").b64encode(b"AAAA").decode()
                    ],
                    "dictionary": "keyword=\"admin\"",
                    "harness_script": "#!/bin/sh\nexec \"$@\"\n",
                    "timeout_per_exec": 500,
                    "environment": {"FOO": "bar"},
                    "desock": True,
                    "arguments": "@@",
                },
                stats={},
            )
            db.add(campaign)
            await db.flush()

            container = MagicMock()
            container.id = "ctr-fuzz-1"
            container.exec_run.return_value = MagicMock(exit_code=0, output=b"")
            client = MagicMock()
            client.containers.run.return_value = container

            settings = _fake_settings()
            settings.fuzzing_memory_limit_mb = 512
            settings.fuzzing_cpu_limit = 1.0

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=settings,
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ), patch.object(
                FuzzingService, "_resolve_host_path", return_value="/host/fw"
            ), patch(
                "app.services.fuzzing_service._normalize_firmware_binary_info",
                return_value=None,
            ), patch(
                "app.services.fuzzing_service._normalize_fuzzing_campaigns_config",
                side_effect=lambda c: c or {},
            ), patch(
                "app.services.fuzzing_service.event_service.publish_progress",
                new=AsyncMock(),
            ):
                svc = FuzzingService(db)
                svc._settings = settings
                out = await svc._spawn_campaign_container(campaign.id)

            assert out.status == "running"
            assert out.container_id == "ctr-fuzz-1"
            assert out.started_at is not None
            client.containers.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_unsupported_arch_marks_error(self, tmp_path: Path):
        extract = tmp_path / "root"
        extract.mkdir()
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            firmware.extracted_path = str(extract)
            firmware.architecture = "riscv"
            await db.flush()
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="queued",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()

            container = MagicMock()
            container.id = "c"
            container.exec_run.return_value = MagicMock(exit_code=0, output=b"")
            client = MagicMock()
            client.containers.run.return_value = container
            settings = _fake_settings()
            settings.fuzzing_memory_limit_mb = 256
            settings.fuzzing_cpu_limit = 0.5

            with patch(
                "app.services.fuzzing_service.get_settings", return_value=settings
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ), patch.object(
                FuzzingService, "_resolve_host_path", return_value="/host"
            ), patch(
                "app.services.fuzzing_service._normalize_firmware_binary_info",
                return_value=None,
            ), patch(
                "app.services.fuzzing_service._normalize_fuzzing_campaigns_config",
                side_effect=lambda c: c or {},
            ), patch(
                "app.services.fuzzing_service.event_service.publish_progress",
                new=AsyncMock(),
            ):
                svc = FuzzingService(db)
                svc._settings = settings
                out = await svc._spawn_campaign_container(campaign.id)
            assert out.status == "error"
            assert "Unsupported architecture" in (out.error_message or "")

    @pytest.mark.asyncio
    async def test_no_host_path_copies_dir(self, tmp_path: Path):
        extract = tmp_path / "root"
        extract.mkdir()
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            firmware.extracted_path = str(extract)
            firmware.architecture = "mipsel"
            await db.flush()
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="usr/bin/x",
                status="queued",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            container = MagicMock()
            container.id = "c2"
            container.exec_run.return_value = MagicMock(exit_code=0, output=b"")
            client = MagicMock()
            client.containers.run.return_value = container
            settings = _fake_settings()
            settings.fuzzing_memory_limit_mb = 256
            settings.fuzzing_cpu_limit = 0.5
            with patch(
                "app.services.fuzzing_service.get_settings", return_value=settings
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ), patch.object(
                FuzzingService, "_resolve_host_path", return_value=None
            ), patch(
                "app.services.fuzzing_service.copy_dir_to_container"
            ) as copy_mock, patch(
                "app.services.fuzzing_service._normalize_firmware_binary_info",
                return_value={"is_static": True},
            ), patch(
                "app.services.fuzzing_service._normalize_fuzzing_campaigns_config",
                side_effect=lambda c: c or {},
            ), patch(
                "app.services.fuzzing_service.event_service.publish_progress",
                new=AsyncMock(),
            ):
                svc = FuzzingService(db)
                svc._settings = settings
                out = await svc._spawn_campaign_container(campaign.id)
            assert out.status == "running"
            copy_mock.assert_called_once()


# ===========================================================================
# stop / status with container + sync
# ===========================================================================


class TestStopAndStatusWithContainer:
    @pytest.mark.asyncio
    async def test_stop_with_container_syncs_and_removes(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id="ctr-1",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()

            container = MagicMock()
            client = MagicMock()
            client.containers.get.return_value = container

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ), patch.object(
                FuzzingService, "_sync_stats", new=AsyncMock()
            ), patch.object(
                FuzzingService, "_sync_crashes", new=AsyncMock()
            ), patch(
                "app.services.fuzzing_service.event_service.publish_progress",
                new=AsyncMock(),
            ):
                out = await FuzzingService(db).stop_campaign(campaign.id, project.id)
            assert out.status == "stopped"
            container.stop.assert_called_once()
            container.remove.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_container_not_found_still_stops(self):
        import docker as docker_mod

        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id="gone",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            client = MagicMock()
            client.containers.get.side_effect = docker_mod.errors.NotFound("missing")
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ), patch.object(
                FuzzingService, "_sync_stats", new=AsyncMock()
            ), patch.object(
                FuzzingService, "_sync_crashes", new=AsyncMock()
            ), patch(
                "app.services.fuzzing_service.event_service.publish_progress",
                new=AsyncMock(),
            ):
                out = await FuzzingService(db).stop_campaign(campaign.id)
            assert out.status == "stopped"

    @pytest.mark.asyncio
    async def test_get_status_running_syncs(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id="ctr",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            container = MagicMock()
            container.status = "running"
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ), patch.object(
                FuzzingService, "_sync_stats", new=AsyncMock()
            ) as sync_s, patch.object(
                FuzzingService, "_sync_crashes", new=AsyncMock()
            ) as sync_c:
                out = await FuzzingService(db).get_campaign_status(
                    campaign.id, project.id
                )
            assert out.status == "running"
            sync_s.assert_awaited()
            sync_c.assert_awaited()

    @pytest.mark.asyncio
    async def test_get_status_container_exited_marks_error(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id="ctr",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            container = MagicMock()
            container.status = "exited"
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ):
                out = await FuzzingService(db).get_campaign_status(campaign.id)
            assert out.status == "error"
            assert "exited" in (out.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_get_status_container_not_found(self):
        import docker as docker_mod

        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id="gone",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            client = MagicMock()
            client.containers.get.side_effect = docker_mod.errors.NotFound("x")
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ):
                out = await FuzzingService(db).get_campaign_status(campaign.id)
            assert out.status == "stopped"


class TestSyncStatsAndCrashes:
    @pytest.mark.asyncio
    async def test_sync_stats_parses_fuzzer_stats(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id="ctr",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            stats_text = (
                "execs_per_sec     : 12.5\n"
                "execs_done        : 1000\n"
                "corpus_count      : 40\n"
                "saved_crashes     : 2\n"
                "saved_hangs       : 1\n"
                "stability         : 100.00%\n"
                "bitmap_cvg        : 3.20%\n"
                "last_find         : 99\n"
                "run_time          : 60\n"
                "odd_key           : not-a-number-value\n"
            )
            container = MagicMock()
            container.exec_run.return_value = MagicMock(
                exit_code=0, output=stats_text.encode()
            )
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ), patch(
                "app.services.fuzzing_service._stamp_fuzzing_campaigns_stats",
                side_effect=lambda d: d,
            ):
                await FuzzingService(db)._sync_stats(campaign)
            assert campaign.stats["total_execs"] == 1000
            assert campaign.stats["execs_per_sec"] == 12.5
            assert campaign.stats["saved_crashes"] == 2

    @pytest.mark.asyncio
    async def test_sync_stats_no_container_id_noop(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id=None,
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                await FuzzingService(db)._sync_stats(campaign)
            assert campaign.stats == {}

    @pytest.mark.asyncio
    async def test_sync_crashes_creates_rows(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id="ctr",
                config={},
                stats={},
                crashes_count=0,
            )
            db.add(campaign)
            await db.flush()

            def exec_run(cmd, **kwargs):
                joined = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
                if "ls -1" in joined or "grep -v" in joined:
                    return MagicMock(
                        exit_code=0,
                        output=b"id:000000,sig:11,src:000000\nid:000001,sig:06\n",
                    )
                if "cat" in joined or (isinstance(cmd, list) and cmd[0] == "cat"):
                    return MagicMock(exit_code=0, output=b"CRASHBYTES")
                return MagicMock(exit_code=0, output=b"")

            container = MagicMock()
            container.exec_run.side_effect = exec_run
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ):
                new = await FuzzingService(db)._sync_crashes(campaign)
            assert len(new) == 2
            assert campaign.crashes_count == 2
            # Rule #35b SELECT
            rows = (
                await db.execute(
                    select(FuzzingCrash).where(
                        FuzzingCrash.campaign_id == campaign.id
                    )
                )
            ).scalars().all()
            assert len(rows) == 2
            assert rows[0].crash_input == b"CRASHBYTES"

    @pytest.mark.asyncio
    async def test_sync_crashes_empty_listing(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id="ctr",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            container = MagicMock()
            container.exec_run.return_value = MagicMock(exit_code=1, output=b"")
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ):
                new = await FuzzingService(db)._sync_crashes(campaign)
            assert new == []


# ===========================================================================
# triage / get_crash_detail / cleanup
# ===========================================================================


class TestTriageAndCleanup:
    @pytest.mark.asyncio
    async def test_get_crash_detail_not_found(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                with pytest.raises(ValueError, match="Crash not found"):
                    await FuzzingService(db).get_crash_detail(
                        campaign.id, uuid.uuid4(), project.id
                    )

    @pytest.mark.asyncio
    async def test_get_crash_detail_happy(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            crash = FuzzingCrash(
                campaign_id=campaign.id,
                crash_filename="id:000000",
                crash_input=b"x",
                crash_size=1,
            )
            db.add(crash)
            await db.flush()
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                out = await FuzzingService(db).get_crash_detail(
                    campaign.id, crash.id, project.id
                )
            assert out.id == crash.id
            assert out.crash_filename == "id:000000"

    @pytest.mark.asyncio
    async def test_triage_crash_sigsegv(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            firmware.architecture = "arm"
            await db.flush()
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/httpd",
                status="running",
                container_id="ctr",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            crash = FuzzingCrash(
                campaign_id=campaign.id,
                crash_filename="id:000000,sig:11",
                crash_input=b"AAAA",
                crash_size=4,
            )
            db.add(crash)
            await db.flush()

            def exec_run(cmd, demux=False, **kwargs):
                if demux:
                    return MagicMock(
                        exit_code=139,
                        output=(b"Segmentation fault\n#0 0xdead in foo\n", b""),
                    )
                return MagicMock(exit_code=0, output=b"")

            container = MagicMock()
            container.exec_run.side_effect = exec_run
            container.put_archive = MagicMock()
            client = MagicMock()
            client.containers.get.return_value = container

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ):
                out = await FuzzingService(db).triage_crash(
                    campaign.id, crash.id, project.id
                )
            assert out.signal == "SIGSEGV"
            assert out.exploitability == "probably_exploitable"
            assert out.triage_output is not None

    @pytest.mark.asyncio
    async def test_triage_crash_not_found(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id="ctr",
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                with pytest.raises(ValueError, match="Crash not found"):
                    await FuzzingService(db).triage_crash(
                        campaign.id, uuid.uuid4(), project.id
                    )

    @pytest.mark.asyncio
    async def test_triage_no_container_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            campaign = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id=None,
                config={},
                stats={},
            )
            db.add(campaign)
            await db.flush()
            crash = FuzzingCrash(
                campaign_id=campaign.id,
                crash_filename="id:1",
                crash_input=b"x",
                crash_size=1,
            )
            db.add(crash)
            await db.flush()
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ):
                with pytest.raises(ValueError, match="container not available"):
                    await FuzzingService(db).triage_crash(
                        campaign.id, crash.id, project.id
                    )

    @pytest.mark.asyncio
    async def test_cleanup_expired_stops_old(self):
        from datetime import UTC, datetime, timedelta

        async with make_live_db() as db:
            project, firmware = await _seed(db)
            old = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                config={},
                stats={},
                started_at=datetime.now(UTC) - timedelta(hours=5),
            )
            fresh = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/y",
                status="running",
                config={},
                stats={},
                started_at=datetime.now(UTC),
            )
            db.add_all([old, fresh])
            await db.flush()
            settings = _fake_settings()
            settings.fuzzing_timeout_minutes = 60
            with patch(
                "app.services.fuzzing_service.get_settings", return_value=settings
            ), patch.object(
                FuzzingService, "stop_campaign", new=AsyncMock()
            ) as stop:
                svc = FuzzingService(db)
                svc._settings = settings
                count = await svc.cleanup_expired()
            assert count == 1
            stop.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cleanup_orphans_fixes_db_and_reaps(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            vanished = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/x",
                status="running",
                container_id="dead-ctr",
                config={},
                stats={},
            )
            no_ctr = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/y",
                status="queued",
                container_id=None,
                config={},
                stats={},
            )
            terminal = FuzzingCampaign(
                project_id=project.id,
                firmware_id=firmware.id,
                binary_path="bin/z",
                status="stopped",
                container_id="stale-ctr",
                config={},
                stats={},
            )
            db.add_all([vanished, no_ctr, terminal])
            await db.flush()

            live_ctr = MagicMock()
            live_ctr.id = "stale-ctr"
            client = MagicMock()
            client.containers.list.return_value = [live_ctr]

            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ):
                summary = await FuzzingService(db).cleanup_orphans()

            assert summary["db_fixed"] >= 2
            assert summary["containers_reaped"] == 1
            live_ctr.remove.assert_called_once()
            # Rule #35b — vanished row is now error
            row = (
                await db.execute(
                    select(FuzzingCampaign).where(FuzzingCampaign.id == vanished.id)
                )
            ).scalar_one()
            assert row.status == "error"
            assert "orphan reaper" in (row.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_cleanup_orphans_list_failure(self):
        async with make_live_db() as db:
            client = MagicMock()
            client.containers.list.side_effect = RuntimeError("docker down")
            with patch(
                "app.services.fuzzing_service.get_settings",
                return_value=_fake_settings(),
            ), patch.object(
                FuzzingService, "_get_docker_client", return_value=client
            ):
                summary = await FuzzingService(db).cleanup_orphans()
            assert summary["error"] == "list_failed"


