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

import os
import uuid
from datetime import datetime, timezone
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
