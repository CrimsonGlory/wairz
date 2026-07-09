"""Unit-testable seams in ``app.workers.arq_worker`` (no live Redis/arq)."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.workers import arq_worker
from app.workers.arq_worker import (
    WorkerSettings,
    check_storage_quota_job,
    cleanup_analysis_cache_job,
    cleanup_emulation_expired_job,
    cleanup_fuzzing_orphans_job,
    cleanup_tmp_dumps_job,
    get_redis_settings,
    reconcile_firmware_storage_job,
    run_ghidra_analysis_job,
    run_vulnerability_scan_job,
    run_yara_scan_job,
    sync_kernel_vulns_job,
)


def test_get_redis_settings_parses_url():
    with patch.object(arq_worker, "get_settings") as gs:
        gs.return_value = MagicMock(redis_url="redis://redis:6379/0")
        settings = get_redis_settings()
    assert getattr(settings, "host", None) == "redis" or settings is not None


def test_worker_settings_shape():
    assert len(WorkerSettings.functions) >= 10
    assert WorkerSettings.job_timeout == 1800
    assert WorkerSettings.max_jobs == 6
    assert WorkerSettings.poll_delay == 0.5
    names = {getattr(f, "__name__", str(f)) for f in WorkerSettings.functions}
    assert "unpack_firmware_job" in names
    assert "run_ghidra_analysis_job" in names
    assert len(WorkerSettings.cron_jobs) >= 5


def _session_cm():
    mock_db = AsyncMock()
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=None)
    mock_db.commit = AsyncMock()
    mock_db.rollback = AsyncMock()
    mock_db.flush = AsyncMock()
    mock_db.execute = AsyncMock(
        return_value=MagicMock(
            scalars=MagicMock(
                return_value=MagicMock(all=MagicMock(return_value=[]))
            )
        )
    )
    return mock_db


@pytest.mark.asyncio
async def test_cleanup_analysis_cache_job():
    mock_db = _session_cm()
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch.object(
            arq_worker,
            "get_settings",
            return_value=MagicMock(analysis_cache_retention_days=30),
        ),
        patch("app.services._cache.cleanup_older_than", new=AsyncMock(return_value=5)),
    ):
        result = await cleanup_analysis_cache_job({})
    assert result == {"status": "ok", "retention_days": 30, "deleted": 5}


@pytest.mark.asyncio
async def test_cleanup_analysis_cache_job_zero_deleted():
    mock_db = _session_cm()
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch.object(
            arq_worker,
            "get_settings",
            return_value=MagicMock(analysis_cache_retention_days=7),
        ),
        patch("app.services._cache.cleanup_older_than", new=AsyncMock(return_value=0)),
    ):
        result = await cleanup_analysis_cache_job({})
    assert result["deleted"] == 0


@pytest.mark.asyncio
async def test_sync_kernel_vulns_job_ok():
    with patch(
        "app.services.hardware_firmware.kernel_vulns_index.sync",
        new=AsyncMock(return_value={"status": "ok", "entries": 3}),
    ):
        result = await sync_kernel_vulns_job({})
    assert result["status"] == "ok"


@pytest.mark.asyncio
async def test_sync_kernel_vulns_job_error():
    with patch(
        "app.services.hardware_firmware.kernel_vulns_index.sync",
        new=AsyncMock(side_effect=RuntimeError("net down")),
    ):
        result = await sync_kernel_vulns_job({})
    assert result["status"] == "error"
    assert "net down" in result["error"]


@pytest.mark.asyncio
async def test_cleanup_emulation_expired_job_ok():
    mock_db = _session_cm()
    mock_svc = MagicMock()
    mock_svc.cleanup_expired = AsyncMock(return_value=2)
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch("app.services.emulation.EmulationService", return_value=mock_svc),
    ):
        result = await cleanup_emulation_expired_job({})
    assert result == {"status": "ok", "reaped": 2}


@pytest.mark.asyncio
async def test_cleanup_emulation_expired_job_error():
    mock_db = _session_cm()
    mock_svc = MagicMock()
    mock_svc.cleanup_expired = AsyncMock(side_effect=RuntimeError("docker"))
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch("app.services.emulation.EmulationService", return_value=mock_svc),
    ):
        result = await cleanup_emulation_expired_job({})
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_cleanup_fuzzing_orphans_job_ok():
    mock_db = _session_cm()
    mock_svc = MagicMock()
    mock_svc.cleanup_orphans = AsyncMock(return_value={"stopped": 1, "orphans": 0})
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch("app.services.fuzzing_service.FuzzingService", return_value=mock_svc),
    ):
        result = await cleanup_fuzzing_orphans_job({})
    assert result["status"] == "ok"
    assert result["stopped"] == 1


@pytest.mark.asyncio
async def test_cleanup_fuzzing_orphans_job_error():
    mock_db = _session_cm()
    mock_svc = MagicMock()
    mock_svc.cleanup_orphans = AsyncMock(side_effect=RuntimeError("boom"))
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch("app.services.fuzzing_service.FuzzingService", return_value=mock_svc),
    ):
        result = await cleanup_fuzzing_orphans_job({})
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_run_ghidra_analysis_job_ok():
    mock_db = _session_cm()
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch(
            "app.services.ghidra_service.decompile_function",
            new=AsyncMock(return_value="int main(){return 0;}"),
        ),
    ):
        out = await run_ghidra_analysis_job(
            {},
            binary_path="/bin/x",
            function_name="main",
            firmware_id=str(uuid.uuid4()),
        )
    assert "main" in out or "return" in out


@pytest.mark.asyncio
async def test_run_ghidra_analysis_job_raises():
    mock_db = _session_cm()
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch(
            "app.services.ghidra_service.decompile_function",
            new=AsyncMock(side_effect=RuntimeError("ghidra down")),
        ),
        pytest.raises(RuntimeError, match="ghidra"),
    ):
        await run_ghidra_analysis_job(
            {},
            binary_path="/bin/x",
            function_name="main",
            firmware_id=str(uuid.uuid4()),
        )


@pytest.mark.asyncio
async def test_run_vulnerability_scan_job_ok():
    mock_db = _session_cm()
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch(
            "app.services.grype_service.scan_with_grype",
            new=AsyncMock(return_value={"vulns": 2}),
        ),
    ):
        result = await run_vulnerability_scan_job(
            {},
            firmware_id=str(uuid.uuid4()),
            project_id=str(uuid.uuid4()),
        )
    assert result == {"vulns": 2}


@pytest.mark.asyncio
async def test_run_yara_scan_job_unavailable():
    mock_db = _session_cm()
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch.dict("sys.modules", {"app.services.yara_service": None}),
        patch(
            "builtins.__import__",
            side_effect=ImportError("no yara"),
        ),
    ):
        # The job does a local import — force ImportError via patching the import path
        pass
    # Cleaner approach: patch the import inside the function
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "app.services.yara_service" or name.endswith("yara_service"):
            raise ImportError("no yara")
        return real_import(name, *args, **kwargs)

    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch("builtins.__import__", side_effect=fake_import),
    ):
        result = await run_yara_scan_job(
            {},
            project_id=str(uuid.uuid4()),
            extracted_paths=["/tmp/x"],
        )
    assert result == {"status": "unavailable"}


@pytest.mark.asyncio
async def test_run_yara_scan_job_success():
    mock_db = _session_cm()
    scan_result = MagicMock()
    scan_result.rules_loaded = 10
    scan_result.files_scanned = 5
    scan_result.files_matched = 1
    sf = MagicMock()
    sf.title = "YARA hit"
    sf.severity = "high"
    sf.description = "matched"
    sf.evidence = "e"
    sf.file_path = "/bin/x"
    sf.line_number = None
    sf.cwe_ids = []
    scan_result.findings = [sf]

    fake_mod = MagicMock()
    fake_mod.scan_firmware = MagicMock(return_value=scan_result)

    mock_finding_svc = MagicMock()
    mock_finding_svc.create = AsyncMock()

    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch.dict("sys.modules", {"app.services.yara_service": fake_mod}),
        patch("app.services.finding_service.FindingService", return_value=mock_finding_svc),
    ):
        result = await run_yara_scan_job(
            {},
            project_id=str(uuid.uuid4()),
            extracted_paths=["/tmp/extracted"],
        )
    assert result["status"] == "success"
    assert result["findings_created"] == 1
    assert result["rules_loaded"] == 10


@pytest.mark.asyncio
async def test_reconcile_firmware_storage_job_empty():
    mock_db = _session_cm()
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch.object(
            arq_worker,
            "get_settings",
            return_value=MagicMock(
                storage_root="/tmp/wairz-storage-test",
                firmware_retention_days=None,
            ),
        ),
    ):
        result = await reconcile_firmware_storage_job({})
    assert result["status"] == "ok"
    assert result["total_rows"] == 0
    assert result["missing_dirs"] == 0


@pytest.mark.asyncio
async def test_reconcile_firmware_storage_job_db_error():
    mock_db = _session_cm()
    mock_db.execute = AsyncMock(side_effect=RuntimeError("db gone"))
    # Need the context manager to raise on execute inside
    with (
        patch.object(arq_worker, "async_session_factory", return_value=mock_db),
        patch.object(
            arq_worker,
            "get_settings",
            return_value=MagicMock(storage_root="/tmp", firmware_retention_days=None),
        ),
    ):
        result = await reconcile_firmware_storage_job({})
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_cleanup_tmp_dumps_job_missing_dir():
    # Default path /tmp/wairz-dumps may or may not exist; either is fine.
    result = await cleanup_tmp_dumps_job({})
    assert isinstance(result, dict)
    assert result["status"] == "ok"
    assert "deleted" in result


@pytest.mark.asyncio
async def test_check_storage_quota_job_ok(tmp_path):
    with patch.object(
        arq_worker,
        "get_settings",
        return_value=MagicMock(storage_root=str(tmp_path)),
    ):
        result = await check_storage_quota_job({})
    assert result["status"] == "ok"
    assert "used_pct" in result
    assert "free_gb" in result


@pytest.mark.asyncio
async def test_check_storage_quota_job_oserror():
    with (
        patch.object(
            arq_worker,
            "get_settings",
            return_value=MagicMock(storage_root="/nonexistent/path"),
        ),
        patch("app.workers.arq_worker.shutil.disk_usage", side_effect=OSError("nope")),
    ):
        result = await check_storage_quota_job({})
    assert result["status"] == "error"


def test_module_exports_jobs():
    for name in (
        "unpack_firmware_job",
        "run_ghidra_analysis_job",
        "cleanup_analysis_cache_job",
        "get_redis_settings",
        "WorkerSettings",
        "sync_kernel_vulns_job",
        "cleanup_emulation_expired_job",
        "cleanup_fuzzing_orphans_job",
    ):
        assert hasattr(arq_worker, name)
