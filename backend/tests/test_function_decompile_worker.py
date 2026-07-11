"""Regression test for the one-shot function-decompile worker.

The worker (app.workers.run_function_decompile) runs ON the Ghidra compute box
itself (its own AWS Batch instance in cloud, or the local host). It must run
Ghidra *in-process* via _run_ghidra_local. A previous version called the
dispatching run_ghidra_subprocess, which in cloud mode (compute_backend=
aws_batch) re-routes to the reuse worker via batch:SubmitJob — so the worker,
already running on Batch, tried to submit *another* Batch job and died with
AccessDeniedException (its job role has no batch:SubmitJob, by design).

This test pins the worker to the in-process executor and guards against the
re-dispatch regression.
"""

import contextlib
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

import app.workers.run_function_decompile as worker


@contextlib.asynccontextmanager
async def _noop_lock(_key):
    yield


@contextlib.asynccontextmanager
async def _fake_session():
    db = MagicMock()
    db.commit = AsyncMock()
    yield db


def _fake_cache():
    cache = MagicMock()
    cache._get_cached = AsyncMock(return_value=None)  # cold: no cached code
    cache._store_cached = AsyncMock()
    cache.mark_function_run_complete = AsyncMock()
    cache.mark_function_run_failed = AsyncMock()
    return cache


@pytest.fixture
def patched(monkeypatch):
    cache = _fake_cache()
    local = AsyncMock(return_value="===DECOMPILE_START===\nint foo(){}\n===DECOMPILE_END===")
    redispatch_guard = AsyncMock(
        side_effect=AssertionError("worker must not re-dispatch via run_ghidra_subprocess"),
    )

    monkeypatch.setattr(worker, "_cross_process_analysis_lock", _noop_lock)
    monkeypatch.setattr(worker, "async_session_factory", _fake_session)
    monkeypatch.setattr(worker, "get_analysis_cache", lambda: cache)
    monkeypatch.setattr(worker, "_run_ghidra_local", local)
    monkeypatch.setattr(worker, "_parse_decompile_output", lambda raw: "int foo(){}")
    # If the worker ever imports/uses the dispatching primitive again, fail loud.
    import app.services.ghidra_service as gs
    monkeypatch.setattr(gs, "run_ghidra_subprocess", redispatch_guard)
    return cache, local


async def test_worker_runs_ghidra_in_process(patched):
    cache, local = patched
    rc = await worker._run(
        firmware_id=uuid.uuid4(),
        binary_path="/sbin/httpd",
        binary_sha256="deadbeef",
        function_name="0x000263d0",
    )

    assert rc == 0
    # Ran Ghidra locally on this box...
    local.assert_awaited_once()
    args = local.await_args.args
    assert args[1] == "DecompileFunction.java"
    assert args[2] == ["0x000263d0"]
    assert args[4] == "deadbeef"  # binary_sha256 threaded through (no re-hash)
    # ...and stored the result + marked the run complete.
    cache._store_cached.assert_awaited_once()
    cache.mark_function_run_complete.assert_awaited_once()
    cache.mark_function_run_failed.assert_not_awaited()


async def test_worker_serves_existing_cache_without_running_ghidra(patched, monkeypatch):
    cache, local = patched
    cache._get_cached = AsyncMock(return_value={"decompiled_code": "int foo(){}"})

    rc = await worker._run(
        firmware_id=uuid.uuid4(),
        binary_path="/sbin/httpd",
        binary_sha256="deadbeef",
        function_name="handle_request",
    )

    assert rc == 0
    local.assert_not_awaited()  # cache hit — no Ghidra run at all
    cache.mark_function_run_complete.assert_awaited_once()
