"""Tests for the compute dispatch seam — focused on the per-firmware Batch
concurrency cap (shared-instance fairness guardrail, enterprise PLAN §7)."""

from types import SimpleNamespace
from uuid import UUID

import pytest

from app.services import compute_dispatch
from app.services.compute_dispatch import (
    BatchDispatcher,
    ConcurrencyLimitError,
    JobHandle,
    _firmware_token,
)

FW = UUID("12345678-1234-5678-1234-567812345678")


def _settings(cap: int) -> SimpleNamespace:
    return SimpleNamespace(
        batch_job_queue="q",
        batch_job_definition="def",
        batch_max_jobs_per_firmware=cap,
        aws_region="us-east-1",
    )


class FakeBatchClient:
    """Records calls; models the real ListJobs API — filtering by JOB_NAME
    returns this firmware's jobs in *every* status, each summary carrying its own
    ``status`` (jobStatus must NOT be combined with filters)."""

    def __init__(self, jobs_by_status: dict | None = None):
        # status -> count; may include non-active statuses (SUCCEEDED/FAILED) to
        # prove they're excluded from the active count.
        self.jobs_by_status = jobs_by_status or {}
        self.submitted: list[dict] = []
        self.list_calls: list[dict] = []

    def list_jobs(self, **kwargs):
        self.list_calls.append(kwargs)
        summaries = []
        for status, n in self.jobs_by_status.items():
            summaries += [{"jobId": f"{status}-{i}", "status": status} for i in range(n)]
        return {"jobSummaryList": summaries}

    def submit_job(self, **kwargs):
        self.submitted.append(kwargs)
        return {"jobId": "job-xyz"}


@pytest.fixture
def patch_dispatch(monkeypatch):
    """Wire a BatchDispatcher to a FakeBatchClient and fake settings."""

    def _apply(cap: int, jobs_by_status: dict | None = None):
        client = FakeBatchClient(jobs_by_status)
        monkeypatch.setattr(compute_dispatch, "get_settings", lambda: _settings(cap))
        d = BatchDispatcher()
        monkeypatch.setattr(d, "_client", lambda: client)
        return d, client

    return _apply


def test_firmware_token_is_stable_and_name_safe():
    tok = _firmware_token(FW)
    assert tok == FW.hex[:12]
    assert tok.isalnum() and len(tok) == 12


def test_under_cap_submits_with_firmware_scoped_name_and_tag(patch_dispatch):
    d, client = patch_dispatch(cap=8, jobs_by_status={"RUNNING": 2})
    handle = d.dispatch_analysis(FW, "/bin/sh", "abc123")
    assert isinstance(handle, JobHandle) and handle.ref == "job-xyz"
    assert len(client.submitted) == 1
    sub = client.submitted[0]
    assert sub["jobName"].startswith(f"wairz-{_firmware_token(FW)}-an-")
    assert sub["tags"] == {"wairz:firmware": str(FW)}


def test_at_cap_rejects_before_submitting(patch_dispatch):
    # 8 in flight across two statuses == cap 8 → reject, no submit.
    d, client = patch_dispatch(cap=8, jobs_by_status={"RUNNING": 5, "RUNNABLE": 3})
    with pytest.raises(ConcurrencyLimitError) as exc:
        d.dispatch_decompile(FW, "/bin/sh", "abc123", "main")
    assert "in flight" in str(exc.value)
    assert client.submitted == []


def test_count_filters_by_name_excludes_finished_no_jobstatus(patch_dispatch):
    # Active statuses are counted; finished ones (SUCCEEDED/FAILED) are not. The
    # query is a SINGLE name-filtered call with NO jobStatus (the API forbids
    # combining them).
    d, client = patch_dispatch(
        cap=99,
        jobs_by_status={"RUNNING": 1, "STARTING": 2, "SUCCEEDED": 9, "FAILED": 4},
    )
    assert d._count_active_jobs(_firmware_token(FW)) == 3
    assert len(client.list_calls) == 1
    call = client.list_calls[0]
    assert "jobStatus" not in call
    assert call["jobQueue"] == "q"
    assert call["filters"] == [
        {"name": "JOB_NAME", "values": [f"wairz-{_firmware_token(FW)}-*"]}
    ]


def test_cap_zero_disables_check(patch_dispatch):
    d, client = patch_dispatch(cap=0, jobs_by_status={"RUNNING": 1000})
    d.dispatch_analysis(FW, "/bin/sh", "abc123")
    assert client.list_calls == []  # no counting when disabled
    assert len(client.submitted) == 1


def test_count_paginates(patch_dispatch):
    """nextToken is followed until exhausted; active statuses summed across pages."""
    d, client = patch_dispatch(cap=99)

    # Two pages of name-filtered results, each carrying per-job status.
    pages = [
        {"jobSummaryList": [{"jobId": "a", "status": "RUNNING"},
                            {"jobId": "b", "status": "SUCCEEDED"},
                            {"jobId": "c", "status": "STARTING"}],
         "nextToken": "more"},
        {"jobSummaryList": [{"jobId": "d", "status": "RUNNING"},
                            {"jobId": "e", "status": "RUNNING"}]},
    ]

    def list_jobs(**kwargs):
        client.list_calls.append(kwargs)
        return pages[len(client.list_calls) - 1]

    client.list_jobs = list_jobs
    # page1: RUNNING+STARTING active (SUCCEEDED excluded) = 2; page2: 2 RUNNING = 2
    assert d._count_active_jobs(_firmware_token(FW)) == 4
    assert len(client.list_calls) == 2
