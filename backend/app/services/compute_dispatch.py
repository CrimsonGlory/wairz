"""Compute dispatch seam for heavy Ghidra jobs.

Decouples *where* a Ghidra worker runs from the MCP tools that kick it off.
Both ``start_binary_analysis`` and ``start_function_decompile`` hand off to a
``ComputeDispatcher`` instead of spawning a subprocess directly.

- ``local`` (default): spawn a detached worker subprocess on the backend host.
  This is the standard docker-compose behavior, byte-for-byte unchanged.
- ``aws_batch``: submit the same worker module as an AWS Batch job. Wired up in
  enterprise/PLAN.md Phase 2; raises NotImplementedError until then.

The async job protocol is unaffected — the worker still writes its result to
the ``ghidra_analysis_run`` / ``analysis_cache`` rows that the status tools
poll. Only the launch mechanism varies by backend.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import sys
import uuid
from dataclasses import dataclass

from app.config import get_settings

logger = logging.getLogger(__name__)


def _job_name(prefix: str, *parts: str) -> str:
    """Build a Batch-legal job name (^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$)."""
    digest = hashlib.sha1(":".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _firmware_token(firmware_id: uuid.UUID) -> str:
    """Short, name-safe token identifying a firmware in Batch job names.

    Per-firmware jobs are named ``wairz-<token>-<kind>-<digest>`` so the queue
    can be counted per firmware via a ``JOB_NAME`` prefix filter (the cap).
    """
    return firmware_id.hex[:12]


class ConcurrencyLimitError(RuntimeError):
    """A firmware is already at its in-flight Batch-job cap.

    Subclasses RuntimeError so existing tool error handling surfaces the
    (descriptive) message; raised *before* any job is submitted or marked
    started, so it never leaves a phantom 'running' cache row.
    """


# Batch job statuses that still consume (or are about to consume) queue/compute.
_ACTIVE_BATCH_STATUSES = ("SUBMITTED", "PENDING", "RUNNABLE", "STARTING", "RUNNING")

# The Ghidra image bakes the project venv at /app/.venv (uv sync). The worker
# MUST run with that interpreter — bare "python" is the slim base image's system
# Python, which has none of the project deps (pydantic_settings, sqlalchemy, …)
# → ModuleNotFoundError at import. `uv run` is not an option (it re-resolves
# against pypi, which the no-egress Batch instance can't reach).
_WORKER_PYTHON = "/app/.venv/bin/python"


@dataclass
class JobHandle:
    """Reference to a dispatched analysis job.

    ``pid`` is the local OS pid for the ``local`` backend (used by the status
    tools' liveness check). For remote backends there is no host pid: ``pid``
    is None and ``ref`` carries the provider job id (e.g. a Batch job id).
    """

    pid: int | None = None
    ref: str | None = None


class ComputeDispatcher:
    """Launches detached Ghidra workers. One concrete impl per compute backend."""

    def dispatch_analysis(
        self, firmware_id: uuid.UUID, binary_path: str, sha256: str,
    ) -> JobHandle:
        raise NotImplementedError

    def dispatch_decompile(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        sha256: str,
        function_name: str,
    ) -> JobHandle:
        raise NotImplementedError

    def dispatch_reuse_worker(self, idle_ttl_seconds: int) -> JobHandle:
        """Start a long-lived reuse worker that drains the Redis script queue."""
        raise NotImplementedError


class LocalDispatcher(ComputeDispatcher):
    """Spawn detached worker subprocesses on the backend host (default).

    ``start_new_session=True`` makes the worker survive the wairz-mcp process
    dying (e.g. an MCP client reconnect mid-analysis); stdio is detached so the
    parent keeps no pipes open.
    """

    def _spawn(self, module_args: list[str]) -> JobHandle:
        proc = subprocess.Popen(
            [sys.executable, "-m", *module_args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        return JobHandle(pid=proc.pid)

    def dispatch_analysis(
        self, firmware_id: uuid.UUID, binary_path: str, sha256: str,
    ) -> JobHandle:
        return self._spawn([
            "app.workers.run_ghidra_analysis",
            "--firmware-id", str(firmware_id),
            "--binary-path", binary_path,
            "--sha256", sha256,
        ])

    def dispatch_decompile(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        sha256: str,
        function_name: str,
    ) -> JobHandle:
        return self._spawn([
            "app.workers.run_function_decompile",
            "--firmware-id", str(firmware_id),
            "--binary-path", binary_path,
            "--sha256", sha256,
            "--function-name", function_name,
        ])


class BatchDispatcher(ComputeDispatcher):
    """Submit the Ghidra worker as an AWS Batch job (enterprise cloud mode).

    Both workers run the SAME image (it bundles Ghidra + the worker code); the
    per-binary command is supplied as a container override, and the EFS mounts /
    env / secrets come from the Batch job definition (Terraform). The job writes
    its result to the EFS project store + Aurora cache, exactly like the local
    worker, so the status/poll protocol is unchanged.
    """

    def _client(self):
        import boto3  # lazy: only the cloud path needs boto3

        region = get_settings().aws_region or None
        return boto3.client("batch", region_name=region)

    def _submit(
        self, job_name: str, command: list[str], tags: dict[str, str] | None = None,
    ) -> JobHandle:
        settings = get_settings()
        kwargs = dict(
            jobName=job_name,
            jobQueue=settings.batch_job_queue,
            jobDefinition=settings.batch_job_definition,
            containerOverrides={"command": command},
        )
        if tags:
            kwargs["tags"] = tags
        resp = self._client().submit_job(**kwargs)
        job_id = resp["jobId"]
        logger.info("Submitted Batch job %s (%s)", job_id, job_name)
        return JobHandle(ref=job_id)

    def _count_active_jobs(self, firmware_token: str) -> int:
        """Count this firmware's in-flight jobs across all active statuses.

        Authoritative source is the queue itself (not a local counter that drifts
        when jobs finish out-of-band). Matches on the ``wairz-<token>-`` job-name
        prefix; paginates each status."""
        client = self._client()
        queue = get_settings().batch_job_queue
        # The Batch ListJobs API forbids combining `jobStatus` with `filters`
        # ("...job status are not applicable when ListJobs filters are
        # specified"). So filter only by the JOB_NAME prefix — that returns this
        # firmware's jobs in *every* status — and count the active ones from each
        # summary's own `status` field.
        name_filter = [{"name": "JOB_NAME", "values": [f"wairz-{firmware_token}-*"]}]
        active = set(_ACTIVE_BATCH_STATUSES)
        total = 0
        next_token = None
        while True:
            kwargs = {"jobQueue": queue, "filters": name_filter}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = client.list_jobs(**kwargs)
            total += sum(
                1 for j in resp.get("jobSummaryList", []) if j.get("status") in active
            )
            next_token = resp.get("nextToken")
            if not next_token:
                break
        return total

    def _enforce_firmware_cap(self, firmware_id: uuid.UUID) -> None:
        """Reject a dispatch when this firmware already has too many jobs running.

        Best-effort guardrail (a small TOCTOU window between count and submit is
        fine — batch_max_vcpus is the hard backstop). Disabled when the cap is 0."""
        cap = get_settings().batch_max_jobs_per_firmware
        if cap <= 0:
            return
        token = _firmware_token(firmware_id)
        active = self._count_active_jobs(token)
        if active >= cap:
            raise ConcurrencyLimitError(
                f"firmware {token} already has {active} Batch job(s) in flight "
                f"(cap {cap}). Wait for one to finish before starting another, "
                f"or raise batch_max_jobs_per_firmware."
            )

    def dispatch_analysis(
        self, firmware_id: uuid.UUID, binary_path: str, sha256: str,
    ) -> JobHandle:
        self._enforce_firmware_cap(firmware_id)
        token = _firmware_token(firmware_id)
        return self._submit(
            _job_name(f"wairz-{token}-an", sha256),
            [
                _WORKER_PYTHON, "-m", "app.workers.run_ghidra_analysis",
                "--firmware-id", str(firmware_id),
                "--binary-path", binary_path,
                "--sha256", sha256,
            ],
            tags={"wairz:firmware": str(firmware_id)},
        )

    def dispatch_decompile(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        sha256: str,
        function_name: str,
    ) -> JobHandle:
        self._enforce_firmware_cap(firmware_id)
        token = _firmware_token(firmware_id)
        return self._submit(
            _job_name(f"wairz-{token}-dec", sha256, function_name),
            [
                _WORKER_PYTHON, "-m", "app.workers.run_function_decompile",
                "--firmware-id", str(firmware_id),
                "--binary-path", binary_path,
                "--sha256", sha256,
                "--function-name", function_name,
            ],
            tags={"wairz:firmware": str(firmware_id)},
        )

    def dispatch_reuse_worker(self, idle_ttl_seconds: int) -> JobHandle:
        return self._submit(
            _job_name("wairz-reuse", str(idle_ttl_seconds)),
            [
                "python", "-m", "app.workers.run_reuse_worker",
                "--idle-ttl", str(idle_ttl_seconds),
            ],
        )


# Normalized job states the status tools understand.
def describe_batch_job_state(job_ref: str | None) -> str:
    """Map an AWS Batch job's status to queued|starting|running|failed|
    succeeded|unknown. Best-effort: any error → 'unknown' (the cache row, not
    this lookup, is the source of truth for completion)."""
    if not job_ref:
        return "unknown"
    try:
        import boto3  # lazy

        region = get_settings().aws_region or None
        resp = boto3.client("batch", region_name=region).describe_jobs(
            jobs=[job_ref],
        )
        jobs = resp.get("jobs", [])
        if not jobs:
            return "unknown"
        status = jobs[0].get("status", "")
        return {
            "SUBMITTED": "queued",
            "PENDING": "queued",
            "RUNNABLE": "queued",
            "STARTING": "starting",
            "RUNNING": "running",
            "SUCCEEDED": "succeeded",
            "FAILED": "failed",
        }.get(status, "unknown")
    except Exception:
        logger.warning("Batch describe_jobs failed for %s", job_ref, exc_info=True)
        return "unknown"


def get_dispatcher() -> ComputeDispatcher:
    """Return the dispatcher for the configured ``compute_backend``."""
    backend = get_settings().compute_backend
    if backend == "local":
        return LocalDispatcher()
    if backend == "aws_batch":
        return BatchDispatcher()
    raise ValueError(f"unknown compute_backend: {backend!r}")
