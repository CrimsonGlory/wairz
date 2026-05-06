"""CWE checker integration via Docker sidecar.

Runs cwe_checker (https://github.com/fkie-cad/cwe_checker) on ELF binaries
inside a Docker container. Each analysis is a one-shot `docker run --rm` that
mounts the target binary, runs the check, and returns structured JSON results.

Results are cached by binary SHA-256 in the analysis_cache table so repeated
checks are instant.
"""

import asyncio
import json
import logging
import os
import uuid
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.services import _cache
from app.utils.docker_client import get_docker_client
from app.utils.hashing import compute_file_sha256

logger = logging.getLogger(__name__)

def _image() -> str:
    return get_settings().cwe_checker_image


def _timeout() -> int:
    return get_settings().cwe_checker_timeout


def _memory() -> str:
    return get_settings().cwe_checker_memory_limit


@dataclass
class CweWarning:
    """A single CWE warning from cwe_checker."""
    cwe_id: str
    name: str
    description: str
    address: str
    symbols: list[str] = field(default_factory=list)
    other_addresses: list[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)


@dataclass
class CweCheckResult:
    """Result of running cwe_checker on a single binary."""
    binary_path: str
    binary_name: str
    sha256: str
    warnings: list[CweWarning] = field(default_factory=list)
    error: str | None = None
    elapsed_seconds: float = 0.0
    from_cache: bool = False


def _parse_cwe_json(raw: str) -> list[CweWarning]:
    """Parse cwe_checker --json output into CweWarning list."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    warnings = []
    for w in data.get("warnings", []):
        warnings.append(CweWarning(
            cwe_id=w.get("cwe_id", ""),
            name=w.get("name", ""),
            description=w.get("description", ""),
            address=w.get("address", ""),
            symbols=w.get("symbols", []),
            other_addresses=w.get("other_addresses", []),
            context=w.get("context", {}),
        ))
    return warnings


async def check_image_available() -> tuple[bool, str]:
    """Check if the cwe_checker Docker image is available."""
    try:
        import docker
        client = get_docker_client()
        client.images.get(_image())
        return True, _image()
    except docker.errors.ImageNotFound:
        return False, (
            f"Image {_image()} not found. Pull with: "
            f"docker pull --platform linux/amd64 {_image()}"
        )
    except Exception as e:
        return False, f"Docker check failed: {e}"


async def _get_cached_result(
    db: AsyncSession, firmware_id: uuid.UUID, sha256: str
) -> list[dict] | None:
    """Check analysis_cache for a prior cwe_checker result."""
    cached = await _cache.get_cached(
        db, firmware_id, "cwe_checker", binary_sha256=sha256,
    )
    if cached:
        return cached.get("warnings", [])
    return None


async def _save_to_cache(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    binary_path: str,
    sha256: str,
    warnings: list[CweWarning],
) -> None:
    """Save cwe_checker result to analysis_cache (idempotent upsert)."""
    await _cache.store_cached(
        db,
        firmware_id,
        "cwe_checker",
        {
            "warnings": [
                {
                    "cwe_id": w.cwe_id,
                    "name": w.name,
                    "description": w.description,
                    "address": w.address,
                    "symbols": w.symbols,
                    "other_addresses": w.other_addresses,
                }
                for w in warnings
            ]
        },
        binary_sha256=sha256,
        binary_path=binary_path,
    )


async def run_cwe_checker(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
    timeout: int | None = None,
    checks: list[str] | None = None,
) -> CweCheckResult:
    """Run cwe_checker on a single ELF binary.

    Args:
        binary_path: Absolute path to the ELF binary on the host filesystem.
        firmware_id: UUID of the firmware (for cache keying).
        db: Async database session.
        timeout: Max seconds for the analysis.
        checks: Optional list of specific CWE checks (e.g., ["CWE676", "CWE119"]).
                If None, runs all checks.

    Returns:
        CweCheckResult with warnings and metadata.
    """
    import time

    timeout = timeout or _timeout()
    binary_name = os.path.basename(binary_path)
    loop = asyncio.get_running_loop()
    sha256 = await loop.run_in_executor(None, compute_file_sha256, binary_path)

    # Check cache first
    cached = await _get_cached_result(db, firmware_id, sha256)
    if cached is not None:
        warnings = [
            CweWarning(
                cwe_id=w.get("cwe_id", ""),
                name=w.get("name", ""),
                description=w.get("description", ""),
                address=w.get("address", ""),
                symbols=w.get("symbols", []),
                other_addresses=w.get("other_addresses", []),
            )
            for w in cached
        ]
        return CweCheckResult(
            binary_path=binary_path,
            binary_name=binary_name,
            sha256=sha256,
            warnings=warnings,
            from_cache=True,
        )

    # Resolve the host path for Docker volume mount
    real_path = os.path.realpath(binary_path)
    if not os.path.isfile(real_path):
        return CweCheckResult(
            binary_path=binary_path,
            binary_name=binary_name,
            sha256=sha256,
            error=f"Binary not found: {binary_path}",
        )

    # Run cwe_checker via Docker SDK (same pattern as emulation/fuzzing services).
    # Use platform=linux/amd64 because the official image is x86_64-only.
    # On ARM64 hosts, Docker uses QEMU user-mode emulation (slower but functional).
    import docker
    import docker.errors

    command = ["/input/binary", "--json", "--quiet"]
    if checks:
        for check in checks:
            command.extend(["--partial", check])

    start = time.monotonic()
    try:
        client = get_docker_client()
        raw = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: client.containers.run(
                image=_image(),
                command=command,
                volumes={real_path: {"bind": "/input/binary", "mode": "ro"}},
                mem_limit=_memory(),
                network_mode="none",
                platform="linux/amd64",
                remove=True,
                stdout=True,
                stderr=False,
            ),
        )
        elapsed = time.monotonic() - start
        raw = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    except docker.errors.ContainerError as e:
        elapsed = time.monotonic() - start
        # cwe_checker may return non-zero but still produce output on stdout
        if e.stderr:
            err = e.stderr.decode("utf-8", errors="replace")[:500] if isinstance(e.stderr, bytes) else str(e.stderr)[:500]
        else:
            err = str(e)[:500]
        return CweCheckResult(
            binary_path=binary_path,
            binary_name=binary_name,
            sha256=sha256,
            error=f"cwe_checker failed: {err}",
            elapsed_seconds=elapsed,
        )
    except docker.errors.ImageNotFound:
        return CweCheckResult(
            binary_path=binary_path,
            binary_name=binary_name,
            sha256=sha256,
            error=f"Image {_image()} not found. Pull with: docker pull --platform linux/amd64 {_image()}",
        )
    except Exception as e:
        elapsed = time.monotonic() - start
        return CweCheckResult(
            binary_path=binary_path,
            binary_name=binary_name,
            sha256=sha256,
            error=f"Docker error: {e}",
            elapsed_seconds=elapsed,
        )
    warnings = _parse_cwe_json(raw)

    # Cache the result
    await _save_to_cache(db, firmware_id, binary_path, sha256, warnings)

    return CweCheckResult(
        binary_path=binary_path,
        binary_name=binary_name,
        sha256=sha256,
        warnings=warnings,
        elapsed_seconds=elapsed,
    )


async def run_cwe_checker_batch(
    binary_paths: list[str],
    firmware_id: uuid.UUID,
    db: AsyncSession,
    timeout: int | None = None,
    max_concurrent: int = 2,  # retained for API compatibility; no longer used
) -> list[CweCheckResult]:
    """Run cwe_checker on multiple binaries sequentially.

    Sequential by design (CLAUDE.md learned rule #7): earlier versions
    used ``asyncio.gather`` on coroutines sharing ``db`` — a direct
    violation of the rule (AsyncSession is not safe for concurrent
    coroutine access).  The prior semaphore(max_concurrent=2) capped
    simultaneous cwe_checker *processes* but did NOT serialise session
    use, so two coroutines could interleave on ``db.execute`` /
    ``db.add`` / ``db.flush`` and trigger
    ``InvalidRequestError: Session is already flushing`` under load,
    silently lose writes, or stamp the wrong cache row.

    Since ``cwe_checker`` is CPU + memory heavy (and was already
    semaphore-limited to 2 effective workers), the sequential rewrite
    is the minimal correctness fix.  If future throughput pressure
    demands parallelism, switch to a per-task session via
    ``async_session_factory()`` — do NOT reintroduce a shared session.

    ``max_concurrent`` is kept in the signature for backward
    compatibility with existing callers; it is no longer consulted.
    """
    results: list[CweCheckResult] = []
    for path in binary_paths:
        try:
            results.append(
                await run_cwe_checker(path, firmware_id, db, timeout)
            )
        except Exception as exc:  # noqa: BLE001 — error captured per-row
            results.append(
                CweCheckResult(
                    binary_path=path,
                    binary_name=os.path.basename(path),
                    sha256="",
                    error=str(exc),
                )
            )
    return results
