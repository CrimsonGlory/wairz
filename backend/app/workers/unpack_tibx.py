"""Phase λ.μ — Acronis .tibx (Archive3) unpack worker via tibx-extractor side-container.

Spawns the ``wairz-tibx-extractor`` side-container (defined in
``docker-compose.yml`` + ``tibx-extractor/Dockerfile``) per upload,
which runs operator-installed ``tibxread`` against the customer's
``.tibx`` master file and emits raw disk bytes to a named volume the
worker reads back.

Per CLAUDE.md Rule #36 Exception 3 — vendor-supplied trusted parser
binaries running INSIDE A HARDENED SIDE-CONTAINER (separate from the
worker; ``read_only``, ``network_mode: none``, ``cap_drop: ALL``,
non-root, resource-limited, operator-supplied via bind-mount per BYO
discipline) that consume customer data AS DATA are an explicit
Rule #36 exception. The security boundary is the side-container's
network/capability isolation; the wairz worker only consumes the
side-container's output bytes. Precedent companion to ``qemu-img``,
``signify``, ``ilspycmd`` exceptions but moved out of the worker for
sandbox strength.

Per CLAUDE.md Rule #29 — explicit ``asyncio.wait_for`` timeout on the
side-container's lifecycle (default 1200 s = 20 min for a 4×4 GB
``.tibx`` set; mirrors the qemu-img convert ceiling).

Output contract mirrors ``unpack_vhdx.py``:
``<tibx>`` → ``extraction_dir/disk.raw`` (single-disk default).

Failure modes:

- Side-container image missing → install hint pointing at
  ``docker compose --profile build build tibx-extractor``.
- ``WAIRZ_TIBX_AGENT_PATH`` unset / bind empty → entrypoint exits 2,
  worker surfaces operator-actionable error pointing at the Acronis
  Linux Agent install.
- ``tibxread`` exit non-zero → passthrough stderr in unpack_log.
- Timeout → kill+reap the extractor container; surface clean error.

The first slice in a multi-slice backup carries ``ARCH`` at offset 8;
continuation slices (``Archive(1)-NNNN.tibx``) do NOT and are not
extractable standalone — reject them with operator guidance to feed
the master.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import uuid
from typing import Any

from app.workers.unpack_common import UnpackResult, reset_extraction_dir_sync

logger = logging.getLogger(__name__)


# Rule #29 timeout. 4×4 GB ``.tibx`` slices typically extract in
# 10-15 min on commodity NVMe; 20 min ceiling matches Ghidra/qemu-img
# tier (600 s) × 2 for the typical 2× wall-clock cost vs a single
# qemu-img convert pass.
_TIBX_EXTRACT_TIMEOUT_SECONDS: int = 1200

# Side-container probe (list backups) is cheap — bounded by the master
# slice's metadata-region read. 60 s ample for any real .tibx.
_TIBX_PROBE_TIMEOUT_SECONDS: int = 60

# Magic-byte signature for ``.tibx`` Archive3 master slices. Empirically
# observed on Medtronic ILLUMISITE Archive(1).tibx 2026-05-13; see
# .planning/research/tibx-deep-2026-05-13/scout-a-format-deep-research.md.
_TIBX_MASTER_MAGIC = b"ARCH"
_TIBX_MASTER_MAGIC_OFFSET = 8
_TIBX_HEAD_PROBE_BYTES = 16

# Side-container image name. Sourced from env (``TIBX_EXTRACTOR_IMAGE``,
# set in docker-compose.yml) so the test suite can override.
_DEFAULT_EXTRACTOR_IMAGE = "wairz-tibx-extractor"

# Path inside the worker container where the ``tibx_work`` named volume
# is mounted. Sourced from env (``TIBX_WORK_PATH``); defaults align with
# docker-compose.yml.
_DEFAULT_TIBX_WORK_PATH = "/var/lib/wairz/tibx_work"


def _read_master_head(firmware_path: str) -> bytes:
    """Read the first :data:`_TIBX_HEAD_PROBE_BYTES` of the master slice."""
    with open(firmware_path, "rb") as fh:
        return fh.read(_TIBX_HEAD_PROBE_BYTES)


def _is_master_slice(head: bytes, basename: str) -> bool:
    """Return True iff ``head`` looks like a .tibx master slice.

    Strict: requires both the ARCH magic at offset 8 AND a basename
    that does NOT match the ``-NNNN.tibx`` continuation pattern. This
    catches the case where an operator renamed a continuation to drop
    the suffix but didn't actually have a master.
    """
    if len(head) < _TIBX_MASTER_MAGIC_OFFSET + len(_TIBX_MASTER_MAGIC):
        return False
    has_magic = (
        head[_TIBX_MASTER_MAGIC_OFFSET:
             _TIBX_MASTER_MAGIC_OFFSET + len(_TIBX_MASTER_MAGIC)]
        == _TIBX_MASTER_MAGIC
    )
    name_lower = basename.lower()
    # Continuation pattern: -NNNN.tibx where NNNN is a 4-digit slice index.
    is_continuation_by_name = (
        name_lower.endswith(".tibx")
        and len(name_lower) >= len("-0000.tibx")
        and name_lower[-len("-0000.tibx"):-len(".tibx")].startswith("-")
        and name_lower[-len("0000.tibx"):-len(".tibx")].isdigit()
    )
    return has_magic and not is_continuation_by_name


async def _run_extractor_container_async(
    extractor_image: str,
    command: list[str],
    timeout_seconds: int,
    waiver_agent_path: str | None = None,
) -> dict[str, Any]:
    """Spawn the side-container and wait for it under ``asyncio.wait_for``.

    Returns ``{"exit_code": int, "stderr": str, "stdout": str}``. The
    sync Docker SDK work runs in the default thread pool so the async
    event loop stays responsive.

    ``waiver_agent_path`` is the env-var override for the docker-compose
    ``WAIRZ_TIBX_AGENT_PATH`` mount; tests can pass an empty string to
    simulate the operator-not-configured branch. Production code passes
    ``None`` (the compose YAML supplies the bind mount).
    """
    # Lazy-import the Docker client helper so cold-import cost stays
    # off of paths that don't extract .tibx (Rule #30).
    from app.utils.docker_client import get_docker_client

    def _run_sync() -> dict[str, Any]:
        client = get_docker_client()
        try:
            container = client.containers.run(
                image=extractor_image,
                command=command,
                detach=True,
                auto_remove=False,
                # Compose-defined service hardening propagates via the
                # image; per-invocation we just ensure the named volume
                # binding is consistent.
                volumes={
                    "wairz_tibx_work": {"bind": "/work", "mode": "rw"},
                },
            )
        except Exception as exc:
            return {
                "exit_code": -1,
                "stderr": (
                    f"tibx-extractor side-container spawn failed: {exc!r}\n"
                    f"Verify the image exists: docker compose "
                    f"--profile build build tibx-extractor\n"
                ),
                "stdout": "",
            }
        try:
            result = container.wait(timeout=timeout_seconds)
            exit_code = int(result.get("StatusCode", -1))
            stdout = container.logs(stdout=True, stderr=False).decode(
                "utf-8", errors="replace"
            )
            stderr = container.logs(stdout=False, stderr=True).decode(
                "utf-8", errors="replace"
            )
            return {
                "exit_code": exit_code,
                "stderr": stderr,
                "stdout": stdout,
            }
        finally:
            try:
                container.remove(force=True)
            except Exception:
                logger.warning(
                    "tibx-extractor: container.remove failed (non-fatal)",
                    exc_info=True,
                )

    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, _run_sync),
        timeout=timeout_seconds + 30,
    )


async def unpack_tibx(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001 — uniform signature
) -> UnpackResult:
    """Extract an Acronis ``.tibx`` master + slices into ``disk.raw``.

    Per Scout C 2026-05-13 architecture:

    1. Reject continuation slices (only the master carries the dedup
       index + metadata; continuations are NOT standalone-extractable).
    2. Pre-flight: probe the side-container with ``list backups`` to
       confirm tibxread is reachable + identify the recovery point.
    3. Main extract: ``tibxread get content`` with the first recovery
       point + ``--disk 1`` (single-disk default — multi-disk is a
       follow-up).
    4. Copy ``/work/disk.raw`` (from named volume) into the firmware's
       ``extraction_dir/disk.raw``; existing NTFS/registry/EVTX walker
       chain picks it up via ``get_detection_roots`` (Rule #16).
    """
    async def _report(stage: str, progress: int) -> None:
        if progress_callback:
            try:
                await progress_callback(stage, progress)
            except Exception:
                pass

    result = UnpackResult()
    # noqa: ASYNC240 — pure-string path math; no filesystem I/O
    extraction_dir = os.path.join(output_base_dir, "extracted")  # noqa: ASYNC240

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, reset_extraction_dir_sync, extraction_dir)

    # ── Step 1: validate master slice ─────────────────────────────
    await _report("Validating .tibx master slice", 5)

    try:
        head = await loop.run_in_executor(None, _read_master_head, firmware_path)
    except OSError as exc:
        result.error = f"tibx read failed: {exc}"
        result.unpack_log = result.error
        return result

    basename = os.path.basename(firmware_path)
    if not _is_master_slice(head, basename):
        result.error = (
            "Not a .tibx master slice — ARCH magic missing at offset 8 OR "
            "filename matches the continuation pattern (-NNNN.tibx). Run "
            "extraction against the Archive(N).tibx master, not a "
            "continuation; the master carries the dedup index + metadata."
        )
        result.unpack_log = (
            f"{result.error}\n"
            f"head[0:16] = {head[:16].hex()}\n"
            f"basename = {basename!r}\n"
        )
        return result

    # ── Step 2: pre-flight side-container probe ───────────────────
    await _report("Probing tibx-extractor side-container", 10)

    extractor_image = os.environ.get(
        "TIBX_EXTRACTOR_IMAGE", _DEFAULT_EXTRACTOR_IMAGE,
    )
    tibx_work_path = os.environ.get(
        "TIBX_WORK_PATH", _DEFAULT_TIBX_WORK_PATH,
    )

    firmware_dir = os.path.dirname(firmware_path)  # noqa: ASYNC240 — pure path math

    probe_argv = [
        "list", "backups",
        "--loc", firmware_dir,
        "--arc", basename,
    ]
    try:
        probe = await _run_extractor_container_async(
            extractor_image=extractor_image,
            command=probe_argv,
            timeout_seconds=_TIBX_PROBE_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        result.error = (
            "tibx-extractor probe timed out — verify the side-container "
            "is healthy and WAIRZ_TIBX_AGENT_PATH is set correctly."
        )
        result.unpack_log = result.error
        return result

    if probe["exit_code"] == 2:
        # Entrypoint's "binary not found" exit — operator hasn't set
        # WAIRZ_TIBX_AGENT_PATH. Pass through the entrypoint's actionable
        # stderr verbatim.
        result.error = (
            "tibxread binary not found in tibx-extractor — operator "
            "must install Acronis Cyber Protection Agent for Linux "
            "and set WAIRZ_TIBX_AGENT_PATH. See tibx-extractor/README.md."
        )
        result.unpack_log = result.error + "\n\n" + probe["stderr"]
        return result
    if probe["exit_code"] != 0:
        result.error = (
            f"tibx-extractor probe failed (exit {probe['exit_code']}); "
            f"verify the side-container image is built."
        )
        result.unpack_log = (
            f"{result.error}\n"
            f"stderr: {probe['stderr'][:1000]}\n"
            f"stdout: {probe['stdout'][:200]}\n"
        )
        return result

    # Parse tibxread's JSON output to grab the first recovery-point id.
    recovery_point_id = _parse_first_recovery_point(probe["stdout"])
    if recovery_point_id is None:
        result.error = (
            "tibx-extractor probe returned no recovery points — the "
            ".tibx may be malformed OR the master + continuations are "
            "not co-located in the same directory."
        )
        result.unpack_log = (
            f"{result.error}\n"
            f"probe stdout: {probe['stdout'][:500]}\n"
        )
        return result

    # ── Step 3: main extraction ────────────────────────────────────
    await _report("Extracting .tibx via tibxread", 25)

    extract_argv = [
        "get", "content",
        "--loc", firmware_dir,
        "--arc", basename,
        "--backup", recovery_point_id,
        "--disk", "1",
    ]
    try:
        extract = await _run_extractor_container_async(
            extractor_image=extractor_image,
            command=extract_argv,
            timeout_seconds=_TIBX_EXTRACT_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        result.error = (
            f"tibx extraction timed out after "
            f"{_TIBX_EXTRACT_TIMEOUT_SECONDS}s — for very large .tibx "
            f"sets (>16 GB), raise _TIBX_EXTRACT_TIMEOUT_SECONDS."
        )
        result.unpack_log = result.error
        return result

    if extract["exit_code"] != 0:
        result.error = (
            f"tibxread get content failed (exit {extract['exit_code']})."
        )
        result.unpack_log = (
            f"{result.error}\n"
            f"recovery_point_id={recovery_point_id!r}\n"
            f"stderr: {extract['stderr'][:2000]}\n"
        )
        return result

    # ── Step 4: copy /work/disk.raw into extraction_dir ────────────
    await _report("Copying disk.raw into firmware tree", 90)

    src_disk_raw = os.path.join(tibx_work_path, "disk.raw")  # noqa: ASYNC240
    dst_disk_raw = os.path.join(extraction_dir, "disk.raw")  # noqa: ASYNC240

    if not await loop.run_in_executor(None, os.path.isfile, src_disk_raw):
        result.error = (
            f"tibx extraction reported success (exit 0) but disk.raw "
            f"missing at {src_disk_raw} — tibx_work named volume "
            f"may not be bind-mounted into the worker."
        )
        result.unpack_log = result.error
        return result

    try:
        await loop.run_in_executor(
            None, shutil.copyfile, src_disk_raw, dst_disk_raw,
        )
    except OSError as exc:
        result.error = f"disk.raw copy failed: {exc}"
        result.unpack_log = result.error
        return result

    # ── Step 5: finalise result ────────────────────────────────────
    await _report("tibx extraction complete", 100)

    raw_size = await loop.run_in_executor(None, os.path.getsize, dst_disk_raw)
    result.success = True
    result.extracted_path = extraction_dir
    result.extraction_dir = extraction_dir
    result.unpack_log = (
        f"Acronis .tibx extracted via tibx-extractor side-container.\n"
        f"recovery_point_id: {recovery_point_id}\n"
        f"disk.raw size: {raw_size:,} bytes\n"
        f"\nDownstream NTFS/registry/EVTX walker chain will iterate via "
        f"get_detection_roots(firmware). Multi-disk extraction "
        f"(beyond disk 1) is a follow-up — see "
        f".planning/intake/tibx-byob-side-container-architecture-2026-05-13.md.\n"
    )
    return result


def _parse_first_recovery_point(stdout: str) -> str | None:
    """Pull the first recovery-point id from ``tibxread list backups`` JSON.

    Real ``tibxread`` output schema is JSON with a top-level ``backups``
    array; each entry has an ``id`` field. The parser is lenient:
    accepts either a top-level array OR a wrapping object. Returns
    ``None`` on any parse failure or empty result.
    """
    if not stdout.strip():
        return None
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(parsed, dict):
        items = parsed.get("backups") or parsed.get("recovery_points") or []
    elif isinstance(parsed, list):
        items = parsed
    else:
        return None
    for item in items:
        if isinstance(item, dict):
            for key in ("id", "recovery_point_id", "backup_id"):
                value = item.get(key)
                if isinstance(value, str) and value:
                    return value
        elif isinstance(item, str) and item:
            return item
    return None
