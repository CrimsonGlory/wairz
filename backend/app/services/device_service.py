"""Service for Android device acquisition via the wairz-device-bridge.

Proxies commands to the host-side bridge over TCP (same pattern as uart_service.py)
and persists per-dump state in the ``device_dump_sessions`` table.

The previous module-level ``_dump_state`` global was replaced (audit-2026-05-04
finding F-A-01) with a per-row ``DeviceDumpSession`` so concurrent dump callers
get their own state and the row survives backend restarts. Standard Rule #33
202+polling shape — the foreground POST returns 202 with a fresh dump_id; the
background ``_run_dump_background`` task uses its own ``async_session_factory()``
session per CLAUDE.md Rule #33d (in-process work, DB-persisted, no worker-only
resources).
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import async_session_factory
from app.models.device_dump import DeviceDumpSession
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.jsonb_normalizers import _stamp_firmware_device_metadata
from app.utils.getprop import extract_device_metadata, parse_getprop_txt
from app.workers.unpack import unpack_firmware

logger = logging.getLogger(__name__)


# Shared dump directory — bind-mounted between host and container so the
# bridge (host-side) can write partition images and the backend (container)
# can read them for import.
DUMP_SHARED_DIR = "/tmp/wairz-dumps"

# JSONB schema_version for the ``partitions`` and ``result`` columns
# (Rule #35c). Bump only on a backwards-incompatible shape change AND
# add a ``_normalize_partitions`` boundary helper for the legacy reader.
DUMP_PARTITIONS_SCHEMA_VERSION = 1
DUMP_RESULT_SCHEMA_VERSION = 1


def _new_partition_state(partition: str) -> dict:
    return {"partition": partition, "status": "pending", "bytes_written": 0}


def _build_partitions_payload(partitions: list[str]) -> dict:
    return {
        "schema_version": DUMP_PARTITIONS_SCHEMA_VERSION,
        "items": [_new_partition_state(p) for p in partitions],
    }


def _normalize_partitions(value: dict | list | None) -> list[dict]:
    """Boundary normaliser per Rule #35c.

    Accepts the canonical wrapped shape (``{schema_version, items}``), a
    bare list (forward-compat with any older callers that may have stored
    a list directly), or ``None``. Returns the per-partition list — what
    the API and the dump runner consume.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        items = value.get("items")
        if isinstance(items, list):
            return items
    return []


class DeviceService:
    """Manages device acquisition and communicates with the host-side bridge."""

    DUMP_SHARED_DIR = DUMP_SHARED_DIR  # backwards-compat for callers reading the constant

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # ── Public API ──

    async def get_bridge_status(self) -> dict:
        """Check if the device bridge is reachable."""
        settings = get_settings()
        try:
            await self._bridge_request({"command": "list_devices"})
            return {
                "connected": True,
                "bridge_host": settings.device_bridge_host,
                "bridge_port": settings.device_bridge_port,
                "error": None,
            }
        except ConnectionError as e:
            return {
                "connected": False,
                "bridge_host": settings.device_bridge_host,
                "bridge_port": settings.device_bridge_port,
                "error": str(e),
            }

    async def list_devices(self) -> list[dict]:
        """List connected ADB devices via the bridge."""
        result = await self._bridge_request({"command": "list_devices"})
        return result.get("devices", [])

    async def get_device_info(self, device_id: str) -> dict:
        """Get device details including getprop and partition list."""
        result = await self._bridge_request({
            "command": "get_device_info",
            "device_id": device_id,
        })

        # Parse getprop and extract structured metadata.
        getprop_raw = result.get("getprop", "")
        props = parse_getprop_txt(getprop_raw)
        metadata = extract_device_metadata(props)

        return {
            "getprop": props,
            "partitions": result.get("partitions", []),
            "partition_sizes": result.get("partition_sizes", []),
            "device_metadata": metadata,
            # Pass the BROM chipset (e.g. "MT6765") through to the
            # response. Bridge sets this from `mtk printgpt` output;
            # None for ADB devices.
            "chipset": result.get("chipset"),
        }

    async def find_active_dump(
        self, project_id: uuid.UUID
    ) -> DeviceDumpSession | None:
        """Return the in-flight dump for ``project_id`` if any (queued or
        running), otherwise None. Used by the router to enforce the
        Rule #33a idempotent-POST + 409 contract.
        """
        result = await self._db.execute(
            select(DeviceDumpSession)
            .where(DeviceDumpSession.project_id == project_id)
            .where(DeviceDumpSession.status.in_(("queued", "running")))
            .order_by(DeviceDumpSession.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def start_dump(
        self,
        project_id: uuid.UUID,
        device_id: str,
        partitions: list[str],
    ) -> DeviceDumpSession:
        """Create a new ``DeviceDumpSession`` row and spawn the background
        runner. Caller (router) is responsible for the Rule #33a 409 check.

        Returns the freshly-committed row with status=queued.
        """
        dump_id = uuid.uuid4()
        dump_dir = os.path.join(DUMP_SHARED_DIR, str(dump_id))
        os.makedirs(dump_dir, exist_ok=True)

        # Check disk space on the shared mount.
        disk_usage = shutil.disk_usage(DUMP_SHARED_DIR)
        free_gb = disk_usage.free / (1024**3)
        if free_gb < 5:
            raise ValueError(
                f"Insufficient disk space: {free_gb:.1f}GB free, "
                f"need at least 5GB for device dumps"
            )

        row = DeviceDumpSession(
            id=dump_id,
            project_id=project_id,
            device_id=device_id,
            status="queued",
            dump_dir=dump_dir,
            partitions=_build_partitions_payload(partitions),
        )
        self._db.add(row)
        # Commit so the background task's fresh session sees the row
        # immediately (Rule #33 reference shape).
        await self._db.commit()

        asyncio.create_task(
            _run_dump_background(dump_id, device_id, list(partitions), dump_dir)
        )

        return row

    async def get_dump(
        self, project_id: uuid.UUID, dump_id: uuid.UUID
    ) -> DeviceDumpSession | None:
        """Look up a dump row by id, scoped to ``project_id``. Returns None if
        the row is missing or belongs to a different project.
        """
        result = await self._db.execute(
            select(DeviceDumpSession).where(DeviceDumpSession.id == dump_id)
        )
        row = result.scalar_one_or_none()
        if row is None or row.project_id != project_id:
            return None
        return row

    async def cancel_dump(
        self, project_id: uuid.UUID, dump_id: uuid.UUID
    ) -> DeviceDumpSession | None:
        """Mark a dump as cancelled. Idempotent — calling on a terminal-state
        dump returns the row unchanged.
        """
        row = await self.get_dump(project_id, dump_id)
        if row is None:
            return None

        if row.status in ("queued", "running"):
            try:
                await self._bridge_request({"command": "cancel_dump"})
            except ConnectionError:
                # Best-effort; the background task's bridge call will
                # surface the cancellation either way.
                pass
            row.status = "cancelled"
            row.finished_at = datetime.now(timezone.utc)
            await self._db.commit()
        return row

    async def import_dump(
        self,
        project_id: uuid.UUID,
        dump_id: uuid.UUID,
        device_id: str,
        version_label: str | None = None,
    ) -> Firmware:
        """Import a completed dump as firmware into the project.

        ``dump_id`` identifies which DeviceDumpSession row to consume; the row
        must be in a terminal state with at least one completed partition.
        """
        dump = await self.get_dump(project_id, dump_id)
        if dump is None:
            raise ValueError(f"Dump {dump_id} not found for project {project_id}")
        if dump.status not in ("completed", "partial"):
            raise ValueError(f"Dump is {dump.status}, cannot import")

        items = _normalize_partitions(dump.partitions)
        completed_partitions = [p["partition"] for p in items if p.get("status") == "complete"]

        # Find all completed partition images on disk.
        img_files = sorted(Path(dump.dump_dir).glob("*.img"))
        if not img_files:
            raise ValueError("No partition images found in dump directory")

        # Get device info for metadata.
        try:
            device_info = await self.get_device_info(device_id)
            device_metadata = device_info.get("device_metadata", {})
        except ConnectionError:
            device_metadata = {}

        # Add acquisition metadata.
        device_metadata["acquisition_method"] = "adb_root"
        device_metadata["partition_list"] = completed_partitions
        device_metadata["source_partitions"] = {
            f.stem: f.name for f in img_files
        }
        device_metadata["dump_id"] = str(dump_id)

        # Compute SHA256 of first (or only) image for firmware record.
        first_img = img_files[0]
        sha256 = hashlib.sha256()
        with open(first_img, "rb") as f:
            for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
                sha256.update(chunk)

        total_size = sum(f.stat().st_size for f in img_files)

        firmware = Firmware(
            project_id=project_id,
            original_filename=f"device-dump-{device_id}",
            sha256=sha256.hexdigest(),
            file_size=total_size,
            storage_path=str(first_img),
            extraction_dir=dump.dump_dir,
            version_label=version_label or f"Device dump ({device_id})",
            device_metadata=_stamp_firmware_device_metadata(device_metadata),
        )
        self._db.add(firmware)
        await self._db.flush()

        # Record the import linkage on the dump row.
        dump.result = {
            "schema_version": DUMP_RESULT_SCHEMA_VERSION,
            "imported_firmware_id": str(firmware.id),
            "imported_at": datetime.now(timezone.utc).isoformat(),
        }
        await self._db.flush()

        asyncio.create_task(
            _run_import_unpack(project_id, firmware.id, str(first_img), dump.dump_dir)
        )

        return firmware

    # ── Internal helpers ──

    async def _bridge_request(self, request: dict) -> dict:
        """Send a JSON request to the bridge and return the response."""
        return await _bridge_request_oneshot(request)


async def _bridge_request_oneshot(request: dict) -> dict:
    """Send a JSON request to the bridge and return the response."""
    settings = get_settings()
    host = settings.device_bridge_host
    port = settings.device_bridge_port

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=5,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise ConnectionError(
            f"Cannot reach device bridge at {host}:{port}. "
            f"Is wairz-device-bridge.py running on the host? Error: {exc}"
        ) from exc

    try:
        if "id" not in request:
            request["id"] = str(uuid.uuid4())

        payload = json.dumps(request) + "\n"
        writer.write(payload.encode("utf-8"))
        await writer.drain()

        line = await asyncio.wait_for(reader.readline(), timeout=60)
        if not line:
            raise ConnectionError("Bridge closed connection without response")

        response = json.loads(line.decode("utf-8"))
        if not response.get("ok"):
            raise ValueError(response.get("error", "Unknown bridge error"))

        return response
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _bridge_request_streaming(request: dict, progress_callback=None) -> dict:
    """Send a request and read multiple lines (progress events + final result)."""
    settings = get_settings()
    host = settings.device_bridge_host
    port = settings.device_bridge_port

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=5,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise ConnectionError(
            f"Cannot reach device bridge at {host}:{port}. Error: {exc}"
        ) from exc

    try:
        if "id" not in request:
            request["id"] = str(uuid.uuid4())

        payload = json.dumps(request) + "\n"
        writer.write(payload.encode("utf-8"))
        await writer.drain()

        # Read lines until we get a final status (complete, error, cancelled).
        while True:
            line = await asyncio.wait_for(
                reader.readline(),
                timeout=1860,  # 31 min (30 min partition timeout + margin)
            )
            if not line:
                raise ConnectionError("Bridge closed connection")

            response = json.loads(line.decode("utf-8"))

            if response.get("event") == "progress":
                if progress_callback:
                    progress_callback(response)
                continue

            return response
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _persist_partitions(
    db: AsyncSession, dump_id: uuid.UUID, items: list[dict]
) -> None:
    """Write the in-flight ``items`` list back to the dump row's
    ``partitions`` JSONB. Wraps in the canonical schema_version envelope.
    """
    row = (
        await db.execute(
            select(DeviceDumpSession).where(DeviceDumpSession.id == dump_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return
    row.partitions = {
        "schema_version": DUMP_PARTITIONS_SCHEMA_VERSION,
        "items": items,
    }
    row.bytes_written = sum(int(p.get("bytes_written", 0) or 0) for p in items)
    await db.commit()


async def _run_dump_background(
    dump_id: uuid.UUID,
    device_id: str,
    partitions: list[str],
    dump_dir: str,
) -> None:
    """Run partition dumps sequentially. Owns its own ``AsyncSession`` per
    Rule #33d reference shape; outer guard catches any unexpected exception.
    """
    try:
        async with async_session_factory() as db:
            row = (
                await db.execute(
                    select(DeviceDumpSession).where(DeviceDumpSession.id == dump_id)
                )
            ).scalar_one_or_none()
            if row is None:
                logger.error("Background dump: row %s not found", dump_id)
                return

            # Defensive: if the row was cancelled between commit and task
            # pickup, bail without touching status.
            if row.status not in ("queued", "running"):
                logger.info(
                    "Dump %s already in terminal state %s — runner exiting",
                    dump_id, row.status,
                )
                return

            row.status = "running"
            row.started_at = datetime.now(timezone.utc)
            items = _normalize_partitions(row.partitions)
            await db.commit()

            try:
                completed = 0
                failed = 0

                for i, partition in enumerate(partitions):
                    items[i]["status"] = "active"
                    await _persist_partitions(db, dump_id, items)

                    try:
                        result = await _bridge_request_streaming(
                            {
                                "command": "dump_partition",
                                "device_id": device_id,
                                "partition": partition,
                                "output_dir": dump_dir,
                            },
                            progress_callback=lambda ev, idx=i: _apply_progress_event(
                                items, idx, ev
                            ),
                        )

                        if result.get("status") == "complete":
                            p = items[i]
                            p["status"] = "complete"
                            p["bytes_written"] = int(result.get("size", 0) or 0)
                            p["size"] = result.get("size", 0)
                            p["path"] = result.get("path")
                            if "total_bytes" in result:
                                p["total_bytes"] = result["total_bytes"]
                            completed += 1
                        else:
                            items[i]["status"] = "failed"
                            items[i]["error"] = result.get("error", "Unknown")
                            failed += 1
                    except Exception as e:
                        items[i]["status"] = "failed"
                        items[i]["error"] = str(e)
                        failed += 1
                        logger.warning(
                            "Dump of %s failed: %s", partition, e, exc_info=True
                        )

                    await _persist_partitions(db, dump_id, items)

                if failed == 0:
                    final_status = "completed"
                elif completed > 0:
                    final_status = "partial"
                else:
                    final_status = "failed"

                row = (
                    await db.execute(
                        select(DeviceDumpSession).where(
                            DeviceDumpSession.id == dump_id
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return
                # Honour an externally-set cancelled state; only flip if
                # we're still in the running tier.
                if row.status == "running":
                    row.status = final_status
                row.finished_at = datetime.now(timezone.utc)
                row.bytes_written = sum(
                    int(p.get("bytes_written", 0) or 0) for p in items
                )
                await db.commit()
            except Exception as exc:
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(DeviceDumpSession).where(
                                DeviceDumpSession.id == dump_id
                            )
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None and fail_row.status not in (
                        "completed", "partial", "failed", "cancelled",
                    ):
                        fail_row.status = "failed"
                        fail_row.error = err
                        fail_row.finished_at = datetime.now(timezone.utc)
                        await fail_db.commit()
                logger.exception("Background dump %s failed", dump_id)
    except Exception:
        logger.exception("Unrecoverable background dump error for %s", dump_id)


def _apply_progress_event(items: list[dict], index: int, event: dict) -> None:
    """Update progress for a partition from a bridge progress event.

    Mutates ``items`` in place; the caller is responsible for persisting on
    the next DB write tick.
    """
    if event.get("event") != "progress":
        return
    p = items[index]
    p["bytes_written"] = int(event.get("bytes_written", 0) or 0)
    if "total_bytes" in event:
        p["total_bytes"] = event["total_bytes"]
    if "progress_percent" in event:
        p["progress_percent"] = event["progress_percent"]
    if "throughput_mbps" in event:
        p["throughput_mbps"] = event["throughput_mbps"]


async def _run_import_unpack(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    storage_path: str,
    output_base: str,
) -> None:
    """Run unpack pipeline in background after import."""
    try:
        result = await unpack_firmware(storage_path, output_base, firmware_id=firmware_id)

        async with async_session_factory() as db:
            try:
                proj_result = await db.execute(
                    select(Project).where(Project.id == project_id)
                )
                project = proj_result.scalar_one_or_none()
                fw_result = await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
                firmware = fw_result.scalar_one_or_none()

                if not project or not firmware:
                    logger.error("Import unpack: project or firmware not found")
                    return

                if result.success:
                    firmware.extracted_path = result.extracted_path
                    firmware.extraction_dir = result.extraction_dir
                    firmware.architecture = result.architecture
                    firmware.endianness = result.endianness
                    firmware.os_info = result.os_info
                    firmware.kernel_path = result.kernel_path
                    firmware.binary_info = result.binary_info
                    firmware.unpack_log = result.unpack_log
                    project.status = "ready"
                else:
                    firmware.unpack_log = result.unpack_log
                    project.status = "error"

                await db.commit()
            except Exception:
                await db.rollback()
                raise
    except Exception:
        logger.exception("Import unpack failed for firmware %s", firmware_id)
