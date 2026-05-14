"""Windows injection walker (Phase λ.γ — memory-forensic-godmode).

Third Vol3-backed walker. Invokes Volatility 3's
``windows.malware.malfind`` / ``windows.malware.hollowprocesses`` /
``windows.malware.ldrmodules`` / ``windows.malware.processghosting`` /
``windows.malware.pebmasquerade`` plugin family against every
``memory_dump_image`` row whose ``os_family`` is ``"windows"`` OR
``"unknown"`` for a given firmware. Surfaces five high-fidelity
injection / hollowing / hiding indicators as
``VolatilityInjectionRecord`` rows.

**Hard 2026-06-07 deprecation deadline** — Vol3 has flagged the
deprecated top-level paths (``hollowprocesses``, ``malfind``,
``ldrmodules``, ``processghosting``, ``psxview``) for removal at
that date. The walker wires EXCLUSIVELY to the canonical
``windows.malware.<X>`` paths. The test gate at
``test_windows_injection_walker.py::test_plugins_pinned_to_windows_malware_namespace``
enforces this at commit time; a separate test gate scans the walker
source for any mention of the deprecated top-level path shapes.

**Rule #44 cross-firmware identity key** — every ``injected_code_region``
detection emits a ``hexdump_sha256`` over the canonicalised first 64
bytes of malfind's hexdump. The same injection appearing across
multiple firmware images hashes to the same value. The
``lookup_volatility_injection_across_firmwares`` MCP tool (λ.γ.C)
joins on this column.

The walker is a CLAUDE.md Rule #39 inner/outer/safe triplet:

- :func:`_do_windows_injection_walk` — INNER pure-logic orchestrator.
  Caller owns ``db`` + the transaction. Resolves detection roots via
  :func:`app.services.firmware_paths.get_detection_roots` (Rule #16).
  Iterates ``MemoryDumpImage`` rows, invokes
  :func:`app.services.vol3_runner.run_vol3_plugin` per (image, plugin)
  combination, parses per-plugin records into
  ``VolatilityInjectionRecord`` rows, returns aggregate UNSTAMPED.
- :func:`run_windows_injection_walk_background` — OUTER state-machine
  wrapper. Owns its own session via ``async_session_factory``,
  transitions ``firmware.windows_injection_walk_status`` through
  ``idle → running → completed | failed``.
- :func:`auto_windows_injection_walk_firmware_safe` — UNPACK-POST-
  DETECTION hook. Fire-and-forget; swallows all exceptions; leaves
  status at ``idle`` so operator re-trigger works without 409
  conflict (Rule #33 .a).

Per CLAUDE.md Rule #36 / #45 discipline: every plugin invocation goes
through ``vol3_runner.run_vol3_plugin``; the walker MUST NOT construct
its own argv. The plugin name list :data:`_PLUGINS_TO_RUN` is HARD-
PINNED to the ``windows.malware.<X>`` namespace and is NOT operator-
configurable through any caller path. The vol3_runner boundary also
enforces the credential-extraction deny-list (hashdump/lsadump/etc.
ARE NOT in this walker's plugin list, but the deny-list applies
universally to any vol3_runner caller).

Per CLAUDE.md Rule #45 / #46: PARSE-ONLY surface. The walker NEVER
deobfuscates injected code, NEVER attempts to repair / rebuild a
hollowed process image, NEVER patches a memory region via Vol3's
optional read-write layer (the runner pins ``--offline`` and reads
only). The Rule #46 canary at
``test_windows_injection_walker.py::test_walker_source_scan_gate_canary_fires``
confirms the no-decrypt gate fires on synthetic violations.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import logging
import re
import time
import traceback
import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.memory_dump_image import MemoryDumpImage
from app.models.volatility_injection_record import VolatilityInjectionRecord
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_windows_injection_walk_result,
    _stamp_volatility_injection_records_evidence,
)
from app.services.vol3_runner import (
    Vol3InvocationFailed,
    Vol3NotInstalled,
    Vol3PluginForbidden,
    Vol3Timeout,
    run_vol3_plugin,
)

logger = logging.getLogger(__name__)


_WALK_OS_FAMILIES: frozenset[str] = frozenset({"windows", "unknown"})


# HARD-PINNED plugin list. The walker invokes EXCLUSIVELY the
# ``windows.malware.<X>`` namespace. The DEPRECATED top-level path
# shapes (bare ``hollowprocesses``, ``malfind``, ``ldrmodules``,
# ``processghosting``, ``psxview`` directly under the windows.*
# package) MUST NOT appear anywhere in this module — a separate test
# gate scans the source for them. 2026-06-07 deprecation deadline.
_PLUGINS_TO_RUN: tuple[str, ...] = (
    "windows.malware.malfind.Malfind",
    "windows.malware.hollowprocesses.HollowProcesses",
    "windows.malware.ldrmodules.LdrModules",
    "windows.malware.processghosting.ProcessGhosting",
    "windows.malware.pebmasquerade.PEBMasquerade",
)


# Mapping from plugin → detection_kind value persisted on the per-row
# ``detection_kind`` column.
_PLUGIN_TO_KIND: dict[str, str] = {
    "windows.malware.malfind.Malfind": "injected_code_region",
    "windows.malware.hollowprocesses.HollowProcesses": "hollow_process",
    "windows.malware.ldrmodules.LdrModules": "unlinked_module",
    "windows.malware.processghosting.ProcessGhosting": "ghosted_process",
    "windows.malware.pebmasquerade.PEBMasquerade": "peb_masquerade",
}


def _empty_aggregate() -> dict:
    return {
        "image_count": 0,
        "detection_count": 0,
        "by_kind": {
            "injected_code_region": 0,
            "hollow_process": 0,
            "unlinked_module": 0,
            "peb_masquerade": 0,
            "ghosted_process": 0,
        },
        "unique_hexdump_sha256_count": 0,
        "total_elapsed_s": 0.0,
        "errors_per_image": [],
    }


# ── Hexdump canonicalisation ────────────────────────────────────────────────


_HEX_PAIR_RE = re.compile(r"\b([0-9a-fA-F]{2})\b")


def _canonicalise_hexdump_first_64(hexdump_raw: str | None) -> str | None:
    """Extract the first 64 bytes of malfind's Hexdump and canonicalise.

    Vol3's malfind Hexdump field emits the canonical xxd-style
    "OFFSET  HEX-PAIRS  ASCII" form, e.g.::

        00000000 fc e8 82 00 00 00 60 89  e5 31 c0 64 8b 50 30 8b
        00000010 52 0c 8b 52 14 8b 72 28  0f b7 4a 26 31 ff ac 3c

    This helper parses out the hex pairs (regex-tolerant of the row
    headers + ASCII trailer), takes the first 64, and joins as
    space-separated lower-case hex. The result is BOTH human-grep-able
    AND the canonical input to SHA256 for cross-firmware lookup.
    """
    if not hexdump_raw:
        return None
    pairs = [m.group(1).lower() for m in _HEX_PAIR_RE.finditer(hexdump_raw)]
    if not pairs:
        return None
    truncated = pairs[:64]
    return " ".join(truncated)


def _hexdump_sha256(canonical_hex: str | None) -> str | None:
    """Return the SHA256 of the canonicalised hexdump (lower-case hex)."""
    if not canonical_hex:
        return None
    return hashlib.sha256(canonical_hex.encode("ascii")).hexdigest()


# ── Per-field coercion helpers ──────────────────────────────────────────────


def _int_or_none(raw: Any) -> int | None:
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s or s.lower() in {"n/a", "none", "null", "-"}:
            return None
        try:
            return int(s, 0)
        except ValueError:
            return None
    return None


def _str_or_none(raw: Any, cap: int = 1024) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    return s[:cap]


# ── Per-plugin record extractors ────────────────────────────────────────────


def _extract_malfind_record(
    rec: dict[str, Any],
    firmware_id: uuid.UUID,
    image_id: uuid.UUID,
) -> VolatilityInjectionRecord | None:
    """Convert a windows.malware.malfind record into a persisted row."""
    pid = _int_or_none(rec.get("PID"))
    name = _str_or_none(rec.get("Process") or rec.get("ImageFileName"), 256)
    if pid is None or not name:
        return None

    hexdump_raw = rec.get("Hexdump") or rec.get("Hex")
    canonical = _canonicalise_hexdump_first_64(
        hexdump_raw if isinstance(hexdump_raw, str) else None
    )
    sha = _hexdump_sha256(canonical)

    protection = _str_or_none(
        rec.get("Protection") or rec.get("PageProtection"), 32
    )
    start_vpn = _int_or_none(rec.get("Start VPN") or rec.get("StartVPN"))
    end_vpn = _int_or_none(rec.get("End VPN") or rec.get("EndVPN"))
    region_size: int | None = None
    if start_vpn is not None and end_vpn is not None and end_vpn >= start_vpn:
        # End VPN is exclusive in Vol3's convention; +1 page (4096) for
        # the inclusive byte size. The exact page math doesn't matter
        # for forensic surface — we want a magnitude reference.
        region_size = (end_vpn - start_vpn + 1) * 4096

    evidence = _stamp_volatility_injection_records_evidence(
        {
            "kind": "injected_code_region",
            "vad_tag": _str_or_none(rec.get("Tag"), 32),
            "commit_charge": _int_or_none(rec.get("CommitCharge")),
            "private_memory": bool(rec.get("PrivateMemory"))
            if rec.get("PrivateMemory") is not None
            else None,
            "protection": protection,
            "disasm_first_line": _str_or_none(rec.get("Disasm"), 512),
            "hexdump_truncated": (
                _str_or_none(hexdump_raw, 2048) if hexdump_raw else None
            ),
        }
    )

    return VolatilityInjectionRecord(
        firmware_id=firmware_id,
        memory_image_id=image_id,
        detection_kind="injected_code_region",
        detected_by_plugin="windows.malware.malfind.Malfind",
        pid=pid,
        image_filename=name[:256],
        region_address=start_vpn,
        region_size=region_size,
        region_protection=protection,
        hexdump_first_64_bytes=canonical,
        hexdump_sha256=sha,
        evidence=evidence,
    )


def _extract_hollowprocesses_record(
    rec: dict[str, Any],
    firmware_id: uuid.UUID,
    image_id: uuid.UUID,
) -> VolatilityInjectionRecord | None:
    pid = _int_or_none(rec.get("PID"))
    name = _str_or_none(rec.get("Process") or rec.get("ImageFileName"), 256)
    if pid is None or not name:
        return None

    peb_path = _str_or_none(
        rec.get("PEB ImagePathName")
        or rec.get("PEBImagePathName")
        or rec.get("PEB_PATH"),
        1024,
    )
    actual_path = _str_or_none(
        rec.get("EPROCESS ImageFileName")
        or rec.get("EPROCESSImageFileName")
        or rec.get("EPROCESS_PATH"),
        1024,
    )
    reason = _str_or_none(
        rec.get("Notes") or rec.get("Reason"), 1024
    )

    evidence = _stamp_volatility_injection_records_evidence(
        {
            "kind": "hollow_process",
            "peb_image_path": peb_path,
            "eprocess_image_path": actual_path,
            "divergence_reason": reason,
        }
    )

    return VolatilityInjectionRecord(
        firmware_id=firmware_id,
        memory_image_id=image_id,
        detection_kind="hollow_process",
        detected_by_plugin="windows.malware.hollowprocesses.HollowProcesses",
        pid=pid,
        image_filename=name[:256],
        masquerade_path=peb_path,
        actual_path=actual_path,
        evidence=evidence,
    )


def _extract_ldrmodules_record(
    rec: dict[str, Any],
    firmware_id: uuid.UUID,
    image_id: uuid.UUID,
) -> VolatilityInjectionRecord | None:
    """Convert a windows.malware.ldrmodules record. Only emit a row when
    at least one list reports False (a fully-linked module is benign)."""
    pid = _int_or_none(rec.get("Pid") or rec.get("PID"))
    name = _str_or_none(rec.get("Process") or rec.get("ImageFileName"), 256)
    if pid is None or not name:
        return None

    in_load = rec.get("InLoad")
    in_init = rec.get("InInit")
    in_mem = rec.get("InMem")
    # Skip benign rows where the module is present everywhere.
    if bool(in_load) and bool(in_init) and bool(in_mem):
        return None

    missing: list[str] = []
    if not bool(in_load):
        missing.append("InLoad")
    if not bool(in_init):
        missing.append("InInit")
    if not bool(in_mem):
        missing.append("InMem")

    module = _str_or_none(
        rec.get("MappedPath") or rec.get("Path") or rec.get("Module"), 256
    )
    base = _int_or_none(rec.get("Base") or rec.get("BaseAddress"))
    size = _int_or_none(rec.get("Size"))

    evidence = _stamp_volatility_injection_records_evidence(
        {
            "kind": "unlinked_module",
            "in_load_order": bool(in_load),
            "in_init_order": bool(in_init),
            "in_mem_order": bool(in_mem),
            "missing_from_lists": missing,
            "base_address": base,
            "module_size": size,
        }
    )

    return VolatilityInjectionRecord(
        firmware_id=firmware_id,
        memory_image_id=image_id,
        detection_kind="unlinked_module",
        detected_by_plugin="windows.malware.ldrmodules.LdrModules",
        pid=pid,
        image_filename=name[:256],
        module_name=module,
        region_address=base,
        region_size=size,
        evidence=evidence,
    )


def _extract_processghosting_record(
    rec: dict[str, Any],
    firmware_id: uuid.UUID,
    image_id: uuid.UUID,
) -> VolatilityInjectionRecord | None:
    pid = _int_or_none(rec.get("PID"))
    name = _str_or_none(rec.get("Process") or rec.get("ImageFileName"), 256)
    if pid is None or not name:
        return None

    ghosted = _str_or_none(
        rec.get("FILE_OBJECT path")
        or rec.get("FilePath")
        or rec.get("ImagePath"),
        1024,
    )
    reason = _str_or_none(
        rec.get("Reason") or rec.get("Status"), 1024
    )

    evidence = _stamp_volatility_injection_records_evidence(
        {
            "kind": "ghosted_process",
            "ghosted_path": ghosted,
            "deletion_reason": reason,
        }
    )

    return VolatilityInjectionRecord(
        firmware_id=firmware_id,
        memory_image_id=image_id,
        detection_kind="ghosted_process",
        detected_by_plugin="windows.malware.processghosting.ProcessGhosting",
        pid=pid,
        image_filename=name[:256],
        ghosted_path=ghosted,
        evidence=evidence,
    )


def _extract_pebmasquerade_record(
    rec: dict[str, Any],
    firmware_id: uuid.UUID,
    image_id: uuid.UUID,
) -> VolatilityInjectionRecord | None:
    pid = _int_or_none(rec.get("PID"))
    name = _str_or_none(rec.get("Process") or rec.get("ImageFileName"), 256)
    if pid is None or not name:
        return None

    peb_path = _str_or_none(
        rec.get("PEB ImagePathName")
        or rec.get("PEBImagePathName"),
        1024,
    )
    eprocess_name = _str_or_none(
        rec.get("EPROCESS ImageFileName")
        or rec.get("EPROCESSImageFileName"),
        256,
    )
    base = _int_or_none(rec.get("Image Base Address") or rec.get("ImageBaseAddress"))

    evidence = _stamp_volatility_injection_records_evidence(
        {
            "kind": "peb_masquerade",
            "peb_image_path_name": peb_path,
            "eprocess_image_file_name": eprocess_name,
            "image_base_address": base,
        }
    )

    return VolatilityInjectionRecord(
        firmware_id=firmware_id,
        memory_image_id=image_id,
        detection_kind="peb_masquerade",
        detected_by_plugin="windows.malware.pebmasquerade.PEBMasquerade",
        pid=pid,
        image_filename=name[:256],
        masquerade_path=peb_path,
        actual_path=eprocess_name,
        region_address=base,
        evidence=evidence,
    )


_EXTRACTORS = {
    "windows.malware.malfind.Malfind": _extract_malfind_record,
    "windows.malware.hollowprocesses.HollowProcesses": (
        _extract_hollowprocesses_record
    ),
    "windows.malware.ldrmodules.LdrModules": _extract_ldrmodules_record,
    "windows.malware.processghosting.ProcessGhosting": (
        _extract_processghosting_record
    ),
    "windows.malware.pebmasquerade.PEBMasquerade": _extract_pebmasquerade_record,
}


# ── Per-image driver ────────────────────────────────────────────────────────


async def _walk_one_image(
    db: AsyncSession,
    image: MemoryDumpImage,
    aggregate: dict[str, Any],
    hexdump_sha256s: set[str],
) -> tuple[int, float, list[str]]:
    """Run all 5 plugins against ONE image and persist records.

    Returns ``(rows_persisted, elapsed_s_total, per_image_errors)``.
    """
    total_elapsed: float = 0.0
    per_image_errors: list[str] = []
    persisted = 0

    # DELETE-then-INSERT semantics — replace any pre-existing rows for
    # this image (re-run dedup).
    await db.execute(
        delete(VolatilityInjectionRecord).where(
            VolatilityInjectionRecord.memory_image_id == image.id
        )
    )

    for plugin in _PLUGINS_TO_RUN:
        try:
            result = await run_vol3_plugin(image.image_path, plugin)
        except Vol3PluginForbidden:
            raise
        except Vol3NotInstalled:
            raise
        except (Vol3Timeout, Vol3InvocationFailed) as exc:
            msg = f"{image.image_filename}/{plugin}: {type(exc).__name__}: {exc}"[:512]
            logger.warning("windows_injection_walk: %s", msg)
            per_image_errors.append(msg)
            continue

        total_elapsed += result.elapsed_s
        kind = _PLUGIN_TO_KIND[plugin]
        extractor = _EXTRACTORS[plugin]

        for rec in result.records:
            row = extractor(rec, image.firmware_id, image.id)
            if row is None:
                continue
            db.add(row)
            persisted += 1
            aggregate["by_kind"][kind] += 1
            if row.hexdump_sha256:
                hexdump_sha256s.add(row.hexdump_sha256)

    image.last_walked_at = _dt.datetime.now(_dt.UTC)
    return (persisted, total_elapsed, per_image_errors)


# ── Inner orchestrator ──────────────────────────────────────────────────────


async def _do_windows_injection_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict:
    """INNER orchestrator — run the 5-plugin malware family on every Windows image."""
    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        logger.warning(
            "windows_injection_walk: firmware %s vanished pre-walk", firmware_id
        )
        return _empty_aggregate()

    aggregate = _empty_aggregate()
    t0 = time.monotonic()

    detection_roots = await get_detection_roots(firmware, db=db, use_cache=True)
    if not detection_roots:
        aggregate["total_elapsed_s"] = round(time.monotonic() - t0, 3)
        return aggregate

    images = (
        (
            await db.execute(
                select(MemoryDumpImage)
                .where(MemoryDumpImage.firmware_id == firmware_id)
                .where(MemoryDumpImage.os_family.in_(_WALK_OS_FAMILIES))
            )
        )
        .scalars()
        .all()
    )
    if not images:
        aggregate["total_elapsed_s"] = round(time.monotonic() - t0, 3)
        return aggregate

    hexdump_sha256s: set[str] = set()
    for image in images:
        try:
            persisted, elapsed_s, errs = await _walk_one_image(
                db, image, aggregate, hexdump_sha256s
            )
        except Vol3NotInstalled as exc:
            aggregate["errors_per_image"].append(
                f"Vol3 not installed — rebuild worker with INCLUDE_VOL3=1 "
                f"({exc})"
            )
            break
        aggregate["image_count"] += 1
        aggregate["detection_count"] += persisted
        aggregate["total_elapsed_s"] += elapsed_s
        if errs:
            aggregate["errors_per_image"].extend(errs)

    aggregate["unique_hexdump_sha256_count"] = len(hexdump_sha256s)
    await db.flush()
    aggregate["total_elapsed_s"] = round(aggregate["total_elapsed_s"], 3)
    logger.info(
        "windows_injection_walk: firmware %s walked %d images "
        "(detections=%d, unique_hexdump_sha256=%d, errors=%d) in %.2fs",
        firmware_id,
        aggregate["image_count"],
        aggregate["detection_count"],
        aggregate["unique_hexdump_sha256_count"],
        len(aggregate["errors_per_image"]),
        aggregate["total_elapsed_s"],
    )
    return aggregate


# ── Outer wrapper (Rule #33 .a state machine) ───────────────────────────────


async def run_windows_injection_walk_background(
    firmware_id: uuid.UUID,
) -> None:
    """OUTER state-machine wrapper (Rule #33 .a + Rule #39 triplet)."""
    try:
        async with async_session_factory() as db:
            firmware = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if firmware is None:
                return
            firmware.windows_injection_walk_status = "running"
            firmware.windows_injection_walk_started_at = _dt.datetime.now(_dt.UTC)
            firmware.windows_injection_walk_error = None
            await db.commit()

            try:
                aggregate = await _do_windows_injection_walk(db, firmware_id)
            except Exception as exc:  # noqa: BLE001 — outer guard captures all
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(
                        type(exc), exc, exc.__traceback__
                    )
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.windows_injection_walk_status = "failed"
                        fail_row.windows_injection_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.windows_injection_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "windows_injection_walk failed for firmware %s", firmware_id
                )
                return

            firmware.windows_injection_walk_status = "completed"
            firmware.windows_injection_walk_finished_at = _dt.datetime.now(_dt.UTC)
            firmware.windows_injection_walk_result = (
                _stamp_firmware_windows_injection_walk_result(aggregate)
            )
            await db.commit()
    except Exception:  # noqa: BLE001 — outermost guard
        logger.exception(
            "unrecoverable error in run_windows_injection_walk_background"
        )


# ── Safe-runner (Rule #39 unpack-post-detection hook) ───────────────────────


async def auto_windows_injection_walk_firmware_safe(
    firmware_id: uuid.UUID,
) -> None:
    """UNPACK-POST-DETECTION hook — fire-and-forget walker (Rule #39).

    Stamps aggregate but leaves ``windows_injection_walk_status`` at
    ``idle`` so a future operator-driven re-trigger succeeds without
    409 conflict (Rule #33 .a).
    """
    try:
        async with async_session_factory() as db:
            try:
                aggregate = await _do_windows_injection_walk(db, firmware_id)
            except Exception:  # noqa: BLE001 — safe-runner swallows per Rule #39
                logger.exception(
                    "auto windows_injection_walk failed for firmware %s",
                    firmware_id,
                )
                return
            firmware = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if firmware is None:
                return
            firmware.windows_injection_walk_result = (
                _stamp_firmware_windows_injection_walk_result(aggregate)
            )
            await db.commit()
    except Exception:  # noqa: BLE001 — outermost guard
        logger.exception(
            "unrecoverable error in auto_windows_injection_walk_firmware_safe"
        )


__all__ = [
    "_PLUGINS_TO_RUN",
    "_PLUGIN_TO_KIND",
    "_WALK_OS_FAMILIES",
    "_canonicalise_hexdump_first_64",
    "_do_windows_injection_walk",
    "_extract_hollowprocesses_record",
    "_extract_ldrmodules_record",
    "_extract_malfind_record",
    "_extract_pebmasquerade_record",
    "_extract_processghosting_record",
    "_hexdump_sha256",
    "auto_windows_injection_walk_firmware_safe",
    "run_windows_injection_walk_background",
]
