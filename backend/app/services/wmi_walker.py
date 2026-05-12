"""Phase θ.B — Windows Management Instrumentation (WMI) persistence
walker.

Reads WMI repository OBJECTS.DATA files (typically under
``Windows/System32/wbem/Repository/`` in firmware extracts) and walks
every detected ``__FilterToConsumerBinding`` triple via the vendored
PyWMIPersistenceFinder (Phase θ.B.A — keyword-search regex parser,
MIT-licensed fork of David Pany's WMI_Forensics). Each binding
becomes one ``WindowsWmiEvent`` row for downstream finding-emit
hooks (θ.B.E + θ.B.F).

**Rule #39 inner/outer/safe runner triplet** (γ.4 + δ.5 + ε.1.b.3 +
ζ.2.B + ζ.3.B + η.B.C + η.C.C + η.A.C + θ.A.C + θ.B.D = Rule-of-Ten):

- :func:`_do_wmi_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every OBJECTS.DATA candidate under detection roots,
  invokes the vendored ``find_persistence(path)`` parser, iterates
  every detected binding, persists per-binding ``WindowsWmiEvent``
  rows, returns aggregate dict UNSTAMPED.
- :func:`run_wmi_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer
  guard catches escapes; failure persistence on a fresh session.
- :func:`auto_wmi_walk_firmware_safe` — UNPACK-POST-DETECTION hook.
  Runs the inner orchestrator + finding-emit hook but does NOT
  mutate ``wmi_walk_status`` (leaves ``idle`` so manual re-trigger
  works without 409).

**Rule #36 no-execute discipline (THE CENTRAL DISCIPLINE FOR θ.B).**
The vendored PyWMIPersistenceFinder is a pure-Python regex-only
parser; it reads OBJECTS.DATA AS DATA. The walker NEVER:

- Invokes ``wscript.exe`` / ``cscript.exe`` / ``powershell.exe`` /
  ``pwsh.exe`` / ``mshta.exe`` / ``rundll32.exe`` / ``regsvr32.exe``
  / ``wmiexec.py`` / ``WmiPrvSE.exe`` / ``mofcomp.exe`` against any
  parsed binding's consumer payload.
- Loads / mmaps / ctypes.CDLL's any extracted-tree binary on the
  basis of a WMI binding.
- Mounts the repository to the worker's filesystem.

The CommandLineTemplate / ScriptText / FileName + WriteString
payloads are surfaced to the operator as DATA in
``WindowsWmiEvent.consumer_payload`` and in the
``windows_wmi_persistence`` Finding row's evidence field. The test
gate ``tests/test_wmi_walker.py::test_wmi_no_script_execution``
asserts this discipline programmatically.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare
``firmware.extracted_path``) so scatter-zip / multi-archive Windows
extracts surface every WMI repository candidate.

**Rule #19 evidence-first probe.** :func:`is_vendor_available`
exposes a graceful-degrade probe so consumers can surface a clear
"vendor not installed" message rather than an opaque ImportError.
The vendor lives in ``backend/third_party/``; the probe protects
against on-disk corruption of the vendor file.

**Performance.** The vendored parser is pure-Python regex; one
OBJECTS.DATA in the 5-50 MB range walks in 1-5 seconds. Total
wall-time per firmware is dominated by the file-search step
(walking detection roots for OBJECTS.DATA candidates), not by
parsing. We cap at 500 bindings persisted per firmware
(``_DEFAULT_MAX_BINDINGS_PER_FIRMWARE``) defensive against
attacker-planted multi-thousand-binding repositories.

**T1546.003 Event-Triggered Execution: WMI Event Subscription** —
notable adversary tradecraft:

- APT29 (Cozy Bear) — PowerShell consumer for persistence + C2.
- APT32 (OceanLotus) — Custom JScript consumer drops.
- Turla — Multi-stage timer-based bindings.
- FIN7 — Carbanak operator tradecraft.
- Conti / BlackCat ransomware affiliates — Pre-encryption WMI
  triggers for staged execution.

Reference: https://attack.mitre.org/techniques/T1546/003/
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_wmi_event import WindowsWmiEvent
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_wmi_walk_result,
    _stamp_windows_wmi_events_anomaly_flags,
    _stamp_windows_wmi_events_consumer_payload,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ─────────────────────────────────────────────────────────

# Maximum WMI bindings persisted per firmware. A typical Windows
# repository has 0-3 bindings (mostly the BVT + SCM benign pair);
# attacker-planted multi-binding files are bounded defensively.
_DEFAULT_MAX_BINDINGS_PER_FIRMWARE: int = 500

# Cap on raw OBJECTS.DATA size to attempt. Typical OBJECTS.DATA is
# 5-50 MB; pathological cases reach a few hundred MB. 1 GiB cap
# protects against attacker-planted gigabyte-padded files.
_DEFAULT_MAX_FILE_BYTES: int = 1024 * 1024 * 1024  # 1 GiB


# ── Anomaly heuristic constants ─────────────────────────────────────────────

# Script-host binary names — used to flag CommandLineEventConsumer
# bindings whose Arguments references one of these.
_SCRIPT_HOST_TOKENS: tuple[str, ...] = (
    "wscript.exe",
    "cscript.exe",
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "cmd.exe",
)

# Encoded-PowerShell indicators (Qakbot signature). Case-insensitive
# match on the consumer payload's Arguments string.
_ENCODED_POWERSHELL_PATTERNS: tuple[str, ...] = (
    "-encodedcommand",
    "-enc ",
    "frombase64string",
    "invoke-expression",
    "downloadstring",
    "iex ",
    "[char[]]",
    "[convert]::frombase64",
)

# ActiveScriptEventConsumer is the highest-impact consumer type
# (in-process VBScript / JScript execution). Flag with high_severity
# regardless of payload content.
_ACTIVE_SCRIPT_CONSUMER_TYPE = "ActiveScriptEventConsumer"


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_vendor_available() -> bool:
    """Return True iff the vendored PyWMIPersistenceFinder package is
    importable in this process.

    Mirrors the dissect.ntfs / LnkParse3 / python-evtx /
    windowsprefetch graceful-degrade probes used by γ.4 / ε.1.b /
    ζ.2.B / η.B.C / η.C.C / η.A.C / θ.A.C.
    """
    try:
        from third_party.pywmi_persistence_finder import (  # noqa: F401
            find_persistence,
        )
    except ImportError:
        return False
    return True


VENDOR_UNAVAILABLE: dict[str, Any] = {
    "status": "unavailable",
    "reason": (
        "third_party.pywmi_persistence_finder not importable — "
        "see backend/third_party/pywmi_persistence_finder/"
    ),
    "bindings": 0,
}


# ── OBJECTS.DATA candidate enumeration ──────────────────────────────────────


def walk_wmi_repositories(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return candidate WMI
    OBJECTS.DATA file paths.

    WMI repositories live under ``Windows/System32/wbem/Repository/``
    on Windows; the canonical filename is ``OBJECTS.DATA`` (no extension
    on disk; the format is a binary WMI repository file). Co-located
    sibling files (``INDEX.BTR``, ``MAPPING1.MAP``, ``MAPPING2.MAP``,
    ``MAPPING3.MAP``) are NOT walked — the vendored parser is
    keyword-search only and doesn't use the index/mapping files.
    Future work may add cross-reference parsing.

    Match is case-insensitive — extracted partitions may surface
    Repository/ as Repository/ or repository/ depending on the
    filesystem case sensitivity (FAT32/exFAT/NTFS-case-insensitive
    vs Linux ext4 with case-sensitive mount).

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Defensive against missing roots, permission errors — every error
    path is swallowed at the per-root / per-file level so one
    corrupted detection root doesn't abort the entire walk.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots` — NEVER ``firmware.extracted_path``
    alone.
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
        except OSError:
            continue
        if not os.path.isdir(real_root):  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            continue
        for dirpath, _dirnames, filenames in os.walk(  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            real_root, followlinks=False
        ):
            for name in filenames:
                if name.upper() != "OBJECTS.DATA":
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math; one realpath per candidate
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                try:
                    if not os.path.isfile(real_full):  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
                        continue
                except OSError:
                    continue
                hits.append(real_full)
    return hits


# ── Anomaly classification helpers ──────────────────────────────────────────


def contains_encoded_powershell(payload: str) -> bool:
    """Return True iff the payload string carries a known
    encoded-PowerShell signature.

    Case-insensitive substring match. The set matches the Qakbot
    tradecraft signature codified at η.C.D / η.B.D / η.E.
    """
    if not payload:
        return False
    lower = payload.lower()
    return any(
        pattern in lower for pattern in _ENCODED_POWERSHELL_PATTERNS
    )


def references_script_host(payload: str) -> bool:
    """Return True iff the payload string references a known
    script-host binary (wscript / cscript / powershell / mshta /
    rundll32 / regsvr32 / cmd)."""
    if not payload:
        return False
    lower = payload.lower()
    return any(token in lower for token in _SCRIPT_HOST_TOKENS)


def build_anomaly_flags(
    *,
    consumer_type: str,
    consumer_payload_aggregate: str,
    probably_benign: bool,
) -> dict:
    """Compute the heuristic anomaly aggregate for one WMI binding.

    Inputs:
    - consumer_type: the binding's consumer type string (e.g.
      ``ActiveScriptEventConsumer``).
    - consumer_payload_aggregate: a single concatenated string built
      from all consumer-detail records' Arguments + Other fields.
      Used for keyword pattern matching.
    - probably_benign: vendored well-known-binding annotation
      (BVTConsumer-BVTFilter, SCM Event Log Consumer-...).
    """
    is_active_script = (
        consumer_type == _ACTIVE_SCRIPT_CONSUMER_TYPE
    )
    has_encoded_ps = contains_encoded_powershell(
        consumer_payload_aggregate
    )
    has_script_host = references_script_host(
        consumer_payload_aggregate
    )

    return {
        "encoded_powershell": has_encoded_ps,
        "script_host_invocation": has_script_host,
        "active_script_consumer": is_active_script,
        "non_benign_binding": not probably_benign,
        # high_severity: at least one of the structural signals fires
        # AND the binding is NOT a well-known benign one.
        "high_severity": (
            (is_active_script or has_encoded_ps)
            and not probably_benign
        ),
    }


# ── Per-binding fingerprint ─────────────────────────────────────────────────


def compute_binding_fingerprint(
    binding_id: str,
    filter_query: str | None,
    first_consumer_arguments: str | None,
) -> str:
    """Compute a stable SHA256 fingerprint for cross-firmware
    aggregation in ``lookup_wmi_persistence``.

    The tuple is (binding_id, filter_query, first_consumer_arguments) —
    these three uniquely identify a binding's behavior. Same
    fingerprint across firmware ⇒ same persistence shape was planted.

    All inputs are coerced to strings with empty-fallback so the hash
    is deterministic on partial-parser-output cases.
    """
    tuple_str = (
        f"{binding_id}|{filter_query or ''}|{first_consumer_arguments or ''}"
    )
    return hashlib.sha256(tuple_str.encode("utf-8")).hexdigest()


# ── Per-repository walk ─────────────────────────────────────────────────────


def _walk_one_repository(
    repository_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_bindings: int,
    started_count: int,
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
) -> tuple[list[WindowsWmiEvent], dict]:
    """Open one WMI OBJECTS.DATA and walk every binding via the
    vendored parser.

    Returns ``(entries_to_persist, per_repository_aggregate)``. The
    entries are SQLAlchemy ORM instances ready for ``db.add()``; the
    aggregate summary tells the caller how many bindings were walked
    + how many were filtered out for the persist cap + anomaly
    counters.

    Defensive boundary:
    - file size > max_file_bytes → status="skipped"
    - vendored parser unavailable → status="unavailable"
    - vendored parser exception → status="error"
    - empty list returned (clean repo or no bindings) → status="ok",
      entries_walked=0
    """
    aggregate: dict = {
        "path": relative_source,
        "status": "ok",
        "bindings_walked": 0,
        "bindings_persisted": 0,
        "active_script_count": 0,
        "command_line_count": 0,
        "encoded_powershell_count": 0,
        "non_benign_count": 0,
        "error": None,
    }

    try:
        size = os.path.getsize(repository_path)  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
    except OSError as exc:
        aggregate["status"] = "error"
        aggregate["error"] = (
            f"stat failed: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return [], aggregate

    if size > max_file_bytes:
        aggregate["status"] = "skipped"
        aggregate["error"] = (
            f"OBJECTS.DATA size {size} exceeds max {max_file_bytes} "
            f"(attacker-DoS / runaway-walk protection); operator can "
            f"re-walk via MCP tool"
        )
        return [], aggregate

    try:
        from third_party.pywmi_persistence_finder import (
            find_persistence,
        )
    except ImportError:
        aggregate["status"] = "unavailable"
        aggregate["error"] = (
            "third_party.pywmi_persistence_finder not importable"
        )
        return [], aggregate

    entries: list[WindowsWmiEvent] = []
    persist_budget = max_bindings - started_count

    try:
        bindings = find_persistence(repository_path)
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        aggregate["status"] = "error"
        aggregate["error"] = f"{type(exc).__name__}: {msg}"
        return [], aggregate

    aggregate["bindings_walked"] = len(bindings)

    for binding in bindings:
        if persist_budget <= 0:
            continue

        # Derive a primary consumer_type. The vendored parser may
        # emit multiple consumer_records (allocated + unallocated
        # repository regions); the first record's consumer_type is
        # the canonical discriminator. Empty list → "Unknown" so
        # the flat column is non-null.
        if binding.consumer_records:
            primary_consumer_type = (
                binding.consumer_records[0].consumer_type
                or "Unknown"
            )
        else:
            # No consumer details extracted — the binding pass fired
            # but the consumer-details pass didn't match. Surface
            # the binding as DATA with type=Unknown so the operator
            # can still review it.
            primary_consumer_type = "Unknown"

        # Aggregate counters
        if primary_consumer_type == _ACTIVE_SCRIPT_CONSUMER_TYPE:
            aggregate["active_script_count"] += 1
        elif primary_consumer_type == "CommandLineEventConsumer":
            aggregate["command_line_count"] += 1
        if not binding.probably_benign:
            aggregate["non_benign_count"] += 1

        # Build the JSONB consumer_payload from the vendored records.
        payload_records: list[dict] = []
        payload_aggregate_strs: list[str] = []
        for cd in binding.consumer_records:
            payload_records.append({
                "consumer_type": cd.consumer_type,
                "arguments": cd.arguments,
                "other": cd.other,
            })
            payload_aggregate_strs.append(
                f"{cd.consumer_type} {cd.arguments} {cd.other}"
            )
        payload_aggregate = " ".join(payload_aggregate_strs)

        if contains_encoded_powershell(payload_aggregate):
            aggregate["encoded_powershell_count"] += 1

        # Pull the primary filter_query from the first filter record.
        if binding.filter_records:
            primary_filter_query = binding.filter_records[0].filter_query
        else:
            primary_filter_query = None

        anomaly = build_anomaly_flags(
            consumer_type=primary_consumer_type,
            consumer_payload_aggregate=payload_aggregate,
            probably_benign=binding.probably_benign,
        )

        # Truncate fields to the column lengths declared in the ORM.
        binding_id_trimmed = (binding.binding_id or "")[:512]
        filter_name_trimmed = (binding.filter_name or "")[:512]
        filter_query_trimmed = (
            (primary_filter_query or "")[:4096] or None
        )
        consumer_name_trimmed = (binding.consumer_name or "")[:512]
        consumer_type_trimmed = primary_consumer_type[:64]

        first_arguments = (
            binding.consumer_records[0].arguments
            if binding.consumer_records
            else None
        )
        fingerprint = compute_binding_fingerprint(
            binding_id_trimmed,
            filter_query_trimmed,
            first_arguments,
        )

        stamped_payload = (
            _stamp_windows_wmi_events_consumer_payload(payload_records)
            if payload_records
            else None
        )
        stamped_anomaly = _stamp_windows_wmi_events_anomaly_flags(
            anomaly
        )

        row = WindowsWmiEvent(
            firmware_id=firmware_id,
            source_path=relative_source[:2048],
            namespace=None,  # Future work — INDEX.BTR cross-reference.
            binding_id=binding_id_trimmed,
            filter_name=filter_name_trimmed,
            filter_query=filter_query_trimmed,
            consumer_name=consumer_name_trimmed,
            consumer_type=consumer_type_trimmed,
            consumer_payload=stamped_payload,
            anomaly_flags=stamped_anomaly,
            fingerprint_sha256=fingerprint,
            probably_benign=binding.probably_benign,
        )
        entries.append(row)
        persist_budget -= 1
        aggregate["bindings_persisted"] += 1

    return entries, aggregate


# ── Aggregate helpers ───────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "objects_data_scanned": 0,
        "bindings_walked": 0,
        "bindings_persisted": 0,
        "active_script_count": 0,
        "command_line_count": 0,
        "encoded_powershell_count": 0,
        "non_benign_count": 0,
        "errors": [],
        "per_repository": [],
    }


def _relativize_path(full_path: str, roots: list[str]) -> str:
    """Compute path relative to whichever detection root contains it."""
    try:
        real_full = os.path.realpath(full_path)
    except OSError:
        return os.path.basename(full_path)
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if real_full == real_root or real_full.startswith(real_root + os.sep):
            return (
                real_full[len(real_root) + 1 :]
                if real_full != real_root
                else "."
            )
    return os.path.basename(full_path)


async def _walk_wmi_repositories_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_wmi_repositories` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_wmi_repositories, roots)


async def _walk_one_repository_async(
    repository_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_bindings: int,
    started_count: int,
) -> tuple[list[WindowsWmiEvent], dict]:
    """Async wrapper around :func:`_walk_one_repository` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_repository(
            repository_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
            max_bindings=max_bindings,
            started_count=started_count,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ─────────────────────────


async def _do_wmi_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_bindings: int = _DEFAULT_MAX_BINDINGS_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every OBJECTS.DATA candidate in ``firmware_id``'s extracted
    tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for OBJECTS.DATA candidates (case-insensitive).
    3. For each candidate: pre-flight size check, invoke vendored
       ``find_persistence()`` (run_in_executor for Rule #5 sync I/O),
       iterate detected bindings, construct + bulk-add
       WindowsWmiEvent rows.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real
    test DB without DNS resolution issues from
    ``async_session_factory()``.
    """
    started = time.monotonic()

    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        return _empty_walk_result(0.0)

    roots = await get_detection_roots(firmware, db=db)
    if not roots:
        return _empty_walk_result(time.monotonic() - started)

    repository_paths = await _walk_wmi_repositories_async(roots)
    if not repository_paths:
        return _empty_walk_result(time.monotonic() - started)

    objects_data_scanned = 0
    bindings_walked = 0
    bindings_persisted = 0
    active_script_count = 0
    command_line_count = 0
    encoded_powershell_count = 0
    non_benign_count = 0
    errors: list[str] = []
    per_repository: list[dict] = []

    for repository_path in repository_paths:
        relative = _relativize_path(repository_path, roots)
        try:
            entries, agg = await _walk_one_repository_async(
                repository_path,
                firmware_id=firmware_id,
                relative_source=relative,
                max_bindings=max_bindings,
                started_count=bindings_persisted,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = (
                f"walk failed for {repository_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_repository.append({
                "path": relative,
                "status": "error",
                "bindings_walked": 0,
                "bindings_persisted": 0,
                "active_script_count": 0,
                "command_line_count": 0,
                "encoded_powershell_count": 0,
                "non_benign_count": 0,
                "error": err,
            })
            continue

        objects_data_scanned += 1
        bindings_walked += agg["bindings_walked"]
        bindings_persisted += agg["bindings_persisted"]
        active_script_count += agg["active_script_count"]
        command_line_count += agg["command_line_count"]
        encoded_powershell_count += agg["encoded_powershell_count"]
        non_benign_count += agg["non_benign_count"]
        per_repository.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

        for row in entries:
            db.add(row)
        if entries:
            await db.flush()

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "objects_data_scanned": objects_data_scanned,
        "bindings_walked": bindings_walked,
        "bindings_persisted": bindings_persisted,
        "active_script_count": active_script_count,
        "command_line_count": command_line_count,
        "encoded_powershell_count": encoded_powershell_count,
        "non_benign_count": non_benign_count,
        "errors": errors,
        "per_repository": per_repository,
    }


# ── Outer wrapper (Rule #33 .a state machine) ───────────────────────────────


async def run_wmi_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the WMI walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back. Mirrors the
    θ.A.C BCD walker shape.

    Status transitions: idle → running → completed | failed. The
    queued state belongs to the trigger router (idempotent POST +
    409-on-conflict per Rule #33 .a).
    """
    try:
        async with async_session_factory() as db:
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is None:
                logger.warning(
                    "wmi_walk: firmware %s not found", firmware_id
                )
                return

            row.wmi_walk_status = "running"
            row.wmi_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_wmi_walk(db, firmware_id)
                row.wmi_walk_status = "completed"
                row.wmi_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.wmi_walk_result = _stamp_firmware_wmi_walk_result(result)
                project_id = row.project_id
                await db.commit()

                # θ.B.F — emit windows_wmi_persistence Finding rows
                # alongside the status transition. Lazy import per
                # Rule #30 to avoid wmi_walker ↔ finding_service
                # circular at module load.
                if result["bindings_persisted"] > 0:
                    try:
                        from app.services.finding_service import (
                            FindingService,
                        )

                        service = FindingService(db=db)
                        emitted = (
                            await service.emit_wmi_findings_from_walk(
                                project_id, firmware_id
                            )
                        )
                        await db.commit()
                        logger.info(
                            "wmi_walk: firmware %s emitted %d Finding rows",
                            firmware_id,
                            len(emitted),
                        )
                    except Exception:
                        await db.rollback()
                        logger.warning(
                            "wmi_walk: firmware %s Finding emit failed",
                            firmware_id,
                            exc_info=True,
                        )

                logger.info(
                    "wmi_walk: firmware %s completed in %.2fs (%d "
                    "OBJECTS.DATA, %d bindings walked, %d persisted, "
                    "%d ActiveScript, %d CommandLine, %d encoded-PS, "
                    "%d non-benign)",
                    firmware_id,
                    result["run_seconds"],
                    result["objects_data_scanned"],
                    result["bindings_walked"],
                    result["bindings_persisted"],
                    result["active_script_count"],
                    result["command_line_count"],
                    result["encoded_powershell_count"],
                    result["non_benign_count"],
                )
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(
                        type(exc), exc, exc.__traceback__
                    )
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(
                                Firmware.id == firmware_id
                            )
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.wmi_walk_status = "failed"
                        fail_row.wmi_walk_finished_at = _dt.datetime.now(
                            _dt.UTC
                        )
                        fail_row.wmi_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "wmi_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "wmi_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_wmi_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as θ.A.C
    auto_bcd_walk_firmware_safe wrapper.

    Distinct from :func:`run_wmi_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-
    triggered walks. The auto-walk-on-unpack flow runs the SAME
    orchestrator (``_do_wmi_walk``) but DOES NOT transition the
    status column — it stays ``idle`` until an operator explicitly
    triggers a re-walk via the trigger MCP tool, which resets and
    runs again.

    Wired to FindingService.emit_wmi_findings_from_walk in θ.B.F so
    auto-walks produce both the per-binding landing-zone rows AND
    the windows_wmi_persistence Finding rows in a single pass.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_wmi_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            project_id: uuid.UUID | None = None
            if row is not None:
                row.wmi_walk_result = _stamp_firmware_wmi_walk_result(result)
                project_id = row.project_id
                await db.commit()

            # θ.B.F — emit windows_wmi_persistence Finding rows for
            # each WindowsWmiEvent persisted by the inner runner.
            # Lazy import per Rule #30 to avoid wmi_walker ↔
            # finding_service circular at module load (and to keep
            # the cold-import cost off the unpack worker's critical
            # path when no WMI repository is present in the firmware).
            if project_id is not None and result["bindings_persisted"] > 0:
                try:
                    from app.services.finding_service import FindingService

                    service = FindingService(db=db)
                    emitted = await service.emit_wmi_findings_from_walk(
                        project_id, firmware_id
                    )
                    await db.commit()
                    logger.info(
                        "wmi_walk auto: firmware %s emitted %d "
                        "Finding rows",
                        firmware_id,
                        len(emitted),
                    )
                except Exception:
                    # Emit failure must NOT roll back the walk-result
                    # persistence — leave the windows_wmi_events rows
                    # + wmi_walk_result aggregate in place even if
                    # the downstream Finding emit raises. Operators
                    # can re-run via the trigger MCP tool to retry.
                    await db.rollback()
                    logger.warning(
                        "wmi_walk auto: firmware %s Finding emit failed",
                        firmware_id,
                        exc_info=True,
                    )

            logger.info(
                "wmi_walk auto: firmware %s walked %d OBJECTS.DATA "
                "/ %d bindings in %.2fs",
                firmware_id,
                result["objects_data_scanned"],
                result["bindings_walked"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "wmi_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "VENDOR_UNAVAILABLE",
    "_do_wmi_walk",
    "auto_wmi_walk_firmware_safe",
    "build_anomaly_flags",
    "compute_binding_fingerprint",
    "contains_encoded_powershell",
    "is_vendor_available",
    "references_script_host",
    "run_wmi_walk_background",
    "walk_wmi_repositories",
]
