"""Linux kernel hardening (KSPP) walker.

Reads ``HardwareFirmwareBlob.metadata.kernel_config`` populated by the
``kernel_image`` parser (commits f947b59 + 108102b) and emits Findings
for each insecure / weak / missing kernel hardening config against a
curated KSPP-aligned rule catalogue.

Architecture per CLAUDE.md Rule #39 — inner/outer/safe runner triplet:

* ``_do_kernel_config_audit_run(db, firmware_id)`` — pure-logic
  orchestrator. Takes a session from the caller. Walks every
  ``HardwareFirmwareBlob`` for the firmware, picks the ones with
  ``metadata.kernel_config`` (parser populated), runs the KSPP rules,
  emits one Finding per matched rule per blob via FindingService.
* ``run_kernel_config_audit_background(firmware_id)`` — Rule #33 .a
  5-state machine wrapper. Owns its own session; transitions
  ``idle → queued → running → completed | failed``; failure persistence
  on a fresh session because inner rolls back on exception.
* ``auto_kernel_config_audit_firmware_safe(firmware_id)`` — unpack-post-
  detection hook. Owns own session, swallows exceptions silently,
  DOES NOT mutate firmware status (leaves it ``idle`` so manual
  re-trigger works without 409 conflict).

Rule discipline applied
-----------------------
- Rule #45 parse-only: walker reads metadata, never invokes the kernel
  binary. The parser already extracted .config text; we just evaluate.
- Rule #35c JSONB normaliser pair: ``_normalize_kernel_config_audit_result``
  + ``_stamp_kernel_config_audit_result`` with
  ``KERNEL_CONFIG_AUDIT_SCHEMA_VERSION = 1``.
- Rule #25 single-slice exception #2: 10 ``kernel_config_*`` finding
  sources are pre-aligned across DB CHECK + Pydantic Literal + frontend
  union + config map in commit dd8af4e; walker just consumes them.
- Rule #46 META-CANARY: the rule table is a closed dispatch — no string
  EVAL, no eval()/exec(), no decrypt path. Tests assert this via a
  tokenize-based source scan in test_linux_kernel_hardening_walker.py.
"""

from __future__ import annotations

import datetime as dt
import logging
import traceback
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.schemas.finding import Confidence, FindingCreate, Severity
from app.services.finding_service import FindingService

logger = logging.getLogger(__name__)

KERNEL_CONFIG_AUDIT_SCHEMA_VERSION = 1

# -----------------------------------------------------------------------------
# KSPP rule catalogue.
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class _KsppRule:
    """One closed-grammar KSPP-aligned hardening check.

    ``check_kind``:
      * ``"missing"`` — fail when the config is absent OR set to 'n'
      * ``"enabled"`` — fail when the config is set to 'y' (risk surface)

    ``finding_source`` MUST match one of the 10 ``kernel_config_*`` values
    declared in ``schemas/finding.py::KernelConfigFindingSource``.
    """

    config_name: str
    check_kind: str  # "missing" | "enabled"
    severity: str    # "high" | "medium" | "low"
    cwe_ids: tuple[str, ...]
    finding_source: str
    title: str
    description: str


_KSPP_RULES: tuple[_KsppRule, ...] = (
    _KsppRule(
        config_name="CONFIG_RANDOMIZE_BASE",
        check_kind="missing",
        severity="high",
        cwe_ids=("CWE-330",),
        finding_source="kernel_config_no_kaslr",
        title="Kernel: KASLR disabled",
        description=(
            "CONFIG_RANDOMIZE_BASE is not set. Kernel Address Space Layout "
            "Randomization (KASLR) is disabled, making kernel exploits with "
            "leaked-pointer primitives significantly easier. KSPP recommended."
        ),
    ),
    _KsppRule(
        config_name="CONFIG_DEVMEM",
        check_kind="enabled",
        severity="high",
        cwe_ids=("CWE-732",),
        finding_source="kernel_config_devmem_enabled",
        title="Kernel: /dev/mem exposed",
        description=(
            "CONFIG_DEVMEM=y exposes raw physical memory via /dev/mem. Root "
            "userland can read/write arbitrary physical pages — historically "
            "a major LPE primitive. KSPP recommends CONFIG_DEVMEM=n."
        ),
    ),
    _KsppRule(
        config_name="CONFIG_DEVKMEM",
        check_kind="enabled",
        severity="high",
        cwe_ids=("CWE-732",),
        finding_source="kernel_config_devkmem_enabled",
        title="Kernel: /dev/kmem exposed",
        description=(
            "CONFIG_DEVKMEM=y exposes raw kernel memory via /dev/kmem. "
            "Direct kernel-memory read/write from root userland. The option "
            "was REMOVED entirely in Linux 5.13+; pre-5.13 kernels with "
            "CONFIG_DEVKMEM=y are exceptionally weak."
        ),
    ),
    _KsppRule(
        config_name="CONFIG_MODULE_SIG",
        check_kind="missing",
        severity="high",
        cwe_ids=("CWE-345",),
        finding_source="kernel_config_no_module_sig",
        title="Kernel: unsigned modules accepted",
        description=(
            "CONFIG_MODULE_SIG is not set. Kernel modules can be loaded "
            "WITHOUT cryptographic signature verification. A root-equivalent "
            "attacker can persist a kernel rootkit via a custom .ko. KSPP "
            "recommends CONFIG_MODULE_SIG=y + CONFIG_MODULE_SIG_FORCE=y."
        ),
    ),
    _KsppRule(
        config_name="CONFIG_STACKPROTECTOR_STRONG",
        check_kind="missing",
        severity="high",
        cwe_ids=("CWE-121",),
        finding_source="kernel_config_no_stackprotector",
        title="Kernel: stack-protector strong missing",
        description=(
            "CONFIG_STACKPROTECTOR_STRONG is not set. The compiler-inserted "
            "stack canary protection against stack-based buffer overflows is "
            "either disabled entirely or set to the weaker REGULAR variant. "
            "KSPP recommended for all kernels."
        ),
    ),
    _KsppRule(
        config_name="CONFIG_HARDENED_USERCOPY",
        check_kind="missing",
        severity="medium",
        cwe_ids=("CWE-120",),
        finding_source="kernel_config_no_hardened_usercopy",
        title="Kernel: hardened usercopy missing",
        description=(
            "CONFIG_HARDENED_USERCOPY is not set. Copies between kernel and "
            "userspace are NOT bounds-checked against allocator slab sizes. "
            "Historically a frequent LPE primitive. KSPP recommended."
        ),
    ),
    _KsppRule(
        config_name="CONFIG_FORTIFY_SOURCE",
        check_kind="missing",
        severity="medium",
        cwe_ids=("CWE-120",),
        finding_source="kernel_config_no_fortify_source",
        title="Kernel: FORTIFY_SOURCE missing",
        description=(
            "CONFIG_FORTIFY_SOURCE is not set. Compile-time + run-time "
            "buffer-overflow detection in str*/mem* family is disabled. "
            "KSPP recommended for kernels using glibc-like fortified libc."
        ),
    ),
    _KsppRule(
        config_name="CONFIG_IO_URING",
        check_kind="enabled",
        severity="medium",
        cwe_ids=("CWE-1188",),
        finding_source="kernel_config_io_uring_enabled",
        title="Kernel: io_uring enabled (risk surface)",
        description=(
            "CONFIG_IO_URING=y. io_uring is a high-CVE-rate kernel surface — "
            "CVE-2021-41073 / CVE-2022-29582 / CVE-2023-2598 / CVE-2024-0582 "
            "all gate on this option. For container-isolated workloads or "
            "fixed-purpose appliances, KSPP suggests CONFIG_IO_URING=n; for "
            "general-purpose servers, keep io_uring updated + sandboxed."
        ),
    ),
    _KsppRule(
        config_name="CONFIG_DM_VERITY",
        check_kind="missing",
        severity="medium",
        cwe_ids=("CWE-353",),
        finding_source="kernel_config_no_dm_verity",
        title="Kernel: dm-verity missing",
        description=(
            "CONFIG_DM_VERITY is not set. Block-level integrity verification "
            "is unavailable; the root filesystem can be mutated without "
            "detection (e.g. attacker writes to /lib/modules + reboots). "
            "Critical for medical / IoT / appliance class devices."
        ),
    ),
)

# Composite check: at least one of these LSMs must be enabled.
_LSM_MAJOR_ALTERNATIVES: tuple[str, ...] = (
    "CONFIG_SECURITY_SELINUX",
    "CONFIG_SECURITY_APPARMOR",
    "CONFIG_SECURITY_SMACK",
    "CONFIG_SECURITY_TOMOYO",
)

_LSM_FINDING = _KsppRule(
    config_name="(composite)",
    check_kind="missing",
    severity="high",
    cwe_ids=("CWE-272",),
    finding_source="kernel_config_no_lsm",
    title="Kernel: no major LSM enabled (DAC only)",
    description=(
        "None of CONFIG_SECURITY_SELINUX / CONFIG_SECURITY_APPARMOR / "
        "CONFIG_SECURITY_SMACK / CONFIG_SECURITY_TOMOYO is enabled. The "
        "system relies on Discretionary Access Control alone — no Mandatory "
        "Access Control gate. Any root-equivalent compromise has unrestricted "
        "kernel access. KSPP recommends at least one major LSM."
    ),
)


# -----------------------------------------------------------------------------
# Pure-logic evaluator (no DB, no I/O — testable in isolation).
# -----------------------------------------------------------------------------


def evaluate_kernel_config(config: dict[str, str]) -> list[_KsppRule]:
    """Return the list of rules that FAIL against ``config``.

    Pure function — easy unit testing.  The 9 single-config rules in
    ``_KSPP_RULES`` use a closed dispatch on ``check_kind`` (no eval,
    no exec — Rule #46 META-CANARY safe).  The 10th LSM rule is a
    composite check evaluating ``_LSM_MAJOR_ALTERNATIVES``.
    """
    fails: list[_KsppRule] = []
    for rule in _KSPP_RULES:
        val = config.get(rule.config_name)
        if rule.check_kind == "missing":
            # Failure: config absent (=> KSPP recommendation NOT applied) OR
            # explicitly disabled.
            if val is None or val == "n":
                fails.append(rule)
        elif rule.check_kind == "enabled":
            # Failure: config explicitly =y (=> risk surface present).
            if val == "y":
                fails.append(rule)
        # No other check_kind values exist — dispatch table is closed.

    # Composite LSM check.
    if not any(config.get(opt) == "y" for opt in _LSM_MAJOR_ALTERNATIVES):
        fails.append(_LSM_FINDING)

    return fails


# -----------------------------------------------------------------------------
# JSONB normaliser (Rule #35c) for firmware.kernel_config_audit_result.
# -----------------------------------------------------------------------------


def _normalize_kernel_config_audit_result(value: Any) -> dict | None:
    """Defensive coercion: read-site normaliser.

    Old / hand-edited rows may have list, str, None — coerce to dict
    or None.  Tested in test_jsonb_normalizers.py.
    """
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    return None


def _stamp_kernel_config_audit_result(payload: dict) -> dict:
    """Add schema_version + walker provenance to a result payload."""
    stamped = dict(payload)
    stamped["schema_version"] = KERNEL_CONFIG_AUDIT_SCHEMA_VERSION
    stamped["provenance"] = "linux_kernel_hardening_walker"
    return stamped


# -----------------------------------------------------------------------------
# INNER pure-logic orchestrator (Rule #39).
# -----------------------------------------------------------------------------


async def _do_kernel_config_audit_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict:
    """Run KSPP rules across every kernel-image blob for the firmware.

    Iterates ``HardwareFirmwareBlob`` rows for ``firmware_id``; for each
    that has ``metadata.kernel_config`` populated (parser detected IKCFG),
    runs the rule catalogue and emits Findings.  Returns the result
    aggregate UNSTAMPED — caller stamps via ``_stamp_kernel_config_audit_result``.
    """
    audited_at = dt.datetime.now(dt.UTC).isoformat()
    firmware = await db.get(Firmware, firmware_id)
    if firmware is None:
        return {
            "audited_at": audited_at,
            "blobs_audited": 0,
            "blobs_with_ikconfig": 0,
            "findings_emitted_count": 0,
            "per_blob": [],
            "errors": [f"firmware {firmware_id} not found"],
        }
    project_id = firmware.project_id

    blob_rows = (
        await db.execute(
            select(HardwareFirmwareBlob).where(
                HardwareFirmwareBlob.firmware_id == firmware_id
            )
        )
    ).scalars().all()

    findings_service = FindingService(db)
    per_blob: list[dict] = []
    findings_emitted = 0
    blobs_with_ikconfig = 0
    errors: list[str] = []

    for blob in blob_rows:
        meta = blob.metadata_ or {}
        if not isinstance(meta, dict):
            continue
        config = meta.get("kernel_config")
        if not isinstance(config, dict) or not config:
            continue
        blobs_with_ikconfig += 1

        try:
            fails = evaluate_kernel_config(config)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"evaluator raised on blob {blob.id}: {exc}")
            continue

        blob_findings: list[dict] = []
        kernel_semver = meta.get("kernel_semver") or "unknown"
        kernel_banner = meta.get("kernel_banner") or ""
        for rule in fails:
            evidence = (
                f"Kernel: Linux {kernel_semver} "
                f"(blob {blob.id} / {blob.blob_path or '<unknown>'})\n"
                f"Config check: {rule.config_name} ({rule.check_kind})\n"
            )
            if rule.config_name != "(composite)":
                evidence += f"Current value: {config.get(rule.config_name) or '(absent)'}\n"
            else:
                evidence += "LSM state: " + ", ".join(
                    f"{opt}={config.get(opt) or '(absent)'}"
                    for opt in _LSM_MAJOR_ALTERNATIVES
                ) + "\n"
            if kernel_banner:
                evidence += f"Banner: {kernel_banner[:200]}\n"

            try:
                finding = await findings_service.create(
                    project_id=project_id,
                    data=FindingCreate(
                        title=rule.title,
                        severity=Severity(rule.severity),
                        description=rule.description,
                        evidence=evidence,
                        cwe_ids=list(rule.cwe_ids),
                        confidence=Confidence("high"),
                        firmware_id=firmware_id,
                        source=rule.finding_source,
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(
                    f"FindingService.create failed for {rule.finding_source} "
                    f"on blob {blob.id}: {exc}"
                )
                continue

            blob_findings.append({
                "finding_source": rule.finding_source,
                "severity": rule.severity,
                "config_name": rule.config_name,
                "cwe_ids": list(rule.cwe_ids),
                "finding_id": str(finding.id),
            })
            findings_emitted += 1

        per_blob.append({
            "blob_id": str(blob.id),
            "blob_path": blob.blob_path,
            "kernel_semver": kernel_semver,
            "config_entries": len(config),
            "findings": blob_findings,
        })

    return {
        "audited_at": audited_at,
        "blobs_audited": len(blob_rows),
        "blobs_with_ikconfig": blobs_with_ikconfig,
        "findings_emitted_count": findings_emitted,
        "per_blob": per_blob,
        "errors": errors,
    }


# -----------------------------------------------------------------------------
# OUTER state-machine wrapper (Rule #33 .a + Rule #39).
# -----------------------------------------------------------------------------


async def run_kernel_config_audit_background(
    firmware_id: uuid.UUID,
) -> None:
    """OUTER wrapper — owns the Rule #33 .a state machine + outer guard.

    Transitions ``firmware.kernel_config_audit_status``:
        queued (set by caller via auto-trigger or operator HTTP)
          → running (this fn, on entry)
          → completed | failed (this fn, on exit)

    Outer guard: any exception escaping the inner runner gets captured
    into ``kernel_config_audit_error`` + status=failed via a FRESH
    session (because the inner session may have rolled back on the
    exception).
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                logger.warning(
                    "kernel_config_audit: firmware %s not found", firmware_id
                )
                return
            firmware.kernel_config_audit_status = "running"
            firmware.kernel_config_audit_started_at = dt.datetime.now(dt.UTC)
            firmware.kernel_config_audit_error = None
            await db.commit()
            try:
                result = await _do_kernel_config_audit_run(db, firmware_id)
                firmware.kernel_config_audit_status = "completed"
                firmware.kernel_config_audit_finished_at = dt.datetime.now(dt.UTC)
                firmware.kernel_config_audit_result = _stamp_kernel_config_audit_result(result)
                await db.commit()
            except Exception as exc:
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.kernel_config_audit_status = "failed"
                        fail_row.kernel_config_audit_finished_at = dt.datetime.now(dt.UTC)
                        fail_row.kernel_config_audit_error = err
                        await fail_db.commit()
                logger.exception(
                    "kernel_config_audit: inner runner failed for %s", firmware_id
                )
    except Exception:  # noqa: BLE001
        logger.exception(
            "kernel_config_audit: unrecoverable outer failure for %s", firmware_id
        )


# -----------------------------------------------------------------------------
# SAFE unpack-post-detection hook (Rule #39 — never raises).
# -----------------------------------------------------------------------------


async def auto_kernel_config_audit_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Auto-triggered post-detection hook.

    Owns own session, swallows exceptions silently, DOES NOT mutate
    ``firmware.kernel_config_audit_status`` (leaves it ``idle`` so a
    manual MCP / HTTP re-trigger works without 409 conflict).

    Stamps the result aggregate so operators can see the audit happened
    via ``firmware.kernel_config_audit_result``.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                return
            try:
                result = await _do_kernel_config_audit_run(db, firmware_id)
                firmware.kernel_config_audit_result = _stamp_kernel_config_audit_result(result)
                # status STAYS idle — operator-triggered re-runs are
                # allowed (Rule #39 safe-wrapper discipline).
                await db.commit()
            except Exception:  # noqa: BLE001
                await db.rollback()
                logger.exception(
                    "auto_kernel_config_audit_firmware_safe: inner failed for %s",
                    firmware_id,
                )
    except Exception:  # noqa: BLE001
        logger.exception(
            "auto_kernel_config_audit_firmware_safe: outer failure for %s",
            firmware_id,
        )


__all__ = [
    "KERNEL_CONFIG_AUDIT_SCHEMA_VERSION",
    "_KSPP_RULES",
    "_LSM_FINDING",
    "_LSM_MAJOR_ALTERNATIVES",
    "_do_kernel_config_audit_run",
    "_normalize_kernel_config_audit_result",
    "_stamp_kernel_config_audit_result",
    "auto_kernel_config_audit_firmware_safe",
    "evaluate_kernel_config",
    "run_kernel_config_audit_background",
]
