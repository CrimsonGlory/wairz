"""Phase β.8 — Authenticode batch-validation background runner.

Walks every PE binary registered in ``hardware_firmware_blobs`` for one
firmware, runs :func:`authenticode_service.verify_pe_file` per PE, and
persists one ``WindowsPESignature`` row per PE. Drives the 202+polling
``firmware.authenticode_chain_*`` status columns from Phase β.3 through
the Rule #33 contract: ``idle`` → ``queued`` → ``running`` →
``completed`` (success) or ``failed`` (unrecoverable error).

Design constraints (from the β.8 prompt + β.5/β.6/β.7 postmortem
recommendations):

1. **Verdict-spread persistence (β.5/β.6 postmortem rec #3).** The verdict
   ↔ ``WindowsPESignature`` mapping is encoded as a single
   :data:`DIRECT_MAPPED` frozenset. The runner constructs each row via
   ``WindowsPESignature(**{k: v for k, v in asdict(verdict).items()
   if k in DIRECT_MAPPED}, blob_id=blob.id)``. The drift-detector test
   imports the SAME frozenset, so β.8 + the test stay in sync as new
   verdict fields land in Phase γ/δ — single source of truth.
2. **Rule #7: NEVER share an AsyncSession across coroutines.** The outer
   runner :func:`run_authenticode_chain_background` owns its own session
   via ``async_session_factory()`` in an ``async with`` block; per-PE
   verification is sequential ``await`` calls inside that session, NOT
   ``asyncio.gather()``'d. Each blocking ``verify_pe_file`` invocation
   is offloaded to the default thread executor via
   ``loop.run_in_executor`` (Rule #5 — verify_pe_file is sync).
3. **Rule #33 status transitions.** ``idle`` → ``queued`` (set by the
   POST handler) → ``running`` (set on entry to the runner) →
   ``completed`` (success) | ``failed`` (exception). The aggregate
   result lands on ``firmware.authenticode_chain_result`` JSONB,
   schema-stamped by :func:`_stamp_firmware_authenticode_chain_result`
   so the column survives the canonical-shape gate.
4. **Per-PE error containment.** A single PE's ``verify_pe_file``
   exception does NOT abort the run. Per-PE failures are captured in the
   aggregate's ``errors`` list; the run still completes with
   ``status='completed'`` even if N PEs individually failed (those PEs
   land as ``chain_status='unknown'`` rows). Only a session-level error
   (DB unavailable, OOM, etc.) trips the outer ``failed`` path.
5. **Rule #19 evidence-first.** ``HardwareFirmwareBlob.blob_path`` is
   the absolute on-disk path (set by
   ``hardware_firmware/detector.py:_walk_and_classify`` from
   ``entry.path``); confirmed by grep before this module was authored.
   The MZ-magic pre-filter (:func:`_is_pe_file`) ensures we only spend
   signify cycles on actual PE binaries — the existing
   ``hardware_firmware/classifier.py`` does not classify PEs, so the
   blob set is dominated by ELF / MBN / DTB content the runner skips.
6. **Re-run idempotency.** Each run starts by DELETE-ing prior
   ``WindowsPESignature`` rows for the firmware's blobs. The CASCADE
   on ``WindowsPESignature.blob_id → hardware_firmware_blobs.id`` does
   not help here because the blobs themselves persist across runs —
   the explicit DELETE keeps the per-firmware row set fresh.

The runner is invoked via ``asyncio.create_task`` from the POST handler
(see ``routers/hardware_firmware.py``) so the 202 can return cleanly.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import traceback
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.windows_pe_signature import WindowsPESignature
from app.services.authenticode_service import verify_pe_file
from app.services.finding_service import FindingService
from app.services.jsonb_normalizers import (
    _stamp_firmware_authenticode_chain_result,
)


# Findings emitted by the runner per PE verdict. Used as the DELETE-scope
# filter for re-run idempotency (the runner DELETEs prior rows of these
# sources for the firmware before re-emitting), mirroring the existing
# WindowsPESignature DELETE. Mirrors the WindowsFindingSource Literal in
# ``app.schemas.finding`` and the ``ck_findings_source`` CHECK extension
# from alembic revision ``c5b6a7d8e9f0`` (Phase β.12a).
_RUNNER_FINDING_SOURCES: tuple[str, ...] = (
    "windows_authenticode",
    "windows_dbx_revoked",
)

logger = logging.getLogger(__name__)


# ── DIRECT_MAPPED — single source of truth for verdict ↔ ORM column mapping ──
#
# The set of ``AuthenticodeVerdict`` fields that map 1:1 onto
# ``WindowsPESignature`` columns. Read by the row-construction site below
# AND by ``test_authenticode_service.test_verdict_maps_to_windows_pe_signature_columns``
# (the drift-detector test) — see β.5/β.6 postmortem rec #3.
#
# Adding a new verdict field that should persist on the model:
#   1. Add it to ``AuthenticodeVerdict`` (services/authenticode_service.py).
#   2. Add it to ``WindowsPESignature`` (models/windows_pe_signature.py)
#      and write the alembic migration.
#   3. Add the field name to this frozenset.
# The drift-detector test will then pass (it asserts
# ``verdict_fields == DIRECT_MAPPED | indirect``); β.8 will spread the
# new field automatically.
DIRECT_MAPPED: frozenset[str] = frozenset({
    "signed",
    "chain_status",
    "signer_subject",
    "signer_issuer",
    "leaf_serial",
    "sig_hash_algo",
    "tsa_authority",
    "signed_at",
    "chain_json",
    "arch_view",
    "rich_header_json",
    "dbx_revoked",
    "dbx_revocation_kb",
})


# ── PE pre-filter ────────────────────────────────────────────────────────────


def _is_pe_file(path: str) -> bool:
    """Return ``True`` when ``path`` is a regular file whose first 2 bytes
    are ``b"MZ"`` (DOS / PE / NE / LX magic; the PE check that signify
    itself does inside ``AuthenticodeFile.from_stream``).

    Sync I/O — caller is responsible for offloading to a thread executor
    when invoked from an async context (Rule #5). Defensive against
    missing files, permission errors, and short reads.
    """
    try:
        if not os.path.isfile(path):
            return False
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


# ── Aggregate shape ──────────────────────────────────────────────────────────

# Histogram bucket order — mirrors the WindowsPESignature.chain_status CHECK
# constraint values. The runner pre-seeds every bucket to 0 so consumers
# can render a complete histogram even when no PE landed in that bucket.
_CHAIN_STATUS_BUCKETS: tuple[str, ...] = (
    "valid_at_signing",
    "valid_now",
    "revoked",
    "never_valid",
    "unknown",
)

# Cap per-PE error string length — protects the JSONB row size when a
# pathological PE produces a multi-KB stack trace. Mirrors the β.6
# _MAX_ENTRIES discipline (Pattern #3, β.5/β.6 patterns).
_MAX_ERROR_LEN: int = 500


def _verdict_to_signature_kwargs(verdict: Any) -> dict[str, Any]:
    """Spread ``verdict`` (an ``AuthenticodeVerdict`` dataclass) onto the
    kwargs accepted by ``WindowsPESignature(...)`` via :data:`DIRECT_MAPPED`.

    Decoupled from the row-construction site for testability (a unit test
    can assert this mapping without spinning a DB session).
    """
    return {k: v for k, v in asdict(verdict).items() if k in DIRECT_MAPPED}


# ── Heavy work: walk + verify + persist ──────────────────────────────────────


async def verify_firmware_pe_chain(
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> dict[str, Any]:
    """Iterate the firmware's hardware-firmware blobs, verify each PE, and
    persist one ``WindowsPESignature`` row per PE.

    Returns the aggregate result dict (un-stamped — the caller is
    responsible for ``_stamp_firmware_authenticode_chain_result``-ing
    it before persisting onto ``firmware.authenticode_chain_result``).

    The aggregate shape matches the Rule #35c normalizer documentation:

    .. code-block:: python

        {
            "signed_count": int,
            "signed_pct": float,        # signed_count / total_pe_count
            "unsigned_count": int,
            "dbx_revoked_count": int,
            "findings_emitted": int,    # Phase β.12c — Finding rows the
                                        # runner produced this run (sum of
                                        # windows_authenticode +
                                        # windows_dbx_revoked emissions)
            "by_chain_status": {        # complete histogram, all buckets
                "valid_at_signing": int, "valid_now": int,
                "revoked": int, "never_valid": int, "unknown": int,
            },
            "run_seconds": float,       # wall-clock duration
            "total_pe_count": int,      # PEs the runner identified
            "errors": [                 # per-PE error containment
                {"blob_path": str, "error": str},
                ...
            ],
        }

    Per-PE verification is sequential ``await`` calls (Rule #7) and runs
    blocking ``verify_pe_file`` work in the default thread executor
    (Rule #5). Per-PE failures are CAPTURED in ``errors`` and counted in
    the ``unknown`` bucket; the run completes with status='completed'
    regardless.

    Phase β.12c — additionally emits ``Finding`` rows for verdict-bearing
    chain_status / dbx_revoked outcomes via
    :meth:`FindingService.emit_pe_signature_findings`. Re-run idempotency
    extends to those Finding rows: prior ``windows_authenticode`` /
    ``windows_dbx_revoked`` findings for the firmware are DELETEd before
    re-emission, mirroring the WindowsPESignature DELETE.
    """
    started = time.monotonic()

    # Phase β.12c — derive project_id for the FindingService.create() path.
    # The outer runner already has fw in scope at the call site; SELECTing
    # again here keeps verify_firmware_pe_chain self-contained (it remains
    # callable with just (firmware_id, db) — see existing tests at
    # test_authenticode_chain_runner.py:228 etc.). Cost: one extra row
    # SELECT per run, dwarfed by the per-PE signify work that follows.
    fw = (
        await db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
    ).scalar_one_or_none()
    if fw is None:
        # The outer runner already guards on firmware presence + flips
        # status to "running" before calling us. If the row vanished
        # between then and now, return an empty-shaped aggregate so the
        # caller's stamp + persist still produces a well-formed JSONB.
        return {
            "signed_count": 0,
            "signed_pct": 0.0,
            "unsigned_count": 0,
            "dbx_revoked_count": 0,
            "findings_emitted": 0,
            "by_chain_status": {b: 0 for b in _CHAIN_STATUS_BUCKETS},
            "run_seconds": round(time.monotonic() - started, 3),
            "total_pe_count": 0,
            "errors": [],
        }
    project_id = fw.project_id

    # Re-run idempotency: drop any prior WindowsPESignature rows for this
    # firmware's blobs. The CASCADE on the FK does not fire on re-run
    # because the blobs themselves persist; the explicit DELETE keeps
    # the per-firmware row set fresh.
    blob_id_subq = select(HardwareFirmwareBlob.id).where(
        HardwareFirmwareBlob.firmware_id == firmware_id
    )
    await db.execute(
        delete(WindowsPESignature).where(
            WindowsPESignature.blob_id.in_(blob_id_subq)
        )
    )

    # Phase β.12c — Re-run idempotency for the runner-emitted Finding rows.
    # Scoped strictly by (firmware_id, source IN windows_*) so manual /
    # security-audit / SBOM findings on the same firmware are untouched.
    # The two source tags match _RUNNER_FINDING_SOURCES + the β.12a CHECK
    # extension; if the campaign adds further runner-emitted sources, both
    # _RUNNER_FINDING_SOURCES and the CHECK list need to grow in lockstep.
    await db.execute(
        delete(Finding).where(
            Finding.firmware_id == firmware_id,
            Finding.source.in_(_RUNNER_FINDING_SOURCES),
        )
    )
    await db.flush()

    blobs = (
        await db.execute(
            select(HardwareFirmwareBlob).where(
                HardwareFirmwareBlob.firmware_id == firmware_id
            )
        )
    ).scalars().all()

    loop = asyncio.get_event_loop()
    histogram: dict[str, int] = {b: 0 for b in _CHAIN_STATUS_BUCKETS}
    signed_count = 0
    unsigned_count = 0
    dbx_revoked_count = 0
    total_pe_count = 0
    errors: list[dict[str, str]] = []
    finding_service = FindingService(db)
    findings_emitted = 0

    for blob in blobs:
        path = blob.blob_path
        if not path:
            continue

        # Pre-filter: only PE files (MZ magic). Sync I/O via run_in_executor.
        is_pe = await loop.run_in_executor(None, _is_pe_file, path)
        if not is_pe:
            continue

        total_pe_count += 1

        # Per-PE error containment (constraint #5): a single failed
        # verify_pe_file does NOT abort the run. The verdict's own four
        # return paths already swallow most failure modes (OSError,
        # generic Exception); this outer guard catches the few left
        # (e.g. an exception leaking out of the executor itself).
        try:
            verdict = await loop.run_in_executor(None, verify_pe_file, path)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "authenticode chain: verify_pe_file raised on %s: %r",
                path, exc,
            )
            err_msg = f"{exc.__class__.__name__}: {exc}"[:_MAX_ERROR_LEN]
            errors.append({"blob_path": path, "error": err_msg})
            histogram["unknown"] += 1
            unsigned_count += 1
            continue

        # Persist one row per PE — verdict spread via DIRECT_MAPPED.
        sig = WindowsPESignature(
            **_verdict_to_signature_kwargs(verdict),
            blob_id=blob.id,
        )
        db.add(sig)
        # Per-PE flush: partial progress survives a session-level abort
        # mid-run (the outer runner's failed-path branch only updates
        # firmware status; previously-flushed sig rows stay).
        await db.flush()

        # Phase β.12c — Emit verdict-bearing Findings (windows_authenticode +
        # windows_dbx_revoked) atomically with the WindowsPESignature
        # row. The helper internally calls FindingService.create() which
        # uses db.flush() (Rule #3); both row sets land in the same
        # session.
        emitted = await finding_service.emit_pe_signature_findings(
            project_id=project_id,
            firmware_id=firmware_id,
            blob_path=path,
            signed=verdict.signed,
            chain_status=verdict.chain_status,
            dbx_revoked=verdict.dbx_revoked,
            leaf_serial=verdict.leaf_serial,
            signer_subject=verdict.signer_subject,
            dbx_revocation_kb=verdict.dbx_revocation_kb,
        )
        findings_emitted += len(emitted)

        # Aggregate.
        if verdict.signed:
            signed_count += 1
        else:
            unsigned_count += 1
        if verdict.dbx_revoked:
            dbx_revoked_count += 1
        bucket = verdict.chain_status if verdict.chain_status in histogram else "unknown"
        histogram[bucket] = histogram.get(bucket, 0) + 1

        # The verdict's own ``error`` field is informational — the
        # verdict itself didn't raise, but verify_pe_file caught a
        # non-fatal parse / read failure. Surface it in errors so the
        # operator can see it; the run itself is still successful.
        if verdict.error:
            errors.append({
                "blob_path": path,
                "error": verdict.error[:_MAX_ERROR_LEN],
            })

    elapsed = time.monotonic() - started
    signed_pct = (signed_count / total_pe_count) if total_pe_count else 0.0

    return {
        "signed_count": signed_count,
        "signed_pct": round(signed_pct, 4),
        "unsigned_count": unsigned_count,
        "dbx_revoked_count": dbx_revoked_count,
        "findings_emitted": findings_emitted,
        "by_chain_status": histogram,
        "run_seconds": round(elapsed, 3),
        "total_pe_count": total_pe_count,
        "errors": errors,
    }


# ── Outer runner: own session + status transitions ───────────────────────────


async def run_authenticode_chain_background(firmware_id: uuid.UUID) -> None:
    """Detached authenticode-chain runner.

    Owns its own ``AsyncSession`` so the FastAPI request that returned
    the 202 ack can close cleanly. Mirrors ``_run_cve_match_background``
    and ``_run_unpack_background``.

    State machine (Rule #33):

    - On entry: flips ``authenticode_chain_status`` from ``queued`` →
      ``running`` and clears prior result/error.
    - On clean return: persists the schema-stamped aggregate via
      :func:`_stamp_firmware_authenticode_chain_result` and flips
      status to ``completed``.
    - On exception (session-level — DB unavailable, OOM, etc.): rolls
      back the run-time session, opens a fresh session to record
      ``failed`` + the truncated traceback so the UI poller sees the
      error.

    Per-PE failures are NOT routed here; they're contained inside
    :func:`verify_firmware_pe_chain` per design constraint #5.
    """
    started = datetime.now(timezone.utc)
    try:
        async with async_session_factory() as db:
            try:
                # Mark running. Use a fresh select so we don't carry over
                # any stale ORM state from the request session that
                # queued the job.
                fw = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one_or_none()
                if fw is None:
                    logger.warning(
                        "authenticode-chain background: firmware %s vanished",
                        firmware_id,
                    )
                    return
                fw.authenticode_chain_status = "running"
                fw.authenticode_chain_started_at = started
                fw.authenticode_chain_finished_at = None
                fw.authenticode_chain_error = None
                fw.authenticode_chain_result = None
                await db.commit()

                # Heavy work — sequential per-PE verification + persistence.
                aggregate = await verify_firmware_pe_chain(firmware_id, db)
                # The persist site stamps schema_version per Rule #35c.
                stamped = _stamp_firmware_authenticode_chain_result(dict(aggregate))

                fw = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one_or_none()
                if fw is None:
                    return
                fw.authenticode_chain_status = "completed"
                fw.authenticode_chain_finished_at = datetime.now(timezone.utc)
                fw.authenticode_chain_result = stamped
                fw.authenticode_chain_error = None
                await db.commit()
                logger.info(
                    "authenticode-chain background: firmware %s completed "
                    "(pe=%d signed=%d unsigned=%d dbx_revoked=%d "
                    "findings=%d errs=%d)",
                    firmware_id,
                    aggregate["total_pe_count"],
                    aggregate["signed_count"],
                    aggregate["unsigned_count"],
                    aggregate["dbx_revoked_count"],
                    aggregate["findings_emitted"],
                    len(aggregate["errors"]),
                )
            except Exception as exc:
                await db.rollback()
                # Best-effort failure persistence on a fresh session — the
                # rolled-back one can't be reused after rollback invalidates
                # its state, and we still want the row to carry the error
                # for the UI poller. Mirror cve-match's failure handling.
                err_summary = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_fw = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_fw is not None:
                        fail_fw.authenticode_chain_status = "failed"
                        fail_fw.authenticode_chain_finished_at = datetime.now(
                            timezone.utc
                        )
                        fail_fw.authenticode_chain_error = err_summary
                        await fail_db.commit()
                logger.exception(
                    "authenticode-chain background: firmware %s failed",
                    firmware_id,
                )
    except Exception:
        # Outer guard — never let the event loop crash on a background
        # job. A DB unavailability mid-run lands here.
        logger.exception(
            "authenticode-chain background: unrecoverable error for firmware %s",
            firmware_id,
        )
