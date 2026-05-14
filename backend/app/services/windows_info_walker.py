"""Windows.info walker (Phase λ.α.D — memory-forensic-godmode).

First Vol3-backed walker in the λ chain. Invokes Volatility 3's
``windows.info`` plugin against every ``memory_dump_image`` row whose
``os_family`` is ``"windows"`` OR ``"unknown"`` for a given firmware,
extracts kernel + ISF metadata from the 22-row plugin output, and
stamps:

- per-image ``kernel_hint`` + ``isf_profile_guess`` + ``last_walked_at``
  on ``MemoryDumpImage`` rows (table from λ.α.A);
- per-firmware aggregate ``windows_info_walk_result`` JSONB on
  ``Firmware`` (column from λ.α.D commit ``c5f6a7b8c9d0``).

The walker is a CLAUDE.md Rule #39 inner/outer/safe triplet:

- :func:`_do_windows_info_walk` — INNER pure-logic orchestrator.
  Caller owns ``db`` and the transaction. Resolves detection roots
  via :func:`app.services.firmware_paths.get_detection_roots`
  (Rule #16). Iterates ``MemoryDumpImage`` rows for the firmware,
  invokes :func:`app.services.vol3_runner.run_vol3_plugin` per image,
  persists per-image fields, returns the aggregate dict UNSTAMPED.
- :func:`run_windows_info_walk_background` — OUTER state-machine
  wrapper. Owns its own session via ``async_session_factory``,
  transitions ``firmware.windows_info_walk_status`` through
  ``idle → running → completed | failed``, stamps the aggregate via
  :func:`_stamp_firmware_windows_info_walk_result`. Failure
  persistence on a FRESH session because the inner session rolled
  back on the exception.
- :func:`auto_windows_info_walk_firmware_safe` — UNPACK-POST-DETECTION
  hook. Fire-and-forget; swallows all exceptions; does NOT mutate
  ``windows_info_walk_status`` (leaves ``idle`` so an operator-driven
  re-trigger via the future ``trigger_windows_info_walk`` MCP tool
  works without 409 conflict per Rule #33 .a).

Per CLAUDE.md Rule #5 sync-I/O wrap: the walker delegates the actual
Vol3 subprocess work to ``vol3_runner.run_vol3_plugin`` (already
async-native via ``asyncio.create_subprocess_exec``). No additional
executor wrap needed in this module — DB writes are async via
SQLAlchemy 2.0 async session.

Per CLAUDE.md Rule #16 detection_roots: the walker resolves
``get_detection_roots(firmware)`` to confirm the firmware has at least
one detection root — but the actual image enumeration uses the
``MemoryDumpImage`` rows persisted by the λ.α.B enumerator. Detection
roots are used only as a sanity check; the image rows ARE the
canonical source of "which memory images exist".

Per CLAUDE.md Rule #29 timeout: every per-image invocation gets the
default ``VOL3_PLUGIN_TIMEOUT_SECONDS = 600``. A firmware with 4
Windows images will take up to 4 × 600 = 2400 s wall-clock; this is
acceptable in the background-task context. The outer-wrapper runs as
``asyncio.create_task`` so the request thread is not blocked.

Per CLAUDE.md Rule #36 + #45: argv discipline + deny-list discipline
are enforced at the ``vol3_runner`` boundary; the walker MUST NOT
construct its own argv or shell out — only call
``run_vol3_plugin(plugin="windows.info")``.

Per CLAUDE.md Rule #33 .d (asyncio.create_task vs arq rubric): the
walker dispatches via ``asyncio.create_task`` because (i) the work is
in-process Python coordinated with subprocess-invocation of
trusted-binary parsing, (ii) per-image state is incrementally
persisted within the same outer task (mid-run crash recoverable via
re-run since the inner re-walks all qualifying images), and (iii)
"fire and observe via row-status" is sufficient. arq isn't needed —
the durable state IS the per-image rows + the firmware aggregate.
"""
from __future__ import annotations

import datetime as _dt
import logging
import time
import traceback
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.memory_dump_image import MemoryDumpImage
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_windows_info_walk_result,
)
from app.services.vol3_runner import (
    Vol3InvocationFailed,
    Vol3NotInstalled,
    Vol3PluginForbidden,
    Vol3Timeout,
    run_vol3_plugin,
)

logger = logging.getLogger(__name__)

# Per-firmware aggregate shape version. Bumped if/when the aggregate
# dict's shape changes in a way that would break a consumer.
_WINDOWS_INFO_WALK_RESULT_SCHEMA_VERSION: int = 1

# OS families the walker invokes Vol3 against. Raw acquisitions (no
# magic bytes) get classified as ``unknown`` by the λ.α.B enumerator;
# Vol3's automagic LayerStacker can still classify them at scan time,
# so we walk them. ``linux`` and ``mac`` images are out-of-scope for
# the windows.info plugin (it raises a plugin requirement error and
# the runner converts that to Vol3InvocationFailed which we record
# per-image).
_WALK_OS_FAMILIES: frozenset[str] = frozenset({"windows", "unknown"})


def _empty_aggregate() -> dict:
    """Default aggregate when no work was done."""
    return {
        "schema_version": _WINDOWS_INFO_WALK_RESULT_SCHEMA_VERSION,
        "image_count": 0,
        "classified_count": 0,
        "by_os_kernel_family": {
            "windows10": 0,
            "windows11": 0,
            "windows_server": 0,
            "unknown": 0,
        },
        "total_elapsed_s": 0.0,
        "errors_per_image": [],
    }


def _extract_variables(records: list[dict[str, Any]]) -> dict[str, str]:
    """Convert Vol3 windows.info's ``[{Variable: K, Value: V}, ...]``
    output into a flat ``{K: V}`` dict.

    Vol3's JsonRenderer emits records with ``TreeDepth`` + ``Variable``
    + ``Value`` keys. Values are always strings (the renderer
    stringifies bool / int / hex). Missing or malformed records are
    tolerated (Rule #11 boundary-defensive pattern).
    """
    out: dict[str, str] = {}
    for rec in records:
        name = rec.get("Variable")
        value = rec.get("Value")
        if not isinstance(name, str):
            continue
        if value is None:
            out[name] = ""
        else:
            out[name] = str(value)
    return out


def _derive_kernel_hint(variables: dict[str, str]) -> str | None:
    """Compose a human-readable kernel identifier from windows.info output.

    Example shapes:

    - ``Windows 10 (NT 10.0.19045) AMD64``
    - ``Windows 11 (NT 10.0.22631) AMD64``
    - ``Windows Server (NT 10.0.20348) AMD64``

    Returns ``None`` if the essential fields are absent (the image
    parsed but didn't classify — e.g. a Linux image walked under the
    ``os_family='unknown'`` policy).
    """
    nt_major = variables.get("NtMajorVersion")
    nt_minor = variables.get("NtMinorVersion")
    build_lab = variables.get("NTBuildLab", "")
    machine = variables.get("MachineType", "")
    product = variables.get("NtProductType", "")
    if not nt_major or not nt_minor:
        return None

    # Extract the build-number prefix from NTBuildLab
    # (e.g. ``19041.1.amd64fre.vb_release.191206-1406`` → ``19041``).
    build_number = build_lab.split(".")[0] if build_lab else ""
    nt_version_str = f"NT {nt_major}.{nt_minor}"
    if build_number:
        nt_version_str = f"{nt_version_str}.{build_number}"

    # Classify by NtProductType + build_number.
    if "Server" in product or "Lanman" in product:
        product_label = "Windows Server"
    elif build_number.isdigit() and int(build_number) >= 22000:
        product_label = "Windows 11"
    elif nt_major == "10":
        product_label = "Windows 10"
    elif nt_major == "6" and nt_minor == "3":
        product_label = "Windows 8.1"
    elif nt_major == "6" and nt_minor == "2":
        product_label = "Windows 8"
    elif nt_major == "6" and nt_minor == "1":
        product_label = "Windows 7"
    else:
        product_label = f"Windows NT {nt_major}.{nt_minor}"

    parts = [product_label, f"({nt_version_str})"]
    if machine:
        parts.append(machine)
    return " ".join(parts)


def _classify_os_kernel_family(variables: dict[str, str]) -> str:
    """Return the family bucket the image lands in for the aggregate."""
    nt_major = variables.get("NtMajorVersion")
    nt_minor = variables.get("NtMinorVersion")
    build_lab = variables.get("NTBuildLab", "")
    product = variables.get("NtProductType", "")
    build_number = build_lab.split(".")[0] if build_lab else ""

    if "Server" in product or "Lanman" in product:
        return "windows_server"
    if build_number.isdigit() and int(build_number) >= 22000:
        return "windows11"
    if nt_major == "10" and nt_minor == "0":
        return "windows10"
    return "unknown"


def _derive_isf_profile_guess(variables: dict[str, str]) -> str | None:
    """Extract the ISF bundle ID from the ``Symbols`` field.

    Vol3 emits a URL like
    ``file:///opt/wairz/vol3-symbols/windows/ntkrnlmp.pdb/<bundle_id>/<sha1>.json.xz``
    after a successful symbol-bundle match. We persist the segment
    just before the SHA1 — this is the canonical 16-char bundle ID
    that operators cross-reference against the
    ``volatility3-test-data`` release manifest.

    Returns the full ``Symbols`` value if no bundle ID can be parsed
    out — better partial-info than empty. Returns ``None`` if the
    field is absent entirely.
    """
    symbols = variables.get("Symbols")
    if not symbols:
        return None

    # Path-walk to find the bundle ID slot.
    parts = symbols.rstrip("/").split("/")
    # Trim trailing .json / .json.xz extension off the leaf for hashing
    # comparisons.
    if len(parts) >= 2:
        # Two segments before the leaf: pdb name and bundle id.
        bundle_segment = parts[-2]
        if bundle_segment and bundle_segment not in (
            "windows",
            "linux",
            "mac",
            "vol3-symbols",
        ):
            # Cap at 64 chars to match the column constraint
            # (`isf_profile_guess` is String(64)).
            return bundle_segment[:64]

    # Fallback — preserve the leaf so an operator can pivot.
    return symbols[:64]


async def _walk_one_image(
    db: AsyncSession,
    image: MemoryDumpImage,
) -> tuple[bool, float, str | None]:
    """Run windows.info against one image and persist the per-image fields.

    Returns ``(classified, elapsed_s, error_message)``. ``classified``
    is ``True`` when Vol3 returned a parseable kernel signature.

    Per Rule #33 .b: per-image kernel_hint + isf_profile_guess +
    last_walked_at are stamped on the image row directly (the row
    serves as the durable result store for the per-image slice; the
    firmware aggregate carries the rollup).
    """
    try:
        result = await run_vol3_plugin(
            image.image_path,
            "windows.info",
        )
    except Vol3PluginForbidden:
        # Re-raise; this is a programmer error (deny-list violation),
        # not a per-image data failure. Surfaces all the way out.
        raise
    except Vol3NotInstalled:
        # Re-raise; the caller is expected to detect this top-level
        # and abort the whole walk with a clear aggregate.
        raise
    except (Vol3Timeout, Vol3InvocationFailed) as exc:
        # Per-image failure — record + continue.
        msg = f"{image.image_filename}: {type(exc).__name__}: {exc}"[:512]
        logger.warning("windows_info_walk: %s", msg)
        return (False, 0.0, msg)

    variables = _extract_variables(result.records)
    kernel_hint = _derive_kernel_hint(variables)
    isf_guess = _derive_isf_profile_guess(variables)

    # Stamp the per-image fields. The row was loaded via the caller's
    # session so the field assignment is enough — flush at the end.
    if kernel_hint:
        image.kernel_hint = kernel_hint[:255]
    if isf_guess:
        image.isf_profile_guess = isf_guess
    image.last_walked_at = _dt.datetime.now(_dt.UTC)

    classified = kernel_hint is not None
    return (classified, result.elapsed_s, None)


async def _do_windows_info_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict:
    """INNER orchestrator — run windows.info against every qualifying image.

    Returns the per-firmware aggregate dict UNSTAMPED. Does NOT mutate
    ``firmware.windows_info_walk_status`` — that's the OUTER wrapper's
    job. Does NOT commit — the caller controls the transaction.

    Resolves detection_roots via Rule #16 helper to confirm the
    firmware has any extracted content; the actual image iteration
    uses the ``MemoryDumpImage`` rows persisted by the λ.α.B
    enumerator.
    """
    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        logger.warning(
            "windows_info_walk: firmware %s vanished pre-walk", firmware_id
        )
        return _empty_aggregate()

    aggregate = _empty_aggregate()
    t0 = time.monotonic()

    # Rule #16 sanity: even though the actual iteration uses
    # MemoryDumpImage rows, confirm the firmware has detection roots.
    # If get_detection_roots returns empty, the firmware never
    # populated its extracted tree and the λ.α.B enumerator can't have
    # produced any image rows either.
    detection_roots = await get_detection_roots(firmware, db=db, use_cache=True)
    if not detection_roots:
        aggregate["total_elapsed_s"] = round(time.monotonic() - t0, 3)
        return aggregate

    # Pull every memory_dump_image for this firmware whose os_family
    # is windows OR unknown.
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

    # Walk each image. Top-level Vol3NotInstalled aborts the entire
    # walk with a single aggregate error — no point retrying per
    # image when the binary's missing.
    for image in images:
        try:
            classified, elapsed_s, err = await _walk_one_image(db, image)
        except Vol3NotInstalled as exc:
            # Abort the loop, surface the install gap clearly.
            aggregate["errors_per_image"].append(
                f"Vol3 not installed — rebuild worker with INCLUDE_VOL3=1 "
                f"({exc})"
            )
            break
        aggregate["image_count"] += 1
        aggregate["total_elapsed_s"] += elapsed_s
        if err is not None:
            aggregate["errors_per_image"].append(err)
            continue
        if classified:
            aggregate["classified_count"] += 1
            # Re-extract variables for the classifier — cheap; avoids
            # threading the dict back through the helper return.
            # Stamp already persisted the kernel_hint; we re-derive
            # the family here without re-invoking Vol3.
            if image.kernel_hint:
                family = _family_from_kernel_hint(image.kernel_hint)
                aggregate["by_os_kernel_family"][family] = (
                    aggregate["by_os_kernel_family"].get(family, 0) + 1
                )

    await db.flush()
    aggregate["total_elapsed_s"] = round(aggregate["total_elapsed_s"], 3)
    logger.info(
        "windows_info_walk: firmware %s walked %d images "
        "(classified=%d, errors=%d) in %.2fs",
        firmware_id,
        aggregate["image_count"],
        aggregate["classified_count"],
        len(aggregate["errors_per_image"]),
        aggregate["total_elapsed_s"],
    )
    return aggregate


def _family_from_kernel_hint(kernel_hint: str) -> str:
    """Reverse the kernel_hint string into a family bucket.

    Cheaper than re-extracting variables — and the persisted
    kernel_hint IS the source of truth for the persisted family
    classification. Kept symmetrical with
    :func:`_classify_os_kernel_family`.
    """
    if "Windows Server" in kernel_hint:
        return "windows_server"
    if "Windows 11" in kernel_hint:
        return "windows11"
    if "Windows 10" in kernel_hint:
        return "windows10"
    return "unknown"


async def run_windows_info_walk_background(firmware_id: uuid.UUID) -> None:
    """OUTER state-machine wrapper (Rule #33 .a).

    Owns its own ``AsyncSession`` via :func:`async_session_factory`,
    transitions ``firmware.windows_info_walk_status`` through the 5
    states, stamps the aggregate via
    :func:`_stamp_firmware_windows_info_walk_result`. Failure
    persistence on a FRESH session.
    """
    try:
        async with async_session_factory() as db:
            firmware = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if firmware is None:
                return
            firmware.windows_info_walk_status = "running"
            firmware.windows_info_walk_started_at = _dt.datetime.now(_dt.UTC)
            firmware.windows_info_walk_error = None
            await db.commit()

            try:
                aggregate = await _do_windows_info_walk(db, firmware_id)
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
                            select(Firmware).where(
                                Firmware.id == firmware_id
                            )
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.windows_info_walk_status = "failed"
                        fail_row.windows_info_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.windows_info_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "windows_info_walk failed for firmware %s", firmware_id
                )
                return

            firmware.windows_info_walk_status = "completed"
            firmware.windows_info_walk_finished_at = _dt.datetime.now(_dt.UTC)
            firmware.windows_info_walk_result = (
                _stamp_firmware_windows_info_walk_result(aggregate)
            )
            await db.commit()
    except Exception:  # noqa: BLE001 — outermost guard; never crash the worker
        logger.exception(
            "unrecoverable error in run_windows_info_walk_background"
        )


async def auto_windows_info_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """UNPACK-POST-DETECTION hook — fire-and-forget walker (Rule #39).

    Owns its own session. Catches all exceptions. Does NOT mutate
    ``windows_info_walk_status`` — leaves ``idle`` so an
    operator-driven re-trigger via the future ``trigger_windows_info_walk``
    MCP tool (λ.δ) succeeds without a 409 conflict (Rule #33 .a).
    Stamps the aggregate so the operator can see the walk's result on
    page reload even without explicit triggering.
    """
    try:
        async with async_session_factory() as db:
            try:
                aggregate = await _do_windows_info_walk(db, firmware_id)
            except Exception:  # noqa: BLE001 — safe-runner swallows per Rule #39
                logger.exception(
                    "auto windows_info_walk failed for firmware %s",
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
            firmware.windows_info_walk_result = (
                _stamp_firmware_windows_info_walk_result(aggregate)
            )
            await db.commit()
    except Exception:  # noqa: BLE001 — outermost guard
        logger.exception(
            "unrecoverable error in auto_windows_info_walk_firmware_safe"
        )


__all__ = [
    "_do_windows_info_walk",
    "auto_windows_info_walk_firmware_safe",
    "run_windows_info_walk_background",
]
