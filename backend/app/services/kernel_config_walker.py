"""C1 generic kernel-config EXTRACTION walker.

This is the UPSTREAM extraction layer that GUARANTEES
``HardwareFirmwareBlob.metadata.kernel_config`` (and a firmware-level
``kernel_config_walk_result`` aggregate) is populated cross-packaging —
content-rescan, Android boot.img v0-v4, A/B OTA payload.bin CrAU, 6-codec
outer-envelope decompress, IKCFG extract, and a fallback ladder. It is
DISTINCT from the DOWNSTREAM ``linux_kernel_hardening_walker``, which
CONSUMES ``metadata.kernel_config`` and emits KSPP Findings — that walker
keeps consuming the metadata UNCHANGED; C1 back-fills the blob metadata
(read-modify-write, preserving pre-existing keys) so the hardening walker
fires on the next pass.

Problem this closes (R49-A / round46 phone evidence): the ``kernel_image``
parser only fires on a blob whose FILENAME matches zImage/uImage/vmlinuz/
Image AND whose magic the detector read. Android ``boot.img`` kernels
(carved into header/padding chunks where the kernel body is CONSUMED by
unblob), non-gzip-compressed kernels, and ``payload.bin``-packed kernels
produce ZERO ``kernel_config`` → the hardening walker silently audits
nothing (the phone firmware had 0 kernel blobs in DB).

Three functions per CLAUDE.md Rule #39 (inner/outer/safe triplet):

  - :func:`_do_kernel_config_run` — INNER pure-logic orchestrator.
    Caller owns the session + transaction. Resolves detection roots via
    ``get_detection_roots`` (Rule #16). Runs Stages A-F. Back-fills blob
    metadata. Returns the result aggregate UNSTAMPED (caller stamps via
    ``_stamp_firmware_kernel_config_walk_result``). Clears stale
    ``kernel_config_walk_result`` at entry.

  - :func:`run_kernel_config_walk_background` — OUTER Rule #33 .a state
    machine. Owns its own ``async_session_factory()``. Cycles
    ``queued → running → completed | failed``. Failure persistence on a
    FRESH session (inner session rolled back).

  - :func:`auto_kernel_config_walk_firmware_safe` — SAFE
    unpack-post-detection hook. Owns own session. Stamps the result so
    operators see the last-known result. Does NOT mutate
    ``kernel_config_walk_status`` (leaves it ``idle`` so an
    operator-triggered re-walk via ``trigger_kernel_config_walk`` MCP tool
    works without a 409 conflict).

**Rule #36 + Rule #45 PARSE-ONLY contract.** The walker reads +
decompresses the kernel AS DATA. It NEVER passes any extracted kernel to a
spawn primitive (``subprocess`` / ``os.system`` / ``exec`` / ``runpy`` /
etc.). The Stage-A original-archive re-extraction uses read-only
``zipfile`` (member-streaming, never ``extractall``, never writes into the
firmware tree). Test gate
``test_kernel_config_walker.py::test_walker_no_execute_no_decrypt``
enforces via tokenize-walk over this module + the 3 parser/decompress
modules; Rule #46 paired META-CANARY confirms the gate fires.

**Stage-A re-extraction (the auto-fire-fix) — GATED + TIME-BOXED.** When a
content-scan finds an ``ANDROID!`` header in a header-sized carved chunk
but no kernel body adjacent on disk, the inner runner falls back to
re-opening the original upload archive at ``firmware.storage_path`` and
pulling ONLY the ``boot.img`` member via read-only ``zipfile``. Gates
(R50.2 verdict): ZIP-only (``zipfile.is_zipfile``); bounded ``boot.img``-
entry heuristic; two size caps (≥256 MB member reject / 64 MB carved-
kernel cap); strictly read-only; degrade to ``live_device_recommended`` on
anything else.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os
import traceback
import uuid
import zipfile

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.schemas.finding import FindingCreate, Severity
from app.services.finding_service import FindingService
from app.services.firmware_paths import get_detection_roots
from app.services.hardware_firmware.parsers._kernel_ikconfig import (
    extract_ikconfig,
    find_linux_banner,
    parse_kernel_config_lines,
)
from app.services.hardware_firmware.parsers.android_boot_image import (
    carve_kernel,
    parse_boot_image,
)
from app.services.hardware_firmware.parsers.android_ota_payload import (
    classify_boot_partition,
    parse_payload_manifest,
)
from app.services.jsonb_normalizers import (
    _normalize_hardware_firmware_blobs_metadata,
    _stamp_firmware_kernel_config_walk_result,
    _stamp_hardware_firmware_blobs_metadata,
)
from app.services.kernel_decompress import decompress_kernel

logger = logging.getLogger(__name__)

# The ONE structural finding source C1 emits (the honest BLOCKED path).
# Closed allowlist gate (mirrors ICS) — if this constant ever drifts from
# the KernelConfigFindingSource Literal + the DB CHECK, the walker SKIPS
# emit rather than risking a FastAPI 422 on FindingService.create. The KSPP
# kernel_config_* sources stay the downstream hardening walker's job.
_EXTRACTION_BLOCKED_SOURCE = "kernel_config_extraction_blocked"

# ── Bounds (Rule #5 + Wave-2 attack D). ────────────────────────────────────
# Per-walk hard candidate cap — a pathological firmware with 10K+ files
# must not blow the wall-clock budget; remaining count is surfaced in
# ``errors``.
_MAX_CANDIDATES_PER_WALK = 4000
# Head-byte window read per candidate for the content signatures. The boot
# header + CrAU header are at offset 0; the IKCFG / banner markers can be
# deeper but a bare-on-disk vmlinux with IKCFG is read fully (capped) only
# when a head-signature matches.
_HEAD_BYTES = 64 * 1024
# Per-candidate full-read cap (bounded vmlinux / boot.img on disk).
_MAX_KERNEL_BYTES = 64 * 1024 * 1024  # 64 MB (matches kernel_image)
# A carved boot partition / boot.img member can be up to this; the kernel
# slice carved out of it is then re-capped at _MAX_KERNEL_BYTES (N2 — two
# distinct caps). 256 MB holds a v3 boot partition.
_MAX_BOOT_MEMBER_BYTES = 256 * 1024 * 1024  # 256 MB
# Min candidate size — sub-512-byte files are placeholders / device nodes.
_MIN_CANDIDATE_SIZE = 512
# Files larger than this on disk are not scanned for head signatures at the
# per-byte content level (kept bounded); a content candidate is only fully
# read up to _MAX_KERNEL_BYTES.
_MAX_CANDIDATE_SIZE_ON_DISK = _MAX_BOOT_MEMBER_BYTES

# Content signatures scanned in the head window (filename-INDEPENDENT —
# this is the load-bearing classification-by-content that finds the carved
# boot.img header chunk the filename classifier missed).
_SIG_ANDROID = b"ANDROID!"
_SIG_CRAU = b"CrAU"
_SIG_IKCFG = b"IKCFG_ST"
_SIG_BANNER = b"Linux version "
# Outer kernel-envelope magics at offset 0 (Stage D candidates).
_ENVELOPE_MAGICS_AT_0 = (
    b"\x1f\x8b",          # gzip
    b"\xfd7zXZ\x00",      # xz
    b"BZh",               # bz2
    b"\x28\xb5\x2f\xfd",  # zstd
    b"\x04\x22\x4d\x18",  # lz4 frame
    b"\x02\x21\x4c\x18",  # lz4 legacy
    b"\x5d\x00\x00",      # lzma-alone
)

# Stage-A re-extraction: ZIP entry-name heuristic (case-insensitive). Match
# `boot.img`, `boot_a.img`, `.../boot.img`, etc. — bounded to the first
# match; we do NOT extract every `.img`.
def _is_boot_img_entry(name: str) -> bool:
    base = os.path.basename(name).lower()
    return base == "boot.img" or (base.startswith("boot") and base.endswith(".img"))


# ── Sync filesystem helpers (Rule #5 — wrapped in run_in_executor). ─────────


def _iter_candidates_sync(root_path: str, max_count: int) -> list[tuple[str, int]]:
    """Walk a detection root for kernel candidates (sync, bounded).

    Returns ``[(path, size), ...]`` capped at ``max_count``. Filters by
    size only — filename is INTENTIONALLY ignored (Stage A finds carved
    boot.img header chunks like ``0-4096.unknown`` by content, not name).
    """
    candidates: list[tuple[str, int]] = []
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            if len(candidates) >= max_count:
                return candidates
            full = os.path.join(dirpath, filename)
            try:
                if os.path.islink(full):
                    continue
                size = os.path.getsize(full)
            except OSError:
                continue
            if size < _MIN_CANDIDATE_SIZE or size > _MAX_CANDIDATE_SIZE_ON_DISK:
                continue
            candidates.append((full, size))
    return candidates


def _read_head_sync(path: str, head_bytes: int) -> bytes | None:
    """Read up to ``head_bytes`` from the start of ``path`` (sync)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(head_bytes)
    except OSError:
        return None


def _read_full_sync(path: str, cap: int) -> bytes | None:
    """Read up to ``cap`` bytes from ``path`` (sync, bounded)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(cap)
    except OSError:
        return None


def _reextract_boot_img_from_zip_sync(
    storage_path: str,
) -> tuple[bytes | None, str | None]:
    """Stage-A re-extract: pull ONLY the boot.img member from the source ZIP.

    Read-only + bounded + ZIP-only (R50.2 gates). Returns
    ``(boot_img_bytes, note)``. ``boot_img_bytes`` is None when: the source
    isn't a readable ZIP, no boot.img-like member exists, or the member
    exceeds the 256 MB cap. ``note`` is a human-readable degrade reason.

    NEVER ``extractall``; NEVER writes into the firmware tree; streams a
    single member's bytes. Wrapped in ``run_in_executor`` by the caller.
    """
    if not storage_path or not os.path.isfile(storage_path):
        return None, "storage_path missing or not a file"
    if not zipfile.is_zipfile(storage_path):
        # Only ZIP is proven (R50.2 gate 1); tar/nested are future work.
        return None, "storage_path is not a ZIP (tar/nested re-extract not supported)"
    try:
        with zipfile.ZipFile(storage_path, "r") as zf:
            boot_member = None
            for info in zf.infolist():
                if _is_boot_img_entry(info.filename):
                    boot_member = info
                    break  # first match only — bounded
            if boot_member is None:
                return None, "no boot.img-like member in source ZIP"
            if boot_member.file_size > _MAX_BOOT_MEMBER_BYTES:
                return None, (
                    f"boot.img member {boot_member.file_size} bytes exceeds "
                    f"{_MAX_BOOT_MEMBER_BYTES} cap"
                )
            with zf.open(boot_member, "r") as fh:
                # Read at most the cap + 1 to detect a lying header.
                data = fh.read(_MAX_BOOT_MEMBER_BYTES + 1)
            if len(data) > _MAX_BOOT_MEMBER_BYTES:
                return None, "boot.img member stream exceeded cap mid-read"
            return data, f"reextracted {boot_member.filename} ({len(data)} bytes)"
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        return None, f"zip re-extract failed: {exc}"


# ── Pure-logic kernel-bytes → config-record helper. ────────────────────────


def _config_stats(config_map: dict[str, str]) -> dict[str, int]:
    """Tally a config map into {y, m, n, value} counts."""
    stats = {"y": 0, "m": 0, "n": 0, "value": 0}
    for v in config_map.values():
        if v == "y":
            stats["y"] += 1
        elif v == "m":
            stats["m"] += 1
        elif v == "n":
            stats["n"] += 1
        else:
            stats["value"] += 1
    return stats


def _module_mode(config_map: dict[str, str]) -> str:
    """Classify the module posture from =m count (the phone built 0 .ko →
    static_builtin; many =m → modular; mixed otherwise). The walker has no
    .ko-on-disk signal here, so this is a config-only heuristic feeding C2.
    """
    m_count = sum(1 for v in config_map.values() if v == "m")
    if m_count == 0:
        return "static_builtin"
    if m_count > 50:
        return "modular"
    return "mixed"


def _build_kernel_record_from_vmlinux(
    vmlinux: bytes,
    blob_path: str,
    source: str,
    compression: str,
) -> dict:
    """Run Stage E (IKCFG + banner) on a decompressed vmlinux; build the
    per-kernel result record. PURE — no DB, no I/O.

    On IKCFG success → ``extraction_status="ok"`` + the kernel_config dict.
    On IKCFG absent but banner present → ``fallback_banner_only``.
    On neither → ``live_device_recommended``.
    """
    banner_info = find_linux_banner(vmlinux) or {}
    banner = banner_info.get("banner")
    semver = banner_info.get("kernel_semver")

    record: dict = {
        "blob_path": blob_path,
        "source": source,
        "banner": banner,
        "kernel_semver": semver,
        "arch": "arm64" if banner and "aarch64" in banner else None,
        "compression": compression,
        "ikconfig_present": False,
        "config_entries": 0,
        "config_stats": {},
        "kernel_config": {},
        "module_mode": None,
        "extraction_status": None,
        "blocked_reason": None,
        "recommendation": None,
        "back_filled_blob_id": None,
    }

    config_text = extract_ikconfig(vmlinux)
    if config_text is not None:
        config_map = parse_kernel_config_lines(config_text)
        record["ikconfig_present"] = True
        record["config_entries"] = len(config_map)
        record["config_stats"] = _config_stats(config_map)
        record["kernel_config"] = config_map
        record["module_mode"] = _module_mode(config_map)
        record["extraction_status"] = "ok"
        # LOCALVERSION can refine the semver if no banner SemVer.
        if not semver:
            localver = config_map.get("CONFIG_LOCALVERSION", "").strip('"').strip()
            if localver:
                record["banner"] = record["banner"] or localver
    elif semver or banner:
        record["extraction_status"] = "fallback_banner_only"
    else:
        record["extraction_status"] = "live_device_recommended"
        record["recommendation"] = "adb shell zcat /proc/config.gz"

    return record


# ---------------------------------------------------------------------------
# INNER pure-logic walker (Rule #39).
# ---------------------------------------------------------------------------


async def _do_kernel_config_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict:
    """INNER pure-logic orchestrator (Stages A-F).

    Caller owns the session + transaction. Resolves detection roots
    (Rule #16). Content-rescans for kernel candidates, parses boot.img /
    payload.bin, decompresses the outer envelope, extracts IKCFG, and
    back-fills ``HardwareFirmwareBlob.metadata.kernel_config`` (read-
    modify-write, preserving pre-existing keys). Returns the result
    aggregate UNSTAMPED. Clears stale ``kernel_config_walk_result`` at
    entry.
    """
    walked_at = dt.datetime.now(dt.UTC).isoformat()

    firmware = await db.get(Firmware, firmware_id)
    if firmware is None:
        return _empty_aggregate(walked_at, [f"firmware {firmware_id} not found"])

    # Clear stale JSONB at entry (mirrors the ICS δ-mitigation).
    firmware.kernel_config_walk_result = None

    detection_roots = await get_detection_roots(firmware, db=db)
    if not detection_roots:
        return _empty_aggregate(
            walked_at,
            ["no detection_roots for firmware (extraction may have failed)"],
        )

    # Pre-load the firmware's blobs once — used to map a discovered kernel
    # path back to its originating HardwareFirmwareBlob for the metadata
    # back-fill. Keyed by realpath of blob_path for robust matching.
    blob_rows = (
        await db.execute(
            select(HardwareFirmwareBlob).where(
                HardwareFirmwareBlob.firmware_id == firmware_id
            )
        )
    ).scalars().all()
    blobs_by_realpath: dict[str, HardwareFirmwareBlob] = {}
    for b in blob_rows:
        if b.blob_path:
            try:
                blobs_by_realpath[os.path.realpath(b.blob_path)] = b
            except OSError:
                continue

    loop = asyncio.get_running_loop()
    kernels: list[dict] = []
    errors: list[str] = []
    defconfig_files: list[str] = []
    candidates_total = 0
    storage_path = firmware.storage_path

    # ── Stage A — content-rescan of detection roots. ──────────────────────
    for root_path in detection_roots:
        remaining = _MAX_CANDIDATES_PER_WALK - candidates_total
        if remaining <= 0:
            errors.append(
                f"reached _MAX_CANDIDATES_PER_WALK={_MAX_CANDIDATES_PER_WALK} "
                f"cap; later roots skipped"
            )
            break
        candidates = await loop.run_in_executor(
            None, _iter_candidates_sync, root_path, remaining,
        )
        for cand_path, size in candidates:
            candidates_total += 1
            head = await loop.run_in_executor(
                None, _read_head_sync, cand_path, _HEAD_BYTES,
            )
            if head is None:
                continue

            # Track defconfig-ish text files for the Stage-F fallback.
            base = os.path.basename(cand_path).lower()
            if base == "defconfig" or base.startswith("config-"):
                defconfig_files.append(cand_path)

            try:
                record = await _dispatch_candidate(
                    loop, cand_path, size, head, storage_path, errors,
                )
            except Exception as exc:  # noqa: BLE001 — per-candidate boundary
                errors.append(f"candidate {cand_path} raised: {exc}")
                continue
            if record is None:
                continue

            # Back-fill the originating blob's metadata (read-modify-write)
            # when we recovered a real config.
            if record["extraction_status"] == "ok" and record["kernel_config"]:
                origin = blobs_by_realpath.get(os.path.realpath(cand_path))
                if origin is not None:
                    _backfill_blob_metadata(origin, record)
                    record["back_filled_blob_id"] = str(origin.id)
            kernels.append(record)

    extracted_count = sum(1 for k in kernels if k["extraction_status"] == "ok")
    blocked_count = sum(1 for k in kernels if k["extraction_status"] == "blocked")
    live_device_recommended = any(
        k["extraction_status"] == "live_device_recommended" for k in kernels
    )

    # Emit ONE structural INFO finding per BLOCKED kernel (the honest
    # ff12d941 / undeterminable verdict). The KSPP hardening findings stay
    # the downstream linux_kernel_hardening_walker's job. Closed-allowlist
    # gated (mirrors ICS §SC5-NEW-ICS-S2-η) — never risk a 422.
    findings_emitted = 0
    blocked_kernels = [k for k in kernels if k["extraction_status"] == "blocked"]
    if blocked_kernels:
        findings_service = FindingService(db)
        for k in blocked_kernels:
            try:
                await findings_service.create(
                    project_id=firmware.project_id,
                    data=FindingCreate(
                        title="Kernel config extraction blocked (proprietary format)",
                        severity=Severity.info,
                        firmware_id=firmware_id,
                        source=_EXTRACTION_BLOCKED_SOURCE,
                        description=(
                            f"C1 kernel-config extraction could NOT recover the "
                            f".config for {k['blob_path']} — "
                            f"reason={k.get('blocked_reason')!r}. This is an HONEST "
                            f"'undeterminable, not proven-absent' verdict (Axiom 1): "
                            f"the kernel exists but its packaging "
                            f"({k.get('blocked_reason')}) is not standard-decodable. "
                            f"Recommendation: {k.get('recommendation')}. Kernel CVEs "
                            f"for this firmware fall through to version_not_affected "
                            f"/ unresolved rather than config_disabled. A future "
                            f"vendor-tool plugin (Rule #52 escape hatch + Rule #36 "
                            f"Exception-3 side-container) is the path if a licensed "
                            f"extractor appears — wairz does NOT bundle one."
                        ),
                    ),
                )
                findings_emitted += 1
            except Exception as exc:  # noqa: BLE001 — emit-boundary
                errors.append(
                    f"extraction-blocked finding emit failed for "
                    f"{k['blob_path']}: {exc}"
                )

    return {
        "walked_at": walked_at,
        "kernels": kernels,
        "fallback_evidence": {
            "defconfig_files": defconfig_files[:50],
            "live_device_recommended": live_device_recommended,
        },
        "kernels_found_count": len(kernels),
        "kernels_extracted_count": extracted_count,
        "kernels_blocked_count": blocked_count,
        "findings_emitted_count": findings_emitted,
        "errors": errors,
    }


async def _dispatch_candidate(
    loop,
    cand_path: str,
    size: int,
    head: bytes,
    storage_path: str | None,
    errors: list[str],
) -> dict | None:
    """Dispatch one candidate by content signature (Stages B-F).

    Returns a per-kernel record, or None when the candidate is not a
    kernel-bearing artefact.
    """
    # ── ANDROID! boot image → Stage B. ────────────────────────────────────
    if _SIG_ANDROID in head[:8]:
        return await _handle_boot_image(loop, cand_path, size, storage_path, errors)

    # ── CrAU payload.bin → Stage C. ───────────────────────────────────────
    if head[:4] == _SIG_CRAU:
        return await _handle_payload(loop, cand_path, size, errors)

    # ── Bare envelope magic at offset 0 → Stage D (compressed kernel). ────
    for magic in _ENVELOPE_MAGICS_AT_0:
        if head[: len(magic)] == magic:
            data = await loop.run_in_executor(
                None, _read_full_sync, cand_path, _MAX_KERNEL_BYTES,
            )
            if data is None:
                return None
            vmlinux, codec = decompress_kernel(data)
            if not vmlinux:
                # Compressed but undecodable (e.g. zstd_unavailable) OR not
                # a kernel — only record if it actually carries IKCFG/banner
                # after a no-op decompress; here vmlinux is empty so skip.
                return None
            record = _build_kernel_record_from_vmlinux(
                vmlinux, cand_path, "named_image", codec,
            )
            # Only surface if it's plausibly a kernel (IKCFG or banner).
            if record["extraction_status"] in ("ok", "fallback_banner_only"):
                return record
            return None

    # ── IKCFG_ST in head (decompressed-on-disk kernel) → Stage E. ─────────
    # ── OR Linux banner (bare vmlinux on disk) → Stage E/F. ───────────────
    if _SIG_IKCFG in head or _SIG_BANNER in head:
        data = await loop.run_in_executor(
            None, _read_full_sync, cand_path, _MAX_KERNEL_BYTES,
        )
        if data is None:
            return None
        record = _build_kernel_record_from_vmlinux(
            data, cand_path, "named_image", "none",
        )
        if record["extraction_status"] in ("ok", "fallback_banner_only"):
            return record
        return None

    return None


async def _handle_boot_image(
    loop,
    cand_path: str,
    size: int,
    storage_path: str | None,
    errors: list[str],
) -> dict | None:
    """Stage B — parse boot.img header, carve the kernel, decompress, IKCFG.

    When the carved chunk is header-only (the phone case where unblob
    consumed the kernel body), fall back to the Stage-A ZIP re-extract from
    ``storage_path``.
    """
    boot_head = await loop.run_in_executor(
        None, _read_full_sync, cand_path, _MAX_BOOT_MEMBER_BYTES,
    )
    if boot_head is None:
        return None
    layout = parse_boot_image(boot_head)
    if layout is None:
        return None

    kernel_slice = carve_kernel(boot_head, layout)
    source = "android_boot_v" + str(layout.header_version)

    if kernel_slice is None:
        # Header-only on disk — re-extract boot.img from the source archive.
        boot_bytes, note = await loop.run_in_executor(
            None, _reextract_boot_img_from_zip_sync, storage_path,
        )
        if note:
            errors.append(f"stage-A re-extract for {cand_path}: {note}")
        if boot_bytes is None:
            # Cannot recover the kernel body → live-device-recommended.
            return {
                "blob_path": cand_path,
                "source": "reextracted_upload",
                "banner": None,
                "kernel_semver": None,
                "arch": None,
                "compression": "none",
                "ikconfig_present": False,
                "config_entries": 0,
                "config_stats": {},
                "kernel_config": {},
                "module_mode": None,
                "extraction_status": "live_device_recommended",
                "blocked_reason": None,
                "recommendation": "adb shell zcat /proc/config.gz",
                "back_filled_blob_id": None,
            }
        re_layout = parse_boot_image(boot_bytes)
        if re_layout is None:
            return None
        kernel_slice = carve_kernel(boot_bytes, re_layout)
        layout = re_layout
        source = "reextracted_upload"
        if kernel_slice is None:
            return None

    # Re-cap the carved kernel (N2 — distinct from the boot-member cap).
    kernel_slice = kernel_slice[:_MAX_KERNEL_BYTES]
    vmlinux, codec = decompress_kernel(kernel_slice)
    if not vmlinux:
        errors.append(f"boot kernel decompress failed for {cand_path} (codec={codec})")
        return {
            "blob_path": cand_path,
            "source": source,
            "banner": None,
            "kernel_semver": None,
            "arch": None,
            "compression": codec,
            "ikconfig_present": False,
            "config_entries": 0,
            "config_stats": {},
            "kernel_config": {},
            "module_mode": None,
            "extraction_status": "fallback_banner_only" if codec.endswith(
                "_unavailable"
            ) else "live_device_recommended",
            "blocked_reason": None,
            "recommendation": "adb shell zcat /proc/config.gz",
            "back_filled_blob_id": None,
        }
    record = _build_kernel_record_from_vmlinux(vmlinux, cand_path, source, codec)
    # Annotate boot-header identity onto the record (Stage F fallback id).
    if layout.os_version:
        record.setdefault("android_os_version", layout.os_version)
    if layout.security_patch:
        record.setdefault("security_patch", layout.security_patch)
    return record


async def _handle_payload(
    loop,
    cand_path: str,
    size: int,
    errors: list[str],
) -> dict | None:
    """Stage C — parse CrAU payload.bin, classify boot ops.

    Standard ops → record the standard verdict (boot-partition reassembly
    is future work; we surface it as fallback_banner_only-equivalent with
    the boot identity). ff12d941 / non-standard → honest BLOCKED record.
    """
    data = await loop.run_in_executor(
        None, _read_full_sync, cand_path, _MAX_BOOT_MEMBER_BYTES,
    )
    if data is None:
        return None
    manifest = parse_payload_manifest(data)
    if manifest is None:
        return None
    verdict = classify_boot_partition(manifest)

    base_record: dict = {
        "blob_path": f"{cand_path}:boot",
        "source": "payload_bin",
        "banner": None,
        "kernel_semver": None,
        "arch": None,
        "compression": "none",
        "ikconfig_present": False,
        "config_entries": 0,
        "config_stats": {},
        "kernel_config": {},
        "module_mode": None,
        "extraction_status": None,
        "blocked_reason": verdict.blocked_reason,
        "recommendation": verdict.recommendation,
        "back_filled_blob_id": None,
    }

    if verdict.extraction_status == "blocked":
        base_record["extraction_status"] = "blocked"
        return base_record
    if verdict.extraction_status == "no_boot_partition":
        # No boot partition in this payload — not a kernel source.
        return None
    # standard ops: boot reassembly not implemented yet — surface honestly.
    base_record["extraction_status"] = "live_device_recommended"
    base_record["recommendation"] = (
        "payload.bin boot partition uses standard ops; boot reassembly + "
        "Stage-B carve is a future C1 enhancement. Use adb shell zcat "
        "/proc/config.gz in the interim."
    )
    return base_record


def _backfill_blob_metadata(blob: HardwareFirmwareBlob, record: dict) -> None:
    """Read-modify-write the blob's metadata to add kernel_config + identity.

    CRITICAL (R50.2 B2): the ``_stamp_*`` helper only stamps schema_version
    — it does NOT merge. We READ the existing metadata via
    ``_normalize_hardware_firmware_blobs_metadata``, SET the new keys, and
    REASSIGN the WHOLE attribute (JSONB dirty-tracking — in-place mutation
    won't flag the column dirty without MutableDict). Pre-existing keys
    (kernel_banner / kernel_semver / vendor / firmware_deps / etc.) SURVIVE.
    """
    meta = dict(_normalize_hardware_firmware_blobs_metadata(blob.metadata_))
    meta["kernel_config"] = dict(record["kernel_config"])
    meta["kernel_config_count"] = record["config_entries"]
    meta["ikconfig_present"] = True
    # Only set semver/banner when we have them AND the blob doesn't already
    # carry a (parser-populated) value — preserve the parser's authority.
    if record.get("kernel_semver") and not meta.get("kernel_semver"):
        meta["kernel_semver"] = record["kernel_semver"]
    if record.get("banner") and not meta.get("kernel_banner"):
        meta["kernel_banner"] = record["banner"]
    # Reassign the WHOLE attribute so SQLAlchemy flags the JSONB dirty.
    blob.metadata_ = _stamp_hardware_firmware_blobs_metadata(meta)


def _empty_aggregate(walked_at: str, errors: list[str]) -> dict:
    """Stable empty-result shape (firmware missing / no detection roots)."""
    return {
        "walked_at": walked_at,
        "kernels": [],
        "fallback_evidence": {"defconfig_files": [], "live_device_recommended": False},
        "kernels_found_count": 0,
        "kernels_extracted_count": 0,
        "kernels_blocked_count": 0,
        "findings_emitted_count": 0,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# OUTER state-machine wrapper (Rule #33 .a + Rule #39).
# ---------------------------------------------------------------------------


async def run_kernel_config_walk_background(firmware_id: uuid.UUID) -> None:
    """OUTER wrapper — owns the Rule #33 .a state machine + outer guard.

    Transitions ``firmware.kernel_config_walk_status``:
        queued (set by caller via MCP trigger)
          → running (this fn, on entry)
          → completed | failed (this fn, on exit)

    Failure persistence on a FRESH session (the inner session rolled back
    on the exception). On failure, ``kernel_config_walk_result`` is cleared.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                logger.warning(
                    "kernel_config_walk: firmware %s not found", firmware_id,
                )
                return
            firmware.kernel_config_walk_status = "running"
            firmware.kernel_config_walk_started_at = dt.datetime.now(dt.UTC)
            firmware.kernel_config_walk_error = None
            await db.commit()
            try:
                result = await _do_kernel_config_run(db, firmware_id)
                firmware.kernel_config_walk_status = "completed"
                firmware.kernel_config_walk_finished_at = dt.datetime.now(dt.UTC)
                firmware.kernel_config_walk_result = (
                    _stamp_firmware_kernel_config_walk_result(result)
                )
                await db.commit()
            except Exception as exc:
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.kernel_config_walk_status = "failed"
                        fail_row.kernel_config_walk_finished_at = dt.datetime.now(dt.UTC)
                        fail_row.kernel_config_walk_error = err
                        fail_row.kernel_config_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "kernel_config_walk: inner runner failed for %s", firmware_id,
                )
    except Exception:
        logger.exception(
            "kernel_config_walk: unrecoverable outer failure for %s", firmware_id,
        )


# ---------------------------------------------------------------------------
# SAFE unpack-post-detection hook (Rule #39 — never raises).
# ---------------------------------------------------------------------------


async def auto_kernel_config_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Auto-triggered post-detection hook (Rule #39 .safe contract).

    Owns own session. Runs the inner walker to populate the
    ``kernel_config_walk_result`` JSONB (and back-fill blob metadata) so
    operators see the last-known result even on the first upload. DOES NOT
    mutate ``kernel_config_walk_status`` — leaves it ``idle`` so an
    operator-triggered re-walk via ``trigger_kernel_config_walk`` MCP tool
    works without a 409 conflict.

    ORDERING (Rule #47): registered in walker_registry.WALKER_AUTO_TRIGGERS
    BEFORE ``auto_kernel_config_audit_firmware_safe`` so this back-fill
    precedes the downstream audit read (sequential dispatch).

    Swallows exceptions silently with structured ``logger.exception``.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                return
            try:
                result = await _do_kernel_config_run(db, firmware_id)
                firmware.kernel_config_walk_result = (
                    _stamp_firmware_kernel_config_walk_result(result)
                )
                # No status flip per Rule #39 .safe.
                await db.commit()
            except Exception:
                await db.rollback()
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.kernel_config_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "auto_kernel_config_walk_firmware_safe: inner failed for %s",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "auto_kernel_config_walk_firmware_safe: unrecoverable for %s",
            firmware_id,
        )


__all__ = [
    "_do_kernel_config_run",
    "auto_kernel_config_walk_firmware_safe",
    "run_kernel_config_walk_background",
]
