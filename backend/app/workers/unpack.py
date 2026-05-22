"""Firmware unpacking orchestrator with adaptive fallback chain.

Strategy: try format-specific fast paths first, then fall back through
generic extractors (binwalk → unblob) until one succeeds.

Delegates to specialized modules:
- unpack_common: classification, filesystem detection, shared utilities
- unpack_linux: architecture detection, kernel detection, tar handling
- unpack_android: OTA extraction, sparse images, super.img partitions
"""

import asyncio
import logging
import os
import uuid

from app.workers.unpack_android import _extract_android_ota, _extract_boot_img  # noqa: F401

# Re-export public API for backward compatibility
from app.workers.unpack_common import (  # noqa: F401
    UnpackResult,
    _find_binwalk_output_dir,
    check_extraction_limits,
    classify_firmware,
    cleanup_unblob_artifacts,
    convert_intel_hex_to_binary,
    find_filesystem_root,
    remove_extraction_escape_symlinks,
    run_binwalk_extraction,
    run_uefi_extraction,
    run_unblob_extraction,
)
from app.workers.unpack_linux import (  # noqa: F401
    _firmware_tar_filter,
    check_tar_bomb,
    detect_architecture,
    detect_architecture_from_elf,
    detect_architecture_from_kernel,
    detect_kernel,
    detect_os_info,
)

logger = logging.getLogger(__name__)


# Cross-firmware walker fan-out concurrency bound (Rule #51 §SC5-NEW-SBOM-θ).
# Within a single `_run_hardware_firmware_detection_safe` call the registered
# walker safe-runners iterate sequentially (Rule #7-compliant — each runner
# owns its own ``async_session_factory()`` session, but sequential dispatch
# avoids the "gather coroutines that secretly share OUR session" trap). Across
# firmware uploads though, multiple `_run_hardware_firmware_detection_safe`
# coroutines may run in parallel (the upload endpoint spawns one per firmware
# via ``asyncio.create_task``). A bare burst of 5 simultaneous bare-metal
# uploads × 27 walkers × short-lived sessions could spike the DB connection
# pool — this semaphore caps cross-firmware walker fan-out at 6 in-flight,
# leaving headroom for unrelated HTTP traffic against the 40-connection pool.
#
# N=6 chosen (bumped from 4 on 2026-05-22): ~15% of pool=40 (Rule #51 .iv
# DB-pool-headroom math), matches the new arq max_jobs=6 envelope so a single
# fully-saturated arq worker doesn't queue the semaphore on its own jobs.
# Still well above typical single-operator triage cadence (~1 upload at a
# time), avoids the §SC5-NEW-SBOM-θ "5 firmware × 27 walkers" detonation case
# while keeping per-firmware fan-out latency under a second when slots free.
_WALKER_FANOUT_SEMAPHORE = asyncio.Semaphore(6)


# Sibling directory names that indicate extracted_path is ONE partition
# inside a multi-partition Android container; we walk the parent to cover
# all partitions (vendor, system, odm, etc.) in a single pass.
_ANDROID_PARTITION_SIBLINGS = frozenset({
    "vendor", "system", "odm", "product", "system_ext", "boot",
    "vendor_boot", "init_boot", "modem", "firmware",
})


def _pick_detection_root(extracted_path: str) -> str:
    """Walk the parent directory when extracted_path is one partition in a
    multi-partition Android layout.  Otherwise return extracted_path as-is.
    """
    try:
        parent = os.path.dirname(extracted_path.rstrip("/"))
        if not parent or parent == extracted_path:
            return extracted_path
        siblings = {e.name for e in os.scandir(parent) if e.is_dir(follow_symlinks=False)}
    except OSError:
        return extracted_path
    # Treat as multi-partition if we see Android partition-style siblings
    # or multiple "partition_*_erofs" entries.
    partition_like = sum(1 for s in siblings if s.startswith("partition_"))
    if partition_like >= 2 or (siblings & _ANDROID_PARTITION_SIBLINGS):
        return parent
    return extracted_path


async def _run_hardware_firmware_detection_safe(
    firmware_id: uuid.UUID, extracted_path: str,
) -> None:
    """Post-extraction detection + graph build. Own sessions; fire-and-forget.

    Detection and graph build each use an independent AsyncSession (per
    CLAUDE.md rule 7 — never share an AsyncSession across concurrency
    boundaries).  The graph build is skipped when detection produced no
    blobs.

    Detection delegates to ``get_detection_roots`` (via
    ``detect_hardware_firmware`` with ``walk_roots=None``) to discover
    every sibling partition dir. The legacy ``_pick_detection_root``
    above is kept for other call paths; this detection call no longer
    needs it.
    """
    from app.database import async_session_factory
    from app.services.hardware_firmware import detect_hardware_firmware
    from app.services.hardware_firmware.graph import build_driver_firmware_graph

    count = 0
    try:
        async with async_session_factory() as db:
            # walk_roots=None → detector fetches the Firmware row and
            # resolves every detection root (rootfs, scatter dirs, etc.).
            count = await detect_hardware_firmware(firmware_id, db)
            await db.commit()
            logger.info("Hardware firmware detection complete: %d blobs", count)
    except Exception:
        # Detection failed — still proceed to walker fan-out so forensic
        # walkers (registry hive / EVTX / journald / systemd / bare-metal
        # MCU audit / …) get their shot. The walker safe-runners use
        # ``get_detection_roots(firmware)`` per Rule #16 to filter targets;
        # firmware without HW blobs but WITH a rootfs still yields useful
        # walker output (Linux artefacts, BCD, EVTX, …). Pre-2026-05-21
        # Fix #3 this `return` short-circuited the whole pipeline — 25+
        # walkers silently skipped cluster-wide per Scout C's live-DB probe.
        logger.warning("Hardware firmware detection failed", exc_info=True)

    # Driver-firmware graph build — STAYS gated on count > 0 because the
    # graph operates over the persisted hardware_firmware_blob rows
    # detection just emitted. With zero blobs, the graph is empty by
    # construction; skipping the build saves a session round-trip.
    if count > 0:
        try:
            async with async_session_factory() as db:
                result = await build_driver_firmware_graph(firmware_id, db)
                await db.commit()
                logger.info(
                    "Hardware firmware graph: %d edges, %d unresolved",
                    len(result.edges),
                    result.unresolved_count,
                )
        except Exception:
            logger.warning("Hardware firmware graph build failed", exc_info=True)

    # Walker auto-trigger registry — registry_hive (γ.4), driver_extractor
    # (γ.5), evtx (ε.1.b.4), AppCompat (κ.B), BCD (θ.A), DPAPI (κ.D),
    # EFS (ι.D), ESP (θ.C), ETL (ι.C), journald (ι.A), linux_persistence
    # (κ.C), LNK (η.D), MBR/VBR (θ.B), MFT (η.A), prefetch (ζ.2),
    # scheduled_task (η.E), SDB (θ.D), SRUM (ζ.3), systemd (ι.B),
    # USN journal (κ.E), WMI (η.C), container (ι.E).
    #
    # Rule #36 no-execute discipline: every safe-runner is parse-only —
    # nothing in wairz invokes rundll32 / cscript / wmic / wine / mono /
    # wevtutil / Get-WinEvent / regedit / .reg apply / any scriptable
    # primitive against extracted firmware contents.
    #
    # Each safe-runner owns its own AsyncSession via async_session_factory(),
    # swallows exceptions silently, and DOES NOT mutate the
    # firmware's per-walker ``*_walk_status`` column — those stay ``idle``
    # so an operator-triggered re-walk via the corresponding
    # ``trigger_*_walk`` MCP tool succeeds without a 409 conflict
    # (Rule #39 .safe semantics).
    #
    # Registry lives at app.workers.walker_registry.WALKER_AUTO_TRIGGERS;
    # adding a new walker is a one-line addition there. Iterated
    # sequentially (not gathered) because each safe-runner opens its own
    # AsyncSession + Rule #7 forbids gathering coroutines that share a
    # session — sequential ``await`` keeps the contract.
    #
    # Wrapped in ``_WALKER_FANOUT_SEMAPHORE`` (Rule #51 §SC5-NEW-SBOM-θ) so a
    # burst of N firmware uploads can't run N concurrent fan-outs unbounded —
    # the semaphore caps cross-firmware walker work at 4 in-flight, leaving
    # DB pool headroom for unrelated traffic. Pre-2026-05-21 Fix #3 this
    # block was gated by ``if count <= 0: return`` above — bare-metal and
    # other zero-HW-blob firmware never got their walker fan-out, leaving
    # forensic artefacts undiscovered cluster-wide.
    from app.workers.walker_registry import get_walker_auto_triggers
    async with _WALKER_FANOUT_SEMAPHORE:
        for safe_runner in get_walker_auto_triggers():
            try:
                await safe_runner(firmware_id)
            except Exception:
                logger.warning(
                    "walker auto-trigger %s failed",
                    getattr(safe_runner, "__qualname__", repr(safe_runner)),
                    exc_info=True,
                )


def _analyze_filesystem(result: UnpackResult, extraction_dir: str) -> None:
    """Post-extraction analysis: find root, detect arch/OS/kernel."""
    fs_root = find_filesystem_root(extraction_dir)
    if not fs_root:
        result.error = "Could not locate filesystem root in extracted contents"
        return

    result.extracted_path = fs_root

    fs_root_real = os.path.realpath(fs_root)
    extraction_dir_real = os.path.realpath(extraction_dir)
    if fs_root_real != extraction_dir_real:
        binwalk_dir = _find_binwalk_output_dir(
            fs_root_real, extraction_dir_real
        )
        # Only set extraction_dir if the binwalk output dir contains
        # meaningful sibling content (other roots, large files).
        # For deep unblob extractions where the rootfs is nested many
        # levels down, showing raw intermediary files is confusing.
        if binwalk_dir:
            result.extraction_dir = binwalk_dir

    arch, endian = detect_architecture(fs_root)
    if arch is None:
        # Fallback: rootfs has no ELFs (encrypted payloads, MCU-only images).
        # Walk sibling extraction trees for a kernel image header we can
        # fingerprint — this is the only arch signal when rootfs is opaque.
        parent = os.path.dirname(extraction_dir.rstrip("/"))
        arch, endian = detect_architecture_from_kernel(
            [d for d in (extraction_dir, parent) if d],
        )
    result.architecture = arch
    result.endianness = endian
    result.os_info = detect_os_info(fs_root)
    result.kernel_path = detect_kernel(extraction_dir, fs_root)
    result.success = True


def _analyze_uefi_extraction(result: UnpackResult, extraction_dir: str) -> None:
    """Post-extraction analysis for UEFI firmware.

    UEFI firmware doesn't have a Linux filesystem root. Instead, UEFIExtract
    produces a .dump/ directory with the firmware hierarchy. We treat the
    .dump/ directory as the "extracted path" and detect architecture from
    PE32+ DXE driver binaries.
    """
    # Find the .dump directory created by UEFIExtract
    dump_dir = None
    for entry in os.scandir(extraction_dir):
        if entry.is_dir() and entry.name.endswith(".dump"):
            dump_dir = entry.path
            break

    if not dump_dir:
        result.error = "UEFIExtract produced no output"
        return

    result.extracted_path = dump_dir
    result.extraction_dir = extraction_dir

    # Detect architecture from PE32+ DXE driver bodies
    arch, endian = _detect_uefi_architecture(dump_dir)
    result.architecture = arch
    result.endianness = endian

    # Count extracted components for OS info
    component_count = 0
    for _root, _dirs, files in os.walk(dump_dir):
        component_count += len(files)
    result.os_info = f"UEFI/BIOS firmware ({component_count} extracted components)"
    result.success = True


def _detect_uefi_architecture(dump_dir: str) -> tuple[str | None, str | None]:
    """Detect architecture from PE32+ body.bin files in UEFIExtract output."""
    # PE machine type constants
    pe_machines = {
        0x014C: ("x86", "little"),
        0x8664: ("x86_64", "little"),
        0xAA64: ("aarch64", "little"),
        0x01C0: ("arm", "little"),
        0x01C4: ("arm", "little"),  # ARMv7 Thumb
    }

    for root, _dirs, files in os.walk(dump_dir):
        if "body.bin" not in files:
            continue
        body_path = os.path.join(root, "body.bin")
        try:
            with open(body_path, "rb") as f:
                magic = f.read(2)
                if magic != b"MZ":
                    continue
                # Read PE header offset at 0x3C
                f.seek(0x3C)
                pe_offset_bytes = f.read(4)
                if len(pe_offset_bytes) < 4:
                    continue
                pe_offset = int.from_bytes(pe_offset_bytes, "little")
                f.seek(pe_offset)
                pe_sig = f.read(4)
                if pe_sig != b"PE\x00\x00":
                    continue
                machine = int.from_bytes(f.read(2), "little")
                if machine in pe_machines:
                    return pe_machines[machine]
        except OSError:
            continue
    return None, None


async def unpack_firmware(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,
) -> UnpackResult:
    """Orchestrate the full unpacking pipeline with adaptive fallback.

    Pipeline:
    1. Classify firmware type
    2. Try format-specific fast path (Android, tar, ELF)
    3. If fast path fails or format is unknown, run fallback chain:
       binwalk (600s) → unblob (1200s)
    4. Post-extraction: find filesystem root, detect architecture/OS/kernel

    Args:
        progress_callback: Optional async callable(stage: str, progress: int)
            called at key pipeline stages to report progress (0-100).
        firmware_id: If provided, schedules a post-extraction hardware firmware
            detection task (fire-and-forget) after a successful extraction.
    """
    result = await _unpack_firmware_inner(
        firmware_path, output_base_dir, progress_callback,
    )
    # NOTE: hardware-firmware detection is NOT spawned here — it runs a
    # concurrent DB session that can race with the caller's commit and
    # silently clobber vendor_decryption / detection_roots in
    # ``firmware.device_metadata`` (last-writer-wins on the whole JSONB
    # dict). Callers (arq_worker.unpack_firmware_job,
    # routers/firmware._run_unpack_background) MUST fire the detection
    # task via ``_run_hardware_firmware_detection_safe`` only AFTER
    # their own ``db.commit()``.
    return result


async def _unpack_firmware_inner(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
) -> UnpackResult:
    """Internal unpack body (see unpack_firmware for docs)."""
    import shutil
    import tarfile as _tarfile

    async def _report(stage: str, progress: int) -> None:
        if progress_callback:
            try:
                await progress_callback(stage, progress)
            except Exception:
                pass  # Never let progress reporting break extraction

    result = UnpackResult()
    extraction_dir = os.path.join(output_base_dir, "extracted")
    loop = asyncio.get_running_loop()

    # Clean leftover data from previous failed attempts so retries work cleanly.
    # The rmtree+makedirs reset is a single sync helper offloaded via
    # run_in_executor so the unpack orchestrator doesn't stall the worker
    # event loop on a large stale tree (Rule #5).
    def _reset_extraction_dir_sync(target: str) -> None:
        if os.path.exists(target):
            shutil.rmtree(target, ignore_errors=True)
        os.makedirs(target, exist_ok=True)

    await loop.run_in_executor(None, _reset_extraction_dir_sync, extraction_dir)

    # Check disk space: need at least 2x firmware size for extraction headroom.
    # The getsize + disk_usage probe is a single sync helper executor hop.
    # ``fw_size`` is also used downstream by ``check_extraction_limits`` (Stage 1
    # branches at lines below) and the standalone-binary-fallback gating
    # (Stage 2 exhausted path). Bail with a clear error if the source file
    # can't be stat'd — otherwise downstream references to ``fw_size`` would
    # raise NameError (regression caught 2026-05-13 on Moto-G32 retry; the
    # rename ``fw_size`` → ``fw_size_check`` in commit ``a83fa14`` 2026-05-11
    # was incomplete — only the disk-headroom block was updated, leaving 6
    # downstream references broken).
    def _disk_headroom_sync(fw_path: str, dest: str) -> tuple[int, int] | None:
        try:
            return os.path.getsize(fw_path), shutil.disk_usage(dest).free
        except OSError:
            return None

    sizes = await loop.run_in_executor(
        None, _disk_headroom_sync, firmware_path, extraction_dir,
    )
    if sizes is None:
        result.error = (
            f"Cannot stat firmware file: {firmware_path}. "
            "Source file may have been deleted or permissions changed."
        )
        result.unpack_log = result.error
        return result
    fw_size, free_space = sizes
    if free_space < fw_size * 2:
        result.error = (
            f"Insufficient disk space: {free_space // (1024*1024)}MB free, "
            f"need ~{fw_size * 2 // (1024*1024)}MB for extraction"
        )
        result.unpack_log = result.error
        return result

    await _report("Classifying firmware", 5)
    fw_type = classify_firmware(firmware_path)
    result.unpack_log = f"Firmware classified as: {fw_type}\n"
    await _report(f"Classified as {fw_type}", 10)

    # === STAGE 1: Format-Specific Fast Paths ===

    if fw_type == "android_apk":
        import shutil
        await _report("Standalone APK detected — preserving for scan", 15)
        apk_name = os.path.basename(firmware_path)
        if not apk_name.lower().endswith(".apk"):
            apk_name += ".apk"
        dest = os.path.join(extraction_dir, apk_name)
        shutil.copy2(firmware_path, dest)
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir
        result.success = True
        result.unpack_log += (
            f"Standalone APK: copied as {apk_name}.\n"
            "Use Security > APK Scan to analyze.\n"
        )
        await _report("APK ready for scanning", 100)
        return result

    if fw_type == "uefi_firmware":
        await _report("Extracting UEFI firmware", 15)
        try:
            # If it's a ZIP containing UEFI, extract inner file first. The
            # zipfile reads + the open() write are all blocking I/O; route
            # through a single sync helper executor hop (Rule #5).
            import zipfile as _zipfile

            def _extract_inner_uefi_sync(zip_path: str, out_dir: str) -> tuple[str, str]:
                """Returns (actual_firmware_path, log_addendum)."""
                if not _zipfile.is_zipfile(zip_path):
                    return zip_path, ""
                with _zipfile.ZipFile(zip_path, "r") as zf_sync:
                    for entry_name in zf_sync.namelist():
                        entry_ext = os.path.splitext(entry_name)[1].lower()
                        if entry_ext in (".cap", ".rom", ".fd", ".upd", ".bin"):
                            inner = os.path.join(
                                out_dir, os.path.basename(entry_name),
                            )
                            with open(inner, "wb") as out:
                                out.write(zf_sync.read(entry_name))
                            return inner, f"Extracted {entry_name} from ZIP container.\n"
                return zip_path, ""

            actual_firmware, log_addendum = await loop.run_in_executor(
                None, _extract_inner_uefi_sync, firmware_path, extraction_dir,
            )
            if log_addendum:
                result.unpack_log += log_addendum

            log = await run_uefi_extraction(actual_firmware, extraction_dir)
            result.unpack_log += log
            await _report("Analyzing UEFI structure", 70)
            _analyze_uefi_extraction(result, extraction_dir)
            if result.success:
                await _report("Extraction complete", 100)
                return result
            result.unpack_log += "\nUEFI extraction produced no usable output.\n"
        except Exception as e:
            result.unpack_log += f"\nUEFI extraction failed: {e}\n"
            logger.warning("UEFI fast path failed, falling through to generic extractors", exc_info=True)

    # Intel HEX firmware — convert to raw binary, then run RTOS detection + binary analysis
    if fw_type == "intel_hex":
        import json
        import shutil

        from app.services.binary_analysis_service import analyze_binary
        from app.services.rtos_detection_service import detect_rtos, extract_companion_components

        await _report("Converting Intel HEX to binary", 15)

        # Keep original .hex alongside the converted binary
        orig_dest = os.path.join(extraction_dir, "original.hex")
        shutil.copy2(firmware_path, orig_dest)

        bin_path = os.path.join(extraction_dir, "firmware.bin")
        try:
            hex_meta = convert_intel_hex_to_binary(firmware_path, bin_path)
        except Exception as e:
            result.unpack_log += f"Intel HEX conversion failed: {e}\n"
            logger.warning("Intel HEX conversion failed, falling through", exc_info=True)
            hex_meta = None

        if hex_meta is not None and hex_meta["size"] > 0:
            result.extracted_path = extraction_dir
            result.extraction_dir = extraction_dir

            regions_str = ", ".join(
                f"0x{r['start']:08X}-0x{r['start'] + r['size'] - 1:08X} ({r['size']} bytes)"
                for r in hex_meta["regions"]
            )
            result.unpack_log += (
                f"Converted Intel HEX to binary: {hex_meta['size']} bytes.\n"
                f"Base address: 0x{hex_meta['base_address']:08X}.\n"
                f"Memory regions: {regions_str}.\n"
            )
            if hex_meta.get("entry_point") is not None:
                result.unpack_log += f"Entry point: 0x{hex_meta['entry_point']:08X}.\n"

            await _report("Analyzing binary", 40)

            # Build os_info from HEX metadata
            os_info_dict: dict = {
                "format": "intel_hex",
                "hex_metadata": {
                    "base_address": hex_meta["base_address"],
                    "entry_point": hex_meta.get("entry_point"),
                    "binary_size": hex_meta["size"],
                    "regions": hex_meta["regions"],
                },
            }

            # Try binary analysis (LIEF — may not recognize raw blobs)
            binary_info: dict = {}
            try:
                binary_info = analyze_binary(bin_path)
                binary_info["extracted_filename"] = "firmware.bin"
                result.binary_info = binary_info
                result.architecture = binary_info.get("architecture")
                result.endianness = binary_info.get("endianness")
            except Exception:
                pass

            # If LIEF didn't detect architecture, try statistical detection
            if not result.architecture:
                try:
                    from app.services.binary_analysis_service import detect_raw_architecture
                    candidates = detect_raw_architecture(bin_path)
                    if candidates:
                        top = candidates[0]
                        binary_info["architecture"] = top["architecture"]
                        binary_info["endianness"] = top.get("endianness")
                        binary_info["arch_candidates"] = candidates
                        binary_info["arch_detection_method"] = "cpu_rec"
                        binary_info["extracted_filename"] = "firmware.bin"
                        result.binary_info = binary_info
                        result.architecture = top["architecture"]
                        result.endianness = top.get("endianness")
                        arch_names = ", ".join(
                            f"{c['raw_name']} ({c['confidence']})" for c in candidates[:3]
                        )
                        result.unpack_log += f"Architecture candidates: {arch_names}\n"
                except Exception:
                    pass

            await _report("Running RTOS detection", 60)

            # RTOS detection on the converted binary
            try:
                rtos = detect_rtos(bin_path)
                if rtos:
                    companions = extract_companion_components(bin_path)
                    os_info_dict["rtos"] = {
                        "name": rtos["rtos_display_name"],
                        "version": rtos.get("version"),
                        "confidence": rtos["confidence"],
                    }
                    os_info_dict["architecture"] = (
                        rtos.get("architecture") or result.architecture
                    )
                    os_info_dict["companion_components"] = companions
                    result.architecture = rtos.get("architecture") or result.architecture
                    result.endianness = rtos.get("endianness") or result.endianness

                    companion_str = ", ".join(
                        f"{c['name']}" + (f" {c['version']}" if c.get('version') else "")
                        for c in companions
                    )
                    result.unpack_log += (
                        f"RTOS detected: {rtos['rtos_display_name']}"
                        f"{' v' + rtos['version'] if rtos.get('version') else ''}"
                        f" ({rtos['confidence']} confidence).\n"
                    )
                    if companion_str:
                        result.unpack_log += f"Companion components: {companion_str}.\n"
            except Exception as e:
                result.unpack_log += f"RTOS detection skipped: {e}\n"

            result.os_info = json.dumps(os_info_dict)
            result.success = True
            await _report("Extraction complete", 100)
            return result
        elif hex_meta is not None:
            result.unpack_log += "Intel HEX file contains no data records.\n"
            # Fall through to generic extractors

    # RTOS firmware (ELF or raw blob)
    if fw_type.endswith("_elf") and fw_type not in ("elf_binary",) or fw_type == "rtos_blob":
        import json
        import shutil

        from app.services.binary_analysis_service import analyze_binary
        from app.services.rtos_detection_service import detect_rtos, extract_companion_components

        dest = os.path.join(extraction_dir, os.path.basename(firmware_path))
        shutil.copy2(firmware_path, dest)
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir

        binary_info = analyze_binary(firmware_path)
        binary_info["extracted_filename"] = os.path.basename(dest)

        rtos = detect_rtos(firmware_path)
        companions = extract_companion_components(firmware_path)
        if rtos:
            binary_info["rtos"] = rtos
            binary_info["companion_components"] = companions
            rtos_info = {
                "rtos": {
                    "name": rtos["rtos_display_name"],
                    "version": rtos.get("version"),
                    "confidence": rtos["confidence"],
                },
                "architecture": rtos.get("architecture") or binary_info.get("architecture"),
                "companion_components": companions,
            }
            result.os_info = json.dumps(rtos_info)
            result.architecture = rtos.get("architecture") or binary_info.get("architecture")
            result.endianness = rtos.get("endianness") or binary_info.get("endianness")
            companion_str = ", ".join(
                f"{c['name']}" + (f" {c['version']}" if c.get('version') else "")
                for c in companions
            )
            result.unpack_log += (
                f"RTOS firmware detected: {rtos['rtos_display_name']}"
                f"{' v' + rtos['version'] if rtos.get('version') else ''}"
                f" ({rtos['confidence']} confidence).\n"
                f"Architecture: {result.architecture or 'unknown'}, "
                f"Endianness: {result.endianness or 'unknown'}.\n"
            )
            if companion_str:
                result.unpack_log += f"Companion components: {companion_str}.\n"
        else:
            result.architecture = binary_info.get("architecture")
            result.endianness = binary_info.get("endianness")

        result.binary_info = binary_info
        result.success = True
        return result

    if fw_type in ("elf_binary", "pe_binary"):
        import shutil

        from app.services.binary_analysis_service import analyze_binary

        dest = os.path.join(extraction_dir, os.path.basename(firmware_path))
        shutil.copy2(firmware_path, dest)
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir

        # Run full binary analysis (format, arch, linking, dependencies)
        binary_info = analyze_binary(firmware_path)
        # Store the actual filename in extraction dir so the frontend can
        # pre-fill binary_path correctly (may differ from original_filename
        # due to sanitization)
        binary_info["extracted_filename"] = os.path.basename(dest)
        result.binary_info = binary_info
        result.architecture = binary_info.get("architecture")
        result.endianness = binary_info.get("endianness")

        fmt = binary_info.get("format", fw_type.replace("_binary", "")).upper()
        linking = "static" if binary_info.get("is_static") else "dynamic"
        deps = binary_info.get("dependencies", [])
        dep_str = f" Dependencies: {', '.join(deps)}." if deps else ""

        result.unpack_log += (
            f"Single {fmt} binary — skipped filesystem extraction. "
            f"Architecture: {result.architecture or 'unknown'}, "
            f"Endianness: {result.endianness or 'unknown'}, "
            f"Linking: {linking}.{dep_str}"
        )
        result.success = True
        return result

    if fw_type in ("android_ota", "android_sparse", "android_boot", "android_scatter"):
        await _report("Extracting Android firmware", 15)
        try:
            if fw_type == "android_boot":
                boot_dir = os.path.join(extraction_dir, "boot")
                boot_log: list[str] = []
                await _extract_boot_img(firmware_path, boot_dir, boot_log)
                result.unpack_log += "\n".join(boot_log)
                # Use ramdisk as rootfs if it was extracted. Single sync
                # helper offloads the isdir + listdir pair (Rule #5).
                ramdisk_dir = os.path.join(boot_dir, "ramdisk")

                def _ramdisk_has_content_sync(path: str) -> bool:
                    return os.path.isdir(path) and bool(os.listdir(path))

                if await loop.run_in_executor(
                    None, _ramdisk_has_content_sync, ramdisk_dir,
                ):
                    result.extracted_path = ramdisk_dir
                else:
                    result.extracted_path = boot_dir
                result.extraction_dir = extraction_dir
                result.success = True
                await _report("Extraction complete", 100)
                return result
            result.unpack_log += await _extract_android_ota(firmware_path, extraction_dir)
            bomb_error = check_extraction_limits(extraction_dir, fw_size)
            _analyze_filesystem(result, extraction_dir)
            if result.success:
                # Fast path produced a usable rootfs — keep it even if the
                # bomb check complained.  The limit is a defensive default
                # (10 GB) that legitimate Android firmware can approach
                # after sparse expansion; rmtree-ing here would discard
                # real work for a defence-in-depth guard.
                if bomb_error:
                    result.unpack_log += (
                        f"\nWARNING: {bomb_error} "
                        "— extraction kept because filesystem analysis succeeded.\n"
                    )
                return result
            # No rootfs AND bomb tripped: likely malformed firmware.  Clean
            # up the oversized tree before trying other extractors.
            if bomb_error:
                result.error = bomb_error
                result.unpack_log += f"\n{bomb_error}\n"
                shutil.rmtree(extraction_dir, ignore_errors=True)
                return result
            result.unpack_log += "\nAndroid extraction produced no filesystem root.\n"
        except Exception as e:
            result.unpack_log += f"\nAndroid extraction failed: {e}\n"
            logger.warning("Android fast path failed, falling through to generic extractors", exc_info=True)

    elif fw_type == "partition_dump_tar":
        # Raw partition image dump (EDL, MTKClient, or device bridge)
        await _report("Extracting partition dump", 15)
        try:
            from app.config import get_settings as _get_settings
            _settings = _get_settings()
            tar_bomb_error = check_tar_bomb(
                firmware_path,
                _settings.max_extraction_size_mb * 1024 * 1024,
                _settings.max_extraction_files,
                _settings.max_compression_ratio,
            )
            if tar_bomb_error:
                result.error = tar_bomb_error
                result.unpack_log += f"\n{tar_bomb_error}\n"
                return result
            with _tarfile.open(firmware_path) as tf:
                tf.extractall(extraction_dir, filter=_firmware_tar_filter)
            result.unpack_log += f"Extracted partition dump tar: {os.path.basename(firmware_path)}\n"
            # Process extracted .img files through Android pipeline, THEN
            # bomb-check — the Android loop skips user-data partitions and
            # drops super.img raw, so sizing is measured after pruning.
            result.unpack_log += await _extract_android_ota(extraction_dir, extraction_dir)
            bomb_error = check_extraction_limits(extraction_dir, fw_size)
            _analyze_filesystem(result, extraction_dir)
            if result.success:
                if bomb_error:
                    result.unpack_log += (
                        f"\nWARNING: {bomb_error} "
                        "— extraction kept because filesystem analysis succeeded.\n"
                    )
                return result
            if bomb_error:
                result.error = bomb_error
                result.unpack_log += f"\n{bomb_error}\n"
                shutil.rmtree(extraction_dir, ignore_errors=True)
                return result
            result.unpack_log += "\nPartition dump extraction produced no filesystem root.\n"
        except Exception as e:
            result.unpack_log += f"\nPartition dump extraction failed: {e}\n"
            logger.warning("Partition dump fast path failed, falling through", exc_info=True)

    elif fw_type == "linux_rootfs_tar":
        await _report("Extracting Linux rootfs", 15)
        try:
            from app.config import get_settings as _get_settings
            _settings = _get_settings()
            tar_bomb_error = check_tar_bomb(
                firmware_path,
                _settings.max_extraction_size_mb * 1024 * 1024,
                _settings.max_extraction_files,
                _settings.max_compression_ratio,
            )
            if tar_bomb_error:
                result.error = tar_bomb_error
                result.unpack_log += f"\n{tar_bomb_error}\n"
                return result
            with _tarfile.open(firmware_path) as tf:
                tf.extractall(extraction_dir, filter=_firmware_tar_filter)
            result.unpack_log += f"Extracted tar rootfs: {os.path.basename(firmware_path)}\n"
            # Recursively expand any nested archives (Samsung tar.md5 →
            # inner tar.lz4 pattern is common for full rootfs tars).
            try:
                from app.workers.unpack_common import _recursive_extract_nested
                nested = _recursive_extract_nested(extraction_dir, max_depth=3)
                if nested:
                    result.unpack_log += (
                        f"Recursive nested extraction: expanded "
                        f"{len(nested)} archive(s).\n"
                    )
            except Exception as e:
                result.unpack_log += f"Nested extraction skipped: {e}\n"
            bomb_error = check_extraction_limits(extraction_dir, fw_size)
            _analyze_filesystem(result, extraction_dir)
            if result.success:
                if bomb_error:
                    result.unpack_log += (
                        f"\nWARNING: {bomb_error} "
                        "— extraction kept because filesystem analysis succeeded.\n"
                    )
                return result
            if bomb_error:
                result.error = bomb_error
                result.unpack_log += f"\n{bomb_error}\n"
                shutil.rmtree(extraction_dir, ignore_errors=True)
                return result
            result.unpack_log += "\nTar extraction produced no filesystem root.\n"
        except Exception as e:
            result.unpack_log += f"\nTar extraction failed: {e}\n"
            logger.warning("Tar fast path failed, falling through to generic extractors", exc_info=True)

    # === STAGE 2: Generic Fallback Chain ===

    fallback_extractors = [
        ("unblob", run_unblob_extraction, 1200),
        ("binwalk3", run_binwalk_extraction, 600),
    ]

    for idx, (name, func, timeout) in enumerate(fallback_extractors):
        progress_base = 30 + idx * 30  # unblob: 30-60, binwalk: 60-90
        try:
            await _report(f"Running {name} extraction", progress_base)
            result.unpack_log += f"\nTrying {name} (timeout {timeout}s)...\n"
            log = await func(firmware_path, extraction_dir, timeout=timeout)
            result.unpack_log += log

            # Clean up unblob/binwalk artifacts (.unknown chunks, raw images
            # that have been extracted) to reduce file explorer noise.  Run
            # BEFORE the bomb check so intermediate chunks don't count.
            removed = cleanup_unblob_artifacts(extraction_dir)
            # Also clean nested extraction dirs (unblob nests under img_extract/)
            for entry in os.scandir(extraction_dir):
                if entry.is_dir(follow_symlinks=False) and entry.name.endswith("_extract"):
                    removed += cleanup_unblob_artifacts(entry.path)
            if removed:
                result.unpack_log += f"Cleaned up {removed} intermediate artifact(s).\n"
            # Remove escape symlinks — binwalk3 always plants one back at
            # the input file in its -C output dir, regardless of whether
            # it found anything to extract.  Leaving it tricks
            # find_filesystem_root into reporting success on a dir whose
            # only "content" is a symlink the sandbox refuses to serve.
            escape_removed = remove_extraction_escape_symlinks(extraction_dir)
            if escape_removed:
                result.unpack_log += (
                    f"Removed {escape_removed} extraction-escape symlink(s).\n"
                )
            # Recursively expand any nested archives that unblob/binwalk
            # didn't touch at the top level (common pattern: a firmware
            # ZIP holds multiple sibling .tar.xz archives — unblob extracts
            # one, the siblings need to be unrolled too so their rootfs /
            # kernel contents become visible to downstream detection).
            try:
                from app.workers.unpack_common import _recursive_extract_nested
                nested = _recursive_extract_nested(extraction_dir, max_depth=3)
                if nested:
                    result.unpack_log += (
                        f"Recursive nested extraction: expanded "
                        f"{len(nested)} archive(s) post-{name}.\n"
                    )
            except Exception as e:
                result.unpack_log += f"Nested extraction skipped: {e}\n"
            # Vendor-AES auto-decrypt: some firmware packages (e.g. EDAN
            # MPM RespArray/target-ld v1.12) ship .tar.xz files that are
            # AES-CBC ciphertext with the decryption key+iv hardcoded in
            # an update shell script inside a recovery rootfs. If we find
            # such a script in the freshly-extracted tree, decrypt any
            # sibling archives whose magic doesn't match their extension
            # and extract them into <path>_extract/ siblings. No-op when
            # no script-level keys are discoverable.
            try:
                from app.workers.unpack_common import (
                    _decrypt_vendor_encrypted_archives,
                    _detect_openssl_key_triples,
                )
                triples = _detect_openssl_key_triples(extraction_dir)
                if triples:
                    decrypted = _decrypt_vendor_encrypted_archives(
                        extraction_dir, triples,
                    )
                    if decrypted:
                        # Record every triple used for audit (Rule #16
                        # companion: operator should be able to reproduce
                        # the decryption from device_metadata alone).
                        result.vendor_decryption = [
                            {
                                "archive": os.path.relpath(p, extraction_dir),  # noqa: ASYNC240 — pure-string path op; no I/O
                                "algorithm": t.algo,
                                "key_hex": t.key_hex,
                                "iv_hex": t.iv_hex,
                                "key_source": t.source,
                            }
                            for p, t in decrypted
                        ]
                        # Absolute paths of the _extract/ output dirs — the
                        # DB runner registers these as detection roots so
                        # the file-explorer virtual-root surfaces them.
                        result.decryption_output_dirs = [
                            p + "_extract" for p, _ in decrypted
                        ]
                        result.unpack_log += (
                            f"Vendor-AES auto-decrypt: "
                            f"{len(decrypted)} archive(s) decrypted using "
                            f"{len(triples)} key triple(s) found in update "
                            f"scripts; contents extracted to <path>_extract/ "
                            f"siblings.\n"
                        )
                        # Recurse one more time — the decrypted output
                        # may contain its own nested archives.
                        try:
                            nested2 = _recursive_extract_nested(
                                extraction_dir, max_depth=3,
                            )
                            if nested2:
                                result.unpack_log += (
                                    f"Post-decrypt nested extraction: "
                                    f"expanded {len(nested2)} archive(s).\n"
                                )
                        except Exception:
                            pass
            except Exception as e:
                result.unpack_log += f"Vendor-AES decrypt skipped: {e}\n"
                logger.debug("Vendor-AES decrypt pass failed", exc_info=True)

            # Post-unblob recovery: scan Android super.img sparsechunk
            # extracts for embedded partitions and extract each carved
            # partition into a walkable rootfs tree. Cheap no-op when no
            # sparsechunks present; on Motorola/Bengal-class firmware it
            # carves the system/vendor/product partition data out of the
            # mmap'd raw.image files unblob left behind, then debugfs/
            # fsck.erofs unpacks each into a walkable filesystem.
            # Bounded per Rule #29 (≤16 chunks × ≤10 GB per chunk,
            # plus 300s per fsck.erofs/debugfs invocation).
            try:
                from app.workers.unpack_android import (
                    recover_sparsechunk_extracts_async,
                )
                recovery_log: list[str] = []
                recovered_walkable = await recover_sparsechunk_extracts_async(
                    extraction_dir, recovery_log,
                )
                if recovery_log:
                    result.unpack_log += "\n".join(recovery_log) + "\n"
                if recovered_walkable:
                    result.unpack_log += (
                        f"Sparsechunk recovery: {len(recovered_walkable)} "
                        f"partition rootfs(es) extracted under "
                        f"super.img_recovered_extract/.\n"
                    )
            except Exception as e:
                result.unpack_log += f"Sparsechunk recovery skipped: {e}\n"
                logger.debug("Sparsechunk recovery failed", exc_info=True)

            bomb_error = check_extraction_limits(extraction_dir, fw_size)
            # Widen read perms so the backend user can stat/open files
            # that vendor tarballs ship with restrictive modes (e.g.
            # rwxr-x--- root:root for cred-gen scripts). Without this
            # pass the file-explorer API returns EPERM on legitimate
            # content. Runs ONCE post-extract, before filesystem analysis.
            try:
                from app.workers.unpack_common import widen_read_perms
                changed = widen_read_perms(extraction_dir)
                if changed:
                    result.unpack_log += (
                        f"Widened read permissions on {changed} entry/entries "
                        "so the file-explorer API can read vendor-restricted files.\n"
                    )
            except Exception as e:
                logger.debug("widen_read_perms failed: %s", e, exc_info=True)
            await _report("Analyzing filesystem", progress_base + 20)
            _analyze_filesystem(result, extraction_dir)
            if result.success:
                await _report("Extraction complete", 100)
                result.unpack_log += f"\n{name} extraction succeeded.\n"
                if bomb_error:
                    result.unpack_log += (
                        f"\nWARNING: {bomb_error} "
                        "— extraction kept because filesystem analysis succeeded.\n"
                    )
                return result
            if bomb_error:
                result.error = bomb_error
                result.unpack_log += f"\n{bomb_error}\n"
                shutil.rmtree(extraction_dir, ignore_errors=True)
                return result

            result.unpack_log += f"\n{name} ran but no filesystem root found. Trying next...\n"
            result.error = None  # Clear for next attempt
        except TimeoutError:
            result.unpack_log += f"\n{name} timed out after {timeout}s.\n"
            logger.info("%s timed out on %s", name, os.path.basename(firmware_path))
        except Exception as e:
            result.unpack_log += f"\n{name} failed: {e}\n"
            logger.info("%s failed on %s: %s", name, os.path.basename(firmware_path), e)

    # All extractors exhausted — fall back to standalone binary mode
    # If the file is small enough, just copy it and let users analyze
    # the binary directly (common for single malware samples, test
    # binaries, bare-metal medical / automotive / IoT firmware).
    # Limit is configurable via MAX_STANDALONE_BINARY_MB (default 512
    # MB — covers most embedded firmware; excludes unbounded bulk
    # images).  Past the limit, the extraction fails cleanly with a
    # readable error and the user gets a defined failure state instead
    # of a silent "analysis unavailable".
    from app.config import get_settings as _get_standalone_settings
    _STANDALONE_BINARY_MAX = (
        _get_standalone_settings().max_standalone_binary_mb * 1024 * 1024
    )
    if not result.success and fw_size > _STANDALONE_BINARY_MAX:
        logger.info(
            "Standalone-binary fallback skipped: %s is %d MB, exceeds "
            "MAX_STANDALONE_BINARY_MB=%d",
            os.path.basename(firmware_path),
            fw_size // (1024 * 1024),
            _STANDALONE_BINARY_MAX // (1024 * 1024),
        )
        result.unpack_log += (
            f"\nAll extraction methods exhausted and file is "
            f"{fw_size // (1024 * 1024)} MB — over the "
            f"{_STANDALONE_BINARY_MAX // (1024 * 1024)} MB standalone-"
            f"binary limit (MAX_STANDALONE_BINARY_MB). Raise the env "
            f"var in .env to analyse larger raw firmware.\n"
        )
    if not result.success and fw_size <= _STANDALONE_BINARY_MAX:
        import shutil

        from app.services.binary_analysis_service import analyze_binary

        dest = os.path.join(extraction_dir, os.path.basename(firmware_path))

        def _stage_fallback_copy_sync(src: str, target: str) -> None:
            if not os.path.exists(target):
                shutil.copy2(src, target)

        await loop.run_in_executor(
            None, _stage_fallback_copy_sync, firmware_path, dest,
        )
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir

        # Attempt binary analysis for arch detection on the fallback path
        try:
            binary_info = analyze_binary(firmware_path)
            if binary_info.get("architecture"):
                binary_info["extracted_filename"] = os.path.basename(dest)
                result.binary_info = binary_info
                result.architecture = binary_info["architecture"]
                result.endianness = binary_info.get("endianness")
            elif binary_info.get("format") == "unknown":
                # No recognized headers — try statistical architecture detection
                # for raw binaries (bare-metal firmware, ROM dumps, bootloaders)
                from app.services.binary_analysis_service import detect_raw_architecture
                candidates = detect_raw_architecture(firmware_path)
                if candidates:
                    top = candidates[0]
                    binary_info["architecture"] = top["architecture"]
                    binary_info["endianness"] = top.get("endianness")
                    binary_info["arch_candidates"] = candidates
                    binary_info["arch_detection_method"] = "cpu_rec"
                    binary_info["extracted_filename"] = os.path.basename(dest)
                    result.binary_info = binary_info
                    result.architecture = top["architecture"]
                    result.endianness = top.get("endianness")
                    arch_names = ", ".join(
                        f"{c['raw_name']} ({c['confidence']})" for c in candidates[:3]
                    )
                    result.unpack_log += (
                        f"Raw binary — detected architecture candidates: {arch_names}\n"
                    )
                else:
                    binary_info["extracted_filename"] = os.path.basename(dest)
                    result.binary_info = binary_info
        except Exception:
            pass

        result.unpack_log += (
            "\nAll extraction methods exhausted.\n"
            "Treating as standalone binary file.\n"
        )
        result.success = True
        return result

    if not result.success:
        result.error = "All extraction methods failed or produced no filesystem root"
        result.unpack_log += "\nAll extraction methods exhausted.\n"

    return result
