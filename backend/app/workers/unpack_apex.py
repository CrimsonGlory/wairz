"""APEX (Android Pony EXpress) unpack worker via 7z (outer zip + inner ext4).

APEX is Google's signed-zip wrapper used for system module updates from
Android 10 onwards (Conscrypt, Tzdata, Media, ART, Tethering, etc.). It
ships hundreds of binaries + libraries per module — major SBOM content
that's invisible to a walker that only sees the outer ``.apex`` blob.

Wire shape::

    <name>.apex                  # outer ZIP container
      ├── apex_manifest.pb       # protobuf manifest (name + version)
      ├── apex_payload.img       # ext4 / ext2 filesystem (the payload)
      ├── apex_pubkey            # signing key
      ├── apex_build_info.pb
      ├── AndroidManifest.xml
      └── META-INF/{CERT.SF,CERT.RSA,MANIFEST.MF}

CAPEX (Compressed APEX — Android 12+) replaces ``apex_payload.img`` with
``original_apex``, which is itself a regular APEX nested inside. The
worker handles both shapes:

* **Plain APEX** — outer 7z extract → inner ``apex_payload.img`` → inner
  7z extract of the ext filesystem → ``<extract>/payload/<tree>``.
* **CAPEX** — outer 7z extract → ``original_apex`` 7z extract → inner
  ``apex_payload.img`` → 7z extract → ``<extract>/payload/<tree>``.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.ANDROID_APEX] = unpack_apex

Why 7z (not unblob): unblob has no APEX-aware handler; it falls back to
generic ZIP extraction at the outer layer, then sometimes (G30) recurses
into the inner ext4 via its ext handler, and sometimes (G32) doesn't —
which is the exact gap Scout 2 reported. The 7z path is deterministic
across both standard and compressed variants and handles ext2/ext4
filesystems directly (``Type = Ext`` under 7z 25.x).

**No-execute discipline (Rule #36):** the worker NEVER invokes any
binary inside the APEX. AndroidManifest.xml is surfaced as data;
CERT.RSA + apex_pubkey are surfaced for signify / asn1crypto parsing
(future SBOM walker enhancement) but never used for signature
verification by this worker. The payload is data, not code.

**No-decrypt discipline (Rule #45 partner):** there is nothing to
decrypt — APEX signing is integrity-only (APK v2/v3 detached signature
chain), not confidentiality. The walker surfaces the cert metadata as
forensic evidence; never attempts key recovery.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import uuid

from app.workers.unpack_common import (
    UnpackResult,
    check_extraction_limits,
    find_filesystem_root,
    reset_extraction_dir_sync,
    widen_read_perms,
)

logger = logging.getLogger(__name__)


# 7z extraction timeout. Most APEX files are 100 KB - 50 MB and extract
# in under 30 s; 5 min is a generous cap for the very largest modules
# (com.android.vndk.current.apex hits 80+ MB on some devices).
# Aligned with radare2-tier (150_000 ms × safety margin) per Rule #29.
_SEVENZ_TIMEOUT_SECONDS = 300

# 7z list. Cheap probe.
_SEVENZ_LIST_TIMEOUT_SECONDS = 30

# 7z returns 0 on success, 1 on warnings (non-fatal). 2+ is real failure.
_SEVENZ_OK_RETURN_CODES = (0, 1)


async def unpack_apex(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001 — uniform signature
) -> UnpackResult:
    """Extract an APEX module (standard or compressed) via 7z.

    Steps:
        1. Prep extraction_dir.
        2. Disk-space check — APEX inflates 1-2x at outer, 2-3x at inner;
           require 4x total headroom.
        3. ``7z x <apex>`` into ``<extraction_dir>/outer/`` — surfaces
           apex_manifest.pb / AndroidManifest.xml / META-INF / and either
           apex_payload.img (plain) or original_apex (CAPEX).
        4. If CAPEX: ``7z x outer/original_apex`` into ``outer/orig/`` to
           recover the inner standard APEX's apex_payload.img.
        5. ``7z x <payload.img>`` into ``<extraction_dir>/payload/`` —
           ext4 walk surfaces the actual binaries / libraries / manifest.
        6. Widen perms + bomb-check.

    Failure modes:
        - 7z not installed → install hint.
        - outer 7z fails → "APEX outer archive unreadable".
        - apex_manifest.pb missing → "Not a recognisable APEX".
        - apex_payload.img missing AND original_apex missing → unknown variant.
        - timeout → "APEX extraction timed out after Ns".
    """
    async def _report(stage: str, progress: int) -> None:
        if progress_callback:
            try:
                await progress_callback(stage, progress)
            except Exception:
                pass

    result = UnpackResult()
    extraction_dir = os.path.join(output_base_dir, "extracted")  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
    outer_dir = os.path.join(extraction_dir, "outer")  # noqa: ASYNC240 — pure-string
    payload_dir = os.path.join(extraction_dir, "payload")  # noqa: ASYNC240 — pure-string

    # Prep + disk-space check.
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, reset_extraction_dir_sync, extraction_dir)
    await loop.run_in_executor(None, os.makedirs, outer_dir, True)  # noqa: FBT003
    await loop.run_in_executor(None, os.makedirs, payload_dir, True)  # noqa: FBT003

    fw_size = 0
    try:
        fw_size = await loop.run_in_executor(None, os.path.getsize, firmware_path)
        free = await loop.run_in_executor(
            None, lambda: shutil.disk_usage(extraction_dir).free,
        )
        if free < fw_size * 4:
            result.error = (
                f"Insufficient disk space: {free // (1024 * 1024)} MB free, "
                f"need ~{fw_size * 4 // (1024 * 1024)} MB for APEX extraction"
            )
            result.unpack_log = result.error
            return result
    except OSError:
        pass

    # ---- Step 1: outer 7z list (validate) ----
    await _report("Inspecting APEX archive", 5)

    list_rc, list_out = await _run_seven_z(
        ["7z", "l", firmware_path], _SEVENZ_LIST_TIMEOUT_SECONDS,
    )
    if list_rc is None:
        result.error = "7z binary missing — install p7zip-full"
        result.unpack_log = (
            f"{result.error}\nAPEX extraction requires the `7z` CLI "
            "from the p7zip-full apt package.\n"
        )
        return result
    if list_rc not in _SEVENZ_OK_RETURN_CODES:
        result.error = f"APEX outer archive unreadable (7z l exit={list_rc})"
        result.unpack_log = (
            f"7z l exit={list_rc}\n"
            f"output (last 2KB):\n{list_out[-2000:]}\n"
            f"{result.error}\n"
        )
        return result

    log_head = (
        f"7z l exit={list_rc}\n"
        f"outer listing (first 2KB):\n{list_out[:2000]}\n"
    )

    # Sanity gate — APEX must declare apex_manifest.pb in the outer ZIP.
    if "apex_manifest.pb" not in list_out:
        result.error = "Not a recognisable APEX (missing apex_manifest.pb)"
        result.unpack_log = log_head + result.error
        return result

    # ---- Step 2: outer 7z extract ----
    await _report("Extracting APEX outer ZIP", 15)

    rc, out = await _run_seven_z(
        ["7z", "x", "-y", f"-o{outer_dir}", firmware_path],
        _SEVENZ_TIMEOUT_SECONDS,
    )
    if rc is None or rc not in _SEVENZ_OK_RETURN_CODES:
        result.error = f"APEX outer extraction failed (7z x exit={rc})"
        result.unpack_log = log_head + (
            f"7z x exit={rc}\noutput (last 2KB):\n{out[-2000:]}\n{result.error}\n"
        )
        return result
    log_head += f"7z x outer exit={rc}\n"

    # ---- Step 3: CAPEX detection + nested extraction ----
    payload_img_path = os.path.join(outer_dir, "apex_payload.img")  # noqa: ASYNC240 — path math
    original_apex_path = os.path.join(outer_dir, "original_apex")  # noqa: ASYNC240 — path math
    is_capex = False

    if not os.path.isfile(payload_img_path) and os.path.isfile(original_apex_path):  # noqa: ASYNC240 — pre-flight stat before sync 7z subprocess; Rule #43 category 1
        is_capex = True
        await _report("Extracting CAPEX nested original_apex", 35)
        orig_dir = os.path.join(outer_dir, "orig")  # noqa: ASYNC240
        await loop.run_in_executor(None, os.makedirs, orig_dir, True)  # noqa: FBT003
        rc2, out2 = await _run_seven_z(
            ["7z", "x", "-y", f"-o{orig_dir}", original_apex_path],
            _SEVENZ_TIMEOUT_SECONDS,
        )
        if rc2 is None or rc2 not in _SEVENZ_OK_RETURN_CODES:
            result.error = (
                f"CAPEX nested original_apex extraction failed (exit={rc2})"
            )
            result.unpack_log = log_head + (
                f"7z x original_apex exit={rc2}\n"
                f"output (last 2KB):\n{out2[-2000:]}\n{result.error}\n"
            )
            return result
        log_head += f"7z x original_apex exit={rc2} (CAPEX variant)\n"
        payload_img_path = os.path.join(orig_dir, "apex_payload.img")  # noqa: ASYNC240

    if not os.path.isfile(payload_img_path):  # noqa: ASYNC240 — pre-flight stat before sync 7z subprocess; Rule #43 category 1
        result.error = (
            "APEX payload missing — neither apex_payload.img nor "
            "original_apex/apex_payload.img found after outer extraction"
        )
        result.unpack_log = log_head + result.error
        return result

    # ---- Step 4: inner ext4/ext2 payload extraction ----
    await _report("Extracting APEX payload filesystem", 55)

    rc3, out3 = await _run_seven_z(
        ["7z", "x", "-y", f"-o{payload_dir}", payload_img_path],
        _SEVENZ_TIMEOUT_SECONDS,
    )
    if rc3 is None or rc3 not in _SEVENZ_OK_RETURN_CODES:
        result.error = f"APEX payload extraction failed (7z x exit={rc3})"
        result.unpack_log = log_head + (
            f"7z x payload exit={rc3}\n"
            f"output (last 2KB):\n{out3[-2000:]}\n{result.error}\n"
        )
        return result
    log_head += f"7z x apex_payload.img exit={rc3} (capex={is_capex})\n"

    # ---- Step 5: widen perms + post-extraction analysis ----
    await _report("Analysing extracted APEX tree", 80)

    try:
        widened = await loop.run_in_executor(
            None, widen_read_perms, extraction_dir,
        )
        if widened:
            log_head += f"Widened read permissions on {widened} entries.\n"
    except Exception as exc:
        logger.debug("widen_read_perms failed for APEX extraction: %s", exc)

    fs_root = await loop.run_in_executor(None, find_filesystem_root, payload_dir)
    if fs_root:
        result.extracted_path = fs_root
    else:
        result.extracted_path = payload_dir
    result.extraction_dir = extraction_dir

    bomb_error = await loop.run_in_executor(
        None, lambda: check_extraction_limits(extraction_dir, fw_size),
    )
    if bomb_error:
        log_head += f"\nWARNING: {bomb_error} — extraction kept.\n"

    # Count payload files for the unpack_log summary.
    payload_file_count = 0
    try:
        for _, _, files in os.walk(payload_dir):
            payload_file_count += len(files)
    except OSError:
        pass

    result.success = True
    result.unpack_log = log_head + (
        f"APEX extraction complete (capex={is_capex}, "
        f"payload_files={payload_file_count}).\n"
    )
    await _report("Extraction complete", 100)
    return result


async def _run_seven_z(
    cmd: list[str], timeout: int,  # noqa: ASYNC109 — caller-supplied timeout per Rule #29 contract; plumbed to communicate(timeout=...) below; Rule #43 category 4
) -> tuple[int | None, str]:
    """Run 7z and capture (rc, combined-output).

    Returns (None, "") if the 7z binary is missing on PATH.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError:
        return None, ""

    try:
        stdout_b, _ = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
    except TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        return None, f"7z timed out after {timeout}s"

    return proc.returncode, (stdout_b or b"").decode(errors="replace")
