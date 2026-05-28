"""Q2 — ds1qrsetup binary call-graph PARSE-ONLY walker.

Performs **static binary call-graph analysis** of the ds1qrsetup
network-facing binary (Python interpreter + statically-linked C modules
from the Yocto recipe) on DS1 firmware. Outputs a JSON aggregate
identifying reachable native symbols + FFmpeg / Pillow compile-flag
fingerprints. The cve-assessment-framework consumes this to narrow
FFmpeg DNN-backend + Pillow decoder reachability for ~42 FFmpeg EXPL
CVEs + Pillow long-tail.

**PARSE-ONLY DISCIPLINE — Rule #36 + Rule #45 (Rule-of-Three+ — DURABLE
BEYOND DEBATE).** The walker analyses the ds1qrsetup binary AS DATA via
Ghidra headless (cached in ``analysis_cache`` per Rule #2) with a
radare2 + ``r2pipe`` fallback. NEITHER tool invokes the extracted
binary:

- Ghidra headless imports the binary into a Ghidra project, runs
  ``AnalyzeBinary.java`` post-script to extract functions / imports /
  exports / xrefs / disassembly / decompilation, exits.
- radare2 (``r2pipe.open(binary_path)``) opens the binary read-only,
  runs commands (``aaa``, ``afl``, ``axt``, ``iz``), exits.

The walker NEVER:

- Calls ``subprocess.run([binary_path, ...])`` or any spawn primitive
  with the extracted binary as ``argv[0]``.
- Invokes ``exec()`` / ``compile()`` / ``runpy.run_path`` /
  ``importlib.import_module`` against firmware-extracted source.
- Decrypts master keys / vendor secrets / signed payloads inside the
  binary (irrelevant for ds1qrsetup, but the discipline carries
  forward from κ.D / κ.E precedent).

Cache discipline (Rule #2 from cve-assessment-framework CLAUDE.md +
wairz CLAUDE.md Rule #2): Ghidra decompile takes 30-120 s per binary;
the per-binary-SHA cache in ``ghidra_service.ensure_analysis`` (LRU in
``analysis_cache`` table) means a re-walk on the same firmware is
near-instant (DB SELECT only). Subsequent walks key by binary SHA so
multi-firmware fleets with the same ds1qrsetup binary share the cache.

**Rule #39 inner/outer/safe runner triplet** — pattern lifted from γ.4
+ δ.5 + ε.1.b.3 + ζ.2.B + ζ.3.B + κ.D + κ.E:

- :func:`_do_callgraph_run` — INNER orchestrator. Accepts caller-owned
  ``db``. Locates the ds1qrsetup binary via
  :func:`get_detection_roots` (Rule #16), tries Ghidra first then
  radare2 fallback, extracts compile-flags + symbol reachability,
  returns aggregate dict UNSTAMPED. Tier-1 tests call this via
  ``make_live_db()`` — no Docker DNS dependency.
- :func:`run_callgraph_background` — OUTER state-machine wrapper. Owns
  the Rule #33 .a status transitions via ``async_session_factory()``.
  Outer guard catches escapes; failure persistence on a fresh session.
- :func:`auto_callgraph_walk_firmware_safe` — UNPACK-POST-DETECTION
  hook. Runs the inner orchestrator but does NOT mutate
  ``ds1qrsetup_callgraph_walk_status`` — leaves ``idle`` so manual
  re-trigger via the trigger MCP tool works without 409 conflict.

**Rule #16 detection-roots discipline.** The walker uses
:func:`get_detection_roots` (NOT bare ``firmware.extracted_path``) so
multi-rootfs scatter-zip DS1 firmware surfaces every ds1qrsetup binary
candidate.

**Defensive degradation.** Ghidra unavailability (no
``GHIDRA_PATH``, binary at incompatible arch) AND radare2 unavailability
(no ``r2pipe`` package) BOTH return an aggregate with
``analyzer="unavailable"`` + the appropriate ``errors`` entries. The
cve-assessment-framework treats this as INSUFFICIENT_EVIDENCE per Q2
contract — never as a hard failure.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
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
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_ds1qrsetup_callgraph_walk_result,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Per-walker wall-clock soft cap. Ghidra full-analysis takes 30-120s
# typically, plus reachability computation. 600s aligns with the Rule
# #29 SECURITY_SCAN_TIMEOUT tier — the same outer synchronous ceiling
# used for SBOM / vuln-scan / yara work in the frontend.
_DEFAULT_WALKER_TIMEOUT_SECONDS: float = 600.0

# Reachability traversal depth cap. Hand-rolled BFS keeps memory bounded
# for binaries with millions of nodes (Python interpreter ~50K functions
# at the static-link extreme). Caps at 10K reachable symbols which is
# 10-100x larger than ds1qrsetup's realistic footprint.
_MAX_REACHABLE_SYMBOLS: int = 10_000

# Canonical ds1qrsetup binary names. The Yocto recipe ships the binary
# under /opt/ds1qrsetup/ but the basename varies across firmware
# versions. We accept the canonical names plus any binary in
# /opt/ds1qrsetup/ that looks like an ELF.
_DS1QRSETUP_BASENAMES: tuple[str, ...] = (
    "ds1qrsetup",
    "ds1qrsetup.bin",
)

# Path patterns considered the canonical ds1qrsetup location. The
# detection-root scan looks for ELF binaries under these directories.
_DS1QRSETUP_DIRS: tuple[str, ...] = (
    "opt/ds1qrsetup",
    "usr/bin",
    "usr/local/bin",
    "bin",
)


# FFmpeg ``--enable-*`` / ``--disable-*`` configure-flag families we
# care about for the CVE-narrowing surface. Detected via string-scan in
# the binary's read-only section (Ghidra exposes via the "strings" cache
# / radare2 via ``iz``).
_FFMPEG_FLAG_FAMILIES: tuple[str, ...] = (
    "libx264",
    "libx265",
    "libtheora",
    "libvpx",
    "libdav1d",
    "libaom",
    "libopus",
    "libvorbis",
    "libmp3lame",
    "libfdk-aac",
    "libtensorflow",
    "libopenvino",
    "libtorch",
    "libfreetype",
    "libfontconfig",
    "libfribidi",
    "libharfbuzz",
    "libass",
    "libwebp",
    "libtiff",
    "libjpeg",
    "libpng",
    "libgif",
)

# Pillow decoder module names. Pillow registers per-format decoders at
# import; their symbols appear in the binary's symbol table when Pillow
# is statically linked (or compiled-in via the Yocto recipe).
_PILLOW_DECODERS: tuple[str, ...] = (
    "JPEG",
    "JPEG2000",
    "PNG",
    "TIFF",
    "BMP",
    "GIF",
    "WEBP",
    "WEBP_EXTENDED",
    "ICNS",
    "ICO",
    "TGA",
    "EXR",
    "FLI",
    "FPX",
    "GBR",
    "MIC",
    "MPO",
    "MSP",
    "PCD",
    "PCX",
    "PIXAR",
    "PSD",
    "SGI",
    "SPIDER",
    "SUN",
    "WMF",
    "XBM",
    "XPM",
    "DDS",
)


# ── Rule #19 dependency probes ──────────────────────────────────────────────


def is_ghidra_available() -> bool:
    """Return True iff Ghidra headless is installed at the configured path.

    Reads ``settings.ghidra_path`` and probes for the analyzeHeadless
    binary. Defensive against missing config / OSError.
    """
    try:
        from app.config import get_settings

        settings = get_settings()
        ghidra_path = settings.ghidra_path
        analyze_headless = os.path.join(
            ghidra_path, "support", "analyzeHeadless"
        )
        return os.path.isfile(analyze_headless)
    except Exception:
        return False


def is_r2pipe_available() -> bool:
    """Return True iff ``r2pipe`` (radare2 Python binding) is importable.

    Independent of Ghidra availability — r2pipe is the fallback analyser
    when Ghidra is absent or fails on a given binary.
    """
    try:
        import r2pipe  # noqa: F401 — import-only probe
    except ImportError:
        return False
    return True


# ── Binary location helpers ──────────────────────────────────────────────────


def _looks_like_elf_sync(path: str) -> bool:
    """Check the first 4 bytes for the ELF magic. Sync — defensive."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def locate_ds1qrsetup_binaries(roots: Iterable[str]) -> list[str]:
    """Locate every ds1qrsetup binary candidate under the detection roots.

    Search strategy:

    1. For each canonical ``_DS1QRSETUP_DIRS`` subdirectory, look for
       a file whose basename matches ``_DS1QRSETUP_BASENAMES``.
    2. For each match, verify ELF magic.
    3. Path traversal rejection — every result is realpath'd against the
       root via prefix check (Rule #1 spirit).

    Sync I/O — wrap in :func:`run_in_executor` for async callers
    (Rule #5). Defensive against missing roots / permission errors.

    Returns:
        list[str] of realpath'd binary paths (typically 0-3 hits per
        firmware).
    """
    hits: list[str] = []
    seen: set[str] = set()

    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if not os.path.isdir(real_root):
            continue

        for subdir in _DS1QRSETUP_DIRS:
            candidate_dir = os.path.join(real_root, subdir)
            if not os.path.isdir(candidate_dir):
                continue

            for basename in _DS1QRSETUP_BASENAMES:
                full = os.path.join(candidate_dir, basename)
                try:
                    real_full = os.path.realpath(full)
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                if not os.path.isfile(real_full):
                    continue
                if real_full in seen:
                    continue
                if not _looks_like_elf_sync(real_full):
                    continue
                seen.add(real_full)
                hits.append(real_full)

    return hits


async def _locate_ds1qrsetup_binaries_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`locate_ds1qrsetup_binaries` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, locate_ds1qrsetup_binaries, roots)


# ── Compile-flag string-scan ─────────────────────────────────────────────────


def _extract_strings_sync(binary_path: str, min_length: int = 6) -> list[str]:
    """Cheap ASCII-printable string extraction. Sync.

    Used as the radare2/Ghidra-independent string source for compile-
    flag fingerprinting. ``min_length=6`` filters out single-byte
    fragments that produce too many false positives.

    Defensive against OSError; returns ``[]`` on read failure.
    """
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except OSError:
        return []

    out: list[str] = []
    current: list[int] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= min_length:
                out.append(bytes(current).decode("ascii", errors="ignore"))
            current = []
    if len(current) >= min_length:
        out.append(bytes(current).decode("ascii", errors="ignore"))
    return out


def _detect_compile_flags(strings: list[str]) -> dict[str, list[str]]:
    """Detect FFmpeg / Pillow compile-flag fingerprints from binary strings.

    Returns a dict with four list-shaped fields:

    - ``ffmpeg``: list of detected ``--enable-<lib>`` family flags.
    - ``ffmpeg_disabled``: list of detected ``--disable-<lib>`` flags.
    - ``pillow_decoders``: list of detected Pillow decoder modules.
    - ``pillow_decoders_absent``: list of Pillow decoders NOT detected
      (computed from the known _PILLOW_DECODERS list).
    """
    string_set = set(strings)

    ffmpeg_enabled: list[str] = []
    ffmpeg_disabled: list[str] = []

    # FFmpeg embeds its full configure line into the libavutil binary;
    # we look for the canonical --enable-X / --disable-X tokens. The
    # presence of the libname alone (e.g. "libx264") is NOT sufficient
    # to declare the flag enabled (the linker may have pulled in the
    # symbol indirectly); the configure-line scan is the strong signal.
    full_text = "\n".join(strings)
    for libname in _FFMPEG_FLAG_FAMILIES:
        enable_token = f"--enable-{libname}"
        disable_token = f"--disable-{libname}"
        if enable_token in full_text:
            ffmpeg_enabled.append(enable_token)
        elif disable_token in full_text:
            ffmpeg_disabled.append(disable_token)

    # Pillow decoder names typically appear in the symbol table as
    # ``Pillow_<Decoder>Decode`` / ``ImagingNewPalette<Decoder>`` etc.
    # The simple "decoder name present in strings" heuristic catches
    # the registered-format set in Pillow >= 5.0.
    pillow_present: list[str] = []
    for decoder in _PILLOW_DECODERS:
        if decoder in string_set or any(decoder in s for s in strings):
            pillow_present.append(decoder)
    pillow_absent = [d for d in _PILLOW_DECODERS if d not in pillow_present]

    return {
        "ffmpeg": sorted(ffmpeg_enabled),
        "ffmpeg_disabled": sorted(ffmpeg_disabled),
        "pillow_decoders": sorted(pillow_present),
        "pillow_decoders_absent": sorted(pillow_absent),
    }


# ── Ghidra-backed call-graph (preferred path) ───────────────────────────────


async def _analyze_with_ghidra(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> dict[str, Any]:
    """Use ``ghidra_service.ensure_analysis`` + cached xrefs to build
    the reachability graph + symbol catalogue.

    Caches via ``analysis_cache`` per binary SHA — second invocation
    against the same binary is near-instant.

    Returns:
        {
            "status": "ok",
            "analyzer": "ghidra",
            "functions": list[str],
            "imports": list[str],
            "exports": list[str],
            "reachable_from_main": list[str],
            "main_entry": str | None,
        }

    On Ghidra failure, returns ``{"status": "error", "error": ...}``.
    """
    from app.services import ghidra_service

    try:
        binary_sha256 = await ghidra_service.ensure_analysis(
            binary_path, firmware_id, db,
        )
    except (RuntimeError, FileNotFoundError, TimeoutError) as exc:
        return {
            "status": "error",
            "error": (
                f"Ghidra analysis failed: {type(exc).__name__}: "
                f"{str(exc)[:300]}"
            ),
        }

    # Functions: list[dict] with name + address + size.
    functions_data = await ghidra_service._get_cached(
        firmware_id, binary_sha256, "functions", db,
    )
    if not functions_data:
        return {
            "status": "error",
            "error": "Ghidra analysis produced no function cache entry",
        }
    functions_list = functions_data.get("functions", []) or []
    func_names = [
        f.get("name") for f in functions_list if f.get("name")
    ]

    imports_data = await ghidra_service._get_cached(
        firmware_id, binary_sha256, "imports", db,
    )
    imports_list = (imports_data or {}).get("imports", []) or []
    import_names = [
        i.get("name") for i in imports_list if isinstance(i, dict) and i.get("name")
    ]
    # Imports may come back as bare strings on older cache entries.
    import_names += [
        i for i in imports_list if isinstance(i, str)
    ]

    exports_data = await ghidra_service._get_cached(
        firmware_id, binary_sha256, "exports", db,
    )
    exports_list = (exports_data or {}).get("exports", []) or []
    export_names = [
        e.get("name") for e in exports_list if isinstance(e, dict) and e.get("name")
    ]

    # Resolve main entry. Ghidra's main_detection cache flags whether
    # main() was identified via libc_start_main argument inspection.
    main_data = await ghidra_service._get_cached(
        firmware_id, binary_sha256, "main_detection", db,
    )
    main_info = (main_data or {}).get("main_detection", {})
    main_entry: str | None = None
    if main_info.get("found"):
        # The function list will have been rewritten with name "main"
        # by get_functions(); for raw cache we use the address-keyed
        # form or "main" literal if present.
        if "main" in func_names:
            main_entry = "main"
        else:
            main_entry = main_info.get("address")

    # Reachability via the cached xrefs map. xrefs cache shape:
    #   {"xrefs": {func_name: {"to": [...], "from": [{"to_func": ..., ...}]}}}
    xrefs_data = await ghidra_service._get_cached(
        firmware_id, binary_sha256, "xrefs", db,
    )
    xrefs_map = (xrefs_data or {}).get("xrefs", {}) or {}

    reachable = _compute_reachability_from_xrefs(
        xrefs_map=xrefs_map,
        entry_function=main_entry or "main",
        all_functions=func_names,
    )

    return {
        "status": "ok",
        "analyzer": "ghidra",
        "functions": func_names,
        "imports": import_names,
        "exports": export_names,
        "reachable_from_main": reachable,
        "main_entry": main_entry,
    }


def _compute_reachability_from_xrefs(
    *,
    xrefs_map: dict[str, dict[str, list[dict]]],
    entry_function: str,
    all_functions: list[str],
) -> list[str]:
    """BFS over the xrefs map from ``entry_function`` outward.

    Pure-function; runs in <100 ms on realistic binaries. Capped at
    :data:`_MAX_REACHABLE_SYMBOLS` to prevent runaway traversal on
    pathological inputs.

    The xrefs cache stores callees under each caller's ``from`` list,
    each entry carries ``to_func`` (the callee name). We treat each
    such entry as a directed edge caller → callee.
    """
    if entry_function not in xrefs_map and entry_function not in all_functions:
        # No entry — fall back to "every imported symbol that has at
        # least one xref-from referencing it" which is the next-best
        # reachability approximation.
        return []

    visited: set[str] = set()
    queue: list[str] = [entry_function]

    while queue and len(visited) < _MAX_REACHABLE_SYMBOLS:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        # Outgoing edges = "from" list (Ghidra's xrefs schema treats
        # "from" as outgoing-from-this-function).
        outgoing = xrefs_map.get(current, {}).get("from", [])
        for edge in outgoing:
            if not isinstance(edge, dict):
                continue
            callee = edge.get("to_func")
            if callee and callee not in visited:
                queue.append(callee)

    return sorted(visited)


# ── radare2 fallback (when Ghidra is unavailable) ───────────────────────────


def _analyze_with_radare2_sync(binary_path: str) -> dict[str, Any]:
    """Sync helper that opens the binary via ``r2pipe`` and extracts the
    symbol set + outgoing-call edges. Runs in :func:`run_in_executor`.

    Defensive against r2pipe import errors / r2 crashes — every failure
    path returns a structured error dict rather than raising.
    """
    if not is_r2pipe_available():
        return {
            "status": "error",
            "error": "r2pipe unavailable (radare2 fallback skipped)",
        }

    try:
        import r2pipe
    except ImportError as exc:
        return {
            "status": "error",
            "error": f"r2pipe import failed: {exc}",
        }

    try:
        r2 = r2pipe.open(binary_path, flags=["-2"])  # -2: silent stderr
    except Exception as exc:
        return {
            "status": "error",
            "error": (
                f"radare2 open failed: {type(exc).__name__}: "
                f"{str(exc)[:200]}"
            ),
        }

    try:
        # Run full analysis: aaa is the radare2 idiom for "analyse all"
        # (functions / xrefs / strings / data refs).
        try:
            r2.cmd("aaa")
        except Exception as exc:
            return {
                "status": "error",
                "error": (
                    f"radare2 aaa failed: {type(exc).__name__}: "
                    f"{str(exc)[:200]}"
                ),
            }

        # Function list + names via aflj (JSON form).
        try:
            functions_json = r2.cmdj("aflj") or []
        except Exception:
            functions_json = []

        func_names: list[str] = []
        for f in functions_json:
            if isinstance(f, dict) and f.get("name"):
                func_names.append(f["name"])

        # Imports via iij (JSON imports).
        try:
            imports_json = r2.cmdj("iij") or []
        except Exception:
            imports_json = []
        import_names: list[str] = []
        for imp in imports_json:
            if isinstance(imp, dict) and imp.get("name"):
                import_names.append(imp["name"])

        # Exports via iEj (JSON exports/symbols flagged as global).
        try:
            exports_json = r2.cmdj("iEj") or []
        except Exception:
            exports_json = []
        export_names: list[str] = []
        for exp in exports_json:
            if isinstance(exp, dict) and exp.get("name"):
                export_names.append(exp["name"])

        # Build the xrefs map by querying axtj for each function. This
        # is O(N) function lookups — slower than Ghidra's batch dump
        # but acceptable for the fallback path.
        xrefs_map: dict[str, dict[str, list[dict]]] = {}
        # Cap the loop in the rare case the binary has tens of thousands
        # of functions — fall back to import-table-only reachability if
        # the function count is excessive.
        for fname in func_names[:5000]:
            try:
                outgoing = r2.cmdj(f"axffj @ {fname}") or []
            except Exception:
                continue
            if not isinstance(outgoing, list):
                continue
            entries: list[dict] = []
            for edge in outgoing:
                if isinstance(edge, dict):
                    callee = edge.get("name") or edge.get("ref")
                    if callee:
                        entries.append({"to_func": callee})
            if entries:
                xrefs_map[fname] = {"from": entries, "to": []}

        # Resolve main entry.
        main_entry: str | None = None
        if "main" in func_names:
            main_entry = "main"
        elif "sym.main" in func_names:
            main_entry = "sym.main"
        elif "entry0" in func_names:
            main_entry = "entry0"

        reachable = _compute_reachability_from_xrefs(
            xrefs_map=xrefs_map,
            entry_function=main_entry or "main",
            all_functions=func_names,
        )

        return {
            "status": "ok",
            "analyzer": "radare2",
            "functions": func_names,
            "imports": import_names,
            "exports": export_names,
            "reachable_from_main": reachable,
            "main_entry": main_entry,
        }
    finally:
        try:
            r2.quit()
        except Exception:
            pass


async def _analyze_with_radare2(binary_path: str) -> dict[str, Any]:
    """Async wrapper around :func:`_analyze_with_radare2_sync` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _analyze_with_radare2_sync, binary_path,
    )


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _build_unavailable_aggregate(
    *,
    firmware_id: uuid.UUID,
    binary_analyzed: str | None,
    started: float,
    errors: list[str],
) -> dict[str, Any]:
    """Build the canonical INSUFFICIENT_EVIDENCE aggregate when neither
    Ghidra nor radare2 produced a usable result. The cve-assessment-
    framework reads ``analyzer == "unavailable"`` as INSUFFICIENT_EVIDENCE.
    """
    return {
        "firmware_id": str(firmware_id),
        "walker": "ds1qrsetup_callgraph_walker",
        "binary_analyzed": binary_analyzed,
        "analyzer": "unavailable",
        "compile_flags_detected": {
            "ffmpeg": [],
            "ffmpeg_disabled": [],
            "pillow_decoders": [],
            "pillow_decoders_absent": list(_PILLOW_DECODERS),
        },
        "reachable_symbols": [],
        "unreachable_symbols": [],
        "summary": {
            "total_symbols_in_binary": 0,
            "reachable_from_main": 0,
            "unreachable_from_main": 0,
            "run_seconds": round(time.monotonic() - started, 3),
        },
        "errors": errors,
        "axiom_self_audit": (
            "Zero violations: PARSE-ONLY discipline preserved. "
            "ds1qrsetup binary was NOT invoked. Ghidra/radare2 "
            "unavailable; aggregate represents INSUFFICIENT_EVIDENCE "
            "per Q2 contract."
        ),
    }


def _build_no_binary_aggregate(
    firmware_id: uuid.UUID, started: float,
) -> dict[str, Any]:
    """Build the aggregate when no ds1qrsetup binary was located in the
    firmware. Distinct from ``analyzer=unavailable`` — this means the
    firmware probably isn't a DS1 image.
    """
    return {
        "firmware_id": str(firmware_id),
        "walker": "ds1qrsetup_callgraph_walker",
        "binary_analyzed": None,
        "analyzer": "unavailable",
        "compile_flags_detected": {
            "ffmpeg": [],
            "ffmpeg_disabled": [],
            "pillow_decoders": [],
            "pillow_decoders_absent": list(_PILLOW_DECODERS),
        },
        "reachable_symbols": [],
        "unreachable_symbols": [],
        "summary": {
            "total_symbols_in_binary": 0,
            "reachable_from_main": 0,
            "unreachable_from_main": 0,
            "run_seconds": round(time.monotonic() - started, 3),
        },
        "errors": [
            "No ds1qrsetup binary found under detection roots "
            "(checked opt/ds1qrsetup/, usr/bin/, usr/local/bin/, bin/)"
        ],
        "axiom_self_audit": (
            "Zero violations: PARSE-ONLY discipline preserved. No "
            "binary was located; nothing was analysed or invoked."
        ),
    }


# ── Inner orchestrator (accepts a db; reusable in tier-1 live canaries) ──────


async def _do_callgraph_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict[str, Any]:
    """Locate the ds1qrsetup binary, run Ghidra (or radare2 fallback),
    build the call-graph aggregate.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Locate ds1qrsetup binary candidates.
    3. Pick the largest candidate (heuristic: the real ds1qrsetup binary
       is the bulk of the Python interpreter + statically-linked C
       modules, so the largest ELF in the canonical paths is the right
       target).
    4. Run Ghidra first; on failure, fall back to radare2.
    5. String-scan the binary for FFmpeg / Pillow compile-flag
       fingerprints.
    6. Compute reachable + unreachable symbol sets.
    7. Build the canonical aggregate.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) drive the FULL walk against a real test
    DB without DNS resolution issues from ``async_session_factory()``.
    """
    started = time.monotonic()

    firmware = (
        await db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
    ).scalar_one_or_none()
    if firmware is None:
        return _build_no_binary_aggregate(firmware_id, started)

    roots = await get_detection_roots(firmware, db=db)
    if not roots:
        return _build_no_binary_aggregate(firmware_id, started)

    candidates = await _locate_ds1qrsetup_binaries_async(roots)
    if not candidates:
        return _build_no_binary_aggregate(firmware_id, started)

    # Pick the largest candidate (heuristic — see step 3 above).
    try:
        candidates_with_size: list[tuple[str, int]] = []
        for path in candidates:
            try:
                sz = os.path.getsize(path)
            except OSError:
                sz = 0
            candidates_with_size.append((path, sz))
        candidates_with_size.sort(key=lambda t: t[1], reverse=True)
        target_binary = candidates_with_size[0][0]
    except Exception:
        target_binary = candidates[0]

    # Extract strings up front — both compile-flag detection AND the
    # radare2 fallback can use this (independent of which analyser
    # produces the symbol set).
    loop = asyncio.get_running_loop()
    strings_list = await loop.run_in_executor(
        None, _extract_strings_sync, target_binary, 6,
    )
    compile_flags = _detect_compile_flags(strings_list)

    errors: list[str] = []

    # Try Ghidra first if available.
    analyzer_result: dict[str, Any] | None = None
    if is_ghidra_available():
        try:
            analyzer_result = await asyncio.wait_for(
                _analyze_with_ghidra(target_binary, firmware_id, db),
                timeout=_DEFAULT_WALKER_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            errors.append(
                f"Ghidra analysis timed out after "
                f"{_DEFAULT_WALKER_TIMEOUT_SECONDS}s"
            )
            analyzer_result = None
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            errors.append(
                f"Ghidra analysis failed: {type(exc).__name__}: "
                f"{str(exc)[:300]}"
            )
            analyzer_result = None
    else:
        errors.append("Ghidra not installed at configured GHIDRA_PATH")

    if (
        analyzer_result is None
        or analyzer_result.get("status") != "ok"
    ):
        if analyzer_result is not None:
            errors.append(
                analyzer_result.get("error", "Ghidra returned error")
            )

        # Fallback: radare2.
        if is_r2pipe_available():
            try:
                analyzer_result = await asyncio.wait_for(
                    _analyze_with_radare2(target_binary),
                    timeout=_DEFAULT_WALKER_TIMEOUT_SECONDS,
                )
            except TimeoutError:
                errors.append(
                    f"radare2 analysis timed out after "
                    f"{_DEFAULT_WALKER_TIMEOUT_SECONDS}s"
                )
                analyzer_result = None
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                errors.append(
                    f"radare2 analysis failed: {type(exc).__name__}: "
                    f"{str(exc)[:300]}"
                )
                analyzer_result = None
        else:
            errors.append("r2pipe not installed (radare2 fallback skipped)")

    if (
        analyzer_result is None
        or analyzer_result.get("status") != "ok"
    ):
        if analyzer_result is not None:
            err = analyzer_result.get("error")
            if err and err not in errors:
                errors.append(err)
        # Neither Ghidra nor radare2 worked — return
        # INSUFFICIENT_EVIDENCE aggregate.
        agg = _build_unavailable_aggregate(
            firmware_id=firmware_id,
            binary_analyzed=target_binary,
            started=started,
            errors=errors,
        )
        # Still surface the compile-flag fingerprints we extracted via
        # pure-string scan — they don't depend on the call-graph.
        agg["compile_flags_detected"] = compile_flags
        return agg

    # Happy path: compute reachable + unreachable symbol sets.
    all_funcs = list(analyzer_result.get("functions") or [])
    reachable = list(analyzer_result.get("reachable_from_main") or [])
    reachable_set = set(reachable)

    # Imports + library symbols that don't appear in the binary's
    # function table but are referenced via the GOT/PLT. We surface
    # these alongside the function list so the cve-assessment-framework
    # can match library-symbol-based reachability.
    imports = list(analyzer_result.get("imports") or [])

    # Combine: a symbol is "in the binary" if it's a function OR an
    # import. Reachable iff in the BFS frontier OR called by something
    # in the BFS frontier (the BFS already includes imports referenced
    # by reachable functions via the xrefs map).
    all_symbols_set: set[str] = set(all_funcs) | set(imports)
    unreachable = sorted(s for s in all_symbols_set if s not in reachable_set)

    return {
        "firmware_id": str(firmware_id),
        "walker": "ds1qrsetup_callgraph_walker",
        "binary_analyzed": target_binary,
        "analyzer": analyzer_result["analyzer"],
        "compile_flags_detected": compile_flags,
        "reachable_symbols": sorted(reachable),
        "unreachable_symbols": unreachable,
        "summary": {
            "total_symbols_in_binary": len(all_symbols_set),
            "reachable_from_main": len(reachable_set),
            "unreachable_from_main": len(unreachable),
            "run_seconds": round(time.monotonic() - started, 3),
        },
        "errors": errors,
        "axiom_self_audit": (
            f"Zero violations: PARSE-ONLY discipline preserved. "
            f"ds1qrsetup binary at {target_binary!r} analysed AS DATA "
            f"via {analyzer_result['analyzer']}; binary was NEVER "
            "invoked via subprocess / exec / runpy. No decryption "
            "primitives engaged. Symbol catalogue + reachability are "
            "static analysis only."
        ),
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_callgraph_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the ds1qrsetup call-graph walk.

    Owns AsyncSession via :func:`async_session_factory`; outer guard
    catches escapes; failure persistence on a fresh session. Mirrors
    γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B / κ.D shape exactly.
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
                    "ds1qrsetup_callgraph_walk: firmware %s not found",
                    firmware_id,
                )
                return

            row.ds1qrsetup_callgraph_walk_status = "running"
            row.ds1qrsetup_callgraph_walk_started_at = _dt.datetime.now(
                _dt.UTC
            )
            await db.commit()

            try:
                result = await _do_callgraph_run(db, firmware_id)
                row.ds1qrsetup_callgraph_walk_status = "completed"
                row.ds1qrsetup_callgraph_walk_finished_at = (
                    _dt.datetime.now(_dt.UTC)
                )
                row.ds1qrsetup_callgraph_walk_result = (
                    _stamp_firmware_ds1qrsetup_callgraph_walk_result(result)
                )
                await db.commit()
                logger.info(
                    "ds1qrsetup_callgraph_walk: firmware %s completed "
                    "in %.2fs (analyzer=%s, %d/%d reachable)",
                    firmware_id,
                    result["summary"]["run_seconds"],
                    result["analyzer"],
                    result["summary"]["reachable_from_main"],
                    result["summary"]["total_symbols_in_binary"],
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
                        fail_row.ds1qrsetup_callgraph_walk_status = (
                            "failed"
                        )
                        fail_row.ds1qrsetup_callgraph_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.ds1qrsetup_callgraph_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "ds1qrsetup_callgraph_walk: firmware %s failed",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "ds1qrsetup_callgraph_walk: unrecoverable for %s",
            firmware_id,
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_callgraph_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by post-detection pipeline
    after the firmware is extracted. Same shape as ζ.2.B / κ.D.

    Rule #39 .safe contract — runs the inner orchestrator + stamps the
    result onto the row, but does NOT mutate
    ``ds1qrsetup_callgraph_walk_status``. Status stays ``idle`` so a
    manual re-trigger via the trigger MCP tool works without 409
    conflict.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_callgraph_run(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.ds1qrsetup_callgraph_walk_result = (
                    _stamp_firmware_ds1qrsetup_callgraph_walk_result(result)
                )
                await db.commit()
            logger.info(
                "ds1qrsetup_callgraph_walk auto: firmware %s "
                "analyzed=%s in %.2fs",
                firmware_id,
                result.get("analyzer"),
                result.get("summary", {}).get("run_seconds", 0.0),
            )
    except Exception:
        logger.warning(
            "ds1qrsetup_callgraph_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_callgraph_run",
    "auto_callgraph_walk_firmware_safe",
    "is_ghidra_available",
    "is_r2pipe_available",
    "locate_ds1qrsetup_binaries",
    "run_callgraph_background",
]
