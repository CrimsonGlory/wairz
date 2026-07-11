"""Ghidra-based binary analysis service with full-binary caching.

Runs Ghidra once per binary via AnalyzeBinary.java to extract all data
(functions, imports, exports, xrefs, disassembly, decompilation, binary_info),
stores everything in PostgreSQL analysis_cache, and serves subsequent queries
instantly from the DB.

Falls back to DecompileFunction.java for single-function decompilation requests
on functions not covered in the initial batch (top 200 by size).

Module-level API replaced the previous ``GhidraAnalysisCache`` singleton
(Q4, 2026-04-19) — callers use ``ghidra_service.get_functions(...)`` etc.
directly. Module-scope ``_analysis_locks`` + ``_lock`` preserve the
concurrency guard so only one Ghidra process runs per binary SHA.
"""

import asyncio
import contextlib
import fcntl
import json
import logging
import os
import pathlib
import pwd
import re
import shutil
import tempfile
import time
import uuid
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import async_session_factory
from app.services import _cache
from app.utils.hashing import compute_file_sha256
from app.utils.log_sanitize import sanitize_for_log

logger = logging.getLogger(__name__)


def _compute_sha256(file_path: str) -> str:
    """Compute SHA256 of a file (thread-friendly wrapper)."""
    return compute_file_sha256(file_path)

# Markers used by both AnalyzeBinary.java and DecompileFunction.java
_START_MARKER = "===ANALYSIS_START==="
_END_MARKER = "===ANALYSIS_END==="
_DECOMPILE_START = "===DECOMPILE_START==="
_DECOMPILE_END = "===DECOMPILE_END==="

# Architecture mapping: Ghidra processor names → common short names
_ARCH_MAP = {
    "ARM": "arm",
    "AARCH64": "aarch64",
    "MIPS": "mips",
    "x86": "x86",
    "x86-64": "x86",
    "PowerPC": "ppc",
    "sparc": "sparc",
}


_ANALYSIS_LOCK_DIR = pathlib.Path(tempfile.gettempdir()) / "wairz-analysis-locks"

# Maps bare-metal rtos_flavor values to Ghidra import params for raw binaries.
# Activated inside ensure_analysis when the binary has no recognised format magic.
_FLAVOR_GHIDRA_PARAMS: dict[str, dict] = {
    "baremetal-cortexm": {
        "processor": "ARM:LE:32:Cortex",
        "loader": "BinaryLoader",
        "base_addr": 0x00000000,
    },
    "baremetal-mips16e": {
        "processor": "MIPS:LE:32:default",
        "loader": "BinaryLoader",
        "base_addr": 0x80000000,  # MIPS kseg0 start; override via start_binary_analysis base_addr param
        "setup_script": "Mips16eSetup.java",  # sets ISA_MODE=1 before AnalyzeBinary.java runs
    },
}


def _read_file_magic(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(4)
    except OSError:
        return b""


def _is_known_format(magic: bytes) -> bool:
    """Return True if the 4-byte magic indicates a self-describing binary format."""
    return magic[:4] in (
        b"\x7fELF",                          # ELF
        b"MZ\x90\x00", b"MZ\x00\x00",       # PE (various stubs)
        b"\xcf\xfa\xed\xfe",                 # Mach-O 64-bit LE
        b"\xce\xfa\xed\xfe",                 # Mach-O 32-bit LE
        b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",  # Mach-O BE
    )


def _format_ghidra_diag(stdout_text: str, stderr_text: str, max_lines: int = 15) -> str:
    """Extract the most useful diagnostic lines from Ghidra stdout/stderr.

    Filters for lines containing error/exception/warning keywords.
    Falls back to the last raw lines if nothing keyword-matches.
    Capped at max_lines to keep MCP response size reasonable.
    """
    _DIAG_KEYWORDS = ("error", "exception", "failed", "warn", "cannot", "unable", "no such")
    combined: list[str] = []
    for text in (stderr_text, stdout_text):
        for line in text.splitlines():
            s = line.strip()
            if s and any(kw in s.lower() for kw in _DIAG_KEYWORDS):
                combined.append(s)

    if not combined:
        fallback = stderr_text.strip() or stdout_text.strip()
        combined = [ln.strip() for ln in fallback.splitlines() if ln.strip()][-max_lines:]

    seen: set[str] = set()
    deduped: list[str] = []
    for ln in combined:
        if ln not in seen:
            seen.add(ln)
            deduped.append(ln)

    return "\n".join(f"  {ln}" for ln in deduped[-max_lines:])


def _make_ghidra_preexec_fn() -> Callable[[], None] | None:
    """Return a ``preexec_fn`` that drops a spawned Ghidra child to 'wairz'.

    Standard deployment already runs as the unprivileged 'wairz' user
    (entrypoint.sh execs uvicorn via ``su -s /bin/sh wairz``), so this is
    a no-op (``None``) there — there is no privilege to drop, and
    ``os.setuid()`` from a non-root process raises ``PermissionError``.
    Only meaningful for a hypothetical root-context invocation, where it
    keeps GZF process-mode project ownership consistently 'wairz' rather
    than root.
    """
    if os.geteuid() != 0:
        return None
    try:
        pw = pwd.getpwnam("wairz")
    except KeyError:
        return None

    def _drop_to_wairz() -> None:
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)

    return _drop_to_wairz


async def resolve_binary_import_params(
    binary_path: str,
    firmware_id: uuid.UUID,
) -> dict | None:
    """Return Ghidra import params for a raw binary, or None for ELF/PE/Mach-O.

    Reads the 4-byte magic; if the format is self-describing (ELF/PE/Mach-O)
    returns None so Ghidra can auto-detect. For raw blobs, queries the
    firmware row's rtos_flavor and returns the matching _FLAVOR_GHIDRA_PARAMS
    entry (processor, loader, base_addr, optional setup_script).

    Called by every Ghidra script launcher — not just the full-analysis path —
    so auxiliary scripts (DecompileFunction.java, FindStringRefs.java, etc.)
    also import raw binaries with the correct processor / loader.

    .gzf archives are checked by extension before the magic-byte read and
    always return None: a saved Ghidra project archive already carries its
    own processor/loader/base-address state from when it was first imported,
    so forcing rtos_flavor BinaryLoader params onto it here would corrupt
    that baked-in state rather than help Ghidra import it.
    """
    if os.path.splitext(binary_path)[1].lower() == ".gzf":
        return None

    loop = asyncio.get_running_loop()
    magic = await loop.run_in_executor(None, _read_file_magic, binary_path)
    if _is_known_format(magic):
        return None

    from sqlalchemy import select as _select

    from app.models.firmware import Firmware as _FirmwareModel  # noqa: PLC0415
    async with async_session_factory() as hint_db:
        row = await hint_db.execute(
            _select(_FirmwareModel.rtos_flavor).where(_FirmwareModel.id == firmware_id)
        )
        flavor = row.scalar_one_or_none()
    if flavor and flavor in _FLAVOR_GHIDRA_PARAMS:
        params = _FLAVOR_GHIDRA_PARAMS[flavor]
        logger.info(
            "Raw binary for firmware %s (flavor=%s) — Ghidra params: %s",
            sanitize_for_log(firmware_id), sanitize_for_log(flavor), sanitize_for_log(params)
        )
        return params
    return None


def _acquire_analysis_flock(lock_path: str) -> int:
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _release_analysis_flock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextlib.asynccontextmanager
async def _flock_analysis_lock(lock_key: str):
    """Host-wide exclusive lock via fcntl.flock (local / shared-filesystem).

    The asyncio.Event guard only dedupes coroutines within a single Python
    process. Each MCP client connection spawns its own wairz-mcp process, so
    concurrent connections can otherwise each decide "no cache yet, I'll run
    Ghidra" and spawn duplicate analyses against the same binary — observed
    in the wild as 7 parallel Ghidras on a 7 MB binary, none finishing.
    fcntl.flock serializes them at the OS level and is released automatically
    if a process crashes, so failed analyses don't leave the binary blocked.
    """
    _ANALYSIS_LOCK_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = str(_ANALYSIS_LOCK_DIR / f"{lock_key}.lock")
    fd = await asyncio.to_thread(_acquire_analysis_flock, lock_path)
    try:
        yield
    finally:
        await asyncio.to_thread(_release_analysis_flock, fd)


async def _renew_redis_lock(lock, ttl: int) -> None:
    """Keep a held Redis lock alive while long work (a Ghidra import) runs."""
    interval = max(1, ttl // 3)
    while True:
        await asyncio.sleep(interval)
        try:
            await lock.extend(ttl, replace_ttl=True)
        except Exception:
            return


@contextlib.asynccontextmanager
async def _redis_analysis_lock(lock_key: str):
    """Distributed exclusive lock via Redis (no shared filesystem for flock)."""
    import redis.asyncio as aioredis

    settings = get_settings()
    ttl = settings.redis_lock_ttl_seconds
    client = aioredis.from_url(settings.redis_url)
    lock = client.lock(
        f"wairz:analysis-lock:{lock_key}", timeout=ttl, blocking=True,
    )
    await lock.acquire()
    renew = asyncio.create_task(_renew_redis_lock(lock, ttl))
    try:
        yield
    finally:
        renew.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await renew
        with contextlib.suppress(Exception):
            await lock.release()
        with contextlib.suppress(Exception):
            await client.aclose()


@contextlib.asynccontextmanager
async def _cross_process_analysis_lock(binary_sha256: str):
    """Exclusive lock keyed by binary sha256 (or any caller-supplied key).

    Dispatches on the compute backend: fcntl.flock when running locally with a
    shared filesystem; a Redis lock when work is distributed across hosts
    (``compute_backend != "local"``). Local behavior is byte-for-byte the
    flock-only path we shipped before the enterprise merge.
    """
    # Default to flock unless explicitly distributed. MagicMock/partial
    # settings objects (unit tests) must not force the Redis path.
    if get_settings().compute_backend == "aws_batch":
        async with _redis_analysis_lock(binary_sha256):
            yield
    else:
        async with _flock_analysis_lock(binary_sha256):
            yield


# ---------------------------------------------------------------------------
# GZF process-mode project location — single source of truth shared by the
# write path (run_ghidra_headless use_saved_project=True, in
# ai/tools/ghidra_research.py) and the read path (ensure_analysis /
# decompile_function below). Both MUST agree on where a GZF's persistent
# Ghidra project lives, or script-applied renames silently diverge from what
# list_functions/decompile_function read (see CLAUDE.md TODO 2026-06-25 —
# GZF process-mode renames invisible to the analysis cache).
# ---------------------------------------------------------------------------


def gzf_project_paths(gzf_sha256: str) -> tuple[str, str, str]:
    """Return (proj_base, proj_name, rep_dir) for a GZF's persistent project.

    Keyed by the first 16 hex chars of the GZF's own content SHA256 (the
    same value used as binary_sha256 when the GZF is the analysis target),
    so the same archive always maps to the same on-disk project directory.
    """
    settings = get_settings()
    proj_base = os.path.join(settings.ghidra_projects_dir, gzf_sha256[:16])
    proj_name = "gzf_project"
    rep_dir = os.path.join(proj_base, f"{proj_name}.rep")
    return proj_base, proj_name, rep_dir


async def gzf_process_project_exists(gzf_sha256: str) -> bool:
    """True if a GZF process-mode project has already been restored for this hash.

    When True, ensure_analysis/decompile_function route Ghidra script runs
    through that persistent project (-process mode) instead of re-importing
    the pristine archive, so they observe any script-applied renames/retypes.
    """
    _, _, rep_dir = gzf_project_paths(gzf_sha256)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, os.path.isdir, rep_dir)


# ---------------------------------------------------------------------------
# GZF persistent-project revision counter — durable cache-invalidation signal.
#
# The OLD mechanism was a consume-once "_wairz_renamed" dirty flag written by
# the write path and DELETED by the first ensure_analysis read. That was
# fragile: after the flag was consumed once, any later cache rebuild (e.g. a
# force_reanalyze worker re-importing the pristine archive, or a second rename)
# had no flag left to trigger re-invalidation, so renames went permanently
# invisible to list_functions/find_callers/decompile_function.
#
# The rev counter is MONOTONIC and NEVER consumed. Every rename run bumps it;
# the read path stamps the rev it analyzed into the ghidra_full_analysis
# sentinel. ensure_analysis compares the on-disk rev against the cached rev and
# rebuilds whenever they diverge — so any number of renames, and any stale
# cache rebuild, self-heals on the next read.
# ---------------------------------------------------------------------------

_GZF_REV_FILENAME = "_wairz_rev"


def _read_gzf_rev_sync(proj_base: str) -> int:
    """Read the persistent project's monotonic rev (0 if never bumped)."""
    rev_path = os.path.join(proj_base, _GZF_REV_FILENAME)
    try:
        with open(rev_path, encoding="utf-8") as f:
            return int(f.read().strip() or "0")
    except (OSError, ValueError):
        return 0


def bump_gzf_project_rev_sync(proj_base: str) -> int:
    """Atomically increment and return the persistent project's rev counter.

    Written via tmp-file + os.replace so a crash mid-write can never leave a
    partially-written rev that parses as a smaller/garbage value. Sync (called
    from the write path's run_in_executor). Returns the new rev.
    """
    new_rev = _read_gzf_rev_sync(proj_base) + 1
    os.makedirs(proj_base, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=proj_base, prefix=".rev-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(str(new_rev))
        os.replace(tmp_path, os.path.join(proj_base, _GZF_REV_FILENAME))
    except Exception:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)
        raise
    return new_rev


async def gzf_project_rev(proj_base: str) -> int:
    """Async wrapper around _read_gzf_rev_sync."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _read_gzf_rev_sync, proj_base)


async def resolve_gzf_process_target(
    binary_path: str, binary_sha256: str,
) -> tuple[str, bool]:
    """Single source of truth for GZF -process-mode routing.

    Returns (ghidra_target, is_gzf_process_mode). For a .gzf whose persistent
    project exists, returns the PROJECT_PROCESS_MODE reference so the Ghidra
    run observes script-applied renames; otherwise returns binary_path
    unchanged. Used by ensure_analysis, decompile_function,
    batch_decompile_functions, and the detached analysis worker so EVERY
    Ghidra invocation against a renamed GZF routes through the persistent
    project identically (the divergence between these paths was the root cause
    of renames being visible to decompile_function but not list_functions /
    batch_decompile_functions).
    """
    if binary_path.lower().endswith(".gzf") and await gzf_process_project_exists(
        binary_sha256
    ):
        proj_base, proj_name, _ = gzf_project_paths(binary_sha256)
        return f"PROJECT_PROCESS_MODE:{proj_base}:{proj_name}", True
    return binary_path, False


def _proj_base_from_process_target(analysis_target: str) -> str | None:
    """Extract proj_base from a 'PROJECT_PROCESS_MODE:<proj_base>:<proj_name>'
    target, or None if the target is not a process-mode reference.

    proj_base is an absolute path that itself contains ':' on no sane setup,
    but to be safe we split off the known leading prefix and trailing
    proj_name component rather than a naive split.
    """
    prefix = "PROJECT_PROCESS_MODE:"
    if not analysis_target.startswith(prefix):
        return None
    rest = analysis_target[len(prefix):]
    # The trailing component is the proj_name (no ':'); everything before the
    # last ':' is proj_base.
    sep = rest.rfind(":")
    if sep == -1:
        return None
    return rest[:sep]


def _build_gzf_process_command(
    proj_base: str,
    proj_name: str,
    script_name: str,
    script_args: list[str] | None = None,
    *,
    extra_script_path: str | None = None,
) -> list[str]:
    """Build an analyzeHeadless command for a GZF process-mode project.

    Used so that .gzf analysis (AnalyzeBinary.java / DecompileFunction.java)
    observes the live, possibly-renamed state of a GZF process-mode project
    (see gzf_project_paths) instead of the pristine archive. Distinct from
    ``_build_process_command`` which targets the per-binary persistent store.
    """
    settings = get_settings()
    analyze_headless = os.path.join(settings.ghidra_path, "support", "analyzeHeadless")
    scripts_path = settings.ghidra_scripts_path

    cmd = [analyze_headless, proj_base, proj_name, "-process", "*", "-noanalysis"]
    if extra_script_path:
        # Single combined -scriptPath flag — see _build_import_command's
        # extra_script_path docstring for why two separate flags don't work.
        cmd.extend(["-scriptPath", f"{extra_script_path};{scripts_path}"])
        postscript_target = os.path.join(extra_script_path, script_name)
    else:
        cmd.extend(["-scriptPath", scripts_path])
        postscript_target = script_name
    cmd.extend(["-postScript", postscript_target])
    if script_args:
        cmd.extend(script_args)
    return cmd


def _map_architecture(ghidra_arch: str) -> str:
    """Map Ghidra architecture string to common short name."""
    for key, val in _ARCH_MAP.items():
        if key.lower() in ghidra_arch.lower():
            return val
    return ghidra_arch.lower()


def _parse_analysis_output(raw_output: str) -> dict | None:
    """Extract JSON from Ghidra AnalyzeBinary.java output between markers.

    Ghidra wraps println() output with log prefixes like:
      INFO  AnalyzeBinary.java> {json...} (GhidraScript)
    So we extract the outermost { ... } between the markers.
    """
    start = raw_output.find(_START_MARKER)
    end = raw_output.find(_END_MARKER)

    if start == -1 or end == -1:
        return None

    content = raw_output[start + len(_START_MARKER):end].strip()
    if not content:
        return None

    # Find the outermost JSON object braces within the content
    json_start = content.find("{")
    json_end = content.rfind("}")
    if json_start == -1 or json_end == -1 or json_end <= json_start:
        logger.error("No JSON object found between analysis markers")
        return None

    json_str = content[json_start:json_end + 1]

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Ghidra analysis JSON: %s", exc)
        return None


# Ghidra's headless logger wraps each script println() as
#   "INFO  DecompileFunction.java> <text> (GhidraScript)"
# (only the first physical line of a multi-line println is wrapped). Strip the
# leading level+script prefix and the trailing " (GhidraScript)" marker so the
# decompiled C comes back clean, the same way _parse_analysis_output pulls the
# bare JSON out from between its markers.
_GHIDRA_LOG_PREFIX = re.compile(r"^(?:INFO|WARN|WARNING|ERROR|DEBUG)\s+\S+\.java>\s?")
_GHIDRA_LOG_SUFFIX = re.compile(r"\s*\(GhidraScript\)\s*$")


def _strip_ghidra_log_wrapper(content: str) -> str:
    cleaned = [
        _GHIDRA_LOG_SUFFIX.sub("", _GHIDRA_LOG_PREFIX.sub("", line))
        for line in content.splitlines()
    ]
    return "\n".join(cleaned).strip()


def _parse_decompile_output(raw_output: str) -> str | None:
    """Extract decompiled code from DecompileFunction.java output between markers."""
    start = raw_output.find(_DECOMPILE_START)
    end = raw_output.find(_DECOMPILE_END)

    if start == -1 or end == -1:
        return None

    content = raw_output[start + len(_DECOMPILE_START):end].strip()
    content = _strip_ghidra_log_wrapper(content)
    return content if content else None


# Name of the single Ghidra project created per binary. The program inside is
# named after the imported file's basename, but every reuse run uses bare
# "-process" (which targets all programs in the project, of which there is
# exactly one), so the program name never has to be threaded through.
_PROJECT_NAME = "wairz"
_ANALYZED_MARKER = ".wairz_analyzed"

# --- Reuse-worker queue (cloud mode) ----------------------------------------
# In cloud mode the backend is a small Fargate task that must NOT run Ghidra
# itself. Query scripts (decompile/string-refs/layouts/dataflow) are delegated
# over Redis to a warm "reuse worker" Batch job that runs -process against the
# shared EFS project. See enterprise/PLAN.md §3.2 (C8).
_REUSE_QUEUE = "wairz:ghidra:reuse:q"
_REUSE_RESULT_PREFIX = "wairz:ghidra:reuse:res:"
_REUSE_WORKER_HB = "wairz:ghidra:reuse:worker:hb"      # worker liveness (TTL)
_REUSE_WORKER_SUBMIT = "wairz:ghidra:reuse:worker:submit"  # de-dupe submits
_REUSE_RESULT_TTL = 120          # seconds a result waits to be collected
_REUSE_DISPATCH_GRACE = 240      # extra wait budget for a cold worker (boot)
_REUSE_SUBMIT_TTL = 300          # how long a "submitting" marker holds


@lru_cache(maxsize=1)
def _ghidra_version() -> str:
    """Installed Ghidra version, read from application.properties.

    Used to namespace the persistent project store so a Ghidra upgrade never
    tries to open a project written by an older (incompatible) version.
    """
    props = os.path.join(
        get_settings().ghidra_path, "Ghidra", "application.properties",
    )
    try:
        with open(props, encoding="utf-8") as f:
            for line in f:
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip() or "unknown"
    except OSError:
        pass
    return "unknown"


def _project_dir(binary_sha256: str) -> str:
    """Persistent Ghidra project directory for a binary, keyed by content hash.

    Layout: <GHIDRA_PROJECT_ROOT>/<ghidra_version>/<sha256>/. Keying by sha256
    means a binary shipped in many firmwares (e.g. busybox) is analyzed once
    and reused everywhere, across sessions/agents/users.
    """
    return os.path.join(
        get_settings().ghidra_project_root, _ghidra_version(), binary_sha256,
    )


def _analyze_headless_path() -> str:
    return os.path.join(get_settings().ghidra_path, "support", "analyzeHeadless")


def _build_import_command(
    binary_path: str,
    project_dir: str,
    script_name: str,
    script_args: list[str] | None = None,
    *,
    ghidra_import_params: dict | None = None,
    extra_script_path: str | None = None,
) -> list[str]:
    """Build a Ghidra analyzeHeadless command.

    ``ghidra_import_params`` (CLAUDE.md Rule #52 — dormant infrastructure
    unlock 2026-05-19) optionally pins the loader / processor / base
    address for raw bare-metal binaries that Ghidra's auto-detect can't
    handle. Mirrors the dict shape declared in chip_family YAML manifests
    + the half-built outputs of parsers/{mediatek_tinysys,atf,geniezone}.

    Recognised keys:
      - ``processor``: Ghidra processor string (e.g. ``ARM:LE:32:Cortex``)
      - ``loader``: typically ``BinaryLoader`` for raw .bin
      - ``base_addr``: integer load address
      - ``load_offset_in_file`` / ``load_length``: optional sub-region load
      - ``cspec``: optional calling-convention selector
      - ``setup_script``: name of a .java script to run as a -preScript,
        i.e. BEFORE Ghidra's auto-analysis pass.  Setting the ISA context
        register here ensures Ghidra's own analyzers see MIPS16E mode from
        the start rather than first mangling the binary as MIPS32.
        Example: ``Mips16eSetup.java``.
      - ``code_offset``: optional integer byte offset from the load base to
        the first real instruction.  Passed as the first script argument to
        ``setup_script`` so the script can skip a firmware header.
        Example: ``0x30`` for RTL8761BU (48-byte Realtechk header).

    Unknown keys are silently ignored so future schema additions don't
    break the build path.

    ``extra_script_path`` (bugfix 2026-06-22, corrected same day after a
    verification pass found the first fix didn't work): when a caller
    resolves ``script_name`` from a research file written to a temp
    directory (save_ghidra_script / run_ghidra_headless script_file_id
    flow), that temp directory must (a) actually be registered with
    analyzeHeadless and (b) be the file that runs, with NO dependence on
    name-collision resolution order. Two real Ghidra behaviours (verified
    empirically against the bundled Ghidra 12.1.2_PUBLIC by running
    analyzeHeadless directly — see backend/tests/test_ghidra_service.py
    for the same scenarios as mocked regression tests) make the naive
    approach wrong:

      1. Passing ``-scriptPath`` as two SEPARATE CLI arguments does not
         accumulate — analyzeHeadless keeps only the LAST occurrence.
         The first fix (passing extra_script_path and scripts_path as two
         ``-scriptPath`` flags) meant the bundled scripts_path silently
         became the ONLY registered script directory; extra_script_path
         was dropped entirely, so a brand-new research script could not
         be found under either script_name or script_file_id. Multiple
         search directories must be joined into ONE ``-scriptPath`` flag
         using Ghidra's own ``;``-delimited list syntax (per
         ``analyzeHeadless -help``: ``-scriptPath "<path1>[;<path2>...]"``).

      2. Even with both directories correctly registered, resolving
         ``-postScript <bare-name>`` against a name that exists in more
         than one registered directory is NOT first-match-by-search-order.
         It is alphabetical-last-wins across the full directory list
         (confirmed by reversing CLI order and renaming probe directories
         — the alphabetically last path always won, independent of flag
         order). Relying on that is fragile and accidental in either
         direction. The robust fix is to never let resolution depend on a
         bare-name collision at all: when extra_script_path is set, pass
         ``-postScript`` the ABSOLUTE path to the saved script file
         (``os.path.join(extra_script_path, script_name)``) rather than
         the bare basename. analyzeHeadless still requires the
         containing directory to be present in ``-scriptPath`` (an
         absolute -postScript path with no matching -scriptPath entry
         fails with "Failed to find script in any script directory"),
         but once it is, the absolute path deterministically selects that
         exact file regardless of what else shares its basename.

    Note: NO ``-deleteProject`` — the analyzed project is kept on disk for reuse
    (persistent Ghidra project store from upstream enterprise work).
    """
    settings = get_settings()
    scripts_path = settings.ghidra_scripts_path
    cmd = [
        _analyze_headless_path(),
        project_dir,
        _PROJECT_NAME,
        "-import",
        binary_path,
    ]
    if extra_script_path:
        # Single combined flag — see extra_script_path docstring above for
        # why two separate -scriptPath flags silently drop the first one.
        cmd.extend(["-scriptPath", f"{extra_script_path};{scripts_path}"])
    else:
        cmd.extend(["-scriptPath", scripts_path])

    # Optional setup script runs as -preScript so ISA context is set BEFORE
    # Ghidra's auto-analysis pass (not after, when MIPS32 damage is done).
    # code_offset (if non-zero) is appended as the first script argument so
    # the setup script can skip a firmware header before seeding disassembly.
    if ghidra_import_params and (setup := ghidra_import_params.get("setup_script")):
        cmd.extend(["-preScript", str(setup)])
        if offset := ghidra_import_params.get("code_offset", 0):
            cmd.append(hex(int(offset)))

    # When a setup script is present, it must run as -postScript BEFORE
    # script_name so that MIPS16E correction (clear MIPS32 garbage, re-set
    # ISAModeSwitch, re-seed, analyzeChanges) completes BEFORE AnalyzeBinary
    # captures the function list.  Running setup after AnalyzeBinary means
    # AnalyzeBinary writes MIPS32 state to the cache and the fix is too late.
    if ghidra_import_params and (setup := ghidra_import_params.get("setup_script")):
        cmd.extend(["-postScript", str(setup)])
        if offset := ghidra_import_params.get("code_offset", 0):
            cmd.append(hex(int(offset)))

    # Absolute path when the script lives in extra_script_path — see
    # extra_script_path docstring above for why a bare name is not safe.
    postscript_target = (
        os.path.join(extra_script_path, script_name) if extra_script_path else script_name
    )
    cmd.extend(["-postScript", postscript_target])

    if ghidra_import_params:
        if (proc := ghidra_import_params.get("processor")):
            cmd.extend(["-processor", str(proc)])
        if (loader := ghidra_import_params.get("loader")):
            cmd.extend(["-loader", str(loader)])
        if (base := ghidra_import_params.get("base_addr")) is not None:
            cmd.extend(["-loader-baseAddr", f"0x{int(base):X}"])
        if (offset := ghidra_import_params.get("load_offset_in_file")) is not None:
            cmd.extend(["-loader-fileOffset", str(int(offset))])
        if (length := ghidra_import_params.get("load_length")) is not None:
            cmd.extend(["-loader-length", str(int(length))])
        if (cspec := ghidra_import_params.get("cspec")):
            cmd.extend(["-cspec", str(cspec)])

    if script_args:
        cmd.extend(script_args)
    return cmd


# Back-compat alias for tests and callers that predate the
# persistent-project rename (_build_analyze_command → _build_import_command).
_build_analyze_command = _build_import_command


def _build_process_command(
    project_dir: str,
    script_name: str,
    script_args: list[str] | None = None,
) -> list[str]:
    """Run a script against an already-analyzed persistent project (reuse).

    -noanalysis skips re-running auto-analysis (the expensive part — already
    done at import); -readOnly never writes back, so the saved project is
    untouched. Bare -process targets the project's single program.
    """
    cmd = [
        _analyze_headless_path(),
        project_dir,
        _PROJECT_NAME,
        "-process",
        "-noanalysis",
        "-readOnly",
        "-scriptPath",
        get_settings().ghidra_scripts_path,
        "-postScript",
        script_name,
    ]
    if script_args:
        cmd.extend(script_args)
    return cmd


async def _exec_headless(cmd: list[str], effective_timeout: int) -> str:
    """Run an analyzeHeadless command and return raw stdout.

    Captures stdout/stderr to tempfiles rather than asyncio PIPEs.
    AnalyzeBinary.java for a multi-MB binary can emit hundreds of MB of
    println output; with PIPE + communicate(), the kernel 64 KB pipe buffer
    fills before asyncio drains it and Ghidra deadlocks blocked in a
    FileOutputStream.write syscall. Tempfiles let the kernel buffer arbitrary
    output with no possibility of deadlock; we read them once Ghidra exits.
    """
    with tempfile.TemporaryFile(prefix="ghidra-stdout-") as stdout_f, \
         tempfile.TemporaryFile(prefix="ghidra-stderr-") as stderr_f:
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=stdout_f,
                stderr=stderr_f,
            )
        except FileNotFoundError:
            raise RuntimeError(
                f"Ghidra not found at {cmd[0]}. "
                "Install Ghidra or set GHIDRA_PATH in .env."
            )

        try:
            await asyncio.wait_for(process.wait(), timeout=effective_timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise TimeoutError(
                f"Ghidra analysis timed out after {effective_timeout}s"
            )

        stdout_f.seek(0)
        stderr_f.seek(0)
        stdout = stdout_f.read()
        stderr = stderr_f.read()

    stdout_text = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr.decode("utf-8", errors="replace")

    if process.returncode != 0:
        # Ghidra often returns non-zero but still produces output.
        known_markers = (
            _START_MARKER, _DECOMPILE_START,
            "===STRING_REFS_START===", "===TAINT_START===",
            "===STACK_LAYOUT_START===", "===GLOBAL_LAYOUT_START===",
        )
        if not any(m in stdout_text for m in known_markers):
            logger.error(
                "Ghidra failed (rc=%d): %s",
                process.returncode,
                stderr_text[-500:],
            )
            raise RuntimeError(
                f"Ghidra analysis failed (exit code {process.returncode})"
            )

    return stdout_text


async def _ensure_project_imported(
    binary_path: str, binary_sha256: str, effective_timeout: int,
) -> str | None:
    """Import + analyze the binary into its persistent project if not already.

    Returns AnalyzeBinary.java's raw output when it performs the import (so the
    caller can reuse it instead of a redundant -process run), or None if the
    project already existed. UNLOCKED — callers must hold
    _cross_process_analysis_lock(binary_sha256) so only one import runs and no
    two headless processes touch the same project concurrently.
    """
    project_dir = _project_dir(binary_sha256)
    marker = os.path.join(project_dir, _ANALYZED_MARKER)

    if os.path.exists(marker):  # noqa: ASYNC240 — pre-flight stat before bounded Ghidra import
        return None

    # A project dir without the marker is a crashed/partial import — discard it
    # so the retry starts clean (avoids a stale Ghidra project lock).
    if os.path.isdir(project_dir):  # noqa: ASYNC240 — pre-flight stat before rmtree/import
        shutil.rmtree(project_dir, ignore_errors=True)
    os.makedirs(project_dir, exist_ok=True)

    logger.info(
        "Importing + analyzing %s into persistent project %s",
        os.path.basename(binary_path), binary_sha256[:12],
    )
    try:
        raw_output = await _exec_headless(
            _build_import_command(binary_path, project_dir, "AnalyzeBinary.java"),
            effective_timeout,
        )
    except BaseException:
        # Don't leave a half-imported project that future runs would treat as
        # reusable (the marker is only written on success, but the dir itself
        # could confuse a -process run, so clear it).
        shutil.rmtree(project_dir, ignore_errors=True)
        raise

    Path(marker).write_text(  # noqa: ASYNC240 — single marker write after import
        f"{binary_sha256}\n", encoding="utf-8",
    )
    # A new project just landed — prune the store back to the cap if needed.
    await _gc_project_store()
    return raw_output


async def _run_process_script(
    binary_sha256: str,
    script_name: str,
    script_args: list[str] | None,
    effective_timeout: int,
) -> str:
    """Run a read-only script against the already-analyzed persistent project.

    UNLOCKED — callers hold _cross_process_analysis_lock(binary_sha256).
    """
    logger.info(
        "Reusing project %s for %s (-process, no re-analysis)",
        binary_sha256[:12], script_name,
    )
    _touch_project(binary_sha256)
    return await _exec_headless(
        _build_process_command(_project_dir(binary_sha256), script_name, script_args),
        effective_timeout,
    )


def _touch_project(binary_sha256: str) -> None:
    """Bump the project's access time so the LRU GC keeps hot projects."""
    marker = os.path.join(_project_dir(binary_sha256), _ANALYZED_MARKER)
    try:
        os.utime(marker, None)
    except OSError:
        pass


def _try_evict_project(sha256: str, project_dir: str) -> bool:
    """Evict a project iff no one holds its per-binary lock (non-blocking).

    Returns True if evicted. Skips projects currently being imported/reused so
    GC never rmtree's files out from under an in-flight Ghidra run.
    """
    lock_path = str(_ANALYSIS_LOCK_DIR / f"{sha256}.lock")
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            return False  # in use — leave it
        shutil.rmtree(project_dir, ignore_errors=True)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    finally:
        os.close(fd)


def _gc_project_store_sync() -> None:
    """Evict least-recently-used projects once the store exceeds the cap.

    'Recently used' = marker mtime, bumped on every import and reuse
    (_touch_project). Only fully-analyzed projects (marker present) are counted
    and evicted. Evictions are logged — never silent.
    """
    settings = get_settings()
    cap = settings.ghidra_project_cache_max
    if cap <= 0:
        return
    # Eviction takes the per-binary flock under this dir; ensure it exists even
    # when GC runs before any lock has been acquired this process.
    _ANALYSIS_LOCK_DIR.mkdir(parents=True, exist_ok=True)
    version_root = os.path.join(settings.ghidra_project_root, _ghidra_version())
    try:
        names = os.listdir(version_root)
    except OSError:
        return

    projects = []
    for name in names:
        d = os.path.join(version_root, name)
        marker = os.path.join(d, _ANALYZED_MARKER)
        try:
            if os.path.isdir(d) and os.path.exists(marker):
                projects.append((os.path.getmtime(marker), d, name))
        except OSError:
            continue

    if len(projects) <= cap:
        return

    projects.sort(key=lambda p: p[0])  # oldest access first
    evicted = 0
    for _, d, name in projects[: len(projects) - cap]:
        if _try_evict_project(name, d):
            evicted += 1
            logger.info(
                "GC: evicted LRU Ghidra project %s (store cap=%d)", name[:12], cap,
            )
    if evicted:
        logger.info(
            "GC: evicted %d project(s); store now ~%d (cap=%d)",
            evicted, len(projects) - evicted, cap,
        )


async def _gc_project_store() -> None:
    """Run the project-store GC off the event loop; never raises."""
    try:
        await asyncio.to_thread(_gc_project_store_sync)
    except Exception:
        logger.warning("Project-store GC failed (non-fatal)", exc_info=True)


async def _run_ghidra_local(
    binary_path: str,
    script_name: str,
    script_args: list[str] | None,
    effective_timeout: int,
    binary_sha256: str,
) -> str:
    """Actually run Ghidra on THIS host against the persistent project.

    On first touch the binary is imported + auto-analyzed once; the script then
    runs against that project, and every later call reuses it via
    -process -readOnly -noanalysis. This is the executor for local mode AND for
    the cloud reuse worker (which calls it directly on its Batch instance).
    """
    # Serialize all headless access to this binary's project (import or reuse):
    # a local Ghidra project allows only one headless process at a time, and
    # this also dedupes concurrent first-touch imports. The lock is flock
    # locally and Redis-backed in cloud (see _cross_process_analysis_lock).
    async with _cross_process_analysis_lock(binary_sha256):
        imported = await _ensure_project_imported(
            binary_path, binary_sha256, effective_timeout,
        )
        if script_name == "AnalyzeBinary.java" and imported is not None:
            # We just analyzed; reuse that output instead of a redundant pass.
            return imported
        return await _run_process_script(
            binary_sha256, script_name, script_args, effective_timeout,
        )


async def run_ghidra_subprocess(
    binary_path: str,
    script_name: str,
    script_args: list[str] | None = None,
    timeout: int | None = None,  # noqa: ASYNC109 -- caller-supplied timeout per Rule #29 contract
    ghidra_import_params: dict | None = None,
    firmware_id: uuid.UUID | None = None,
    binary_sha256: str | None = None,
    is_gzf_process_mode: bool = False,
) -> str:
    """Run a Ghidra headless script against the persistent per-binary project.

    Dispatches on ``compute_backend``: locally it runs Ghidra in-process
    (``_run_ghidra_local``); in cloud mode it delegates to the warm reuse
    worker over Redis (``_run_ghidra_remote``).

    ``is_gzf_process_mode``: if True, ``binary_path`` is a GZF project
    reference (``PROJECT_PROCESS_MODE:proj_base:proj_name``) and the
    script runs via ``_build_gzf_process_command`` + ``_exec_headless``.

    ``ghidra_import_params`` / ``firmware_id`` are accepted for API
    compatibility with our fork's callers; import params are applied on
    first-touch via ``_build_import_command`` when the persistent project
    is created (passed through ``_ensure_project_imported`` callers).
    """
    del ghidra_import_params  # reserved for first-touch import path extension
    effective_timeout = timeout if timeout is not None else get_settings().ghidra_timeout

    # GZF process-mode projects are local-only (project lives on this host).
    if is_gzf_process_mode:
        _, proj_base, proj_name = binary_path.split(":", 2)
        cmd = _build_gzf_process_command(
            proj_base, proj_name, script_name, script_args,
        )
        logger.info(
            "Running Ghidra %s on GZF project %s",
            script_name, os.path.basename(proj_name),
        )
        return await _exec_headless(cmd, effective_timeout)

    if binary_sha256 is None:
        binary_sha256 = await asyncio.to_thread(_compute_sha256, binary_path)

    if get_settings().compute_backend != "aws_batch":
        output = await _run_ghidra_local(
            binary_path, script_name, script_args, effective_timeout, binary_sha256,
        )
    else:
        output = await _run_ghidra_remote(
            binary_path, script_name, script_args, effective_timeout, binary_sha256,
        )

    # Best-effort log cache (same shape as pre-merge local path).
    if firmware_id is not None and binary_sha256 is not None:
        try:
            async with async_session_factory() as log_db:
                await _store_cached(
                    firmware_id, binary_path, binary_sha256,
                    f"ghidra_log:{script_name}",
                    {"log": output[:100_000], "rc": 0},
                    log_db,
                )
                await log_db.commit()
        except Exception:
            logger.warning(
                "Failed to persist Ghidra log for %s:%s", script_name, binary_path,
            )

    return output


async def ensure_reuse_worker(client, idle_ttl_seconds: int) -> str | None:
    """Ensure one reuse worker is running; submit one if none is alive.

    Returns the submitted job ref (or None if a worker was already alive / a
    submit was already in flight). De-duped via a Redis NX marker so concurrent
    callers don't spawn a fleet.
    """
    if await client.exists(_REUSE_WORKER_HB):
        return None
    if not await client.set(
        _REUSE_WORKER_SUBMIT, "1", nx=True, ex=_REUSE_SUBMIT_TTL,
    ):
        return None
    from app.services.compute_dispatch import get_dispatcher

    handle = get_dispatcher().dispatch_reuse_worker(idle_ttl_seconds)
    logger.info(
        "Started reuse worker job %s (idle_ttl=%ds)", handle.ref, idle_ttl_seconds,
    )
    return handle.ref


async def _run_ghidra_remote(
    binary_path: str,
    script_name: str,
    script_args: list[str] | None,
    effective_timeout: int,
    binary_sha256: str,
) -> str:
    """Delegate a Ghidra script run to the warm reuse worker over Redis."""
    import json

    import redis.asyncio as aioredis

    settings = get_settings()
    wait = int(effective_timeout) + _REUSE_DISPATCH_GRACE
    client = aioredis.from_url(
        settings.redis_url,
        socket_timeout=wait + 30,
        socket_keepalive=True,
    )
    req_id = uuid.uuid4().hex
    result_key = f"{_REUSE_RESULT_PREFIX}{req_id}"
    payload = json.dumps({
        "id": req_id,
        "binary_path": binary_path,
        "script_name": script_name,
        "script_args": script_args,
        "binary_sha256": binary_sha256,
        "timeout": effective_timeout,
    })
    try:
        await client.rpush(_REUSE_QUEUE, payload)
        await ensure_reuse_worker(
            client, settings.re_worker_idle_ttl_minutes * 60,
        )
        popped = await client.blpop([result_key], timeout=wait)
        if popped is None:
            raise TimeoutError(
                f"reuse worker did not return within {wait}s for {script_name} "
                f"(sha256={binary_sha256[:12]}); is a worker running? "
                f"Try warm_analysis_worker."
            )
        _, raw = popped
        res = json.loads(raw)
        if not res.get("ok"):
            raise RuntimeError(res.get("error", "reuse worker error"))
        return res["output"]
    finally:
        with contextlib.suppress(Exception):
            await client.aclose()


# ---------------------------------------------------------------------------
# Concurrency guard: one Ghidra full-analysis per (binary_sha256) at a time.
# Locks are created lazily (on first use) so module import does not require
# a running event loop.
# ---------------------------------------------------------------------------

_analysis_locks: dict[str, asyncio.Event] = {}
_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    """Lazily construct the module-level asyncio.Lock on first call."""
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


# ---------------------------------------------------------------------------
# Low-level cache + SHA helpers
# ---------------------------------------------------------------------------


async def _get_binary_sha256(binary_path: str) -> str:
    """Compute SHA256 in a thread."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, compute_file_sha256, binary_path)


async def get_binary_sha256(binary_path: str) -> str:
    """Public wrapper: compute SHA256 in a thread."""
    return await _get_binary_sha256(binary_path)


async def _is_analysis_complete(
    firmware_id: uuid.UUID,
    binary_sha256: str,
    db: AsyncSession,
) -> bool:
    """Check if full analysis has been completed for this binary."""
    return await _cache.exists_cached(
        db,
        firmware_id,
        "ghidra_full_analysis",
        binary_sha256=binary_sha256,
    )


async def get_cached(
    firmware_id: uuid.UUID,
    binary_sha256: str,
    operation: str,
    db: AsyncSession,
) -> dict | None:
    """Get a cached result by operation key (public API)."""
    return await _get_cached(firmware_id, binary_sha256, operation, db)


async def _get_cached(
    firmware_id: uuid.UUID,
    binary_sha256: str,
    operation: str,
    db: AsyncSession,
) -> dict | None:
    """Get a cached result by operation key."""
    return await _cache.get_cached(
        db, firmware_id, operation, binary_sha256=binary_sha256,
    )


async def store_cached(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    operation: str,
    result_data: dict,
    db: AsyncSession,
) -> None:
    """Store a result in the cache (public API)."""
    await _store_cached(
        firmware_id, binary_path, binary_sha256, operation, result_data, db,
    )


async def _store_cached(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    operation: str,
    result_data: dict,
    db: AsyncSession,
) -> None:
    """Store a result in the cache (delete-then-insert upsert)."""
    await _cache.store_cached(
        db,
        firmware_id,
        operation,
        result_data,
        binary_sha256=binary_sha256,
        binary_path=binary_path,
    )


async def _run_full_analysis(
    binary_path: str,
    firmware_id: uuid.UUID,
    binary_sha256: str,
    db: AsyncSession,
    timeout: int | None = None,  # noqa: ASYNC109 -- caller-supplied timeout per Rule #29 contract
    ghidra_import_params: dict | None = None,
    is_gzf_process_mode: bool = False,
) -> None:
    """Run AnalyzeBinary.java and store all results in DB.

    timeout: passed through to run_ghidra_subprocess. None means use
    the global ghidra_timeout. Background workers pass a larger value.

    is_gzf_process_mode: if True, binary_path is a GZF persistent project
    reference (format: "PROJECT_PROCESS_MODE:proj_base:proj_name") and
    AnalyzeBinary.java should be run in -process mode against that project.
    """
    raw_output = await run_ghidra_subprocess(
        binary_path, "AnalyzeBinary.java",
        timeout=timeout,
        ghidra_import_params=ghidra_import_params,
        firmware_id=firmware_id,
        binary_sha256=binary_sha256,
        is_gzf_process_mode=is_gzf_process_mode,
    )

    data = _parse_analysis_output(raw_output)
    if data is None:
        raise RuntimeError(
            "Ghidra full analysis produced no parseable output. "
            "Check Ghidra installation and binary compatibility."
        )

    # Store each section as a separate cache entry
    sections = [
        ("functions", "functions"),
        ("imports", "imports"),
        ("exports", "exports"),
        ("binary_info", "binary_info"),
        ("xrefs", "xrefs"),
        ("main_detection", "main_detection"),
    ]

    for key, operation in sections:
        if key in data:
            await _store_cached(
                firmware_id, binary_path, binary_sha256,
                operation, {key: data[key]}, db,
            )

    # Store disassembly per function
    disassembly = data.get("disassembly", {})
    for func_name, disasm_text in disassembly.items():
        await _store_cached(
            firmware_id, binary_path, binary_sha256,
            f"disasm:{func_name}",
            {"disassembly": disasm_text},
            db,
        )

    # Store decompilation per function
    decompilation = data.get("decompilation", {})
    for func_name, code in decompilation.items():
        await _store_cached(
            firmware_id, binary_path, binary_sha256,
            f"decompile:{func_name}",
            {"decompiled_code": code},
            db,
        )

    # Store sentinel marking analysis as complete. For GZF process-mode runs,
    # stamp the persistent project's current rev so ensure_analysis can detect
    # a later rename (which bumps the rev) and invalidate this cache durably.
    function_count = len(data.get("functions", []))
    decompile_count = len(decompilation)
    sentinel: dict = {
        "status": "complete",
        "function_count": function_count,
        "decompiled_count": decompile_count,
    }
    if is_gzf_process_mode:
        proj_base = _proj_base_from_process_target(binary_path)
        if proj_base is not None:
            sentinel["gzf_rev"] = await gzf_project_rev(proj_base)
    await _store_cached(
        firmware_id, binary_path, binary_sha256,
        "ghidra_full_analysis",
        sentinel,
        db,
    )

    logger.info(
        "Ghidra full analysis complete for %s: %d functions, %d decompiled",
        os.path.basename(binary_path),
        function_count,
        decompile_count,
    )


async def ensure_analysis(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> str:
    """Ensure full analysis has been run for this binary. Returns binary_sha256.

    Uses a concurrency guard so only one Ghidra process runs per binary.

    If the binary is a GZF with a persistent renamed project (from a prior
    run_ghidra_headless use_saved_project=True), analyzes the persistent
    project instead of the pristine archive, making script-applied renames visible.
    """
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    binary_sha256 = await _get_binary_sha256(binary_path)

    # Check if this GZF has a persistent renamed project from a prior
    # run_ghidra_headless use_saved_project=True. This MUST happen before the
    # fast-path cache check: if a rename has bumped the project rev past the
    # rev stamped in the cached sentinel, the cache contains pre-rename names
    # and must be cleared so analysis re-runs against the renamed project.
    analysis_target, is_gzf_with_persistent_project = await resolve_gzf_process_target(
        binary_path, binary_sha256,
    )
    if is_gzf_with_persistent_project:
        proj_base = _proj_base_from_process_target(analysis_target)
        current_rev = await gzf_project_rev(proj_base) if proj_base else 0
        sentinel = await _get_cached(
            firmware_id, binary_sha256, "ghidra_full_analysis", db,
        )
        if sentinel is not None and sentinel.get("gzf_rev") != current_rev:
            # Stale: the persistent project was renamed (rev bumped) after this
            # cache was built. Clear so the re-analysis below sees live names.
            await clear_binary_analysis(firmware_id, binary_sha256, db)
            await db.commit()
            logger.info(
                "GZF rev mismatch for %s (cached=%s on-disk=%s) — analysis "
                "cache cleared",
                sanitize_for_log(os.path.basename(binary_path)),
                sentinel.get("gzf_rev"),
                current_rev,
            )

    # Fast path: already analyzed (and cache is not stale)
    if await _is_analysis_complete(firmware_id, binary_sha256, db):
        return binary_sha256

    # Within-process concurrency guard: dedupe parallel coroutines
    should_analyze = False
    lock = _get_lock()
    async with lock:
        event = _analysis_locks.get(binary_sha256)
        if event is not None:
            # Another coroutine is already analyzing this binary — wait for it
            pass
        else:
            # We're the leader — create the event and do the analysis
            event = asyncio.Event()
            _analysis_locks[binary_sha256] = event
            should_analyze = True

    if not should_analyze:
        # Wait for the leader coroutine to finish
        await event.wait()
        return binary_sha256

    ghidra_import_params = await resolve_binary_import_params(binary_path, firmware_id)

    # We're responsible for running the analysis. Wrap in an OS-level flock
    # to dedupe across multiple wairz-mcp processes (each MCP connection is
    # a separate process; asyncio.Event only guards within one process).
    try:
        async with _cross_process_analysis_lock(binary_sha256):
            # Re-check under the cross-process lock with a fresh session so
            # we see rows committed by a sibling process that just finished.
            async with async_session_factory() as recheck_db:
                if not await _is_analysis_complete(firmware_id, binary_sha256, recheck_db):
                    async with async_session_factory() as analysis_db:
                        await _run_full_analysis(
                            analysis_target, firmware_id, binary_sha256, analysis_db,
                            ghidra_import_params=ghidra_import_params,
                            is_gzf_process_mode=is_gzf_with_persistent_project,
                        )
                        await analysis_db.commit()
    finally:
        async with lock:
            _analysis_locks.pop(binary_sha256, None)
        event.set()

    return binary_sha256


# ---------------------------------------------------------------------------
# Public per-binary query API (all cache-backed)
# ---------------------------------------------------------------------------


async def clear_binary_analysis(
    firmware_id: uuid.UUID,
    binary_sha256: str,
    db: AsyncSession,
) -> None:
    """Delete all cached analysis data for a binary (all operations for that sha256).

    Call before force-reanalyzing with different Ghidra import params.
    The caller owns commit().
    """
    from sqlalchemy import delete as _delete  # noqa: PLC0415

    from app.models.analysis_cache import AnalysisCache as _AC  # noqa: PLC0415
    await db.execute(
        _delete(_AC).where(
            _AC.firmware_id == firmware_id,
            _AC.binary_sha256 == binary_sha256,
        )
    )
    await db.flush()


async def get_functions_if_cached(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Like get_functions but never triggers Ghidra analysis.

    Use this when function metadata is a nice-to-have annotation (e.g.
    mapping byte-scan offsets to enclosing functions) rather than the
    primary product of the call. Returns [] if the binary has not been
    analyzed yet.
    """
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, binary_path):
        return []
    binary_sha256 = await _get_binary_sha256(binary_path)
    if not await _is_analysis_complete(firmware_id, binary_sha256, db):
        return []
    cached = await _get_cached(firmware_id, binary_sha256, "functions", db)
    return cached.get("functions", []) if cached else []


async def get_run_status(
    firmware_id: uuid.UUID,
    binary_sha256: str,
    db: AsyncSession,
) -> dict | None:
    """Read the most recent background-analysis run row.

    Returned dict has keys: status ("running"|"complete"|"failed"),
    started_at (epoch seconds), optional finished_at, optional pid,
    optional error. None means no run has been kicked off via
    start_binary_analysis.
    """
    return await _get_cached(firmware_id, binary_sha256, "ghidra_analysis_run", db)


async def mark_run_started(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    pid: int,
    db: AsyncSession,
) -> None:
    await _store_cached(
        firmware_id, binary_path, binary_sha256, "ghidra_analysis_run",
        {"status": "running", "started_at": time.time(), "pid": pid},
        db,
    )


async def mark_run_complete(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    db: AsyncSession,
) -> None:
    await _store_cached(
        firmware_id, binary_path, binary_sha256, "ghidra_analysis_run",
        {"status": "complete", "finished_at": time.time()},
        db,
    )


async def mark_run_failed(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    error: str,
    db: AsyncSession,
) -> None:
    await _store_cached(
        firmware_id, binary_path, binary_sha256, "ghidra_analysis_run",
        {"status": "failed", "finished_at": time.time(), "error": error[:2000]},
        db,
    )


async def get_function_run_status(
    firmware_id: uuid.UUID,
    binary_sha256: str,
    function_name: str,
    db: AsyncSession,
) -> dict | None:
    """Read the most recent per-function decompile run row."""
    return await _get_cached(
        firmware_id, binary_sha256,
        f"function_decompile_run:{function_name}", db,
    )


async def mark_function_run_started(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    function_name: str,
    pid: int,
    db: AsyncSession,
) -> None:
    await _store_cached(
        firmware_id, binary_path, binary_sha256,
        f"function_decompile_run:{function_name}",
        {"status": "running", "started_at": time.time(), "pid": pid},
        db,
    )


async def mark_function_run_complete(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    function_name: str,
    db: AsyncSession,
) -> None:
    await _store_cached(
        firmware_id, binary_path, binary_sha256,
        f"function_decompile_run:{function_name}",
        {"status": "complete", "finished_at": time.time()},
        db,
    )


async def mark_function_run_failed(
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    function_name: str,
    error: str,
    db: AsyncSession,
) -> None:
    await _store_cached(
        firmware_id, binary_path, binary_sha256,
        f"function_decompile_run:{function_name}",
        {
            "status": "failed",
            "finished_at": time.time(),
            "error": error[:2000],
        },
        db,
    )


async def get_functions(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Get function list for a binary (sorted by size desc)."""
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "functions", db)
    if cached:
        functions = cached.get("functions", [])
        # Apply main detection: if main was detected, update the list
        main_cached = await _get_cached(
            firmware_id, binary_sha256, "main_detection", db,
        )
        if main_cached:
            main_info = main_cached.get("main_detection", {})
            if main_info.get("found") and main_info.get("method") == "libc_start_main_arg":
                main_addr = main_info.get("address")
                for func in functions:
                    if func.get("address") == main_addr and func["name"].startswith("FUN_"):
                        func["name"] = "main"
                        break
        return functions
    return []


async def get_disassembly(
    binary_path: str,
    function_name: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
    max_instructions: int = 200,
) -> str:
    """Get disassembly for a function."""
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(
        firmware_id, binary_sha256, f"disasm:{function_name}", db,
    )
    if cached:
        disasm = cached.get("disassembly", "")
        # Apply max_instructions limit
        lines = disasm.split("\n")
        if len(lines) > max_instructions:
            lines = lines[:max_instructions]
            lines.append(f"... (truncated at {max_instructions} instructions)")
        return "\n".join(lines)

    return f"No disassembly found for function '{function_name}'. Use list_functions to see available function names."


async def get_imports(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Get import list for a binary."""
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "imports", db)
    if cached:
        return cached.get("imports", [])
    return []


async def get_exports(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Get export list for a binary."""
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "exports", db)
    if cached:
        return cached.get("exports", [])
    return []


async def get_xrefs_to(
    binary_path: str,
    target: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Get cross-references to a function/symbol.

    First checks for direct 'to' xrefs under the target name. If none
    found (common for imported symbols like doSystemCmd, system, etc.),
    performs a reverse scan of all functions' outgoing ('from') xrefs to
    find callers whose 'to_func' matches the target.
    """
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "xrefs", db)
    if not cached:
        return []

    xrefs = cached.get("xrefs", {})

    # Direct lookup
    func_xrefs = xrefs.get(target, {})
    direct_results = func_xrefs.get("to", [])
    if direct_results:
        return direct_results

    # Reverse scan: check all functions' outgoing xrefs for calls to target
    reverse_results: list[dict] = []
    for func_name, func_data in xrefs.items():
        for ref in func_data.get("from", []):
            if ref.get("to_func") == target:
                reverse_results.append({
                    "from": ref.get("from", ref.get("address", "unknown")),
                    "type": ref.get("type", "CALL"),
                    "from_func": func_name,
                })
    return reverse_results


async def get_xrefs_from(
    binary_path: str,
    target: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> list[dict]:
    """Get cross-references from a function/symbol."""
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "xrefs", db)
    if cached:
        xrefs = cached.get("xrefs", {})
        func_xrefs = xrefs.get(target, {})
        return func_xrefs.get("from", [])
    return []


async def get_binary_info(
    binary_path: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> dict:
    """Get binary metadata in r2-compatible shape for frontend compatibility.

    Returns a dict shaped like: {"core": {}, "bin": {"arch": ..., "libs": [...]}}
    """
    binary_sha256 = await ensure_analysis(binary_path, firmware_id, db)

    cached = await _get_cached(firmware_id, binary_sha256, "binary_info", db)
    if not cached:
        return {}

    info = cached.get("binary_info", {})

    # Map to r2-compatible shape
    arch = _map_architecture(info.get("arch", "unknown"))
    bits = info.get("bits", 0)
    endian = info.get("endian", "unknown")
    fmt = info.get("format", "unknown")
    libs = info.get("libraries", [])
    entry = info.get("entry_point", "unknown")
    compiler = info.get("compiler", "unknown")
    image_base = info.get("image_base", "unknown")

    return {
        "core": {
            "format": fmt,
            "file": binary_path,
        },
        "bin": {
            "file": binary_path,
            "bintype": "elf" if "elf" in fmt.lower() else fmt.lower(),
            "arch": arch,
            "bits": bits,
            "endian": endian,
            "os": "linux",
            "machine": info.get("arch", "unknown"),
            "class": f"ELF{bits}" if "elf" in fmt.lower() else fmt,
            "lang": compiler if compiler != "unknown" else "c",
            "stripped": False,  # Ghidra doesn't report this directly; pyelftools handles it
            "static": len(libs) == 0,
            "libs": libs,
            "entry_point": entry,
            "image_base": image_base,
        },
    }


async def decompile_function(
    binary_path: str,
    function_name: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> str:
    """Decompile a function, using cached results or falling back to single-function Ghidra.

    First tries the full-analysis cache. If the function wasn't in the top 200
    decompiled, falls back to running DecompileFunction.java for that specific function.

    For GZF archives with a persistent renamed project (from run_ghidra_headless
    use_saved_project=True), DecompileFunction.java runs in -process mode against
    the persistent project so renamed functions are visible.
    """
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    binary_sha256 = await _get_binary_sha256(binary_path)
    operation = f"decompile:{function_name}"

    # Determine whether this GZF has a persistent renamed project.
    # When it does, DecompileFunction.java must run in -process mode against
    # that project so it sees renamed functions instead of the pristine archive.
    ghidra_import_params = None
    ghidra_subprocess_target, is_gzf_process_mode = await resolve_gzf_process_target(
        binary_path, binary_sha256,
    )

    # Check cache (works for both full-analysis and single-function cache entries).
    # Cache entries written after a -process mode run already reflect renames.
    cached = await _get_cached(firmware_id, binary_sha256, operation, db)
    if cached:
        code = cached.get("decompiled_code")
        if code:
            logger.info(
                "Cache hit for %s:%s",
                sanitize_for_log(os.path.basename(binary_path)),
                sanitize_for_log(function_name),
            )
            return code

    # Fall back to single-function decompilation. Big handler functions
    # (the kind you actually want to look at in a daemon) can take
    # several minutes; bump well past the default 300s but stay under
    # the MCP transport timeout (~600s) so the agent gets a real
    # result instead of a transport-level "user doesn't want to
    # proceed" rejection. If a function needs longer than this, the
    # agent should fall back to start_function_decompile /
    # check_function_decompile_status which runs in a detached
    # worker with a 30-minute timeout.
    if not is_gzf_process_mode:
        ghidra_import_params = await resolve_binary_import_params(binary_path, firmware_id)
    raw_output = await run_ghidra_subprocess(
        ghidra_subprocess_target,
        "DecompileFunction.java",
        script_args=[function_name],
        timeout=580,
        ghidra_import_params=ghidra_import_params,
        firmware_id=firmware_id,
        binary_sha256=binary_sha256,
        is_gzf_process_mode=is_gzf_process_mode,
    )

    decompiled = _parse_decompile_output(raw_output)
    if decompiled is None:
        if "ERROR: Function" in raw_output and "not found" in raw_output:
            lines = raw_output.split("\n")
            func_lines = [
                line.strip()
                for line in lines
                if line.strip().startswith("  ") and "@" in line
            ]
            suggestion = ""
            if func_lines:
                suggestion = "\n\nAvailable functions:\n" + "\n".join(func_lines[:20])
            return f"Function '{function_name}' not found in binary.{suggestion}"
        return "Decompilation produced no output. The function may be too small or a thunk."

    # Store in cache for future use
    await _store_cached(
        firmware_id, binary_path, binary_sha256, operation,
        {"decompiled_code": decompiled}, db,
    )

    return decompiled


async def batch_decompile_functions(
    binary_path: str,
    function_names: list[str],
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> dict[str, str | None]:
    """Batch decompile multiple functions using a single Ghidra headless run.

    Returns a dict mapping function_name -> decompiled_code (or None if failed).
    Attempts to load from cache first for each function, falls back to batch
    Ghidra run for uncached functions. Results are cached individually.
    """
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    if not function_names:
        return {}

    binary_sha256 = await _get_binary_sha256(binary_path)

    # Attempt cache hits first
    results = {}
    uncached_funcs = []

    for func_name in function_names:
        operation = f"decompile:{func_name}"
        cached = await _get_cached(firmware_id, binary_sha256, operation, db)
        if cached and cached.get("decompiled_code"):
            results[func_name] = cached["decompiled_code"]
            logger.info("Cache hit for %s:%s", os.path.basename(binary_path), func_name)
        else:
            uncached_funcs.append(func_name)

    # If all cached, return early
    if not uncached_funcs:
        return results

    # Run batch decompilation for uncached functions. Route GZF archives with
    # a persistent renamed project through -process mode — identical to
    # decompile_function — so batch lookups resolve renamed functions instead
    # of failing "not found" against the pristine archive (the Bug 2 root
    # cause: batch_decompile_functions never did this detection, so every name
    # decompile_function could resolve individually came back "not found" in a
    # batch). In process mode the persistent project already carries the
    # correct loader/processor, so import params MUST be None.
    ghidra_subprocess_target, is_gzf_process_mode = await resolve_gzf_process_target(
        binary_path, binary_sha256,
    )
    ghidra_import_params = (
        None
        if is_gzf_process_mode
        else await resolve_binary_import_params(binary_path, firmware_id)
    )
    raw_output = await run_ghidra_subprocess(
        ghidra_subprocess_target,
        "DecompileFunction.java",
        script_args=uncached_funcs,
        timeout=min(580, 60 * len(uncached_funcs)),  # 60s per function, max 580s
        ghidra_import_params=ghidra_import_params,
        firmware_id=firmware_id,
        binary_sha256=binary_sha256,
        is_gzf_process_mode=is_gzf_process_mode,
    )

    # Parse batch output: collect all decompilations between markers
    batch_results = _parse_batch_decompile_output(raw_output)

    # Cache individual results and build response dict
    for func_name in uncached_funcs:
        decompiled = batch_results.get(func_name)
        results[func_name] = decompiled

        # Cache even on failure (None value)
        if decompiled:
            operation = f"decompile:{func_name}"
            await _store_cached(
                firmware_id, binary_path, binary_sha256, operation,
                {"decompiled_code": decompiled}, db,
            )

    return results


def _parse_batch_decompile_output(raw_output: str) -> dict[str, str | None]:
    """Parse batch decompilation output containing multiple DECOMPILE_START/END blocks.

    Returns dict mapping function_name -> decompiled_code.
    """
    results: dict[str, str | None] = {}
    current_func = None
    current_code_lines = []
    in_decompile = False

    for line in raw_output.split("\n"):
        if line.startswith("===DECOMPILE_START==="):
            in_decompile = True
            current_code_lines = []
        elif line.startswith("===DECOMPILE_END==="):
            if current_func and current_code_lines:
                # Join and clean up the code
                code = "\n".join(current_code_lines).strip()
                # Remove leading comment lines that are metadata
                lines = code.split("\n")
                # Skip metadata comment lines at the start
                skip = 0
                for i, line_text in enumerate(lines):
                    if line_text.startswith("//"):
                        skip = i + 1
                    else:
                        break
                if skip < len(lines):
                    code = "\n".join(lines[skip:]).strip()
                results[current_func] = code if code else None
            in_decompile = False
            current_func = None
            current_code_lines = []
        elif in_decompile:
            # Capture function name from "// Function: <name>" line
            if line.startswith("// Function:"):
                current_func = line.replace("// Function:", "").strip()
            elif not line.startswith("// "):  # Skip other metadata lines
                current_code_lines.append(line)

    return results
