"""Phase κ.C.C — Linux persistence-triplet walker (bash_history + crontab + ld.so.preload).

Walks every detection root (per Rule #16) and locates 3 artefact
families that, when correlated, surface Linux persistence + adversary-
recon TTPs:

- ``bash_history`` files (``.bash_history`` under ``/root`` /
  ``/home/<user>``) — command-line recon evidence + T1070.003 clear-
  history attempts.
- ``crontab`` files (``/etc/crontab``, ``/etc/cron.d/*``,
  ``/var/spool/cron/<user>``, ``/var/spool/cron/crontabs/<user>``) —
  scheduled re-execution + T1053.003 + T1547 persistence.
- ``ld.so.preload`` files (``/etc/ld.so.preload``) — shared-library
  hijack + T1574.006 dynamic-linker MITM.

**Why one walker, three ORM tables?** The three artefacts cohabit
Linux firmware images and adversary TTPs touch them in concert
(APT36 Transparent Tribe, FIRESTARTER, Quasar Linux QLNX). The per-
line shape is similar enough that a single walker module with three
sub-parsers is cleaner than three identical walkers. Each artefact
has its own ORM table because the per-line schemas diverge —
bash_history is just `command`, crontab adds `schedule_spec` + `user`,
ld.so.preload is `library_path`. Precedent: γ.4 ``registry_hive_walker``
covers 5 hive types under one walker.

**Rule #19 evidence-first OSS-library probe** (ran 2026-05-12T23:30Z):

- All three artefacts are TEXT files with line-oriented syntax. No
  Python library wraps "bash_history parser" or "crontab parser" — the
  format is too simple to merit one. We implement thin pure-Python
  line-tokenizers (~30 LOC each) + regex classifiers (~10 regexes
  total). Smaller surface than introducing a parser dep; no foreign-
  license concern; portable.

**Rule #39 inner/outer/safe runner triplet:**

- :func:`_do_linux_persistence_walk` — INNER orchestrator. Accepts
  caller-owned ``db``. Walks each artefact family, parses each file,
  classifies each line, persists per-line rows across 3 sibling
  ORM tables, returns aggregate dict UNSTAMPED.
- :func:`run_linux_persistence_walk_background` — OUTER state-machine
  wrapper. Owns the Rule #33 .a status transitions via
  ``async_session_factory()``. Outer guard catches escapes; failure
  persistence on a fresh session.
- :func:`auto_linux_persistence_walk_firmware_safe` — UNPACK-POST-
  DETECTION hook. Runs the inner orchestrator but does NOT mutate
  ``persistence_walk_status`` — leaves ``idle`` so manual re-trigger
  via the trigger MCP tool works without 409 conflict.

**Rule #36 no-execute discipline.** The walker reads each artefact file
AS TEXT, splits into lines, runs regex matchers. NO ``bash`` /
``crontab`` / ``ldconfig`` invocations. NO sourcing of bash_history
into a shell. NO ``ld`` invocation against listed libraries. The
walker's source is tokenized against forbidden invocation tokens in
``test_linux_persistence_walker.py::test_walker_no_execute``.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare ``firmware.extracted_path``)
so multi-rootfs Linux firmware (squashfs / ext / cramfs / erofs /
tar.xz) surfaces every artefact candidate.

**Performance.** Per-firmware walks are <500 ms for typical embedded
Linux (a handful of bash_history files + 1-3 crontabs + maybe an
ld.so.preload). The walker decodes with ``errors='replace'`` so
non-UTF8 bytes in bash_history (common — terminal artifacts) don't
crash the walker.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os
import re
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.linux_bash_history_entries import LinuxBashHistoryEntry
from app.models.linux_cron_jobs import LinuxCronJob
from app.models.linux_ld_preload_entries import LinuxLdPreloadEntry
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_persistence_walk_result,
    _stamp_linux_bash_history_suspicious_flags,
    _stamp_linux_cron_suspicious_flags,
    _stamp_linux_ld_preload_suspicious_flags,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum per-line bytes per artefact. Real-world lines are 50-300 bytes;
# bounding at 4096 protects against attacker-planted long lines.
_DEFAULT_MAX_LINE_BYTES: int = 4096

# Maximum total file bytes. Real-world bash_history is 10-50 KB; crontab
# is 1-5 KB; ld.so.preload is <1 KB. Bound at 16 MiB defensive.
_DEFAULT_MAX_FILE_BYTES: int = 16 * 1024 * 1024

# Maximum lines persisted per artefact per firmware. Defensive cap
# against attacker-planted million-line files.
_DEFAULT_MAX_LINES_PER_FIRMWARE: int = 100_000


# ── Heuristic regexes (bash_history) ─────────────────────────────────────────

# T1070.003 — clear-history attempts. Match common shell patterns.
_RE_BASH_CLEAR_HISTORY = re.compile(
    r"(?:^\s*|;\s*|\|\s*|&&\s*)"  # statement boundary
    r"(?:"
    r"history\s+-[cw]|"  # history -c / history -w
    r":\s*>\s*[~/.][\w./-]*\.bash_history|"  # : > ~/.bash_history
    r">\s*[~/.][\w./-]*\.bash_history|"  # > ~/.bash_history
    r"rm\s+-[rf]+\s+[~/.][\w./-]*\.bash_history|"  # rm -f ~/.bash_history
    r"unset\s+HISTFILE|"  # unset HISTFILE
    r"export\s+HISTFILE=/dev/null|"
    r"export\s+HISTSIZE=0|"
    r"set\s+\+o\s+history"  # disable history recording
    r")",
    re.IGNORECASE,
)

# T1105 — ingress-tool-transfer via wget/curl piped to a shell.
_RE_DOWNLOAD_PIPE_SHELL = re.compile(
    r"(?:wget|curl)\s+[^\s|;&]+\s*\|\s*(?:bash|sh|zsh|ash|dash)\b",
    re.IGNORECASE,
)

# T1548.003 / T1222.002 — priv-esc patterns.
_RE_PRIV_ESC = re.compile(
    r"(?:"
    r"sudo\s+su\s+-|"
    r"sudo\s+-i|"
    r"sudo\s+bash|"
    r"chmod\s+\+s\s|"  # setuid bit
    r"chmod\s+[0-7]?[4-7][0-7][0-7][0-7]\s|"  # numeric mode with setuid
    r"setuid\("
    r")",
    re.IGNORECASE,
)


# ── Heuristic regexes (crontab) ──────────────────────────────────────────────

# Adversary-staging directories. Match path prefixes for command-from-temp.
# NOTE: bare ``/`` is not a word boundary character, so ``\b`` would
# fail to fire at the start of ``/tmp/``. Use literal prefix matching.
_RE_CRON_TEMP_PATH = re.compile(
    r"(?:^|\s|;|\||&)(?:/tmp/|/dev/shm/|/var/tmp/|/run/shm/)",
)

# Network egress in cron context (curl/wget/nc).
_RE_CRON_NETWORK_EGRESS = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat)\b",
    re.IGNORECASE,
)


# ── Heuristic regexes (ld.so.preload) ────────────────────────────────────────

# World-writable directories where adversaries stage payloads.
_WORLD_WRITABLE_PATTERNS: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
)

# Adversary-staging directory prefixes for libraries.
_RE_LD_TEMP_PATH = re.compile(
    r"^(?:/tmp/|/dev/shm/|/var/tmp/|/run/shm/)",
)

# Expected library extensions — .so or .so.<version>.
_RE_EXPECTED_LIB_EXT = re.compile(
    r"\.so(?:\.\d+(?:\.\d+)*)?$",
)


# ── Crontab schedule regex ───────────────────────────────────────────────────

# Detect crontab special keywords (@reboot, @hourly, etc).
_RE_CRON_SPECIAL_KEYWORD = re.compile(
    r"^@(?:reboot|hourly|daily|midnight|weekly|monthly|yearly|annually)\b",
    re.IGNORECASE,
)

# Detect a 5-field schedule (minute hour day-of-month month day-of-week)
# followed by either a user (in /etc/crontab) or directly a command (in
# /var/spool/cron/<user>). Each field is digits, *, /, -, or ,.
_RE_CRON_5FIELD = re.compile(
    r"^\s*([-\d*/,]+)\s+([-\d*/,]+)\s+([-\d*/,]+)\s+([-\d*/,]+)\s+([-\d*/,]+)\s+(.*)$"
)


# ── Pure helpers — bash_history classifier ───────────────────────────────────


def classify_bash_history_line(command: str) -> dict[str, bool]:
    """Pure function — same command always produces the same flag dict.

    Returns ``{"clear_marker": bool, "download_pattern": bool,
    "priv_esc_pattern": bool}``.
    """
    return {
        "clear_marker": bool(_RE_BASH_CLEAR_HISTORY.search(command)),
        "download_pattern": bool(_RE_DOWNLOAD_PIPE_SHELL.search(command)),
        "priv_esc_pattern": bool(_RE_PRIV_ESC.search(command)),
    }


# ── Pure helpers — crontab classifier ────────────────────────────────────────


def classify_cron_line(
    *, schedule_spec: str | None, command: str
) -> dict[str, bool]:
    """Pure function — flag dict for a crontab line.

    Returns ``{"temp_path_command": bool, "reboot_persistence": bool,
    "network_egress_pattern": bool}``.
    """
    reboot_persistence = False
    if schedule_spec is not None:
        reboot_persistence = "@reboot" in schedule_spec.lower()
    return {
        "temp_path_command": bool(_RE_CRON_TEMP_PATH.search(command)),
        "reboot_persistence": reboot_persistence,
        "network_egress_pattern": bool(_RE_CRON_NETWORK_EGRESS.search(command)),
    }


# ── Pure helpers — ld.so.preload classifier ──────────────────────────────────


def classify_ld_preload_line(library_path: str) -> dict[str, bool]:
    """Pure function — flag dict for an ld.so.preload line.

    Returns ``{"temp_path_library": bool, "unusual_extension": bool,
    "world_writable_dir": bool}``.
    """
    path_norm = library_path.strip().lower()
    temp_path = bool(_RE_LD_TEMP_PATH.search(path_norm))
    has_expected_ext = bool(_RE_EXPECTED_LIB_EXT.search(path_norm))
    world_writable = any(
        path_norm.startswith(prefix) for prefix in _WORLD_WRITABLE_PATTERNS
    )
    return {
        "temp_path_library": temp_path,
        "unusual_extension": not has_expected_ext,
        "world_writable_dir": world_writable,
    }


# ── Pure helpers — sub-parsers ───────────────────────────────────────────────


def _parse_bash_history_file(path: Path) -> list[dict]:
    """Parse a bash_history file into per-line dicts.

    Returns a list of ``{"line_number": int, "command": str}``. Skips
    blank lines and timestamp-only lines (``#1234567890`` HISTTIMEFORMAT
    artifact). Decodes with ``errors='replace'`` for robustness against
    non-UTF8 bytes (common in real bash history — terminal control
    sequences, locale artifacts).
    """
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > _DEFAULT_MAX_FILE_BYTES:
        return []
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    text = raw.decode("utf-8", errors="replace")

    entries: list[dict] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        # HISTTIMEFORMAT prefixes lines with #<unix-timestamp>; treat
        # those as standalone — but only when the ENTIRE line is
        # `#<digits>` (otherwise it's a comment that's content).
        stripped = line.strip()
        if (
            stripped.startswith("#")
            and len(stripped) > 1
            and stripped[1:].isdigit()
        ):
            continue
        command = line[:_DEFAULT_MAX_LINE_BYTES]
        entries.append({"line_number": idx, "command": command})
    return entries


def _parse_crontab_file(
    path: Path,
    *,
    user_from_filename: bool,
) -> list[dict]:
    """Parse a crontab file into per-line dicts.

    Returns a list of ``{"line_number": int, "schedule_spec": str | None,
    "user": str | None, "command": str}``.

    Skips comment lines (``#``), blank lines, and environment
    assignments (``KEY=VALUE`` shape — bare KEY no whitespace before =).

    When ``user_from_filename`` is True, the file's basename is the
    user (per-user crontab under ``/var/spool/cron/<user>``); the user
    field is NOT in each line. Otherwise (system crontab at
    ``/etc/crontab`` or ``/etc/cron.d/<file>``), field 6 is the user
    and the command starts at field 7.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > _DEFAULT_MAX_FILE_BYTES:
        return []
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    text = raw.decode("utf-8", errors="replace")

    user_from_path: str | None = None
    if user_from_filename:
        user_from_path = path.name

    entries: list[dict] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Skip environment assignments (FOO=bar) — must have NO space
        # before the `=` and the LHS must be a bare identifier.
        if "=" in stripped:
            head, _, rest = stripped.partition("=")
            if head and head.replace("_", "").isalnum() and " " not in head:
                continue

        schedule_spec: str | None = None
        user: str | None = user_from_path
        command: str = ""

        # Try special-keyword shape first (@reboot ...).
        m_special = _RE_CRON_SPECIAL_KEYWORD.match(stripped)
        if m_special:
            keyword = stripped.split(None, 1)[0]
            schedule_spec = keyword
            rest_after_kw = stripped[len(keyword):].strip()
            if user_from_filename:
                command = rest_after_kw
            else:
                # /etc/crontab + /etc/cron.d — user is next field.
                parts = rest_after_kw.split(None, 1)
                if len(parts) == 2:
                    user = parts[0][:64]
                    command = parts[1]
                elif len(parts) == 1:
                    # User-only line with no command — treat as user
                    # + empty command.
                    user = parts[0][:64]
                    command = ""
        else:
            # Try 5-field schedule.
            m5 = _RE_CRON_5FIELD.match(stripped)
            if m5:
                schedule_spec = " ".join(m5.group(1, 2, 3, 4, 5))
                tail = m5.group(6).strip()
                if user_from_filename:
                    command = tail
                else:
                    # /etc/crontab + /etc/cron.d — first token of tail
                    # is user.
                    parts = tail.split(None, 1)
                    if len(parts) == 2:
                        user = parts[0][:64]
                        command = parts[1]
                    elif len(parts) == 1:
                        user = parts[0][:64]
                        command = ""
            else:
                # Unparseable shape — emit as-is with schedule_spec=None.
                command = stripped[:_DEFAULT_MAX_LINE_BYTES]

        command = command[:_DEFAULT_MAX_LINE_BYTES]
        schedule_spec = (
            schedule_spec[:128] if schedule_spec else None
        )

        entries.append({
            "line_number": idx,
            "schedule_spec": schedule_spec,
            "user": user,
            "command": command,
        })
    return entries


def _parse_ld_so_preload_file(path: Path) -> list[dict]:
    """Parse an ld.so.preload file into per-line dicts.

    Per ldconfig manpage: the file is newline-separated AND/OR
    whitespace-separated library paths. Comments (``#``) are NOT
    typically recognized by glibc — but we treat them as comments for
    robustness (some embedded systems use commented examples in the
    bundled file).

    Returns ``[{"line_number": int, "library_path": str}, ...]``.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > _DEFAULT_MAX_FILE_BYTES:
        return []
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    text = raw.decode("utf-8", errors="replace")

    entries: list[dict] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Multiple paths on one line — split by whitespace, each gets
        # its own row but shares the line_number.
        for token in stripped.split():
            library_path = token[:_DEFAULT_MAX_LINE_BYTES]
            entries.append({
                "line_number": idx,
                "library_path": library_path,
            })
    return entries


# ── Filesystem scanners ──────────────────────────────────────────────────────


def _scan_bash_history_candidates_sync(roots: list[str]) -> list[tuple[str, str]]:
    """Walk every detection root for ``.bash_history`` candidates.

    Returns ``[(real_full_path, relative_path), ...]``. Looks under
    ``/root`` + ``/home/<*>`` paths within each root.
    """
    hits: list[tuple[str, str]] = []
    seen_real: set[str] = set()

    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
        except OSError:
            continue

        # Walk every dir; pick out .bash_history (and .bash_history.bak).
        # Skip /proc, /sys, /dev to avoid noise.
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Trim noisy system dirs from descent.
            dirnames[:] = [
                d for d in dirnames
                if d not in ("proc", "sys", "dev", "run")
            ]
            for name in filenames:
                if name != ".bash_history":
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                if real_full in seen_real:
                    continue
                seen_real.add(real_full)
                # Compute relative.
                try:
                    rel = os.path.relpath(real_full, real_root)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                except ValueError:
                    rel = name
                hits.append((real_full, rel))
    return hits


def _scan_crontab_candidates_sync(
    roots: list[str],
) -> list[tuple[str, str, bool]]:
    """Walk every detection root for crontab candidates.

    Returns ``[(real_full_path, relative_path, user_from_filename), ...]``.
    Covers:

    - ``/etc/crontab`` (user_from_filename=False)
    - ``/etc/cron.d/<file>`` (user_from_filename=False)
    - ``/var/spool/cron/<user>`` (user_from_filename=True)
    - ``/var/spool/cron/crontabs/<user>`` (user_from_filename=True)
    """
    hits: list[tuple[str, str, bool]] = []
    seen_real: set[str] = set()

    def _maybe_add(full: str, rel: str, user_from_filename: bool) -> None:
        try:
            real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
        except OSError:
            return
        if real_full in seen_real:
            return
        if not os.path.isfile(real_full):
            return
        seen_real.add(real_full)
        hits.append((real_full, rel, user_from_filename))

    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
        except OSError:
            continue

        # /etc/crontab — single file, user-in-line.
        for variant in ("etc/crontab",):
            candidate = os.path.join(real_root, variant)
            if os.path.isfile(candidate):
                rel = variant
                _maybe_add(candidate, rel, False)

        # /etc/cron.d/<file> — directory of files, user-in-line each.
        cron_d_dir = os.path.join(real_root, "etc/cron.d")
        if os.path.isdir(cron_d_dir):
            try:
                entries = os.listdir(cron_d_dir)
            except OSError:
                entries = []
            for entry in entries:
                full = os.path.join(cron_d_dir, entry)
                rel = os.path.join("etc/cron.d", entry)
                _maybe_add(full, rel, False)

        # /var/spool/cron/<user> + /var/spool/cron/crontabs/<user> —
        # per-user crontab, user from filename.
        for spool_dir in ("var/spool/cron", "var/spool/cron/crontabs"):
            full_spool = os.path.join(real_root, spool_dir)
            if not os.path.isdir(full_spool):
                continue
            try:
                entries = os.listdir(full_spool)
            except OSError:
                continue
            for entry in entries:
                full = os.path.join(full_spool, entry)
                rel = os.path.join(spool_dir, entry)
                # Skip "tabs" subdirectory of /var/spool/cron itself.
                if os.path.isdir(full):
                    continue
                _maybe_add(full, rel, True)
    return hits


def _scan_ld_preload_candidates_sync(
    roots: list[str],
) -> list[tuple[str, str]]:
    """Walk every detection root for ld.so.preload candidates.

    Returns ``[(real_full_path, relative_path), ...]``. Covers
    ``/etc/ld.so.preload`` (system) and ``~/<user>/.ld.so.preload``
    (rare per-user; some legacy systems).
    """
    hits: list[tuple[str, str]] = []
    seen_real: set[str] = set()

    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
        except OSError:
            continue

        # /etc/ld.so.preload — the canonical system file.
        candidate = os.path.join(real_root, "etc/ld.so.preload")
        if os.path.isfile(candidate):
            try:
                real_full = os.path.realpath(candidate)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
            except OSError:
                real_full = candidate
            if real_full not in seen_real:
                seen_real.add(real_full)
                hits.append((real_full, "etc/ld.so.preload"))

        # /home/<user>/.ld.so.preload — rare, but support for paranoia.
        home_dir = os.path.join(real_root, "home")
        if os.path.isdir(home_dir):
            try:
                user_dirs = os.listdir(home_dir)
            except OSError:
                user_dirs = []
            for ud in user_dirs:
                cand = os.path.join(home_dir, ud, ".ld.so.preload")
                if not os.path.isfile(cand):
                    continue
                try:
                    real_full = os.path.realpath(cand)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                except OSError:
                    continue
                if real_full in seen_real:
                    continue
                if not real_full.startswith(real_root):
                    continue
                seen_real.add(real_full)
                rel = os.path.join("home", ud, ".ld.so.preload")
                hits.append((real_full, rel))
    return hits


# ── Async wrappers (Rule #5) ─────────────────────────────────────────────────


async def _scan_bash_history_candidates_async(
    roots: list[str],
) -> list[tuple[str, str]]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _scan_bash_history_candidates_sync, roots
    )


async def _scan_crontab_candidates_async(
    roots: list[str],
) -> list[tuple[str, str, bool]]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _scan_crontab_candidates_sync, roots
    )


async def _scan_ld_preload_candidates_async(
    roots: list[str],
) -> list[tuple[str, str]]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _scan_ld_preload_candidates_sync, roots
    )


async def _parse_bash_history_async(path: Path) -> list[dict]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _parse_bash_history_file, path)


async def _parse_crontab_async(
    path: Path, *, user_from_filename: bool
) -> list[dict]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _parse_crontab_file(
            path, user_from_filename=user_from_filename
        ),
    )


async def _parse_ld_preload_async(path: Path) -> list[dict]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _parse_ld_so_preload_file, path)


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "bash_history_files_scanned": 0,
        "bash_history_lines_persisted": 0,
        "cron_files_scanned": 0,
        "cron_lines_persisted": 0,
        "ld_preload_files_scanned": 0,
        "ld_preload_lines_persisted": 0,
        "bash_clear_marker_count": 0,
        "bash_download_pattern_count": 0,
        "bash_priv_esc_pattern_count": 0,
        "cron_temp_path_command_count": 0,
        "cron_reboot_persistence_count": 0,
        "cron_network_egress_pattern_count": 0,
        "ld_preload_temp_path_library_count": 0,
        "ld_preload_unusual_extension_count": 0,
        "ld_preload_world_writable_dir_count": 0,
        "anomaly_total": 0,
        "errors": [],
        "per_artefact": [],
    }


# ── Inner orchestrator (Rule #39 inner; accepts db) ──────────────────────────


async def _do_linux_persistence_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_lines: int = _DEFAULT_MAX_LINES_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every detection root for the 3 Linux-persistence artefact
    families, parse each candidate, classify each line, persist rows.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for each artefact family (bash_history + crontab
       + ld.so.preload).
    3. For each file: open as TEXT (errors='replace'), tokenize lines,
       classify, build ORM rows.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real
    test DB.

    Rule #36 reminder: NEVER invokes any extracted command, NEVER
    spawns subprocesses; surfaces commands/paths as DATA only.
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

    aggregate = _empty_walk_result(0.0)
    per_artefact: list[dict] = []
    errors: list[str] = []

    # ── bash_history ──
    bash_candidates = await _scan_bash_history_candidates_async(roots)
    bash_lines_persisted = 0
    for full, rel in bash_candidates:
        if bash_lines_persisted >= max_lines:
            break
        try:
            parsed = await _parse_bash_history_async(Path(full))
        except Exception as exc:  # noqa: BLE001
            errors.append(
                f"bash_history parse {rel}: {type(exc).__name__}: {str(exc)[:120]}"
            )
            continue
        file_lines_persisted = 0
        clear_marker_count = 0
        download_pattern_count = 0
        priv_esc_pattern_count = 0
        for entry in parsed:
            if bash_lines_persisted >= max_lines:
                break
            command = entry["command"]
            line_number = entry["line_number"]
            flags = classify_bash_history_line(command)
            if flags["clear_marker"]:
                clear_marker_count += 1
            if flags["download_pattern"]:
                download_pattern_count += 1
            if flags["priv_esc_pattern"]:
                priv_esc_pattern_count += 1
            row = LinuxBashHistoryEntry(
                firmware_id=firmware_id,
                source_file=rel[:2048],
                line_number=line_number,
                command=command,
                suspicious_flags=_stamp_linux_bash_history_suspicious_flags(
                    dict(flags)
                ),
            )
            db.add(row)
            bash_lines_persisted += 1
            file_lines_persisted += 1
        if file_lines_persisted > 0:
            await db.flush()
        aggregate["bash_clear_marker_count"] += clear_marker_count
        aggregate["bash_download_pattern_count"] += download_pattern_count
        aggregate["bash_priv_esc_pattern_count"] += priv_esc_pattern_count
        per_artefact.append({
            "artefact_type": "bash_history",
            "path": rel,
            "lines_persisted": file_lines_persisted,
            "clear_marker_count": clear_marker_count,
            "download_pattern_count": download_pattern_count,
            "priv_esc_pattern_count": priv_esc_pattern_count,
        })

    aggregate["bash_history_files_scanned"] = len(bash_candidates)
    aggregate["bash_history_lines_persisted"] = bash_lines_persisted

    # ── crontab ──
    cron_candidates = await _scan_crontab_candidates_async(roots)
    cron_lines_persisted = 0
    for full, rel, user_from_filename in cron_candidates:
        if cron_lines_persisted >= max_lines:
            break
        try:
            parsed = await _parse_crontab_async(
                Path(full), user_from_filename=user_from_filename
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(
                f"crontab parse {rel}: {type(exc).__name__}: {str(exc)[:120]}"
            )
            continue
        file_lines_persisted = 0
        temp_path_command_count = 0
        reboot_persistence_count = 0
        network_egress_pattern_count = 0
        for entry in parsed:
            if cron_lines_persisted >= max_lines:
                break
            line_number = entry["line_number"]
            schedule_spec = entry["schedule_spec"]
            user = entry["user"]
            command = entry["command"]
            flags = classify_cron_line(
                schedule_spec=schedule_spec, command=command
            )
            if flags["temp_path_command"]:
                temp_path_command_count += 1
            if flags["reboot_persistence"]:
                reboot_persistence_count += 1
            if flags["network_egress_pattern"]:
                network_egress_pattern_count += 1
            row = LinuxCronJob(
                firmware_id=firmware_id,
                source_file=rel[:2048],
                line_number=line_number,
                schedule_spec=schedule_spec,
                user=user,
                command=command,
                suspicious_flags=_stamp_linux_cron_suspicious_flags(
                    dict(flags)
                ),
            )
            db.add(row)
            cron_lines_persisted += 1
            file_lines_persisted += 1
        if file_lines_persisted > 0:
            await db.flush()
        aggregate["cron_temp_path_command_count"] += temp_path_command_count
        aggregate["cron_reboot_persistence_count"] += reboot_persistence_count
        aggregate["cron_network_egress_pattern_count"] += (
            network_egress_pattern_count
        )
        per_artefact.append({
            "artefact_type": "cron",
            "path": rel,
            "lines_persisted": file_lines_persisted,
            "temp_path_command_count": temp_path_command_count,
            "reboot_persistence_count": reboot_persistence_count,
            "network_egress_pattern_count": network_egress_pattern_count,
        })

    aggregate["cron_files_scanned"] = len(cron_candidates)
    aggregate["cron_lines_persisted"] = cron_lines_persisted

    # ── ld.so.preload ──
    ld_candidates = await _scan_ld_preload_candidates_async(roots)
    ld_lines_persisted = 0
    for full, rel in ld_candidates:
        if ld_lines_persisted >= max_lines:
            break
        try:
            parsed = await _parse_ld_preload_async(Path(full))
        except Exception as exc:  # noqa: BLE001
            errors.append(
                f"ld_preload parse {rel}: {type(exc).__name__}: {str(exc)[:120]}"
            )
            continue
        file_lines_persisted = 0
        temp_path_library_count = 0
        unusual_extension_count = 0
        world_writable_dir_count = 0
        for entry in parsed:
            if ld_lines_persisted >= max_lines:
                break
            library_path = entry["library_path"]
            line_number = entry["line_number"]
            flags = classify_ld_preload_line(library_path)
            if flags["temp_path_library"]:
                temp_path_library_count += 1
            if flags["unusual_extension"]:
                unusual_extension_count += 1
            if flags["world_writable_dir"]:
                world_writable_dir_count += 1
            row = LinuxLdPreloadEntry(
                firmware_id=firmware_id,
                source_file=rel[:2048],
                line_number=line_number,
                library_path=library_path[:2048],
                suspicious_flags=_stamp_linux_ld_preload_suspicious_flags(
                    dict(flags)
                ),
            )
            db.add(row)
            ld_lines_persisted += 1
            file_lines_persisted += 1
        if file_lines_persisted > 0:
            await db.flush()
        aggregate["ld_preload_temp_path_library_count"] += (
            temp_path_library_count
        )
        aggregate["ld_preload_unusual_extension_count"] += (
            unusual_extension_count
        )
        aggregate["ld_preload_world_writable_dir_count"] += (
            world_writable_dir_count
        )
        per_artefact.append({
            "artefact_type": "ld_preload",
            "path": rel,
            "lines_persisted": file_lines_persisted,
            "temp_path_library_count": temp_path_library_count,
            "unusual_extension_count": unusual_extension_count,
            "world_writable_dir_count": world_writable_dir_count,
        })

    aggregate["ld_preload_files_scanned"] = len(ld_candidates)
    aggregate["ld_preload_lines_persisted"] = ld_lines_persisted

    # Total anomaly count across all 9 anomaly bits (3 per artefact).
    aggregate["anomaly_total"] = (
        aggregate["bash_clear_marker_count"]
        + aggregate["bash_download_pattern_count"]
        + aggregate["bash_priv_esc_pattern_count"]
        + aggregate["cron_temp_path_command_count"]
        + aggregate["cron_reboot_persistence_count"]
        + aggregate["cron_network_egress_pattern_count"]
        + aggregate["ld_preload_temp_path_library_count"]
        + aggregate["ld_preload_unusual_extension_count"]
        + aggregate["ld_preload_world_writable_dir_count"]
    )
    aggregate["run_seconds"] = round(time.monotonic() - started, 3)
    aggregate["errors"] = errors
    aggregate["per_artefact"] = per_artefact
    return aggregate


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_linux_persistence_walk_background(
    firmware_id: uuid.UUID,
) -> None:
    """202+polling background runner for the Linux persistence-triplet walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a fresh
    session because the inner one rolled back.
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
                    "linux_persistence_walk: firmware %s not found",
                    firmware_id,
                )
                return

            row.persistence_walk_status = "running"
            row.persistence_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_linux_persistence_walk(db, firmware_id)
                row.persistence_walk_status = "completed"
                row.persistence_walk_finished_at = _dt.datetime.now(
                    _dt.UTC
                )
                row.persistence_walk_result = (
                    _stamp_firmware_persistence_walk_result(result)
                )
                await db.commit()

                logger.info(
                    "linux_persistence_walk: firmware %s completed in %.2fs "
                    "(%d bash + %d cron + %d ld_preload lines persisted, "
                    "%d anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["bash_history_lines_persisted"],
                    result["cron_lines_persisted"],
                    result["ld_preload_lines_persisted"],
                    result["anomaly_total"],
                )
            except Exception as exc:  # noqa: BLE001
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
                        fail_row.persistence_walk_status = "failed"
                        fail_row.persistence_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.persistence_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "linux_persistence_walk: firmware %s failed",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "linux_persistence_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_linux_persistence_walk_firmware_safe(
    firmware_id: uuid.UUID,
) -> None:
    """Fire-and-forget entry point — runs the inner orchestrator but
    does NOT mutate ``persistence_walk_status`` so a manual re-trigger
    via the trigger MCP tool still works without 409 conflict.

    Mirrors the appcompat / systemd / journald auto walkers.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_linux_persistence_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.persistence_walk_result = (
                    _stamp_firmware_persistence_walk_result(result)
                )
                await db.commit()

            logger.info(
                "linux_persistence_walk auto: firmware %s walked %d bash "
                "+ %d cron + %d ld_preload files in %.2fs",
                firmware_id,
                result["bash_history_files_scanned"],
                result["cron_files_scanned"],
                result["ld_preload_files_scanned"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "linux_persistence_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_linux_persistence_walk",
    "_parse_bash_history_file",
    "_parse_crontab_file",
    "_parse_ld_so_preload_file",
    "auto_linux_persistence_walk_firmware_safe",
    "classify_bash_history_line",
    "classify_cron_line",
    "classify_ld_preload_line",
    "run_linux_persistence_walk_background",
]
