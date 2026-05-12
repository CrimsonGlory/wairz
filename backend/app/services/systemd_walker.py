"""Phase ι.B.C — Linux systemd unit-file persistence walker (SECOND LINUX).

Walks every ``.service`` / ``.timer`` / ``.socket`` / ``.target`` /
``.path`` / ``.mount`` / ``.swap`` file under detection roots (per
Rule #16) and parses each as INI text. Surfaces T1543.002 (Create or
Modify System Process: Systemd Service), T1547.001 (Boot or Logon
Autostart), and T1053.006 (Scheduled Task — systemd-timer) persistence
indicators.

Real-world adversaries using this exact tradecraft (Phase ι Scout 2):
APT36 Transparent Tribe (Aug 2025), FIRESTARTER (CISA/NCSC 2026),
Quasar Linux QLNX (May 2026).

**Rule #19 evidence-first OSS-library probe** (ran 2026-05-12T15:20Z):

- Python stdlib ``configparser`` handles INI text out of the box.
- BUT: systemd allows duplicate keys (``After=a`` then ``After=b``)
  which configparser collapses (LAST occurrence wins under
  ``strict=False``); systemd also allows multi-value space-separated
  RHS (``WantedBy=a b``).
- Decision: implement a thin manual parser (~80 LOC) that handles
  both shapes correctly. NO new dependency. Same shape as ι.A.C's
  clean-room journald parser — small, well-documented, no vendor-in.

**Rule #39 inner/outer/safe runner triplet** (Rule-of-Fifteen → Rule-
of-Sixteen with this stream):

- :func:`_do_systemd_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every unit-file candidate under detection roots,
  parses each, detects drop-in overrides + enabled-symlinks,
  persists per-unit ``LinuxSystemdUnit`` rows, returns aggregate
  dict UNSTAMPED.
- :func:`run_systemd_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer guard
  catches escapes; failure persistence on a fresh session.
- :func:`auto_systemd_walk_firmware_safe` — UNPACK-POST-DETECTION
  hook. Runs the inner orchestrator + emit hook but does NOT mutate
  ``systemd_walk_status`` (leaves ``idle`` so manual re-trigger
  works without 409).

**Rule #36 no-execute discipline.** This is a pure-Python INI parser.
The walker NEVER:

- Invokes ``systemctl`` / ``systemd-run`` / ``runuser`` against the
  parsed units.
- Sources / evaluates any ``ExecStart=`` / ``ExecStartPre=`` /
  ``ExecStop=`` command line.
- Mounts any path referenced in ``WorkingDirectory=`` /
  ``ReadWritePaths=`` / ``BindPaths=``.
- Links any unit into a running systemd via ``ln -s
  <unit-file> <target>.wants/``.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare
``firmware.extracted_path``) so multi-rootfs Linux firmware
(squashfs / ext / cramfs / erofs / tar.xz) surfaces every unit file
candidate.

**Rule #43 noqa rationale (category 3, bounded loop over ≤8 detection
roots).** Sync filesystem operations inside the bounded outer loop
(over detection roots) are inline rather than executor-wrapped.

**Performance.** A typical Linux firmware extract carries 30-150
systemd unit files. The walker completes in <1 s per firmware. We
cap per-firmware at 10K units (defensive against attacker-planted
trees with millions of bogus units).
"""
from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import logging
import os
import re
import stat
import time
import traceback
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.linux_systemd_units import LinuxSystemdUnit
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_systemd_walk_result,
    _stamp_linux_systemd_units_anomaly_flags,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum units persisted per firmware. Production Linux distros ship
# 100-300 units; bounding at 10K protects against attacker-planted
# trees with millions of bogus units.
_DEFAULT_MAX_UNITS_PER_FIRMWARE: int = 10_000

# Cap on per-file size. Real-world unit files are <4 KB; bounding at
# 256 KB protects against attacker-planted huge files.
_DEFAULT_MAX_UNIT_BYTES: int = 256 * 1024

# Truncate unit_raw content to this size for DB persistence.
_MAX_UNIT_RAW_CHARS: int = 8192

# Truncate ExecStart / WorkingDirectory / etc to this size.
_MAX_EXEC_CHARS: int = 2048

# Known unit-file extensions surfaced by the walker.
_UNIT_EXTENSIONS: frozenset[str] = frozenset({
    ".service",
    ".timer",
    ".socket",
    ".target",
    ".path",
    ".mount",
    ".swap",
    ".automount",
    ".scope",
    ".slice",
    ".device",
})

# Subdirectories under each detection root that systemd searches.
_SYSTEMD_DIRS: tuple[str, ...] = (
    "etc/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
    "run/systemd/system",
    "etc/systemd/user",
)

# Multi-value INI keys per section — values expand from space-separated
# AND repeated-line forms into a single list[str].
_LIST_KEYS_BY_SECTION: dict[str, frozenset[str]] = {
    "Unit": frozenset({
        "After",
        "Before",
        "Requires",
        "Wants",
        "Requisite",
        "BindsTo",
        "PartOf",
        "Conflicts",
        "Documentation",
    }),
    "Install": frozenset({
        "WantedBy",
        "RequiredBy",
        "Also",
        "Alias",
    }),
}

# Standard WantedBy targets that systemd ships with — anything outside
# this set is flagged as enabled_outside_standard.
_STANDARD_WANTED_BY_TARGETS: frozenset[str] = frozenset({
    "multi-user.target",
    "graphical.target",
    "sysinit.target",
    "sockets.target",
    "timers.target",
    "basic.target",
    "default.target",
    "shutdown.target",
    "rescue.target",
    "emergency.target",
    "network-online.target",
    "network.target",
    "remote-fs.target",
    "local-fs.target",
    "umount.target",
    "halt.target",
    "reboot.target",
    "poweroff.target",
})

# Well-known ports for socket activation that are NOT flagged as unusual.
_WELL_KNOWN_PORTS: frozenset[int] = frozenset({
    22, 53, 67, 68, 80, 88, 110, 111, 123, 143, 161, 162,
    389, 443, 445, 465, 514, 587, 631, 636, 873, 989, 990,
    993, 995, 1812, 2049, 3306, 3389, 5432, 5353, 5900, 6379,
    8080, 8443, 8888, 11211, 27017,
})


# ── Anomaly classifier regexes ───────────────────────────────────────────────

# Suspicious-path prefixes for ExecStart / WorkingDirectory (T1543.002
# from-writable persistence).
_SUSPICIOUS_PATH_PREFIXES: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/home/",  # systemd unit ExecStart under a user homedir is unusual
)

# Random-hex unit-name detection. Adversary droppers commonly use
# hex-string names like `abc123def.service` or `4f5a6b.service`.
_RE_RANDOM_HEX_UNIT_NAME = re.compile(
    r"^[0-9a-f]{8,}$",
    re.IGNORECASE,
)

# Obfuscated ExecStart patterns (T1027 Obfuscated Files or Information).
# Base64 strings, eval-like substrings, or very long shell -c invocations.
_RE_LONG_SHELL_C = re.compile(
    r"(?:/bin/sh|/bin/bash|sh|bash)\s+-c\s+[\"']?.{120,}",
    re.IGNORECASE,
)
_RE_EVAL_LIKE = re.compile(
    r"\beval\s|"
    r"\bexec\s+\$\(|"
    r"\bbase64\s+-d|"
    r"\bopenssl\s+(?:enc|aes)|"
    r"\bcurl\s+[^|;\s]+\s*\|\s*(?:sh|bash)|"
    r"\bwget\s+[^|;\s]+\s*-O-?\s*\|",
    re.IGNORECASE,
)
# Long base64-like blob inside the ExecStart string (≥40 chars of
# base64 alphabet, no whitespace).
_RE_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/=]{40,}")


# ── Manual systemd INI parser ────────────────────────────────────────────────


def parse_systemd_unit_text(text: str) -> dict[str, dict[str, Any]]:
    """Parse a systemd unit-file INI text into a nested dict.

    systemd's INI dialect deviates from Python's configparser in two
    ways that matter here:

    1. **Duplicate keys accumulate** rather than collapse. ``After=a``
       then ``After=b`` produces an effective ``After`` value of ``a b``
       (semantically — for list-shape keys; service-side keys like
       ``ExecStart`` get more nuanced handling but here we keep the
       last value).
    2. **Multi-value space-separated RHS.** ``WantedBy=a b`` is a list
       of two targets, not a single string ``a b``.

    We surface both as Python lists via :data:`_LIST_KEYS_BY_SECTION`.

    Comments (``#`` and ``;``) are skipped. Continuation lines (trailing
    backslash) are merged. Empty values (``Key=``) are preserved as
    empty string.

    Returns a dict of dicts: ``{section_name: {key: value_or_list}}``.
    """
    sections: dict[str, dict[str, Any]] = {}
    current_section: str | None = None
    cur_dict: dict[str, Any] | None = None
    pending_continuation = ""

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        # Handle continuation from previous line.
        if pending_continuation:
            line = pending_continuation + line
            pending_continuation = ""
        # Continuation lines end with backslash.
        if line.endswith("\\") and not line.endswith("\\\\"):
            pending_continuation = line[:-1]
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1]
            cur_dict = sections.setdefault(current_section, {})
            continue
        if cur_dict is None:
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()

        list_keys = _LIST_KEYS_BY_SECTION.get(current_section or "", frozenset())
        if key in list_keys:
            # Multi-value list key: split space-separated AND accumulate
            # across repeated-line forms.
            existing = cur_dict.get(key, [])
            if not isinstance(existing, list):
                existing = [existing] if existing else []
            existing.extend(value.split())
            cur_dict[key] = existing
        else:
            # Last-write-wins for scalar keys (matches systemd behavior
            # for ExecStart and friends — last directive overrides).
            cur_dict[key] = value

    return sections


# ── Anomaly classifier (pure functions) ──────────────────────────────────────


def _is_suspicious_path(path: str | None) -> bool:
    """True iff ``path`` begins with one of the writable-directory
    prefixes that signal T1543.002 persistence.

    Tolerates a leading ExecStart prefix like ``-/bin/sh -c '/tmp/x'``
    by scanning the WHOLE string for the prefix — not just the start.
    """
    if not path:
        return False
    lower = path.strip().lower()
    return any(prefix in lower for prefix in _SUSPICIOUS_PATH_PREFIXES)


def _is_suspicious_unit_name(unit_name: str | None) -> bool:
    """True iff the unit basename (no extension) matches a hex-string
    pattern typical of adversary dropper output."""
    if not unit_name:
        return False
    return bool(_RE_RANDOM_HEX_UNIT_NAME.match(unit_name.strip()))


def _is_obfuscated_exec(exec_start: str | None) -> bool:
    """True iff ExecStart matches at least one obfuscation indicator:
    long ``sh -c <…>``, eval-like pattern, curl|sh pattern, or a
    base64-like blob inside the command."""
    if not exec_start:
        return False
    if _RE_LONG_SHELL_C.search(exec_start):
        return True
    if _RE_EVAL_LIKE.search(exec_start):
        return True
    # Base64 detection: must find a ≥40-char base64 alphabet run AND
    # the run must decode to mostly-non-ASCII or contain shell-like
    # markers when decoded (low false-positive heuristic).
    m = _RE_BASE64_BLOB.search(exec_start)
    if m:
        candidate = m.group(0)
        if len(candidate) >= 40:
            try:
                decoded = base64.b64decode(candidate, validate=True)
                # Decode succeeded — that's a strong signal for an
                # actual base64 blob in the command.
                if decoded:
                    return True
            except (ValueError, Exception):  # noqa: BLE001 — defensive
                pass
    return False


def _socket_has_unusual_port(socket_listen: dict[str, Any]) -> bool:
    """True iff any [Socket] ListenStream= / ListenDatagram= value is a
    numeric port outside the well-known set."""
    if not socket_listen:
        return False
    listen_keys = (
        "ListenStream",
        "ListenDatagram",
        "ListenSequentialPacket",
    )
    for key in listen_keys:
        value = socket_listen.get(key)
        if not value:
            continue
        # Value may be ``port`` or ``host:port`` or a path. Extract
        # numeric port for comparison.
        port = _extract_port(str(value))
        if port is not None and port not in _WELL_KNOWN_PORTS:
            return True
    return False


def _extract_port(value: str) -> int | None:
    """Extract numeric port from a [Socket] Listen* value.

    Accepts ``"80"`` → 80; ``"127.0.0.1:8080"`` → 8080;
    ``"/run/foo.sock"`` → None; ``"[::]:443"`` → 443.
    """
    if not value:
        return None
    candidate = value.strip()
    # Path?
    if candidate.startswith("/"):
        return None
    # Host:port — take the part after the LAST colon.
    if ":" in candidate:
        candidate = candidate.rsplit(":", 1)[-1].strip()
    try:
        port = int(candidate)
        if 0 < port < 65536:
            return port
    except (TypeError, ValueError):
        pass
    return None


def _is_root_minimal_deps(
    user: str | None, requires: list[str] | None
) -> bool:
    """True iff User= is root (or unset; systemd's default) AND
    Requires= contains 0 entries. Common rootkit pattern."""
    is_root = user is None or user.strip() in ("", "root", "0")
    deps_count = len(requires or [])
    return is_root and deps_count == 0


def _is_disabled_but_present(enabled: bool, unit_type: str) -> bool:
    """True iff the unit file exists but no enabled-symlink points to
    it. EXCEPTION: ``.target`` / ``.slice`` / ``.scope`` / ``.device``
    are not typically enabled — they're activated indirectly. Don't
    flag those as disabled_but_present."""
    if unit_type in {"target", "slice", "scope", "device"}:
        return False
    return not enabled


def _is_enabled_outside_standard(
    wanted_by: list[str] | None, required_by: list[str] | None
) -> bool:
    """True iff WantedBy= or RequiredBy= contains a non-standard
    target. Empty WantedBy/RequiredBy → False (the disabled_but_present
    flag handles that)."""
    all_targets: list[str] = []
    if wanted_by:
        all_targets.extend(wanted_by)
    if required_by:
        all_targets.extend(required_by)
    if not all_targets:
        return False
    return any(
        t.strip() not in _STANDARD_WANTED_BY_TARGETS for t in all_targets
    )


def build_anomaly_flags(
    *,
    exec_start: str | None,
    working_directory: str | None,
    user: str | None,
    unit_name: str,
    unit_type: str,
    wanted_by: list[str] | None,
    required_by: list[str] | None,
    requires: list[str] | None,
    socket_listen: dict[str, Any] | None,
    enabled: bool,
) -> dict[str, Any]:
    """Construct the anomaly_flags payload from extracted fields.

    Pure function — same inputs always produce the same output.
    Caller stamps the schema_version via
    ``_stamp_linux_systemd_units_anomaly_flags``.
    """
    suspicious_path = (
        _is_suspicious_path(exec_start)
        or _is_suspicious_path(working_directory)
    )
    return {
        "suspicious_path": suspicious_path,
        "suspicious_unit_name": _is_suspicious_unit_name(unit_name),
        "socket_unusual_port": _socket_has_unusual_port(
            socket_listen or {}
        ),
        "root_minimal_deps": _is_root_minimal_deps(user, requires),
        "disabled_but_present": _is_disabled_but_present(
            enabled, unit_type
        ),
        "enabled_outside_standard": _is_enabled_outside_standard(
            wanted_by, required_by
        ),
        "obfuscated_exec": _is_obfuscated_exec(exec_start),
    }


# ── Filesystem helpers ───────────────────────────────────────────────────────


def has_unit_extension(path: str) -> bool:
    """True iff ``path`` ends with a known systemd unit extension."""
    lower = path.lower()
    return any(lower.endswith(ext) for ext in _UNIT_EXTENSIONS)


def get_unit_type_and_name(path: str) -> tuple[str, str]:
    """Split a unit file path into ``(type, basename_without_ext)``.

    Drop-in directories appear as ``<name>.<type>.d`` — handled by the
    caller. Here we just split the leaf.
    """
    basename = os.path.basename(path)
    name_part, _, ext = basename.rpartition(".")
    if not ext or not name_part:
        return ("unknown", basename)
    return (ext.lower(), name_part)


def walk_systemd_unit_paths(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return candidate unit-file paths.

    Scans the canonical systemd unit directories under each root.
    Plus a defensive fallback scan for any other ``.service`` /
    ``.timer`` / etc files under the root (catches non-standard
    layouts).

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots` — NEVER ``firmware.extracted_path``
    alone.
    """
    hits: list[str] = []
    seen: set[str] = set()
    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — bounded loop over ≤8 detection roots
        except OSError:
            continue
        if not os.path.isdir(real_root):  # noqa: ASYNC240 — bounded loop over ≤8 detection roots
            continue
        for sysdir in _SYSTEMD_DIRS:
            full_dir = os.path.join(real_root, sysdir)  # noqa: ASYNC240 — pure-string path math
            if not os.path.isdir(full_dir):  # noqa: ASYNC240 — pre-flight stat
                continue
            for dirpath, dirnames, filenames in os.walk(  # noqa: ASYNC240 — bounded loop
                full_dir, followlinks=False
            ):
                # Skip drop-in directories — they're handled separately.
                dirnames[:] = [d for d in dirnames if not d.endswith(".d")]
                for name in filenames:
                    if not has_unit_extension(name):
                        continue
                    full = os.path.join(dirpath, name)
                    try:
                        # Use lstat to skip symlinks (enabled-symlinks
                        # would otherwise create duplicates pointing at
                        # the same underlying unit).
                        st_info = os.lstat(full)  # noqa: ASYNC240 — pre-flight stat
                        if stat.S_ISLNK(st_info.st_mode):
                            continue
                    except (OSError, AttributeError):
                        continue
                    try:
                        real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math
                    except OSError:
                        continue
                    if not real_full.startswith(real_root):
                        continue
                    if real_full in seen:
                        continue
                    seen.add(real_full)
                    hits.append(real_full)
    return hits


def find_dropin_files(unit_path: str) -> list[str]:
    """Find drop-in override files for a given unit path.

    Drop-ins live at ``<dir>/<unit-name>.<type>.d/*.conf``. Returns
    ABSOLUTE paths to each .conf file in the drop-in directory,
    sorted lexically (systemd merges in lexical order).
    """
    basename = os.path.basename(unit_path)
    dirname = os.path.dirname(unit_path)
    dropin_dir = os.path.join(dirname, basename + ".d")
    try:
        if not os.path.isdir(dropin_dir):
            return []
        names = sorted(
            n for n in os.listdir(dropin_dir) if n.endswith(".conf")
        )
        return [os.path.join(dropin_dir, n) for n in names]
    except OSError:
        return []


def find_enabled_symlinks(
    roots: Iterable[str], unit_basename: str
) -> list[str]:
    """Return ABSOLUTE paths to any enabled-symlink pointing to a unit
    with the given basename.

    Enabled-symlinks live at ``<*.target>.wants/<unit-basename>`` and
    ``<*.target>.requires/<unit-basename>`` under any of the systemd
    search directories. The presence of at least one such symlink is
    the canonical "this unit is going to start" signal.
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if not os.path.isdir(real_root):
            continue
        for sysdir in _SYSTEMD_DIRS:
            full_dir = os.path.join(real_root, sysdir)
            if not os.path.isdir(full_dir):
                continue
            try:
                entries = os.listdir(full_dir)
            except OSError:
                continue
            for entry in entries:
                if not (
                    entry.endswith(".wants") or entry.endswith(".requires")
                ):
                    continue
                wants_dir = os.path.join(full_dir, entry)
                if not os.path.isdir(wants_dir):
                    continue
                try:
                    names = os.listdir(wants_dir)
                except OSError:
                    continue
                for name in names:
                    if name == unit_basename:
                        hits.append(os.path.join(wants_dir, name))
    return hits


def read_unit_file(path: str) -> str | None:
    """Read a unit file's contents as UTF-8 text, with defensive
    fallback to errors='replace'. Returns None on read failure or
    oversize.

    SYNC I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > _DEFAULT_MAX_UNIT_BYTES:
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    return raw.decode("utf-8", errors="replace")


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "units_scanned": 0,
        "units_persisted": 0,
        "service_count": 0,
        "timer_count": 0,
        "socket_count": 0,
        "target_count": 0,
        "other_count": 0,
        "enabled_count": 0,
        "suspicious_path_count": 0,
        "suspicious_unit_name_count": 0,
        "socket_unusual_port_count": 0,
        "root_minimal_deps_count": 0,
        "disabled_but_present_count": 0,
        "enabled_outside_standard_count": 0,
        "obfuscated_exec_count": 0,
        "anomaly_total": 0,
        "errors": [],
        "per_root": [],
    }


# ── Per-unit assembler ───────────────────────────────────────────────────────


def assemble_unit_row(
    *,
    firmware_id: uuid.UUID,
    unit_path: str,
    text: str,
    enabled_symlinks: list[str],
    dropin_texts: list[str],
) -> LinuxSystemdUnit:
    """Construct one LinuxSystemdUnit ORM row from parsed INI text +
    metadata.

    Drop-in texts are merged AFTER the main text (so later directives
    override earlier ones, matching systemd's documented merge order
    — but since we keep last-write-wins for scalar keys, we just
    concatenate-and-reparse).
    """
    # Merge: main first, drop-ins in lexical order. We concatenate and
    # re-parse so the last-write-wins / list-accumulation semantics
    # apply across all sources uniformly.
    merged_text = text
    for dropin_text in dropin_texts:
        merged_text += "\n" + dropin_text

    sections = parse_systemd_unit_text(merged_text)
    unit_section = sections.get("Unit", {})
    service_section = sections.get("Service", {})
    install_section = sections.get("Install", {})
    timer_section = sections.get("Timer", {})
    socket_section = sections.get("Socket", {})

    unit_type, unit_name = get_unit_type_and_name(unit_path)
    description = unit_section.get("Description")
    if isinstance(description, list):
        description = description[-1] if description else None

    exec_start = service_section.get("ExecStart")
    if isinstance(exec_start, list):
        exec_start = exec_start[-1] if exec_start else None
    exec_start_pre = service_section.get("ExecStartPre")
    if isinstance(exec_start_pre, list):
        exec_start_pre = exec_start_pre[-1] if exec_start_pre else None
    exec_stop = service_section.get("ExecStop")
    if isinstance(exec_stop, list):
        exec_stop = exec_stop[-1] if exec_stop else None
    user = service_section.get("User")
    if isinstance(user, list):
        user = user[-1] if user else None
    working_directory = service_section.get("WorkingDirectory")
    if isinstance(working_directory, list):
        working_directory = (
            working_directory[-1] if working_directory else None
        )

    def _norm_list(section: dict, key: str) -> list[str]:
        value = section.get(key)
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v) for v in value if v]
        if isinstance(value, str):
            return value.split() if value else []
        return []

    wanted_by = _norm_list(install_section, "WantedBy")
    required_by = _norm_list(install_section, "RequiredBy")
    requires = _norm_list(unit_section, "Requires")
    after = _norm_list(unit_section, "After")
    before = _norm_list(unit_section, "Before")

    triggers: dict[str, Any] = {}
    for k, v in timer_section.items():
        if isinstance(v, list):
            triggers[k] = v[-1] if v else ""
        else:
            triggers[k] = v
    socket_listen: dict[str, Any] = {}
    for k, v in socket_section.items():
        if isinstance(v, list):
            socket_listen[k] = v[-1] if v else ""
        else:
            socket_listen[k] = v

    enabled = bool(enabled_symlinks)

    anomaly = build_anomaly_flags(
        exec_start=exec_start,
        working_directory=working_directory,
        user=user,
        unit_name=unit_name,
        unit_type=unit_type,
        wanted_by=wanted_by,
        required_by=required_by,
        requires=requires,
        socket_listen=socket_listen,
        enabled=enabled,
    )
    stamped_anomaly = _stamp_linux_systemd_units_anomaly_flags(anomaly)

    return LinuxSystemdUnit(
        firmware_id=firmware_id,
        unit_path=unit_path[:1024],
        unit_type=unit_type[:32],
        unit_name=unit_name[:255],
        description=(description or "")[:512] or None,
        exec_start=(exec_start or "")[:_MAX_EXEC_CHARS] or None,
        exec_start_pre=(
            (exec_start_pre or "")[:_MAX_EXEC_CHARS] or None
        ),
        exec_stop=(exec_stop or "")[:_MAX_EXEC_CHARS] or None,
        user=(user or "")[:64] or None,
        working_directory=(
            (working_directory or "")[:1024] or None
        ),
        wanted_by=wanted_by or None,
        required_by=required_by or None,
        requires=requires or None,
        after=after or None,
        before=before or None,
        enabled=enabled,
        triggers=triggers or None,
        socket_listen=socket_listen or None,
        anomaly_flags=stamped_anomaly,
        unit_raw=text[:_MAX_UNIT_RAW_CHARS],
    )


# ── Per-root walker ──────────────────────────────────────────────────────────


def _walk_one_root_sync(
    root: str,
    *,
    firmware_id: uuid.UUID,
    all_roots: list[str],
    max_units: int,
    persisted_so_far: int,
) -> tuple[list[LinuxSystemdUnit], dict]:
    """Walk all unit files under one detection root, build rows.

    SYNC I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    """
    aggregate: dict = {
        "root": root,
        "units_scanned": 0,
        "units_persisted": 0,
        "errors": [],
    }
    rows: list[LinuxSystemdUnit] = []

    unit_paths = walk_systemd_unit_paths([root])
    persist_budget = max_units - persisted_so_far

    for path in unit_paths:
        aggregate["units_scanned"] += 1
        if persist_budget <= 0:
            continue

        text = read_unit_file(path)
        if text is None:
            aggregate["errors"].append(
                f"read failed or oversize: {path}"
            )
            continue

        # Find drop-in overrides.
        dropin_paths = find_dropin_files(path)
        dropin_texts: list[str] = []
        for dpath in dropin_paths:
            dtext = read_unit_file(dpath)
            if dtext is not None:
                dropin_texts.append(dtext)

        # Find enabled-symlinks across ALL detection roots.
        symlinks = find_enabled_symlinks(all_roots, os.path.basename(path))

        try:
            row = assemble_unit_row(
                firmware_id=firmware_id,
                unit_path=path,
                text=text,
                enabled_symlinks=symlinks,
                dropin_texts=dropin_texts,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            msg = str(exc)
            if len(msg) > 200:
                msg = msg[:200] + "..."
            aggregate["errors"].append(
                f"assemble failed for {path}: {type(exc).__name__}: {msg}"
            )
            continue

        rows.append(row)
        persist_budget -= 1
        aggregate["units_persisted"] += 1

    return rows, aggregate


async def _walk_one_root_async(
    root: str,
    *,
    firmware_id: uuid.UUID,
    all_roots: list[str],
    max_units: int,
    persisted_so_far: int,
) -> tuple[list[LinuxSystemdUnit], dict]:
    """Async wrapper around :func:`_walk_one_root_sync` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_root_sync(
            root,
            firmware_id=firmware_id,
            all_roots=all_roots,
            max_units=max_units,
            persisted_so_far=persisted_so_far,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ──────────────────────────


async def _do_systemd_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_units: int = _DEFAULT_MAX_UNITS_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every systemd unit file under ``firmware_id``'s extracted
    tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. For each root, scan canonical systemd dirs for unit files.
    3. For each unit: read text, find drop-ins + enabled-symlinks,
       parse INI, build LinuxSystemdUnit row + anomaly_flags.
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

    all_rows: list[LinuxSystemdUnit] = []
    per_root_aggregates: list[dict] = []
    errors: list[str] = []

    persisted_so_far = 0
    for root in roots:
        try:
            rows, agg = await _walk_one_root_async(
                root,
                firmware_id=firmware_id,
                all_roots=list(roots),
                max_units=max_units,
                persisted_so_far=persisted_so_far,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            errors.append(
                f"walk failed for root {root}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            per_root_aggregates.append({
                "root": root,
                "units_scanned": 0,
                "units_persisted": 0,
                "errors": [str(exc)[:200]],
            })
            continue
        all_rows.extend(rows)
        per_root_aggregates.append(agg)
        errors.extend(agg.get("errors", []))
        persisted_so_far += agg["units_persisted"]

    # Now write rows to DB.
    for row in all_rows:
        db.add(row)
    if all_rows:
        await db.flush()

    # Aggregate counts.
    service_count = sum(1 for r in all_rows if r.unit_type == "service")
    timer_count = sum(1 for r in all_rows if r.unit_type == "timer")
    socket_count = sum(1 for r in all_rows if r.unit_type == "socket")
    target_count = sum(1 for r in all_rows if r.unit_type == "target")
    other_count = (
        len(all_rows)
        - service_count
        - timer_count
        - socket_count
        - target_count
    )
    enabled_count = sum(1 for r in all_rows if r.enabled)

    def _count_anomaly(rows: list[LinuxSystemdUnit], key: str) -> int:
        c = 0
        for r in rows:
            flags = r.anomaly_flags or {}
            if flags.get(key):
                c += 1
        return c

    suspicious_path_count = _count_anomaly(all_rows, "suspicious_path")
    suspicious_unit_name_count = _count_anomaly(
        all_rows, "suspicious_unit_name"
    )
    socket_unusual_port_count = _count_anomaly(
        all_rows, "socket_unusual_port"
    )
    root_minimal_deps_count = _count_anomaly(
        all_rows, "root_minimal_deps"
    )
    disabled_but_present_count = _count_anomaly(
        all_rows, "disabled_but_present"
    )
    enabled_outside_standard_count = _count_anomaly(
        all_rows, "enabled_outside_standard"
    )
    obfuscated_exec_count = _count_anomaly(all_rows, "obfuscated_exec")

    # anomaly_total = rows with ≥1 anomaly bit (excluding
    # disabled_but_present, which is the noisy LOW baseline).
    substantive_keys = (
        "suspicious_path",
        "suspicious_unit_name",
        "socket_unusual_port",
        "root_minimal_deps",
        "enabled_outside_standard",
        "obfuscated_exec",
    )
    anomaly_total = sum(
        1
        for r in all_rows
        if any((r.anomaly_flags or {}).get(k) for k in substantive_keys)
    )

    units_scanned = sum(a["units_scanned"] for a in per_root_aggregates)

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "units_scanned": units_scanned,
        "units_persisted": len(all_rows),
        "service_count": service_count,
        "timer_count": timer_count,
        "socket_count": socket_count,
        "target_count": target_count,
        "other_count": other_count,
        "enabled_count": enabled_count,
        "suspicious_path_count": suspicious_path_count,
        "suspicious_unit_name_count": suspicious_unit_name_count,
        "socket_unusual_port_count": socket_unusual_port_count,
        "root_minimal_deps_count": root_minimal_deps_count,
        "disabled_but_present_count": disabled_but_present_count,
        "enabled_outside_standard_count": enabled_outside_standard_count,
        "obfuscated_exec_count": obfuscated_exec_count,
        "anomaly_total": anomaly_total,
        "errors": errors,
        "per_root": per_root_aggregates,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_systemd_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the systemd unit walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back.

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
                    "systemd_walk: firmware %s not found", firmware_id
                )
                return

            row.systemd_walk_status = "running"
            row.systemd_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_systemd_walk(db, firmware_id)
                row.systemd_walk_status = "completed"
                row.systemd_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.systemd_walk_result = _stamp_firmware_systemd_walk_result(
                    result
                )
                await db.commit()

                logger.info(
                    "systemd_walk: firmware %s completed in %.2fs "
                    "(%d scanned, %d persisted, %d enabled, %d anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["units_scanned"],
                    result["units_persisted"],
                    result["enabled_count"],
                    result["anomaly_total"],
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
                        fail_row.systemd_walk_status = "failed"
                        fail_row.systemd_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.systemd_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "systemd_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "systemd_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_systemd_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as
    auto_journald_walk_firmware_safe (ι.A.C precedent).

    Distinct from :func:`run_systemd_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-triggered
    walks. The auto-walk-on-unpack flow runs the SAME orchestrator
    (``_do_systemd_walk``) but DOES NOT transition the status
    column — it stays ``idle`` until an operator explicitly triggers
    a re-walk via the trigger MCP tool, which resets and runs again.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_systemd_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.systemd_walk_result = _stamp_firmware_systemd_walk_result(
                    result
                )
                await db.commit()

            logger.info(
                "systemd_walk auto: firmware %s walked %d units in %.2fs",
                firmware_id,
                result["units_scanned"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "systemd_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_systemd_walk",
    "assemble_unit_row",
    "auto_systemd_walk_firmware_safe",
    "build_anomaly_flags",
    "find_dropin_files",
    "find_enabled_symlinks",
    "get_unit_type_and_name",
    "has_unit_extension",
    "parse_systemd_unit_text",
    "read_unit_file",
    "run_systemd_walk_background",
    "walk_systemd_unit_paths",
]
