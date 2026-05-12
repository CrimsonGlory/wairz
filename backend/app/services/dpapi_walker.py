"""Phase κ.D.C — Windows DPAPI master-key PARSE-ONLY METADATA walker
(NINTH κ-era walker; SECOND Rule #45 parse-only-metadata application).

Walks every detection root (per Rule #16) and locates Windows DPAPI
master-key files via the canonical path pattern
``Users/<user>/AppData/Roaming/Microsoft/Protect/<sid>/<guid>``. Parses
each file's HEADER + body PREAMBLE via a pure-Python ``struct``-based
parser, classifies per-file anomalies, and persists per-file rows into
``windows_dpapi_master_keys``.

**PARSE-ONLY DISCIPLINE — Rule #36 + Rule #45 (parse-only-metadata
walker, Rule-of-Two — DURABLE BEYOND DEBATE).** The walker captures
METADATA ONLY. It NEVER:

- Decrypts master keys.
- Invokes Windows DPAPI APIs.
- Attempts plaintext recovery of any protected secret.
- Imports cryptographic decryption modules.
- Records the salt bytes themselves (only the SIZE — exposing the
  salt bytes would aid an attacker doing offline cracking).

The "who created the key (creator_sid)" + "is this key orphaned"
surface IS the forensic value:

- **Orphaned master-keys** (creator_sid no match in firmware user list)
  — backdoor key stash indicator (attacker pre-staged keys for later
  use to decrypt credentials).
- **Admin / SYSTEM-creator master-keys** — privileged-account
  compromise indicator OR legitimate service-account use.
- **Large master-keys** (>2048 bytes vs typical 740-1024) — unusual
  configuration / attacker-planted artefact.

**Rule #19 evidence-first format probe** (against published
references): Master-key file format documented across SharpDPAPI
(public domain references), Mimikatz DPAPI module
(gentilkiwi.com), impacket.dpapi (we may IMPORT the class for layout
constants only — ``.decrypt()`` is FORBIDDEN). Pure-Python ``struct``
parser is the right shape — small surface, no foreign-license
concern, no decryption capability accidentally pulled in.

**Master-key file format** (offsets from file start):
```
DWORD version           (offset 0x00 — 1 or 2)
DWORD unused1           (offset 0x04)
DWORD unused2           (offset 0x08)
BYTE  guid_text[72]     (offset 0x0c — UTF-16LE GUID text)
DWORD unused3           (offset 0x54)
DWORD flags             (offset 0x58)
QWORD policy            (offset 0x5c)
QWORD master_key_len    (offset 0x64)
QWORD backup_key_len    (offset 0x6c)
QWORD cred_hist_len     (offset 0x74)
QWORD domain_key_len    (offset 0x7c)
// payload bodies follow at 0x84 onwards
```

Within the master-key BODY preamble (we may probe ONLY for HMAC
iterations + salt SIZE — NEVER touch the encrypted block):
```
DWORD version
BYTE  salt[16]          (we record salt_size = 16, NOT the bytes)
DWORD pbkdf2_iterations (hmac_iterations — recorded for forensic
                          downgrade-attack detection)
DWORD hash_alg
DWORD crypt_alg
// encrypted body follows (NEVER TOUCH)
```

**Rule #39 inner/outer/safe runner triplet** (Rule-of-Twenty-Two
with this stream):

- :func:`_do_dpapi_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks each detection root, locates master-key file
  candidates via path pattern, parses headers, builds rows. Returns
  aggregate dict UNSTAMPED. Tier-1 tests call this via
  ``make_live_db()`` — no Docker DNS dependency.
- :func:`run_dpapi_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions via
  ``async_session_factory()``. Outer guard catches escapes; failure
  persistence on a fresh session.
- :func:`auto_dpapi_walk_firmware_safe` — UNPACK-POST-DETECTION hook.
  Runs the inner orchestrator but does NOT mutate
  ``dpapi_walk_status`` — leaves ``idle`` so manual re-trigger via the
  trigger MCP tool works without 409 conflict.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare ``firmware.extracted_path``)
so multi-rootfs Windows firmware (VHDX / NTFS / FAT32 / system images)
surfaces every Protect folder candidate.

**Performance.** Per-firmware walks scan only files matching the
DPAPI path pattern (typically 0-50 master-key files per Windows
install); each file is <2 KB so the pure-Python ``struct`` parser
processes <10 ms per file. Total per-firmware: <1 s in the common case.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os
import re
import struct
import time
import traceback
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_dpapi_master_keys import WindowsDpapiMasterKey
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_dpapi_walk_result,
    _stamp_windows_dpapi_anomaly_flags,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum master-key files persisted per firmware. Real Windows installs
# have 0-50 master-key files (one per user × one per credential lifetime).
# Cap at 10000 defensive against attacker-planted artifacts.
_DEFAULT_MAX_FILES_PER_FIRMWARE: int = 10_000

# Maximum master-key file size we'll attempt to parse. Typical files
# are 740-1024 bytes; oversize is a red flag (we still record the row
# with parse_error + large_masterkey flag).
_DEFAULT_MAX_FILE_BYTES: int = 1 * 1024 * 1024  # 1 MiB cap

# Master-key header is fixed-size 0x84 (132) bytes.
_MASTER_KEY_HEADER_SIZE: int = 0x84

# Anomaly threshold: files exceeding this byte count trigger
# large_masterkey anomaly flag. Typical files are 740-1024 bytes; 2048
# is a comfortable threshold above noise + below attacker-planted sizes.
_LARGE_MASTERKEY_THRESHOLD: int = 2048

# Master-key body preamble: version(4) + salt(16) + iterations(4) +
# hash_alg(4) + crypt_alg(4) = 32 bytes. We parse the preamble for
# hmac_iterations + salt_size; the encrypted body following is NEVER
# touched.
_MASTER_KEY_BODY_PREAMBLE_SIZE: int = 32
_MASTER_KEY_SALT_SIZE_OFFSET: int = 4  # bytes 4-20 are salt
_MASTER_KEY_SALT_SIZE: int = 16
_MASTER_KEY_ITERATIONS_OFFSET: int = 20  # bytes 20-24 are PBKDF2 iters

# Path-pattern recognizer.
# Match files like ``Users/<user>/AppData/Roaming/Microsoft/Protect/
# S-1-5-21-<digits>-<digits>-<digits>-<rid>/<hex-guid>``. The GUID
# basename uses lowercase hex with dashes.
# Use EXPLICIT boundary char groups instead of `\b` (Rule from κ.C
# postmortem — `\b` semantics at `/` differ from word boundaries).
_DPAPI_PATH_PATTERN = re.compile(
    # Match the Protect directory anywhere in the path (case-insensitive
    # for the directory name parts; SID and GUID are case-sensitive on
    # disk by typical extraction but we accept both).
    r"(?:[\\/]|^)Users[\\/](?P<user>[^\\/]+)[\\/]AppData[\\/]Roaming[\\/]"
    r"Microsoft[\\/]Protect[\\/]"
    r"(?P<sid>S-1-5-[0-9-]+)[\\/]"
    r"(?P<guid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)

# Lighter pattern that just checks the file basename looks like a GUID
# without the surrounding path — used during the directory walk as a
# fast pre-filter before applying the full pattern above.
_GUID_FILE_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Admin RID suffixes — Windows well-known accounts that DPAPI is
# notable when used by:
# - RID 500 = Built-in Administrator
# - RID 512 = Domain Admins
# - RID 519 = Enterprise Admins
# - SID S-1-5-18 = Local System (entire SID match)
_ADMIN_RID_SUFFIXES: tuple[str, ...] = ("-500", "-512", "-519")
_LOCAL_SYSTEM_SID: str = "S-1-5-18"


# ── SID classification helpers ───────────────────────────────────────────────


def is_admin_creator_sid(sid: str | None) -> bool:
    """Return True iff the SID matches a Windows admin RID pattern
    (RID 500 / 512 / 519) OR is the Local System SID (S-1-5-18).

    Per Rule #45 + Rule #36 PARSE-ONLY — this is METADATA classification
    only. We never invoke anything on behalf of the matched SID.
    """
    if not sid:
        return False
    if sid == _LOCAL_SYSTEM_SID:
        return True
    return any(sid.endswith(suffix) for suffix in _ADMIN_RID_SUFFIXES)


# ── Master-key file header parser (PARSE-ONLY — Rule #36 + Rule #45) ─────────


def parse_master_key_header(
    blob: bytes,
) -> tuple[dict[str, Any], list[str]]:
    """Parse the 0x84-byte master-key file header.

    Returns ``(fields, errors)`` where fields is a dict with keys:
    ``version``, ``flags``, ``master_key_size``, ``backup_key_size``,
    ``cred_hist_size``, ``domain_key_size``, ``has_body_preamble``,
    ``hmac_iterations`` (None if body preamble absent),
    ``salt_size`` (None if body preamble absent).

    PARSE-ONLY: this function reads bytes, unpacks structs, returns
    metadata. It DOES NOT process the encrypted body that follows the
    header + preamble. The walker NEVER decrypts master keys.

    Defensive: bounds-checked; never raises. Returns ``{}`` + a single
    error if the blob is too short to parse the header.
    """
    fields: dict[str, Any] = {}
    errors: list[str] = []

    if len(blob) < _MASTER_KEY_HEADER_SIZE:
        errors.append(
            f"blob too short ({len(blob)} bytes < {_MASTER_KEY_HEADER_SIZE}"
            f"-byte header)"
        )
        return fields, errors

    try:
        version = struct.unpack_from("<I", blob, 0x00)[0]
        flags = struct.unpack_from("<I", blob, 0x58)[0]
        master_key_size = struct.unpack_from("<Q", blob, 0x64)[0]
        backup_key_size = struct.unpack_from("<Q", blob, 0x6c)[0]
        cred_hist_size = struct.unpack_from("<Q", blob, 0x74)[0]
        domain_key_size = struct.unpack_from("<Q", blob, 0x7c)[0]
    except struct.error as exc:
        errors.append(f"header unpack error: {exc}")
        return fields, errors

    # Defensive — version field MUST be 1 or 2 per the canonical
    # master-key file format. Other values are corrupted / not-a-
    # master-key.
    if version not in (1, 2):
        errors.append(
            f"unexpected version {version} (expected 1 or 2); not a "
            "master-key file"
        )
        return fields, errors

    fields["version"] = int(version)
    fields["flags"] = int(flags)
    fields["master_key_size"] = int(master_key_size)
    fields["backup_key_size"] = int(backup_key_size)
    fields["cred_hist_size"] = int(cred_hist_size)
    fields["domain_key_size"] = int(domain_key_size)

    # Attempt to read the master-key body preamble.
    # The master-key body STARTS at offset 0x84 (right after header).
    # We probe ONLY the preamble — version(4) + salt(16) + iterations(4)
    # — and STOP. The encrypted block follows; we NEVER read it.
    fields["hmac_iterations"] = None
    fields["salt_size"] = None
    fields["has_body_preamble"] = False
    body_start = _MASTER_KEY_HEADER_SIZE
    body_preamble_end = body_start + _MASTER_KEY_BODY_PREAMBLE_SIZE

    # The body only exists if master_key_size > 0 (some files have a
    # zero master_key_size — backup-only or cred-hist-only files).
    if master_key_size >= _MASTER_KEY_BODY_PREAMBLE_SIZE and (
        body_preamble_end <= len(blob)
    ):
        try:
            # We READ ONLY the iteration count from the body preamble.
            # The salt bytes at offset 4-20 in the body are NEVER copied
            # out — we only record the salt SIZE constant (16).
            iterations = struct.unpack_from(
                "<I", blob, body_start + _MASTER_KEY_ITERATIONS_OFFSET
            )[0]
            fields["hmac_iterations"] = int(iterations)
            fields["salt_size"] = _MASTER_KEY_SALT_SIZE
            fields["has_body_preamble"] = True
        except struct.error:
            # Preamble unparseable — leave the fields as None; caller
            # decides whether this is parse_error or just an empty
            # body.
            pass

    return fields, errors


# ── Path-pattern + GUID extraction helpers ───────────────────────────────────


def extract_dpapi_path_info(
    path: str,
) -> dict[str, str | None]:
    """Match the canonical DPAPI path pattern and extract:
    ``user``, ``creator_sid``, ``master_key_guid``.

    Returns dict with keys ``user`` / ``creator_sid`` / ``master_key_guid``.
    Values are ``None`` when the path doesn't match the pattern.
    """
    # Normalise backslashes to forward slashes for pattern matching.
    # The pattern accepts both, but normalisation reduces variance.
    match = _DPAPI_PATH_PATTERN.search(path)
    if not match:
        return {
            "user": None,
            "creator_sid": None,
            "master_key_guid": None,
        }
    return {
        "user": match.group("user"),
        "creator_sid": match.group("sid"),
        "master_key_guid": match.group("guid").lower(),
    }


def looks_like_dpapi_master_key_file(file_path: str) -> bool:
    """Quick filename-based pre-filter — True iff the basename looks
    like a DPAPI master-key GUID.

    Fast check before applying the full path-pattern regex. The full
    regex (which also matches the surrounding directory chain) is
    applied only when this returns True, reducing overhead during
    directory walks.
    """
    basename = os.path.basename(file_path)
    return _GUID_FILE_PATTERN.match(basename) is not None


# ── Anomaly classifier (pure functions) ──────────────────────────────────────


def build_anomaly_flags(
    *,
    creator_sid: str | None,
    file_size_bytes: int | None,
    parse_error: bool,
    known_user_sids: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Construct the anomaly_flags payload for one master-key file.

    Pure function — same inputs always produce the same output. Caller
    stamps the schema_version via ``_stamp_windows_dpapi_anomaly_flags``.

    Anomaly bits:
    - ``orphaned_masterkey``: creator_sid is present BUT doesn't match
      any SID in ``known_user_sids`` (when known_user_sids is provided).
      When known_user_sids is None, this bit is always False (no signal).
    - ``admin_creator_sid``: creator_sid matches Windows admin RID
      pattern (RID 500 / 512 / 519) OR Local System SID.
    - ``large_masterkey``: file_size_bytes > 2048 (typical: 740-1024).
    - ``parse_error``: the file header couldn't be parsed cleanly.
    """
    is_orphaned = False
    if known_user_sids is not None and creator_sid:
        is_orphaned = creator_sid not in known_user_sids

    flags: dict[str, Any] = {
        "orphaned_masterkey": is_orphaned,
        "admin_creator_sid": is_admin_creator_sid(creator_sid),
        "large_masterkey": (
            file_size_bytes is not None
            and file_size_bytes > _LARGE_MASTERKEY_THRESHOLD
        ),
        "parse_error": bool(parse_error),
    }
    return flags


# ── Filesystem scan helpers ──────────────────────────────────────────────────


def scan_for_dpapi_files(roots: list[str]) -> list[str]:
    """Walk every detection root and return absolute paths of files
    matching the DPAPI master-key path pattern.

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Skips symlinks pointing outside the root tree (Rule #1 spirit).
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for name in filenames:
                if not _GUID_FILE_PATTERN.match(name):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                # Apply the full path pattern as the authoritative check.
                if extract_dpapi_path_info(real_full)["master_key_guid"]:
                    hits.append(real_full)
    return hits


def discover_user_sids_in_extraction(roots: list[str]) -> frozenset[str]:
    """Discover user SIDs visible in the firmware extraction by
    enumerating Protect directories.

    Used by the orphaned_masterkey anomaly heuristic — if a master-key
    file's creator_sid doesn't match any of these SIDs, the key is
    "orphaned" relative to the extraction (suggests it was placed by
    an attacker for offline use OR belongs to a deleted user).

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    """
    sids: set[str] = set()
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        # Look for any user directory under Users/<user>/AppData/Roaming/
        # Microsoft/Protect/ — the immediate child directory under
        # Protect is a SID directory.
        protect_pattern = re.compile(
            r"Users[\\/](?P<user>[^\\/]+)[\\/]AppData[\\/]Roaming[\\/]"
            r"Microsoft[\\/]Protect$",
            re.IGNORECASE,
        )
        for dirpath, dirnames, _filenames in os.walk(
            root, followlinks=False
        ):
            try:
                real_dirpath = os.path.realpath(dirpath)
            except OSError:
                continue
            if not real_dirpath.startswith(real_root):
                continue
            if protect_pattern.search(real_dirpath):
                # Each immediate subdirectory under Protect is a SID
                # directory.
                for entry in dirnames:
                    if entry.startswith("S-1-5-"):
                        sids.add(entry)
    return frozenset(sids)


# ── Per-file walker ──────────────────────────────────────────────────────────


def _walk_one_file_sync(
    file_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    known_user_sids: frozenset[str] | None = None,
) -> tuple[WindowsDpapiMasterKey | None, dict[str, Any]]:
    """Open one DPAPI master-key file and parse its header.

    SYNC I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Defensive: returns None on any error EXCEPT path-pattern mismatch
    (returns row with parse_error in that case so operators can audit).

    PARSE-ONLY: this function reads the file's HEADER + body PREAMBLE
    AS DATA. The encrypted body following the preamble is NEVER read
    or processed.
    """
    aggregate: dict[str, Any] = {
        "path": relative_source,
        "status": "ok",
        "anomaly_flags": {},
        "parse_error": None,
    }

    try:
        size = os.path.getsize(file_path)
    except OSError as exc:
        aggregate["status"] = "error"
        aggregate["parse_error"] = (
            f"stat failed: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return None, aggregate

    if size > _DEFAULT_MAX_FILE_BYTES:
        aggregate["status"] = "skipped"
        aggregate["parse_error"] = (
            f"file size {size} exceeds max {_DEFAULT_MAX_FILE_BYTES}"
        )
        return None, aggregate

    # Get last-modified ts from filesystem mtime.
    try:
        mtime = os.path.getmtime(file_path)
        last_modified_ts = _dt.datetime.fromtimestamp(mtime, tz=_dt.UTC)
    except OSError:
        last_modified_ts = None

    # Read file content.
    try:
        with open(file_path, "rb") as fh:
            blob = fh.read()
    except OSError as exc:
        aggregate["status"] = "error"
        aggregate["parse_error"] = (
            f"read failed: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return None, aggregate

    # Extract path info (creator_sid + master_key_guid + user).
    path_info = extract_dpapi_path_info(file_path)
    creator_sid = path_info["creator_sid"]
    master_key_guid = path_info["master_key_guid"]

    # Parse header + body preamble (PARSE-ONLY).
    header_fields, header_errors = parse_master_key_header(blob)
    parse_error_text: str | None = None
    if header_errors:
        parse_error_text = " | ".join(header_errors)[:1000]
        aggregate["parse_error"] = parse_error_text

    # Build anomaly flags.
    anomaly = build_anomaly_flags(
        creator_sid=creator_sid,
        file_size_bytes=size,
        parse_error=parse_error_text is not None,
        known_user_sids=known_user_sids,
    )
    aggregate["anomaly_flags"] = anomaly

    # Truncate source path defensively.
    truncated_path = relative_source
    if len(truncated_path) > 1024:
        truncated_path = truncated_path[:1024]

    row = WindowsDpapiMasterKey(
        firmware_id=firmware_id,
        source_file_path=truncated_path,
        master_key_guid=master_key_guid,
        creator_sid=creator_sid,
        flags=header_fields.get("flags"),
        hmac_iterations=header_fields.get("hmac_iterations"),
        salt_size=header_fields.get("salt_size"),
        master_key_size=header_fields.get("master_key_size"),
        backup_key_size=header_fields.get("backup_key_size"),
        cred_hist_size=header_fields.get("cred_hist_size"),
        domain_key_size=header_fields.get("domain_key_size"),
        file_size_bytes=int(size),
        last_modified_ts=last_modified_ts,
        anomaly_flags=_stamp_windows_dpapi_anomaly_flags(dict(anomaly)),
        parse_error=parse_error_text,
        schema_version=int(header_fields.get("version", 1) or 1),
    )

    return row, aggregate


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "files_scanned": 0,
        "files_persisted": 0,
        "files_capped": 0,
        "parse_errors": 0,
        "orphaned_masterkey_count": 0,
        "admin_creator_sid_count": 0,
        "large_masterkey_count": 0,
        "anomaly_total": 0,
        "errors": [],
        "per_file": [],
    }


def _relativize_path(full_path: str, roots: list[str]) -> str:
    """Compute path relative to whichever detection root contains it."""
    try:
        real_full = os.path.realpath(full_path)
    except OSError:
        return os.path.basename(full_path)
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if real_full == real_root or real_full.startswith(real_root + os.sep):
            return (
                real_full[len(real_root) + 1:]
                if real_full != real_root
                else "."
            )
    return os.path.basename(full_path)


async def _scan_for_dpapi_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around scan_for_dpapi_files (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, scan_for_dpapi_files, roots)


async def _discover_user_sids_async(
    roots: list[str],
) -> frozenset[str]:
    """Async wrapper around discover_user_sids_in_extraction (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, discover_user_sids_in_extraction, roots
    )


async def _walk_one_file_async(
    file_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    known_user_sids: frozenset[str] | None,
) -> tuple[WindowsDpapiMasterKey | None, dict[str, Any]]:
    """Async wrapper around _walk_one_file_sync (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_file_sync(
            file_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
            known_user_sids=known_user_sids,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ──────────────────────────


async def _do_dpapi_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_files: int = _DEFAULT_MAX_FILES_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every DPAPI master-key file under ``firmware_id``'s detection
    roots, parse each file's HEADER + body PREAMBLE (PARSE-ONLY), classify
    anomalies, and persist per-file rows.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Discover known user SIDs (for orphaned_masterkey heuristic).
    3. Scan filesystem for master-key files (filename + path pattern).
    4. For each file: parse header, classify anomalies, build row.
    5. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real test
    DB without DNS resolution issues from ``async_session_factory()``.

    Rule #36 + Rule #45 reminder: NEVER decrypts master keys, NEVER
    invokes DPAPI APIs, NEVER attempts plaintext recovery, NEVER records
    salt bytes (only the SIZE).
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

    file_paths = await _scan_for_dpapi_files_async(roots)
    known_user_sids = await _discover_user_sids_async(roots)

    files_scanned = 0
    files_persisted = 0
    files_capped = 0
    parse_errors = 0
    orphaned_masterkey_count = 0
    admin_creator_sid_count = 0
    large_masterkey_count = 0
    anomaly_total = 0
    errors: list[str] = []
    per_file: list[dict] = []

    for file_path in file_paths:
        files_scanned += 1
        if files_persisted >= max_files:
            files_capped += 1
            continue

        relative = _relativize_path(file_path, roots)
        try:
            row, agg = await _walk_one_file_async(
                file_path,
                firmware_id=firmware_id,
                relative_source=relative,
                known_user_sids=known_user_sids,
            )
        except Exception as exc:  # noqa: BLE001
            err = (
                f"walk failed for {file_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_file.append({
                "path": relative,
                "status": "error",
                "parse_error": err,
                "anomaly_flags": {},
            })
            continue

        if agg.get("parse_error"):
            parse_errors += 1
            errors.append(f"{relative}: {agg['parse_error']}")

        if row is None:
            per_file.append(agg)
            continue

        anomaly = agg["anomaly_flags"]
        if anomaly.get("orphaned_masterkey"):
            orphaned_masterkey_count += 1
        if anomaly.get("admin_creator_sid"):
            admin_creator_sid_count += 1
        if anomaly.get("large_masterkey"):
            large_masterkey_count += 1
        if any(
            v for k, v in anomaly.items()
            if isinstance(v, bool) and k != "parse_error"
        ):
            anomaly_total += 1

        per_file.append(agg)

        db.add(row)
        files_persisted += 1

    if files_persisted > 0:
        await db.flush()

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "files_scanned": files_scanned,
        "files_persisted": files_persisted,
        "files_capped": files_capped,
        "parse_errors": parse_errors,
        "orphaned_masterkey_count": orphaned_masterkey_count,
        "admin_creator_sid_count": admin_creator_sid_count,
        "large_masterkey_count": large_masterkey_count,
        "anomaly_total": anomaly_total,
        "errors": errors,
        "per_file": per_file,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_dpapi_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the DPAPI master-key METADATA
    walk.

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
                    "dpapi_walk: firmware %s not found", firmware_id
                )
                return

            row.dpapi_walk_status = "running"
            row.dpapi_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_dpapi_walk(db, firmware_id)
                row.dpapi_walk_status = "completed"
                row.dpapi_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.dpapi_walk_result = (
                    _stamp_firmware_dpapi_walk_result(result)
                )
                await db.commit()

                logger.info(
                    "dpapi_walk: firmware %s completed in %.2fs "
                    "(%d files scanned, %d persisted, %d anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["files_scanned"],
                    result["files_persisted"],
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
                        fail_row.dpapi_walk_status = "failed"
                        fail_row.dpapi_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.dpapi_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "dpapi_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "dpapi_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_dpapi_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point — runs the inner orchestrator but
    does NOT mutate ``dpapi_walk_status`` so a manual re-trigger via the
    trigger MCP tool still works without 409 conflict.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_dpapi_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.dpapi_walk_result = (
                    _stamp_firmware_dpapi_walk_result(result)
                )
                await db.commit()

            logger.info(
                "dpapi_walk auto: firmware %s scanned %d files / "
                "%d persisted in %.2fs",
                firmware_id,
                result["files_scanned"],
                result["files_persisted"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "dpapi_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_dpapi_walk",
    "auto_dpapi_walk_firmware_safe",
    "build_anomaly_flags",
    "discover_user_sids_in_extraction",
    "extract_dpapi_path_info",
    "is_admin_creator_sid",
    "looks_like_dpapi_master_key_file",
    "parse_master_key_header",
    "run_dpapi_walk_background",
    "scan_for_dpapi_files",
]
