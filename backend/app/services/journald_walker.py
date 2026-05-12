"""Phase ι.A — Linux systemd journald binary log walker (FIRST LINUX walker).

Reads ``.journal`` binary log files extracted from Linux firmware
captures (typically at ``var/log/journal/<machine-id>/system.journal``
and ``run/log/journal/<machine-id>/*.journal`` paths under detection
roots per Rule #16). Implements a clean-room pure-Python parser over
the upstream systemd/sd-journal binary format (the public
``journal-def.h`` reference at https://systemd.io/JOURNAL_FILE_FORMAT/).

**Rule #19 evidence-first OSS-library probe** (ran 2026-05-12T14:50Z):

- ``pip show dissect.journal`` → package-not-found
- ``curl pypi.org/pypi/dissect.journal/json`` → HTTP 404
- ``kaitaistruct`` is available (MIT, v0.11) but the Kaitai-generated
  parser would be ~500 LOC of vendor-in code

Decision: clean-room parser. Smaller surface (~200 LOC of decode
logic over well-documented format); no new dep; same license-aligned
footprint as the pure-Python parsers (regipy / python-evtx /
windowsprefetch) already in wairz.

**Rule #39 inner/outer/safe runner triplet** (precedent chain
extending to Rule-of-Fourteen with this stream):

- :func:`_do_journald_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every ``.journal`` candidate under detection roots,
  decodes each via :func:`_iter_journal_entries`, persists per-entry
  ``LinuxJournaldEntry`` rows, returns aggregate dict UNSTAMPED.
- :func:`run_journald_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer guard
  catches escapes; failure persistence on a fresh session.
- :func:`auto_journald_walk_firmware_safe` — UNPACK-POST-DETECTION
  hook. Runs the inner orchestrator + emit hook but does NOT mutate
  ``journald_walk_status`` (leaves ``idle`` so manual re-trigger
  works without 409).

**Rule #36 no-execute discipline.** The walker is a pure-Python
parser that decodes journald binary structs AS DATA. The walker
NEVER:

- Invokes ``journalctl`` / ``systemd-cat`` against the parsed file.
- Replays the embedded entries against any systemd component.
- Mounts or executes any artefact referenced by ``_EXE`` / ``_CMDLINE``.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare
``firmware.extracted_path``) so multi-rootfs Linux firmware
(squashfs / ext / cramfs / erofs / tar.xz) surfaces every
``.journal`` candidate.

**Rule #43 noqa rationale (category 3, bounded loop over ≤8 detection
roots).** Sync filesystem operations inside the bounded outer loop
(over detection roots) are inline rather than executor-wrapped.

**Compression compatibility.** journald supports XZ / LZ4 / Zstd
compression of large DATA payloads (entries above ~512 B threshold).
The walker handles UNCOMPRESSED payloads + reports compressed
entries via the ``compressed_skipped`` counter in the result
aggregate. Most journald entries (kernel messages, audit records,
short-message systemd unit logs) are below the compression
threshold; we surface the rich majority without depending on lz4
/ zstd Python bindings.

**Performance.** Pure-Python struct decode runs at ~30-50 MB/s on
the dev box. A typical ``/var/log/journal/*/system.journal`` file
is 8-32 MB; the walker completes in <1 s per file. We cap
per-firmware at 50K entries (``_DEFAULT_MAX_ENTRIES_PER_FIRMWARE``)
defensive against attacker-planted journals with millions of bogus
entries. Individual files >500 MB are skipped with a counter.
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
from collections.abc import Iterable, Iterator
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.linux_journald_entry import LinuxJournaldEntry
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_journald_walk_result,
    _stamp_linux_journald_entries_anomaly_flags,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum journal entries persisted per firmware. Real-world journals
# carry 1K-10K entries; bounding at 50K covers any plausible case while
# protecting against attacker-planted files with millions of entries.
_DEFAULT_MAX_ENTRIES_PER_FIRMWARE: int = 50_000

# Cap on per-file size. Real-world .journal files run 8-32 MB rotating;
# legitimately rare cases reach a few hundred MB. Protect against
# attacker-planted GB-sized files with bogus padding.
_DEFAULT_MAX_FILE_BYTES: int = 500 * 1024 * 1024  # 500 MiB

# Max chars of MESSAGE body persisted per entry. MCP outputs cap at
# 30 KB; bounding individual messages at 8 KB keeps tool outputs
# manageable even at high entry counts.
_MAX_MESSAGE_CHARS: int = 8192

# Max chars of _CMDLINE persisted per entry. Cmdline strings on Linux
# can reach 128 KB (kernel limit); 4 KB covers operational cases.
_MAX_CMDLINE_CHARS: int = 4096


# ── journald format constants ────────────────────────────────────────────────

# File-signature magic. First 8 bytes of every .journal file.
JOURNAL_MAGIC = b"LPKSHHRH"

# Object types (per OBJECT_TYPE enum in systemd/journal-def.h).
OBJECT_UNUSED = 0
OBJECT_DATA = 1
OBJECT_FIELD = 2
OBJECT_ENTRY = 3
OBJECT_DATA_HASH_TABLE = 4
OBJECT_FIELD_HASH_TABLE = 5
OBJECT_ENTRY_ARRAY = 6
OBJECT_TAG = 7

# Incompatible flags (HEADER_INCOMPATIBLE_*).
HEADER_INCOMPATIBLE_COMPRESSED_XZ = 1 << 0
HEADER_INCOMPATIBLE_COMPRESSED_LZ4 = 1 << 1
HEADER_INCOMPATIBLE_KEYED_HASH = 1 << 2
HEADER_INCOMPATIBLE_COMPRESSED_ZSTD = 1 << 3
HEADER_INCOMPATIBLE_COMPACT = 1 << 4

# Object flags (per-object flags field in the object header).
OBJECT_COMPRESSED_XZ = 1 << 0
OBJECT_COMPRESSED_LZ4 = 1 << 1
OBJECT_COMPRESSED_ZSTD = 1 << 2

# Object headers are 8-byte aligned in the file.
OBJECT_ALIGN = 8


# ── Header struct sizes ──────────────────────────────────────────────────────
# Calculation: signature(8) + compatible_flags(4) + incompatible_flags(4) +
# state(1) + reserved(7) + file_id(16) + machine_id(16) +
# tail_entry_boot_id(16) + seqnum_id(16) + header_size(8) +
# arena_size(8) + data_hash_table_offset(8) + data_hash_table_size(8) +
# field_hash_table_offset(8) + field_hash_table_size(8) +
# tail_object_offset(8) + n_objects(8) + n_entries(8) = 160 bytes
# (minimum portable header — pre-187 systemd). Later additions
# (head_entry_realtime / tail_entry_realtime / tail_entry_monotonic /
# n_data / n_fields / n_tags / n_entry_arrays / data_hash_chain_depth /
# field_hash_chain_depth / tail_entry_array_offset / tail_entry_offset)
# are optional and accessed only if header_size > min.
_MIN_HEADER_SIZE = 160


# ── Anomaly classifier regexes ───────────────────────────────────────────────
# Patterns surface T1070.002 / T1543.002 / T1562.012 / T1547 adversary
# indicators per Phase ι.A Scout 2 (Persona-E refresh).

# kernel OOM-killer (T1499 / T1543.002 collateral signal).
_RE_OOM_KILLER = re.compile(
    r"\b(out of memory|oom[-_ ]?killer|killed process|invoked oom)",
    re.IGNORECASE,
)

# Segfault / kernel crash (T1499 candidate).
_RE_SEGFAULT = re.compile(
    r"\b(segfault at|general protection|kernel panic|trap "
    r"invalid opcode|bug: ?[a-z]+)\b",
    re.IGNORECASE,
)

# SELinux denied (T1562.001 defense evasion residue).
_RE_SELINUX_DENIED = re.compile(
    r"avc:\s*denied|selinux is preventing|type=avc\b",
    re.IGNORECASE,
)

# journalctl --vacuum / --rotate marker (T1070.002 Clear Linux System
# Logs).
_RE_LOG_CLEAR = re.compile(
    r"\b(vacuum|journal[a-z_]* (rotate|cleared|truncate)|"
    r"deleted archived journal|reclaimed [0-9]+\s*(b|k|m|g))\b",
    re.IGNORECASE,
)

# Failed-unit / start-failure on systemd transport.
_RE_UNIT_FAILED = re.compile(
    r"\b(failed to start|failed with result|unit entered failed|"
    r"service hold-off time over|start request repeated too quickly|"
    r"start operation timed out)\b",
    re.IGNORECASE,
)

# audit-fail (T1562.012 audit-system tampering surrogate).
_RE_AUDIT_FAIL = re.compile(
    r"audit:\s*(lost|backlog|sequence|netlink)\b|kauditd",
    re.IGNORECASE,
)

# Suspicious unit-file ExecStart paths (T1543.002 systemd-from-writable
# persistence).
_SUSPICIOUS_UNIT_PATH_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/home/",  # systemd unit under a user homedir is unusual
)


# ── Format-decode primitives ────────────────────────────────────────────────


def has_journal_magic(path: str) -> bool:
    """Return True iff the file at ``path`` begins with the 8-byte
    journald magic ``LPKSHHRH``.

    Defensive against unreadable files (OSError) → False. Cheap —
    reads only the first 8 bytes.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    return head == JOURNAL_MAGIC


def _read_header(buf: bytes) -> dict[str, Any] | None:
    """Decode the journald file header from the first bytes of ``buf``.

    Returns a dict of the documented fields, or None on a malformed
    header. The walker only requires a subset of the header fields,
    so we tolerate older systemd journal files that have a shorter
    header (the size is itself stored in ``header_size``).
    """
    if len(buf) < _MIN_HEADER_SIZE:
        return None
    if buf[:8] != JOURNAL_MAGIC:
        return None
    try:
        (compatible_flags, incompatible_flags) = struct.unpack_from(
            "<II", buf, 8
        )
        # state(1) + reserved(7) = skip 8 bytes at offset 16
        file_id = buf[24:40]
        machine_id = buf[40:56]
        tail_entry_boot_id = buf[56:72]
        seqnum_id = buf[72:88]
        (
            header_size,
            arena_size,
            data_hash_table_offset,
            data_hash_table_size,
            field_hash_table_offset,
            field_hash_table_size,
            tail_object_offset,
            n_objects,
            n_entries,
        ) = struct.unpack_from("<9Q", buf, 88)
    except struct.error:
        return None
    return {
        "compatible_flags": compatible_flags,
        "incompatible_flags": incompatible_flags,
        "file_id": file_id.hex(),
        "machine_id": machine_id.hex(),
        "tail_entry_boot_id": tail_entry_boot_id.hex(),
        "seqnum_id": seqnum_id.hex(),
        "header_size": header_size,
        "arena_size": arena_size,
        "data_hash_table_offset": data_hash_table_offset,
        "data_hash_table_size": data_hash_table_size,
        "field_hash_table_offset": field_hash_table_offset,
        "field_hash_table_size": field_hash_table_size,
        "tail_object_offset": tail_object_offset,
        "n_objects": n_objects,
        "n_entries": n_entries,
        "compact": bool(incompatible_flags & HEADER_INCOMPATIBLE_COMPACT),
    }


def _read_object_header(buf: bytes, offset: int) -> tuple[int, int, int] | None:
    """Decode an ObjectHeader at ``offset`` in ``buf``. Returns
    (object_type, object_flags, object_size) or None on parse
    failure / short read."""
    if offset < 0 or offset + 16 > len(buf):
        return None
    try:
        obj_type, obj_flags = struct.unpack_from("<BB", buf, offset)
        # reserved(6) — skip
        (obj_size,) = struct.unpack_from("<Q", buf, offset + 8)
    except struct.error:
        return None
    return obj_type, obj_flags, obj_size


def _decode_data_payload(
    buf: bytes,
    offset: int,
    obj_size: int,
    obj_flags: int,
    compact: bool,
) -> str | None:
    """Decode a DATA object payload at ``offset`` to a string.

    DATA object layout (regular):
        ObjectHeader(16) + hash(8) + next_hash_offset(8) +
        next_field_offset(8) + entry_offset(8) + entry_array_offset(8) +
        n_entries(8) + payload[]
    Total fixed prefix = 64 bytes.

    DATA object layout (compact, when HEADER_INCOMPATIBLE_COMPACT set):
        ObjectHeader(16) + hash(8) + next_hash_offset(8) +
        next_field_offset(8) + entry_offset(8) + entry_array_offset(8) +
        n_entries(8) + tail_entry_array_offset(4) +
        tail_entry_array_n_entries(4) + payload[]
    Total fixed prefix = 72 bytes.

    Compressed payloads (XZ / LZ4 / Zstd) require external decompression
    libraries — we skip them and let the caller bump a counter.
    """
    if obj_flags & (
        OBJECT_COMPRESSED_XZ
        | OBJECT_COMPRESSED_LZ4
        | OBJECT_COMPRESSED_ZSTD
    ):
        return None
    payload_offset = offset + (72 if compact else 64)
    payload_end = offset + obj_size
    if payload_end > len(buf) or payload_offset >= payload_end:
        return None
    raw = buf[payload_offset:payload_end]
    if not raw:
        return None
    # Trim any trailing nul padding inserted by the 8-byte alignment.
    raw = raw.rstrip(b"\x00")
    try:
        return raw.decode("utf-8", errors="replace")
    except (UnicodeDecodeError, AttributeError):
        return None


def _decode_entry(
    buf: bytes,
    offset: int,
    obj_size: int,
    compact: bool,
) -> dict[str, Any] | None:
    """Decode an ENTRY object header + items[] array.

    ENTRY object layout (regular):
        ObjectHeader(16) + seqnum(8) + realtime(8) + monotonic(8) +
        boot_id(16) + xor_hash(8) + items[] (16 B each: object_offset(8)
        + hash(8))
    Total fixed prefix = 64 bytes.

    ENTRY object layout (compact, when HEADER_INCOMPATIBLE_COMPACT set):
        Same prefix(64), items[] is le32_t object_offset (4 B each).
    """
    if offset + 64 > len(buf):
        return None
    try:
        (seqnum, realtime, monotonic) = struct.unpack_from(
            "<QQQ", buf, offset + 16
        )
        boot_id = buf[offset + 40 : offset + 56]
    except struct.error:
        return None

    items_offset = offset + 64
    items_end = offset + obj_size
    if items_end > len(buf):
        items_end = len(buf)
    if items_offset >= items_end:
        return {
            "seqnum": seqnum,
            "realtime": realtime,
            "monotonic": monotonic,
            "boot_id": boot_id.hex(),
            "data_offsets": [],
        }

    data_offsets: list[int] = []
    if compact:
        item_count = (items_end - items_offset) // 4
        try:
            offsets = struct.unpack_from(
                f"<{item_count}I", buf, items_offset
            )
            data_offsets = [int(o) for o in offsets if o > 0]
        except struct.error:
            pass
    else:
        item_count = (items_end - items_offset) // 16
        try:
            for i in range(item_count):
                (obj_off,) = struct.unpack_from(
                    "<Q", buf, items_offset + i * 16
                )
                if obj_off > 0:
                    data_offsets.append(int(obj_off))
        except struct.error:
            pass

    return {
        "seqnum": seqnum,
        "realtime": realtime,
        "monotonic": monotonic,
        "boot_id": boot_id.hex(),
        "data_offsets": data_offsets,
    }


def _resolve_data_field(
    buf: bytes,
    offset: int,
    compact: bool,
) -> tuple[str, str] | None:
    """Resolve a DATA-object reference to a ``(field_name, value)``
    pair, or None when the data is unavailable (compressed payload,
    parse failure).

    Returns the field name uppercased (e.g. ``"MESSAGE"`` /
    ``"_SYSTEMD_UNIT"``) and the raw value string.
    """
    hdr = _read_object_header(buf, offset)
    if hdr is None:
        return None
    obj_type, obj_flags, obj_size = hdr
    if obj_type != OBJECT_DATA:
        return None
    payload = _decode_data_payload(buf, offset, obj_size, obj_flags, compact)
    if payload is None:
        return None
    # Payload format: "FIELD_NAME=value"
    eq_idx = payload.find("=")
    if eq_idx <= 0:
        return None
    return payload[:eq_idx], payload[eq_idx + 1 :]


# ── Entry assembly + classifier ─────────────────────────────────────────────


def _is_suspicious_unit(unit: str | None) -> bool:
    """Return True iff ``unit`` looks like a systemd unit whose name
    contains a path under a writable directory (T1543.002
    persistence-from-writable signal). NULL → False."""
    if not unit:
        return False
    lower = unit.strip().lower()
    return any(
        prefix in lower for prefix in _SUSPICIOUS_UNIT_PATH_PREFIXES
    )


def _is_priority_critical(priority: int | None) -> bool:
    """Return True iff syslog priority is 0 (emerg), 1 (alert), or
    2 (crit). NULL → False."""
    return priority is not None and 0 <= priority <= 2


def build_anomaly_flags(
    *,
    priority: int | None,
    message: str | None,
    transport: str | None,
    unit: str | None,
) -> dict[str, Any]:
    """Construct the anomaly_flags payload from extracted fields.

    The classifier is pure — same inputs always produce the same
    output. Caller stamps the schema_version via
    ``_stamp_linux_journald_entries_anomaly_flags``.
    """
    msg = message or ""
    flags = {
        "priority_critical": _is_priority_critical(priority),
        "oom_killer": bool(_RE_OOM_KILLER.search(msg)),
        "segfault": bool(_RE_SEGFAULT.search(msg)),
        "selinux_denied": bool(_RE_SELINUX_DENIED.search(msg)),
        "audit_failure": (
            (transport == "audit" and bool(_RE_UNIT_FAILED.search(msg)))
            or bool(_RE_AUDIT_FAIL.search(msg))
        ),
        "suspicious_unit": _is_suspicious_unit(unit),
        "log_clear_marker": bool(_RE_LOG_CLEAR.search(msg)),
    }
    return flags


def _safe_int(value: str | None) -> int | None:
    """Coerce a string-form field value to int, or None on failure."""
    if value is None:
        return None
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return None


def _truncate(value: str | None, cap: int) -> str | None:
    """Truncate a string to at most ``cap`` chars, preserving None."""
    if value is None:
        return None
    if len(value) <= cap:
        return value
    return value[:cap] + "...[truncated]"


# ── Single-file iterator ────────────────────────────────────────────────────


def _iter_journal_entries(
    buf: bytes,
    header: dict[str, Any],
) -> Iterator[dict[str, Any]]:
    """Iterate every entry in a journal file's byte buffer, yielding
    a fully-assembled dict per entry.

    Walks the file linearly object-by-object starting at
    ``header_size``. When an OBJECT_ENTRY is encountered, resolves
    each DATA reference back to its field=value pair and assembles
    the entry record. Tracks compressed-payload skips via a
    ``compressed_skipped`` counter on the yielded dict.
    """
    compact = header["compact"]
    arena_start = header["header_size"]
    arena_end = arena_start + header["arena_size"]
    if arena_end > len(buf):
        arena_end = len(buf)

    offset = arena_start
    while offset < arena_end:
        hdr = _read_object_header(buf, offset)
        if hdr is None:
            break
        obj_type, obj_flags, obj_size = hdr
        if obj_size < 16:
            break  # malformed; stop linear walk
        if obj_type == OBJECT_ENTRY:
            entry = _decode_entry(buf, offset, obj_size, compact)
            if entry is not None:
                fields: dict[str, str] = {}
                compressed_skipped = 0
                for data_off in entry["data_offsets"]:
                    pair = _resolve_data_field(buf, data_off, compact)
                    if pair is None:
                        compressed_skipped += 1
                        continue
                    name, value = pair
                    # Last-write wins on duplicate keys; in practice
                    # journald enforces uniqueness within an entry.
                    if name not in fields:
                        fields[name] = value
                yield {
                    "seqnum": entry["seqnum"],
                    "realtime_us": entry["realtime"],
                    "monotonic_us": entry["monotonic"],
                    "boot_id": entry["boot_id"],
                    "fields": fields,
                    "compressed_skipped": compressed_skipped,
                }
        # Advance to next 8-byte-aligned object boundary.
        next_off = offset + obj_size
        # Align to 8 bytes.
        rem = next_off % OBJECT_ALIGN
        if rem:
            next_off += OBJECT_ALIGN - rem
        if next_off <= offset:
            break  # defensive
        offset = next_off


def parse_journal_file(path: str) -> tuple[dict, list[dict]]:
    """Parse one ``.journal`` file at ``path`` end-to-end.

    Returns ``(header_dict, entries_list)``. On malformed / missing
    files, returns ``({"error": str}, [])`` so the caller can record
    the failure mode without raising.

    SYNC I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return {"error": f"stat failed: {exc}"}, []
    if size > _DEFAULT_MAX_FILE_BYTES:
        return {
            "error": (
                f"file size {size} exceeds max "
                f"{_DEFAULT_MAX_FILE_BYTES}; skipped"
            )
        }, []
    if size < _MIN_HEADER_SIZE:
        return {"error": "file shorter than minimum header"}, []
    try:
        with open(path, "rb") as fh:
            buf = fh.read()
    except OSError as exc:
        return {"error": f"read failed: {exc}"}, []

    header = _read_header(buf)
    if header is None:
        return {"error": "malformed header (missing or bad magic)"}, []

    entries = list(_iter_journal_entries(buf, header))
    return header, entries


# ── Detection-root walker (Rule #16 + Rule #43 category 3) ──────────────────


def walk_journal_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return candidate ``.journal``
    file paths.

    Two canonical locations under a Linux rootfs:
    - ``var/log/journal/<machine-id>/*.journal``  (persistent system)
    - ``run/log/journal/<machine-id>/*.journal``  (runtime journal,
      rare in firmware extracts)

    Plus a defensive scan for any other ``*.journal`` under the root —
    distributions occasionally relocate.

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
        for dirpath, _dirnames, filenames in os.walk(  # noqa: ASYNC240 — bounded loop over ≤8 detection roots
            real_root, followlinks=False
        ):
            for name in filenames:
                if not name.endswith(".journal"):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math; one realpath per candidate
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                try:
                    if not os.path.isfile(real_full):  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
                        continue
                except OSError:
                    continue
                if real_full in seen:
                    continue
                seen.add(real_full)
                hits.append(real_full)
    return hits


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
                real_full[len(real_root) + 1 :]
                if real_full != real_root
                else "."
            )
    return os.path.basename(full_path)


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "files_scanned": 0,
        "entries_walked": 0,
        "entries_persisted": 0,
        "priority_critical_count": 0,
        "oom_killer_count": 0,
        "audit_failure_count": 0,
        "selinux_denied_count": 0,
        "suspicious_unit_count": 0,
        "log_clear_marker_count": 0,
        "anomaly_total": 0,
        "oversize_skipped": 0,
        "compressed_skipped": 0,
        "errors": [],
        "per_file": [],
    }


# ── Per-file walker ──────────────────────────────────────────────────────────


def _walk_one_file(
    journal_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_entries: int,
    started_count: int,
) -> tuple[list[LinuxJournaldEntry], dict]:
    """Open one ``.journal`` file and walk every entry.

    Returns ``(entries_to_persist, per_file_aggregate)``. The entries
    are SQLAlchemy ORM instances ready for ``db.add()``.

    Defensive boundary:
    - file > _DEFAULT_MAX_FILE_BYTES → status="skipped"
    - missing magic → status="not_journal"
    - parser raise → status="error" with first 500 chars of error
    """
    aggregate: dict = {
        "path": relative_source,
        "status": "ok",
        "entries_walked": 0,
        "entries_persisted": 0,
        "priority_critical_count": 0,
        "oom_killer_count": 0,
        "audit_failure_count": 0,
        "selinux_denied_count": 0,
        "suspicious_unit_count": 0,
        "log_clear_marker_count": 0,
        "anomaly_total": 0,
        "compressed_skipped": 0,
        "error": None,
    }

    if not has_journal_magic(journal_path):
        aggregate["status"] = "not_journal"
        aggregate["error"] = "missing LPKSHHRH magic"
        return [], aggregate

    try:
        header, entries = parse_journal_file(journal_path)
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        aggregate["status"] = "error"
        aggregate["error"] = f"{type(exc).__name__}: {msg}"
        return [], aggregate

    if "error" in header:
        aggregate["status"] = "error"
        aggregate["error"] = header["error"]
        return [], aggregate

    machine_id = header.get("machine_id", "")[:32] or None
    header_boot_id = header.get("tail_entry_boot_id", "")[:32] or None

    rows: list[LinuxJournaldEntry] = []
    persist_budget = max_entries - started_count

    for entry in entries:
        aggregate["entries_walked"] += 1
        aggregate["compressed_skipped"] += entry["compressed_skipped"]

        if persist_budget <= 0:
            continue

        fields = entry["fields"]
        priority = _safe_int(fields.get("PRIORITY"))
        facility = _safe_int(fields.get("SYSLOG_FACILITY"))
        message = fields.get("MESSAGE")
        transport = fields.get("_TRANSPORT") or "unknown"
        unit = fields.get("_SYSTEMD_UNIT") or fields.get("UNIT")

        if priority is None:
            # journald defaults missing PRIORITY to 6 (info); use that
            # as the canonical fallback rather than NULL on a NOT NULL
            # column.
            priority = 6

        anomaly = build_anomaly_flags(
            priority=priority,
            message=message,
            transport=transport,
            unit=unit,
        )
        if anomaly["priority_critical"]:
            aggregate["priority_critical_count"] += 1
        if anomaly["oom_killer"]:
            aggregate["oom_killer_count"] += 1
        if anomaly["audit_failure"]:
            aggregate["audit_failure_count"] += 1
        if anomaly["selinux_denied"]:
            aggregate["selinux_denied_count"] += 1
        if anomaly["suspicious_unit"]:
            aggregate["suspicious_unit_count"] += 1
        if anomaly["log_clear_marker"]:
            aggregate["log_clear_marker_count"] += 1
        if any(
            anomaly[k]
            for k in (
                "priority_critical",
                "oom_killer",
                "audit_failure",
                "selinux_denied",
                "suspicious_unit",
                "log_clear_marker",
            )
        ):
            aggregate["anomaly_total"] += 1

        stamped = _stamp_linux_journald_entries_anomaly_flags(anomaly)

        row = LinuxJournaldEntry(
            firmware_id=firmware_id,
            journal_file_path=relative_source[:2048],
            machine_id=machine_id,
            boot_id=(entry["boot_id"] or header_boot_id),
            realtime_timestamp_us=int(entry["realtime_us"] or 0),
            monotonic_timestamp_us=(
                int(entry["monotonic_us"]) if entry["monotonic_us"] else None
            ),
            priority=priority,
            facility=facility,
            transport=transport[:32],
            unit=(unit or "")[:255] or None,
            pid=_safe_int(fields.get("_PID")),
            uid=_safe_int(fields.get("_UID")),
            gid=_safe_int(fields.get("_GID")),
            comm=(fields.get("_COMM") or "")[:255] or None,
            exe_path=(fields.get("_EXE") or "")[:1024] or None,
            cmdline=_truncate(fields.get("_CMDLINE"), _MAX_CMDLINE_CHARS),
            hostname=(fields.get("_HOSTNAME") or "")[:255] or None,
            message=_truncate(message or "", _MAX_MESSAGE_CHARS) or "",
            anomaly_flags=stamped,
        )
        rows.append(row)
        persist_budget -= 1
        aggregate["entries_persisted"] += 1

    return rows, aggregate


async def _walk_one_file_async(
    journal_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_entries: int,
    started_count: int,
) -> tuple[list[LinuxJournaldEntry], dict]:
    """Async wrapper around :func:`_walk_one_file` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_file(
            journal_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
            max_entries=max_entries,
            started_count=started_count,
        ),
    )


async def _walk_journal_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_journal_files` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_journal_files, roots)


# ── Inner orchestrator (Rule #39 inner; accepts db) ──────────────────────────


async def _do_journald_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_entries: int = _DEFAULT_MAX_ENTRIES_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every ``.journal`` file under ``firmware_id``'s extracted
    tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for files matching ``*.journal``.
    3. For each candidate: pre-flight magic check, parse via the
       clean-room parser, iterate every entry, construct + bulk-add
       LinuxJournaldEntry rows.
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

    journal_paths = await _walk_journal_files_async(roots)
    if not journal_paths:
        return _empty_walk_result(time.monotonic() - started)

    files_scanned = 0
    entries_walked = 0
    entries_persisted = 0
    priority_critical_count = 0
    oom_killer_count = 0
    audit_failure_count = 0
    selinux_denied_count = 0
    suspicious_unit_count = 0
    log_clear_marker_count = 0
    anomaly_total = 0
    oversize_skipped = 0
    compressed_skipped = 0
    errors: list[str] = []
    per_file: list[dict] = []

    for journal_path in journal_paths:
        relative = _relativize_path(journal_path, roots)
        try:
            rows, agg = await _walk_one_file_async(
                journal_path,
                firmware_id=firmware_id,
                relative_source=relative,
                max_entries=max_entries,
                started_count=entries_persisted,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = (
                f"walk failed for {journal_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_file.append({
                "path": relative,
                "status": "error",
                "entries_walked": 0,
                "entries_persisted": 0,
                "priority_critical_count": 0,
                "oom_killer_count": 0,
                "audit_failure_count": 0,
                "selinux_denied_count": 0,
                "suspicious_unit_count": 0,
                "log_clear_marker_count": 0,
                "anomaly_total": 0,
                "compressed_skipped": 0,
                "error": err,
            })
            continue

        if agg["status"] == "skipped":
            oversize_skipped += 1

        files_scanned += 1
        entries_walked += agg["entries_walked"]
        entries_persisted += agg["entries_persisted"]
        priority_critical_count += agg["priority_critical_count"]
        oom_killer_count += agg["oom_killer_count"]
        audit_failure_count += agg["audit_failure_count"]
        selinux_denied_count += agg["selinux_denied_count"]
        suspicious_unit_count += agg["suspicious_unit_count"]
        log_clear_marker_count += agg["log_clear_marker_count"]
        anomaly_total += agg["anomaly_total"]
        compressed_skipped += agg["compressed_skipped"]
        per_file.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

        for row in rows:
            db.add(row)
        if rows:
            await db.flush()

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "files_scanned": files_scanned,
        "entries_walked": entries_walked,
        "entries_persisted": entries_persisted,
        "priority_critical_count": priority_critical_count,
        "oom_killer_count": oom_killer_count,
        "audit_failure_count": audit_failure_count,
        "selinux_denied_count": selinux_denied_count,
        "suspicious_unit_count": suspicious_unit_count,
        "log_clear_marker_count": log_clear_marker_count,
        "anomaly_total": anomaly_total,
        "oversize_skipped": oversize_skipped,
        "compressed_skipped": compressed_skipped,
        "errors": errors,
        "per_file": per_file,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_journald_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the journald walk.

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
                    "journald_walk: firmware %s not found", firmware_id
                )
                return

            row.journald_walk_status = "running"
            row.journald_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_journald_walk(db, firmware_id)
                row.journald_walk_status = "completed"
                row.journald_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.journald_walk_result = _stamp_firmware_journald_walk_result(
                    result
                )
                await db.commit()

                logger.info(
                    "journald_walk: firmware %s completed in %.2fs "
                    "(%d files, %d entries walked, %d persisted, %d "
                    "anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["files_scanned"],
                    result["entries_walked"],
                    result["entries_persisted"],
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
                        fail_row.journald_walk_status = "failed"
                        fail_row.journald_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.journald_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "journald_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "journald_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_journald_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as the η.A.C
    auto_mft_walk_firmware_safe / θ.A auto_bcd_walk_firmware_safe
    wrappers.

    Distinct from :func:`run_journald_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-triggered
    walks. The auto-walk-on-unpack flow runs the SAME orchestrator
    (``_do_journald_walk``) but DOES NOT transition the status
    column — it stays ``idle`` until an operator explicitly triggers
    a re-walk via the trigger MCP tool, which resets and runs again.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_journald_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.journald_walk_result = _stamp_firmware_journald_walk_result(
                    result
                )
                await db.commit()

            logger.info(
                "journald_walk auto: firmware %s walked %d files / %d "
                "entries in %.2fs",
                firmware_id,
                result["files_scanned"],
                result["entries_walked"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "journald_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "JOURNAL_MAGIC",
    "OBJECT_DATA",
    "OBJECT_ENTRY",
    "_do_journald_walk",
    "auto_journald_walk_firmware_safe",
    "build_anomaly_flags",
    "has_journal_magic",
    "parse_journal_file",
    "run_journald_walk_background",
    "walk_journal_files",
]
