"""Phase θ.A — Windows Boot Configuration Data (BCD) walker.

Reads BCD store files (typically named ``BCD`` without extension,
under ``Boot/`` or ``EFI/Microsoft/Boot/`` partition prefixes of
firmware extracts) and walks every ``\\Objects\\{guid}`` subkey via
regipy's ``RegistryHive`` (BCD is REGF format; regipy recognises
``BCD_HIVE_TYPE = 'bcd'``). Each parsed boot entry becomes one
``WindowsBcdEntry`` row for downstream finding-emit hooks (θ.A.D).

**Rule #39 inner/outer/safe runner triplet** (γ.4 + δ.5 + ε.1.b.3 +
ζ.2.B + ζ.3.B + η.B.C + η.C.C + η.A.C + θ.A.C = Rule-of-Nine):

- :func:`_do_bcd_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every BCD store candidate under detection roots,
  opens each via ``RegistryHive(path, hive_type=BCD_HIVE_TYPE)``,
  iterates ``\\Objects\\{guid}`` subkeys, persists per-entry
  ``WindowsBcdEntry`` rows, returns aggregate dict UNSTAMPED.
- :func:`run_bcd_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer
  guard catches escapes; failure persistence on a fresh session.
- :func:`auto_bcd_walk_firmware_safe` — UNPACK-POST-DETECTION hook.
  Runs the inner orchestrator + emit hook but does NOT mutate
  ``bcd_walk_status`` (leaves ``idle`` so manual re-trigger works
  without 409).

**Rule #36 no-execute discipline.** regipy is a pure-Python parser
that decodes REGF structures (header, hbins, NK cells, VK cells,
LH/LF subkey lists) AS DATA. The walker NEVER:

- Invokes ``bcdedit`` / ``reg.exe`` / ``bootmgr`` / ``winload.efi``
  against the parsed BCD store.
- Loads the bootloader binary referenced by the ``image_path``
  element — that path is surfaced as DATA for operator review only.
- Mounts the partition described by the ApplicationDevice element.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare
``firmware.extracted_path``) so scatter-zip / multi-archive Windows
extracts surface every BCD store candidate.

**Rule #19 evidence-first probe.** :func:`is_regipy_available`
exposes a graceful-degrade probe so consumers can surface a clear
"library not installed" message rather than an opaque ImportError.
The library is in pyproject.toml; the probe protects against
container-level dep skew. Mirrors the LnkParse3 / python-evtx /
windowsprefetch probes used by ε.1.b / ζ.2.B / η.B.C / η.C.C.

**Performance**. regipy is pure-Python and cold-imports in ~50 ms
on the dev box. A typical BCD store carries 10-30 boot entries —
iteration runs sub-second per store. Total wall-time per firmware
is dominated by the file-search step (walking detection roots for
BCD candidates), not by parsing. We cap at 500 persisted entries
per firmware (``_DEFAULT_MAX_ENTRIES_PER_FIRMWARE``) defensive
against attacker-planted BCD with thousands of bogus entries.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable, Iterator
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_bcd_entry import WindowsBcdEntry
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_bcd_walk_result,
    _stamp_windows_bcd_entries_anomaly_flags,
    _stamp_windows_bcd_entries_custom_elements,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum BCD entries persisted per firmware. A typical BCD store has
# ~10-30 entries; an attacker-planted store with hundreds of bogus
# boot entries is suspicious but the row count should be bounded
# defensively. 500 covers any plausible real-world case.
_DEFAULT_MAX_ENTRIES_PER_FIRMWARE: int = 500

# Cap on raw BCD store size to attempt. BCD stores are typically
# 24-100 KB; legitimately rare cases reach a few MB. Protect against
# attacker-planted gigabyte BCD with bogus padding.
_DEFAULT_MAX_STORE_BYTES: int = 64 * 1024 * 1024  # 64 MiB

# Cap on custom element roster size persisted per entry. A typical
# boot entry has 5-15 elements (description, path, device, recovery
# settings, debug settings, integrity). 100 covers any plausible
# real-world case and bounds the JSONB column size.
_DEFAULT_MAX_CUSTOM_ELEMENTS_PER_ENTRY: int = 100


# ── BCD element type constants (per Microsoft / Geoff Chappell) ──────────────
#
# Reference: https://www.geoffchappell.com/notes/windows/boot/bcd/elements.htm
#
# Elements not promoted to a flat column persist in the custom_elements
# JSONB. The element type is a 32-bit value combining class + format +
# subtype; we render as hex strings for stable identification.

ELEM_APPLICATION_DEVICE = 0x11000001  # ApplicationDevice (raw bytes)
ELEM_APPLICATION_PATH = 0x12000002    # ApplicationPath (UTF-16 string)
ELEM_DESCRIPTION = 0x12000004         # ApplicationDescription (UTF-16)
ELEM_TESTSIGNING = 0x16000010         # TestSigning (boolean)
ELEM_NO_INTEGRITY_CHECKS = 0x16000048  # NoIntegrityChecks (boolean)
ELEM_NX_POLICY = 0x25000020           # NxPolicy (DWORD)
ELEM_DISPLAY_ORDER = 0x14000006       # DisplayOrder (list of GUIDs)
ELEM_DEFAULT_OBJECT = 0x23000003      # DefaultObject (GUID)

# Element types that get flat-column promotion. All others land in
# custom_elements JSONB.
_FLAT_ELEMENT_TYPES = frozenset({
    ELEM_APPLICATION_DEVICE,
    ELEM_APPLICATION_PATH,
    ELEM_DESCRIPTION,
    ELEM_TESTSIGNING,
    ELEM_NO_INTEGRITY_CHECKS,
    ELEM_NX_POLICY,
})


# ── Path heuristics for anomaly classification ──────────────────────────────

# Microsoft-vetted bootloader path prefixes. An image_path NOT under
# any of these AND a non-Microsoft description is the θ.A.D
# "suspicious_path" anomaly signal.
_KNOWN_GOOD_BOOTLOADER_PREFIXES = (
    "\\windows\\",
    "\\boot\\",
    "\\efi\\microsoft\\",
    "\\efi\\boot\\",
    "\\bootmgr",
    "\\bootmgfw.efi",
)

# Description prefixes that indicate a Microsoft-signed boot entry.
# Used by the non_microsoft_description heuristic.
_MICROSOFT_DESCRIPTION_PREFIXES = (
    "windows ",
    "microsoft windows ",
    "memory diagnostic",
    "memory test",
    "hypervisor",
    "boot manager",
    "windows boot manager",
    "windows recovery environment",
    "windows resume",
    "windows setup",
)


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_regipy_available() -> bool:
    """Return True iff ``regipy`` is importable in this process.

    Mirrors the dissect.ntfs / LnkParse3 / python-evtx /
    windowsprefetch graceful-degrade probes used by γ.4 / ε.1.b /
    ζ.2.B / η.B.C / η.C.C / η.A.C. Probe runs in <1 ms after first
    call (Python's import cache).
    """
    try:
        import regipy  # noqa: F401 — import-only probe
        import regipy.registry  # noqa: F401
    except ImportError:
        return False
    return True


REGIPY_UNAVAILABLE: dict[str, Any] = {
    "status": "unavailable",
    "reason": "regipy not installed — see backend/pyproject.toml",
    "entries": 0,
}


# ── BCD store candidate enumeration ──────────────────────────────────────────


def walk_bcd_stores(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return candidate BCD store paths.

    BCD stores are typically files named ``BCD`` (no extension) under
    Windows-format partition prefixes. We accept:

    - Any file named exactly ``BCD`` (case-insensitive — Windows is
      case-insensitive, and FAT32/EFI ESP partitions on extracted
      images may surface as either case).
    - Any file named ``bcd`` / ``BCD.LOG`` siblings IGNORED — the
      .LOG files are write-ahead logs not parseable independently;
      they accompany the primary BCD but the parser opens BCD.

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Defensive against missing roots, permission errors — every error
    path is swallowed at the per-root / per-file level so one
    corrupted detection root doesn't abort the entire walk.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots` — NEVER ``firmware.extracted_path``
    alone.
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
        except OSError:
            continue
        if not os.path.isdir(real_root):  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            continue
        for dirpath, _dirnames, filenames in os.walk(  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            root, followlinks=False
        ):
            for name in filenames:
                # BCD store filename match — case-insensitive equality.
                if name.upper() != "BCD":
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
                hits.append(real_full)
    return hits


def looks_like_regf(path: str) -> bool:
    """Return True iff the file at ``path`` has the REGF magic
    signature (``regf`` at byte offset 0 of the file).

    BCD stores share the REGF format with standard registry hives;
    regipy's hive_type='bcd' parameter tells the parser to interpret
    the keys under the BCD-specific schema. Magic check is the same
    as standard hives.

    Defensive against unreadable files (OSError) → False.
    Cheap — reads only the first 4 bytes.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head == b"regf"


# ── Element extraction helpers ───────────────────────────────────────────────


def _safe_element_value(obj_key: Any, element_type: int) -> Any:
    """Pull a BCD element by its 32-bit type. Returns None on any
    access failure (Elements subkey missing, element-type subkey
    missing, value missing, parser raise).

    BCD object element values live under
    ``Objects/{guid}/Elements/{hex-type}/Element``. The hex-type
    subkey name is the 8-character uppercase hex rendering of the
    32-bit element type.
    """
    try:
        elements_key = obj_key.get_subkey(
            "Elements", raise_on_missing=False
        )
    except Exception:  # noqa: BLE001 — defensive boundary
        return None
    if elements_key is None:
        return None
    try:
        if elements_key.subkey_count == 0:
            return None
    except Exception:  # noqa: BLE001 — defensive boundary
        return None
    try:
        elem_key = elements_key.get_subkey(
            f"{element_type:08X}", raise_on_missing=False
        )
    except Exception:  # noqa: BLE001 — defensive boundary
        return None
    if elem_key is None:
        return None
    try:
        return elem_key.get_value("Element")
    except Exception:  # noqa: BLE001 — defensive boundary
        return None


def _safe_description_type(obj_key: Any) -> int | None:
    """Pull the Description/Type 32-bit value for a BCD object.

    The Description subkey carries a ``Type`` value (REG_DWORD) that
    discriminates object class (boot mgr / boot loader / boot
    settings / etc.). Returns None on any access failure.
    """
    try:
        desc_key = obj_key.get_subkey(
            "Description", raise_on_missing=False
        )
    except Exception:  # noqa: BLE001 — defensive boundary
        return None
    if desc_key is None:
        return None
    try:
        v = desc_key.get_value("Type")
    except Exception:  # noqa: BLE001 — defensive boundary
        return None
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _parse_application_device_blob(blob: Any) -> tuple[str | None, str | None]:
    """Decode the ApplicationDevice raw blob into (partition_guid,
    disk_guid).

    Per the regipy boot_entry_list plugin: bytes [32:48] = GPT
    partition GUID (UUID bytes_le encoding); bytes [56:72] = GPT
    disk GUID. Defensive — returns (None, None) on any parse failure
    or short blob (< 72 bytes).
    """
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 72:
        return None, None
    try:
        partition_guid = "{" + str(uuid.UUID(bytes_le=bytes(blob[32:48]))) + "}"
        disk_guid = "{" + str(uuid.UUID(bytes_le=bytes(blob[56:72]))) + "}"
    except (ValueError, TypeError):
        return None, None
    return partition_guid, disk_guid


def _coerce_str(value: Any) -> str | None:
    """Coerce a regipy value to str, truncating None / non-str safely."""
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode("utf-16-le", errors="ignore").rstrip("\x00")
        except Exception:  # noqa: BLE001 — defensive boundary
            return None
    if isinstance(value, str):
        return value.rstrip("\x00")
    try:
        return str(value)
    except Exception:  # noqa: BLE001 — defensive boundary
        return None


def _coerce_bool(value: Any) -> bool | None:
    """Coerce a regipy element value to bool. BCD boolean elements
    (TestSigning, NoIntegrityChecks) are typically encoded as a single
    byte: \\x01 for True, \\x00 for False. regipy may return the byte
    string OR an integer; defensive boundary handles both."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 0:
            return False
        return value[0] != 0
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes"):
            return True
        if v in ("0", "false", "no", ""):
            return False
    return None


def _coerce_int(value: Any) -> int | None:
    """Coerce a regipy element value to int. BCD DWORD elements (e.g.
    NxPolicy 0x25000020) are typically returned as either an int or a
    little-endian byte string."""
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 0:
            return None
        try:
            return int.from_bytes(value, "little", signed=False)
        except Exception:  # noqa: BLE001 — defensive boundary
            return None
    if isinstance(value, str):
        try:
            return int(value, 0)
        except (TypeError, ValueError):
            return None
    return None


def _coerce_custom_element_value(value: Any) -> Any:
    """Coerce an arbitrary regipy element value to a JSON-friendly
    form for the custom_elements JSONB column. Handles bytes (hex
    rendering), lists (decoded), strings (rstrip), ints (pass-through).
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value.rstrip("\x00")
    if isinstance(value, (bytes, bytearray)):
        # First try UTF-16 LE decode (common for BCD string elements
        # that aren't flat-column-promoted).
        try:
            s = value.decode("utf-16-le", errors="ignore").rstrip("\x00")
            if s and all(c.isprintable() or c.isspace() for c in s):
                return s
        except Exception:  # noqa: BLE001 — defensive boundary
            pass
        # Fallback: hex render, truncated to 1024 hex chars to bound
        # JSONB size.
        try:
            return bytes(value)[:512].hex()
        except Exception:  # noqa: BLE001 — defensive boundary
            return None
    if isinstance(value, list):
        out: list[Any] = []
        for item in value:
            try:
                out.append(_coerce_custom_element_value(item))
            except Exception:  # noqa: BLE001 — defensive boundary
                continue
        return out
    try:
        return str(value)[:512]
    except Exception:  # noqa: BLE001 — defensive boundary
        return None


# ── Anomaly classification helpers ───────────────────────────────────────────


def is_microsoft_description(description: str | None) -> bool:
    """Return True iff ``description`` matches a Microsoft-known
    boot entry description prefix (case-insensitive). NULL → False
    (no description = can't claim Microsoft origin)."""
    if not description:
        return False
    lower = description.strip().lower()
    return any(
        lower.startswith(prefix)
        for prefix in _MICROSOFT_DESCRIPTION_PREFIXES
    )


def is_suspicious_bootloader_path(image_path: str | None) -> bool:
    """Return True iff ``image_path`` does NOT lie under any
    Microsoft-vetted bootloader prefix. NULL → False (no path = can't
    claim suspicion; some entries legitimately have no
    ApplicationPath, e.g. ``{globalsettings}`` aggregator)."""
    if not image_path:
        return False
    lower = image_path.strip().lower()
    # Normalize forward / back slashes.
    lower = lower.replace("/", "\\")
    # If it lies under any known-good prefix, NOT suspicious.
    return not any(
        lower.startswith(prefix)
        for prefix in _KNOWN_GOOD_BOOTLOADER_PREFIXES
    )


def build_anomaly_flags(
    *,
    description: str | None,
    image_path: str | None,
    testsigning: bool | None,
    no_integrity_checks: bool | None,
    nx_policy: int | None,
    is_default_boot: bool,
) -> dict:
    """Construct the anomaly_flags payload from extracted fields.

    The classifier is pure — same inputs always produce the same
    output. Caller stamps the schema_version via
    ``_stamp_windows_bcd_entries_anomaly_flags``.
    """
    return {
        "suspicious_path": is_suspicious_bootloader_path(image_path),
        "non_microsoft_description": (
            description is not None
            and not is_microsoft_description(description)
        ),
        "testsigning_enabled": bool(testsigning),
        "no_integrity_checks": bool(no_integrity_checks),
        # NX policy value 2 = AlwaysOff (DEP disabled).
        "nx_disabled": (nx_policy == 2),
        "is_default_boot": is_default_boot,
    }


# ── Per-entry extraction ─────────────────────────────────────────────────────


def _extract_entry_fields(obj_key: Any) -> dict[str, Any]:
    """Pull every promoted field from a single ``Objects/{guid}``
    NKRecord. Returns a dict ready for the WindowsBcdEntry
    constructor (caller adds firmware_id + source_path + anomaly
    flags + custom_elements stamping)."""
    # GUID is the NKRecord name.
    try:
        guid = obj_key.name
    except Exception:  # noqa: BLE001 — defensive boundary
        guid = None

    # Description/Type 32-bit discriminator.
    object_type = _safe_description_type(obj_key)

    # Description element 0x12000004.
    description = _coerce_str(
        _safe_element_value(obj_key, ELEM_DESCRIPTION)
    )

    # ApplicationPath element 0x12000002.
    image_path = _coerce_str(
        _safe_element_value(obj_key, ELEM_APPLICATION_PATH)
    )

    # ApplicationDevice element 0x11000001 — GPT partition + disk GUIDs.
    device_blob = _safe_element_value(obj_key, ELEM_APPLICATION_DEVICE)
    partition_guid, disk_guid = _parse_application_device_blob(device_blob)

    # TestSigning element 0x16000010.
    testsigning = _coerce_bool(
        _safe_element_value(obj_key, ELEM_TESTSIGNING)
    )

    # NoIntegrityChecks element 0x16000048.
    no_integrity_checks = _coerce_bool(
        _safe_element_value(obj_key, ELEM_NO_INTEGRITY_CHECKS)
    )

    # NxPolicy element 0x25000020.
    nx_policy = _coerce_int(
        _safe_element_value(obj_key, ELEM_NX_POLICY)
    )

    # Last-modified timestamp from the NKRecord header. Stored as a
    # string for stable serialization across regipy versions (the
    # raw FILETIME int is a Construct field).
    try:
        last_modified_ns = str(obj_key.header.last_modified)
    except Exception:  # noqa: BLE001 — defensive boundary
        last_modified_ns = None

    return {
        "object_guid": str(guid)[:64] if guid is not None else None,
        "object_type": object_type,
        "description": (description or "")[:512] or None,
        "image_path": (image_path or "")[:2048] or None,
        "gpt_partition_guid": (
            (partition_guid or "")[:64] or None
        ),
        "gpt_disk_guid": (disk_guid or "")[:64] or None,
        "testsigning": testsigning,
        "no_integrity_checks": no_integrity_checks,
        "nx_policy": nx_policy,
        "last_modified_ns": (
            (last_modified_ns or "")[:64] or None
        ),
    }


def _extract_custom_elements(
    obj_key: Any, *, max_elements: int
) -> list[dict]:
    """Iterate every ``Objects/{guid}/Elements/<type>`` subkey and
    capture every element whose type is NOT promoted to a flat column.

    Returns a list of dicts ready for the
    ``_stamp_windows_bcd_entries_custom_elements`` writer. Capped at
    ``max_elements`` entries (defensive against attacker-planted
    blobs).
    """
    try:
        elements_key = obj_key.get_subkey(
            "Elements", raise_on_missing=False
        )
    except Exception:  # noqa: BLE001 — defensive boundary
        return []
    if elements_key is None:
        return []
    try:
        if elements_key.subkey_count == 0:
            return []
    except Exception:  # noqa: BLE001 — defensive boundary
        return []

    captured: list[dict] = []
    try:
        sub_iter = elements_key.iter_subkeys()
        if sub_iter is None:
            return []
        for sub in sub_iter:
            if len(captured) >= max_elements:
                break
            try:
                name = sub.name
            except Exception:  # noqa: BLE001 — defensive boundary
                continue
            if not name:
                continue
            # Parse the hex element type from the subkey name.
            try:
                type_int = int(name, 16)
            except (TypeError, ValueError):
                # Non-hex element key; capture raw with element_type
                # as the literal name for forensic visibility.
                try:
                    value = sub.get_value("Element")
                except Exception:  # noqa: BLE001 — defensive boundary
                    value = None
                captured.append({
                    "element_type": str(name)[:32],
                    "element_value": _coerce_custom_element_value(value),
                })
                continue
            if type_int in _FLAT_ELEMENT_TYPES:
                # Already captured as flat column.
                continue
            try:
                value = sub.get_value("Element")
            except Exception:  # noqa: BLE001 — defensive boundary
                value = None
            captured.append({
                "element_type": f"0x{type_int:08X}",
                "element_value": _coerce_custom_element_value(value),
            })
    except Exception:  # noqa: BLE001 — defensive boundary
        # Element iteration failed mid-way — return what we got so
        # far rather than nothing.
        pass
    return captured


def _find_default_boot_guid(hive: Any) -> str | None:
    """Resolve the default boot entry GUID by reading
    ``\\Objects\\{9dea862c-...}\\Elements\\23000003\\Element``
    (BcdLibraryString_DefaultObject = 0x23000003) on the bootmgr
    object. Returns None on any access failure (no bootmgr entry,
    no default, parser raise)."""
    try:
        objects_key = hive.get_key(r"\Objects")
    except Exception:  # noqa: BLE001 — defensive boundary
        return None
    if objects_key is None:
        return None
    try:
        bootmgr = objects_key.get_subkey(
            "{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
            raise_on_missing=False,
        )
    except Exception:  # noqa: BLE001 — defensive boundary
        return None
    if bootmgr is None:
        return None
    default = _safe_element_value(bootmgr, ELEM_DEFAULT_OBJECT)
    default_str = _coerce_custom_element_value(default)
    if isinstance(default_str, str):
        return default_str
    return None


# ── Per-store walk ───────────────────────────────────────────────────────────


def _iter_object_subkeys_safe(objects_key: Any) -> Iterator[Any]:
    """Iterate ``\\Objects\\{guid}`` NKRecord subkeys swallowing
    per-record corruption."""
    try:
        sub_iter = objects_key.iter_subkeys()
    except Exception:  # noqa: BLE001 — defensive boundary
        return iter([])
    if sub_iter is None:
        return iter([])

    def _generator() -> Iterator[Any]:
        while True:
            try:
                record = next(sub_iter)
            except StopIteration:
                return
            except Exception:  # noqa: BLE001 — defensive boundary
                continue
            yield record

    return _generator()


def _walk_one_store(
    store_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_entries: int,
    started_count: int,
    max_store_bytes: int = _DEFAULT_MAX_STORE_BYTES,
) -> tuple[list[WindowsBcdEntry], dict]:
    """Open one BCD store and walk every ``\\Objects\\{guid}`` entry.

    Returns ``(entries_to_persist, per_store_aggregate)``. The entries
    are SQLAlchemy ORM instances ready for ``db.add()``; the aggregate
    summary tells the caller how many entries were walked + how many
    were filtered out for the persist cap + anomaly counters.

    Defensive boundary:
    - file size > max_store_bytes → status="skipped"
    - file doesn't pass the REGF magic check → status="not_regf"
    - parser raises → status="error" with first 500 chars of error
    """
    aggregate: dict = {
        "path": relative_source,
        "status": "ok",
        "entries_walked": 0,
        "entries_persisted": 0,
        "testsigning_count": 0,
        "suspicious_path_count": 0,
        "non_microsoft_description_count": 0,
        "anomaly_total": 0,
        "error": None,
    }

    try:
        size = os.path.getsize(store_path)  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
    except OSError as exc:
        aggregate["status"] = "error"
        aggregate["error"] = (
            f"stat failed: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return [], aggregate

    if size > max_store_bytes:
        aggregate["status"] = "skipped"
        aggregate["error"] = (
            f"BCD store size {size} exceeds max {max_store_bytes} "
            f"(attacker-DoS / runaway-walk protection); operator can "
            f"re-walk via MCP tool"
        )
        return [], aggregate

    if not looks_like_regf(store_path):
        aggregate["status"] = "not_regf"
        aggregate["error"] = "REGF magic signature not found"
        return [], aggregate

    try:
        from regipy.hive_types import BCD_HIVE_TYPE
        from regipy.registry import RegistryHive
    except ImportError:
        aggregate["status"] = "unavailable"
        aggregate["error"] = "regipy not importable"
        return [], aggregate

    entries: list[WindowsBcdEntry] = []
    persist_budget = max_entries - started_count

    try:
        hive = RegistryHive(store_path, hive_type=BCD_HIVE_TYPE)
        default_guid = _find_default_boot_guid(hive)

        try:
            objects_key = hive.get_key(r"\Objects")
        except Exception:  # noqa: BLE001 — defensive boundary
            aggregate["status"] = "error"
            aggregate["error"] = (
                "BCD store has no \\Objects key — not a valid BCD store"
            )
            return entries, aggregate
        if objects_key is None:
            aggregate["status"] = "error"
            aggregate["error"] = (
                "BCD store \\Objects key resolved to None"
            )
            return entries, aggregate

        for obj_key in _iter_object_subkeys_safe(objects_key):
            aggregate["entries_walked"] += 1

            if persist_budget <= 0:
                continue

            fields = _extract_entry_fields(obj_key)
            if not fields.get("object_guid"):
                continue

            is_default = (
                default_guid is not None
                and fields["object_guid"] == default_guid
            )

            anomaly = build_anomaly_flags(
                description=fields["description"],
                image_path=fields["image_path"],
                testsigning=fields["testsigning"],
                no_integrity_checks=fields["no_integrity_checks"],
                nx_policy=fields["nx_policy"],
                is_default_boot=is_default,
            )

            # Aggregate counters
            if anomaly["testsigning_enabled"]:
                aggregate["testsigning_count"] += 1
            if anomaly["suspicious_path"]:
                aggregate["suspicious_path_count"] += 1
            if anomaly["non_microsoft_description"]:
                aggregate["non_microsoft_description_count"] += 1
            if any(
                anomaly[k]
                for k in (
                    "suspicious_path",
                    "non_microsoft_description",
                    "testsigning_enabled",
                    "no_integrity_checks",
                    "nx_disabled",
                )
            ):
                aggregate["anomaly_total"] += 1

            custom_elements = _extract_custom_elements(
                obj_key,
                max_elements=_DEFAULT_MAX_CUSTOM_ELEMENTS_PER_ENTRY,
            )
            stamped_custom = (
                _stamp_windows_bcd_entries_custom_elements(custom_elements)
                if custom_elements
                else []
            )
            stamped_anomaly = _stamp_windows_bcd_entries_anomaly_flags(
                anomaly
            )

            row = WindowsBcdEntry(
                firmware_id=firmware_id,
                source_path=relative_source[:2048],
                object_guid=fields["object_guid"],
                object_type=fields["object_type"],
                description=fields["description"],
                image_path=fields["image_path"],
                gpt_partition_guid=fields["gpt_partition_guid"],
                gpt_disk_guid=fields["gpt_disk_guid"],
                testsigning=fields["testsigning"],
                no_integrity_checks=fields["no_integrity_checks"],
                nx_policy=fields["nx_policy"],
                custom_elements=stamped_custom,
                anomaly_flags=stamped_anomaly,
                last_modified_ns=fields["last_modified_ns"],
            )
            entries.append(row)
            persist_budget -= 1
            aggregate["entries_persisted"] += 1
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        aggregate["status"] = "error"
        aggregate["error"] = f"{type(exc).__name__}: {msg}"
        return entries, aggregate

    return entries, aggregate


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "stores_scanned": 0,
        "entries_walked": 0,
        "entries_persisted": 0,
        "testsigning_count": 0,
        "suspicious_path_count": 0,
        "non_microsoft_description_count": 0,
        "anomaly_total": 0,
        "errors": [],
        "per_store": [],
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
                real_full[len(real_root) + 1 :]
                if real_full != real_root
                else "."
            )
    return os.path.basename(full_path)


async def _walk_bcd_stores_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_bcd_stores` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_bcd_stores, roots)


async def _walk_one_store_async(
    store_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_entries: int,
    started_count: int,
) -> tuple[list[WindowsBcdEntry], dict]:
    """Async wrapper around :func:`_walk_one_store` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_store(
            store_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
            max_entries=max_entries,
            started_count=started_count,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ──────────────────────────


async def _do_bcd_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_entries: int = _DEFAULT_MAX_ENTRIES_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every BCD store candidate in ``firmware_id``'s extracted
    tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for files named ``BCD`` (case-insensitive).
    3. For each candidate: pre-flight REGF magic check, open via
       regipy ``RegistryHive`` (run_in_executor for Rule #5 sync I/O),
       iterate ``\\Objects\\{guid}`` subkeys, construct + bulk-add
       WindowsBcdEntry rows.
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

    store_paths = await _walk_bcd_stores_async(roots)
    if not store_paths:
        return _empty_walk_result(time.monotonic() - started)

    stores_scanned = 0
    entries_walked = 0
    entries_persisted = 0
    testsigning_count = 0
    suspicious_path_count = 0
    non_microsoft_description_count = 0
    anomaly_total = 0
    errors: list[str] = []
    per_store: list[dict] = []

    for store_path in store_paths:
        relative = _relativize_path(store_path, roots)
        try:
            entries, agg = await _walk_one_store_async(
                store_path,
                firmware_id=firmware_id,
                relative_source=relative,
                max_entries=max_entries,
                started_count=entries_persisted,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = (
                f"walk failed for {store_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_store.append({
                "path": relative,
                "status": "error",
                "entries_walked": 0,
                "entries_persisted": 0,
                "testsigning_count": 0,
                "suspicious_path_count": 0,
                "non_microsoft_description_count": 0,
                "anomaly_total": 0,
                "error": err,
            })
            continue

        stores_scanned += 1
        entries_walked += agg["entries_walked"]
        entries_persisted += agg["entries_persisted"]
        testsigning_count += agg["testsigning_count"]
        suspicious_path_count += agg["suspicious_path_count"]
        non_microsoft_description_count += agg[
            "non_microsoft_description_count"
        ]
        anomaly_total += agg["anomaly_total"]
        per_store.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

        for row in entries:
            db.add(row)
        if entries:
            await db.flush()

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "stores_scanned": stores_scanned,
        "entries_walked": entries_walked,
        "entries_persisted": entries_persisted,
        "testsigning_count": testsigning_count,
        "suspicious_path_count": suspicious_path_count,
        "non_microsoft_description_count": non_microsoft_description_count,
        "anomaly_total": anomaly_total,
        "errors": errors,
        "per_store": per_store,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_bcd_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the BCD walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back. Mirrors the
    η.A.C MFT walker / η.C.C LNK walker / η.B.C scheduled-task walker
    shape.

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
                    "bcd_walk: firmware %s not found", firmware_id
                )
                return

            row.bcd_walk_status = "running"
            row.bcd_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_bcd_walk(db, firmware_id)
                row.bcd_walk_status = "completed"
                row.bcd_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.bcd_walk_result = _stamp_firmware_bcd_walk_result(result)
                project_id = row.project_id
                await db.commit()

                # θ.A.E — emit windows_bcd_* Finding rows alongside
                # the status transition. Lazy import per Rule #30 to
                # avoid bcd_walker ↔ finding_service circular at
                # module load.
                if result["entries_persisted"] > 0:
                    try:
                        from app.services.finding_service import (
                            FindingService,
                        )

                        service = FindingService(db=db)
                        emitted = (
                            await service.emit_bcd_findings_from_walk(
                                project_id, firmware_id
                            )
                        )
                        await db.commit()
                        logger.info(
                            "bcd_walk: firmware %s emitted %d Finding rows",
                            firmware_id,
                            len(emitted),
                        )
                    except Exception:
                        await db.rollback()
                        logger.warning(
                            "bcd_walk: firmware %s Finding emit failed",
                            firmware_id,
                            exc_info=True,
                        )

                logger.info(
                    "bcd_walk: firmware %s completed in %.2fs (%d "
                    "stores, %d entries walked, %d persisted, %d "
                    "testsigning, %d suspicious paths, %d anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["stores_scanned"],
                    result["entries_walked"],
                    result["entries_persisted"],
                    result["testsigning_count"],
                    result["suspicious_path_count"],
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
                        fail_row.bcd_walk_status = "failed"
                        fail_row.bcd_walk_finished_at = _dt.datetime.now(
                            _dt.UTC
                        )
                        fail_row.bcd_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "bcd_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "bcd_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_bcd_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as the η.A.C
    auto_mft_walk_firmware_safe wrapper.

    Distinct from :func:`run_bcd_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-
    triggered walks. The auto-walk-on-unpack flow runs the SAME
    orchestrator (``_do_bcd_walk``) but DOES NOT transition the
    status column — it stays ``idle`` until an operator explicitly
    triggers a re-walk via the trigger MCP tool, which resets and
    runs again.

    Wired to FindingService.emit_bcd_findings_from_walk in θ.A.E so
    auto-walks produce both the per-entry landing-zone rows AND the
    bootkit-precursor Finding rows in a single pass.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_bcd_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            project_id: uuid.UUID | None = None
            if row is not None:
                row.bcd_walk_result = _stamp_firmware_bcd_walk_result(result)
                project_id = row.project_id
                await db.commit()

            # θ.A.E — emit windows_bcd_* Finding rows for each
            # WindowsBcdEntry persisted by the inner runner. Lazy
            # import per Rule #30 to avoid bcd_walker ↔ finding_service
            # circular at module load (and to keep the cold-import
            # cost off the unpack worker's critical path when no BCD
            # is actually present in the firmware).
            if project_id is not None and result["entries_persisted"] > 0:
                try:
                    from app.services.finding_service import FindingService

                    service = FindingService(db=db)
                    emitted = await service.emit_bcd_findings_from_walk(
                        project_id, firmware_id
                    )
                    await db.commit()
                    logger.info(
                        "bcd_walk auto: firmware %s emitted %d Finding rows",
                        firmware_id,
                        len(emitted),
                    )
                except Exception:
                    # Emit failure must NOT roll back the walk-result
                    # persistence — leave the windows_bcd_entries rows
                    # + bcd_walk_result aggregate in place even if the
                    # downstream Finding emit raises. Operators can
                    # re-run via the trigger MCP tool to retry.
                    await db.rollback()
                    logger.warning(
                        "bcd_walk auto: firmware %s Finding emit failed",
                        firmware_id,
                        exc_info=True,
                    )

            logger.info(
                "bcd_walk auto: firmware %s walked %d stores / %d "
                "entries in %.2fs",
                firmware_id,
                result["stores_scanned"],
                result["entries_walked"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "bcd_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "REGIPY_UNAVAILABLE",
    "_do_bcd_walk",
    "auto_bcd_walk_firmware_safe",
    "build_anomaly_flags",
    "is_microsoft_description",
    "is_regipy_available",
    "is_suspicious_bootloader_path",
    "looks_like_regf",
    "run_bcd_walk_background",
    "walk_bcd_stores",
]
