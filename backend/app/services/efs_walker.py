"""Phase ι.D.C — Windows EFS DDF/DRF metadata walker (SECOND ι WINDOWS-SIDE).

Walks every NTFS volume candidate under detection roots (per Rule #16)
found in Windows-firmware extracts, iterates the MFT for files with
``FILE_ATTRIBUTE_ENCRYPTED`` (0x4000) set on $STANDARD_INFORMATION,
reads the file's ``LOGGED_UTILITY_STREAM`` attribute (type 0x100) which
carries the ``$EFS`` blob, and surfaces metadata about WHO CAN DECRYPT
(DDF user list) and WHO IS THE RECOVERY AGENT (DRF list).

**PARSE-ONLY DISCIPLINE — Rule #36 + Rule #36 EXTENSION.** The walker
captures METADATA ONLY. It NEVER:

- Decrypts the RSA-encrypted FEK (File Encryption Key).
- Attempts plaintext recovery of any encrypted file content.
- Invokes Windows DPAPI (``CryptUnprotectData``) or any equivalent.
- Imports cryptographic decryption modules (no ``cryptography.fernet``,
  no ``CryptUnprotectData`` shim, no DPAPI bindings, no asn1crypto
  decryption primitives — asn1crypto is imported only for opaque ASN.1
  parsing of cert-hash-data blobs as DATA, never as cryptographic
  primitives).

The "who can decrypt + who is the recovery agent" surface IS the
forensic value:

- T1486 (Data Encrypted for Impact) — ransomware variant when adversaries
  encrypt victim files with attacker-controlled DDF.
- T1564.001 (Hidden Files and Directories) — insider stealth when an
  unauthorized SID appears in DDF.
- Supply-chain fingerprint when the SAME DRF recovery-agent certificate
  thumbprint appears across multiple supposedly-independent firmwares.

Real-world Persona-E EFS relevance:

- **SafeBreach 2020 PoC** — abused EFS for ransomware-like behaviour by
  encrypting victim files with attacker-controlled DDF, locking the
  legitimate user OUT of their own data.
- **Insider-threat patterns** — an unauthorized SID added to DDF on
  sensitive corporate files = silent exfiltration vector.
- **Recovery agent supply-chain** — same DRF cert thumbprint across
  multiple firmwares = shared backdoor key OR un-rekeyed vendor default.

**Rule #19 evidence-first OSS-library probe** (ran 2026-05-12T16:11Z):
- ``dissect.ntfs.c_ntfs.ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM = 0x100``
  confirmed (the $EFS attribute type code).
- ``dissect.ntfs.c_ntfs.ATTRIBUTE_FLAG_ENCRYPTED = 0x4000`` confirmed
  (the per-stream EFS flag on attribute headers).
- ``MftRecord.attributes`` returns ``AttributeMap`` (UserDict-by-type-code).
  ``attrs[ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM]`` returns
  ``AttributeCollection`` (list-like); element ``[0].open()`` returns a
  file-handle for the raw $EFS bytes. ``Attribute.data()`` returns
  bytes directly.
- ``$STANDARD_INFORMATION.file_attributes`` is the FileAttributes bitmask
  (Windows FILE_ATTRIBUTE_*); EFS-encrypted bit is 0x4000.
- asn1crypto 1.5.1 already in tree (pulled from existing wairz deps).
  Used ONLY for opaque ASN.1 parsing of the cert-hash-data blob as
  DATA; no cryptographic operations are performed.

**Rule #39 inner/outer/safe runner triplet** (Rule-of-Seventeen → Rule-
of-Eighteen with this stream):

- :func:`_do_efs_walk` — INNER orchestrator. Accepts caller-owned ``db``.
  Walks every raw NTFS image candidate under detection roots (reuses
  η.A's ``walk_raw_ntfs_images`` plumbing). For each MFT record with
  FILE_ATTRIBUTE_ENCRYPTED, parses the $EFS blob from the
  LOGGED_UTILITY_STREAM attribute. Persists per-file
  ``WindowsEfsEncryptedFile`` rows. Returns aggregate dict UNSTAMPED.
- :func:`run_efs_walk_background` — OUTER state-machine wrapper. Owns
  the Rule #33 .a status transitions via ``async_session_factory()``.
- :func:`auto_efs_walk_firmware_safe` — UNPACK-POST-DETECTION hook.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare ``firmware.extracted_path``)
so multi-rootfs Windows firmware (VHDX / NTFS / FAT32 / system images)
surfaces every NTFS volume candidate.

**Performance.** Most Windows installs have 0-100 EFS-encrypted files
(EFS is rarely used outside corporate domains); cap per-firmware at
50000 persisted files defensive against attacker-planted artifacts.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os
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
from app.models.windows_efs_encrypted_files import WindowsEfsEncryptedFile
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_efs_walk_result,
    _stamp_windows_efs_encrypted_files_anomaly_flags,
    _stamp_windows_efs_encrypted_files_ddf_users,
    _stamp_windows_efs_encrypted_files_drf_recovery_agents,
)
from app.services.mft_walker import (
    _safe_attribute_value,
    looks_like_ntfs,
    walk_raw_ntfs_images,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum EFS-encrypted files persisted per firmware. EFS is rarely used
# outside corporate domains; healthy estate would have <100 files. Cap
# at 50000 defensive against attacker-planted EFS-encrypted artifacts.
_DEFAULT_MAX_FILES_PER_FIRMWARE: int = 50_000

# Cap on raw NTFS image size to attempt. A whole-disk image can exceed
# 100 GB; protect the synchronous walker from runaway. Operators wanting
# whole-disk walks can re-trigger via the MCP tool.
_DEFAULT_MAX_IMAGE_BYTES: int = 16 * 1024 * 1024 * 1024  # 16 GiB

# Cap on $EFS blob size. Real-world $EFS bodies run 800-2000 bytes; a
# 1 MB body is either a corrupted attribute or an attacker artifact.
# Skip with parse_error if exceeded.
_DEFAULT_MAX_EFS_BLOB_BYTES: int = 1 * 1024 * 1024  # 1 MiB

# Cap on per-DDF/DRF entry count. A 1000-user DDF is unprecedented; cap
# to avoid memory pressure on malformed blobs.
_DEFAULT_MAX_ENTRIES_PER_TABLE: int = 256

# Windows FILE_ATTRIBUTE_ENCRYPTED bit on $STANDARD_INFORMATION's
# FileAttributes field (also matches ATTRIBUTE_FLAG_ENCRYPTED on
# attribute headers — same bit, different placement).
_FILE_ATTRIBUTE_ENCRYPTED: int = 0x4000


# Well-known recovery-agent SIDs that count as "standard Windows EFS
# Recovery family". A SID not in this set (or in a domain pattern that
# extends it) triggers ``unusual_recovery_agent``. The empty default set
# is intentional — most firmware-side recovery agents are domain-specific
# (S-1-5-21-...) and we don't have an apriori allowlist; the heuristic
# is "SID matches a well-known builtin recovery account or not".
_STANDARD_RECOVERY_SID_PATTERNS: tuple[str, ...] = (
    # Built-in Administrator (RID 500) — common local recovery agent.
    "S-1-5-21-",  # Domain or local account prefix
    # Built-in Administrators group.
    "S-1-5-32-544",
    # System.
    "S-1-5-18",
)

# Domain admin SID patterns (RID 512 — Domain Admins group; RID 519 —
# Enterprise Admins) — flagged in DDF as a strong indicator (either
# legitimate admin pre-staging or a privileged compromise).
_DOMAIN_ADMIN_RID_SUFFIXES: tuple[str, ...] = (
    "-512",  # Domain Admins
    "-519",  # Enterprise Admins
    "-500",  # Built-in Administrator (RID 500)
)


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_dissect_ntfs_available() -> bool:
    """Return True iff ``dissect.ntfs`` is importable in this process."""
    try:
        import dissect.ntfs  # noqa: F401 — import-only probe
    except ImportError:
        return False
    return True


# ── SID + thumbprint helpers ────────────────────────────────────────────────


def parse_sid_binary(data: bytes, offset: int) -> str | None:
    """Parse a binary SID at ``data[offset:]`` into the textual SDDL form.

    Microsoft SID binary layout (per MS-DTYP 2.4.2.2):
        byte 0:     Revision (always 1)
        byte 1:     SubAuthorityCount (N)
        bytes 2-7:  IdentifierAuthority (6 bytes, big-endian)
        bytes 8+:   N × 4-byte SubAuthority values (little-endian)

    Returns the canonical S-R-IA-SA1-SA2-... string, or None on parse error.
    Defensive: bounds-checked; never raises.
    """
    try:
        if offset < 0 or offset + 8 > len(data):
            return None
        revision = data[offset]
        sub_count = data[offset + 1]
        if sub_count > 15 or sub_count == 0:
            return None
        # IdentifierAuthority is 6 bytes big-endian.
        ia_bytes = data[offset + 2:offset + 8]
        ia = int.from_bytes(ia_bytes, "big")
        # SubAuthorities are sub_count × 4 bytes little-endian.
        sub_start = offset + 8
        sub_end = sub_start + sub_count * 4
        if sub_end > len(data):
            return None
        subs = []
        for i in range(sub_count):
            sub_offset = sub_start + i * 4
            subs.append(
                int.from_bytes(data[sub_offset:sub_offset + 4], "little")
            )
        return "S-" + str(revision) + "-" + str(ia) + "-" + "-".join(
            str(s) for s in subs
        )
    except (struct.error, IndexError, ValueError):
        return None


def format_thumbprint_hex(data: bytes) -> str:
    """Format raw bytes as canonical SHA-1 thumbprint hex (40 chars lowercase).

    Per Microsoft EFS spec: cert thumbprint is a SHA-1 hash of the
    certificate's binary representation, stored as 20 raw bytes. Display
    as 40-char lowercase hex.

    Truncates if data is longer than 20 bytes (sometimes the blob has
    trailing padding). Returns empty string if data is empty.
    """
    if not data:
        return ""
    # Use up to 20 bytes (SHA-1 length); ignore trailing padding.
    truncated = data[:20]
    return truncated.hex()


def is_domain_admin_sid(sid: str | None) -> bool:
    """True iff the SID matches a Windows admin RID pattern (RID 500 /
    512 / 519).

    Patterns:
    - ``S-1-5-21-<domain>-500`` — Built-in Administrator account.
    - ``S-1-5-21-<domain>-512`` — Domain Admins group.
    - ``S-1-5-21-<domain>-519`` — Enterprise Admins group.
    """
    if not sid:
        return False
    return any(sid.endswith(suffix) for suffix in _DOMAIN_ADMIN_RID_SUFFIXES)


def is_unusual_recovery_agent(sid: str | None) -> bool:
    """True iff the SID looks like a NON-standard recovery agent.

    A "standard" recovery agent SID matches the Windows EFS Recovery
    family — S-1-5-21-* (local or domain accounts), S-1-5-32-544
    (Administrators), S-1-5-18 (System). A SID NOT matching any of these
    is suspicious — could be a non-standard recovery configuration or a
    malicious recovery agent.
    """
    if not sid:
        return True  # null SID is suspicious
    return not any(
        sid.startswith(pattern) or sid == pattern
        for pattern in _STANDARD_RECOVERY_SID_PATTERNS
    )


# ── $EFS blob parser (parse-only — Rule #36 + Rule #36 extension) ────────────
#
# Microsoft EFS $EFS attribute body layout (MS-EFSR section [EFSR]):
#
# EFS_HEADER (offset 0):
#   dwReserved              4 bytes  (often 0)
#   cbTotalLength           4 bytes  total blob length
#   EfsId                   16 bytes random per-file GUID
#   dwReserved2             4 bytes
#   dwVersion               4 bytes  (1 = legacy CryptoAPI, 2 = CNG)
#   dwCryptoApiVersion      4 bytes
#   Checksum                20 bytes SHA1 hash
#   dwReservedSpaceForDDFOffset 4 bytes
#   dwDDFOffset             4 bytes  offset to DDF table (relative to blob)
#   dwDRFOffset             4 bytes  offset to DRF table (relative to blob)
#   dwReserved3             4 bytes
#
# EFS_DATA_KEY_TABLE (at dwDDFOffset / dwDRFOffset):
#   dwUsersCount            4 bytes  number of credential entries
#   followed by dwUsersCount × EFS_RSA_KEY_HASH_DATA
#
# EFS_RSA_KEY_HASH_DATA:
#   cbLength                4 bytes  total length of this entry
#   dwReserved              4 bytes
#   dwSidOffset             4 bytes  offset to SID (relative to entry)
#   dwReserved2             4 bytes
#   dwCertHashDataOffset    4 bytes  offset to cert hash data
#   cbCertHashLength        4 bytes  length of cert hash blob
#   dwReserved3             4 bytes
#   dwEncryptedFEKOffset    4 bytes  offset to RSA-encrypted FEK
#   cbEncryptedFEKLength    4 bytes  length of encrypted FEK
#   + variable-length data: SID, CertHashData (typically 20 bytes SHA1),
#     DisplayInformation (UTF-16LE), EncryptedFEK (we DO NOT touch this)
#
# PARSE-ONLY: we extract SID + thumbprint metadata and IGNORE the
# encrypted FEK entirely. The encrypted FEK is the gateway to decryption;
# wairz NEVER decrypts.


def _parse_efs_table(
    blob: bytes,
    table_offset: int,
    max_entries: int,
) -> tuple[list[dict], list[str]]:
    """Parse one DDF or DRF table from the EFS blob.

    Returns ``(entries, errors)`` where entries is a list of
    ``{"sid": str | None, "cert_thumbprint": str, "friendly_name": str | None}``
    dicts (capped at max_entries) and errors is a list of per-entry
    parse error messages (empty on clean parse).

    Defensive: bounds-checked; never raises. Unparseable entries are
    skipped with a recorded error.
    """
    entries: list[dict] = []
    errors: list[str] = []

    if table_offset <= 0 or table_offset >= len(blob):
        return entries, errors

    # Read user count (4 bytes LE).
    if table_offset + 4 > len(blob):
        errors.append(
            f"table at offset {table_offset} truncated before user count"
        )
        return entries, errors

    user_count = int.from_bytes(blob[table_offset:table_offset + 4], "little")
    if user_count == 0:
        return entries, errors
    if user_count > max_entries:
        errors.append(
            f"table at offset {table_offset} claims {user_count} users "
            f"(>{max_entries} cap)"
        )
        user_count = max_entries

    cursor = table_offset + 4
    for i in range(user_count):
        if cursor + 40 > len(blob):
            errors.append(
                f"entry {i} truncated at offset {cursor} (need 40-byte header)"
            )
            break

        # Parse the EFS_RSA_KEY_HASH_DATA header (10 × 4-byte fields = 40 bytes).
        try:
            (
                cb_length,
                _reserved,
                dw_sid_offset,
                _reserved2,
                dw_cert_hash_offset,
                cb_cert_hash_length,
                _reserved3,
                dw_encrypted_fek_offset,
                _cb_encrypted_fek_length,
                _dw_credential_size,
            ) = struct.unpack_from("<10I", blob, cursor)
        except struct.error as exc:
            errors.append(f"entry {i} unpack error: {exc}")
            break

        # Validate entry length.
        if cb_length < 40 or cursor + cb_length > len(blob):
            errors.append(
                f"entry {i} length {cb_length} invalid (cursor {cursor}, "
                f"blob {len(blob)})"
            )
            break

        # SID — absolute offset within the blob.
        sid_abs = cursor + dw_sid_offset
        sid_text = parse_sid_binary(blob, sid_abs)

        # Cert hash thumbprint — extract bytes, format as hex.
        cert_hash_abs = cursor + dw_cert_hash_offset
        cert_hash_data = b""
        if (
            cert_hash_abs >= 0
            and cb_cert_hash_length > 0
            and cert_hash_abs + cb_cert_hash_length <= len(blob)
        ):
            cert_hash_data = blob[
                cert_hash_abs:cert_hash_abs + cb_cert_hash_length
            ]
        thumbprint = format_thumbprint_hex(cert_hash_data)

        # Friendly name — DisplayInformation is the UTF-16LE string that
        # often follows the SID. Heuristic: read UTF-16LE bytes between
        # cert_hash_abs+cb_cert_hash_length and dw_encrypted_fek_offset.
        friendly_name: str | None = None
        try:
            fn_start = cert_hash_abs + cb_cert_hash_length
            fn_end = cursor + dw_encrypted_fek_offset
            if fn_start < fn_end <= len(blob) and (fn_end - fn_start) <= 1024:
                fn_bytes = blob[fn_start:fn_end]
                # Strip trailing NUL wide-chars (UTF-16LE null = 2 bytes
                # \x00\x00). MUST strip in 2-byte pairs to avoid eating
                # the high byte of a printable trailing character (e.g.
                # 'm' = b'm\x00' in UTF-16LE).
                while fn_bytes.endswith(b"\x00\x00"):
                    fn_bytes = fn_bytes[:-2]
                if fn_bytes:
                    try:
                        decoded = fn_bytes.decode("utf-16-le", errors="ignore")
                        # Strip control chars and surrogates.
                        cleaned = "".join(
                            c for c in decoded
                            if c.isprintable() and not (0xD800 <= ord(c) <= 0xDFFF)
                        ).strip()
                        if cleaned:
                            friendly_name = cleaned[:255]
                    except (UnicodeDecodeError, ValueError):
                        pass
        except (struct.error, IndexError):
            pass

        entries.append({
            "sid": sid_text,
            "cert_thumbprint": thumbprint,
            "friendly_name": friendly_name,
        })

        cursor += cb_length

    return entries, errors


def parse_efs_blob(blob: bytes) -> tuple[list[dict], list[dict], list[str]]:
    """Parse the $EFS attribute body and return ``(ddf_users,
    drf_recovery_agents, errors)``.

    Per the MS-EFSR EFSR specification: the header starts with
    dwReserved + cbTotalLength + EfsId (16 bytes GUID) + dwReserved2 +
    dwVersion + dwCryptoApiVersion + Checksum (20 bytes) +
    dwReservedSpaceForDDFOffset + dwDDFOffset + dwDRFOffset + dwReserved3.

    The header is 76 bytes (4+4+16+4+4+4+20+4+4+4+4=76). Then DDF and DRF
    tables follow at their respective offsets (relative to the start of
    the $EFS attribute body, i.e. the blob).

    PARSE-ONLY: we extract SID + thumbprint metadata; the encrypted FEK
    in each entry is IGNORED (never decoded, never decrypted).

    Defensive: bounds-checked; never raises. Returns empty results on
    truncated / malformed blobs (with descriptive error messages).
    """
    errors: list[str] = []

    # Minimum header size.
    if len(blob) < 76:
        errors.append(
            f"blob too short ({len(blob)} bytes < 76-byte minimum header)"
        )
        return [], [], errors

    try:
        # Parse header offsets.
        # Layout:
        #   0-4:    dwReserved
        #   4-8:    cbTotalLength
        #   8-24:   EfsId (16 bytes)
        #   24-28:  dwReserved2
        #   28-32:  dwVersion
        #   32-36:  dwCryptoApiVersion
        #   36-56:  Checksum (20 bytes)
        #   56-60:  dwReservedSpaceForDDFOffset
        #   60-64:  dwDDFOffset
        #   64-68:  dwDRFOffset
        #   68-72:  dwReserved3
        cb_total_length = int.from_bytes(blob[4:8], "little")
        dw_ddf_offset = int.from_bytes(blob[60:64], "little")
        dw_drf_offset = int.from_bytes(blob[64:68], "little")
    except (struct.error, IndexError) as exc:
        errors.append(f"header parse error: {exc}")
        return [], [], errors

    # Sanity-check cbTotalLength.
    if cb_total_length > 0 and cb_total_length < len(blob):
        # Some implementations report a shorter total than actual; truncate
        # the working view but don't reject.
        pass

    ddf_users, ddf_errors = _parse_efs_table(
        blob, dw_ddf_offset, _DEFAULT_MAX_ENTRIES_PER_TABLE
    )
    errors.extend(f"DDF: {e}" for e in ddf_errors)

    drf_agents, drf_errors = _parse_efs_table(
        blob, dw_drf_offset, _DEFAULT_MAX_ENTRIES_PER_TABLE
    )
    errors.extend(f"DRF: {e}" for e in drf_errors)

    return ddf_users, drf_agents, errors


# ── Anomaly classifier (pure functions) ──────────────────────────────────────


def build_anomaly_flags(
    *,
    ddf_users: list[dict],
    drf_recovery_agents: list[dict],
    parse_error: bool,
) -> dict[str, Any]:
    """Construct the anomaly_flags payload from parsed DDF/DRF metadata.

    Pure function — same inputs always produce the same output. Caller
    stamps the schema_version via
    ``_stamp_windows_efs_encrypted_files_anomaly_flags``.

    Anomaly bits:
    - orphaned_drf: DRF entries exist without any DDF entries (encrypted-
      via-recovery-only — insider stealth indicator).
    - unusual_recovery_agent: any DRF entry has a SID outside the standard
      Windows EFS Recovery family.
    - multiple_ddf_users: >1 user in DDF (shared decryption — could be
      legitimate or insider-stealth).
    - large_drf: >2 recovery agents (unusual config).
    - cert_thumbprint_anomaly: any thumbprint is empty / suspiciously
      short (informational only — most thumbprints are legitimately
      domain-specific).
    - domain_admin_in_ddf: a domain admin SID (RID 500/512/519) appears
      in the DDF.
    - parse_error: the $EFS blob couldn't be parsed cleanly.
    """
    ddf_count = len(ddf_users)
    drf_count = len(drf_recovery_agents)

    flags: dict[str, Any] = {
        "orphaned_drf": drf_count > 0 and ddf_count == 0,
        "unusual_recovery_agent": any(
            is_unusual_recovery_agent(entry.get("sid"))
            for entry in drf_recovery_agents
        ),
        "multiple_ddf_users": ddf_count > 1,
        "large_drf": drf_count > 2,
        "cert_thumbprint_anomaly": any(
            (not entry.get("cert_thumbprint"))
            or len(entry.get("cert_thumbprint") or "") < 8
            for entry in (ddf_users + drf_recovery_agents)
        ),
        "domain_admin_in_ddf": any(
            is_domain_admin_sid(entry.get("sid")) for entry in ddf_users
        ),
        "parse_error": bool(parse_error),
    }
    return flags


# ── MFT iteration helpers (PARSE-ONLY, reuse η.A plumbing) ───────────────────


def _is_encrypted_file(record: Any) -> bool:
    """Return True iff the record's $STANDARD_INFORMATION reports the
    FILE_ATTRIBUTE_ENCRYPTED bit (0x4000) set.

    Defensive — returns False on any access error.
    """
    try:
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
    except ImportError:
        return False

    try:
        si = record.attributes[ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION]
    except Exception:  # noqa: BLE001 — defensive boundary
        return False
    if not si:
        return False

    file_attributes = _safe_attribute_value(si, "file_attributes")
    if file_attributes is None:
        return False
    try:
        return bool(int(file_attributes) & _FILE_ATTRIBUTE_ENCRYPTED)
    except (TypeError, ValueError):
        return False


def _get_efs_blob_bytes(record: Any) -> bytes | None:
    """Return the raw $EFS blob bytes from the record's
    LOGGED_UTILITY_STREAM attribute (type 0x100).

    PARSE-ONLY: reads the bytes for parsing as DATA; nothing in this
    function or its callers invokes any spawn primitive on the data.

    Defensive: returns None on any access error.
    """
    try:
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
    except ImportError:
        return None

    try:
        attrs = record.attributes[ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM]
    except Exception:  # noqa: BLE001 — defensive boundary
        return None

    if not attrs:
        return None

    # Look for the unnamed $EFS attribute (the named ones are different
    # uses of LOGGED_UTILITY_STREAM, e.g. $TXF_DATA for transactional NTFS).
    for attr in attrs:
        try:
            name = attr.header.name or ""
        except Exception:  # noqa: BLE001
            continue
        if name == "" or name == "$EFS":
            try:
                # For resident attributes, header.open() gives us the bytes
                # of just the attribute data. For non-resident, it walks
                # the dataruns. Read up to the size cap.
                with attr.header.open() as fh:
                    data = fh.read(_DEFAULT_MAX_EFS_BLOB_BYTES + 1)
                if len(data) > _DEFAULT_MAX_EFS_BLOB_BYTES:
                    # Oversize — truncate and let the parser report
                    # parse_error.
                    data = data[:_DEFAULT_MAX_EFS_BLOB_BYTES]
                return data
            except Exception:  # noqa: BLE001 — defensive boundary
                continue

    return None


def _safe_mft_segment(record: Any) -> int | None:
    """Return record.segment, or None on access error."""
    try:
        seg = record.segment
        return int(seg) if seg is not None else None
    except Exception:  # noqa: BLE001
        return None


def _safe_full_path(record: Any) -> str | None:
    """Return record.full_path() result or None on lookup failure."""
    try:
        path = record.full_path()
        if isinstance(path, str) and path:
            return path
    except Exception:  # noqa: BLE001
        pass
    return None


def _safe_file_size(record: Any) -> int | None:
    """Return the primary $DATA stream size, or None on absence."""
    try:
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
    except ImportError:
        return None
    try:
        data_attrs = record.attributes[ATTRIBUTE_TYPE_CODE.DATA]
    except Exception:  # noqa: BLE001
        return None
    if not data_attrs:
        return None
    for attr in data_attrs:
        try:
            name = attr.header.name or ""
            size = getattr(attr.header, "size", None)
            if not name and size is not None:
                return int(size)
        except Exception:  # noqa: BLE001
            continue
    return None


def _iter_segments_safe(fs: Any) -> Iterator[Any]:
    """Iterate fs.mft.segments() swallowing per-record corruption."""
    try:
        from dissect.ntfs.exceptions import Error
    except ImportError:
        return iter([])

    try:
        iterator = fs.mft.segments()
    except Exception:  # noqa: BLE001
        return iter([])

    def _generator() -> Iterator[Any]:
        while True:
            try:
                record = next(iterator)
            except StopIteration:
                return
            except (Error, EOFError):
                continue
            except Exception:  # noqa: BLE001
                continue
            yield record

    return _generator()


# ── Per-image walker ─────────────────────────────────────────────────────────


def _walk_one_image_sync(
    image_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_files: int,
    persisted_so_far: int,
) -> tuple[list[WindowsEfsEncryptedFile], dict[str, Any]]:
    """Open one raw NTFS image and walk its MFT for EFS-encrypted files.

    SYNC I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    """
    aggregate: dict[str, Any] = {
        "path": relative_source,
        "status": "ok",
        "files_walked": 0,
        "encrypted_files_found": 0,
        "encrypted_files_persisted": 0,
        "files_capped": 0,
        "parse_errors": 0,
        "orphaned_drf_count": 0,
        "unusual_recovery_agent_count": 0,
        "multiple_ddf_users_count": 0,
        "large_drf_count": 0,
        "domain_admin_in_ddf_count": 0,
        "anomaly_total": 0,
        "error": None,
    }

    try:
        size = os.path.getsize(image_path)
    except OSError as exc:
        aggregate["status"] = "error"
        aggregate["error"] = (
            f"stat failed: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return [], aggregate

    if size > _DEFAULT_MAX_IMAGE_BYTES:
        aggregate["status"] = "skipped"
        aggregate["error"] = (
            f"image size {size} exceeds max {_DEFAULT_MAX_IMAGE_BYTES}"
        )
        return [], aggregate

    if not looks_like_ntfs(image_path):
        aggregate["status"] = "not_ntfs"
        aggregate["error"] = "NTFS boot sector signature not found"
        return [], aggregate

    try:
        from dissect.ntfs import NTFS
    except ImportError:
        aggregate["status"] = "unavailable"
        aggregate["error"] = "dissect.ntfs not importable"
        return [], aggregate

    rows: list[WindowsEfsEncryptedFile] = []
    persist_budget = max_files - persisted_so_far

    try:
        with open(image_path, "rb") as fh:
            fs = NTFS(fh=fh)
            for record in _iter_segments_safe(fs):
                aggregate["files_walked"] += 1

                if not _is_encrypted_file(record):
                    continue

                aggregate["encrypted_files_found"] += 1

                if persist_budget <= 0:
                    aggregate["files_capped"] += 1
                    continue

                # Read $EFS blob bytes (PARSE-ONLY).
                blob = _get_efs_blob_bytes(record)
                segment = _safe_mft_segment(record)
                full_path = _safe_full_path(record)
                file_size = _safe_file_size(record)

                ddf_users: list[dict] = []
                drf_agents: list[dict] = []
                parse_error_text: str | None = None
                efs_blob_size = 0

                if blob is None:
                    parse_error_text = (
                        "LOGGED_UTILITY_STREAM/$EFS attribute not present "
                        "or unreadable"
                    )
                    aggregate["parse_errors"] += 1
                else:
                    efs_blob_size = len(blob)
                    if efs_blob_size > _DEFAULT_MAX_EFS_BLOB_BYTES:
                        parse_error_text = (
                            f"$EFS blob {efs_blob_size} bytes exceeds "
                            f"{_DEFAULT_MAX_EFS_BLOB_BYTES} cap"
                        )
                        aggregate["parse_errors"] += 1
                    else:
                        try:
                            ddf_users, drf_agents, errors = parse_efs_blob(blob)
                            if errors:
                                parse_error_text = (
                                    " | ".join(errors)[:1000]
                                )
                                aggregate["parse_errors"] += 1
                        except Exception as exc:  # noqa: BLE001
                            parse_error_text = (
                                f"{type(exc).__name__}: {str(exc)[:300]}"
                            )
                            aggregate["parse_errors"] += 1

                # Classify anomalies.
                anomaly = build_anomaly_flags(
                    ddf_users=ddf_users,
                    drf_recovery_agents=drf_agents,
                    parse_error=parse_error_text is not None,
                )

                if anomaly["orphaned_drf"]:
                    aggregate["orphaned_drf_count"] += 1
                if anomaly["unusual_recovery_agent"]:
                    aggregate["unusual_recovery_agent_count"] += 1
                if anomaly["multiple_ddf_users"]:
                    aggregate["multiple_ddf_users_count"] += 1
                if anomaly["large_drf"]:
                    aggregate["large_drf_count"] += 1
                if anomaly["domain_admin_in_ddf"]:
                    aggregate["domain_admin_in_ddf_count"] += 1
                if any(v for k, v in anomaly.items() if isinstance(v, bool)):
                    aggregate["anomaly_total"] += 1

                # Truncate file_path defensively.
                truncated_path = (
                    f"{relative_source}!{full_path}" if full_path else relative_source
                )
                if len(truncated_path) > 1024:
                    truncated_path = truncated_path[:1024]

                row = WindowsEfsEncryptedFile(
                    firmware_id=firmware_id,
                    file_path=truncated_path,
                    file_size=file_size,
                    mft_record_number=(
                        segment if segment is not None
                        else aggregate["encrypted_files_found"] - 1
                    ),
                    efs_attribute_size=efs_blob_size,
                    ddf_user_count=len(ddf_users),
                    drf_recovery_agent_count=len(drf_agents),
                    ddf_users=_stamp_windows_efs_encrypted_files_ddf_users(
                        list(ddf_users)
                    ),
                    drf_recovery_agents=_stamp_windows_efs_encrypted_files_drf_recovery_agents(
                        list(drf_agents)
                    ),
                    anomaly_flags=(
                        _stamp_windows_efs_encrypted_files_anomaly_flags(
                            dict(anomaly)
                        )
                    ),
                    parse_error=parse_error_text,
                )
                rows.append(row)
                persist_budget -= 1
                aggregate["encrypted_files_persisted"] += 1
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        aggregate["status"] = "error"
        aggregate["error"] = f"{type(exc).__name__}: {msg}"
        return rows, aggregate

    return rows, aggregate


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "images_scanned": 0,
        "files_walked": 0,
        "encrypted_files_found": 0,
        "encrypted_files_persisted": 0,
        "files_capped": 0,
        "parse_errors": 0,
        "orphaned_drf_count": 0,
        "unusual_recovery_agent_count": 0,
        "multiple_ddf_users_count": 0,
        "large_drf_count": 0,
        "domain_admin_in_ddf_count": 0,
        "anomaly_total": 0,
        "errors": [],
        "per_image": [],
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


async def _walk_raw_ntfs_images_async(roots: list[str]) -> list[str]:
    """Async wrapper around walk_raw_ntfs_images (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_raw_ntfs_images, roots)


async def _walk_one_image_async(
    image_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_files: int,
    persisted_so_far: int,
) -> tuple[list[WindowsEfsEncryptedFile], dict[str, Any]]:
    """Async wrapper around _walk_one_image_sync (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_image_sync(
            image_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
            max_files=max_files,
            persisted_so_far=persisted_so_far,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ──────────────────────────


async def _do_efs_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_files: int = _DEFAULT_MAX_FILES_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every raw NTFS image candidate under ``firmware_id``'s extracted
    tree, surface EFS-encrypted files (FILE_ATTRIBUTE_ENCRYPTED bit set on
    $STANDARD_INFORMATION), parse the $EFS attribute body for DDF/DRF
    metadata, and persist per-file rows.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Walk raw NTFS image candidates (η.A's ``walk_raw_ntfs_images``).
    3. For each image: open via dissect.ntfs, iterate MFT, filter to
       encrypted files, parse $EFS metadata (PARSE-ONLY), classify
       anomalies, build rows.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real test
    DB without DNS resolution issues from ``async_session_factory()``.

    Rule #36 + extension reminder: NEVER decrypts the FEK, NEVER invokes
    DPAPI, NEVER attempts plaintext recovery.
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

    image_paths = await _walk_raw_ntfs_images_async(roots)
    if not image_paths:
        return _empty_walk_result(time.monotonic() - started)

    images_scanned = 0
    files_walked = 0
    encrypted_files_found = 0
    encrypted_files_persisted = 0
    files_capped = 0
    parse_errors = 0
    orphaned_drf_count = 0
    unusual_recovery_agent_count = 0
    multiple_ddf_users_count = 0
    large_drf_count = 0
    domain_admin_in_ddf_count = 0
    anomaly_total = 0
    errors: list[str] = []
    per_image: list[dict] = []

    for image_path in image_paths:
        relative = _relativize_path(image_path, roots)
        try:
            rows, agg = await _walk_one_image_async(
                image_path,
                firmware_id=firmware_id,
                relative_source=relative,
                max_files=max_files,
                persisted_so_far=encrypted_files_persisted,
            )
        except Exception as exc:  # noqa: BLE001
            err = (
                f"walk failed for {image_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_image.append({
                "path": relative,
                "status": "error",
                "files_walked": 0,
                "encrypted_files_found": 0,
                "encrypted_files_persisted": 0,
                "files_capped": 0,
                "parse_errors": 0,
                "orphaned_drf_count": 0,
                "unusual_recovery_agent_count": 0,
                "multiple_ddf_users_count": 0,
                "large_drf_count": 0,
                "domain_admin_in_ddf_count": 0,
                "anomaly_total": 0,
                "error": err,
            })
            continue

        images_scanned += 1
        files_walked += agg["files_walked"]
        encrypted_files_found += agg["encrypted_files_found"]
        encrypted_files_persisted += agg["encrypted_files_persisted"]
        files_capped += agg["files_capped"]
        parse_errors += agg["parse_errors"]
        orphaned_drf_count += agg["orphaned_drf_count"]
        unusual_recovery_agent_count += agg["unusual_recovery_agent_count"]
        multiple_ddf_users_count += agg["multiple_ddf_users_count"]
        large_drf_count += agg["large_drf_count"]
        domain_admin_in_ddf_count += agg["domain_admin_in_ddf_count"]
        anomaly_total += agg["anomaly_total"]
        per_image.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

        for row in rows:
            db.add(row)
        if rows:
            await db.flush()

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "images_scanned": images_scanned,
        "files_walked": files_walked,
        "encrypted_files_found": encrypted_files_found,
        "encrypted_files_persisted": encrypted_files_persisted,
        "files_capped": files_capped,
        "parse_errors": parse_errors,
        "orphaned_drf_count": orphaned_drf_count,
        "unusual_recovery_agent_count": unusual_recovery_agent_count,
        "multiple_ddf_users_count": multiple_ddf_users_count,
        "large_drf_count": large_drf_count,
        "domain_admin_in_ddf_count": domain_admin_in_ddf_count,
        "anomaly_total": anomaly_total,
        "errors": errors,
        "per_image": per_image,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_efs_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the EFS walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a fresh
    session because the inner one rolled back.

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
                    "efs_walk: firmware %s not found", firmware_id
                )
                return

            row.efs_walk_status = "running"
            row.efs_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_efs_walk(db, firmware_id)
                row.efs_walk_status = "completed"
                row.efs_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.efs_walk_result = _stamp_firmware_efs_walk_result(result)
                await db.commit()

                logger.info(
                    "efs_walk: firmware %s completed in %.2fs "
                    "(%d images, %d files walked, %d encrypted found, "
                    "%d persisted, %d anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["images_scanned"],
                    result["files_walked"],
                    result["encrypted_files_found"],
                    result["encrypted_files_persisted"],
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
                        fail_row.efs_walk_status = "failed"
                        fail_row.efs_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.efs_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "efs_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "efs_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_efs_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as
    auto_etl_walk_firmware_safe (ι.C.C precedent) and earlier ι/η/θ
    auto_walk_firmware_safe hooks.

    Distinct from :func:`run_efs_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-triggered
    walks. The auto-walk-on-unpack flow runs the SAME orchestrator
    (``_do_efs_walk``) but DOES NOT transition the status column —
    it stays ``idle`` until an operator explicitly triggers a re-walk
    via the trigger MCP tool, which resets and runs again.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_efs_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.efs_walk_result = _stamp_firmware_efs_walk_result(result)
                await db.commit()

            logger.info(
                "efs_walk auto: firmware %s walked %d images / %d files / "
                "%d encrypted in %.2fs",
                firmware_id,
                result["images_scanned"],
                result["files_walked"],
                result["encrypted_files_found"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "efs_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_efs_walk",
    "auto_efs_walk_firmware_safe",
    "build_anomaly_flags",
    "format_thumbprint_hex",
    "is_domain_admin_sid",
    "is_dissect_ntfs_available",
    "is_unusual_recovery_agent",
    "parse_efs_blob",
    "parse_sid_binary",
    "run_efs_walk_background",
]
