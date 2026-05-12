"""Per-file Windows DPAPI master-key METADATA row (Phase κ.D.A — NINTH κ-era walker).

One row per DPAPI master-key file extracted from a Windows extraction
under ``Users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\<sid>\\<guid>``.
The Phase κ.D.C walker walks every detection root (per Rule #16),
locates master-key files via the canonical path pattern, parses each
file's header via a pure-Python ``struct``-based parser, and persists
ONE row per master-key file with METADATA ONLY.

**PARSE-ONLY DISCIPLINE — Rule #36 + Rule #45 (parse-only-metadata
walker, Rule-of-Two — DURABLE BEYOND DEBATE).** This walker MIRRORS
the ι.D EFS shape — the walker NEVER decrypts master keys, NEVER
invokes ``CryptUnprotectData``, NEVER attempts plaintext recovery,
NEVER imports cryptographic decryption modules. The walker surfaces
ONLY METADATA:

- ``master_key_guid`` — the file's GUID (the file basename).
- ``flags`` — the DWORD flags field from the file header.
- ``hmac_iterations`` — PBKDF2 iteration count from the master-key
  body PREAMBLE (NOT the encrypted body — we stop at the preamble).
- ``salt_size`` — the size of the salt (16 bytes typically), NOT the
  salt bytes themselves (those would aid an attacker in offline
  cracking).
- ``creator_sid`` — extracted from the path (``Users\\<user>\\AppData
  \\Roaming\\Microsoft\\Protect\\<sid>\\<guid>``).
- ``last_modified_ts`` — the file's mtime (cross-platform; the file's
  ON-DISK mtime from ``os.stat()``, not a FILETIME extracted from the
  body).
- Per-section sizes — ``master_key_size``, ``backup_key_size``,
  ``cred_hist_size``, ``domain_key_size`` from the file header.

**Real-world Persona-E DPAPI master-key relevance:**

- **Orphaned master-keys** — a master-key whose ``creator_sid``
  doesn't correspond to any user account found elsewhere in the
  firmware. Could be a backdoor key stash (attacker pre-staged keys
  for later use) or a legacy artefact (user deleted, key files
  remained). Persona-E HIGH.

- **Admin / SYSTEM-creator master-keys** — a master-key whose
  ``creator_sid`` matches a Windows admin RID pattern (RID 500 / 512 /
  519 / 18 — Built-in Administrator, Domain Admins, Enterprise Admins,
  Local System). Could be legitimate (admin uses DPAPI for service
  accounts) or compromise indicator (attacker created keys under
  admin identity to access protected data). Persona-E MEDIUM.

- **Large master-keys** — a master-key file larger than typical
  (>2048 bytes). Typical master-key files are 740-1024 bytes;
  oversized files may indicate unusual DPAPI configuration or
  attacker-planted artefact. Persona-E LOW baseline.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. Multi-rootfs Windows firmware (VHDX
/ NTFS / FAT32 / system images) surfaces every Protect folder candidate.

Per CLAUDE.md Rule #35c JSONB discipline: the ``anomaly_flags`` JSONB
column carries its own normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #36 (no-execute discipline) and Rule #45 (parse-
only-metadata walker, Rule-of-Two): the κ.D.C walker parses the
master-key file AS DATA via pure-Python ``struct`` unpacking. NO
sub-process invocations, NO ``CryptUnprotectData`` shim, NO DPAPI
bindings, NO decryption primitives. The walker's source is tokenized
against forbidden invocation + decryption tokens in
``test_dpapi_walker.py::test_walker_no_decrypt``.

κ.D.D finding emit leverages the parsed metadata to flag persona-E
adversary-residue indicators (orphaned master-keys, admin-creator
master-keys, oversized master-keys). Wairz NEVER decrypts those
artefacts — they are surfaced to operator review as DATA only.

Reference for the DPAPI master-key file format:

- SharpDPAPI (will@harmj0y.net, public domain references)
- Mimikatz DPAPI module (gentilkiwi.com)
- impacket.dpapi.MasterKeyFile (Class-level reference for the layout
  ONLY; ``.decrypt()`` method calls are FORBIDDEN per Rule #45)
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsDpapiMasterKey(Base):
    """Per-file row decoded from a Windows DPAPI master-key file under
    ``Users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\<sid>\\<guid>``.

    PARSE-ONLY discipline (Rule #36 + Rule #45): rows surface DPAPI
    master-key METADATA only — guid, flags, iteration count, salt SIZE
    (NOT bytes), per-section sizes, creator SID extracted from path. The
    walker NEVER decrypts any master-key data, NEVER invokes
    ``CryptUnprotectData``. Operators triage as DATA.
    """

    __tablename__ = "windows_dpapi_master_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this master-key file came from.
    # Cascade DELETE so removing a firmware row removes its DPAPI rows.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relative path within the detection root to the source master-key file.
    # E.g. ``Users/alice/AppData/Roaming/Microsoft/Protect/S-1-5-21-.../e0f...``.
    # Truncated to 1024 chars defensively.
    source_file_path: Mapped[str] = mapped_column(
        String(1024), nullable=False
    )

    # Master-key file GUID — the file basename and the GUID embedded in
    # the file header. Typical form: ``e0f1a2b3-c4d5-6789-abcd-ef0123456789``.
    # Extracted from the path / file basename rather than parsing the
    # 72-byte UTF-16LE GUID text inside the header (which would be
    # redundant — the filename IS the GUID).
    master_key_guid: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Creator SID — extracted from the path. The file lives under
    # ``Protect\\<sid>\\`` where <sid> is the canonical SDDL form
    # ``S-1-5-21-<domain>-<rid>``. NULL when the parser couldn't extract
    # a SID from the path (malformed structure).
    creator_sid: Mapped[str | None] = mapped_column(
        String(256), nullable=True
    )

    # Header DWORD flags field. Typically 0 or small bitmask values;
    # reserved for future format use. Surfaced as integer for operator
    # filtering.
    flags: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # PBKDF2 iteration count from the master-key body PREAMBLE. This is
    # the iteration count used by the OS to derive the key-encryption key
    # from the user's password. Typical Windows defaults: 8000 (Win7) /
    # 17500 (Win10) / 20000+ (Win11). NULL when the body preamble was
    # malformed or absent.
    #
    # IMPORTANT — RULE #45 BOUNDARY: we surface this metadata for
    # operator awareness (compromise indicator: low iteration count may
    # signal downgrade attack). We DO NOT use it to compute / attempt
    # any decryption.
    hmac_iterations: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Salt size in bytes (typically 16). We RECORD THE SIZE, NOT THE
    # BYTES — exposing the salt bytes would aid an attacker doing
    # offline cracking. NULL when the body preamble was absent.
    salt_size: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Length of the master-key BLOB section from the header. Typically
    # 200-400 bytes for active master-key files. Operators can spot
    # oversized blobs as anomalies.
    master_key_size: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Length of the backup-key section from the header. Typically 0 (no
    # backup) or 200-400 bytes when domain-backup is configured.
    backup_key_size: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Length of the credential-history section from the header.
    cred_hist_size: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Length of the domain-key section from the header.
    domain_key_size: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Total file size in bytes. Useful for spotting oversized files
    # (attacker-planted artefacts) AND for sanity-checking the sum of
    # section sizes against the actual on-disk size.
    file_size_bytes: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # File modification timestamp from ``os.stat()`` (NOT from any
    # FILETIME inside the body — we don't trust attacker-controllable
    # in-file fields for forensic-timeline purposes). NULL on stat
    # failure.
    last_modified_ts: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Anomaly flags — heuristic detection summary for the κ.D.D classifier.
    # Canonical shape (boolean bits + schema_version):
    #   {
    #     "schema_version": 1,
    #     "orphaned_masterkey": bool,    # creator_sid no match elsewhere
    #     "admin_creator_sid": bool,     # RID 500 / 512 / 519 / 18 match
    #     "large_masterkey": bool,       # file_size_bytes > 2048
    #     "parse_error": bool,           # file header parse failed
    #   }
    # Rule #35c stamped envelope.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Schema version of the binary format this row was parsed under
    # (DPAPI v1 / v2 — currently we accept both). Reserved for future
    # format support. NOT the JSONB schema_version — that lives in
    # anomaly_flags.
    schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="1"
    )

    # If the file's structured parse failed (truncated, malformed magic,
    # missing body preamble), record the error so operators can triage
    # without losing the row. The walker still emits the row (with
    # parse_error anomaly bit set) rather than silently skipping.
    parse_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        # "All DPAPI master-keys for firmware Y by master_key_guid" —
        # fast lookup for cross-firmware GUID joins.
        Index(
            "ix_windows_dpapi_master_keys_firmware_guid",
            "firmware_id",
            "master_key_guid",
        ),
        # "All DPAPI master-keys for firmware Y by creator_sid" —
        # insider-threat queries for "which keys did user X create?".
        Index(
            "ix_windows_dpapi_master_keys_firmware_sid",
            "firmware_id",
            "creator_sid",
        ),
        # "All DPAPI master-keys for firmware Y by last_modified_ts" —
        # timeline-correlation queries for incident response.
        Index(
            "ix_windows_dpapi_master_keys_firmware_modified",
            "firmware_id",
            "last_modified_ts",
        ),
    )
