"""Per-file Windows EFS DDF/DRF metadata row (Phase ι.D.A — FOURTH ι, SECOND ι Windows).

One row per EFS-encrypted file located inside a Windows-firmware NTFS
volume extracted from a firmware capture. The Phase ι.D.C walker
identifies encrypted files via the ``FILE_ATTRIBUTE_ENCRYPTED`` bit
(0x4000) on the ``$STANDARD_INFORMATION`` attribute, reads the file's
``LOGGED_UTILITY_STREAM`` attribute (type 0x100) which carries the
``$EFS`` blob, and surfaces metadata about WHO CAN DECRYPT (DDF user
list) and WHO IS THE RECOVERY AGENT (DRF list).

**PARSE-ONLY discipline — Rule #36 + Rule #36 EXTENSION.** This table
captures metadata only. The walker NEVER:

- Decrypts the RSA-encrypted FEK (File Encryption Key).
- Attempts plaintext recovery of any encrypted file content.
- Invokes Windows DPAPI (``CryptUnprotectData``) or any equivalent.
- Imports cryptographic decryption modules (no ``cryptography.fernet``,
  no ``CryptUnprotectData`` shim, no DPAPI bindings).

The "who can decrypt + who is the recovery agent" surface is the
forensic value (T1486 ransomware variant when used at scale, T1564.001
insider stealth when an unauthorized SID appears in DDF, supply-chain
fingerprint when the same recovery agent thumbprint appears across
multiple supposedly-independent firmwares).

Real-world Persona-E EFS relevance:

- **SafeBreach 2020 PoC** — abused EFS for ransomware-like behaviour
  by encrypting victim files with attacker-controlled DDF, locking
  the legitimate user OUT of their own data.
- **Insider-threat patterns** — an unauthorized SID added to DDF on
  sensitive corporate files = silent exfiltration vector; the file
  appears normal to the file owner but is also decryptable by the
  insider.
- **Recovery agent supply-chain** — if the SAME DRF certificate
  thumbprint appears across multiple supposedly-independent customer
  firmware images, the implication is either a shared backdoor key
  (high-severity) or a vendor-default recovery configuration that
  was never re-keyed (medium-severity baseline review).

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. Multi-rootfs Windows firmware (VHDX
/ NTFS / FAT32 / system images) surfaces every NTFS volume candidate.

Per CLAUDE.md Rule #35c JSONB discipline: every JSONB column (``ddf_users``,
``drf_recovery_agents``, ``anomaly_flags``) carries its own normalizer
+ schema_version stamp; see ``app.services.jsonb_normalizers``.

ι.D.D finding emit leverages the parsed metadata to flag
adversary-residue indicators (orphaned DRF without DDF, unusual
recovery agent SIDs, domain admin SIDs in DDF, oversized DRF lists).

Reference for the $EFS blob format:

- Microsoft MS-EFSR open-spec, section [EFSR] EfsBlob + EFS_RSA_KEY_HASH_DATA
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/
- Wikipedia: Encrypting File System (Windows)
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


class WindowsEfsEncryptedFile(Base):
    """Per-file row decoded from the $EFS LOGGED_UTILITY_STREAM (DDF/DRF metadata only)."""

    __tablename__ = "windows_efs_encrypted_files"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this EFS file was located in.
    # Cascade DELETE so removing a firmware row removes its EFS metadata.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Absolute path inside the firmware NTFS volume (volume-local). E.g.
    # ``Users\\alice\\Documents\\secret.docx``. NULL when the orphan record
    # has no resolvable parent path.
    file_path: Mapped[str | None] = mapped_column(
        String(1024), nullable=True
    )

    # File size in bytes (the unnamed $DATA primary stream size).
    # NULL when the record has no $DATA attribute (rare — encrypted
    # directories or sparse oddities).
    file_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # MFT segment / record number — used for cross-correlation with the
    # η.A NTFS MFT walker output (operator can join EFS files to their
    # full MFT metadata via firmware_id + mft_record_number).
    mft_record_number: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )

    # Raw size of the $EFS LOGGED_UTILITY_STREAM attribute body in bytes.
    # Useful for forensic accounting + identifying outliers (typical
    # $EFS is 800-2000 bytes; a 50 KB $EFS is suspicious).
    efs_attribute_size: Mapped[int] = mapped_column(
        Integer, nullable=False
    )

    # Number of users in the DDF (Data Decryption Field). Typically 1
    # (the file owner is the only allowed decryptor); >1 indicates
    # shared decryption — could be legitimate ("share decryption with
    # bob@example.com") or insider stealth ("attacker added themselves
    # to the DDF").
    ddf_user_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    # Number of recovery agents in the DRF (Data Recovery Field).
    # Typically 0 (standalone Windows installs) to 2 (domain joined +
    # local recovery agent). >2 = unusual configuration; 0 paired with
    # absent corporate policy = potential disable-evidence.
    drf_recovery_agent_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    # DDF user list — per-user dicts with SID + cert thumbprint + optional
    # friendly name. Canonical shape:
    #   [
    #     {
    #       "sid": "S-1-5-21-...-1001",
    #       "cert_thumbprint": "0123456789abcdef..." (40-char SHA-1 hex),
    #       "friendly_name": str | null,
    #     },
    #     ...
    #   ]
    # Rule #35c stamped envelope.
    ddf_users: Mapped[list[dict] | None] = mapped_column(
        JSONB, nullable=True
    )

    # DRF recovery agent list — same shape as ddf_users. Empty list when
    # no recovery agents are configured for the file (standalone Win
    # installs with no domain policy).
    drf_recovery_agents: Mapped[list[dict] | None] = mapped_column(
        JSONB, nullable=True
    )

    # Anomaly flags — heuristic detection summary for the ι.D.D
    # classifier. Canonical shape (boolean bits + schema_version):
    #   {
    #     "schema_version": 1,
    #     "orphaned_drf": bool,
    #     "unusual_recovery_agent": bool,
    #     "multiple_ddf_users": bool,
    #     "large_drf": bool,
    #     "cert_thumbprint_anomaly": bool,
    #     "domain_admin_in_ddf": bool,
    #     "parse_error": bool,
    #   }
    # Rule #35c stamped envelope.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # If the $EFS blob couldn't be parsed (truncated, corrupted,
    # unrecognised wrapper format, etc.), record the error so operators
    # can review without losing the row. The walker still emits the
    # row (with parse_error anomaly bit set + ddf_user_count=0 /
    # drf_recovery_agent_count=0) rather than silently skipping.
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
        # "All EFS files for firmware Y by MFT record" — cross-correlation
        # with the η.A NTFS $MFT walker output.
        Index(
            "ix_windows_efs_encrypted_files_firmware_mft_record",
            "firmware_id",
            "mft_record_number",
        ),
        # "All EFS files for firmware Y with >N users in DDF" — quick
        # filter for shared-decryption candidates.
        Index(
            "ix_windows_efs_encrypted_files_firmware_ddf_count",
            "firmware_id",
            "ddf_user_count",
        ),
        # "All EFS files for firmware Y with >N recovery agents" — quick
        # filter for unusual DRF configurations.
        Index(
            "ix_windows_efs_encrypted_files_firmware_drf_count",
            "firmware_id",
            "drf_recovery_agent_count",
        ),
    )
