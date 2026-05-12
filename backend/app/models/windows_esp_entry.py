"""Per-`.efi` PE Windows EFI System Partition (ESP) row (Phase θ.C.A).

One row per parsed `.efi` PE32+ file extracted from the EFI System
Partition (ESP — FAT32 partition typically mounted at ``/boot/efi`` on
Linux extractions OR ``EFI/`` at the partition root on raw extractions)
of a firmware capture. Captures forensic-triage metadata for the boot-
chain integrity scan (θ.C):

- The relative file path within the detection root (Rule #16).
- SHA256 of the `.efi` file contents (the canonical cross-firmware
  identifier — same hash across multiple firmware ⇒ same bootloader
  artifact planted; see ``lookup_esp_chain`` MCP tool).
- File size in bytes (small `.efi` < 64 KB is an early bootkit
  signal — most legitimate `.efi` binaries are 100 KB – 4 MB).
- Authenticode state (signed_valid / signed_expired / signed_revoked /
  unsigned / parse_failed) — derived from the β.4 ``verify_pe_file``
  Authenticode pipeline + the β.10 DBX revocation cross-reference.
- Authenticode chain summary JSONB (signer subject + leaf serial +
  signed_at + chain_status from signify).
- DBX revocation match JSONB (NULL when no match; canonical dict
  shape from β.10 ``match_dbx_revocation`` on hit).
- Anomaly flags JSONB (heuristic detection summary: unsigned,
  expired, revoked, non_microsoft_signer, suspicious_path).
- Fingerprint sha256 (cross-firmware aggregation surface — same
  fingerprint across firmware ⇒ same .efi shape was planted).

**T1542.003 Pre-OS Boot: Bootkit** — adversaries (BlackLotus,
MoonBounce, CosmicStrand, Bootkitty) drop unsigned / revoked `.efi`
binaries into the ESP for pre-OS persistence. The ESP is a FAT32
partition mounted by the UEFI firmware BEFORE any OS code runs; a
modified bootmgfw.efi / shimx64.efi / grubx64.efi survives reboot at
the highest privilege level (Ring -2). The detection focus:

- **Unsigned `.efi`** in known-bootloader paths
  (``EFI/Boot/bootx64.efi`` / ``EFI/Microsoft/Boot/bootmgfw.efi`` /
  ``EFI/<vendor>/...``) is a strong bootkit signal.
- **DBX-revoked `.efi`** — Microsoft's revocation list bundles
  hashes / certificate-serials of known-bad bootloaders (the
  BlackLotus revocation, the GRUB2 BootHole revocation, etc.). A
  ``dbx_revoked=true`` hit ⇒ the binary will fail Secure Boot
  enforcement on a current-patch UEFI install.
- **Signed by non-Microsoft / non-Linux-vendor** — most legitimate
  ESP `.efi` files chain to Microsoft Corporation UEFI CA 2011 (or
  newer Microsoft UEFI CA 2023), Red Hat, Canonical, SUSE, Debian.
  An unknown signer is a triage candidate.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. ESP partitions surface differently
across firmware unpackers (FAT32 mount, raw partition image,
``EFI/`` directory at the root of an extracted UEFI capsule, etc.);
the multi-root discipline catches all forms.

**Per CLAUDE.md Rule #36 no-execute discipline**: this table holds
DATA only. The walker treats `.efi` binaries as untrusted PE32+
input via the β.4 signify Authenticode chain validator + the β.10
DBX matcher + pefile metadata. NO code path in wairz invokes wine /
mono / qemu-system / chainloader against the persisted `.efi` files.
The PE is parsed AS DATA (signify reads the certificate table; pefile
reads the COFF header), but never loaded into an executable mapping
or transferred control to. The test gate
``tests/test_esp_walker.py::test_esp_no_efi_execution`` asserts this
discipline programmatically.

Per CLAUDE.md Rule #35c JSONB discipline: all three JSONB columns
(``authenticode_chain``, ``dbx_revocation_match``, ``anomaly_flags``)
carry their own normaliser + schema_version stamp; see
``app.services.jsonb_normalizers``:

- ``_normalize_windows_esp_entries_authenticode_chain`` /
  ``_stamp_windows_esp_entries_authenticode_chain``
- ``_normalize_windows_esp_entries_dbx_revocation_match`` /
  ``_stamp_windows_esp_entries_dbx_revocation_match``
- ``_normalize_windows_esp_entries_anomaly_flags`` /
  ``_stamp_windows_esp_entries_anomaly_flags``

The flat columns (file_path / file_sha256 / file_size /
authenticode_state / fingerprint_sha256) are materialized for fast
indexed lookup; the JSONB columns carry the per-entry chain detail +
revocation evidence + heuristic detection flag aggregate.

θ.C.D finding emit (``windows_esp_unsigned`` +
``windows_esp_dbx_revoked``) leverages the parsed data to flag:

- **windows_esp_unsigned** — `.efi` file under a known-bootloader
  path with authenticode_state=unsigned. Confidence tier mapping:

  - HIGH (Confidence.high) — unsigned `.efi` AND path matches the
    canonical OS-bootloader paths (``EFI/Boot/bootx64.efi``,
    ``EFI/Microsoft/Boot/bootmgfw.efi``). BlackLotus / Bootkitty
    canonical bootkit shape.
  - MEDIUM (Confidence.medium) — unsigned `.efi` AND path is under
    a vendor-specific ``EFI/<vendor>/`` directory.

- **windows_esp_dbx_revoked** — `.efi` file whose Authenticode chain
  matched the DBX revocation list. Confidence tier mapping:

  - HIGH (Confidence.high) — DBX-revoked AND signed at file-sha256
    OR leaf-serial level. Microsoft has explicitly revoked this
    bootloader; on Secure Boot it would fail enforcement.

Reference for ESP / EFI architecture:
- UEFI Specification 2.10 §13 (Boot Manager)
- Microsoft Secure Boot:
  https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot
- BlackLotus analysis (ESET 2023): https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsEspEntry(Base):
    """Per-`.efi` row from a walked EFI System Partition."""

    __tablename__ = "windows_esp_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this `.efi` was parsed from.
    # Cascade DELETE so removing a firmware row removes its ESP entries.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relative path to the `.efi` file within the detection root
    # (Rule #16). Stored relative for stable cross-extraction
    # identifiers. E.g. ``EFI/Boot/bootx64.efi`` or
    # ``EFI/Microsoft/Boot/bootmgfw.efi``.
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)

    # SHA256 of the .efi file contents (canonical cross-firmware
    # identifier). 64 hex chars.
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # File size in bytes. BigInteger because legitimate .efi files
    # can reach a few MB (winload.efi is ~4-8 MB on Win11).
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Authenticode state discriminator. One of:
    # - signed_valid — signify chain_status == "valid_now" /
    #   "valid_at_signing".
    # - signed_expired — chain validates but timestamp is past +
    #   no countersigner OR countersigner outside validity window.
    # - signed_revoked — DBX revocation hit OR chain_status ==
    #   "revoked".
    # - unsigned — no Authenticode signature present.
    # - parse_failed — signify / pefile raised on the file; the
    #   binary may be truncated / non-PE / malformed.
    # CHECK constraint enforces the 5-state enum in the alembic
    # migration; the Literal mirror in app/schemas/windows_esp.py
    # type-checks at the API boundary.
    authenticode_state: Mapped[str] = mapped_column(
        String(32), nullable=False
    )

    # Authenticode chain summary JSONB. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "signed": bool,
    #     "chain_status": str,         # signify ChainStatus literal
    #     "signer_subject": str | None,
    #     "signer_issuer": str | None,
    #     "leaf_serial": str | None,
    #     "sig_hash_algo": str | None,
    #     "signed_at": str | None,     # ISO-8601 from countersigner
    #     "signatures_count": int,
    #     "error": str | None,
    #   }
    # NULL only on defensive parser-failure paths where signify
    # didn't return a verdict at all. Empty dict on unsigned PEs.
    authenticode_chain: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # DBX revocation match JSONB. NULL when no DBX match was made
    # (either bundle wasn't provisioned per β.10 deferral OR the leaf
    # serial wasn't revoked). Canonical shape on a hit:
    #   {
    #     "schema_version": 1,
    #     "revoked": bool,
    #     "revocation_kb": str | None,
    #     "leaf_serial_normalized": str,
    #     "match_kind": str,           # "x509_serial" | "sha256"
    #     "bundle_entries": int,
    #     "bundle_path": str,
    #   }
    # Sourced verbatim from ``app.services.dbx_service.match_dbx_revocation``.
    dbx_revocation_match: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Anomaly flags — heuristic detection summary for the θ.C.D
    # classifier. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "is_unsigned": bool,
    #     "is_expired": bool,
    #     "is_revoked": bool,
    #     "is_non_microsoft_signer": bool,
    #     "is_known_bootloader_path": bool,
    #     "is_vendor_path": bool,
    #     "is_suspiciously_small": bool,    # file_size < 4 KB
    #   }
    # NULL only on defensive parser-failure paths.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # SHA256 fingerprint of the canonical entry tuple
    # (file_path_lower + file_sha256 + authenticode_state) for
    # cross-firmware aggregation in ``lookup_esp_chain`` MCP tool.
    # Same fingerprint across firmware ⇒ same `.efi` shape was
    # planted (BlackLotus / Bootkitty correlation across the wairz
    # corpus). NULL on defensive parser-failure paths.
    fingerprint_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Walker run timestamp — when this row was inserted.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # "All ESP entries for firmware Y" — canonical triage.
        Index(
            "ix_windows_esp_entries_firmware",
            "firmware_id",
        ),
        # "All ESP entries for firmware Y, by sha256" — natural lookup
        # for "show me the bootmgfw.efi hash for this firmware".
        Index(
            "ix_windows_esp_entries_firmware_sha256",
            "firmware_id",
            "file_sha256",
        ),
        # "All ESP entries matching this fingerprint across all
        # firmware" — the lookup_esp_chain MCP tool's query shape
        # (cross-firmware aggregation for boot-chain hunt).
        Index(
            "ix_windows_esp_entries_fingerprint",
            "fingerprint_sha256",
        ),
        # "All unsigned-or-revoked ESP entries for firmware Y" — the
        # anomaly-focused MCP search filter.
        Index(
            "ix_windows_esp_entries_firmware_state",
            "firmware_id",
            "authenticode_state",
        ),
    )
