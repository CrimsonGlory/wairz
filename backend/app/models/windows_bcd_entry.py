"""Per-entry Windows Boot Configuration Data (BCD) row (Phase θ.A.A).

One row per parsed BCD ``Objects/{guid}`` entry from a BCD store
extracted from a firmware capture. Captures forensic-triage metadata:
per-entry description, image path (bootloader binary), application
device (partition GUID + disk GUID), object type discriminator,
testsigning / no-integrity-checks security flags, custom element
roster (the elements table not promoted to flat columns), parent
{globalsettings}/{bootmgr}/{dbgsettings}/{ramdiskoptions} aggregator
linkage, anomaly flags from heuristic detection (suspicious path,
non-Microsoft description, unsigned bootloader, hidden entry).

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. BCD stores live as files named
``BCD`` (no extension) typically under ``Boot/`` or
``EFI/Microsoft/Boot/`` partition prefixes of the extracted firmware.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker treats BCD stores as untrusted REGF input via
regipy (a pure-Python parser; no shell-out, no
``reg.exe`` / ``bcdedit`` invocation). The parsed image_path is
surfaced for operator review; the bootloader binary referenced by
the entry is NEVER loaded, invoked, or executed.

Per CLAUDE.md Rule #35c JSONB discipline: both JSONB columns
(``custom_elements`` and ``anomaly_flags``) carry their own
normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``
``_normalize_windows_bcd_entries_custom_elements`` /
``_stamp_windows_bcd_entries_custom_elements`` and
``_normalize_windows_bcd_entries_anomaly_flags`` /
``_stamp_windows_bcd_entries_anomaly_flags``. The flat columns
(description / image_path / GUIDs / signing flags) are materialized
for fast indexed lookup; the JSONB columns carry the per-entry
custom element roster + the heuristic detection flag aggregate.

θ.A.D finding emit (windows_bcd_suspicious_path +
windows_bcd_testsigning_enabled) leverages the parsed data to flag:

- Suspicious bootloader path — image_path NOT under ``Windows\\`` /
  ``Boot\\`` / ``EFI\\Microsoft\\`` AND description is non-Microsoft.
  MEDIUM confidence (path heuristic alone), HIGH when paired with
  testsigning enabled or anomalous parent.
- TestSigning enabled — the ``{globalsettings}`` entry carries
  TestSigning=Yes (or any boot entry with 0x16000010 TestSigning
  element set true). MEDIUM confidence baseline; HIGH if the boot
  application is a non-Microsoft signed binary OR unsigned.

Reference for BCD element types:
https://www.geoffchappell.com/notes/windows/boot/bcd/elements.htm
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsBcdEntry(Base):
    """Per-BCD-object row from a walked BCD store."""

    __tablename__ = "windows_bcd_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this BCD store was parsed
    # from. Cascade DELETE so removing a firmware row removes its BCD
    # entries.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Path to the BCD store file within the detection root (Rule #16).
    # Stored relative for stable cross-extraction identifiers.
    # E.g. ``Boot/BCD`` or ``EFI/Microsoft/Boot/BCD``.
    source_path: Mapped[str] = mapped_column(String(2048), nullable=False)

    # BCD object identifier — the GUID under ``\Objects\``. The canonical
    # well-known GUIDs include:
    #   {9dea862c-5cdd-4e70-acc1-f32b344d4795} = {bootmgr}
    #   {fa926493-6f1c-4193-a414-58f0b2456d1e} = {memdiag}
    #   {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e} = {emssettings}
    #   {7ff607e0-4395-11db-b0de-0800200c9a66} = {hypervisorsettings}
    #   {0ce4991b-e6b3-4b16-b23c-5e0d9250e5d9} = {eventsettings}
    #   {9dea862c-5cdd-4e70-acc1-f32b344d4795} = {bootmgr}
    #   {fa926493-6f1c-4193-a414-58f0b2456d1e} = {memdiag}
    #   {7254a080-1510-4e85-ac0f-e7fb3d444736} = {dbgsettings}
    #   {a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba} = {globalsettings}
    # Non-well-known GUIDs are the per-boot-entry IDs (Windows Boot
    # Loader OS entry, recovery entry, etc.). Stored verbatim from the
    # NKRecord.name field.
    object_guid: Mapped[str] = mapped_column(String(64), nullable=False)

    # BCD object type discriminator (Description/Type value at
    # ``Objects/{guid}/Description/Type``). Per
    # https://www.geoffchappell.com/notes/windows/boot/bcd/objects.htm,
    # this is a 32-bit value combining object class (boot mgr / boot
    # loader / boot settings / boot resume / boot service / application
    # / device option) + image type + application class. Stored as
    # BigInt-ish via Integer (the value fits in 32 bits) but kept
    # nullable because some entries (well-known IDs) may not have a
    # Description subkey.
    object_type: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Application description (BCD element 0x12000004 — UTF-16 string).
    # E.g. "Windows Boot Manager", "Windows 10", "Microsoft Windows
    # Recovery Environment", "Ubuntu". A suspicious description string
    # (non-ASCII / atypical / contains script-host hint) is a θ.A.D
    # anomaly signal. NULL when the entry has no Description element.
    description: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )

    # Application path (BCD element 0x12000002 — UTF-16 string). The
    # bootloader binary path within the application device's filesystem.
    # E.g. "\\Windows\\System32\\winload.efi",
    # "\\Boot\\BCD", "\\EFI\\Microsoft\\Boot\\bootmgfw.efi". Mismatched
    # paths (outside the known-good roots) are a θ.A.D suspicious-path
    # signal. NULL when the entry has no ApplicationPath element.
    image_path: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )

    # GPT partition GUID (parsed from the ApplicationDevice element
    # 0x11000001 — bytes [32:48] of the device blob). Identifies which
    # disk partition the bootloader lives on. NULL when the element is
    # missing, the device blob is shorter than 72 bytes (non-GPT
    # encoding), or parsing failed.
    gpt_partition_guid: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # GPT disk GUID (parsed from the ApplicationDevice element
    # 0x11000001 — bytes [56:72] of the device blob). Identifies which
    # disk the partition lives on. NULL conditions same as
    # gpt_partition_guid.
    gpt_disk_guid: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # TestSigning policy element (BCD 0x16000010 — boolean). When True,
    # Windows boots with TestSigning enabled — kernel-mode drivers
    # signed by self-signed test certificates are accepted. Common
    # bootkit / BYOVD precursor. NULL when the element is absent.
    testsigning: Mapped[bool | None] = mapped_column(
        Boolean, nullable=True
    )

    # NoIntegrityChecks element (BCD 0x16000048 — boolean). Disables
    # Driver Signing Enforcement. NULL when absent.
    no_integrity_checks: Mapped[bool | None] = mapped_column(
        Boolean, nullable=True
    )

    # NX policy element (BCD 0x25000020 — DWORD). Values: 0=OptIn,
    # 1=OptOut, 2=AlwaysOff, 3=AlwaysOn. AlwaysOff (2) disables DEP,
    # commonly seen in pre-Vista bootkits. NULL when absent.
    nx_policy: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Custom elements roster — additional BCD elements not promoted to
    # flat columns. Canonical shape:
    #   [
    #     {
    #       "schema_version": 1,
    #       "element_type": "0x14000006",  # hex string of BCD element type
    #       "element_value": str | int | bool | list[str] | None,
    #     },
    #     ...
    #   ]
    # Empty list when no extra elements; NULL only on defensive parser
    # failure. Rule #35c stamped envelope. Includes DisplayOrder
    # (0x14000006 — list of boot-entry GUIDs), DefaultObject
    # (0x23000003), and any vendor-specific or attacker-planted
    # elements.
    custom_elements: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # Anomaly flags — heuristic detection summary for the θ.A.D
    # classifier. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "suspicious_path": bool,
    #     "non_microsoft_description": bool,
    #     "testsigning_enabled": bool,
    #     "no_integrity_checks": bool,
    #     "nx_disabled": bool,
    #     "is_default_boot": bool,
    #   }
    # NULL when no anomaly evaluation was performed (rare — defensive
    # shape). Rule #35c stamped envelope.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Last-modified timestamp from the NKRecord header (FILETIME ns).
    # Stored as BigInt-ish via Integer→too small; use String for the
    # ISO-8601 rendering to keep the migration small, OR use BigInteger.
    # Going with BigInteger for ns precision matching the η.A approach.
    # NULL when the parser can't expose the timestamp.
    last_modified_ns: Mapped[int | None] = mapped_column(
        # BigInteger import would add a dep; reuse Integer via cast
        # at write site OR use String. Going with String for the
        # ISO-8601 rendering — simpler at read sites and matches the
        # forensic-UX shape (NKRecord.last_modified is FILETIME).
        String(64), nullable=True
    )

    # Walker run timestamp — when this row was inserted. Distinct from
    # last_modified_ns (which describes the BCD entry's lineage).
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # "All BCD entries for firmware Y" — the canonical triage query.
        Index(
            "ix_windows_bcd_entries_firmware",
            "firmware_id",
        ),
        # "All BCD entries for firmware Y, by GUID" — the natural lookup
        # key for "show me the {bootmgr} entry of this BCD".
        Index(
            "ix_windows_bcd_entries_firmware_guid",
            "firmware_id",
            "object_guid",
        ),
        # "All BCD entries with testsigning enabled across all firmware"
        # — the θ.A.D anomaly-search query shape (also useful for
        # cross-firmware bootkit detection sweeps).
        Index(
            "ix_windows_bcd_entries_firmware_testsigning",
            "firmware_id",
            "testsigning",
        ),
    )
