"""Per-detection Volatility 3 injection record (Phase λ.γ.A).

One row per detection across the Vol3 ``windows.malware.*`` plugin
family that the λ.γ walker invokes:

- ``windows.malware.malfind`` — injected code regions in process VAD
  (RWX private memory; classic shellcode injection T1055.001 /
  Reflective DLL Injection T1055.002).
- ``windows.malware.hollowprocesses`` — process-hollowing T1055.012
  (PEB ImagePathName diverges from EPROCESS ImageFileName / file on
  disk).
- ``windows.malware.ldrmodules`` — module-list discrepancy T1055
  (module present in some LDR lists, missing from others).
- ``windows.malware.processghosting`` — process-ghosting T1055.013
  (image_path resolves to a deleted file).
- ``windows.malware.pebmasquerade`` — PEB string masquerading T1055
  (PEB ImagePathName overwritten to look like a different process).

The ``hexdump_sha256`` column is the **Rule #44 cross-firmware
identity key** — SHA256 of the canonicalised first 64 bytes of an
``injected_code_region`` detection's hexdump. The same injection
appearing across multiple firmware images hashes to the same value,
revealing supply-chain or threat-actor TTP-reuse signal that no other
walker provides at the same fidelity.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — detection records come from Vol3's pure-Python framework
(layer reads + struct unpack); wairz NEVER attempts to deobfuscate
injected code, NEVER patches a process, NEVER instantiates a region
for execution. The walker is strict PARSE-ONLY.

Per CLAUDE.md Rule #45 metadata-walker discipline: hexdumps, paths,
and region metadata are surfaced AS DATA. The downstream finding-emit
hook (deferred to a future λ.γ.E commit) maps detection_kind to
``vol3_<kind>`` source values.

Per CLAUDE.md Rule #35c JSONB discipline: ``evidence`` is a
schema-versioned dict carrying per-detection extra context — Vol3
emits different fields per plugin (Protection, Hexdump, BasePath,
InLoad/InInit/InMem booleans, MissingFromList, etc.); rather than
adding a column for every plugin's idiosyncrasy, we capture the
plugin-specific payload here.

Indexes:

- ``ix_volatility_injection_records_firmware_kind`` —
  ``(firmware_id, detection_kind)`` covers the operator filter
  "show me every injected_code_region for this firmware".
- ``ix_volatility_injection_records_firmware_pid`` —
  ``(firmware_id, pid)`` covers cross-plugin per-PID joins (a
  hollowed process often has injected regions too).
- ``ix_volatility_injection_records_memory_image_id`` —
  ``(memory_image_id,)`` covers the per-image detection listing.
- ``ix_volatility_injection_records_hexdump_sha256`` —
  ``(hexdump_sha256,)`` covers the cross-firmware aggregation key
  used by the Rule #44 MCP tool.
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
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class VolatilityInjectionRecord(Base):
    """One per detection across the windows.malware.* plugin family."""

    __tablename__ = "volatility_injection_records"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    memory_image_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("memory_dump_image.id", ondelete="CASCADE"),
        nullable=False,
    )

    # One of: 'injected_code_region', 'hollow_process', 'unlinked_module',
    # 'peb_masquerade', 'ghosted_process'. CHECK enforced at DB level.
    detection_kind: Mapped[str] = mapped_column(String(32), nullable=False)

    # Full Vol3 plugin name — 'windows.malware.malfind' etc. PINNED to
    # the ``windows.malware.<X>`` namespace per the 2026-06-07
    # deprecation (top-level paths removed at that date).
    detected_by_plugin: Mapped[str] = mapped_column(String(64), nullable=False)

    pid: Mapped[int] = mapped_column(Integer, nullable=False)

    image_filename: Mapped[str] = mapped_column(String(256), nullable=False)

    # Region metadata — set for injected_code_region + peb_masquerade.
    region_address: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    region_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    region_protection: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )

    # First 64 bytes of malfind's Hexdump field, canonicalised as
    # "01 02 03 ..." spaced-hex pairs (lower-case). String(256) is
    # safety margin (64 * 3 = 192 chars; gives 64 chars headroom).
    hexdump_first_64_bytes: Mapped[str | None] = mapped_column(
        String(256), nullable=True
    )

    # SHA256 of the canonicalised hexdump_first_64_bytes. The **Rule
    # #44 cross-firmware identity key** — lookup via
    # lookup_volatility_injection_across_firmwares joins on this.
    hexdump_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Process-hollowing + PEB-masquerade: the path the PEB claims
    # the process runs as.
    masquerade_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Process-hollowing: the path EPROCESS actually points at (the
    # delta from masquerade_path is the canonical hollow indicator).
    actual_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # ldrmodules: the module name that's missing from at least one
    # LDR list (T1055 supporting indicator).
    module_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # processghosting: the image path that's been deleted from disk.
    ghosted_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Schema-versioned per-plugin payload. Canonical shape varies by
    # detection_kind; see jsonb_normalizers._normalize_volatility_
    # injection_records_evidence for the full per-kind contract.
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index(
            "ix_volatility_injection_records_firmware_kind",
            "firmware_id",
            "detection_kind",
        ),
        Index(
            "ix_volatility_injection_records_firmware_pid",
            "firmware_id",
            "pid",
        ),
        Index(
            "ix_volatility_injection_records_memory_image_id",
            "memory_image_id",
        ),
        Index(
            "ix_volatility_injection_records_hexdump_sha256",
            "hexdump_sha256",
        ),
    )
