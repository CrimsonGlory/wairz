"""Per-process Volatility 3 process record (Phase λ.β.A).

One row per de-duplicated process observation across the Vol3
``windows.pslist`` / ``windows.psscan`` / ``windows.pstree`` /
``windows.cmdline`` plugin family. The de-dup key is
``(memory_image_id, pid, image_filename, create_time)`` — a single
process appears in 1-3 of the four plugins (pslist + pstree see live
linked processes; psscan also sees DKOM-unlinked rootkit hides;
cmdline supplements with the full command line + image path).

The pslist/psscan **delta** is the highest-value forensic signal —
a row with ``seen_in_psscan=True AND seen_in_pslist=False`` is the
canonical T1014 Rootkit DKOM-unlink indicator (Persona-E HIGH —
the ``windows_unlinked_process`` source family is reserved for
walker emission downstream).

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
``get_detection_roots(firmware)`` before iterating
``memory_dump_image`` rows. The walker invokes
:func:`app.services.vol3_runner.run_vol3_plugin` per (image, plugin)
combination.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — process records are extracted by Vol3's pure-Python framework
from memory images parsed as data (struct unpack of EPROCESS
structures via OS-specific layer plugins). wairz NEVER invokes a
process image to confirm its identity; the rule extends to memory
forensics exactly as to PE / installer / driver-package parsing.

Per CLAUDE.md Rule #45 metadata-walker discipline: the per-process
``command_line`` column carries the full command-line string AS
DATA — wairz NEVER executes the command, never resolves the binary,
never expands environment variables at scan time. The string is
surfaced for operator review (and downstream finding-emit
correlation) only.

Per CLAUDE.md Rule #35c JSONB discipline: ``anomaly_flags`` is a
schema-versioned dict carrying derived properties (unlinked, orphan,
terminated, suspicious_path, etc.) computed at walker time so
downstream finding emitters don't need to re-derive them.

Indexes:

- ``ix_volatility_process_records_firmware_pid`` —
  ``(firmware_id, pid)`` covers the common "find PID 1234 across all
  images for this firmware" filter.
- ``ix_volatility_process_records_firmware_image_filename`` —
  ``(firmware_id, image_filename)`` covers the "find every powershell.exe
  / svchost.exe / cmd.exe" filter for cross-image process-name surveys.
- ``ix_volatility_process_records_memory_image_id`` —
  ``(memory_image_id,)`` covers the per-image process listing used
  by the MCP per-firmware tool.
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
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class VolatilityProcessRecord(Base):
    """One per de-duplicated process observation across pslist/psscan/pstree/cmdline."""

    __tablename__ = "volatility_process_records"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this image+process belongs to.
    # Cascade DELETE — removing a firmware row removes its process records.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # FK to the per-image row. Many processes belong to one memory image.
    memory_image_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("memory_dump_image.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Process ID from EPROCESS.UniqueProcessId. Win10 limits to 16-bit
    # for older builds and 32-bit for newer; Integer is sufficient.
    pid: Mapped[int] = mapped_column(Integer, nullable=False)

    # Parent process ID from EPROCESS.InheritedFromUniqueProcessId.
    # Nullable because the kernel's idle process (PID 0) has no parent
    # and Vol3 emits NULL for it.
    ppid: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ImageFileName from EPROCESS — a 15-char fixed-size field truncated
    # at the last null. Common values: "svchost.exe", "powershell.exe",
    # "cmd.exe", "explorer.exe". Stored as String(256) for safety
    # margin; real values are always <= 15.
    image_filename: Mapped[str] = mapped_column(String(256), nullable=False)

    # Full command line as extracted via windows.cmdline (NULL if the
    # cmdline plugin didn't see this process). Win32 command lines can
    # exceed 32 KB in extreme cases; Text is unbounded.
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Full image path as resolved via windows.cmdline (NULL if cmdline
    # didn't see this process). Example:
    # "C:\\Windows\\System32\\svchost.exe".
    image_path_full: Mapped[str | None] = mapped_column(
        String(1024), nullable=True
    )

    # Process creation time from EPROCESS.CreateTime. Nullable because
    # the kernel idle process has no create time.
    create_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Process exit time from EPROCESS.ExitTime — NULL for running
    # processes, non-NULL for terminated processes whose EPROCESS
    # structure is still resident (psscan finds these even after pslist
    # has unlinked them from the active-process list).
    exit_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Bitfield columns — which plugin(s) saw this process.
    seen_in_pslist: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=func.false()
    )
    seen_in_psscan: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=func.false()
    )
    seen_in_pstree: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=func.false()
    )

    # Derived anomaly flags computed at walker time. Schema-versioned
    # per Rule #35c. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "unlinked": bool,            # psscan-saw + pslist-missed (T1014)
    #     "terminated": bool,          # exit_time is not None
    #     "orphan": bool,              # ppid points to no observed parent
    #     "suspicious_path": bool,     # image_path_full outside System32/SysWOW64
    #   }
    anomaly_flags: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index(
            "ix_volatility_process_records_firmware_pid",
            "firmware_id",
            "pid",
        ),
        Index(
            "ix_volatility_process_records_firmware_image_filename",
            "firmware_id",
            "image_filename",
        ),
        Index(
            "ix_volatility_process_records_memory_image_id",
            "memory_image_id",
        ),
    )
