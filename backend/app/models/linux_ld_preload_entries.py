"""Per-line Linux ld.so.preload row (Phase κ.C.A — EIGHTH κ-era walker).

One row per parsed line from a Linux ``ld.so.preload`` text file
discovered in a firmware extraction. Sources covered:

- ``/etc/ld.so.preload`` — system-wide LD_PRELOAD list (newline-separated
  library paths; loaded into every dynamically-linked process).
- ``~/<user>/.ld.so.preload`` — historical per-user (rare; mostly seen
  on legacy systems).

**Real-world Persona-E ld.so.preload relevance (T1574.006 — TOP TIER):**

- ``/etc/ld.so.preload`` is the canonical dynamic-linker hijack target
  on Linux. Every dynamically-linked process loaded after the file is
  written gets the listed libraries injected BEFORE its own dependencies
  resolve — adversary library functions can shadow libc functions (open,
  read, write) and hide files / processes / network connections from
  every userspace tool. Classic rootkits using this: ``libprocesshider``,
  Diamorphine variants, Reptile.

- **Persona-E patterns surfaced by κ.C.D classifier (3 anomaly bits):**

  - ``temp_path_library``: library_path under ``/tmp/`` / ``/dev/shm/``
    / ``/var/tmp/``. T1574.006 + T1027 — Persona-E HIGH.

  - ``unusual_extension``: library doesn't end in ``.so`` or
    ``.so.<digit>`` (typical shared-object naming). Adversaries
    occasionally use ``.dat`` / ``.png`` / no-extension for blending.
    T1036 Masquerading — Persona-E MEDIUM.

  - ``world_writable_dir``: library_path in a known world-writable
    directory pattern (``/tmp``, ``/var/tmp``, ``/dev/shm``, ``/run/shm``).
    Independent risk from temp_path_library — distinguishes "in /tmp/"
    from "writable by anyone elsewhere". Persona-E MEDIUM.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone.

Per CLAUDE.md Rule #35c JSONB discipline: the ``suspicious_flags`` JSONB
column gets a dedicated normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #36 (no-execute discipline): the κ.C.C walker reads
ld.so.preload files AS TEXT and splits into lines. NO ``ldconfig``
invocation, NO library loading, NO ``ldd`` inspection of the listed
paths. The walker's source is tokenized against forbidden invocation
tokens in ``test_linux_persistence_walker.py``.

κ.C.D finding emit (``linux_ld_preload_hijack``) — ANY entry in a
discovered ld.so.preload file warrants operator review; the file is
inherently sensitive. Suspicious-flags raise the priority.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class LinuxLdPreloadEntry(Base):
    """Per-line row decoded from a Linux ``ld.so.preload`` text file.

    PARSE-ONLY discipline (Rule #36): rows surface dynamic-linker hijack
    METADATA only — library_path + suspicious_flags. The walker NEVER
    loads any listed library, NEVER invokes ``ldconfig``.
    """

    __tablename__ = "linux_ld_preload_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this ld.so.preload line came
    # from. Cascade DELETE so removing a firmware row removes its rows.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relative path within the detection root to the source preload
    # file. Stored RELATIVE for stable cross-extraction identifiers.
    # E.g. ``etc/ld.so.preload``.
    source_file: Mapped[str] = mapped_column(
        String(2048), nullable=False
    )

    # 1-indexed line number within the source file.
    line_number: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    # The library path on each line — typically an absolute path like
    # ``/usr/lib/libfoo.so`` or ``/tmp/evil.so``. Truncated to 2048
    # chars defensive.
    library_path: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )

    # Suspicious-flags JSONB — heuristic detection summary for the κ.C.D
    # classifier. Canonical shape (boolean bits + schema_version):
    #   {
    #     "schema_version": 1,
    #     "temp_path_library": bool,    # /tmp/, /dev/shm/, ...
    #     "unusual_extension": bool,    # not .so / .so.<digit>
    #     "world_writable_dir": bool,   # known world-writable dir
    #   }
    # Rule #35c stamped envelope.
    suspicious_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

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
        # "All ld.so.preload entries for firmware Y by source_file then
        # line_number" — covers per-file iteration + pagination.
        Index(
            "ix_linux_ld_preload_entries_firmware_source_line",
            "firmware_id",
            "source_file",
            "line_number",
        ),
    )
