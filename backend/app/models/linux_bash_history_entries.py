"""Per-line Linux bash_history row (Phase κ.C.A — EIGHTH κ-era walker).

One row per parsed line from a Linux ``.bash_history`` text file
discovered in a firmware extraction (e.g. ``/root/.bash_history``,
``/home/<user>/.bash_history``). The κ.C.C walker walks every detection
root (per Rule #16), locates bash_history candidates, decodes with
``errors='replace'`` for robustness against non-UTF8 bytes, splits into
lines, and persists one row per non-empty line.

**Real-world Persona-E bash_history relevance (forensic gold for T1059):**

- bash_history records every interactive shell command a user typed (when
  HISTSIZE/HISTFILE haven't been zeroed). Adversaries with shell access
  leave first-hand evidence of their staging, recon, and exfil tradecraft.
  When the adversary tries to clean up (``history -c``, ``> ~/.bash_history``),
  the cleanup attempt itself surfaces in the historical entries on disk.

- **Persona-E patterns surfaced by κ.C.D classifier (3 anomaly bits):**

  - ``clear_marker``: line matches ``history -c`` / ``> ~/.bash_history`` /
    ``: > ~/.bash_history`` / ``rm -f ~/.bash_history``. T1070.003
    (Indicator Removal: Clear Command History) — Persona-E HIGH.

  - ``download_pattern``: line contains ``wget`` / ``curl`` + URL + ``| sh`` /
    ``| bash`` (ingress-tool-transfer pipe-to-shell). T1105 (Ingress Tool
    Transfer) — Persona-E HIGH.

  - ``priv_esc_pattern``: line contains ``sudo su -`` / ``sudo -i`` /
    ``chmod +s`` / ``setuid`` invocations. T1548.003 (Sudo and Sudo Caching)
    + T1222.002 (File and Directory Permissions Modification) — Persona-E
    MEDIUM.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. bash_history candidates can live in
multiple rootfs (squashfs + tar.xz + ramdisk image).

Per CLAUDE.md Rule #35c JSONB discipline: the ``suspicious_flags`` JSONB
column gets a dedicated normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #36 (no-execute discipline): the κ.C.C walker reads
bash_history files AS TEXT, splits into lines, and emits rows. NO
``bash`` invocation, NO ``source`` of the file, NO shell substitution.
The walker's source is tokenized against forbidden invocation tokens
in ``test_linux_persistence_walker.py::test_walker_no_execute``.

κ.C.D finding emit (``linux_bash_history_clear``) leverages
``clear_marker`` for T1070.003 detection — the act of trying to clear
history leaves the cleanup command in the historical entries below.
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
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class LinuxBashHistoryEntry(Base):
    """Per-line row decoded from a Linux ``.bash_history`` text file.

    PARSE-ONLY discipline (Rule #36): rows surface command-line history
    METADATA only — line + line_number + suspicious_flags. The walker
    NEVER invokes the parsed command; operators triage commands as DATA.
    """

    __tablename__ = "linux_bash_history_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this bash_history line came
    # from. Cascade DELETE so removing a firmware row removes its
    # bash_history rows.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relative path within the detection root to the source bash_history
    # file. Stored RELATIVE for stable cross-extraction identifiers. E.g.
    # ``root/.bash_history`` or ``home/admin/.bash_history``.
    source_file: Mapped[str] = mapped_column(
        String(2048), nullable=False
    )

    # 1-indexed line number within the source file. Useful for operator
    # cross-reference against the raw file and for stable ordering when
    # paginating results.
    line_number: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    # The command line as recorded. Truncated to 4096 chars defensive
    # against malformed / attacker-planted multi-MB lines.
    command: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Suspicious-flags JSONB — heuristic detection summary for the κ.C.D
    # classifier. Canonical shape (boolean bits + schema_version):
    #   {
    #     "schema_version": 1,
    #     "clear_marker": bool,        # T1070.003 clear-history attempt
    #     "download_pattern": bool,    # T1105 ingress-tool-transfer
    #     "priv_esc_pattern": bool,    # T1548.003 / T1222.002 priv-esc
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
        # "All bash_history entries for firmware Y by source_file then
        # line_number" — covers per-file iteration + pagination.
        Index(
            "ix_linux_bash_history_entries_firmware_source_line",
            "firmware_id",
            "source_file",
            "line_number",
        ),
    )
