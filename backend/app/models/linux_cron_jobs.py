"""Per-line Linux crontab row (Phase κ.C.A — EIGHTH κ-era walker).

One row per parsed line from a Linux crontab text file discovered in a
firmware extraction. Sources covered:

- ``/etc/crontab`` — system-wide crontab with user field
- ``/etc/cron.d/*`` — drop-in crontab files (also user field)
- ``/var/spool/cron/<user>`` — per-user crontab (user inferred from
  filename; no user field in the lines themselves)
- ``/var/spool/cron/crontabs/<user>`` — Debian/Ubuntu per-user crontab
- ``/etc/cron.{hourly,daily,weekly,monthly}/*`` — script directories
  (each file is the script itself, no schedule line; we DO NOT emit
  rows for these; the κ.C.C walker focuses on schedule-line crontabs)

**Real-world Persona-E crontab relevance (T1053.003 + persistence):**

- crontab provides reliable, schedule-driven re-execution that survives
  reboot. Adversary patterns:
  - ``@reboot`` + ExecStart from ``/tmp/`` / ``/dev/shm/`` (staged
    payload pinned to reboot).
  - Tight schedules (``* * * * *``) for beacon callbacks.
  - Crontab entries pulling fresh payload via ``curl | sh`` (continuous
    delivery from C2).

- **Persona-E patterns surfaced by κ.C.D classifier (3 anomaly bits):**

  - ``temp_path_command``: command runs a binary from ``/tmp/`` /
    ``/dev/shm/`` / ``/var/tmp/`` / ``/run/shm/``. T1543.002 / T1053.003
    canonical adversary-staging — Persona-E HIGH.

  - ``reboot_persistence``: schedule_spec includes ``@reboot``. Boot-time
    re-execution. T1547 (Boot or Logon Autostart Execution) — Persona-E
    MEDIUM.

  - ``network_egress_pattern``: command pipes through ``curl`` / ``wget`` /
    ``nc`` (network-fetch primitive in a scheduled context). T1105 +
    T1071 — Persona-E MEDIUM.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone.

Per CLAUDE.md Rule #35c JSONB discipline: the ``suspicious_flags`` JSONB
column gets a dedicated normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #36 (no-execute discipline): the κ.C.C walker reads
crontab files AS TEXT, splits into lines, parses schedule + command via
pure-Python string ops. NO ``crontab`` CLI invocation, NO ``cron``
daemon interaction. The walker's source is tokenized against forbidden
invocation tokens in ``test_linux_persistence_walker.py``.
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


class LinuxCronJob(Base):
    """Per-line row decoded from a Linux crontab text file.

    PARSE-ONLY discipline (Rule #36): rows surface scheduled-command
    METADATA only — schedule + command + suspicious_flags. The walker
    NEVER invokes the parsed command.
    """

    __tablename__ = "linux_cron_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this crontab line came from.
    # Cascade DELETE so removing a firmware row removes its cron rows.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relative path within the detection root to the source crontab
    # file. Stored RELATIVE for stable cross-extraction identifiers.
    source_file: Mapped[str] = mapped_column(
        String(2048), nullable=False
    )

    # 1-indexed line number within the source file.
    line_number: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    # The schedule spec — first 5 fields of a crontab line or a special
    # ``@reboot`` / ``@hourly`` / ``@daily`` / ``@weekly`` / ``@monthly``
    # / ``@yearly`` / ``@annually`` keyword. NULL when the line shape
    # is unparseable (caller stores raw line in ``command`` instead).
    schedule_spec: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )

    # The user under which the command runs. SOURCED FROM:
    # - Field 6 of /etc/crontab and /etc/cron.d/ lines (explicit field).
    # - The filename for /var/spool/cron/<user> and
    #   /var/spool/cron/crontabs/<user> (per-user crontabs have no user
    #   field in the lines).
    # NULL when the source format doesn't provide a user.
    user: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # The command line to be executed. Truncated to 4096 chars defensive
    # against malformed / attacker-planted multi-MB lines.
    command: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Suspicious-flags JSONB — heuristic detection summary for the κ.C.D
    # classifier. Canonical shape (boolean bits + schema_version):
    #   {
    #     "schema_version": 1,
    #     "temp_path_command": bool,    # command from /tmp/, /dev/shm/, ...
    #     "reboot_persistence": bool,   # @reboot schedule keyword
    #     "network_egress_pattern": bool,  # curl/wget/nc in command
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
        # "All cron jobs for firmware Y by source_file then line_number"
        # — covers per-file iteration + pagination.
        Index(
            "ix_linux_cron_jobs_firmware_source_line",
            "firmware_id",
            "source_file",
            "line_number",
        ),
    )
