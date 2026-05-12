"""Per-entry Linux systemd journald row (Phase ι.A.A — FIRST LINUX WALKER).

One row per parsed entry from a Linux systemd ``.journal`` binary log
extracted from a firmware capture. Captures forensic-triage metadata:
syslog priority, transport (kernel / journal / audit / stdout),
systemd unit, process identifiers (PID/UID/GID/comm/exe/cmdline),
hostname, machine + boot IDs, and the message body (truncated at
the boundary for LLM-readability). Anomaly flags surface priority-0/1/2
emergencies, audit failures, OOM-kills, SELinux denials, and
suspicious unit paths.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. Journal files live at
``/var/log/journal/<machine-id>/*.journal`` (persistent) and
``/run/log/journal/<machine-id>/*.journal`` (runtime) on extracted
Linux rootfs.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker parses ``.journal`` binary log entries as untrusted
data via a clean-room parser implementing the upstream
systemd/sd-journal format (``journal-def.h``). Nothing in wairz
invokes any ``EXEC=`` field or replays journal entries against
journalctl / systemd-cat. The cmdline / exe_path / unit are surfaced
for operator review.

Per CLAUDE.md Rule #35c JSONB discipline: the ``anomaly_flags`` JSONB
column carries its own normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``
``_normalize_linux_journald_entries_anomaly_flags`` /
``_stamp_linux_journald_entries_anomaly_flags``. The flat columns
(unit / priority / transport / hostname / etc) are materialized for
fast indexed lookup; the JSONB column carries the heuristic detection
flag aggregate.

ι.A.D finding emit (linux_journald_priority_critical +
linux_journald_oom_killer + linux_journald_suspicious_unit +
linux_journald_audit_failure + linux_journald_log_clear) leverages
the parsed data to flag T1070.002 (Clear Linux/Mac System Logs),
T1543.002 (Systemd Service), T1562.012 (Disable or Modify Linux Audit
System), T1547 (Boot or Logon Autostart).

Reference for the journald binary format:
https://systemd.io/JOURNAL_FILE_FORMAT/
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
    SmallInteger,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class LinuxJournaldEntry(Base):
    """Per-entry row from a walked Linux systemd ``.journal`` binary log."""

    __tablename__ = "linux_journald_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this journal file was parsed
    # from. Cascade DELETE so removing a firmware row removes its
    # journald entries.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relative path to the .journal file within the detection root
    # (Rule #16). Stored relative for stable cross-extraction
    # identifiers. E.g.
    # ``var/log/journal/4f5a.../system.journal``.
    journal_file_path: Mapped[str] = mapped_column(
        String(2048), nullable=False
    )

    # Machine ID — 32-character hex string identifying the system that
    # produced the journal. Comes from the .journal header. NULL on
    # headerless / unreadable journals.
    machine_id: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )

    # Boot ID — 32-character hex string identifying the boot cycle.
    # From the entry's _BOOT_ID field (falls back to header).
    boot_id: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )

    # Realtime timestamp in usec since epoch (journald native).
    realtime_timestamp_us: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )

    # Monotonic timestamp in usec since boot. NULL when not present.
    monotonic_timestamp_us: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # Syslog priority 0-7 (emerg / alert / crit / err / warning /
    # notice / info / debug). PRIORITY field of the entry.
    priority: Mapped[int] = mapped_column(
        SmallInteger, nullable=False
    )

    # Syslog facility 0-23 (kernel / user / mail / daemon / ...).
    # SYSLOG_FACILITY field, NULL when not present.
    facility: Mapped[int | None] = mapped_column(
        SmallInteger, nullable=True
    )

    # _TRANSPORT — how the message arrived in journald: ``kernel`` /
    # ``journal`` / ``audit`` / ``stdout`` / ``syslog`` / ``driver``.
    # Bounded to 32 chars (longest current is ``stdout`` at 6).
    transport: Mapped[str] = mapped_column(
        String(32), nullable=False
    )

    # _SYSTEMD_UNIT — the systemd unit name (e.g.
    # ``ssh.service``, ``cron.service``, ``cloud-init.service``).
    # NULL on bare kernel / non-unit-attributed messages.
    # Anomaly: unit paths under /tmp/, /dev/shm/, /var/tmp/ are
    # suspicious (T1543.002 systemd-service-from-writable persistence).
    unit: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # _PID — process identifier of the message source. NULL on
    # kernel-transport messages.
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # _UID — real UID of the message source. NULL on kernel.
    uid: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # _GID — real GID of the message source. NULL on kernel.
    gid: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # _COMM — short process name (15 chars max in kernel). NULL on
    # kernel-transport.
    comm: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # _EXE — full path to the executable that produced the message.
    # NULL on kernel-transport.
    exe_path: Mapped[str | None] = mapped_column(
        String(1024), nullable=True
    )

    # _CMDLINE — full command line of the process. Truncated to
    # ~4096 chars at the walker boundary to bound row size.
    cmdline: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    # _HOSTNAME — system hostname at message-emission time. NULL when
    # not present.
    hostname: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # MESSAGE — the actual log message body. Truncated to ~8192 chars
    # at the walker boundary so MCP tool outputs stay below 30 KB.
    message: Mapped[str] = mapped_column(Text, nullable=False)

    # Anomaly flags — heuristic detection summary for the ι.A.D
    # classifier. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "priority_critical": bool,   # priority <= 2
    #     "oom_killer": bool,          # message matches oom-killer pattern
    #     "audit_failure": bool,       # transport=audit AND failure indicator
    #     "selinux_denied": bool,      # message matches SELinux denial
    #     "segfault": bool,            # message matches segfault pattern
    #     "suspicious_unit": bool,     # unit path under writable dir
    #     "log_clear_marker": bool,    # message matches journalctl vacuum
    #   }
    # Rule #35c stamped envelope.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Walker run timestamp — when this row was inserted. Distinct from
    # realtime_timestamp_us (which describes the log entry's lineage).
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # "All journald entries for firmware Y, ordered by time" — the
        # canonical timeline query.
        Index(
            "ix_linux_journald_entries_firmware_time",
            "firmware_id",
            "realtime_timestamp_us",
        ),
        # "All entries for firmware Y for a given unit" — natural
        # T1543.002 persistence-investigation shape.
        Index(
            "ix_linux_journald_entries_firmware_unit",
            "firmware_id",
            "unit",
        ),
        # "All high-priority entries for firmware Y" — fast scan for
        # priority <= 2 emergencies + ι.A.D anomaly emit.
        Index(
            "ix_linux_journald_entries_firmware_priority",
            "firmware_id",
            "priority",
        ),
        # "All entries for firmware Y by transport" — e.g. all audit
        # records (T1562.012 audit-system manipulation).
        Index(
            "ix_linux_journald_entries_firmware_transport",
            "firmware_id",
            "transport",
        ),
    )
