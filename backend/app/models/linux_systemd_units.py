"""Per-unit Linux systemd unit-file row (Phase ι.B.A — SECOND LINUX WALKER).

One row per parsed systemd unit file (``.service`` / ``.timer`` /
``.socket`` / ``.target`` / ``.path`` / ``.mount`` / ``.swap``) found
under a Linux firmware extract. Captures forensic-triage metadata for
the T1543.002 (Create or Modify System Process: Systemd Service),
T1547.001 (Boot or Logon Autostart), and T1053.006 (Scheduled Task —
systemd-timer) persistence vectors.

Real-world adversaries using this exact tradecraft (Phase ι Scout 2
Persona-E refresh):

- APT36 Transparent Tribe (Aug 2025) — Linux backdoors persisted via
  ``.service`` units staged in ``/etc/systemd/system/``.
- FIRESTARTER (CISA/NCSC 2026) — Russian APT toolkit with multi-stage
  systemd-unit persistence chain.
- Quasar Linux QLNX (May 2026) — 7-mechanism persistence kit including
  ``.service`` units, ``.timer`` units, drop-in overrides, and enabled-
  symlink hijacks.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. Systemd unit files live at:

- ``etc/systemd/system/*`` (admin overrides — highest precedence)
- ``usr/lib/systemd/system/*`` (vendor units)
- ``lib/systemd/system/*`` (vendor units, legacy symlink to usr/lib)
- ``run/systemd/system/*`` (runtime units, rare in firmware)
- ``etc/systemd/user/*`` (per-user units)
- ``<unit>.<type>.d/*.conf`` (drop-in overrides — multi-file unit
  assembly)
- ``<target>.wants/<unit>`` symlinks (enabled-via-WantedBy indicator)
- ``<target>.requires/<unit>`` symlinks (enabled-via-RequiredBy)

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker parses ``.service`` INI text via stdlib
``configparser`` and surfaces ExecStart=/ExecStartPre=/ExecStartPost=
values as untrusted strings. Nothing in wairz invokes any embedded
ExecStart command, mounts any referenced path, or links any unit into
a running systemd. The exec_start / working_directory / user fields
are surfaced for operator review only.

Per CLAUDE.md Rule #35c JSONB discipline: every JSONB column carries
its own normalizer + schema_version stamp; see
``app.services.jsonb_normalizers`` (8 helpers, one per JSONB column).
Multi-value INI keys (``WantedBy=a b c`` or repeated ``WantedBy=``
lines) collapse into list[str]; timer/socket triggers collapse into
dict[str, Any].

ι.B.D finding emit (5 new sources — suspicious_path /
obfuscated_exec / socket_unusual_port / root_minimal_deps /
enabled_outside_standard) leverages the parsed data to flag the
canonical persistence + execution + autostart TTPs above.

Reference for the systemd unit file format:
https://www.freedesktop.org/software/systemd/man/systemd.unit.html
https://www.freedesktop.org/software/systemd/man/systemd.service.html
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class LinuxSystemdUnit(Base):
    """Per-unit row from a walked Linux systemd unit-file directory."""

    __tablename__ = "linux_systemd_units"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this unit file was parsed
    # from. Cascade DELETE so removing a firmware row removes its
    # systemd units.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Absolute path inside the firmware extract. E.g.
    # ``/usr/lib/systemd/system/sshd.service`` or
    # ``/etc/systemd/system/multi-user.target.wants/cron.service``.
    unit_path: Mapped[str] = mapped_column(
        String(1024), nullable=False
    )

    # Unit type — extension without the leading dot. One of:
    # service / timer / socket / target / path / mount / swap /
    # device / scope / slice / automount.
    unit_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )

    # Unit basename — filename WITHOUT the extension. E.g. ``sshd`` for
    # ``sshd.service``. The ``WantedBy=multi-user.target`` references
    # use unit_name + unit_type joined; we keep both denormalised for
    # fast lookup.
    unit_name: Mapped[str] = mapped_column(
        String(255), nullable=False
    )

    # [Unit] Description= value. Operator-facing label; first line is
    # typically a one-sentence description. NULL when missing.
    description: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )

    # [Service] ExecStart= value — the primary command the unit runs.
    # Anomaly: paths under /tmp/, /var/tmp/, /dev/shm/, /home/<user>/
    # are HIGH-priority T1543.002 indicators. NULL on non-service
    # units (timer / socket / target don't have ExecStart).
    exec_start: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )

    # [Service] ExecStartPre= — pre-start command. Same anomaly
    # surface as exec_start. NULL when unset.
    exec_start_pre: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )

    # [Service] ExecStop= — clean-stop command. NULL when unset.
    exec_stop: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )

    # [Service] User= — UID the service runs as. NULL on system
    # default (typically root). Anomaly: User=root (or unset) +
    # minimal Requires= is a common rootkit pattern.
    user: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # [Service] WorkingDirectory= — cwd the service runs in. Same
    # anomaly surface as exec_start. NULL when unset.
    working_directory: Mapped[str | None] = mapped_column(
        String(1024), nullable=True
    )

    # [Install] WantedBy= — list of target units that pull this unit
    # in. Multi-value (systemd allows ``WantedBy=a b`` AND repeated
    # ``WantedBy=`` lines). Canonical shape: list[str].
    # Anomaly: WantedBy outside the standard set (multi-user.target /
    # graphical.target / sysinit.target / sockets.target / timers.target)
    # is unusual.
    wanted_by: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # [Install] RequiredBy= — list of target units that REQUIRE this
    # unit (vs WantedBy which is best-effort). Multi-value.
    required_by: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # [Unit] Requires= — list of units this unit requires. Multi-value.
    # Anomaly: minimal Requires= on a root-running service.
    requires: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # [Unit] After= — list of units to start AFTER this one. Multi-
    # value. Surfaces dependency ordering for forensic timeline
    # reconstruction.
    after: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # [Unit] Before= — list of units to start BEFORE this one. Multi-
    # value.
    before: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # True iff at least one enabled-symlink exists under a *.wants/
    # or *.requires/ directory pointing to this unit. The canonical
    # "is this unit going to start on boot" signal.
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )

    # [Timer] section payload — OnCalendar / OnBootSec / OnUnitActiveSec
    # / OnStartupSec / etc. Canonical shape: dict[str, Any] where keys
    # are the systemd timer directives (OnCalendar / OnBootSec / etc)
    # and values are the raw strings. Empty dict on non-timer units.
    # NULL when no [Timer] section.
    triggers: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # [Socket] section payload — ListenStream / ListenDatagram /
    # ListenSequentialPacket / ListenFIFO / etc. Canonical shape:
    # dict[str, Any] (same layout as triggers). NULL when no [Socket]
    # section.
    socket_listen: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Anomaly flags — heuristic detection summary for the ι.B.D
    # classifier. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "suspicious_path": bool,          # ExecStart under writable dir
    #     "suspicious_unit_name": bool,     # unit name matches rand-hex
    #     "socket_unusual_port": bool,      # ListenStream/-Datagram on odd
    #     "root_minimal_deps": bool,        # User=root + minimal Requires
    #     "disabled_but_present": bool,     # no enabled-symlink
    #     "enabled_outside_standard": bool, # WantedBy != standard targets
    #     "obfuscated_exec": bool,          # base64/eval/long shell pattern
    #   }
    # Rule #35c stamped envelope.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Full INI content (truncated to ~8K at the walker boundary).
    # Surfaces for operator forensic review — the parsed columns above
    # are summary; the raw text carries comments, ordering, and
    # any unusual directive that the parser doesn't enumerate.
    unit_raw: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    # Walker run timestamp — when this row was inserted.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Updated_at — bumped on re-walk if the unit content changed.
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        # "All units for firmware Y by type" — canonical timer/service
        # split query.
        Index(
            "ix_linux_systemd_units_firmware_type",
            "firmware_id",
            "unit_type",
        ),
        # "All units for firmware Y by name" — lookup by basename
        # (for cross-firmware aggregation in ι.B.E).
        Index(
            "ix_linux_systemd_units_firmware_name",
            "firmware_id",
            "unit_name",
        ),
        # "All enabled units for firmware Y" — the boot-time-active set,
        # which is the operator's primary persistence-investigation
        # query.
        Index(
            "ix_linux_systemd_units_firmware_enabled",
            "firmware_id",
            "enabled",
        ),
    )
