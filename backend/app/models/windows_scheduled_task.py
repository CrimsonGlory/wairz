"""Per-task Windows Scheduled Task XML row (Phase η.B.A).

One row per parsed task XML extracted from
``\\Windows\\System32\\Tasks\\`` (recursive). Captures persistence-
candidate metadata: triggers (Calendar / Logon / Boot / Event / Time),
actions (Exec / ComHandler — surfaced as data only per Rule #36),
principal (RunAs UserId / GroupId / RunLevel — HighestAvailable is
the privilege-escalation marker), settings, and registration info.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. The ``source_path`` column stores
the path RELATIVE to the detection root (so multi-root firmware
re-extraction yields stable identifiers).

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the parsed Action's <Command>/<Arguments> are surfaced for
operator review, NEVER invoked. The walker treats the XML as untrusted
input via ``defusedxml.ElementTree.fromstring`` (Decision D2 in
intake — defusedxml swap pattern from Phase Lint.B.3 baseline).

Per CLAUDE.md Rule #35c JSONB discipline: ``triggers`` /
``actions`` / ``principal`` / ``settings`` JSONB columns each carry
their own normalizer + schema_version stamp; see
``app.services.jsonb_normalizers`` ``_normalize_windows_scheduled_tasks_*``.

Persistence-finding emit (η.B.D) leverages the parsed data to flag:
- Encoded-PowerShell action shape (-EncodedCommand / FromBase64String)
  → Qakbot pattern → HIGH confidence.
- RunLevel=HighestAvailable + non-system Author → MEDIUM confidence.
- Baseline rows → LOW confidence.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsScheduledTask(Base):
    """Per-task row from a walked ``\\Windows\\System32\\Tasks\\<name>`` XML."""

    __tablename__ = "windows_scheduled_tasks"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this task XML was parsed from.
    # Cascade DELETE so removing a firmware row removes its tasks.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Path to the .xml file within the detection root (Rule #16).
    # Stored relative for stable cross-extraction identifiers.
    # E.g. ``Windows/System32/Tasks/Microsoft/Windows/Maintenance/WinSAT``.
    source_path: Mapped[str] = mapped_column(String(2048), nullable=False)

    # Logical task path from <RegistrationInfo><URI>. The Windows Task
    # Scheduler uses this as the canonical name (e.g. ``\Microsoft\Windows
    # \Maintenance\WinSAT``). Falls back to the relative ``source_path``
    # path with the leading folder stripped when URI is absent.
    task_uri: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    # Task name — the file basename for fast operator search.
    task_name: Mapped[str] = mapped_column(String(512), nullable=False)

    # <RegistrationInfo><Author> — typically "Microsoft Corporation"
    # for system tasks, "${SOMEPRINCIPAL}" for installer-created tasks,
    # ``\\<HOSTNAME>\<USER>`` for end-user-created tasks. NULL when
    # missing. The classifier flags non-system Author + HighestAvailable
    # as MEDIUM confidence.
    author: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # <RegistrationInfo><Date> — task creation timestamp from the XML.
    # Authoritative for forensic-timeline queries; indexed jointly
    # with firmware_id.
    registration_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # <Principals><Principal><RunLevel> — "LeastPrivilege" (default)
    # or "HighestAvailable" (privilege-escalation marker). NULL when
    # absent (defaults to LeastPrivilege).
    run_level: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # <Principals><Principal><UserId> | <GroupId> resolved at parse time.
    # Common values: ``S-1-5-18`` (LocalSystem), ``S-1-5-19`` (LocalService),
    # ``S-1-5-20`` (NetworkService), or ``\\<HOSTNAME>\<USER>``.
    run_as_user: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Triggers — JSONB list of dicts. One entry per <Trigger>:
    #   [{"type": "CalendarTrigger" | "LogonTrigger" | "BootTrigger" |
    #             "EventTrigger" | "TimeTrigger" | "RegistrationTrigger" |
    #             "SessionStateChangeTrigger" | "IdleTrigger",
    #     "enabled": bool,
    #     "start_boundary": str | None,
    #     "end_boundary": str | None,
    #     "details": dict}]
    # Rule #35c stamped envelope.
    triggers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Actions — JSONB list of dicts. One entry per <Action>:
    #   [{"type": "Exec" | "ComHandler",
    #     "command": str | None,           # <Exec><Command>
    #     "arguments": str | None,         # <Exec><Arguments>
    #     "working_directory": str | None,
    #     "class_id": str | None,          # <ComHandler><ClassId>
    #     "details": dict}]
    # Rule #35c stamped envelope. Per Rule #36, command/arguments are
    # surfaced AS DATA — never invoked.
    actions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Principal — JSONB dict carrying the full <Principals><Principal>
    # block (id, UserId/GroupId, RunLevel, LogonType, ProcessTokenSidType,
    # RequiredPrivileges). Rule #35c stamped envelope.
    principal: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Settings — JSONB dict carrying the <Settings> block (Enabled,
    # Hidden, AllowDemandStart, DisallowStartIfOnBatteries, etc.). The
    # Hidden=true + Enabled=true combo is a persistence-evasion marker.
    # Rule #35c stamped envelope.
    settings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        # "All tasks for firmware Y, newest first" — the canonical
        # operator query shape.
        Index(
            "ix_windows_scheduled_tasks_firmware_registration",
            "firmware_id",
            "registration_date",
        ),
        # "Lookup by author" — quick filter for Microsoft vs third-party.
        Index(
            "ix_windows_scheduled_tasks_firmware_author",
            "firmware_id",
            "author",
        ),
        # "Lookup by URI" — direct path lookup for known persistence-tasks.
        Index(
            "ix_windows_scheduled_tasks_firmware_uri",
            "firmware_id",
            "task_uri",
        ),
    )
