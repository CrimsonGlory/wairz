"""Per-shim Windows SDB entry row (Phase θ.D.B).

One row per shim entry parsed from an attacker-planted Application
Compatibility Shim Database (`.sdb`) file in a Windows firmware
capture. A single `.sdb` typically carries a handful of APPS (one
per shimmed target executable) and each APP wraps 0-N SHIMs and 0-N
PATCHes. We persist ONE WindowsSdbEntry row per SHIM (or PATCH, with
the shim_class distinguishing) for downstream finding-emit hooks
(θ.D.E).

Captures forensic-triage metadata for the application-shim threat
hunt (θ.D — final stream of the θ campaign, closing 5-of-5
walkers matching η's precedent):

- The relative file path to the `.sdb` file within the detection
  root (Rule #16) — typically ``Windows/AppPatch/Custom/<exe>.sdb``
  for attacker-planted shims (well-known T1546.011 location) OR
  ``Windows/AppPatch/sysmain.sdb`` for the legitimate Microsoft
  bundle.
- SHA256 of the `.sdb` file (canonical cross-firmware identifier —
  same hash across multiple firmware ⇒ same shim was planted; see
  ``lookup_sdb_shim`` MCP tool for cross-corpus correlation).
- SDB kind discriminator (microsoft, custom, unknown) — derived from
  the parent directory of the `.sdb` file. ``Windows/AppPatch/`` →
  microsoft (legitimate Microsoft-shipped shims); ``Custom/`` or
  ``Custom64/`` → custom (operator review needed; high suspicion);
  anything else → unknown.
- App name + EXE name (text — TAG_APP_NAME / TAG_NAME of the
  parent TAG_APP) for human-readable triage. Example: app_name=
  "EvilApp", app_exe="myapp.exe".
- Shim class discriminator (RedirectEXE, InjectDll, GetCommandLineW,
  RedirectShortcut, Custom, Patch, Other). This is the high-signal
  classifier — InjectDll / RedirectEXE / RedirectShortcut shims are
  the canonical attacker primitives.
- Shim payload JSONB (raw shim instructions verbatim — shim name,
  module/DLL filename, command-line arguments, description, OR for
  PATCH-class entries, the raw TAG_PATCH_BITS hex blob).
- Anomaly flags JSONB (heuristic detection summary: is_custom_path,
  has_inject_dll, has_redirect_exe, has_get_command_line,
  has_redirect_shortcut, has_dll_outside_appdir, has_command_line).
- Fingerprint sha256 (cross-firmware aggregation surface — same
  fingerprint across firmware ⇒ same shim was planted).

**T1546.011 Application Shimming** — adversaries (APT41, FIN7,
Carbanak, various ransomware affiliates) plant custom `.sdb` shims
under ``Windows/AppPatch/Custom/<exe>.sdb``. Windows loads the shim
on every launch of the target executable, executing attacker code
in the application's context. Detection focus:

- **Custom-path shim** (``Custom/`` or ``Custom64/`` directory) —
  strong supply-chain / persistence signal. Microsoft ships shims
  ONLY in ``Windows/AppPatch/`` proper; custom shims under
  ``Custom/`` are application-author-shipped at best, attacker-
  shipped at worst.
- **InjectDll shim primitive** — DIRECTLY loads an attacker-
  controlled DLL into the target process address space.
- **RedirectEXE shim primitive** — DIRECTLY replaces the executed
  binary with an attacker-controlled one.
- **GetCommandLineW shim primitive** — hooks the application's
  command line; classic argument-injection / spoofing tradecraft.
- **DLL path outside the application directory** — the shim's
  ``DLLFile`` points to a non-system, non-app path; suspicious
  even without a known-bad primitive name.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. `.sdb` files surface differently
across firmware unpackers (full Windows partition image vs partial
extract of ``Windows/AppPatch/``); the multi-root discipline catches
all forms.

**Per CLAUDE.md Rule #36 no-execute discipline**: this table holds
DATA only. `.sdb` files describe shim instructions that Windows
loads + executes via AppHelp / sdbinst infrastructure. The walker
parses the binary format via the vendored python_sdb clean-room
parser (no execution); NO codepath in wairz invokes sdbinst /
AppHelp / Mscoree / any shim infrastructure on the host. The test
gate ``tests/test_sdb_walker.py::test_sdb_no_shim_execution``
asserts this discipline programmatically.

Per CLAUDE.md Rule #35c JSONB discipline: the ``shim_payload`` +
``anomaly_flags`` JSONB columns carry their own normaliser +
schema_version stamps; see ``app.services.jsonb_normalizers``:

- ``_normalize_windows_sdb_entries_shim_payload`` /
  ``_stamp_windows_sdb_entries_shim_payload``
- ``_normalize_windows_sdb_entries_anomaly_flags`` /
  ``_stamp_windows_sdb_entries_anomaly_flags``

The flat columns (file_path / file_sha256 / sdb_kind / app_name /
app_exe / shim_class / fingerprint_sha256) are materialized for
fast indexed lookup; the JSONB columns carry the per-entry payload
+ heuristic detection flag aggregate.

θ.D.E finding emit (``windows_sdb_inject_dll`` +
``windows_sdb_redirect_exe`` + ``windows_sdb_custom_shim``)
leverages the parsed data to flag:

- **windows_sdb_inject_dll** — Custom-path shim with shim_class=
  InjectDll. Tier: HIGH always — direct DLL-injection primitive
  in attacker-controllable directory.
- **windows_sdb_redirect_exe** — Custom-path shim with shim_class=
  RedirectEXE. Tier: HIGH always — replaces the executed binary.
- **windows_sdb_custom_shim** — Any Custom-path shim that doesn't
  match the above two HIGH classifiers but still warrants review.
  Tier: MEDIUM (Custom-path AND has_command_line OR has_get_command_line)
  vs LOW (Custom-path baseline).

Reference for SDB / shim architecture:
- Microsoft Application Compatibility Toolkit (ACT) format docs.
- python-sdb format reverse-engineering (Apache 2.0):
  https://github.com/williballenthin/python-sdb
- Mandiant / Mitre ATT&CK T1546.011 Application Shimming.
- FIN7 / Carbanak / APT41 case studies on shim-based persistence.
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


class WindowsSdbEntry(Base):
    """Per-shim-entry row from a walked .sdb file."""

    __tablename__ = "windows_sdb_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this shim entry was parsed
    # from. Cascade DELETE so removing a firmware row removes its
    # shim entries.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relative path to the `.sdb` file within the detection root
    # (Rule #16). Stored relative for stable cross-extraction
    # identifiers. E.g. ``Windows/AppPatch/Custom/myapp.sdb``.
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)

    # SHA256 of the `.sdb` file contents (canonical cross-firmware
    # identifier). 64 hex chars.
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # SDB kind discriminator. One of:
    # - microsoft     — file_path under Windows/AppPatch/ proper
    #                   (NOT under Custom/ or Custom64/).
    # - custom        — file_path under Windows/AppPatch/Custom/
    #                   or Windows/AppPatch/Custom64/.
    # - unknown       — file_path doesn't match either canonical
    #                   shape (e.g. .sdb dropped in a non-standard
    #                   directory — highly suspicious).
    # CHECK constraint enforces the 3-state enum in the alembic
    # migration; the Literal mirror in app/schemas/firmware.py
    # type-checks at the API boundary.
    sdb_kind: Mapped[str] = mapped_column(
        String(32), nullable=False
    )

    # App name (text — TAG_APP_NAME of the parent TAG_APP).
    # NULL when the .sdb has no APP or when the APP has no TAG_APP_NAME.
    app_name: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )

    # App EXE filename (text — TAG_NAME of the first TAG_EXE
    # under the parent TAG_APP). E.g. "myapp.exe", "notepad.exe".
    # NULL when the .sdb has no matching EXE record.
    app_exe: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )

    # Shim class discriminator. One of:
    # - RedirectEXE       — replaces the executed binary entirely.
    # - InjectDll         — loads an attacker-controlled DLL into the
    #                       target process address space.
    # - GetCommandLineW   — hooks the application's command line
    #                       (argument-injection / spoofing).
    # - RedirectShortcut  — redirects shortcut-target resolution.
    # - Custom            — TAG_SHIM with a shim_name not matching
    #                       any of the above primitives.
    # - Patch             — this row represents a TAG_PATCH entry
    #                       (binary patch to the target executable's
    #                       in-memory image), not a TAG_SHIM.
    # - Other             — TAG_SHIM with an unknown / empty shim_name.
    # CHECK constraint enforces the 7-state enum.
    shim_class: Mapped[str] = mapped_column(
        String(64), nullable=False
    )

    # Shim payload — JSONB dict-shape. For shim entries, carries the
    # raw shim name + module/DLL filename + command-line arguments
    # + description. For patch entries, carries the raw TAG_PATCH_BITS
    # hex blob + name + size.
    shim_payload: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Anomaly flags — heuristic detection summary for the θ.D.E
    # classifier. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "is_custom_path": bool,
    #     "has_inject_dll": bool,
    #     "has_redirect_exe": bool,
    #     "has_get_command_line": bool,
    #     "has_redirect_shortcut": bool,
    #     "has_dll_outside_appdir": bool,
    #     "has_command_line": bool,
    #   }
    # NULL only on defensive parser-failure paths.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # SHA256 fingerprint of the canonical entry tuple
    # (file_path_lower + file_sha256 + shim_class + shim_name)
    # for cross-firmware aggregation in ``lookup_sdb_shim`` MCP
    # tool. Same fingerprint across firmware ⇒ same shim was
    # planted (campaign / supply-chain correlation across the wairz
    # corpus). NULL on defensive parser-failure paths.
    fingerprint_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Walker run timestamp — when this row was inserted.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # "All SDB entries for firmware Y" — canonical triage.
        Index(
            "ix_windows_sdb_entries_firmware",
            "firmware_id",
        ),
        # "All SDB entries for firmware Y, by file_sha256" — natural
        # lookup for "show me this exact .sdb file" triage.
        Index(
            "ix_windows_sdb_entries_firmware_sha",
            "firmware_id",
            "file_sha256",
        ),
        # "All SDB entries matching this fingerprint across all
        # firmware" — the lookup_sdb_shim MCP tool's query
        # shape (cross-firmware aggregation for shim hunt).
        Index(
            "ix_windows_sdb_entries_fingerprint",
            "fingerprint_sha256",
        ),
        # "All custom-path shims for firmware Y" — anomaly-focused
        # MCP search filter.
        Index(
            "ix_windows_sdb_entries_firmware_kind",
            "firmware_id",
            "sdb_kind",
        ),
    )
