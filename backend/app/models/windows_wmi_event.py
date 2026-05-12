"""Per-binding Windows WMI ``__FilterToConsumerBinding`` row
(Phase θ.B.B).

One row per parsed WMI persistence binding from an OBJECTS.DATA file
extracted from a firmware capture. Captures forensic-triage metadata:
the binding ID (consumer-filter pair name), the WMI namespace, the
filter Query (WQL trigger condition), the consumer type discriminator
(CommandLine / ActiveScript / LogFile / NTEventLog / SMTP / Other),
the consumer payload (the attacker-controlled command line OR script
text OR file template — whichever the binding's consumer type defines),
the source repository path (relative to the detection root per
Rule #16), the anomaly flags from the θ.B.E classifier (suspicious
consumer type, encoded-PowerShell pattern, script-host invocation,
non-benign-binding indicator), the fingerprint sha256 of the canonical
binding payload tuple for cross-firmware aggregation, and the
``probably_benign`` flag inherited from the vendored
PyWMIPersistenceFinder's well-known-binding annotation.

**T1546.003 Event-Triggered Execution: Windows Management
Instrumentation Event Subscription** — the WMI Filter+Consumer+Binding
triple is one of the most durable persistence mechanisms in Windows:
the WMI service runs from boot, the binding survives reboot via the
repository's MAPPING{1,2,3}.MAP allocation, and the binding fires
without spawning a visible process (the WmiPrvSE.exe host runs the
consumer payload in-process). Notable adversary tradecraft:

- **APT29 (Cozy Bear)** — WMI persistence via PowerShell consumer.
- **APT32 (OceanLotus)** — WMI persistence with custom JS consumer.
- **Turla** — Multi-stage WMI bindings with timer filters.
- **FIN7** — Carbanak operator tradecraft, WMI consumer drops.
- **Ransomware affiliates (Conti, BlackCat)** — pre-encryption WMI
  triggers for staged payload execution.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. WMI repository files live as
``OBJECTS.DATA`` + ``INDEX.BTR`` + ``MAPPING{1,2,3}.MAP`` co-located
under ``Windows/System32/wbem/Repository/`` paths of the extracted
firmware (matching is case-insensitive — extracted partitions may
surface as either Repository/ or repository/ depending on the
underlying filesystem case sensitivity).

**Per CLAUDE.md Rule #36 no-execute discipline**: this table holds
DATA only. The walker treats OBJECTS.DATA as untrusted text input
via the vendored PyWMIPersistenceFinder (regex-only parser; zero
process-spawn primitives). The ``consumer_payload`` JSONB carries
the attacker-controlled CommandLineTemplate / ScriptText / FileName /
WriteString verbatim from the repository for operator review; NO
code path in wairz invokes wscript / cscript / powershell / mshta /
WmiPrvSE / wmiexec / WBEM_OBJECT_TEXTUAL_REPRESENTATION_QUERY against
the persisted payloads. The test gate
``tests/test_wmi_walker.py::test_wmi_no_script_execution`` asserts
this discipline programmatically (negative test: the spawn-grep
across the walker module yields zero matches).

Per CLAUDE.md Rule #35c JSONB discipline: both JSONB columns
(``consumer_payload`` and ``anomaly_flags``) carry their own
normaliser + schema_version stamp; see
``app.services.jsonb_normalizers``
``_normalize_windows_wmi_events_consumer_payload`` /
``_stamp_windows_wmi_events_consumer_payload`` and
``_normalize_windows_wmi_events_anomaly_flags`` /
``_stamp_windows_wmi_events_anomaly_flags``. The flat columns
(binding_id / filter_name / consumer_name / consumer_type / namespace
/ source_path / fingerprint_sha256 / probably_benign) are
materialized for fast indexed lookup; the JSONB columns carry the
per-binding payload roster + the heuristic detection flag aggregate.

θ.B.E finding emit (``windows_wmi_persistence``) leverages the parsed
data to flag attacker-controlled WMI persistence bindings. Confidence
tier mapping is heuristic-driven:

- HIGH — consumer_payload carries encoded-PowerShell pattern
  (``-EncodedCommand`` / ``-enc`` / ``FromBase64String`` /
  ``Invoke-Expression`` / ``[char[]]`` / ``DownloadString`` / ``IEX``),
  OR consumer_type is ActiveScriptEventConsumer (in-process script
  execution — the highest-impact WMI consumer type).
- MEDIUM — consumer_type is CommandLineEventConsumer AND the
  payload references a known script-host (wscript / cscript /
  powershell / pwsh / mshta / regsvr32 / rundll32).
- LOW — baseline review-candidate row (any non-benign
  FilterToConsumerBinding deserves operator attention).

Reference for WMI persistence detection:
https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
https://attack.mitre.org/techniques/T1546/003/
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
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsWmiEvent(Base):
    """Per-binding row from a walked WMI repository OBJECTS.DATA."""

    __tablename__ = "windows_wmi_events"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this WMI binding was parsed
    # from. Cascade DELETE so removing a firmware row removes its
    # WMI entries.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Path to the OBJECTS.DATA file within the detection root
    # (Rule #16). Stored relative for stable cross-extraction
    # identifiers. E.g. ``Windows/System32/wbem/Repository/OBJECTS.DATA``.
    source_path: Mapped[str] = mapped_column(String(2048), nullable=False)

    # WMI namespace the binding lives in. Typically
    # ``ROOT\\subscription`` or ``ROOT\\CIMV2`` — the keyword-search
    # parser doesn't reliably extract the namespace (it's encoded in
    # binary CIM structures, not in the regex's keyword window), so
    # this column is typically NULL on vendor-derived rows. Future
    # work: cross-reference INDEX.BTR for the namespace mapping.
    namespace: Mapped[str | None] = mapped_column(
        String(256), nullable=True
    )

    # Synthesized binding identifier (consumer_name + "-" +
    # filter_name) for stable cross-firmware aggregation. Mirrors the
    # vendored PyWMIPersistenceFinder's binding_id field. E.g.
    # ``ASEC-ASECFilter`` (Stuxnet); ``BVTConsumer-BVTFilter`` (benign).
    binding_id: Mapped[str] = mapped_column(String(512), nullable=False)

    # Filter name from the binding. The ``Name`` field of
    # ``__EventFilter``. E.g. ``ASECFilter``, ``BVTFilter``.
    filter_name: Mapped[str] = mapped_column(String(512), nullable=False)

    # WQL filter query — the SELECT statement that defines the
    # filter's trigger condition. E.g.
    # ``SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE
    # TargetInstance ISA 'Win32_Process'``. NULL when the vendor
    # parser couldn't extract the Query (incomplete repository, etc.).
    filter_query: Mapped[str | None] = mapped_column(
        String(4096), nullable=True
    )

    # Consumer name from the binding. The ``Name`` field of the
    # EventConsumer instance. E.g. ``ASEC``, ``BVTConsumer``.
    consumer_name: Mapped[str] = mapped_column(String(512), nullable=False)

    # Consumer type discriminator. The WMI repository defines:
    # - CommandLineEventConsumer — argv string + cwd
    # - ActiveScriptEventConsumer — VBScript / JScript body
    # - LogFileEventConsumer — log path + text template
    # - NTEventLogEventConsumer — event message string
    # - SMTPEventConsumer — email template + recipient list
    # plus less-common types. Stored as a CHECK-constrained string for
    # forensic-triage discoverability.
    consumer_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # Consumer payload — the attacker-controlled CommandLineTemplate /
    # ScriptText / FileName + WriteString — JSONB list-shape because
    # the vendor parser may surface multiple distinct payloads from
    # the same consumer name across allocated + unallocated repository
    # regions. Canonical shape:
    #
    #   [
    #     {
    #       "schema_version": 1,
    #       "consumer_type": str,    # e.g. "CommandLineEventConsumer"
    #       "arguments": str,        # the printable-filtered argv/payload
    #       "other": str,            # secondary field per upstream regex
    #     },
    #     ...
    #   ]
    #
    # Per Rule #36: this is DATA, never passed as argv[0] to any
    # process-spawn primitive.
    consumer_payload: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # Anomaly flags — heuristic detection summary for the θ.B.E
    # classifier. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "encoded_powershell": bool,
    #     "script_host_invocation": bool,
    #     "active_script_consumer": bool,
    #     "non_benign_binding": bool,
    #     "high_severity": bool,
    #   }
    # NULL when no anomaly evaluation was performed (rare — defensive
    # shape; the walker stamps this on every emit).
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # SHA256 fingerprint of the canonical binding payload tuple
    # (binding_id + filter_query + first consumer arguments) for
    # cross-firmware aggregation in
    # ``lookup_wmi_persistence``. Lets operators detect "this exact
    # binding shape appears in N firmware images" across the wairz
    # corpus. NULL on defensive parser-failure paths.
    fingerprint_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Vendored PyWMIPersistenceFinder's well-known-binding annotation.
    # True iff the binding_id matches one of the canonical benign
    # entries (BVTConsumer-BVTFilter, SCM Event Log Consumer-SCM Event
    # Log Filter). The MCP layer surfaces these but with reduced
    # priority; the finding emit hook skips benign bindings entirely.
    probably_benign: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    # Walker run timestamp — when this row was inserted.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # "All WMI bindings for firmware Y" — the canonical triage query.
        Index(
            "ix_windows_wmi_events_firmware",
            "firmware_id",
        ),
        # "All WMI bindings for firmware Y, by binding_id" — the natural
        # lookup key for "show me the FooConsumer-BarFilter binding".
        Index(
            "ix_windows_wmi_events_firmware_binding",
            "firmware_id",
            "binding_id",
        ),
        # "All WMI bindings with this fingerprint across all firmware"
        # — the lookup_wmi_persistence MCP tool's query shape (cross-
        # firmware aggregation).
        Index(
            "ix_windows_wmi_events_fingerprint",
            "fingerprint_sha256",
        ),
        # "All non-benign WMI bindings for firmware Y" — the anomaly-
        # focused MCP search filter.
        Index(
            "ix_windows_wmi_events_firmware_benign",
            "firmware_id",
            "probably_benign",
        ),
    )
