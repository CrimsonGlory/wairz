import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Firmware(Base):
    __tablename__ = "firmware"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    original_filename: Mapped[str | None] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    storage_path: Mapped[str | None] = mapped_column(String(512))
    extracted_path: Mapped[str | None] = mapped_column(String(512))
    extraction_dir: Mapped[str | None] = mapped_column(String(512))
    architecture: Mapped[str | None] = mapped_column(String(50))
    endianness: Mapped[str | None] = mapped_column(String(10))
    os_info: Mapped[str | None] = mapped_column(Text)
    kernel_path: Mapped[str | None] = mapped_column(String(512))
    version_label: Mapped[str | None] = mapped_column(String(100))
    unpack_log: Mapped[str | None] = mapped_column(Text)
    unpack_stage: Mapped[str | None] = mapped_column(String(100))
    unpack_progress: Mapped[int | None] = mapped_column(Integer)
    binary_info: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    device_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    cve_match_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    cve_match_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cve_match_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cve_match_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_match_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # SBOM vulnerability-scan 202+polling state (Rule #29 + Rule #33).
    # The synchronous endpoint at routers/sbom.py POST /vulnerabilities/scan
    # held a TCP connection idle for ~4m10s on 72 components; with the 16 GB
    # Illumisite image incoming and a cold Grype DB sync the scan can blow
    # past the SECURITY_SCAN_TIMEOUT (600s) ceiling. The persisted
    # SbomVulnerability rows ARE the result — no JSONB result column.
    vuln_scan_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    vuln_scan_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    vuln_scan_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    vuln_scan_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Upload-time post-processing state (Rule #29 + Rule #33).
    # Synchronous tier was holding the TCP connection for 5+ minutes of
    # post-write CPU work (hash, archive extract, filesystem detection,
    # arch/endian/OS detect); the 16 GB Illumisite upload tripped the
    # frontend axios 600s ceiling. Detected_format is populated by
    # services/format_detection.detect_format() before the extracting
    # stage; capability is derived in the schema layer (no CHECK).
    upload_stage: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="ready"
    )
    upload_stage_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    upload_stage_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    upload_stage_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_format: Mapped[str | None] = mapped_column(String(48), nullable=True)
    # Phase β Authenticode batch-validation 202+polling state.
    # _run_authenticode_chain_background walks every PE in the firmware's
    # hardware_firmware_blobs, runs the signify validator, and writes a
    # WindowsPESignature row per PE. The aggregate result lives here so
    # the frontend's last-known-result render survives session reloads.
    # Rule #33 .c CHECK constraint enforces the 5-state machine.
    authenticode_chain_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    authenticode_chain_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    authenticode_chain_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    authenticode_chain_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    authenticode_chain_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Phase γ batch registry-walk 202+polling state. Background runner
    # _run_registry_hive_walk_background walks every registry hive across
    # the firmware's hardware_firmware_blobs (regipy read-only binding
    # per Rule #36 — DATA only, never invoked) and writes a
    # WindowsRegistryExtract row per hive (γ.1). The aggregate result
    # (hive_count, by_hive_type, by_walk_status, total_keys, total_values,
    # run_seconds) lives here so the frontend's last-known-result render
    # survives session reloads. Rule #33 .c CHECK enforces the 5-state
    # machine; Pydantic RegistryHiveWalkStatus Literal at writer
    # boundary catches code-side typos. Rule #33 .d — asyncio.create_task
    # dispatch (in-process; per-hive INSERTs are the durable state;
    # restart recovery via the extract table's (blob, hive_path)
    # UniqueConstraint).
    registry_hive_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    registry_hive_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    registry_hive_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    registry_hive_walk_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    registry_hive_walk_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Phase δ batch .NET single-file bundle decompile 202+polling state.
    # Worker arq job ``decompile_dotnet_bundle_job`` walks every .NET
    # single-file bundle in the firmware's hardware_firmware_blobs
    # (dnfile read-only PE table walk per Rule #36 — DATA only, never
    # invokes the assembly's entry point) and runs ilspycmd inside the
    # gated worker container (ARG INCLUDE_DOTNET=1 → dotnet-runtime-8.0 +
    # ilspycmd dotnet-tool). The aggregate result (counts +
    # per-bundle output paths) lives here so the frontend's last-known-
    # result render survives session reloads. Rule #33 .c CHECK enforces
    # the 5-state machine; Pydantic ``DotnetDecompileStatus`` Literal at
    # writer boundary catches code-side typos. Rule #33 .d — arq dispatch
    # (worker-only resource: ilspycmd lives in the worker container only).
    dotnet_decompile_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    dotnet_decompile_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    dotnet_decompile_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    dotnet_decompile_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    dotnet_decompile_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Phase δ KB-vs-KB update-diff 202+polling state. Background runner
    # ``_run_windows_update_diff_background`` (δ.5) walks every
    # (older_kb, newer_kb) pair across the firmware's
    # ``windows_update_packages`` rows (δ.1), computes per-DLL changeset
    # via SHA256 comparison, and persists per-DLL diff rows incrementally
    # to a dedicated table introduced in δ.5. The aggregate result
    # (counts + by-KB-pair histogram + run_seconds) lives here so the
    # frontend's last-known-result render survives session reloads.
    # Rule #33 .c CHECK enforces the 5-state machine; Pydantic
    # ``WindowsUpdateDiffStatus`` Literal at writer boundary catches
    # code-side typos. Rule #33 .d — asyncio.create_task dispatch
    # (in-process pure-Python diff + per-DLL incremental persistence is
    # the durable state; restart recovery via the per-DLL table's
    # (firmware_id, dll_path) UniqueConstraint).
    windows_update_diff_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    windows_update_diff_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    windows_update_diff_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    windows_update_diff_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    windows_update_diff_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Phase ε batch EVTX (Windows Event Log) walk 202+polling state.
    # Background runner ``run_evtx_walk_background`` (ε.1.b.3) walks every
    # ``.evtx`` file across the firmware's detection roots
    # (``app.services.firmware_paths.get_detection_roots`` per Rule #16),
    # invokes ``app.services.evtx_service.parse_evtx_file`` per file
    # (python-evtx read-only record stream per Rule #36 — DATA only, never
    # invoked via wevtutil / Get-WinEvent), and aggregates per-EVTX
    # summaries (counts by EID, by provider, time range, sample records,
    # run_seconds) into ``evtx_walk_result`` so the frontend's last-known-
    # result render survives session reloads. Rule #33 .c CHECK enforces
    # the 5-state machine; Pydantic ``EvtxWalkStatus`` Literal at writer
    # boundary catches code-side typos. Rule #33 .d — asyncio.create_task
    # dispatch (in-process pure-Python parser; per-firmware JSONB aggregate
    # is the durable state; per-event row persistence deferred to a future
    # ζ.X phase per ε.1.b campaign Decision #1).
    evtx_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    evtx_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    evtx_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    evtx_walk_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    evtx_walk_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Phase ζ.2.B Prefetch walker columns (CLAUDE.md Rule #33 contract).
    # Background runner ``run_prefetch_walk_background`` walks every ``.pf``
    # across the firmware's detection roots (windowsprefetch read-only
    # struct-unpack per Rule #36 — DATA only, never invoked via pftriage /
    # Get-CimInstance Win32_PrefetchedApp), persists per-execution rows
    # into ``windows_prefetch_records`` (table from ζ.2.A), and stamps
    # an aggregate JSONB result onto ``prefetch_walk_result``. Rule #33 .c
    # CHECK enforces the 5-state machine; Pydantic ``PrefetchWalkStatus``
    # Literal at writer boundary catches code-side typos. Rule #33 .d —
    # asyncio.create_task dispatch (in-process pure-Python parser).
    prefetch_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    prefetch_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    prefetch_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    prefetch_walk_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    prefetch_walk_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Phase ζ.3.B SRUM walker columns (CLAUDE.md Rule #33 contract).
    # Background runner ``run_srum_walk_background`` walks every
    # ``SRUDB.dat`` across the firmware's detection roots (libesedb-python
    # read-only ESEDB binding per Rule #36 — DATA only, never invoked via
    # esedbutil / Get-CimInstance SRUMState), persists per-record rows
    # into ``windows_srum_records`` (table from ζ.3.A), and stamps an
    # aggregate JSONB result onto ``srum_walk_result``. Rule #33 .c CHECK
    # enforces the 5-state machine; Rule #33 .d — asyncio.create_task
    # dispatch (in-process libesedb-python parser).
    srum_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    srum_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    srum_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    srum_walk_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    srum_walk_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Phase η.B.B Scheduled Task XML walker columns (CLAUDE.md Rule #33
    # contract). Background runner ``run_scheduled_task_walk_background``
    # walks every ``\Windows\System32\Tasks\**\*`` XML file across the
    # firmware's detection roots (defusedxml.ElementTree.fromstring per
    # Rule #36 — DATA only, never invoked via schtasks /create or
    # Register-ScheduledTask), persists per-task rows into
    # ``windows_scheduled_tasks`` (table from η.B.A), and stamps an
    # aggregate JSONB result onto ``scheduled_task_walk_result``.
    # Rule #33 .c CHECK enforces the 5-state machine; Rule #33 .d —
    # asyncio.create_task dispatch (in-process pure-Python parser).
    scheduled_task_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    scheduled_task_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    scheduled_task_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    scheduled_task_walk_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    scheduled_task_walk_result: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Phase η.C.B Windows Shell Link (.lnk) walker columns (CLAUDE.md
    # Rule #33 contract). Background runner ``run_lnk_walk_background``
    # walks every ``*.lnk`` file under user-profile + system shortcut
    # locations across the firmware's detection roots
    # (LnkParse3.lnk_file(fhandle=...) per Rule #36 — DATA only,
    # never invoked via cscript / wscript / Start-Process / cmd /c on
    # the resolved target_path), persists per-LNK rows into
    # ``windows_lnk_records`` (table from η.C.A), and stamps an
    # aggregate JSONB result onto ``lnk_walk_result``. Rule #33 .c
    # CHECK enforces the 5-state machine; Rule #33 .d —
    # asyncio.create_task dispatch (in-process pure-Python parser).
    lnk_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    lnk_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    lnk_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    lnk_walk_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    lnk_walk_result: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Phase η.A.B NTFS $MFT walker columns (CLAUDE.md Rule #33 contract).
    # Background runner ``run_mft_walk_background`` opens each raw NTFS
    # image candidate (``.dd`` / ``.raw`` / ``.ntfs`` under any detection
    # root per Rule #16) via ``with open(path, "rb") as fh: NTFS(fh)``
    # (dissect.ntfs is a pure-Python parser per Rule #36 — DATA only,
    # never mounted via ntfs-3g / mount / qemu-system), iterates every
    # MFT segment via ``fs.mft.segments()`` (yields both allocated and
    # unallocated records), persists per-record rows into
    # ``windows_mft_records`` (table from η.A.A), and stamps an aggregate
    # JSONB result onto ``mft_walk_result``. Rule #33 .c CHECK enforces
    # the 5-state machine; Rule #33 .d — asyncio.create_task dispatch
    # (in-process pure-Python parser; no Docker spawn).
    mft_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    mft_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mft_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mft_walk_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    mft_walk_result: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Phase θ.A.B BCD store walker columns (CLAUDE.md Rule #33 contract).
    # Background runner ``run_bcd_walk_background`` opens each BCD store
    # candidate (files named ``BCD`` under any detection root per
    # Rule #16) via regipy's ``RegistryHive`` (BCD is REGF format —
    # the same parser handles all standard hives plus BCD via
    # ``BCD_HIVE_TYPE``; pure-Python parser per Rule #36 — DATA only,
    # never invoked via bcdedit / reg.exe / boot manager), iterates
    # every ``\Objects\{guid}`` subkey via the regipy NKRecord
    # iter_subkeys() API, persists per-entry rows into
    # ``windows_bcd_entries`` (table from θ.A.A), and stamps an
    # aggregate JSONB result onto ``bcd_walk_result``. Rule #33 .c CHECK
    # enforces the 5-state machine; Rule #33 .d — asyncio.create_task
    # dispatch (in-process pure-Python parser; no Docker spawn).
    bcd_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    bcd_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    bcd_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    bcd_walk_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    bcd_walk_result: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Phase ι.A.B Linux journald walker columns (CLAUDE.md Rule #33 contract).
    # FIRST LINUX walker in wairz's portfolio. Background runner
    # ``run_journald_walk_background`` opens each ``.journal`` file
    # candidate (typically ``var/log/journal/<machine-id>/*.journal`` or
    # ``run/log/journal/<machine-id>/*.journal`` under any detection root
    # per Rule #16) via a clean-room parser implementing the upstream
    # systemd/sd-journal binary format (no third-party Python package
    # matched the Rule #19 evidence-first probe — ``dissect.journal``
    # does not exist on PyPI; ``kaitaistruct`` is available but would
    # require ~500 LOC of vendor-in generated code; clean-room is the
    # smaller path. Pure-Python parser per Rule #36 — DATA only, never
    # invoked via journalctl / systemd-cat), iterates every entry,
    # persists per-entry rows into ``linux_journald_entries`` (table
    # from ι.A.A), and stamps an aggregate JSONB result onto
    # ``journald_walk_result``. Rule #33 .c CHECK enforces the 5-state
    # machine; Rule #33 .d — asyncio.create_task dispatch (in-process
    # pure-Python parser; no Docker spawn).
    journald_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    journald_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    journald_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    journald_walk_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    journald_walk_result: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Phase θ.B.C WMI persistence walker columns (CLAUDE.md Rule #33 contract).
    # Background runner ``run_wmi_walk_background`` opens each WMI
    # OBJECTS.DATA file (typically under ``Windows/System32/wbem/Repository/``
    # per Rule #16 detection-roots), parses each via the vendored
    # PyWMIPersistenceFinder (pure-Python keyword-search parser per
    # Rule #36 — DATA only, never invoked via wscript / cscript /
    # powershell / mshta / WmiPrvSE / wmiexec), iterates every detected
    # ``__FilterToConsumerBinding`` triple, persists per-binding rows
    # into ``windows_wmi_events`` (table from θ.B.B), and stamps an
    # aggregate JSONB result onto ``wmi_walk_result``. Rule #33 .c CHECK
    # enforces the 5-state machine; Rule #33 .d — asyncio.create_task
    # dispatch (in-process pure-Python parser; no Docker spawn).
    wmi_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    wmi_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    wmi_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    wmi_walk_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    wmi_walk_result: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Phase θ.C.B ESP `.efi` PE chain walker columns (CLAUDE.md Rule #33
    # contract). Background runner ``run_esp_walk_background`` walks for
    # `.efi` PE32+ files under each detection root (Rule #16 — the EFI
    # System Partition surfaces as a FAT32 mount OR a top-level ``EFI/``
    # directory depending on the unpacker), validates each PE against
    # the β.4 signify Authenticode chain + β.10 DBX revocation list +
    # pefile COFF metadata (all pure-Python parsers reading the file
    # as DATA per Rule #36 — never invoked via wine / mono / qemu-system /
    # chainloader), persists per-`.efi` rows into ``windows_esp_entries``
    # (table from θ.C.A), and stamps an aggregate JSONB result onto
    # ``esp_walk_result``. Rule #33 .c CHECK enforces the 5-state
    # machine; Rule #33 .d — asyncio.create_task dispatch (in-process
    # pure-Python validators; no Docker spawn).
    esp_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    esp_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    esp_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    esp_walk_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    esp_walk_result: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Phase θ.E.B MBR/VBR boot-sector walker columns (CLAUDE.md Rule #33
    # contract). Background runner ``run_mbr_vbr_walk_background`` walks
    # for raw disk image files (.img / .raw / .vhd / .vhdx — possibly
    # converted by α.2.7) AND partition images under each detection
    # root (Rule #16 — disk images surface differently per unpacker),
    # reads the first 512 bytes (MBR), examines the partition table at
    # offset 446, then reads each partition's first sector (VBR),
    # SHA256-hashes each sector, signature-matches against the bundled
    # known-good Windows VBR + known-malicious bootkit (TDL4 / Olmasco /
    # Mebroot / Petya / etc.) tables, and persists per-sector rows
    # (table from θ.E.A). All pure-Python; no subprocess (per Rule #36 —
    # MBR/VBR are 512 bytes of x86 boot code and MUST NEVER be invoked
    # via nasm / objdump / qemu-system / chainloader). Rule #33 .c
    # CHECK enforces the 5-state machine; Rule #33 .d —
    # asyncio.create_task dispatch (in-process pure-Python; no Docker
    # spawn).
    mbr_vbr_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    mbr_vbr_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mbr_vbr_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mbr_vbr_walk_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    mbr_vbr_walk_result: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Phase θ.D.C SDB shim walker columns (CLAUDE.md Rule #33 contract).
    # Background runner ``run_sdb_walk_background`` walks for `.sdb`
    # files under each detection root (Rule #16 — `.sdb` files surface
    # differently per unpacker; typically under
    # Windows/AppPatch/Custom/<exe>.sdb for attacker-planted shims),
    # parses the binary format via the vendored python_sdb clean-room
    # parser, classifies each TAG_SHIM / TAG_PATCH entry into the
    # 7-state shim_class enum, and persists per-entry rows (table from
    # θ.D.B). All pure-Python; no subprocess (per Rule #36 — .sdb
    # files describe shim instructions Windows AppHelp loads + executes
    # via sdbinst.exe; wairz MUST NEVER invoke these). Rule #33 .c
    # CHECK enforces the 5-state machine; Rule #33 .d — asyncio
    # .create_task dispatch (in-process pure-Python; no Docker spawn).
    sdb_walk_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    sdb_walk_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    sdb_walk_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    sdb_walk_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    sdb_walk_result: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    project: Mapped["Project"] = relationship(back_populates="firmware")  # noqa: F821

    __table_args__ = (
        Index("ix_firmware_project_id", "project_id"),
        UniqueConstraint("project_id", "sha256", name="uq_firmware_project_sha256"),
    )
