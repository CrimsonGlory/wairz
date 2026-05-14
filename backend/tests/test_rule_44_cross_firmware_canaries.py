"""Rule #35b live canaries for the 11 Issue #15 cross-firmware lookup tools.

Each of the 11 ``lookup_<artefact>_across_firmwares`` MCP handlers ships
a one-line registration assertion (per-walker test file). This file
adds the value-flow backstop that Rule #35b requires: actual round-
trip through ``make_live_db()`` with seeded Firmware + Project +
record rows, then SELECT-equivalent invocation of the handler, then
field-by-field assertion on the returned shape.

Two canaries per tool:

1. **Guard canary** — ``scope='project'`` with ``context.project_id=None``
   returns the actionable error string. This catches the code-review
   F#2 MED regression if the guard is ever removed.

2. **Value-flow canary** — two firmwares (in the SAME project) each
   carry one matching record. Calling the handler with
   ``scope='project'`` must:
     - return ``match_firmware_count == 2``
     - emit ``supply_chain_signal`` correctly per the per-tool
       calibration (BCD / EVTX / scheduled_task have stricter
       thresholds; the other 8 use the canonical ``match_count >= 2``).

The canaries are parameterized over a registry of ``_ToolSpec``
records so a future Rule #44 walker can register itself in one place
and inherit the full coverage.

Author note: tests are written against the ORM models as they exist
at HEAD; if a model adds a NOT NULL column, the factory below must
be updated AND the canary must continue to pass without modification
to the handler.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import pytest

from app.ai.tool_registry import ToolContext
from app.ai.tools.windows_bcd import (
    _handle_lookup_bcd_entry_across_firmwares,
)
from app.ai.tools.windows_esp import (
    _handle_lookup_esp_entry_across_firmwares,
)
from app.ai.tools.windows_event_log import (
    _handle_lookup_event_record_across_firmwares,
)
from app.ai.tools.windows_lnk import (
    _handle_lookup_lnk_record_across_firmwares,
)
from app.ai.tools.windows_mbr_vbr import (
    _handle_lookup_mbr_vbr_sector_across_firmwares,
)
from app.ai.tools.windows_mft import (
    _handle_lookup_mft_record_across_firmwares,
)
from app.ai.tools.windows_prefetch import (
    _handle_lookup_prefetch_record_across_firmwares,
)
from app.ai.tools.windows_registry import (
    _handle_lookup_registry_extract_across_firmwares,
)
from app.ai.tools.windows_scheduled_task import (
    _handle_lookup_scheduled_task_across_firmwares,
)
from app.ai.tools.windows_sdb import (
    _handle_lookup_sdb_entry_across_firmwares,
)
from app.ai.tools.windows_srum import (
    _handle_lookup_srum_record_across_firmwares,
)
from app.models import (
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsBcdEntry,
    WindowsEspEntry,
    WindowsEventRecord,
    WindowsLnkRecord,
    WindowsMbrVbrSector,
    WindowsMftRecord,
    WindowsPrefetchRecord,
    WindowsRegistryExtract,
    WindowsScheduledTask,
    WindowsSdbEntry,
    WindowsSrumRecord,
)

# Importing windows_processes / windows_injection tool modules (above)
# transitively registers VolatilityProcessRecord + VolatilityInjectionRecord
# on Base.metadata. Their FK targets (MemoryDumpImage) also need to be
# present or Base.metadata.create_all() fails with NoReferencedTableError.
from app.models.memory_dump_image import MemoryDumpImage  # noqa: F401
from tests._live_db import make_live_db


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── Per-tool record factories ────────────────────────────────────────────────
# Each factory returns ONE record matching its tool's identity key.


def _event(fw_id: uuid.UUID) -> WindowsEventRecord:
    import datetime as _dt
    return WindowsEventRecord(
        firmware_id=fw_id,
        evtx_file_path="Security.evtx",
        provider="Microsoft-Windows-Security-Auditing",
        event_id=4624,
        level=4,
        recorded_at=_dt.datetime(2025, 1, 1, 12, 0, 0),
    )


def _mft(fw_id: uuid.UUID) -> WindowsMftRecord:
    return WindowsMftRecord(
        firmware_id=fw_id,
        source_path="disk.raw",
        segment_number=1234,
        in_use=True,
        is_directory=False,
        filename="cmd.exe",
        full_path="Windows\\System32\\cmd.exe",
        file_size=512000,
    )


def _lnk(fw_id: uuid.UUID) -> WindowsLnkRecord:
    return WindowsLnkRecord(
        firmware_id=fw_id,
        source_path="Recent.lnk",
        lnk_filename="cmd.lnk",
        target_path="C:\\Windows\\System32\\cmd.exe",
        arguments="/c whoami",
    )


def _scheduled_task(fw_id: uuid.UUID) -> WindowsScheduledTask:
    return WindowsScheduledTask(
        firmware_id=fw_id,
        source_path="Windows\\System32\\Tasks\\Updater",
        task_name="Updater",
        run_as_user="SYSTEM",
    )


def _scheduled_task_with_encoded_ps(fw_id: uuid.UUID) -> WindowsScheduledTask:
    """Scheduled task with -EncodedCommand action — triggers
    any_encoded_powershell + supply_chain_signal calibration. The
    actions JSONB uses the canonical Rule #35c stamped envelope
    {schema_version, items: [...]} that the normalizer recognises."""
    return WindowsScheduledTask(
        firmware_id=fw_id,
        source_path="Windows\\System32\\Tasks\\Updater",
        task_name="Updater",
        run_as_user="SYSTEM",
        actions={
            "schema_version": 1,
            "items": [
                {
                    "type": "Exec",
                    "command": "powershell.exe",
                    "arguments": "-EncodedCommand AAAA",
                    "working_directory": None,
                },
            ],
        },
    )


def _prefetch(fw_id: uuid.UUID) -> WindowsPrefetchRecord:
    return WindowsPrefetchRecord(
        firmware_id=fw_id,
        prefetch_file_path="Windows\\Prefetch\\CMD.EXE-0123ABCD.pf",
        executable_name="CMD.EXE",
        prefetch_hash="0123ABCD",
        run_count=8,
    )


def _srum(fw_id: uuid.UUID) -> WindowsSrumRecord:
    return WindowsSrumRecord(
        firmware_id=fw_id,
        record_type="application_resource_usage",
        source_path="Windows\\System32\\sru\\SRUDB.dat",
        app_identifier="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        bytes_sent=10_000,
        bytes_received=200_000,
    )


def _bcd(fw_id: uuid.UUID, *, testsigning: bool = False) -> WindowsBcdEntry:
    return WindowsBcdEntry(
        firmware_id=fw_id,
        source_path="EFI/Microsoft/Boot/BCD",
        object_guid="{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
        description="Windows Boot Manager",
        testsigning=testsigning,
    )


def _esp(fw_id: uuid.UUID) -> WindowsEspEntry:
    return WindowsEspEntry(
        firmware_id=fw_id,
        file_path="EFI/Boot/bootx64.efi",
        file_sha256="a" * 64,
        file_size=1_000_000,
        authenticode_state="signed_valid",
        fingerprint_sha256="b" * 64,
    )


def _mbr_vbr(fw_id: uuid.UUID) -> WindowsMbrVbrSector:
    return WindowsMbrVbrSector(
        firmware_id=fw_id,
        file_path="disk.raw",
        sector_offset=0,
        sector_kind="mbr",
        sector_sha256="c" * 64,
        sector_size=512,
        fingerprint_sha256="d" * 64,
    )


def _sdb(fw_id: uuid.UUID) -> WindowsSdbEntry:
    return WindowsSdbEntry(
        firmware_id=fw_id,
        file_path="Windows\\AppPatch\\Custom\\custom.sdb",
        file_sha256="e" * 64,
        sdb_kind="custom",
        shim_class="InjectDll",
        fingerprint_sha256="f" * 64,
    )


def _registry_blob(fw_id: uuid.UUID) -> HardwareFirmwareBlob:
    """Registry walker chains through HardwareFirmwareBlob; the blob
    row is created first, then a WindowsRegistryExtract is created
    once the blob's FK is known."""
    return HardwareFirmwareBlob(
        firmware_id=fw_id,
        blob_path="Windows/System32/config/SOFTWARE",
        blob_sha256="0" * 64,
        file_size=1024,
        category="registry",
        format="hive",
        detection_source="walker",
    )


def _registry_extract(blob_id: uuid.UUID) -> WindowsRegistryExtract:
    return WindowsRegistryExtract(
        blob_id=blob_id,
        hive_path="Windows/System32/config/SOFTWARE",
        hive_type="SOFTWARE",
        walk_status="completed",
    )


@dataclass
class _ToolSpec:
    """Registry entry for the parameterized canary suite."""

    handler: Callable[[dict, ToolContext], Awaitable[str]]
    seed: Callable[[uuid.UUID], Any]
    lookup_kwargs: dict
    expects_supply_chain_signal: bool
    name: str


# Calibrated supply_chain_signal expectations:
# - BCD: 2 firmwares with testsigning=True ⇒ supply_chain_signal=True
# - EVTX: 2 firmwares is below the >=5 threshold ⇒ supply_chain_signal=False
# - scheduled_task: 2 firmwares WITH any_encoded_powershell ⇒ True
# - all others: 2 firmwares ⇒ supply_chain_signal=True
TOOLS = [
    _ToolSpec(
        handler=_handle_lookup_event_record_across_firmwares,
        seed=_event,
        lookup_kwargs={
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4624,
        },
        # 2 firmwares is below the >=5 EVTX threshold (forensic calibration)
        expects_supply_chain_signal=False,
        name="event_record",
    ),
    _ToolSpec(
        handler=_handle_lookup_mft_record_across_firmwares,
        seed=_mft,
        lookup_kwargs={"filename": "cmd.exe"},
        expects_supply_chain_signal=True,
        name="mft_record",
    ),
    _ToolSpec(
        handler=_handle_lookup_lnk_record_across_firmwares,
        seed=_lnk,
        lookup_kwargs={"target_path": "C:\\Windows\\System32\\cmd.exe"},
        expects_supply_chain_signal=True,
        name="lnk_record",
    ),
    _ToolSpec(
        handler=_handle_lookup_scheduled_task_across_firmwares,
        seed=_scheduled_task_with_encoded_ps,
        lookup_kwargs={"task_name": "Updater"},
        # 2 firmwares WITH any_encoded_powershell triggers the calibration
        expects_supply_chain_signal=True,
        name="scheduled_task",
    ),
    _ToolSpec(
        handler=_handle_lookup_prefetch_record_across_firmwares,
        seed=_prefetch,
        # Mixed-case input verifies the .upper() normalization (C5 fix)
        lookup_kwargs={"executable_name": "cmd.exe"},
        expects_supply_chain_signal=True,
        name="prefetch_record",
    ),
    _ToolSpec(
        handler=_handle_lookup_srum_record_across_firmwares,
        seed=_srum,
        lookup_kwargs={
            "app_identifier": (
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
            ),
        },
        expects_supply_chain_signal=True,
        name="srum_record",
    ),
    _ToolSpec(
        handler=_handle_lookup_bcd_entry_across_firmwares,
        seed=lambda fw: _bcd(fw, testsigning=True),
        lookup_kwargs={
            "object_guid": "{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
        },
        # 2 firmwares WITH any_testsigning triggers the calibration
        expects_supply_chain_signal=True,
        name="bcd_entry",
    ),
    _ToolSpec(
        handler=_handle_lookup_esp_entry_across_firmwares,
        seed=_esp,
        lookup_kwargs={"fingerprint_sha256": "b" * 64},
        expects_supply_chain_signal=True,
        name="esp_entry",
    ),
    _ToolSpec(
        handler=_handle_lookup_mbr_vbr_sector_across_firmwares,
        seed=_mbr_vbr,
        lookup_kwargs={"fingerprint_sha256": "d" * 64},
        expects_supply_chain_signal=True,
        name="mbr_vbr_sector",
    ),
    _ToolSpec(
        handler=_handle_lookup_sdb_entry_across_firmwares,
        seed=_sdb,
        lookup_kwargs={"fingerprint_sha256": "f" * 64},
        expects_supply_chain_signal=True,
        name="sdb_entry",
    ),
]


# ── Guard canary — applies to every tool uniformly ──────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "spec",
    TOOLS + [
        # Registry handler is parameterized separately below (needs blob seed)
    ],
    ids=lambda s: s.name,
)
async def test_lookup_across_firmwares_guards_project_id_none(
    spec: _ToolSpec,
):
    """C1 backstop — scope='project' with context.project_id=None
    returns the actionable error string. Catches a regression if the
    guard is ever removed from a handler."""
    async with make_live_db() as db:
        ctx = ToolContext(
            project_id=None,
            firmware_id=uuid.uuid4(),
            extracted_path=None,
            db=db,
        )
        kwargs = dict(spec.lookup_kwargs)
        kwargs["scope"] = "project"
        out_str = await spec.handler(kwargs, ctx)
        out = json.loads(out_str)
        assert "error" in out, f"{spec.name}: expected error key in {out}"
        assert "scope='project'" in out["error"], (
            f"{spec.name}: error should mention scope='project': {out['error']}"
        )


# ── Value-flow canary — 2 firmwares in same project + supply_chain_signal ──


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "spec",
    TOOLS,
    ids=lambda s: s.name,
)
async def test_lookup_across_firmwares_value_flow(spec: _ToolSpec):
    """Rule #35b live canary — two firmwares each carry a matching
    record. scope='project' aggregates them into 2-firmware match
    count with the per-tool supply_chain_signal calibration."""
    async with make_live_db() as db:
        project = Project(name=f"rule44-canary-{spec.name}")
        db.add(project)
        await db.flush()

        fw_a = _make_firmware(project.id, f"{spec.name}-a.bin", "A")
        fw_b = _make_firmware(project.id, f"{spec.name}-b.bin", "B")
        db.add_all([fw_a, fw_b])
        await db.flush()

        db.add(spec.seed(fw_a.id))
        db.add(spec.seed(fw_b.id))
        await db.commit()

        ctx = ToolContext(
            project_id=project.id,
            firmware_id=fw_a.id,
            extracted_path=None,
            db=db,
        )
        kwargs = dict(spec.lookup_kwargs)
        kwargs["scope"] = "project"
        out_str = await spec.handler(kwargs, ctx)
        out = json.loads(out_str)

        assert out["match_firmware_count"] == 2, (
            f"{spec.name}: expected 2 matching firmwares, got "
            f"{out['match_firmware_count']}: {out}"
        )
        assert out["supply_chain_signal"] is spec.expects_supply_chain_signal, (
            f"{spec.name}: expected supply_chain_signal="
            f"{spec.expects_supply_chain_signal}, got {out['supply_chain_signal']}"
        )
        # Each firmware's sample_<record> field must be populated.
        for slot in out["matches"]:
            # Sample-record field name varies per tool; pick whichever
            # key starts with "sample_".
            sample_keys = [k for k in slot if k.startswith("sample_")]
            assert sample_keys, f"{spec.name}: matches[i] missing sample_*: {slot}"
            assert slot[sample_keys[0]] is not None, (
                f"{spec.name}: matches[i]['{sample_keys[0]}'] is None"
            )


# ── Registry walker — needs blob seed (separate from the parameterized set) ─


@pytest.mark.asyncio
async def test_lookup_registry_extract_across_firmwares_guards_project_id_none():
    """C1 backstop for windows_registry — joins through HardwareFirmwareBlob
    so blob seeding is required for the value-flow test (separate function);
    the guard test is shape-identical and verified here for completeness."""
    async with make_live_db() as db:
        ctx = ToolContext(
            project_id=None,
            firmware_id=uuid.uuid4(),
            extracted_path=None,
            db=db,
        )
        out_str = await _handle_lookup_registry_extract_across_firmwares(
            {"hive_type": "SOFTWARE", "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out
        assert "scope='project'" in out["error"]


@pytest.mark.asyncio
async def test_lookup_registry_extract_across_firmwares_value_flow():
    """Rule #35b live canary for windows_registry — seeds two firmwares
    each with a HardwareFirmwareBlob carrying a SOFTWARE hive registry
    extract. The JOIN chain
    (WindowsRegistryExtract → HardwareFirmwareBlob → Firmware → Project)
    must surface both rows aggregated by firmware."""
    async with make_live_db() as db:
        project = Project(name="rule44-canary-registry_extract")
        db.add(project)
        await db.flush()

        fw_a = _make_firmware(project.id, "registry-a.bin", "A")
        fw_b = _make_firmware(project.id, "registry-b.bin", "B")
        db.add_all([fw_a, fw_b])
        await db.flush()

        blob_a = _registry_blob(fw_a.id)
        blob_b = _registry_blob(fw_b.id)
        db.add_all([blob_a, blob_b])
        await db.flush()  # populate blob_a.id / blob_b.id

        db.add_all([
            _registry_extract(blob_a.id),
            _registry_extract(blob_b.id),
        ])
        await db.commit()

        ctx = ToolContext(
            project_id=project.id,
            firmware_id=fw_a.id,
            extracted_path=None,
            db=db,
        )
        out_str = await _handle_lookup_registry_extract_across_firmwares(
            {"hive_type": "SOFTWARE", "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_firmware_count"] == 2, out
        assert out["supply_chain_signal"] is True, out


# ── Calibration regression canaries — pin the forensic-review fixes ─────────


@pytest.mark.asyncio
async def test_bcd_calibration_no_signal_without_anomaly():
    """C2 regression backstop — 2 firmwares with the {bootmgr} GUID and
    testsigning=False must NOT trigger supply_chain_signal. The naïve
    pre-calibration would have triggered True on match_count >= 2."""
    async with make_live_db() as db:
        project = Project(name="rule44-canary-bcd-baseline")
        db.add(project)
        await db.flush()

        fw_a = _make_firmware(project.id, "bcd-baseline-a.bin", "A")
        fw_b = _make_firmware(project.id, "bcd-baseline-b.bin", "B")
        db.add_all([fw_a, fw_b])
        await db.flush()

        db.add(_bcd(fw_a.id, testsigning=False))
        db.add(_bcd(fw_b.id, testsigning=False))
        await db.commit()

        ctx = ToolContext(
            project_id=project.id,
            firmware_id=fw_a.id,
            extracted_path=None,
            db=db,
        )
        out_str = await _handle_lookup_bcd_entry_across_firmwares(
            {
                "object_guid": "{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
                "scope": "project",
            },
            ctx,
        )
        out = json.loads(out_str)
        assert out["match_firmware_count"] == 2
        assert out["supply_chain_signal"] is False, (
            "C2 regression: BCD supply_chain_signal must be False when "
            "no firmware has testsigning OR no_integrity_checks set "
            f"(got {out['supply_chain_signal']})"
        )


@pytest.mark.asyncio
async def test_evtx_threshold_no_signal_under_5_firmwares():
    """C3 regression backstop — 4 firmwares matching the same
    (provider, event_id) must NOT trigger supply_chain_signal under
    the calibrated >= 5 threshold."""
    async with make_live_db() as db:
        project = Project(name="rule44-canary-evtx-threshold")
        db.add(project)
        await db.flush()

        for i in range(4):
            fw = _make_firmware(project.id, f"evtx-thr-{i}.bin", chr(0x41 + i))
            db.add(fw)
            await db.flush()
            db.add(_event(fw.id))
        await db.commit()

        ctx = ToolContext(
            project_id=project.id,
            firmware_id=uuid.uuid4(),
            extracted_path=None,
            db=db,
        )
        out_str = await _handle_lookup_event_record_across_firmwares(
            {
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": 4624,
                "scope": "project",
            },
            ctx,
        )
        out = json.loads(out_str)
        assert out["match_firmware_count"] == 4
        assert out["supply_chain_signal"] is False, (
            "C3 regression: EVTX supply_chain_signal must be False under "
            f"the >= 5 firmware threshold (got match_count=4, signal="
            f"{out['supply_chain_signal']})"
        )


@pytest.mark.asyncio
async def test_scheduled_task_no_signal_without_encoded_powershell():
    """C4 regression backstop — 2 firmwares with the same task_name
    but NO encoded-PowerShell action must NOT trigger
    supply_chain_signal."""
    async with make_live_db() as db:
        project = Project(name="rule44-canary-scheduled-task-baseline")
        db.add(project)
        await db.flush()

        fw_a = _make_firmware(project.id, "task-baseline-a.bin", "A")
        fw_b = _make_firmware(project.id, "task-baseline-b.bin", "B")
        db.add_all([fw_a, fw_b])
        await db.flush()

        db.add(_scheduled_task(fw_a.id))  # no encoded-PS
        db.add(_scheduled_task(fw_b.id))
        await db.commit()

        ctx = ToolContext(
            project_id=project.id,
            firmware_id=fw_a.id,
            extracted_path=None,
            db=db,
        )
        out_str = await _handle_lookup_scheduled_task_across_firmwares(
            {"task_name": "Updater", "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_firmware_count"] == 2
        assert out["supply_chain_signal"] is False, (
            "C4 regression: scheduled_task supply_chain_signal must be "
            "False when no matching task has any_encoded_powershell "
            f"(got {out['supply_chain_signal']})"
        )


@pytest.mark.asyncio
async def test_prefetch_input_normalization_mixed_case_matches():
    """C5 regression backstop — analyst supplies mixed-case
    'cmd.exe'; the handler must .upper() it and match the
    walker-persisted 'CMD.EXE' rows."""
    async with make_live_db() as db:
        project = Project(name="rule44-canary-prefetch-case")
        db.add(project)
        await db.flush()

        fw = _make_firmware(project.id, "pf-case.bin", "P")
        db.add(fw)
        await db.flush()
        db.add(_prefetch(fw.id))
        await db.commit()

        ctx = ToolContext(
            project_id=project.id,
            firmware_id=fw.id,
            extracted_path=None,
            db=db,
        )
        # Mixed-case input — must still hit the CMD.EXE row.
        out_str = await _handle_lookup_prefetch_record_across_firmwares(
            {"executable_name": "Cmd.Exe", "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_firmware_count"] == 1, (
            "C5 regression: prefetch handler must .upper() input — "
            f"mixed-case 'Cmd.Exe' should match the persisted CMD.EXE "
            f"row (got {out['match_firmware_count']})"
        )
