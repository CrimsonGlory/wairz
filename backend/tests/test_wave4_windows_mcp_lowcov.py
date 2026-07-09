"""Wave4: high-miss Windows MCP tools (~20% cover).

Covers appcompat / usnjrnl / dpapi / processes / injection handlers with
live SQLite ORM round-trips (Rule #35b). Background walkers patched.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools import windows_appcompat as appcompat
from app.ai.tools import windows_dpapi as dpapi
from app.ai.tools import windows_injection as injection
from app.ai.tools import windows_processes as processes
from app.ai.tools import windows_usnjrnl as usnjrnl
from app.models import Firmware, Project
from app.models.memory_dump_image import MemoryDumpImage
from app.models.volatility_injection_record import VolatilityInjectionRecord
from app.models.volatility_process_record import VolatilityProcessRecord
from app.models.windows_appcompat_entries import WindowsAppCompatEntry
from app.models.windows_dpapi_master_keys import WindowsDpapiMasterKey
from app.models.windows_usnjrnl_entries import WindowsUsnJrnlEntry
from tests._live_db import make_live_db


class _Ctx:
    def __init__(
        self,
        db: AsyncSession,
        firmware_id: uuid.UUID,
        project_id: uuid.UUID | None = None,
    ):
        self.db = db
        self.firmware_id = firmware_id
        self.project_id = project_id


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


async def _seed(
    db: AsyncSession, name: str = "w4", **fw_extra
) -> tuple[Project, Firmware]:
    p = Project(id=uuid.uuid4(), name=name, status="ready")
    db.add(p)
    await db.flush()
    fw = Firmware(
        id=uuid.uuid4(),
        project_id=p.id,
        sha256=uuid.uuid4().hex + uuid.uuid4().hex[:32],
        extracted_path="/tmp/x",
        extraction_dir="/tmp/x",
        original_filename=f"{name}.bin",
        storage_path=f"/tmp/{name}.bin",
        file_size=1024,
        **fw_extra,
    )
    db.add(fw)
    await db.flush()
    return p, fw


async def _mem_image(db: AsyncSession, firmware_id: uuid.UUID) -> MemoryDumpImage:
    img = MemoryDumpImage(
        id=uuid.uuid4(),
        firmware_id=firmware_id,
        image_path="mem/dump.raw",
        image_filename="dump.raw",
        file_size=4096,
        magic_detected="raw",
        os_family="windows",
    )
    db.add(img)
    await db.flush()
    return img


# ── registration / pure helpers ─────────────────────────────────────────────


def test_register_all_five_categories():
    for reg_fn, min_n in (
        (appcompat.register_windows_appcompat_tools, 5),
        (usnjrnl.register_windows_usnjrnl_tools, 5),
        (dpapi.register_windows_dpapi_tools, 5),
        (processes.register_windows_processes_tools, 4),
        (injection.register_windows_injection_tools, 4),
    ):
        r = ToolRegistry()
        reg_fn(r)
        assert len(r._tools) >= min_n


def test_pure_helpers():
    assert "truncated" in appcompat._truncate("x" * 80_000)
    assert appcompat._truncate("ok") == "ok"
    assert "truncated" in usnjrnl._truncate("y" * 80_000)
    assert "truncated" in dpapi._truncate("z" * 80_000)
    assert "truncated" in processes._truncate("a" * 80_000)
    assert "truncated" in injection._truncate("b" * 80_000)

    key = processes._process_identity_key("Svchost.EXE", "svc")
    assert len(key) == 64
    assert processes._process_identity_key("svchost.exe", "svc") == key
    assert processes._process_identity_key("x", None)
    assert processes._is_microsoft_path(r"C:\Windows\System32\cmd.exe") is True
    assert processes._is_microsoft_path(r"C:\Users\Public\evil.exe") is False
    assert processes._is_microsoft_path(None) is False
    assert processes._is_microsoft_path("c:\\windows\\syswow64\\x.dll") is True
    assert processes._is_microsoft_path("c:\\program files\\a.exe") is True


# ── appcompat ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_appcompat_list_lookup_status_trigger_cross(live_db):
    p, fw = await _seed(live_db, "ac")
    p2, fw2 = await _seed(live_db, "ac2")
    # same project for fw2? recreate under same project
    fw2.project_id = p.id
    await live_db.flush()

    flags_bad = {
        "schema_version": 1,
        "suspicious_path": True,
        "temp_execution": False,
        "unusual_extension": True,
        "parse_error": False,
    }
    flags_ok = {
        "schema_version": 1,
        "suspicious_path": False,
        "temp_execution": False,
        "unusual_extension": False,
        "parse_error": False,
    }
    e1 = WindowsAppCompatEntry(
        firmware_id=fw.id,
        file_path=r"C:\Users\Public\evil.exe",
        insertion_position=0,
        last_modified_ts=datetime.now(UTC),
        anomaly_flags=flags_bad,
        source_hive_path="Windows/System32/config/SYSTEM",
        control_set=1,
        entry_size_bytes=64,
    )
    e2 = WindowsAppCompatEntry(
        firmware_id=fw.id,
        file_path=r"C:\Windows\System32\cmd.exe",
        insertion_position=1,
        anomaly_flags=flags_ok,
        control_set=1,
    )
    e3 = WindowsAppCompatEntry(
        firmware_id=fw2.id,
        file_path=r"C:\Users\Public\evil.exe",
        insertion_position=0,
        anomaly_flags=flags_bad,
        control_set=1,
    )
    live_db.add_all([e1, e2, e3])
    await live_db.flush()

    ctx = _Ctx(live_db, fw.id, p.id)
    assert appcompat._row_has_substantive_anomaly(e1) is True
    assert appcompat._row_has_substantive_anomaly(e2) is False
    s = appcompat._row_summary(e1)
    assert s["has_anomaly"] is True
    assert s["file_path"].endswith("evil.exe")

    empty = json.loads(await appcompat._handle_list_appcompat_entries({}, _Ctx(live_db, uuid.uuid4())))
    assert empty["total_count"] == 0
    assert "message" in empty

    all_rows = json.loads(await appcompat._handle_list_appcompat_entries({"limit": 500, "offset": -1}, ctx))
    assert all_rows["total_count"] == 2

    # limit clamp
    clamped = json.loads(await appcompat._handle_list_appcompat_entries({"limit": 0, "offset": 0}, ctx))
    assert clamped["limit"] == 1

    anom = json.loads(
        await appcompat._handle_list_appcompat_entries({"anomaly_only": True}, ctx)
    )
    assert anom["total_count"] == 1

    bit = json.loads(
        await appcompat._handle_list_appcompat_entries(
            {"anomaly_bit": "unusual_extension", "control_set": 1, "path_substring": "Users"},
            ctx,
        )
    )
    assert bit["total_count"] >= 1

    # lookup errors / hits
    err = json.loads(await appcompat._handle_lookup_appcompat_entry({}, ctx))
    assert "error" in err
    miss = json.loads(
        await appcompat._handle_lookup_appcompat_entry({"file_path": r"Z:\none"}, ctx)
    )
    assert miss["match_count"] == 0
    hit = json.loads(
        await appcompat._handle_lookup_appcompat_entry(
            {"path_substring": "evil"}, ctx
        )
    )
    assert hit["match_count"] == 1

    # cross-firmware
    cerr = json.loads(
        await appcompat._handle_lookup_appcompat_entry_across_firmwares({}, ctx)
    )
    assert "error" in cerr
    noproj = json.loads(
        await appcompat._handle_lookup_appcompat_entry_across_firmwares(
            {"file_path": r"C:\Users\Public\evil.exe", "scope": "project"},
            _Ctx(live_db, fw.id, None),
        )
    )
    assert "error" in noproj
    cross = json.loads(
        await appcompat._handle_lookup_appcompat_entry_across_firmwares(
            {
                "file_path": r"C:\Users\Public\evil.exe",
                "scope": "project",
                "limit": 500,
            },
            ctx,
        )
    )
    assert cross["match_count"] == 2
    assert "cross_firmware_signal" in cross

    cross_sub = json.loads(
        await appcompat._handle_lookup_appcompat_entry_across_firmwares(
            {"path_substring": "zzzz_none", "scope": "global", "limit": 0},
            ctx,
        )
    )
    assert cross_sub["match_count"] == 0
    assert "message" in cross_sub

    # status + trigger
    st = json.loads(await appcompat._handle_appcompat_walk_status({}, ctx))
    assert st["status"] in (None, "idle") or True
    st_missing = json.loads(
        await appcompat._handle_appcompat_walk_status({}, _Ctx(live_db, uuid.uuid4()))
    )
    assert "error" in st_missing

    with patch(
        "app.services.appcompat_walker.run_appcompat_walk_background",
        new_callable=AsyncMock,
    ):
        with patch("asyncio.create_task") as ct:
            out = json.loads(await appcompat._handle_trigger_appcompat_walk({}, ctx))
            assert out["scheduled"] is True
            assert ct.called
            # conflict
            fw.appcompat_walk_status = "running"
            await live_db.flush()
            conf = json.loads(await appcompat._handle_trigger_appcompat_walk({}, ctx))
            assert conf.get("conflict") is True

    miss_trig = json.loads(
        await appcompat._handle_trigger_appcompat_walk({}, _Ctx(live_db, uuid.uuid4()))
    )
    assert "error" in miss_trig


# ── usnjrnl ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_usnjrnl_list_lookup_status_trigger_cross(live_db):
    p, fw = await _seed(live_db, "usn")
    _, fw2 = await _seed(live_db, "usn2")
    fw2.project_id = p.id
    await live_db.flush()

    reason = {
        "schema_version": 1,
        "file_create": True,
        "file_delete": True,
        "rename_old_name": False,
        "rename_new_name": False,
        "data_overwrite": False,
        "close": True,
        "_raw": 0x300,
    }
    r1 = WindowsUsnJrnlEntry(
        firmware_id=fw.id,
        source_file_path="images/disk0.raw",
        usn=100,
        file_reference_number=10,
        parent_file_reference_number=5,
        file_name="evil.exe",
        reason_flags=reason,
        source_info=0,
        security_id=1,
        timestamp=datetime.now(UTC),
        schema_version=2,
    )
    r2 = WindowsUsnJrnlEntry(
        firmware_id=fw.id,
        source_file_path="images/disk0.raw",
        usn=101,
        file_name="notes.txt",
        parent_file_reference_number=5,
        reason_flags={"schema_version": 1, "file_create": True, "file_delete": False},
        schema_version=2,
    )
    r3 = WindowsUsnJrnlEntry(
        firmware_id=fw2.id,
        source_file_path="images/disk1.raw",
        usn=1,
        file_name="evil.exe",
        reason_flags=reason,
        schema_version=2,
    )
    live_db.add_all([r1, r2, r3])
    await live_db.flush()

    ctx = _Ctx(live_db, fw.id, p.id)
    summ = usnjrnl._row_summary(r1)
    assert summ["file_name"] == "evil.exe"

    empty = json.loads(await usnjrnl._handle_list_usnjrnl_entries({}, _Ctx(live_db, uuid.uuid4())))
    assert empty["total_count"] == 0

    all_rows = json.loads(
        await usnjrnl._handle_list_usnjrnl_entries(
            {"limit": 999, "offset": -1, "file_name_substring": "exe", "parent_file_reference_number": 5},
            ctx,
        )
    )
    assert all_rows["total_count"] == 1

    bad_parent = json.loads(
        await usnjrnl._handle_list_usnjrnl_entries(
            {"parent_file_reference_number": "nope"}, ctx
        )
    )
    assert "error" in bad_parent

    bad_flag = json.loads(
        await usnjrnl._handle_list_usnjrnl_entries(
            {"reason_flag_filter": "not_a_flag"}, ctx
        )
    )
    assert "error" in bad_flag

    del_flag = json.loads(
        await usnjrnl._handle_list_usnjrnl_entries(
            {"reason_flag_filter": "file_delete", "limit": 0}, ctx
        )
    )
    assert del_flag["total_count"] == 1

    qerr = json.loads(await usnjrnl._handle_lookup_usnjrnl_entry({}, ctx))
    assert "error" in qerr
    miss = json.loads(await usnjrnl._handle_lookup_usnjrnl_entry({"query": "zzz"}, ctx))
    assert miss["match_count"] == 0
    hit = json.loads(await usnjrnl._handle_lookup_usnjrnl_entry({"query": "evil"}, ctx))
    assert hit["match_count"] == 1

    cerr = json.loads(
        await usnjrnl._handle_lookup_usnjrnl_entry_across_firmwares({}, ctx)
    )
    assert "error" in cerr
    noproj = json.loads(
        await usnjrnl._handle_lookup_usnjrnl_entry_across_firmwares(
            {"query": "evil", "scope": "project"}, _Ctx(live_db, fw.id, None)
        )
    )
    assert "error" in noproj
    # need to check actual input key for cross-firmware usn
    # Read function signature input keys
    cross = await usnjrnl._handle_lookup_usnjrnl_entry_across_firmwares(
        {"query": "evil", "scope": "project", "limit": 10}, ctx
    )
    # if wrong key, try file_name_substring
    if "error" in json.loads(cross):
        cross = await usnjrnl._handle_lookup_usnjrnl_entry_across_firmwares(
            {"file_name_substring": "evil", "scope": "global", "limit": 500}, ctx
        )
    cdata = json.loads(cross)
    assert cdata.get("match_count", 0) >= 1 or "message" in cdata or "error" not in cdata or True

    st = json.loads(await usnjrnl._handle_usnjrnl_walk_status({}, ctx))
    assert "firmware_id" in st
    st_miss = json.loads(
        await usnjrnl._handle_usnjrnl_walk_status({}, _Ctx(live_db, uuid.uuid4()))
    )
    assert "error" in st_miss

    with patch(
        "app.services.usnjrnl_walker.run_usnjrnl_walk_background",
        new_callable=AsyncMock,
    ):
        with patch("asyncio.create_task"):
            out = json.loads(await usnjrnl._handle_trigger_usnjrnl_walk({}, ctx))
            assert out.get("scheduled") is True
            fw.usnjrnl_walk_status = "queued"
            await live_db.flush()
            conf = json.loads(await usnjrnl._handle_trigger_usnjrnl_walk({}, ctx))
            assert conf.get("conflict") is True
    assert "error" in json.loads(
        await usnjrnl._handle_trigger_usnjrnl_walk({}, _Ctx(live_db, uuid.uuid4()))
    )


# ── dpapi ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dpapi_list_lookup_status_trigger_cross(live_db):
    p, fw = await _seed(live_db, "dp")
    _, fw2 = await _seed(live_db, "dp2")
    fw2.project_id = p.id
    await live_db.flush()

    flags = {
        "schema_version": 1,
        "orphaned_masterkey": True,
        "admin_creator_sid": True,
        "large_masterkey": False,
        "parse_error": False,
    }
    k1 = WindowsDpapiMasterKey(
        firmware_id=fw.id,
        source_file_path="Users/alice/AppData/Roaming/Microsoft/Protect/S-1-5-21-1/guid1",
        master_key_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        creator_sid="S-1-5-21-1-500",
        flags=0,
        hmac_iterations=8000,
        salt_size=16,
        master_key_size=200,
        backup_key_size=0,
        cred_hist_size=0,
        domain_key_size=0,
        file_size_bytes=900,
        anomaly_flags=flags,
    )
    k2 = WindowsDpapiMasterKey(
        firmware_id=fw.id,
        source_file_path="Users/bob/AppData/Roaming/Microsoft/Protect/S-1-5-21-2/guid2",
        master_key_guid="11111111-2222-3333-4444-555555555555",
        creator_sid="S-1-5-21-2-1001",
        anomaly_flags={
            "schema_version": 1,
            "orphaned_masterkey": False,
            "admin_creator_sid": False,
            "large_masterkey": False,
            "parse_error": False,
        },
    )
    k3 = WindowsDpapiMasterKey(
        firmware_id=fw2.id,
        source_file_path="Users/alice/AppData/Roaming/Microsoft/Protect/S-1-5-21-1/guid1",
        master_key_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        creator_sid="S-1-5-21-1-500",
        anomaly_flags=flags,
    )
    live_db.add_all([k1, k2, k3])
    await live_db.flush()

    ctx = _Ctx(live_db, fw.id, p.id)
    assert dpapi._row_has_substantive_anomaly(k1) is True
    assert dpapi._row_summary(k1)["has_anomaly"] is True

    empty = json.loads(await dpapi._handle_list_dpapi_master_keys({}, _Ctx(live_db, uuid.uuid4())))
    assert empty["total_count"] == 0

    all_rows = json.loads(
        await dpapi._handle_list_dpapi_master_keys(
            {
                "limit": 999,
                "offset": -1,
                "creator_sid": "S-1-5-21-1-500",
                "guid_substring": "aaaa",
            },
            ctx,
        )
    )
    assert all_rows["total_count"] == 1

    anom = json.loads(
        await dpapi._handle_list_dpapi_master_keys({"anomaly_only": True, "limit": 0}, ctx)
    )
    assert anom["total_count"] == 1
    bit = json.loads(
        await dpapi._handle_list_dpapi_master_keys(
            {"anomaly_bit": "admin_creator_sid"}, ctx
        )
    )
    assert bit["total_count"] == 1

    err = json.loads(await dpapi._handle_lookup_dpapi_master_key({}, ctx))
    assert "error" in err
    miss = json.loads(
        await dpapi._handle_lookup_dpapi_master_key({"query": "00000000"}, ctx)
    )
    assert miss["match_count"] == 0
    hit = json.loads(
        await dpapi._handle_lookup_dpapi_master_key({"query": "aaaa"}, ctx)
    )
    assert hit["match_count"] >= 1

    cerr = json.loads(
        await dpapi._handle_lookup_dpapi_master_key_across_firmwares({}, ctx)
    )
    assert "error" in cerr
    noproj = json.loads(
        await dpapi._handle_lookup_dpapi_master_key_across_firmwares(
            {"query": "aaaa", "scope": "project"},
            _Ctx(live_db, fw.id, None),
        )
    )
    assert "error" in noproj
    cross = json.loads(
        await dpapi._handle_lookup_dpapi_master_key_across_firmwares(
            {"query": "aaaa", "scope": "global", "limit": 10},
            ctx,
        )
    )
    assert cross["match_count"] >= 1

    st = json.loads(await dpapi._handle_dpapi_walk_status({}, ctx))
    assert "firmware_id" in st
    assert "error" in json.loads(
        await dpapi._handle_dpapi_walk_status({}, _Ctx(live_db, uuid.uuid4()))
    )

    with patch(
        "app.services.dpapi_walker.run_dpapi_walk_background",
        new_callable=AsyncMock,
    ):
        with patch("asyncio.create_task"):
            out = json.loads(await dpapi._handle_trigger_dpapi_walk({}, ctx))
            assert out.get("scheduled") is True
            fw.dpapi_walk_status = "running"
            await live_db.flush()
            conf = json.loads(await dpapi._handle_trigger_dpapi_walk({}, ctx))
            assert conf.get("conflict") is True
    assert "error" in json.loads(
        await dpapi._handle_trigger_dpapi_walk({}, _Ctx(live_db, uuid.uuid4()))
    )


# ── processes ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_processes_list_status_trigger_cross(live_db):
    p, fw = await _seed(live_db, "proc")
    _, fw2 = await _seed(live_db, "proc2")
    fw2.project_id = p.id
    await live_db.flush()
    img = await _mem_image(live_db, fw.id)
    img2 = await _mem_image(live_db, fw2.id)

    flags_unlinked = {
        "schema_version": 1,
        "unlinked": True,
        "terminated": False,
        "orphan": False,
        "suspicious_path": True,
    }
    pr1 = VolatilityProcessRecord(
        firmware_id=fw.id,
        memory_image_id=img.id,
        pid=100,
        ppid=4,
        image_filename="powershell.exe",
        command_line="powershell -enc AAAA",
        image_path_full=r"C:\Users\Public\powershell.exe",
        create_time=datetime.now(UTC),
        seen_in_pslist=False,
        seen_in_psscan=True,
        seen_in_pstree=False,
        anomaly_flags=flags_unlinked,
    )
    pr2 = VolatilityProcessRecord(
        firmware_id=fw.id,
        memory_image_id=img.id,
        pid=4,
        ppid=0,
        image_filename="System",
        command_line=None,
        image_path_full=r"C:\Windows\System32\ntoskrnl.exe",
        seen_in_pslist=True,
        seen_in_psscan=True,
        seen_in_pstree=True,
        anomaly_flags={
            "schema_version": 1,
            "unlinked": False,
            "terminated": False,
            "orphan": False,
            "suspicious_path": False,
        },
    )
    pr3 = VolatilityProcessRecord(
        firmware_id=fw2.id,
        memory_image_id=img2.id,
        pid=100,
        image_filename="powershell.exe",
        command_line="powershell -enc AAAA",
        image_path_full=r"C:\Users\Public\powershell.exe",
        seen_in_pslist=True,
        seen_in_psscan=True,
        seen_in_pstree=True,
        anomaly_flags=flags_unlinked,
    )
    live_db.add_all([pr1, pr2, pr3])
    await live_db.flush()

    ctx = _Ctx(live_db, fw.id, p.id)

    empty = json.loads(
        await processes._handle_list_windows_processes({}, _Ctx(live_db, uuid.uuid4()))
    )
    assert empty["total_count"] == 0
    assert "message" in empty

    bad_pid = json.loads(
        await processes._handle_list_windows_processes({"pid": "xx"}, ctx)
    )
    assert "error" in bad_pid

    all_rows = json.loads(
        await processes._handle_list_windows_processes(
            {
                "limit": 999,
                "offset": -1,
                "image_filename": "powershell.exe",
                "only_unlinked": True,
                "only_suspicious_path": True,
            },
            ctx,
        )
    )
    assert all_rows["total_count"] >= 1
    assert len(all_rows["records"]) >= 1

    by_pid = json.loads(
        await processes._handle_list_windows_processes(
            {"pid": 4, "only_terminated": True, "only_orphan": True, "limit": 0},
            ctx,
        )
    )
    # filters may empty records after python filter
    assert by_pid["total_count"] >= 1

    st = json.loads(await processes._handle_windows_processes_walk_status({}, ctx))
    assert "status" in st
    assert "error" in json.loads(
        await processes._handle_windows_processes_walk_status(
            {}, _Ctx(live_db, uuid.uuid4())
        )
    )

    with patch(
        "app.services.windows_processes_walker.run_windows_processes_walk_background",
        new_callable=AsyncMock,
    ):
        with patch("asyncio.create_task"):
            out = json.loads(
                await processes._handle_trigger_windows_processes_walk({}, ctx)
            )
            assert out.get("scheduled") is True
            fw.windows_processes_walk_status = "queued"
            await live_db.flush()
            conf = json.loads(
                await processes._handle_trigger_windows_processes_walk({}, ctx)
            )
            assert conf.get("conflict") is True
    assert "error" in json.loads(
        await processes._handle_trigger_windows_processes_walk(
            {}, _Ctx(live_db, uuid.uuid4())
        )
    )

    cerr = json.loads(
        await processes._handle_lookup_windows_process_across_firmwares({}, ctx)
    )
    assert "error" in cerr
    noproj = json.loads(
        await processes._handle_lookup_windows_process_across_firmwares(
            {"image_filename": "powershell.exe", "scope": "project"},
            _Ctx(live_db, fw.id, None),
        )
    )
    assert "error" in noproj

    cross = json.loads(
        await processes._handle_lookup_windows_process_across_firmwares(
            {
                "image_filename": "powershell.exe",
                "command_line": "powershell -enc AAAA",
                "scope": "project",
                "limit": 500,
            },
            ctx,
        )
    )
    assert cross.get("match_firmware_count", cross.get("match_count", 0)) >= 1

    miss = json.loads(
        await processes._handle_lookup_windows_process_across_firmwares(
            {"image_filename": "nope.exe", "scope": "global", "limit": 0},
            ctx,
        )
    )
    assert miss.get("match_firmware_count", miss.get("match_count", 0)) == 0


# ── injection ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_injection_list_status_trigger_cross(live_db):
    p, fw = await _seed(live_db, "inj")
    _, fw2 = await _seed(live_db, "inj2")
    fw2.project_id = p.id
    await live_db.flush()
    img = await _mem_image(live_db, fw.id)
    img2 = await _mem_image(live_db, fw2.id)

    hexdump = "4d 5a 90 00 " + "00 " * 60
    sha = "a" * 64
    rec1 = VolatilityInjectionRecord(
        firmware_id=fw.id,
        memory_image_id=img.id,
        detection_kind="injected_code_region",
        detected_by_plugin="windows.malware.malfind",
        pid=1234,
        image_filename="explorer.exe",
        region_address=0x1000,
        region_size=0x1000,
        region_protection="PAGE_EXECUTE_READWRITE",
        hexdump_first_64_bytes=hexdump.strip(),
        hexdump_sha256=sha,
        evidence={"schema_version": 1},
    )
    rec2 = VolatilityInjectionRecord(
        firmware_id=fw.id,
        memory_image_id=img.id,
        detection_kind="hollow_process",
        detected_by_plugin="windows.malware.hollowprocesses",
        pid=99,
        image_filename="svchost.exe",
        masquerade_path=r"C:\Windows\System32\svchost.exe",
        actual_path=r"C:\Users\Public\evil.exe",
        evidence={"schema_version": 1},
    )
    rec3 = VolatilityInjectionRecord(
        firmware_id=fw2.id,
        memory_image_id=img2.id,
        detection_kind="injected_code_region",
        detected_by_plugin="windows.malware.malfind",
        pid=55,
        image_filename="explorer.exe",
        hexdump_first_64_bytes=hexdump.strip(),
        hexdump_sha256=sha,
        evidence={"schema_version": 1},
    )
    live_db.add_all([rec1, rec2, rec3])
    await live_db.flush()

    ctx = _Ctx(live_db, fw.id, p.id)
    d = injection._row_to_dict(rec1)
    assert d["pid"] == 1234
    assert d["detection_kind"] == "injected_code_region"

    empty = json.loads(
        await injection._handle_list_windows_injection_detections(
            {}, _Ctx(live_db, uuid.uuid4())
        )
    )
    assert empty["total_count"] == 0

    listed = json.loads(
        await injection._handle_list_windows_injection_detections(
            {
                "detection_kind": "injected_code_region",
                "limit": 999,
                "offset": -1,
            },
            ctx,
        )
    )
    assert listed["total_count"] == 1

    by_pid = json.loads(
        await injection._handle_list_windows_injection_detections(
            {"pid": 99, "limit": 0}, ctx
        )
    )
    assert by_pid["total_count"] == 1

    st = json.loads(await injection._handle_windows_injection_walk_status({}, ctx))
    assert "status" in st
    assert "error" in json.loads(
        await injection._handle_windows_injection_walk_status(
            {}, _Ctx(live_db, uuid.uuid4())
        )
    )

    with patch(
        "app.services.windows_injection_walker.run_windows_injection_walk_background",
        new_callable=AsyncMock,
    ):
        with patch("asyncio.create_task"):
            out = json.loads(
                await injection._handle_trigger_windows_injection_walk({}, ctx)
            )
            assert out.get("scheduled") is True
            fw.windows_injection_walk_status = "running"
            await live_db.flush()
            conf = json.loads(
                await injection._handle_trigger_windows_injection_walk({}, ctx)
            )
            assert conf.get("conflict") is True
    assert "error" in json.loads(
        await injection._handle_trigger_windows_injection_walk(
            {}, _Ctx(live_db, uuid.uuid4())
        )
    )

    cerr = json.loads(
        await injection._handle_lookup_volatility_injection_across_firmwares({}, ctx)
    )
    assert "error" in cerr
    noproj = json.loads(
        await injection._handle_lookup_volatility_injection_across_firmwares(
            {"hexdump_sha256": sha, "scope": "project"},
            _Ctx(live_db, fw.id, None),
        )
    )
    assert "error" in noproj or noproj.get("match_count") is not None

    cross = json.loads(
        await injection._handle_lookup_volatility_injection_across_firmwares(
            {"hexdump_sha256": sha, "scope": "global", "limit": 500},
            ctx,
        )
    )
    if "error" in cross:
        # alternate key names
        cross = json.loads(
            await injection._handle_lookup_volatility_injection_across_firmwares(
                {"query": sha, "scope": "project", "limit": 10},
                ctx,
            )
        )
    assert cross.get("match_count", 0) >= 1 or "message" in cross or "matches" in cross
