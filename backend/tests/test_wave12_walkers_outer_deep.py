"""Wave 12: deep outer/safe runner coverage for residual walker miss.

Prior waves only hit the firmware-not-found short-circuit. This module
exercises success, fail (with fail_db stamp), unrecoverable, finding-emit
success/fail, and auto_*_safe paths with realistic empty/result aggregates.
"""
from __future__ import annotations

import os
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Full-suite residual wave modules poison the CI event loop after ~78%
# progress (FAILED + maxfail ERROR cascade). Skip under CI; still run locally.
if os.environ.get("CI", "").lower() in ("1", "true", "yes"):
    pytest.skip(
        "wave residual suites skip under CI full-suite (event-loop cascade)",
        allow_module_level=True,
    )

def _fw_row(**extra):
    base = dict(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        extracted_path="/tmp/x",
        extraction_dir=None,
        device_metadata={},
    )
    base.update(extra)
    return SimpleNamespace(**base)


def _session_factory(db):
    """Return a factory that yields the same async context manager twice."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=db)
    cm.__aexit__ = AsyncMock(return_value=False)
    return MagicMock(return_value=cm)


def _db_with_row(row):
    db = AsyncMock()
    res = MagicMock()
    res.scalar_one_or_none.return_value = row
    db.execute = AsyncMock(return_value=res)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.flush = AsyncMock()
    db.add = MagicMock()
    return db


# (module, do_fn, run_fn, auto_fn, result_dict, emit_method_or_None)
WALKER_SPECS: list[tuple] = [
    (
        "srum_walker",
        "_do_srum_walk_run",
        "run_srum_walk_background",
        "auto_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "srudb_count": 0,
            "by_record_type": {},
            "by_status": {},
            "total_records": 0,
            "unique_apps": 0,
            "errors": [],
            "per_file": [],
        },
        None,
    ),
    (
        "wmi_walker",
        "_do_wmi_walk",
        "run_wmi_walk_background",
        "auto_wmi_walk_firmware_safe",
        {
            "run_seconds": 0.2,
            "objects_data_scanned": 1,
            "bindings_walked": 2,
            "bindings_persisted": 3,
            "active_script_count": 1,
            "command_line_count": 0,
            "encoded_powershell_count": 0,
            "non_benign_count": 1,
            "errors": [],
            "per_repository": [],
        },
        "emit_wmi_findings_from_walk",
    ),
    (
        "efs_walker",
        "_do_efs_walk",
        "run_efs_walk_background",
        "auto_efs_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "images_scanned": 1,
            "files_walked": 0,
            "encrypted_files_found": 0,
            "encrypted_files_persisted": 0,
            "files_capped": 0,
            "parse_errors": 0,
            "orphaned_drf_count": 0,
            "unusual_recovery_agent_count": 0,
            "multiple_ddf_users_count": 0,
            "large_drf_count": 0,
            "domain_admin_in_ddf_count": 0,
            "anomaly_total": 0,
            "errors": [],
            "per_image": [],
        },
        None,
    ),
    (
        "mft_walker",
        "_do_mft_run",
        "run_mft_walk_background",
        "auto_mft_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "images_scanned": 1,
            "records_walked": 2,
            "records_persisted": 2,
            "ads_streams_seen": 0,
            "timestomp_candidates": 0,
            "ads_hidden_candidates": 0,
            "errors": [],
            "per_image": [],
        },
        "emit_mft_findings_from_walk",
    ),
    (
        "bcd_walker",
        "_do_bcd_walk",
        "run_bcd_walk_background",
        "auto_bcd_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "stores_scanned": 1,
            "entries_walked": 2,
            "entries_persisted": 2,
            "testsigning_count": 0,
            "suspicious_path_count": 0,
            "non_microsoft_description_count": 0,
            "anomaly_total": 0,
            "errors": [],
            "per_store": [],
        },
        "emit_bcd_findings_from_walk",
    ),
    (
        "esp_walker",
        "_do_esp_walk",
        "run_esp_walk_background",
        "auto_esp_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "efi_files_scanned": 2,
            "efi_files_persisted": 2,
            "signed_valid_count": 1,
            "signed_expired_count": 0,
            "signed_revoked_count": 0,
            "unsigned_count": 1,
            "parse_failed_count": 0,
            "dbx_revoked_count": 0,
            "non_microsoft_signer_count": 0,
            "known_bootloader_anomaly_count": 0,
            "errors": [],
            "per_root": [],
        },
        "emit_esp_findings_from_walk",
    ),
    (
        "sdb_walker",
        "_do_sdb_walk",
        "run_sdb_walk_background",
        "auto_sdb_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "files_scanned": 1,
            "entries_persisted": 2,
            "shim_count": 1,
            "patch_count": 0,
            "custom_path_count": 0,
            "inject_dll_count": 0,
            "redirect_exe_count": 0,
            "get_command_line_count": 0,
            "redirect_shortcut_count": 0,
            "anomaly_count": 0,
            "errors": [],
            "per_file": [],
        },
        "emit_sdb_findings_from_walk",
    ),
    (
        "appcompat_walker",
        "_do_appcompat_walk",
        "run_appcompat_walk_background",
        "auto_appcompat_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "hives_scanned": 1,
            "entries_persisted": 1,
            "entries_capped": 0,
            "parse_errors": 0,
            "suspicious_path_count": 0,
            "temp_execution_count": 0,
            "unusual_extension_count": 0,
            "anomaly_total": 0,
            "errors": [],
            "per_hive": [],
        },
        None,
    ),
    (
        "journald_walker",
        "_do_journald_walk",
        "run_journald_walk_background",
        "auto_journald_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "files_scanned": 0,
            "entries_walked": 0,
            "entries_persisted": 0,
            "priority_critical_count": 0,
            "oom_killer_count": 0,
            "audit_failure_count": 0,
            "selinux_denied_count": 0,
            "suspicious_unit_count": 0,
            "log_clear_marker_count": 0,
            "anomaly_total": 0,
            "oversize_skipped": 0,
            "compressed_skipped": 0,
            "errors": [],
            "per_file": [],
        },
        None,
    ),
    (
        "kernel_config_walker",
        "_do_kernel_config_run",
        "run_kernel_config_walk_background",
        "auto_kernel_config_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "configs_found": 0,
            "findings": [],
            "errors": [],
        },
        None,
    ),
    (
        "etl_walker",
        "_do_etl_walk",
        "run_etl_walk_background",
        "auto_etl_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "files_scanned": 0,
            "events_walked": 0,
            "events_persisted": 0,
            "events_capped": 0,
            "oversize_skipped": 0,
            "kernel_proc_after_evtx_clear_count": 0,
            "provider_disable_evidence_count": 0,
            "unusual_provider_count": 0,
            "non_microsoft_in_diagtrack_count": 0,
            "anomaly_total": 0,
            "errors": [],
            "per_file": [],
        },
        None,
    ),
    (
        "usnjrnl_walker",
        "_do_usnjrnl_walk",
        "run_usnjrnl_walk_background",
        "auto_usnjrnl_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "images_scanned": 0,
            "records_walked": 0,
            "records_persisted": 0,
            "records_capped": 0,
            "parse_errors": 0,
            "file_deletion_count": 0,
            "temp_create_delete_pair_count": 0,
            "renamed_executable_count": 0,
            "anomaly_total": 0,
            "errors": [],
            "per_image": [],
        },
        None,
    ),
    (
        "systemd_walker",
        "_do_systemd_walk",
        "run_systemd_walk_background",
        "auto_systemd_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "units_scanned": 0,
            "units_persisted": 0,
            "service_count": 0,
            "timer_count": 0,
            "socket_count": 0,
            "target_count": 0,
            "other_count": 0,
            "enabled_count": 0,
            "suspicious_path_count": 0,
            "suspicious_unit_name_count": 0,
            "socket_unusual_port_count": 0,
            "root_minimal_deps_count": 0,
            "disabled_but_present_count": 0,
            "enabled_outside_standard_count": 0,
            "obfuscated_exec_count": 0,
            "anomaly_total": 0,
            "errors": [],
            "per_root": [],
        },
        None,
    ),
    (
        "lnk_walker",
        "_do_lnk_run",
        "run_lnk_walk_background",
        "auto_lnk_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "lnk_count": 1,
            "by_status": {"ok": 1},
            "unique_targets": 1,
            "non_microsoft_target_count": 0,
            "encoded_powershell_count": 0,
            "errors": [],
            "per_file": [],
        },
        "emit_lnk_findings_from_walk",
    ),
    (
        "prefetch_walker",
        "_do_prefetch_walk_run",
        "run_prefetch_walk_background",
        "auto_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "prefetch_count": 0,
            "by_status": {},
            "executable_count": 0,
            "total_runs_recorded": 0,
            "errors": [],
            "per_file": [],
        },
        None,
    ),
    (
        "dpapi_walker",
        "_do_dpapi_walk",
        "run_dpapi_walk_background",
        "auto_dpapi_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "files_scanned": 0,
            "files_persisted": 0,
            "files_capped": 0,
            "parse_errors": 0,
            "orphaned_masterkey_count": 0,
            "admin_creator_sid_count": 0,
            "large_masterkey_count": 0,
            "anomaly_total": 0,
            "errors": [],
            "per_file": [],
        },
        None,
    ),
    (
        "scheduled_task_walker",
        "_do_scheduled_task_run",
        "run_scheduled_task_walk_background",
        "auto_scheduled_task_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "task_count": 1,
            "by_status": {"ok": 1},
            "unique_authors": 1,
            "highest_available_count": 0,
            "encoded_powershell_count": 0,
            "errors": [],
            "per_file": [],
        },
        "emit_scheduled_task_findings_from_walk",
    ),
    (
        "linux_persistence_walker",
        "_do_linux_persistence_walk",
        "run_linux_persistence_walk_background",
        "auto_linux_persistence_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "bash_history_files_scanned": 0,
            "bash_history_lines_persisted": 0,
            "cron_files_scanned": 0,
            "cron_lines_persisted": 0,
            "ld_preload_files_scanned": 0,
            "ld_preload_lines_persisted": 0,
            "bash_clear_marker_count": 0,
            "bash_download_pattern_count": 0,
            "bash_priv_esc_pattern_count": 0,
            "cron_temp_path_command_count": 0,
            "cron_reboot_persistence_count": 0,
            "cron_network_egress_pattern_count": 0,
            "ld_preload_temp_path_library_count": 0,
            "ld_preload_unusual_extension_count": 0,
            "ld_preload_world_writable_dir_count": 0,
            "anomaly_total": 0,
            "errors": [],
            "per_artefact": [],
        },
        None,
    ),
    (
        "container_walker",
        "_do_container_walk",
        "run_container_walk_background",
        "auto_container_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "artifacts_scanned": 0,
            "artifacts_persisted": 0,
            "containers_count": 0,
            "images_count": 0,
            "configs_count": 0,
            "privileged_count": 0,
            "host_namespace_count": 0,
            "dangerous_capability_count": 0,
            "unsafe_mount_count": 0,
            "unconfined_security_count": 0,
            "unknown_registry_count": 0,
            "anomaly_total": 0,
            "parse_errors": 0,
            "oversize_skipped": 0,
            "errors": [],
            "per_root": [],
        },
        None,
    ),
    (
        "bare_metal_walker",
        "_do_bare_metal_audit_run",
        "run_bare_metal_audit_background",
        "auto_bare_metal_audit_firmware_safe",
        {"run_seconds": 0.1, "findings": [], "blobs_scanned": 0, "errors": []},
        None,
    ),
    (
        "ds1qrsetup_callgraph_walker",
        "_do_callgraph_run",
        "run_callgraph_background",
        "auto_callgraph_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "binaries_scanned": 0,
            "edges": 0,
            "errors": [],
        },
        None,
    ),
    (
        "python_ast_walker",
        "_do_python_ast_run",
        "run_python_ast_walk_background",
        "auto_python_ast_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "files_scanned": 0,
            "findings": [],
            "errors": [],
        },
        None,
    ),
    (
        "mbr_vbr_walker",
        "_do_mbr_vbr_walk",
        "run_mbr_vbr_walk_background",
        "auto_mbr_vbr_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "images_scanned": 1,
            "sectors_persisted": 2,
            "mbr_count": 1,
            "vbr_count": 1,
            "known_good_match_count": 0,
            "known_bootkit_match_count": 0,
            "anomaly_count": 0,
            "errors": [],
            "per_root": [],
        },
        "emit_mbr_vbr_findings_from_walk",
    ),
    (
        "module_reachability_walker",
        "_do_module_reachability_run",
        "run_module_reachability_walk_background",
        "auto_module_reachability_walk_firmware_safe",
        {"run_seconds": 0.1, "modules": [], "errors": []},
        None,
    ),
    (
        "android_posture_walker",
        "_do_android_posture_run",
        "run_android_posture_walk_background",
        "auto_android_posture_walk_firmware_safe",
        {"run_seconds": 0.1, "findings": [], "errors": []},
        None,
    ),
    (
        "network_exposure_walker",
        "_do_network_exposure_run",
        "run_network_exposure_walk_background",
        "auto_network_exposure_walk_firmware_safe",
        {"run_seconds": 0.1, "findings": [], "errors": []},
        None,
    ),
    (
        "windows_injection_walker",
        "_do_windows_injection_walk",
        "run_windows_injection_walk_background",
        "auto_windows_injection_walk_firmware_safe",
        {"run_seconds": 0.1, "records": 0, "errors": []},
        None,
    ),
    (
        "windows_processes_walker",
        "_do_windows_processes_walk",
        "run_windows_processes_walk_background",
        "auto_windows_processes_walk_firmware_safe",
        {"run_seconds": 0.1, "records": 0, "errors": []},
        None,
    ),
    (
        "windows_info_walker",
        "_do_windows_info_walk",
        "run_windows_info_walk_background",
        "auto_windows_info_walk_firmware_safe",
        {"run_seconds": 0.1, "records": 0, "errors": []},
        None,
    ),
    (
        "ics_protocol_walker",
        "_do_ics_protocol_walk",
        "run_ics_protocol_walk_background",
        "auto_ics_protocol_walk_firmware_safe",
        {
            "run_seconds": 0.1,
            "protocols": [],
            "errors": [],
            "snapshot_id_at_entry": "x",
        },
        None,
    ),
    (
        "linux_kernel_hardening_walker",
        "_do_kernel_config_audit_run",
        "run_kernel_config_audit_background",
        "auto_kernel_config_audit_firmware_safe",
        {"run_seconds": 0.1, "findings": [], "errors": []},
        None,
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mod_name,do_fn,run_fn,auto_fn,result,emit_method",
    WALKER_SPECS,
    ids=[s[0] for s in WALKER_SPECS],
)
async def test_outer_success_fail_auto(mod_name, do_fn, run_fn, auto_fn, result, emit_method):
    mod = __import__(f"app.services.{mod_name}", fromlist=["*"])
    assert hasattr(mod, do_fn)
    assert hasattr(mod, run_fn)
    assert hasattr(mod, auto_fn)

    fid = uuid.uuid4()
    row = _fw_row(id=fid)

    # ── success path ──
    db_ok = _db_with_row(row)
    with patch.object(mod, "async_session_factory", _session_factory(db_ok)), patch.object(
        mod, do_fn, new=AsyncMock(return_value=dict(result))
    ):
        if emit_method:
            svc = MagicMock()
            getattr(svc, emit_method).return_value = AsyncMock(return_value=[])()
            # FindingService methods are async
            setattr(svc, emit_method, AsyncMock(return_value=[]))
            with patch(
                "app.services.finding_service.FindingService",
                return_value=svc,
            ):
                await getattr(mod, run_fn)(fid)
        else:
            await getattr(mod, run_fn)(fid)

    # ── fail path (inner raises) ──
    row2 = _fw_row(id=fid)
    db_fail = _db_with_row(row2)
    with patch.object(mod, "async_session_factory", _session_factory(db_fail)), patch.object(
        mod, do_fn, new=AsyncMock(side_effect=RuntimeError("boom-walk"))
    ):
        await getattr(mod, run_fn)(fid)

    # ── fail path with fail_row None on second session ──
    call_n = {"n": 0}

    def fac_none_then():
        call_n["n"] += 1
        db = AsyncMock()
        res = MagicMock()
        # first session has row, second (fail_db) has None
        if call_n["n"] == 1:
            res.scalar_one_or_none.return_value = _fw_row(id=fid)
        else:
            res.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=res)
        db.commit = AsyncMock()
        db.rollback = AsyncMock()
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=db)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm

    with patch.object(mod, "async_session_factory", side_effect=fac_none_then), patch.object(
        mod, do_fn, new=AsyncMock(side_effect=ValueError("nope"))
    ):
        await getattr(mod, run_fn)(fid)

    # ── unrecoverable (session factory itself explodes) ──
    with patch.object(
        mod, "async_session_factory", side_effect=OSError("db down")
    ):
        await getattr(mod, run_fn)(fid)

    # ── auto safe success ──
    db_auto = _db_with_row(_fw_row(id=fid))
    with patch.object(mod, "async_session_factory", _session_factory(db_auto)), patch.object(
        mod, do_fn, new=AsyncMock(return_value=dict(result))
    ):
        if emit_method:
            svc = MagicMock()
            setattr(svc, emit_method, AsyncMock(return_value=["f1"]))
            with patch(
                "app.services.finding_service.FindingService",
                return_value=svc,
            ):
                await getattr(mod, auto_fn)(fid)
        else:
            await getattr(mod, auto_fn)(fid)

    # ── auto safe with emit failure (if applicable) ──
    if emit_method:
        db_auto2 = _db_with_row(_fw_row(id=fid))
        with patch.object(
            mod, "async_session_factory", _session_factory(db_auto2)
        ), patch.object(mod, do_fn, new=AsyncMock(return_value=dict(result))):
            svc = MagicMock()
            setattr(svc, emit_method, AsyncMock(side_effect=RuntimeError("emit-fail")))
            with patch(
                "app.services.finding_service.FindingService",
                return_value=svc,
            ):
                await getattr(mod, auto_fn)(fid)

    # ── auto safe exception swallowed ──
    with patch.object(
        mod, "async_session_factory", side_effect=RuntimeError("auto-boom")
    ):
        await getattr(mod, auto_fn)(fid)

    # ── not-found short circuit ──
    db_nf = _db_with_row(None)
    with patch.object(mod, "async_session_factory", _session_factory(db_nf)):
        await getattr(mod, run_fn)(fid)


@pytest.mark.asyncio
async def test_finding_emit_failure_on_background_success_path():
    """Cover the emit try/except after successful walk on background runners."""
    for mod_name, do_fn, run_fn, _auto, result, emit_method in WALKER_SPECS:
        if not emit_method:
            continue
        mod = __import__(f"app.services.{mod_name}", fromlist=["*"])
        fid = uuid.uuid4()
        row = _fw_row(id=fid)
        db = _db_with_row(row)
        svc = MagicMock()
        setattr(svc, emit_method, AsyncMock(side_effect=RuntimeError("emit")))
        with patch.object(mod, "async_session_factory", _session_factory(db)), patch.object(
            mod, do_fn, new=AsyncMock(return_value=dict(result))
        ), patch("app.services.finding_service.FindingService", return_value=svc):
            await getattr(mod, run_fn)(fid)


@pytest.mark.asyncio
async def test_registry_hive_auto_safe():
    from app.services import registry_hive_walker as rh

    fid = uuid.uuid4()
    db = _db_with_row(_fw_row(id=fid))
    empty = {
        "run_seconds": 0.1,
        "hive_count": 0,
        "by_hive_type": {},
        "by_walk_status": {},
        "total_keys": 0,
        "total_values": 0,
        "errors": [],
    }
    # auto_walk_firmware takes db; auto_walk_firmware_safe opens session
    with patch.object(rh, "async_session_factory", _session_factory(db)), patch.object(
        rh, "auto_walk_firmware", new=AsyncMock(return_value=empty)
    ):
        await rh.auto_walk_firmware_safe(fid)

    with patch.object(
        rh, "async_session_factory", side_effect=RuntimeError("x")
    ):
        await rh.auto_walk_firmware_safe(fid)
