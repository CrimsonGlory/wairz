"""Tests for ``app.services.jsonb_normalizers`` — boundary normalisers
for every JSONB column on the wairz schema (CLAUDE.md Rule #35c).

Each normaliser is verified with three properties:

1. **Canonical pass-through** — a value already in the canonical shape
   is returned unchanged (idempotency).
2. **Defensive coercion** — ``None`` and wrong-typed inputs return the
   canonical empty default rather than raising.
3. **Schema_version fidelity** — for columns that stamp a discriminator,
   the writer-side helper produces a payload whose ``schema_version``
   matches the module-level constant.
"""
from __future__ import annotations

import pytest

from app.services.jsonb_normalizers import (
    ANALYSIS_CACHE_RESULT_SCHEMA_VERSION,
    ATTACK_SURFACE_ENTRIES_DANGEROUS_IMPORTS_SCHEMA_VERSION,
    ATTACK_SURFACE_ENTRIES_INPUT_CATEGORIES_SCHEMA_VERSION,
    ATTACK_SURFACE_ENTRIES_SCORE_BREAKDOWN_SCHEMA_VERSION,
    CONVERSATIONS_MESSAGES_SCHEMA_VERSION,
    CRA_REQUIREMENT_RESULTS_FINDING_IDS_SCHEMA_VERSION,
    CRA_REQUIREMENT_RESULTS_RELATED_CVES_SCHEMA_VERSION,
    CRA_REQUIREMENT_RESULTS_RELATED_CWES_SCHEMA_VERSION,
    CRA_REQUIREMENT_RESULTS_TOOL_SOURCES_SCHEMA_VERSION,
    EMULATION_PRESETS_PORT_FORWARDS_SCHEMA_VERSION,
    EMULATION_SESSIONS_DISCOVERED_SERVICES_SCHEMA_VERSION,
    EMULATION_SESSIONS_PORT_FORWARDS_SCHEMA_VERSION,
    FIRMWARE_APPCOMPAT_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_AUTHENTICODE_CHAIN_RESULT_SCHEMA_VERSION,
    FIRMWARE_BCD_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_BINARY_INFO_SCHEMA_VERSION,
    FIRMWARE_CONTAINER_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION,
    FIRMWARE_DOTNET_DECOMPILE_RESULT_SCHEMA_VERSION,
    FIRMWARE_DPAPI_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_EFS_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_ESP_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_ETL_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_EVTX_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_JOURNALD_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_MBR_VBR_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_MFT_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_PERSISTENCE_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_REGISTRY_HIVE_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_SRUM_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_SYSTEMD_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_USNJRNL_WALK_RESULT_SCHEMA_VERSION,
    FIRMWARE_WINDOWS_ARTIFACTS_SCHEMA_VERSION,
    FIRMWARE_WINDOWS_UPDATE_DIFF_RESULT_SCHEMA_VERSION,
    FIRMWARE_WMI_WALK_RESULT_SCHEMA_VERSION,
    FUZZING_CAMPAIGNS_CONFIG_SCHEMA_VERSION,
    FUZZING_CAMPAIGNS_STATS_SCHEMA_VERSION,
    HARDWARE_FIRMWARE_BLOBS_METADATA_SCHEMA_VERSION,
    LINUX_BASH_HISTORY_ENTRIES_SUSPICIOUS_FLAGS_SCHEMA_VERSION,
    LINUX_CONTAINER_ARTIFACTS_ANOMALY_FLAGS_SCHEMA_VERSION,
    LINUX_CRON_JOBS_SUSPICIOUS_FLAGS_SCHEMA_VERSION,
    LINUX_JOURNALD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION,
    LINUX_LD_PRELOAD_ENTRIES_SUSPICIOUS_FLAGS_SCHEMA_VERSION,
    LINUX_SYSTEMD_UNITS_ANOMALY_FLAGS_SCHEMA_VERSION,
    SBOM_COMPONENTS_METADATA_SCHEMA_VERSION,
    WINDOWS_APPCOMPAT_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION,
    WINDOWS_BCD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION,
    WINDOWS_BCD_ENTRIES_CUSTOM_ELEMENTS_SCHEMA_VERSION,
    WINDOWS_DPAPI_MASTER_KEYS_ANOMALY_FLAGS_SCHEMA_VERSION,
    WINDOWS_DRIVERS_INF_METADATA_SCHEMA_VERSION,
    WINDOWS_EFS_ENCRYPTED_FILES_ANOMALY_FLAGS_SCHEMA_VERSION,
    WINDOWS_EFS_ENCRYPTED_FILES_DDF_USERS_SCHEMA_VERSION,
    WINDOWS_EFS_ENCRYPTED_FILES_DRF_RECOVERY_AGENTS_SCHEMA_VERSION,
    WINDOWS_ESP_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION,
    WINDOWS_ESP_ENTRIES_AUTHENTICODE_CHAIN_SCHEMA_VERSION,
    WINDOWS_ESP_ENTRIES_DBX_REVOCATION_MATCH_SCHEMA_VERSION,
    WINDOWS_ETL_EVENTS_ANOMALY_FLAGS_SCHEMA_VERSION,
    WINDOWS_ETL_EVENTS_PAYLOAD_SCHEMA_VERSION,
    WINDOWS_EVENT_RECORDS_MESSAGE_XML_SCHEMA_VERSION,
    WINDOWS_MBR_VBR_SECTORS_ANOMALY_FLAGS_SCHEMA_VERSION,
    WINDOWS_MFT_RECORDS_ADS_STREAMS_SCHEMA_VERSION,
    WINDOWS_MFT_RECORDS_TARGET_METADATA_SCHEMA_VERSION,
    WINDOWS_PE_SIGNATURES_ARCH_VIEW_SCHEMA_VERSION,
    WINDOWS_PE_SIGNATURES_RICH_HEADER_JSON_SCHEMA_VERSION,
    WINDOWS_PREFETCH_RECORDS_ALL_RUN_TIMES_SCHEMA_VERSION,
    WINDOWS_PREFETCH_RECORDS_FILENAMES_REFERENCED_SCHEMA_VERSION,
    WINDOWS_PREFETCH_RECORDS_VOLUMES_SCHEMA_VERSION,
    WINDOWS_REGISTRY_EXTRACTS_PARSED_TREE_SCHEMA_VERSION,
    WINDOWS_SRUM_RECORDS_EXTRA_METADATA_SCHEMA_VERSION,
    WINDOWS_UPDATE_PACKAGES_UPDATE_METADATA_SCHEMA_VERSION,
    WINDOWS_USNJRNL_ENTRIES_REASON_FLAGS_SCHEMA_VERSION,
    WINDOWS_WMI_EVENTS_ANOMALY_FLAGS_SCHEMA_VERSION,
    WINDOWS_WMI_EVENTS_CONSUMER_PAYLOAD_SCHEMA_VERSION,
    _normalize_analysis_cache_result,
    _normalize_attack_surface_entries_dangerous_imports,
    _normalize_attack_surface_entries_input_categories,
    _normalize_attack_surface_entries_score_breakdown,
    _normalize_conversations_messages,
    _normalize_cra_requirement_results_finding_ids,
    _normalize_cra_requirement_results_related_cves,
    _normalize_cra_requirement_results_related_cwes,
    _normalize_cra_requirement_results_tool_sources,
    _normalize_emulation_presets_port_forwards,
    _normalize_emulation_sessions_discovered_services,
    _normalize_emulation_sessions_nvram_state,
    _normalize_emulation_sessions_port_forwards,
    _normalize_firmware_appcompat_walk_result,
    _normalize_firmware_authenticode_chain_result,
    _normalize_firmware_bcd_walk_result,
    _normalize_firmware_binary_info,
    _normalize_firmware_container_walk_result,
    _normalize_firmware_cve_match_result,
    _normalize_firmware_device_metadata,
    _normalize_firmware_dotnet_decompile_result,
    _normalize_firmware_dpapi_walk_result,
    _normalize_firmware_efs_walk_result,
    _normalize_firmware_esp_walk_result,
    _normalize_firmware_etl_walk_result,
    _normalize_firmware_evtx_walk_result,
    _normalize_firmware_journald_walk_result,
    _normalize_firmware_mbr_vbr_walk_result,
    _normalize_firmware_mft_walk_result,
    _normalize_firmware_persistence_walk_result,
    _normalize_firmware_registry_hive_walk_result,
    _normalize_firmware_srum_walk_result,
    _normalize_firmware_systemd_walk_result,
    _normalize_firmware_usnjrnl_walk_result,
    _normalize_firmware_windows_artifacts,
    _normalize_firmware_windows_update_diff_result,
    _normalize_firmware_wmi_walk_result,
    _normalize_fuzzing_campaigns_config,
    _normalize_fuzzing_campaigns_stats,
    _normalize_hardware_firmware_blobs_metadata,
    _normalize_linux_bash_history_suspicious_flags,
    _normalize_linux_container_artifacts_anomaly_flags,
    _normalize_linux_container_artifacts_capabilities_add,
    _normalize_linux_container_artifacts_capabilities_drop,
    _normalize_linux_container_artifacts_env_vars,
    _normalize_linux_container_artifacts_mounts,
    _normalize_linux_cron_suspicious_flags,
    _normalize_linux_journald_entries_anomaly_flags,
    _normalize_linux_ld_preload_suspicious_flags,
    _normalize_linux_systemd_units_after,
    _normalize_linux_systemd_units_anomaly_flags,
    _normalize_linux_systemd_units_before,
    _normalize_linux_systemd_units_required_by,
    _normalize_linux_systemd_units_requires,
    _normalize_linux_systemd_units_socket_listen,
    _normalize_linux_systemd_units_triggers,
    _normalize_linux_systemd_units_wanted_by,
    _normalize_sbom_components_metadata,
    _normalize_windows_appcompat_entries_anomaly_flags,
    _normalize_windows_bcd_entries_anomaly_flags,
    _normalize_windows_bcd_entries_custom_elements,
    _normalize_windows_dpapi_anomaly_flags,
    _normalize_windows_drivers_inf_metadata,
    _normalize_windows_efs_encrypted_files_anomaly_flags,
    _normalize_windows_efs_encrypted_files_ddf_users,
    _normalize_windows_efs_encrypted_files_drf_recovery_agents,
    _normalize_windows_esp_entries_anomaly_flags,
    _normalize_windows_esp_entries_authenticode_chain,
    _normalize_windows_esp_entries_dbx_revocation_match,
    _normalize_windows_etl_events_anomaly_flags,
    _normalize_windows_etl_events_payload,
    _normalize_windows_event_records_message_xml,
    _normalize_windows_mbr_vbr_sectors_anomaly_flags,
    _normalize_windows_mft_records_ads_streams,
    _normalize_windows_mft_records_target_metadata,
    _normalize_windows_pe_signatures_arch_view,
    _normalize_windows_pe_signatures_rich_header_json,
    _normalize_windows_prefetch_records_all_run_times,
    _normalize_windows_prefetch_records_filenames_referenced,
    _normalize_windows_prefetch_records_volumes,
    _normalize_windows_registry_extracts_parsed_tree,
    _normalize_windows_srum_records_extra_metadata,
    _normalize_windows_update_packages_update_metadata,
    _normalize_windows_usnjrnl_reason_flags,
    _normalize_windows_wmi_events_anomaly_flags,
    _normalize_windows_wmi_events_consumer_payload,
    _stamp_analysis_cache_result,
    _stamp_attack_surface_entries_score_breakdown,
    _stamp_firmware_appcompat_walk_result,
    _stamp_firmware_authenticode_chain_result,
    _stamp_firmware_bcd_walk_result,
    _stamp_firmware_binary_info,
    _stamp_firmware_container_walk_result,
    _stamp_firmware_device_metadata,
    _stamp_firmware_dotnet_decompile_result,
    _stamp_firmware_dpapi_walk_result,
    _stamp_firmware_efs_walk_result,
    _stamp_firmware_esp_walk_result,
    _stamp_firmware_etl_walk_result,
    _stamp_firmware_evtx_walk_result,
    _stamp_firmware_journald_walk_result,
    _stamp_firmware_mbr_vbr_walk_result,
    _stamp_firmware_mft_walk_result,
    _stamp_firmware_persistence_walk_result,
    _stamp_firmware_registry_hive_walk_result,
    _stamp_firmware_srum_walk_result,
    _stamp_firmware_systemd_walk_result,
    _stamp_firmware_usnjrnl_walk_result,
    _stamp_firmware_windows_artifacts,
    _stamp_firmware_windows_update_diff_result,
    _stamp_firmware_wmi_walk_result,
    _stamp_fuzzing_campaigns_config,
    _stamp_fuzzing_campaigns_stats,
    _stamp_hardware_firmware_blobs_metadata,
    _stamp_linux_bash_history_suspicious_flags,
    _stamp_linux_container_artifacts_anomaly_flags,
    _stamp_linux_cron_suspicious_flags,
    _stamp_linux_journald_entries_anomaly_flags,
    _stamp_linux_ld_preload_suspicious_flags,
    _stamp_linux_systemd_units_anomaly_flags,
    _stamp_windows_appcompat_entries_anomaly_flags,
    _stamp_windows_bcd_entries_anomaly_flags,
    _stamp_windows_bcd_entries_custom_elements,
    _stamp_windows_dpapi_anomaly_flags,
    _stamp_windows_drivers_inf_metadata,
    _stamp_windows_efs_encrypted_files_anomaly_flags,
    _stamp_windows_efs_encrypted_files_ddf_users,
    _stamp_windows_efs_encrypted_files_drf_recovery_agents,
    _stamp_windows_esp_entries_anomaly_flags,
    _stamp_windows_esp_entries_authenticode_chain,
    _stamp_windows_esp_entries_dbx_revocation_match,
    _stamp_windows_etl_events_anomaly_flags,
    _stamp_windows_etl_events_payload,
    _stamp_windows_event_records_message_xml,
    _stamp_windows_mbr_vbr_sectors_anomaly_flags,
    _stamp_windows_mft_records_ads_streams,
    _stamp_windows_mft_records_target_metadata,
    _stamp_windows_pe_signatures_arch_view,
    _stamp_windows_pe_signatures_rich_header_json,
    _stamp_windows_prefetch_records_all_run_times,
    _stamp_windows_prefetch_records_filenames_referenced,
    _stamp_windows_prefetch_records_volumes,
    _stamp_windows_registry_extracts_parsed_tree,
    _stamp_windows_srum_records_extra_metadata,
    _stamp_windows_update_packages_update_metadata,
    _stamp_windows_usnjrnl_reason_flags,
    _stamp_windows_wmi_events_anomaly_flags,
    _stamp_windows_wmi_events_consumer_payload,
)

# ── _normalize_firmware_device_metadata ──────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical shape — dict with arbitrary sub-keys.
        ({"detection_roots": ["/tmp/x"], "manufacturer": "ACME"},
         {"detection_roots": ["/tmp/x"], "manufacturer": "ACME"}),
        # Empty dict — preserved.
        ({}, {}),
        # Schema-versioned dict — preserved.
        ({"schema_version": 1, "vendor_decryption": []},
         {"schema_version": 1, "vendor_decryption": []}),
        # None — coerced to empty dict so callers can ``meta.get(...)`` safely.
        (None, {}),
        # Wrong type — list — coerced to empty dict.
        ([1, 2, 3], {}),
        # Wrong type — string — coerced to empty dict.
        ("not a dict", {}),
        # Wrong type — int — coerced to empty dict.
        (42, {}),
    ],
)
def test_normalize_firmware_device_metadata(value, expected):
    assert _normalize_firmware_device_metadata(value) == expected


def test_normalize_firmware_device_metadata_idempotent():
    canonical = {"schema_version": 1, "manufacturer": "ACME", "detection_roots": []}
    once = _normalize_firmware_device_metadata(canonical)
    twice = _normalize_firmware_device_metadata(once)
    assert once == twice == canonical


# ── _stamp_firmware_device_metadata ──────────────────────────────────────────


def test_stamp_firmware_device_metadata_adds_version():
    payload = {"manufacturer": "ACME"}
    out = _stamp_firmware_device_metadata(payload)
    assert out is not None
    assert out["schema_version"] == FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION
    assert out["manufacturer"] == "ACME"


def test_stamp_firmware_device_metadata_idempotent():
    payload = {"manufacturer": "ACME"}
    once = _stamp_firmware_device_metadata(payload)
    twice = _stamp_firmware_device_metadata(once)
    assert once == twice
    assert once["schema_version"] == FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION


def test_stamp_firmware_device_metadata_none_in_none_out():
    """None payload preserves the column's nullable contract."""
    assert _stamp_firmware_device_metadata(None) is None


def test_stamp_firmware_device_metadata_empty_in_none_out():
    """Empty dict collapses to None — writer semantic for `clear`."""
    assert _stamp_firmware_device_metadata({}) is None


def test_stamp_firmware_device_metadata_mutates_input():
    """Documents the mutation contract — writers may rely on it."""
    payload = {"manufacturer": "ACME"}
    out = _stamp_firmware_device_metadata(payload)
    assert out is payload  # same dict object
    assert "schema_version" in payload


# ── _normalize_conversations_messages ────────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical chat-style list-of-dicts.
        ([{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}],
         [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]),
        # Empty list — the column's server default — preserved.
        ([], []),
        # None — the column allows it briefly during writes — coerced to [].
        (None, []),
        # Wrong type — dict — coerced to [].
        ({"messages": []}, []),
        # Wrong type — string — coerced to [].
        ("not a list", []),
        # Mixed content — non-dict entries dropped.
        ([{"role": "user"}, "stray scalar", 42, {"role": "assistant"}],
         [{"role": "user"}, {"role": "assistant"}]),
    ],
)
def test_normalize_conversations_messages(value, expected):
    assert _normalize_conversations_messages(value) == expected


def test_normalize_conversations_messages_idempotent():
    canonical = [{"role": "user", "content": "hi"}]
    once = _normalize_conversations_messages(canonical)
    twice = _normalize_conversations_messages(once)
    assert once == twice == canonical


def test_conversations_messages_schema_version_constant():
    assert CONVERSATIONS_MESSAGES_SCHEMA_VERSION == 1


# ── _normalize_analysis_cache_result ─────────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Ghidra-style decompilation cache.
        ({"decompilation": "void main() { ... }", "function": "main"},
         {"decompilation": "void main() { ... }", "function": "main"}),
        # Canonical mobsfscan-style report.
        ({"results": [{"id": "X", "severity": "HIGH"}]},
         {"results": [{"id": "X", "severity": "HIGH"}]}),
        # Empty dict — preserved (writer's choice to store-empty is honoured).
        ({}, {}),
        # None — distinct from device_metadata: NULL means "not yet computed",
        # not "no data" — preserve None.
        (None, None),
        # Wrong type — list — collapses to None ("no usable cache").
        ([1, 2, 3], None),
        # Wrong type — string — collapses to None.
        ("not a dict", None),
    ],
)
def test_normalize_analysis_cache_result(value, expected):
    assert _normalize_analysis_cache_result(value) == expected


def test_normalize_analysis_cache_result_idempotent():
    canonical = {"results": [{"id": "X"}], "schema_version": 1}
    once = _normalize_analysis_cache_result(canonical)
    twice = _normalize_analysis_cache_result(once)
    assert once == twice == canonical


def test_stamp_analysis_cache_result_adds_version():
    payload = {"results": []}
    out = _stamp_analysis_cache_result(payload)
    assert out["schema_version"] == ANALYSIS_CACHE_RESULT_SCHEMA_VERSION
    assert out["results"] == []


def test_stamp_analysis_cache_result_idempotent():
    payload = {"results": []}
    once = _stamp_analysis_cache_result(payload)
    twice = _stamp_analysis_cache_result(once)
    assert once == twice
    assert once["schema_version"] == ANALYSIS_CACHE_RESULT_SCHEMA_VERSION


# ── _normalize_firmware_binary_info ──────────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical analyse_binary output.
        ({"architecture": "arm", "endianness": "little", "format": "elf",
          "extracted_filename": "firmware.bin"},
         {"architecture": "arm", "endianness": "little", "format": "elf",
          "extracted_filename": "firmware.bin"}),
        # Empty dict — preserved (writer's choice).
        ({}, {}),
        # None — preserved (semantic load: not analysed as a single binary).
        (None, None),
        # Wrong type — list — collapse to None (callers gate on `is not None`).
        ([1, 2], None),
        # Wrong type — string.
        ("elf", None),
    ],
)
def test_normalize_firmware_binary_info(value, expected):
    assert _normalize_firmware_binary_info(value) == expected


def test_normalize_firmware_binary_info_idempotent():
    canonical = {"architecture": "x86_64", "format": "elf"}
    once = _normalize_firmware_binary_info(canonical)
    twice = _normalize_firmware_binary_info(once)
    assert once == twice == canonical


def test_stamp_firmware_binary_info_adds_version():
    payload = {"architecture": "mips"}
    out = _stamp_firmware_binary_info(payload)
    assert out["schema_version"] == FIRMWARE_BINARY_INFO_SCHEMA_VERSION
    assert out["architecture"] == "mips"


def test_stamp_firmware_binary_info_preserves_none():
    """None payload is preserved — column is nullable for non-binary firmwares."""
    assert _stamp_firmware_binary_info(None) is None


def test_stamp_firmware_binary_info_idempotent():
    payload = {"architecture": "arm"}
    once = _stamp_firmware_binary_info(payload)
    twice = _stamp_firmware_binary_info(once)
    assert once == twice


# ── _normalize_firmware_cve_match_result ─────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical CveMatchRunResult.model_dump() shape — one slice.
        ({"summary": {"total": 5}, "tier_4": [], "tier_3": []},
         {"summary": {"total": 5}, "tier_4": [], "tier_3": []}),
        # None — preserved (no completed run).
        (None, None),
        # Wrong type — list — collapses to None.
        ([], None),
        # Empty dict — preserved (legitimate empty aggregate).
        ({}, {}),
    ],
)
def test_normalize_firmware_cve_match_result(value, expected):
    assert _normalize_firmware_cve_match_result(value) == expected


def test_normalize_firmware_cve_match_result_idempotent():
    canonical = {"summary": {"total": 0}}
    once = _normalize_firmware_cve_match_result(canonical)
    twice = _normalize_firmware_cve_match_result(once)
    assert once == twice == canonical


# ── _normalize_fuzzing_campaigns_config ──────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical AFL++ config dict.
        ({"timeout": 1000, "memory_limit": 256, "dictionary": None,
          "seed_corpus": "/seeds"},
         {"timeout": 1000, "memory_limit": 256, "dictionary": None,
          "seed_corpus": "/seeds"}),
        # Empty dict — server default.
        ({}, {}),
        # None — coerce to {} so consumers .get() safely.
        (None, {}),
        # Wrong type — list — coerce to {}.
        ([1, 2], {}),
    ],
)
def test_normalize_fuzzing_campaigns_config(value, expected):
    assert _normalize_fuzzing_campaigns_config(value) == expected


def test_stamp_fuzzing_campaigns_config_adds_version():
    payload = {"timeout": 2000}
    out = _stamp_fuzzing_campaigns_config(payload)
    assert out["schema_version"] == FUZZING_CAMPAIGNS_CONFIG_SCHEMA_VERSION


def test_stamp_fuzzing_campaigns_config_idempotent():
    payload = {"timeout": 2000}
    once = _stamp_fuzzing_campaigns_config(payload)
    twice = _stamp_fuzzing_campaigns_config(once)
    assert once == twice


# ── _normalize_fuzzing_campaigns_stats ───────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical AFL++ stats.
        ({"execs_per_sec": 5000, "total_execs": 1000000, "saved_crashes": 3},
         {"execs_per_sec": 5000, "total_execs": 1000000, "saved_crashes": 3}),
        ({}, {}),
        (None, {}),
        ([], {}),
    ],
)
def test_normalize_fuzzing_campaigns_stats(value, expected):
    assert _normalize_fuzzing_campaigns_stats(value) == expected


def test_stamp_fuzzing_campaigns_stats_adds_version():
    payload = {"total_execs": 100}
    out = _stamp_fuzzing_campaigns_stats(payload)
    assert out["schema_version"] == FUZZING_CAMPAIGNS_STATS_SCHEMA_VERSION


def test_stamp_fuzzing_campaigns_stats_idempotent():
    payload = {"total_execs": 100}
    once = _stamp_fuzzing_campaigns_stats(payload)
    twice = _stamp_fuzzing_campaigns_stats(once)
    assert once == twice


# ── _normalize_emulation_sessions_port_forwards ──────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical list-of-host/guest pairs.
        ([{"host": 8080, "guest": 80}, {"host": 2222, "guest": 22}],
         [{"host": 8080, "guest": 80}, {"host": 2222, "guest": 22}]),
        ([], []),
        (None, []),
        ({"port": 8080}, []),
        ("8080:80", []),
        # Mixed — non-dict entries dropped.
        ([{"host": 80, "guest": 80}, "scalar"], [{"host": 80, "guest": 80}]),
    ],
)
def test_normalize_emulation_sessions_port_forwards(value, expected):
    assert _normalize_emulation_sessions_port_forwards(value) == expected


def test_normalize_emulation_sessions_port_forwards_idempotent():
    canonical = [{"host": 8000, "guest": 80}]
    once = _normalize_emulation_sessions_port_forwards(canonical)
    twice = _normalize_emulation_sessions_port_forwards(once)
    assert once == twice == canonical


def test_emulation_sessions_port_forwards_schema_version_constant():
    assert EMULATION_SESSIONS_PORT_FORWARDS_SCHEMA_VERSION == 1


# ── _normalize_emulation_sessions_discovered_services ────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        ([{"port": 80, "protocol": "tcp", "service": "http",
           "host_port": 8080, "url": "http://localhost:8080"}],
         [{"port": 80, "protocol": "tcp", "service": "http",
           "host_port": 8080, "url": "http://localhost:8080"}]),
        ([], []),
        # None — typical pre-startup-probe state — coerce to empty list.
        (None, []),
        ({"port": 80}, []),
        # Mixed — drop scalar.
        ([{"port": 22}, "ssh"], [{"port": 22}]),
    ],
)
def test_normalize_emulation_sessions_discovered_services(value, expected):
    assert _normalize_emulation_sessions_discovered_services(value) == expected


def test_emulation_sessions_discovered_services_schema_version_constant():
    assert EMULATION_SESSIONS_DISCOVERED_SERVICES_SCHEMA_VERSION == 1


# ── _normalize_emulation_sessions_nvram_state ────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical NVRAM key→string dict.
        ({"wifi_ssid": "MyAP", "wifi_password": "secret"},
         {"wifi_ssid": "MyAP", "wifi_password": "secret"}),
        ({}, {}),
        # None — typical pre-read state — preserved.
        (None, None),
        # Wrong type — list — collapse to None.
        ([], None),
        # Wrong type — string.
        ("nvram=value", None),
    ],
)
def test_normalize_emulation_sessions_nvram_state(value, expected):
    assert _normalize_emulation_sessions_nvram_state(value) == expected


def test_normalize_emulation_sessions_nvram_state_idempotent():
    canonical = {"key": "val"}
    once = _normalize_emulation_sessions_nvram_state(canonical)
    twice = _normalize_emulation_sessions_nvram_state(once)
    assert once == twice == canonical


# ── _normalize_emulation_presets_port_forwards ───────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        ([{"host": 8080, "guest": 80}], [{"host": 8080, "guest": 80}]),
        ([], []),
        (None, []),
        ({"host": 80}, []),
        ([{"host": 22, "guest": 22}, None, "scalar"], [{"host": 22, "guest": 22}]),
    ],
)
def test_normalize_emulation_presets_port_forwards(value, expected):
    assert _normalize_emulation_presets_port_forwards(value) == expected


def test_emulation_presets_port_forwards_schema_version_constant():
    assert EMULATION_PRESETS_PORT_FORWARDS_SCHEMA_VERSION == 1


# ── _normalize_attack_surface_entries_score_breakdown ────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"network_score": 10, "dangerous_score": 8, "setuid_score": 0},
         {"network_score": 10, "dangerous_score": 8, "setuid_score": 0}),
        ({}, {}),
        (None, {}),
        ([], {}),
    ],
)
def test_normalize_attack_surface_entries_score_breakdown(value, expected):
    assert _normalize_attack_surface_entries_score_breakdown(value) == expected


def test_stamp_attack_surface_entries_score_breakdown_adds_version():
    payload = {"network_score": 10}
    out = _stamp_attack_surface_entries_score_breakdown(payload)
    assert out["schema_version"] == ATTACK_SURFACE_ENTRIES_SCORE_BREAKDOWN_SCHEMA_VERSION


# ── _normalize_attack_surface_entries_dangerous_imports ──────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (["strcpy", "gets", "sprintf"], ["strcpy", "gets", "sprintf"]),
        ([], []),
        (None, []),
        # Mixed list — only strings survive.
        (["strcpy", 42, None, {"sym": "x"}], ["strcpy"]),
    ],
)
def test_normalize_attack_surface_entries_dangerous_imports(value, expected):
    assert _normalize_attack_surface_entries_dangerous_imports(value) == expected


def test_attack_surface_entries_dangerous_imports_schema_version_constant():
    assert ATTACK_SURFACE_ENTRIES_DANGEROUS_IMPORTS_SCHEMA_VERSION == 1


# ── _normalize_attack_surface_entries_input_categories ───────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (["network", "filesystem", "ipc"], ["network", "filesystem", "ipc"]),
        ([], []),
        (None, []),
        (["network", 1, None], ["network"]),
    ],
)
def test_normalize_attack_surface_entries_input_categories(value, expected):
    assert _normalize_attack_surface_entries_input_categories(value) == expected


def test_attack_surface_entries_input_categories_schema_version_constant():
    assert ATTACK_SURFACE_ENTRIES_INPUT_CATEGORIES_SCHEMA_VERSION == 1


# ── _normalize_sbom_components_metadata ──────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"package": "openssl", "epoch": "1"}, {"package": "openssl", "epoch": "1"}),
        ({}, {}),
        (None, {}),
        ([], {}),
    ],
)
def test_normalize_sbom_components_metadata(value, expected):
    assert _normalize_sbom_components_metadata(value) == expected


def test_sbom_components_metadata_schema_version_constant():
    assert SBOM_COMPONENTS_METADATA_SCHEMA_VERSION == 1


# ── _normalize_hardware_firmware_blobs_metadata ──────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"kernel_semver": "5.4.224", "known_vulnerabilities": []},
         {"kernel_semver": "5.4.224", "known_vulnerabilities": []}),
        ({}, {}),
        (None, {}),
        ([1, 2], {}),
    ],
)
def test_normalize_hardware_firmware_blobs_metadata(value, expected):
    assert _normalize_hardware_firmware_blobs_metadata(value) == expected


def test_stamp_hardware_firmware_blobs_metadata_adds_version():
    payload = {"kernel_semver": "5.4.224"}
    out = _stamp_hardware_firmware_blobs_metadata(payload)
    assert out["schema_version"] == HARDWARE_FIRMWARE_BLOBS_METADATA_SCHEMA_VERSION


def test_stamp_hardware_firmware_blobs_metadata_idempotent():
    payload = {"foo": "bar"}
    once = _stamp_hardware_firmware_blobs_metadata(payload)
    twice = _stamp_hardware_firmware_blobs_metadata(once)
    assert once == twice


# ── _normalize_cra_requirement_results_* (4 list[str] columns) ───────────────


@pytest.mark.parametrize(
    "fn,value,expected",
    [
        # finding_ids
        (_normalize_cra_requirement_results_finding_ids,
         ["uuid1", "uuid2"], ["uuid1", "uuid2"]),
        (_normalize_cra_requirement_results_finding_ids, [], []),
        (_normalize_cra_requirement_results_finding_ids, None, []),
        (_normalize_cra_requirement_results_finding_ids, ["a", 1, None], ["a"]),
        # tool_sources
        (_normalize_cra_requirement_results_tool_sources,
         ["yara", "ghidra", "mobsfscan"],
         ["yara", "ghidra", "mobsfscan"]),
        (_normalize_cra_requirement_results_tool_sources, None, []),
        # related_cwes
        (_normalize_cra_requirement_results_related_cwes,
         ["CWE-79", "CWE-89"], ["CWE-79", "CWE-89"]),
        (_normalize_cra_requirement_results_related_cwes, "CWE-79", []),
        # related_cves
        (_normalize_cra_requirement_results_related_cves,
         ["CVE-2024-1234"], ["CVE-2024-1234"]),
        (_normalize_cra_requirement_results_related_cves, {"foo": "bar"}, []),
    ],
)
def test_normalize_cra_requirement_results_columns(fn, value, expected):
    assert fn(value) == expected


def test_cra_requirement_results_schema_version_constants():
    assert CRA_REQUIREMENT_RESULTS_FINDING_IDS_SCHEMA_VERSION == 1
    assert CRA_REQUIREMENT_RESULTS_TOOL_SOURCES_SCHEMA_VERSION == 1
    assert CRA_REQUIREMENT_RESULTS_RELATED_CWES_SCHEMA_VERSION == 1
    assert CRA_REQUIREMENT_RESULTS_RELATED_CVES_SCHEMA_VERSION == 1


# ── _normalize_firmware_windows_artifacts (sub-key) ──────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Phase-α shape.
        ({"schema_version": 1, "cab_count": 3, "msi_count": 1, "msix_count": 0,
          "msu_count": 1, "psf_count": 1, "vhdx_count": 0, "driver_package_count": 2,
          "driver_package_subtype": "cab_inf_sys_cat"},
         {"schema_version": 1, "cab_count": 3, "msi_count": 1, "msix_count": 0,
          "msu_count": 1, "psf_count": 1, "vhdx_count": 0, "driver_package_count": 2,
          "driver_package_subtype": "cab_inf_sys_cat"}),
        # Empty dict — preserved (no Windows artifacts found, but sub-key present).
        ({}, {}),
        # None — sub-key absent on non-Windows firmware — coerced to {}.
        (None, {}),
        # Wrong type — list — coerced to {}.
        ([{"cab_count": 1}], {}),
        # Wrong type — string — coerced to {}.
        ("3 CABs found", {}),
        # Wrong type — int — coerced to {}.
        (3, {}),
    ],
)
def test_normalize_firmware_windows_artifacts(value, expected):
    assert _normalize_firmware_windows_artifacts(value) == expected


def test_normalize_firmware_windows_artifacts_idempotent():
    canonical = {"schema_version": 1, "cab_count": 1, "msi_count": 0}
    once = _normalize_firmware_windows_artifacts(canonical)
    twice = _normalize_firmware_windows_artifacts(once)
    assert once == twice == canonical


def test_stamp_firmware_windows_artifacts_adds_version():
    payload = {"cab_count": 2, "msi_count": 1}
    out = _stamp_firmware_windows_artifacts(payload)
    assert out is not None
    assert out["schema_version"] == FIRMWARE_WINDOWS_ARTIFACTS_SCHEMA_VERSION
    assert out["cab_count"] == 2
    assert out["msi_count"] == 1


def test_stamp_firmware_windows_artifacts_idempotent():
    payload = {"cab_count": 2}
    once = _stamp_firmware_windows_artifacts(payload)
    twice = _stamp_firmware_windows_artifacts(once)
    assert once == twice
    assert once["schema_version"] == FIRMWARE_WINDOWS_ARTIFACTS_SCHEMA_VERSION


def test_stamp_firmware_windows_artifacts_none_in_none_out():
    """None payload preserves the sub-key's nullable contract."""
    assert _stamp_firmware_windows_artifacts(None) is None


def test_stamp_firmware_windows_artifacts_empty_in_none_out():
    """Empty dict collapses to None — writer's clear-the-sub-key semantic."""
    assert _stamp_firmware_windows_artifacts({}) is None


def test_stamp_firmware_windows_artifacts_mutates_input():
    """Documents the mutation contract — writers may rely on it."""
    payload = {"cab_count": 1}
    out = _stamp_firmware_windows_artifacts(payload)
    assert out is payload  # same dict object
    assert "schema_version" in payload


def test_firmware_windows_artifacts_schema_version_constant():
    assert FIRMWARE_WINDOWS_ARTIFACTS_SCHEMA_VERSION == 1


# ── _normalize_firmware_authenticode_chain_result (Phase β.3) ────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Phase-β.4 aggregate shape.
        ({"schema_version": 1, "signed_count": 42, "signed_pct": 0.84,
          "unsigned_count": 8, "dbx_revoked_count": 0,
          "by_chain_status": {"valid_at_signing": 30, "valid_now": 12, "revoked": 0,
                              "never_valid": 0, "unknown": 8},
          "run_seconds": 12.5, "total_pe_count": 50},
         {"schema_version": 1, "signed_count": 42, "signed_pct": 0.84,
          "unsigned_count": 8, "dbx_revoked_count": 0,
          "by_chain_status": {"valid_at_signing": 30, "valid_now": 12, "revoked": 0,
                              "never_valid": 0, "unknown": 8},
          "run_seconds": 12.5, "total_pe_count": 50}),
        ({}, {}),
        # None preserved — distinct from device_metadata: NULL means "no
        # completed run yet" not "no signatures present".
        (None, None),
        ([1, 2, 3], None),
        ("not a dict", None),
    ],
)
def test_normalize_firmware_authenticode_chain_result(value, expected):
    assert _normalize_firmware_authenticode_chain_result(value) == expected


def test_normalize_firmware_authenticode_chain_result_idempotent():
    canonical = {"schema_version": 1, "signed_count": 0, "total_pe_count": 0}
    once = _normalize_firmware_authenticode_chain_result(canonical)
    twice = _normalize_firmware_authenticode_chain_result(once)
    assert once == twice == canonical


def test_stamp_firmware_authenticode_chain_result_adds_version():
    payload = {"signed_count": 5}
    out = _stamp_firmware_authenticode_chain_result(payload)
    assert out["schema_version"] == FIRMWARE_AUTHENTICODE_CHAIN_RESULT_SCHEMA_VERSION
    assert out["signed_count"] == 5


def test_stamp_firmware_authenticode_chain_result_idempotent():
    payload = {"signed_count": 5}
    once = _stamp_firmware_authenticode_chain_result(payload)
    twice = _stamp_firmware_authenticode_chain_result(once)
    assert once == twice
    assert once["schema_version"] == FIRMWARE_AUTHENTICODE_CHAIN_RESULT_SCHEMA_VERSION


def test_firmware_authenticode_chain_result_schema_version_constant():
    assert FIRMWARE_AUTHENTICODE_CHAIN_RESULT_SCHEMA_VERSION == 1


# ── _normalize_windows_pe_signatures_arch_view (Phase β.5) ───────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical ARM64X shape — bimorphic ARM64 + AMD64 with measured
        # divergence count.
        ({"schema_version": 1, "primary": "arm64x", "secondary": "amd64",
          "divergence_score": 42},
         {"schema_version": 1, "primary": "arm64x", "secondary": "amd64",
          "divergence_score": 42}),
        # Canonical ARM64EC shape — x64-ABI ARM64 with redirection count.
        ({"schema_version": 1, "primary": "arm64ec", "secondary": "x64_abi",
          "divergence_score": 128},
         {"schema_version": 1, "primary": "arm64ec", "secondary": "x64_abi",
          "divergence_score": 128}),
        # Empty dict — preserved (writer will collapse via _stamp).
        ({}, {}),
        # None — durable signal for "single-arch PE; no bimorphic split".
        # Distinct from other JSONB columns that coerce None → {}.
        (None, None),
        # Wrong type — list — coerced to None (no usable arch_view).
        ([{"primary": "arm64x"}], None),
        # Wrong type — string — coerced to None.
        ("arm64x", None),
        # Wrong type — int — coerced to None.
        (42, None),
    ],
)
def test_normalize_windows_pe_signatures_arch_view(value, expected):
    assert _normalize_windows_pe_signatures_arch_view(value) == expected


def test_normalize_windows_pe_signatures_arch_view_idempotent():
    canonical = {"schema_version": 1, "primary": "arm64x",
                 "secondary": "amd64", "divergence_score": 7}
    once = _normalize_windows_pe_signatures_arch_view(canonical)
    twice = _normalize_windows_pe_signatures_arch_view(once)
    assert once == twice == canonical


def test_stamp_windows_pe_signatures_arch_view_adds_version():
    payload = {"primary": "arm64ec", "secondary": "x64_abi",
               "divergence_score": 3}
    out = _stamp_windows_pe_signatures_arch_view(payload)
    assert out is not None
    assert out["schema_version"] == WINDOWS_PE_SIGNATURES_ARCH_VIEW_SCHEMA_VERSION
    assert out["primary"] == "arm64ec"
    assert out["secondary"] == "x64_abi"
    assert out["divergence_score"] == 3


def test_stamp_windows_pe_signatures_arch_view_idempotent():
    payload = {"primary": "arm64x", "secondary": "amd64", "divergence_score": 1}
    once = _stamp_windows_pe_signatures_arch_view(payload)
    twice = _stamp_windows_pe_signatures_arch_view(once)
    assert once == twice
    assert once["schema_version"] == WINDOWS_PE_SIGNATURES_ARCH_VIEW_SCHEMA_VERSION


def test_stamp_windows_pe_signatures_arch_view_none_in_none_out():
    """None payload preserves the "single-arch PE" semantic."""
    assert _stamp_windows_pe_signatures_arch_view(None) is None


def test_stamp_windows_pe_signatures_arch_view_empty_in_none_out():
    """Empty dict collapses to None — writer's clear / single-arch semantic."""
    assert _stamp_windows_pe_signatures_arch_view({}) is None


def test_stamp_windows_pe_signatures_arch_view_mutates_input():
    """Documents the mutation contract — writers may rely on it."""
    payload = {"primary": "arm64x", "secondary": "amd64", "divergence_score": 1}
    out = _stamp_windows_pe_signatures_arch_view(payload)
    assert out is payload  # same dict object
    assert "schema_version" in payload


def test_windows_pe_signatures_arch_view_schema_version_constant():
    assert WINDOWS_PE_SIGNATURES_ARCH_VIEW_SCHEMA_VERSION == 1


# ── _normalize_windows_pe_signatures_rich_header_json (Phase β.6) ────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Phase-β.6 shape.
        ({"schema_version": 1, "xor_key": "0x12345678", "entry_count": 2,
          "entries": [{"comp_id": 0x010500CC, "build_number": 0x0105,
                       "product_id": 0x00CC, "instances": 7}],
          "hash_md5": "deadbeef" + "0" * 24},
         {"schema_version": 1, "xor_key": "0x12345678", "entry_count": 2,
          "entries": [{"comp_id": 0x010500CC, "build_number": 0x0105,
                       "product_id": 0x00CC, "instances": 7}],
          "hash_md5": "deadbeef" + "0" * 24}),
        # Empty dict — preserved (writer collapses via _stamp).
        ({}, {}),
        # None — durable signal for "PE has no RICH header".
        (None, None),
        # Wrong type — list — coerced to None.
        ([{"comp_id": 1}], None),
        # Wrong type — string — coerced to None.
        ("0x12345678", None),
        # Wrong type — int — coerced to None.
        (42, None),
    ],
)
def test_normalize_windows_pe_signatures_rich_header_json(value, expected):
    assert _normalize_windows_pe_signatures_rich_header_json(value) == expected


def test_normalize_windows_pe_signatures_rich_header_json_idempotent():
    canonical = {"schema_version": 1, "xor_key": "0x0", "entry_count": 0,
                 "entries": [], "hash_md5": "abc"}
    once = _normalize_windows_pe_signatures_rich_header_json(canonical)
    twice = _normalize_windows_pe_signatures_rich_header_json(once)
    assert once == twice == canonical


def test_stamp_windows_pe_signatures_rich_header_json_adds_version():
    payload = {"xor_key": "0x12345678", "entry_count": 1,
               "entries": [], "hash_md5": "abc"}
    out = _stamp_windows_pe_signatures_rich_header_json(payload)
    assert out is not None
    assert out["schema_version"] == WINDOWS_PE_SIGNATURES_RICH_HEADER_JSON_SCHEMA_VERSION
    assert out["xor_key"] == "0x12345678"


def test_stamp_windows_pe_signatures_rich_header_json_idempotent():
    payload = {"xor_key": "0x0", "entry_count": 0, "entries": [], "hash_md5": "x"}
    once = _stamp_windows_pe_signatures_rich_header_json(payload)
    twice = _stamp_windows_pe_signatures_rich_header_json(once)
    assert once == twice
    assert once["schema_version"] == WINDOWS_PE_SIGNATURES_RICH_HEADER_JSON_SCHEMA_VERSION


def test_stamp_windows_pe_signatures_rich_header_json_none_in_none_out():
    """None payload preserves the "no RICH header" semantic."""
    assert _stamp_windows_pe_signatures_rich_header_json(None) is None


def test_stamp_windows_pe_signatures_rich_header_json_empty_in_none_out():
    """Empty dict collapses to None — writer's clear / no-RICH semantic."""
    assert _stamp_windows_pe_signatures_rich_header_json({}) is None


def test_stamp_windows_pe_signatures_rich_header_json_mutates_input():
    """Documents the mutation contract — writers may rely on it."""
    payload = {"xor_key": "0x0", "entry_count": 0, "entries": [], "hash_md5": "x"}
    out = _stamp_windows_pe_signatures_rich_header_json(payload)
    assert out is payload  # same dict object
    assert "schema_version" in payload


def test_windows_pe_signatures_rich_header_json_schema_version_constant():
    assert WINDOWS_PE_SIGNATURES_RICH_HEADER_JSON_SCHEMA_VERSION == 1


# ── _normalize_windows_registry_extracts_parsed_tree (Phase γ.1) ─────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Phase γ.4 walker shape — flat list of subkeys with
        # values per path; SOFTWARE.hive walk that found a Run key.
        (
            {
                "schema_version": 1,
                "hive_type": "SOFTWARE",
                "walk_complete": True,
                "depth_limit": 5,
                "key_count": 12345,
                "value_count": 56789,
                "truncated": False,
                "errors": [],
                "subkeys": [
                    {
                        "path": "Microsoft\\Windows\\CurrentVersion\\Run",
                        "values": [
                            {
                                "name": "OneDrive",
                                "type": "REG_SZ",
                                "data": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
                            },
                        ],
                    },
                ],
            },
            {
                "schema_version": 1,
                "hive_type": "SOFTWARE",
                "walk_complete": True,
                "depth_limit": 5,
                "key_count": 12345,
                "value_count": 56789,
                "truncated": False,
                "errors": [],
                "subkeys": [
                    {
                        "path": "Microsoft\\Windows\\CurrentVersion\\Run",
                        "values": [
                            {
                                "name": "OneDrive",
                                "type": "REG_SZ",
                                "data": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
                            },
                        ],
                    },
                ],
            },
        ),
        # Truncated walk — depth/key cap stopped the walker; partial
        # data should still pass through canonically.
        (
            {
                "schema_version": 1,
                "hive_type": "SYSTEM",
                "walk_complete": False,
                "depth_limit": 3,
                "key_count": 10000,
                "value_count": 30000,
                "truncated": True,
                "errors": ["max_keys_per_hive=10000 reached at CurrentControlSet\\Services"],
                "subkeys": [],
            },
            {
                "schema_version": 1,
                "hive_type": "SYSTEM",
                "walk_complete": False,
                "depth_limit": 3,
                "key_count": 10000,
                "value_count": 30000,
                "truncated": True,
                "errors": ["max_keys_per_hive=10000 reached at CurrentControlSet\\Services"],
                "subkeys": [],
            },
        ),
        # Empty dict — preserved (writer's degenerate-but-valid case).
        ({}, {}),
        # None — durable signal for "row exists but no parsed_tree
        # written" (walk failed before producing output, or walk_status
        # is 'skipped'). Distinct from {} which means "walk ran".
        (None, None),
        # Wrong type — list — coerced to None (no usable parsed_tree).
        ([{"path": "X"}], None),
        # Wrong type — string.
        ("not a dict", None),
        # Wrong type — int.
        (42, None),
    ],
)
def test_normalize_windows_registry_extracts_parsed_tree(value, expected):
    assert _normalize_windows_registry_extracts_parsed_tree(value) == expected


def test_normalize_windows_registry_extracts_parsed_tree_idempotent():
    canonical = {
        "schema_version": 1,
        "hive_type": "SAM",
        "walk_complete": True,
        "depth_limit": 5,
        "key_count": 0,
        "value_count": 0,
        "truncated": False,
        "errors": [],
        "subkeys": [],
    }
    once = _normalize_windows_registry_extracts_parsed_tree(canonical)
    twice = _normalize_windows_registry_extracts_parsed_tree(once)
    assert once == twice == canonical


def test_stamp_windows_registry_extracts_parsed_tree_adds_version():
    payload = {
        "hive_type": "NTUSER",
        "walk_complete": True,
        "subkeys": [],
    }
    out = _stamp_windows_registry_extracts_parsed_tree(payload)
    assert out is not None
    assert out["schema_version"] == WINDOWS_REGISTRY_EXTRACTS_PARSED_TREE_SCHEMA_VERSION
    assert out["hive_type"] == "NTUSER"


def test_stamp_windows_registry_extracts_parsed_tree_idempotent():
    payload = {"hive_type": "SOFTWARE", "subkeys": []}
    once = _stamp_windows_registry_extracts_parsed_tree(payload)
    twice = _stamp_windows_registry_extracts_parsed_tree(once)
    assert once == twice
    assert once["schema_version"] == WINDOWS_REGISTRY_EXTRACTS_PARSED_TREE_SCHEMA_VERSION


def test_stamp_windows_registry_extracts_parsed_tree_none_in_none_out():
    """None payload preserves the "row exists but no walk yet" semantic."""
    assert _stamp_windows_registry_extracts_parsed_tree(None) is None


def test_stamp_windows_registry_extracts_parsed_tree_mutates_input():
    """Documents the mutation contract — writers may rely on it."""
    payload = {"hive_type": "SYSTEM", "subkeys": []}
    out = _stamp_windows_registry_extracts_parsed_tree(payload)
    assert out is payload  # same dict object
    assert "schema_version" in payload


def test_windows_registry_extracts_parsed_tree_schema_version_constant():
    assert WINDOWS_REGISTRY_EXTRACTS_PARSED_TREE_SCHEMA_VERSION == 1


# ── _normalize_windows_drivers_inf_metadata (Phase γ.2) ──────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Phase γ.5 INF parse — multi-mfg INF with one model
        # entry, [Strings] block populated, no parse errors.
        (
            {
                "schema_version": 1,
                "version_block": {
                    "Class": "Display",
                    "ClassGuid": "{4d36e968-e325-11ce-bfc1-08002be10318}",
                    "Provider": "%MfgName%",
                    "DriverVer": "01/15/2024,31.0.101.5333",
                    "CatalogFile": "iigd_dch.cat",
                },
                "manufacturer_block": [
                    {
                        "name": "%MfgName%",
                        "section": "IntelGfx",
                        "decorations": ["NTAMD64.10.0..19041"],
                    },
                ],
                "models": [
                    {
                        "manufacturer": "Intel Corporation",
                        "device_description": "Intel(R) UHD Graphics 770",
                        "install_section": "iIGDX",
                        "hardware_id": "PCI\\VEN_8086&DEV_4680",
                        "compatible_ids": ["PCI\\VEN_8086&CC_0300"],
                    },
                ],
                "strings": {
                    "MfgName": "Intel Corporation",
                    "INTEL_HD_GRAPHICS": "Intel(R) HD Graphics",
                },
                "errors": [],
            },
            {
                "schema_version": 1,
                "version_block": {
                    "Class": "Display",
                    "ClassGuid": "{4d36e968-e325-11ce-bfc1-08002be10318}",
                    "Provider": "%MfgName%",
                    "DriverVer": "01/15/2024,31.0.101.5333",
                    "CatalogFile": "iigd_dch.cat",
                },
                "manufacturer_block": [
                    {
                        "name": "%MfgName%",
                        "section": "IntelGfx",
                        "decorations": ["NTAMD64.10.0..19041"],
                    },
                ],
                "models": [
                    {
                        "manufacturer": "Intel Corporation",
                        "device_description": "Intel(R) UHD Graphics 770",
                        "install_section": "iIGDX",
                        "hardware_id": "PCI\\VEN_8086&DEV_4680",
                        "compatible_ids": ["PCI\\VEN_8086&CC_0300"],
                    },
                ],
                "strings": {
                    "MfgName": "Intel Corporation",
                    "INTEL_HD_GRAPHICS": "Intel(R) HD Graphics",
                },
                "errors": [],
            },
        ),
        # Partial parse — INF [Version] block extracted but [Models]
        # blew up; errors list populated, models list empty.
        (
            {
                "schema_version": 1,
                "version_block": {
                    "Class": "Net",
                    "ClassGuid": "{4d36e972-e325-11ce-bfc1-08002be10318}",
                    "Provider": None,
                    "DriverVer": None,
                    "CatalogFile": None,
                },
                "manufacturer_block": [],
                "models": [],
                "strings": {},
                "errors": [
                    "[Models] section section-name resolution failed: "
                    "unresolved %SubstToken%",
                ],
            },
            {
                "schema_version": 1,
                "version_block": {
                    "Class": "Net",
                    "ClassGuid": "{4d36e972-e325-11ce-bfc1-08002be10318}",
                    "Provider": None,
                    "DriverVer": None,
                    "CatalogFile": None,
                },
                "manufacturer_block": [],
                "models": [],
                "strings": {},
                "errors": [
                    "[Models] section section-name resolution failed: "
                    "unresolved %SubstToken%",
                ],
            },
        ),
        # Empty dict — preserved (writer's degenerate-but-valid case).
        ({}, {}),
        # None — durable signal for "row exists but no INF parse"
        # (driver detected via SYS-only or pre-γ row).
        (None, None),
        # Wrong type — list — coerced to None.
        ([{"Class": "Display"}], None),
        # Wrong type — string.
        ("not a dict", None),
        # Wrong type — int.
        (42, None),
    ],
)
def test_normalize_windows_drivers_inf_metadata(value, expected):
    assert _normalize_windows_drivers_inf_metadata(value) == expected


def test_normalize_windows_drivers_inf_metadata_idempotent():
    canonical = {
        "schema_version": 1,
        "version_block": {"Class": "USB", "ClassGuid": None,
                          "Provider": None, "DriverVer": None,
                          "CatalogFile": None},
        "manufacturer_block": [],
        "models": [],
        "strings": {},
        "errors": [],
    }
    once = _normalize_windows_drivers_inf_metadata(canonical)
    twice = _normalize_windows_drivers_inf_metadata(once)
    assert once == twice == canonical


def test_stamp_windows_drivers_inf_metadata_adds_version():
    payload = {
        "version_block": {"Class": "Display"},
        "manufacturer_block": [],
        "models": [],
        "strings": {},
        "errors": [],
    }
    out = _stamp_windows_drivers_inf_metadata(payload)
    assert out is not None
    assert out["schema_version"] == WINDOWS_DRIVERS_INF_METADATA_SCHEMA_VERSION
    assert out["version_block"]["Class"] == "Display"


def test_stamp_windows_drivers_inf_metadata_idempotent():
    payload = {"version_block": {}, "manufacturer_block": [], "models": [],
               "strings": {}, "errors": []}
    once = _stamp_windows_drivers_inf_metadata(payload)
    twice = _stamp_windows_drivers_inf_metadata(once)
    assert once == twice
    assert once["schema_version"] == WINDOWS_DRIVERS_INF_METADATA_SCHEMA_VERSION


def test_stamp_windows_drivers_inf_metadata_none_in_none_out():
    """None payload preserves the "no INF parse yet" semantic."""
    assert _stamp_windows_drivers_inf_metadata(None) is None


def test_stamp_windows_drivers_inf_metadata_mutates_input():
    """Documents the mutation contract — writers may rely on it."""
    payload = {"version_block": {}, "manufacturer_block": [], "models": [],
               "strings": {}, "errors": []}
    out = _stamp_windows_drivers_inf_metadata(payload)
    assert out is payload  # same dict object
    assert "schema_version" in payload


def test_windows_drivers_inf_metadata_schema_version_constant():
    assert WINDOWS_DRIVERS_INF_METADATA_SCHEMA_VERSION == 1


# ── _normalize_firmware_registry_hive_walk_result (Phase γ.3) ────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Phase γ.4 aggregate shape — multi-hive walk.
        (
            {
                "schema_version": 1,
                "run_seconds": 4.5,
                "hive_count": 8,
                "by_hive_type": {
                    "SOFTWARE": 1,
                    "SYSTEM": 1,
                    "SAM": 1,
                    "SECURITY": 1,
                    "NTUSER": 4,
                },
                "by_walk_status": {
                    "completed": 6,
                    "partial": 1,
                    "failed": 0,
                    "skipped": 1,
                },
                "total_keys": 56789,
                "total_values": 234567,
                "errors": [],
            },
            {
                "schema_version": 1,
                "run_seconds": 4.5,
                "hive_count": 8,
                "by_hive_type": {
                    "SOFTWARE": 1,
                    "SYSTEM": 1,
                    "SAM": 1,
                    "SECURITY": 1,
                    "NTUSER": 4,
                },
                "by_walk_status": {
                    "completed": 6,
                    "partial": 1,
                    "failed": 0,
                    "skipped": 1,
                },
                "total_keys": 56789,
                "total_values": 234567,
                "errors": [],
            },
        ),
        # Empty-firmware run — no hives detected.
        (
            {
                "schema_version": 1,
                "run_seconds": 0.1,
                "hive_count": 0,
                "by_hive_type": {},
                "by_walk_status": {
                    "completed": 0,
                    "partial": 0,
                    "failed": 0,
                    "skipped": 0,
                },
                "total_keys": 0,
                "total_values": 0,
                "errors": [],
            },
            {
                "schema_version": 1,
                "run_seconds": 0.1,
                "hive_count": 0,
                "by_hive_type": {},
                "by_walk_status": {
                    "completed": 0,
                    "partial": 0,
                    "failed": 0,
                    "skipped": 0,
                },
                "total_keys": 0,
                "total_values": 0,
                "errors": [],
            },
        ),
        # Empty dict — preserved.
        ({}, {}),
        # None — durable signal for "no completed run yet" (matches the
        # cve_match_result + authenticode_chain_result null contract).
        (None, None),
        # Wrong type — list — coerced to None.
        ([{"hive_count": 5}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_registry_hive_walk_result(value, expected):
    assert _normalize_firmware_registry_hive_walk_result(value) == expected


def test_normalize_firmware_registry_hive_walk_result_idempotent():
    canonical = {
        "schema_version": 1,
        "run_seconds": 1.0,
        "hive_count": 1,
        "by_hive_type": {"SOFTWARE": 1},
        "by_walk_status": {"completed": 1, "partial": 0, "failed": 0, "skipped": 0},
        "total_keys": 100,
        "total_values": 500,
        "errors": [],
    }
    once = _normalize_firmware_registry_hive_walk_result(canonical)
    twice = _normalize_firmware_registry_hive_walk_result(once)
    assert once == twice == canonical


def test_stamp_firmware_registry_hive_walk_result_adds_version():
    payload = {"hive_count": 3, "total_keys": 1000}
    out = _stamp_firmware_registry_hive_walk_result(payload)
    assert out["schema_version"] == FIRMWARE_REGISTRY_HIVE_WALK_RESULT_SCHEMA_VERSION
    assert out["hive_count"] == 3


def test_stamp_firmware_registry_hive_walk_result_idempotent():
    payload = {"hive_count": 0}
    once = _stamp_firmware_registry_hive_walk_result(payload)
    twice = _stamp_firmware_registry_hive_walk_result(once)
    assert once == twice
    assert once["schema_version"] == FIRMWARE_REGISTRY_HIVE_WALK_RESULT_SCHEMA_VERSION


def test_firmware_registry_hive_walk_result_schema_version_constant():
    assert FIRMWARE_REGISTRY_HIVE_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize_firmware_windows_info_walk_result (Phase λ.α.D) ────────────────


@pytest.mark.parametrize(
    "value, expected",
    [
        # Canonical pass-through — full λ.α.D aggregate shape.
        (
            {
                "schema_version": 1,
                "image_count": 3,
                "classified_count": 2,
                "by_os_kernel_family": {
                    "windows10": 1,
                    "windows11": 1,
                    "windows_server": 0,
                    "unknown": 0,
                },
                "total_elapsed_s": 12.5,
                "errors_per_image": [],
            },
            {
                "schema_version": 1,
                "image_count": 3,
                "classified_count": 2,
                "by_os_kernel_family": {
                    "windows10": 1,
                    "windows11": 1,
                    "windows_server": 0,
                    "unknown": 0,
                },
                "total_elapsed_s": 12.5,
                "errors_per_image": [],
            },
        ),
        # Empty dict preserved.
        ({}, {}),
        # None — durable signal for "no completed run yet".
        (None, None),
        # Wrong-typed values coerce to None (Rule #35c defensive boundary).
        ([{"image_count": 5}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_windows_info_walk_result(value, expected):
    from app.services.jsonb_normalizers import (
        _normalize_firmware_windows_info_walk_result,
    )

    assert _normalize_firmware_windows_info_walk_result(value) == expected


def test_normalize_firmware_windows_info_walk_result_idempotent():
    from app.services.jsonb_normalizers import (
        _normalize_firmware_windows_info_walk_result,
    )

    canonical = {
        "schema_version": 1,
        "image_count": 1,
        "classified_count": 1,
        "by_os_kernel_family": {"windows11": 1},
        "total_elapsed_s": 1.0,
        "errors_per_image": [],
    }
    once = _normalize_firmware_windows_info_walk_result(canonical)
    twice = _normalize_firmware_windows_info_walk_result(once)
    assert once == twice == canonical


def test_stamp_firmware_windows_info_walk_result_adds_version():
    from app.services.jsonb_normalizers import (
        FIRMWARE_WINDOWS_INFO_WALK_RESULT_SCHEMA_VERSION,
        _stamp_firmware_windows_info_walk_result,
    )

    payload = {"image_count": 3, "classified_count": 2}
    out = _stamp_firmware_windows_info_walk_result(payload)
    assert out["schema_version"] == (
        FIRMWARE_WINDOWS_INFO_WALK_RESULT_SCHEMA_VERSION
    )
    assert out["image_count"] == 3


def test_stamp_firmware_windows_info_walk_result_idempotent():
    from app.services.jsonb_normalizers import (
        FIRMWARE_WINDOWS_INFO_WALK_RESULT_SCHEMA_VERSION,
        _stamp_firmware_windows_info_walk_result,
    )

    payload = {"image_count": 0}
    once = _stamp_firmware_windows_info_walk_result(payload)
    twice = _stamp_firmware_windows_info_walk_result(once)
    assert once == twice
    assert once["schema_version"] == (
        FIRMWARE_WINDOWS_INFO_WALK_RESULT_SCHEMA_VERSION
    )


def test_firmware_windows_info_walk_result_schema_version_constant():
    from app.services.jsonb_normalizers import (
        FIRMWARE_WINDOWS_INFO_WALK_RESULT_SCHEMA_VERSION,
    )

    assert FIRMWARE_WINDOWS_INFO_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize_windows_update_packages_update_metadata (Phase δ.1) ────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Phase δ.4 manifest-parser shape — full BOM with PE
        # files marked, supersedence both directions, applicability,
        # release channels.
        (
            {
                "schema_version": 1,
                "manifest": {
                    "title": "2024-04 Cumulative Update for Windows 11 ...",
                    "description": "Install this update...",
                    "support_url": "https://support.microsoft.com/help/5036893",
                    "msu_handler": "Windows Update Standalone Installer",
                },
                "supersedence": {
                    "supersedes": ["KB5034441", "KB5034123"],
                    "superseded_by": [],
                },
                "applicability": {
                    "products": ["Windows 11"],
                    "architectures": ["amd64"],
                    "release_channels": ["GA"],
                },
                "files": [
                    {
                        "path": "Windows10.0-KB5036893-x64.cab",
                        "size": 1234567,
                        "sha256": "abc123",
                        "is_pe": False,
                        "kind": "manifest",
                    },
                    {
                        "path": "amd64_microsoft-windows-kernel-base_31bf3856ad364e35_22621.3447.1.5.dll",
                        "size": 2345678,
                        "sha256": "def456",
                        "is_pe": True,
                        "kind": "binary",
                    },
                ],
                "errors": [],
            },
            {
                "schema_version": 1,
                "manifest": {
                    "title": "2024-04 Cumulative Update for Windows 11 ...",
                    "description": "Install this update...",
                    "support_url": "https://support.microsoft.com/help/5036893",
                    "msu_handler": "Windows Update Standalone Installer",
                },
                "supersedence": {
                    "supersedes": ["KB5034441", "KB5034123"],
                    "superseded_by": [],
                },
                "applicability": {
                    "products": ["Windows 11"],
                    "architectures": ["amd64"],
                    "release_channels": ["GA"],
                },
                "files": [
                    {
                        "path": "Windows10.0-KB5036893-x64.cab",
                        "size": 1234567,
                        "sha256": "abc123",
                        "is_pe": False,
                        "kind": "manifest",
                    },
                    {
                        "path": "amd64_microsoft-windows-kernel-base_31bf3856ad364e35_22621.3447.1.5.dll",
                        "size": 2345678,
                        "sha256": "def456",
                        "is_pe": True,
                        "kind": "binary",
                    },
                ],
                "errors": [],
            },
        ),
        # Side-loaded vendor cab without manifest fields populated — partial
        # data passes through canonically.
        (
            {
                "schema_version": 1,
                "manifest": {"title": None, "description": None, "support_url": None},
                "supersedence": {"supersedes": [], "superseded_by": []},
                "applicability": {"products": [], "architectures": [], "release_channels": []},
                "files": [],
                "errors": ["manifest_metadata_missing"],
            },
            {
                "schema_version": 1,
                "manifest": {"title": None, "description": None, "support_url": None},
                "supersedence": {"supersedes": [], "superseded_by": []},
                "applicability": {"products": [], "architectures": [], "release_channels": []},
                "files": [],
                "errors": ["manifest_metadata_missing"],
            },
        ),
        # Empty dict — preserved (writer's degenerate-but-valid case).
        ({}, {}),
        # None — durable signal for "row exists but no manifest parsed
        # yet". Distinct from {} which means "manifest parser ran but
        # produced an empty payload".
        (None, None),
        # Wrong type — list — coerced to None (no usable manifest).
        ([{"path": "foo"}], None),
        # Wrong type — string.
        ("not a dict", None),
        # Wrong type — int.
        (42, None),
    ],
)
def test_normalize_windows_update_packages_update_metadata(value, expected):
    assert _normalize_windows_update_packages_update_metadata(value) == expected


def test_normalize_windows_update_packages_update_metadata_idempotent():
    canonical = {
        "schema_version": 1,
        "manifest": {"title": "T", "description": "D", "support_url": "U"},
        "supersedence": {"supersedes": ["KB1"], "superseded_by": []},
        "applicability": {"products": ["W11"], "architectures": ["amd64"], "release_channels": ["GA"]},
        "files": [],
        "errors": [],
    }
    once = _normalize_windows_update_packages_update_metadata(canonical)
    twice = _normalize_windows_update_packages_update_metadata(once)
    assert once == twice == canonical


def test_stamp_windows_update_packages_update_metadata_adds_version():
    payload = {
        "manifest": {"title": "T"},
        "supersedence": {"supersedes": [], "superseded_by": []},
        "files": [],
    }
    out = _stamp_windows_update_packages_update_metadata(payload)
    assert out is not None
    assert out["schema_version"] == WINDOWS_UPDATE_PACKAGES_UPDATE_METADATA_SCHEMA_VERSION
    assert out["manifest"]["title"] == "T"


def test_stamp_windows_update_packages_update_metadata_idempotent():
    payload = {"manifest": {"title": "T"}, "files": []}
    once = _stamp_windows_update_packages_update_metadata(payload)
    twice = _stamp_windows_update_packages_update_metadata(once)
    assert once == twice
    assert once["schema_version"] == WINDOWS_UPDATE_PACKAGES_UPDATE_METADATA_SCHEMA_VERSION


def test_stamp_windows_update_packages_update_metadata_none_in_none_out():
    """None payload preserves the column's nullable contract."""
    assert _stamp_windows_update_packages_update_metadata(None) is None


def test_stamp_windows_update_packages_update_metadata_mutates_input():
    """Documents the mutation contract — writers may rely on it."""
    payload = {"manifest": {"title": "T"}, "files": []}
    out = _stamp_windows_update_packages_update_metadata(payload)
    assert out is payload  # same dict object
    assert "schema_version" in payload


def test_windows_update_packages_update_metadata_schema_version_constant():
    assert WINDOWS_UPDATE_PACKAGES_UPDATE_METADATA_SCHEMA_VERSION == 1


# ── _normalize_firmware_dotnet_decompile_result (Phase δ.2) ──────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Phase δ.4 worker shape — full aggregate with per-bundle
        # output paths, by-arch histogram, totals.
        (
            {
                "schema_version": 1,
                "run_seconds": 123.45,
                "bundle_count": 3,
                "bundles_decompiled": 2,
                "bundles_failed": 1,
                "total_assemblies_extracted": 47,
                "by_arch": {"amd64": 2, "msil": 1},
                "bundles": [
                    {
                        "bundle_path": "Windows/SomeApp.exe",
                        "bundle_sha256": "abc",
                        "extracted_count": 25,
                        "decompile_target_dir": "/data/firmware/x/dotnet/abc/",
                        "errors": [],
                    },
                    {
                        "bundle_path": "Windows/OtherApp.exe",
                        "bundle_sha256": "def",
                        "extracted_count": 22,
                        "decompile_target_dir": "/data/firmware/x/dotnet/def/",
                        "errors": [],
                    },
                ],
                "errors": [],
            },
            {
                "schema_version": 1,
                "run_seconds": 123.45,
                "bundle_count": 3,
                "bundles_decompiled": 2,
                "bundles_failed": 1,
                "total_assemblies_extracted": 47,
                "by_arch": {"amd64": 2, "msil": 1},
                "bundles": [
                    {
                        "bundle_path": "Windows/SomeApp.exe",
                        "bundle_sha256": "abc",
                        "extracted_count": 25,
                        "decompile_target_dir": "/data/firmware/x/dotnet/abc/",
                        "errors": [],
                    },
                    {
                        "bundle_path": "Windows/OtherApp.exe",
                        "bundle_sha256": "def",
                        "extracted_count": 22,
                        "decompile_target_dir": "/data/firmware/x/dotnet/def/",
                        "errors": [],
                    },
                ],
                "errors": [],
            },
        ),
        # Empty dict — preserved.
        ({}, {}),
        # None — durable signal for "no completed run yet" (matches the
        # cve_match_result + authenticode_chain_result + registry_hive_walk_result
        # null contract).
        (None, None),
        # Wrong type — list — coerced to None.
        ([{"bundle_count": 5}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_dotnet_decompile_result(value, expected):
    assert _normalize_firmware_dotnet_decompile_result(value) == expected


def test_normalize_firmware_dotnet_decompile_result_idempotent():
    canonical = {
        "schema_version": 1,
        "run_seconds": 1.0,
        "bundle_count": 1,
        "bundles_decompiled": 1,
        "bundles_failed": 0,
        "total_assemblies_extracted": 5,
        "by_arch": {"msil": 1},
        "bundles": [],
        "errors": [],
    }
    once = _normalize_firmware_dotnet_decompile_result(canonical)
    twice = _normalize_firmware_dotnet_decompile_result(once)
    assert once == twice == canonical


def test_stamp_firmware_dotnet_decompile_result_adds_version():
    payload = {"bundle_count": 3, "bundles_decompiled": 3}
    out = _stamp_firmware_dotnet_decompile_result(payload)
    assert out["schema_version"] == FIRMWARE_DOTNET_DECOMPILE_RESULT_SCHEMA_VERSION
    assert out["bundle_count"] == 3


def test_stamp_firmware_dotnet_decompile_result_idempotent():
    payload = {"bundle_count": 0}
    once = _stamp_firmware_dotnet_decompile_result(payload)
    twice = _stamp_firmware_dotnet_decompile_result(once)
    assert once == twice
    assert once["schema_version"] == FIRMWARE_DOTNET_DECOMPILE_RESULT_SCHEMA_VERSION


def test_firmware_dotnet_decompile_result_schema_version_constant():
    assert FIRMWARE_DOTNET_DECOMPILE_RESULT_SCHEMA_VERSION == 1


# ── _normalize_firmware_windows_update_diff_result (Phase δ.3) ───────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Phase δ.5 runner shape — full aggregate with by-KB-pair
        # histogram, totals, no errors.
        (
            {
                "schema_version": 1,
                "run_seconds": 89.12,
                "package_count": 3,
                "kb_pair_count": 2,
                "dlls_compared": 4500,
                "dlls_added": 32,
                "dlls_removed": 18,
                "dlls_modified": 142,
                "dlls_unchanged": 4308,
                "by_kb_pair": [
                    {
                        "older_kb": "KB5034441",
                        "newer_kb": "KB5036893",
                        "added": 32,
                        "removed": 18,
                        "modified": 142,
                        "unchanged": 4308,
                    },
                ],
                "errors": [],
            },
            {
                "schema_version": 1,
                "run_seconds": 89.12,
                "package_count": 3,
                "kb_pair_count": 2,
                "dlls_compared": 4500,
                "dlls_added": 32,
                "dlls_removed": 18,
                "dlls_modified": 142,
                "dlls_unchanged": 4308,
                "by_kb_pair": [
                    {
                        "older_kb": "KB5034441",
                        "newer_kb": "KB5036893",
                        "added": 32,
                        "removed": 18,
                        "modified": 142,
                        "unchanged": 4308,
                    },
                ],
                "errors": [],
            },
        ),
        # Empty dict — preserved.
        ({}, {}),
        # None — durable signal for "no completed run yet".
        (None, None),
        # Wrong type — list — coerced to None.
        ([{"package_count": 5}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_windows_update_diff_result(value, expected):
    assert _normalize_firmware_windows_update_diff_result(value) == expected


def test_normalize_firmware_windows_update_diff_result_idempotent():
    canonical = {
        "schema_version": 1,
        "run_seconds": 1.0,
        "package_count": 1,
        "kb_pair_count": 1,
        "dlls_compared": 0,
        "dlls_added": 0,
        "dlls_removed": 0,
        "dlls_modified": 0,
        "dlls_unchanged": 0,
        "by_kb_pair": [],
        "errors": [],
    }
    once = _normalize_firmware_windows_update_diff_result(canonical)
    twice = _normalize_firmware_windows_update_diff_result(once)
    assert once == twice == canonical


def test_stamp_firmware_windows_update_diff_result_adds_version():
    payload = {"package_count": 3, "dlls_modified": 50}
    out = _stamp_firmware_windows_update_diff_result(payload)
    assert out["schema_version"] == FIRMWARE_WINDOWS_UPDATE_DIFF_RESULT_SCHEMA_VERSION
    assert out["package_count"] == 3


def test_stamp_firmware_windows_update_diff_result_idempotent():
    payload = {"package_count": 0}
    once = _stamp_firmware_windows_update_diff_result(payload)
    twice = _stamp_firmware_windows_update_diff_result(once)
    assert once == twice
    assert once["schema_version"] == FIRMWARE_WINDOWS_UPDATE_DIFF_RESULT_SCHEMA_VERSION


def test_firmware_windows_update_diff_result_schema_version_constant():
    assert FIRMWARE_WINDOWS_UPDATE_DIFF_RESULT_SCHEMA_VERSION == 1


# ── _normalize_firmware_evtx_walk_result (Phase ε.1.b.3) ─────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical Phase ε.1.b.3 inner-runner aggregate shape.
        (
            {
                "schema_version": 1,
                "run_seconds": 0.5,
                "evtx_count": 2,
                "by_provider": {"Microsoft-Windows-Sysmon": 142, "Microsoft-Windows-Security-Auditing": 98},
                "by_status": {"ok": 2, "error": 0, "unavailable": 0},
                "total_records": 240,
                "sample_records_per_file": 32,
                "errors": [],
                "per_file": [
                    {"path": "/extracted/Windows/System32/winevt/Logs/Sysmon.evtx",
                     "status": "ok", "record_count": 142, "error": None},
                    {"path": "/extracted/Windows/System32/winevt/Logs/Security.evtx",
                     "status": "ok", "record_count": 98, "error": None},
                ],
            },
            {
                "schema_version": 1,
                "run_seconds": 0.5,
                "evtx_count": 2,
                "by_provider": {"Microsoft-Windows-Sysmon": 142, "Microsoft-Windows-Security-Auditing": 98},
                "by_status": {"ok": 2, "error": 0, "unavailable": 0},
                "total_records": 240,
                "sample_records_per_file": 32,
                "errors": [],
                "per_file": [
                    {"path": "/extracted/Windows/System32/winevt/Logs/Sysmon.evtx",
                     "status": "ok", "record_count": 142, "error": None},
                    {"path": "/extracted/Windows/System32/winevt/Logs/Security.evtx",
                     "status": "ok", "record_count": 98, "error": None},
                ],
            },
        ),
        # Empty walk — preserved (matches the _empty_walk_result default).
        (
            {
                "run_seconds": 0.0,
                "evtx_count": 0,
                "by_provider": {},
                "by_status": {"ok": 0, "error": 0, "unavailable": 0},
                "total_records": 0,
                "sample_records_per_file": 32,
                "errors": [],
                "per_file": [],
            },
            {
                "run_seconds": 0.0,
                "evtx_count": 0,
                "by_provider": {},
                "by_status": {"ok": 0, "error": 0, "unavailable": 0},
                "total_records": 0,
                "sample_records_per_file": 32,
                "errors": [],
                "per_file": [],
            },
        ),
        # Empty dict — preserved.
        ({}, {}),
        # None — durable signal for "no completed run yet" (matches the
        # cve_match_result + authenticode_chain_result null contract).
        (None, None),
        # Wrong type — list — coerced to None.
        ([{"evtx_count": 1}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_evtx_walk_result(value, expected):
    assert _normalize_firmware_evtx_walk_result(value) == expected


def test_normalize_firmware_evtx_walk_result_idempotent():
    canonical = {
        "schema_version": 1,
        "run_seconds": 0.1,
        "evtx_count": 1,
        "by_provider": {"Microsoft-Windows-Sysmon": 5},
        "by_status": {"ok": 1, "error": 0, "unavailable": 0},
        "total_records": 5,
        "sample_records_per_file": 32,
        "errors": [],
        "per_file": [{"path": "/x.evtx", "status": "ok", "record_count": 5, "error": None}],
    }
    once = _normalize_firmware_evtx_walk_result(canonical)
    twice = _normalize_firmware_evtx_walk_result(once)
    assert once == twice == canonical


def test_stamp_firmware_evtx_walk_result_adds_version():
    payload = {"evtx_count": 3, "total_records": 1234}
    out = _stamp_firmware_evtx_walk_result(payload)
    assert out["schema_version"] == FIRMWARE_EVTX_WALK_RESULT_SCHEMA_VERSION
    assert out["evtx_count"] == 3
    assert out["total_records"] == 1234


def test_stamp_firmware_evtx_walk_result_idempotent():
    payload = {"evtx_count": 0}
    once = _stamp_firmware_evtx_walk_result(payload)
    twice = _stamp_firmware_evtx_walk_result(once)
    assert once == twice
    assert once["schema_version"] == FIRMWARE_EVTX_WALK_RESULT_SCHEMA_VERSION


def test_firmware_evtx_walk_result_schema_version_constant():
    assert FIRMWARE_EVTX_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize_windows_event_records_message_xml (Phase ε.2.A) ───────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through.
        (
            {
                "schema_version": 1,
                "EventData": {"SubjectUserName": "alice", "TargetUserName": "bob"},
            },
            {
                "schema_version": 1,
                "EventData": {"SubjectUserName": "alice", "TargetUserName": "bob"},
            },
        ),
        # Empty dict pass-through (writer may stamp before populating).
        ({}, {}),
        # None preserved — semantic load is "no parsed payload available".
        (None, None),
        # Wrong type collapses to None — defensive coercion.
        ("<Event>not a dict</Event>", None),
        ([{"EventData": "list-shaped"}], None),
        (42, None),
    ],
)
def test_normalize_windows_event_records_message_xml(value, expected):
    assert _normalize_windows_event_records_message_xml(value) == expected


def test_normalize_windows_event_records_message_xml_idempotent():
    canonical = {
        "schema_version": 1,
        "EventData": {
            "ProcessName": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe foo.txt",
        },
    }
    once = _normalize_windows_event_records_message_xml(canonical)
    twice = _normalize_windows_event_records_message_xml(once)
    assert once == twice == canonical


def test_stamp_windows_event_records_message_xml_adds_version():
    payload = {"EventData": {"SubjectUserName": "alice"}}
    out = _stamp_windows_event_records_message_xml(payload)
    assert out["schema_version"] == WINDOWS_EVENT_RECORDS_MESSAGE_XML_SCHEMA_VERSION
    assert out["EventData"]["SubjectUserName"] == "alice"


def test_stamp_windows_event_records_message_xml_idempotent():
    payload = {"EventData": {}}
    once = _stamp_windows_event_records_message_xml(payload)
    twice = _stamp_windows_event_records_message_xml(once)
    assert once == twice
    assert once["schema_version"] == WINDOWS_EVENT_RECORDS_MESSAGE_XML_SCHEMA_VERSION


def test_windows_event_records_message_xml_schema_version_constant():
    assert WINDOWS_EVENT_RECORDS_MESSAGE_XML_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_prefetch_records_* (Phase ζ.2.A) ───────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical envelope pass-through.
        (
            {"schema_version": 1, "items": ["2026-05-09T14:23:45+00:00"]},
            ["2026-05-09T14:23:45+00:00"],
        ),
        # Bare list (legacy / pre-stamp) pass-through.
        (["2026-05-09T14:23:45+00:00"], ["2026-05-09T14:23:45+00:00"]),
        # None → empty list (no run times recorded).
        (None, []),
        # Wrong type → empty list (defensive).
        ("2026-05-09", []),
        (42, []),
        # Empty envelope.
        ({"schema_version": 1, "items": []}, []),
        # None entries within the list dropped.
        (
            {"schema_version": 1, "items": ["t1", None, "t2"]},
            ["t1", "t2"],
        ),
    ],
)
def test_normalize_windows_prefetch_records_all_run_times(value, expected):
    assert _normalize_windows_prefetch_records_all_run_times(value) == expected


def test_normalize_windows_prefetch_records_all_run_times_idempotent():
    canonical = {"schema_version": 1, "items": ["t1", "t2", "t3"]}
    once = _normalize_windows_prefetch_records_all_run_times(canonical)
    twice = _normalize_windows_prefetch_records_all_run_times(once)
    assert once == twice == ["t1", "t2", "t3"]


def test_stamp_windows_prefetch_records_all_run_times_adds_version():
    out = _stamp_windows_prefetch_records_all_run_times(["t1", "t2"])
    assert out["schema_version"] == WINDOWS_PREFETCH_RECORDS_ALL_RUN_TIMES_SCHEMA_VERSION
    assert out["items"] == ["t1", "t2"]


def test_stamp_windows_prefetch_records_all_run_times_idempotent():
    once = _stamp_windows_prefetch_records_all_run_times(["t1"])
    twice = _stamp_windows_prefetch_records_all_run_times(once)
    assert once == twice
    assert once["items"] == ["t1"]


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {"schema_version": 1, "items": ["\\WIN\\SYS32\\NTDLL.DLL"]},
            ["\\WIN\\SYS32\\NTDLL.DLL"],
        ),
        (["\\WIN\\SYS32\\NTDLL.DLL"], ["\\WIN\\SYS32\\NTDLL.DLL"]),
        (None, []),
        ("not a list", []),
    ],
)
def test_normalize_windows_prefetch_records_filenames_referenced(value, expected):
    assert _normalize_windows_prefetch_records_filenames_referenced(value) == expected


def test_stamp_windows_prefetch_records_filenames_referenced_adds_version():
    out = _stamp_windows_prefetch_records_filenames_referenced(["a.dll"])
    assert (
        out["schema_version"]
        == WINDOWS_PREFETCH_RECORDS_FILENAMES_REFERENCED_SCHEMA_VERSION
    )
    assert out["items"] == ["a.dll"]


def test_stamp_windows_prefetch_records_filenames_referenced_idempotent():
    once = _stamp_windows_prefetch_records_filenames_referenced(["a.dll"])
    twice = _stamp_windows_prefetch_records_filenames_referenced(once)
    assert once == twice


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "items": [
                    {
                        "device_path": "\\DEVICE\\HARDDISKVOLUME3",
                        "serial_number": "12345678",
                    }
                ],
            },
            [
                {
                    "device_path": "\\DEVICE\\HARDDISKVOLUME3",
                    "serial_number": "12345678",
                }
            ],
        ),
        # Bare list pass-through.
        (
            [{"device_path": "\\DEVICE\\HARDDISKVOLUME0"}],
            [{"device_path": "\\DEVICE\\HARDDISKVOLUME0"}],
        ),
        # None → empty.
        (None, []),
        # Non-dict entries inside list are filtered out.
        (
            {"schema_version": 1, "items": [{"a": 1}, "not-a-dict", 42]},
            [{"a": 1}],
        ),
    ],
)
def test_normalize_windows_prefetch_records_volumes(value, expected):
    assert _normalize_windows_prefetch_records_volumes(value) == expected


def test_stamp_windows_prefetch_records_volumes_adds_version():
    out = _stamp_windows_prefetch_records_volumes(
        [{"device_path": "\\DEVICE\\HARDDISKVOLUME3"}]
    )
    assert out["schema_version"] == WINDOWS_PREFETCH_RECORDS_VOLUMES_SCHEMA_VERSION
    assert out["items"] == [{"device_path": "\\DEVICE\\HARDDISKVOLUME3"}]


def test_stamp_windows_prefetch_records_volumes_idempotent():
    once = _stamp_windows_prefetch_records_volumes([{"a": 1}])
    twice = _stamp_windows_prefetch_records_volumes(once)
    assert once == twice


def test_windows_prefetch_records_schema_version_constants():
    assert WINDOWS_PREFETCH_RECORDS_ALL_RUN_TIMES_SCHEMA_VERSION == 1
    assert WINDOWS_PREFETCH_RECORDS_FILENAMES_REFERENCED_SCHEMA_VERSION == 1
    assert WINDOWS_PREFETCH_RECORDS_VOLUMES_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_srum_records_extra_metadata (Phase ζ.3.A) ─────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through.
        (
            {"schema_version": 1, "guid_table": "{973F5D5C-...}"},
            {"schema_version": 1, "guid_table": "{973F5D5C-...}"},
        ),
        # Empty dict pass-through.
        ({}, {}),
        # None preserved.
        (None, None),
        # Wrong type collapses to None.
        ("not a dict", None),
        ([{"a": 1}], None),
        (42, None),
    ],
)
def test_normalize_windows_srum_records_extra_metadata(value, expected):
    assert _normalize_windows_srum_records_extra_metadata(value) == expected


def test_stamp_windows_srum_records_extra_metadata_adds_version():
    out = _stamp_windows_srum_records_extra_metadata(
        {"guid_table": "{973F5D5C-...}"}
    )
    assert (
        out["schema_version"]
        == WINDOWS_SRUM_RECORDS_EXTRA_METADATA_SCHEMA_VERSION
    )


def test_stamp_windows_srum_records_extra_metadata_idempotent():
    once = _stamp_windows_srum_records_extra_metadata({"a": 1})
    twice = _stamp_windows_srum_records_extra_metadata(once)
    assert once == twice


def test_windows_srum_records_extra_metadata_schema_version_constant():
    assert WINDOWS_SRUM_RECORDS_EXTRA_METADATA_SCHEMA_VERSION == 1


# ── _normalize/_stamp_firmware_srum_walk_result (Phase ζ.3.B) ───────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {"schema_version": 1, "srudb_count": 1, "total_records": 100},
            {"schema_version": 1, "srudb_count": 1, "total_records": 100},
        ),
        ({}, {}),
        (None, None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_srum_walk_result(value, expected):
    assert _normalize_firmware_srum_walk_result(value) == expected


def test_stamp_firmware_srum_walk_result_adds_version():
    out = _stamp_firmware_srum_walk_result({"srudb_count": 0})
    assert out["schema_version"] == FIRMWARE_SRUM_WALK_RESULT_SCHEMA_VERSION


def test_stamp_firmware_srum_walk_result_idempotent():
    once = _stamp_firmware_srum_walk_result({"srudb_count": 0})
    twice = _stamp_firmware_srum_walk_result(once)
    assert once == twice


def test_firmware_srum_walk_result_schema_version_constant():
    assert FIRMWARE_SRUM_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_mft_records_ads_streams (Phase η.A.A) ─────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through (list of dicts).
        (
            [
                {"name": "Zone.Identifier", "size": 100, "data_size": None},
                {"name": "hidden", "size": 4096, "data_size": 4096},
            ],
            [
                {"name": "Zone.Identifier", "size": 100, "data_size": None},
                {"name": "hidden", "size": 4096, "data_size": 4096},
            ],
        ),
        # Empty list pass-through.
        ([], []),
        # None collapses to empty list.
        (None, []),
        # Wrong type — int — collapses to empty list.
        (42, []),
        # Wrong type — string — collapses to empty list.
        ("not a list", []),
        # Legacy single-stream dict shape coerces to single-element list.
        (
            {"name": "Zone.Identifier", "size": 100, "data_size": None},
            [{"name": "Zone.Identifier", "size": 100, "data_size": None}],
        ),
        # List with non-dict items coerces each item to a defensive dict.
        (
            ["legacy_stream_name"],
            [{"name": "legacy_stream_name", "size": 0, "data_size": None}],
        ),
    ],
)
def test_normalize_windows_mft_records_ads_streams(value, expected):
    assert _normalize_windows_mft_records_ads_streams(value) == expected


def test_normalize_windows_mft_records_ads_streams_idempotent():
    canonical = [
        {"name": "Zone.Identifier", "size": 100, "data_size": None},
    ]
    once = _normalize_windows_mft_records_ads_streams(canonical)
    twice = _normalize_windows_mft_records_ads_streams(once)
    assert once == twice == canonical


def test_stamp_windows_mft_records_ads_streams_adds_version_per_entry():
    payload = [
        {"name": "Zone.Identifier", "size": 100, "data_size": None},
        {"name": "hidden", "size": 4096, "data_size": 4096},
    ]
    out = _stamp_windows_mft_records_ads_streams(payload)
    for entry in out:
        assert (
            entry["schema_version"]
            == WINDOWS_MFT_RECORDS_ADS_STREAMS_SCHEMA_VERSION
        )


def test_stamp_windows_mft_records_ads_streams_idempotent():
    payload = [{"name": "Zone.Identifier", "size": 100, "data_size": None}]
    once = _stamp_windows_mft_records_ads_streams(payload)
    twice = _stamp_windows_mft_records_ads_streams(once)
    assert once == twice


def test_windows_mft_records_ads_streams_schema_version_constant():
    assert WINDOWS_MFT_RECORDS_ADS_STREAMS_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_mft_records_target_metadata (Phase η.A.A) ──────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through.
        (
            {
                "schema_version": 1,
                "parent_segment_ref": 5,
                "reparse_point": False,
                "attribute_flags": 1,
            },
            {
                "schema_version": 1,
                "parent_segment_ref": 5,
                "reparse_point": False,
                "attribute_flags": 1,
            },
        ),
        # Empty dict pass-through.
        ({}, {}),
        # None collapses to empty dict.
        (None, {}),
        # Wrong type — list — collapses to empty dict.
        ([{"a": 1}], {}),
        # Wrong type — string — collapses to empty dict.
        ("not a dict", {}),
        # Wrong type — int — collapses to empty dict.
        (42, {}),
    ],
)
def test_normalize_windows_mft_records_target_metadata(value, expected):
    assert _normalize_windows_mft_records_target_metadata(value) == expected


def test_normalize_windows_mft_records_target_metadata_idempotent():
    canonical = {
        "schema_version": 1,
        "parent_segment_ref": 5,
        "reparse_point": False,
    }
    once = _normalize_windows_mft_records_target_metadata(canonical)
    twice = _normalize_windows_mft_records_target_metadata(once)
    assert once == twice == canonical


def test_stamp_windows_mft_records_target_metadata_adds_version():
    out = _stamp_windows_mft_records_target_metadata(
        {"parent_segment_ref": 5}
    )
    assert (
        out["schema_version"]
        == WINDOWS_MFT_RECORDS_TARGET_METADATA_SCHEMA_VERSION
    )


def test_stamp_windows_mft_records_target_metadata_idempotent():
    once = _stamp_windows_mft_records_target_metadata({"a": 1})
    twice = _stamp_windows_mft_records_target_metadata(once)
    assert once == twice


def test_windows_mft_records_target_metadata_schema_version_constant():
    assert WINDOWS_MFT_RECORDS_TARGET_METADATA_SCHEMA_VERSION == 1


# ── _normalize/_stamp_firmware_mft_walk_result (Phase η.A.B) ────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "images_scanned": 1,
                "records_walked": 5000,
            },
            {
                "schema_version": 1,
                "images_scanned": 1,
                "records_walked": 5000,
            },
        ),
        ({}, {}),
        (None, None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_mft_walk_result(value, expected):
    assert _normalize_firmware_mft_walk_result(value) == expected


def test_stamp_firmware_mft_walk_result_adds_version():
    out = _stamp_firmware_mft_walk_result({"images_scanned": 0})
    assert out["schema_version"] == FIRMWARE_MFT_WALK_RESULT_SCHEMA_VERSION


def test_stamp_firmware_mft_walk_result_idempotent():
    once = _stamp_firmware_mft_walk_result({"images_scanned": 0})
    twice = _stamp_firmware_mft_walk_result(once)
    assert once == twice


def test_firmware_mft_walk_result_schema_version_constant():
    assert FIRMWARE_MFT_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_bcd_entries_custom_elements (Phase θ.A.A) ──────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through (list of dicts).
        (
            [
                {"element_type": "0x14000006", "element_value": ["{a}", "{b}"]},
                {"element_type": "0x16000010", "element_value": True},
            ],
            [
                {"element_type": "0x14000006", "element_value": ["{a}", "{b}"]},
                {"element_type": "0x16000010", "element_value": True},
            ],
        ),
        # Empty list pass-through.
        ([], []),
        # None collapses to empty list.
        (None, []),
        # Wrong type — int — collapses to empty list.
        (42, []),
        # Wrong type — string — collapses to empty list.
        ("not a list", []),
        # Legacy single-element dict shape coerces to single-element list.
        (
            {"element_type": "0x12000004", "element_value": "Windows 10"},
            [{"element_type": "0x12000004", "element_value": "Windows 10"}],
        ),
        # List with non-dict items coerces each item to a defensive dict.
        (
            ["0x14000006"],
            [{"element_type": "0x14000006", "element_value": None}],
        ),
    ],
)
def test_normalize_windows_bcd_entries_custom_elements(value, expected):
    assert _normalize_windows_bcd_entries_custom_elements(value) == expected


def test_normalize_windows_bcd_entries_custom_elements_idempotent():
    canonical = [
        {"element_type": "0x14000006", "element_value": ["{a}"]},
    ]
    once = _normalize_windows_bcd_entries_custom_elements(canonical)
    twice = _normalize_windows_bcd_entries_custom_elements(once)
    assert once == twice == canonical


def test_stamp_windows_bcd_entries_custom_elements_adds_version_per_entry():
    payload = [
        {"element_type": "0x14000006", "element_value": ["{a}"]},
        {"element_type": "0x16000010", "element_value": True},
    ]
    out = _stamp_windows_bcd_entries_custom_elements(payload)
    for entry in out:
        assert (
            entry["schema_version"]
            == WINDOWS_BCD_ENTRIES_CUSTOM_ELEMENTS_SCHEMA_VERSION
        )


def test_stamp_windows_bcd_entries_custom_elements_idempotent():
    payload = [{"element_type": "0x14000006", "element_value": ["{a}"]}]
    once = _stamp_windows_bcd_entries_custom_elements(payload)
    twice = _stamp_windows_bcd_entries_custom_elements(once)
    assert once == twice


def test_windows_bcd_entries_custom_elements_schema_version_constant():
    assert WINDOWS_BCD_ENTRIES_CUSTOM_ELEMENTS_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_bcd_entries_anomaly_flags (Phase θ.A.A) ────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through.
        (
            {
                "schema_version": 1,
                "suspicious_path": True,
                "testsigning_enabled": False,
                "no_integrity_checks": False,
            },
            {
                "schema_version": 1,
                "suspicious_path": True,
                "testsigning_enabled": False,
                "no_integrity_checks": False,
            },
        ),
        # Empty dict pass-through.
        ({}, {}),
        # None collapses to empty dict.
        (None, {}),
        # Wrong type — list — collapses to empty dict.
        ([{"a": 1}], {}),
        # Wrong type — string — collapses to empty dict.
        ("not a dict", {}),
        # Wrong type — int — collapses to empty dict.
        (42, {}),
    ],
)
def test_normalize_windows_bcd_entries_anomaly_flags(value, expected):
    assert _normalize_windows_bcd_entries_anomaly_flags(value) == expected


def test_normalize_windows_bcd_entries_anomaly_flags_idempotent():
    canonical = {
        "schema_version": 1,
        "suspicious_path": True,
        "testsigning_enabled": False,
    }
    once = _normalize_windows_bcd_entries_anomaly_flags(canonical)
    twice = _normalize_windows_bcd_entries_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_windows_bcd_entries_anomaly_flags_adds_version():
    out = _stamp_windows_bcd_entries_anomaly_flags(
        {"suspicious_path": True}
    )
    assert (
        out["schema_version"]
        == WINDOWS_BCD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_windows_bcd_entries_anomaly_flags_idempotent():
    once = _stamp_windows_bcd_entries_anomaly_flags({"a": 1})
    twice = _stamp_windows_bcd_entries_anomaly_flags(once)
    assert once == twice


def test_windows_bcd_entries_anomaly_flags_schema_version_constant():
    assert WINDOWS_BCD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── _normalize/_stamp_firmware_bcd_walk_result (Phase θ.A.B) ────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "stores_scanned": 1,
                "entries_walked": 30,
                "entries_persisted": 30,
                "testsigning_count": 0,
            },
            {
                "schema_version": 1,
                "stores_scanned": 1,
                "entries_walked": 30,
                "entries_persisted": 30,
                "testsigning_count": 0,
            },
        ),
        ({}, {}),
        (None, None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_bcd_walk_result(value, expected):
    assert _normalize_firmware_bcd_walk_result(value) == expected


def test_stamp_firmware_bcd_walk_result_adds_version():
    out = _stamp_firmware_bcd_walk_result({"stores_scanned": 0})
    assert out["schema_version"] == FIRMWARE_BCD_WALK_RESULT_SCHEMA_VERSION


def test_stamp_firmware_bcd_walk_result_idempotent():
    once = _stamp_firmware_bcd_walk_result({"stores_scanned": 0})
    twice = _stamp_firmware_bcd_walk_result(once)
    assert once == twice


def test_firmware_bcd_walk_result_schema_version_constant():
    assert FIRMWARE_BCD_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_wmi_events_consumer_payload (Phase θ.B.B) ──────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical list[dict] passes through unchanged.
        (
            [{"consumer_type": "CommandLineEventConsumer", "arguments": "x"}],
            [{"consumer_type": "CommandLineEventConsumer", "arguments": "x"}],
        ),
        # Empty list — preserved.
        ([], []),
        # None — coerced to empty list.
        (None, []),
        # Wrong type — string — coerced to empty list.
        ("garbage", []),
        # Wrong type — int — coerced to empty list.
        (42, []),
        # Dict input (legacy single-record) → list-wrapped.
        (
            {"consumer_type": "Active", "arguments": "vbs", "other": ""},
            [{"consumer_type": "Active", "arguments": "vbs", "other": ""}],
        ),
        # List with non-dict items — coerced.
        (
            ["bareconsumer"],
            [{"consumer_type": "bareconsumer", "arguments": "", "other": ""}],
        ),
    ],
)
def test_normalize_windows_wmi_events_consumer_payload(value, expected):
    assert _normalize_windows_wmi_events_consumer_payload(value) == expected


def test_normalize_windows_wmi_events_consumer_payload_idempotent():
    canonical = [
        {
            "schema_version": 1,
            "consumer_type": "CommandLineEventConsumer",
            "arguments": "powershell -enc x",
            "other": "%COMSPEC%",
        },
    ]
    once = _normalize_windows_wmi_events_consumer_payload(canonical)
    twice = _normalize_windows_wmi_events_consumer_payload(once)
    assert once == twice == canonical


def test_stamp_windows_wmi_events_consumer_payload_adds_version_per_entry():
    payload = [
        {"consumer_type": "A", "arguments": "a", "other": ""},
        {"consumer_type": "B", "arguments": "b", "other": ""},
    ]
    out = _stamp_windows_wmi_events_consumer_payload(payload)
    assert len(out) == 2
    for entry in out:
        assert entry["schema_version"] == (
            WINDOWS_WMI_EVENTS_CONSUMER_PAYLOAD_SCHEMA_VERSION
        )


def test_stamp_windows_wmi_events_consumer_payload_idempotent():
    payload = [{"consumer_type": "A", "arguments": "a", "other": ""}]
    once = _stamp_windows_wmi_events_consumer_payload(payload)
    twice = _stamp_windows_wmi_events_consumer_payload(once)
    assert once == twice


def test_windows_wmi_events_consumer_payload_schema_version_constant():
    assert WINDOWS_WMI_EVENTS_CONSUMER_PAYLOAD_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_wmi_events_anomaly_flags (Phase θ.B.B) ────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical dict passes through.
        (
            {"encoded_powershell": True, "high_severity": True},
            {"encoded_powershell": True, "high_severity": True},
        ),
        # Empty dict — preserved.
        ({}, {}),
        # None — coerced to empty dict.
        (None, {}),
        # Wrong-type — list — coerced to empty dict.
        ([1, 2, 3], {}),
        # Wrong-type — string — coerced to empty dict.
        ("not a dict", {}),
        # Wrong-type — int — coerced to empty dict.
        (42, {}),
    ],
)
def test_normalize_windows_wmi_events_anomaly_flags(value, expected):
    assert _normalize_windows_wmi_events_anomaly_flags(value) == expected


def test_normalize_windows_wmi_events_anomaly_flags_idempotent():
    canonical = {
        "schema_version": 1,
        "encoded_powershell": True,
        "script_host_invocation": False,
        "active_script_consumer": False,
        "non_benign_binding": True,
        "high_severity": True,
    }
    once = _normalize_windows_wmi_events_anomaly_flags(canonical)
    twice = _normalize_windows_wmi_events_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_windows_wmi_events_anomaly_flags_adds_version():
    payload = {"encoded_powershell": True, "high_severity": True}
    out = _stamp_windows_wmi_events_anomaly_flags(payload)
    assert out["schema_version"] == (
        WINDOWS_WMI_EVENTS_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_windows_wmi_events_anomaly_flags_idempotent():
    payload = {"encoded_powershell": True}
    once = _stamp_windows_wmi_events_anomaly_flags(payload)
    twice = _stamp_windows_wmi_events_anomaly_flags(once)
    assert once == twice


def test_windows_wmi_events_anomaly_flags_schema_version_constant():
    assert WINDOWS_WMI_EVENTS_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── _normalize/_stamp_firmware_wmi_walk_result (Phase θ.B.C) ────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "objects_data_scanned": 1,
                "bindings_walked": 3,
                "bindings_persisted": 3,
                "active_script_count": 1,
            },
            {
                "schema_version": 1,
                "objects_data_scanned": 1,
                "bindings_walked": 3,
                "bindings_persisted": 3,
                "active_script_count": 1,
            },
        ),
        ({}, {}),
        (None, None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_wmi_walk_result(value, expected):
    assert _normalize_firmware_wmi_walk_result(value) == expected


def test_stamp_firmware_wmi_walk_result_adds_version():
    out = _stamp_firmware_wmi_walk_result({"objects_data_scanned": 0})
    assert out["schema_version"] == FIRMWARE_WMI_WALK_RESULT_SCHEMA_VERSION


def test_stamp_firmware_wmi_walk_result_idempotent():
    once = _stamp_firmware_wmi_walk_result({"objects_data_scanned": 0})
    twice = _stamp_firmware_wmi_walk_result(once)
    assert once == twice


def test_firmware_wmi_walk_result_schema_version_constant():
    assert FIRMWARE_WMI_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_esp_entries_authenticode_chain (θ.C.A) ────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical dict passes through.
        (
            {"signed": True, "chain_status": "valid_now"},
            {"signed": True, "chain_status": "valid_now"},
        ),
        # Empty dict — preserved.
        ({}, {}),
        # None — coerced to empty dict.
        (None, {}),
        # Wrong-type — list — coerced to empty dict.
        ([1, 2, 3], {}),
        # Wrong-type — string — coerced to empty dict.
        ("not a dict", {}),
        # Wrong-type — int — coerced to empty dict.
        (42, {}),
    ],
)
def test_normalize_windows_esp_entries_authenticode_chain(value, expected):
    assert _normalize_windows_esp_entries_authenticode_chain(value) == expected


def test_normalize_windows_esp_entries_authenticode_chain_idempotent():
    canonical = {
        "schema_version": 1,
        "signed": True,
        "chain_status": "valid_now",
        "signer_subject": "CN=Microsoft Corporation UEFI CA 2011",
        "signatures_count": 1,
    }
    once = _normalize_windows_esp_entries_authenticode_chain(canonical)
    twice = _normalize_windows_esp_entries_authenticode_chain(once)
    assert once == twice == canonical


def test_stamp_windows_esp_entries_authenticode_chain_adds_version():
    payload = {"signed": True, "chain_status": "valid_now"}
    out = _stamp_windows_esp_entries_authenticode_chain(payload)
    assert out["schema_version"] == (
        WINDOWS_ESP_ENTRIES_AUTHENTICODE_CHAIN_SCHEMA_VERSION
    )


def test_stamp_windows_esp_entries_authenticode_chain_idempotent():
    payload = {"signed": True, "chain_status": "valid_now"}
    once = _stamp_windows_esp_entries_authenticode_chain(payload)
    twice = _stamp_windows_esp_entries_authenticode_chain(once)
    assert once == twice


def test_windows_esp_entries_authenticode_chain_schema_version_constant():
    assert WINDOWS_ESP_ENTRIES_AUTHENTICODE_CHAIN_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_esp_entries_dbx_revocation_match (θ.C.A) ──────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical dict passes through.
        (
            {"revoked": True, "match_kind": "x509_serial"},
            {"revoked": True, "match_kind": "x509_serial"},
        ),
        # Empty dict — preserved.
        ({}, {}),
        # None — preserved (no match semantic).
        (None, None),
        # Wrong-type — list — coerced to None.
        ([1, 2, 3], None),
        # Wrong-type — string — coerced to None.
        ("not a dict", None),
        # Wrong-type — int — coerced to None.
        (42, None),
    ],
)
def test_normalize_windows_esp_entries_dbx_revocation_match(value, expected):
    assert (
        _normalize_windows_esp_entries_dbx_revocation_match(value) == expected
    )


def test_normalize_windows_esp_entries_dbx_revocation_match_idempotent():
    canonical = {
        "schema_version": 1,
        "revoked": True,
        "match_kind": "x509_serial",
        "bundle_entries": 5000,
    }
    once = _normalize_windows_esp_entries_dbx_revocation_match(canonical)
    twice = _normalize_windows_esp_entries_dbx_revocation_match(once)
    assert once == twice == canonical


def test_stamp_windows_esp_entries_dbx_revocation_match_adds_version():
    payload = {"revoked": True, "match_kind": "x509_serial"}
    out = _stamp_windows_esp_entries_dbx_revocation_match(payload)
    assert out["schema_version"] == (
        WINDOWS_ESP_ENTRIES_DBX_REVOCATION_MATCH_SCHEMA_VERSION
    )


def test_stamp_windows_esp_entries_dbx_revocation_match_idempotent():
    payload = {"revoked": True, "match_kind": "x509_serial"}
    once = _stamp_windows_esp_entries_dbx_revocation_match(payload)
    twice = _stamp_windows_esp_entries_dbx_revocation_match(once)
    assert once == twice


def test_windows_esp_entries_dbx_revocation_match_schema_version_constant():
    assert WINDOWS_ESP_ENTRIES_DBX_REVOCATION_MATCH_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_esp_entries_anomaly_flags (θ.C.A) ─────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical dict passes through.
        (
            {"is_unsigned": True, "is_revoked": False},
            {"is_unsigned": True, "is_revoked": False},
        ),
        # Empty dict — preserved.
        ({}, {}),
        # None — coerced to empty dict.
        (None, {}),
        # Wrong-type — list — coerced to empty dict.
        ([1, 2, 3], {}),
        # Wrong-type — string — coerced to empty dict.
        ("not a dict", {}),
        # Wrong-type — int — coerced to empty dict.
        (42, {}),
    ],
)
def test_normalize_windows_esp_entries_anomaly_flags(value, expected):
    assert _normalize_windows_esp_entries_anomaly_flags(value) == expected


def test_normalize_windows_esp_entries_anomaly_flags_idempotent():
    canonical = {
        "schema_version": 1,
        "is_unsigned": True,
        "is_known_bootloader_path": True,
        "is_suspiciously_small": False,
    }
    once = _normalize_windows_esp_entries_anomaly_flags(canonical)
    twice = _normalize_windows_esp_entries_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_windows_esp_entries_anomaly_flags_adds_version():
    payload = {"is_unsigned": True}
    out = _stamp_windows_esp_entries_anomaly_flags(payload)
    assert out["schema_version"] == (
        WINDOWS_ESP_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_windows_esp_entries_anomaly_flags_idempotent():
    payload = {"is_unsigned": True}
    once = _stamp_windows_esp_entries_anomaly_flags(payload)
    twice = _stamp_windows_esp_entries_anomaly_flags(once)
    assert once == twice


def test_windows_esp_entries_anomaly_flags_schema_version_constant():
    assert WINDOWS_ESP_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── _normalize/_stamp_firmware_esp_walk_result (Phase θ.C.B) ────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "efi_files_scanned": 5,
                "efi_files_persisted": 5,
                "unsigned_count": 1,
            },
            {
                "schema_version": 1,
                "efi_files_scanned": 5,
                "efi_files_persisted": 5,
                "unsigned_count": 1,
            },
        ),
        ({}, {}),
        (None, None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_esp_walk_result(value, expected):
    assert _normalize_firmware_esp_walk_result(value) == expected


def test_stamp_firmware_esp_walk_result_adds_version():
    out = _stamp_firmware_esp_walk_result({"efi_files_scanned": 0})
    assert out["schema_version"] == FIRMWARE_ESP_WALK_RESULT_SCHEMA_VERSION


def test_stamp_firmware_esp_walk_result_idempotent():
    once = _stamp_firmware_esp_walk_result({"efi_files_scanned": 0})
    twice = _stamp_firmware_esp_walk_result(once)
    assert once == twice


def test_firmware_esp_walk_result_schema_version_constant():
    assert FIRMWARE_ESP_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize/_stamp_windows_mbr_vbr_sectors_anomaly_flags (θ.E.A) ─────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical dict passes through.
        (
            {"is_mbr": True, "non_standard_jmp": True},
            {"is_mbr": True, "non_standard_jmp": True},
        ),
        # Empty dict — preserved.
        ({}, {}),
        # None — coerced to empty dict.
        (None, {}),
        # Wrong-type — list — coerced to empty dict.
        ([1, 2, 3], {}),
        # Wrong-type — string — coerced to empty dict.
        ("not a dict", {}),
        # Wrong-type — int — coerced to empty dict.
        (42, {}),
    ],
)
def test_normalize_windows_mbr_vbr_sectors_anomaly_flags(value, expected):
    assert (
        _normalize_windows_mbr_vbr_sectors_anomaly_flags(value) == expected
    )


def test_normalize_windows_mbr_vbr_sectors_anomaly_flags_idempotent():
    canonical = {
        "schema_version": 1,
        "non_zero_padding": True,
        "unexpected_partition_table": False,
        "non_standard_jmp": True,
        "is_mbr": True,
        "is_vbr": False,
    }
    once = _normalize_windows_mbr_vbr_sectors_anomaly_flags(canonical)
    twice = _normalize_windows_mbr_vbr_sectors_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_windows_mbr_vbr_sectors_anomaly_flags_adds_version():
    payload = {"is_mbr": True}
    out = _stamp_windows_mbr_vbr_sectors_anomaly_flags(payload)
    assert out["schema_version"] == (
        WINDOWS_MBR_VBR_SECTORS_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_windows_mbr_vbr_sectors_anomaly_flags_idempotent():
    payload = {"is_mbr": True}
    once = _stamp_windows_mbr_vbr_sectors_anomaly_flags(payload)
    twice = _stamp_windows_mbr_vbr_sectors_anomaly_flags(once)
    assert once == twice


def test_windows_mbr_vbr_sectors_anomaly_flags_schema_version_constant():
    assert WINDOWS_MBR_VBR_SECTORS_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── _normalize/_stamp_firmware_mbr_vbr_walk_result (Phase θ.E.B) ────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "images_scanned": 2,
                "sectors_persisted": 5,
                "mbr_count": 2,
                "vbr_count": 3,
            },
            {
                "schema_version": 1,
                "images_scanned": 2,
                "sectors_persisted": 5,
                "mbr_count": 2,
                "vbr_count": 3,
            },
        ),
        ({}, {}),
        (None, None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_mbr_vbr_walk_result(value, expected):
    assert _normalize_firmware_mbr_vbr_walk_result(value) == expected


def test_stamp_firmware_mbr_vbr_walk_result_adds_version():
    out = _stamp_firmware_mbr_vbr_walk_result({"images_scanned": 0})
    assert out["schema_version"] == (
        FIRMWARE_MBR_VBR_WALK_RESULT_SCHEMA_VERSION
    )


def test_stamp_firmware_mbr_vbr_walk_result_idempotent():
    once = _stamp_firmware_mbr_vbr_walk_result({"images_scanned": 0})
    twice = _stamp_firmware_mbr_vbr_walk_result(once)
    assert once == twice


def test_firmware_mbr_vbr_walk_result_schema_version_constant():
    assert FIRMWARE_MBR_VBR_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize/_stamp_linux_journald_entries_anomaly_flags (Phase ι.A.A) ─────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through.
        (
            {
                "schema_version": 1,
                "priority_critical": True,
                "oom_killer": False,
                "audit_failure": False,
                "selinux_denied": False,
                "segfault": False,
                "suspicious_unit": True,
                "log_clear_marker": False,
            },
            {
                "schema_version": 1,
                "priority_critical": True,
                "oom_killer": False,
                "audit_failure": False,
                "selinux_denied": False,
                "segfault": False,
                "suspicious_unit": True,
                "log_clear_marker": False,
            },
        ),
        # Empty dict pass-through.
        ({}, {}),
        # None collapses to empty dict.
        (None, {}),
        # Wrong type — list — collapses to empty dict.
        ([{"a": 1}], {}),
        # Wrong type — string — collapses to empty dict.
        ("not a dict", {}),
        # Wrong type — int — collapses to empty dict.
        (42, {}),
    ],
)
def test_normalize_linux_journald_entries_anomaly_flags(value, expected):
    assert _normalize_linux_journald_entries_anomaly_flags(value) == expected


def test_normalize_linux_journald_entries_anomaly_flags_idempotent():
    canonical = {
        "schema_version": 1,
        "priority_critical": True,
        "oom_killer": True,
    }
    once = _normalize_linux_journald_entries_anomaly_flags(canonical)
    twice = _normalize_linux_journald_entries_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_linux_journald_entries_anomaly_flags_adds_version():
    out = _stamp_linux_journald_entries_anomaly_flags(
        {"priority_critical": True}
    )
    assert (
        out["schema_version"]
        == LINUX_JOURNALD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_linux_journald_entries_anomaly_flags_idempotent():
    once = _stamp_linux_journald_entries_anomaly_flags({"a": 1})
    twice = _stamp_linux_journald_entries_anomaly_flags(once)
    assert once == twice


def test_linux_journald_entries_anomaly_flags_schema_version_constant():
    assert LINUX_JOURNALD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── _normalize/_stamp_firmware_journald_walk_result (Phase ι.A.B) ────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "files_scanned": 1,
                "entries_walked": 100,
                "entries_persisted": 100,
                "priority_critical_count": 3,
                "anomaly_total": 5,
            },
            {
                "schema_version": 1,
                "files_scanned": 1,
                "entries_walked": 100,
                "entries_persisted": 100,
                "priority_critical_count": 3,
                "anomaly_total": 5,
            },
        ),
        ({}, {}),
        (None, None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_journald_walk_result(value, expected):
    assert _normalize_firmware_journald_walk_result(value) == expected


def test_stamp_firmware_journald_walk_result_adds_version():
    out = _stamp_firmware_journald_walk_result({"files_scanned": 0})
    assert out["schema_version"] == FIRMWARE_JOURNALD_WALK_RESULT_SCHEMA_VERSION


def test_stamp_firmware_journald_walk_result_idempotent():
    once = _stamp_firmware_journald_walk_result({"files_scanned": 0})
    twice = _stamp_firmware_journald_walk_result(once)
    assert once == twice


def test_firmware_journald_walk_result_schema_version_constant():
    assert FIRMWARE_JOURNALD_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize linux_systemd_units list-shape columns (Phase ι.B.A) ──────────


@pytest.mark.parametrize(
    "normalizer",
    [
        _normalize_linux_systemd_units_wanted_by,
        _normalize_linux_systemd_units_required_by,
        _normalize_linux_systemd_units_requires,
        _normalize_linux_systemd_units_after,
        _normalize_linux_systemd_units_before,
    ],
)
def test_normalize_linux_systemd_units_list_columns_canonical_passthrough(
    normalizer,
):
    canonical = ["multi-user.target", "graphical.target"]
    assert normalizer(canonical) == canonical


@pytest.mark.parametrize(
    "normalizer",
    [
        _normalize_linux_systemd_units_wanted_by,
        _normalize_linux_systemd_units_required_by,
        _normalize_linux_systemd_units_requires,
        _normalize_linux_systemd_units_after,
        _normalize_linux_systemd_units_before,
    ],
)
@pytest.mark.parametrize("bad", [None, {}, "string", 42, 0.5])
def test_normalize_linux_systemd_units_list_columns_defensive(
    normalizer, bad
):
    """None / wrong-typed → empty list."""
    assert normalizer(bad) == []


@pytest.mark.parametrize(
    "normalizer",
    [
        _normalize_linux_systemd_units_wanted_by,
        _normalize_linux_systemd_units_required_by,
        _normalize_linux_systemd_units_requires,
        _normalize_linux_systemd_units_after,
        _normalize_linux_systemd_units_before,
    ],
)
def test_normalize_linux_systemd_units_list_columns_idempotent(normalizer):
    canonical = ["sshd.service"]
    once = normalizer(canonical)
    twice = normalizer(once)
    assert once == twice == canonical


def test_normalize_linux_systemd_units_list_columns_coerce_non_string_elements():
    """Non-string list elements coerce via str(); None elements dropped."""
    raw = ["foo.target", None, 42]
    out = _normalize_linux_systemd_units_wanted_by(raw)
    assert out == ["foo.target", "42"]


# ── _normalize linux_systemd_units dict-shape columns (Phase ι.B.A) ──────────


@pytest.mark.parametrize(
    "normalizer",
    [
        _normalize_linux_systemd_units_triggers,
        _normalize_linux_systemd_units_socket_listen,
    ],
)
def test_normalize_linux_systemd_units_dict_columns_canonical_passthrough(
    normalizer,
):
    canonical = {"OnCalendar": "*-*-* 02:00:00", "Persistent": "true"}
    assert normalizer(canonical) == canonical


@pytest.mark.parametrize(
    "normalizer",
    [
        _normalize_linux_systemd_units_triggers,
        _normalize_linux_systemd_units_socket_listen,
    ],
)
@pytest.mark.parametrize("bad", [None, [], "string", 42, 0.5])
def test_normalize_linux_systemd_units_dict_columns_defensive(
    normalizer, bad
):
    """None / wrong-typed → empty dict."""
    assert normalizer(bad) == {}


@pytest.mark.parametrize(
    "normalizer",
    [
        _normalize_linux_systemd_units_triggers,
        _normalize_linux_systemd_units_socket_listen,
    ],
)
def test_normalize_linux_systemd_units_dict_columns_idempotent(normalizer):
    canonical = {"ListenStream": "8080"}
    once = normalizer(canonical)
    twice = normalizer(once)
    assert once == twice == canonical


# ── _normalize/_stamp linux_systemd_units.anomaly_flags (Phase ι.B.A) ────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through.
        (
            {
                "schema_version": 1,
                "suspicious_path": True,
                "suspicious_unit_name": False,
                "socket_unusual_port": False,
                "root_minimal_deps": True,
                "disabled_but_present": False,
                "enabled_outside_standard": False,
                "obfuscated_exec": False,
            },
            {
                "schema_version": 1,
                "suspicious_path": True,
                "suspicious_unit_name": False,
                "socket_unusual_port": False,
                "root_minimal_deps": True,
                "disabled_but_present": False,
                "enabled_outside_standard": False,
                "obfuscated_exec": False,
            },
        ),
        # Empty dict pass-through.
        ({}, {}),
        # None collapses to empty dict.
        (None, {}),
        # Wrong type — list — collapses to empty dict.
        ([{"a": 1}], {}),
        # Wrong type — string — collapses to empty dict.
        ("not a dict", {}),
        # Wrong type — int — collapses to empty dict.
        (42, {}),
    ],
)
def test_normalize_linux_systemd_units_anomaly_flags(value, expected):
    assert _normalize_linux_systemd_units_anomaly_flags(value) == expected


def test_normalize_linux_systemd_units_anomaly_flags_idempotent():
    canonical = {
        "schema_version": 1,
        "suspicious_path": True,
        "obfuscated_exec": True,
    }
    once = _normalize_linux_systemd_units_anomaly_flags(canonical)
    twice = _normalize_linux_systemd_units_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_linux_systemd_units_anomaly_flags_adds_version():
    out = _stamp_linux_systemd_units_anomaly_flags(
        {"suspicious_path": True}
    )
    assert (
        out["schema_version"]
        == LINUX_SYSTEMD_UNITS_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_linux_systemd_units_anomaly_flags_idempotent():
    once = _stamp_linux_systemd_units_anomaly_flags({"a": 1})
    twice = _stamp_linux_systemd_units_anomaly_flags(once)
    assert once == twice


def test_linux_systemd_units_anomaly_flags_schema_version_constant():
    assert LINUX_SYSTEMD_UNITS_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── _normalize/_stamp firmware.systemd_walk_result (Phase ι.B.B) ─────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "units_scanned": 24,
                "units_persisted": 24,
                "service_count": 18,
                "timer_count": 4,
                "anomaly_total": 2,
            },
            {
                "schema_version": 1,
                "units_scanned": 24,
                "units_persisted": 24,
                "service_count": 18,
                "timer_count": 4,
                "anomaly_total": 2,
            },
        ),
        ({}, {}),
        (None, None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_systemd_walk_result(value, expected):
    assert _normalize_firmware_systemd_walk_result(value) == expected


def test_stamp_firmware_systemd_walk_result_adds_version():
    out = _stamp_firmware_systemd_walk_result({"units_scanned": 0})
    assert out["schema_version"] == FIRMWARE_SYSTEMD_WALK_RESULT_SCHEMA_VERSION


def test_stamp_firmware_systemd_walk_result_idempotent():
    once = _stamp_firmware_systemd_walk_result({"units_scanned": 0})
    twice = _stamp_firmware_systemd_walk_result(once)
    assert once == twice


def test_firmware_systemd_walk_result_schema_version_constant():
    assert FIRMWARE_SYSTEMD_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize/_stamp windows_etl_events.payload (Phase ι.C.A) ───────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through — decoded manifest payload.
        (
            {
                "schema_version": 1,
                "ProcessId": 1234,
                "ImageName": "C:\\Windows\\System32\\svchost.exe",
            },
            {
                "schema_version": 1,
                "ProcessId": 1234,
                "ImageName": "C:\\Windows\\System32\\svchost.exe",
            },
        ),
        # Raw bytes preview pass-through.
        (
            {"schema_version": 1, "raw_b64": "AABB==", "raw_size": 64},
            {"schema_version": 1, "raw_b64": "AABB==", "raw_size": 64},
        ),
        # Empty dict pass-through.
        ({}, {}),
        # None / wrong-types collapse to empty dict.
        (None, {}),
        ([], {}),
        ("not a dict", {}),
        (42, {}),
    ],
)
def test_normalize_windows_etl_events_payload(value, expected):
    assert _normalize_windows_etl_events_payload(value) == expected


def test_normalize_windows_etl_events_payload_idempotent():
    canonical = {"schema_version": 1, "ProcessId": 1234}
    once = _normalize_windows_etl_events_payload(canonical)
    twice = _normalize_windows_etl_events_payload(once)
    assert once == twice == canonical


def test_stamp_windows_etl_events_payload_adds_version():
    out = _stamp_windows_etl_events_payload({"ProcessId": 1234})
    assert out["schema_version"] == WINDOWS_ETL_EVENTS_PAYLOAD_SCHEMA_VERSION


def test_stamp_windows_etl_events_payload_idempotent():
    once = _stamp_windows_etl_events_payload({"a": 1})
    twice = _stamp_windows_etl_events_payload(once)
    assert once == twice


def test_windows_etl_events_payload_schema_version_constant():
    assert WINDOWS_ETL_EVENTS_PAYLOAD_SCHEMA_VERSION == 1


# ── _normalize/_stamp windows_etl_events.anomaly_flags (Phase ι.C.A) ─────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through.
        (
            {
                "schema_version": 1,
                "kernel_proc_after_evtx_clear": True,
                "provider_disable_evidence": False,
                "unusual_provider": False,
                "non_microsoft_in_diagtrack": False,
            },
            {
                "schema_version": 1,
                "kernel_proc_after_evtx_clear": True,
                "provider_disable_evidence": False,
                "unusual_provider": False,
                "non_microsoft_in_diagtrack": False,
            },
        ),
        # Empty dict pass-through.
        ({}, {}),
        # None / wrong-types collapse to empty dict.
        (None, {}),
        ([{"a": 1}], {}),
        ("not a dict", {}),
        (42, {}),
    ],
)
def test_normalize_windows_etl_events_anomaly_flags(value, expected):
    assert _normalize_windows_etl_events_anomaly_flags(value) == expected


def test_normalize_windows_etl_events_anomaly_flags_idempotent():
    canonical = {
        "schema_version": 1,
        "kernel_proc_after_evtx_clear": True,
    }
    once = _normalize_windows_etl_events_anomaly_flags(canonical)
    twice = _normalize_windows_etl_events_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_windows_etl_events_anomaly_flags_adds_version():
    out = _stamp_windows_etl_events_anomaly_flags(
        {"unusual_provider": True}
    )
    assert (
        out["schema_version"]
        == WINDOWS_ETL_EVENTS_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_windows_etl_events_anomaly_flags_idempotent():
    once = _stamp_windows_etl_events_anomaly_flags({"unusual_provider": True})
    twice = _stamp_windows_etl_events_anomaly_flags(once)
    assert once == twice


def test_windows_etl_events_anomaly_flags_schema_version_constant():
    assert WINDOWS_ETL_EVENTS_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── _normalize/_stamp firmware.etl_walk_result (Phase ι.C.B) ─────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "files_scanned": 8,
                "events_walked": 12345,
                "events_persisted": 9999,
                "anomaly_total": 17,
            },
            {
                "schema_version": 1,
                "files_scanned": 8,
                "events_walked": 12345,
                "events_persisted": 9999,
                "anomaly_total": 17,
            },
        ),
        ({}, {}),
        (None, None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_etl_walk_result(value, expected):
    assert _normalize_firmware_etl_walk_result(value) == expected


def test_stamp_firmware_etl_walk_result_adds_version():
    out = _stamp_firmware_etl_walk_result({"files_scanned": 0})
    assert out["schema_version"] == FIRMWARE_ETL_WALK_RESULT_SCHEMA_VERSION


def test_stamp_firmware_etl_walk_result_idempotent():
    once = _stamp_firmware_etl_walk_result({"files_scanned": 0})
    twice = _stamp_firmware_etl_walk_result(once)
    assert once == twice


def test_firmware_etl_walk_result_schema_version_constant():
    assert FIRMWARE_ETL_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize/_stamp windows_efs_encrypted_files.ddf_users (Phase ι.D.A) ────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical list of user entries — pass-through.
        (
            [
                {
                    "sid": "S-1-5-21-1-2-3-1001",
                    "cert_thumbprint": "0123456789abcdef" * 2 + "01234567",
                    "friendly_name": "alice@example.com",
                },
            ],
            [
                {
                    "sid": "S-1-5-21-1-2-3-1001",
                    "cert_thumbprint": "0123456789abcdef" * 2 + "01234567",
                    "friendly_name": "alice@example.com",
                },
            ],
        ),
        # Empty list pass-through.
        ([], []),
        # None / wrong-types collapse to empty list.
        (None, []),
        ({}, []),
        ("not a list", []),
        (42, []),
        # Non-dict elements silently dropped.
        ([{"sid": "S-1"}, "garbage", 42, {"sid": "S-2"}], [{"sid": "S-1"}, {"sid": "S-2"}]),
    ],
)
def test_normalize_windows_efs_encrypted_files_ddf_users(value, expected):
    assert _normalize_windows_efs_encrypted_files_ddf_users(value) == expected


def test_normalize_windows_efs_encrypted_files_ddf_users_idempotent():
    canonical = [{"sid": "S-1-5-21-1-2-3-1001", "cert_thumbprint": "abc"}]
    once = _normalize_windows_efs_encrypted_files_ddf_users(canonical)
    twice = _normalize_windows_efs_encrypted_files_ddf_users(once)
    assert once == twice == canonical


def test_stamp_windows_efs_encrypted_files_ddf_users_adds_sentinel():
    out = _stamp_windows_efs_encrypted_files_ddf_users(
        [{"sid": "S-1-5-21-1-2-3-1001"}]
    )
    # First element is the schema_version sentinel; user entries follow.
    assert isinstance(out, list)
    assert (
        out[0]["schema_version"]
        == WINDOWS_EFS_ENCRYPTED_FILES_DDF_USERS_SCHEMA_VERSION
    )
    assert out[1]["sid"] == "S-1-5-21-1-2-3-1001"


def test_stamp_windows_efs_encrypted_files_ddf_users_empty_input():
    out = _stamp_windows_efs_encrypted_files_ddf_users([])
    assert out == [
        {"schema_version": WINDOWS_EFS_ENCRYPTED_FILES_DDF_USERS_SCHEMA_VERSION},
    ]


def test_stamp_windows_efs_encrypted_files_ddf_users_idempotent():
    once = _stamp_windows_efs_encrypted_files_ddf_users([{"sid": "S-1"}])
    twice = _stamp_windows_efs_encrypted_files_ddf_users(once)
    assert once == twice


def test_windows_efs_encrypted_files_ddf_users_schema_version_constant():
    assert WINDOWS_EFS_ENCRYPTED_FILES_DDF_USERS_SCHEMA_VERSION == 1


# ── _normalize/_stamp windows_efs_encrypted_files.drf_recovery_agents (Phase ι.D.A) ──


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical list of recovery-agent entries — pass-through.
        (
            [
                {
                    "sid": "S-1-5-32-544",
                    "cert_thumbprint": "abcdef0123456789" * 2 + "abcdef01",
                    "friendly_name": "BUILTIN\\Administrators",
                },
            ],
            [
                {
                    "sid": "S-1-5-32-544",
                    "cert_thumbprint": "abcdef0123456789" * 2 + "abcdef01",
                    "friendly_name": "BUILTIN\\Administrators",
                },
            ],
        ),
        # Empty list pass-through.
        ([], []),
        # None / wrong-types collapse to empty list.
        (None, []),
        ({}, []),
        ("not a list", []),
        (42, []),
    ],
)
def test_normalize_windows_efs_encrypted_files_drf_recovery_agents(value, expected):
    assert (
        _normalize_windows_efs_encrypted_files_drf_recovery_agents(value)
        == expected
    )


def test_normalize_windows_efs_encrypted_files_drf_recovery_agents_idempotent():
    canonical = [{"sid": "S-1-5-32-544", "cert_thumbprint": "abc"}]
    once = _normalize_windows_efs_encrypted_files_drf_recovery_agents(canonical)
    twice = _normalize_windows_efs_encrypted_files_drf_recovery_agents(once)
    assert once == twice == canonical


def test_stamp_windows_efs_encrypted_files_drf_recovery_agents_adds_sentinel():
    out = _stamp_windows_efs_encrypted_files_drf_recovery_agents(
        [{"sid": "S-1-5-32-544"}]
    )
    assert isinstance(out, list)
    assert (
        out[0]["schema_version"]
        == WINDOWS_EFS_ENCRYPTED_FILES_DRF_RECOVERY_AGENTS_SCHEMA_VERSION
    )
    assert out[1]["sid"] == "S-1-5-32-544"


def test_stamp_windows_efs_encrypted_files_drf_recovery_agents_empty_input():
    out = _stamp_windows_efs_encrypted_files_drf_recovery_agents([])
    assert out == [
        {
            "schema_version": (
                WINDOWS_EFS_ENCRYPTED_FILES_DRF_RECOVERY_AGENTS_SCHEMA_VERSION
            )
        }
    ]


def test_stamp_windows_efs_encrypted_files_drf_recovery_agents_idempotent():
    once = _stamp_windows_efs_encrypted_files_drf_recovery_agents(
        [{"sid": "S-1-5-32-544"}]
    )
    twice = _stamp_windows_efs_encrypted_files_drf_recovery_agents(once)
    assert once == twice


def test_windows_efs_encrypted_files_drf_recovery_agents_schema_version_constant():
    assert WINDOWS_EFS_ENCRYPTED_FILES_DRF_RECOVERY_AGENTS_SCHEMA_VERSION == 1


# ── _normalize/_stamp windows_efs_encrypted_files.anomaly_flags (Phase ι.D.A) ─


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through.
        (
            {
                "schema_version": 1,
                "orphaned_drf": True,
                "unusual_recovery_agent": False,
                "multiple_ddf_users": False,
                "large_drf": False,
                "cert_thumbprint_anomaly": False,
                "domain_admin_in_ddf": False,
                "parse_error": False,
            },
            {
                "schema_version": 1,
                "orphaned_drf": True,
                "unusual_recovery_agent": False,
                "multiple_ddf_users": False,
                "large_drf": False,
                "cert_thumbprint_anomaly": False,
                "domain_admin_in_ddf": False,
                "parse_error": False,
            },
        ),
        # Empty dict pass-through.
        ({}, {}),
        # None / wrong-types collapse to empty dict.
        (None, {}),
        ([{"a": 1}], {}),
        ("not a dict", {}),
        (42, {}),
    ],
)
def test_normalize_windows_efs_encrypted_files_anomaly_flags(value, expected):
    assert (
        _normalize_windows_efs_encrypted_files_anomaly_flags(value) == expected
    )


def test_normalize_windows_efs_encrypted_files_anomaly_flags_idempotent():
    canonical = {"schema_version": 1, "orphaned_drf": True}
    once = _normalize_windows_efs_encrypted_files_anomaly_flags(canonical)
    twice = _normalize_windows_efs_encrypted_files_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_windows_efs_encrypted_files_anomaly_flags_adds_version():
    out = _stamp_windows_efs_encrypted_files_anomaly_flags(
        {"orphaned_drf": True}
    )
    assert (
        out["schema_version"]
        == WINDOWS_EFS_ENCRYPTED_FILES_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_windows_efs_encrypted_files_anomaly_flags_idempotent():
    once = _stamp_windows_efs_encrypted_files_anomaly_flags(
        {"orphaned_drf": True}
    )
    twice = _stamp_windows_efs_encrypted_files_anomaly_flags(once)
    assert once == twice


def test_windows_efs_encrypted_files_anomaly_flags_schema_version_constant():
    assert WINDOWS_EFS_ENCRYPTED_FILES_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── _normalize/_stamp firmware.efs_walk_result (Phase ι.D.B) ─────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "images_scanned": 3,
                "files_walked": 150000,
                "encrypted_files_found": 12,
                "encrypted_files_persisted": 12,
                "anomaly_total": 2,
            },
            {
                "schema_version": 1,
                "images_scanned": 3,
                "files_walked": 150000,
                "encrypted_files_found": 12,
                "encrypted_files_persisted": 12,
                "anomaly_total": 2,
            },
        ),
        # None preserved as the "no completed run yet" sentinel.
        (None, None),
        # Wrong-types collapse to None.
        ([], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_efs_walk_result(value, expected):
    assert _normalize_firmware_efs_walk_result(value) == expected


def test_stamp_firmware_efs_walk_result_adds_version():
    out = _stamp_firmware_efs_walk_result({"images_scanned": 0})
    assert out["schema_version"] == FIRMWARE_EFS_WALK_RESULT_SCHEMA_VERSION


def test_stamp_firmware_efs_walk_result_idempotent():
    once = _stamp_firmware_efs_walk_result({"images_scanned": 0})
    twice = _stamp_firmware_efs_walk_result(once)
    assert once == twice


def test_firmware_efs_walk_result_schema_version_constant():
    assert FIRMWARE_EFS_WALK_RESULT_SCHEMA_VERSION == 1


# ── _normalize linux_container_artifacts list-shape columns (Phase ι.E.A) ────


@pytest.mark.parametrize(
    "normalizer",
    [
        _normalize_linux_container_artifacts_capabilities_add,
        _normalize_linux_container_artifacts_capabilities_drop,
        _normalize_linux_container_artifacts_env_vars,
    ],
)
def test_normalize_linux_container_artifacts_str_list_columns_canonical_passthrough(
    normalizer,
):
    canonical = ["CAP_SYS_ADMIN", "CAP_NET_BIND_SERVICE"]
    assert normalizer(canonical) == canonical


@pytest.mark.parametrize(
    "normalizer",
    [
        _normalize_linux_container_artifacts_capabilities_add,
        _normalize_linux_container_artifacts_capabilities_drop,
        _normalize_linux_container_artifacts_env_vars,
    ],
)
@pytest.mark.parametrize("bad", [None, {}, "string", 42, 0.5])
def test_normalize_linux_container_artifacts_str_list_columns_defensive(
    normalizer, bad
):
    """None / wrong-typed → empty list."""
    assert normalizer(bad) == []


@pytest.mark.parametrize(
    "normalizer",
    [
        _normalize_linux_container_artifacts_capabilities_add,
        _normalize_linux_container_artifacts_capabilities_drop,
        _normalize_linux_container_artifacts_env_vars,
    ],
)
def test_normalize_linux_container_artifacts_str_list_columns_idempotent(
    normalizer,
):
    canonical = ["FOO"]
    once = normalizer(canonical)
    twice = normalizer(once)
    assert once == twice == canonical


def test_normalize_linux_container_artifacts_capabilities_coerce_non_string():
    """Non-string list elements coerce via str(); None elements dropped."""
    raw = ["CAP_SYS_ADMIN", None, 42]
    out = _normalize_linux_container_artifacts_capabilities_add(raw)
    assert out == ["CAP_SYS_ADMIN", "42"]


def test_normalize_linux_container_artifacts_env_vars_keys_only():
    """env_vars surfaces KEYS only — string list, never key=value pairs."""
    raw = ["PATH", "HOME", "DEBUG"]
    assert _normalize_linux_container_artifacts_env_vars(raw) == raw


# ── _normalize linux_container_artifacts.mounts (list[dict] shape) ──────────


def test_normalize_linux_container_artifacts_mounts_canonical_passthrough():
    canonical = [
        {
            "source": "/var/log",
            "destination": "/host_logs",
            "mode": "ro",
            "type": "bind",
        },
    ]
    assert _normalize_linux_container_artifacts_mounts(canonical) == canonical


@pytest.mark.parametrize("bad", [None, {}, "string", 42, 0.5])
def test_normalize_linux_container_artifacts_mounts_defensive(bad):
    """None / wrong-typed → empty list."""
    assert _normalize_linux_container_artifacts_mounts(bad) == []


def test_normalize_linux_container_artifacts_mounts_idempotent():
    canonical = [{"source": "/x", "destination": "/y"}]
    once = _normalize_linux_container_artifacts_mounts(canonical)
    twice = _normalize_linux_container_artifacts_mounts(once)
    assert once == twice == canonical


def test_normalize_linux_container_artifacts_mounts_drops_non_dict():
    """Non-dict list elements silently dropped."""
    raw = [{"source": "/a", "destination": "/b"}, "not a dict", 42]
    out = _normalize_linux_container_artifacts_mounts(raw)
    assert out == [{"source": "/a", "destination": "/b"}]


# ── _normalize/_stamp linux_container_artifacts.anomaly_flags (Phase ι.E.A) ──


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through.
        (
            {
                "schema_version": 1,
                "privileged_mode": True,
                "host_pid_namespace": False,
                "host_network_namespace": True,
                "host_ipc_namespace": False,
                "dangerous_capability": True,
                "unconfined_seccomp": False,
                "unconfined_apparmor": False,
                "unsafe_mount": True,
                "unknown_registry": False,
            },
            {
                "schema_version": 1,
                "privileged_mode": True,
                "host_pid_namespace": False,
                "host_network_namespace": True,
                "host_ipc_namespace": False,
                "dangerous_capability": True,
                "unconfined_seccomp": False,
                "unconfined_apparmor": False,
                "unsafe_mount": True,
                "unknown_registry": False,
            },
        ),
        # Empty dict pass-through.
        ({}, {}),
        # None collapses to empty dict.
        (None, {}),
        # Wrong type — list — collapses to empty dict.
        ([{"a": 1}], {}),
        # Wrong type — string — collapses to empty dict.
        ("not a dict", {}),
        # Wrong type — int — collapses to empty dict.
        (42, {}),
    ],
)
def test_normalize_linux_container_artifacts_anomaly_flags(value, expected):
    assert (
        _normalize_linux_container_artifacts_anomaly_flags(value) == expected
    )


def test_normalize_linux_container_artifacts_anomaly_flags_idempotent():
    canonical = {
        "schema_version": 1,
        "privileged_mode": True,
        "dangerous_capability": True,
    }
    once = _normalize_linux_container_artifacts_anomaly_flags(canonical)
    twice = _normalize_linux_container_artifacts_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_linux_container_artifacts_anomaly_flags_adds_version():
    out = _stamp_linux_container_artifacts_anomaly_flags(
        {"privileged_mode": True}
    )
    assert (
        out["schema_version"]
        == LINUX_CONTAINER_ARTIFACTS_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_linux_container_artifacts_anomaly_flags_idempotent():
    once = _stamp_linux_container_artifacts_anomaly_flags(
        {"privileged_mode": True}
    )
    twice = _stamp_linux_container_artifacts_anomaly_flags(once)
    assert once == twice


def test_linux_container_artifacts_anomaly_flags_schema_version_constant():
    assert LINUX_CONTAINER_ARTIFACTS_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── _normalize/_stamp firmware.container_walk_result (Phase ι.E.B) ───────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "artifacts_scanned": 8,
                "artifacts_persisted": 8,
                "containers_count": 3,
                "privileged_count": 1,
                "anomaly_total": 4,
            },
            {
                "schema_version": 1,
                "artifacts_scanned": 8,
                "artifacts_persisted": 8,
                "containers_count": 3,
                "privileged_count": 1,
                "anomaly_total": 4,
            },
        ),
        # None preserved.
        (None, None),
        # Wrong types collapse to None.
        ([], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_container_walk_result(value, expected):
    assert _normalize_firmware_container_walk_result(value) == expected


def test_stamp_firmware_container_walk_result_adds_version():
    out = _stamp_firmware_container_walk_result({"artifacts_scanned": 0})
    assert (
        out["schema_version"] == FIRMWARE_CONTAINER_WALK_RESULT_SCHEMA_VERSION
    )


def test_stamp_firmware_container_walk_result_idempotent():
    once = _stamp_firmware_container_walk_result({"artifacts_scanned": 0})
    twice = _stamp_firmware_container_walk_result(once)
    assert once == twice


def test_firmware_container_walk_result_schema_version_constant():
    assert FIRMWARE_CONTAINER_WALK_RESULT_SCHEMA_VERSION == 1


# ── windows_appcompat_entries.anomaly_flags (Phase κ.B.A) ────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical shape — dict with all bits + schema_version.
        (
            {
                "schema_version": 1,
                "suspicious_path": True,
                "temp_execution": False,
                "unusual_extension": False,
                "parse_error": False,
            },
            {
                "schema_version": 1,
                "suspicious_path": True,
                "temp_execution": False,
                "unusual_extension": False,
                "parse_error": False,
            },
        ),
        # Empty dict pass-through.
        ({}, {}),
        # None / wrong-types collapse to empty dict.
        (None, {}),
        ([{"a": 1}], {}),
        ("not a dict", {}),
        (42, {}),
    ],
)
def test_normalize_windows_appcompat_entries_anomaly_flags(value, expected):
    assert (
        _normalize_windows_appcompat_entries_anomaly_flags(value) == expected
    )


def test_normalize_windows_appcompat_entries_anomaly_flags_idempotent():
    canonical = {"schema_version": 1, "suspicious_path": True}
    once = _normalize_windows_appcompat_entries_anomaly_flags(canonical)
    twice = _normalize_windows_appcompat_entries_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_windows_appcompat_entries_anomaly_flags_adds_version():
    out = _stamp_windows_appcompat_entries_anomaly_flags(
        {"suspicious_path": True}
    )
    assert (
        out["schema_version"]
        == WINDOWS_APPCOMPAT_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_windows_appcompat_entries_anomaly_flags_idempotent():
    once = _stamp_windows_appcompat_entries_anomaly_flags(
        {"suspicious_path": True}
    )
    twice = _stamp_windows_appcompat_entries_anomaly_flags(once)
    assert once == twice


def test_windows_appcompat_entries_anomaly_flags_schema_version_constant():
    assert WINDOWS_APPCOMPAT_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── firmware.appcompat_walk_result (Phase κ.B.B) ─────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical shape — dict with arbitrary sub-keys.
        (
            {
                "schema_version": 1,
                "hives_scanned": 2,
                "entries_persisted": 50,
                "anomaly_total": 3,
            },
            {
                "schema_version": 1,
                "hives_scanned": 2,
                "entries_persisted": 50,
                "anomaly_total": 3,
            },
        ),
        # Empty dict — preserved (no run yet but field exists).
        ({}, {}),
        # None preserved (semantic "no completed run").
        (None, None),
        # Wrong-types collapse to None.
        ([{"a": 1}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_appcompat_walk_result(value, expected):
    assert _normalize_firmware_appcompat_walk_result(value) == expected


def test_stamp_firmware_appcompat_walk_result_adds_version():
    out = _stamp_firmware_appcompat_walk_result({"hives_scanned": 0})
    assert (
        out["schema_version"] == FIRMWARE_APPCOMPAT_WALK_RESULT_SCHEMA_VERSION
    )


def test_stamp_firmware_appcompat_walk_result_idempotent():
    once = _stamp_firmware_appcompat_walk_result({"hives_scanned": 0})
    twice = _stamp_firmware_appcompat_walk_result(once)
    assert once == twice


def test_firmware_appcompat_walk_result_schema_version_constant():
    assert FIRMWARE_APPCOMPAT_WALK_RESULT_SCHEMA_VERSION == 1


# ── linux_bash_history_entries.suspicious_flags (Phase κ.C.A) ────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "clear_marker": True,
                "download_pattern": False,
                "priv_esc_pattern": False,
            },
            {
                "schema_version": 1,
                "clear_marker": True,
                "download_pattern": False,
                "priv_esc_pattern": False,
            },
        ),
        ({}, {}),
        (None, {}),
        ([{"a": 1}], {}),
        ("not a dict", {}),
        (42, {}),
    ],
)
def test_normalize_linux_bash_history_suspicious_flags(value, expected):
    assert (
        _normalize_linux_bash_history_suspicious_flags(value) == expected
    )


def test_normalize_linux_bash_history_suspicious_flags_idempotent():
    canonical = {"schema_version": 1, "clear_marker": True}
    once = _normalize_linux_bash_history_suspicious_flags(canonical)
    twice = _normalize_linux_bash_history_suspicious_flags(once)
    assert once == twice == canonical


def test_stamp_linux_bash_history_suspicious_flags_adds_version():
    out = _stamp_linux_bash_history_suspicious_flags({"clear_marker": True})
    assert (
        out["schema_version"]
        == LINUX_BASH_HISTORY_ENTRIES_SUSPICIOUS_FLAGS_SCHEMA_VERSION
    )


def test_stamp_linux_bash_history_suspicious_flags_idempotent():
    once = _stamp_linux_bash_history_suspicious_flags(
        {"clear_marker": True}
    )
    twice = _stamp_linux_bash_history_suspicious_flags(once)
    assert once == twice


def test_linux_bash_history_entries_suspicious_flags_schema_version_constant():
    assert LINUX_BASH_HISTORY_ENTRIES_SUSPICIOUS_FLAGS_SCHEMA_VERSION == 1


# ── linux_cron_jobs.suspicious_flags (Phase κ.C.A) ───────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "temp_path_command": False,
                "reboot_persistence": True,
                "network_egress_pattern": False,
            },
            {
                "schema_version": 1,
                "temp_path_command": False,
                "reboot_persistence": True,
                "network_egress_pattern": False,
            },
        ),
        ({}, {}),
        (None, {}),
        ([{"a": 1}], {}),
        ("not a dict", {}),
        (42, {}),
    ],
)
def test_normalize_linux_cron_suspicious_flags(value, expected):
    assert _normalize_linux_cron_suspicious_flags(value) == expected


def test_normalize_linux_cron_suspicious_flags_idempotent():
    canonical = {"schema_version": 1, "reboot_persistence": True}
    once = _normalize_linux_cron_suspicious_flags(canonical)
    twice = _normalize_linux_cron_suspicious_flags(once)
    assert once == twice == canonical


def test_stamp_linux_cron_suspicious_flags_adds_version():
    out = _stamp_linux_cron_suspicious_flags({"reboot_persistence": True})
    assert (
        out["schema_version"]
        == LINUX_CRON_JOBS_SUSPICIOUS_FLAGS_SCHEMA_VERSION
    )


def test_stamp_linux_cron_suspicious_flags_idempotent():
    once = _stamp_linux_cron_suspicious_flags({"reboot_persistence": True})
    twice = _stamp_linux_cron_suspicious_flags(once)
    assert once == twice


def test_linux_cron_jobs_suspicious_flags_schema_version_constant():
    assert LINUX_CRON_JOBS_SUSPICIOUS_FLAGS_SCHEMA_VERSION == 1


# ── linux_ld_preload_entries.suspicious_flags (Phase κ.C.A) ──────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "temp_path_library": True,
                "unusual_extension": False,
                "world_writable_dir": True,
            },
            {
                "schema_version": 1,
                "temp_path_library": True,
                "unusual_extension": False,
                "world_writable_dir": True,
            },
        ),
        ({}, {}),
        (None, {}),
        ([{"a": 1}], {}),
        ("not a dict", {}),
        (42, {}),
    ],
)
def test_normalize_linux_ld_preload_suspicious_flags(value, expected):
    assert (
        _normalize_linux_ld_preload_suspicious_flags(value) == expected
    )


def test_normalize_linux_ld_preload_suspicious_flags_idempotent():
    canonical = {"schema_version": 1, "temp_path_library": True}
    once = _normalize_linux_ld_preload_suspicious_flags(canonical)
    twice = _normalize_linux_ld_preload_suspicious_flags(once)
    assert once == twice == canonical


def test_stamp_linux_ld_preload_suspicious_flags_adds_version():
    out = _stamp_linux_ld_preload_suspicious_flags(
        {"temp_path_library": True}
    )
    assert (
        out["schema_version"]
        == LINUX_LD_PRELOAD_ENTRIES_SUSPICIOUS_FLAGS_SCHEMA_VERSION
    )


def test_stamp_linux_ld_preload_suspicious_flags_idempotent():
    once = _stamp_linux_ld_preload_suspicious_flags(
        {"temp_path_library": True}
    )
    twice = _stamp_linux_ld_preload_suspicious_flags(once)
    assert once == twice


def test_linux_ld_preload_entries_suspicious_flags_schema_version_constant():
    assert LINUX_LD_PRELOAD_ENTRIES_SUSPICIOUS_FLAGS_SCHEMA_VERSION == 1


# ── firmware.persistence_walk_result (Phase κ.C.B) ────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical shape — dict with arbitrary sub-keys.
        (
            {
                "schema_version": 1,
                "bash_history_files_scanned": 2,
                "cron_lines_persisted": 5,
                "anomaly_total": 3,
            },
            {
                "schema_version": 1,
                "bash_history_files_scanned": 2,
                "cron_lines_persisted": 5,
                "anomaly_total": 3,
            },
        ),
        # Empty dict — preserved (no run yet but field exists).
        ({}, {}),
        # None preserved (semantic "no completed run").
        (None, None),
        # Wrong-types collapse to None.
        ([{"a": 1}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_persistence_walk_result(value, expected):
    assert _normalize_firmware_persistence_walk_result(value) == expected


def test_stamp_firmware_persistence_walk_result_adds_version():
    out = _stamp_firmware_persistence_walk_result(
        {"bash_history_files_scanned": 0}
    )
    assert (
        out["schema_version"]
        == FIRMWARE_PERSISTENCE_WALK_RESULT_SCHEMA_VERSION
    )


def test_stamp_firmware_persistence_walk_result_idempotent():
    once = _stamp_firmware_persistence_walk_result(
        {"bash_history_files_scanned": 0}
    )
    twice = _stamp_firmware_persistence_walk_result(once)
    assert once == twice


def test_firmware_persistence_walk_result_schema_version_constant():
    assert FIRMWARE_PERSISTENCE_WALK_RESULT_SCHEMA_VERSION == 1


# ── windows_dpapi_master_keys.anomaly_flags (Phase κ.D.A) ─────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "orphaned_masterkey": True,
                "admin_creator_sid": False,
                "large_masterkey": False,
                "parse_error": False,
            },
            {
                "schema_version": 1,
                "orphaned_masterkey": True,
                "admin_creator_sid": False,
                "large_masterkey": False,
                "parse_error": False,
            },
        ),
        ({}, {}),
        (None, {}),
        ([{"a": 1}], {}),
        ("not a dict", {}),
        (42, {}),
    ],
)
def test_normalize_windows_dpapi_anomaly_flags(value, expected):
    assert _normalize_windows_dpapi_anomaly_flags(value) == expected


def test_normalize_windows_dpapi_anomaly_flags_idempotent():
    canonical = {"schema_version": 1, "orphaned_masterkey": True}
    once = _normalize_windows_dpapi_anomaly_flags(canonical)
    twice = _normalize_windows_dpapi_anomaly_flags(once)
    assert once == twice == canonical


def test_stamp_windows_dpapi_anomaly_flags_adds_version():
    out = _stamp_windows_dpapi_anomaly_flags(
        {"orphaned_masterkey": True}
    )
    assert (
        out["schema_version"]
        == WINDOWS_DPAPI_MASTER_KEYS_ANOMALY_FLAGS_SCHEMA_VERSION
    )


def test_stamp_windows_dpapi_anomaly_flags_idempotent():
    once = _stamp_windows_dpapi_anomaly_flags(
        {"orphaned_masterkey": True}
    )
    twice = _stamp_windows_dpapi_anomaly_flags(once)
    assert once == twice


def test_windows_dpapi_master_keys_anomaly_flags_schema_version_constant():
    assert WINDOWS_DPAPI_MASTER_KEYS_ANOMALY_FLAGS_SCHEMA_VERSION == 1


# ── firmware.dpapi_walk_result (Phase κ.D.B) ──────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "files_scanned": 3,
                "files_persisted": 3,
                "anomaly_total": 1,
            },
            {
                "schema_version": 1,
                "files_scanned": 3,
                "files_persisted": 3,
                "anomaly_total": 1,
            },
        ),
        ({}, {}),
        (None, None),
        ([{"a": 1}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_dpapi_walk_result(value, expected):
    assert _normalize_firmware_dpapi_walk_result(value) == expected


def test_stamp_firmware_dpapi_walk_result_adds_version():
    out = _stamp_firmware_dpapi_walk_result({"files_scanned": 0})
    assert (
        out["schema_version"]
        == FIRMWARE_DPAPI_WALK_RESULT_SCHEMA_VERSION
    )


def test_stamp_firmware_dpapi_walk_result_idempotent():
    once = _stamp_firmware_dpapi_walk_result({"files_scanned": 0})
    twice = _stamp_firmware_dpapi_walk_result(once)
    assert once == twice


def test_firmware_dpapi_walk_result_schema_version_constant():
    assert FIRMWARE_DPAPI_WALK_RESULT_SCHEMA_VERSION == 1


# ── windows_usnjrnl_entries.reason_flags (Phase κ.E.A) ───────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical dict pass-through (already-stamped payload).
        (
            {
                "schema_version": 1,
                "file_create": True,
                "file_delete": False,
                "_raw": 0x00000100,
            },
            {
                "schema_version": 1,
                "file_create": True,
                "file_delete": False,
                "_raw": 0x00000100,
            },
        ),
        # Empty dict — preserved as "no decoded flags".
        ({}, {}),
        # None / wrong-typed values → empty dict (no signal).
        (None, {}),
        ([{"a": 1}], {}),
        ("not a dict", {}),
        (4.2, {}),
    ],
)
def test_normalize_windows_usnjrnl_reason_flags(value, expected):
    assert _normalize_windows_usnjrnl_reason_flags(value) == expected


def test_normalize_windows_usnjrnl_reason_flags_legacy_int_bitmask():
    """Legacy production shape — raw int bitmask decodes to canonical
    dict per Rule #35c boundary-normalisation discipline."""
    # USN_REASON_FILE_CREATE (0x100) | USN_REASON_FILE_DELETE (0x200)
    # | USN_REASON_CLOSE (0x80000000).
    raw = 0x00000100 | 0x00000200 | 0x80000000
    out = _normalize_windows_usnjrnl_reason_flags(raw)
    assert out["file_create"] is True
    assert out["file_delete"] is True
    assert out["close"] is True
    assert out["data_overwrite"] is False  # bit NOT set in our mask
    assert out["_raw"] == raw


def test_normalize_windows_usnjrnl_reason_flags_idempotent():
    canonical = {
        "schema_version": 1,
        "file_create": True,
        "_raw": 0x100,
    }
    once = _normalize_windows_usnjrnl_reason_flags(canonical)
    twice = _normalize_windows_usnjrnl_reason_flags(once)
    assert once == twice == canonical


def test_stamp_windows_usnjrnl_reason_flags_adds_version():
    out = _stamp_windows_usnjrnl_reason_flags({"file_create": True})
    assert (
        out["schema_version"]
        == WINDOWS_USNJRNL_ENTRIES_REASON_FLAGS_SCHEMA_VERSION
    )


def test_stamp_windows_usnjrnl_reason_flags_idempotent():
    once = _stamp_windows_usnjrnl_reason_flags({"file_create": True})
    twice = _stamp_windows_usnjrnl_reason_flags(once)
    assert once == twice


def test_windows_usnjrnl_entries_reason_flags_schema_version_constant():
    assert WINDOWS_USNJRNL_ENTRIES_REASON_FLAGS_SCHEMA_VERSION == 1


# ── firmware.usnjrnl_walk_result (Phase κ.E.B) ───────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "images_scanned": 1,
                "records_persisted": 42,
                "anomaly_total": 2,
            },
            {
                "schema_version": 1,
                "images_scanned": 1,
                "records_persisted": 42,
                "anomaly_total": 2,
            },
        ),
        ({}, {}),
        (None, None),
        ([{"a": 1}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_usnjrnl_walk_result(value, expected):
    assert _normalize_firmware_usnjrnl_walk_result(value) == expected


def test_stamp_firmware_usnjrnl_walk_result_adds_version():
    out = _stamp_firmware_usnjrnl_walk_result({"images_scanned": 0})
    assert (
        out["schema_version"]
        == FIRMWARE_USNJRNL_WALK_RESULT_SCHEMA_VERSION
    )


def test_stamp_firmware_usnjrnl_walk_result_idempotent():
    once = _stamp_firmware_usnjrnl_walk_result({"images_scanned": 0})
    twice = _stamp_firmware_usnjrnl_walk_result(once)
    assert once == twice


def test_firmware_usnjrnl_walk_result_schema_version_constant():
    assert FIRMWARE_USNJRNL_WALK_RESULT_SCHEMA_VERSION == 1


# ---------------------------------------------------------------------------
# firmware.bare_metal_audit_result (CLAUDE.md Rule #52 — schema-driven MCU/DSP)
# ---------------------------------------------------------------------------

from app.services.jsonb_normalizers import (  # noqa: E402
    BARE_METAL_DESCRIPTOR_PAYLOAD_SCHEMA_VERSION,
    FIRMWARE_BARE_METAL_AUDIT_RESULT_SCHEMA_VERSION,
    _normalize_bare_metal_descriptor_payload,
    _normalize_firmware_bare_metal_audit_result,
    _stamp_bare_metal_descriptor_payload,
    _stamp_firmware_bare_metal_audit_result,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "audited_at": "2026-05-19T15:00:00Z",
                "chip_match": {
                    "family_id": "ti/tms320f28066",
                    "domain_name": "c28x_core",
                    "confidence": 0.85,
                    "descriptor_source": "operator",
                    "evidence": [],
                },
                "blob_id": "78ad638b-f99b-4cb0-ac28-e36e05846007",
                "blob_size_bytes": 262144,
                "region_audits": [
                    {
                        "region_name": "csm_pwl",
                        "start": 0x3F7FF8,
                        "end": 0x3F7FFF,
                        "semantic": ["security_password_csm"],
                        "policies_evaluated": [
                            {
                                "operator": "unsecure_when_all_words_equal",
                                "value_hex": "FFFF",
                                "matched": True,
                                "cwe_ids": [1273, 1191],
                                "severity": "high",
                                "finding_source": "c28x_unsecure_csm",
                                "finding_id": None,
                            },
                        ],
                    },
                ],
                "skipped_regions": [],
                "findings_emitted_count": 1,
                "errors": [],
            },
            # Canonical shape passes through unchanged
            {
                "schema_version": 1,
                "audited_at": "2026-05-19T15:00:00Z",
                "chip_match": {
                    "family_id": "ti/tms320f28066",
                    "domain_name": "c28x_core",
                    "confidence": 0.85,
                    "descriptor_source": "operator",
                    "evidence": [],
                },
                "blob_id": "78ad638b-f99b-4cb0-ac28-e36e05846007",
                "blob_size_bytes": 262144,
                "region_audits": [
                    {
                        "region_name": "csm_pwl",
                        "start": 0x3F7FF8,
                        "end": 0x3F7FFF,
                        "semantic": ["security_password_csm"],
                        "policies_evaluated": [
                            {
                                "operator": "unsecure_when_all_words_equal",
                                "value_hex": "FFFF",
                                "matched": True,
                                "cwe_ids": [1273, 1191],
                                "severity": "high",
                                "finding_source": "c28x_unsecure_csm",
                                "finding_id": None,
                            },
                        ],
                    },
                ],
                "skipped_regions": [],
                "findings_emitted_count": 1,
                "errors": [],
            },
        ),
        ({}, {}),
        (None, None),
        ([{"a": 1}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_bare_metal_audit_result(value, expected):
    assert _normalize_firmware_bare_metal_audit_result(value) == expected


def test_stamp_firmware_bare_metal_audit_result_adds_version():
    out = _stamp_firmware_bare_metal_audit_result({"findings_emitted_count": 0})
    assert out["schema_version"] == FIRMWARE_BARE_METAL_AUDIT_RESULT_SCHEMA_VERSION


def test_stamp_firmware_bare_metal_audit_result_idempotent():
    once = _stamp_firmware_bare_metal_audit_result({"findings_emitted_count": 0})
    twice = _stamp_firmware_bare_metal_audit_result(once)
    assert once == twice


def test_firmware_bare_metal_audit_result_schema_version_constant():
    assert FIRMWARE_BARE_METAL_AUDIT_RESULT_SCHEMA_VERSION == 1


# ---------------------------------------------------------------------------
# bare_metal_descriptors.payload (external-ingestor protocol)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "firmware_id": "78ad638b-f99b-4cb0-ac28-e36e05846007",
                "descriptor_source": "operator",
                "chip_family_hint": "ti/tms320f28066",
                "domain_hint": "c28x_core",
            },
            {
                "schema_version": 1,
                "firmware_id": "78ad638b-f99b-4cb0-ac28-e36e05846007",
                "descriptor_source": "operator",
                "chip_family_hint": "ti/tms320f28066",
                "domain_hint": "c28x_core",
            },
        ),
        ({}, {}),
        (None, {}),
        ("not a dict", {}),
        ([1, 2, 3], {}),
        (42, {}),
    ],
)
def test_normalize_bare_metal_descriptor_payload(value, expected):
    assert _normalize_bare_metal_descriptor_payload(value) == expected


def test_stamp_bare_metal_descriptor_payload_adds_version():
    out = _stamp_bare_metal_descriptor_payload(
        {"firmware_id": "78ad638b-f99b-4cb0-ac28-e36e05846007"}
    )
    assert out["schema_version"] == BARE_METAL_DESCRIPTOR_PAYLOAD_SCHEMA_VERSION


def test_stamp_bare_metal_descriptor_payload_idempotent():
    once = _stamp_bare_metal_descriptor_payload(
        {"firmware_id": "78ad638b-f99b-4cb0-ac28-e36e05846007"}
    )
    twice = _stamp_bare_metal_descriptor_payload(once)
    assert once == twice


def test_bare_metal_descriptor_payload_schema_version_constant():
    assert BARE_METAL_DESCRIPTOR_PAYLOAD_SCHEMA_VERSION == 1


# ---------------------------------------------------------------------------
# firmware.ics_protocol_walk_result (CLAUDE.md Rule #52 instance #3 —
# Session 2 ICS protocol catalog walker, 2026-05-22)
# ---------------------------------------------------------------------------


from app.services.jsonb_normalizers import (  # noqa: E402
    FIRMWARE_ICS_PROTOCOL_WALK_RESULT_SCHEMA_VERSION,
    _normalize_firmware_ics_protocol_walk_result,
    _stamp_firmware_ics_protocol_walk_result,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {
                "schema_version": 1,
                "provenance": "walker",
                "walked_at": "2026-05-22T09:00:00+00:00",
                "snapshot_id_at_entry": "snap-abc123",
                "snapshot_id_at_exit": "snap-abc123",
                "consistency_warning": None,
                "binaries_scanned_count": 5,
                "binaries_total_count": 5,
                "per_binary": [
                    {
                        "blob_path": "/bin/modbus_server",
                        "blob_size": 102400,
                        "matches": [
                            {
                                "manifest_id": "modbus_tcp",
                                "protocol_family": "modbus_tcp",
                                "confidence": "high",
                            }
                        ],
                    }
                ],
                "protocol_family_counts": {"modbus_tcp": 1},
                "manifest_ids_seen": ["modbus_tcp"],
                "manifest_sources_seen": ["_system"],
                "errors": [],
            },
            {
                "schema_version": 1,
                "provenance": "walker",
                "walked_at": "2026-05-22T09:00:00+00:00",
                "snapshot_id_at_entry": "snap-abc123",
                "snapshot_id_at_exit": "snap-abc123",
                "consistency_warning": None,
                "binaries_scanned_count": 5,
                "binaries_total_count": 5,
                "per_binary": [
                    {
                        "blob_path": "/bin/modbus_server",
                        "blob_size": 102400,
                        "matches": [
                            {
                                "manifest_id": "modbus_tcp",
                                "protocol_family": "modbus_tcp",
                                "confidence": "high",
                            }
                        ],
                    }
                ],
                "protocol_family_counts": {"modbus_tcp": 1},
                "manifest_ids_seen": ["modbus_tcp"],
                "manifest_sources_seen": ["_system"],
                "errors": [],
            },
        ),
        ({}, {}),
        (None, None),
        ([{"a": 1}], None),
        ("not a dict", None),
        (42, None),
    ],
)
def test_normalize_firmware_ics_protocol_walk_result(value, expected):
    assert _normalize_firmware_ics_protocol_walk_result(value) == expected


def test_stamp_firmware_ics_protocol_walk_result_adds_version():
    out = _stamp_firmware_ics_protocol_walk_result({"binaries_scanned_count": 0})
    assert out["schema_version"] == FIRMWARE_ICS_PROTOCOL_WALK_RESULT_SCHEMA_VERSION


def test_stamp_firmware_ics_protocol_walk_result_idempotent():
    once = _stamp_firmware_ics_protocol_walk_result({"binaries_scanned_count": 0})
    twice = _stamp_firmware_ics_protocol_walk_result(once)
    assert once == twice


def test_firmware_ics_protocol_walk_result_schema_version_constant():
    assert FIRMWARE_ICS_PROTOCOL_WALK_RESULT_SCHEMA_VERSION == 1


# ── W2-β §SC5-NEW-ICS-S2-1 sister-provenance gate META-CANARY (Rule #46) ────
#
# The ``_stamp_*`` helper MUST stamp ``provenance: "walker"`` onto every
# walker-side commit so downstream CVE matcher consumers can distinguish a
# walker-authored result from a pre-seed via descriptor route. Without this
# gate, a future operator-supplied descriptor route could write
# ``ics_protocol_walk_result = {"protocol_family_counts": {"s7comm": 1}}``
# pre-walker, and the CVE matcher's downstream consumer would apply Siemens
# CVEs to a non-Siemens firmware (false attribution at CRITICAL severity per
# Wave-1 C §SC5-NEW-ICS-S2-1).


def test_stamp_firmware_ics_protocol_walk_result_enforces_provenance_walker():
    """Every walker-side stamp emits ``provenance: "walker"``. Asserts the
    sister-key is present (W2-β §SC5-NEW-ICS-S2-1 gate fires)."""
    out = _stamp_firmware_ics_protocol_walk_result({"binaries_scanned_count": 0})
    assert out["provenance"] == "walker", (
        "_stamp_firmware_ics_protocol_walk_result MUST stamp "
        "provenance='walker' — W2-β §SC5-NEW-ICS-S2-1 sister-key gate."
    )


def test_stamp_firmware_ics_protocol_walk_result_overwrites_hostile_provenance():
    """Gate-canary (Rule #46): a hostile pre-seed declaring
    ``provenance: "descriptor"`` MUST be overwritten by the stamp helper.
    Without this overwrite, the descriptor route could bypass the
    sister-provenance check at downstream CVE matcher consumers."""
    hostile_pre_seed = {
        "binaries_scanned_count": 0,
        "provenance": "descriptor",  # pretending to be operator-tier
        "protocol_family_counts": {"s7comm": 99},  # over-attributed
    }
    out = _stamp_firmware_ics_protocol_walk_result(hostile_pre_seed)
    assert out["provenance"] == "walker", (
        "Stamp helper MUST overwrite hostile provenance — W2-β "
        "§SC5-NEW-ICS-S2-1 mitigation. A descriptor route MUST NOT be able "
        "to claim walker provenance via JSONB pre-seed."
    )
