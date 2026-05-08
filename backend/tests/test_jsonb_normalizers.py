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
    EMULATION_PRESETS_PORT_FORWARDS_SCHEMA_VERSION,
    EMULATION_SESSIONS_DISCOVERED_SERVICES_SCHEMA_VERSION,
    EMULATION_SESSIONS_PORT_FORWARDS_SCHEMA_VERSION,
    FIRMWARE_AUTHENTICODE_CHAIN_RESULT_SCHEMA_VERSION,
    FIRMWARE_BINARY_INFO_SCHEMA_VERSION,
    FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION,
    FIRMWARE_WINDOWS_ARTIFACTS_SCHEMA_VERSION,
    WINDOWS_PE_SIGNATURES_ARCH_VIEW_SCHEMA_VERSION,
    WINDOWS_PE_SIGNATURES_RICH_HEADER_JSON_SCHEMA_VERSION,
    FUZZING_CAMPAIGNS_CONFIG_SCHEMA_VERSION,
    FUZZING_CAMPAIGNS_STATS_SCHEMA_VERSION,
    CRA_REQUIREMENT_RESULTS_FINDING_IDS_SCHEMA_VERSION,
    CRA_REQUIREMENT_RESULTS_RELATED_CVES_SCHEMA_VERSION,
    CRA_REQUIREMENT_RESULTS_RELATED_CWES_SCHEMA_VERSION,
    CRA_REQUIREMENT_RESULTS_TOOL_SOURCES_SCHEMA_VERSION,
    HARDWARE_FIRMWARE_BLOBS_METADATA_SCHEMA_VERSION,
    SBOM_COMPONENTS_METADATA_SCHEMA_VERSION,
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
    _normalize_firmware_authenticode_chain_result,
    _normalize_firmware_binary_info,
    _normalize_firmware_cve_match_result,
    _normalize_firmware_device_metadata,
    _normalize_firmware_windows_artifacts,
    _normalize_fuzzing_campaigns_config,
    _normalize_fuzzing_campaigns_stats,
    _normalize_hardware_firmware_blobs_metadata,
    _normalize_sbom_components_metadata,
    _stamp_analysis_cache_result,
    _stamp_attack_surface_entries_score_breakdown,
    _normalize_windows_pe_signatures_arch_view,
    _normalize_windows_pe_signatures_rich_header_json,
    _stamp_firmware_authenticode_chain_result,
    _stamp_firmware_binary_info,
    _stamp_firmware_device_metadata,
    _stamp_firmware_windows_artifacts,
    _stamp_fuzzing_campaigns_config,
    _stamp_fuzzing_campaigns_stats,
    _stamp_hardware_firmware_blobs_metadata,
    _stamp_windows_pe_signatures_arch_view,
    _stamp_windows_pe_signatures_rich_header_json,
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
