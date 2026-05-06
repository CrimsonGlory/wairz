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
    CONVERSATIONS_MESSAGES_SCHEMA_VERSION,
    EMULATION_SESSIONS_PORT_FORWARDS_SCHEMA_VERSION,
    FIRMWARE_BINARY_INFO_SCHEMA_VERSION,
    FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION,
    FUZZING_CAMPAIGNS_CONFIG_SCHEMA_VERSION,
    FUZZING_CAMPAIGNS_STATS_SCHEMA_VERSION,
    _normalize_analysis_cache_result,
    _normalize_conversations_messages,
    _normalize_emulation_sessions_port_forwards,
    _normalize_firmware_binary_info,
    _normalize_firmware_cve_match_result,
    _normalize_firmware_device_metadata,
    _normalize_fuzzing_campaigns_config,
    _normalize_fuzzing_campaigns_stats,
    _stamp_analysis_cache_result,
    _stamp_firmware_binary_info,
    _stamp_firmware_device_metadata,
    _stamp_fuzzing_campaigns_config,
    _stamp_fuzzing_campaigns_stats,
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
