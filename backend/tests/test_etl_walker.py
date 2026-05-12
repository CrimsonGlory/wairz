"""Tests for the Phase ι.C.C Windows ETW .etl trace-log walker triplet.

Rule #35b live canary — exercises the inner orchestrator
(``_do_etl_walk``) against a real test DB via ``make_live_db()`` for
the "no etl files present" path AND a synthetic on-disk tree path
that mocks the dissect.etl parser to feed deterministic event records
into the row builder.

Covers:
- GUID normalisation (normalize_provider_guid).
- FILETIME conversion (datetime_to_filetime).
- Payload preview encoding (encode_payload_preview).
- Event-value serialisation (serialise_event_values).
- Provider classification — known Microsoft / unusual / non-Microsoft
  in Diagtrack / kernel process / provider-disable event.
- Anomaly flag builder (build_anomaly_flags).
- Filesystem walker (walk_etl_files) — discovers .etl files under
  canonical ETW dirs.
- Inner orchestrator end-to-end via Rule #35b live canary — no ETL
  files present + with-files mocked dissect.etl parser.
- Rule #36 no-execute test gate — the source file does not invoke
  any spawn primitive.
"""
from __future__ import annotations

import base64
import datetime as _dt
import pathlib
import re
import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsEtlEvent
from app.services.etl_walker import (
    _do_etl_walk,
    _walk_one_file_sync,
    build_anomaly_flags,
    datetime_to_filetime,
    encode_payload_preview,
    is_kernel_process_event,
    is_known_microsoft_provider,
    is_non_microsoft_in_diagtrack,
    is_provider_disable_event,
    is_unusual_provider,
    normalize_provider_guid,
    serialise_event_values,
    walk_etl_files,
)
from tests._live_db import make_live_db


# ── normalize_provider_guid ───────────────────────────────────────────────────


def test_normalize_provider_guid_canonical_lowercase():
    guid = uuid.UUID("9E814AAD-3204-11D2-9A82-006008A86939")
    assert (
        normalize_provider_guid(guid)
        == "9e814aad-3204-11d2-9a82-006008a86939"
    )


def test_normalize_provider_guid_string_with_braces():
    assert (
        normalize_provider_guid("{9e814aad-3204-11d2-9a82-006008a86939}")
        == "9e814aad-3204-11d2-9a82-006008a86939"
    )


def test_normalize_provider_guid_string_no_hyphens():
    assert (
        normalize_provider_guid("9e814aad320411d29a82006008a86939")
        == "9e814aad-3204-11d2-9a82-006008a86939"
    )


def test_normalize_provider_guid_bytes_le():
    raw = uuid.UUID("9e814aad-3204-11d2-9a82-006008a86939").bytes
    assert (
        normalize_provider_guid(raw)
        == "9e814aad-3204-11d2-9a82-006008a86939"
    )


def test_normalize_provider_guid_none():
    assert normalize_provider_guid(None) is None


def test_normalize_provider_guid_invalid_string():
    assert normalize_provider_guid("not-a-guid") is None


def test_normalize_provider_guid_empty_string():
    assert normalize_provider_guid("") is None


def test_normalize_provider_guid_bad_byte_length():
    assert normalize_provider_guid(b"\x00\x01") is None


# ── datetime_to_filetime ──────────────────────────────────────────────────────


def test_datetime_to_filetime_unix_epoch_boundary():
    """1970-01-01 00:00:00 UTC is FILETIME 116444736000000000."""
    dt = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
    assert datetime_to_filetime(dt) == 116444736000000000


def test_datetime_to_filetime_naive_treated_as_utc():
    dt = _dt.datetime(1970, 1, 1)
    assert datetime_to_filetime(dt) == 116444736000000000


def test_datetime_to_filetime_filetime_zero_is_1601():
    """The FILETIME zero epoch (1601-01-01) → 0."""
    dt = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
    assert datetime_to_filetime(dt) == 0


def test_datetime_to_filetime_none_returns_zero():
    assert datetime_to_filetime(None) == 0


def test_datetime_to_filetime_invalid_returns_zero():
    assert datetime_to_filetime("not a datetime") == 0


# ── encode_payload_preview ────────────────────────────────────────────────────


def test_encode_payload_preview_small():
    out = encode_payload_preview(b"hello")
    assert out["raw_size"] == 5
    assert base64.b64decode(out["raw_b64"]) == b"hello"


def test_encode_payload_preview_truncates_oversize():
    big = b"A" * 5000
    out = encode_payload_preview(big)
    assert out["raw_size"] == 5000
    decoded = base64.b64decode(out["raw_b64"])
    assert len(decoded) <= 1024  # truncated to _MAX_PAYLOAD_PREVIEW_BYTES


def test_encode_payload_preview_empty():
    out = encode_payload_preview(b"")
    assert out["raw_size"] == 0
    assert out["raw_b64"] == ""


# ── serialise_event_values ────────────────────────────────────────────────────


def test_serialise_event_values_primitives_pass_through():
    out = serialise_event_values({"ProcessId": 1234, "Name": "svchost.exe"})
    assert out == {"ProcessId": 1234, "Name": "svchost.exe"}


def test_serialise_event_values_uuid_to_lower_str():
    g = uuid.UUID("9E814AAD-3204-11D2-9A82-006008A86939")
    out = serialise_event_values({"ProviderId": g})
    assert out == {"ProviderId": "9e814aad-3204-11d2-9a82-006008a86939"}


def test_serialise_event_values_bytes_to_b64_preview():
    out = serialise_event_values({"Blob": b"\x00\x01\x02hello"})
    assert "_bytes_b64" in out["Blob"]
    assert out["Blob"]["_bytes_size"] == len(b"\x00\x01\x02hello")


def test_serialise_event_values_datetime_iso():
    dt = _dt.datetime(2024, 1, 1, 12, 0, tzinfo=_dt.timezone.utc)
    out = serialise_event_values({"Timestamp": dt})
    assert out["Timestamp"].startswith("2024-01-01T12:00:00")


def test_serialise_event_values_unknown_to_str_truncated():
    class Custom:
        def __str__(self):
            return "X" * 5000

    out = serialise_event_values({"Field": Custom()})
    assert len(out["Field"]) <= 1100
    assert out["Field"].endswith("...[truncated]")


def test_serialise_event_values_none_returns_empty():
    assert serialise_event_values(None) == {}


def test_serialise_event_values_non_dict_returns_empty():
    assert serialise_event_values("not a dict") == {}


# ── is_known_microsoft_provider ───────────────────────────────────────────────


def test_is_known_microsoft_provider_known_guid_match():
    # NT Kernel Logger.
    assert (
        is_known_microsoft_provider(
            "9e814aad-3204-11d2-9a82-006008a86939", None
        )
        is True
    )


def test_is_known_microsoft_provider_microsoft_prefix_name():
    assert (
        is_known_microsoft_provider(
            None, "Microsoft-Windows-Kernel-Process"
        )
        is True
    )


def test_is_known_microsoft_provider_unknown():
    assert (
        is_known_microsoft_provider(
            "12345678-1234-1234-1234-123456789abc",
            "ThirdPartyProvider",
        )
        is False
    )


def test_is_known_microsoft_provider_null_both():
    assert is_known_microsoft_provider(None, None) is False


# ── is_unusual_provider ───────────────────────────────────────────────────────


def test_is_unusual_provider_known_microsoft_is_not_unusual():
    assert (
        is_unusual_provider(
            "9e814aad-3204-11d2-9a82-006008a86939",
            "NT Kernel Logger",
        )
        is False
    )


def test_is_unusual_provider_microsoft_prefix_is_not_unusual():
    assert (
        is_unusual_provider(None, "Microsoft-Windows-Kernel-File")
        is False
    )


def test_is_unusual_provider_third_party_is_unusual():
    assert (
        is_unusual_provider(
            "12345678-1234-1234-1234-123456789abc",
            "ThirdPartyProvider",
        )
        is True
    )


def test_is_unusual_provider_null_both_is_not_unusual():
    """Null guid + null name → we can't judge; treat as not unusual."""
    assert is_unusual_provider(None, None) is False


# ── is_non_microsoft_in_diagtrack ─────────────────────────────────────────────


def test_is_non_microsoft_in_diagtrack_third_party_in_diagtrack():
    assert (
        is_non_microsoft_in_diagtrack(
            "AutoLogger-Diagtrack-Listener",
            "12345678-1234-1234-1234-123456789abc",
            "ThirdPartyProvider",
        )
        is True
    )


def test_is_non_microsoft_in_diagtrack_microsoft_in_diagtrack():
    assert (
        is_non_microsoft_in_diagtrack(
            "AutoLogger-Diagtrack-Listener",
            "9e814aad-3204-11d2-9a82-006008a86939",
            "NT Kernel Logger",
        )
        is False
    )


def test_is_non_microsoft_in_diagtrack_third_party_in_other_session():
    """Third-party provider in a non-Diagtrack session — not flagged."""
    assert (
        is_non_microsoft_in_diagtrack(
            "Eventlog-Security",
            "12345678-1234-1234-1234-123456789abc",
            "ThirdPartyProvider",
        )
        is False
    )


def test_is_non_microsoft_in_diagtrack_null_session():
    assert (
        is_non_microsoft_in_diagtrack(
            None, "12345678-1234-1234-1234-123456789abc", "X"
        )
        is False
    )


# ── is_kernel_process_event ───────────────────────────────────────────────────


def test_is_kernel_process_event_nt_kernel_logger_guid():
    assert (
        is_kernel_process_event(
            "9e814aad-3204-11d2-9a82-006008a86939", None
        )
        is True
    )


def test_is_kernel_process_event_kernel_process_guid():
    assert (
        is_kernel_process_event(
            "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716", None
        )
        is True
    )


def test_is_kernel_process_event_name_match():
    assert (
        is_kernel_process_event(None, "Microsoft-Windows-Kernel-Process")
        is True
    )


def test_is_kernel_process_event_not_kernel():
    assert (
        is_kernel_process_event(
            "12345678-1234-1234-1234-123456789abc",
            "Microsoft-Windows-Diagtrack",
        )
        is False
    )


def test_is_kernel_process_event_null_both():
    assert is_kernel_process_event(None, None) is False


# ── is_provider_disable_event ─────────────────────────────────────────────────


def test_is_provider_disable_event_opcode_02_with_logger_marker():
    assert (
        is_provider_disable_event(
            0x02, "Microsoft-Windows-Trace-Control"
        )
        is True
    )


def test_is_provider_disable_event_opcode_06_with_eventlog_marker():
    assert (
        is_provider_disable_event(0x06, "Microsoft-EventLog-Service")
        is True
    )


def test_is_provider_disable_event_opcode_02_unrelated_provider():
    """Opcode 0x02 fires for many event types — only flag with marker."""
    assert (
        is_provider_disable_event(0x02, "Microsoft-Windows-Kernel-Process")
        is False
    )


def test_is_provider_disable_event_other_opcode():
    assert (
        is_provider_disable_event(0x01, "Microsoft-EventLog-Service")
        is False
    )


def test_is_provider_disable_event_null_opcode():
    assert is_provider_disable_event(None, "X") is False


# ── build_anomaly_flags ───────────────────────────────────────────────────────


def test_build_anomaly_flags_all_false_for_microsoft_event():
    flags = build_anomaly_flags(
        session_name="Eventlog-Security",
        provider_guid="9e814aad-3204-11d2-9a82-006008a86939",
        provider_name="NT Kernel Logger",
        event_opcode=0x01,
        is_kernel_process=True,
        evtx_clear_correlated=False,
    )
    assert flags == {
        "kernel_proc_after_evtx_clear": False,
        "provider_disable_evidence": False,
        "unusual_provider": False,
        "non_microsoft_in_diagtrack": False,
    }


def test_build_anomaly_flags_kernel_after_clear():
    flags = build_anomaly_flags(
        session_name="AutoLogger-Diagtrack-Listener",
        provider_guid="9e814aad-3204-11d2-9a82-006008a86939",
        provider_name="NT Kernel Logger",
        event_opcode=0x01,
        is_kernel_process=True,
        evtx_clear_correlated=True,
    )
    assert flags["kernel_proc_after_evtx_clear"] is True


def test_build_anomaly_flags_third_party_in_diagtrack():
    flags = build_anomaly_flags(
        session_name="AutoLogger-Diagtrack-Listener",
        provider_guid="12345678-1234-1234-1234-123456789abc",
        provider_name="ThirdPartyProvider",
        event_opcode=0x01,
        is_kernel_process=False,
        evtx_clear_correlated=False,
    )
    assert flags["non_microsoft_in_diagtrack"] is True
    assert flags["unusual_provider"] is True


def test_build_anomaly_flags_provider_disable():
    flags = build_anomaly_flags(
        session_name="Eventlog-Security",
        provider_guid="abcdef00-0000-0000-0000-000000000001",
        provider_name="Microsoft-EventLog-Service",
        event_opcode=0x02,
        is_kernel_process=False,
        evtx_clear_correlated=False,
    )
    assert flags["provider_disable_evidence"] is True


# ── walk_etl_files ────────────────────────────────────────────────────────────


def test_walk_etl_files_discovers_canonical_dir(tmp_path):
    # Create a .etl in Windows/System32/WDI/LogFiles/
    canonical = (
        tmp_path / "Windows" / "System32" / "WDI" / "LogFiles"
    )
    canonical.mkdir(parents=True)
    target = canonical / "BootCKCL.etl"
    target.write_bytes(b"\x00" * 64)
    found = walk_etl_files([str(tmp_path)])
    assert len(found) == 1
    assert found[0].endswith("BootCKCL.etl")


def test_walk_etl_files_discovers_winevt_logs(tmp_path):
    canonical = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
    canonical.mkdir(parents=True)
    target = canonical / "Microsoft-Windows-Diagnostics-PCW%4Operational.etl"
    target.write_bytes(b"\x00" * 64)
    found = walk_etl_files([str(tmp_path)])
    assert any("PCW" in p for p in found)


def test_walk_etl_files_discovers_fallback_etl(tmp_path):
    """Files outside the canonical dirs are still found via defensive
    fallback scan."""
    odd_dir = tmp_path / "vendor_logs"
    odd_dir.mkdir()
    target = odd_dir / "custom.etl"
    target.write_bytes(b"\x00" * 64)
    found = walk_etl_files([str(tmp_path)])
    assert any("custom.etl" in p for p in found)


def test_walk_etl_files_deduplicates(tmp_path):
    """If a .etl is in a canonical dir, it isn't double-listed by the
    fallback scan."""
    canonical = (
        tmp_path / "Windows" / "System32" / "WDI" / "LogFiles"
    )
    canonical.mkdir(parents=True)
    target = canonical / "BootCKCL.etl"
    target.write_bytes(b"\x00" * 64)
    found = walk_etl_files([str(tmp_path)])
    assert len(found) == 1


def test_walk_etl_files_ignores_non_etl(tmp_path):
    canonical = (
        tmp_path / "Windows" / "System32" / "WDI" / "LogFiles"
    )
    canonical.mkdir(parents=True)
    (canonical / "BootCKCL.evtx").write_bytes(b"\x00" * 64)
    (canonical / "BootCKCL.log").write_bytes(b"\x00" * 64)
    found = walk_etl_files([str(tmp_path)])
    assert found == []


def test_walk_etl_files_missing_root_skipped(tmp_path):
    """Non-existent root directories don't raise."""
    found = walk_etl_files([str(tmp_path / "nonexistent")])
    assert found == []


def test_walk_etl_files_case_insensitive(tmp_path):
    canonical = (
        tmp_path / "Windows" / "System32" / "WDI" / "LogFiles"
    )
    canonical.mkdir(parents=True)
    (canonical / "FOO.ETL").write_bytes(b"\x00" * 64)
    found = walk_etl_files([str(tmp_path)])
    assert any("FOO.ETL" in p for p in found)


# ── Mock-based per-file walker test ───────────────────────────────────────────
#
# Synthesizing a real ETL binary that dissect.etl will parse end-to-end
# is impractical (XPRESS-compressed buffers + variable struct types +
# manifest catalog). We monkey-patch parse_etl_file_sync to return a
# fixture event list and verify _walk_one_file_sync builds rows correctly.


def test_walk_one_file_sync_builds_rows_from_synthetic_events(tmp_path):
    """Mock parse_etl_file_sync to return fixture events; verify
    _walk_one_file_sync constructs proper WindowsEtlEvent rows."""

    fixture_events = [
        {
            "etl_file_path": "/dummy",
            "provider_guid": "9e814aad-3204-11d2-9a82-006008a86939",
            "provider_name": "NT Kernel Logger",
            "event_id": 1,
            "event_version": 0,
            "event_channel": None,
            "event_level": 4,
            "event_opcode": 1,
            "event_keywords": 0,
            "event_task": 0,
            "timestamp_ft": 132000000000000000,
            "process_id": 1234,
            "thread_id": 5678,
            "processor_id": None,
            "kernel_time_us": None,
            "user_time_us": None,
            "payload": {"ProcessId": 1234, "ImageName": "svchost.exe"},
            "raw_record_size": 128,
        },
        {
            "etl_file_path": "/dummy",
            "provider_guid": "12345678-1234-1234-1234-123456789abc",
            "provider_name": "ThirdPartyEvil",
            "event_id": 99,
            "event_version": 0,
            "event_channel": None,
            "event_level": 4,
            "event_opcode": 1,
            "event_keywords": 0,
            "event_task": 0,
            "timestamp_ft": 132000000000000001,
            "process_id": 4321,
            "thread_id": 8765,
            "processor_id": None,
            "kernel_time_us": None,
            "user_time_us": None,
            "payload": {"raw_b64": "AABB==", "raw_size": 4},
            "raw_record_size": 64,
        },
    ]

    metadata = {
        "session_name": "AutoLogger-Diagtrack-Listener",
        "events_walked": 2,
        "size_bytes": 1024,
    }

    fake_etl = tmp_path / "fake.etl"
    fake_etl.write_bytes(b"\x00" * 64)

    with patch(
        "app.services.etl_walker.parse_etl_file_sync",
        return_value=(metadata, fixture_events),
    ):
        firmware_id = uuid.uuid4()
        rows, agg = _walk_one_file_sync(
            str(fake_etl),
            firmware_id=firmware_id,
            relative_source="Windows/System32/WDI/LogFiles/fake.etl",
            max_events=100,
            persisted_so_far=0,
            evtx_clear_correlated=True,
        )

    assert len(rows) == 2
    assert agg["events_walked"] == 2
    assert agg["events_persisted"] == 2
    assert agg["session_name"] == "AutoLogger-Diagtrack-Listener"

    # First row — kernel logger event with evtx_clear correlated.
    assert rows[0].provider_guid == "9e814aad-3204-11d2-9a82-006008a86939"
    assert rows[0].process_id == 1234
    assert rows[0].thread_id == 5678
    assert rows[0].payload["schema_version"] == 1
    assert rows[0].payload["ProcessId"] == 1234
    assert rows[0].anomaly_flags["schema_version"] == 1
    assert rows[0].anomaly_flags["kernel_proc_after_evtx_clear"] is True

    # Second row — third-party in Diagtrack.
    assert rows[1].provider_name == "ThirdPartyEvil"
    assert rows[1].anomaly_flags["unusual_provider"] is True
    assert rows[1].anomaly_flags["non_microsoft_in_diagtrack"] is True

    # Aggregate counts.
    assert agg["kernel_proc_after_evtx_clear_count"] >= 1
    assert agg["unusual_provider_count"] >= 1
    assert agg["non_microsoft_in_diagtrack_count"] >= 1
    assert agg["anomaly_total"] >= 2


def test_walk_one_file_sync_respects_cap(tmp_path):
    """events_capped increments when persist_budget is exhausted."""
    fixture_events = [
        {
            "etl_file_path": "/dummy",
            "provider_guid": "9e814aad-3204-11d2-9a82-006008a86939",
            "provider_name": "NT Kernel Logger",
            "event_id": i,
            "event_version": 0,
            "event_channel": None,
            "event_level": 4,
            "event_opcode": 1,
            "event_keywords": 0,
            "event_task": 0,
            "timestamp_ft": 132000000000000000 + i,
            "process_id": 1000 + i,
            "thread_id": 2000 + i,
            "processor_id": None,
            "kernel_time_us": None,
            "user_time_us": None,
            "payload": {},
            "raw_record_size": 64,
        }
        for i in range(10)
    ]
    metadata = {
        "session_name": "Eventlog-Security",
        "events_walked": 10,
        "size_bytes": 640,
    }

    fake_etl = tmp_path / "fake.etl"
    fake_etl.write_bytes(b"\x00" * 64)

    with patch(
        "app.services.etl_walker.parse_etl_file_sync",
        return_value=(metadata, fixture_events),
    ):
        firmware_id = uuid.uuid4()
        rows, agg = _walk_one_file_sync(
            str(fake_etl),
            firmware_id=firmware_id,
            relative_source="x.etl",
            max_events=3,  # cap at 3
            persisted_so_far=0,
            evtx_clear_correlated=False,
        )

    assert len(rows) == 3
    assert agg["events_walked"] == 10
    assert agg["events_persisted"] == 3
    assert agg["events_capped"] == 7


def test_walk_one_file_sync_error_metadata():
    """parse_etl_file_sync returns {'error': ...} → aggregate has
    status='error'."""
    with patch(
        "app.services.etl_walker.parse_etl_file_sync",
        return_value=({"error": "malformed header"}, []),
    ):
        firmware_id = uuid.uuid4()
        rows, agg = _walk_one_file_sync(
            "/dev/null",
            firmware_id=firmware_id,
            relative_source="x.etl",
            max_events=100,
            persisted_so_far=0,
            evtx_clear_correlated=False,
        )
    assert rows == []
    assert agg["status"] == "error"
    assert agg["error"] == "malformed header"


def test_walk_one_file_sync_oversize_metadata():
    """parse_etl_file_sync returns {'oversize': True} → status=
    'skipped_oversize'."""
    with patch(
        "app.services.etl_walker.parse_etl_file_sync",
        return_value=(
            {"error": "too big", "oversize": True},
            [],
        ),
    ):
        firmware_id = uuid.uuid4()
        rows, agg = _walk_one_file_sync(
            "/dev/null",
            firmware_id=firmware_id,
            relative_source="x.etl",
            max_events=100,
            persisted_so_far=0,
            evtx_clear_correlated=False,
        )
    assert rows == []
    assert agg["status"] == "skipped_oversize"


# ── Rule #35b live canaries — end-to-end against real ORM/DB ──────────────────


@pytest.mark.asyncio
async def test_do_etl_walk_no_files_returns_empty(tmp_path):
    """No ETL files under detection roots → empty aggregate, no rows."""
    async with make_live_db() as db:
        project = Project(name="test-iota-c", description="ι.C.C live canary empty")
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="empty.bin",
            storage_path="/tmp/empty",
            file_size=0,
            sha256="0" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.flush()

        result = await _do_etl_walk(db, firmware.id)
        assert result["files_scanned"] == 0
        assert result["events_walked"] == 0
        assert result["events_persisted"] == 0
        assert result["anomaly_total"] == 0


@pytest.mark.asyncio
async def test_do_etl_walk_persists_events_with_mocked_parser(tmp_path):
    """Rule #35b live canary — full _do_etl_walk pipeline against an
    ORM-backed test session. Mocks the parser so we don't need a real
    ETL binary; verifies file discovery → row construction → DB
    persistence → aggregate accounting.
    """
    # Plant a .etl file the walker will discover.
    canonical = (
        tmp_path / "Windows" / "System32" / "WDI" / "LogFiles"
    )
    canonical.mkdir(parents=True)
    target = canonical / "BootCKCL.etl"
    target.write_bytes(b"\x00" * 128)

    # Synthetic event the mocked parser will return.
    fixture_events = [
        {
            "etl_file_path": str(target),
            "provider_guid": "9e814aad-3204-11d2-9a82-006008a86939",
            "provider_name": "NT Kernel Logger",
            "event_id": 1,
            "event_version": 0,
            "event_channel": None,
            "event_level": 4,
            "event_opcode": 1,
            "event_keywords": 0,
            "event_task": 0,
            "timestamp_ft": 132000000000000000,
            "process_id": 4444,
            "thread_id": 5555,
            "processor_id": None,
            "kernel_time_us": None,
            "user_time_us": None,
            "payload": {"ProcessId": 4444, "ImageName": "lsass.exe"},
            "raw_record_size": 128,
        },
    ]
    metadata = {
        "session_name": "AutoLogger-Diagtrack-Listener",
        "events_walked": 1,
        "size_bytes": 128,
    }

    async with make_live_db() as db:
        project = Project(name="t-etl", description="ι.C.C live canary")
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="win10.bin",
            storage_path="/tmp/x",
            file_size=128,
            sha256="0" * 64,
            extracted_path=str(tmp_path),
            # Simulate prior EVTX walk with a log_clear marker so the
            # kernel_proc_after_evtx_clear flag fires.
            evtx_walk_result={"log_clear_count": 1, "schema_version": 1},
        )
        db.add(firmware)
        await db.flush()

        with patch(
            "app.services.etl_walker.parse_etl_file_sync",
            return_value=(metadata, fixture_events),
        ):
            result = await _do_etl_walk(db, firmware.id)
            await db.commit()

    assert result["files_scanned"] == 1
    assert result["events_walked"] == 1
    assert result["events_persisted"] == 1
    assert result["kernel_proc_after_evtx_clear_count"] >= 1
    assert result["anomaly_total"] >= 1

    # Verify per-row persistence via a fresh session.
    async with make_live_db() as db2:
        project2 = Project(name="t2-etl", description="reuse fixtures")
        db2.add(project2)
        await db2.flush()

        firmware2 = Firmware(
            project_id=project2.id,
            original_filename="win10b.bin",
            storage_path="/tmp/y",
            file_size=128,
            sha256="1" * 64,
            extracted_path=str(tmp_path),
            evtx_walk_result={"log_clear_count": 1, "schema_version": 1},
        )
        db2.add(firmware2)
        await db2.flush()

        with patch(
            "app.services.etl_walker.parse_etl_file_sync",
            return_value=(metadata, fixture_events),
        ):
            await _do_etl_walk(db2, firmware2.id)
            await db2.commit()

        rows = (await db2.execute(
            select(WindowsEtlEvent).where(
                WindowsEtlEvent.firmware_id == firmware2.id,
            )
        )).scalars().all()
        assert len(rows) == 1
        evt = rows[0]
        assert evt.provider_guid == "9e814aad-3204-11d2-9a82-006008a86939"
        assert evt.process_id == 4444
        assert evt.thread_id == 5555
        assert evt.etl_session_name == "AutoLogger-Diagtrack-Listener"
        assert evt.payload["schema_version"] == 1
        assert evt.payload["ProcessId"] == 4444
        assert evt.anomaly_flags["schema_version"] == 1
        assert evt.anomaly_flags["kernel_proc_after_evtx_clear"] is True


# ── Rule #36 no-execute test gate ────────────────────────────────────────────


def test_etl_walker_no_execute():
    """Rule #36 — the etl_walker.py source MUST NOT invoke any spawn
    primitive against extracted artefacts. The walker is a pure-Python
    binary parser; nothing should execute the parsed data.
    """
    source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "etl_walker.py"
    ).read_text()
    forbidden_patterns = (
        r"subprocess\.(run|Popen|call|check_output|check_call)",
        r"asyncio\.create_subprocess_(exec|shell)",
        r"os\.(system|execvp|execve|spawnvp)",
        r"\brunpy\.run_path\b",
        r"\beval\s*\(",
        r"\bexec\s*\([\"\']",
    )
    for pattern in forbidden_patterns:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in etl_walker.py — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke spawn primitives against extracted artefacts."
        )
