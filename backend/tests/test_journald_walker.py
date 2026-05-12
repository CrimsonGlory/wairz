"""Tests for the Phase ι.A.C Linux systemd journald walker triplet.

Rule #35b live canary — exercises the inner orchestrator
(``_do_journald_walk``) against a real test DB via ``make_live_db()``
with a synthetically-constructed journald binary file.

Covers:
- Magic-byte detection (has_journal_magic).
- Header decode (_read_header).
- Object-header decode (_read_object_header).
- DATA payload extraction (_decode_data_payload).
- ENTRY decode + items[] resolution (_decode_entry).
- End-to-end parse_journal_file against a synthetic single-entry file.
- Anomaly classifier (priority_critical / oom_killer / segfault /
  selinux_denied / audit_failure / suspicious_unit / log_clear_marker).
- Detection-root walker (walk_journal_files) — discovers files under
  var/log/journal and skips non-.journal files.
- Inner orchestrator end-to-end via Rule #35b live canary —
  LinuxJournaldEntry rows persist with correct field mapping.
- Rule #36 no-execute test gate — the source file does not invoke
  any spawn primitive.
"""
from __future__ import annotations

import os
import pathlib
import re
import struct
import tempfile
import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, LinuxJournaldEntry, Project
from app.services.journald_walker import (
    JOURNAL_MAGIC,
    OBJECT_DATA,
    OBJECT_ENTRY,
    _decode_data_payload,
    _decode_entry,
    _do_journald_walk,
    _read_header,
    _read_object_header,
    build_anomaly_flags,
    has_journal_magic,
    parse_journal_file,
    walk_journal_files,
)
from tests._live_db import make_live_db

# ── Synthetic .journal file builder ──────────────────────────────────────────


def _build_minimal_journal(
    field_values: list[tuple[str, str]],
    *,
    machine_id: bytes | None = None,
    boot_id: bytes | None = None,
    realtime_us: int = 1_700_000_000_000_000,
    monotonic_us: int = 12_345_678,
    priority: int = 6,
    incompatible_flags: int = 0,
) -> bytes:
    """Build a minimal valid uncompressed, non-compact .journal file
    with ONE entry referencing the given list of DATA fields.

    Layout produced (offsets approximate):
    - 0..168 : header
    - 168..N : DATA objects (one per field)
    - N..M   : ENTRY object referencing all DATA offsets

    Returns the full file bytes. Uses the documented format so the
    walker's clean-room parser can consume it end-to-end.
    """
    if machine_id is None:
        machine_id = b"\x11" * 16
    if boot_id is None:
        boot_id = b"\x22" * 16

    OBJECT_ALIGN = 8

    def align_up(n: int) -> int:
        rem = n % OBJECT_ALIGN
        return n if rem == 0 else n + (OBJECT_ALIGN - rem)

    # Build DATA objects.
    HEADER_SIZE = 160
    cursor = HEADER_SIZE
    data_offsets: list[int] = []
    data_blobs: list[bytes] = []

    for field_name, field_value in field_values:
        # payload = "FIELD=value" UTF-8.
        payload = f"{field_name}={field_value}".encode()
        # DATA object regular layout: 16 hdr + 56 body + payload.
        body_size = 64 + len(payload)
        aligned_size = align_up(body_size)
        # Construct:
        # ObjectHeader: type=1, flags=0, reserved=0, size=body_size
        hdr = struct.pack("<BB6sQ", OBJECT_DATA, 0, b"\x00" * 6, body_size)
        # hash + next_hash_offset + next_field_offset + entry_offset +
        # entry_array_offset + n_entries (all zeroed for simplicity)
        body = struct.pack("<6Q", 0, 0, 0, 0, 0, 0)
        # Pad payload to alignment.
        padded = payload + b"\x00" * (aligned_size - body_size)
        blob = hdr + body + padded
        data_offsets.append(cursor)
        data_blobs.append(blob)
        cursor += aligned_size

    # Build ENTRY object referencing all DATA offsets (regular form).
    entry_offset = cursor
    item_count = len(data_offsets)
    # Layout: 16 hdr + 8 seqnum + 8 realtime + 8 monotonic + 16 boot_id +
    # 8 xor_hash + 16 * item_count items
    entry_body_size = 64 + 16 * item_count
    entry_aligned = align_up(entry_body_size)
    entry_hdr = struct.pack(
        "<BB6sQ", OBJECT_ENTRY, 0, b"\x00" * 6, entry_body_size
    )
    entry_body = struct.pack(
        "<QQQ", 1, realtime_us, monotonic_us
    ) + boot_id + struct.pack("<Q", 0)
    items_buf = b""
    for off in data_offsets:
        items_buf += struct.pack("<QQ", off, 0)
    entry_blob = entry_hdr + entry_body + items_buf
    entry_blob = entry_blob + b"\x00" * (entry_aligned - len(entry_blob))

    cursor = entry_offset + entry_aligned

    # Build header.
    arena_size = cursor - HEADER_SIZE
    header = (
        JOURNAL_MAGIC
        + struct.pack("<II", 0, incompatible_flags)  # compatible / incompatible
        + b"\x00"  # state
        + b"\x00" * 7  # reserved
        + b"\x33" * 16  # file_id
        + machine_id
        + boot_id  # tail_entry_boot_id
        + b"\x44" * 16  # seqnum_id
        + struct.pack(
            "<9Q",
            HEADER_SIZE,
            arena_size,
            0,  # data_hash_table_offset
            0,  # data_hash_table_size
            0,  # field_hash_table_offset
            0,  # field_hash_table_size
            entry_offset,  # tail_object_offset
            len(data_offsets) + 1,  # n_objects (DATA + 1 ENTRY)
            1,  # n_entries
        )
    )
    assert len(header) == HEADER_SIZE, (
        f"header size mismatch: {len(header)} != {HEADER_SIZE}"
    )

    return header + b"".join(data_blobs) + entry_blob


# ── Magic + header tests ─────────────────────────────────────────────────────


def test_has_journal_magic_true():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(JOURNAL_MAGIC + b"\x00" * 100)
        path = f.name
    try:
        assert has_journal_magic(path) is True
    finally:
        os.unlink(path)


def test_has_journal_magic_false():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"not_a_journal_file" + b"\x00" * 50)
        path = f.name
    try:
        assert has_journal_magic(path) is False
    finally:
        os.unlink(path)


def test_has_journal_magic_missing_file():
    assert has_journal_magic("/nonexistent/path/system.journal") is False


def test_read_header_minimal():
    buf = _build_minimal_journal([("MESSAGE", "hello")])
    hdr = _read_header(buf)
    assert hdr is not None
    assert hdr["header_size"] == 160
    assert hdr["n_entries"] == 1
    assert hdr["compact"] is False


def test_read_header_bad_magic_returns_none():
    buf = b"BADMAGIC" + b"\x00" * 200
    assert _read_header(buf) is None


def test_read_header_too_short_returns_none():
    assert _read_header(b"\x00" * 50) is None


def test_read_object_header_short_buf_returns_none():
    assert _read_object_header(b"\x00" * 8, 0) is None


def test_read_object_header_negative_offset_returns_none():
    assert _read_object_header(b"\x00" * 100, -1) is None


# ── DATA / ENTRY decode tests ────────────────────────────────────────────────


def test_decode_data_payload_strips_alignment_padding():
    # Synthesize a DATA object with payload "MESSAGE=hi" + padding.
    obj_hdr = struct.pack("<BB6sQ", OBJECT_DATA, 0, b"\x00" * 6, 64 + 10)
    body = struct.pack("<6Q", 0, 0, 0, 0, 0, 0)
    payload = b"MESSAGE=hi"
    buf = obj_hdr + body + payload + b"\x00" * 6  # 8-byte alignment
    result = _decode_data_payload(
        buf, 0, 64 + 10, obj_flags=0, compact=False
    )
    assert result == "MESSAGE=hi"


def test_decode_data_payload_compressed_returns_none():
    obj_hdr = struct.pack("<BB6sQ", OBJECT_DATA, 0, b"\x00" * 6, 64 + 4)
    body = struct.pack("<6Q", 0, 0, 0, 0, 0, 0)
    buf = obj_hdr + body + b"\x01\x02\x03\x04"
    # OBJECT_COMPRESSED_LZ4 = 1 << 1 = 2
    result = _decode_data_payload(buf, 0, 64 + 4, obj_flags=2, compact=False)
    assert result is None


def test_decode_entry_extracts_offsets():
    # ENTRY body: seqnum=42, realtime=1000, monotonic=2000, boot_id=zero,
    # xor_hash=0, 1 item with offset=128
    obj_hdr = struct.pack("<BB6sQ", OBJECT_ENTRY, 0, b"\x00" * 6, 80)
    body = (
        struct.pack("<QQQ", 42, 1000, 2000)
        + b"\x00" * 16
        + struct.pack("<Q", 0)
        + struct.pack("<QQ", 128, 0)
    )
    buf = obj_hdr + body
    entry = _decode_entry(buf, 0, 80, compact=False)
    assert entry is not None
    assert entry["seqnum"] == 42
    assert entry["realtime"] == 1000
    assert entry["monotonic"] == 2000
    assert entry["data_offsets"] == [128]


# ── End-to-end parse_journal_file ────────────────────────────────────────────


def test_parse_journal_file_one_entry(tmp_path):
    path = tmp_path / "test.journal"
    buf = _build_minimal_journal([
        ("MESSAGE", "test message body"),
        ("PRIORITY", "3"),
        ("_TRANSPORT", "stdout"),
        ("_SYSTEMD_UNIT", "sshd.service"),
        ("_PID", "1234"),
        ("_UID", "0"),
        ("_HOSTNAME", "test-host"),
    ])
    path.write_bytes(buf)
    header, entries = parse_journal_file(str(path))
    assert "error" not in header
    assert len(entries) == 1
    entry = entries[0]
    fields = entry["fields"]
    assert fields["MESSAGE"] == "test message body"
    assert fields["PRIORITY"] == "3"
    assert fields["_TRANSPORT"] == "stdout"
    assert fields["_SYSTEMD_UNIT"] == "sshd.service"


def test_parse_journal_file_missing_returns_error():
    header, entries = parse_journal_file("/nonexistent/x.journal")
    assert "error" in header
    assert entries == []


def test_parse_journal_file_bad_magic_returns_error(tmp_path):
    path = tmp_path / "bogus.journal"
    path.write_bytes(b"BAD_MAGIC" + b"\x00" * 500)
    header, entries = parse_journal_file(str(path))
    assert "error" in header
    assert entries == []


# ── Anomaly classifier tests ─────────────────────────────────────────────────


def test_build_anomaly_flags_priority_critical():
    flags = build_anomaly_flags(
        priority=1, message="alert", transport="syslog", unit=None
    )
    assert flags["priority_critical"] is True


def test_build_anomaly_flags_priority_info_not_critical():
    flags = build_anomaly_flags(
        priority=6, message="info", transport="syslog", unit=None
    )
    assert flags["priority_critical"] is False


def test_build_anomaly_flags_oom_killer():
    flags = build_anomaly_flags(
        priority=4,
        message="Out of memory: Killed process 1234 (chrome)",
        transport="kernel",
        unit=None,
    )
    assert flags["oom_killer"] is True


def test_build_anomaly_flags_segfault():
    flags = build_anomaly_flags(
        priority=4,
        message="myapp[1234]: segfault at 0 ip 0x400000 sp 0x7fff",
        transport="kernel",
        unit=None,
    )
    assert flags["segfault"] is True


def test_build_anomaly_flags_selinux_denied():
    flags = build_anomaly_flags(
        priority=4,
        message="avc: denied { execute } for pid=999",
        transport="audit",
        unit=None,
    )
    assert flags["selinux_denied"] is True


def test_build_anomaly_flags_audit_failure_via_audit_transport():
    flags = build_anomaly_flags(
        priority=4,
        message="audit: lost=15 backlog=0",
        transport="audit",
        unit=None,
    )
    assert flags["audit_failure"] is True


def test_build_anomaly_flags_suspicious_unit_tmp():
    flags = build_anomaly_flags(
        priority=6,
        message="started",
        transport="journal",
        unit="/tmp/evil-payload.service",
    )
    assert flags["suspicious_unit"] is True


def test_build_anomaly_flags_suspicious_unit_dev_shm():
    flags = build_anomaly_flags(
        priority=6,
        message="started",
        transport="journal",
        unit="x-/dev/shm/backdoor.service",
    )
    assert flags["suspicious_unit"] is True


def test_build_anomaly_flags_legitimate_unit_not_suspicious():
    flags = build_anomaly_flags(
        priority=6,
        message="started",
        transport="journal",
        unit="ssh.service",
    )
    assert flags["suspicious_unit"] is False


def test_build_anomaly_flags_log_clear():
    flags = build_anomaly_flags(
        priority=6,
        message="Deleted archived journal /var/log/journal/... (300M).",
        transport="journal",
        unit="systemd-journald.service",
    )
    assert flags["log_clear_marker"] is True


def test_build_anomaly_flags_empty_message_clean():
    flags = build_anomaly_flags(
        priority=6, message="", transport="journal", unit=None
    )
    assert flags == {
        "priority_critical": False,
        "oom_killer": False,
        "segfault": False,
        "selinux_denied": False,
        "audit_failure": False,
        "suspicious_unit": False,
        "log_clear_marker": False,
    }


# ── Detection-root walker tests ──────────────────────────────────────────────


def test_walk_journal_files_finds_system_journal(tmp_path):
    journal_dir = tmp_path / "var" / "log" / "journal" / "abc123"
    journal_dir.mkdir(parents=True)
    (journal_dir / "system.journal").write_bytes(JOURNAL_MAGIC + b"\x00" * 100)
    (journal_dir / "user-1000.journal").write_bytes(JOURNAL_MAGIC + b"\x00" * 100)
    (journal_dir / "not-a-journal.txt").write_bytes(b"text")
    hits = walk_journal_files([str(tmp_path)])
    names = {os.path.basename(h) for h in hits}
    assert "system.journal" in names
    assert "user-1000.journal" in names
    assert "not-a-journal.txt" not in names


def test_walk_journal_files_empty_root(tmp_path):
    assert walk_journal_files([str(tmp_path)]) == []


def test_walk_journal_files_dedupes_via_seen_set(tmp_path):
    journal_dir = tmp_path / "var" / "log" / "journal"
    journal_dir.mkdir(parents=True)
    (journal_dir / "x.journal").write_bytes(JOURNAL_MAGIC + b"\x00" * 100)
    # Pass the same root twice — should not duplicate.
    hits = walk_journal_files([str(tmp_path), str(tmp_path)])
    assert len(hits) == 1


def test_walk_journal_files_missing_root_swallows():
    assert walk_journal_files(["/this/path/does/not/exist"]) == []


# ── Rule #35b live canary — end-to-end against real ORM/DB ──────────────────


@pytest.mark.asyncio
async def test_do_journald_walk_persists_entries(tmp_path):
    """Live canary — _do_journald_walk persists a real LinuxJournaldEntry
    row against a fresh ORM-backed SQLite session, with all field
    mappings correctly applied (per Rule #35b — mock assertions verify
    'X was called', live canaries verify 'X persisted with the right
    args').
    """
    # Set up a tmpdir with a synthetic .journal file under
    # var/log/journal/<machine-id>/.
    machine_hex = "abcd1234abcd1234abcd1234abcd1234"
    journal_dir = tmp_path / "var" / "log" / "journal" / machine_hex
    journal_dir.mkdir(parents=True)
    buf = _build_minimal_journal(
        [
            ("MESSAGE", "audit: lost=5 backlog=0"),
            ("PRIORITY", "1"),
            ("_TRANSPORT", "audit"),
            ("_SYSTEMD_UNIT", "/tmp/evil.service"),
            ("_PID", "9999"),
            ("_UID", "0"),
            ("_HOSTNAME", "victim"),
            ("_COMM", "kauditd"),
        ],
        machine_id=bytes.fromhex(machine_hex),
    )
    (journal_dir / "system.journal").write_bytes(buf)

    async with make_live_db() as db:
        project = Project(name="test-iota", description="ι.A.C live canary")
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="test.bin",
            storage_path="/tmp/x",
            file_size=100,
            sha256="0" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.flush()

        result = await _do_journald_walk(db, firmware.id)
        await db.commit()

    # Verify the aggregate result.
    assert result["files_scanned"] == 1
    assert result["entries_walked"] == 1
    assert result["entries_persisted"] == 1
    # priority=1 → priority_critical anomaly counted
    assert result["priority_critical_count"] == 1
    # /tmp/ unit → suspicious_unit anomaly counted
    assert result["suspicious_unit_count"] == 1
    # audit transport + audit failure pattern → audit_failure
    assert result["audit_failure_count"] >= 1
    # At least one anomaly bit fired
    assert result["anomaly_total"] == 1

    # Open a fresh session and SELECT the persisted row to verify the
    # value flow.
    async with make_live_db() as db2:
        # NB: SQLite engines are isolated per make_live_db() call, so
        # the above row was lost when we exited that context. The
        # purpose of this canary is to verify _do_journald_walk
        # ASSEMBLES rows correctly. We re-run with a fresh DB to
        # confirm SELECTability against a single-engine view.
        project = Project(name="test-iota-2", description="select check")
        db2.add(project)
        await db2.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="test2.bin",
            storage_path="/tmp/y",
            file_size=200,
            sha256="1" * 64,
            extracted_path=str(tmp_path),
        )
        db2.add(firmware)
        await db2.flush()

        await _do_journald_walk(db2, firmware.id)
        await db2.commit()

        # SELECT the row — confirm constructor args persisted.
        persisted = (
            await db2.execute(
                select(LinuxJournaldEntry).where(
                    LinuxJournaldEntry.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert persisted.priority == 1
        assert persisted.transport == "audit"
        assert persisted.unit == "/tmp/evil.service"
        assert persisted.pid == 9999
        assert persisted.uid == 0
        assert persisted.hostname == "victim"
        assert persisted.comm == "kauditd"
        assert "audit: lost=5" in persisted.message
        assert persisted.machine_id == machine_hex
        # anomaly_flags stamped with schema_version.
        assert persisted.anomaly_flags is not None
        assert persisted.anomaly_flags["schema_version"] == 1
        assert persisted.anomaly_flags["priority_critical"] is True
        assert persisted.anomaly_flags["suspicious_unit"] is True


@pytest.mark.asyncio
async def test_do_journald_walk_no_files_returns_empty_aggregate(tmp_path):
    """When no .journal files exist, the walker returns the empty
    aggregate without raising."""
    async with make_live_db() as db:
        project = Project(name="test-empty", description="empty case")
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

        result = await _do_journald_walk(db, firmware.id)
        assert result["files_scanned"] == 0
        assert result["entries_walked"] == 0
        assert result["entries_persisted"] == 0


# ── Rule #36 no-execute test gate ────────────────────────────────────────────


def test_journald_walker_no_execute():
    """Rule #36 — the journald_walker.py source MUST NOT invoke any
    spawn primitive against extracted artefacts. The walker is a
    pure-Python clean-room parser; nothing should execute the
    parsed data.

    Mechanical: grep the module source for spawn-primitive tokens.
    """
    source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "journald_walker.py"
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
            f"Rule #36 violation in journald_walker.py — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke spawn primitives against extracted artefacts."
        )
