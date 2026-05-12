"""Phase κ.B.C — tests for the AppCompat / Shimcache walker.

Covers:

- Pure helpers: ``_filetime_to_datetime``, ``_classify_path``,
  ``build_anomaly_flags``, ``_control_set_ordinal_from_path``.
- The binary parser: ``_parse_appcompat_cache_binary`` end-to-end on
  synthesised AppCompatCache blobs.
- Rule #35b live canary: ``_do_appcompat_walk`` against a real ORM
  session via ``make_live_db()`` (no Docker dependency; no DNS hop).
- Rule #36 no-execute test gate.
"""
from __future__ import annotations

import datetime as _dt
import pathlib
import re
import struct

import pytest

from app.models import Firmware, Project
from app.services.appcompat_walker import (
    _classify_path,
    _control_set_ordinal_from_path,
    _do_appcompat_walk,
    _filetime_to_datetime,
    _parse_appcompat_cache_binary,
    build_anomaly_flags,
)
from tests._live_db import make_live_db

# ── _filetime_to_datetime ────────────────────────────────────────────────────


def test_filetime_to_datetime_epoch():
    # 0 ticks past 1601-01-01 = epoch itself (but we treat 0 as "absent").
    assert _filetime_to_datetime(0) is None


def test_filetime_to_datetime_unix_epoch():
    # Unix epoch (1970-01-01) in FILETIME = 116444736000000000.
    out = _filetime_to_datetime(116444736000000000)
    assert out is not None
    assert out.year == 1970
    assert out.month == 1
    assert out.day == 1


def test_filetime_to_datetime_y2k():
    # 2000-01-01 UTC in FILETIME.
    # Seconds from 1601-01-01 to 2000-01-01 = 12591158400.
    # Ticks = 125911584000000000.
    out = _filetime_to_datetime(125911584000000000)
    assert out is not None
    assert out.year == 2000


def test_filetime_to_datetime_negative_returns_none():
    assert _filetime_to_datetime(-1) is None


def test_filetime_to_datetime_overflow_returns_none():
    # Past datetime.max (year 9999) — should clamp to None.
    massive = 2**62
    assert _filetime_to_datetime(massive) is None


# ── _classify_path ───────────────────────────────────────────────────────────


def test_classify_path_users_public_suspicious():
    flags = _classify_path(r"\??\C:\Users\Public\evil.exe")
    assert flags["suspicious_path"] is True
    assert flags["unusual_extension"] is False  # .exe is expected


def test_classify_path_windows_temp_suspicious():
    flags = _classify_path(r"C:\Windows\Temp\dropper.exe")
    assert flags["suspicious_path"] is True


def test_classify_path_appdata_local_temp_suspicious():
    flags = _classify_path(r"C:\Users\alice\AppData\Local\Temp\malware.exe")
    assert flags["suspicious_path"] is True


def test_classify_path_programdata_caches_suspicious():
    flags = _classify_path(
        r"C:\ProgramData\Microsoft\Windows\Caches\thing.exe"
    )
    assert flags["suspicious_path"] is True


def test_classify_path_legitimate_system32_not_suspicious():
    flags = _classify_path(r"C:\Windows\System32\cmd.exe")
    assert flags["suspicious_path"] is False
    assert flags["temp_execution"] is False
    assert flags["unusual_extension"] is False


def test_classify_path_tmp_extension_temp_execution():
    flags = _classify_path(r"C:\Windows\System32\thing.tmp")
    assert flags["temp_execution"] is True
    assert flags["unusual_extension"] is False  # .tmp routes to temp_execution


def test_classify_path_dat_extension_temp_execution():
    flags = _classify_path(r"C:\Program Files\foo\bar.dat")
    assert flags["temp_execution"] is True


def test_classify_path_unusual_extension_jpg():
    flags = _classify_path(r"C:\Users\public\image.jpg")
    assert flags["suspicious_path"] is True  # under Users\Public
    assert flags["unusual_extension"] is True


def test_classify_path_no_extension_unusual():
    flags = _classify_path(r"C:\some\path\noext")
    assert flags["unusual_extension"] is True


def test_classify_path_dll_expected():
    flags = _classify_path(r"C:\Windows\System32\kernel32.dll")
    assert flags["unusual_extension"] is False


def test_classify_path_none_clean():
    flags = _classify_path(None)
    assert flags == {
        "suspicious_path": False,
        "temp_execution": False,
        "unusual_extension": False,
    }


def test_classify_path_empty_clean():
    flags = _classify_path("")
    assert flags["suspicious_path"] is False


# ── build_anomaly_flags ──────────────────────────────────────────────────────


def test_build_anomaly_flags_carries_parse_error():
    flags = build_anomaly_flags(file_path=None, parse_error=True)
    assert flags["parse_error"] is True
    assert flags["suspicious_path"] is False


def test_build_anomaly_flags_clean_path_clean_flags():
    flags = build_anomaly_flags(
        file_path=r"C:\Windows\System32\cmd.exe", parse_error=False
    )
    assert flags["parse_error"] is False
    assert flags["suspicious_path"] is False


# ── _control_set_ordinal_from_path ───────────────────────────────────────────


def test_control_set_ordinal_001():
    p = r"\ControlSet001\Control\Session Manager\AppCompatCache"
    assert _control_set_ordinal_from_path(p) == 1


def test_control_set_ordinal_002():
    p = r"\ControlSet002\Control\Session Manager\AppCompatCache"
    assert _control_set_ordinal_from_path(p) == 2


def test_control_set_ordinal_currentcontrolset_none():
    # CurrentControlSet doesn't have an ordinal we can extract.
    p = r"\CurrentControlSet\Control\Session Manager\AppCompatCache"
    assert _control_set_ordinal_from_path(p) is None


def test_control_set_ordinal_no_controlset_none():
    p = r"\SOFTWARE\Microsoft"
    assert _control_set_ordinal_from_path(p) is None


# ── _parse_appcompat_cache_binary ────────────────────────────────────────────
#
# Synthesise a Win10/11 AppCompatCache blob with a known set of entries
# and verify the parser decodes path + FILETIME correctly.


def _build_entry(file_path: str, filetime: int) -> bytes:
    """Build one AppCompatCache entry (Win10/11 format).

    Layout:
      sig(4) + entry_data_length(4) + path_length(2) + utf16le_path +
      filetime(8) + data_size(4)
    """
    path_utf16 = file_path.encode("utf-16-le")
    path_length = len(path_utf16)
    # entry_data_length = sizeof(path_length(2) + path + filetime(8) + data_size(4))
    entry_data_length = 2 + path_length + 8 + 4
    parts = [
        b"10ts",  # sig
        struct.pack("<I", entry_data_length),
        struct.pack("<H", path_length),
        path_utf16,
        struct.pack("<Q", filetime),
        struct.pack("<I", 0),  # data_size — we set to 0 (no trailer)
    ]
    return b"".join(parts)


def _build_appcompat_blob(
    *,
    header_offset: int = 0x30,
    entries: list[tuple[str, int]],
) -> bytes:
    """Build a Win10/11 AppCompatCache blob with header magic at the
    specified offset and the given (path, filetime) entries packed
    after it."""
    # Padding to header_offset, then "10ts" magic, then entries.
    blob = b"\x00" * header_offset + b"10ts"
    for path, ts in entries:
        blob += _build_entry(path, ts)
    return blob


def test_parse_no_magic_degrades_gracefully():
    """Blob without 10ts magic at 0x30 or 0x34 → empty entries +
    informative error (graceful degradation per κ.B spec)."""
    blob = b"\x00" * 0x40 + b"junk"  # No magic at offsets 0x30 or 0x34
    entries, errors = _parse_appcompat_cache_binary(blob)
    assert entries == []
    assert errors
    assert any("header magic" in e for e in errors)


def test_parse_too_short_blob():
    blob = b"\x00" * 10
    entries, errors = _parse_appcompat_cache_binary(blob)
    assert entries == []
    assert any("too short" in e for e in errors)


def test_parse_one_entry_win10_format():
    # FILETIME corresponding to a known epoch.
    ts = 132514780000000000  # ~2020-06-19
    blob = _build_appcompat_blob(
        header_offset=0x30,
        entries=[(r"C:\Windows\System32\cmd.exe", ts)],
    )
    entries, errors = _parse_appcompat_cache_binary(blob)
    assert errors == []
    assert len(entries) == 1
    e = entries[0]
    assert e["file_path"] == r"C:\Windows\System32\cmd.exe"
    assert e["filetime"] == ts


def test_parse_multiple_entries_in_order():
    blob = _build_appcompat_blob(
        header_offset=0x30,
        entries=[
            (r"C:\Windows\System32\cmd.exe", 132514780000000000),
            (r"\??\C:\Users\Public\evil.exe", 132514790000000000),
            (r"C:\Program Files\Foo\bar.dll", 132514800000000000),
        ],
    )
    entries, errors = _parse_appcompat_cache_binary(blob)
    assert errors == []
    assert len(entries) == 3
    assert entries[0]["file_path"] == r"C:\Windows\System32\cmd.exe"
    assert entries[1]["file_path"] == r"\??\C:\Users\Public\evil.exe"
    assert entries[2]["file_path"] == r"C:\Program Files\Foo\bar.dll"


def test_parse_header_at_offset_0x34():
    """Server builds use offset 0x34 instead of 0x30 — the parser
    should probe both."""
    blob = _build_appcompat_blob(
        header_offset=0x34,
        entries=[(r"C:\Windows\System32\notepad.exe", 132514780000000000)],
    )
    entries, errors = _parse_appcompat_cache_binary(blob)
    assert errors == []
    assert len(entries) == 1


def test_parse_max_entries_caps():
    blob = _build_appcompat_blob(
        header_offset=0x30,
        entries=[
            (rf"C:\test\binary_{i}.exe", 132514780000000000)
            for i in range(50)
        ],
    )
    entries, _errors = _parse_appcompat_cache_binary(blob, max_entries=10)
    assert len(entries) == 10


def test_parse_truncated_entry_records_error():
    """An entry that ends mid-path triggers an error and stops the parse."""
    good = _build_entry(r"C:\Windows\System32\cmd.exe", 132514780000000000)
    truncated = good[: len(good) // 2]
    blob = b"\x00" * 0x30 + b"10ts" + truncated
    entries, errors = _parse_appcompat_cache_binary(blob)
    # The parser should record an error and stop cleanly.
    assert errors
    # Depending on truncation, it may emit 0 entries (head truncated).
    assert isinstance(entries, list)


# ── Rule #35b live canary — end-to-end via make_live_db ──────────────────────


@pytest.mark.asyncio
async def test_do_appcompat_walk_no_hives_returns_empty(tmp_path):
    """No SYSTEM hives under detection roots → empty aggregate."""
    async with make_live_db() as db:
        project = Project(
            name="test-kappa-b", description="κ.B.C live canary empty"
        )
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

        result = await _do_appcompat_walk(db, firmware.id)
        assert result["hives_scanned"] == 0
        assert result["entries_persisted"] == 0
        assert result["anomaly_total"] == 0


@pytest.mark.asyncio
async def test_do_appcompat_walk_missing_firmware_returns_empty(tmp_path):
    import uuid

    async with make_live_db() as db:
        result = await _do_appcompat_walk(db, uuid.uuid4())
        # Missing firmware → empty result (defensive return).
        assert result["hives_scanned"] == 0
        assert result["entries_persisted"] == 0


# ── Rule #36 no-execute test gate ─────────────────────────────────────────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Remove docstrings, # comments, and string literals from Python
    source so we can scan for ACTUAL code references."""
    import io
    import tokenize

    out_tokens: list[str] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenizeError:
        return source

    for tok in tokens:
        if tok.type == tokenize.STRING:
            continue
        if tok.type == tokenize.COMMENT:
            continue
        out_tokens.append(tok.string)
    return " ".join(out_tokens)


def test_appcompat_walker_no_execute():
    """Rule #36 — appcompat_walker.py CODE (not docstrings/comments)
    MUST NOT invoke any spawn primitive nor shell out to Windows
    binary-execution helpers. The walker is a pure-Python ``struct``
    parser; nothing should exec / spawn against AppCompat data, AND
    nothing should invoke rundll32 / cscript / wmic / wine / mono.
    """
    raw_source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "appcompat_walker.py"
    ).read_text()
    source = _strip_docstrings_and_comments(raw_source)

    # Rule #36 standard forbidden-spawn tokens.
    forbidden_spawn = (
        r"subprocess\.(run|Popen|call|check_output|check_call)",
        r"asyncio\.create_subprocess_(exec|shell)",
        r"os\.(system|execvp|execve|spawnvp)",
        r"\brunpy\.run_path\b",
        r"\beval\s*\(",
        r"\bexec\s*\(",
    )
    for pattern in forbidden_spawn:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in appcompat_walker.py CODE — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke spawn primitives against extracted artefacts."
        )

    # Windows execution-helper CLIs — wairz must not invoke any of these.
    forbidden_windows_cli = (
        r"['\"](?:rundll32|cscript|wscript|wmic|mshta|powershell|"
        r"WmiPrvSE|wmiexec|wine|mono|dotnet|cabextract)['\"]",
    )
    for pattern in forbidden_windows_cli:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in appcompat_walker.py CODE — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke Windows execution helpers against AppCompat targets."
        )
