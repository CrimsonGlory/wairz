"""Tests for the Phase θ.D.D SDB shim walker.

Critical test: ``test_sdb_no_shim_execution`` — the Rule #36
no-execute gate. The SDB walker module MUST contain ZERO process-
spawn primitives. `.sdb` files describe shim instructions that
Windows loads + executes via AppHelp / sdbinst infrastructure on
every application launch. NO codepath in this walker may invoke
sdbinst / AppHelp / Mscoree / wine / mono against parsed entries.

Test coverage:
- Pure helpers (sdb-kind classification, shim-class classification,
  anomaly classification, fingerprint compute, DLL-outside-appdir
  heuristic).
- ``walk_sdb_files`` — extension-allow-list + size-gate +
  path-traversal-resistance across detection roots.
- Inner orchestrator ``_do_sdb_walk`` — Rule #35b live canaries
  via make_live_db: no-roots, no-files, successful walk with
  custom-path attacker shim, microsoft-path benign shim.
- **Rule #36 no-execute test gate** — ``test_sdb_no_shim_execution``
  asserts the walker module surfaces shim entries as DATA only.
"""
from __future__ import annotations

import os
import re
import struct
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsSdbEntry
from app.services.sdb_walker import (
    _do_sdb_walk,
    build_anomaly_flags,
    classify_sdb_kind,
    classify_shim_class,
    compute_entry_fingerprint,
    walk_sdb_files,
)
from tests._live_db import make_live_db
from third_party.python_sdb import (
    SDB_MAGIC,
    TAG_APP,
    TAG_APP_NAME,
    TAG_COMMAND_LINE,
    TAG_DATABASE,
    TAG_DLLFILE,
    TAG_EXE,
    TAG_NAME,
    TAG_PATCH,
    TAG_PATCH_BITS,
    TAG_SHIM,
    TAG_STRINGTABLE,
    TAG_STRINGTABLE_ITEM,
)


def _make_firmware(
    project_id: uuid.UUID, name: str, sha_seed: str
) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── Rule #36 no-execute test gate ──────────────────────────────────────────


_WALKER_MODULE = (
    Path(__file__).parent.parent
    / "app"
    / "services"
    / "sdb_walker.py"
)


# Forbidden execution primitives — patterns the walker MUST NOT
# contain. We scrub string literals + comments before matching so
# documentation / examples don't false-positive.
_FORBIDDEN_EXEC_PATTERNS: list[str] = [
    r"\bsubprocess\.\w+\(",
    r"\bos\.system\(",
    r"\bos\.execvp\(",
    r"\bos\.execve\(",
    r"\bos\.spawnvp\(",
    r"\basyncio\.create_subprocess_(exec|shell)\(",
    r"\brunpy\.\w+\(",
    r"(?:^|[^a-zA-Z_])eval\s*\(",
    r"(?:^|[^a-zA-Z_])exec\s*\(",
    # SDB-specific execution wrappers — even via subprocess.
    r"\bsdbinst(?:\.exe)?\s+",
    r"\bAppHelp(?:\.dll)?",
    r"\bMscoree(?:\.dll)?",
    r"\bshim_eng",
    r"\bwine\s+",
    r"\bmono\s+",
]


def _strip_string_literals_and_comments(source: str) -> str:
    """Strip Python string literals + comments so the forbidden-
    pattern gate doesn't fire on documentation / examples."""
    source = re.sub(r'"""[\s\S]*?"""', '""', source)
    source = re.sub(r"'''[\s\S]*?'''", "''", source)
    source = re.sub(r'"[^"\n]*"', '""', source)
    source = re.sub(r"'[^'\n]*'", "''", source)
    source = re.sub(r"#[^\n]*", "", source)
    return source


def test_sdb_no_shim_execution():
    """**Rule #36 central gate** — the SDB walker module MUST NOT
    contain ANY process-spawn primitive that could execute parsed
    SDB payloads via Windows shim infrastructure.

    Scrubs string literals + comments first so documentation examples
    don't fire the gate. The actual CODE must contain ZERO matches
    for every forbidden pattern: subprocess.*, asyncio.create_subprocess_*,
    os.system / execvp / spawnvp, runpy, eval/exec function calls, OR
    SDB execution wrappers (sdbinst / AppHelp / Mscoree / shim_eng /
    wine / mono).

    `.sdb` files describe shim instructions Windows loads + executes
    via AppHelp on every application launch. The walker parses bytes
    via the vendored python_sdb (no execution); wairz never invokes
    sdbinst.exe / AppHelp.dll / Mscoree.dll / any shim infrastructure
    against parsed entries. The shim entries surface as DATA via
    WindowsSdbEntry.shim_payload + Finding evidence.
    """
    walker_source = _WALKER_MODULE.read_text()
    scrubbed = _strip_string_literals_and_comments(walker_source)

    for pattern in _FORBIDDEN_EXEC_PATTERNS:
        match = re.search(pattern, scrubbed)
        assert match is None, (
            f"sdb_walker.py contains forbidden pattern {pattern!r} "
            f"at offset {match.start()}: "
            f"{scrubbed[max(0, match.start()-30):match.end()+30]!r}. "
            "Rule #36 no-execute discipline violated — .sdb files "
            "are attacker-controlled shim definitions and must NEVER "
            "be loaded by Windows shim infrastructure."
        )


# ── Synthetic .sdb byte construction ───────────────────────────────────────


def _utf16(s: str) -> bytes:
    return (s + "\x00").encode("utf-16-le")


def _emit_string_chunk(s: str) -> bytes:
    payload = _utf16(s)
    return struct.pack("<HI", TAG_STRINGTABLE_ITEM, len(payload)) + payload


def _emit_stringtable(strings: list[str]) -> tuple[bytes, dict[str, int]]:
    body = b""
    offsets: dict[str, int] = {}
    for s in strings:
        offsets[s] = len(body)
        body += _emit_string_chunk(s)
    return struct.pack("<HI", TAG_STRINGTABLE, len(body)) + body, offsets


def _emit_stringref(tag: int, offset: int) -> bytes:
    return struct.pack("<HI", tag, offset)


def _emit_list(tag: int, body: bytes) -> bytes:
    return struct.pack("<HI", tag, len(body)) + body


def _emit_binary(tag: int, data: bytes) -> bytes:
    return struct.pack("<HI", tag, len(data)) + data


def _build_sdb_bytes(
    database_body: bytes, stringtable_chunk: bytes
) -> bytes:
    header = struct.pack("<II", 0xDEADBEEF, 0xCAFEBABE) + SDB_MAGIC
    database_chunk = _emit_list(TAG_DATABASE, database_body)
    return header + stringtable_chunk + database_chunk


def _attacker_inject_dll_sdb() -> bytes:
    """Synthetic InjectDll-shaped .sdb — the canonical T1546.011
    attacker tradecraft."""
    strings = [
        "EvilApp",                     # TAG_APP_NAME
        "myapp.exe",                   # TAG_NAME for EXE
        "InjectDll",                   # TAG_NAME for SHIM
        "C:/Temp/attacker.dll",        # TAG_DLLFILE for SHIM
    ]
    stringtable, refs = _emit_stringtable(strings)
    exe_body = _emit_stringref(TAG_NAME, refs["myapp.exe"])
    shim_body = (
        _emit_stringref(TAG_NAME, refs["InjectDll"])
        + _emit_stringref(TAG_DLLFILE, refs["C:/Temp/attacker.dll"])
    )
    app_body = (
        _emit_stringref(TAG_APP_NAME, refs["EvilApp"])
        + _emit_list(TAG_EXE, exe_body)
        + _emit_list(TAG_SHIM, shim_body)
    )
    return _build_sdb_bytes(_emit_list(TAG_APP, app_body), stringtable)


def _benign_microsoft_sdb() -> bytes:
    """Synthetic benign Microsoft-shipped shim — VersionLie shim."""
    strings = [
        "LegacyApp",
        "legacy.exe",
        "VersionLie",
    ]
    stringtable, refs = _emit_stringtable(strings)
    exe_body = _emit_stringref(TAG_NAME, refs["legacy.exe"])
    shim_body = _emit_stringref(TAG_NAME, refs["VersionLie"])
    app_body = (
        _emit_stringref(TAG_APP_NAME, refs["LegacyApp"])
        + _emit_list(TAG_EXE, exe_body)
        + _emit_list(TAG_SHIM, shim_body)
    )
    return _build_sdb_bytes(_emit_list(TAG_APP, app_body), stringtable)


# ── classify_sdb_kind tests ────────────────────────────────────────────────


def test_classify_sdb_kind_custom_path():
    assert classify_sdb_kind(
        "Windows/AppPatch/Custom/myapp.sdb"
    ) == "custom"
    assert classify_sdb_kind(
        "Windows/AppPatch/Custom64/myapp64.sdb"
    ) == "custom"
    # Case-insensitive.
    assert classify_sdb_kind(
        "windows/apppatch/custom/myapp.sdb"
    ) == "custom"
    # Backslashes normalized.
    assert classify_sdb_kind(
        "Windows\\AppPatch\\Custom\\myapp.sdb"
    ) == "custom"


def test_classify_sdb_kind_microsoft_path():
    assert classify_sdb_kind(
        "Windows/AppPatch/sysmain.sdb"
    ) == "microsoft"
    assert classify_sdb_kind(
        "Windows/AppPatch/drvmain.sdb"
    ) == "microsoft"


def test_classify_sdb_kind_unknown_path():
    assert classify_sdb_kind("orphan.sdb") == "unknown"
    assert classify_sdb_kind("Temp/random.sdb") == "unknown"
    assert classify_sdb_kind("Users/Public/dropped.sdb") == "unknown"


# ── classify_shim_class tests ──────────────────────────────────────────────


def test_classify_shim_class_known_bad_primitives():
    assert classify_shim_class("InjectDll") == "InjectDll"
    assert classify_shim_class("RedirectEXE") == "RedirectEXE"
    assert classify_shim_class("GetCommandLineW") == "GetCommandLineW"
    # ANSI variant maps to same class.
    assert classify_shim_class("GetCommandLineA") == "GetCommandLineW"
    assert classify_shim_class("RedirectShortcut") == "RedirectShortcut"


def test_classify_shim_class_custom_for_unknown_names():
    assert classify_shim_class("VersionLie") == "Custom"
    assert classify_shim_class("MyCustomShim") == "Custom"


def test_classify_shim_class_other_for_empty():
    assert classify_shim_class("") == "Other"


# ── build_anomaly_flags tests ──────────────────────────────────────────────


def test_anomaly_flags_inject_dll_custom_path():
    flags = build_anomaly_flags(
        sdb_kind="custom",
        shim_class="InjectDll",
        shim_name="InjectDll",
        module="C:/Temp/attacker.dll",
        command_line="",
        app_exe="myapp.exe",
    )
    assert flags["is_custom_path"] is True
    assert flags["has_inject_dll"] is True
    assert flags["has_dll_outside_appdir"] is True
    assert flags["has_command_line"] is False


def test_anomaly_flags_benign_microsoft_shim():
    flags = build_anomaly_flags(
        sdb_kind="microsoft",
        shim_class="Custom",
        shim_name="VersionLie",
        module="",
        command_line="",
        app_exe="legacy.exe",
    )
    assert flags["is_custom_path"] is False
    assert flags["has_inject_dll"] is False
    assert flags["has_redirect_exe"] is False
    assert flags["has_dll_outside_appdir"] is False
    assert flags["has_command_line"] is False


def test_anomaly_flags_command_line_flag_set():
    flags = build_anomaly_flags(
        sdb_kind="custom",
        shim_class="GetCommandLineW",
        shim_name="GetCommandLineW",
        module="",
        command_line="--inject-args",
        app_exe="myapp.exe",
    )
    assert flags["has_get_command_line"] is True
    assert flags["has_command_line"] is True


def test_anomaly_flags_system_dll_path_not_flagged():
    """System32/syswow64 DLL paths are NOT flagged as outside-appdir."""
    flags = build_anomaly_flags(
        sdb_kind="microsoft",
        shim_class="Custom",
        shim_name="VersionLie",
        module="C:/Windows/System32/apphelp.dll",
        command_line="",
        app_exe="legacy.exe",
    )
    assert flags["has_dll_outside_appdir"] is False


# ── compute_entry_fingerprint tests ────────────────────────────────────────


def test_fingerprint_is_deterministic():
    f1 = compute_entry_fingerprint(
        file_path="Windows/AppPatch/Custom/x.sdb",
        file_sha256="a" * 64,
        shim_class="InjectDll",
        shim_name="InjectDll",
    )
    f2 = compute_entry_fingerprint(
        file_path="Windows/AppPatch/Custom/x.sdb",
        file_sha256="a" * 64,
        shim_class="InjectDll",
        shim_name="InjectDll",
    )
    assert f1 == f2
    assert len(f1) == 64  # SHA256 hex


def test_fingerprint_differs_on_different_shim_class():
    f1 = compute_entry_fingerprint(
        file_path="x.sdb",
        file_sha256="a" * 64,
        shim_class="InjectDll",
        shim_name="x",
    )
    f2 = compute_entry_fingerprint(
        file_path="x.sdb",
        file_sha256="a" * 64,
        shim_class="RedirectEXE",
        shim_name="x",
    )
    assert f1 != f2


def test_fingerprint_case_insensitive_on_path():
    f1 = compute_entry_fingerprint(
        file_path="Windows/AppPatch/Custom/X.sdb",
        file_sha256="a" * 64,
        shim_class="InjectDll",
        shim_name="x",
    )
    f2 = compute_entry_fingerprint(
        file_path="windows/apppatch/custom/x.sdb",
        file_sha256="a" * 64,
        shim_class="InjectDll",
        shim_name="x",
    )
    assert f1 == f2


# ── walk_sdb_files tests ───────────────────────────────────────────────────


def test_walk_sdb_files_finds_canonical_extensions(tmp_path):
    """Files with `.sdb` extension and size >= 12 bytes are returned."""
    sub = tmp_path / "Windows" / "AppPatch" / "Custom"
    sub.mkdir(parents=True)
    candidate = sub / "myapp.sdb"
    candidate.write_bytes(b"x" * 20)
    other = sub / "myapp.txt"
    other.write_bytes(b"x" * 20)

    hits = walk_sdb_files([str(tmp_path)])
    assert any("myapp.sdb" in h for h in hits)
    assert all("myapp.txt" not in h for h in hits)


def test_walk_sdb_files_skips_undersized(tmp_path):
    """Files smaller than _MIN_FILE_BYTES (12) are skipped."""
    candidate = tmp_path / "tiny.sdb"
    candidate.write_bytes(b"x")
    hits = walk_sdb_files([str(tmp_path)])
    assert hits == []


def test_walk_sdb_files_handles_missing_root():
    """Missing detection root is silently skipped, not raise."""
    hits = walk_sdb_files(["/nonexistent/root"])
    assert hits == []


def test_walk_sdb_files_path_traversal_rejected(tmp_path):
    """Symlinks pointing outside the root are rejected."""
    sub = tmp_path / "Windows" / "AppPatch" / "Custom"
    sub.mkdir(parents=True)
    outside = tmp_path.parent / "outside.sdb"
    outside.write_bytes(b"x" * 20)
    link = sub / "evil.sdb"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("symlink not supported on this system")
    hits = walk_sdb_files([str(tmp_path)])
    # The symlink target is outside the root → realpath check rejects.
    assert all(
        not h.endswith("outside.sdb") for h in hits
    ), "path traversal via symlink leaked outside root"


# ── _do_sdb_walk live canaries (Rule #35b) ─────────────────────────────────


def _fake_roots_factory(root_dir):
    """Patch helper — returns a single-root replacement for
    get_detection_roots to avoid the multi-tmp-dir contamination
    issue documented in θ.E walker (postmortem #1)."""
    async def _fake_roots(firmware, *, db=None):
        return [root_dir]
    return _fake_roots


@pytest.mark.asyncio
async def test_do_sdb_walk_no_roots():
    """No detection roots → empty result, no rows persisted."""
    async with make_live_db() as db:
        project = Project(name="θ.D.D no-roots canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "n")
        firmware.extracted_path = "/nonexistent/tree"
        db.add(firmware)
        await db.flush()

        result = await _do_sdb_walk(db, firmware.id)
        assert result["files_scanned"] == 0
        assert result["entries_persisted"] == 0


@pytest.mark.asyncio
async def test_do_sdb_walk_no_sdb_files(tmp_path):
    """Tree with no `.sdb` files → empty result.

    Patches get_detection_roots to avoid sibling tmp dir
    contamination (θ.E walker postmortem #1)."""
    async with make_live_db() as db:
        project = Project(name="θ.D.D no-files canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "f")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.flush()

        with patch(
            "app.services.sdb_walker.get_detection_roots",
            _fake_roots_factory(str(tmp_path)),
        ):
            result = await _do_sdb_walk(db, firmware.id)

        assert result["files_scanned"] == 0
        assert result["entries_persisted"] == 0


@pytest.mark.asyncio
async def test_do_sdb_walk_attacker_inject_dll_custom_path(tmp_path):
    """Rule #35b live canary — attacker InjectDll shim under
    Custom/ persists with HIGH-confidence anomaly flags set."""
    custom_dir = tmp_path / "Windows" / "AppPatch" / "Custom"
    custom_dir.mkdir(parents=True)
    sdb_path = custom_dir / "myapp.sdb"
    sdb_path.write_bytes(_attacker_inject_dll_sdb())

    async with make_live_db() as db:
        project = Project(name="θ.D.D InjectDll canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "windows.zip", "a")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.flush()

        with patch(
            "app.services.sdb_walker.get_detection_roots",
            _fake_roots_factory(str(tmp_path)),
        ):
            result = await _do_sdb_walk(db, firmware.id)

        assert result["files_scanned"] == 1
        assert result["entries_persisted"] == 1
        assert result["shim_count"] == 1
        assert result["custom_path_count"] == 1
        assert result["inject_dll_count"] == 1
        assert result["anomaly_count"] == 1

        rows = (
            await db.execute(
                select(WindowsSdbEntry).where(
                    WindowsSdbEntry.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        r = rows[0]
        assert r.sdb_kind == "custom"
        assert r.shim_class == "InjectDll"
        assert r.app_name == "EvilApp"
        assert r.app_exe == "myapp.exe"
        assert r.anomaly_flags["has_inject_dll"] is True
        assert r.anomaly_flags["is_custom_path"] is True
        assert r.anomaly_flags["has_dll_outside_appdir"] is True
        assert r.shim_payload["shim_name"] == "InjectDll"
        assert r.shim_payload["module"] == "C:/Temp/attacker.dll"


@pytest.mark.asyncio
async def test_do_sdb_walk_benign_microsoft_shim(tmp_path):
    """Microsoft-path benign shim persists with NO attacker flags
    raised — sdb_kind=microsoft, shim_class=Custom."""
    ms_dir = tmp_path / "Windows" / "AppPatch"
    ms_dir.mkdir(parents=True)
    sdb_path = ms_dir / "sysmain.sdb"
    sdb_path.write_bytes(_benign_microsoft_sdb())

    async with make_live_db() as db:
        project = Project(name="θ.D.D benign-MS canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "windows.zip", "b")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.flush()

        with patch(
            "app.services.sdb_walker.get_detection_roots",
            _fake_roots_factory(str(tmp_path)),
        ):
            result = await _do_sdb_walk(db, firmware.id)

        assert result["files_scanned"] == 1
        assert result["entries_persisted"] == 1
        assert result["custom_path_count"] == 0
        assert result["inject_dll_count"] == 0
        # Microsoft-path shim with no attacker primitive → no anomaly.
        assert result["anomaly_count"] == 0

        r = (
            await db.execute(
                select(WindowsSdbEntry).where(
                    WindowsSdbEntry.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert r.sdb_kind == "microsoft"
        assert r.shim_class == "Custom"
        assert r.anomaly_flags["is_custom_path"] is False
        assert r.anomaly_flags["has_inject_dll"] is False


@pytest.mark.asyncio
async def test_do_sdb_walk_skips_invalid_sdb_files(tmp_path):
    """File with `.sdb` extension but wrong magic → parse_error
    aggregate entry, no rows persisted."""
    sub = tmp_path / "Windows" / "AppPatch"
    sub.mkdir(parents=True)
    bogus = sub / "bogus.sdb"
    bogus.write_bytes(b"NOT_A_VALID_SDB" * 10)

    async with make_live_db() as db:
        project = Project(name="θ.D.D parse-error canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "e")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.flush()

        with patch(
            "app.services.sdb_walker.get_detection_roots",
            _fake_roots_factory(str(tmp_path)),
        ):
            result = await _do_sdb_walk(db, firmware.id)

        assert result["files_scanned"] == 1
        assert result["entries_persisted"] == 0
        per_file = result["per_file"]
        assert any(pf["status"] == "parse_error" for pf in per_file)


@pytest.mark.asyncio
async def test_do_sdb_walk_max_entries_cap_truncates(tmp_path):
    """Tight max_entries budget caps the persist count."""
    custom_dir = tmp_path / "Windows" / "AppPatch" / "Custom"
    custom_dir.mkdir(parents=True)
    # 3 files each with 1 shim → 3 total entries.
    for i in range(3):
        (custom_dir / f"app{i}.sdb").write_bytes(_attacker_inject_dll_sdb())

    async with make_live_db() as db:
        project = Project(name="θ.D.D cap canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "c")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.flush()

        with patch(
            "app.services.sdb_walker.get_detection_roots",
            _fake_roots_factory(str(tmp_path)),
        ):
            result = await _do_sdb_walk(db, firmware.id, max_entries=2)

        # Budget caps at 2 even though 3 are available.
        assert result["entries_persisted"] == 2


@pytest.mark.asyncio
async def test_do_sdb_walk_missing_firmware_returns_empty():
    """firmware_id not in DB → empty result, no exception."""
    async with make_live_db() as db:
        result = await _do_sdb_walk(db, uuid.uuid4())
        assert result["files_scanned"] == 0


@pytest.mark.asyncio
async def test_do_sdb_walk_relative_path_persists_correctly(tmp_path):
    """The persisted file_path is RELATIVE to the detection root."""
    custom_dir = tmp_path / "Windows" / "AppPatch" / "Custom"
    custom_dir.mkdir(parents=True)
    sdb_path = custom_dir / "myapp.sdb"
    sdb_path.write_bytes(_attacker_inject_dll_sdb())

    async with make_live_db() as db:
        project = Project(name="θ.D.D relpath canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "r")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.flush()

        with patch(
            "app.services.sdb_walker.get_detection_roots",
            _fake_roots_factory(str(tmp_path)),
        ):
            await _do_sdb_walk(db, firmware.id)

        r = (
            await db.execute(
                select(WindowsSdbEntry).where(
                    WindowsSdbEntry.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        # Path is relative — should NOT start with tmp_path absolute.
        assert not r.file_path.startswith(str(tmp_path))
        # Should contain the relative components.
        assert "Custom" in r.file_path
        assert r.file_path.endswith("myapp.sdb")
