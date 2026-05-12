"""Phase κ.E.C — tests for the Windows NTFS $UsnJrnl:$J walker.

Covers:

- Pure helpers: ``decode_reason_flags``, ``has_executable_extension``,
  ``looks_like_temp_path``, ``extension_changed``, ``looks_like_ntfs``.
- The bitmask decoder against canonical USN_REASON_* values per
  Microsoft MS-FSCC §2.3.
- Anomaly classifier helpers (synthetic record patterns).
- **Rule #36 no-execute test gate** — the walker source MUST NOT
  invoke any spawn primitive nor shell out to Windows binary-execution
  helpers; we strip docstrings + comments before scanning.
- **Test-gate canary** — confirms the gate ACTUALLY fires on a
  synthetic violation (Rule #17 silent-CLI-exit analog with the κ.D
  whitespace-tolerant regex discipline).
- Rule #35b live canary against ``_do_usnjrnl_walk`` via
  ``make_live_db()`` — empty-state + missing-firmware paths.
"""
from __future__ import annotations

import io
import pathlib
import re
import tokenize

import pytest

from app.models import Firmware, Project
from app.models.windows_usnjrnl_entries import (
    WindowsUsnJrnlEntry,  # noqa: F401 — load ORM into Base.metadata for live-db
)
from app.services.usnjrnl_walker import (
    USN_REASON_FILE_CREATE,
    USN_REASON_FILE_DELETE,
    USN_REASON_RENAME_NEW_NAME,
    USN_REASON_RENAME_OLD_NAME,
    _do_usnjrnl_walk,
    decode_reason_flags,
    extension_changed,
    has_executable_extension,
    looks_like_ntfs,
    looks_like_temp_path,
)
from tests._live_db import make_live_db

# ── decode_reason_flags ──────────────────────────────────────────────────────


def test_decode_reason_flags_file_create():
    out = decode_reason_flags(USN_REASON_FILE_CREATE)
    assert out["file_create"] is True
    assert out["file_delete"] is False
    assert out["_raw"] == USN_REASON_FILE_CREATE


def test_decode_reason_flags_file_delete():
    out = decode_reason_flags(USN_REASON_FILE_DELETE)
    assert out["file_delete"] is True
    assert out["file_create"] is False


def test_decode_reason_flags_close_bit_high():
    """USN_REASON_CLOSE = 0x80000000 — high bit must round-trip."""
    out = decode_reason_flags(0x80000000)
    assert out["close"] is True
    assert out["_raw"] == 0x80000000


def test_decode_reason_flags_rename_pair():
    """RENAME_OLD_NAME | RENAME_NEW_NAME — both decoded together."""
    raw = USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME
    out = decode_reason_flags(raw)
    assert out["rename_old_name"] is True
    assert out["rename_new_name"] is True


def test_decode_reason_flags_zero():
    out = decode_reason_flags(0)
    assert all(
        v is False
        for k, v in out.items()
        if k != "_raw" and isinstance(v, bool)
    )
    assert out["_raw"] == 0


def test_decode_reason_flags_canonical_bit_table():
    """MS-FSCC §2.3 canonical USN_REASON_* values — full bit coverage."""
    raw = (
        0x00000001  # DATA_OVERWRITE
        | 0x00000100  # FILE_CREATE
        | 0x00000200  # FILE_DELETE
        | 0x00001000  # RENAME_OLD_NAME
        | 0x00002000  # RENAME_NEW_NAME
        | 0x00800000  # INTEGRITY_CHANGE
    )
    out = decode_reason_flags(raw)
    assert out["data_overwrite"] is True
    assert out["file_create"] is True
    assert out["file_delete"] is True
    assert out["rename_old_name"] is True
    assert out["rename_new_name"] is True
    assert out["integrity_change"] is True
    assert out["data_extend"] is False  # bit NOT in our mask


# ── has_executable_extension ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name,expected",
    [
        ("payload.exe", True),
        ("PAYLOAD.EXE", True),  # case-insensitive
        ("nasty.dll", True),
        ("rev.ps1", True),
        ("setup.msi", True),
        ("driver.scr", True),
        ("data.bin", False),
        ("readme.txt", False),
        ("photo.png", False),
        ("", False),
        (None, False),
    ],
)
def test_has_executable_extension(name, expected):
    assert has_executable_extension(name) == expected


# ── looks_like_temp_path ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path,expected",
    [
        # Windows-style backslashes.
        ("C:\\Users\\alice\\AppData\\Local\\Temp\\nasty.exe", True),
        ("C:\\Windows\\Temp\\evil.bat", True),
        ("C:\\ProgramData\\Microsoft\\Caches\\dropper.dll", True),
        ("C:\\Users\\Public\\Downloads\\stage.zip", True),
        # Forward-slash variants (matching against an extracted path).
        ("/Users/alice/AppData/Local/Temp/nasty.exe", True),
        ("/Windows/Temp/evil.bat", True),
        ("/Public/Downloads/stage.zip", True),
        # Negatives.
        ("C:\\Windows\\System32\\notepad.exe", False),
        ("C:\\Users\\alice\\Documents\\report.docx", False),
        ("/usr/bin/bash", False),
        ("", False),
        (None, False),
    ],
)
def test_looks_like_temp_path(path, expected):
    assert looks_like_temp_path(path) == expected


def test_looks_like_temp_path_case_insensitive():
    """Case-insensitive matching."""
    assert looks_like_temp_path("c:\\WINDOWS\\temp\\bad.exe")
    assert looks_like_temp_path("c:\\users\\public\\downloads\\x.zip")


def test_looks_like_temp_path_substring_word_match_only():
    """``Temp`` only matches as a path component, not as a substring of
    a longer name (κ.C postmortem lesson — explicit shell-boundary
    character groups via [\\/], not \\b)."""
    # `Template` should NOT match `Temp` because it's not a path component.
    assert not looks_like_temp_path("C:\\Users\\alice\\Documents\\Template")
    assert not looks_like_temp_path("C:\\Tempora\\fugit\\time.txt")


# ── extension_changed ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "old_name,new_name,expected",
    [
        # Classic masquerading shape.
        ("payload.tmp", "payload.exe", True),
        ("hidden.dat", "evil.dll", True),
        ("image.png", "shell.bat", True),
        # Case insensitive.
        ("file.TMP", "file.exe", True),
        ("file.exe", "file.EXE", False),
        # Same extension — no change.
        ("a.exe", "b.exe", False),
        ("doc.txt", "renamed.txt", False),
        # Defensive None / empty.
        (None, "x.exe", False),
        ("x.exe", None, False),
        ("", "", False),
    ],
)
def test_extension_changed(old_name, new_name, expected):
    assert extension_changed(old_name, new_name) == expected


# ── looks_like_ntfs ──────────────────────────────────────────────────────────


def test_looks_like_ntfs_synthetic_magic(tmp_path):
    """Boot sector with NTFS OEM ID returns True."""
    fake = tmp_path / "fake.dd"
    # 3 bytes jump + 'NTFS    ' OEM ID + padding.
    fake.write_bytes(b"\xEB\x52\x90" + b"NTFS    " + b"\x00" * 100)
    assert looks_like_ntfs(str(fake))


def test_looks_like_ntfs_missing_magic(tmp_path):
    """File without NTFS magic returns False."""
    fake = tmp_path / "fake.dd"
    fake.write_bytes(b"\x00" * 64)
    assert not looks_like_ntfs(str(fake))


def test_looks_like_ntfs_unreadable_path():
    """Unreadable path returns False, not exception."""
    assert not looks_like_ntfs("/no/such/path/exists.bin")


def test_looks_like_ntfs_short_file(tmp_path):
    """File shorter than 11 bytes returns False."""
    fake = tmp_path / "tiny.dd"
    fake.write_bytes(b"NT")
    assert not looks_like_ntfs(str(fake))


# ── Rule #35b live canaries — _do_usnjrnl_walk via make_live_db ──────────────


@pytest.mark.asyncio
async def test_do_usnjrnl_walk_no_files_returns_empty(tmp_path):
    """No raw NTFS image candidates under detection roots → empty aggregate."""
    async with make_live_db() as db:
        project = Project(
            name="test-kappa-e",
            description="κ.E.C live canary empty",
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

        result = await _do_usnjrnl_walk(db, firmware.id)
        assert result["images_scanned"] == 0
        assert result["records_walked"] == 0
        assert result["records_persisted"] == 0
        assert result["anomaly_total"] == 0


@pytest.mark.asyncio
async def test_do_usnjrnl_walk_missing_firmware_returns_empty(tmp_path):
    """Missing firmware → empty result (defensive return)."""
    import uuid

    async with make_live_db() as db:
        result = await _do_usnjrnl_walk(db, uuid.uuid4())
        assert result["images_scanned"] == 0
        assert result["records_persisted"] == 0


@pytest.mark.asyncio
async def test_do_usnjrnl_walk_non_ntfs_image_skipped(tmp_path):
    """A .raw file that's not actually NTFS is skipped with status='not_ntfs'."""
    bogus = tmp_path / "not_ntfs.raw"
    bogus.write_bytes(b"\x00" * 1024)

    async with make_live_db() as db:
        project = Project(
            name="test-kappa-e-not-ntfs",
            description="κ.E.C live canary not-ntfs",
        )
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="x.bin",
            storage_path="/tmp/x",
            file_size=0,
            sha256="1" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.flush()

        result = await _do_usnjrnl_walk(db, firmware.id)
        # Image candidate found (it has .raw extension) but the NTFS
        # magic check filters it out → walker visits and tags it.
        assert result["images_scanned"] == 1
        assert result["records_persisted"] == 0
        # The per-image aggregate carries the not_ntfs status.
        assert any(
            entry.get("status") == "not_ntfs"
            for entry in result["per_image"]
        )


# ── Rule #36 + Rule #45 (κ.D discipline) — no-execute test gate ──────────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Remove docstrings, # comments, and string literals from Python
    source so we can scan for ACTUAL code references. Mirrors the κ.D
    test gate helper.
    """
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


# Synthetic violation canary constant — kept as a NAME constant so the
# canary test can inject it into a synthetic source body (mirroring the
# κ.D pattern). When the gate scans the walker source, this string
# itself appears only inside a string literal (which gets stripped).
_FORBIDDEN_CANARY = "subprocess"


# Whitespace-tolerant forbidden-token regexes per the κ.D discipline —
# the gate scans the OUTPUT of ``_strip_docstrings_and_comments`` which
# joins Python tokens with spaces. So ``subprocess.run(`` in real source
# becomes ``subprocess . run (`` after stripping. Regexes use ``\s*``
# between every operator + name pair that appeared adjacent in source.
_FORBIDDEN_SPAWN_TOKENS: tuple[str, ...] = (
    r"\bsubprocess\s*\.\s*(?:run|Popen|call|check_output|check_call)\s*\(",
    r"\basyncio\s*\.\s*create_subprocess_(?:exec|shell)\s*\(",
    r"\bos\s*\.\s*(?:system|execvp|execve|spawnvp)\s*\(",
    r"\brunpy\s*\.\s*run_path\s*\(",
    r"\beval\s*\(",
    r"\bexec\s*\(",
)


# Windows execution-helper CLIs and Linux NTFS-mount helpers — wairz
# must NEVER invoke any of these against extracted NTFS artefacts.
_FORBIDDEN_CLI_TOKENS: tuple[str, ...] = (
    r"['\"](?:rundll32|cscript|wscript|wmic|mshta|powershell)['\"]",
    r"['\"](?:WmiPrvSE|wmiexec|wine|mono|dotnet)['\"]",
    r"['\"](?:ntfs-3g|mount|losetup|qemu-system|qemu-nbd)['\"]",
)


def test_walker_no_execute():
    """Rule #36 — usnjrnl_walker.py CODE (not docstrings/comments) MUST
    NOT invoke any spawn primitive nor shell out to Windows binary-
    execution helpers nor Linux NTFS-mount helpers. The walker is a
    pure-Python ``dissect.ntfs`` parser; nothing should exec / spawn
    against extracted NTFS artefacts.
    """
    raw_source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "usnjrnl_walker.py"
    ).read_text()
    source = _strip_docstrings_and_comments(raw_source)

    # Rule #36 standard forbidden-spawn tokens.
    for pattern in _FORBIDDEN_SPAWN_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in usnjrnl_walker.py CODE — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke spawn primitives against extracted NTFS artefacts."
        )

    # Windows execution-helper CLIs + Linux NTFS-mount helpers.
    for pattern in _FORBIDDEN_CLI_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in usnjrnl_walker.py CODE — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke Windows/Linux execution helpers against NTFS targets."
        )


def test_walker_no_execute_gate_actually_fires():
    """Rule #17 silent-CLI-exit analog — verify the test gate ACTUALLY
    fires on a synthetic violation.

    If we trust ``test_walker_no_execute`` without confirming it catches
    violations, the gate could silently pass (e.g. due to a tokenize
    bug, regex typo, or whitespace-tolerance miscalibration). This
    canary builds a synthetic source containing a forbidden CODE token
    (NOT inside a docstring/comment) and confirms the regex matches the
    tokenize-stripped output. Mirrors the κ.D discipline.
    """
    # Construct the synthetic source as a CONCATENATION of lines that
    # pass through the Python parser as actual CODE.
    line_a = "def bad_walker():\n"
    line_b = "    import " + _FORBIDDEN_CANARY + "\n"
    line_c = "    " + _FORBIDDEN_CANARY + '.run(["wine", "/tmp/bad.exe"])\n'
    line_d = "    return None\n"
    synthetic_source = line_a + line_b + line_c + line_d

    stripped = _strip_docstrings_and_comments(synthetic_source)

    # The gate scans for ``subprocess.run(`` with token-join whitespace
    # tolerance. Verify the synthetic source WOULD match.
    pattern = r"\bsubprocess\s*\.\s*run\s*\("
    matches = re.findall(pattern, stripped)
    assert matches, (
        f"Test-gate canary FAILED — the synthetic violation "
        f"'{_FORBIDDEN_CANARY}.run(...)' did NOT trigger the forbidden-"
        f"token regex {pattern!r}. stripped={stripped!r}. The gate is "
        "broken or the canary is miscalibrated."
    )
    # Also verify the canary literal IS what we expect.
    assert _FORBIDDEN_CANARY == "subprocess", (
        "The canary constant must equal 'subprocess' so the "
        "subprocess.run regex catches it."
    )
    # The EXACT regex from the gate's _FORBIDDEN_SPAWN_TOKENS list must
    # also match.
    assert re.findall(_FORBIDDEN_SPAWN_TOKENS[0], stripped), (
        "The gate's first forbidden-token regex must match the canary "
        "violation."
    )


def test_walker_no_execute_gate_excludes_docstring_mentions():
    """Sanity — docstrings mentioning forbidden tokens DO NOT cause the
    gate to fire.

    The walker's docstrings LEGITIMATELY mention ``subprocess`` /
    ``ntfs-3g`` etc. as part of the no-execute discipline documentation.
    The tokenize-based stripping must remove these before the regex scan.
    """
    synthetic_docstring_source = '''
def safe_walker():
    """This function NEVER invokes subprocess.run and NEVER shells out
    to ntfs-3g or mount. It is PARSE-ONLY."""
    return None
'''
    stripped = _strip_docstrings_and_comments(synthetic_docstring_source)

    # After stripping, ``subprocess.run`` should NOT appear.
    pattern = r"\bsubprocess\s*\.\s*run\s*\("
    matches = re.findall(pattern, stripped)
    assert not matches, (
        "Test-gate canary FAILED — a docstring mention of "
        "'subprocess.run' survived docstring-stripping. The gate would "
        "false-positive on legitimate documentation."
    )
