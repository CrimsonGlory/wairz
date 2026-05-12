"""Tests for the vendored python-sdb clean-room parser (Phase θ.D.A).

Critical tests:

- ``test_no_execute_in_vendor`` — Rule #36 structural gate. The
  vendored parser MUST contain ZERO process-spawn primitives. The
  consumer (``app.services.sdb_walker``) treats parsed entries as
  DATA only; passing them to ``sdbinst.exe`` / ``AppHelp.dll`` /
  ``Mscoree.dll`` etc. would defeat the security boundary.

- ``test_no_execute_across_entire_package`` — Belt-and-suspenders.
  Scans every file in the vendor directory (not just ``__init__.py``)
  for forbidden primitives, so future contributors can't slip an
  execution primitive into a sibling module.

Round-trip tests construct synthetic .sdb byte sequences from the
documented format and assert that parse_sdb produces the expected
ParsedSDB shape.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest

from third_party.python_sdb import (
    SDB_HEADER_SIZE,
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
    InvalidSDBFileError,
    SDBApp,
    SDBPatch,
    SDBShim,
    parse_sdb,
    tag_name_for,
)

# ── Synthetic .sdb byte construction helpers ───────────────────────────────


def _utf16(s: str) -> bytes:
    """UTF-16-LE encode with trailing NUL."""
    return (s + "\x00").encode("utf-16-le")


def _emit_string_chunk(s: str) -> bytes:
    """Emit a TAG_STRINGTABLE_ITEM chunk for ``s``."""
    payload = _utf16(s)
    return struct.pack("<HI", TAG_STRINGTABLE_ITEM, len(payload)) + payload


def _emit_stringtable(strings: list[str]) -> tuple[bytes, dict[str, int]]:
    """Emit a TAG_STRINGTABLE LIST chunk with ``strings``.

    Returns (chunk_bytes, lookup_map) where lookup_map[s] is the
    relative offset into the LIST payload at which the STRING_ITEM
    chunk for ``s`` begins (this is the STRINGREF value to embed in
    consumer chunks).
    """
    body = b""
    offsets: dict[str, int] = {}
    for s in strings:
        offsets[s] = len(body)
        body += _emit_string_chunk(s)
    chunk = struct.pack("<HI", TAG_STRINGTABLE, len(body)) + body
    return chunk, offsets


def _emit_stringref(tag: int, stringref_offset: int) -> bytes:
    """Emit one STRINGREF chunk: 2-byte tag + 4-byte uint32 offset."""
    return struct.pack("<HI", tag, stringref_offset)


def _emit_list(tag: int, body: bytes) -> bytes:
    """Wrap ``body`` in a LIST chunk with ``tag``."""
    return struct.pack("<HI", tag, len(body)) + body


def _emit_binary(tag: int, data: bytes) -> bytes:
    """Emit a BINARY chunk with ``data``."""
    return struct.pack("<HI", tag, len(data)) + data


def _build_sdb(database_body: bytes, stringtable_chunk: bytes) -> bytes:
    """Build a complete .sdb file: header + STRINGTABLE + DATABASE."""
    header = struct.pack("<II", 0xDEADBEEF, 0xCAFEBABE) + SDB_MAGIC
    database_chunk = _emit_list(TAG_DATABASE, database_body)
    # Convention: STRINGTABLE first (so the parser populates the map
    # before walking DATABASE). The parser does TWO passes; layout
    # order doesn't matter, but we mirror the canonical Windows
    # layout for realism.
    return header + stringtable_chunk + database_chunk


# ── Rule #36 no-execute test gates ─────────────────────────────────────────


_VENDOR_DIR = Path(__file__).parent.parent / "third_party" / "python_sdb"


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


def test_no_execute_in_vendor():
    """Rule #36 central gate — the vendor __init__.py MUST NOT contain
    any process-spawn primitive that could execute parsed SDB
    payloads via Windows shim infrastructure."""
    source = (_VENDOR_DIR / "__init__.py").read_text()
    scrubbed = _strip_string_literals_and_comments(source)
    for pattern in _FORBIDDEN_EXEC_PATTERNS:
        match = re.search(pattern, scrubbed)
        assert match is None, (
            f"vendor __init__.py contains forbidden pattern "
            f"{pattern!r} at offset {match.start()}: "
            f"{scrubbed[max(0, match.start()-30):match.end()+30]!r}. "
            "Rule #36 no-execute discipline violated — .sdb files "
            "are attacker-controlled shim definitions and must NEVER "
            "be loaded by Windows shim infrastructure."
        )


def test_no_execute_across_entire_package():
    """Belt-and-suspenders — scan every .py file in the vendor
    directory, not just __init__.py."""
    for py in _VENDOR_DIR.rglob("*.py"):
        source = py.read_text()
        scrubbed = _strip_string_literals_and_comments(source)
        for pattern in _FORBIDDEN_EXEC_PATTERNS:
            match = re.search(pattern, scrubbed)
            assert match is None, (
                f"{py.relative_to(_VENDOR_DIR.parent)} contains "
                f"forbidden pattern {pattern!r} — Rule #36 violation."
            )


# ── Magic / header tests ────────────────────────────────────────────────────


def test_parse_sdb_rejects_wrong_magic():
    """Wrong magic at offset 8 → InvalidSDBFileError."""
    bad = b"\x00" * 8 + b"WRONG" + b"\x00" * 100
    with pytest.raises(InvalidSDBFileError):
        parse_sdb(bad)


def test_parse_sdb_rejects_too_small():
    """File shorter than SDB_HEADER_SIZE → InvalidSDBFileError."""
    with pytest.raises(InvalidSDBFileError):
        parse_sdb(b"\x00\x00\x00\x00\x00")


def test_parse_sdb_rejects_too_large():
    """File larger than max_file_bytes → InvalidSDBFileError."""
    huge = b"\x00" * 8 + SDB_MAGIC + b"\x00" * 10
    with pytest.raises(InvalidSDBFileError):
        parse_sdb(huge, max_file_bytes=10)


def test_parse_sdb_empty_after_header_returns_empty_parse():
    """Header-only file (no chunks) → empty ParsedSDB, not raise."""
    header = struct.pack("<II", 0xDEADBEEF, 0xCAFEBABE) + SDB_MAGIC
    result = parse_sdb(header)
    assert result.apps == ()
    assert result.orphan_shims == ()
    assert result.orphan_patches == ()


# ── tag_name_for tests ──────────────────────────────────────────────────────


def test_tag_name_for_known_tags():
    assert tag_name_for(TAG_APP) == "TAG_APP"
    assert tag_name_for(TAG_SHIM) == "TAG_SHIM"
    assert tag_name_for(TAG_PATCH) == "TAG_PATCH"
    assert tag_name_for(TAG_NAME) == "TAG_NAME"
    assert tag_name_for(TAG_DATABASE) == "TAG_DATABASE"


def test_tag_name_for_unknown_returns_hex_marker():
    assert tag_name_for(0xBABE) == "TAG_UNKNOWN_0xBABE"


# ── End-to-end parse_sdb tests on synthetic byte streams ──────────────────


def test_parse_sdb_single_app_with_inject_dll_shim():
    """A single APP with an InjectDll shim — the canonical
    attacker tradecraft shape for T1546.011."""
    strings = [
        "MyApp Compatibility Fix",  # TAG_NAME for APP
        "EvilApp",                   # TAG_APP_NAME for APP
        "Evil Inc",                  # TAG_VENDOR for APP
        "myapp.exe",                 # TAG_NAME for EXE
        "InjectDll",                 # TAG_NAME for SHIM
        "attacker.dll",              # TAG_DLLFILE for SHIM
        "Inject malicious DLL",      # TAG_DESCRIPTION for SHIM
    ]
    stringtable, refs = _emit_stringtable(strings)

    exe_body = _emit_stringref(TAG_NAME, refs["myapp.exe"])
    shim_body = (
        _emit_stringref(TAG_NAME, refs["InjectDll"])
        + _emit_stringref(TAG_DLLFILE, refs["attacker.dll"])
    )
    app_body = (
        _emit_stringref(TAG_NAME, refs["MyApp Compatibility Fix"])
        + _emit_stringref(TAG_APP_NAME, refs["EvilApp"])
        + _emit_list(TAG_EXE, exe_body)
        + _emit_list(TAG_SHIM, shim_body)
    )
    database_body = _emit_list(TAG_APP, app_body)

    sdb_bytes = _build_sdb(database_body, stringtable)
    result = parse_sdb(sdb_bytes)

    assert len(result.apps) == 1
    app = result.apps[0]
    assert app.name == "MyApp Compatibility Fix"
    assert app.app_name == "EvilApp"
    assert app.exes == ("myapp.exe",)
    assert len(app.shims) == 1
    shim = app.shims[0]
    assert shim.name == "InjectDll"
    assert shim.module == "attacker.dll"
    assert result.stringtable_entries == len(strings)
    assert not result.truncated


def test_parse_sdb_app_with_redirect_exe_shim():
    """RedirectEXE shim — the most direct attacker primitive (replaces
    the application entirely)."""
    strings = [
        "Notepad Fix",
        "notepad.exe",
        "RedirectEXE",
        "redirect.dll",
        "calc.exe",
    ]
    stringtable, refs = _emit_stringtable(strings)
    exe_body = _emit_stringref(TAG_NAME, refs["notepad.exe"])
    shim_body = (
        _emit_stringref(TAG_NAME, refs["RedirectEXE"])
        + _emit_stringref(TAG_DLLFILE, refs["redirect.dll"])
        + _emit_stringref(TAG_COMMAND_LINE, refs["calc.exe"])
    )
    app_body = (
        _emit_stringref(TAG_NAME, refs["Notepad Fix"])
        + _emit_list(TAG_EXE, exe_body)
        + _emit_list(TAG_SHIM, shim_body)
    )
    database_body = _emit_list(TAG_APP, app_body)
    result = parse_sdb(_build_sdb(database_body, stringtable))
    assert len(result.apps) == 1
    shim = result.apps[0].shims[0]
    assert shim.name == "RedirectEXE"
    assert shim.module == "redirect.dll"
    assert shim.command_line == "calc.exe"


def test_parse_sdb_app_with_patch_emits_patch_bits_hex():
    """A PATCH entry emits patch_bits as hex of TAG_PATCH_BITS."""
    strings = ["MyApp", "BadPatch", "myapp.exe"]
    stringtable, refs = _emit_stringtable(strings)
    patch_bits = b"\xDE\xAD\xBE\xEF\xCA\xFE"
    patch_body = (
        _emit_stringref(TAG_NAME, refs["BadPatch"])
        + _emit_binary(TAG_PATCH_BITS, patch_bits)
    )
    exe_body = _emit_stringref(TAG_NAME, refs["myapp.exe"])
    app_body = (
        _emit_stringref(TAG_NAME, refs["MyApp"])
        + _emit_list(TAG_EXE, exe_body)
        + _emit_list(TAG_PATCH, patch_body)
    )
    database_body = _emit_list(TAG_APP, app_body)
    result = parse_sdb(_build_sdb(database_body, stringtable))
    assert len(result.apps) == 1
    patches = result.apps[0].patches
    assert len(patches) == 1
    assert patches[0].name == "BadPatch"
    assert patches[0].patch_bits_hex == "deadbeefcafe"
    assert patches[0].patch_bits_size == len(patch_bits)


def test_parse_sdb_multiple_apps_and_orphan_shim():
    """Multiple APPS + a top-level orphan SHIM (uncommon but legitimate
    for Library-only shims)."""
    strings = ["App1", "App2", "app1.exe", "app2.exe", "OrphanShim"]
    stringtable, refs = _emit_stringtable(strings)
    app1_body = (
        _emit_stringref(TAG_NAME, refs["App1"])
        + _emit_list(TAG_EXE, _emit_stringref(TAG_NAME, refs["app1.exe"]))
    )
    app2_body = (
        _emit_stringref(TAG_NAME, refs["App2"])
        + _emit_list(TAG_EXE, _emit_stringref(TAG_NAME, refs["app2.exe"]))
    )
    orphan_shim_body = _emit_stringref(TAG_NAME, refs["OrphanShim"])
    database_body = (
        _emit_list(TAG_APP, app1_body)
        + _emit_list(TAG_APP, app2_body)
        + _emit_list(TAG_SHIM, orphan_shim_body)
    )
    result = parse_sdb(_build_sdb(database_body, stringtable))
    assert len(result.apps) == 2
    assert result.apps[0].name == "App1"
    assert result.apps[1].name == "App2"
    assert len(result.orphan_shims) == 1
    assert result.orphan_shims[0].name == "OrphanShim"


def test_parse_sdb_max_chunks_cap_truncates():
    """Tight chunk-budget triggers truncated=True without crashing."""
    strings = ["MyApp", "myapp.exe", "InjectDll", "attacker.dll"]
    stringtable, refs = _emit_stringtable(strings)
    shim_body = (
        _emit_stringref(TAG_NAME, refs["InjectDll"])
        + _emit_stringref(TAG_DLLFILE, refs["attacker.dll"])
    )
    app_body = (
        _emit_stringref(TAG_NAME, refs["MyApp"])
        + _emit_list(TAG_EXE, _emit_stringref(TAG_NAME, refs["myapp.exe"]))
        + _emit_list(TAG_SHIM, shim_body)
    )
    database_body = _emit_list(TAG_APP, app_body)
    result = parse_sdb(
        _build_sdb(database_body, stringtable),
        max_chunks=3,  # Below what the parse needs
    )
    assert result.truncated is True


def test_parse_sdb_unparseable_stringref_yields_empty_value():
    """STRINGREF pointing at a non-existent offset → empty string,
    not raise."""
    stringtable, refs = _emit_stringtable(["MyApp"])
    # Use a STRINGREF offset 999999 that's far outside the
    # stringtable.
    app_body = (
        struct.pack("<HI", TAG_NAME, 999999)
        + _emit_list(TAG_EXE, struct.pack("<HI", TAG_NAME, 999999))
    )
    database_body = _emit_list(TAG_APP, app_body)
    result = parse_sdb(_build_sdb(database_body, stringtable))
    assert len(result.apps) == 1
    assert result.apps[0].name == ""


def test_parse_sdb_dataclasses_are_frozen():
    """ParsedSDB / SDBApp / SDBShim / SDBPatch are dataclass(frozen=True)
    so callers can use them as dict keys / set members."""
    shim = SDBShim(name="x", description="", module="", command_line="")
    with pytest.raises(AttributeError):
        shim.name = "y"  # type: ignore[misc]
    patch = SDBPatch(name="x", patch_bits_hex="", patch_bits_size=0)
    with pytest.raises(AttributeError):
        patch.name = "y"  # type: ignore[misc]
    app = SDBApp(
        name="a", app_name="b", vendor="c", exes=(), shims=(), patches=()
    )
    with pytest.raises(AttributeError):
        app.name = "z"  # type: ignore[misc]


# ── Public API surface tests ────────────────────────────────────────────────


def test_public_api_exports():
    """The public ``__all__`` exports the documented surface."""
    from third_party import python_sdb

    expected = {
        "InvalidSDBFileError",
        "ParsedSDB",
        "SDBApp",
        "SDBPatch",
        "SDBShim",
        "parse_sdb",
        "tag_name_for",
        "SDB_MAGIC",
        "SDB_HEADER_SIZE",
    }
    actual = set(python_sdb.__all__)
    missing = expected - actual
    assert not missing, f"public API missing exports: {missing}"
