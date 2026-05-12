"""Phase κ.D.C — tests for the Windows DPAPI master-key PARSE-ONLY
METADATA walker.

Covers:

- Pure helpers: ``is_admin_creator_sid``, ``extract_dpapi_path_info``,
  ``looks_like_dpapi_master_key_file``, ``build_anomaly_flags``.
- The binary parser: ``parse_master_key_header`` end-to-end on
  synthesised master-key file blobs.
- Rule #35b live canary: ``_do_dpapi_walk`` against a real ORM session
  via ``make_live_db()`` (no Docker dependency; no DNS hop).
- **Rule #36 + Rule #45 PARSE-ONLY test gate** — the walker source MUST
  NOT contain ANY decryption / DPAPI-invocation tokens in CODE (we
  strip docstrings + comments before scanning).
- **Test-gate canary** — confirms the gate ACTUALLY fires on a
  synthetic violation (Rule #17 silent-CLI-exit analog).
"""
from __future__ import annotations

import io
import pathlib
import re
import struct
import tokenize

import pytest

from app.models import Firmware, Project
from app.models.windows_dpapi_master_keys import (
    WindowsDpapiMasterKey,  # noqa: F401 — load ORM into Base.metadata for live-db
)
from app.services.dpapi_walker import (
    _do_dpapi_walk,
    build_anomaly_flags,
    extract_dpapi_path_info,
    is_admin_creator_sid,
    looks_like_dpapi_master_key_file,
    parse_master_key_header,
)
from tests._live_db import make_live_db

# ── is_admin_creator_sid ─────────────────────────────────────────────────────


def test_is_admin_creator_sid_rid_500():
    """Built-in Administrator (RID 500)."""
    assert is_admin_creator_sid(
        "S-1-5-21-1234567890-9876543210-1111111111-500"
    )


def test_is_admin_creator_sid_rid_512():
    """Domain Admins."""
    assert is_admin_creator_sid(
        "S-1-5-21-1234567890-9876543210-1111111111-512"
    )


def test_is_admin_creator_sid_rid_519():
    """Enterprise Admins."""
    assert is_admin_creator_sid(
        "S-1-5-21-1234567890-9876543210-1111111111-519"
    )


def test_is_admin_creator_sid_local_system():
    """S-1-5-18 = Local System."""
    assert is_admin_creator_sid("S-1-5-18")


def test_is_admin_creator_sid_regular_user_not_admin():
    """RID 1001 = first regular user, NOT admin."""
    assert not is_admin_creator_sid(
        "S-1-5-21-1234567890-9876543210-1111111111-1001"
    )


def test_is_admin_creator_sid_none():
    assert not is_admin_creator_sid(None)


def test_is_admin_creator_sid_empty():
    assert not is_admin_creator_sid("")


# ── extract_dpapi_path_info ──────────────────────────────────────────────────


def test_extract_dpapi_path_canonical():
    """Standard DPAPI master-key path → all fields extracted."""
    p = (
        "/extracted/Users/alice/AppData/Roaming/Microsoft/Protect/"
        "S-1-5-21-1234567890-9876543210-1111111111-1001/"
        "e0f1a2b3-c4d5-6789-abcd-ef0123456789"
    )
    info = extract_dpapi_path_info(p)
    assert info["user"] == "alice"
    assert info["creator_sid"] == (
        "S-1-5-21-1234567890-9876543210-1111111111-1001"
    )
    assert info["master_key_guid"] == (
        "e0f1a2b3-c4d5-6789-abcd-ef0123456789"
    )


def test_extract_dpapi_path_with_backslashes():
    """Windows-style backslashes also match."""
    p = (
        "C:\\Windows\\Users\\bob\\AppData\\Roaming\\Microsoft\\Protect\\"
        "S-1-5-21-1-2-3-1002\\"
        "deadbeef-1234-5678-90ab-cdef01234567"
    )
    info = extract_dpapi_path_info(p)
    assert info["user"] == "bob"
    assert info["creator_sid"] == "S-1-5-21-1-2-3-1002"
    assert info["master_key_guid"] == (
        "deadbeef-1234-5678-90ab-cdef01234567"
    )


def test_extract_dpapi_path_non_dpapi_returns_none():
    """A non-DPAPI path returns None for all fields."""
    p = "/some/random/path/not_a_dpapi_file.txt"
    info = extract_dpapi_path_info(p)
    assert info["user"] is None
    assert info["creator_sid"] is None
    assert info["master_key_guid"] is None


def test_extract_dpapi_path_missing_guid_basename_returns_none():
    """A path under Protect/SID/ but not ending in a GUID returns None."""
    p = (
        "/extracted/Users/alice/AppData/Roaming/Microsoft/Protect/"
        "S-1-5-21-1-2-3-1001/Preferred"
    )
    info = extract_dpapi_path_info(p)
    assert info["master_key_guid"] is None


def test_extract_dpapi_path_uppercase_guid_normalized():
    """Uppercase GUID is lowercased on output."""
    p = (
        "/extracted/Users/alice/AppData/Roaming/Microsoft/Protect/"
        "S-1-5-21-1-2-3-1001/"
        "DEADBEEF-1234-5678-90AB-CDEF01234567"
    )
    info = extract_dpapi_path_info(p)
    assert info["master_key_guid"] == (
        "deadbeef-1234-5678-90ab-cdef01234567"
    )


# ── looks_like_dpapi_master_key_file ─────────────────────────────────────────


def test_looks_like_dpapi_guid_basename_true():
    assert looks_like_dpapi_master_key_file(
        "/some/path/e0f1a2b3-c4d5-6789-abcd-ef0123456789"
    )


def test_looks_like_dpapi_guid_basename_uppercase_true():
    assert looks_like_dpapi_master_key_file(
        "/some/path/DEADBEEF-1234-5678-90AB-CDEF01234567"
    )


def test_looks_like_dpapi_not_a_guid_false():
    assert not looks_like_dpapi_master_key_file(
        "/some/path/Preferred"
    )


def test_looks_like_dpapi_guid_with_extension_false():
    """GUID with an extension is NOT a master-key file."""
    assert not looks_like_dpapi_master_key_file(
        "/some/path/e0f1a2b3-c4d5-6789-abcd-ef0123456789.bak"
    )


# ── parse_master_key_header ──────────────────────────────────────────────────


def _build_master_key_blob(
    *,
    version: int = 2,
    flags: int = 0,
    master_key_size: int = 200,
    backup_key_size: int = 0,
    cred_hist_size: int = 0,
    domain_key_size: int = 0,
    iterations: int = 8000,
    include_body_preamble: bool = True,
) -> bytes:
    """Build a synthetic master-key file blob for testing.

    Layout (per the file format docstring):
      0x00 version (DWORD)
      0x04 unused1
      0x08 unused2
      0x0c guid_text[72]
      0x54 unused3
      0x58 flags (DWORD)
      0x5c policy (QWORD)
      0x64 master_key_len (QWORD)
      0x6c backup_key_len (QWORD)
      0x74 cred_hist_len (QWORD)
      0x7c domain_key_len (QWORD)
      0x84 onwards: body sections
    """
    header = bytearray(0x84)
    struct.pack_into("<I", header, 0x00, version)
    struct.pack_into("<I", header, 0x58, flags)
    struct.pack_into("<Q", header, 0x64, master_key_size)
    struct.pack_into("<Q", header, 0x6c, backup_key_size)
    struct.pack_into("<Q", header, 0x74, cred_hist_size)
    struct.pack_into("<Q", header, 0x7c, domain_key_size)

    body = b""
    if include_body_preamble and master_key_size >= 32:
        # Body preamble: version(4) + salt(16) + iterations(4) +
        # hash_alg(4) + crypt_alg(4) = 32 bytes.
        preamble = bytearray(32)
        struct.pack_into("<I", preamble, 0, 1)  # body version
        # salt at bytes 4-20 (we just zero it for fixture purposes —
        # the walker ONLY records the SIZE, never the bytes).
        struct.pack_into("<I", preamble, 20, iterations)
        body = bytes(preamble)
        # Add padding to reach the master_key_size declared in header.
        if master_key_size > 32:
            body += b"\x00" * (master_key_size - 32)

    return bytes(header) + body


def test_parse_master_key_header_canonical_v2():
    """Standard Win10/11 v2 master-key file → all fields extracted."""
    blob = _build_master_key_blob(
        version=2,
        flags=0,
        master_key_size=200,
        backup_key_size=0,
        cred_hist_size=24,
        domain_key_size=0,
        iterations=20000,
    )
    fields, errors = parse_master_key_header(blob)
    assert errors == []
    assert fields["version"] == 2
    assert fields["flags"] == 0
    assert fields["master_key_size"] == 200
    assert fields["backup_key_size"] == 0
    assert fields["cred_hist_size"] == 24
    assert fields["domain_key_size"] == 0
    assert fields["hmac_iterations"] == 20000
    assert fields["salt_size"] == 16
    assert fields["has_body_preamble"] is True


def test_parse_master_key_header_v1():
    """Win7-era v1 master-key file is also accepted."""
    blob = _build_master_key_blob(version=1, iterations=8000)
    fields, errors = parse_master_key_header(blob)
    assert errors == []
    assert fields["version"] == 1
    assert fields["hmac_iterations"] == 8000


def test_parse_master_key_header_invalid_version_rejected():
    """Version != 1 or 2 → defensive rejection with error."""
    blob = _build_master_key_blob(version=99)
    fields, errors = parse_master_key_header(blob)
    assert fields == {}
    assert errors
    assert any("unexpected version" in e for e in errors)


def test_parse_master_key_header_too_short():
    """Blob shorter than 0x84 returns error."""
    blob = b"\x00" * 10
    fields, errors = parse_master_key_header(blob)
    assert fields == {}
    assert errors
    assert any("too short" in e for e in errors)


def test_parse_master_key_header_no_body_preamble():
    """master_key_size == 0 → no body preamble, fields still parsed."""
    blob = _build_master_key_blob(
        version=2,
        master_key_size=0,
        include_body_preamble=False,
    )
    fields, errors = parse_master_key_header(blob)
    assert errors == []
    assert fields["master_key_size"] == 0
    assert fields["hmac_iterations"] is None
    assert fields["salt_size"] is None
    assert fields["has_body_preamble"] is False


def test_parse_master_key_header_records_size_not_salt():
    """Critical: the parser records salt_size = 16 (constant), NEVER
    extracts the salt bytes themselves.

    Rule #45 boundary — exposing salt bytes would aid offline cracking.
    """
    # Build with KNOWN salt bytes — verify they don't leak into output.
    blob = _build_master_key_blob(iterations=8000)
    # Stamp a non-zero salt pattern in the body to be sure.
    blob_mut = bytearray(blob)
    for i in range(16):
        blob_mut[0x84 + 4 + i] = 0xAB  # canary byte pattern
    fields, _errors = parse_master_key_header(bytes(blob_mut))
    # salt_size is a SIZE constant; no bytes leaked.
    assert fields["salt_size"] == 16
    # And no field named "salt" or "salt_bytes" exists.
    assert "salt" not in fields
    assert "salt_bytes" not in fields


# ── build_anomaly_flags ──────────────────────────────────────────────────────


def test_build_anomaly_flags_clean_user():
    """Regular user, normal-sized file, no parse error → all False."""
    known = frozenset(["S-1-5-21-1-2-3-1001"])
    flags = build_anomaly_flags(
        creator_sid="S-1-5-21-1-2-3-1001",
        file_size_bytes=800,
        parse_error=False,
        known_user_sids=known,
    )
    assert flags["orphaned_masterkey"] is False
    assert flags["admin_creator_sid"] is False
    assert flags["large_masterkey"] is False
    assert flags["parse_error"] is False


def test_build_anomaly_flags_orphaned():
    """Creator SID not in known set → orphaned_masterkey True."""
    known = frozenset(["S-1-5-21-1-2-3-1001"])
    flags = build_anomaly_flags(
        creator_sid="S-1-5-21-1-2-3-9999",  # not in known set
        file_size_bytes=800,
        parse_error=False,
        known_user_sids=known,
    )
    assert flags["orphaned_masterkey"] is True


def test_build_anomaly_flags_admin_creator():
    """Admin RID match → admin_creator_sid True."""
    flags = build_anomaly_flags(
        creator_sid="S-1-5-21-1-2-3-500",  # Built-in Admin
        file_size_bytes=800,
        parse_error=False,
        known_user_sids=None,
    )
    assert flags["admin_creator_sid"] is True


def test_build_anomaly_flags_local_system_admin():
    flags = build_anomaly_flags(
        creator_sid="S-1-5-18",
        file_size_bytes=800,
        parse_error=False,
        known_user_sids=None,
    )
    assert flags["admin_creator_sid"] is True


def test_build_anomaly_flags_large():
    """File size > 2048 → large_masterkey True."""
    flags = build_anomaly_flags(
        creator_sid="S-1-5-21-1-2-3-1001",
        file_size_bytes=4096,
        parse_error=False,
        known_user_sids=None,
    )
    assert flags["large_masterkey"] is True


def test_build_anomaly_flags_parse_error_carried():
    flags = build_anomaly_flags(
        creator_sid=None,
        file_size_bytes=None,
        parse_error=True,
        known_user_sids=None,
    )
    assert flags["parse_error"] is True


def test_build_anomaly_flags_no_orphan_signal_without_known_sids():
    """orphaned_masterkey is False when known_user_sids is None."""
    flags = build_anomaly_flags(
        creator_sid="S-1-5-21-1-2-3-1001",
        file_size_bytes=800,
        parse_error=False,
        known_user_sids=None,
    )
    assert flags["orphaned_masterkey"] is False


# ── Rule #35b live canary — end-to-end via make_live_db ──────────────────────


@pytest.mark.asyncio
async def test_do_dpapi_walk_no_files_returns_empty(tmp_path):
    """No DPAPI master-key files under detection roots → empty aggregate."""
    async with make_live_db() as db:
        project = Project(
            name="test-kappa-d", description="κ.D.C live canary empty"
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

        result = await _do_dpapi_walk(db, firmware.id)
        assert result["files_scanned"] == 0
        assert result["files_persisted"] == 0
        assert result["anomaly_total"] == 0


@pytest.mark.asyncio
async def test_do_dpapi_walk_missing_firmware_returns_empty(tmp_path):
    """Missing firmware → empty result (defensive return)."""
    import uuid

    async with make_live_db() as db:
        result = await _do_dpapi_walk(db, uuid.uuid4())
        assert result["files_scanned"] == 0
        assert result["files_persisted"] == 0


@pytest.mark.asyncio
async def test_do_dpapi_walk_persists_master_key_file(tmp_path):
    """Synthesise a master-key file at a canonical DPAPI path; verify
    the walker persists one WindowsDpapiMasterKey row with correct
    METADATA-ONLY fields (no salt bytes leaked)."""
    # Build the canonical directory chain.
    sid = "S-1-5-21-1234567890-9876543210-1111111111-1001"
    guid = "e0f1a2b3-c4d5-6789-abcd-ef0123456789"
    protect_dir = (
        tmp_path
        / "Users" / "alice" / "AppData" / "Roaming" / "Microsoft"
        / "Protect" / sid
    )
    protect_dir.mkdir(parents=True)
    mk_file = protect_dir / guid
    blob = _build_master_key_blob(
        version=2,
        master_key_size=200,
        cred_hist_size=24,
        iterations=20000,
    )
    mk_file.write_bytes(blob)

    async with make_live_db() as db:
        project = Project(
            name="test-kappa-d-persist",
            description="κ.D.C live canary persist",
        )
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="dpapi.bin",
            storage_path="/tmp/dpapi",
            file_size=0,
            sha256="1" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.flush()

        result = await _do_dpapi_walk(db, firmware.id)
        assert result["files_scanned"] == 1
        assert result["files_persisted"] == 1

        # SELECT the persisted row and inspect.
        from sqlalchemy import select as sa_select
        rows = (
            await db.execute(
                sa_select(WindowsDpapiMasterKey).where(
                    WindowsDpapiMasterKey.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        row = rows[0]
        assert row.master_key_guid == guid
        assert row.creator_sid == sid
        assert row.flags == 0
        assert row.hmac_iterations == 20000
        # CRITICAL Rule #45 boundary — salt_size is a constant (16),
        # NOT bytes.
        assert row.salt_size == 16
        # The ORM column doesn't even have a salt-bytes field — verify.
        assert not hasattr(row, "salt_bytes")
        assert not hasattr(row, "salt")
        # Verify other parsed metadata.
        assert row.master_key_size == 200
        assert row.cred_hist_size == 24
        assert row.file_size_bytes is not None
        assert row.last_modified_ts is not None
        assert row.parse_error is None


# ── Rule #36 + Rule #45 PARSE-ONLY test gate (CAMPAIGN-DEFINING) ─────────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Remove docstrings, # comments, and string literals from Python
    source so we can scan for ACTUAL code references.

    Returns the STRING tokens joined — so only CODE tokens are present
    in the output. This is what the test gate scans against.
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


# Synthetic violation canary constant — used by the canary test below.
# This string MUST NOT appear unwrapped in walker code; it appears
# wrapped in a string literal here so the gate's docstring-stripping
# would NOT see it. The canary test injects this string into a synthetic
# source body to confirm the gate fires.
_FORBIDDEN_CANARY = "decrypt"


# The forbidden-token list scanned by the gate.
#
# IMPORTANT — the gate scans the OUTPUT of _strip_docstrings_and_comments,
# which joins Python tokens with spaces. So `obj.decrypt(b"x")` in
# real source becomes `obj . decrypt ( )` after stripping. Regexes
# below MUST be tolerant of single spaces between tokens that appear
# adjacent in source (i.e. ``\s*`` between every operator + name pair
# that mattered as adjacent in source).
_FORBIDDEN_DECRYPT_TOKENS: tuple[str, ...] = (
    # Bare ``.decrypt(`` method call — catches `obj.decrypt(blob)`.
    # Tokens get space-joined, so ``\.\s*decrypt\s*\(`` matches
    # ``. decrypt (`` in the stripped output.
    r"\.\s*decrypt\s*\(",
    # DPAPI primitives — \b boundaries hold across the space-joined
    # output because the name appears whole.
    r"\bCryptUnprotectData\b",
    r"\bCryptProtectData\b",
    # cryptography.fernet imports / usage.
    r"from\s+cryptography\s*\.\s*fernet",
    r"cryptography\s*\.\s*fernet\s*\.",
    # asn1crypto cryptographic primitives.
    r"asn1crypto\s*\.\s*cms\s*\.",
    r"asn1crypto\s*\.\s*algos\s*\.",
    # Common decrypt API call patterns.
    r"\bdecrypt_fek\b",
    r"\bdecrypt_master_key\b",
    r"\bextract_fek\b",
    # impacket.dpapi.MasterKey().decrypt() — class import IS OK but
    # the .decrypt() method call (matched above) is forbidden. The
    # MasterKey class itself is NOT imported as that pulls in the
    # decryption module.
    r"impacket\s*\.\s*dpapi\s*\.\s*MasterKey\s*\(",
    # pyDes / pycryptodome decryption entry points.
    r"\bpyDes\b",
    r"from\s+Crypto\s*\.\s*Cipher",
    r"Crypto\s*\.\s*Cipher\s*\.",
)


def test_walker_no_decrypt():
    """Rule #36 + Rule #45 — the dpapi_walker.py CODE (not docstrings
    /comments) MUST NOT invoke any decryption / DPAPI / cryptographic
    primitive.

    PARSE-ONLY discipline is the CAMPAIGN-DEFINING constraint for κ.D.
    The walker is a pure metadata parser; nothing should decrypt the
    parsed data.

    Note: docstrings and comments LEGITIMATELY mention forbidden
    primitives (e.g. "NEVER invokes CryptUnprotectData") — we strip
    them before scanning so the test catches actual code references
    only.
    """
    raw_source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "dpapi_walker.py"
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
            f"Rule #36 violation in dpapi_walker.py CODE — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke spawn primitives against extracted artefacts."
        )

    # Rule #45 EXTENSION — no decryption / DPAPI / FEK-handling tokens
    # in EXECUTABLE CODE.
    for pattern in _FORBIDDEN_DECRYPT_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #45 violation in dpapi_walker.py CODE — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "attempt decryption, invoke DPAPI, or handle master-key "
            "decryption. PARSE-ONLY METADATA only."
        )

    # Belt-and-braces: assert no salt-bytes persistence path exists.
    # The ORM column is salt_size (an integer), never salt_bytes or
    # salt (bytes). Scan ORIGINAL source — these patterns are clearly
    # executable code, not prose.
    persistence_anti_tokens = (
        r"\brow\.salt_bytes\s*=",
        r"\brow\.salt\s*=",
        r"WindowsDpapiMasterKey\([^)]*salt_bytes\s*=",
        r"WindowsDpapiMasterKey\([^)]*\bsalt\s*=",
    )
    for pattern in persistence_anti_tokens:
        matches = re.findall(pattern, raw_source)
        assert not matches, (
            f"Rule #45 violation in dpapi_walker.py — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "persist the salt bytes anywhere — only the salt_size "
            "constant."
        )


def test_walker_no_decrypt_gate_actually_fires():
    """Rule #17 silent-CLI-exit analog — verify the test gate ACTUALLY
    fires on a synthetic violation.

    If we trust ``test_walker_no_decrypt`` without confirming it
    catches violations, the gate could silently pass on legitimate
    violations (e.g. due to a tokenize bug, regex typo, etc.). This
    canary builds a synthetic source containing a forbidden CODE token
    (NOT inside a docstring/comment) and confirms:

    1. ``_strip_docstrings_and_comments`` preserves the code token.
    2. The forbidden-token regex matches the stripped source.

    The synthetic source is constructed via concatenation rather than
    an f-string to avoid being a single STRING token that
    ``_strip_docstrings_and_comments`` would drop entirely.
    """
    # Construct the synthetic source as a CONCATENATION of two lines.
    # Both lines pass through the Python parser as actual code
    # (not as string literals) because they're at module scope when
    # passed to tokenize.generate_tokens.
    line_a = "def bad_walker():\n"
    line_b = "    obj = SomeClass()\n"
    # The CODE token below — `obj.decrypt(b"x")` — survives tokenize
    # stripping because it's NOT a string literal in the input to
    # generate_tokens; tokenize sees `obj` (NAME), `.` (OP),
    # `decrypt` (NAME), `(` (OP), `b"x"` (STRING), `)` (OP).
    line_c = "    obj." + _FORBIDDEN_CANARY + '(b"x")\n'
    line_d = "    return None\n"
    synthetic_source = line_a + line_b + line_c + line_d

    # Strip docstrings/comments — the canary call SHOULD survive
    # because `obj.decrypt(b"x")` is CODE tokens, not a string literal.
    stripped = _strip_docstrings_and_comments(synthetic_source)

    # The gate scans for `.\s*decrypt\s*\(` pattern (tolerant of
    # token-join whitespace). Verify the synthetic source WOULD match.
    pattern = r"\.\s*decrypt\s*\("
    matches = re.findall(pattern, stripped)
    assert matches, (
        f"Test-gate canary FAILED — the synthetic violation "
        f"'{_FORBIDDEN_CANARY}' did NOT trigger the forbidden-token "
        f"regex {pattern!r}. stripped={stripped!r}. The gate is broken "
        "or the canary is miscalibrated. Without a working canary, "
        "test_walker_no_decrypt could silently pass on real violations."
    )
    # Also verify the canary literal IS the forbidden token we expect.
    assert _FORBIDDEN_CANARY == "decrypt", (
        "The canary constant must equal 'decrypt' so the .decrypt( "
        "regex catches it."
    )
    # Final correctness check — the EXACT regex from the gate's
    # _FORBIDDEN_DECRYPT_TOKENS list must also match.
    assert re.findall(_FORBIDDEN_DECRYPT_TOKENS[0], stripped), (
        "The gate's first forbidden-token regex must match the canary "
        "violation."
    )


def test_walker_no_decrypt_gate_excludes_docstring_mentions():
    """Sanity check — docstrings mentioning forbidden tokens DO NOT
    cause the gate to fire.

    The walker's docstrings LEGITIMATELY mention 'decrypt' /
    'CryptUnprotectData' etc. as part of the PARSE-ONLY discipline
    documentation. The tokenize-based stripping must remove these
    before the regex scan.
    """
    synthetic_docstring_source = '''
def safe_walker():
    """This function NEVER invokes CryptUnprotectData and NEVER tries
    to decrypt anything. It is PARSE-ONLY."""
    return None
'''
    stripped = _strip_docstrings_and_comments(synthetic_docstring_source)

    # After stripping, the forbidden tokens should NOT appear in
    # `stripped`.
    pattern = r"\bCryptUnprotectData\b"
    matches = re.findall(pattern, stripped)
    assert not matches, (
        "Test-gate canary FAILED — a docstring mention of "
        "'CryptUnprotectData' survived docstring-stripping. The "
        "gate would false-positive on legitimate documentation."
    )
