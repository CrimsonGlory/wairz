"""Tests for the Phase ι.D.C Windows EFS DDF/DRF metadata walker triplet.

Rule #35b live canary — exercises the inner orchestrator
(``_do_efs_walk``) against a real test DB via ``make_live_db()`` for
the "no NTFS images present" path AND a synthetic on-disk tree path
that mocks dissect.ntfs to feed deterministic records into the row
builder.

Covers:
- SID binary parsing (parse_sid_binary).
- Thumbprint hex formatting (format_thumbprint_hex).
- Domain admin SID detection (is_domain_admin_sid).
- Unusual recovery agent detection (is_unusual_recovery_agent).
- Anomaly flag builder (build_anomaly_flags) — all 7 bit combinations.
- $EFS blob parser (parse_efs_blob) — header + DDF/DRF table extraction
  via synthetic structures.
- Inner orchestrator end-to-end via Rule #35b live canary — no NTFS
  images present + with-images mocked dissect.ntfs.
- Rule #36 + Rule #36 EXTENSION no-execute test gate — the source file
  does not invoke any spawn primitive AND does not invoke any
  decryption / DPAPI / FEK-handling primitive.
"""
from __future__ import annotations

import pathlib
import re
import struct
import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsEfsEncryptedFile
from app.services.efs_walker import (
    _do_efs_walk,
    build_anomaly_flags,
    format_thumbprint_hex,
    is_domain_admin_sid,
    is_unusual_recovery_agent,
    parse_efs_blob,
    parse_sid_binary,
)
from tests._live_db import make_live_db

# ── parse_sid_binary ─────────────────────────────────────────────────────────


def _build_sid_binary(revision: int, ia: int, subs: list[int]) -> bytes:
    """Build a SID in Windows binary form for testing."""
    out = bytes([revision, len(subs)])
    out += ia.to_bytes(6, "big")
    for s in subs:
        out += s.to_bytes(4, "little")
    return out


def test_parse_sid_binary_local_user():
    """S-1-5-21-1-2-3-1001 — typical domain/local user SID."""
    sid_bytes = _build_sid_binary(1, 5, [21, 1, 2, 3, 1001])
    assert parse_sid_binary(sid_bytes, 0) == "S-1-5-21-1-2-3-1001"


def test_parse_sid_binary_builtin_administrators():
    """S-1-5-32-544 — Built-in Administrators."""
    sid_bytes = _build_sid_binary(1, 5, [32, 544])
    assert parse_sid_binary(sid_bytes, 0) == "S-1-5-32-544"


def test_parse_sid_binary_system():
    """S-1-5-18 — Local System."""
    sid_bytes = _build_sid_binary(1, 5, [18])
    assert parse_sid_binary(sid_bytes, 0) == "S-1-5-18"


def test_parse_sid_binary_truncated_returns_none():
    """Truncated SID bytes return None."""
    assert parse_sid_binary(b"\x01\x02", 0) is None


def test_parse_sid_binary_invalid_subcount_returns_none():
    """SubAuthorityCount > 15 returns None (invalid SID)."""
    bad = bytes([1, 16]) + b"\x00" * 60
    assert parse_sid_binary(bad, 0) is None


def test_parse_sid_binary_zero_subcount_returns_none():
    """SubAuthorityCount = 0 returns None (invalid SID)."""
    bad = bytes([1, 0]) + b"\x00" * 60
    assert parse_sid_binary(bad, 0) is None


def test_parse_sid_binary_offset_into_data():
    """Parse at non-zero offset inside a larger buffer."""
    prefix = b"\xff" * 10
    sid_bytes = _build_sid_binary(1, 5, [32, 544])
    combined = prefix + sid_bytes
    assert parse_sid_binary(combined, 10) == "S-1-5-32-544"


def test_parse_sid_binary_negative_offset_returns_none():
    sid_bytes = _build_sid_binary(1, 5, [32, 544])
    assert parse_sid_binary(sid_bytes, -1) is None


# ── format_thumbprint_hex ────────────────────────────────────────────────────


def test_format_thumbprint_hex_20_bytes():
    raw = bytes(range(20))
    out = format_thumbprint_hex(raw)
    assert out == "000102030405060708090a0b0c0d0e0f10111213"
    assert len(out) == 40


def test_format_thumbprint_hex_truncates_oversize():
    """Trailing bytes beyond 20 are dropped."""
    raw = bytes(range(40))
    out = format_thumbprint_hex(raw)
    assert len(out) == 40  # First 20 bytes only.
    assert out.startswith("000102030405")


def test_format_thumbprint_hex_empty_input():
    assert format_thumbprint_hex(b"") == ""


def test_format_thumbprint_hex_short_input():
    """Less than 20 bytes returns whatever was there."""
    raw = b"\x01\x02\x03"
    assert format_thumbprint_hex(raw) == "010203"


# ── is_domain_admin_sid ──────────────────────────────────────────────────────


def test_is_domain_admin_sid_rid_512():
    assert is_domain_admin_sid("S-1-5-21-1234567890-9876543210-1111111111-512")


def test_is_domain_admin_sid_rid_519():
    assert is_domain_admin_sid("S-1-5-21-1234567890-9876543210-1111111111-519")


def test_is_domain_admin_sid_rid_500():
    """RID 500 = Built-in Administrator."""
    assert is_domain_admin_sid("S-1-5-21-1234567890-9876543210-1111111111-500")


def test_is_domain_admin_sid_regular_user():
    assert not is_domain_admin_sid(
        "S-1-5-21-1234567890-9876543210-1111111111-1001"
    )


def test_is_domain_admin_sid_none():
    assert not is_domain_admin_sid(None)


def test_is_domain_admin_sid_empty():
    assert not is_domain_admin_sid("")


# ── is_unusual_recovery_agent ────────────────────────────────────────────────


def test_is_unusual_recovery_agent_local_account_not_unusual():
    """A local/domain account SID (S-1-5-21-...) is NOT unusual."""
    assert not is_unusual_recovery_agent(
        "S-1-5-21-1234567890-9876543210-1111111111-500"
    )


def test_is_unusual_recovery_agent_administrators_not_unusual():
    assert not is_unusual_recovery_agent("S-1-5-32-544")


def test_is_unusual_recovery_agent_system_not_unusual():
    assert not is_unusual_recovery_agent("S-1-5-18")


def test_is_unusual_recovery_agent_anonymous_unusual():
    """S-1-5-7 (anonymous) is not in the standard recovery family."""
    assert is_unusual_recovery_agent("S-1-5-7")


def test_is_unusual_recovery_agent_null_is_suspicious():
    """A null SID is treated as suspicious."""
    assert is_unusual_recovery_agent(None)


# ── build_anomaly_flags ──────────────────────────────────────────────────────


def test_build_anomaly_flags_all_clean():
    """Single legitimate user, no DRF, no parse errors → all False."""
    ddf = [
        {
            "sid": "S-1-5-21-1-2-3-1001",
            "cert_thumbprint": "0123456789abcdef0123",
            "friendly_name": "alice",
        }
    ]
    flags = build_anomaly_flags(
        ddf_users=ddf,
        drf_recovery_agents=[],
        parse_error=False,
    )
    assert flags["orphaned_drf"] is False
    assert flags["unusual_recovery_agent"] is False
    assert flags["multiple_ddf_users"] is False
    assert flags["large_drf"] is False
    assert flags["cert_thumbprint_anomaly"] is False
    assert flags["domain_admin_in_ddf"] is False
    assert flags["parse_error"] is False


def test_build_anomaly_flags_orphaned_drf():
    """DRF without DDF — encrypted-via-recovery-only."""
    flags = build_anomaly_flags(
        ddf_users=[],
        drf_recovery_agents=[
            {
                "sid": "S-1-5-21-1-2-3-500",
                "cert_thumbprint": "abcdef" * 10,
                "friendly_name": None,
            }
        ],
        parse_error=False,
    )
    assert flags["orphaned_drf"] is True


def test_build_anomaly_flags_multiple_ddf_users():
    flags = build_anomaly_flags(
        ddf_users=[
            {"sid": "S-1-5-21-1-2-3-1001", "cert_thumbprint": "a" * 40},
            {"sid": "S-1-5-21-1-2-3-1002", "cert_thumbprint": "b" * 40},
        ],
        drf_recovery_agents=[],
        parse_error=False,
    )
    assert flags["multiple_ddf_users"] is True


def test_build_anomaly_flags_large_drf():
    """More than 2 recovery agents flagged."""
    drf = [
        {"sid": f"S-1-5-21-1-2-3-{500 + i}", "cert_thumbprint": "a" * 40}
        for i in range(3)
    ]
    flags = build_anomaly_flags(
        ddf_users=[
            {"sid": "S-1-5-21-1-2-3-1001", "cert_thumbprint": "a" * 40},
        ],
        drf_recovery_agents=drf,
        parse_error=False,
    )
    assert flags["large_drf"] is True


def test_build_anomaly_flags_unusual_recovery_agent():
    """Recovery agent SID not in standard EFS family."""
    flags = build_anomaly_flags(
        ddf_users=[
            {"sid": "S-1-5-21-1-2-3-1001", "cert_thumbprint": "a" * 40},
        ],
        drf_recovery_agents=[
            {"sid": "S-1-5-7", "cert_thumbprint": "b" * 40},  # Anonymous
        ],
        parse_error=False,
    )
    assert flags["unusual_recovery_agent"] is True


def test_build_anomaly_flags_domain_admin_in_ddf():
    flags = build_anomaly_flags(
        ddf_users=[
            {
                "sid": "S-1-5-21-1234567890-9876543210-1111111111-512",
                "cert_thumbprint": "a" * 40,
            }
        ],
        drf_recovery_agents=[],
        parse_error=False,
    )
    assert flags["domain_admin_in_ddf"] is True


def test_build_anomaly_flags_cert_thumbprint_anomaly_empty():
    """Empty thumbprint triggers the anomaly bit."""
    flags = build_anomaly_flags(
        ddf_users=[
            {"sid": "S-1-5-21-1-2-3-1001", "cert_thumbprint": ""},
        ],
        drf_recovery_agents=[],
        parse_error=False,
    )
    assert flags["cert_thumbprint_anomaly"] is True


def test_build_anomaly_flags_cert_thumbprint_anomaly_short():
    """Suspiciously short thumbprint triggers the anomaly bit."""
    flags = build_anomaly_flags(
        ddf_users=[
            {"sid": "S-1-5-21-1-2-3-1001", "cert_thumbprint": "ab"},
        ],
        drf_recovery_agents=[],
        parse_error=False,
    )
    assert flags["cert_thumbprint_anomaly"] is True


def test_build_anomaly_flags_parse_error():
    flags = build_anomaly_flags(
        ddf_users=[],
        drf_recovery_agents=[],
        parse_error=True,
    )
    assert flags["parse_error"] is True


# ── parse_efs_blob — synthetic test fixtures ─────────────────────────────────


def _build_efs_header(
    cb_total_length: int,
    dw_ddf_offset: int,
    dw_drf_offset: int,
) -> bytes:
    """Build a 76-byte EFS_HEADER for testing.

    Layout (offsets relative to blob start):
      0:  dwReserved (4 bytes)
      4:  cbTotalLength (4 bytes)
      8:  EfsId (16 bytes GUID)
      24: dwReserved2 (4 bytes)
      28: dwVersion (4 bytes)
      32: dwCryptoApiVersion (4 bytes)
      36: Checksum (20 bytes SHA1)
      56: dwReservedSpaceForDDFOffset (4 bytes)
      60: dwDDFOffset (4 bytes)
      64: dwDRFOffset (4 bytes)
      68: dwReserved3 (4 bytes)
      72: padding (4 bytes — header is 76 bytes total in parser)
    """
    return (
        b"\x00" * 4                         # dwReserved
        + cb_total_length.to_bytes(4, "little")
        + b"\x11" * 16                      # EfsId (fake GUID)
        + b"\x00" * 4                       # dwReserved2
        + (2).to_bytes(4, "little")         # dwVersion = 2 (CNG)
        + (0).to_bytes(4, "little")         # dwCryptoApiVersion
        + b"\x00" * 20                      # Checksum
        + b"\x00" * 4                       # dwReservedSpaceForDDFOffset
        + dw_ddf_offset.to_bytes(4, "little")
        + dw_drf_offset.to_bytes(4, "little")
        + b"\x00" * 4                       # dwReserved3
        + b"\x00" * 4                       # padding
    )


def _build_efs_entry(
    sid: bytes,
    cert_hash: bytes,
    friendly_name: bytes = b"",
    encrypted_fek: bytes = b"\x00\x00",
) -> bytes:
    """Build one EFS_RSA_KEY_HASH_DATA entry for testing.

    Layout (40-byte header + variable-length data):
      0:  cbLength (4 bytes)
      4:  dwReserved (4 bytes)
      8:  dwSidOffset (4 bytes) — relative to entry start
      12: dwReserved2 (4 bytes)
      16: dwCertHashDataOffset (4 bytes)
      20: cbCertHashLength (4 bytes)
      24: dwReserved3 (4 bytes)
      28: dwEncryptedFEKOffset (4 bytes)
      32: cbEncryptedFEKLength (4 bytes)
      36: dwCredentialSize (4 bytes — sometimes called dwUserCredentialSize)
      40+: variable-length data in this order:
           SID, CertHashData, DisplayInformation (UTF-16LE), EncryptedFEK
    """
    data = sid + cert_hash + friendly_name + encrypted_fek

    sid_offset = 40
    cert_hash_offset = sid_offset + len(sid)
    fn_offset = cert_hash_offset + len(cert_hash)
    fek_offset = fn_offset + len(friendly_name)
    cb_length = 40 + len(data)

    header = (
        cb_length.to_bytes(4, "little")
        + (0).to_bytes(4, "little")               # dwReserved
        + sid_offset.to_bytes(4, "little")        # dwSidOffset
        + (0).to_bytes(4, "little")               # dwReserved2
        + cert_hash_offset.to_bytes(4, "little")  # dwCertHashDataOffset
        + len(cert_hash).to_bytes(4, "little")    # cbCertHashLength
        + (0).to_bytes(4, "little")               # dwReserved3
        + fek_offset.to_bytes(4, "little")        # dwEncryptedFEKOffset
        + len(encrypted_fek).to_bytes(4, "little")  # cbEncryptedFEKLength
        + (0).to_bytes(4, "little")               # dwCredentialSize
    )
    return header + data


def test_parse_efs_blob_truncated():
    """Blob shorter than 76 bytes returns parse error."""
    ddf, drf, errors = parse_efs_blob(b"\x00" * 50)
    assert ddf == []
    assert drf == []
    assert errors  # non-empty


def test_parse_efs_blob_ddf_only():
    """Synthetic blob with 1 DDF user, no DRF."""
    sid = _build_sid_binary(1, 5, [21, 1, 2, 3, 1001])
    cert_hash = bytes(range(20))  # 20-byte SHA-1
    entry = _build_efs_entry(sid, cert_hash)

    ddf_offset = 76  # Right after header
    drf_offset = 0  # No DRF
    user_count = (1).to_bytes(4, "little")
    blob = (
        _build_efs_header(76 + len(user_count) + len(entry), ddf_offset, drf_offset)
        + user_count
        + entry
    )

    ddf, drf, errors = parse_efs_blob(blob)
    assert len(ddf) == 1
    assert ddf[0]["sid"] == "S-1-5-21-1-2-3-1001"
    assert ddf[0]["cert_thumbprint"] == cert_hash.hex()
    assert len(drf) == 0


def test_parse_efs_blob_ddf_and_drf():
    """Blob with 1 DDF user + 1 DRF recovery agent."""
    sid_user = _build_sid_binary(1, 5, [21, 1, 2, 3, 1001])
    cert_user = bytes(range(20))
    entry_user = _build_efs_entry(sid_user, cert_user)

    sid_admin = _build_sid_binary(1, 5, [32, 544])  # Administrators
    cert_admin = bytes(range(20, 40))
    entry_admin = _build_efs_entry(sid_admin, cert_admin)

    ddf_table = (1).to_bytes(4, "little") + entry_user
    drf_table = (1).to_bytes(4, "little") + entry_admin

    ddf_offset = 76
    drf_offset = ddf_offset + len(ddf_table)
    total_len = drf_offset + len(drf_table)

    blob = (
        _build_efs_header(total_len, ddf_offset, drf_offset)
        + ddf_table
        + drf_table
    )

    ddf, drf, errors = parse_efs_blob(blob)
    assert len(ddf) == 1
    assert ddf[0]["sid"] == "S-1-5-21-1-2-3-1001"
    assert len(drf) == 1
    assert drf[0]["sid"] == "S-1-5-32-544"
    assert drf[0]["cert_thumbprint"] == cert_admin.hex()


def test_parse_efs_blob_zero_user_count():
    """Empty DDF table (user_count = 0) returns empty list, no errors."""
    ddf_table = (0).to_bytes(4, "little")
    blob = (
        _build_efs_header(76 + 4, 76, 0)
        + ddf_table
    )

    ddf, drf, errors = parse_efs_blob(blob)
    assert ddf == []
    assert drf == []


def test_parse_efs_blob_three_ddf_users():
    """Multiple DDF users (shared decryption)."""
    sids = [
        _build_sid_binary(1, 5, [21, 1, 2, 3, 1001]),
        _build_sid_binary(1, 5, [21, 1, 2, 3, 1002]),
        _build_sid_binary(1, 5, [21, 1, 2, 3, 1003]),
    ]
    entries = [_build_efs_entry(s, bytes(range(20))) for s in sids]

    ddf_table = (3).to_bytes(4, "little") + b"".join(entries)
    blob = (
        _build_efs_header(76 + len(ddf_table), 76, 0)
        + ddf_table
    )

    ddf, drf, errors = parse_efs_blob(blob)
    assert len(ddf) == 3
    assert ddf[0]["sid"] == "S-1-5-21-1-2-3-1001"
    assert ddf[1]["sid"] == "S-1-5-21-1-2-3-1002"
    assert ddf[2]["sid"] == "S-1-5-21-1-2-3-1003"


def test_parse_efs_blob_friendly_name_extraction():
    """Friendly name in UTF-16LE between cert hash and encrypted FEK."""
    sid = _build_sid_binary(1, 5, [21, 1, 2, 3, 1001])
    cert_hash = bytes(range(20))
    friendly_name = "alice@example.com\x00".encode("utf-16-le")
    entry = _build_efs_entry(sid, cert_hash, friendly_name=friendly_name)

    ddf_table = (1).to_bytes(4, "little") + entry
    blob = (
        _build_efs_header(76 + len(ddf_table), 76, 0)
        + ddf_table
    )

    ddf, drf, errors = parse_efs_blob(blob)
    assert len(ddf) == 1
    assert ddf[0]["friendly_name"] == "alice@example.com"


def test_parse_efs_blob_corrupted_entry_skipped():
    """Truncated entry past header — table parser stops cleanly."""
    # Build a header that claims 2 users but only provides 1 valid entry
    # followed by truncated bytes.
    sid = _build_sid_binary(1, 5, [21, 1, 2, 3, 1001])
    cert_hash = bytes(range(20))
    valid_entry = _build_efs_entry(sid, cert_hash)
    truncated = b"\x99" * 20  # Less than 40-byte header

    ddf_table = (2).to_bytes(4, "little") + valid_entry + truncated
    blob = (
        _build_efs_header(76 + len(ddf_table), 76, 0)
        + ddf_table
    )

    ddf, drf, errors = parse_efs_blob(blob)
    assert len(ddf) == 1  # Only valid entry parsed
    assert ddf[0]["sid"] == "S-1-5-21-1-2-3-1001"
    assert errors  # Truncation reported


# ── Rule #35b live canaries — end-to-end against real ORM/DB ─────────────────


@pytest.mark.asyncio
async def test_do_efs_walk_no_images_returns_empty(tmp_path):
    """No raw NTFS images under detection roots → empty aggregate."""
    async with make_live_db() as db:
        project = Project(name="test-iota-d", description="ι.D.C live canary empty")
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

        result = await _do_efs_walk(db, firmware.id)
        assert result["images_scanned"] == 0
        assert result["files_walked"] == 0
        assert result["encrypted_files_found"] == 0
        assert result["encrypted_files_persisted"] == 0
        assert result["anomaly_total"] == 0


@pytest.mark.asyncio
async def test_do_efs_walk_persists_efs_files_with_mocked_ntfs(tmp_path):
    """Rule #35b live canary — full _do_efs_walk pipeline against an
    ORM-backed test session. Mocks dissect.ntfs.NTFS so we don't need
    a real NTFS image; verifies image discovery → encrypted-file
    filtering → $EFS blob parsing → row construction → DB persistence
    → aggregate accounting.
    """
    # Plant a fake NTFS image the walker will discover.
    image_path = tmp_path / "win10.raw"
    # Header: jump (3 bytes) + OEM "NTFS    " (8 bytes) + padding.
    image_path.write_bytes(b"\xeb\x52\x90" + b"NTFS    " + b"\x00" * 512)

    # Build a synthetic $EFS blob for the mocked record.
    sid_user = _build_sid_binary(1, 5, [21, 1, 2, 3, 1001])
    cert_user = bytes(range(20))
    entry_user = _build_efs_entry(sid_user, cert_user)
    ddf_table = (1).to_bytes(4, "little") + entry_user
    efs_blob = (
        _build_efs_header(76 + len(ddf_table), 76, 0)
        + ddf_table
    )

    # Mock the dissect.ntfs imports + record iteration.
    from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE

    mock_record = MagicMock()
    mock_record.segment = 42

    # Mock $STANDARD_INFORMATION with FILE_ATTRIBUTE_ENCRYPTED.
    mock_si = MagicMock()
    mock_si.file_attributes = 0x4020  # ENCRYPTED + ARCHIVE

    # Mock LOGGED_UTILITY_STREAM attribute returning our blob.
    mock_efs_attr = MagicMock()
    mock_efs_attr.header.name = ""

    class _FakeFileHandle:
        def __init__(self, data):
            self._data = data
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self, n=-1):
            if n == -1:
                return self._data
            return self._data[:n]

    mock_efs_attr.header.open.return_value = _FakeFileHandle(efs_blob)

    # Mock $DATA attribute for file_size.
    mock_data_attr = MagicMock()
    mock_data_attr.header.name = ""
    mock_data_attr.header.size = 1024

    def fake_getitem(item):
        # item is ATTRIBUTE_TYPE_CODE enum
        if isinstance(item, ATTRIBUTE_TYPE_CODE):
            item_val = item.value
        else:
            item_val = item
        if item_val == ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION.value:
            return mock_si
        if item_val == ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM.value:
            return [mock_efs_attr]
        if item_val == ATTRIBUTE_TYPE_CODE.DATA.value:
            return [mock_data_attr]
        return None

    mock_record.attributes = MagicMock()
    mock_record.attributes.__getitem__.side_effect = fake_getitem
    mock_record.full_path.return_value = "Users\\alice\\Documents\\secret.docx"

    # Mock NTFS to return a fake MFT yielding our record.
    fake_ntfs = MagicMock()
    fake_ntfs.mft.segments.return_value = iter([mock_record])

    async with make_live_db() as db:
        project = Project(name="t-efs", description="ι.D.C live canary")
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="win10.bin",
            storage_path="/tmp/x",
            file_size=512,
            sha256="0" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.flush()

        with patch("app.services.efs_walker.NTFS", return_value=fake_ntfs, create=True), \
             patch("dissect.ntfs.NTFS", return_value=fake_ntfs):
            result = await _do_efs_walk(db, firmware.id)
            await db.commit()

    assert result["images_scanned"] == 1
    assert result["encrypted_files_found"] >= 1
    assert result["encrypted_files_persisted"] >= 1

    # Verify per-row persistence via a fresh session.
    async with make_live_db() as db2:
        project2 = Project(name="t2-efs", description="reuse fixtures")
        db2.add(project2)
        await db2.flush()

        firmware2 = Firmware(
            project_id=project2.id,
            original_filename="win10b.bin",
            storage_path="/tmp/y",
            file_size=512,
            sha256="1" * 64,
            extracted_path=str(tmp_path),
        )
        db2.add(firmware2)
        await db2.flush()

        with patch("app.services.efs_walker.NTFS", return_value=fake_ntfs, create=True), \
             patch("dissect.ntfs.NTFS", return_value=fake_ntfs):
            # Re-set the iterator (consumed in the previous run).
            fake_ntfs.mft.segments.return_value = iter([mock_record])
            await _do_efs_walk(db2, firmware2.id)
            await db2.commit()

        rows = (
            await db2.execute(
                select(WindowsEfsEncryptedFile).where(
                    WindowsEfsEncryptedFile.firmware_id == firmware2.id,
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        efs_file = rows[0]
        assert efs_file.mft_record_number == 42
        assert efs_file.ddf_user_count == 1
        assert efs_file.drf_recovery_agent_count == 0
        # ddf_users[0] is the schema_version sentinel; [1] is the user.
        assert efs_file.ddf_users[0]["schema_version"] == 1
        assert efs_file.ddf_users[1]["sid"] == "S-1-5-21-1-2-3-1001"


# ── Rule #36 + Rule #36 EXTENSION no-execute test gate ───────────────────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Remove docstrings, # comments, and string literals from Python
    source so we can scan for ACTUAL code references (calls, imports,
    attribute access) without false positives from prose that MENTIONS
    forbidden primitives in the context of "we don't do this".

    Conservative: drops every triple-quoted block (docstring AND multi-
    line string literals), every `# ...` line comment, and every single-
    line string literal. The remaining text is the executable code.
    """
    import io
    import tokenize

    out_tokens = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenizeError:
        # Fallback: return original (defensive — should never hit in
        # practice for a syntactically valid module).
        return source

    for tok in tokens:
        # Skip strings (catches docstrings AND any string literal).
        if tok.type == tokenize.STRING:
            continue
        # Skip comments.
        if tok.type == tokenize.COMMENT:
            continue
        # Skip NL / NEWLINE / INDENT / DEDENT — just preserve token text.
        out_tokens.append(tok.string)
    return " ".join(out_tokens)


def test_efs_walker_no_execute_no_decrypt_attempt():
    """Rule #36 + Rule #36 EXTENSION — the efs_walker.py CODE (not
    docstrings/comments) MUST NOT invoke any spawn primitive against
    extracted artefacts AND MUST NOT invoke any decryption / DPAPI /
    FEK-handling primitive.

    The walker is a pure metadata parser; nothing should execute the
    parsed data OR attempt to decrypt it.

    Note: docstrings and comments LEGITIMATELY mention forbidden
    primitives (e.g. "NEVER invokes CryptUnprotectData") — we strip
    them before scanning so the test catches actual code references
    only.
    """
    raw_source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "efs_walker.py"
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
            f"Rule #36 violation in efs_walker.py CODE — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke spawn primitives against extracted artefacts."
        )

    # Rule #36 EXTENSION — no decryption / DPAPI / FEK-handling tokens
    # in EXECUTABLE CODE.
    forbidden_decrypt = (
        # DPAPI primitives.
        r"\bCryptUnprotectData\b",
        r"\bCryptProtectData\b",
        # cryptography.fernet imports / usage.
        r"from cryptography\.fernet",
        r"cryptography\.fernet\.",
        # asn1crypto cryptographic primitives (parsing is fine; the lib
        # is allowed as DATA parser per the docstring).
        r"asn1crypto\.cms\.",
        r"asn1crypto\.algos\.",
        # Common decrypt API call patterns.
        r"\.decrypt\s*\(",
        r"\bdecrypt_fek\b",
        # FEK extraction — we explicitly avoid touching the encrypted FEK.
        r"\bextract_fek\b",
        r"\bdecode_fek\b",
        # DPAPI shim / wrapper packages.
        r"\bimpacket\.dpapi\b",
        r"\bdpapick\b",
    )
    for pattern in forbidden_decrypt:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 EXTENSION violation in efs_walker.py CODE — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "attempt decryption, invoke DPAPI, or handle the "
            "RSA-encrypted FEK. PARSE-ONLY discipline."
        )

    # Belt-and-braces: assert the encrypted_fek field is NOT extracted
    # in any persistence path (scan ORIGINAL source — these patterns
    # are clearly executable code, not prose).
    persistence_anti_tokens = (
        r'\brow\.encrypted_fek\s*=',
        r'WindowsEfsEncryptedFile\([^)]*encrypted_fek\s*=',
    )
    for pattern in persistence_anti_tokens:
        matches = re.findall(pattern, raw_source)
        assert not matches, (
            f"Rule #36 EXTENSION violation in efs_walker.py — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "persist the encrypted FEK anywhere."
        )
