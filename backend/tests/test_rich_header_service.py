"""Phase β.6 contract tests: rich_header_service.decode_rich_header.

Mocks pefile at the ``pefile.PE`` boundary. The pefile library is
already exercised heavily by other parts of the wairz backend — these
tests focus on the canonical-dict mapping and defensive failure modes.
A real-PE Rule #35b live canary is deferred to Phase β.7+ MCP integration
tests (same pattern as authenticode_service β.4 deferral).
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from app.services.rich_header_service import (
    _MAX_ENTRIES,
    _decode_entries,
    decode_rich_header,
)

# ── _decode_entries unit tests ────────────────────────────────────────────


def test_decode_entries_empty():
    assert _decode_entries([]) == []


def test_decode_entries_one_entry():
    """Single entry: comp_id (build<<16 | prod_id) + count."""
    # build_number=0x100, product_id=0xCC → comp_id=0x010000CC, instances=42
    out = _decode_entries([0x010000CC, 42])
    assert out == [{
        "comp_id": 0x010000CC,
        "build_number": 0x0100,
        "product_id": 0x00CC,
        "instances": 42,
    }]


def test_decode_entries_multiple():
    out = _decode_entries([0x01010000, 1, 0x02020001, 2, 0x03030002, 3])
    assert len(out) == 3
    assert out[0]["build_number"] == 0x0101
    assert out[0]["product_id"] == 0x0000
    assert out[1]["instances"] == 2
    assert out[2]["comp_id"] == 0x03030002


def test_decode_entries_clamped_to_max():
    """A malformed RICH header could produce an arbitrary entry stream;
    the decoder caps at _MAX_ENTRIES to bound JSONB size."""
    huge = [0] * (4 * _MAX_ENTRIES)  # 2*_MAX_ENTRIES dwords paired
    out = _decode_entries(huge)
    assert len(out) == _MAX_ENTRIES


def test_decode_entries_handles_odd_length():
    """Odd-length values list — last unpaired dword is ignored (the
    pairing arithmetic floors)."""
    out = _decode_entries([0x010000CC, 42, 0xDEADBEEF])
    assert len(out) == 1


def test_decode_entries_masks_to_32bit():
    """Negative or >32-bit ints from struct.unpack signed paths get
    masked to canonical 32-bit unsigned for stable JSONB."""
    out = _decode_entries([-1, -1])  # would be 0xFFFFFFFF, 0xFFFFFFFF
    assert out[0]["comp_id"] == 0xFFFFFFFF
    assert out[0]["instances"] == 0xFFFFFFFF


# ── decode_rich_header file-handling tests ────────────────────────────────


def test_decode_rich_header_returns_none_for_missing_file(tmp_path: Path):
    """Non-existent paths return None — never raise."""
    assert decode_rich_header(tmp_path / "missing.exe") is None


def test_decode_rich_header_returns_none_for_non_pe(tmp_path: Path):
    """A file pefile can't parse as PE returns None — never raise."""
    p = tmp_path / "random.bin"
    p.write_bytes(b"\xff" * 1024)
    # No mock — pefile itself raises PEFormatError; helper swallows it.
    assert decode_rich_header(p) is None


def test_decode_rich_header_returns_none_when_no_rich(tmp_path: Path):
    """A PE with no RICH header (parse_rich_header returns None) → None.
    Non-Microsoft-toolchain PEs commonly have no RICH header."""
    p = tmp_path / "no_rich.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)

    fake_pe = MagicMock()
    fake_pe.parse_rich_header.return_value = None
    with patch("pefile.PE", return_value=fake_pe):
        assert decode_rich_header(p) is None


def test_decode_rich_header_pefile_raises_yields_none(tmp_path: Path):
    """pefile.PE() can raise PEFormatError on malformed inputs — must
    not propagate."""
    p = tmp_path / "bad.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)

    with patch("pefile.PE", side_effect=RuntimeError("pefile boom")):
        assert decode_rich_header(p) is None


def test_decode_rich_header_parse_rich_header_raises_yields_none(tmp_path: Path):
    """parse_rich_header itself raising must not propagate."""
    p = tmp_path / "weird.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)

    fake_pe = MagicMock()
    fake_pe.parse_rich_header.side_effect = RuntimeError("rich parse boom")
    with patch("pefile.PE", return_value=fake_pe):
        assert decode_rich_header(p) is None


# ── decode_rich_header canonical-shape tests ──────────────────────────────


def _build_rich_dict(values: list[int], key: bytes = b"\x12\x34\x56\x78") -> dict:
    """Build a pefile-shaped rich dict for mocking."""
    return {
        "key": key,
        "values": values,
        "raw_data": b"\x00" * (4 * (len(values) + 4)),
        "clear_data": b"\x00" * (4 * (len(values) + 4)),
        "checksum": int.from_bytes(key, "little"),
    }


def test_decode_rich_header_canonical_shape(tmp_path: Path):
    """Happy path — a 2-entry RICH header maps onto the canonical dict."""
    p = tmp_path / "vs2019.dll"
    p.write_bytes(b"MZ" + b"\x00" * 64)

    rich = _build_rich_dict([
        0x010500CC, 7,    # cl.exe build 0x0105 prod 0xCC, used 7 times
        0x010600CD, 3,    # linker build 0x0106 prod 0xCD, used 3 times
    ])

    fake_pe = MagicMock()
    fake_pe.parse_rich_header.return_value = rich
    fake_pe.get_rich_header_hash.return_value = "deadbeefcafebabe"
    with patch("pefile.PE", return_value=fake_pe):
        out = decode_rich_header(p)

    assert out is not None
    assert out["xor_key"] == "0x12345678"
    assert out["entry_count"] == 2
    assert out["entries"][0] == {
        "comp_id": 0x010500CC,
        "build_number": 0x0105,
        "product_id": 0x00CC,
        "instances": 7,
    }
    assert out["entries"][1]["instances"] == 3
    assert out["hash_md5"] == "deadbeefcafebabe"


def test_decode_rich_header_falls_back_when_pefile_hash_unavailable(tmp_path: Path):
    """If pefile.get_rich_header_hash() raises or returns falsy, the helper
    computes its own MD5 of raw_data so the cluster fingerprint stays
    populated."""
    p = tmp_path / "olddll.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)

    rich = _build_rich_dict([0x01010001, 1])
    fake_pe = MagicMock()
    fake_pe.parse_rich_header.return_value = rich
    fake_pe.get_rich_header_hash.side_effect = AttributeError("not available")
    with patch("pefile.PE", return_value=fake_pe):
        out = decode_rich_header(p)

    assert out is not None
    # 32 hex chars = MD5
    assert len(out["hash_md5"]) == 32
    assert all(c in "0123456789abcdef" for c in out["hash_md5"])


def test_decode_rich_header_handles_missing_key(tmp_path: Path):
    """A pefile dict with missing/short key still produces a verdict —
    xor_key collapses to empty string but other fields populate."""
    p = tmp_path / "weird.dll"
    p.write_bytes(b"MZ" + b"\x00" * 64)

    rich = {
        "values": [0x01000001, 1],
        "raw_data": b"\x00" * 16,
        "clear_data": b"\x00" * 16,
        # No "key" — defensive default applies.
    }
    fake_pe = MagicMock()
    fake_pe.parse_rich_header.return_value = rich
    fake_pe.get_rich_header_hash.return_value = "abc123"
    with patch("pefile.PE", return_value=fake_pe):
        out = decode_rich_header(p)

    assert out is not None
    assert out["xor_key"] == ""
    assert out["entry_count"] == 1


def test_decode_rich_header_xor_key_uppercase_hex(tmp_path: Path):
    """xor_key always renders as ``0xAABBCCDD`` uppercase hex — stable
    for cross-PE diffing in JSONB queries."""
    p = tmp_path / "x.dll"
    p.write_bytes(b"MZ" + b"\x00" * 64)

    rich = _build_rich_dict([], key=b"\xab\xcd\xef\x00")
    fake_pe = MagicMock()
    fake_pe.parse_rich_header.return_value = rich
    fake_pe.get_rich_header_hash.return_value = "0" * 32
    with patch("pefile.PE", return_value=fake_pe):
        out = decode_rich_header(p)

    assert out is not None
    assert out["xor_key"] == "0xABCDEF00"
    assert out["entry_count"] == 0


def test_decode_rich_header_empty_values_yields_zero_entry_count(tmp_path: Path):
    """A RICH header with empty values list produces entry_count=0 but
    is still distinct from None (a parse-failure)."""
    p = tmp_path / "empty.dll"
    p.write_bytes(b"MZ" + b"\x00" * 64)

    rich = _build_rich_dict([])
    fake_pe = MagicMock()
    fake_pe.parse_rich_header.return_value = rich
    fake_pe.get_rich_header_hash.return_value = "deadbeef" + "0" * 24
    with patch("pefile.PE", return_value=fake_pe):
        out = decode_rich_header(p)

    assert out is not None
    assert out["entry_count"] == 0
    assert out["entries"] == []


# ── Output-shape contract test ────────────────────────────────────────────


def test_decode_rich_header_output_keys(tmp_path: Path):
    """The output dict must carry exactly the documented keys — drift
    detector against silent shape changes that would break the JSONB
    column / MCP tool / frontend trio."""
    p = tmp_path / "x.dll"
    p.write_bytes(b"MZ" + b"\x00" * 64)

    rich = _build_rich_dict([0x01010001, 1])
    fake_pe = MagicMock()
    fake_pe.parse_rich_header.return_value = rich
    fake_pe.get_rich_header_hash.return_value = "deadbeef" + "0" * 24
    with patch("pefile.PE", return_value=fake_pe):
        out = decode_rich_header(p)

    assert out is not None
    assert set(out.keys()) == {"xor_key", "entry_count", "entries", "hash_md5"}
    # Each entry has the documented sub-keys.
    for entry in out["entries"]:
        assert set(entry.keys()) == {
            "comp_id", "build_number", "product_id", "instances",
        }
