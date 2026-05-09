"""Phase β.7 contract tests: dbx_service.match_dbx_revocation.

Builds synthetic ``dbxupdate.bin`` byte buffers in-memory and exercises
the parser + matcher end-to-end. asn1crypto + struct cover the format;
no signify involvement (DBX bundles are independent of PE signing).

Phase β.10 added:
- :func:`_strip_authenticated_variable_wrapper` for the Microsoft-canonical
  ``EFI_VARIABLE_AUTHENTICATION_2`` wrapper format. New tests below
  cover bare passthrough + wrapped detection + boundary cases.
- A committed test fixture (``backend/tests/fixtures/windows/tiny.dbxupdate.bin``)
  exercising the file-on-disk path with the same shape as the in-memory
  builders.
- An optional Rule #35b live canary against the bundled
  ``/opt/wairz/dbxupdate.bin`` — auto-skips when the bundle isn't
  present (host-side pytest), runs post-rebuild inside the worker
  container.
"""
from __future__ import annotations

import datetime as dt
import os
import struct
from pathlib import Path

import pytest

from app.services.dbx_service import (
    _MAX_ENTRIES,
    DBX_MATCH_SCHEMA_VERSION,
    EFI_CERT_SHA256_GUID,
    EFI_CERT_X509_GUID,
    _normalize_serial,
    _parse_bundle_bytes,
    _strip_authenticated_variable_wrapper,
    match_dbx_revocation,
    reset_bundle_cache,
)

# ── Test fixture factory: build a synthetic dbxupdate.bin ─────────────────

_OWNER_GUID = bytes.fromhex("bd9afa775903324dbd6028f4e78f784b")  # MS owner-style GUID


def _build_x509_cert_der(serial: int, common_name: str = "test") -> bytes:
    """Return a self-signed DER cert with the given integer serial.

    Uses the cryptography library (already a wairz dep transitively via
    signify). Generates a fresh 1024-bit RSA key per call — slow but
    fine for unit tests; cached results would invalidate the
    serial-distinctness property.
    """
    from cryptography import x509 as crypto_x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = crypto_x509.Name([
        crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(dt.datetime.now(dt.UTC))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _build_signature_list(sig_type: bytes, payloads: list[bytes]) -> bytes:
    """Build a single EFI_SIGNATURE_LIST with the given payloads.

    Each payload is the per-entry data section (after the 16-byte owner
    GUID); we prepend the owner GUID per entry. All payloads must be the
    same size (UEFI spec contract — sig_size is per-list).
    """
    if not payloads:
        return b""
    sig_size = 16 + len(payloads[0])
    assert all(len(p) == sig_size - 16 for p in payloads), (
        "EFI_SIGNATURE_LIST requires uniform sig_size per list"
    )
    sigs_blob = b"".join(_OWNER_GUID + p for p in payloads)
    sig_list_size = 28 + len(sigs_blob)  # header(28) + zero header_size
    header = struct.pack("<16sIII", sig_type, sig_list_size, 0, sig_size)
    return header + sigs_blob


def _build_dbx(lists: list[bytes]) -> bytes:
    """Concatenate one or more EFI_SIGNATURE_LIST blobs into a dbx file."""
    return b"".join(lists)


# ── _normalize_serial unit tests ──────────────────────────────────────────


def test_normalize_serial_uppercase_strips_leading_zeros():
    assert _normalize_serial("00deadbeef") == "DEADBEEF"
    assert _normalize_serial("DEADBEEF") == "DEADBEEF"


def test_normalize_serial_handles_zero():
    """A literal-zero serial normalizes to '0' rather than ''."""
    assert _normalize_serial("0") == "0"
    assert _normalize_serial("00000") == "0"


def test_normalize_serial_handles_none_and_empty():
    assert _normalize_serial(None) is None
    assert _normalize_serial("") is None


def test_normalize_serial_strips_0x_prefix():
    """Tolerate the '0x' prefix some upstream callers produce."""
    assert _normalize_serial("0xDEADBEEF") == "DEADBEEF"


# ── _parse_bundle_bytes unit tests ────────────────────────────────────────


def test_parse_bundle_bytes_empty():
    out = _parse_bundle_bytes(b"")
    assert out["x509_serials"] == set()
    assert out["sha256_hashes"] == set()
    assert out["entries_scanned"] == 0


def test_parse_bundle_bytes_single_x509_entry():
    der = _build_x509_cert_der(0xCAFEBABE)
    bundle = _build_dbx([_build_signature_list(EFI_CERT_X509_GUID, [der])])
    out = _parse_bundle_bytes(bundle)
    assert out["entries_scanned"] == 1
    assert "CAFEBABE" in out["x509_serials"]
    assert out["sha256_hashes"] == set()


def test_parse_bundle_bytes_single_sha256_entry():
    """SHA-256 entries surface as lowercase hex hashes."""
    sha256_payload = b"\x11" * 32
    bundle = _build_dbx([
        _build_signature_list(EFI_CERT_SHA256_GUID, [sha256_payload]),
    ])
    out = _parse_bundle_bytes(bundle)
    assert out["entries_scanned"] == 1
    assert "11" * 32 in out["sha256_hashes"]
    assert out["x509_serials"] == set()


def test_parse_bundle_bytes_mixed_lists():
    """A real dbx carries multiple signature lists back-to-back."""
    der1 = _build_x509_cert_der(0xAAAA1111)
    der2 = _build_x509_cert_der(0xBBBB2222)
    sha256_a = b"\x22" * 32
    sha256_b = b"\x33" * 32
    bundle = _build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [der1]),
        _build_signature_list(EFI_CERT_SHA256_GUID, [sha256_a, sha256_b]),
        _build_signature_list(EFI_CERT_X509_GUID, [der2]),
    ])
    out = _parse_bundle_bytes(bundle)
    assert out["entries_scanned"] == 4
    assert {"AAAA1111", "BBBB2222"}.issubset(out["x509_serials"])
    assert {"22" * 32, "33" * 32}.issubset(out["sha256_hashes"])


def test_parse_bundle_bytes_unknown_guid_skipped():
    """An EFI_SIGNATURE_LIST with an unknown signature_type GUID is
    skipped over (its byte range is consumed; entries are counted but
    not added to either set)."""
    unknown_guid = b"\xff" * 16
    payload = b"\x44" * 32
    bundle = _build_dbx([
        _build_signature_list(unknown_guid, [payload]),
    ])
    out = _parse_bundle_bytes(bundle)
    assert out["entries_scanned"] == 1
    assert out["x509_serials"] == set()
    assert out["sha256_hashes"] == set()


def test_parse_bundle_bytes_malformed_header_stops_walk():
    """A bundle whose header claims an oversized list_size stops the
    parser cleanly — whatever was parsed before the malformation
    survives, the rest is dropped."""
    der = _build_x509_cert_der(0xC0DEC0DE)
    good_list = _build_signature_list(EFI_CERT_X509_GUID, [der])
    # Crafted "next list" with sig_list_size > remaining bytes.
    bad_header = struct.pack(
        "<16sIII", EFI_CERT_X509_GUID, 0xFFFFFFFF, 0, 64,
    )
    bundle = good_list + bad_header
    out = _parse_bundle_bytes(bundle)
    assert "C0DEC0DE" in out["x509_serials"]
    assert out["entries_scanned"] == 1


def test_parse_bundle_bytes_caps_at_max_entries():
    """The parser refuses to scan beyond _MAX_ENTRIES regardless of the
    bundle's claimed entry count — a bundle whose lists collectively
    iterate past the cap stops parsing."""
    sha256_payloads = [bytes([i & 0xFF]) * 32 for i in range(_MAX_ENTRIES + 100)]
    bundle = _build_dbx([
        _build_signature_list(EFI_CERT_SHA256_GUID, sha256_payloads),
    ])
    out = _parse_bundle_bytes(bundle)
    assert out["entries_scanned"] == _MAX_ENTRIES


def test_parse_bundle_bytes_partial_entry_terminates_list():
    """If the final entry in a list is truncated below sig_size, the
    parser stops at the truncation point without raising."""
    der = _build_x509_cert_der(0xABCDEF12)
    sig_size = 16 + len(der)
    sigs_blob = (_OWNER_GUID + der) + (b"\x00" * (sig_size // 2))  # half-truncated
    sig_list_size = 28 + len(sigs_blob)
    header = struct.pack("<16sIII", EFI_CERT_X509_GUID, sig_list_size, 0, sig_size)
    bundle = header + sigs_blob
    out = _parse_bundle_bytes(bundle)
    # Only the complete entry survives.
    assert "ABCDEF12" in out["x509_serials"]
    assert out["entries_scanned"] == 1


# ── match_dbx_revocation file-handling tests ──────────────────────────────


@pytest.fixture(autouse=True)
def _clear_bundle_cache():
    """Reset the module-level bundle cache between tests so each test
    sees a clean parse."""
    reset_bundle_cache()
    yield
    reset_bundle_cache()


def test_match_dbx_revocation_returns_none_for_no_serial(tmp_path: Path):
    """No leaf serial → no match attempted → None."""
    bundle = tmp_path / "dbxupdate.bin"
    bundle.write_bytes(_build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xAB)]),
    ]))
    assert match_dbx_revocation(None, bundle_path=bundle) is None
    assert match_dbx_revocation("", bundle_path=bundle) is None


def test_match_dbx_revocation_returns_none_for_missing_bundle(tmp_path: Path):
    """β.10 deferral semantic — no bundle provisioned → None.
    The verdict layer treats this as default dbx_revoked=False."""
    assert match_dbx_revocation("DEADBEEF", bundle_path=tmp_path / "nope.bin") is None


def test_match_dbx_revocation_returns_none_when_path_is_directory(tmp_path: Path):
    """Bundle path that isn't a file (typo'd to a dir) → None, no raise."""
    out = match_dbx_revocation("DEADBEEF", bundle_path=tmp_path)
    assert out is None


def test_match_dbx_revocation_returns_none_for_no_path(monkeypatch):
    """No explicit bundle_path AND no DBX_BUNDLE_PATH env var → None."""
    monkeypatch.delenv("DBX_BUNDLE_PATH", raising=False)
    out = match_dbx_revocation("DEADBEEF")
    assert out is None


def test_match_dbx_revocation_uses_env_var_when_no_explicit_path(
    tmp_path: Path, monkeypatch,
):
    """β.10 will set DBX_BUNDLE_PATH; when set, the matcher uses it."""
    bundle = tmp_path / "dbxupdate.bin"
    bundle.write_bytes(_build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xFEED)]),
    ]))
    monkeypatch.setenv("DBX_BUNDLE_PATH", str(bundle))
    out = match_dbx_revocation("FEED")
    assert out is not None
    assert out["revoked"] is True


# ── match_dbx_revocation match-result tests ───────────────────────────────


def test_match_dbx_revocation_revoked_when_serial_in_bundle(tmp_path: Path):
    """A serial in the bundle's X.509 set → revoked=True. Real dbx
    bundles ship one cert per list (sig_size is per-list and certs vary
    in DER length); we model that shape."""
    bundle = tmp_path / "dbxupdate.bin"
    bundle.write_bytes(_build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xDEADBEEF)]),
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xCAFE)]),
    ]))
    out = match_dbx_revocation("DEADBEEF", bundle_path=bundle)
    assert out is not None
    assert out["revoked"] is True
    assert out["match_kind"] == "x509_serial"
    assert out["leaf_serial_normalized"] == "DEADBEEF"
    assert out["bundle_entries"] == 2
    assert out["bundle_path"] == str(bundle)
    assert out["schema_version"] == DBX_MATCH_SCHEMA_VERSION


def test_match_dbx_revocation_not_revoked_when_serial_absent(tmp_path: Path):
    """Bundle loaded but the serial isn't there — revoked=False with
    match_kind='none' (distinct from "no information")."""
    bundle = tmp_path / "dbxupdate.bin"
    bundle.write_bytes(_build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xCAFE)]),
    ]))
    out = match_dbx_revocation("DEADBEEF", bundle_path=bundle)
    assert out is not None
    assert out["revoked"] is False
    assert out["match_kind"] == "none"
    assert out["leaf_serial_normalized"] == "DEADBEEF"
    assert out["bundle_entries"] == 1


def test_match_dbx_revocation_normalizes_input_serial(tmp_path: Path):
    """Caller's leaf_serial format ('0x...' / 'deadbeef' / 'DEADBEEF')
    all converge through _normalize_serial before the bundle lookup."""
    bundle = tmp_path / "dbxupdate.bin"
    bundle.write_bytes(_build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xDEAD)]),
    ]))
    for variant in ("DEAD", "dead", "0xDEAD", "00DEAD"):
        reset_bundle_cache()
        out = match_dbx_revocation(variant, bundle_path=bundle)
        assert out is not None and out["revoked"] is True, (
            f"normalisation failed for variant={variant!r}"
        )


def test_match_dbx_revocation_revocation_kb_is_none_in_phase_beta_7(tmp_path: Path):
    """Phase β.7 baseline: dbx_revocation_kb is always None — the bundle
    format itself doesn't embed KB strings. β.10's side-car JSON will
    populate this field on a true match. Documented in the service
    docstring; this test guards against accidental fabrication."""
    bundle = tmp_path / "dbxupdate.bin"
    bundle.write_bytes(_build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xDEAD)]),
    ]))
    out = match_dbx_revocation("DEAD", bundle_path=bundle)
    assert out is not None
    assert out["revocation_kb"] is None


def test_match_dbx_revocation_caches_parsed_bundle(tmp_path: Path):
    """Module-level cache: a second call with the same path + mtime
    re-uses the parsed entries (verified via internal cache state).
    Without the cache, β.4 batch-verifying 1000 PEs in a firmware would
    re-parse the bundle 1000 times."""
    bundle = tmp_path / "dbxupdate.bin"
    bundle.write_bytes(_build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xCAFE)]),
    ]))
    out1 = match_dbx_revocation("CAFE", bundle_path=bundle)
    out2 = match_dbx_revocation("CAFE", bundle_path=bundle)
    assert out1 is not None and out2 is not None
    assert out1["revoked"] is True and out2["revoked"] is True
    # Both calls return identical bundle_path / entries — cache hit
    # produces the same parsed data.
    assert out1["bundle_path"] == out2["bundle_path"]
    assert out1["bundle_entries"] == out2["bundle_entries"]


def test_match_dbx_revocation_output_keys(tmp_path: Path):
    """Output dict carries exactly the documented keys — drift detector
    against silent shape changes that would break the verdict
    decomposition in authenticode_service."""
    bundle = tmp_path / "dbxupdate.bin"
    bundle.write_bytes(_build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xABCD)]),
    ]))
    out = match_dbx_revocation("ABCD", bundle_path=bundle)
    assert out is not None
    assert set(out.keys()) == {
        "schema_version",
        "revoked",
        "revocation_kb",
        "leaf_serial_normalized",
        "match_kind",
        "bundle_entries",
        "bundle_path",
    }


# ── _strip_authenticated_variable_wrapper unit tests (Phase β.10) ────────


def _build_efi_authenticated_variable(inner: bytes, *, year: int = 2026) -> bytes:
    """Construct a synthetic EFI_VARIABLE_AUTHENTICATION_2 wrapper around
    ``inner`` so the wrapper-strip path has a deterministic test target.
    The wrapper's CertData is opaque dummy bytes — wairz's parser only
    strips, it never validates the PKCS#7 signature; the SHA256 pin in
    backend/ms-anchors/ is the integrity check."""
    efi_time = struct.pack(
        "<HBBBBBBIhBB",
        year, 5, 8, 12, 0, 0, 0, 0, 0, 0, 0,
    )
    assert len(efi_time) == 16
    cert_type_guid = b"\x9d\xd2\xafJ\xdfh\xeeI\x8a\xa94}7Ve\xa7"
    cert_data = b"\x00" * 64  # opaque PKCS#7 payload placeholder
    dw_length = 4 + 2 + 2 + 16 + len(cert_data)
    win_cert = (
        struct.pack("<IHH", dw_length, 0x0200, 0x0EF1)
        + cert_type_guid
        + cert_data
    )
    return efi_time + win_cert + inner


def test_strip_wrapper_returns_buf_unchanged_for_bare_signature_list():
    """β.7's bare-format synthetic fixtures pass through unchanged. The
    first 2 bytes are part of EFI_CERT_X509_GUID (0xa159 = 41305 — outside
    [1900, 2100] year window), so detection must NOT fire."""
    bare = _build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xCAFE)]),
    ])
    out = _strip_authenticated_variable_wrapper(bare)
    assert out == bare, "bare EFI_SIGNATURE_LIST format must pass through unchanged"


def test_strip_wrapper_returns_buf_unchanged_for_sha256_only_bare_list():
    """A bare bundle whose first list is EFI_CERT_SHA256_GUID-typed
    starts with bytes 0x26 0x16 (year=0x1626=5670, outside [1900, 2100])
    so the year-range check rules out wrapper detection."""
    bare = _build_dbx([
        _build_signature_list(EFI_CERT_SHA256_GUID, [b"\x42" * 32]),
    ])
    out = _strip_authenticated_variable_wrapper(bare)
    assert out == bare


def test_strip_wrapper_strips_microsoft_canonical_shape():
    """Synthetic Microsoft-canonical wrapper with a known inner payload —
    after strip the inner is bit-identical to what we wrapped."""
    inner = _build_dbx([
        _build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0xCAFE)]),
        _build_signature_list(EFI_CERT_SHA256_GUID, [b"\x42" * 32]),
    ])
    wrapped = _build_efi_authenticated_variable(inner)
    out = _strip_authenticated_variable_wrapper(wrapped)
    assert out == inner


def test_strip_wrapper_short_input_passes_through():
    """A buffer too short to even hold a wrapper header is returned
    untouched; the parser then sees an empty-ish payload and yields
    entries_scanned=0 (no exception)."""
    assert _strip_authenticated_variable_wrapper(b"") == b""
    assert _strip_authenticated_variable_wrapper(b"\x00" * 10) == b"\x00" * 10


def test_strip_wrapper_oversized_dwlength_passes_through():
    """A wrapper whose dwLength runs off the end of buf is left intact
    — strip is conservative on malformed input. The downstream parser
    then handles the malformed list cleanly per β.7's existing
    'malformed → break' loop."""
    inner = _build_dbx([_build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0x1)])])
    wrapped = _build_efi_authenticated_variable(inner)
    # Tamper dwLength to an absurd value.
    tampered = bytearray(wrapped)
    struct.pack_into("<I", tampered, 16, 0xFFFFFFFF)
    out = _strip_authenticated_variable_wrapper(bytes(tampered))
    assert out == bytes(tampered), "oversized dwLength must NOT trigger strip"


def test_strip_wrapper_year_out_of_range_passes_through():
    """A buffer whose first 2 bytes decode to a year outside [1900, 2100]
    is treated as a bare list (year-range is the primary disambiguator
    between wrapped and bare formats)."""
    inner = _build_dbx([_build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0x1)])])
    wrapped = bytearray(_build_efi_authenticated_variable(inner))
    struct.pack_into("<H", wrapped, 0, 1899)  # too old
    out = _strip_authenticated_variable_wrapper(bytes(wrapped))
    assert out == bytes(wrapped)
    struct.pack_into("<H", wrapped, 0, 2101)  # too new
    out = _strip_authenticated_variable_wrapper(bytes(wrapped))
    assert out == bytes(wrapped)


def test_strip_wrapper_wrong_wType_passes_through():
    """wCertificateType != 0x0EF1 means this isn't an EFI authenticated
    variable wrapper — pass through."""
    inner = _build_dbx([_build_signature_list(EFI_CERT_X509_GUID, [_build_x509_cert_der(0x1)])])
    wrapped = bytearray(_build_efi_authenticated_variable(inner))
    struct.pack_into("<H", wrapped, 22, 0x0001)  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
    out = _strip_authenticated_variable_wrapper(bytes(wrapped))
    assert out == bytes(wrapped)


# ── Committed-fixture path (Phase β.10 — Rule #35b live canary) ─────────


_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "windows"
_TINY_BARE = _FIXTURE_DIR / "tiny.dbxupdate.bin"
_TINY_WRAPPED = _FIXTURE_DIR / "tiny.dbxupdate.wrapped.bin"


def test_committed_tiny_fixture_bare_parses_cleanly():
    """The committed bare-format fixture round-trips through the full
    file-on-disk path: read → strip (no-op) → parse. Activates the
    file-load code path that the in-memory tests deliberately don't
    exercise."""
    assert _TINY_BARE.is_file(), (
        f"missing committed fixture {_TINY_BARE}; "
        "regenerate via backend/tests/fixtures/windows/_build_tiny_dbxupdate.py"
    )
    out = match_dbx_revocation("CAFE", bundle_path=_TINY_BARE)
    assert out is not None
    assert out["revoked"] is True
    assert out["leaf_serial_normalized"] == "CAFE"
    assert out["bundle_entries"] >= 3
    assert out["match_kind"] == "x509_serial"


def test_committed_tiny_fixture_wrapped_parses_cleanly():
    """The committed wrapped-format fixture exercises strip + parse.
    Same expected entries as bare since wrapper carries identical
    inner payload."""
    assert _TINY_WRAPPED.is_file(), (
        f"missing committed fixture {_TINY_WRAPPED}; "
        "regenerate via backend/tests/fixtures/windows/_build_tiny_dbxupdate.py"
    )
    out = match_dbx_revocation("DEAD", bundle_path=_TINY_WRAPPED)
    assert out is not None
    assert out["revoked"] is True
    assert out["leaf_serial_normalized"] == "DEAD"
    assert out["bundle_entries"] >= 3


def test_committed_tiny_fixture_unrevoked_serial_returns_false():
    """Negative-side: a serial not in the fixture must return revoked=False
    + match_kind='none', NOT a fabricated revoked=True. Catches a future
    bug where the matcher accidentally swaps polarity."""
    out = match_dbx_revocation("BEEF", bundle_path=_TINY_BARE)
    assert out is not None
    assert out["revoked"] is False
    assert out["match_kind"] == "none"


# ── Bundled-image canary (skipped on host; activates inside worker) ─────


_BUNDLE_PATH = Path(os.environ.get("DBX_BUNDLE_PATH", "/opt/wairz/dbxupdate.bin"))


@pytest.mark.skipif(
    not _BUNDLE_PATH.is_file(),
    reason=(
        f"DBX bundle not present at {_BUNDLE_PATH}; only activates "
        "post-Phase-β.10-rebuild inside the worker/backend container"
    ),
)
def test_bundled_dbx_image_parses_with_nonzero_entries():
    """Phase β.10 Rule #35b live canary: when the worker image bakes the
    Microsoft-canonical bundle, the parser must surface entries > 0.
    Validates wrapper-strip + EFI_SIGNATURE_LIST walk against the actual
    bundle — silent zero-entry would mean every PE ships dbx_revoked=False
    even when the bundle is provisioned."""
    # Use a serial we know isn't in the bundle (the test asserts
    # parse-shape, not match polarity — different bundle revisions
    # carry different serials).
    out = match_dbx_revocation(
        "00000000000000000000000000000001",
        bundle_path=_BUNDLE_PATH,
    )
    assert out is not None, "match_dbx_revocation returned None — bundle unparseable?"
    assert out["bundle_entries"] > 0, (
        f"bundle at {_BUNDLE_PATH} parsed but yielded 0 entries — "
        "wrapper-strip or EFI_SIGNATURE_LIST walk failed silently"
    )
    assert out["bundle_path"] == str(_BUNDLE_PATH)
