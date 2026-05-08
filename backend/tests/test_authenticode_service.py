"""Phase β.4 contract tests: AuthenticodeVerdict mapping.

Mocks signify at the AuthenticodeFile boundary. Real-PE Rule #35b live
canary deferred to Phase β.7 (MCP tool integration tests have access to
fixture PEs in the firmware extraction tree).
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from signify.authenticode import AuthenticodeVerificationResult

from app.services.authenticode_service import (
    AuthenticodeVerdict,
    _map_verification_result_to_chain_status,
    verify_pe_file,
)


# ── Mapping function unit tests ───────────────────────────────────────────


@pytest.mark.parametrize(
    "result,has_timestamp,expected",
    [
        # OK → valid_now (subsumes valid_at_signing).
        (AuthenticodeVerificationResult.OK, False, "valid_now"),
        (AuthenticodeVerificationResult.OK, True, "valid_now"),
        # CERTIFICATE_ERROR + timestamp → was valid at signing, now revoked.
        (AuthenticodeVerificationResult.CERTIFICATE_ERROR, True, "revoked"),
        # CERTIFICATE_ERROR without timestamp → can't distinguish; pessimistic.
        (AuthenticodeVerificationResult.CERTIFICATE_ERROR, False, "never_valid"),
        # Hard-fail verdicts → never_valid regardless of timestamp.
        (AuthenticodeVerificationResult.VERIFY_ERROR, False, "never_valid"),
        (AuthenticodeVerificationResult.INVALID_DIGEST, True, "never_valid"),
        (
            AuthenticodeVerificationResult.INCONSISTENT_DIGEST_ALGORITHM,
            False,
            "never_valid",
        ),
        (AuthenticodeVerificationResult.COUNTERSIGNER_ERROR, True, "never_valid"),
        (AuthenticodeVerificationResult.INVALID_ADDITIONAL_HASH, False, "never_valid"),
        # Soft / parse / unknown verdicts → unknown.
        (AuthenticodeVerificationResult.PARSE_ERROR, False, "unknown"),
        (AuthenticodeVerificationResult.UNKNOWN_ERROR, True, "unknown"),
        (AuthenticodeVerificationResult.NOT_SIGNED, False, "unknown"),
    ],
)
def test_map_verification_result(result, has_timestamp, expected):
    assert _map_verification_result_to_chain_status(result, has_timestamp) == expected


# ── verify_pe_file file-handling tests ────────────────────────────────────


def test_verify_pe_file_handles_missing_file(tmp_path: Path):
    out = verify_pe_file(tmp_path / "missing.exe")
    assert out.signed is False
    assert out.chain_status == "unknown"
    assert "PE file not found" in (out.error or "")


def test_verify_pe_file_handles_corrupt_pe(tmp_path: Path):
    """A non-PE file (random bytes) must not raise; returns a clear verdict."""
    bogus = tmp_path / "random.exe"
    bogus.write_bytes(b"\x00" * 1024)

    out = verify_pe_file(bogus)
    # Either NOT a PE (signify raises ParseError) or signed=False with no signatures.
    assert out.signed is False
    assert out.chain_status == "unknown"


def test_verify_pe_file_handles_unsigned_pe(tmp_path: Path):
    """An unsigned PE (MZ + minimal PE header, no security directory)
    yields signed=False / chain_status=unknown — the worker shouldn't crash
    when the firmware contains 99% unsigned IoT vendor PEs."""
    # Build a minimal PE-like file: MZ + PE\x00\x00 at e_lfanew=0x40
    pe_bytes = bytearray(0x100)
    pe_bytes[0:2] = b"MZ"
    pe_bytes[0x3c:0x40] = (0x40).to_bytes(4, "little")
    pe_bytes[0x40:0x44] = b"PE\x00\x00"

    pe_file = tmp_path / "unsigned.exe"
    pe_file.write_bytes(bytes(pe_bytes))

    out = verify_pe_file(pe_file)
    # Real signify may bail on this minimal-but-malformed PE — accept any
    # un-signed verdict (the contract is "never raises"; what verdict
    # specifically depends on signify's tolerance).
    assert out.signed is False
    assert out.chain_status in ("unknown", "never_valid")


# ── verify_pe_file mock-injected verdict tests ────────────────────────────


def test_verify_pe_file_signed_ok(tmp_path: Path):
    """Mock signify to return OK; verify the verdict mapping end-to-end."""
    pe_file = tmp_path / "signed.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_sig = MagicMock()
    fake_sig.signer_info = MagicMock()
    fake_sig.signer_info.certificate = MagicMock()
    fake_sig.signer_info.certificate.subject = "CN=Microsoft Windows"
    fake_sig.signer_info.certificate.issuer = "CN=Microsoft Code Signing PCA 2011"
    fake_sig.signer_info.certificate.serial_number = 0x33ABCDEF
    fake_sig.signer_info.digest_algorithm = "sha256"

    # Counter-signer with timestamp.
    fake_sig.countersigner = MagicMock()
    fake_sig.countersigner.signing_time = datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC)
    fake_sig.countersigner.certificate = MagicMock()
    fake_sig.countersigner.certificate.subject = "CN=Microsoft Time-Stamp PCA 2010"

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([fake_sig])
    fake_af.explain_verify.return_value = (AuthenticodeVerificationResult.OK, None)

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is True
    assert out.chain_status == "valid_now"
    assert out.signer_subject == "CN=Microsoft Windows"
    assert out.signer_issuer == "CN=Microsoft Code Signing PCA 2011"
    assert out.leaf_serial == "33ABCDEF"
    assert out.sig_hash_algo == "sha256"
    assert out.tsa_authority == "CN=Microsoft Time-Stamp PCA 2010"
    assert out.signed_at == datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC)
    assert out.signatures_count == 1
    assert out.chain_json["verification_result"] == "OK"
    assert out.chain_json["has_countersigner"] is True


def test_verify_pe_file_revoked_chain_with_timestamp(tmp_path: Path):
    """Mock signify CERTIFICATE_ERROR with a timestamp present →
    chain_status='revoked' (Persona-E #2 time-anchor: was valid at signing,
    now revoked)."""
    pe_file = tmp_path / "expired.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_sig = MagicMock()
    fake_sig.signer_info = MagicMock(certificate=None)
    fake_sig.countersigner = MagicMock()
    fake_sig.countersigner.signing_time = datetime(2018, 1, 1, tzinfo=UTC)
    fake_sig.countersigner.certificate = MagicMock(subject="CN=TSA")

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([fake_sig])
    fake_af.explain_verify.return_value = (
        AuthenticodeVerificationResult.CERTIFICATE_ERROR,
        Exception("Certificate has expired"),
    )

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is True
    assert out.chain_status == "revoked"
    # The timestamp is what discriminates revoked vs never_valid.
    assert out.signed_at == datetime(2018, 1, 1, tzinfo=UTC)
    assert out.tsa_authority == "CN=TSA"
    # Exception captured in chain_json for forensics.
    assert "Certificate has expired" in out.chain_json["verify_exception"]


def test_verify_pe_file_dual_signed(tmp_path: Path):
    """Mock signify with TWO signatures present (Persona-E sec.2 #3).
    signatures_count must reflect both even though we map verdict from one."""
    pe_file = tmp_path / "dualsig.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    sig1 = MagicMock(signer_info=MagicMock(certificate=None), countersigner=None)
    sig2 = MagicMock(signer_info=MagicMock(certificate=None), countersigner=None)

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([sig1, sig2])
    fake_af.explain_verify.return_value = (AuthenticodeVerificationResult.OK, None)

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is True
    assert out.signatures_count == 2
    assert out.chain_status == "valid_now"
    assert out.chain_json["signatures_count"] == 2


def test_verify_pe_file_no_signatures(tmp_path: Path):
    """Mock signify with empty signature iterator → signed=False."""
    pe_file = tmp_path / "unsigned.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([])

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is False
    assert out.chain_status == "unknown"
    assert out.signatures_count == 0


def test_verify_pe_file_explain_verify_raises(tmp_path: Path):
    """If explain_verify itself raises, surface as error but signed=True
    since signatures were enumerated."""
    pe_file = tmp_path / "weird.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([MagicMock()])
    fake_af.explain_verify.side_effect = RuntimeError("verify pipeline crashed")

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is True
    assert out.chain_status == "unknown"
    assert "verify pipeline crashed" in (out.error or "")


# ── arch_view plumbing (Phase β.5) ────────────────────────────────────────


def test_verify_pe_file_populates_arch_view_from_detector(tmp_path: Path):
    """β.5: verify_pe_file must call detect_pe_arch_view and copy the
    result onto the verdict's arch_view field, irrespective of signing
    state. The arch_view persists onto WindowsPESignature.arch_view JSONB.
    """
    pe_file = tmp_path / "arm64x.dll"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([])  # unsigned

    fake_arch_view = {
        "primary": "arm64x",
        "secondary": "amd64",
        "divergence_score": 17,
    }

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ), patch(
        "app.services.authenticode_service.detect_pe_arch_view",
        return_value=fake_arch_view,
    ) as mock_detect:
        out = verify_pe_file(pe_file)

    mock_detect.assert_called_once()
    assert out.arch_view == fake_arch_view
    # Unsigned PE — arch_view still ships.
    assert out.signed is False


def test_verify_pe_file_arch_view_none_on_single_arch(tmp_path: Path):
    """Single-arch PEs propagate arch_view=None onto the verdict — the
    column is nullable, NULL is the durable single-arch signal."""
    pe_file = tmp_path / "amd64.dll"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([])

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ), patch(
        "app.services.authenticode_service.detect_pe_arch_view",
        return_value=None,
    ):
        out = verify_pe_file(pe_file)

    assert out.arch_view is None


def test_verify_pe_file_arch_view_attached_when_pe_read_fails(tmp_path: Path):
    """When signify can't open the PE (OSError), the verdict still ships
    the arch_view if lief could read it — the two parsers are independent."""
    pe_file = tmp_path / "weird.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_arch_view = {
        "primary": "arm64ec",
        "secondary": "x64_abi",
        "divergence_score": 5,
    }

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        side_effect=OSError("simulated read failure"),
    ), patch(
        "app.services.authenticode_service.detect_pe_arch_view",
        return_value=fake_arch_view,
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is False
    assert out.chain_status == "unknown"
    assert out.arch_view == fake_arch_view
    assert "PE read failed" in (out.error or "")


def test_verify_pe_file_arch_view_attached_when_signify_parse_fails(tmp_path: Path):
    """When signify raises a non-OSError parse error, the arch_view still
    rides on the verdict — independent parsers, independent failure modes."""
    pe_file = tmp_path / "corrupt.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_arch_view = {
        "primary": "arm64x",
        "secondary": "amd64",
        "divergence_score": 0,
    }

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        side_effect=RuntimeError("malformed signature blob"),
    ), patch(
        "app.services.authenticode_service.detect_pe_arch_view",
        return_value=fake_arch_view,
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is False
    assert out.chain_status == "unknown"
    assert out.arch_view == fake_arch_view
    assert "PE parse failed" in (out.error or "")


# ── rich_header_json plumbing (Phase β.6) ─────────────────────────────────


def test_verify_pe_file_populates_rich_header_json_from_decoder(tmp_path: Path):
    """β.6: verify_pe_file must call decode_rich_header and copy the
    result onto the verdict's rich_header_json field, irrespective of
    signing state. The dict persists onto WindowsPESignature.rich_header_json."""
    pe_file = tmp_path / "ms.dll"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([])

    fake_rich = {
        "xor_key": "0x12345678",
        "entry_count": 1,
        "entries": [{"comp_id": 0x010500CC, "build_number": 0x0105,
                     "product_id": 0x00CC, "instances": 7}],
        "hash_md5": "abc",
    }

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ), patch(
        "app.services.authenticode_service.decode_rich_header",
        return_value=fake_rich,
    ) as mock_decode:
        out = verify_pe_file(pe_file)

    mock_decode.assert_called_once()
    assert out.rich_header_json == fake_rich


def test_verify_pe_file_rich_header_json_none_for_non_ms_toolchain(tmp_path: Path):
    """Non-Microsoft-toolchain PEs have no RICH header — verdict carries
    rich_header_json=None (the durable signal)."""
    pe_file = tmp_path / "mingw.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([])

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ), patch(
        "app.services.authenticode_service.decode_rich_header",
        return_value=None,
    ):
        out = verify_pe_file(pe_file)

    assert out.rich_header_json is None


def test_verify_pe_file_rich_header_json_attached_when_pe_read_fails(tmp_path: Path):
    """When signify can't open the PE (OSError), the verdict still ships
    rich_header_json if pefile could read it — independent parsers."""
    pe_file = tmp_path / "weird.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_rich = {
        "xor_key": "0x0", "entry_count": 0, "entries": [], "hash_md5": "x",
    }

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        side_effect=OSError("simulated read failure"),
    ), patch(
        "app.services.authenticode_service.decode_rich_header",
        return_value=fake_rich,
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is False
    assert out.chain_status == "unknown"
    assert out.rich_header_json == fake_rich
    assert "PE read failed" in (out.error or "")


def test_verify_pe_file_rich_header_json_attached_when_signify_parse_fails(
    tmp_path: Path,
):
    """When signify raises non-OSError, rich_header_json still rides."""
    pe_file = tmp_path / "corrupt.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_rich = {
        "xor_key": "0xABCDEF00", "entry_count": 0,
        "entries": [], "hash_md5": "y",
    }

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        side_effect=RuntimeError("malformed signature blob"),
    ), patch(
        "app.services.authenticode_service.decode_rich_header",
        return_value=fake_rich,
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is False
    assert out.chain_status == "unknown"
    assert out.rich_header_json == fake_rich
    assert "PE parse failed" in (out.error or "")


# ── dbx_revoked / dbx_revocation_kb plumbing (Phase β.7) ──────────────────


def test_verify_pe_file_dbx_revoked_when_serial_matches(tmp_path: Path):
    """β.7: a signed PE whose leaf serial appears in the bundle's revoked
    set produces verdict.dbx_revoked=True. The match function is patched
    at the authenticode_service boundary."""
    pe_file = tmp_path / "revoked.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_sig = MagicMock()
    fake_sig.signer_info = MagicMock()
    fake_sig.signer_info.certificate = MagicMock()
    fake_sig.signer_info.certificate.subject = "CN=Bad Signer"
    fake_sig.signer_info.certificate.issuer = "CN=Compromised CA"
    fake_sig.signer_info.certificate.serial_number = 0xDEADBEEF
    fake_sig.signer_info.digest_algorithm = "sha256"
    fake_sig.countersigner = None

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([fake_sig])
    fake_af.explain_verify.return_value = (
        AuthenticodeVerificationResult.CERTIFICATE_ERROR,
        Exception("revoked"),
    )

    fake_match = {
        "schema_version": 1,
        "revoked": True,
        "revocation_kb": "KB5012170",
        "leaf_serial_normalized": "DEADBEEF",
        "match_kind": "x509_serial",
        "bundle_entries": 5000,
        "bundle_path": "/opt/wairz/dbxupdate.bin",
    }

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ), patch(
        "app.services.authenticode_service.match_dbx_revocation",
        return_value=fake_match,
    ) as mock_match:
        out = verify_pe_file(pe_file)

    mock_match.assert_called_once_with("DEADBEEF")
    assert out.dbx_revoked is True
    assert out.dbx_revocation_kb == "KB5012170"


def test_verify_pe_file_dbx_not_revoked_when_serial_misses(tmp_path: Path):
    """β.7: signed PE whose serial is absent from the bundle produces
    dbx_revoked=False. Bundle was loaded; the answer is "not revoked"
    not "no information"."""
    pe_file = tmp_path / "ok.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_sig = MagicMock()
    fake_sig.signer_info = MagicMock()
    fake_sig.signer_info.certificate = MagicMock()
    fake_sig.signer_info.certificate.subject = "CN=Microsoft"
    fake_sig.signer_info.certificate.issuer = "CN=MS PCA 2011"
    fake_sig.signer_info.certificate.serial_number = 0x12345
    fake_sig.signer_info.digest_algorithm = "sha256"
    fake_sig.countersigner = None

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([fake_sig])
    fake_af.explain_verify.return_value = (AuthenticodeVerificationResult.OK, None)

    fake_match = {
        "schema_version": 1,
        "revoked": False,
        "revocation_kb": None,
        "leaf_serial_normalized": "12345",
        "match_kind": "none",
        "bundle_entries": 5000,
        "bundle_path": "/opt/wairz/dbxupdate.bin",
    }

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ), patch(
        "app.services.authenticode_service.match_dbx_revocation",
        return_value=fake_match,
    ):
        out = verify_pe_file(pe_file)

    assert out.dbx_revoked is False
    assert out.dbx_revocation_kb is None


def test_verify_pe_file_dbx_defaults_when_bundle_missing(tmp_path: Path):
    """β.7: when the matcher returns None (bundle not provisioned per
    β.10 deferral), the verdict carries the default dbx_revoked=False /
    dbx_revocation_kb=None — the "no DBX information" semantic."""
    pe_file = tmp_path / "ok.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_sig = MagicMock()
    fake_sig.signer_info = MagicMock()
    fake_sig.signer_info.certificate = MagicMock()
    fake_sig.signer_info.certificate.subject = "CN=X"
    fake_sig.signer_info.certificate.issuer = "CN=Y"
    fake_sig.signer_info.certificate.serial_number = 0xAB
    fake_sig.signer_info.digest_algorithm = "sha256"
    fake_sig.countersigner = None

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([fake_sig])
    fake_af.explain_verify.return_value = (AuthenticodeVerificationResult.OK, None)

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ), patch(
        "app.services.authenticode_service.match_dbx_revocation",
        return_value=None,
    ):
        out = verify_pe_file(pe_file)

    assert out.dbx_revoked is False
    assert out.dbx_revocation_kb is None


def test_verify_pe_file_dbx_defaults_when_pe_read_fails(tmp_path: Path):
    """β.7 four-path plumbing (Pattern #1): OSError verdict still ships
    dbx_revoked=False / dbx_revocation_kb=None — no PE means no leaf
    serial means no match attempt; the defaults are the truthful
    "no DBX information for this PE"."""
    pe_file = tmp_path / "weird.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        side_effect=OSError("simulated read failure"),
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is False
    assert out.chain_status == "unknown"
    assert out.dbx_revoked is False
    assert out.dbx_revocation_kb is None


def test_verify_pe_file_dbx_defaults_when_signify_parse_fails(tmp_path: Path):
    """β.7 four-path plumbing (Pattern #1): generic-Exception verdict
    still ships dbx default values. Independent parsers, independent
    failure modes — DBX matching is gated on a leaf serial we don't have
    when signify fails to parse."""
    pe_file = tmp_path / "corrupt.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        side_effect=RuntimeError("malformed signature blob"),
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is False
    assert out.chain_status == "unknown"
    assert out.dbx_revoked is False
    assert out.dbx_revocation_kb is None


def test_verify_pe_file_dbx_defaults_for_unsigned_pe(tmp_path: Path):
    """An unsigned PE (no signatures) skips the dbx match (no leaf serial
    to match) — defaults preserved."""
    pe_file = tmp_path / "unsigned.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)

    fake_af = MagicMock()
    fake_af.iter_signatures.return_value = iter([])  # zero signatures

    with patch(
        "app.services.authenticode_service.AuthenticodeFile.from_stream",
        return_value=fake_af,
    ):
        out = verify_pe_file(pe_file)

    assert out.signed is False
    assert out.dbx_revoked is False
    assert out.dbx_revocation_kb is None


# ── AuthenticodeVerdict shape contract ────────────────────────────────────


def test_verdict_maps_to_windows_pe_signature_columns():
    """Verify field names match WindowsPESignature columns 1:1.

    The ``DIRECT_MAPPED`` frozenset lives in
    :mod:`app.services.authenticode_chain_runner` (Phase β.8) — the
    runner imports it for the row-construction site
    ``WindowsPESignature(**asdict(verdict)|DIRECT_MAPPED, blob_id=...)``
    AND this test imports the same constant. Single source of truth
    keeps β.8 + the drift-detector synchronized; if the verdict gains
    a new field, updating ``DIRECT_MAPPED`` in one place propagates to
    both the runner and this test.

    If this test fails, the verdict, the model, OR the
    ``DIRECT_MAPPED`` set have drifted — fix all three together.
    """
    from app.models import WindowsPESignature
    from app.services.authenticode_chain_runner import DIRECT_MAPPED

    verdict = AuthenticodeVerdict(signed=True, chain_status="valid_now")

    # Every field on the verdict either lives in DIRECT_MAPPED (spread
    # 1:1 onto WindowsPESignature columns) or in ``indirect`` (in
    # chain_json or runner-level — not on the model).
    indirect = {"signatures_count", "error"}  # in chain_json / runner-level
    verdict_fields = set(verdict.__dataclass_fields__.keys())

    assert verdict_fields == DIRECT_MAPPED | indirect, (
        f"verdict fields drifted: {verdict_fields ^ (DIRECT_MAPPED | indirect)}"
    )
    for name in DIRECT_MAPPED:
        assert hasattr(WindowsPESignature, name), (
            f"WindowsPESignature missing column for verdict field {name}"
        )
