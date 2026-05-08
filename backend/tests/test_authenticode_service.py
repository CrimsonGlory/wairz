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


# ── AuthenticodeVerdict shape contract ────────────────────────────────────


def test_verdict_maps_to_windows_pe_signature_columns():
    """Verify field names match WindowsPESignature columns 1:1.
    If this test fails, the model and verdict have drifted — update both."""
    from app.models import WindowsPESignature

    verdict = AuthenticodeVerdict(signed=True, chain_status="valid_now")

    # Every field on the verdict must exist on the model (or be implicitly
    # mapped — chain_json → chain_json, signatures_count is on chain_json
    # not the model directly).
    direct_mapped = {
        "signed", "chain_status", "signer_subject", "signer_issuer",
        "leaf_serial", "sig_hash_algo", "tsa_authority", "signed_at",
        "chain_json", "arch_view",
    }
    indirect = {"signatures_count", "error"}  # in chain_json / runner-level
    verdict_fields = set(verdict.__dataclass_fields__.keys())

    assert verdict_fields == direct_mapped | indirect, (
        f"verdict fields drifted: {verdict_fields ^ (direct_mapped | indirect)}"
    )
    for name in direct_mapped:
        assert hasattr(WindowsPESignature, name), (
            f"WindowsPESignature missing column for verdict field {name}"
        )
