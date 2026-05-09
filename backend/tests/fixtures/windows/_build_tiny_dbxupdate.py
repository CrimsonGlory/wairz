"""Generator for ``tiny.dbxupdate.bin`` — Phase β.10 test fixture.

Produces a 2 X.509 + 1 SHA256 entry synthetic dbxupdate.bin written in
the bare ``EFI_SIGNATURE_LIST`` format (β.7's parser shape — no
``EFI_VARIABLE_AUTHENTICATION_2`` wrapper). The fixture exercises the
file-on-disk path of :mod:`app.services.dbx_service` with the same
shape ``test_dbx_service.py``'s in-memory builders use.

A second helper, ``build_tiny_wrapped_dbxupdate``, produces a
synthetic Microsoft-canonical-shaped bundle (with a minimal
``EFI_VARIABLE_AUTHENTICATION_2`` header) so the wrapper-strip code
path has a deterministic test target without depending on the live
Microsoft bundle.

Re-run from the repo root to regenerate:

    python3 backend/tests/fixtures/windows/_build_tiny_dbxupdate.py

Cert serials are deterministic; RSA keys are fresh per-run, so the
exact byte-content of the regenerated file may shift even when the
schema doesn't change. Tests assert structural properties (entries
scanned, expected serials present), NOT byte-for-byte equality.
"""
from __future__ import annotations

import datetime as dt
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

EFI_CERT_X509_GUID = bytes.fromhex("a159c0a5e494a74a87b5ab155c2bf072")
EFI_CERT_SHA256_GUID = bytes.fromhex("2616c4c14c509240aca941f936934328")
_OWNER_GUID = bytes.fromhex("bd9afa775903324dbd6028f4e78f784b")
_WIN_CERT_TYPE_EFI_GUID = 0x0EF1


def _build_x509_cert_der(serial: int, common_name: str = "wairz-test") -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.UTC))
        .not_valid_after(dt.datetime(2027, 1, 1, tzinfo=dt.UTC))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _build_signature_list(sig_type: bytes, payloads: list[bytes]) -> bytes:
    if not payloads:
        return b""
    sig_size = 16 + len(payloads[0])
    if not all(len(p) == sig_size - 16 for p in payloads):
        raise ValueError("uniform sig_size per list")
    sigs_blob = b"".join(_OWNER_GUID + p for p in payloads)
    sig_list_size = 28 + len(sigs_blob)
    header = struct.pack("<16sIII", sig_type, sig_list_size, 0, sig_size)
    return header + sigs_blob


def build_tiny_dbxupdate() -> bytes:
    """Bare EFI_SIGNATURE_LIST format: 2 X.509 entries + 1 SHA256."""
    der1 = _build_x509_cert_der(0xCAFE, "wairz-test-cafe")
    der2 = _build_x509_cert_der(0xDEAD, "wairz-test-dead")
    sha256_payload = b"\x42" * 32
    return b"".join([
        _build_signature_list(EFI_CERT_X509_GUID, [der1]),
        _build_signature_list(EFI_CERT_X509_GUID, [der2]),
        _build_signature_list(EFI_CERT_SHA256_GUID, [sha256_payload]),
    ])


def build_tiny_wrapped_dbxupdate() -> bytes:
    """Microsoft-canonical-shaped: EFI_VARIABLE_AUTHENTICATION_2 wrapper +
    bare list payload. The wrapper's CertData is opaque dummy bytes
    (we don't sign — wairz's parser only strips, never verifies the
    wrapper's PKCS#7 signature; the integrity check is the SHA256 pin
    in backend/ms-anchors/)."""
    inner = build_tiny_dbxupdate()
    # EFI_TIME: year=2026, month=5, day=8 (β.10 build date).
    efi_time = struct.pack(
        "<HBBBBBBIhBB",
        2026, 5, 8, 12, 0, 0, 0, 0, 0, 0, 0,
    )
    assert len(efi_time) == 16
    cert_type_guid = b"\x9d\xd2\xafJ\xdfh\xeeI\x8a\xa94}7Ve\xa7"
    cert_data = b"\x00" * 64  # opaque PKCS#7 placeholder
    dw_length = 4 + 2 + 2 + 16 + len(cert_data)
    win_cert = (
        struct.pack("<IHH", dw_length, 0x0200, _WIN_CERT_TYPE_EFI_GUID)
        + cert_type_guid
        + cert_data
    )
    return efi_time + win_cert + inner


def main() -> None:
    here = Path(__file__).parent
    bare_path = here / "tiny.dbxupdate.bin"
    bare_path.write_bytes(build_tiny_dbxupdate())
    print(f"wrote {bare_path} ({bare_path.stat().st_size} bytes)")

    wrapped_path = here / "tiny.dbxupdate.wrapped.bin"
    wrapped_path.write_bytes(build_tiny_wrapped_dbxupdate())
    print(f"wrote {wrapped_path} ({wrapped_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
