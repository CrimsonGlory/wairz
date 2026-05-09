"""Phase β.9 contract tests: windows_pe_signature MCP tools.

Mirrors the α.4 ``test_windows_archive_tools.py`` shape: stub
ToolContext + mocked service-layer calls. The β.4-β.7 services
themselves are tested separately under
``test_authenticode_service.py`` / ``test_dbx_service.py`` /
``test_rich_header_service.py`` / ``test_format_detection.py``;
this file verifies the MCP-tool layer's path-resolution + JSON
shaping + error-path handling.

Two of the six tools (``list_signatures``, ``get_signature_chain``)
read ``WindowsPESignature`` rows from the DB — those get Rule #35b
live canaries via ``tests._live_db.make_live_db`` so the SELECT
round-trip is exercised, not just mocked.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.windows_pe_signature import (
    _handle_decode_rich_header,
    _handle_detect_pe_arch_view,
    _handle_get_signature_chain,
    _handle_list_signatures,
    _handle_scan_dbx_revocation,
    _handle_verify_authenticode,
    register_windows_pe_signature_tools,
)
from app.models import (
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsPESignature,
)
from app.services.authenticode_service import AuthenticodeVerdict
from tests._live_db import make_live_db

# ── Stub ToolContext ──────────────────────────────────────────────────────


@dataclass
class _StubContext:
    """Minimal ToolContext stub for unit testing the MCP handlers.

    Only exposes the attributes/methods the handlers actually use:
    resolve_path() + extracted_path + firmware_id + db. Real
    ToolContext has project_id, review_id, etc. — irrelevant here.
    """

    extracted_path: str
    firmware_id: uuid.UUID = uuid.uuid4()
    db: object = None

    def resolve_path(self, path: str) -> str:
        full = os.path.join(self.extracted_path, path.lstrip("/"))
        full_real = os.path.realpath(full)
        root_real = os.path.realpath(self.extracted_path)
        if not full_real.startswith(root_real):
            raise ValueError(f"Path traversal: {path}")
        return full_real


# ── Registration smoke ────────────────────────────────────────────────────


def test_register_windows_pe_signature_tools_registers_six_tools():
    """The category must register exactly the six tools the PRD names —
    no more, no less. A drift-detection guard against silently dropping
    or duplicating a tool registration."""
    reg = ToolRegistry()
    register_windows_pe_signature_tools(reg)
    names = sorted(reg._tools.keys())  # type: ignore[attr-defined]
    assert names == [
        "decode_rich_header",
        "detect_pe_arch_view",
        "get_signature_chain",
        "list_signatures",
        "scan_dbx_revocation",
        "verify_authenticode",
    ]


# ── verify_authenticode ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_authenticode_handles_missing_file(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_verify_authenticode({"path": "missing.exe"}, ctx)
    assert "PE file not found" in out


@pytest.mark.asyncio
async def test_verify_authenticode_returns_json_verdict(tmp_path: Path):
    pe = tmp_path / "vendor.dll"
    pe.write_bytes(b"MZ" + b"\x00" * 200)
    ctx = _StubContext(extracted_path=str(tmp_path))

    fake_verdict = AuthenticodeVerdict(
        signed=True,
        chain_status="valid_now",
        signer_subject="CN=Microsoft Windows",
        leaf_serial="DEADBEEF",
        sig_hash_algo="sha256",
        signed_at=datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC),
        signatures_count=1,
        chain_json={"verification_result": "OK"},
    )

    with patch(
        "app.ai.tools.windows_pe_signature.verify_pe_file",
        return_value=fake_verdict,
    ):
        out = await _handle_verify_authenticode({"path": "vendor.dll"}, ctx)

    parsed = json.loads(out)
    assert parsed["signed"] is True
    assert parsed["chain_status"] == "valid_now"
    assert parsed["leaf_serial"] == "DEADBEEF"
    # Datetime serialised via _json_default → isoformat.
    assert parsed["signed_at"].startswith("2024-06-15")


@pytest.mark.asyncio
async def test_verify_authenticode_catches_unexpected_exec_error(tmp_path: Path):
    """verify_pe_file is supposed to never raise. Defend against an
    executor bug that would propagate an exception up the MCP layer."""
    pe = tmp_path / "weird.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 200)
    ctx = _StubContext(extracted_path=str(tmp_path))

    with patch(
        "app.ai.tools.windows_pe_signature.verify_pe_file",
        side_effect=RuntimeError("simulated executor crash"),
    ):
        out = await _handle_verify_authenticode({"path": "weird.exe"}, ctx)

    assert "verify_authenticode failed" in out
    assert "RuntimeError" in out
    assert "simulated executor crash" in out


# ── decode_rich_header ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_decode_rich_header_handles_missing_file(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_decode_rich_header({"path": "missing.exe"}, ctx)
    assert "PE file not found" in out


@pytest.mark.asyncio
async def test_decode_rich_header_returns_null_for_non_ms_toolchain(
    tmp_path: Path,
):
    pe = tmp_path / "mingw.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 200)
    ctx = _StubContext(extracted_path=str(tmp_path))

    with patch(
        "app.ai.tools.windows_pe_signature.decode_rich_header",
        return_value=None,
    ):
        out = await _handle_decode_rich_header({"path": "mingw.exe"}, ctx)

    assert "No RICH header" in out


@pytest.mark.asyncio
async def test_decode_rich_header_returns_json_when_present(tmp_path: Path):
    pe = tmp_path / "ms.dll"
    pe.write_bytes(b"MZ" + b"\x00" * 200)
    ctx = _StubContext(extracted_path=str(tmp_path))

    fake_decoded = {
        "xor_key": "0x12345678",
        "entry_count": 2,
        "entries": [{"comp_id": 0x010500CC, "instances": 7}],
        "hash_md5": "abcdef",
    }

    with patch(
        "app.ai.tools.windows_pe_signature.decode_rich_header",
        return_value=fake_decoded,
    ):
        out = await _handle_decode_rich_header({"path": "ms.dll"}, ctx)

    parsed = json.loads(out)
    assert parsed == fake_decoded


# ── scan_dbx_revocation ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_dbx_revocation_rejects_both_args(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_scan_dbx_revocation(
        {"leaf_serial": "DEADBEEF", "path": "vendor.exe"}, ctx,
    )
    assert "exactly one of" in out


@pytest.mark.asyncio
async def test_scan_dbx_revocation_rejects_neither_arg(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_scan_dbx_revocation({}, ctx)
    assert "Neither was provided" in out


@pytest.mark.asyncio
async def test_scan_dbx_revocation_returns_match_for_serial(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
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
        "app.ai.tools.windows_pe_signature.match_dbx_revocation",
        return_value=fake_match,
    ):
        out = await _handle_scan_dbx_revocation(
            {"leaf_serial": "DEADBEEF"}, ctx,
        )

    parsed = json.loads(out)
    assert parsed["revoked"] is True
    assert parsed["revocation_kb"] == "KB5012170"


@pytest.mark.asyncio
async def test_scan_dbx_revocation_handles_bundle_missing(tmp_path: Path):
    """When match_dbx_revocation returns None (β.10 deferral), the
    tool surfaces an explicit 'bundle not provisioned' message rather
    than silently returning 'null' — the operator needs to know
    why."""
    ctx = _StubContext(extracted_path=str(tmp_path))
    with patch(
        "app.ai.tools.windows_pe_signature.match_dbx_revocation",
        return_value=None,
    ):
        out = await _handle_scan_dbx_revocation(
            {"leaf_serial": "ABCDEF"}, ctx,
        )
    assert "bundle not provisioned" in out
    assert "ABCDEF" in out


@pytest.mark.asyncio
async def test_scan_dbx_revocation_extracts_serial_from_pe(tmp_path: Path):
    """Path branch: the tool runs verify_pe_file to extract the serial,
    then forwards to match_dbx_revocation."""
    pe = tmp_path / "vendor.dll"
    pe.write_bytes(b"MZ" + b"\x00" * 200)
    ctx = _StubContext(extracted_path=str(tmp_path))

    fake_verdict = AuthenticodeVerdict(
        signed=True, chain_status="valid_now", leaf_serial="C0FFEE",
    )
    fake_match = {
        "schema_version": 1,
        "revoked": False,
        "leaf_serial_normalized": "C0FFEE",
        "match_kind": "none",
    }

    with patch(
        "app.ai.tools.windows_pe_signature.verify_pe_file",
        return_value=fake_verdict,
    ), patch(
        "app.ai.tools.windows_pe_signature.match_dbx_revocation",
        return_value=fake_match,
    ) as mock_match:
        out = await _handle_scan_dbx_revocation({"path": "vendor.dll"}, ctx)

    # The tool extracted the serial then forwarded it to match.
    mock_match.assert_called_once_with("C0FFEE")
    parsed = json.loads(out)
    assert parsed["revoked"] is False


@pytest.mark.asyncio
async def test_scan_dbx_revocation_pe_without_signer_info(tmp_path: Path):
    """If verify_pe_file produces a verdict with no leaf_serial (unsigned
    PE), the tool reports the gap rather than calling match with None."""
    pe = tmp_path / "unsigned.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 200)
    ctx = _StubContext(extracted_path=str(tmp_path))

    fake_verdict = AuthenticodeVerdict(
        signed=False, chain_status="unknown", leaf_serial=None,
    )

    with patch(
        "app.ai.tools.windows_pe_signature.verify_pe_file",
        return_value=fake_verdict,
    ):
        out = await _handle_scan_dbx_revocation({"path": "unsigned.exe"}, ctx)

    assert "no extractable leaf certificate serial" in out


# ── detect_pe_arch_view ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_detect_pe_arch_view_handles_missing_file(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_detect_pe_arch_view({"path": "missing.exe"}, ctx)
    assert "PE file not found" in out


@pytest.mark.asyncio
async def test_detect_pe_arch_view_returns_json_for_bimorphic(tmp_path: Path):
    pe = tmp_path / "arm64x.dll"
    pe.write_bytes(b"MZ" + b"\x00" * 200)
    ctx = _StubContext(extracted_path=str(tmp_path))

    fake_view = {
        "primary": "arm64x",
        "secondary": "amd64",
        "divergence_score": 17,
    }
    with patch(
        "app.ai.tools.windows_pe_signature.detect_pe_arch_view",
        return_value=fake_view,
    ):
        out = await _handle_detect_pe_arch_view({"path": "arm64x.dll"}, ctx)

    parsed = json.loads(out)
    assert parsed == fake_view


@pytest.mark.asyncio
async def test_detect_pe_arch_view_null_for_single_arch(tmp_path: Path):
    pe = tmp_path / "amd64.dll"
    pe.write_bytes(b"MZ" + b"\x00" * 200)
    ctx = _StubContext(extracted_path=str(tmp_path))

    with patch(
        "app.ai.tools.windows_pe_signature.detect_pe_arch_view",
        return_value=None,
    ):
        out = await _handle_detect_pe_arch_view({"path": "amd64.dll"}, ctx)

    assert "single-arch" in out


# ── list_signatures + get_signature_chain — Rule #35b live canaries ────────


async def _seed_pe_signature_row(db, *, blob_basename: str = "vendor.sys"):
    """Seed Project + Firmware + HardwareFirmwareBlob + WindowsPESignature
    so the read-side tools can SELECT against a live row."""
    project = Project(name="pe-sig-mcp-test", description="β.9")
    db.add(project)
    await db.flush()
    fw = Firmware(
        project_id=project.id,
        original_filename="windows.cab",
        file_size=4096,
        sha256="d" * 64,
    )
    db.add(fw)
    await db.flush()
    blob = HardwareFirmwareBlob(
        firmware_id=fw.id,
        blob_path=f"/firmware/extracted/{blob_basename}",
        blob_sha256="b" * 64,
        file_size=2048,
        category="other",
        format="raw_bin",
        detection_source="test",
    )
    db.add(blob)
    await db.flush()
    sig = WindowsPESignature(
        blob_id=blob.id,
        signed=True,
        chain_status="valid_now",
        signer_subject="CN=Microsoft Windows",
        signer_issuer="CN=Microsoft Code Signing PCA 2011",
        leaf_serial="DEADBEEF",
        sig_hash_algo="sha256",
        chain_json={"verification_result": "OK"},
    )
    db.add(sig)
    await db.flush()
    return fw, blob, sig


@pytest.mark.asyncio
async def test_list_signatures_returns_persisted_rows(tmp_path: Path):
    async with make_live_db() as db:
        fw, blob, sig = await _seed_pe_signature_row(db)
        await db.commit()

        ctx = _StubContext(
            extracted_path=str(tmp_path),
            firmware_id=fw.id,
            db=db,
        )
        out = await _handle_list_signatures({}, ctx)

    assert "Found 1 signature row" in out
    assert blob.blob_path in out
    assert "DEADBEEF" in out
    assert "valid_now" in out


@pytest.mark.asyncio
async def test_list_signatures_filters_by_chain_status(tmp_path: Path):
    async with make_live_db() as db:
        fw, blob, _ = await _seed_pe_signature_row(db)
        await db.commit()

        ctx = _StubContext(
            extracted_path=str(tmp_path),
            firmware_id=fw.id,
            db=db,
        )
        # Filter does not match — empty result.
        out = await _handle_list_signatures(
            {"chain_status": "revoked"}, ctx,
        )

    assert "No WindowsPESignature rows" in out


@pytest.mark.asyncio
async def test_list_signatures_rejects_invalid_filter(tmp_path: Path):
    """Validate the filter against the chain_status enum — bogus values
    fail with an explicit error rather than silently returning 0 rows."""
    async with make_live_db() as db:
        fw, _, _ = await _seed_pe_signature_row(db)
        await db.commit()

        ctx = _StubContext(
            extracted_path=str(tmp_path),
            firmware_id=fw.id,
            db=db,
        )
        out = await _handle_list_signatures(
            {"chain_status": "bogus_status"}, ctx,
        )

    assert "Invalid chain_status" in out


@pytest.mark.asyncio
async def test_get_signature_chain_matches_by_basename(tmp_path: Path):
    async with make_live_db() as db:
        fw, blob, sig = await _seed_pe_signature_row(
            db, blob_basename="custom.sys",
        )
        await db.commit()

        ctx = _StubContext(
            extracted_path=str(tmp_path),
            firmware_id=fw.id,
            db=db,
        )
        # Pass just the basename — the tool extracts and matches.
        out = await _handle_get_signature_chain({"path": "custom.sys"}, ctx)

    parsed = json.loads(out)
    assert parsed["leaf_serial"] == "DEADBEEF"
    assert parsed["chain_status"] == "valid_now"
    assert parsed["signer_subject"] == "CN=Microsoft Windows"
    assert parsed["chain_json"] == {"verification_result": "OK"}


@pytest.mark.asyncio
async def test_get_signature_chain_no_match_explains(tmp_path: Path):
    async with make_live_db() as db:
        fw, _, _ = await _seed_pe_signature_row(db)
        await db.commit()

        ctx = _StubContext(
            extracted_path=str(tmp_path),
            firmware_id=fw.id,
            db=db,
        )
        out = await _handle_get_signature_chain(
            {"path": "nonexistent.dll"}, ctx,
        )

    assert "No WindowsPESignature row matches basename" in out


@pytest.mark.asyncio
async def test_get_signature_chain_full_path_falls_back_to_basename(
    tmp_path: Path,
):
    """The tool accepts either a basename or a full firmware-tree path
    — it derives the basename internally."""
    async with make_live_db() as db:
        fw, _, _ = await _seed_pe_signature_row(
            db, blob_basename="vendor.sys",
        )
        await db.commit()

        ctx = _StubContext(
            extracted_path=str(tmp_path),
            firmware_id=fw.id,
            db=db,
        )
        # Pass a full virtualised path; the tool basename-extracts.
        out = await _handle_get_signature_chain(
            {"path": "/rootfs/system32/drivers/vendor.sys"}, ctx,
        )

    parsed = json.loads(out)
    assert parsed["leaf_serial"] == "DEADBEEF"
