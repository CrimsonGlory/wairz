"""Tests for unpack_audit_service — promotes vendor_decryption /
extraction_diagnostics into Finding rows.

Pure-function extractors are tested directly; ``run()`` is tested
against a mocked AsyncSession factory.

Reference fixture: real RespArray data was harvested from firmware
6f8f9cc2-e05f-45b3-9a02-8af47f7c9b96 (project 00815038-…). The
synthetic key/iv match the production triple to keep the test fixture
realistic — this is a known-good vendor key, not a secret.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.unpack_audit_service import (
    UNPACK_AUDIT_SOURCE,
    _extract_aes_key_findings,
    _extract_partial_extraction_findings,
    _extract_signed_archive_finding,
    run,
)


# Real RespArray triple (recovered from force_update.sh:755).
_KEY = "43c8e032ff65f5cc762d1dc15580d425"
_IV = "50719d498aa89db2d3fccac9ff310c79"
_KEY_SOURCE = (
    "RespArray_1.05.00.17.zip_extract/target/zImage-restore.tar.xz_extract/"
    "xz.uncompressed_extract/zImage-restore/zImage-restore_extract/"
    "59945-21865201.gzip_extract/gzip.uncompressed_extract/"
    "14001444-29725989.gzip_extract/gzip.uncompressed_extract/"
    "usr/sbin/force_update.sh:755"
)
_ARCHIVES = [
    "RespArray_1.05.00.17.zip_extract/target/rootfs_partition.tar.xz",
    "RespArray_1.05.00.17.zip_extract/target/scripts.tar.xz",
    "RespArray_1.05.00.17.zip_extract/target/libqt.tar.xz",
    "RespArray_1.05.00.17.zip_extract/target/nxapp-0.2.2-Linux.tar.xz",
    "RespArray_1.05.00.17.zip_extract/target/boot_partition.tar.xz",
    "RespArray_1.05.00.17.zip_extract/target/nxcore-0.2.2-Linux.tar.xz",
]


def _vendor_decryption(archives: list[str] | None = None) -> list[dict]:
    """Build a vendor_decryption audit list — one entry per archive,
    all citing the same triple (production shape)."""
    return [
        {
            "algorithm": "aes-128-cbc",
            "key_hex": _KEY,
            "iv_hex": _IV,
            "key_source": _KEY_SOURCE,
            "archive": a,
        }
        for a in (archives or _ARCHIVES)
    ]


def _extraction_diagnostics(archives: list[str] | None = None) -> dict:
    """Match the upload-time diagnostics shape from
    diagnose_failed_archives — note this is written BEFORE decrypt."""
    paths = archives or [
        "target/rootfs_partition.tar.xz",
        "target/scripts.tar.xz",
        "target/libqt.tar.xz",
        "target/nxapp-0.2.2-Linux.tar.xz",
        "target/boot_partition.tar.xz",
        "target/nxcore-0.2.2-Linux.tar.xz",
    ]
    return {
        "summary": f"{len(paths)} archive(s) not extracted: {len(paths)} vendor-encrypted (edan)",
        "encrypted_archives": [
            {
                "path": p,
                "size_bytes": 1000,
                "suffix": ".tar.xz",
                "magic_hex": "a3dfbbbf4e947c6649859f5e45d273ed",
                "format": "edan_mpm_signed",
                "vendor": "edan",
                "note": "EDAN MPM signed firmware container (AM43xx platform). Payload is vendor-encrypted; decryption key must be recovered from nxapp/nxcore via Ghidra.",
            }
            for p in paths
        ],
        "partial_extraction": True,
        "unrecognised_archives": [],
    }


# ---------------------------------------------------------------------------
# _extract_aes_key_findings — F1+F2+F3 + dedup
# ---------------------------------------------------------------------------


def test_emits_three_findings_per_triple_for_clean_decrypt():
    fid = uuid.uuid4()
    meta = {"vendor_decryption": _vendor_decryption()}
    findings = _extract_aes_key_findings(meta, fid)
    assert len(findings) == 3, f"expected 3 (F1+F2+F3), got {len(findings)}"

    titles = [f.title for f in findings]
    assert any("Hardcoded AES-128-CBC key" in t for t in titles), "F1 missing"
    assert any("Static IV reused" in t for t in titles), "F2 missing"
    assert any("Decryption key shipped in plaintext" in t for t in titles), "F3 missing"

    # F1 = high; F2/F3 = medium
    f1 = next(f for f in findings if "Hardcoded" in f.title)
    assert f1.severity.value == "high"
    assert f1.confidence.value == "high"
    assert f1.cwe_ids == ["CWE-798", "CWE-321"]

    f2 = next(f for f in findings if "Static IV" in f.title)
    assert f2.severity.value == "medium"
    assert f2.cwe_ids == ["CWE-323", "CWE-329"]
    assert "across 6 AES-CBC ciphertexts" in f2.title

    f3 = next(f for f in findings if "Decryption key shipped" in f.title)
    assert f3.severity.value == "medium"
    assert f3.cwe_ids == ["CWE-312", "CWE-256"]


def test_dedup_collapses_repeated_triples():
    """Six audit entries citing the same (algo, key, iv) → one F1+F2+F3 set."""
    fid = uuid.uuid4()
    meta = {"vendor_decryption": _vendor_decryption()}
    findings = _extract_aes_key_findings(meta, fid)
    assert len(findings) == 3, "Six identical triples must produce 3 findings, not 18"


def test_two_distinct_triples_emit_two_finding_sets():
    """If a firmware ever ships two distinct triples, emit 2 sets."""
    fid = uuid.uuid4()
    audit = _vendor_decryption(archives=["archive_a.tar.xz"])
    audit_b = [
        {
            "algorithm": "aes-256-cbc",
            "key_hex": "ab" * 32,  # 64 hex chars for AES-256
            "iv_hex": "cd" * 16,
            "key_source": "scripts/install.sh:42",
            "archive": "archive_b.tar.xz",
        }
    ]
    meta = {"vendor_decryption": audit + audit_b}
    findings = _extract_aes_key_findings(meta, fid)
    # First triple (1 archive) → F1+F3 only (F2 needs 2+ archives)
    # Second triple (1 archive) → F1+F3 only
    assert len(findings) == 4


def test_single_archive_does_not_emit_iv_reuse():
    """F2 requires 2+ archives sharing the same IV."""
    fid = uuid.uuid4()
    meta = {"vendor_decryption": _vendor_decryption(archives=["only.tar.xz"])}
    findings = _extract_aes_key_findings(meta, fid)
    assert len(findings) == 2, "single-archive triple = F1+F3, no F2"
    assert not any("Static IV" in f.title for f in findings)


def test_file_path_and_line_number_parsed_from_key_source():
    fid = uuid.uuid4()
    meta = {"vendor_decryption": _vendor_decryption()}
    findings = _extract_aes_key_findings(meta, fid)
    f1 = next(f for f in findings if "Hardcoded" in f.title)
    assert f1.line_number == 755
    assert f1.file_path is not None
    assert f1.file_path.endswith("/usr/sbin/force_update.sh")


def test_evidence_carries_full_triple_and_archive_list():
    fid = uuid.uuid4()
    meta = {"vendor_decryption": _vendor_decryption()}
    findings = _extract_aes_key_findings(meta, fid)
    f1 = next(f for f in findings if "Hardcoded" in f.title)
    assert _KEY in f1.evidence
    assert _IV in f1.evidence
    for archive in _ARCHIVES:
        assert archive in f1.evidence


def test_empty_audit_returns_empty():
    assert _extract_aes_key_findings({}, uuid.uuid4()) == []
    assert _extract_aes_key_findings({"vendor_decryption": []}, uuid.uuid4()) == []
    assert _extract_aes_key_findings({"vendor_decryption": None}, uuid.uuid4()) == []


def test_malformed_audit_entries_skipped():
    fid = uuid.uuid4()
    meta = {"vendor_decryption": [
        {"algorithm": "aes-128-cbc"},  # missing key/iv
        {"key_hex": _KEY, "iv_hex": _IV},  # missing algo
        {},  # empty
    ]}
    assert _extract_aes_key_findings(meta, fid) == []


# ---------------------------------------------------------------------------
# _extract_partial_extraction_findings — gap, not non-emptiness
# ---------------------------------------------------------------------------


def test_clean_decrypt_emits_no_partial_findings():
    """All 6 archives decrypted → 0 'key not recovered' findings.

    This is the Rule #31 width-canary case: extraction_diagnostics
    still lists 6 encrypted archives even after they all succeeded
    (the dict is upload-time and never updated post-decrypt). The
    extractor must compute set-difference, not non-emptiness.
    """
    fid = uuid.uuid4()
    meta = {
        "vendor_decryption": _vendor_decryption(),
        "extraction_diagnostics": _extraction_diagnostics(),
    }
    findings = _extract_partial_extraction_findings(meta, fid)
    assert findings == [], f"expected 0 findings on full decrypt, got {len(findings)}"


def test_partial_decrypt_emits_one_per_undecrypted_archive():
    """3 encrypted, 1 decrypted → 2 info findings."""
    fid = uuid.uuid4()
    paths = ["target/a.tar.xz", "target/b.tar.xz", "target/c.tar.xz"]
    meta = {
        "vendor_decryption": _vendor_decryption(archives=["X/target/a.tar.xz"]),
        "extraction_diagnostics": _extraction_diagnostics(archives=paths),
    }
    findings = _extract_partial_extraction_findings(meta, fid)
    titles = [f.title for f in findings]
    paths_in_findings = [f.file_path for f in findings]
    assert len(findings) == 2
    assert "target/b.tar.xz" in paths_in_findings
    assert "target/c.tar.xz" in paths_in_findings
    assert "target/a.tar.xz" not in paths_in_findings
    for t in titles:
        assert "edan/edan_mpm_signed" in t


def test_no_encrypted_archives_no_findings():
    fid = uuid.uuid4()
    assert _extract_partial_extraction_findings({}, fid) == []
    assert _extract_partial_extraction_findings(
        {"extraction_diagnostics": {"encrypted_archives": []}}, fid,
    ) == []


def test_partial_finding_severity_is_info():
    fid = uuid.uuid4()
    meta = {
        "vendor_decryption": [],
        "extraction_diagnostics": _extraction_diagnostics(archives=["target/x.tar.xz"]),
    }
    findings = _extract_partial_extraction_findings(meta, fid)
    assert len(findings) == 1
    assert findings[0].severity.value == "info"


# ---------------------------------------------------------------------------
# _extract_signed_archive_finding — bootloader signature surface
# ---------------------------------------------------------------------------


def test_signed_archive_finding_fires_when_format_present():
    fid = uuid.uuid4()
    meta = {"extraction_diagnostics": _extraction_diagnostics()}
    findings = _extract_signed_archive_finding(meta, fid)
    assert len(findings) == 1
    assert "edan_mpm_signed" in findings[0].title
    assert findings[0].severity.value == "info"


def test_no_signed_archive_finding_without_format():
    fid = uuid.uuid4()
    assert _extract_signed_archive_finding({}, fid) == []
    assert _extract_signed_archive_finding(
        {"extraction_diagnostics": {"encrypted_archives": [
            {"path": "x.tar.xz"},  # no format key
        ]}}, fid,
    ) == []


# ---------------------------------------------------------------------------
# run() — mocked AsyncSession integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_skips_when_firmware_missing():
    fid = uuid.uuid4()
    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=None)

    mock_factory = MagicMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_db)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("app.services.unpack_audit_service.async_session_factory", mock_factory):
        count = await run(fid)
    assert count == 0
    # Must not have issued DELETE / commit
    mock_db.execute.assert_not_called()
    mock_db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_run_emits_three_for_clean_decrypt():
    fid = uuid.uuid4()
    pid = uuid.uuid4()

    fw = MagicMock()
    fw.project_id = pid
    fw.device_metadata = {
        "vendor_decryption": _vendor_decryption(),
        "extraction_diagnostics": _extraction_diagnostics(),
    }

    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=fw)
    mock_db.add = MagicMock()
    mock_db.execute = AsyncMock()
    mock_db.flush = AsyncMock()
    mock_db.commit = AsyncMock()

    mock_factory = MagicMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_db)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("app.services.unpack_audit_service.async_session_factory", mock_factory):
        count = await run(fid)

    # F1 + F2 + F3 + signed-archive info = 4. No partial-extraction
    # findings (all decrypted).
    assert count == 4
    # DELETE was called once before INSERTs
    assert mock_db.execute.call_count == 1
    # Each finding triggered FindingService.create → db.add + db.flush
    assert mock_db.add.call_count == 4
    assert mock_db.commit.call_count == 1


@pytest.mark.asyncio
async def test_run_idempotent_clears_prior_findings_on_empty_meta():
    """Even when there's nothing to emit, prior unpack_audit findings
    for this firmware are cleared. Lets a re-unpack with new
    (empty) state revoke stale findings."""
    fid = uuid.uuid4()
    pid = uuid.uuid4()

    fw = MagicMock()
    fw.project_id = pid
    fw.device_metadata = {}

    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=fw)
    mock_db.execute = AsyncMock()
    mock_db.commit = AsyncMock()

    mock_factory = MagicMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_db)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("app.services.unpack_audit_service.async_session_factory", mock_factory):
        count = await run(fid)
    assert count == 0
    # DELETE still happens
    assert mock_db.execute.call_count == 1
    assert mock_db.commit.call_count == 1
