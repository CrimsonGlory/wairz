"""Tests for the Phase θ.C.C ESP `.efi` PE chain walker.

Critical test: ``test_esp_no_efi_execution`` — the Rule #36
no-execute gate. The ESP walker module MUST contain ZERO process-
spawn primitives. `.efi` files are PE32+ binaries; the walker treats
them as DATA via signify (Authenticode chain reader), pefile (COFF
reader), and the β.10 DBX matcher (byte/serial comparison). NO
codepath in this walker may invoke wine / mono / qemu-system /
chainloader against the `.efi` files.

Test coverage:
- Pure helpers (anomaly classification, fingerprint compute,
  signer-substring detection, signify-availability probe,
  path-heuristic helpers).
- ``walk_esp_efi_files`` — case-insensitive `.efi` filename match
  under ``EFI/`` subdirectories across detection roots.
- Verdict → state mapping (signed_valid / signed_revoked /
  unsigned / parse_failed / signed_expired).
- Inner orchestrator ``_do_esp_walk`` — Rule #35b live canaries via
  make_live_db: no-roots, no-candidates, successful walk with mixed
  states, parse_failed handling.
- **Rule #36 no-execute test gate** — ``test_esp_no_efi_execution``
  asserts the walker module surfaces `.efi` files as DATA only.
"""
from __future__ import annotations

import os
import re
import struct
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsEspEntry
from app.services.esp_walker import (
    SIGNIFY_UNAVAILABLE,
    _do_esp_walk,
    build_anomaly_flags,
    compute_entry_fingerprint,
    is_known_bootloader_path,
    is_non_microsoft_signer,
    is_signify_available,
    is_vendor_path,
    looks_like_pe,
    map_verdict_to_authenticode_state,
    verdict_to_chain_dict,
    verdict_to_dbx_match_dict,
    walk_esp_efi_files,
)
from tests._live_db import make_live_db


def _make_firmware(
    project_id: uuid.UUID, name: str, sha_seed: str
) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── Rule #36 no-execute test gate ───────────────────────────────────────────


_WALKER_MODULE = Path(__file__).parent.parent / "app" / "services" / "esp_walker.py"


# Forbidden execution primitives — patterns the walker MUST NOT
# contain. We scrub string literals + comments before matching so
# documentation / examples don't false-positive.
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
    # EFI/PE execution wrappers — even via subprocess.
    r"\bwine\s+",
    r"\bmono\s+",
    r"\bqemu-system",
    r"\bchainloader",
    r"\brundll32\.exe\s+",
    r"\bregsvr32\.exe\s+",
]


def _strip_string_literals_and_comments(source: str) -> str:
    """Strip Python string literals + comments from source so the
    forbidden-pattern gate doesn't fire on documentation / examples."""
    source = re.sub(r'"""[\s\S]*?"""', '""', source)
    source = re.sub(r"'''[\s\S]*?'''", "''", source)
    source = re.sub(r'"[^"\n]*"', '""', source)
    source = re.sub(r"'[^'\n]*'", "''", source)
    source = re.sub(r"#[^\n]*", "", source)
    return source


def test_esp_no_efi_execution():
    """**Rule #36 central gate** — the ESP walker module MUST NOT
    contain ANY process-spawn primitive that could execute the
    parsed `.efi` PE32+ binaries.

    Scrubs string literals + comments first so documentation examples
    don't fire the gate. The actual CODE must contain ZERO matches
    for every forbidden pattern: subprocess.*, asyncio.create_subprocess_*,
    os.system / execvp / spawnvp, runpy, eval/exec function calls, OR
    EFI execution wrappers (wine / mono / qemu-system / chainloader /
    rundll32 / regsvr32).

    The walker treats `.efi` files as DATA via signify Authenticode
    chain reading + β.10 DBX matching + pefile COFF reading — none
    of which transfer control to the executable. The PEs surface
    as DATA in WindowsEspEntry.authenticode_chain + Finding evidence;
    the walker never INVOKES them.
    """
    walker_source = _WALKER_MODULE.read_text()
    scrubbed = _strip_string_literals_and_comments(walker_source)

    for pattern in _FORBIDDEN_EXEC_PATTERNS:
        match = re.search(pattern, scrubbed)
        assert match is None, (
            f"esp_walker.py contains forbidden pattern {pattern!r} "
            f"at offset {match.start()}: "
            f"{scrubbed[max(0, match.start()-30):match.end()+30]!r}. "
            "Rule #36 no-execute discipline violated — `.efi` files "
            "are attacker-controlled PE32+ binaries and must NEVER "
            "be invoked."
        )


def test_esp_walker_payload_is_data_only():
    """Smoke that `_do_esp_walk` returns DATA only — no callables,
    no thread/process handles, no file-handles — only str / int /
    dict / list types from the result aggregate."""
    import asyncio

    async def _run():
        async with make_live_db() as db:
            project = Project(name="θ.C.C data-only smoke")
            db.add(project)
            await db.flush()

            firmware = _make_firmware(project.id, "fw.bin", "d")
            db.add(firmware)
            await db.flush()

            result = await _do_esp_walk(db, firmware.id)
            assert isinstance(result, dict)
            for key, value in result.items():
                assert isinstance(key, str)
                assert isinstance(
                    value, (str, int, float, dict, list, type(None))
                ), (
                    f"_do_esp_walk returned non-DATA value for {key}: "
                    f"{type(value).__name__}"
                )

    asyncio.run(_run())


# ── Pure helper tests ───────────────────────────────────────────────────────


def test_is_known_bootloader_path_microsoft():
    assert is_known_bootloader_path("efi/microsoft/boot/bootmgfw.efi")
    assert is_known_bootloader_path("EFI/Microsoft/Boot/bootmgfw.efi".lower())
    assert is_known_bootloader_path(r"efi\microsoft\boot\bootmgfw.efi")


def test_is_known_bootloader_path_efi_boot():
    assert is_known_bootloader_path("efi/boot/bootx64.efi")
    assert is_known_bootloader_path("efi/boot/bootia32.efi")
    assert is_known_bootloader_path("efi/boot/bootaa64.efi")


def test_is_known_bootloader_path_linux_vendors():
    assert is_known_bootloader_path("efi/redhat/shimx64.efi")
    assert is_known_bootloader_path("efi/ubuntu/grubx64.efi")
    assert is_known_bootloader_path("efi/debian/shimx64.efi")


def test_is_known_bootloader_path_negative():
    assert not is_known_bootloader_path("efi/some-app/random.efi")
    assert not is_known_bootloader_path("efi/myapp/myapp.efi")


def test_is_vendor_path():
    assert is_vendor_path("efi/microsoft/boot/something.efi")
    assert is_vendor_path("efi/dell/dellapp.efi")
    assert is_vendor_path("efi/hp/hp-util.efi")
    assert not is_vendor_path("efi/randomapp/whatever.efi")


def test_is_non_microsoft_signer_negatives():
    """Microsoft / known-good signer subjects return False."""
    assert not is_non_microsoft_signer(
        "CN=Microsoft Corporation UEFI CA 2011"
    )
    assert not is_non_microsoft_signer(
        "CN=Microsoft Windows Production PCA 2011"
    )
    assert not is_non_microsoft_signer("CN=Red Hat, Inc.")
    assert not is_non_microsoft_signer("CN=Canonical Ltd")
    assert not is_non_microsoft_signer(None)


def test_is_non_microsoft_signer_positives():
    """Unknown signers return True."""
    assert is_non_microsoft_signer("CN=Sketchy Boot Co")
    assert is_non_microsoft_signer("CN=Attacker LLC")


def test_build_anomaly_flags_known_bootloader_unsigned():
    flags = build_anomaly_flags(
        file_path="EFI/Boot/bootx64.efi",
        file_size=200_000,
        authenticode_state="unsigned",
        signer_subject=None,
    )
    assert flags["is_unsigned"] is True
    assert flags["is_known_bootloader_path"] is True
    assert flags["is_vendor_path"] is False
    assert flags["is_suspiciously_small"] is False
    assert flags["is_revoked"] is False


def test_build_anomaly_flags_signed_valid_microsoft():
    flags = build_anomaly_flags(
        file_path="EFI/Microsoft/Boot/bootmgfw.efi",
        file_size=2_000_000,
        authenticode_state="signed_valid",
        signer_subject="CN=Microsoft Corporation UEFI CA 2011",
    )
    assert flags["is_unsigned"] is False
    assert flags["is_known_bootloader_path"] is True
    assert flags["is_non_microsoft_signer"] is False
    assert flags["is_vendor_path"] is True


def test_build_anomaly_flags_suspiciously_small():
    flags = build_anomaly_flags(
        file_path="EFI/Boot/bootx64.efi",
        file_size=128,
        authenticode_state="unsigned",
        signer_subject=None,
    )
    assert flags["is_suspiciously_small"] is True


def test_build_anomaly_flags_revoked():
    flags = build_anomaly_flags(
        file_path="EFI/Microsoft/Boot/bootmgfw.efi",
        file_size=2_000_000,
        authenticode_state="signed_revoked",
        signer_subject="CN=Microsoft Windows Production PCA 2011",
    )
    assert flags["is_revoked"] is True
    assert flags["is_unsigned"] is False


def test_compute_entry_fingerprint_deterministic():
    a = compute_entry_fingerprint(
        file_path="EFI/Boot/bootx64.efi",
        file_sha256="d" * 64,
        authenticode_state="signed_valid",
    )
    b = compute_entry_fingerprint(
        file_path="EFI/Boot/bootx64.efi",
        file_sha256="d" * 64,
        authenticode_state="signed_valid",
    )
    assert a == b


def test_compute_entry_fingerprint_case_insensitive_path():
    """The fingerprint folds path case so the same `.efi` shape across
    case-variant extractions yields the same fingerprint."""
    a = compute_entry_fingerprint(
        file_path="EFI/Boot/bootx64.efi",
        file_sha256="d" * 64,
        authenticode_state="unsigned",
    )
    b = compute_entry_fingerprint(
        file_path="efi/boot/bootx64.efi",
        file_sha256="d" * 64,
        authenticode_state="unsigned",
    )
    assert a == b


def test_compute_entry_fingerprint_differs_on_sha():
    a = compute_entry_fingerprint(
        file_path="EFI/Boot/bootx64.efi",
        file_sha256="d" * 64,
        authenticode_state="signed_valid",
    )
    b = compute_entry_fingerprint(
        file_path="EFI/Boot/bootx64.efi",
        file_sha256="e" * 64,
        authenticode_state="signed_valid",
    )
    assert a != b


# ── Verdict → state mapping ──────────────────────────────────────────────────


class _MockVerdict:
    """Minimal mock of AuthenticodeVerdict for verdict-mapping tests."""

    def __init__(
        self,
        signed=False,
        chain_status="unknown",
        signer_subject=None,
        signer_issuer=None,
        leaf_serial=None,
        sig_hash_algo=None,
        tsa_authority=None,
        signed_at=None,
        signatures_count=0,
        dbx_revoked=False,
        dbx_revocation_kb=None,
        error=None,
    ):
        self.signed = signed
        self.chain_status = chain_status
        self.signer_subject = signer_subject
        self.signer_issuer = signer_issuer
        self.leaf_serial = leaf_serial
        self.sig_hash_algo = sig_hash_algo
        self.tsa_authority = tsa_authority
        self.signed_at = signed_at
        self.signatures_count = signatures_count
        self.dbx_revoked = dbx_revoked
        self.dbx_revocation_kb = dbx_revocation_kb
        self.error = error


def test_map_verdict_to_state_unsigned():
    v = _MockVerdict(signed=False, chain_status="unknown")
    assert map_verdict_to_authenticode_state(v) == "unsigned"


def test_map_verdict_to_state_parse_failed():
    v = _MockVerdict(
        signed=False,
        chain_status="unknown",
        error="PE parse failed: PEFormatError",
    )
    assert map_verdict_to_authenticode_state(v) == "parse_failed"


def test_map_verdict_to_state_signed_valid():
    v = _MockVerdict(signed=True, chain_status="valid_now")
    assert map_verdict_to_authenticode_state(v) == "signed_valid"


def test_map_verdict_to_state_signed_valid_at_signing():
    v = _MockVerdict(signed=True, chain_status="valid_at_signing")
    assert map_verdict_to_authenticode_state(v) == "signed_valid"


def test_map_verdict_to_state_dbx_revoked_overrides_chain():
    """DBX revocation is the AUTHORITATIVE revocation signal — even
    if chain_status would otherwise say valid_now."""
    v = _MockVerdict(
        signed=True,
        chain_status="valid_now",
        dbx_revoked=True,
    )
    assert map_verdict_to_authenticode_state(v) == "signed_revoked"


def test_map_verdict_to_state_chain_revoked():
    v = _MockVerdict(signed=True, chain_status="revoked")
    assert map_verdict_to_authenticode_state(v) == "signed_revoked"


def test_map_verdict_to_state_signed_expired_unknown_chain():
    v = _MockVerdict(signed=True, chain_status="never_valid")
    assert map_verdict_to_authenticode_state(v) == "signed_expired"


def test_verdict_to_chain_dict_shape():
    v = _MockVerdict(
        signed=True,
        chain_status="valid_now",
        signer_subject="CN=Microsoft Corporation UEFI CA 2011",
        leaf_serial="DEADBEEF",
        sig_hash_algo="sha256",
        signatures_count=1,
    )
    out = verdict_to_chain_dict(v)
    assert out["signed"] is True
    assert out["chain_status"] == "valid_now"
    assert "Microsoft" in out["signer_subject"]
    assert out["signatures_count"] == 1
    assert out["error"] is None


def test_verdict_to_dbx_match_dict_none_when_not_revoked():
    v = _MockVerdict(dbx_revoked=False)
    assert verdict_to_dbx_match_dict(v) is None


def test_verdict_to_dbx_match_dict_hit_shape():
    v = _MockVerdict(
        dbx_revoked=True,
        dbx_revocation_kb="KB5012170",
        leaf_serial="DEADBEEF",
    )
    out = verdict_to_dbx_match_dict(v)
    assert out is not None
    assert out["revoked"] is True
    assert out["revocation_kb"] == "KB5012170"
    assert out["match_kind"] == "x509_serial"


# ── walk_esp_efi_files ──────────────────────────────────────────────────────


def test_walk_esp_efi_files_finds_under_efi_subdir():
    """The walker finds `.efi` files only under ``EFI/`` subdirs
    (case-insensitive)."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # Canonical layouts
        (root / "EFI" / "Boot").mkdir(parents=True)
        (root / "EFI" / "Boot" / "bootx64.efi").write_bytes(b"MZ" + b"\x00" * 100)
        (root / "EFI" / "Microsoft" / "Boot").mkdir(parents=True)
        (root / "EFI" / "Microsoft" / "Boot" / "bootmgfw.efi").write_bytes(
            b"MZ" + b"\x00" * 100
        )
        # Mixed-case path
        (root / "efi" / "ubuntu").mkdir(parents=True)
        (root / "efi" / "ubuntu" / "grubx64.efi").write_bytes(
            b"MZ" + b"\x00" * 100
        )
        # Non-EFI file ignored
        (root / "EFI" / "Boot" / "readme.txt").write_text("not efi")
        # `.efi` outside EFI/ ignored
        (root / "elsewhere").mkdir()
        (root / "elsewhere" / "stray.efi").write_bytes(
            b"MZ" + b"\x00" * 100
        )

        hits = walk_esp_efi_files([str(root)])
        assert len(hits) == 3
        names = {Path(h).name for h in hits}
        assert names == {"bootx64.efi", "bootmgfw.efi", "grubx64.efi"}


def test_walk_esp_efi_files_missing_root_swallows():
    """Missing detection roots are skipped silently."""
    hits = walk_esp_efi_files(["/nonexistent/path"])
    assert hits == []


def test_looks_like_pe_positive():
    with tempfile.NamedTemporaryFile(suffix=".efi", delete=False) as fh:
        fh.write(b"MZ" + b"\x00" * 64)
        path = fh.name
    try:
        assert looks_like_pe(path) is True
    finally:
        os.unlink(path)


def test_looks_like_pe_negative():
    with tempfile.NamedTemporaryFile(suffix=".efi", delete=False) as fh:
        fh.write(b"ELF" + b"\x00" * 64)
        path = fh.name
    try:
        assert looks_like_pe(path) is False
    finally:
        os.unlink(path)


def test_looks_like_pe_unreadable():
    """Unreadable / nonexistent file → False (defensive boundary)."""
    assert looks_like_pe("/nonexistent/pe.efi") is False


# ── is_signify_available probe ──────────────────────────────────────────────


def test_is_signify_available():
    """signify is in pyproject.toml; importable in this venv."""
    assert is_signify_available() is True


def test_signify_unavailable_constant_shape():
    """The fallback dict is the canonical shape for graceful-degrade."""
    assert SIGNIFY_UNAVAILABLE["status"] == "unavailable"
    assert "signify" in SIGNIFY_UNAVAILABLE["reason"]


# ── Inner orchestrator (_do_esp_walk) — Rule #35b live canaries ─────────────


@pytest.mark.asyncio
async def test_do_esp_walk_no_firmware():
    """firmware_id that doesn't exist → empty result."""
    async with make_live_db() as db:
        result = await _do_esp_walk(db, uuid.uuid4())
        assert result["efi_files_scanned"] == 0
        assert result["efi_files_persisted"] == 0
        assert result["per_root"] == []


@pytest.mark.asyncio
async def test_do_esp_walk_no_roots():
    """Firmware with no extracted_path / detection_roots → empty
    result."""
    async with make_live_db() as db:
        project = Project(name="θ.C.C no-roots canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "n")
        db.add(firmware)
        await db.flush()

        result = await _do_esp_walk(db, firmware.id)
        assert result["efi_files_scanned"] == 0
        assert result["efi_files_persisted"] == 0


@pytest.mark.asyncio
async def test_do_esp_walk_no_efi_candidates():
    """Firmware with detection root but no `.efi` files → empty
    result."""
    with tempfile.TemporaryDirectory() as td:
        async with make_live_db() as db:
            project = Project(name="θ.C.C no-candidates canary")
            db.add(project)
            await db.flush()
            firmware = _make_firmware(project.id, "fw.bin", "z")
            firmware.extracted_path = td
            db.add(firmware)
            await db.flush()

            result = await _do_esp_walk(db, firmware.id)
            assert result["efi_files_scanned"] == 0
            assert result["efi_files_persisted"] == 0


@pytest.mark.asyncio
async def test_do_esp_walk_walks_unsigned_efi():
    """Live canary — walk a real `.efi` candidate and verify the
    walker produces a WindowsEspEntry row with authenticode_state=
    unsigned/parse_failed (synthetic byte fixture has no real
    signature)."""
    with tempfile.TemporaryDirectory() as td:
        # Lay out a canonical ESP shape.
        boot_dir = Path(td) / "EFI" / "Boot"
        boot_dir.mkdir(parents=True)
        efi_path = boot_dir / "bootx64.efi"
        # Build a minimal MZ + PE so looks_like_pe passes and signify
        # can attempt to parse. We don't expect a valid signature —
        # signify should return a verdict with signed=False or
        # parse_failed.
        efi_path.write_bytes(b"MZ" + b"\x00" * 4096)

        async def _fake_roots(firmware, *, db=None, use_cache=True):
            return [td]

        async with make_live_db() as db:
            project = Project(name="θ.C.C unsigned-walk canary")
            db.add(project)
            await db.flush()
            firmware = _make_firmware(project.id, "fw.bin", "w")
            firmware.extracted_path = td
            db.add(firmware)
            await db.flush()

            with patch(
                "app.services.esp_walker.get_detection_roots",
                _fake_roots,
            ):
                result = await _do_esp_walk(db, firmware.id)
            assert result["efi_files_scanned"] == 1
            # Either unsigned (signify returns 0 signatures) or
            # parse_failed (signify rejects the minimal PE). Both are
            # legitimate verdicts; the walker handled either path.
            assert result["efi_files_persisted"] == 1
            assert (
                result["unsigned_count"] == 1
                or result["parse_failed_count"] == 1
            )

            rows = (
                await db.execute(
                    select(WindowsEspEntry).where(
                        WindowsEspEntry.firmware_id == firmware.id
                    )
                )
            ).scalars().all()
            assert len(rows) == 1
            r = rows[0]
            assert r.authenticode_state in ("unsigned", "parse_failed")
            assert r.file_path.endswith("bootx64.efi")
            assert r.file_size == 4098  # MZ + 4096 nulls
            assert r.file_sha256 != ""
            assert r.fingerprint_sha256 is not None


@pytest.mark.asyncio
async def test_do_esp_walk_mocked_verdict_signed_valid():
    """Mock verify_pe_file to return a signed_valid Microsoft verdict;
    verify the walker persists the row with the correct shape."""
    with tempfile.TemporaryDirectory() as td:
        boot_dir = Path(td) / "EFI" / "Microsoft" / "Boot"
        boot_dir.mkdir(parents=True)
        efi_path = boot_dir / "bootmgfw.efi"
        efi_path.write_bytes(b"MZ" + b"\x00" * 4096)

        # Mock signify's verdict for a fully signed Microsoft .efi.
        mock_verdict = _MockVerdict(
            signed=True,
            chain_status="valid_now",
            signer_subject="CN=Microsoft Corporation UEFI CA 2011",
            signer_issuer="CN=Microsoft Corporation Third Party Marketplace Root",
            leaf_serial="61077656000000000008",
            sig_hash_algo="sha256",
            signatures_count=1,
        )

        async def _fake_roots(firmware, *, db=None, use_cache=True):
            return [td]

        # patch the lazy-imported verify_pe_file at the SOURCE module
        # per Rule #30 (the import is inside _walk_one_efi).
        with patch(
            "app.services.authenticode_service.verify_pe_file",
            return_value=mock_verdict,
        ), patch(
            "app.services.esp_walker.get_detection_roots",
            _fake_roots,
        ):
            async with make_live_db() as db:
                project = Project(name="θ.C.C signed-valid canary")
                db.add(project)
                await db.flush()
                firmware = _make_firmware(project.id, "fw.bin", "v")
                firmware.extracted_path = td
                db.add(firmware)
                await db.flush()

                result = await _do_esp_walk(db, firmware.id)
                assert result["efi_files_persisted"] == 1
                assert result["signed_valid_count"] == 1
                assert result["unsigned_count"] == 0
                assert result["non_microsoft_signer_count"] == 0

                r = (
                    await db.execute(
                        select(WindowsEspEntry).where(
                            WindowsEspEntry.firmware_id == firmware.id
                        )
                    )
                ).scalar_one()
                assert r.authenticode_state == "signed_valid"
                assert isinstance(r.authenticode_chain, dict)
                assert "Microsoft" in r.authenticode_chain["signer_subject"]
                assert r.authenticode_chain["chain_status"] == "valid_now"
                assert r.dbx_revocation_match is None
                assert r.anomaly_flags["is_known_bootloader_path"] is True


@pytest.mark.asyncio
async def test_do_esp_walk_mocked_verdict_dbx_revoked():
    """Mock signify to return a DBX-revoked verdict; verify the walker
    sets authenticode_state=signed_revoked + persists the DBX match
    JSONB."""
    with tempfile.TemporaryDirectory() as td:
        boot_dir = Path(td) / "EFI" / "Microsoft" / "Boot"
        boot_dir.mkdir(parents=True)
        efi_path = boot_dir / "bootmgfw.efi"
        efi_path.write_bytes(b"MZ" + b"\x00" * 4096)

        mock_verdict = _MockVerdict(
            signed=True,
            chain_status="valid_now",
            signer_subject="CN=Microsoft Windows Production PCA 2011",
            leaf_serial="DEADBEEFCAFEBABE",
            sig_hash_algo="sha256",
            signatures_count=1,
            dbx_revoked=True,
            dbx_revocation_kb=None,
        )

        async def _fake_roots(firmware, *, db=None, use_cache=True):
            return [td]

        with patch(
            "app.services.authenticode_service.verify_pe_file",
            return_value=mock_verdict,
        ), patch(
            "app.services.esp_walker.get_detection_roots",
            _fake_roots,
        ):
            async with make_live_db() as db:
                project = Project(name="θ.C.C dbx-revoked canary")
                db.add(project)
                await db.flush()
                firmware = _make_firmware(project.id, "fw.bin", "r")
                firmware.extracted_path = td
                db.add(firmware)
                await db.flush()

                result = await _do_esp_walk(db, firmware.id)
                assert result["efi_files_persisted"] == 1
                assert result["signed_revoked_count"] == 1
                assert result["dbx_revoked_count"] == 1

                r = (
                    await db.execute(
                        select(WindowsEspEntry).where(
                            WindowsEspEntry.firmware_id == firmware.id
                        )
                    )
                ).scalar_one()
                assert r.authenticode_state == "signed_revoked"
                assert isinstance(r.dbx_revocation_match, dict)
                assert r.dbx_revocation_match["revoked"] is True
                assert r.dbx_revocation_match["match_kind"] == "x509_serial"
                assert r.anomaly_flags["is_revoked"] is True
