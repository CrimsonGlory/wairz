"""Contract tests + Rule #36/#45 token-scan gates for :func:`unpack_apex`.

Mirrors test_unpack_msi.py / test_unpack_cab.py shape. The 7z toolchain
is multi-phase: ``7z l`` for the outer validity probe, ``7z x`` for the
outer extraction, optionally another ``7z x`` for CAPEX nested
``original_apex``, then a final ``7z x`` for the inner apex_payload.img
ext4 walk.

Rule #36 (no-execute) + Rule #45 (no-decrypt) token-scan gates ensure
the worker source NEVER invokes binaries inside the APEX and NEVER
attempts decryption of CERT.RSA / apex_pubkey. The paired Rule #46
META-CANARY confirms the token-scan gate would catch a deliberate
violation.
"""
from __future__ import annotations

import io
import os
import tokenize
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from app.workers.unpack_apex import (
    _SEVENZ_TIMEOUT_SECONDS,
    unpack_apex,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_proc_stub(returncode: int, stdout: bytes = b"") -> object:
    """Mimic asyncio.subprocess.Process — returncode + communicate()."""

    class _Proc:
        def __init__(self) -> None:
            self.returncode = returncode

        async def communicate(self) -> tuple[bytes, bytes]:
            return stdout, b""

        def kill(self) -> None:
            pass

    return _Proc()


def _make_apex_zip(
    path: Path, *, capex: bool = False, with_payload_img: bool = True,
) -> None:
    """Build a minimal-but-realistic APEX ZIP at ``path``.

    ``capex=True`` writes a CAPEX (original_apex nested) shape;
    ``with_payload_img=False`` omits the apex_payload.img to trigger the
    payload-missing failure mode.
    """
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("apex_manifest.pb", b"\x0a\x05fake\x12\x03\x01\x02\x03")
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("apex_pubkey", b"FAKEKEY")
        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", b"\x00" * 32)
        if capex:
            # Embed a tiny inner APEX as original_apex (zip-in-zip).
            inner = io.BytesIO()
            with zipfile.ZipFile(inner, "w") as inner_zf:
                inner_zf.writestr("apex_manifest.pb", b"\x0a\x05fake")
                if with_payload_img:
                    inner_zf.writestr("apex_payload.img", b"\x00" * 64)
            zf.writestr("original_apex", inner.getvalue())
        elif with_payload_img:
            zf.writestr("apex_payload.img", b"\x00" * 64)


# ---------------------------------------------------------------------------
# 1. 7z binary missing → clear failure with install hint.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_apex_reports_missing_7z(tmp_path: Path):
    apex = tmp_path / "fake.apex"
    _make_apex_zip(apex)

    with patch(
        "app.workers.unpack_apex.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        result = await unpack_apex(
            firmware_path=str(apex),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "7z binary missing" in result.error
    assert "p7zip-full" in result.unpack_log


# ---------------------------------------------------------------------------
# 2. Missing apex_manifest.pb → "Not a recognisable APEX".
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_apex_rejects_non_apex_zip(tmp_path: Path):
    apex = tmp_path / "not_apex.apex"
    with zipfile.ZipFile(apex, "w") as zf:
        zf.writestr("just_a_file.txt", b"hello")

    # 7z l succeeds but listing has no apex_manifest.pb.
    list_proc = _make_proc_stub(
        returncode=0,
        stdout=b"7z 25.01 \n  Date  Time  Attr  Size  Compressed  Name\njust_a_file.txt\n",
    )

    with patch(
        "app.workers.unpack_apex.asyncio.create_subprocess_exec",
        return_value=list_proc,
    ):
        result = await unpack_apex(
            firmware_path=str(apex),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "Not a recognisable APEX" in result.error
    assert "apex_manifest.pb" in result.error


# ---------------------------------------------------------------------------
# 3. Timeout constant sanity — Rule #29 alignment.
# ---------------------------------------------------------------------------


def test_unpack_apex_timeout_aligns_with_rule_29() -> None:
    """7z timeout should match the radare2-tier (matches `unpack_msi.py`)."""
    # 300 s backend ceiling × 1200 = 360_000 ms frontend tier; we already
    # have SECURITY_SCAN_TIMEOUT=600_000 + GHIDRA_ANALYSIS_TIMEOUT=360_000
    # so 300 s here is safely under the existing tiers.
    assert _SEVENZ_TIMEOUT_SECONDS == 300


# ---------------------------------------------------------------------------
# 4. Rule #36 + Rule #45 token-scan gate: no execute / decrypt tokens.
# ---------------------------------------------------------------------------


_FORBIDDEN_EXEC_TOKENS = (
    # No execution of extracted APEX contents.
    "rundll32",
    "wine",
    "mono",
    "dotnet",
    "cscript",
    "wscript",
    # No decryption of APEX cert / key material.
    ".decrypt(",
    "CryptUnprotectData",
    "fernet",
    "Crypto.Cipher",
    "asn1crypto.cms.SignedData(",  # parsing fine; CMS decrypt is forbidden
)


def _scan_source_tokens(path: str) -> str:
    """Tokenize the source file and join non-comment / non-docstring tokens.

    Returns a single string suitable for forbidden-substring scanning.
    Comments + module-level docstrings DO mention "decrypt" / "execute"
    legitimately (we document the policy in comments) — strip them.
    """
    with open(path, "rb") as fp:
        tokens = list(tokenize.tokenize(fp.readline))
    parts: list[str] = []
    saw_first_non_strpass = False
    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and not saw_first_non_strpass:
            # module-level docstring — skip
            continue
        if tok.type not in (
            tokenize.NEWLINE,
            tokenize.NL,
            tokenize.INDENT,
            tokenize.DEDENT,
            tokenize.ENCODING,
            tokenize.ENDMARKER,
        ):
            saw_first_non_strpass = True
            parts.append(tok.string)
    return " ".join(parts)


def test_unpack_apex_source_no_execute_or_decrypt_tokens() -> None:
    """Worker source must not contain any execute / decrypt entry point.

    Rule #36 (no-execute) — the worker NEVER invokes binaries inside the
    APEX. AndroidManifest.xml is surfaced as data; CERT.RSA + apex_pubkey
    are surfaced for later parsing by signify / asn1crypto, never executed.

    Rule #45 partner (no-decrypt) — APEX signing is integrity-only;
    there's nothing to decrypt. The worker NEVER calls any .decrypt(),
    CryptUnprotectData, Fernet, Crypto.Cipher, etc.
    """
    src = Path(__file__).resolve().parents[1] / "app" / "workers" / "unpack_apex.py"
    body = _scan_source_tokens(str(src))

    # 7z is the only allowed subprocess argv[0] (and only with `l` or `x`
    # list/extract — never with eval/run/execute flags).
    assert "7z" in body  # sanity — the worker DOES use 7z
    for forbidden in _FORBIDDEN_EXEC_TOKENS:
        # tokenize joins tokens with single spaces; normalise.
        body_norm = body.replace(" ", "")
        forbidden_norm = forbidden.replace(" ", "")
        assert forbidden_norm not in body_norm, (
            f"Rule #36/#45 violation: forbidden token {forbidden!r} found "
            f"in unpack_apex.py — the worker must not execute or decrypt "
            f"APEX contents."
        )


def test_unpack_apex_source_no_execute_or_decrypt_gate_actually_fires() -> None:
    """Rule #46 META-CANARY for the no-execute / no-decrypt gate.

    Synthesize a forbidden-token violation in memory and confirm the
    scanner would catch it. Without this canary the gate is structurally
    indistinguishable from "the scanner isn't actually scanning."
    """
    src_with_violation = (
        "import asyncio\n"
        "async def bad():\n"
        "    proc = await asyncio.create_subprocess_exec('wine', 'evil.exe')\n"
        "    cert.decrypt(payload)\n"
    )
    # Write to a tmp file and run the same gate logic.
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False,
    ) as f:
        f.write(src_with_violation)
        tmp = f.name
    try:
        body = _scan_source_tokens(tmp).replace(" ", "")
        violations = [
            tok for tok in _FORBIDDEN_EXEC_TOKENS
            if tok.replace(" ", "") in body
        ]
        # Should catch both `wine` and `.decrypt(`.
        assert "wine" in violations
        assert ".decrypt(" in violations
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# 5. Detection: _classify_zip recognises both standard and CAPEX shapes.
# ---------------------------------------------------------------------------


def test_classify_zip_detects_standard_apex(tmp_path: Path) -> None:
    """A ZIP carrying apex_manifest.pb + apex_payload.img classifies APEX."""
    from app.services.format_detection import (
        DetectedFormat,
        _classify_zip,
    )

    apex = tmp_path / "std.apex"
    _make_apex_zip(apex, capex=False)
    assert _classify_zip(apex) == DetectedFormat.ANDROID_APEX


def test_classify_zip_detects_capex(tmp_path: Path) -> None:
    """A ZIP carrying apex_manifest.pb + original_apex classifies APEX."""
    from app.services.format_detection import (
        DetectedFormat,
        _classify_zip,
    )

    apex = tmp_path / "capex.apex"
    _make_apex_zip(apex, capex=True)
    assert _classify_zip(apex) == DetectedFormat.ANDROID_APEX


def test_classify_zip_apex_does_not_match_bare_zip(tmp_path: Path) -> None:
    """A ZIP without the APEX markers does NOT misclassify as APEX."""
    from app.services.format_detection import (
        DetectedFormat,
        _classify_zip,
    )

    bare = tmp_path / "bare.zip"
    with zipfile.ZipFile(bare, "w") as zf:
        zf.writestr("readme.txt", b"hello")
    # Missing apex_manifest.pb — should NOT classify as APEX.
    assert _classify_zip(bare) != DetectedFormat.ANDROID_APEX


# ---------------------------------------------------------------------------
# 6. Recursive walker wiring: .apex is in _NESTED_ARCHIVE_SUFFIXES so
#    APEX files inside an extracted firmware tree get expanded by the
#    background _recursive_extract_nested pass. Closes the Scout-2 G32 gap.
# ---------------------------------------------------------------------------


def test_apex_is_in_nested_archive_suffixes() -> None:
    """``_recursive_extract_nested`` must include ``.apex`` so APEX files
    inside an extracted Android partition tree get expanded.

    Without this, G32-style firmwares where unblob fails to recurse into
    apex_payload.img leave the 25+ APEX modules opaque — no SBOM
    components, no ELF inventory, no AndroidManifest.xml introspection.
    """
    from app.workers.unpack_common import _NESTED_ARCHIVE_SUFFIXES

    assert ".apex" in _NESTED_ARCHIVE_SUFFIXES
