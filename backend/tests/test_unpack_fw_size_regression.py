"""Regression test for the ``fw_size`` NameError in ``_unpack_firmware_inner``.

Commit ``a83fa14`` (2026-05-11) renamed the local variable
``fw_size`` → ``fw_size_check`` inside the disk-headroom block but
left 6 downstream references at lines 661 / 710 / 759 / 889 / 944
/ 959 unmigrated. Every extraction that reached:

- a Stage 1 branch (Android OTA, partition dump tar, Linux rootfs
  tar) — line 661 / 710 / 759 / 889 calls
  ``check_extraction_limits(extraction_dir, fw_size)``;
- OR the Stage 2 fallback exhausted path (line 944) —
  raised ``NameError: name 'fw_size' is not defined``.

The NameError inside Stage 1 was caught by the per-stage try/except
and surfaced as a generic "extraction failed". The NameError at line
944 was UNCAUGHT and crashed the whole arq job, which the
``arq_worker.py:240`` finally block then reported as
"Extraction timed out or was interrupted at stage: Running binwalk3
extraction (60% complete)" — a misleading message that hid the real
NameError from the operator.

Surfaced on Moto-G32-XT2235-1.zip (2.8 GB) + Moto-G30-XT2129-1.zip
(2.3 GB) retries on 2026-05-13 after the
``super.img_sparsechunk`` reassembly fix in commit ``6538735`` finally
let extraction reach the bomb-check + standalone-fallback logic.

Fix in commit chain (this commit): rename ``fw_size_check`` → ``fw_size``
in the disk-headroom block, and ensure the variable is unconditionally
defined before any downstream reference. Adds a hard-fail branch when
the source file cannot be stat'd (previously the function silently
continued with ``fw_size_check`` undefined).
"""
from __future__ import annotations

import asyncio
import pathlib

import pytest


@pytest.mark.asyncio
async def test_unpack_firmware_inner_defines_fw_size_before_use(
    tmp_path: pathlib.Path,
) -> None:
    """Verify ``fw_size`` is in scope at every downstream reference site.

    We don't run the full extraction (it would invoke binwalk3 / unblob
    on the host); instead, we just call the function and assert it
    doesn't raise ``NameError: name 'fw_size'``. Any other failure mode
    is acceptable for this regression test — the bug we're guarding
    against is specifically the NameError.
    """
    from app.workers.unpack import _unpack_firmware_inner

    # Tiny non-firmware test file. classify_firmware will return some
    # tier-3 fallback type; the unpack chain will exhaust extractors
    # and hit the standalone-binary-fallback gate where ``fw_size`` is
    # referenced at line 944.
    fw_path = tmp_path / "tiny.bin"
    fw_path.write_bytes(b"\x7fELF" + b"\x00" * 60)

    extraction_base = tmp_path / "extract"
    extraction_base.mkdir()

    # The function returns an UnpackResult; we don't care what it says
    # (probably "failed, no extractors recognised the format" — that's
    # fine). We care that it does NOT raise NameError.
    try:
        result = await asyncio.wait_for(
            _unpack_firmware_inner(str(fw_path), str(extraction_base)),
            timeout=60,
        )
    except NameError as exc:
        pytest.fail(
            f"NameError raised inside _unpack_firmware_inner: {exc}. "
            "The fw_size variable is not defined at one of its "
            "downstream reference sites (lines 661 / 710 / 759 / 889 "
            "/ 944 / 959 in unpack.py). The 2026-05-11 a83fa14 rename "
            "regression has reappeared — re-check the disk-headroom "
            "block."
        )

    # Sanity: the function returned an UnpackResult-shaped object.
    assert hasattr(result, "success")
    assert hasattr(result, "unpack_log")


def test_unpack_firmware_inner_source_has_no_undefined_fw_size_refs() -> None:
    """Static check — every ``fw_size`` reference in CODE inside
    ``_unpack_firmware_inner`` is preceded by the assignment.

    Strips docstrings + comments via ``tokenize`` so that prose
    mentions of ``fw_size`` (in the function docstring or block
    comments) don't false-positive the check. Mirrors κ.D's
    Rule #46 source-scan gate technique.
    """
    import io
    import re
    import tokenize

    source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "workers"
        / "unpack.py"
    ).read_text()

    # Find the function body by locating the function declaration and
    # the next ``async def`` / ``def`` at column 0, OR end-of-file
    # (``_unpack_firmware_inner`` is currently the last function in
    # unpack.py).
    func_match = re.search(
        r"^async def _unpack_firmware_inner\(.*?(?=^(?:async )?def |\Z)",
        source,
        re.DOTALL | re.MULTILINE,
    )
    assert func_match, "could not locate _unpack_firmware_inner in unpack.py"
    body = func_match.group(0)

    # Strip string literals + comments — leaving only CODE tokens.
    code_only_parts: list[str] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(body).readline):
            if tok.type in (tokenize.STRING, tokenize.COMMENT):
                continue
            code_only_parts.append(tok.string)
    except tokenize.TokenizeError:
        code_only_parts = [body]
    code_only = " ".join(code_only_parts)

    # Find the assignment in the CODE-only view.
    assignment_match = re.search(
        r"\bfw_size\b\s*,\s*\bfree_space\b\s*=\s*\bsizes\b", code_only
    )
    assert assignment_match, (
        "fw_size assignment 'fw_size, free_space = sizes' not found in "
        "_unpack_firmware_inner CODE — the disk-headroom block may have "
        "been renamed again. References to fw_size at other lines will "
        "NameError."
    )

    # Confirm every CODE-token fw_size reference appears AFTER the
    # assignment.
    references = [m.start() for m in re.finditer(r"\bfw_size\b", code_only)]
    for ref_pos in references:
        assert ref_pos >= assignment_match.start(), (
            f"fw_size reference at CODE offset {ref_pos} precedes the "
            f"assignment at {assignment_match.start()} — NameError "
            "would fire at this site."
        )
