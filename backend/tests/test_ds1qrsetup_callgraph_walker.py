"""Q2 — tier-1 tests for the ds1qrsetup binary call-graph walker.

Per Rule #39 / Rule #35b: tests target the INNER runner
(:func:`_do_callgraph_run`) with a ``make_live_db()``-provided session —
never the OUTER runner (:func:`run_callgraph_background`) which would
attempt ``async_session_factory()`` and fail with ``socket.gaierror``
on the dev host.

Per Rule #45 + Rule #36 + Rule #46 META-CANARY: the walker source MUST
NOT contain ANY spawn / exec / decrypt tokens in CODE (we strip
docstrings + comments before scanning) AND the test gate must be
canary-verified to ACTUALLY fire on a synthetic violation.

The walker depends on Ghidra (configured via GHIDRA_PATH) and r2pipe
(optional). On the dev host neither is typically available, so the
"happy path" tests use the small synthetic ELF fixture +
INSUFFICIENT_EVIDENCE return path. The compile-flag string-scan +
binary-locator helpers are exercised independently against synthetic
fixtures.
"""
from __future__ import annotations

import io
import pathlib
import re
import struct
import tokenize
import uuid
from pathlib import Path

import pytest

from app.models import Firmware, Project
from app.services.ds1qrsetup_callgraph_walker import (
    _build_no_binary_aggregate,
    _build_unavailable_aggregate,
    _compute_reachability_from_xrefs,
    _detect_compile_flags,
    _do_callgraph_run,
    _extract_strings_sync,
    _looks_like_elf_sync,
    is_ghidra_available,
    is_r2pipe_available,
    locate_ds1qrsetup_binaries,
)
from tests._live_db import make_live_db


# ── Minimal ELF fixture ──────────────────────────────────────────────────────


def _make_minimal_elf(path: Path, *, extra_strings: list[str] | None = None) -> None:
    """Produce a minimal ELF64 LE binary with a few embedded strings.

    Enough header to pass :func:`_looks_like_elf_sync` (4-byte magic
    check); the bulk of the file is the embedded ``extra_strings``
    payload so :func:`_extract_strings_sync` returns them.

    Real ELF parsing happens via Ghidra/radare2 — neither runs in tier-1
    tests; the fixture only needs the magic + the strings the
    compile-flag detector cares about.
    """
    # ELF64 header (only the first 4 bytes need to match the magic).
    # Pack zeros for the remaining 60 bytes of the 64-byte header.
    hdr = b"\x7fELF" + b"\x00" * 60
    body_parts: list[bytes] = []
    if extra_strings:
        for s in extra_strings:
            body_parts.append(s.encode("ascii") + b"\x00")
    body = b"".join(body_parts) if body_parts else b"\x00" * 16
    path.write_bytes(hdr + body)


# ── ELF magic check ──────────────────────────────────────────────────────────


def test_looks_like_elf_sync_true(tmp_path: Path):
    elf = tmp_path / "fake.bin"
    _make_minimal_elf(elf)
    assert _looks_like_elf_sync(str(elf)) is True


def test_looks_like_elf_sync_false_for_ascii(tmp_path: Path):
    not_elf = tmp_path / "ascii.bin"
    not_elf.write_text("not an ELF\n")
    assert _looks_like_elf_sync(str(not_elf)) is False


def test_looks_like_elf_sync_false_for_missing_file(tmp_path: Path):
    assert _looks_like_elf_sync(str(tmp_path / "absent.bin")) is False


# ── locate_ds1qrsetup_binaries ──────────────────────────────────────────────


def test_locate_finds_canonical_opt_path(tmp_path: Path):
    """The canonical Yocto path ``opt/ds1qrsetup/ds1qrsetup`` is
    located, ELF-verified, and surfaced."""
    target_dir = tmp_path / "opt" / "ds1qrsetup"
    target_dir.mkdir(parents=True)
    _make_minimal_elf(target_dir / "ds1qrsetup")

    hits = locate_ds1qrsetup_binaries([str(tmp_path)])
    assert len(hits) == 1
    assert hits[0].endswith("/ds1qrsetup")


def test_locate_skips_non_elf_files(tmp_path: Path):
    """A file named ds1qrsetup but lacking ELF magic must be skipped."""
    target_dir = tmp_path / "opt" / "ds1qrsetup"
    target_dir.mkdir(parents=True)
    (target_dir / "ds1qrsetup").write_text("not an elf\n")

    hits = locate_ds1qrsetup_binaries([str(tmp_path)])
    assert hits == []


def test_locate_handles_missing_root(tmp_path: Path):
    """Roots that don't exist on disk must not blow up; return []."""
    hits = locate_ds1qrsetup_binaries([str(tmp_path / "nope")])
    assert hits == []


def test_locate_finds_usr_bin_basename(tmp_path: Path):
    """``usr/bin/ds1qrsetup`` is also a canonical location."""
    target_dir = tmp_path / "usr" / "bin"
    target_dir.mkdir(parents=True)
    _make_minimal_elf(target_dir / "ds1qrsetup")

    hits = locate_ds1qrsetup_binaries([str(tmp_path)])
    assert len(hits) == 1


def test_locate_dedup_across_roots(tmp_path: Path):
    """When multiple roots resolve to the same realpath, dedup."""
    target_dir = tmp_path / "opt" / "ds1qrsetup"
    target_dir.mkdir(parents=True)
    _make_minimal_elf(target_dir / "ds1qrsetup")

    # Pass the same root twice; dedup via the seen-set.
    hits = locate_ds1qrsetup_binaries([str(tmp_path), str(tmp_path)])
    assert len(hits) == 1


# ── _extract_strings_sync ────────────────────────────────────────────────────


def test_extract_strings_recovers_ascii_runs(tmp_path: Path):
    elf = tmp_path / "fake.bin"
    _make_minimal_elf(
        elf,
        extra_strings=[
            "--enable-libx264",
            "--disable-libtensorflow",
            "PIL_JPEGDecode",
        ],
    )
    strings = _extract_strings_sync(str(elf), min_length=6)
    assert "--enable-libx264" in strings
    assert "--disable-libtensorflow" in strings
    assert "PIL_JPEGDecode" in strings


def test_extract_strings_filters_short_runs(tmp_path: Path):
    elf = tmp_path / "fake.bin"
    _make_minimal_elf(
        elf,
        extra_strings=["abc", "very_long_string_here"],
    )
    strings = _extract_strings_sync(str(elf), min_length=6)
    assert "very_long_string_here" in strings
    assert "abc" not in strings


def test_extract_strings_returns_empty_on_missing_file(tmp_path: Path):
    assert _extract_strings_sync(str(tmp_path / "absent.bin")) == []


# ── _detect_compile_flags ────────────────────────────────────────────────────


def test_detect_compile_flags_picks_up_enables():
    strings = [
        "Various unrelated strings",
        "--enable-libx264 --enable-libtheora",
        "PIL_JPEGDecode",
        "PIL_PNGDecode",
    ]
    flags = _detect_compile_flags(strings)
    # The configure line includes --enable-libx264 + --enable-libtheora.
    assert "--enable-libx264" in flags["ffmpeg"]
    assert "--enable-libtheora" in flags["ffmpeg"]
    # JPEG and PNG decoders present.
    assert "JPEG" in flags["pillow_decoders"]
    assert "PNG" in flags["pillow_decoders"]
    # EXR not present → in the absent list.
    assert "EXR" in flags["pillow_decoders_absent"]


def test_detect_compile_flags_disabled_only_when_no_enable():
    """A library that has --disable but no --enable in the configure
    line is listed in ffmpeg_disabled, not ffmpeg."""
    strings = [
        "--disable-libtensorflow --disable-libopenvino",
    ]
    flags = _detect_compile_flags(strings)
    assert "--disable-libtensorflow" in flags["ffmpeg_disabled"]
    assert "--disable-libopenvino" in flags["ffmpeg_disabled"]
    assert "--enable-libtensorflow" not in flags["ffmpeg"]
    assert "--enable-libopenvino" not in flags["ffmpeg"]


def test_detect_compile_flags_empty_strings_returns_empty_enables():
    flags = _detect_compile_flags([])
    assert flags["ffmpeg"] == []
    assert flags["ffmpeg_disabled"] == []
    assert flags["pillow_decoders"] == []
    # All canonical decoders are absent when no strings.
    assert "JPEG" in flags["pillow_decoders_absent"]
    assert "EXR" in flags["pillow_decoders_absent"]


# ── _compute_reachability_from_xrefs ─────────────────────────────────────────


def test_reachability_simple_chain():
    """main → foo → bar; all three reachable."""
    xrefs = {
        "main": {"from": [{"to_func": "foo"}], "to": []},
        "foo": {"from": [{"to_func": "bar"}], "to": []},
        "bar": {"from": [], "to": []},
    }
    reachable = _compute_reachability_from_xrefs(
        xrefs_map=xrefs,
        entry_function="main",
        all_functions=["main", "foo", "bar", "orphan"],
    )
    assert set(reachable) == {"main", "foo", "bar"}


def test_reachability_excludes_orphan():
    """main → foo; ``orphan`` is unreachable."""
    xrefs = {
        "main": {"from": [{"to_func": "foo"}], "to": []},
        "foo": {"from": [], "to": []},
    }
    reachable = _compute_reachability_from_xrefs(
        xrefs_map=xrefs,
        entry_function="main",
        all_functions=["main", "foo", "orphan"],
    )
    assert "orphan" not in reachable


def test_reachability_handles_cycle():
    """foo → bar → foo cycle must not loop forever."""
    xrefs = {
        "main": {"from": [{"to_func": "foo"}], "to": []},
        "foo": {"from": [{"to_func": "bar"}], "to": []},
        "bar": {"from": [{"to_func": "foo"}], "to": []},
    }
    reachable = _compute_reachability_from_xrefs(
        xrefs_map=xrefs,
        entry_function="main",
        all_functions=["main", "foo", "bar"],
    )
    assert set(reachable) == {"main", "foo", "bar"}


def test_reachability_missing_entry_returns_empty():
    """Entry function not in xrefs nor the function list → []."""
    reachable = _compute_reachability_from_xrefs(
        xrefs_map={},
        entry_function="main",
        all_functions=["foo", "bar"],
    )
    assert reachable == []


# ── Aggregate builders ──────────────────────────────────────────────────────


def test_no_binary_aggregate_shape():
    fid = uuid.uuid4()
    import time as _time
    started = _time.monotonic()
    agg = _build_no_binary_aggregate(fid, started)
    assert agg["analyzer"] == "unavailable"
    assert agg["binary_analyzed"] is None
    assert agg["walker"] == "ds1qrsetup_callgraph_walker"
    assert agg["summary"]["total_symbols_in_binary"] == 0
    assert "errors" in agg
    assert "No ds1qrsetup binary found" in agg["errors"][0]


def test_unavailable_aggregate_shape():
    fid = uuid.uuid4()
    import time as _time
    started = _time.monotonic()
    agg = _build_unavailable_aggregate(
        firmware_id=fid,
        binary_analyzed="/extracted/opt/ds1qrsetup/ds1qrsetup",
        started=started,
        errors=["Ghidra unavailable", "r2pipe unavailable"],
    )
    assert agg["analyzer"] == "unavailable"
    assert agg["binary_analyzed"] == "/extracted/opt/ds1qrsetup/ds1qrsetup"
    assert len(agg["errors"]) == 2
    # PARSE-ONLY discipline note appears in axiom_self_audit.
    assert "PARSE-ONLY" in agg["axiom_self_audit"]


# ── Dependency probes ───────────────────────────────────────────────────────


def test_is_ghidra_available_does_not_raise():
    """The probe is total: returns bool, never raises."""
    result = is_ghidra_available()
    assert isinstance(result, bool)


def test_is_r2pipe_available_does_not_raise():
    """The probe is total: returns bool, never raises."""
    result = is_r2pipe_available()
    assert isinstance(result, bool)


# ── Inner runner — Rule #39 + Rule #35b live canary ──────────────────────────


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


@pytest.mark.asyncio
async def test_do_callgraph_run_missing_firmware_returns_no_binary():
    """If firmware_id doesn't exist, runner returns the no-binary
    aggregate rather than raising."""
    async with make_live_db() as db:
        result = await _do_callgraph_run(db, uuid.uuid4())
        assert result["analyzer"] == "unavailable"
        assert result["binary_analyzed"] is None


@pytest.mark.asyncio
async def test_do_callgraph_run_no_extracted_path_returns_no_binary(tmp_path: Path):
    """A firmware row without extracted_path → no detection roots →
    no-binary aggregate."""
    async with make_live_db() as db:
        project = Project(name="Q2 no-extraction")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "noext.bin", "a")
        # Don't set extracted_path.
        db.add(firmware)
        await db.commit()

        result = await _do_callgraph_run(db, firmware.id)
        assert result["analyzer"] == "unavailable"
        assert result["binary_analyzed"] is None
        assert result["walker"] == "ds1qrsetup_callgraph_walker"


@pytest.mark.asyncio
async def test_do_callgraph_run_no_binary_in_extraction(tmp_path: Path):
    """A firmware whose extraction has NO ds1qrsetup binary returns the
    no-binary aggregate."""
    async with make_live_db() as db:
        project = Project(name="Q2 no-binary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "nobin.bin", "b")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        # Make some unrelated files; no ds1qrsetup binary.
        (tmp_path / "README.md").write_text("# Not a binary\n")
        (tmp_path / "config.txt").write_text("foo=bar\n")

        result = await _do_callgraph_run(db, firmware.id)
        assert result["analyzer"] == "unavailable"
        assert result["binary_analyzed"] is None


@pytest.mark.asyncio
async def test_do_callgraph_run_binary_present_no_analyzer(tmp_path: Path):
    """With a binary present BUT neither Ghidra nor r2pipe available,
    the aggregate carries analyzer='unavailable' AND
    compile_flags_detected populated from the pure-string scan.

    This is the canonical INSUFFICIENT_EVIDENCE path for the
    cve-assessment-framework Q2 contract.
    """
    async with make_live_db() as db:
        project = Project(name="Q2 binary-no-analyzer")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "ds1.bin", "c")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        target_dir = tmp_path / "opt" / "ds1qrsetup"
        target_dir.mkdir(parents=True)
        _make_minimal_elf(
            target_dir / "ds1qrsetup",
            extra_strings=[
                "--enable-libx264",
                "--disable-libtensorflow",
                "PIL_JPEGDecode",
                "PIL_PNGDecode",
            ],
        )

        result = await _do_callgraph_run(db, firmware.id)

        # Even when no analyser ran, the compile-flag string scan ran.
        flags = result["compile_flags_detected"]
        assert "--enable-libx264" in flags["ffmpeg"]
        assert "--disable-libtensorflow" in flags["ffmpeg_disabled"]
        assert "JPEG" in flags["pillow_decoders"]
        assert "PNG" in flags["pillow_decoders"]

        # Binary path is recorded even on INSUFFICIENT_EVIDENCE path.
        assert result["binary_analyzed"].endswith("/ds1qrsetup")


@pytest.mark.asyncio
async def test_do_callgraph_run_aggregate_canonical_shape(tmp_path: Path):
    """Aggregate result has the canonical shape per Rule #35c
    _normalize_firmware_ds1qrsetup_callgraph_walk_result documentation."""
    async with make_live_db() as db:
        project = Project(name="Q2 shape canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "shape.bin", "d")
        firmware.extracted_path = str(tmp_path)
        db.add(firmware)
        await db.commit()

        result = await _do_callgraph_run(db, firmware.id)

        # Top-level keys present per Rule #35c contract.
        for key in (
            "firmware_id",
            "walker",
            "binary_analyzed",
            "analyzer",
            "compile_flags_detected",
            "reachable_symbols",
            "unreachable_symbols",
            "summary",
            "errors",
            "axiom_self_audit",
        ):
            assert key in result, f"missing key {key!r} in walk result"

        for key in (
            "ffmpeg",
            "ffmpeg_disabled",
            "pillow_decoders",
            "pillow_decoders_absent",
        ):
            assert key in result["compile_flags_detected"], (
                f"missing compile_flags_detected key {key!r}"
            )

        for key in (
            "total_symbols_in_binary",
            "reachable_from_main",
            "unreachable_from_main",
            "run_seconds",
        ):
            assert key in result["summary"], (
                f"missing summary key {key!r}"
            )


# ── Rule #45 + Rule #36 PARSE-ONLY test gate ────────────────────────────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Remove docstrings, # comments, and string literals from Python
    source so we can scan for ACTUAL code references.

    Returns the STRING tokens joined — so only CODE tokens are present
    in the output. This is what the test gate scans against.
    """
    out_tokens: list[str] = []
    try:
        tokens = list(
            tokenize.generate_tokens(io.StringIO(source).readline)
        )
    except tokenize.TokenizeError:
        return source

    for tok in tokens:
        if tok.type == tokenize.STRING:
            continue
        if tok.type == tokenize.COMMENT:
            continue
        out_tokens.append(tok.string)
    return " ".join(out_tokens)


# Synthetic violation canary constant — used by the canary test below.
# This string MUST NOT appear unwrapped in walker code; it appears
# wrapped here in a string literal so the gate's docstring-stripping
# would NOT see it. The canary test injects this string into a
# synthetic source body to confirm the gate fires.
_FORBIDDEN_CANARY = "exec"


# Forbidden-token list — patterns to scan for in CODE.
#
# IMPORTANT — the gate scans the OUTPUT of
# _strip_docstrings_and_comments, which joins Python tokens with
# spaces. So `obj.exec(...)` in real source becomes `obj . exec ( ... )`
# after stripping. Regexes MUST be tolerant of single spaces between
# tokens that appear adjacent in source.
_FORBIDDEN_EXEC_DECRYPT_TOKENS: tuple[str, ...] = (
    # Rule #36 — exec / eval / compile (the binary is data, never code).
    r"\bexec\s*\(",
    r"\beval\s*\(",
    r"\bcompile\s*\(",
    # Rule #36 — runpy / importlib runtime imports of firmware names.
    r"\brunpy\s*\.\s*run_path\b",
    r"\brunpy\s*\.\s*run_module\b",
    r"\b__import__\s*\(",
    r"\bimportlib\s*\.\s*import_module\b",
    # Rule #36 — spawn primitives targeting the extracted binary. The
    # walker MAY spawn Ghidra/radare2 (via ghidra_service which lives
    # in a different module) but MUST NOT invoke the firmware binary
    # itself. The gate scans the walker source only.
    r"subprocess\s*\.\s*(run|Popen|call|check_output|check_call)\s*\(",
    r"asyncio\s*\.\s*create_subprocess_(exec|shell)\s*\(",
    r"os\s*\.\s*(system|execvp|execve|spawnvp)\s*\(",
    # Rule #45 — no-decrypt discipline. While ds1qrsetup analysis
    # doesn't typically engage cryptographic decryption (call-graph
    # walkers analyse structure, not encrypted payloads), the
    # PARSE-ONLY discipline carries forward from κ.D / κ.E precedent.
    r"\.\s*decrypt\s*\(",
    r"\bCryptUnprotectData\b",
)


def test_walker_no_decrypt_no_exec():
    """Rule #45 + Rule #36 — the ds1qrsetup_callgraph_walker.py CODE
    (not docstrings / comments) MUST NOT invoke exec / eval / compile /
    runpy / importlib.import_module / subprocess of the extracted
    ds1qrsetup binary, AND MUST NOT engage any cryptographic decrypt
    primitive.

    PARSE-ONLY discipline is the CAMPAIGN-DEFINING constraint for the
    Q2 ds1qrsetup call-graph walker. Ghidra/radare2 analyse the binary
    AS DATA; neither tool invokes the binary, and wairz NEVER calls
    ``exec(binary_bytes)`` / ``subprocess.run([binary_path, ...])`` /
    ``runpy.run_path(binary_path)``. The walker MAY delegate to
    ``ghidra_service.ensure_analysis`` (which spawns analyzeHeadless
    against the binary — a trusted, image-shipped Java parser); the
    walker source itself contains no spawn primitives.

    Note: docstrings and comments LEGITIMATELY mention forbidden
    primitives — we strip them before scanning so the test catches
    actual code references only.
    """
    raw_source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "ds1qrsetup_callgraph_walker.py"
    ).read_text()
    source = _strip_docstrings_and_comments(raw_source)

    for pattern in _FORBIDDEN_EXEC_DECRYPT_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #45 / Rule #36 violation in "
            f"ds1qrsetup_callgraph_walker.py CODE — found {matches} "
            f"matching {pattern!r}; the walker MUST NOT invoke "
            "exec/eval/compile/runpy/importlib.import_module/"
            "subprocess on the extracted binary, AND MUST NOT engage "
            "any decryption primitive. PARSE-ONLY discipline only "
            "allows static analysis via Ghidra/radare2 which read the "
            "binary AS DATA."
        )


def test_walker_no_decrypt_no_exec_gate_actually_fires():
    """Rule #46 META-CANARY — verify the test gate ACTUALLY fires on
    a synthetic violation.

    If we trust ``test_walker_no_decrypt_no_exec`` without confirming
    it catches violations, the gate could silently pass on legitimate
    violations (tokenize bug, regex typo, etc.). This canary builds a
    synthetic source containing a forbidden CODE token (NOT inside a
    docstring/comment) and confirms:

    1. ``_strip_docstrings_and_comments`` preserves the code token.
    2. The forbidden-token regex matches the stripped source.

    The synthetic source is constructed via concatenation rather than
    an f-string to avoid being a single STRING token that
    ``_strip_docstrings_and_comments`` would drop entirely.
    """
    # Construct the synthetic source as a CONCATENATION of lines.
    # All lines pass through tokenize.generate_tokens as actual code
    # (not as string literals).
    line_a = "def bad_walker():\n"
    line_b = "    src = 'x = 1'\n"
    # The CODE token below — `exec(src)` — survives tokenize stripping
    # because it's NOT a string literal in the input.
    line_c = "    " + _FORBIDDEN_CANARY + "(src)\n"
    line_d = "    return None\n"
    synthetic_source = line_a + line_b + line_c + line_d

    stripped = _strip_docstrings_and_comments(synthetic_source)

    # The gate's first forbidden-token pattern is `\bexec\s*\(`. Verify
    # the synthetic source WOULD match.
    pattern = r"\bexec\s*\("
    matches = re.findall(pattern, stripped)
    assert matches, (
        f"Test-gate canary FAILED — the synthetic violation "
        f"'{_FORBIDDEN_CANARY}' did NOT trigger the forbidden-token "
        f"regex {pattern!r}. stripped={stripped!r}. The gate is broken "
        "or the canary is miscalibrated. Without a working canary, "
        "test_walker_no_decrypt_no_exec could silently pass on real "
        "violations."
    )
    assert _FORBIDDEN_CANARY == "exec", (
        "The canary constant must equal 'exec' so the \\bexec\\s*\\("
        " regex catches it."
    )
    assert re.findall(_FORBIDDEN_EXEC_DECRYPT_TOKENS[0], stripped), (
        "The gate's first forbidden-token regex must match the canary "
        "violation."
    )


def test_walker_no_decrypt_no_exec_gate_excludes_docstring_mentions():
    """Sanity check — docstrings mentioning forbidden tokens DO NOT
    cause the gate to fire.

    The walker's docstrings LEGITIMATELY mention 'exec', 'compile',
    'runpy', 'importlib.import_module', 'decrypt', 'subprocess' etc.
    as part of the PARSE-ONLY discipline documentation. The tokenize-
    based stripping must remove these before the regex scan.
    """
    synthetic_docstring_source = '''
def safe_walker():
    """This function NEVER calls exec() and NEVER tries
    to compile() anything. It never invokes runpy.run_path,
    subprocess.run([binary]), or obj.decrypt(blob).
    PARSE-ONLY."""
    return None
'''
    stripped = _strip_docstrings_and_comments(synthetic_docstring_source)

    # After stripping, the forbidden tokens should NOT appear in
    # executable-code form. The docstring's text content is dropped.
    for pattern in _FORBIDDEN_EXEC_DECRYPT_TOKENS:
        matches = re.findall(pattern, stripped)
        assert not matches, (
            f"docstring sanity check FAILED — pattern {pattern!r} "
            f"matched {matches} in stripped docstring source "
            f"{stripped!r}. The tokenize stripping is leaking string "
            "literal content into the scanned output."
        )
