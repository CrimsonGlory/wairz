"""Tests for ``_concatenate_sparsechunks`` (Motorola flash-package reassembly).

Motorola Android factory flash packages (e.g. Moto-G32-XT2235-1.zip
2.8 GB) split the super partition across N sparse-chunk files named
``super.img_sparsechunk.0`` ... ``super.img_sparsechunk.N``. Without
reassembly, the downstream simg2img + super-partition scan misses the
content entirely; the extraction falls through to unblob + binwalk3
which both timeout on multi-GB archives.

These tests cover the chunk-reassembly helper added to
``unpack_android.py`` to handle this case.
"""
from __future__ import annotations

from pathlib import Path

from app.workers.unpack_android import _concatenate_sparsechunks


def test_concatenate_sparsechunks_reassembles_motorola_super_img(
    tmp_path: Path,
) -> None:
    """Three sparse chunks → single super.img with their bytes concatenated
    in numeric order."""
    (tmp_path / "super.img_sparsechunk.0").write_bytes(b"AAAA")
    (tmp_path / "super.img_sparsechunk.1").write_bytes(b"BBBB")
    (tmp_path / "super.img_sparsechunk.2").write_bytes(b"CCCC")

    merged = _concatenate_sparsechunks(str(tmp_path))
    assert merged == [("super.img", 3)]

    out = (tmp_path / "super.img").read_bytes()
    assert out == b"AAAABBBBCCCC"


def test_concatenate_sparsechunks_removes_individual_chunks_after_merge(
    tmp_path: Path,
) -> None:
    """After successful merge, individual chunk files are deleted."""
    (tmp_path / "super.img_sparsechunk.0").write_bytes(b"A" * 32)
    (tmp_path / "super.img_sparsechunk.1").write_bytes(b"B" * 32)

    _concatenate_sparsechunks(str(tmp_path))

    # super.img exists; chunk files do not.
    assert (tmp_path / "super.img").is_file()
    assert not (tmp_path / "super.img_sparsechunk.0").exists()
    assert not (tmp_path / "super.img_sparsechunk.1").exists()


def test_concatenate_sparsechunks_sorts_by_numeric_index(
    tmp_path: Path,
) -> None:
    """Chunks 0, 1, 10, 11 must concat in numeric (not lexical) order.

    Motorola packages can have ≥10 chunks (Moto-G32 has 11 spanning
    super.img_sparsechunk.0 .. .10). Lexical sort would put .10 before
    .2 and produce a corrupted super.img.
    """
    (tmp_path / "super.img_sparsechunk.0").write_bytes(b"00")
    (tmp_path / "super.img_sparsechunk.1").write_bytes(b"11")
    (tmp_path / "super.img_sparsechunk.2").write_bytes(b"22")
    (tmp_path / "super.img_sparsechunk.10").write_bytes(b"AA")

    # 4 chunks ⇒ contiguity check expects indices 0..3, but our chunks
    # are 0,1,2,10 — that fails the gap check. Add the missing ones to
    # make a valid 11-chunk sequence so the merge proceeds.
    for i in range(3, 10):
        (tmp_path / f"super.img_sparsechunk.{i}").write_bytes(b"--")

    _concatenate_sparsechunks(str(tmp_path))

    out = (tmp_path / "super.img").read_bytes()
    # Order: 0, 1, 2, 3..9 (all "--"), 10.
    assert out.startswith(b"001122")
    assert out.endswith(b"AA")
    assert len(out) == 2 * 11  # 11 chunks × 2 bytes each


def test_concatenate_sparsechunks_skips_when_chunk_gap_present(
    tmp_path: Path,
) -> None:
    """Non-contiguous indices (0, 1, 3 — missing 2) abort the merge.

    A gap implies the upload was incomplete; silently producing a
    truncated super.img would mask the corruption. Better to fail
    obviously by leaving the chunks for inspection.
    """
    (tmp_path / "super.img_sparsechunk.0").write_bytes(b"A")
    (tmp_path / "super.img_sparsechunk.1").write_bytes(b"B")
    (tmp_path / "super.img_sparsechunk.3").write_bytes(b"D")  # gap at 2

    merged = _concatenate_sparsechunks(str(tmp_path))
    assert merged == []
    # No super.img created.
    assert not (tmp_path / "super.img").exists()
    # Chunks remain for operator inspection.
    assert (tmp_path / "super.img_sparsechunk.0").exists()
    assert (tmp_path / "super.img_sparsechunk.3").exists()


def test_concatenate_sparsechunks_does_not_overwrite_existing_image(
    tmp_path: Path,
) -> None:
    """If a same-named ``super.img`` already exists, leave it alone.

    A malformed firmware shipping BOTH a complete ``super.img`` AND
    sparsechunk files should surface to the operator, not silently
    replace the existing super.img with a chunk-merged variant.
    """
    (tmp_path / "super.img").write_bytes(b"PRE-EXISTING")
    (tmp_path / "super.img_sparsechunk.0").write_bytes(b"AAAA")
    (tmp_path / "super.img_sparsechunk.1").write_bytes(b"BBBB")

    merged = _concatenate_sparsechunks(str(tmp_path))

    # Merge was refused; the pre-existing super.img is preserved.
    assert merged == []
    assert (tmp_path / "super.img").read_bytes() == b"PRE-EXISTING"


def test_concatenate_sparsechunks_handles_no_chunks_present(
    tmp_path: Path,
) -> None:
    """An extraction_dir with no sparsechunk files yields empty result."""
    (tmp_path / "boot.img").write_bytes(b"\x7fELF")
    (tmp_path / "vbmeta.img").write_bytes(b"AVB0")

    merged = _concatenate_sparsechunks(str(tmp_path))
    assert merged == []


def test_concatenate_sparsechunks_handles_multiple_prefixes(
    tmp_path: Path,
) -> None:
    """Two distinct prefixes (e.g. super.img + system.img chunks) each
    get their own merge."""
    (tmp_path / "super.img_sparsechunk.0").write_bytes(b"S0")
    (tmp_path / "super.img_sparsechunk.1").write_bytes(b"S1")
    (tmp_path / "system.img_sparsechunk.0").write_bytes(b"Y0")
    (tmp_path / "system.img_sparsechunk.1").write_bytes(b"Y1")

    merged = _concatenate_sparsechunks(str(tmp_path))
    merged_names = {name for name, _ in merged}
    assert merged_names == {"super.img", "system.img"}
    assert (tmp_path / "super.img").read_bytes() == b"S0S1"
    assert (tmp_path / "system.img").read_bytes() == b"Y0Y1"
