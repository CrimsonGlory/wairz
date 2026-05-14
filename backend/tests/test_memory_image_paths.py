"""Tests for ``app.services.memory_image_paths`` (Phase λ.α.B helper).

Covers:

- Extension allowlist (case-insensitive) — every entry in
  ``MEMORY_IMAGE_EXTENSIONS`` + a few negative cases.
- ``MIN_MEMORY_IMAGE_BYTES`` is 100 MB (the operator-facing contract).
- Magic-byte sniffer — every entry in ``_MAGIC_SIGNATURES`` + the
  fallback ``("raw", "unknown")`` for unrecognised heads + the error
  path ``("error", "unknown")`` when the file is unreadable.
- ``enumerate_memory_image_candidates`` end-to-end against a tmp_path
  tree: size gate, extension gate, magic classification, no-recursive
  duplicate emission, symlink-not-followed discipline.

These tests do NOT require a database — they exercise the pure
filesystem helper.
"""
from __future__ import annotations

import os
import pathlib

import pytest

from app.services.memory_image_paths import (
    MEMORY_IMAGE_EXTENSIONS,
    MIN_MEMORY_IMAGE_BYTES,
    MemoryImageCandidate,
    _has_memory_image_extension,
    _sniff_memory_image_magic,
    enumerate_memory_image_candidates,
)


# ── Extension allowlist ──────────────────────────────────────────────────────


def test_extension_allowlist_contains_six_expected_entries() -> None:
    """The 6 canonical extensions the λ.α.B enumerator recognises."""
    expected = {".raw", ".dmp", ".vmem", ".lime", ".mem", ".crash"}
    assert set(MEMORY_IMAGE_EXTENSIONS) == expected


@pytest.mark.parametrize(
    "filename",
    [
        "memory.raw",
        "crash.dmp",
        "vmware.vmem",
        "linux.lime",
        "win.mem",
        "system.crash",
        # Case variants — extension match is case-insensitive.
        "MEMORY.RAW",
        "Crash.DMP",
        "VMware.VMEM",
    ],
)
def test_has_memory_image_extension_accepts_canonical_forms(
    filename: str,
) -> None:
    assert _has_memory_image_extension(filename) is True


@pytest.mark.parametrize(
    "filename",
    [
        "noext",
        "image.bin",
        "kernel.img",
        "rootfs.tar",
        "memory.txt",
        "memory",
        ".raw",  # bare extension as filename — still matches via endswith
        # Bare extension matches our helper because we check via endswith.
        # That's INTENTIONAL — a file actually named ".raw" is exceedingly
        # rare and a real one should still be considered.
    ],
)
def test_has_memory_image_extension_rejects_non_matches(filename: str) -> None:
    if filename == ".raw":
        # As documented in the parametrize comment — bare ".raw" matches.
        assert _has_memory_image_extension(filename) is True
        return
    assert _has_memory_image_extension(filename) is False


# ── Size gate ───────────────────────────────────────────────────────────────


def test_min_memory_image_bytes_is_100_mb() -> None:
    """The operator-facing contract: < 100 MB candidates are skipped."""
    assert MIN_MEMORY_IMAGE_BYTES == 100 * 1024 * 1024


# ── Magic-byte sniffer ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "head_bytes, expected_label, expected_family",
    [
        (b"MDMP\x93\xa7\x00\x00", "MDMP", "windows"),
        (b"PAGEDU64\x00\x00\x00\x00", "PAGEDU64", "windows"),
        (b"PAGEDUMP\x00\x00\x00\x00", "PAGEDUMP", "windows"),
        (b"LiME\x00\x00\x00\x00", "LiME", "linux"),
        (b"VMware\x00\x00\x00", "VMware", "unknown"),
        (b"hibr\x00\x00\x00\x00", "hibr", "windows"),
    ],
)
def test_sniff_magic_matches_six_signatures(
    tmp_path: pathlib.Path,
    head_bytes: bytes,
    expected_label: str,
    expected_family: str,
) -> None:
    """Each of the 6 magic-byte signatures classifies to the expected label."""
    target = tmp_path / "sample.raw"
    target.write_bytes(head_bytes + b"\x00" * 1024)
    label, family = _sniff_memory_image_magic(str(target))
    assert label == expected_label
    assert family == expected_family


def test_sniff_magic_falls_back_to_raw_unknown(tmp_path: pathlib.Path) -> None:
    """Unrecognised magic head → ``("raw", "unknown")``."""
    target = tmp_path / "flat.raw"
    target.write_bytes(b"random bytes nothing magical" + b"\x00" * 1024)
    label, family = _sniff_memory_image_magic(str(target))
    assert label == "raw"
    assert family == "unknown"


def test_sniff_magic_unreadable_file_returns_error(
    tmp_path: pathlib.Path,
) -> None:
    """An unreadable / missing file surfaces ``("error", "unknown")`` instead
    of crashing the enumerator."""
    missing = tmp_path / "does_not_exist.raw"
    label, family = _sniff_memory_image_magic(str(missing))
    assert label == "error"
    assert family == "unknown"


# ── enumerate_memory_image_candidates ───────────────────────────────────────


def _make_image(path: pathlib.Path, *, size: int, magic: bytes = b"") -> None:
    """Write a fake memory image of ``size`` bytes with optional magic prefix."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        if magic:
            fh.write(magic)
        # Sparse seek-and-write keeps the test cheap (~ms even at 200 MB).
        fh.seek(size - 1)
        fh.write(b"\x00")


def test_enumerator_yields_qualifying_candidates(tmp_path: pathlib.Path) -> None:
    """Files >= 100 MB with allowed extensions are yielded; size-gate fails are skipped."""
    big = tmp_path / "winmem.raw"
    _make_image(big, size=MIN_MEMORY_IMAGE_BYTES + 1024, magic=b"MDMP")

    small = tmp_path / "small.raw"
    _make_image(small, size=1024)  # below the gate

    wrong_ext = tmp_path / "notmemory.bin"
    _make_image(wrong_ext, size=MIN_MEMORY_IMAGE_BYTES + 1024)

    results = list(enumerate_memory_image_candidates([str(tmp_path)]))
    assert len(results) == 1
    cand = results[0]
    assert isinstance(cand, MemoryImageCandidate)
    assert cand.image_filename == "winmem.raw"
    assert cand.image_path == str(big)
    assert cand.file_size >= MIN_MEMORY_IMAGE_BYTES
    assert cand.magic_detected == "MDMP"
    assert cand.os_family == "windows"


def test_enumerator_classifies_all_six_magics(tmp_path: pathlib.Path) -> None:
    """One candidate per magic signature → all 6 detected + classified."""
    signatures = [
        ("a.raw", b"MDMP", "MDMP", "windows"),
        ("b.dmp", b"PAGEDU64", "PAGEDU64", "windows"),
        ("c.dmp", b"PAGEDUMP", "PAGEDUMP", "windows"),
        ("d.lime", b"LiME", "LiME", "linux"),
        ("e.vmem", b"VMware", "VMware", "unknown"),
        ("f.mem", b"hibr", "hibr", "windows"),
    ]
    for name, magic, _, _ in signatures:
        _make_image(tmp_path / name, size=MIN_MEMORY_IMAGE_BYTES + 256, magic=magic)

    results = {c.image_filename: c for c in enumerate_memory_image_candidates([str(tmp_path)])}
    assert len(results) == 6
    for name, _, expected_label, expected_family in signatures:
        assert name in results, f"missing {name} in enumerated set"
        assert results[name].magic_detected == expected_label
        assert results[name].os_family == expected_family


def test_enumerator_no_magic_falls_back_to_raw_unknown(
    tmp_path: pathlib.Path,
) -> None:
    """A qualifying-size .raw file with no magic → raw / unknown."""
    target = tmp_path / "flat.raw"
    _make_image(target, size=MIN_MEMORY_IMAGE_BYTES + 1024)
    results = list(enumerate_memory_image_candidates([str(tmp_path)]))
    assert len(results) == 1
    assert results[0].magic_detected == "raw"
    assert results[0].os_family == "unknown"


def test_enumerator_skips_unknown_extensions(tmp_path: pathlib.Path) -> None:
    """Files with non-allowlisted extensions are skipped even if big."""
    for ext in (".bin", ".img", ".tar", ".sqsh", ".zip"):
        _make_image(
            tmp_path / f"big{ext}", size=MIN_MEMORY_IMAGE_BYTES + 4096
        )
    results = list(enumerate_memory_image_candidates([str(tmp_path)]))
    assert results == []


def test_enumerator_dedupes_across_overlapping_roots(
    tmp_path: pathlib.Path,
) -> None:
    """Overlapping detection_roots don't yield the same candidate twice."""
    subdir = tmp_path / "scatter"
    subdir.mkdir()
    target = subdir / "mem.raw"
    _make_image(target, size=MIN_MEMORY_IMAGE_BYTES + 512, magic=b"MDMP")
    # Pass BOTH the parent + the subdir. The walk from the parent will
    # visit subdir; the walk from subdir would re-visit. Internal de-dup
    # by seen-set prevents duplicate emission.
    results = list(
        enumerate_memory_image_candidates([str(tmp_path), str(subdir)])
    )
    assert len(results) == 1
    assert results[0].image_filename == "mem.raw"


def test_enumerator_recurses_into_subdirectories(
    tmp_path: pathlib.Path,
) -> None:
    """Memory images deep inside the tree are still found."""
    target = tmp_path / "a" / "b" / "c" / "deep.raw"
    _make_image(target, size=MIN_MEMORY_IMAGE_BYTES + 256, magic=b"MDMP")
    results = list(enumerate_memory_image_candidates([str(tmp_path)]))
    assert len(results) == 1
    assert results[0].image_filename == "deep.raw"


def test_enumerator_handles_missing_root(tmp_path: pathlib.Path) -> None:
    """A non-existent detection root is silently skipped (not an error)."""
    bad = str(tmp_path / "does_not_exist")
    results = list(enumerate_memory_image_candidates([bad]))
    assert results == []


def test_enumerator_does_not_follow_symlinks(
    tmp_path: pathlib.Path,
) -> None:
    """A symlink whose target is outside the root tree is not followed.

    Rule #36 / Rule #1 spirit — never escape the firmware tree via a
    symlink. The enumerator passes ``followlinks=False`` to os.walk.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    _make_image(
        outside / "secret.raw", size=MIN_MEMORY_IMAGE_BYTES + 512, magic=b"MDMP"
    )
    inside = tmp_path / "inside"
    inside.mkdir()
    # Symlink the outside dir into the inside tree.
    (inside / "leak").symlink_to(outside, target_is_directory=True)

    results = list(enumerate_memory_image_candidates([str(inside)]))
    # os.walk(followlinks=False) means the symlinked dir is reported but
    # not descended INTO — so the inside walk doesn't find the secret.raw.
    # However, the symlink itself appears as a dir entry; if any image is
    # placed at the top of `inside`, that should still surface.
    assert all(
        os.path.realpath(r.image_path).startswith(str(inside))
        for r in results
    ), "enumerator escaped the root tree via a symlink"
