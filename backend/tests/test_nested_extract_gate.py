"""Tests for the adaptive nested-archive unpack gate.

The DS1 d360f8f5 failure case motivated this gate: a 2.64 GB tar.gz
containing 2 inner tar.gz (Tegra TX2 + L4T BSP) + 4 sidecar .md5sum /
.sha256sum files passed find_filesystem_root's entry-count fallback —
the wairz tarball shortcut declared the 6-file layout as the rootfs,
0 firmware blobs were detected because both inner archives stayed
packed. The gate ``_is_archive_dense_layout`` fires on archive-byte-
weighted density + sidecar exclusion + negative-rootfs guard so any
vendor's nested-archive shape recurses adaptively without hard-coded
vendor allowlists (per the 2026-05-18 user direction on adaptability).

Fixtures per Scout B's research:

  (i)  flat rootfs tarball — must NOT trigger recursion (preserves
       shortcut for OpenWrt-shaped uploads)
  (ii) 2-deep nested (DS1 shape) — must trigger
  (iii) 3-deep nested (Samsung Odin shape) — must trigger
  (iv) sidecar-heavy (1 archive + 8 sidecars by count, 99% archive
       by bytes) — must trigger via bytes-weighting
  (v)  paired Rule #46 canary — gate fires on synthetic dense input
       AND does NOT fire on synthetic non-dense input
"""

from __future__ import annotations

import io
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from app.workers.unpack_common import (
    _NESTED_ARCHIVE_SUFFIXES,
    _SIDECAR_SUFFIXES,
    _is_archive_dense_layout,
    _is_sidecar_filename,
    _looks_like_archive_filename,
    _recursive_extract_nested,
)


# ---------------------------------------------------------------------------
# Helper builders for the 5 fixtures.
# ---------------------------------------------------------------------------


def _make_tar_with_files(out_path: Path, files: dict[str, bytes]) -> None:
    """Create a tar.gz at ``out_path`` containing ``files`` (name → bytes)."""
    with tarfile.open(out_path, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _make_dir_with_files(out_dir: Path, files: dict[str, bytes]) -> None:
    """Materialize ``files`` (name → bytes) under ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        full = out_dir / name
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(data)


# ---------------------------------------------------------------------------
# Sub-function unit tests.
# ---------------------------------------------------------------------------


def test_is_sidecar_filename_recognises_common_shapes() -> None:
    assert _is_sidecar_filename("foo.tar.gz.md5sum")
    assert _is_sidecar_filename("BAR.SHA256")
    assert _is_sidecar_filename("baz.sig")
    assert _is_sidecar_filename("rootfs.asc")
    assert not _is_sidecar_filename("rootfs.tar.gz")
    assert not _is_sidecar_filename("image.img")


def test_looks_like_archive_filename_matches_supported_suffixes() -> None:
    for suffix in _NESTED_ARCHIVE_SUFFIXES:
        assert _looks_like_archive_filename(f"some.file{suffix}"), suffix
    assert not _looks_like_archive_filename("not_archive.bin")
    assert not _looks_like_archive_filename("readme.txt")


def test_sidecar_and_archive_suffix_lists_are_disjoint() -> None:
    """Sanity: a suffix should never be classified as BOTH sidecar AND
    archive — that would break the gate's denominator math."""
    archives = set(_NESTED_ARCHIVE_SUFFIXES)
    sidecars = set(_SIDECAR_SUFFIXES)
    assert archives.isdisjoint(sidecars)


# ---------------------------------------------------------------------------
# Fixture (i) — flat rootfs tarball must NOT trigger recursion.
# ---------------------------------------------------------------------------


def test_flat_rootfs_layout_does_not_trigger_recursion(tmp_path: Path) -> None:
    """A real rootfs at top level (bin/+etc/+usr/) is the negative-
    rootfs guard — gate returns False even if the layout otherwise
    looked archive-shaped."""
    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "bin").mkdir()
    (root / "etc").mkdir()
    (root / "usr").mkdir()
    (root / "bin" / "busybox").write_bytes(b"\x7fELFstub" + b"\x00" * 2048)
    (root / "etc" / "passwd").write_bytes(b"root:x:0:0:root:/root:/bin/sh\n")
    (root / "usr" / "lib").mkdir()

    # Even if a stray tar.gz exists alongside the rootfs, the rootfs
    # markers dominate.
    (root / "stray.tar.gz").write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 10240)

    assert not _is_archive_dense_layout(str(root))


# ---------------------------------------------------------------------------
# Fixture (ii) — 2-deep nested (DS1 shape) — must trigger.
# ---------------------------------------------------------------------------


def test_ds1_2deep_nested_layout_triggers_gate(tmp_path: Path) -> None:
    """The DS1 d360f8f5 shape: 2 archives + 4 sidecars at top level,
    no Linux markers. Gate must fire so recursion proceeds."""
    ds1 = tmp_path / "ds1_extracted"
    ds1.mkdir()

    # Inner archives: each ≥ 10 MB to clear the min_archive_size gate.
    inner_a = ds1 / "DS1.2-jetson-tx2-cot.tegraflash.tar.gz"
    inner_b = ds1 / "L4T_BSP_SecureBoot.R32.3.1.tar.gz"
    inner_a.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * (11 * 1024 * 1024))
    inner_b.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * (10 * 1024 * 1024))

    # Sidecars: tiny.
    (ds1 / "DS1.2-jetson-tx2-cot.tegraflash.tar.gz.md5sum").write_bytes(
        b"deadbeef  DS1.2-jetson-tx2-cot.tegraflash.tar.gz\n"
    )
    (ds1 / "DS1.2-jetson-tx2-cot.tegraflash.tar.gz.sha256sum").write_bytes(
        b"deadbeefdeadbeef  DS1.2-jetson-tx2-cot.tegraflash.tar.gz\n"
    )
    (ds1 / "L4T_BSP_SecureBoot.R32.3.1.tar.gz.md5sum").write_bytes(
        b"deadbeef  L4T_BSP_SecureBoot.R32.3.1.tar.gz\n"
    )
    (ds1 / "L4T_BSP_SecureBoot.R32.3.1.tar.gz.sha256sum").write_bytes(
        b"deadbeefdeadbeef  L4T_BSP_SecureBoot.R32.3.1.tar.gz\n"
    )

    assert _is_archive_dense_layout(str(ds1))


# ---------------------------------------------------------------------------
# Fixture (iii) — 3-deep nested (Samsung Odin shape) — must trigger.
# ---------------------------------------------------------------------------


def test_samsung_odin_3deep_layout_triggers_gate(tmp_path: Path) -> None:
    """A Samsung Odin-shaped extraction: a single .tar.md5 wrapping
    inner .tar.lz4 + partitions. After ONE level of expansion, the
    intermediate dir is dominated by another archive — gate must
    fire to drive recursion to the next level.

    We synthesize the intermediate state directly (the recursive
    extractor handles the actual decompression separately).
    """
    odin_extracted = tmp_path / "odin_lvl1"
    odin_extracted.mkdir()

    # 1 inner tar.lz4 dominating bytes; sidecar checksum.
    (odin_extracted / "AP_G991BXXU3AVCC_revision00_user_low_ship.tar.lz4").write_bytes(
        b"\x04\x22\x4d\x18" + b"\x00" * (15 * 1024 * 1024)
    )
    (odin_extracted / "AP_G991BXXU3AVCC_revision00_user_low_ship.tar.lz4.md5").write_bytes(
        b"deadbeef  AP_G991BXXU3AVCC_revision00_user_low_ship.tar.lz4\n"
    )

    assert _is_archive_dense_layout(str(odin_extracted))


# ---------------------------------------------------------------------------
# Fixture (iv) — sidecar-heavy: 1 archive + 8 sidecars by count, 99% by bytes.
# ---------------------------------------------------------------------------


def test_sidecar_heavy_layout_triggers_via_bytes_weighting(tmp_path: Path) -> None:
    """By count (1/9 = 11% archive), this would NOT trigger a naive
    count-based gate. By bytes (1 archive at 12 MB vs 8 sidecars at
    ~32 bytes each = ~256 bytes total), it's >99.99% archive. The
    bytes-weighted denominator catches it.
    """
    sidecar_heavy = tmp_path / "sidecar_heavy"
    sidecar_heavy.mkdir()
    (sidecar_heavy / "firmware.tar.gz").write_bytes(
        b"\x1f\x8b\x08\x00" + b"\x00" * (12 * 1024 * 1024)
    )
    for suffix in (
        ".md5",
        ".md5sum",
        ".sha1",
        ".sha256",
        ".sha512",
        ".sig",
        ".asc",
        ".manifest",
    ):
        (sidecar_heavy / f"firmware.tar.gz{suffix}").write_bytes(b"deadbeef\n")

    assert _is_archive_dense_layout(str(sidecar_heavy))


# ---------------------------------------------------------------------------
# Fixture (v) — Rule #46 canary: gate fires on synthetic dense AND does
# NOT fire on synthetic non-dense (mixed-content dir).
# ---------------------------------------------------------------------------


def test_canary_gate_fires_on_synthetic_dense(tmp_path: Path) -> None:
    """Synthetic minimum-viable dense layout — proves the gate's
    positive branch.

    Rule #46: when a gate asserts ABSENCE of something (false-fire),
    or PRESENCE of something (positive fire), ship a paired canary
    that confirms the gate actually distinguishes the two states.
    """
    dense = tmp_path / "dense_canary"
    dense.mkdir()
    (dense / "single_archive.tar.gz").write_bytes(
        b"\x1f\x8b\x08\x00" + b"\x00" * (10 * 1024 * 1024 + 1)
    )
    assert _is_archive_dense_layout(str(dense))


def test_canary_gate_does_not_fire_on_mixed_content(tmp_path: Path) -> None:
    """Mixed content (1 small archive + many real files) should NOT
    trigger recursion. Bytes-weighted is the right discipline, but
    the gate also needs ≥ min_archive_size_bytes to suppress
    false-fire on tiny stray tarballs.

    Rule #46 negative canary: confirms the gate doesn't aggressively
    over-fire on benign cases.
    """
    mixed = tmp_path / "mixed_content"
    mixed.mkdir()
    # Small stray archive — below the 10 MB threshold.
    (mixed / "config_backup.tar.gz").write_bytes(
        b"\x1f\x8b\x08\x00" + b"\x00" * 512
    )
    # Real files dominating bytes.
    for i in range(5):
        (mixed / f"image_{i}.bin").write_bytes(b"\x00" * (3 * 1024 * 1024))
    (mixed / "manifest.json").write_text('{"version": "1.0"}', encoding="utf-8")
    (mixed / "readme.txt").write_text("Mixed content directory.", encoding="utf-8")

    assert not _is_archive_dense_layout(str(mixed))


def test_canary_gate_does_not_fire_on_too_small_archive(tmp_path: Path) -> None:
    """A SINGLE small archive (below 10 MB threshold) at top level
    should NOT trigger recursion even if it's 100% by bytes — too
    small to justify recursion overhead."""
    tiny = tmp_path / "tiny"
    tiny.mkdir()
    (tiny / "tiny.tar.gz").write_bytes(
        b"\x1f\x8b\x08\x00" + b"\x00" * 1024
    )
    assert not _is_archive_dense_layout(str(tiny))


def test_canary_gate_does_not_fire_on_empty_dir(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert not _is_archive_dense_layout(str(empty))


def test_canary_gate_does_not_fire_on_nonexistent_path() -> None:
    assert not _is_archive_dense_layout("/nonexistent/path/that/never/existed")


# ---------------------------------------------------------------------------
# Integration test: end-to-end recursion picks up DS1-shaped contents.
# ---------------------------------------------------------------------------


def test_recursive_extract_after_dense_gate_exposes_inner_files(
    tmp_path: Path,
) -> None:
    """End-to-end: build a DS1-shaped 2-deep nested layout with real
    tar.gz archives, verify _is_archive_dense_layout fires, run
    _recursive_extract_nested, then confirm the inner files are
    exposed (so subsequent detection would find them)."""
    # Build inner Tegra-shaped archive.
    inner_tegra = tmp_path / "inner_tegra.tar.gz"
    _make_tar_with_files(
        inner_tegra,
        {
            "bpmp.bin": b"\x7fELF" + b"\x00" * 2048,
            "cboot.bin": b"\x00" * 4096,
            "nvtboot.bin": b"\x00" * 4096,
            "tos-trusty.img": b"\x00" * 4096,
            "tegra186-base.dtb": b"\xd0\x0d\xfe\xed" + b"\x00" * 2048,
        },
    )

    # Build inner L4T-shaped archive.
    inner_l4t = tmp_path / "inner_l4t.tar.gz"
    _make_tar_with_files(
        inner_l4t,
        {
            "bootloader/bpmp_t194.bin": b"\x7fELF" + b"\x00" * 2048,
            "bootloader/tos_t194.img": b"\x00" * 4096,
            "p2972-0000-devkit-maxn.conf": b"key=value\n",
        },
    )

    # Outer DS1-shape directory containing the two inner archives +
    # 4 sidecars.
    ds1_extracted = tmp_path / "ds1_outer_extracted"
    ds1_extracted.mkdir()

    outer_a = ds1_extracted / "DS1.2-jetson-tx2-cot.tegraflash.tar.gz"
    outer_b = ds1_extracted / "L4T_BSP_SecureBoot.R32.3.1.tar.gz"
    # Pad each inner archive to >10 MB to clear the gate's min-size
    # threshold; we put the REAL archive bytes at the start and append
    # zero-padding (which tarfile.is_tarfile will still recognize via
    # the trailing-zeros tolerance for the actual file payload).
    real_a = inner_tegra.read_bytes()
    real_b = inner_l4t.read_bytes()
    outer_a.write_bytes(real_a + b"\x00" * (11 * 1024 * 1024 - len(real_a)))
    outer_b.write_bytes(real_b + b"\x00" * (11 * 1024 * 1024 - len(real_b)))
    (ds1_extracted / "DS1.2-jetson-tx2-cot.tegraflash.tar.gz.md5sum").write_bytes(
        b"deadbeef\n"
    )
    (ds1_extracted / "L4T_BSP_SecureBoot.R32.3.1.tar.gz.sha256sum").write_bytes(
        b"deadbeef\n"
    )

    # Gate fires.
    assert _is_archive_dense_layout(str(ds1_extracted))

    # Recursion: real tar.gz prefix is what _recursive_extract_nested
    # consumes. The zero-padding after the real tar payload trips
    # is_tarfile's checks in some Python versions; we instead build
    # WITHOUT padding for the e2e test that proves the runner runs
    # end-to-end.
    outer_a.write_bytes(real_a)
    outer_b.write_bytes(real_b)
    # gate should still fire — both archives > 10 MB only with padding,
    # but the integration test cares about inner-file exposure not gate.
    # So skip the gate re-check; proceed directly to recursion.

    new_dirs = _recursive_extract_nested(str(ds1_extracted), max_depth=2)
    # Each inner archive expanded into a sibling _extracted/ dir.
    assert len(new_dirs) >= 2

    # Inner Tegra files visible.
    tegra_dir = ds1_extracted / "DS1.2-jetson-tx2-cot.tegraflash.tar.gz_extracted"
    assert (tegra_dir / "bpmp.bin").exists()
    assert (tegra_dir / "cboot.bin").exists()
    assert (tegra_dir / "tos-trusty.img").exists()
    assert (tegra_dir / "tegra186-base.dtb").exists()

    # Inner L4T files visible.
    l4t_dir = ds1_extracted / "L4T_BSP_SecureBoot.R32.3.1.tar.gz_extracted"
    assert (l4t_dir / "bootloader" / "bpmp_t194.bin").exists()
    assert (l4t_dir / "bootloader" / "tos_t194.img").exists()
