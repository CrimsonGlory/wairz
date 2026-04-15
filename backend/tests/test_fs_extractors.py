"""Unit tests for the recursive filesystem-image dispatcher."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.workers import fs_extractors
from app.workers.fs_extractors import (
    _MAGICS,
    _detect_fs_type,
    _is_excluded,
    _sha256_file,
    recursive_extract,
)


def _write(path: Path, data: bytes, pad_to: int | None = None) -> None:
    """Write *data* to *path*, optionally zero-padding up to *pad_to* bytes."""
    if pad_to is not None and len(data) < pad_to:
        data = data + b"\x00" * (pad_to - len(data))
    path.write_bytes(data)


MIN_SIZE = 4 * 1024  # matches fs_extractors._MIN_FS_SIZE


# ---------------------------------------------------------------------------
# _detect_fs_type
# ---------------------------------------------------------------------------

class TestDetect:
    def test_squashfs_hsqs(self, tmp_path: Path):
        p = tmp_path / "img.bin"
        _write(p, b"hsqs" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _detect_fs_type(str(p)) == "squashfs"

    def test_squashfs_sqsh_be(self, tmp_path: Path):
        p = tmp_path / "img.bin"
        _write(p, b"sqsh" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _detect_fs_type(str(p)) == "squashfs"

    def test_ubi(self, tmp_path: Path):
        p = tmp_path / "img.bin"
        _write(p, b"UBI#" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _detect_fs_type(str(p)) == "ubi"

    def test_ubifs(self, tmp_path: Path):
        p = tmp_path / "img.bin"
        _write(p, b"\x31\x18\x10\x06" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _detect_fs_type(str(p)) == "ubifs"

    def test_jffs2_le(self, tmp_path: Path):
        p = tmp_path / "img.bin"
        _write(p, b"\x85\x19" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _detect_fs_type(str(p)) == "jffs2"

    def test_jffs2_be(self, tmp_path: Path):
        p = tmp_path / "img.bin"
        _write(p, b"\x19\x85" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _detect_fs_type(str(p)) == "jffs2"

    def test_cramfs(self, tmp_path: Path):
        p = tmp_path / "img.bin"
        _write(p, b"\x45\x3d\xcd\x28" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _detect_fs_type(str(p)) == "cramfs"

    def test_cpio(self, tmp_path: Path):
        p = tmp_path / "img.bin"
        _write(p, b"070701" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _detect_fs_type(str(p)) == "cpio"

    def test_ext4_at_offset_0x438(self, tmp_path: Path):
        # Junk in the first 1024 bytes (bootloader area), then the superblock.
        # The ext magic sits at absolute offset 0x438.
        buf = bytearray(b"\x00" * 0x600)
        buf[0x438:0x43A] = b"\x53\xef"
        p = tmp_path / "img.bin"
        _write(p, bytes(buf), pad_to=MIN_SIZE)
        assert _detect_fs_type(str(p)) == "ext"

    def test_too_small(self, tmp_path: Path):
        # SquashFS magic but under MIN_FS_SIZE — should be rejected.
        p = tmp_path / "tiny.bin"
        p.write_bytes(b"hsqs" + b"\x00" * 100)
        assert _detect_fs_type(str(p)) is None

    def test_no_match(self, tmp_path: Path):
        p = tmp_path / "random.bin"
        _write(p, b"random garbage" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _detect_fs_type(str(p)) is None

    def test_all_magics_have_tests(self):
        # Sanity check: ensure every declared magic is exercised above by
        # counting how many FsTypes we have tests for. If someone adds a
        # new FsType to _MAGICS, they should add a test here.
        expected = {"squashfs", "ubi", "ubifs", "jffs2", "cramfs", "cpio", "ext"}
        declared = set(_MAGICS.keys()) | {"ext"}
        assert declared == expected


# ---------------------------------------------------------------------------
# _is_excluded
# ---------------------------------------------------------------------------

class TestExclusion:
    def test_kernel_name(self, tmp_path: Path):
        p = tmp_path / "vmlinux-5.15"
        _write(p, b"anything" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _is_excluded(str(p), str(tmp_path)) is True

    def test_uimage_name(self, tmp_path: Path):
        p = tmp_path / "uImage"
        _write(p, b"anything" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _is_excluded(str(p), str(tmp_path)) is True

    def test_large_elf_executable(self, tmp_path: Path):
        # Mimic an uncompressed vmlinux: \x7fELF magic + >500 KB size.
        p = tmp_path / "some_binary"
        _write(p, b"\x7fELF" + b"\x00" * 60, pad_to=600_000)
        assert _is_excluded(str(p), str(tmp_path)) is True

    def test_small_elf_not_excluded(self, tmp_path: Path):
        # Small ELFs are just shared libraries / utilities — don't exclude.
        p = tmp_path / "libfoo.so"
        _write(p, b"\x7fELF" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _is_excluded(str(p), str(tmp_path)) is False

    def test_symlink_escaping_sandbox(self, tmp_path: Path):
        outside = tmp_path.parent / "outside.bin"
        outside.write_bytes(b"hsqs" + b"\x00" * MIN_SIZE)
        inside_link = tmp_path / "linked.bin"
        inside_link.symlink_to(outside)
        assert _is_excluded(str(inside_link), str(tmp_path)) is True

    def test_regular_file_in_sandbox(self, tmp_path: Path):
        p = tmp_path / "inside.bin"
        _write(p, b"hsqs" + b"\x00" * 60, pad_to=MIN_SIZE)
        assert _is_excluded(str(p), str(tmp_path)) is False


# ---------------------------------------------------------------------------
# _sha256_file
# ---------------------------------------------------------------------------

class TestSha:
    def test_identical_contents_same_sha(self, tmp_path: Path):
        a = tmp_path / "a.bin"
        b = tmp_path / "b.bin"
        content = b"hsqs" + b"\x11" * MIN_SIZE
        a.write_bytes(content)
        b.write_bytes(content)
        assert _sha256_file(str(a)) == _sha256_file(str(b))

    def test_different_contents_different_sha(self, tmp_path: Path):
        a = tmp_path / "a.bin"
        b = tmp_path / "b.bin"
        a.write_bytes(b"hsqs" + b"\x11" * MIN_SIZE)
        b.write_bytes(b"hsqs" + b"\x22" * MIN_SIZE)
        assert _sha256_file(str(a)) != _sha256_file(str(b))


# ---------------------------------------------------------------------------
# recursive_extract orchestration
# ---------------------------------------------------------------------------

def _install_fake_extractor(monkeypatch, behaviour):
    """Replace all real extractors with a single async fake.

    *behaviour* is an async callable (src, out_dir, timeout) -> (ok, msg).
    """
    async def fake(src, out_dir, timeout):
        return await behaviour(src, out_dir, timeout)

    fake_map = {k: fake for k in fs_extractors._EXTRACTORS}
    monkeypatch.setattr(fs_extractors, "_EXTRACTORS", fake_map)


@pytest.mark.asyncio
async def test_dedup_same_blob_under_two_names(tmp_path: Path, monkeypatch):
    content = b"hsqs" + b"\xaa" * MIN_SIZE
    (tmp_path / "a.squashfs").write_bytes(content)
    (tmp_path / "b.squashfs").write_bytes(content)

    call_count = {"n": 0}

    async def fake(src, out_dir, timeout):
        call_count["n"] += 1
        os.makedirs(out_dir, exist_ok=True)
        (Path(out_dir) / "marker").write_text("extracted")
        return True, "fake ok"

    _install_fake_extractor(monkeypatch, fake)

    log = await recursive_extract(str(tmp_path))
    assert call_count["n"] == 1, f"expected 1 extraction, got {call_count['n']}"
    assert "iter 1: 1 candidate" in log or "iter 1: 2 candidate" in log


@pytest.mark.asyncio
async def test_loop_terminates_when_no_new_images(tmp_path: Path, monkeypatch):
    (tmp_path / "one.squashfs").write_bytes(b"hsqs" + b"\x01" * MIN_SIZE)

    async def fake(src, out_dir, timeout):
        # Extract to a directory, but don't produce any new filesystem images.
        os.makedirs(out_dir, exist_ok=True)
        (Path(out_dir) / "hello.txt").write_text("payload")
        return True, "fake ok"

    _install_fake_extractor(monkeypatch, fake)

    log = await recursive_extract(str(tmp_path), max_depth=5)
    # Loop should stop at iter 2 because iter 2 finds no new candidates.
    assert "iter 2: no new images; stopping" in log


@pytest.mark.asyncio
async def test_max_depth_caps_runaway(tmp_path: Path, monkeypatch):
    # Extractor keeps producing a fresh squashfs image each iteration —
    # a pathological case we must terminate.
    counter = {"n": 0}

    async def fake(src, out_dir, timeout):
        counter["n"] += 1
        os.makedirs(out_dir, exist_ok=True)
        # Emit a new squashfs blob with unique content so SHA dedup doesn't
        # save us — only max_depth should.
        (Path(out_dir) / f"nested-{counter['n']}.squashfs").write_bytes(
            b"hsqs" + bytes([counter["n"]]) * MIN_SIZE
        )
        return True, "fake ok"

    _install_fake_extractor(monkeypatch, fake)

    (tmp_path / "seed.squashfs").write_bytes(b"hsqs" + b"\x42" * MIN_SIZE)

    log = await recursive_extract(str(tmp_path), max_depth=3)
    assert "reached max_depth=3" in log
    assert counter["n"] == 3


@pytest.mark.asyncio
async def test_extractor_exception_is_logged_not_raised(tmp_path: Path, monkeypatch):
    (tmp_path / "bad.squashfs").write_bytes(b"hsqs" + b"\x00" * MIN_SIZE)

    async def fake(src, out_dir, timeout):
        raise RuntimeError("simulated extractor crash")

    _install_fake_extractor(monkeypatch, fake)

    log = await recursive_extract(str(tmp_path))
    assert "exception" in log
    assert "simulated extractor crash" in log


@pytest.mark.asyncio
async def test_size_cap_halts_extraction(tmp_path: Path, monkeypatch):
    (tmp_path / "a.squashfs").write_bytes(b"hsqs" + b"\x01" * MIN_SIZE)
    (tmp_path / "b.squashfs").write_bytes(b"hsqs" + b"\x02" * MIN_SIZE)
    (tmp_path / "c.squashfs").write_bytes(b"hsqs" + b"\x03" * MIN_SIZE)

    async def fake(src, out_dir, timeout):
        os.makedirs(out_dir, exist_ok=True)
        # Emit a huge payload (10 MB) per extraction.
        (Path(out_dir) / "big").write_bytes(b"\x00" * (10 * 1024 * 1024))
        return True, "fake ok"

    _install_fake_extractor(monkeypatch, fake)

    # original_size=1 MB, multiplier=5 → cap at 5 MB. The first extraction
    # (10 MB) exceeds the cap, so subsequent candidates are skipped.
    log = await recursive_extract(
        str(tmp_path),
        original_size=1024 * 1024,
        max_total_bytes_multiplier=5.0,
    )
    assert "size cap hit" in log


@pytest.mark.asyncio
async def test_no_candidates_returns_clean_log(tmp_path: Path):
    # Empty extraction dir — dispatcher should be a no-op.
    log = await recursive_extract(str(tmp_path))
    assert "no new images; stopping" in log
    assert "[fs_extractors] done" in log


@pytest.mark.asyncio
async def test_yaffs_images_are_reported(tmp_path: Path):
    (tmp_path / "firmware.yaffs2").write_bytes(b"\x00" * MIN_SIZE)
    log = await recursive_extract(str(tmp_path))
    assert "YAFFS image(s) detected" in log
