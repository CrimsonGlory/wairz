"""Tests for ``app.services.firmware_paths`` — detection-roots helper.

Phase 2 of ``feature-extraction-integrity``. Covers:

* Multi-partition Android OTA (DPCS10 shape) — rootfs/ + scatter sibling.
* ACM-style nested Linux extraction.
* Single-image bare-metal firmware.
* APK extraction directory.
* No-extraction firmware row (null path).
* JSONB cache hit, stale invalidation, and explicit invalidation.
* ``get_primary_root`` fallback semantics.
* ``realpath`` deduplication.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.firmware_paths import (
    _compute_roots_sync,
    _dedup_by_realpath,
    get_detection_roots,
    get_primary_root,
    invalidate_detection_roots,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_firmware(
    *,
    extracted_path: str | None,
    device_metadata: dict | None = None,
) -> MagicMock:
    """Return a MagicMock that mimics the ``Firmware`` ORM row interface.

    ``device_metadata`` is writable so the helper can persist the cache.
    """
    fw = MagicMock()
    fw.extracted_path = extracted_path
    fw.device_metadata = device_metadata
    return fw


def _build_dpcs10_tree(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """DPCS10-shape layout.

    Returns (extraction_dir, rootfs_dir, scatter_dir, partition_dir).
    """
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    rootfs = extraction / "rootfs"
    for p in ("vendor", "system", "odm"):
        (rootfs / p).mkdir(parents=True)
    partition = rootfs / "partition_2_erofs"
    partition.mkdir()

    scatter = extraction / "DPCS10_260414-1134"
    scatter.mkdir()
    for name in ("lk.img", "md1dsp.img", "tee.img", "preloader_foo.bin"):
        (scatter / name).write_bytes(b"\xde\xad\xbe\xef" * 32)
    return extraction, rootfs, scatter, partition


def _reals(paths) -> set[str]:
    """Sync helper: realpath-set for a list of paths.

    Wrapped in a sync function to keep ruff's ASYNC240 check happy inside
    async test bodies.
    """
    return {os.path.realpath(str(p)) for p in paths}


def _real(path) -> str:
    return os.path.realpath(str(path))


def _isdir(path) -> bool:
    return os.path.isdir(str(path))


# ---------------------------------------------------------------------------
# 1. Multi-partition Android OTA
# ---------------------------------------------------------------------------


async def test_dpcs10_android_ota_returns_rootfs_and_scatter(tmp_path: Path):
    """Scatter-zip plus rootfs siblings: both show up, rootfs leads."""
    _, rootfs, scatter, partition = _build_dpcs10_tree(tmp_path)
    fw = _make_firmware(extracted_path=str(partition))

    roots = await get_detection_roots(fw)

    # Must include at least rootfs + scatter
    resolved = _reals(roots)
    assert _real(rootfs) in resolved
    assert _real(scatter) in resolved
    # Ordering: rootfs first (score 0 beats default score 1).
    assert _real(roots[0]) == _real(rootfs)


async def test_dpcs10_includes_nested_partition_when_caller_pointed_at_it(
    tmp_path: Path,
):
    """``partition_2_erofs`` is buried under ``rootfs/`` and must be
    returned as its own root because ``extracted_path`` pointed at it."""
    _, _, _, partition = _build_dpcs10_tree(tmp_path)
    fw = _make_firmware(extracted_path=str(partition))

    roots = await get_detection_roots(fw)
    assert _real(partition) in _reals(roots)


# ---------------------------------------------------------------------------
# 2. ACM nested Linux
# ---------------------------------------------------------------------------


async def test_acm_nested_linux_returns_extraction_root(tmp_path: Path):
    """ACM-style deeply nested extracts resolve to the extraction dir
    (consumers recurse from there; we don't promote every intermediate)."""
    extraction = tmp_path / "extracted"
    zimg = extraction / "zImage-restore_extract"
    zimg.mkdir(parents=True)
    gz = zimg / "gzip.uncompressed_extract"
    gz.mkdir()
    # DTBs at the zImage-restore level and actual extractable content inside.
    (extraction / "acm.dtb").write_bytes(b"\xd0\x0d\xfe\xed" + b"X" * 200)
    (gz / "vmlinux.bin").write_bytes(b"\x7fELF" + b"X" * 400)

    fw = _make_firmware(extracted_path=str(extraction))
    roots = await get_detection_roots(fw)

    # At minimum, the extraction root must be a detection root.
    assert _real(extraction) in _reals(roots)
    # Nothing points at a vanished intermediate — every returned root
    # exists on disk.
    for r in roots:
        assert _isdir(r)


# ---------------------------------------------------------------------------
# 3. Single-image bare-metal (hex / ELF)
# ---------------------------------------------------------------------------


async def test_bare_metal_hex_returns_single_parent(tmp_path: Path):
    """A flat dir with one blob must NOT spawn sibling exploration."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    (extraction / "fw.elf").write_bytes(b"\x7fELF" + b"X" * 400)

    fw = _make_firmware(extracted_path=str(extraction))
    roots = await get_detection_roots(fw)

    assert len(roots) == 1
    assert _real(roots[0]) == _real(extraction)


# ---------------------------------------------------------------------------
# 4. APK extraction
# ---------------------------------------------------------------------------


async def test_apk_extracted_returns_single_root(tmp_path: Path):
    """An ``apk_extracted/`` dir with normal APK children is a single root."""
    apk = tmp_path / "apk_extracted"
    (apk / "res").mkdir(parents=True)
    (apk / "META-INF").mkdir()
    (apk / "classes.dex").write_bytes(b"dex\n035\0" + b"X" * 400)

    fw = _make_firmware(extracted_path=str(apk))
    roots = await get_detection_roots(fw)

    assert len(roots) == 1
    assert _real(roots[0]) == _real(apk)


# ---------------------------------------------------------------------------
# 5. Null extracted_path
# ---------------------------------------------------------------------------


async def test_null_extracted_path_returns_empty():
    fw = _make_firmware(extracted_path=None)
    roots = await get_detection_roots(fw)
    assert roots == []


async def test_empty_string_extracted_path_returns_empty():
    fw = _make_firmware(extracted_path="")
    roots = await get_detection_roots(fw)
    assert roots == []


async def test_missing_extracted_path_returns_empty(tmp_path: Path):
    """A row whose on-disk extraction was deleted should return []."""
    gone = tmp_path / "gone"
    # never created
    fw = _make_firmware(extracted_path=str(gone))
    roots = await get_detection_roots(fw)
    assert roots == []


# ---------------------------------------------------------------------------
# 6. Cache hit
# ---------------------------------------------------------------------------


async def test_cache_hit_returns_cached_list_without_recomputing(tmp_path: Path):
    """Pre-populated cache short-circuits the walk."""
    # Build a real on-disk tree but have the cache point *somewhere else*
    # that also exists. If caching works, we never look at extracted_path.
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    cached_dir = tmp_path / "totally_unrelated"
    cached_dir.mkdir()

    fw = _make_firmware(
        extracted_path=str(extracted),
        device_metadata={"detection_roots": [str(cached_dir)], "other_key": "x"},
    )
    roots = await get_detection_roots(fw, use_cache=True)

    assert roots == [str(cached_dir)]


async def test_use_cache_false_ignores_cache(tmp_path: Path):
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    cached_dir = tmp_path / "cached"
    cached_dir.mkdir()

    fw = _make_firmware(
        extracted_path=str(extracted),
        device_metadata={"detection_roots": [str(cached_dir)]},
    )
    roots = await get_detection_roots(fw, use_cache=False)

    resolved = _reals(roots)
    assert _real(cached_dir) not in resolved
    assert _real(extracted) in resolved


# ---------------------------------------------------------------------------
# 7. Cache invalidation on stale path
# ---------------------------------------------------------------------------


async def test_stale_cache_is_invalidated_and_recomputed(tmp_path: Path):
    """Cache containing a missing path must NOT be returned."""
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    fw = _make_firmware(
        extracted_path=str(extracted),
        device_metadata={
            "detection_roots": [str(tmp_path / "does_not_exist")],
        },
    )
    roots = await get_detection_roots(fw, use_cache=True)

    resolved = _reals(roots)
    assert _real(extracted) in resolved
    assert str(tmp_path / "does_not_exist") not in roots


async def test_cache_with_non_list_value_is_ignored(tmp_path: Path):
    """Bogus cache types (e.g. old string value) are ignored."""
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    fw = _make_firmware(
        extracted_path=str(extracted),
        device_metadata={"detection_roots": "not a list"},
    )
    roots = await get_detection_roots(fw, use_cache=True)
    assert roots == [str(extracted)]


# ---------------------------------------------------------------------------
# 8. invalidate_detection_roots clears cache
# ---------------------------------------------------------------------------


async def test_invalidate_detection_roots_clears_and_flushes(tmp_path: Path):
    db = AsyncMock()
    fw = _make_firmware(
        extracted_path=str(tmp_path),
        device_metadata={
            "detection_roots": [str(tmp_path)],
            "device_model": "DPCS10",
        },
    )

    await invalidate_detection_roots(fw, db)

    assert "detection_roots" not in (fw.device_metadata or {})
    # Other keys preserved.
    assert fw.device_metadata.get("device_model") == "DPCS10"
    db.flush.assert_awaited_once()


async def test_invalidate_noop_when_cache_absent():
    db = AsyncMock()
    fw = _make_firmware(
        extracted_path="/tmp/fake",
        device_metadata={"device_model": "X"},
    )
    await invalidate_detection_roots(fw, db)
    db.flush.assert_not_awaited()
    assert fw.device_metadata == {"device_model": "X"}


async def test_invalidate_with_only_detection_roots_nulls_metadata(
    tmp_path: Path,
):
    """If detection_roots was the only key, device_metadata becomes None."""
    db = AsyncMock()
    fw = _make_firmware(
        extracted_path=str(tmp_path),
        device_metadata={"detection_roots": [str(tmp_path)]},
    )
    await invalidate_detection_roots(fw, db)
    assert fw.device_metadata is None


# ---------------------------------------------------------------------------
# 9. get_primary_root fallback
# ---------------------------------------------------------------------------


def test_get_primary_root_falls_back_to_extracted_path(tmp_path: Path):
    fw = _make_firmware(
        extracted_path=str(tmp_path),
        device_metadata=None,
    )
    assert get_primary_root(fw) == str(tmp_path)


def test_get_primary_root_returns_cached_first(tmp_path: Path):
    """Cached list trumps ``extracted_path`` (assumes cache is authoritative)."""
    cached = tmp_path / "cached_root"
    cached.mkdir()
    fw = _make_firmware(
        extracted_path=str(tmp_path / "other_root"),
        device_metadata={"detection_roots": [str(cached), "/tmp/second"]},
    )
    assert get_primary_root(fw) == str(cached)


def test_get_primary_root_falls_back_when_cache_path_missing(tmp_path: Path):
    """If cached[0] vanished on disk, fall back to ``extracted_path``."""
    fw = _make_firmware(
        extracted_path=str(tmp_path),
        device_metadata={"detection_roots": [str(tmp_path / "missing")]},
    )
    assert get_primary_root(fw) == str(tmp_path)


def test_get_primary_root_none_for_empty_row():
    fw = _make_firmware(extracted_path=None, device_metadata=None)
    assert get_primary_root(fw) is None


def test_get_primary_root_preserves_empty_string_extracted_path():
    """Edge case: extracted_path="" is returned as-is per spec."""
    fw = _make_firmware(extracted_path="", device_metadata=None)
    # Either "" or None acceptable — both signal no root.
    assert get_primary_root(fw) in ("", None)


# ---------------------------------------------------------------------------
# 10. Realpath dedup
# ---------------------------------------------------------------------------


def test_dedup_by_realpath_removes_symlink_duplicate(tmp_path: Path):
    real = tmp_path / "real_dir"
    real.mkdir()
    link = tmp_path / "link_dir"
    link.symlink_to(real, target_is_directory=True)

    out = _dedup_by_realpath([str(real), str(link)])
    # Only one entry survives — the first one wins.
    assert len(out) == 1
    assert out[0] == str(real)


def test_dedup_preserves_distinct_paths(tmp_path: Path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    out = _dedup_by_realpath([str(a), str(b)])
    assert len(out) == 2


async def test_symlink_sibling_not_double_counted(tmp_path: Path):
    """End-to-end: a rootfs/ + rootfs-sym -> rootfs layout must not
    produce two entries pointing at the same realpath."""
    extraction = tmp_path / "extracted"
    rootfs = extraction / "rootfs"
    for p in ("vendor", "system", "odm"):
        (rootfs / p).mkdir(parents=True)
    sibling_link = extraction / "rootfs-sym"
    sibling_link.symlink_to(rootfs, target_is_directory=True)

    fw = _make_firmware(extracted_path=str(rootfs))
    roots = await get_detection_roots(fw)

    reals = [_real(r) for r in roots]
    assert len(set(reals)) == len(reals), (
        f"Duplicate real paths in {roots}"
    )


# ---------------------------------------------------------------------------
# Cache persistence path
# ---------------------------------------------------------------------------


async def test_persist_writes_detection_roots_to_metadata_and_flushes(
    tmp_path: Path,
):
    """When a db session is provided, the JSONB cache gets populated."""
    _, _, _, partition = _build_dpcs10_tree(tmp_path)
    fw = _make_firmware(
        extracted_path=str(partition),
        device_metadata={"device_model": "DPCS10"},
    )
    db = AsyncMock()

    roots = await get_detection_roots(fw, db=db)

    assert roots  # sanity
    assert fw.device_metadata.get("detection_roots") == roots
    # Preserved prior key.
    assert fw.device_metadata.get("device_model") == "DPCS10"
    db.flush.assert_awaited_once()


async def test_persist_no_flush_when_db_absent(tmp_path: Path):
    """Compute-only mode: no db → no mutation of ``device_metadata``."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    fw = _make_firmware(
        extracted_path=str(extraction),
        device_metadata={"device_model": "DPCS10"},
    )
    roots = await get_detection_roots(fw)
    assert roots == [str(extraction)]
    # No mutation.
    assert "detection_roots" not in (fw.device_metadata or {})


# ---------------------------------------------------------------------------
# Internal helper sanity (lightweight coverage for edge-cases)
# ---------------------------------------------------------------------------


def test_compute_roots_handles_only_raw_images_in_scatter(tmp_path: Path):
    """A dir that has .img/.bin files but no android siblings still gets
    promoted to a detection root."""
    extraction = tmp_path / "ext"
    scatter = extraction / "FW_4_0_1"
    scatter.mkdir(parents=True)
    (scatter / "boot.img").write_bytes(b"X" * 100)
    (scatter / "tee.img").write_bytes(b"X" * 100)

    roots = _compute_roots_sync(str(extraction))

    reals = {_real(r) for r in roots}
    assert _real(scatter) in reals


def test_compute_roots_ignores_hidden_and_cache_dirs(tmp_path: Path):
    """``.git`` and ``__pycache__`` never promoted even if they have .img."""
    extraction = tmp_path / "ext"
    extraction.mkdir()
    bogus = extraction / "__pycache__"
    bogus.mkdir()
    (bogus / "fake.img").write_bytes(b"X" * 100)
    hidden = extraction / ".git"
    hidden.mkdir()
    (hidden / "also.img").write_bytes(b"X" * 100)
    # A legit partition_* dir to ensure the walk ran.
    legit = extraction / "partition_0_raw"
    legit.mkdir()

    roots = _compute_roots_sync(str(extraction))
    reals = {_real(r) for r in roots}
    assert _real(bogus) not in reals
    assert _real(hidden) not in reals
    assert _real(legit) in reals


async def test_persist_failure_is_non_fatal(tmp_path: Path):
    """A DB flush that raises must not blow up the caller — roots still returned."""
    extraction = tmp_path / "ext"
    extraction.mkdir()
    fw = _make_firmware(
        extracted_path=str(extraction),
        device_metadata=None,
    )
    db = AsyncMock()
    db.flush.side_effect = RuntimeError("simulated connection error")

    # Should NOT raise.
    roots = await get_detection_roots(fw, db=db)
    assert roots == [str(extraction)]


# ---------------------------------------------------------------------------
# Post-scatter-relocation layout — regression guard
# ---------------------------------------------------------------------------
#
# After ``_relocate_scatter_subdirs`` runs, the scatter version subdirectory
# is empty and the firmware blobs live as direct children of
# ``extraction/``.  The detector must treat the extraction container
# itself as a walk root so those blobs surface.  Without this guard the
# helper returns only [rootfs, rootfs/partition_*], dropping ~14
# MediaTek blobs (lk.img, tee.img, gz.img, preloader*.bin, scp/sspm/
# spmfw/md1dsp/modem.img, cam_vpu*, logo.bin) from downstream detection.


def test_post_relocation_layout_includes_container(tmp_path: Path):
    """Files at ``extracted/`` top level → container is a detection root."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    # Android rootfs with system + vendor children (valid partition-like
    # layout — proves the helper doesn't mistakenly skip the container
    # just because rootfs/ is also present).
    rootfs = extraction / "rootfs"
    (rootfs / "system").mkdir(parents=True)
    (rootfs / "vendor").mkdir()
    # Scatter version subdir — empty after relocation.
    (extraction / "DPCS10_260414-1134").mkdir()
    # Relocated firmware blobs live directly under extraction/
    for name in (
        "lk.img", "tee.img", "gz.img", "scp.img", "sspm.img",
        "spmfw.img", "md1dsp.img", "modem.img",
        "preloader_aiot8788ep1_64_bsp_k66.bin",
    ):
        (extraction / name).write_bytes(b"\x00" * 64)

    roots = _compute_roots_sync(str(rootfs))
    real_roots = _reals(roots)
    assert os.path.realpath(str(extraction)) in real_roots, (
        f"Expected extraction container as a detection root; got {roots}"
    )
    assert os.path.realpath(str(rootfs)) in real_roots, (
        f"Expected rootfs as a detection root; got {roots}"
    )


def test_linux_rootfs_only_container_not_included(tmp_path: Path):
    """Pure Linux rootfs (no raw images at extraction root) → container
    is NOT promoted.  Regression guard so the fix for the Android post-
    relocation case doesn't over-include for Linux tarballs."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    rootfs = extraction / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "bin").mkdir()
    (rootfs / "lib").mkdir()
    # No .img / .bin at the extraction top level.

    roots = _compute_roots_sync(str(rootfs))
    real_roots = _reals(roots)
    assert os.path.realpath(str(extraction)) not in real_roots, (
        f"Linux extraction container should not be promoted; got {roots}"
    )


def test_pre_relocation_scatter_subdir_still_detected(tmp_path: Path):
    """Pre-relocation layout (files still in DPCS10_*/ subdir) → the
    subdir is a detection root per ``_dir_has_raw_image`` — unchanged
    from pre-fix behaviour."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    rootfs = extraction / "rootfs"
    (rootfs / "system").mkdir(parents=True)
    scatter = extraction / "DPCS10_260414-1134"
    scatter.mkdir()
    for name in ("lk.img", "tee.img", "gz.img"):
        (scatter / name).write_bytes(b"\x00" * 64)

    roots = _compute_roots_sync(str(rootfs))
    real_roots = _reals(roots)
    assert os.path.realpath(str(scatter)) in real_roots, (
        f"Pre-relocation scatter subdir should still be a root; got {roots}"
    )


# ---------------------------------------------------------------------------
# Issue #20: Motorola / nested-unblob multi-candidate detection
# ---------------------------------------------------------------------------
#
# Before this fix, ``_compute_roots_sync`` only inspected ONE level of
# children under the extraction container and returned the first plausible
# rootfs (typically the boot.img ramdisk for Moto firmware). Sibling
# content extracted by unblob's recursive ``_extract`` chain — radio.img
# modem firmware, BTFM Bluetooth blobs, dspso DSP modules, the 11
# super.img_sparsechunk.N raw images — was invisible to every downstream
# walker (SBOM, security audit, hardware firmware tools).
#
# The deep-walk pass now sweeps the whole nested-extract tree from the
# unblob-extraction top, scoring each dir against Issue #20's heuristic
# (``/etc/passwd`` OR ``/system/build.prop`` OR ``/vendor`` at depth ≤3,
# firmware-blob bundles, partition siblings) and collecting every
# qualifying candidate. Initramfs-shaped dirs (tiny, just ``init`` +
# a few binaries) get a score demotion so they cannot outrank a real
# Android filesystem.


def _build_moto_extraction_tree(tmp_path: Path) -> dict[str, Path]:
    """Synthesise the Motorola flash-package extraction shape on disk.

    Matches the structure unblob produces for a Moto-G32-style factory
    flash ZIP (verified against real Moto-G32 firmware
    2807bc24-d012-4f64-ba07-b3a0639f2417):

        extracted/
            Moto-G32-XT2235-1.zip_extract/
                boot.img_extract/
                    14880768-27311594.gzip_extract/
                        gzip.uncompressed_extract/   ← rich boot ramdisk
                            init, oem/, etc/, apex/, odm/, ...
                vendor_boot.img_extract/
                    4096-2467875.gzip_extract/
                        gzip.uncompressed             (single file)
                radio.img_extract/
                    77243904-95270400.extfs_extract/
                        a1_aut.mbn, a1_bgr.mbn, ...   (many .mbn)
                BTFM.bin_extract/
                    raw.image_extract/
                        image/
                            apbtfw10.tlv, ...         (many .tlv)
                dspso.bin_extract/
                    adsp/                              (many .so.1)
                    cdsp/                              (many .so.1)
                super.img_sparsechunk.0_extract/
                    raw.image                          (sole partition image)
                ... × 10 more sparsechunks ...

    Returns a dict of named paths for assertions.
    """
    extracted = tmp_path / "extracted"
    zip_root = extracted / "Moto-G32-XT2235-1.zip_extract"
    zip_root.mkdir(parents=True)

    # 1. boot.img → recovery/first-stage ramdisk with Android partition
    #    siblings as direct children (odm + product + apex). Substantial
    #    enough to NOT trip the initramfs demotion.
    boot_ramdisk = (
        zip_root / "boot.img_extract" / "14880768-27311594.gzip_extract" / "gzip.uncompressed_extract"
    )
    boot_ramdisk.mkdir(parents=True)
    (boot_ramdisk / "init").write_bytes(b"\x7fELF" + b"\x00" * 128)
    for d in ("oem", "etc", "apex", "odm", "product", "bin",
              "first_stage_ramdisk", "data_mirror", "storage",
              "debug_ramdisk", "postinstall", "config", "bugreports",
              "module_hashes", "d"):
        (boot_ramdisk / d).mkdir()
    (boot_ramdisk / "odm_property_contexts").write_text("")
    (boot_ramdisk / "plat_file_contexts").write_text("")

    # 2. vendor_boot.img → has a single non-blob file (gzip.uncompressed
    #    not recursed). Should NOT qualify as a detection root.
    vboot = zip_root / "vendor_boot.img_extract" / "4096-2467875.gzip_extract"
    vboot.mkdir(parents=True)
    (vboot / "gzip.uncompressed").write_bytes(b"\x00" * 64)

    # 3. radio.img → ext filesystem extract with many Qualcomm modem
    #    firmware .mbn files. Should qualify as firmware-blob bundle.
    radio = zip_root / "radio.img_extract" / "77243904-95270400.extfs_extract"
    radio.mkdir(parents=True)
    for n in ("a1_aut.mbn", "a1_bgr.mbn", "a1_hrv.mbn", "a1_svn.mbn",
              "acg_usa_ims.mbn", "acglte_usa.mbn", "airtel_ind_volte.mbn",
              "ais_tha.mbn", "att_usa_volte.mbn", "att_canada_volte.mbn"):
        (radio / n).write_bytes(b"\xde\xad" * 32)
    (radio / "0.img.gz").write_bytes(b"\x1f\x8b" + b"X" * 64)

    # 4. BTFM Bluetooth firmware bundle — many .tlv / .bin files.
    btfm = zip_root / "BTFM.bin_extract" / "raw.image_extract" / "image"
    btfm.mkdir(parents=True)
    for n in ("apbtfw10.tlv", "apbtfw11.tlv", "apnv10.bin", "apnv11.bin",
              "cmbtfw10.tlv", "cmbtfw11.tlv", "cmbtfw12.tlv",
              "cmbtfw12.ver", "cmbtfw13.tlv", "cmbtfw13.ver"):
        (btfm / n).write_bytes(b"\xab\xcd" * 16)

    # 5. dspso DSP firmware — versioned .so.1 modules.
    dspso_adsp = zip_root / "dspso.bin_extract" / "adsp"
    dspso_adsp.mkdir(parents=True)
    for n in ("AlacDecoderModule.so.1", "ApeDecoderModule.so.1",
              "AudioContextDetection.so.1", "AudioSphereModule.so.1",
              "CFCMModule.so.1", "EtsiAmrWbPlusDecModule.so.1",
              "FlacDecoderModule.so.1", "HeaacDecoderModule.so.1",
              "LdacModule.so.1", "WmaDecoderModule.so.1"):
        (dspso_adsp / n).write_bytes(b"\x7fELF" + b"\x00" * 96)

    dspso_cdsp = zip_root / "dspso.bin_extract" / "cdsp"
    dspso_cdsp.mkdir(parents=True)
    for n in ("CdspModule.so.1", "AudioModule.so.1", "VideoModule.so.1"):
        (dspso_cdsp / n).write_bytes(b"\x7fELF" + b"\x00" * 96)

    # 6. 11 super.img_sparsechunk.N — each holds a single raw.image file.
    sparsechunks: list[Path] = []
    for i in range(11):
        chunk = zip_root / f"super.img_sparsechunk.{i}_extract"
        chunk.mkdir()
        (chunk / "raw.image").write_bytes(b"\xff" * 512)
        sparsechunks.append(chunk)

    return {
        "extracted": extracted,
        "zip_root": zip_root,
        "boot_ramdisk": boot_ramdisk,
        "radio": radio,
        "btfm": btfm,
        "dspso_adsp": dspso_adsp,
        "dspso_cdsp": dspso_cdsp,
        # First and middle sparsechunks for assertion sampling.
        "sparsechunk_0": sparsechunks[0],
        "sparsechunk_5": sparsechunks[5],
        "sparsechunk_10": sparsechunks[10],
        "all_sparsechunks": sparsechunks,
    }


async def test_moto_extraction_returns_multiple_candidates(tmp_path: Path):
    """Moto-shape: boot ramdisk + radio + BTFM + dspso sit as siblings
    under the unblob _extract chain. All of them should appear as
    detection roots, not just the one extracted_path happens to point at.
    """
    paths = _build_moto_extraction_tree(tmp_path)
    fw = _make_firmware(extracted_path=str(paths["boot_ramdisk"]))

    roots = await get_detection_roots(fw)
    real_set = _reals(roots)

    # All the substantive content directories must appear.
    assert _real(paths["boot_ramdisk"]) in real_set, (
        f"boot ramdisk missing from {roots}"
    )
    assert _real(paths["radio"]) in real_set, (
        f"radio modem firmware missing from {roots}"
    )
    assert _real(paths["btfm"]) in real_set, (
        f"BTFM bluetooth firmware missing from {roots}"
    )
    assert _real(paths["dspso_adsp"]) in real_set, (
        f"dspso adsp missing from {roots}"
    )
    # We should pick up materially more than the single pre-fix root.
    assert len(roots) >= 4, (
        f"Expected ≥4 detection roots for Moto shape; got {len(roots)}: {roots}"
    )


async def test_moto_extraction_includes_sparsechunks(tmp_path: Path):
    """Every super.img_sparsechunk.N_extract/raw.image dir should be a
    detection root via the T4 sole-partition-image scoring branch — they
    hold the bulk of /system /vendor /product partition data even when
    unblob didn't recurse further. The 11 chunks total ~5 GB of partition
    content for Moto-G32 specifically."""
    paths = _build_moto_extraction_tree(tmp_path)
    fw = _make_firmware(extracted_path=str(paths["boot_ramdisk"]))

    roots = await get_detection_roots(fw)
    real_set = _reals(roots)

    for chunk in paths["all_sparsechunks"]:
        assert _real(chunk) in real_set, (
            f"super.img_sparsechunk dir {chunk.name} missing from detection roots"
        )


async def test_real_android_fs_outranks_boot_ramdisk(tmp_path: Path):
    """Issue #20 ordering ask: when both a real Android FS (with
    ``/system/build.prop``) AND a Moto-style boot ramdisk are present,
    the real FS must lead detection_roots so security/SBOM walkers hit
    it first."""
    paths = _build_moto_extraction_tree(tmp_path)
    # Add a synthetic super.img_extract/ dir with /system/build.prop —
    # this is what we'd see if unblob recursed into the merged super.img.
    super_extracted = paths["zip_root"] / "super.img_extract"
    super_extracted.mkdir()
    (super_extracted / "system").mkdir()
    (super_extracted / "system" / "build.prop").write_text(
        "ro.build.version.release=12\nro.product.brand=motorola\n"
    )
    (super_extracted / "vendor").mkdir()
    (super_extracted / "vendor" / "build.prop").write_text(
        "ro.vendor.build.fingerprint=motorola/devon/devon:12/...\n"
    )
    (super_extracted / "product").mkdir()
    (super_extracted / "product" / "build.prop").write_text("")

    fw = _make_firmware(extracted_path=str(paths["boot_ramdisk"]))
    roots = await get_detection_roots(fw)

    # The real Android system partition must lead the boot ramdisk.
    real_indices = {_real(r): i for i, r in enumerate(roots)}
    super_idx = real_indices[_real(super_extracted)]
    boot_idx = real_indices[_real(paths["boot_ramdisk"])]
    assert super_idx < boot_idx, (
        f"Real Android FS at {super_extracted} should lead boot ramdisk; "
        f"got order {roots}"
    )


async def test_pure_initramfs_demoted_below_full_android_fs(tmp_path: Path):
    """The Issue #20 framing: 'A path containing only init, system/bin/sh,
    and 5 kernel modules (typical initramfs) should NOT count as a
    primary rootfs'. A real-world tiny initramfs (≤10 entries with
    /init file, no /vendor) gets the demotion."""
    extraction = tmp_path / "extracted"
    extraction.mkdir()

    # Tiny initramfs: just init + a couple kernel modules. <15 entries, no
    # /vendor, no /system/build.prop → score demotion to ≤0.
    tiny_initramfs = extraction / "tiny_boot_extract"
    tiny_initramfs.mkdir()
    (tiny_initramfs / "init").write_bytes(b"\x7fELF" + b"\x00" * 64)
    (tiny_initramfs / "sbin").mkdir()
    (tiny_initramfs / "sbin" / "sh").write_bytes(b"\x7fELF")
    (tiny_initramfs / "lib").mkdir()
    (tiny_initramfs / "lib" / "modules").mkdir()
    (tiny_initramfs / "lib" / "modules" / "kernel.ko").write_bytes(b"\x7fELF")

    # Full Android system partition sibling.
    super_sys = extraction / "super.img_extract"
    super_sys.mkdir()
    (super_sys / "system").mkdir()
    (super_sys / "system" / "build.prop").write_text("ro.build=1")
    (super_sys / "vendor").mkdir()
    (super_sys / "product").mkdir()

    fw = _make_firmware(extracted_path=str(extraction))
    roots = await get_detection_roots(fw)
    real_set = _reals(roots)

    assert _real(super_sys) in real_set, (
        f"Full Android FS missing from {roots}"
    )
    # If the initramfs made it into roots at all, it must come AFTER the
    # full Android FS. In practice the demotion drives it to score 0 and
    # it's skipped entirely (good).
    if _real(tiny_initramfs) in real_set:
        sys_idx = roots.index(
            next(r for r in roots if _real(r) == _real(super_sys))
        )
        ramdisk_idx = roots.index(
            next(r for r in roots if _real(r) == _real(tiny_initramfs))
        )
        assert sys_idx < ramdisk_idx, (
            f"initramfs outranked real Android FS; got {roots}"
        )


async def test_initramfs_only_still_returned_as_fallback(tmp_path: Path):
    """Regression guard: when an initramfs is the ONLY content in the
    extraction tree, it must still come back as a detection root. The
    demotion shouldn't make us return [] for the only available content."""
    extraction = tmp_path / "extracted"
    initramfs = extraction / "boot.img_extract" / "ramdisk_extract"
    initramfs.mkdir(parents=True)
    (initramfs / "init").write_bytes(b"\x7fELF")
    (initramfs / "sbin").mkdir()
    (initramfs / "sbin" / "sh").write_bytes(b"\x7fELF")

    fw = _make_firmware(extracted_path=str(initramfs))
    roots = await get_detection_roots(fw)

    # Must include the initramfs as fallback even when scoring demotes it.
    assert _real(initramfs) in _reals(roots), (
        f"Initramfs-only extraction must fall back to extracted_path; got {roots}"
    )


def test_rootfs_score_real_android_fs_high(tmp_path: Path):
    """Unit-level sanity: a dir with /system/build.prop + /vendor scores
    in the definitive-rootfs band (≥ prune threshold = 200)."""
    from app.services.firmware_paths import _rootfs_score
    root = tmp_path / "super"
    (root / "system").mkdir(parents=True)
    (root / "system" / "build.prop").write_text("ro.build=1")
    (root / "vendor").mkdir()
    (root / "product").mkdir()
    (root / "etc").mkdir()
    (root / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/sh")

    score = _rootfs_score(str(root))
    # 400 (system/build.prop) + 300 (etc/passwd) + 150 (vendor) + 100*3
    # (android sibling count) = 1150 minimum.
    assert score >= 1000, f"Real Android FS scored only {score}, expected ≥1000"


def test_rootfs_score_sole_partition_image_low(tmp_path: Path):
    """Unit-level sanity: a dir with one raw partition image gets the
    T4 sole-blob score of 10 — enough to be picked up but below any
    real rootfs."""
    from app.services.firmware_paths import _rootfs_score
    chunk = tmp_path / "super.img_sparsechunk.0_extract"
    chunk.mkdir()
    (chunk / "raw.image").write_bytes(b"\xff" * 512)

    score = _rootfs_score(str(chunk))
    assert 0 < score < 100, (
        f"Sparsechunk raw.image scored {score}; expected 0<x<100"
    )


def test_rootfs_score_tiny_initramfs_demoted(tmp_path: Path):
    """Unit-level sanity: tiny initramfs (init + 3 entries) scores 0
    after demotion."""
    from app.services.firmware_paths import _rootfs_score
    ramdisk = tmp_path / "ramdisk_extract"
    ramdisk.mkdir()
    (ramdisk / "init").write_bytes(b"\x7fELF")
    (ramdisk / "sbin").mkdir()
    (ramdisk / "lib").mkdir()
    (ramdisk / "etc").mkdir()  # empty etc — no passwd

    score = _rootfs_score(str(ramdisk))
    assert score == 0, (
        f"Tiny initramfs should score 0 after demotion; got {score}"
    )


def test_find_unblob_extraction_top_climbs_nested_extract_chain(tmp_path: Path):
    """The unblob-top finder walks up through the ``_extract`` chain
    until it hits the firmware-named container under ``extracted/``."""
    from app.services.firmware_paths import _find_unblob_extraction_top
    leaf = (
        tmp_path / "extracted" / "Moto-G32-XT2235-1.zip_extract"
        / "boot.img_extract" / "14880768-27311594.gzip_extract"
        / "gzip.uncompressed_extract"
    )
    leaf.mkdir(parents=True)
    top = _find_unblob_extraction_top(str(leaf))
    assert os.path.realpath(top) == os.path.realpath(
        tmp_path / "extracted" / "Moto-G32-XT2235-1.zip_extract"
    ), f"Expected climb to firmware-named zip_extract dir; got {top}"


def test_find_unblob_extraction_top_no_climb_when_not_nested(tmp_path: Path):
    """When the input path isn't inside an ``_extract`` chain, no climb
    happens (existing single-rootfs extracts work as before)."""
    from app.services.firmware_paths import _find_unblob_extraction_top
    plain = tmp_path / "extracted"
    plain.mkdir()
    top = _find_unblob_extraction_top(str(plain))
    assert os.path.realpath(top) == os.path.realpath(plain)


def test_walk_for_additional_roots_respects_max_dirs_cap(tmp_path: Path):
    """Pathological deep trees must not blow up the walk — the max_dirs
    cap should kick in and return whatever was found so far."""
    from app.services.firmware_paths import _walk_for_additional_roots
    # Build a tree of 50 sibling _extract dirs each with a raw.image
    # file — well below the 20,000 cap but enough to verify the walk
    # completes cleanly.
    top = tmp_path / "extracted"
    top.mkdir()
    for i in range(50):
        chunk = top / f"chunk.{i}_extract"
        chunk.mkdir()
        (chunk / "raw.image").write_bytes(b"\x00" * 16)
    results = _walk_for_additional_roots(str(top), max_dirs=20)
    # The cap bounded the walk early — we got SOME results, not all 50.
    assert 0 < len(results) <= 20


# ---------------------------------------------------------------------------
# Pytest collection sanity marker
# ---------------------------------------------------------------------------

# asyncio_mode = "auto" in pyproject.toml, so no @pytest.mark.asyncio needed.
# Verify at least one test can still be marked explicitly without conflict.
@pytest.mark.asyncio
async def test_explicit_asyncio_marker_still_works(tmp_path: Path):
    fw = _make_firmware(extracted_path=str(tmp_path))
    roots = await get_detection_roots(fw)
    assert roots == [str(tmp_path)]
