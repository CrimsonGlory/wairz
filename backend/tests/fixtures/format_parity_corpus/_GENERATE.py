"""Regenerate the parity-test corpus from the file-format catalog manifests.

Run from the backend/ directory:

    uv run python tests/fixtures/format_parity_corpus/_GENERATE.py

Emits one ``<format_id>.head`` fixture per supported format. Each fixture
carries the MINIMUM byte sequence required to trigger the manifest's
detection signals on a fixed-size head buffer (<=4 KB each).

Fixtures are versioned in git alongside the YAML manifests. Regenerate
this corpus only when adding a new format_id or extending an existing
manifest's signals.

Special cases that need on-disk file shape rather than just head bytes
(zip_markers, tar_markers) emit a ``.head`` carrying the magic bytes
prefix only; the parity test detects these by name and falls back to
inflating a real zip / tar fixture in tmp_path. ``always_matches`` is
not emitted — every blob trivially matches the catch-all.
"""
from __future__ import annotations

from pathlib import Path

# format_id -> head bytes (extended with zero-padding to >=128 B)
# Mirrors the bytes_hex declared in each YAML's magic_bytes signal.
_FIXTURES: dict[str, bytes] = {
    # Linux firmware-blob magic bytes (offset 0)
    "linux_squashfs":        bytes.fromhex("68737173"),       # 'hsqs'
    "linux_cramfs":          bytes.fromhex("453dcd28"),       # 0x28cd3d45 LE
    "linux_jffs2":           bytes.fromhex("85190320"),       # JFFS2 dirent
    "linux_uboot_uimage":    bytes.fromhex("27051956"),       # U-Boot uImage
    "linux_fit_dtb":         bytes.fromhex("d00dfeed"),       # FIT/DTB
    "linux_elf":             b"\x7fELF",                      # ELF magic
    "linux_zimage":          b"",                             # special; see below
    # Android
    "android_boot":          bytes.fromhex("414e44524f494421"),  # 'ANDROID!'
    "android_sparse":        bytes.fromhex("3aff26ed"),       # 0xed26ff3a
    "android_dtb":           bytes.fromhex("d00dfeed"),       # same as DTB
    "android_dtbo":          bytes.fromhex("d7b7ab1e"),       # Android DTBO
    # Vendor partition magic
    "qcom_mbn":              b"\x7fELF",                      # ELF — refined by filename
    "samsung_shannon_toc":   b"TOC\x00",                      # Shannon TOC
    "kinibi_mclf":           b"TRUS",                         # Kinibi MCLF
    "mtk_lk":                bytes.fromhex("88168858"),       # MediaTek LK
    "mtk_preloader":         bytes.fromhex("4d4d4d0138"),     # MMM\x01 + 0x38
    "signed_archive":        bytes.fromhex("a3dfbbbf"),       # Vendor signed archive
    # Windows family
    "pe_binary":             b"MZ",                           # PE/MZ
    "wim_archive":           b"MSWIM\x00\x00\x00",            # WIM magic
    "windows_vhdx":          b"vhdxfile",                     # VHDX magic
    "windows_psf":           b"PA30",                         # PSF (Win10/11)
    "windows_cab":           b"MSCF",                         # CAB family
    "windows_msu":           b"MSCF",                         # CAB + .msu (filename signal)
    "windows_msi":           bytes.fromhex("d0cf11e0a1b11ae1"),  # OLE2
    # Container family — magic at non-zero offsets
    "iso_9660":              b"\x00" * 0x8001 + b"CD001",     # ISO at offset 0x8001 (bare)
    # windows_installer_iso: CD001 magic + bootmgr substring (substring_in_head
    # signal). bootmgr at offset 0x100 (catalog substring_in_head_constraint
    # scans the whole head from offset 0). P3.x 2026-05-20.
    "windows_installer_iso": (
        b"\x00" * 0x100 + b"bootmgr" + b"\x00" * (0x8001 - 0x100 - 7)
        + b"CD001"
    ),
    "tar_archive":           b"\x00" * 0x101 + b"ustar",      # tar 'ustar' at 0x101
    # Misc
    "qnx_ifs":               bytes.fromhex("00ff7eeb"),       # QNX IFS
    "rtos_blob":             b"",                             # RTOS plugin — skip
    # Container-shape (zip / tar with inner content) — parity test builds them in-memory
    "zip_archive":           b"PK\x03\x04",                   # ZIP local file header
    "android_apk":           b"PK\x03\x04",                   # ZIP + manifest+dex inner
    "android_ota":           b"PK\x03\x04",                   # ZIP + payload.bin inner
    "android_scatter":       b"PK\x03\x04",                   # ZIP + scatter.txt + super.img
    "uefi_firmware":         b"_FVH",                         # UEFI FVH magic
    "windows_msix":          b"PK\x03\x04",                   # ZIP + AppxManifest inner
    "windows_driver_package": b"MSCF",                        # CAB + .inf inner
    "partition_dump_tar":    b"\x00" * 0x101 + b"ustar",      # tar + partition .img inner
    "rootfs_tar":            b"\x00" * 0x101 + b"ustar",      # tar + linux dirs inner
    "acronis_backup":        b"\x00" * 8 + b"ARCH",           # 'ARCH' at offset 8
    "intel_hex":             b":",                            # text_format stub — won't fire
    "bt_fw_banner":          b"",                             # banner-string parser
    "awinic_acf":            b"",                             # ACF magic — unknown
    "mtk_atf":               bytes.fromhex("88168858"),       # via mtk_lk dispatch
    "mtk_geniezone":         bytes.fromhex("88168858"),       # via mtk_lk dispatch
    "mtk_tinysys":           bytes.fromhex("88168858"),       # via mtk_lk dispatch
    "qcom_mbn_split":        b"",                             # filename-based
    "linux_blob":            b"",                             # fallback — every blob
}


def main() -> None:
    """Write each fixture to disk under the corpus directory."""
    corpus_dir = Path(__file__).parent
    for fmt_id, head in _FIXTURES.items():
        # Pad to 4096 bytes so size_range signals + offset reads always succeed.
        body = head + b"\x00" * max(0, 4096 - len(head))
        (corpus_dir / f"{fmt_id}.head").write_bytes(body)
    print(f"wrote {len(_FIXTURES)} fixtures to {corpus_dir}")


if __name__ == "__main__":
    main()
