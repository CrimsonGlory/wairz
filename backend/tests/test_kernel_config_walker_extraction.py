"""C1 kernel-config extraction pipeline unit tests (Stages B, C, D) +
Rule #35b live canary (in test_kernel_config_walker.py).

This file covers the deterministic byte-work primitives the C1 walker
composes:

* **Stage B** (``android_boot_image.parse_boot_image`` + ``carve_kernel``)
  — boot_img_hdr v0-v4 parse + page-aligned kernel carve. Includes the
  Moto G32 phone v3 reference geometry (kernel_size=14,873,776 etc).
* **Stage C** (``android_ota_payload.parse_payload_manifest`` +
  ``classify_boot_partition``) — CrAU manifest walk: standard REPLACE_XZ
  boot op → ``standard``; ff12d941 (op type != standard) → honest
  ``blocked`` with ``blocked_reason="ff12d941_proprietary_block"`` (NOT
  an exception, NOT a silent no-op).
* **Stage D** (``kernel_decompress.decompress_kernel``) — each stdlib
  codec (gzip / xz / lzma-alone / bz2) round-trips; absent optional
  codecs (zstd / lz4) degrade truthfully; bare input → ``none``.

The headline AUTO-FIRE-FIX canary (synthetic-ZIP re-extract) lives in
test_kernel_config_walker.py alongside the walker triplet.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct

from app.services.hardware_firmware.parsers._kernel_ikconfig import (
    IKCFG_ED,
    IKCFG_ST,
)
from app.services.hardware_firmware.parsers.android_boot_image import (
    carve_kernel,
    parse_boot_image,
)
from app.services.hardware_firmware.parsers.android_ota_payload import (
    classify_boot_partition,
    parse_payload_manifest,
)
from app.services.kernel_decompress import decompress_kernel

# ───────────────────────────────────────────────────────────────────────
# Synthetic fixture builders.
# ───────────────────────────────────────────────────────────────────────


def _build_ikconfig_vmlinux(config_text: str) -> bytes:
    """Build a synthetic decompressed vmlinux carrying an IKCFG payload +
    a Linux banner — the Stage-E input shape.
    """
    inner = io.BytesIO()
    with gzip.GzipFile(fileobj=inner, mode="wb") as gz:
        gz.write(config_text.encode())
    gz_payload = inner.getvalue()
    banner = b"Linux version 4.19.157-perf+ (nobody@android-build) #1 SMP\x00"
    return (
        b"\x00" * 64
        + banner
        + b"\x00" * 64
        + IKCFG_ST
        + gz_payload
        + IKCFG_ED
        + b"\x00" * 32
    )


def _build_boot_image_v3(kernel_bytes: bytes, os_version_packed: int = 0) -> bytes:
    """Build a synthetic Android boot.img v3 with an embedded kernel slice.

    v3 layout: magic@0, kernel_size@8, ramdisk_size@12, os_version@16,
    header_version@40. Kernel begins at fixed page offset 4096. (Offsets
    verified against the real Moto G32 boot.img during real-data validation.)
    """
    hdr = bytearray(4096)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 8, len(kernel_bytes))  # kernel_size
    struct.pack_into("<I", hdr, 16, os_version_packed)  # os_version
    struct.pack_into("<I", hdr, 40, 3)  # header_version
    return bytes(hdr) + kernel_bytes


def _build_boot_image_v2(kernel_bytes: bytes, page_size: int = 4096) -> bytes:
    """Build a synthetic Android boot.img v2: kernel_size@8, page_size@36,
    header_version@40. Kernel begins at page_size.
    """
    hdr = bytearray(page_size)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 8, len(kernel_bytes))  # kernel_size
    struct.pack_into("<I", hdr, 36, page_size)  # page_size
    struct.pack_into("<I", hdr, 40, 2)  # header_version
    return bytes(hdr) + kernel_bytes


# ── Minimal protobuf encoders (mirror the hand-rolled reader) ──────────────


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _encode_tag(field_num: int, wire_type: int) -> bytes:
    return _encode_varint((field_num << 3) | wire_type)


def _encode_len_delim(field_num: int, payload: bytes) -> bytes:
    return _encode_tag(field_num, 2) + _encode_varint(len(payload)) + payload


def _encode_install_operation(op_type: int) -> bytes:
    # InstallOperation.field 1 (type, varint).
    return _encode_tag(1, 0) + _encode_varint(op_type)


def _encode_partition_update(name: str, op_types: list[int]) -> bytes:
    buf = _encode_len_delim(1, name.encode())  # partition_name
    for t in op_types:
        buf += _encode_len_delim(8, _encode_install_operation(t))  # operations
    return buf


def _build_crau_payload(partitions: list[tuple[str, list[int]]]) -> bytes:
    """Build a synthetic CrAU v2 payload.bin with the given partitions.

    Each partition is (name, [op_type, ...]). Header: magic + version=2 +
    manifest_size + metadata_signature_size + manifest.
    """
    manifest = bytearray()
    for name, op_types in partitions:
        part = _encode_partition_update(name, op_types)
        manifest += _encode_len_delim(13, part)  # field 13 = partitions
    header = bytearray()
    header += b"CrAU"
    header += struct.pack(">Q", 2)  # version
    header += struct.pack(">Q", len(manifest))  # manifest_size
    header += struct.pack(">I", 0)  # metadata_signature_size
    return bytes(header) + bytes(manifest)


# ───────────────────────────────────────────────────────────────────────
# Stage B — Android boot image header parse + carve.
# ───────────────────────────────────────────────────────────────────────


def test_stage_b_boot_v3_parse_and_carve():
    kernel = b"KERNELDATA" * 100
    img = _build_boot_image_v3(kernel)
    layout = parse_boot_image(img)
    assert layout is not None
    assert layout.header_version == 3
    assert layout.kernel_offset == 4096
    assert layout.kernel_size == len(kernel)
    assert layout.page_size == 4096
    carved = carve_kernel(img, layout)
    assert carved == kernel


def test_stage_b_boot_v3_phone_reference_geometry():
    """Moto G32 phone (A-phone-ikconfig-result.md §2): v3, kernel_size
    14,873,776 (@8), os_version (@16, packed 369099122) → 11.0.0 / 2023-02.
    The packed os_version value is taken VERBATIM from the real boot.img
    (confirmed during real-data validation)."""
    # Real packed os_version from the Moto G32 boot.img header @16.
    packed = 369099122  # → 11.0.0 + 2023-02 (AOSP (year-2000)<<4|month)
    fake_kernel = b"\x1f\x8b" + b"\x00" * 100  # gzip-magic head
    hdr = bytearray(4096)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 8, 14873776)  # the real phone kernel_size @8
    struct.pack_into("<I", hdr, 16, packed)  # os_version @16
    struct.pack_into("<I", hdr, 40, 3)  # header_version
    img = bytes(hdr) + fake_kernel
    layout = parse_boot_image(img)
    assert layout is not None
    assert layout.kernel_size == 14873776
    assert layout.kernel_offset == 4096
    assert layout.os_version == "11.0.0"
    assert layout.security_patch == "2023-02"
    # carve returns None because the buffer is header-only (the phone case
    # where unblob consumed the kernel body → walker re-extracts from ZIP).
    assert carve_kernel(img, layout) is None


def test_stage_b_boot_v2_parse_and_carve():
    kernel = b"V2KERNEL" * 50
    img = _build_boot_image_v2(kernel, page_size=2048)
    layout = parse_boot_image(img)
    assert layout is not None
    assert layout.header_version == 2
    assert layout.page_size == 2048
    assert layout.kernel_offset == 2048
    assert layout.kernel_size == len(kernel)
    assert carve_kernel(img, layout) == kernel


def test_stage_b_rejects_non_boot_image():
    assert parse_boot_image(b"NOTABOOTIMAGE" + b"\x00" * 100) is None
    assert parse_boot_image(b"") is None
    assert parse_boot_image(b"ANDROID!") is None  # too short


# ───────────────────────────────────────────────────────────────────────
# Stage C — CrAU payload.bin manifest walk + ff12d941 BLOCKED.
# ───────────────────────────────────────────────────────────────────────


def test_stage_c_standard_replace_xz_boot_op():
    """A CrAU payload whose boot partition uses REPLACE_XZ (op 8) →
    extraction_status='standard'."""
    payload = _build_crau_payload([("boot", [8]), ("system", [8])])
    manifest = parse_payload_manifest(payload)
    assert manifest is not None
    assert manifest.version == 2
    boot = manifest.boot_partition()
    assert boot is not None
    assert boot.op_types == [8]
    verdict = classify_boot_partition(manifest)
    assert verdict.extraction_status == "standard"
    assert verdict.blocked_reason is None


def test_stage_c_ff12d941_proprietary_block_is_blocked_not_silent():
    """A CrAU payload whose boot partition uses a NON-standard op (the
    ff12d941 proprietary block class, simulated by op type 13) → honest
    extraction_status='blocked' with the ff12d941 reason. NOT an
    exception, NOT a silent no-op (the tablet R47.1b verdict)."""
    payload = _build_crau_payload([("boot", [13])])  # 13 = non-standard
    manifest = parse_payload_manifest(payload)
    assert manifest is not None
    verdict = classify_boot_partition(manifest)
    assert verdict.extraction_status == "blocked"
    assert verdict.blocked_reason == "ff12d941_proprietary_block"
    assert verdict.recommendation == "live_adb_or_vendor_tool"


def test_stage_c_no_boot_partition():
    payload = _build_crau_payload([("system", [0]), ("vendor", [0])])
    manifest = parse_payload_manifest(payload)
    assert manifest is not None
    verdict = classify_boot_partition(manifest)
    assert verdict.extraction_status == "no_boot_partition"


def test_stage_c_rejects_non_crau():
    assert parse_payload_manifest(b"NOTCRAU" + b"\x00" * 100) is None
    assert parse_payload_manifest(b"") is None


# ───────────────────────────────────────────────────────────────────────
# Stage D — multi-codec outer-envelope decompress.
# ───────────────────────────────────────────────────────────────────────

_VMLINUX_SAMPLE = _build_ikconfig_vmlinux("CONFIG_DEVMEM=y\nCONFIG_WLAN=y\n")


def test_stage_d_gzip():
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(_VMLINUX_SAMPLE)
    out, codec = decompress_kernel(buf.getvalue())
    assert codec == "gzip"
    assert out == _VMLINUX_SAMPLE


def test_stage_d_xz():
    compressed = lzma.compress(_VMLINUX_SAMPLE, format=lzma.FORMAT_XZ)
    out, codec = decompress_kernel(compressed)
    assert codec == "xz"
    assert out == _VMLINUX_SAMPLE


def test_stage_d_lzma_alone():
    compressed = lzma.compress(_VMLINUX_SAMPLE, format=lzma.FORMAT_ALONE)
    out, codec = decompress_kernel(compressed)
    assert codec == "lzma"
    assert out == _VMLINUX_SAMPLE


def test_stage_d_bz2():
    compressed = bz2.compress(_VMLINUX_SAMPLE)
    out, codec = decompress_kernel(compressed)
    assert codec == "bz2"
    assert out == _VMLINUX_SAMPLE


def test_stage_d_bare_vmlinux_no_envelope():
    out, codec = decompress_kernel(_VMLINUX_SAMPLE)
    assert codec == "none"
    assert out == _VMLINUX_SAMPLE


def test_stage_d_empty_input():
    out, codec = decompress_kernel(b"")
    assert out == b""
    assert codec == "none"


def test_stage_d_optional_codecs_degrade_gracefully():
    """zstd / lz4-frame magic without the optional dep installed degrades
    to a truthful ``*_unavailable`` (or decodes if the dep IS present) —
    NEVER crashes, NEVER shells out (Rule #36)."""
    # zstd magic + junk.
    zstd_out, zstd_codec = decompress_kernel(b"\x28\xb5\x2f\xfd" + b"\x00" * 32)
    assert zstd_codec in ("zstd_unavailable", "zstd_error", "zstd"), zstd_codec
    # lz4 frame magic + junk.
    lz4_out, lz4_codec = decompress_kernel(b"\x04\x22\x4d\x18" + b"\x00" * 32)
    assert lz4_codec in ("lz4_unavailable", "lz4_error", "lz4"), lz4_codec


def test_stage_d_corrupt_gzip_returns_error_not_crash():
    out, codec = decompress_kernel(b"\x1f\x8b" + b"\xff" * 64)
    assert codec == "gzip_error"
    assert out == b""
