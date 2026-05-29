"""Stage D — multi-codec outer-envelope kernel decompressor (bounded).

A Linux kernel image is typically a compressed ``vmlinux`` wrapped in one
of several outer envelopes (``CONFIG_KERNEL_GZIP`` / ``_LZ4`` / ``_XZ`` /
``_ZSTD`` / ``_LZMA`` / ``_BZIP2``). The existing
``_kernel_ikconfig.extract_ikconfig`` only handles the INNER IKCFG gzip
payload — it does NOT decompress the OUTER kernel envelope, so a non-gzip
or even a gzip-outer-wrapped kernel that hasn't been decompressed on disk
yields no IKCFG. C1's Stage D closes that gap: magic-dispatch the outer
envelope, decompress to the raw ``vmlinux`` bytes, then hand those to the
IKCFG + banner scan.

Reference (Moto G32 phone, ``A-phone-ikconfig-result.md`` §2): the carved
14,873,776-byte kernel began with gzip magic ``1f8b0800`` and decompressed
to a 34,361,856-byte ``vmlinux``. THIS is the gap that made non-Tegra
kernels invisible.

Rule #36 + Rule #45 PARSE-ONLY contract
---------------------------------------
This module reads + decompresses bytes AS DATA. It NEVER passes any input
to a spawn primitive (``subprocess`` / ``os.system`` / ``exec`` / etc.).
All decompression uses the Python stdlib (``gzip`` / ``lzma`` / ``bz2``)
plus OPTIONAL third-party codecs (``zstandard`` / ``lz4``) imported
defensively — when an optional codec is absent the function degrades to
a truthful ``(b"", "<codec>_unavailable")`` verdict rather than crashing
or shelling out to a CLI decompressor.

Bounded output (Wave-2 attack D / gzip-bomb mitigation)
-------------------------------------------------------
Every decompressor caps its output at ``_MAX_VMLINUX_BYTES`` (64 MB,
matching ``kernel_image._MAX_KERNEL_BYTES``). A kernel that decompresses
beyond the cap is treated as suspect and the decompression returns the
partial-up-to-cap bytes flagged with a ``_truncated`` codec suffix so the
caller can surface the anomaly in ``errors[]``.
"""
from __future__ import annotations

import bz2
import gzip
import io
import logging
import lzma

logger = logging.getLogger(__name__)

# Upper bound on the decompressed vmlinux. Real arm64/x86 kernels run
# 20-40 MB decompressed; 64 MB is comfortable headroom and matches
# kernel_image._MAX_KERNEL_BYTES. Caps every codec's output.
_MAX_VMLINUX_BYTES = 64 * 1024 * 1024  # 64 MB

# Outer-envelope magics. Order matters only for readability — each is
# distinct at offset 0.
_GZIP_MAGIC = b"\x1f\x8b"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_BZ2_MAGIC = b"BZh"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_LZ4_FRAME_MAGIC = b"\x04\x22\x4d\x18"
_LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"
# LZMA-alone (.lzma) has no robust magic; the canonical signature is a
# properties byte 0x5d followed by a little-endian dict size. We match the
# common kernel ``CONFIG_KERNEL_LZMA`` shape ``5d 00 00`` conservatively.
_LZMA_ALONE_PREFIX = b"\x5d\x00\x00"


def _read_bounded(decompressor_obj, cap: int) -> tuple[bytes, bool]:
    """Read up to ``cap`` bytes from a file-like decompressor.

    Reads ``cap + 1`` to detect overflow; returns ``(bytes_up_to_cap,
    truncated_flag)``.
    """
    raw = decompressor_obj.read(cap + 1)
    if len(raw) > cap:
        return raw[:cap], True
    return raw, False


def decompress_kernel(data: bytes) -> tuple[bytes, str]:
    """Decompress the OUTER kernel envelope; return ``(vmlinux_bytes, codec)``.

    Magic-dispatch on offset 0:

    * gzip ``1f8b``          → stdlib ``gzip``
    * xz   ``fd377a585a00``  → stdlib ``lzma`` (auto format)
    * bz2  ``425a68``        → stdlib ``bz2``
    * lzma-alone ``5d0000``  → stdlib ``lzma`` (FORMAT_ALONE)
    * zstd ``28b52ffd``      → optional ``zstandard`` (degrade if absent)
    * lz4-frame ``04224d18`` → optional ``lz4`` (degrade if absent)
    * lz4-legacy ``02214c18``→ optional ``lz4`` legacy block (degrade)
    * else                   → ``(data, "none")`` — already a bare vmlinux

    On a decompression error returns ``(b"", "<codec>_error")``. When an
    optional codec module is missing returns ``(b"", "<codec>_unavailable")``.
    Output capped at ``_MAX_VMLINUX_BYTES``; over-cap output yields a
    ``<codec>_truncated`` codec tag and the partial bytes.

    Idempotent + side-effect free — safe to call on any input.
    """
    if not data:
        return b"", "none"

    # ── gzip ──────────────────────────────────────────────────────────
    if data[:2] == _GZIP_MAGIC:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                raw, truncated = _read_bounded(gz, _MAX_VMLINUX_BYTES)
            return raw, "gzip_truncated" if truncated else "gzip"
        except Exception as exc:  # noqa: BLE001 — defensive decompress boundary
            logger.debug("decompress_kernel: gzip failed: %s", exc)
            return b"", "gzip_error"

    # ── xz ────────────────────────────────────────────────────────────
    if data[:6] == _XZ_MAGIC:
        try:
            with lzma.LZMAFile(io.BytesIO(data), format=lzma.FORMAT_XZ) as xz:
                raw, truncated = _read_bounded(xz, _MAX_VMLINUX_BYTES)
            return raw, "xz_truncated" if truncated else "xz"
        except Exception as exc:  # noqa: BLE001
            logger.debug("decompress_kernel: xz failed: %s", exc)
            return b"", "xz_error"

    # ── bz2 ───────────────────────────────────────────────────────────
    if data[:3] == _BZ2_MAGIC:
        try:
            with bz2.BZ2File(io.BytesIO(data)) as bz:
                raw, truncated = _read_bounded(bz, _MAX_VMLINUX_BYTES)
            return raw, "bz2_truncated" if truncated else "bz2"
        except Exception as exc:  # noqa: BLE001
            logger.debug("decompress_kernel: bz2 failed: %s", exc)
            return b"", "bz2_error"

    # ── lzma-alone ────────────────────────────────────────────────────
    # Checked AFTER xz (xz is also an lzma container but has a distinct
    # 6-byte magic above). The bare-lzma prefix is weaker, so this branch
    # sits late to avoid shadowing a real format.
    if data[:3] == _LZMA_ALONE_PREFIX:
        try:
            with lzma.LZMAFile(io.BytesIO(data), format=lzma.FORMAT_ALONE) as lz:
                raw, truncated = _read_bounded(lz, _MAX_VMLINUX_BYTES)
            return raw, "lzma_truncated" if truncated else "lzma"
        except Exception as exc:  # noqa: BLE001
            logger.debug("decompress_kernel: lzma-alone failed: %s", exc)
            return b"", "lzma_error"

    # ── zstd (optional dep) ───────────────────────────────────────────
    if data[:4] == _ZSTD_MAGIC:
        try:
            import zstandard  # noqa: PLC0415 — optional dep, lazy per Rule #30
        except ImportError:
            logger.info(
                "decompress_kernel: zstd magic present but `zstandard` not "
                "installed; degrading. Install zstandard to support "
                "CONFIG_KERNEL_ZSTD kernels.",
            )
            return b"", "zstd_unavailable"
        try:
            dctx = zstandard.ZstdDecompressor()
            with dctx.stream_reader(io.BytesIO(data)) as reader:
                raw, truncated = _read_bounded(reader, _MAX_VMLINUX_BYTES)
            return raw, "zstd_truncated" if truncated else "zstd"
        except Exception as exc:  # noqa: BLE001
            logger.debug("decompress_kernel: zstd failed: %s", exc)
            return b"", "zstd_error"

    # ── lz4 frame + legacy (optional dep) ─────────────────────────────
    if data[:4] in (_LZ4_FRAME_MAGIC, _LZ4_LEGACY_MAGIC):
        is_legacy = data[:4] == _LZ4_LEGACY_MAGIC
        try:
            import lz4.frame  # noqa: PLC0415 — optional dep, lazy per Rule #30
        except ImportError:
            logger.info(
                "decompress_kernel: lz4 magic present but `lz4` not "
                "installed; degrading. Install lz4 to support "
                "CONFIG_KERNEL_LZ4 kernels.",
            )
            return b"", "lz4_unavailable"
        if is_legacy:
            # lz4 legacy block format is not handled by lz4.frame; the
            # kernel uses the legacy format for CONFIG_KERNEL_LZ4 on some
            # arches. We honestly report unsupported rather than mis-decode.
            return b"", "lz4_legacy_unsupported"
        try:
            raw = lz4.frame.decompress(data)
            if len(raw) > _MAX_VMLINUX_BYTES:
                return raw[:_MAX_VMLINUX_BYTES], "lz4_truncated"
            return raw, "lz4"
        except Exception as exc:  # noqa: BLE001
            logger.debug("decompress_kernel: lz4 failed: %s", exc)
            return b"", "lz4_error"

    # ── no envelope — already a bare vmlinux ──────────────────────────
    return data, "none"


__all__ = ["decompress_kernel"]
