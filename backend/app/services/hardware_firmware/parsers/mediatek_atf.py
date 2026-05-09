"""MediaTek ARM Trusted Firmware (TF-A bl31) parser.

Handles classifier format ``mtk_atf``. Input file begins with the outer
LK-container header (``0x58881688``) whose partition name is ``atf``.
The payload itself carries a second MediaTek wrapper — ASCII magic
``"MTK TEE "`` (word-swapped LE), 0x240 bytes — before the raw AArch64
bl31 image begins. Skipping both wrappers gives Ghidra a clean raw
AArch64 import at the canonical MT6771/MT8788 ``BL31_BASE``.

Extractable metadata we surface:

- TF-A version string with git short-hash (``v1.3(debug):0cf92e67769``)
- Build date (``Built : 16:06:49, Apr 13 2026``)
- Platform source path (``plat/mediatek/common/bl31_fiq_handler.c``)
- Ghidra import params (processor, base_addr, entry_point, load_offset)

References:
    - ARM TF-A ``plat/mediatek/mt6771/`` (MediaTek platform port)
    - TF-A ``runtime_exceptions`` vector at BL31_BASE + 0x800
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser
from app.services.hardware_firmware.parsers.mediatek_gfh import (
    derive_chipset,
    signed_from_subimages,
    walk_sub_images,
)

logger = logging.getLogger(__name__)


# MTK ATF secondary wrapper — 0x240 bytes between the LK container header
# and the raw bl31 image.
_MTK_ATF_MAGIC = b"\x45\x45\x54\x20\x4B\x54\x4D\x20"  # word-swapped "MTK TEE "
_MTK_ATF_WRAPPER_SIZE = 0x240

# MediaTek BL31 typically loads at 0x54600000 on Helio P60 / Genio 700
# (MT6771 / MT8788). The GFH extension blocks carry the authoritative
# address; we emit this default with a "verify" caveat. The actual entry
# (vbar_el3 installation) sits at base + 0x800 per TF-A conventions, but
# cold_boot jumps to base.
_MT_ATF_DEFAULT_BASE = 0x54600000
_MT_ATF_DEFAULT_ENTRY_OFFSET = 0

_VERSION_RE = re.compile(rb"v\d+\.\d+\(\w+\):[0-9a-f]{6,12}")
_BUILT_RE = re.compile(rb"Built\s*:\s*([^\x00]{0,80})")
_PLAT_RE = re.compile(rb"plat/mediatek/(\w+)/")


def _read_payload(path: str, limit: int = 4 * 1024 * 1024) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


class MediatekAtfParser:
    """Parser for MediaTek-flavored ARM Trusted Firmware (bl31) blobs."""

    FORMAT = "mtk_atf"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {"component": "atf", "runtime": "arm_trusted_firmware"}
        version: str | None = None
        data = _read_payload(path)
        if not data:
            meta["error"] = "unable to read file"
            return ParsedBlob(metadata=meta)

        subimages = walk_sub_images(data)
        meta["sub_images"] = [
            {"name": s.name, "offset": s.offset, "size": s.payload_size,
             "is_signature": s.is_signature}
            for s in subimages
        ]

        # Primary payload = first non-signature sub-image
        primary = next((s for s in subimages if not s.is_signature), None)
        if primary is None:
            meta["error"] = "no primary payload found"
            return ParsedBlob(metadata=meta)

        payload_start = primary.payload_offset
        payload = data[payload_start : payload_start + primary.payload_size]

        # Check for MTK TEE secondary wrapper and skip it
        code_offset = payload_start
        inner_wrapper_skipped = 0
        if payload[:8] == _MTK_ATF_MAGIC:
            meta["inner_wrapper"] = "mtk_tee"
            code_offset = payload_start + _MTK_ATF_WRAPPER_SIZE
            inner_wrapper_skipped = _MTK_ATF_WRAPPER_SIZE

        # Extract version banner + build date + platform
        search_window = payload[: 200 * 1024]
        m = _VERSION_RE.search(search_window)
        if m:
            version = m.group(0).decode("ascii", errors="replace")
            meta["tfa_version"] = version
            # Pull the git short-hash from the version (":<hash>" suffix)
            if ":" in version:
                meta["tfa_git_hash"] = version.rsplit(":", 1)[-1]

        built = _BUILT_RE.search(search_window)
        if built:
            meta["build_date"] = built.group(1).decode("ascii", errors="replace").strip()

        plat = _PLAT_RE.search(search_window)
        if plat:
            meta["platform_tree"] = plat.group(1).decode("ascii", errors="replace")

        # Ghidra import params. The LK container + MTK TEE wrapper are
        # stripped before disassembly; base_addr is the MT6771/MT8788 BL31
        # default (verify via GFH once we parse extension blocks).
        meta["ghidra_import_params"] = {
            "processor": "AARCH64:LE:64:v8A",
            "loader": "BinaryLoader",
            "base_addr": _MT_ATF_DEFAULT_BASE,
            "entry_point": _MT_ATF_DEFAULT_BASE + _MT_ATF_DEFAULT_ENTRY_OFFSET,
            "load_offset_in_file": code_offset,
            "load_length": primary.payload_size - inner_wrapper_skipped,
            "notes": "BL31_BASE default for MT6771/MT8788; verify via GFH maddr",
        }

        return ParsedBlob(
            version=version,
            signed=signed_from_subimages(subimages),
            metadata=meta,
            chipset_target=derive_chipset(meta),
        )


register_parser(MediatekAtfParser())
