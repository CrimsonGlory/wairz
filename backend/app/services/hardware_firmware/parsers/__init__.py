"""Hardware firmware parser plugin registry.

Importing this package side-effects each parser module so they can
self-register in ``PARSER_REGISTRY`` via ``register_parser``.  The
detector does ``from app.services.hardware_firmware.parsers import
get_parser`` and looks up the parser by the classifier's format string.
"""

from __future__ import annotations

# Self-registration fires on import.
from app.services.hardware_firmware.parsers import (  # noqa: F401,E402
    awinic_acf,
    broadcom_wl,
    bt_firmware_banner,
    dtb,
    elf_tee,
    kmod,
    mediatek_atf,
    mediatek_geniezone,
    mediatek_lk,
    mediatek_modem,
    mediatek_preloader,
    mediatek_tinysys,
    mediatek_wifi,
    qualcomm_mbn,
    raw_bin,
)
from app.services.hardware_firmware.parsers.base import (
    PARSER_REGISTRY,
    ParsedBlob,
    Parser,
    get_parser,
    register_parser,
)

__all__ = [
    "PARSER_REGISTRY",
    "ParsedBlob",
    "Parser",
    "get_parser",
    "register_parser",
]
