"""Chip-matcher plugin contract for bare-metal MCU/DSP firmware identification.

Mirrors the existing :mod:`app.services.hardware_firmware.parsers.base` shape
— a small Protocol + a module-level registry + a registration helper. Lets
the hybrid schema-driven architecture (Scout AA Alt C) ship per-vendor
Python plugins for cases the closed-grammar YAML can't express (composite
SoCs with vendor-specific decode tables, runtime-decrypted flashes that
need a known KDF, multi-stage bootloaders that compose at detection time).

The :class:`YamlDrivenMatcher` in :mod:`.yaml_driven` is the default
matcher — it walks the catalog and scores domains via the YAML's declared
``detection_signals``. Per-vendor plugins are escape hatches, not the
default extension surface.

**Address-space packing helpers** live here too: ``address_to_file_offset``
+ ``read_word_at_address`` translate a chip's logical address to a host-file
byte offset, respecting the domain's :class:`Packing` enum. Critical for
TI C28x and similar 16-bit-word-addressed architectures where a single
"address" represents a 16-bit word, not a byte (Scout AA §1 attack-surface
#2).
"""
from __future__ import annotations

import logging
from typing import Protocol

from app.schemas.chip_family import ChipMatch, Domain, Packing

logger = logging.getLogger(__name__)


class ChipMatcher(Protocol):
    """Protocol all chip matchers MUST implement.

    Dissect.target inspired — single classmethod-shaped detect entry point.
    Implementations may keep state, but each ``detect()`` call should be
    self-contained (no caller-visible side effects).
    """

    NAME: str   # e.g. "yaml_driven", "ti_c28x_specialised", "nxp_spc58_bam"

    def detect(
        self,
        blob_bytes: bytes,
        blob_metadata: dict | None = None,
        *,
        threshold: float = 0.3,
        max_candidates: int = 5,
    ) -> list[ChipMatch]:
        """Score the blob against known chips; return scored candidates.

        Returns a list of :class:`ChipMatch` sorted by confidence descending.
        Empty list = no chip family matched above ``threshold``. The walker
        treats an empty result as "unknown chip — fall back to heuristic
        report" (Scout CC §SC12).
        """
        ...


# Module-level registry keyed by matcher NAME. Populated by per-matcher
# modules via ``register_matcher`` at import time.
MATCHER_REGISTRY: dict[str, ChipMatcher] = {}


def register_matcher(matcher: ChipMatcher) -> None:
    """Register ``matcher`` under its :attr:`NAME`.

    Idempotent — re-registration logs a WARN and overwrites (pytest-safe
    under module reload). Empty-name matchers raise ``ValueError`` —
    mirrors :func:`app.services.hardware_firmware.parsers.base.register_parser`.
    """
    name = getattr(matcher, "NAME", None)
    if not name:
        raise ValueError("ChipMatcher missing NAME attribute")
    if name in MATCHER_REGISTRY:
        logger.warning("ChipMatcher %r already registered; overwriting", name)
    MATCHER_REGISTRY[name] = matcher


def get_matcher(name: str) -> ChipMatcher | None:
    """Look up a matcher by name."""
    return MATCHER_REGISTRY.get(name)


# ---------------------------------------------------------------------------
# Address-space + packing helpers.
# ---------------------------------------------------------------------------


def address_to_file_offset(
    address: int,
    base_addr: int,
    packing: Packing,
) -> int:
    """Translate a chip's logical address to a host-file byte offset.

    For TI C28x ``two_bytes_per_word_le``: each address slot holds 1 word
    = 2 host bytes, so file_offset = (address - base_addr) × 2.

    For byte-addressed architectures (Cortex-M, etc.): file_offset =
    address - base_addr.

    Raises ``ValueError`` on negative offset (address below base_addr).
    """
    if address < base_addr:
        raise ValueError(
            f"address 0x{address:X} is below base_addr 0x{base_addr:X}"
        )
    word_offset = address - base_addr
    if packing in ("two_bytes_per_word_le", "two_bytes_per_word_be"):
        return word_offset * 2
    if packing == "ti_txt_native_word":
        # TI-TXT format stores each word as 4 hex chars + space — but on
        # the wairz side we only see the source TI-TXT file as text. The
        # decoded form is two_bytes_per_word_le bytes; matchers should
        # operate on the decoded form. Falling through to word offset
        # here would be wrong; treat the same as one_byte_per_address for
        # safety — operator should decode TI-TXT before invoking the matcher.
        logger.warning(
            "address_to_file_offset called with packing=ti_txt_native_word; "
            "decode TI-TXT to binary form first (treating as one_byte_per_address)"
        )
        return word_offset
    if packing == "intel_hex_packed":
        # Intel HEX is a record format; decode to binary before matcher invocation.
        logger.warning(
            "address_to_file_offset called with packing=intel_hex_packed; "
            "decode IHEX to binary form first (treating as one_byte_per_address)"
        )
        return word_offset
    # one_byte_per_address (default)
    return word_offset


def read_word_at_address(
    blob_bytes: bytes,
    address: int,
    base_addr: int,
    packing: Packing,
    word_size_bits: int = 16,
) -> int | None:
    """Read one word at the chip's logical ``address``. Returns None if OOB.

    Respects packing's endianness convention (``two_bytes_per_word_le``
    → little-endian word, ``two_bytes_per_word_be`` → big-endian).
    """
    word_size_bytes = max(1, word_size_bits // 8)
    try:
        offset = address_to_file_offset(address, base_addr, packing)
    except ValueError:
        return None
    if offset < 0 or offset + word_size_bytes > len(blob_bytes):
        return None
    raw = blob_bytes[offset : offset + word_size_bytes]
    if packing == "two_bytes_per_word_be":
        return int.from_bytes(raw, "big")
    # Default: little-endian (covers two_bytes_per_word_le and the
    # one-byte-per-address case where endianness is irrelevant for 1-byte reads).
    return int.from_bytes(raw, "little")


def read_region_bytes(
    blob_bytes: bytes,
    region_start: int,
    region_size: int,
    base_addr: int,
    packing: Packing,
) -> bytes | None:
    """Slice the file bytes corresponding to a region. Returns None if OOB."""
    try:
        offset = address_to_file_offset(region_start, base_addr, packing)
    except ValueError:
        return None
    if packing in ("two_bytes_per_word_le", "two_bytes_per_word_be"):
        byte_length = region_size * 2
    else:
        byte_length = region_size
    if offset < 0 or offset + byte_length > len(blob_bytes):
        return None
    return blob_bytes[offset : offset + byte_length]


def domain_base_addr_for_blob(domain: Domain) -> int:
    """Pick the base address for translating logical → file offsets.

    Prefers the domain's declared ``ghidra_import_params.base_addr`` (the
    operator's stated "where does this blob load") with fallback to the
    lowest non-RAM region (heuristic for bare flash dumps).
    """
    if domain.ghidra_import_params is not None:
        return domain.ghidra_import_params.base_addr
    candidates = [
        r.start for r in domain.address_regions
        if "flash_code" in r.semantic or "flash_data" in r.semantic
    ]
    if candidates:
        return min(candidates)
    return min(r.start for r in domain.address_regions)


__all__ = [
    "ChipMatcher",
    "MATCHER_REGISTRY",
    "address_to_file_offset",
    "domain_base_addr_for_blob",
    "get_matcher",
    "read_region_bytes",
    "read_word_at_address",
    "register_matcher",
]
