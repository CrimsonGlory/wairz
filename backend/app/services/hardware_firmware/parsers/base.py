"""Parser plugin contract for hardware firmware blobs.

Each per-format parser registers itself in ``PARSER_REGISTRY`` keyed by the
classifier format string (see ``classifier.FORMATS``).  The detector looks up
the parser for a classified blob and invokes ``parse(path, magic, size)`` to
fill in version / signing / chipset / parser-specific metadata fields.

Parsers MUST NOT raise up to the caller.  On any internal error they should
return ``ParsedBlob(metadata={"error": "..."})`` so detection continues for
other blobs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

logger = logging.getLogger(__name__)


@dataclass
class ParsedBlob:
    """Output of a parser.  All fields optional — parser sets what it can extract.

    ``vendor`` is a content-derived override for the classifier's
    filename-derived vendor: when the parser populates it (e.g. the
    ``bt_fw_banner`` parser reading a ``BTFM.<codename>.x.y.z-QCACHROM*``
    banner), the detector OVERRIDES ``Classification.vendor`` with this
    value because content evidence beats filename evidence (see Rule #19
    + the BTFM→Broadcom misattribution postmortem 2026-05-15). Parsers
    leave it ``None`` to defer to the classifier's filename-derived
    vendor — the default behaviour for the existing parser fleet.
    """

    version: str | None = None
    signed: str | None = None  # signed|unsigned|unknown|weakly_signed
    signature_algorithm: str | None = None
    cert_subject: str | None = None
    chipset_target: str | None = None
    vendor: str | None = None
    metadata: dict = field(default_factory=dict)


class Parser(Protocol):
    """Protocol all format parsers must implement."""

    FORMAT: str

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        """Parse a blob at ``path``; ``magic`` is the first 64 bytes, ``size`` is file size."""
        ...


# Registry keyed by format string (e.g. "qcom_mbn", "dtb", "ko", ...).  Populated
# at import time by each parser module via ``register_parser``.
PARSER_REGISTRY: dict[str, Parser] = {}


def register_parser(parser: Parser) -> None:
    """Register a parser, keyed by its FORMAT string."""
    fmt = getattr(parser, "FORMAT", None)
    if not fmt:
        raise ValueError("Parser instance missing FORMAT attribute")
    if fmt in PARSER_REGISTRY:
        logger.warning("Parser for format %s already registered; overwriting", fmt)
    PARSER_REGISTRY[fmt] = parser


def get_parser(format: str) -> Parser | None:
    """Return parser for a format, or None if no parser is registered."""
    return PARSER_REGISTRY.get(format)
