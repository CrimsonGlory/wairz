"""Chip-matcher plugin package.

Importing this package triggers ``register_matcher()`` for every matcher
module via the explicit imports below. Matches the
:mod:`app.services.hardware_firmware.parsers` registration idiom.

Operators adding a new per-vendor matcher (Scout AA Alt C hybrid escape
hatch — for cases the closed-grammar YAML can't express) drop a new
module here and add it to the import list. The :class:`YamlDrivenMatcher`
remains the default for YAML-expressible chip families.
"""
from __future__ import annotations

# Module imports trigger register_matcher() at the bottom of each file.
from app.services.hardware_firmware.matchers.base import (  # noqa: F401
    MATCHER_REGISTRY,
    ChipMatcher,
    address_to_file_offset,
    domain_base_addr_for_blob,
    get_matcher,
    read_region_bytes,
    read_word_at_address,
    register_matcher,
)
from app.services.hardware_firmware.matchers.yaml_driven import (  # noqa: F401
    REJECT,
    SIGNAL_EVALUATORS,
    YamlDrivenMatcher,
    get_default_matcher,
)


__all__ = [
    "MATCHER_REGISTRY",
    "REJECT",
    "SIGNAL_EVALUATORS",
    "ChipMatcher",
    "YamlDrivenMatcher",
    "address_to_file_offset",
    "domain_base_addr_for_blob",
    "get_default_matcher",
    "get_matcher",
    "read_region_bytes",
    "read_word_at_address",
    "register_matcher",
]
