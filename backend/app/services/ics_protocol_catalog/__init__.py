"""ICS protocol catalog package.

Session 1 surface (this file's exports):

* :class:`IcsProtocolCatalog` — hot-reloadable manifest loader
* :func:`get_default_catalog` — process-wide singleton accessor
* :func:`derive_vendor_authority` — manifest → IcsVendorAuthority (Wave-2 I2)
* :data:`SIGNAL_EVALUATORS` — closed dispatch over IcsSignalKind
* :data:`_SIGNAL_COST_CLASS` — resolver cost-sort table
* :data:`_SOURCE_PRECEDENCE` — manifest_source rank
* :class:`IcsResolverContext` — per-resolve context (Session 1 stub)
* :func:`resolve_all` — list[IcsProtocolMatch] (multi-protocol-per-binary)
* :class:`IcsProtocolCatalogSnapshot` — frozen catalog snapshot

Session 2 will add (deferred per Wave-2 γ Rule #28 yardstick):

* Plugin registry (`MatcherProto` + `register_matcher` + `freeze_plugin_registry`)
* Bundled plugins: `ics_string_scanner_default`, `ics_elf_symtab_default`, etc.
* Refinement block + Dispatch block + ProvenanceStub
* Cross-feature gates I5-I19 (analogs of file_format A5-A9 + W2-β NEW)
* Walker triplet (Rule #39 inner/outer/safe in `app/services/ics_protocol_walker.py`)
* MCP tool category (`app/ai/tools/ics_protocol.py`)
"""
from __future__ import annotations

from app.services.ics_protocol_catalog.catalog import (
    IcsProtocolCatalog,
    derive_vendor_authority,
    get_default_catalog,
    reset_default_catalog,
)
from app.services.ics_protocol_catalog.resolver import (
    _SIGNAL_COST_CLASS,
    _SOURCE_PRECEDENCE,
    PLUGIN_REGISTRY,
    SIGNAL_EVALUATORS,
    IcsProtocolMatcherProto,
    IcsResolverContext,
    _unfreeze_plugin_registry_for_tests,
    freeze_plugin_registry,
    is_plugin_registry_frozen,
    register_matcher,
    resolve_all,
)
from app.services.ics_protocol_catalog.snapshot import (
    IcsProtocolCatalogSnapshot,
)


def get_default_snapshot() -> IcsProtocolCatalogSnapshot:
    """Return the latest default-catalog snapshot."""
    return get_default_catalog().get_snapshot()


__all__ = [
    "IcsProtocolCatalog",
    "IcsProtocolCatalogSnapshot",
    "IcsProtocolMatcherProto",
    "IcsResolverContext",
    "PLUGIN_REGISTRY",
    "SIGNAL_EVALUATORS",
    "_SIGNAL_COST_CLASS",
    "_SOURCE_PRECEDENCE",
    "_unfreeze_plugin_registry_for_tests",
    "derive_vendor_authority",
    "freeze_plugin_registry",
    "get_default_catalog",
    "get_default_snapshot",
    "is_plugin_registry_frozen",
    "register_matcher",
    "reset_default_catalog",
    "resolve_all",
]
