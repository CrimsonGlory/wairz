"""Bundled string-scanner plugin (CLAUDE.md Rule #52 instance #3, Phase 4).

Detects ICS protocol stacks by scanning the binary's head bytes for
library-symbol byte signatures that closed-grammar
``string_in_binary_constraint`` evaluators cannot express compactly.
The plugin is STATELESS — accepts head + path + size + context, returns
a (protocol_family, evidence) tuple per hit.

**Stateless contract — Rule #45 + W2-β §SC5-NEW-ICS-S2-ζ.** The plugin
does NOT capture session state, settings, or context-var values in its
closure. The ``register_matcher`` closure-capture gate would reject
this plugin at registration if it did; the gate's META-CANARY proves
the rejection fires.

**Bundled byte signatures.** Each entry maps a protocol_family to a
list of byte-sequence needles. Hits in ANY needle imply detection
(disjunctive). For the v0 release we ship coarse signatures for the
3 SHIPPED protocols (modbus_tcp, dnp3, s7comm) — future plugin updates
can extend.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.services.ics_protocol_catalog.resolver import IcsResolverContext


# Per-protocol byte-needle library. Operators can extend this by
# authoring YAML manifests with ``string_in_binary`` signal kinds
# (closed-grammar path); this plugin covers cases where the byte
# sequence is too varied for a single YAML constraint.
_BYTE_NEEDLES: dict[str, list[bytes]] = {
    "modbus_tcp": [
        b"libmodbus",
        b"modbus_tcp_listen",
        b"modbus.so",
        b"mbap_header",
    ],
    "dnp3": [
        b"dnp3-bin",
        b"dnp3_outstation",
        b"opendnp3",
        b"libdnp3",
    ],
    "s7comm": [
        b"libs7comm",
        b"s7_open_connection",
        b"snap7",
        b"libsnap7",
    ],
}


class StringScannerPlugin:
    """Stateless string-scanning matcher. Closure carries no session
    state — confirmed by the register_matcher closure-capture gate.
    """

    # IcsProtocolMatcherProto contract — accessed by namespace-collision
    # check + cost-class ranking.
    cost_class: int = 3  # expensive — substring scan over head window
    protocol_families: frozenset[str] = frozenset(_BYTE_NEEDLES.keys())

    def detect(
        self,
        blob_head: bytes,
        path: str,
        size: int,
        context: IcsResolverContext | None,
    ) -> list[dict] | None:
        """Return a list of ``{protocol_family, evidence}`` dicts or None.

        Stateless: reads only its arguments + the module-level
        ``_BYTE_NEEDLES`` constant.
        """
        hits: list[dict] = []
        for protocol_family, needles in _BYTE_NEEDLES.items():
            for needle in needles:
                if needle in blob_head:
                    hits.append({
                        "protocol_family": protocol_family,
                        "evidence": (
                            f"byte-needle {needle.decode('latin-1')!r} "
                            f"in head"
                        ),
                    })
                    break  # one needle hit per family is enough
        return hits or None


__all__ = ["StringScannerPlugin"]
