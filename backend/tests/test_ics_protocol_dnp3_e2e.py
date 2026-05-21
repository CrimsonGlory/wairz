"""End-to-end integration test for the Phase 5 DNP3 v0 YAML.

Session 2 Phase 5.A — proves the schema + catalog + resolver + YAML
loader chain works against the real ``data/ics_protocols/_system/dnp3.yaml``
shipped in this commit. Rule #35b live canary form against the IN-TREE
production YAML.

Cross-protocol matrix tests live in
``test_ics_protocol_dnp3_s7comm_e2e.py`` (Commit 5.B; ships with
s7comm.yaml so both YAMLs are present for the matrix checks).
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.services.ics_protocol_catalog import (
    IcsProtocolCatalog,
    resolve_all,
)


@pytest.fixture
def production_catalog() -> IcsProtocolCatalog:
    data_root = (
        Path(__file__).resolve().parents[1]
        / "app" / "services" / "ics_protocol_catalog"
        / "data" / "ics_protocols"
    )
    overlay_root = (
        Path(__file__).resolve().parents[1]
        / "app" / "services" / "ics_protocol_catalog"
        / "data" / "ics_protocols.local"
    )
    return IcsProtocolCatalog(
        data_root=data_root, overlay_root=overlay_root,
    )


def test_production_catalog_loads_dnp3_v0(production_catalog):
    """The shipped _system/dnp3.yaml loads cleanly."""
    snap = production_catalog.get_snapshot()
    m = snap.get("dnp3_v0_system")
    assert m is not None
    assert m.manifest_source == "_system"
    assert m.output.protocol_family == "dnp3"
    assert m.output.layer == "application"
    assert m.output.transport == "tcp"
    assert m.detection.combine == "all_required"
    kinds = [s.kind for s in m.detection.signals]
    assert set(kinds) == {
        "string_in_binary", "port_signature", "function_code_set",
    }
    assert production_catalog.last_warning is None


def test_dnp3_resolves_all_three_signals_fire(production_catalog):
    """Blob with DNP3 banner ('opendnp3') + port 20000 LE constant +
    FCs 0x01/0x02/0x03/0x04 in 512-byte window → matches."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:108] = b"opendnp3"
    blob[200:202] = struct.pack("<H", 20000)
    blob[800:804] = bytes([0x01, 0x02, 0x03, 0x04])
    matches = resolve_all(bytes(blob), "/tmp/dnp3-test.bin", 4096, snap)
    dnp3 = [m for m in matches if m.protocol_family == "dnp3"]
    assert len(dnp3) == 1
    m = dnp3[0]
    assert m.confidence == "high"
    assert set(m.matched_signals) == {
        "string_in_binary", "port_signature", "function_code_set",
    }


def test_dnp3_rejects_banner_only_combine_all_required(production_catalog):
    """W2-β §SC5-NEW-ICS-2 — banner-only does NOT fire (combine forces
    co-occurrence)."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:108] = b"opendnp3"
    matches = resolve_all(bytes(blob), "/tmp/t.bin", 4096, snap)
    dnp3 = [m for m in matches if m.protocol_family == "dnp3"]
    assert len(dnp3) == 0


def test_dnp3_rejects_port_only(production_catalog):
    """Port-only — rejected by combine."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[200:202] = struct.pack("<H", 20000)
    matches = resolve_all(bytes(blob), "/tmp/t.bin", 4096, snap)
    dnp3 = [m for m in matches if m.protocol_family == "dnp3"]
    assert len(dnp3) == 0


def test_dnp3_rejects_function_codes_only(production_catalog):
    """Function codes alone — rejected by combine."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[800:808] = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0d, 0x82])
    matches = resolve_all(bytes(blob), "/tmp/t.bin", 4096, snap)
    dnp3 = [m for m in matches if m.protocol_family == "dnp3"]
    assert len(dnp3) == 0
