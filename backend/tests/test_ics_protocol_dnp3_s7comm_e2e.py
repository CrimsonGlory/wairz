"""End-to-end integration test for the Phase 5 S7Comm v0 YAML +
cross-protocol disjointness matrix.

Session 2 Phase 5.B — proves the shipped
``data/ics_protocols/_system/s7comm.yaml`` works AND that the 3-protocol
production set (modbus_tcp + dnp3 + s7comm) is mutually disjoint under
the ``combine: all_required`` discipline. Cross-protocol false-positive
matrix tests require BOTH dnp3 + s7comm YAMLs present — this file ships
in Commit 5.B AFTER Commit 5.A landed the dnp3 YAML.
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


# ───────────────────────────────────────────────────────────────────────
# S7Comm v0 — load + happy path + combine rejections.
# ───────────────────────────────────────────────────────────────────────


def test_production_catalog_loads_s7comm_v0(production_catalog):
    """The shipped _system/s7comm.yaml loads cleanly."""
    snap = production_catalog.get_snapshot()
    m = snap.get("s7comm_v0_system")
    assert m is not None
    assert m.manifest_source == "_system"
    assert m.output.protocol_family == "s7comm"
    assert m.output.vendor == "siemens"
    assert m.output.vendor_product == "simatic_s7"
    assert m.detection.combine == "all_required"
    assert production_catalog.last_warning is None


def test_s7comm_resolves_all_three_signals_fire(production_catalog):
    """Blob with snap7 banner + port 102 LE constant + S7 FCs in
    a 512-byte window → matches."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:105] = b"snap7"
    blob[200:202] = struct.pack("<H", 102)
    blob[800:804] = bytes([0x04, 0x05, 0x1a, 0xf0])
    matches = resolve_all(bytes(blob), "/tmp/s7-test.bin", 4096, snap)
    s7 = [m for m in matches if m.protocol_family == "s7comm"]
    assert len(s7) == 1
    m = s7[0]
    assert m.confidence == "high"
    assert m.vendor == "siemens"


def test_s7comm_rejects_port_only_no_iso_tsap_false_positive(production_catalog):
    """W2-β §SC5-NEW-ICS-2 — port 102 alone (other ISO-TSAP services)
    does NOT fire S7Comm. Banner + FCs required."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[200:202] = struct.pack("<H", 102)
    matches = resolve_all(bytes(blob), "/tmp/t.bin", 4096, snap)
    s7 = [m for m in matches if m.protocol_family == "s7comm"]
    assert len(s7) == 0


# ───────────────────────────────────────────────────────────────────────
# Cross-protocol disjointness matrix (W2-α DNP3+S7Comm pre-spec).
# ───────────────────────────────────────────────────────────────────────


def test_modbus_blob_does_not_cross_match_dnp3_or_s7comm(production_catalog):
    """A Modbus-shaped blob MUST NOT cross-match dnp3 or s7comm. Both
    Modbus + DNP3 use FCs 0x01-0x06 but the port + banner co-requirement
    under combine=all_required disambiguates."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:106] = b"Modbus"
    blob[200:202] = struct.pack("<H", 502)
    blob[800:806] = bytes([0x01, 0x03, 0x05, 0x06, 0x0f, 0x10])
    matches = resolve_all(bytes(blob), "/tmp/modbus.bin", 4096, snap)
    families = {m.protocol_family for m in matches}
    assert "modbus_tcp" in families
    assert "dnp3" not in families, (
        f"Cross-protocol disjointness BROKEN — Modbus blob matched dnp3"
    )
    assert "s7comm" not in families


def test_dnp3_blob_does_not_cross_match_modbus_or_s7comm(production_catalog):
    """A DNP3-shaped blob MUST NOT cross-match modbus_tcp or s7comm."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:108] = b"opendnp3"
    blob[200:202] = struct.pack("<H", 20000)
    blob[800:804] = bytes([0x01, 0x02, 0x03, 0x04])
    matches = resolve_all(bytes(blob), "/tmp/dnp3.bin", 4096, snap)
    families = {m.protocol_family for m in matches}
    assert "dnp3" in families
    assert "modbus_tcp" not in families
    assert "s7comm" not in families


def test_s7comm_blob_does_not_cross_match_modbus_or_dnp3(production_catalog):
    """An S7Comm-shaped blob MUST NOT cross-match modbus_tcp or dnp3."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:105] = b"snap7"
    blob[200:202] = struct.pack("<H", 102)
    blob[800:804] = bytes([0x04, 0x05, 0x1a, 0xf0])
    matches = resolve_all(bytes(blob), "/tmp/s7.bin", 4096, snap)
    families = {m.protocol_family for m in matches}
    assert "s7comm" in families
    assert "modbus_tcp" not in families
    assert "dnp3" not in families


def test_multi_protocol_firmware_matches_all_three(production_catalog):
    """A binary containing all 3 protocols' signatures (multi-vendor HMI
    gateway) MUST match all 3 families. Validates the multi-protocol
    cardinality contract — ``resolve_all()`` returns
    ``list[IcsProtocolMatch]`` per Session 1 postmortem Pattern #6."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(8192)
    # Modbus block
    blob[100:106] = b"Modbus"
    blob[200:202] = struct.pack("<H", 502)
    blob[300:306] = bytes([0x01, 0x03, 0x05, 0x06, 0x0f, 0x10])
    # DNP3 block
    blob[2000:2008] = b"opendnp3"
    blob[2100:2102] = struct.pack("<H", 20000)
    blob[2200:2204] = bytes([0x01, 0x02, 0x03, 0x04])
    # S7Comm block
    blob[4000:4005] = b"snap7"
    blob[4100:4102] = struct.pack("<H", 102)
    blob[4200:4204] = bytes([0x04, 0x05, 0x1a, 0xf0])
    matches = resolve_all(bytes(blob), "/tmp/multi.bin", 8192, snap)
    families = {m.protocol_family for m in matches}
    assert "modbus_tcp" in families
    assert "dnp3" in families
    assert "s7comm" in families
