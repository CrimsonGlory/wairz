"""End-to-end integration test for the Modbus/TCP v0 YAML.

Session 1 Commit 3 — proves the schema + catalog + resolver + YAML loader
chain works together against the real `data/ics_protocols/_system/modbus_tcp.yaml`
shipped in this commit. This is the Rule #35b live canary form — not a
mock test; the catalog reads the actual on-disk YAML and resolves a
synthesized binary blob.

Companion to `test_ics_protocol_schema.py` (unit-level schema validation)
and `test_ics_protocol_catalog.py` (catalog + resolver against tmp-path
YAMLs). This file validates the IN-TREE production YAML directly.
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
    """Catalog rooted at the IN-TREE _system YAMLs (not tmp_path)."""
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


def test_production_catalog_loads_modbus_tcp_v0(production_catalog):
    """The shipped _system/modbus_tcp.yaml loads cleanly with no warnings."""
    snap = production_catalog.get_snapshot()
    assert len(snap) >= 1
    m = snap.get("modbus_tcp_v0_system")
    assert m is not None
    assert m.manifest_source == "_system"
    assert m.output.protocol_family == "modbus_tcp"
    assert m.output.layer == "application"
    assert m.output.transport == "tcp"
    assert m.detection.combine == "all_required"
    assert m.detection.certainty == "stack_present"
    # 3 signals: string_in_binary + port_signature + function_code_set
    kinds = [s.kind for s in m.detection.signals]
    assert "string_in_binary" in kinds
    assert "port_signature" in kinds
    assert "function_code_set" in kinds
    assert production_catalog.last_warning is None


def test_modbus_resolves_all_three_signals_fire(production_catalog):
    """Blob with Modbus banner + port 502 LE constant + FCs 0x01/0x03/0x05/0x06
    in a 512-byte window → matches the manifest with all 3 signals fired."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:106] = b"Modbus"
    blob[200:202] = struct.pack("<H", 502)
    blob[800:804] = bytes([0x01, 0x03, 0x05, 0x06])
    matches = resolve_all(bytes(blob), "/tmp/test.bin", 4096, snap)
    modbus_matches = [m for m in matches if m.protocol_family == "modbus_tcp"]
    assert len(modbus_matches) == 1
    m = modbus_matches[0]
    assert m.confidence == "high"
    assert m.certainty == "stack_present"
    assert set(m.matched_signals) == {
        "string_in_binary", "port_signature", "function_code_set",
    }


def test_modbus_rejects_banner_only_combine_all_required(production_catalog):
    """combine=all_required — single-signal hit (banner only) does NOT fire.
    W2-β §SC5-NEW-ICS-2 mitigation: combine forces co-occurrence."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:106] = b"Modbus"  # only banner
    matches = resolve_all(bytes(blob), "/tmp/t2.bin", 4096, snap)
    modbus_matches = [m for m in matches if m.protocol_family == "modbus_tcp"]
    assert len(modbus_matches) == 0


def test_modbus_rejects_port_only(production_catalog):
    """Port-only (no banner / no function codes) — rejected by combine."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[200:202] = struct.pack("<H", 502)
    matches = resolve_all(bytes(blob), "/tmp/t3.bin", 4096, snap)
    modbus_matches = [m for m in matches if m.protocol_family == "modbus_tcp"]
    assert len(modbus_matches) == 0


def test_modbus_rejects_function_codes_only(production_catalog):
    """Function codes alone (no banner / no port) — rejected by combine."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[800:806] = bytes([0x01, 0x03, 0x05, 0x06, 0x0F, 0x10])
    matches = resolve_all(bytes(blob), "/tmp/t4.bin", 4096, snap)
    modbus_matches = [m for m in matches if m.protocol_family == "modbus_tcp"]
    assert len(modbus_matches) == 0


def test_modbus_resolves_uppercase_banner_case_insensitive(production_catalog):
    """case_sensitive=False — 'MODBUS' in binary matches 'Modbus' needle."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:106] = b"MODBUS"
    blob[200:202] = struct.pack("<H", 502)
    blob[800:804] = bytes([0x01, 0x03, 0x05, 0x06])
    matches = resolve_all(bytes(blob), "/tmp/t5.bin", 4096, snap)
    modbus_matches = [m for m in matches if m.protocol_family == "modbus_tcp"]
    assert len(modbus_matches) == 1


def test_modbus_resolves_libmodbus_alternative_banner(production_catalog):
    """Alternative needle — 'libmodbus' (static-linked variant) also matches."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:109] = b"libmodbus"
    blob[200:202] = struct.pack("<H", 502)
    blob[800:804] = bytes([0x01, 0x03, 0x05, 0x06])
    matches = resolve_all(bytes(blob), "/tmp/t6.bin", 4096, snap)
    modbus_matches = [m for m in matches if m.protocol_family == "modbus_tcp"]
    assert len(modbus_matches) == 1


def test_modbus_resolves_mbap_alternative_banner(production_catalog):
    """Alternative needle — 'MBAP' (Modbus Application Protocol header)."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:104] = b"MBAP"
    blob[200:202] = struct.pack("<H", 502)
    blob[800:804] = bytes([0x01, 0x03, 0x05, 0x06])
    matches = resolve_all(bytes(blob), "/tmp/t7.bin", 4096, snap)
    modbus_matches = [m for m in matches if m.protocol_family == "modbus_tcp"]
    assert len(modbus_matches) == 1


def test_modbus_function_codes_must_appear_in_close_window(production_catalog):
    """FCs separated by > 512 bytes — function_code_set evaluator's
    window_bytes=512 floor means scattered FCs do NOT match."""
    snap = production_catalog.get_snapshot()
    blob = bytearray(4096)
    blob[100:106] = b"Modbus"
    blob[200:202] = struct.pack("<H", 502)
    # FCs scattered far apart — should fail window check (window_bytes=512)
    blob[300] = 0x01
    blob[900] = 0x03
    blob[1500] = 0x05
    blob[2100] = 0x06
    matches = resolve_all(bytes(blob), "/tmp/t8.bin", 4096, snap)
    modbus_matches = [m for m in matches if m.protocol_family == "modbus_tcp"]
    assert len(modbus_matches) == 0  # FCs too scattered


def test_production_catalog_snapshot_id_deterministic(production_catalog):
    """Catalog snapshot_id is deterministic on the YAML's canonical content."""
    snap_1 = production_catalog.get_snapshot()
    production_catalog.reload()
    snap_2 = production_catalog.get_snapshot()
    assert snap_1.snapshot_id == snap_2.snapshot_id


def test_production_catalog_no_validator_warnings(production_catalog):
    """The in-tree _system/modbus_tcp.yaml passes all catalog-load validators
    (path tier match, manifest-id unique, no I4 collision, no warnings)."""
    production_catalog.reload()
    snap = production_catalog.get_snapshot()
    assert len(snap) >= 1
    assert production_catalog.last_warning is None
