"""Unit tests for the QCA codename YAML loader (Reviewer C H1 2026-05-17).

Validates the externalization of the QCA codename → chipset map +
BrakTooth-DoS chipset scope + MediaTek known-chip allowlist into
``data/bt_qca_codenames.yaml`` (postmortem-bt-banner-parser-session-
2026-05-16.md recommendation #1):

* Shipped YAML loads cleanly into all six accessors.
* Tmp YAML with novel codenames surfaces through the accessors — the
  parser will pick them up the next time ``get_qca_codename_map()`` is
  invoked, validating that operators can add QCA codenames without
  Python changes.
* Missing YAML file → ``_BT_CODENAME_DEFAULTS`` fallback (Rule #34).
* Malformed YAML structure (codenames not a list, list of non-mappings,
  missing required keys) → defaults fallback (loud-on-bad-structure).
* YAML syntax error (unparseable) → defaults fallback (already-logged
  warning chain via ``_safe_load``).
* Parser-side live-canary: monkeypatched YAML with a fake codename is
  consumed correctly by the BT firmware banner parser.

Each test resets the lru_cache via ``_load_bt_qca_codenames.cache_clear``
so a stale load from a sibling test cannot bleed across.
"""

from __future__ import annotations

import struct
import textwrap
from pathlib import Path

import pytest

from app.services.hardware_firmware import patterns_loader as PL
from app.services.hardware_firmware.parsers import get_parser


@pytest.fixture(autouse=True)
def _reset_codename_cache():
    """Ensure the @lru_cache is empty before AND after each test."""
    PL._load_bt_qca_codenames.cache_clear()
    yield
    PL._load_bt_qca_codenames.cache_clear()


# ---------------------------------------------------------------------------
# Shipped YAML — sanity that the in-tree file loads with the expected shape.
# ---------------------------------------------------------------------------


def test_shipped_yaml_codename_map() -> None:
    cn = PL.get_qca_codename_map()
    assert cn["CMC"] == "wcn3950"
    assert cn["CHE"] == "wcn3990"
    assert cn["APA"] == "wcn3988"
    assert cn["HAS"] == "qca6390"
    assert cn["MOS"] == "wcn6750"
    assert set(cn.keys()) == {"CMC", "CHE", "APA", "HAS", "MOS"}


def test_shipped_yaml_codename_display() -> None:
    disp = PL.get_qca_codename_display()
    assert disp["CMC"] == "Comanche"
    assert disp["CHE"] == "Cherokee"
    assert disp["APA"] == "Apache"
    assert disp["HAS"] == "Hastings"
    assert disp["MOS"] == "Moselle"


def test_shipped_yaml_also_covers_cherokee() -> None:
    """CHE/Cherokee codename covers WCN3990 (primary) + WCN3991 + WCN3998."""
    also = PL.get_qca_also_covers()
    assert "CHE" in also
    assert also["CHE"] == frozenset({"wcn3991", "wcn3998"})
    # Codenames without also_covers should NOT appear in the dict (sparse).
    assert "CMC" not in also
    assert "MOS" not in also


def test_shipped_yaml_codename_families() -> None:
    fams = PL.get_qca_codename_families()
    assert fams["CMC"] == ("Rome",)
    assert fams["CHE"] == ("Rome",)
    assert fams["APA"] == ("Rome",)
    assert fams["HAS"] == ("FastConnect",)
    assert fams["MOS"] == ("FastConnect",)


def test_shipped_yaml_braktooth_chipsets() -> None:
    bt = PL.get_braktooth_chipsets()
    assert bt == frozenset({"wcn3950", "wcn3990", "wcn3991", "wcn3998"})


def test_shipped_yaml_mtk_chips_are_bytes() -> None:
    chips = PL.get_mtk_chips()
    # All entries must be `bytes` (encoded once at load time for cheap
    # byte-wise `in firmware_bytes` membership tests downstream).
    assert all(isinstance(c, bytes) for c in chips)
    # Spot-check the high-leverage entries the BT parser uses for the
    # MediaTek BT detection fast path.
    assert b"MT7961" in chips
    assert b"MT7921" in chips
    assert b"MT7663" in chips
    assert b"MT6620" in chips
    # Count should match the in-tree default (sanity that YAML stayed in sync).
    assert len(chips) == 18


def test_lru_cache_is_active() -> None:
    """Two calls return the same instance — proves @lru_cache cache hit."""
    a = PL._load_bt_qca_codenames()
    b = PL._load_bt_qca_codenames()
    assert a is b


# ---------------------------------------------------------------------------
# Operator-extension semantics — tmp YAML with novel codenames.
# ---------------------------------------------------------------------------


def test_extending_yaml_adds_new_codename(tmp_path: Path, monkeypatch) -> None:
    """An operator adding a new QCA codename to the YAML surfaces through
    every accessor — NO Python change required.

    Authoritative-when-present semantics: only what's in the YAML is
    returned. Defaults DO NOT bleed through for codenames the YAML
    omits (operators are expected to copy the shipping YAML wholesale
    and add to it, just like firmware_patterns.yaml).
    """
    yaml_content = textwrap.dedent("""\
        codenames:
          - codename: HEN
            chipset: qca6490
            display: Hennessy
            families: [FastConnect]
          - codename: CHE
            chipset: wcn3990
            display: Cherokee
            families: [Rome]
            also_covers: [wcn3991, wcn3998]
        braktooth_chipsets:
          - wcn3990
          - wcn3991
          - wcn3998
        mtk_known_chips:
          - MT9999
    """)
    yaml_path = tmp_path / "bt_qca_codenames.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", yaml_path)
    PL._load_bt_qca_codenames.cache_clear()

    cn = PL.get_qca_codename_map()
    # New codename surfaces.
    assert cn["HEN"] == "qca6490"
    assert cn["CHE"] == "wcn3990"
    # Codenames not in this tmp YAML are NOT present (authoritative-when-present).
    assert "CMC" not in cn
    assert "APA" not in cn
    assert "HAS" not in cn
    assert "MOS" not in cn

    fams = PL.get_qca_codename_families()
    assert fams["HEN"] == ("FastConnect",)
    assert fams["CHE"] == ("Rome",)

    also = PL.get_qca_also_covers()
    assert also["CHE"] == frozenset({"wcn3991", "wcn3998"})
    # HEN has no also_covers → sparse.
    assert "HEN" not in also

    bt = PL.get_braktooth_chipsets()
    assert bt == frozenset({"wcn3990", "wcn3991", "wcn3998"})

    mtk = PL.get_mtk_chips()
    assert mtk == (b"MT9999",)


def test_extending_yaml_with_only_codenames_section(tmp_path: Path, monkeypatch) -> None:
    """A YAML omitting braktooth/mtk sections is still well-formed —
    those fields fall back to empty (NOT to defaults; operator opt-in)."""
    yaml_content = textwrap.dedent("""\
        codenames:
          - codename: ZZZ
            chipset: fakechipset
    """)
    yaml_path = tmp_path / "bt_qca_codenames.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", yaml_path)
    PL._load_bt_qca_codenames.cache_clear()

    cn = PL.get_qca_codename_map()
    assert cn == {"ZZZ": "fakechipset"}
    # braktooth + mtk sections were absent in the YAML → empty defaults.
    assert PL.get_braktooth_chipsets() == frozenset()
    assert PL.get_mtk_chips() == ()
    # display/also_covers/families sparse — codename had none of those fields.
    assert PL.get_qca_codename_display() == {}
    assert PL.get_qca_also_covers() == {}
    assert PL.get_qca_codename_families() == {}


# ---------------------------------------------------------------------------
# Graceful-degrade fallback (Rule #34) — missing / malformed YAML.
# ---------------------------------------------------------------------------


def test_missing_yaml_falls_back_to_defaults(tmp_path: Path, monkeypatch) -> None:
    """Missing file → in-tree _BT_CODENAME_DEFAULTS."""
    nonexistent = tmp_path / "does_not_exist.yaml"
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", nonexistent)
    PL._load_bt_qca_codenames.cache_clear()

    cn = PL.get_qca_codename_map()
    # All 5 in-tree default codenames should be present.
    assert cn["CMC"] == "wcn3950"
    assert cn["CHE"] == "wcn3990"
    assert cn["APA"] == "wcn3988"
    assert cn["HAS"] == "qca6390"
    assert cn["MOS"] == "wcn6750"
    # Display + braktooth + mtk also fall back to in-tree defaults.
    assert PL.get_qca_codename_display()["CMC"] == "Comanche"
    assert PL.get_braktooth_chipsets() == frozenset(
        {"wcn3950", "wcn3990", "wcn3991", "wcn3998"}
    )
    assert b"MT7961" in PL.get_mtk_chips()


def test_malformed_yaml_structure_codenames_not_list(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    """codenames must be a list — string here → defaults."""
    yaml_path = tmp_path / "bt_qca_codenames.yaml"
    yaml_path.write_text("codenames: not-a-list\n")
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", yaml_path)
    PL._load_bt_qca_codenames.cache_clear()

    with caplog.at_level("WARNING", logger="app.services.hardware_firmware.patterns_loader"):
        cn = PL.get_qca_codename_map()

    # Defaults fired.
    assert cn["CMC"] == "wcn3950"
    # And we logged the structural-validation failure.
    assert any("structural validation failed" in r.message for r in caplog.records)


def test_malformed_yaml_codename_entry_missing_chipset(
    tmp_path: Path, monkeypatch
) -> None:
    """codenames[i] must carry both 'codename' and 'chipset' keys."""
    yaml_content = textwrap.dedent("""\
        codenames:
          - codename: BROKEN
            # missing chipset key
    """)
    yaml_path = tmp_path / "bt_qca_codenames.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", yaml_path)
    PL._load_bt_qca_codenames.cache_clear()

    cn = PL.get_qca_codename_map()
    # Structural failure → defaults.
    assert cn["CMC"] == "wcn3950"


def test_malformed_yaml_codename_entry_is_string(
    tmp_path: Path, monkeypatch
) -> None:
    """codenames[i] must be a mapping — list of strings → defaults."""
    yaml_content = textwrap.dedent("""\
        codenames:
          - just-a-string
    """)
    yaml_path = tmp_path / "bt_qca_codenames.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", yaml_path)
    PL._load_bt_qca_codenames.cache_clear()

    cn = PL.get_qca_codename_map()
    assert cn["CMC"] == "wcn3950"


def test_malformed_yaml_braktooth_chipsets_wrong_type(
    tmp_path: Path, monkeypatch
) -> None:
    """braktooth_chipsets must be a list when present — string → defaults."""
    yaml_content = textwrap.dedent("""\
        codenames:
          - codename: OK
            chipset: ok_chip
        braktooth_chipsets: "not a list"
    """)
    yaml_path = tmp_path / "bt_qca_codenames.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", yaml_path)
    PL._load_bt_qca_codenames.cache_clear()

    # Structural failure → ALL defaults fire (not just braktooth).
    cn = PL.get_qca_codename_map()
    assert cn["CMC"] == "wcn3950"
    assert "OK" not in cn  # The YAML's good half is discarded too — atomic fallback.


def test_yaml_syntax_error_falls_back_to_defaults(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    """Outright unparseable YAML → _safe_load returns {} → defaults."""
    yaml_path = tmp_path / "bt_qca_codenames.yaml"
    # Broken YAML: tab in a place yaml.safe_load rejects.
    yaml_path.write_text("codenames:\n\t- broken: indent\n")
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", yaml_path)
    PL._load_bt_qca_codenames.cache_clear()

    with caplog.at_level("WARNING", logger="app.services.hardware_firmware.patterns_loader"):
        cn = PL.get_qca_codename_map()

    assert cn["CMC"] == "wcn3950"
    # _safe_load logged the parse failure (the message says "failed to parse").
    assert any("failed to parse" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Parser-side integration — monkeypatched YAML wires through the parser.
# ---------------------------------------------------------------------------


def _make_qca_tlv(banner: str, *, with_patch_release: str | None = None) -> bytes:
    """Synthesize a QCA Rome TLV-shaped fixture with the given banner."""
    header = bytearray(28)
    payload = bytearray()
    if with_patch_release:
        payload += with_patch_release.encode("ascii") + b"\x00"
    payload += banner.encode("ascii") + b"\x00"
    payload += b"\x00" * 64
    total_len = len(header) + len(payload)
    type_len = (total_len << 8) | 0x01
    struct.pack_into("<I", header, 0, type_len)
    return bytes(header) + bytes(payload)


def test_parser_consumes_new_codename_via_yaml(
    tmp_path: Path, monkeypatch
) -> None:
    """End-to-end: a new ZZZ codename added via YAML produces the right
    chipset_target in ParsedBlob.metadata WITHOUT touching parser code."""
    yaml_content = textwrap.dedent("""\
        codenames:
          - codename: ZZZ
            chipset: future_chip_42
            display: ZuluZuluZulu
            families: [Future]
        braktooth_chipsets: []
        mtk_known_chips:
          - MT7961
          - MT7921
    """)
    yaml_path = tmp_path / "bt_qca_codenames.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", yaml_path)
    PL._load_bt_qca_codenames.cache_clear()

    # Synthetic banner with the future codename.
    banner = "BTFM.ZZZ.1.0.0-99999-QCACHROM-1"
    fixture = _make_qca_tlv(banner)
    fpath = tmp_path / "zzzbtfw01.tlv"
    fpath.write_bytes(fixture)

    parser = get_parser("bt_fw_banner")
    assert parser is not None
    result = parser.parse(str(fpath), fixture[:64], len(fixture))

    assert result.vendor == "qualcomm"
    assert result.version == banner
    assert result.chipset_target == "future_chip_42"  # ← from YAML
    fb = result.metadata["bt_fw_banner"]
    assert fb["family"] == "qca_rome"
    assert fb["codename"] == "ZZZ"
    assert fb["codename_display"] == "ZuluZuluZulu"
    assert fb["chipset_source"] == "codename_map"


def test_parser_skips_braktooth_pin_when_chipset_excluded_via_yaml(
    tmp_path: Path, monkeypatch
) -> None:
    """When the operator removes a chipset from braktooth_chipsets in YAML,
    the parser no longer pins the BrakTooth DoS cluster on that chipset.

    Live demonstration that the safety scope is operator-configurable —
    crucial for the BrakTooth-RCE-on-ESP32 fault class (operators who
    discover a new disclosure-batch CPE mismatch fix the YAML and the
    Tier 0 pin stops firing on rebuild)."""
    yaml_content = textwrap.dedent("""\
        codenames:
          - codename: CMC
            chipset: wcn3950
            display: Comanche
            families: [Rome]
        braktooth_chipsets: []   # explicitly empty — no Tier 0 pins
        mtk_known_chips: []
    """)
    yaml_path = tmp_path / "bt_qca_codenames.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", yaml_path)
    PL._load_bt_qca_codenames.cache_clear()

    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    fixture = _make_qca_tlv(banner)
    fpath = tmp_path / "cmbtfw13.tlv"
    fpath.write_bytes(fixture)

    parser = get_parser("bt_fw_banner")
    assert parser is not None
    result = parser.parse(str(fpath), fixture[:64], len(fixture))

    # Vendor + version still pinned by content.
    assert result.vendor == "qualcomm"
    assert result.chipset_target == "wcn3950"
    # But no Tier 0 BRAKTOOTH pin because the YAML scope was empty.
    assert "known_vulnerabilities" not in result.metadata
