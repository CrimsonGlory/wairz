"""Unit tests for the banner-pin → CVE YAML loader + engine (Reviewer C
H2 2026-05-17 + Reviewer B fixup 2026-05-17).

Validates the externalization of the BT firmware banner-pin → CVE rules
into ``data/bt_banner_cve_pins.yaml`` + the in-parser rule engine:

* Shipped YAML loads cleanly — the regression BRAKTOOTH Tier 0 pin is
  present with the single NVD-CPE-confirmed Qualcomm-CNA BrakTooth-DoS
  CVE (CVE-2021-30348) and the four non-Qualcomm-CNA disclosure-batch
  CVEs (CVE-2021-28139 ESP32, -34147 Cypress, -31609 Silicon Labs,
  -31612 Zhuhai Jieli) are EXPLICITLY NOT in any qca_rome family pin
  (Reviewer B 2026-05-16 + 2026-05-17 invariant).
* Each match condition gates correctly: family, codename_in,
  chipset_target_in, banner_match (regex), build_date_before,
  build_id_lt. Failing gates short-circuit.
* Operator-extension: a tmp YAML adds a novel pin with custom rationale
  templating and the parser fires it end-to-end.
* Multiple pins on the same record produce concatenated findings.
* Missing/malformed YAML → in-tree _BANNER_CVE_PIN_DEFAULTS (still emits
  the BRAKTOOTH cluster — detection survives YAML loss).
* Rationale templating handles missing placeholders gracefully (logs +
  emits raw template; never crashes).
* CVE-2021-28139 SHALL NOT regress into any qca_rome pin (Reviewer B
  invariant; canary test that would catch a future YAML edit).

Each test resets the @lru_cache via ``_load_banner_cve_pins.cache_clear``.
"""

from __future__ import annotations

import struct
import textwrap
from datetime import date
from pathlib import Path

import pytest

from app.services.hardware_firmware import patterns_loader as PL
from app.services.hardware_firmware.parsers import get_parser
from app.services.hardware_firmware.parsers.bt_firmware_banner import (
    _coerce_build_id,
    _emit_pins,
    _parse_build_date,
    _pin_from_yaml_rules,
    _pin_matches,
)


@pytest.fixture(autouse=True)
def _reset_pin_cache():
    """Clear both H1 and H2 lru_caches around every test."""
    PL._load_banner_cve_pins.cache_clear()
    PL._load_bt_qca_codenames.cache_clear()
    yield
    PL._load_banner_cve_pins.cache_clear()
    PL._load_bt_qca_codenames.cache_clear()


def _make_pin(**overrides) -> PL.BannerCvePin:
    """Test factory: construct a BannerCvePin with all match conditions
    defaulting to None, override any subset for the test under exam.

    Adding a new match condition to the dataclass only requires updating
    this factory's defaults — individual tests stay simple.
    """
    defaults: dict[str, object] = {
        "pin_id": "t",
        "description": "t",
        "family": None,
        "codename_in": None,
        "chipset_target_in": None,
        "banner_re": None,
        "build_date_before": None,
        "build_id_lt": None,
        "signed_eq": None,
        "cves": (),
    }
    defaults.update(overrides)
    return PL.BannerCvePin(**defaults)


# ---------------------------------------------------------------------------
# Shipped YAML — regression coverage for the BRAKTOOTH Tier 0 pin.
# ---------------------------------------------------------------------------


def test_shipped_yaml_loads_with_braktooth_pin() -> None:
    pins = PL.get_banner_cve_pins()
    assert len(pins) >= 1
    bt = pins[0]
    assert bt.pin_id == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"
    assert bt.family == "qca_rome"
    assert bt.chipset_target_in == frozenset(
        {"wcn3950", "wcn3990", "wcn3991", "wcn3998"}
    )
    cve_ids = {c.cve_id for c in bt.cves}
    # Single NVD-CPE-confirmed Qualcomm-CNA BrakTooth CVE per Reviewer B
    # 2026-05-17. The other 3 batch CVEs (34147/31609/31612) and the ESP32
    # RCE (28139) are NOT Qualcomm-CNA in NVD and must NOT pin under a
    # qca_rome family pin.
    assert cve_ids == {"CVE-2021-30348"}
    assert all(c.severity == "medium" for c in bt.cves)
    assert all(
        c.reference == "https://nvd.nist.gov/vuln/detail/CVE-2021-30348"
        for c in bt.cves
    )


def test_shipped_yaml_does_not_contain_non_qualcomm_cna_braktooth_cves() -> (
    None
):
    """Reviewer B 2026-05-16 + 2026-05-17 invariant — broader canary.

    The 2026-05-16 version of this test only guarded CVE-2021-28139.
    Reviewer B 2026-05-17 caught CVE-2021-34147 / 31609 / 31612 had
    slipped past that narrow guard — same disclosure-batch antipattern
    shape, but with the 3 DoS CVEs the original parser shipped. The
    broader canary asserts NO non-Qualcomm-CNA BrakTooth-batch CVE
    appears under any qca_rome family pin.

    If a future YAML edit re-introduces any of these CVEs, this test
    fails LOUD with the offending CVE ID + pin_id in the message.
    """
    # CVEs in the ASSET BrakTooth disclosure batch whose NVD CPE lists
    # do NOT contain Qualcomm chipsets — pinning them under qca_rome
    # would replicate the misattribution this campaign was built to
    # prevent. Source: NVD per-CVE CPE lists verified 2026-05-17.
    non_qualcomm_cna_braktooth_cves = {
        "CVE-2021-28139",   # Espressif ESP32 RCE (CVSS 8.8) — caught 2026-05-16
        "CVE-2021-34147",   # Cypress/Infineon WICED + CYW20735B1 — caught 2026-05-17
        "CVE-2021-31609",   # Silicon Labs iWRAP + WT32i-A    — caught 2026-05-17
        "CVE-2021-31612",   # Zhuhai Jieli AC69xx              — caught 2026-05-17
    }
    pins = PL.get_banner_cve_pins()
    for pin in pins:
        if pin.family != "qca_rome":
            continue
        for cve in pin.cves:
            assert cve.cve_id not in non_qualcomm_cna_braktooth_cves, (
                f"Reviewer B invariant violated: qca_rome pin {pin.pin_id!r} "
                f"includes {cve.cve_id} — that CVE is in the BrakTooth "
                "disclosure batch but its NVD CPE list does NOT include "
                "Qualcomm chipsets. The only Qualcomm-CNA BrakTooth CVE "
                "per NVD is CVE-2021-30348."
            )


def test_shipped_yaml_qualcomm_braktooth_cve_30348_present() -> None:
    """Positive-side assertion: CVE-2021-30348 IS pinned on qca_rome.

    Complements the negative canary above. If a future refactor
    accidentally drops the CVE-2021-30348 entry, this canary catches it
    instead of letting BRAKTOOTH detection silently disappear.
    """
    pins = PL.get_banner_cve_pins()
    qca_pins = [p for p in pins if p.family == "qca_rome"]
    assert qca_pins, "no qca_rome family pins present"
    all_qca_cves = {c.cve_id for pin in qca_pins for c in pin.cves}
    assert "CVE-2021-30348" in all_qca_cves, (
        "CVE-2021-30348 (Qualcomm-CNA BrakTooth DoS) missing from qca_rome "
        "pins — Tier 0 BRAKTOOTH detection silently disabled."
    )


def test_lru_cache_is_active() -> None:
    a = PL._load_banner_cve_pins()
    b = PL._load_banner_cve_pins()
    assert a is b


# ---------------------------------------------------------------------------
# Match-condition unit tests against the engine.
# ---------------------------------------------------------------------------


@pytest.fixture
def _basic_qca_record():
    return {
        "family": "qca_rome",
        "vendor": "qualcomm",
        "banner": "BTFM.CMC.1.3.0-00069-QCACHROMZ-1",
        "codename": "CMC",
        "chipset_target": "wcn3950",
        "build_id": "00069",
    }


def test_pin_matches_family_gate(_basic_qca_record) -> None:
    p = PL.BannerCvePin(
        pin_id="t", description="t",
        family="qca_rome",
        codename_in=None, chipset_target_in=None, banner_re=None,
        build_date_before=None, build_id_lt=None, signed_eq=None,
        cves=(),
    )
    assert _pin_matches(p, _basic_qca_record) is True
    p2 = PL.BannerCvePin(
        pin_id="t", description="t",
        family="broadcom_hcd",
        codename_in=None, chipset_target_in=None, banner_re=None,
        build_date_before=None, build_id_lt=None, signed_eq=None,
        cves=(),
    )
    assert _pin_matches(p2, _basic_qca_record) is False


def test_pin_matches_codename_gate(_basic_qca_record) -> None:
    p = PL.BannerCvePin(
        pin_id="t", description="t",
        family=None,
        codename_in=frozenset({"CMC", "CHE"}),
        chipset_target_in=None, banner_re=None,
        build_date_before=None, build_id_lt=None, signed_eq=None,
        cves=(),
    )
    assert _pin_matches(p, _basic_qca_record) is True
    p2 = PL.BannerCvePin(
        pin_id="t", description="t",
        family=None,
        codename_in=frozenset({"APA", "HAS"}),
        chipset_target_in=None, banner_re=None,
        build_date_before=None, build_id_lt=None, signed_eq=None,
        cves=(),
    )
    assert _pin_matches(p2, _basic_qca_record) is False


def test_pin_matches_chipset_gate(_basic_qca_record) -> None:
    assert _pin_matches(
        _make_pin(chipset_target_in=frozenset({"wcn3950"})), _basic_qca_record
    ) is True
    assert _pin_matches(
        _make_pin(chipset_target_in=frozenset({"mt7663"})), _basic_qca_record
    ) is False


def test_pin_matches_banner_regex_gate(_basic_qca_record) -> None:
    import re as _re
    p = PL.BannerCvePin(
        pin_id="t", description="t",
        family=None, codename_in=None, chipset_target_in=None,
        banner_re=_re.compile(r"BTFM\.CMC\.1\."),
        build_date_before=None, build_id_lt=None, signed_eq=None,
        cves=(),
    )
    assert _pin_matches(p, _basic_qca_record) is True
    p2 = PL.BannerCvePin(
        pin_id="t", description="t",
        family=None, codename_in=None, chipset_target_in=None,
        banner_re=_re.compile(r"BTFM\.CHE\."),
        build_date_before=None, build_id_lt=None, signed_eq=None,
        cves=(),
    )
    assert _pin_matches(p2, _basic_qca_record) is False


def test_pin_matches_build_date_before_gate() -> None:
    record = {
        "family": "broadcom_hcd",
        "chipset_target": "bcm4339",
        "banner": "...",
        "build_date": "Jun 12 2017",
    }
    p = _make_pin(build_date_before=date(2017, 9, 12))
    assert _pin_matches(p, record) is True

    # Built AFTER the cutoff — should fail.
    record_after = {**record, "build_date": "Dec 12 2017"}
    assert _pin_matches(p, record_after) is False

    # Unparseable build_date → fail-closed (no pin under uncertainty).
    record_unparse = {**record, "build_date": "not a date"}
    assert _pin_matches(p, record_unparse) is False

    # Missing build_date → fail-closed.
    record_missing = {**record, "build_date": None}
    assert _pin_matches(p, record_missing) is False


def test_pin_matches_build_id_lt_gate(_basic_qca_record) -> None:
    p = _make_pin(build_id_lt=100)
    # build_id "00069" → 69 < 100 → match
    assert _pin_matches(p, _basic_qca_record) is True

    # Dotted CI build "00076.1" → 76 head-only → < 100 → match
    record_dotted = {**_basic_qca_record, "build_id": "00076.1"}
    assert _pin_matches(p, record_dotted) is True

    # build_id "00200" → 200 < 100 false → no match
    record_high = {**_basic_qca_record, "build_id": "00200"}
    assert _pin_matches(p, record_high) is False

    # Non-int build_id → fail closed
    record_nonint = {**_basic_qca_record, "build_id": "alpha"}
    assert _pin_matches(p, record_nonint) is False


def test_pin_matches_logical_and_all_conditions(_basic_qca_record) -> None:
    """All conditions must evaluate true (logical AND)."""
    import re as _re
    p = PL.BannerCvePin(
        pin_id="t", description="t",
        family="qca_rome",
        codename_in=frozenset({"CMC"}),
        chipset_target_in=frozenset({"wcn3950"}),
        banner_re=_re.compile(r"BTFM\.CMC"),
        build_date_before=None,
        build_id_lt=100,
        signed_eq=None,
        cves=(),
    )
    assert _pin_matches(p, _basic_qca_record) is True

    # Flip one condition → false.
    wrong_chipset = {**_basic_qca_record, "chipset_target": "wcn3990"}
    assert _pin_matches(p, wrong_chipset) is False


def test_pin_matches_signed_eq_gate(_basic_qca_record) -> None:
    """signed_eq gate (Reviewer C 2026-05-17): match record['signed']."""
    p_signed = PL.BannerCvePin(
        pin_id="t", description="t",
        family=None, codename_in=None, chipset_target_in=None, banner_re=None,
        build_date_before=None, build_id_lt=None,
        signed_eq="signed",
        cves=(),
    )
    signed_record = {**_basic_qca_record, "signed": "signed"}
    assert _pin_matches(p_signed, signed_record) is True
    unsigned_record = {**_basic_qca_record, "signed": "unsigned"}
    assert _pin_matches(p_signed, unsigned_record) is False
    # Missing signed field — fails closed (no pin under uncertainty).
    record_no_signed = {k: v for k, v in _basic_qca_record.items() if k != "signed"}
    assert _pin_matches(p_signed, record_no_signed) is False

    p_unsigned = PL.BannerCvePin(
        pin_id="t", description="t",
        family=None, codename_in=None, chipset_target_in=None, banner_re=None,
        build_date_before=None, build_id_lt=None,
        signed_eq="unsigned",
        cves=(),
    )
    assert _pin_matches(p_unsigned, unsigned_record) is True
    assert _pin_matches(p_unsigned, signed_record) is False


def test_loader_rejects_signed_eq_invalid_value(tmp_path: Path, monkeypatch) -> None:
    """signed_eq must be 'signed' or 'unsigned' — other strings rejected."""
    yaml_content = textwrap.dedent("""\
        pins:
          - id: bad-signed
            description: invalid signed_eq value
            family: qca_rome
            signed_eq: maybe
            cves:
              - id: CVE-X
                severity: low
                rationale: x
    """)
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()
    pins = PL.get_banner_cve_pins()
    # Falls back to defaults (single CVE-2021-30348 pin).
    assert pins[0].pin_id == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"


def test_loader_rejects_build_id_lt_zero_sentinel(
    tmp_path: Path, monkeypatch
) -> None:
    """Reviewer C 2026-05-17: build_id_lt: 0 with no other gate rejected.

    A pin with only ``build_id_lt: 0`` and no other match condition
    would never fire (every real build_id is >= 0). Loud-on-likely-
    mistake matches the rest of the loader's strict-validation discipline.
    """
    yaml_content = textwrap.dedent("""\
        pins:
          - id: sentinel-zero
            description: build_id_lt 0 with no other gate
            build_id_lt: 0
            cves:
              - id: CVE-X
                severity: low
                rationale: x
    """)
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()
    pins = PL.get_banner_cve_pins()
    # Falls back to defaults — bad pin rejected.
    assert pins[0].pin_id == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"


def test_loader_allows_build_id_lt_zero_with_other_gate(
    tmp_path: Path, monkeypatch
) -> None:
    """build_id_lt: 0 WITH another gate IS allowed (operator may have
    a build_id-0 special-case alongside a chipset_target_in)."""
    yaml_content = textwrap.dedent("""\
        pins:
          - id: zero-build-id-special-case
            description: legitimate build_id=0 + chipset gate
            family: qca_rome
            chipset_target_in: [wcn3950]
            build_id_lt: 1
            cves:
              - id: CVE-X
                severity: low
                rationale: x
    """)
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()
    pins = PL.get_banner_cve_pins()
    assert pins[0].pin_id == "zero-build-id-special-case"
    assert pins[0].build_id_lt == 1


def test_safe_formatter_rejects_attribute_access(tmp_path: Path) -> None:
    """Reviewer A 2026-05-17: rationale templates cannot use {x.attr}.

    Defense-in-depth for the operator-extensible YAML surface. A future
    operator-supplied YAML containing {banner.__class__.__mro__} or
    {chipset[0]} resolves through Python's str.format attribute/item
    access by default; the _SafeRationaleFormatter rejects both forms.
    """
    from app.services.hardware_firmware.parsers.bt_firmware_banner import (
        _format_rationale,
    )

    record = {"banner": "test-banner", "chipset_target": "wcn3950"}

    # Attribute access is rejected; the formatter falls back to the raw template.
    out = _format_rationale(
        "leaked: {banner.__class__.__mro__}", "test-pin", record
    )
    # Raw template emitted unchanged (defense — operator sees the gap).
    assert "{banner.__class__.__mro__}" in out

    # Item access is rejected.
    out2 = _format_rationale("leaked: {banner[0]}", "test-pin", record)
    assert "{banner[0]}" in out2

    # Normal usage still works.
    out3 = _format_rationale(
        "banner is {banner}, chipset is {chipset_upper}", "test-pin", record
    )
    assert out3 == "banner is test-banner, chipset is WCN3950"


# ---------------------------------------------------------------------------
# Operator-extension semantics — tmp YAML with novel pins.
# ---------------------------------------------------------------------------


def test_extending_yaml_adds_new_pin(tmp_path: Path, monkeypatch) -> None:
    """A novel pin added via YAML fires through the parser without Python."""
    yaml_content = textwrap.dedent("""\
        pins:
          - id: mediatek-mt7663-test-pin
            description: Synthetic test pin for MT7663 detection
            family: mediatek_bt
            chipset_target_in: [mt7663]
            cves:
              - id: CVE-2099-99999
                severity: high
                rationale: |
                  MT7663 detection canary — chipset {chipset_upper}
                  banner '{banner}'.
                reference: https://example.invalid/cve-test
    """)
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()

    pins = PL.get_banner_cve_pins()
    assert len(pins) == 1
    p = pins[0]
    assert p.pin_id == "mediatek-mt7663-test-pin"
    assert p.family == "mediatek_bt"
    assert p.chipset_target_in == frozenset({"mt7663"})
    assert len(p.cves) == 1
    assert p.cves[0].cve_id == "CVE-2099-99999"
    assert p.cves[0].severity == "high"
    assert p.cves[0].confidence == "high"  # default


def test_extending_yaml_with_banner_regex_and_date(
    tmp_path: Path, monkeypatch
) -> None:
    """Multi-condition pin loads with regex compiled + date parsed."""
    yaml_content = textwrap.dedent("""\
        pins:
          - id: bcm-blueborne-canary
            description: Synthetic BlueBorne canary
            family: broadcom_hcd
            chipset_target_in: [bcm4339, bcm4358]
            banner_match: "BCM4339.*Jun"
            build_date_before: 2017-09-12
            cves:
              - id: CVE-2017-0781
                severity: critical
                confidence: medium
                rationale: |
                  BlueBorne-class canary for {chipset_upper} built {build_date}
                reference: https://nvd.nist.gov/vuln/detail/CVE-2017-0781
    """)
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()

    pins = PL.get_banner_cve_pins()
    assert len(pins) == 1
    p = pins[0]
    assert p.banner_re is not None
    assert p.banner_re.search("BCM4339 Jun 12 2017 build")
    assert p.build_date_before == date(2017, 9, 12)
    assert p.cves[0].confidence == "medium"


def test_family_only_pin_rejected_per_forensic_invariant(
    tmp_path: Path, monkeypatch
) -> None:
    """F-FORENSIC-10 (Reviewer B 2026-05-18 CRITICAL): a pin with ONLY
    `family:` set (no chipset / codename / banner / version narrowing)
    is the disclosure-batch antipattern that the BTFM/BrakTooth
    incidents shipped. Schema gate MUST reject such pins.

    Rule #46 paired canary: synthesise the forbidden shape + verify
    the gate fires + the loader keeps previous state (defaults).
    """
    yaml_content = textwrap.dedent("""\
        pins:
          - id: family-only-antipattern
            description: Synthetic disclosure-batch antipattern
            family: realtek_bt
            cves:
              - id: CVE-9999-9999
                severity: high
                rationale: would fire on ALL realtek_bt chipsets
    """)
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()

    pins = PL.get_banner_cve_pins()
    # Falls back to defaults (the in-tree BRAKTOOTH pin) — does NOT
    # accept the family-only antipattern.
    assert len(pins) == 1
    assert pins[0].pin_id == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"


def test_family_paired_with_chipset_in_accepted(
    tmp_path: Path, monkeypatch
) -> None:
    """Rule #46 negative canary: family + chipset_target_in IS the
    correct shape — must load cleanly."""
    yaml_content = textwrap.dedent("""\
        pins:
          - id: family-with-chipset-narrowing
            description: Correctly narrowed pin
            family: realtek_bt
            chipset_target_in: [rtl8761b]
            cves:
              - id: CVE-9999-0001
                severity: low
                rationale: pin fires only on rtl8761b
    """)
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()

    pins = PL.get_banner_cve_pins()
    assert len(pins) == 1
    assert pins[0].pin_id == "family-with-chipset-narrowing"
    assert pins[0].chipset_target_in == frozenset({"rtl8761b"})


def test_multiple_pins_load_in_yaml_order(tmp_path: Path, monkeypatch) -> None:
    # Each pin pairs family with a narrowing gate per the F-FORENSIC-10
    # invariant (2026-05-18): family alone is insufficient.
    yaml_content = textwrap.dedent("""\
        pins:
          - id: first
            description: first pin
            family: qca_rome
            chipset_target_in: [wcn3950]
            cves:
              - id: CVE-A
                severity: low
                rationale: a
          - id: second
            description: second pin
            family: broadcom_hcd
            chipset_target_in: [bcm4345c0]
            cves:
              - id: CVE-B
                severity: low
                rationale: b
    """)
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()

    pins = PL.get_banner_cve_pins()
    assert [p.pin_id for p in pins] == ["first", "second"]


# ---------------------------------------------------------------------------
# Graceful-degrade fallback.
# ---------------------------------------------------------------------------


def test_missing_yaml_falls_back_to_defaults(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        PL, "_BT_BANNER_CVE_PINS_YAML", tmp_path / "missing.yaml"
    )
    PL._load_banner_cve_pins.cache_clear()
    pins = PL.get_banner_cve_pins()
    # Defaults preserve the BRAKTOOTH pin — single Qualcomm-CNA CVE per
    # Reviewer B 2026-05-17 NVD CPE verification (CVE-2021-30348).
    assert len(pins) == 1
    assert pins[0].pin_id == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"
    assert {c.cve_id for c in pins[0].cves} == {"CVE-2021-30348"}


def test_malformed_yaml_pin_missing_id(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(textwrap.dedent("""\
        pins:
          - description: missing id
            family: qca_rome
            cves:
              - id: CVE-X
                severity: low
                rationale: x
    """))
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()

    with caplog.at_level("WARNING", logger="app.services.hardware_firmware.patterns_loader"):
        pins = PL.get_banner_cve_pins()
    assert pins[0].pin_id == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"
    assert any("structural validation failed" in r.message for r in caplog.records)


def test_malformed_yaml_pin_no_match_condition(
    tmp_path: Path, monkeypatch
) -> None:
    """A pin with ALL match conditions absent is invalid (would fire universally)."""
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(textwrap.dedent("""\
        pins:
          - id: fires-everywhere
            description: no gates at all
            cves:
              - id: CVE-X
                severity: low
                rationale: x
    """))
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()

    pins = PL.get_banner_cve_pins()
    # Falls back to defaults — bad pin rejected.
    assert pins[0].pin_id == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"


def test_malformed_yaml_bad_family(tmp_path: Path, monkeypatch) -> None:
    """family: must be one of the recognised BT parser verdicts."""
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(textwrap.dedent("""\
        pins:
          - id: bad-family
            description: bogus family
            family: not_a_real_family
            cves:
              - id: CVE-X
                severity: low
                rationale: x
    """))
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()
    pins = PL.get_banner_cve_pins()
    assert pins[0].pin_id == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"


def test_malformed_yaml_bad_regex(tmp_path: Path, monkeypatch) -> None:
    """An uncompilable banner_match regex falls back to defaults."""
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(textwrap.dedent(r"""
        pins:
          - id: bad-regex
            description: invalid regex
            family: qca_rome
            banner_match: "[unclosed"
            cves:
              - id: CVE-X
                severity: low
                rationale: x
    """))
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()
    pins = PL.get_banner_cve_pins()
    assert pins[0].pin_id == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"


def test_malformed_yaml_duplicate_pin_id(tmp_path: Path, monkeypatch) -> None:
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(textwrap.dedent("""\
        pins:
          - id: dup
            description: a
            family: qca_rome
            cves: [{id: CVE-A, severity: low, rationale: a}]
          - id: dup
            description: b
            family: broadcom_hcd
            cves: [{id: CVE-B, severity: low, rationale: b}]
    """))
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()
    pins = PL.get_banner_cve_pins()
    assert pins[0].pin_id == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"


# ---------------------------------------------------------------------------
# Helper coverage — _coerce_build_id + _parse_build_date.
# ---------------------------------------------------------------------------


def test_coerce_build_id_handles_int_string_and_dotted() -> None:
    assert _coerce_build_id("00069") == 69
    assert _coerce_build_id("00076.1") == 76
    assert _coerce_build_id("0") == 0
    assert _coerce_build_id(None) is None
    assert _coerce_build_id("alpha") is None
    assert _coerce_build_id("") is None


def test_parse_build_date_strict_format() -> None:
    assert _parse_build_date("Jun 12 2017").date() == date(2017, 6, 12)
    assert _parse_build_date("Sep 12 2017").date() == date(2017, 9, 12)
    assert _parse_build_date("Dec  5 2024").date() == date(2024, 12, 5)
    assert _parse_build_date(None) is None
    assert _parse_build_date("") is None
    assert _parse_build_date("not a date") is None
    assert _parse_build_date("2017-09-12") is None  # Wrong format — strict.


# ---------------------------------------------------------------------------
# End-to-end parser integration.
# ---------------------------------------------------------------------------


def _make_qca_tlv(banner: str) -> bytes:
    header = bytearray(28)
    payload = bytearray(banner.encode("ascii") + b"\x00\x00" * 32)
    total_len = len(header) + len(payload)
    type_len = (total_len << 8) | 0x01
    struct.pack_into("<I", header, 0, type_len)
    return bytes(header) + bytes(payload)


def test_shipped_yaml_fires_braktooth_pin_via_parser(tmp_path: Path) -> None:
    """End-to-end: a CMC banner produces the single CVE-2021-30348 pin
    (Qualcomm-CNA-attributed per NVD, Reviewer B 2026-05-17)."""
    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    fixture = _make_qca_tlv(banner)
    p = tmp_path / "cmbtfw13.tlv"
    p.write_bytes(fixture)
    parser = get_parser("bt_fw_banner")
    assert parser is not None
    result = parser.parse(str(p), fixture[:64], len(fixture))

    kvs = result.metadata.get("known_vulnerabilities") or []
    assert len(kvs) == 1
    cve_ids = {k["cve_id"] for k in kvs}
    assert cve_ids == {"CVE-2021-30348"}
    # Each finding carries the pin_id traceback per H2 design.
    assert all(
        k["pin_id"] == "qualcomm-braktooth-qca-rome-dos-cve-2021-30348"
        for k in kvs
    )
    # Rationale templating substituted the banner + chipset.
    assert "WCN3950" in kvs[0]["rationale"]
    assert "BTFM.CMC.1.3.0-00069-QCACHROMZ-1" in kvs[0]["rationale"]


def test_parser_skips_pin_when_chipset_excluded_in_yaml(
    tmp_path: Path, monkeypatch
) -> None:
    """Operator restricts the BRAKTOOTH scope via YAML — parser respects it."""
    yaml_content = textwrap.dedent("""\
        pins:
          - id: tight-scope
            description: only fire on wcn3990 — wcn3950 excluded
            family: qca_rome
            chipset_target_in: [wcn3990]
            cves:
              - id: CVE-TEST-001
                severity: medium
                rationale: 'only fires on {chipset_upper}'
    """)
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    yaml_path.write_text(yaml_content)
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL._load_banner_cve_pins.cache_clear()

    # CMC banner → wcn3950 — should NOT fire.
    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    fixture = _make_qca_tlv(banner)
    p = tmp_path / "cmbtfw13.tlv"
    p.write_bytes(fixture)
    parser = get_parser("bt_fw_banner")
    result = parser.parse(str(p), fixture[:64], len(fixture))
    assert "known_vulnerabilities" not in result.metadata


def test_parser_emits_custom_pin_for_new_codename(
    tmp_path: Path, monkeypatch
) -> None:
    """A custom pin authored in YAML fires end-to-end on a synthetic banner."""
    # Both H1 + H2 YAMLs are monkeypatched — operator adds a codename + pin.
    h1_yaml = tmp_path / "bt_qca_codenames.yaml"
    h1_yaml.write_text(textwrap.dedent("""\
        codenames:
          - codename: ZZZ
            chipset: synthetic_chip
            display: Zulu
        braktooth_chipsets: []
        mtk_known_chips: []
    """))
    h2_yaml = tmp_path / "bt_banner_cve_pins.yaml"
    h2_yaml.write_text(textwrap.dedent("""\
        pins:
          - id: synthetic-zulu-rce
            description: Synthetic pin for Zulu chipset
            family: qca_rome
            chipset_target_in: [synthetic_chip]
            cves:
              - id: CVE-2099-12345
                severity: critical
                confidence: high
                rationale: |
                  Synthetic_chip banner '{banner}' — codename {codename}
                reference: https://example.invalid/cve-test
    """))
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", h1_yaml)
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", h2_yaml)
    PL._load_bt_qca_codenames.cache_clear()
    PL._load_banner_cve_pins.cache_clear()

    banner = "BTFM.ZZZ.9.9.9-99999-QCACHROM-1"
    fixture = _make_qca_tlv(banner)
    p = tmp_path / "zzzbtfw.tlv"
    p.write_bytes(fixture)
    parser = get_parser("bt_fw_banner")
    result = parser.parse(str(p), fixture[:64], len(fixture))

    assert result.chipset_target == "synthetic_chip"
    kvs = result.metadata.get("known_vulnerabilities") or []
    assert len(kvs) == 1
    assert kvs[0]["cve_id"] == "CVE-2099-12345"
    assert kvs[0]["severity"] == "critical"
    assert kvs[0]["pin_id"] == "synthetic-zulu-rce"
    assert "ZZZ" in kvs[0]["rationale"]


def test_multiple_pins_fire_concatenated(
    tmp_path: Path, monkeypatch
) -> None:
    """When two pins both match the same record, both contribute findings."""
    h2_yaml = tmp_path / "bt_banner_cve_pins.yaml"
    h2_yaml.write_text(textwrap.dedent("""\
        pins:
          - id: pin-a
            description: a
            family: qca_rome
            chipset_target_in: [wcn3950]
            cves:
              - id: CVE-A
                severity: medium
                rationale: A {chipset_upper}
          - id: pin-b
            description: b
            family: qca_rome
            codename_in: [CMC]
            cves:
              - id: CVE-B
                severity: low
                rationale: B {codename}
    """))
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", h2_yaml)
    PL._load_banner_cve_pins.cache_clear()

    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    fixture = _make_qca_tlv(banner)
    p = tmp_path / "cmbtfw13.tlv"
    p.write_bytes(fixture)
    parser = get_parser("bt_fw_banner")
    result = parser.parse(str(p), fixture[:64], len(fixture))

    kvs = result.metadata.get("known_vulnerabilities") or []
    cve_ids = [k["cve_id"] for k in kvs]
    assert "CVE-A" in cve_ids
    assert "CVE-B" in cve_ids
    pin_ids = {k["pin_id"] for k in kvs}
    assert pin_ids == {"pin-a", "pin-b"}


def test_rationale_with_missing_placeholder_falls_back_to_raw(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    """An unknown {placeholder} in rationale logs WARN + emits raw template."""
    h2_yaml = tmp_path / "bt_banner_cve_pins.yaml"
    h2_yaml.write_text(textwrap.dedent("""\
        pins:
          - id: bad-template
            description: uses {unknown_var}
            family: qca_rome
            chipset_target_in: [wcn3950]
            cves:
              - id: CVE-X
                severity: low
                rationale: 'this references {unknown_var}'
    """))
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", h2_yaml)
    PL._load_banner_cve_pins.cache_clear()

    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    fixture = _make_qca_tlv(banner)
    p = tmp_path / "cmbtfw13.tlv"
    p.write_bytes(fixture)
    parser = get_parser("bt_fw_banner")

    with caplog.at_level("WARNING", logger="app.services.hardware_firmware.parsers.bt_firmware_banner"):
        result = parser.parse(str(p), fixture[:64], len(fixture))

    kvs = result.metadata.get("known_vulnerabilities") or []
    assert len(kvs) == 1
    # Raw template emitted (still useful to the operator).
    assert "{unknown_var}" in kvs[0]["rationale"]
    assert any("template error" in r.message for r in caplog.records)


def test_pin_id_traceback_in_findings(tmp_path: Path) -> None:
    """Every emitted finding carries pin_id for audit traceback."""
    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    fixture = _make_qca_tlv(banner)
    p = tmp_path / "cmbtfw13.tlv"
    p.write_bytes(fixture)
    parser = get_parser("bt_fw_banner")
    result = parser.parse(str(p), fixture[:64], len(fixture))
    kvs = result.metadata.get("known_vulnerabilities") or []
    assert all("pin_id" in k for k in kvs)
    # Source field tagged the finding origin.
    assert all(k["source"] == "parser_version_pin" for k in kvs)


def test_emit_pins_helper_idempotent_on_empty_pin_list(
    tmp_path: Path, monkeypatch
) -> None:
    """When no pin matches, _emit_pins does NOT inject an empty key into meta."""
    monkeypatch.setattr(
        PL, "_BT_BANNER_CVE_PINS_YAML", tmp_path / "missing.yaml"
    )
    PL._load_banner_cve_pins.cache_clear()
    # Default pin is qca_rome-only; a broadcom_hcd record won't match.
    record = {
        "family": "broadcom_hcd",
        "chipset_target": "bcm43455",
        "banner": "BCM43455A0",
    }
    meta: dict = {}
    _emit_pins(record, meta)
    assert "known_vulnerabilities" not in meta


def test_pin_from_yaml_rules_returns_empty_when_no_pins_match() -> None:
    record = {
        "family": "mediatek_bt",
        "chipset_target": "mt9999",  # not in any default pin
    }
    assert _pin_from_yaml_rules(record) == []
