"""Phase γ.5 — driver_inf_parser tests.

Pure-text parser tests with a small set of synthetic INF samples
covering: minimal Version block; multi-manufacturer with decorations;
[Models] with hardware ID + multiple compatible IDs; [Strings]
substitution including the case-insensitive-token-name behaviour;
defensive cases (malformed sections, line continuation, comments,
unresolved tokens).

UTF-16 BOM-prefixed file decode is also exercised against a tmp file.
"""
from __future__ import annotations

from app.services.driver_inf_parser import (
    parse_inf_file,
    parse_inf_text,
)

# ── Minimal happy path ──────────────────────────────────────────────────────


_MINIMAL_INF = """
[Version]
Signature   = "$WINDOWS NT$"
Class       = Display
ClassGuid   = {4d36e968-e325-11ce-bfc1-08002be10318}
Provider    = "Intel Corporation"
DriverVer   = 01/15/2024,31.0.101.5333
CatalogFile = iigd_dch.cat

[Manufacturer]
%Intel%     = IntelGfx, NTAMD64.10.0..19041

[IntelGfx.NTAMD64.10.0..19041]
"Intel(R) UHD Graphics 770" = iIGDX_Section, PCI\\VEN_8086&DEV_4680, PCI\\VEN_8086&CC_0300

[Strings]
Intel       = "Intel Corporation"
"""


def test_parse_minimal_inf_extracts_version_block():
    result = parse_inf_text(_MINIMAL_INF)
    vb = result["version_block"]
    assert vb["Class"] == "Display"
    assert vb["ClassGuid"] == "{4d36e968-e325-11ce-bfc1-08002be10318}"
    assert vb["Provider"] == "Intel Corporation"
    assert vb["DriverVer"] == "01/15/2024,31.0.101.5333"
    assert vb["CatalogFile"] == "iigd_dch.cat"


def test_parse_minimal_inf_extracts_manufacturer_block():
    result = parse_inf_text(_MINIMAL_INF)
    mfg = result["manufacturer_block"]
    assert len(mfg) == 1
    assert mfg[0]["name"] == "%Intel%"
    assert mfg[0]["section"] == "IntelGfx"
    assert mfg[0]["decorations"] == ["NTAMD64.10.0..19041"]


def test_parse_minimal_inf_extracts_models():
    result = parse_inf_text(_MINIMAL_INF)
    models = result["models"]
    # Manufacturer's Models section is "IntelGfx" with NTAMD64.10.0..19041
    # decoration; the parser walks both base + decorated section names.
    # Only the decorated variant has the Models entry, so one match.
    assert len(models) == 1
    m = models[0]
    assert m["device_description"] == "Intel(R) UHD Graphics 770"
    assert m["install_section"] == "iIGDX_Section"
    assert m["hardware_id"] == "PCI\\VEN_8086&DEV_4680"
    assert m["compatible_ids"] == ["PCI\\VEN_8086&CC_0300"]
    assert m["manufacturer"] == "Intel Corporation"  # %Intel% resolved


def test_parse_minimal_inf_strings_table_lower_cases_keys():
    result = parse_inf_text(_MINIMAL_INF)
    # Strings table is lowercased per case-insensitive lookup convention.
    assert result["strings"]["intel"] == "Intel Corporation"


def test_parse_minimal_inf_no_errors():
    assert parse_inf_text(_MINIMAL_INF)["errors"] == []


# ── Multi-manufacturer with multiple Models ─────────────────────────────────


_MULTI_MFG_INF = """
[Version]
Class       = Net
ClassGuid   = {4d36e972-e325-11ce-bfc1-08002be10318}
DriverVer   = 02/01/2025,1.0.0.0

[Manufacturer]
%Mfg1%      = Mfg1Section
%Mfg2%      = Mfg2Section, NTAMD64

[Mfg1Section]
"Device A" = InstallA, USB\\VID_1111&PID_AAAA

[Mfg2Section.NTAMD64]
"Device B" = InstallB, PCI\\VEN_2222&DEV_BBBB, PCI\\VEN_2222&DEV_CCCC, PCI\\VEN_2222&CC_0200

[Strings]
Mfg1        = "Vendor One"
Mfg2        = "Vendor Two"
"""


def test_parse_multi_mfg_collects_two_manufacturers():
    result = parse_inf_text(_MULTI_MFG_INF)
    assert len(result["manufacturer_block"]) == 2
    names = [m["name"] for m in result["manufacturer_block"]]
    assert names == ["%Mfg1%", "%Mfg2%"]


def test_parse_multi_mfg_collects_models_from_both_sections():
    result = parse_inf_text(_MULTI_MFG_INF)
    models = result["models"]
    assert len(models) == 2
    # Manufacturers are resolved against [Strings].
    by_desc = {m["device_description"]: m for m in models}
    assert by_desc["Device A"]["manufacturer"] == "Vendor One"
    assert by_desc["Device B"]["manufacturer"] == "Vendor Two"
    # Multi-compatible-ID expansion for the PCI device.
    assert by_desc["Device B"]["compatible_ids"] == [
        "PCI\\VEN_2222&DEV_CCCC",
        "PCI\\VEN_2222&CC_0200",
    ]


# ── Unresolved tokens + comments + line continuation ────────────────────────


_DEFENSIVE_INF = """
; Header comment — should be ignored.
[Version]
Class       = USB ; inline comment
ClassGuid   = {4d36e96b-e325-11ce-bfc1-08002be10318}
Provider    = %UnresolvedToken%
DriverVer   = \\
              03/01/2025,1.2.3.4

[Manufacturer]
ACME = ACMESection

[ACMESection]
; All-comment lines should be ignored.
"""


def test_parse_defensive_inline_comment_stripped():
    result = parse_inf_text(_DEFENSIVE_INF)
    assert result["version_block"]["Class"] == "USB"


def test_parse_defensive_unresolved_token_left_inplace():
    """When a %TokenName% references a missing string, the token is
    left in-place per the parser contract (operator can see the raw
    value)."""
    result = parse_inf_text(_DEFENSIVE_INF)
    assert result["version_block"]["Provider"] == "%UnresolvedToken%"


def test_parse_defensive_line_continuation():
    """A trailing backslash continues the line — DriverVer is on two
    physical lines, one logical line."""
    result = parse_inf_text(_DEFENSIVE_INF)
    assert "03/01/2025" in result["version_block"]["DriverVer"]


def test_parse_defensive_no_errors_on_partial_models():
    """Empty or section-only Models blocks don't error — the section
    just produces zero model rows."""
    result = parse_inf_text(_DEFENSIVE_INF)
    assert result["models"] == []
    assert result["errors"] == []


# ── Empty / malformed inputs ────────────────────────────────────────────────


def test_parse_empty_returns_empty_canonical():
    result = parse_inf_text("")
    assert result["version_block"]["Class"] is None
    assert result["manufacturer_block"] == []
    assert result["models"] == []
    assert result["strings"] == {}


def test_parse_random_garbage_does_not_raise():
    """Defensive — non-INF content produces an empty parsed dict
    rather than an exception."""
    garbage = "this is not an inf file\xff\xfe\x00\x00 !@#$%^"
    result = parse_inf_text(garbage)
    assert result["version_block"]["Class"] is None


# ── parse_inf_file (UTF-16 BOM decode) ──────────────────────────────────────


def test_parse_inf_file_utf16_le_bom(tmp_path):
    """Modern Windows INFs are UTF-16 LE BOM-prefixed; the file
    reader strips the BOM + decodes."""
    p = tmp_path / "test.inf"
    p.write_bytes(b"\xff\xfe" + _MINIMAL_INF.encode("utf-16-le"))
    result = parse_inf_file(str(p))
    assert result["version_block"]["Class"] == "Display"
    assert result["errors"] == []


def test_parse_inf_file_utf8_no_bom(tmp_path):
    """UTF-8 (no BOM) is the fallback path — standard for older /
    test INFs."""
    p = tmp_path / "utf8.inf"
    p.write_text(_MINIMAL_INF, encoding="utf-8")
    result = parse_inf_file(str(p))
    assert result["version_block"]["Class"] == "Display"


def test_parse_inf_file_missing_path_returns_error(tmp_path):
    result = parse_inf_file(str(tmp_path / "nope.inf"))
    assert result["version_block"]["Class"] is None
    assert any(e.startswith("read:") for e in result["errors"])
