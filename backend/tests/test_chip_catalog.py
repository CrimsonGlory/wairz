"""Hot-reload + graceful-degrade tests for the chip-family catalog loader.

Mirrors the ``test_yaml_cache`` shape — single instance + tmp_path fixture +
per-file mtime probes. Confirms the catalog handles:

  * Empty / missing root directory
  * Multi-vendor subdir structure
  * Hot-reload on file modification (mtime change)
  * File deletion drops from catalog
  * File addition appears in catalog
  * Malformed YAML keeps prior cached entry + WARN
  * Pydantic ValidationError preserves prior entry
  * Domain triple resolution
"""
from __future__ import annotations

import time

import pytest
import yaml

from app.schemas.chip_family import ChipFamilyManifest
from app.services.hardware_firmware.chip_catalog import ChipCatalog


def _minimal_manifest_dict(*, vendor: str = "ti", family: str = "f28066", domain: str = "c28x_core") -> dict:
    """Minimal valid manifest as a dict that survives YAML round-trip."""
    return {
        "schema_version": 1,
        "vendor": vendor,
        "family": family,
        "display_name": f"{vendor.upper()} {family}",
        "domains": [
            {
                "name": domain,
                "arch": "tms320c28x",
                "endianness": "little",
                "instruction_word_bits": 16,
                "data_word_bits": 16,
                "address_bus_bits": 22,
                "packing": "two_bytes_per_word_le",
                "address_regions": [
                    {
                        "name": "flash",
                        "start": 0x3D8000,
                        "size": 0x20000,
                        "access": "read-execute",
                        "semantic": ["flash_code"],
                    },
                ],
            },
        ],
    }


def _write_yaml(path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


@pytest.fixture
def catalog(tmp_path):
    """Catalog rooted at a per-test tmp_path."""
    return ChipCatalog(root_resolver=lambda: tmp_path)


def test_empty_root_returns_empty_catalog(catalog, tmp_path):
    assert catalog.get_catalog() == {}
    assert catalog.last_warning is None


def test_missing_root_returns_empty_catalog(tmp_path):
    # Resolver points at a non-existent path
    bogus = tmp_path / "no_such_dir"
    cat = ChipCatalog(root_resolver=lambda: bogus)
    assert cat.get_catalog() == {}


def test_loads_single_valid_yaml(catalog, tmp_path):
    ti_dir = tmp_path / "ti"
    ti_dir.mkdir()
    _write_yaml(ti_dir / "tms320f28066.yaml", _minimal_manifest_dict())
    snapshot = catalog.get_catalog()
    assert "ti/f28066" in snapshot
    manifest = snapshot["ti/f28066"]
    assert isinstance(manifest, ChipFamilyManifest)
    assert manifest.source_path == str(ti_dir / "tms320f28066.yaml")


def test_multiple_vendor_subdirs(catalog, tmp_path):
    (tmp_path / "ti").mkdir()
    (tmp_path / "nxp").mkdir()
    _write_yaml(tmp_path / "ti" / "a.yaml", _minimal_manifest_dict(vendor="ti", family="a"))
    _write_yaml(tmp_path / "nxp" / "b.yaml", _minimal_manifest_dict(vendor="nxp", family="b"))
    snapshot = catalog.get_catalog()
    assert "ti/a" in snapshot
    assert "nxp/b" in snapshot


def test_cached_on_unchanged_mtime(catalog, tmp_path):
    _write_yaml(tmp_path / "a.yaml", _minimal_manifest_dict(family="a"))
    catalog.get_catalog()
    initial_reloads = catalog.reload_count
    catalog.get_catalog()
    catalog.get_catalog()
    # Two more calls but file unchanged → no extra reloads
    assert catalog.reload_count == initial_reloads


def test_reloads_on_mtime_change(catalog, tmp_path):
    path = tmp_path / "a.yaml"
    _write_yaml(path, _minimal_manifest_dict(family="a"))
    snapshot1 = catalog.get_catalog()
    assert snapshot1["ti/a"].display_name == "TI a"

    # Modify content + bump mtime
    modified = _minimal_manifest_dict(family="a")
    modified["display_name"] = "TI a (revised)"
    time.sleep(0.01)
    _write_yaml(path, modified)
    snapshot2 = catalog.get_catalog()
    assert snapshot2["ti/a"].display_name == "TI a (revised)"


def test_file_deletion_drops_from_catalog(catalog, tmp_path):
    path = tmp_path / "a.yaml"
    _write_yaml(path, _minimal_manifest_dict(family="a"))
    assert "ti/a" in catalog.get_catalog()
    path.unlink()
    snapshot = catalog.get_catalog()
    assert snapshot == {}


def test_new_file_appears_in_catalog(catalog, tmp_path):
    _write_yaml(tmp_path / "a.yaml", _minimal_manifest_dict(family="a"))
    assert "ti/a" in catalog.get_catalog()
    assert "ti/b" not in catalog.get_catalog()
    _write_yaml(tmp_path / "b.yaml", _minimal_manifest_dict(family="b"))
    snapshot = catalog.get_catalog()
    assert "ti/a" in snapshot
    assert "ti/b" in snapshot


def test_malformed_yaml_no_prior_skipped(catalog, tmp_path):
    """Malformed YAML at startup with no prior valid cache → skipped + WARN."""
    bad = tmp_path / "bad.yaml"
    bad.write_text("{this: is: not: valid: yaml", encoding="utf-8")
    snapshot = catalog.get_catalog()
    assert snapshot == {}
    assert catalog.last_warning is not None
    assert "bad.yaml" in catalog.last_warning


def test_malformed_yaml_keeps_prior(catalog, tmp_path):
    """Malformed mid-flight keeps PREVIOUS valid cached value (Rule #34)."""
    path = tmp_path / "a.yaml"
    _write_yaml(path, _minimal_manifest_dict(family="a"))
    snapshot1 = catalog.get_catalog()
    assert "ti/a" in snapshot1

    # Corrupt the file
    time.sleep(0.01)
    path.write_text("garbage: [unclosed", encoding="utf-8")
    snapshot2 = catalog.get_catalog()
    # Prior valid manifest retained
    assert "ti/a" in snapshot2
    assert catalog.last_warning is not None


def test_warn_once_per_failed_mtime(catalog, tmp_path):
    """Repeated calls at SAME malformed mtime should NOT re-warn."""
    bad = tmp_path / "bad.yaml"
    bad.write_text("{unclosed", encoding="utf-8")
    catalog.get_catalog()
    first_warning = catalog.last_warning
    catalog.get_catalog()
    catalog.get_catalog()
    # Same warning string; no re-warn shoals — we don't have a direct
    # log-capture here, so we assert the failed_mtime cursor is set by
    # confirming a SECOND call with the file UNCHANGED doesn't update
    # last_warning to a new message (it stays pinned).
    assert catalog.last_warning == first_warning


def test_pydantic_validation_error_keeps_prior(catalog, tmp_path):
    """Schema-violation YAML keeps prior catalog state."""
    path = tmp_path / "a.yaml"
    _write_yaml(path, _minimal_manifest_dict(family="a"))
    snapshot1 = catalog.get_catalog()
    assert "ti/a" in snapshot1

    # Replace with structurally-invalid manifest
    bad_manifest = _minimal_manifest_dict(family="a")
    bad_manifest["domains"][0]["arch"] = "totally_made_up_arch"  # Literal violation
    time.sleep(0.01)
    _write_yaml(path, bad_manifest)
    snapshot2 = catalog.get_catalog()
    assert "ti/a" in snapshot2  # Prior preserved
    assert "totally_made_up_arch" in (catalog.last_warning or "")


def test_get_family_by_id(catalog, tmp_path):
    _write_yaml(tmp_path / "a.yaml", _minimal_manifest_dict(family="a"))
    assert catalog.get_family("ti/a") is not None
    assert catalog.get_family("ti/does_not_exist") is None


def test_get_domain_triple(catalog, tmp_path):
    _write_yaml(tmp_path / "a.yaml", _minimal_manifest_dict(family="a", domain="core_zero"))
    resolved = catalog.get_domain("ti/a/core_zero")
    assert resolved is not None
    manifest, domain_name = resolved
    assert manifest.family_id == "ti/a"
    assert domain_name == "core_zero"


def test_get_domain_missing_returns_none(catalog, tmp_path):
    _write_yaml(tmp_path / "a.yaml", _minimal_manifest_dict(family="a", domain="core_zero"))
    assert catalog.get_domain("ti/a/no_such_domain") is None
    assert catalog.get_domain("nope/nope/nope") is None
    assert catalog.get_domain("malformed_id") is None


def test_cache_clear_forces_reload(catalog, tmp_path):
    _write_yaml(tmp_path / "a.yaml", _minimal_manifest_dict(family="a"))
    catalog.get_catalog()
    reloads_before = catalog.reload_count
    catalog.cache_clear()
    catalog.get_catalog()
    assert catalog.reload_count > reloads_before


def test_empty_yaml_file_treated_as_malformed(catalog, tmp_path):
    """A 0-byte / blank YAML is rejected, not treated as ``None`` manifest."""
    (tmp_path / "empty.yaml").write_text("", encoding="utf-8")
    snapshot = catalog.get_catalog()
    assert snapshot == {}
    assert catalog.last_warning is not None


def test_subdir_recursion_two_levels_deep(catalog, tmp_path):
    """rglob picks up YAMLs at arbitrary depth (e.g. ti/c28x/<part>.yaml)."""
    deep = tmp_path / "ti" / "c28x"
    deep.mkdir(parents=True)
    _write_yaml(deep / "f28066.yaml", _minimal_manifest_dict(family="f28066"))
    assert "ti/f28066" in catalog.get_catalog()
