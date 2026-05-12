"""Tier-1 tests for the LOLDrivers BYOVD lookup service — Phase η.D.C.

Per CLAUDE.md Rule #35c (JSONB normalizer discipline), this suite covers:
- canonical pass-through (primary SHA256 lookup)
- defensive coercion (mixed-case hash, missing/empty/malformed bundles)
- idempotency (cache hits return identical verdicts)

Per Rule #35b (mocks-vs-live-canaries), the lookups in this file are
already EXECUTING the real production lookup code against a real JSON
file — there are no mocks of the parser. The "live canary" discipline
is satisfied by parsing an actual JSON fixture (mirroring upstream
shape exactly: CVE/CVEs key drift, flat hash duplicates, case drift) and
asserting downstream lookups + verdict shape against the real bundle
loader path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.loldrivers_lookup_service import (
    BYOVDVerdict,
    _normalize_cve_ids,
    _normalize_hash,
    _normalize_sample,
    is_loldrivers_available,
    lookup_driver_byovd,
    reference_url,
    reset_index_cache,
)

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "byovd" / "tiny.loldrivers.json"


@pytest.fixture(autouse=True)
def _clear_cache_between_tests():
    """Reset the in-process lookup index between tests so each test
    re-loads from the fixture path explicitly passed (Rule #35c
    idempotency boundary)."""
    reset_index_cache()
    yield
    reset_index_cache()


# ── Primary SHA256 lookup (canonical pass-through) ──────────────────────────


def test_primary_sha256_lookup_returns_verdict():
    """Lookup by KVS SHA256 — primary key, hit on first dict."""
    verdict = lookup_driver_byovd(
        "cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6",
        bundle_path=_FIXTURE_PATH,
    )
    assert verdict is not None
    assert isinstance(verdict, BYOVDVerdict)
    assert verdict.sha256 == "cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6"
    assert verdict.sha256_match_kind == "file"
    assert verdict.category == "vulnerable driver"
    assert verdict.filename == "amp.sys"
    assert verdict.mitre_id == "T1068"
    assert verdict.loldrivers_id == "00000000-0000-0000-0000-000000000001"
    assert verdict.cve_ids == ["CVE-2026-00001", "CVE-2026-00002"]
    assert verdict.authentihash_sha256 == "3333333333333333333333333333333333333333333333333333333333333333"
    assert verdict.loads_despite_hvci is False


# ── Authenticode-hash fallback (re-signed variant) ──────────────────────────


def test_authentihash_lookup_falls_back_when_file_hash_missing():
    """Lookup by Authentihash.SHA256 hits when KVS SHA256 doesn't match."""
    verdict = lookup_driver_byovd(
        "3333333333333333333333333333333333333333333333333333333333333333",
        bundle_path=_FIXTURE_PATH,
    )
    assert verdict is not None
    assert verdict.sha256_match_kind == "authentihash"
    # The lookup-key normalized form lands in the verdict's sha256 field.
    assert verdict.sha256 == "3333333333333333333333333333333333333333333333333333333333333333"
    assert verdict.filename == "amp.sys"


# ── Mixed-case hash normalization ───────────────────────────────────────────


def test_mixed_case_hash_normalizes():
    """Caller passes an UPPERCASE hash with surrounding whitespace; lookup
    normalizes to lowercase + strip and still hits."""
    verdict = lookup_driver_byovd(
        "  DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF  ",
        bundle_path=_FIXTURE_PATH,
    )
    assert verdict is not None
    assert verdict.sha256 == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    assert verdict.filename == "midcase.sys"


# ── CVE / CVEs coalescing ───────────────────────────────────────────────────


def test_cve_cves_key_drift_coalesces_into_one_list():
    """Record #2 uses CVEs (drift variant); verdict carries the coalesced
    list, not None."""
    verdict = lookup_driver_byovd(
        "9999999999999999999999999999999999999999999999999999999999999999",
        bundle_path=_FIXTURE_PATH,
    )
    assert verdict is not None
    assert verdict.cve_ids == ["CVE-2026-00003"]


def test_cve_empty_strings_and_duplicates_dropped():
    """Record #3 has ["", "  ", "CVE-2026-00004", "CVE-2026-00004"]; the
    coalesced list dedups + drops empties."""
    verdict = lookup_driver_byovd(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        bundle_path=_FIXTURE_PATH,
    )
    assert verdict is not None
    assert verdict.cve_ids == ["CVE-2026-00004"]


# ── Flat / nested hash duplicate-key merge (23-records anomaly) ─────────────


def test_flat_authentihash_sha256_merges_into_nested_form():
    """Record #2 has FLAT ``AuthentihashSHA256`` (no nested Authentihash
    dict). The normalizer merges this into the nested form so lookup
    by the flat hash value succeeds via the authentihash index."""
    # Lookup by the FLAT hash → it should land in the authentihash index.
    verdict = lookup_driver_byovd(
        "9999999999999999999999999999999999999999999999999999999999999999",
        bundle_path=_FIXTURE_PATH,
    )
    assert verdict is not None
    assert verdict.authentihash_sha256 == "9999999999999999999999999999999999999999999999999999999999999999"
    assert verdict.sha256_match_kind == "authentihash"


# ── HVCI bypass tag detection ───────────────────────────────────────────────


def test_loads_despite_hvci_tag_surfaces():
    """Record #2 has Tags=['loads-despite-hvci']; verdict reflects the
    HVCI bypass capability."""
    verdict = lookup_driver_byovd(
        "9999999999999999999999999999999999999999999999999999999999999999",
        bundle_path=_FIXTURE_PATH,
    )
    assert verdict is not None
    assert verdict.loads_despite_hvci is True


def test_loads_despite_hvci_false_when_no_tag():
    """Record #1 has Tags=['amp.sys'] only — no HVCI bypass signal."""
    verdict = lookup_driver_byovd(
        "cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6",
        bundle_path=_FIXTURE_PATH,
    )
    assert verdict is not None
    assert verdict.loads_despite_hvci is False


# ── Category preservation ───────────────────────────────────────────────────


def test_malicious_vs_vulnerable_driver_category():
    """Record #2 has Category='malicious'; record #1 has 'vulnerable driver'."""
    verdict_malicious = lookup_driver_byovd(
        "9999999999999999999999999999999999999999999999999999999999999999",
        bundle_path=_FIXTURE_PATH,
    )
    verdict_vulnerable = lookup_driver_byovd(
        "cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6",
        bundle_path=_FIXTURE_PATH,
    )
    assert verdict_malicious is not None and verdict_malicious.category == "malicious"
    assert verdict_vulnerable is not None and verdict_vulnerable.category == "vulnerable driver"


# ── Miss / graceful-degrade paths ───────────────────────────────────────────


def test_no_match_returns_none():
    """SHA256 not in the fixture → None (not an exception)."""
    verdict = lookup_driver_byovd(
        "0000000000000000000000000000000000000000000000000000000000000000",
        bundle_path=_FIXTURE_PATH,
    )
    assert verdict is None


def test_empty_hash_returns_none():
    """Empty / whitespace-only input → None without touching the bundle."""
    assert lookup_driver_byovd("", bundle_path=_FIXTURE_PATH) is None
    assert lookup_driver_byovd("   ", bundle_path=_FIXTURE_PATH) is None


def test_missing_bundle_graceful_degrade():
    """Bundle file does not exist → lookup returns None;
    is_loldrivers_available returns False."""
    fake_path = Path("/nonexistent/loldrivers.json")
    assert is_loldrivers_available(bundle_path=fake_path) is False
    assert lookup_driver_byovd("abc", bundle_path=fake_path) is None


def test_empty_bundle_string_disables_lookup(monkeypatch):
    """Explicit empty $LOLDRIVERS_BUNDLE_PATH disables lookup per Rule
    #37 operator-opt-out path."""
    monkeypatch.setenv("LOLDRIVERS_BUNDLE_PATH", "")
    assert is_loldrivers_available() is False
    assert lookup_driver_byovd("abc") is None


def test_empty_json_array_disables_lookup(tmp_path):
    """A bundle that parses to [] → no indexed entries → graceful degrade."""
    empty_bundle = tmp_path / "empty.json"
    empty_bundle.write_text("[]")
    assert is_loldrivers_available(bundle_path=empty_bundle) is False
    assert lookup_driver_byovd("abc", bundle_path=empty_bundle) is None


def test_malformed_json_bundle_disables_lookup(tmp_path):
    """Garbage in the bundle file → graceful degrade."""
    bad_bundle = tmp_path / "bad.json"
    bad_bundle.write_text("{garbage")
    assert is_loldrivers_available(bundle_path=bad_bundle) is False
    assert lookup_driver_byovd("abc", bundle_path=bad_bundle) is None


def test_non_list_top_level_disables_lookup(tmp_path):
    """Bundle whose root is a dict (not list) — defensive boundary."""
    bad_bundle = tmp_path / "bad.json"
    bad_bundle.write_text('{"records": []}')
    assert is_loldrivers_available(bundle_path=bad_bundle) is False


# ── Availability probe + reference URL ──────────────────────────────────────


def test_is_loldrivers_available_with_fixture():
    """Fixture bundle parses + indexes ≥1 entry → available=True."""
    assert is_loldrivers_available(bundle_path=_FIXTURE_PATH) is True


def test_reference_url_builds_canonical_form():
    """reference_url returns the upstream-canonical /drivers/{id}/ shape."""
    url = reference_url("00000000-0000-0000-0000-000000000001")
    assert url == "https://www.loldrivers.io/drivers/00000000-0000-0000-0000-000000000001/"


# ── Idempotency (Rule #35c) ─────────────────────────────────────────────────


def test_repeated_lookups_return_consistent_verdict():
    """Cache hits + cache misses both produce identical verdict shapes."""
    v1 = lookup_driver_byovd(
        "cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6",
        bundle_path=_FIXTURE_PATH,
    )
    v2 = lookup_driver_byovd(
        "cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6",
        bundle_path=_FIXTURE_PATH,
    )
    assert v1 == v2


# ── Internal normalizer unit tests (Rule #35c boundary discipline) ─────────


def test_normalize_cve_ids_coalesces():
    """Both CVE + CVEs keys coalesce; empties + dups drop."""
    record = {"CVE": ["A", "", "B", "B"], "CVEs": ["C", "  ", "A"]}
    assert _normalize_cve_ids(record) == ["A", "B", "C"]


def test_normalize_cve_ids_none_safe():
    """Missing keys / wrong types → empty list, no exception."""
    assert _normalize_cve_ids({}) == []
    assert _normalize_cve_ids({"CVE": None}) == []
    assert _normalize_cve_ids({"CVE": "not-a-list"}) == []
    assert _normalize_cve_ids({"CVE": [1, 2, 3]}) == []  # ints dropped


def test_normalize_sample_merges_flat_authentihash():
    """Flat AuthentihashSHA256 merges into nested form."""
    raw = {"AuthentihashSHA256": "ABC", "SHA256": "DEF"}
    out = _normalize_sample(raw)
    assert out.get("Authentihash") == {"SHA256": "ABC"}
    assert out.get("SHA256") == "DEF"
    assert "AuthentihashSHA256" not in out


def test_normalize_sample_preserves_nested_when_no_flat():
    """No flat key → nested Authentihash dict passes through unchanged."""
    raw = {"Authentihash": {"SHA256": "ABC", "MD5": "XX"}, "SHA256": "DEF"}
    out = _normalize_sample(raw)
    assert out["Authentihash"] == {"SHA256": "ABC", "MD5": "XX"}


def test_normalize_sample_handles_non_dict_input():
    """Non-dict input → empty dict (defensive boundary)."""
    assert _normalize_sample(None) == {}
    assert _normalize_sample("string") == {}
    assert _normalize_sample(["list"]) == {}


def test_normalize_hash_handles_edges():
    """None / empty / non-string → None; case + whitespace normalize."""
    assert _normalize_hash(None) is None
    assert _normalize_hash("") is None
    assert _normalize_hash("   ") is None
    assert _normalize_hash(123) is None
    assert _normalize_hash("  ABC  ") == "abc"
