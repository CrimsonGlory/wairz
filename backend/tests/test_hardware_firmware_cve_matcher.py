"""Unit tests for the three-tier hardware firmware CVE matcher.

Uses the same mock-session pattern as ``test_hardware_firmware_graph.py``.
Covers the Phase 4 surface: YAML load, curated match rules, metadata
fallback, advisory-only families, persistence, and idempotency.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.sbom import SbomComponent, SbomVulnerability
from app.services.hardware_firmware.cve_matcher import (
    CveMatch,
    _load_known_firmware,
    _match_curated,
    _match_kernel_cpe,
    _match_parser_detected,
    _stringify_metadata,
    match_firmware_cves,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_blob(
    *,
    vendor: str | None,
    category: str,
    version: str | None = None,
    chipset_target: str | None = None,
    metadata: dict | None = None,
    blob_id: uuid.UUID | None = None,
) -> MagicMock:
    """Build a HardwareFirmwareBlob-shaped mock."""
    blob = MagicMock(spec=HardwareFirmwareBlob)
    blob.id = blob_id or uuid.uuid4()
    blob.vendor = vendor
    blob.category = category
    blob.version = version
    blob.chipset_target = chipset_target
    blob.metadata_ = metadata or {}
    return blob


def _mock_db_for_matcher(
    *,
    blobs: list,
    existing: list[tuple[uuid.UUID, str]] | None = None,
) -> AsyncMock:
    """Mock AsyncSession: first execute() returns blobs, second returns dedup keys."""
    existing = existing or []

    blobs_result = MagicMock()
    blobs_result.scalars.return_value.all.return_value = blobs

    existing_result = MagicMock()
    # second execute() is `select(blob_id, cve_id)` — code does .all()
    existing_result.all.return_value = existing

    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.execute = AsyncMock(side_effect=[blobs_result, existing_result])
    return db


# ---------------------------------------------------------------------------
# YAML load
# ---------------------------------------------------------------------------


def test_load_known_firmware_has_seeded_entries() -> None:
    families = _load_known_firmware()
    assert isinstance(families, list)
    assert len(families) >= 10, (
        f"Expected >=10 curated CVE families, got {len(families)}"
    )
    # Each family needs the core fields for matching.
    for fam in families:
        assert "name" in fam
        assert "vendor" in fam
        assert "category" in fam
        # cves may be present-and-empty (advisory-only families)
        assert "cves" in fam


# ---------------------------------------------------------------------------
# _stringify_metadata
# ---------------------------------------------------------------------------


def test_stringify_metadata() -> None:
    md = {
        "fw_version_raw": "7.35.180.11",
        "tags": ["alpha", "beta", 42, None],
        "nested": {"ignored": "not-returned"},
        "num": 100,
        "flag": True,
    }
    out = _stringify_metadata(md)
    # Only top-level strings + strings inside lists must be returned.
    assert "7.35.180.11" in out
    assert "alpha" in out
    assert "beta" in out
    assert "not-returned" not in out  # nested dict ignored
    # Non-strings filtered.
    for v in out:
        assert isinstance(v, str)


# ---------------------------------------------------------------------------
# _match_parser_detected — Tier 0 (parser-embedded version-pin fingerprints)
# ---------------------------------------------------------------------------


class TestMatchParserDetected:
    """Tier 0 reads ``blob.metadata_["known_vulnerabilities"]`` directly and
    projects records into CveMatch rows.  No DB access, no YAML load."""

    def test_single_cve_produces_match_with_full_mapping(self) -> None:
        blob = _make_blob(
            vendor="mediatek",
            category="hypervisor",
            version="3.2.1.004",
            metadata={
                "known_vulnerabilities": [
                    {
                        "cve_id": "CVE-2025-20707",
                        "severity": "medium",
                        "cwe": "CWE-416",
                        "subcomponent": "geniezone",
                        "confidence": "high",
                        "source": "parser_version_pin",
                        "rationale": (
                            "GZ_hypervisor 3.2.1.004 built 2025-12-12 "
                            "predates MediaTek Feb 2026 PSB fix."
                        ),
                        "reference": (
                            "https://corp.mediatek.com/product-security-bulletin/"
                            "September-2025"
                        ),
                    }
                ]
            },
        )
        matches = _match_parser_detected([blob])
        assert len(matches) == 1
        m = matches[0]
        assert m.cve_id == "CVE-2025-20707"
        assert m.severity == "medium"
        assert m.confidence == "high"
        assert m.tier == "parser_version_pin"
        assert m.cvss_score is None
        assert m.blob_id == blob.id
        assert "3.2.1.004" in m.description
        assert "Feb 2026" in m.description

    def test_no_known_vulnerabilities_returns_empty(self) -> None:
        blob = _make_blob(
            vendor="mediatek", category="hypervisor", metadata={"other": "stuff"}
        )
        assert _match_parser_detected([blob]) == []

    def test_empty_metadata_returns_empty(self) -> None:
        blob = _make_blob(vendor="mediatek", category="hypervisor", metadata={})
        assert _match_parser_detected([blob]) == []

    def test_none_metadata_returns_empty(self) -> None:
        blob = _make_blob(vendor="mediatek", category="hypervisor")
        blob.metadata_ = None
        assert _match_parser_detected([blob]) == []

    def test_malformed_known_vulnerabilities_not_a_list(self) -> None:
        blob = _make_blob(
            vendor="mediatek",
            category="hypervisor",
            metadata={"known_vulnerabilities": "not-a-list"},
        )
        assert _match_parser_detected([blob]) == []

    def test_non_dict_records_skipped(self) -> None:
        blob = _make_blob(
            vendor="mediatek",
            category="hypervisor",
            metadata={
                "known_vulnerabilities": [
                    "not-a-dict",
                    42,
                    None,
                    {"cve_id": "CVE-2025-9999", "severity": "low"},
                ]
            },
        )
        matches = _match_parser_detected([blob])
        assert len(matches) == 1
        assert matches[0].cve_id == "CVE-2025-9999"

    def test_records_without_cve_id_skipped(self) -> None:
        blob = _make_blob(
            vendor="mediatek",
            category="hypervisor",
            metadata={
                "known_vulnerabilities": [
                    {"severity": "high"},            # missing cve_id
                    {"cve_id": "", "severity": "low"},  # empty cve_id
                    {"cve_id": None, "severity": "low"},  # null cve_id
                    {"cve_id": "CVE-2025-REAL"},
                ]
            },
        )
        matches = _match_parser_detected([blob])
        assert [m.cve_id for m in matches] == ["CVE-2025-REAL"]

    def test_defaults_when_optional_fields_missing(self) -> None:
        """severity → 'medium', confidence → 'high', description → '' when absent."""
        blob = _make_blob(
            vendor="mediatek",
            category="hypervisor",
            metadata={"known_vulnerabilities": [{"cve_id": "CVE-2025-BARE"}]},
        )
        matches = _match_parser_detected([blob])
        assert len(matches) == 1
        m = matches[0]
        assert m.severity == "medium"
        assert m.confidence == "high"
        assert m.description == ""
        assert m.cvss_score is None

    def test_multiple_blobs_aggregated(self) -> None:
        blob_a = _make_blob(
            vendor="mediatek",
            category="hypervisor",
            metadata={"known_vulnerabilities": [{"cve_id": "CVE-2025-A"}]},
        )
        blob_b = _make_blob(
            vendor="mediatek",
            category="tee",
            metadata={"known_vulnerabilities": [{"cve_id": "CVE-2025-B"}]},
        )
        blob_no_meta = _make_blob(vendor="samsung", category="modem", metadata={})
        matches = _match_parser_detected([blob_a, blob_b, blob_no_meta])
        by_blob = {m.blob_id: m.cve_id for m in matches}
        assert by_blob == {blob_a.id: "CVE-2025-A", blob_b.id: "CVE-2025-B"}

    def test_multiple_cves_on_one_blob(self) -> None:
        blob = _make_blob(
            vendor="mediatek",
            category="hypervisor",
            metadata={
                "known_vulnerabilities": [
                    {"cve_id": "CVE-2025-ONE", "severity": "medium"},
                    {"cve_id": "CVE-2025-TWO", "severity": "high"},
                ]
            },
        )
        matches = _match_parser_detected([blob])
        assert {m.cve_id for m in matches} == {"CVE-2025-ONE", "CVE-2025-TWO"}
        for m in matches:
            assert m.tier == "parser_version_pin"
            assert m.blob_id == blob.id


# ---------------------------------------------------------------------------
# _match_curated
# ---------------------------------------------------------------------------


class TestMatchCurated:
    def _families(self) -> list[dict]:
        return _load_known_firmware()

    def test_exact_vendor_category_matches_broadpwn(self) -> None:
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version="7.35.180.11",
            chipset_target="bcm4358",
        )
        matches = _match_curated(blob, self._families())
        cve_ids = {m.cve_id for m in matches}
        assert "CVE-2017-9417" in cve_ids
        # All matches must be tier=curated_yaml, confidence=high
        for m in matches:
            assert m.tier == "curated_yaml"
            assert m.confidence == "high"

    def test_chipset_regex_required_when_present(self) -> None:
        # Matching vendor/category/version but chipset missing entirely
        # (BroadPwn demands a bcm4xxx chipset_target).
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version="7.35.180.11",
            chipset_target=None,
        )
        matches = _match_curated(blob, self._families())
        broadpwn_hits = [m for m in matches if m.cve_id == "CVE-2017-9417"]
        assert broadpwn_hits == []

    def test_chipset_regex_miss_excludes(self) -> None:
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version="7.35.180.11",
            chipset_target="bcm1234",  # miss — regex wants bcm43xx
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" not in {m.cve_id for m in matches}

    def test_version_regex_miss_filters_out(self) -> None:
        # BroadPwn version_regex wants 7.30-7.59.x; 8.x falls outside.
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version="8.10.0.0",
            chipset_target="bcm4358",
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" not in {m.cve_id for m in matches}

    def test_metadata_version_fallback_matches(self) -> None:
        # blob.version None, but metadata carries a matching version string.
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version=None,
            chipset_target="bcm4358",
            metadata={"fw_version_raw": "7.35.180.11"},
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" in {m.cve_id for m in matches}

    def test_advisory_when_cves_empty(self) -> None:
        # kamakiri BROM — MediaTek bootloader, cves: []
        blob = _make_blob(
            vendor="mediatek",
            category="bootloader",
            chipset_target="mt6785",
        )
        matches = _match_curated(blob, self._families())
        advisories = [m for m in matches if m.cve_id.startswith("ADVISORY-")]
        assert len(advisories) >= 1
        kamakiri = [m for m in advisories if "KAMAKIRI" in m.cve_id]
        assert len(kamakiri) == 1
        # Advisories should be tier=curated_yaml, confidence=high
        assert kamakiri[0].tier == "curated_yaml"
        assert kamakiri[0].confidence == "high"

    def test_returns_multiple_cves_for_shannon_cluster(self) -> None:
        blob = _make_blob(
            vendor="samsung",
            category="modem",
            version="s5123",
        )
        matches = _match_curated(blob, self._families())
        shannon = {
            m.cve_id
            for m in matches
            if m.cve_id
            in {
                "CVE-2023-24033",
                "CVE-2023-26496",
                "CVE-2023-26072",
                "CVE-2023-26073",
                "CVE-2023-26074",
            }
        }
        assert len(shannon) == 5

    def test_vendor_mismatch_filters_out(self) -> None:
        # Wrong vendor: should never match BroadPwn even with right category/version
        blob = _make_blob(
            vendor="qualcomm",
            category="wifi",
            version="7.35.180.11",
            chipset_target="bcm4358",
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" not in {m.cve_id for m in matches}

    def test_category_mismatch_filters_out(self) -> None:
        blob = _make_blob(
            vendor="broadcom",
            category="modem",  # BroadPwn is wifi
            version="7.35.180.11",
            chipset_target="bcm4358",
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" not in {m.cve_id for m in matches}


# ---------------------------------------------------------------------------
# match_firmware_cves — persistence + idempotency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_match_firmware_cves_no_blobs_returns_empty() -> None:
    firmware_id = uuid.uuid4()

    # Only the blobs query runs; short-circuit on empty.
    blobs_result = MagicMock()
    blobs_result.scalars.return_value.all.return_value = []
    db = AsyncMock()
    db.execute = AsyncMock(return_value=blobs_result)
    db.add = MagicMock()
    db.flush = AsyncMock()

    out = await match_firmware_cves(firmware_id, db)
    assert out == []
    db.add.assert_not_called()
    db.flush.assert_not_called()


@pytest.mark.asyncio
async def test_match_firmware_cves_persists_sbom_vulnerability() -> None:
    firmware_id = uuid.uuid4()
    blob_id = uuid.uuid4()

    blob = _make_blob(
        vendor="broadcom",
        category="wifi",
        version="7.35.180.11",
        chipset_target="bcm4358",
        blob_id=blob_id,
    )
    db = _mock_db_for_matcher(blobs=[blob], existing=[])

    matches = await match_firmware_cves(firmware_id, db)
    assert len(matches) >= 1
    # All persisted rows were SbomVulnerability instances with blob_id set.
    assert db.add.call_count == len(matches)
    added_rows = [call.args[0] for call in db.add.call_args_list]
    for row in added_rows:
        assert isinstance(row, SbomVulnerability)
        assert row.blob_id == blob_id
        assert row.firmware_id == firmware_id
        assert row.component_id is None
        assert row.match_tier == "curated_yaml"
        assert row.match_confidence == "high"
        assert row.resolution_status == "open"
    db.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_match_firmware_cves_is_idempotent() -> None:
    firmware_id = uuid.uuid4()
    blob_id = uuid.uuid4()

    blob = _make_blob(
        vendor="broadcom",
        category="wifi",
        version="7.35.180.11",
        chipset_target="bcm4358",
        blob_id=blob_id,
    )

    # First run: no existing rows.
    db1 = _mock_db_for_matcher(blobs=[blob], existing=[])
    run1 = await match_firmware_cves(firmware_id, db1)
    first_inserts = db1.add.call_count
    assert first_inserts >= 1

    # Second run: feed back the (blob_id, cve_id) pairs the first run produced.
    # The matcher still *returns* all matches (function signature contract),
    # but must not persist any new rows.
    existing_pairs = [(m.blob_id, m.cve_id) for m in run1]
    db2 = _mock_db_for_matcher(blobs=[blob], existing=existing_pairs)
    run2 = await match_firmware_cves(firmware_id, db2)
    # Returns the recomputed matches (same count), but no new inserts.
    assert len(run2) == len(run1)
    db2.add.assert_not_called()


@pytest.mark.asyncio
async def test_match_firmware_cves_force_rescan_reinserts() -> None:
    firmware_id = uuid.uuid4()
    blob_id = uuid.uuid4()

    blob = _make_blob(
        vendor="broadcom",
        category="wifi",
        version="7.35.180.11",
        chipset_target="bcm4358",
        blob_id=blob_id,
    )
    # Existing rows present, but force_rescan=True should still insert.
    db = _mock_db_for_matcher(
        blobs=[blob],
        existing=[(blob_id, "CVE-2017-9417")],
    )
    matches = await match_firmware_cves(firmware_id, db, force_rescan=True)
    # force_rescan should bypass the dedup set.
    assert db.add.call_count == len(matches)


# ---------------------------------------------------------------------------
# Tier 0 — parser_version_pin persistence (integration via match_firmware_cves)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_match_firmware_cves_persists_parser_version_pin_tier() -> None:
    """A blob that carries ``metadata_["known_vulnerabilities"]`` yields a
    persisted SbomVulnerability with ``match_tier='parser_version_pin'``.

    Uses a vendor/category combination (``mediatek`` + ``hypervisor``)
    absent from the curated YAML so Tier 3 doesn't also fire; the blob is
    non-kmod so Tier 4/5 short-circuit without touching the DB."""
    firmware_id = uuid.uuid4()
    blob_id = uuid.uuid4()

    blob = _make_blob(
        vendor="mediatek",
        category="hypervisor",
        version="3.2.1.004",
        blob_id=blob_id,
        metadata={
            "known_vulnerabilities": [
                {
                    "cve_id": "CVE-2025-20707",
                    "severity": "medium",
                    "cwe": "CWE-416",
                    "subcomponent": "geniezone",
                    "confidence": "high",
                    "source": "parser_version_pin",
                    "rationale": "GZ 3.2.1.004 predates Feb 2026 PSB fix.",
                }
            ]
        },
    )
    db = _mock_db_for_matcher(blobs=[blob], existing=[])

    matches = await match_firmware_cves(firmware_id, db)
    tier0 = [m for m in matches if m.tier == "parser_version_pin"]
    assert len(tier0) == 1
    assert tier0[0].cve_id == "CVE-2025-20707"

    added_rows = [call.args[0] for call in db.add.call_args_list]
    tier0_rows = [r for r in added_rows if r.match_tier == "parser_version_pin"]
    assert len(tier0_rows) == 1
    row = tier0_rows[0]
    assert isinstance(row, SbomVulnerability)
    assert row.cve_id == "CVE-2025-20707"
    assert row.match_confidence == "high"
    assert row.severity == "medium"
    assert row.blob_id == blob_id
    assert row.firmware_id == firmware_id
    assert row.component_id is None
    assert row.resolution_status == "open"


@pytest.mark.asyncio
async def test_match_firmware_cves_tier0_dedups_on_rerun() -> None:
    """A re-run with the same ``(blob_id, cve_id)`` pair already persisted
    produces zero new inserts — Tier 0 goes through the same dedup path as
    every other tier."""
    firmware_id = uuid.uuid4()
    blob_id = uuid.uuid4()

    blob = _make_blob(
        vendor="mediatek",
        category="hypervisor",
        blob_id=blob_id,
        metadata={
            "known_vulnerabilities": [
                {"cve_id": "CVE-2025-20707", "severity": "medium"}
            ]
        },
    )
    # Feed back the existing pair so the dedup set rejects the insert.
    db = _mock_db_for_matcher(
        blobs=[blob],
        existing=[(blob_id, "CVE-2025-20707")],
    )

    matches = await match_firmware_cves(firmware_id, db)
    # Returned matches still include the Tier 0 hit (signature contract),
    # but nothing was persisted.
    tier0 = [m for m in matches if m.tier == "parser_version_pin"]
    assert len(tier0) == 1
    db.add.assert_not_called()


# ---------------------------------------------------------------------------
# CveMatch dataclass importable
# ---------------------------------------------------------------------------


def test_cve_match_dataclass_importable() -> None:
    m = CveMatch(
        blob_id=uuid.uuid4(),
        cve_id="CVE-2017-9417",
        severity="critical",
        cvss_score=9.8,
        description="test",
        confidence="high",
        tier="curated_yaml",
    )
    assert m.cve_id == "CVE-2017-9417"
    assert m.tier == "curated_yaml"


# ---------------------------------------------------------------------------
# Tier 4 — kernel CPE matcher (projects grype's kernel CVEs onto kmod blobs)
# ---------------------------------------------------------------------------


def _make_kernel_component(
    *,
    name: str = "linux-kernel",
    version: str = "6.6.102",
    comp_id: uuid.UUID | None = None,
    type_: str = "operating-system",
    detection_source: str = "kernel_vermagic",
) -> MagicMock:
    """Build an SbomComponent-shaped mock flagged as the Linux kernel."""
    comp = MagicMock(spec=SbomComponent)
    comp.id = comp_id or uuid.uuid4()
    comp.name = name
    comp.version = version
    comp.type = type_
    comp.detection_source = detection_source
    return comp


def _make_kernel_vuln(
    *,
    cve_id: str,
    component_id: uuid.UUID,
    severity: str = "high",
    cvss_score: float | None = 7.5,
    description: str = "kernel CVE from grype",
) -> MagicMock:
    """Build an SbomVulnerability-shaped mock attached to a kernel component."""
    v = MagicMock(spec=SbomVulnerability)
    v.cve_id = cve_id
    v.component_id = component_id
    v.severity = severity
    v.cvss_score = cvss_score
    v.description = description
    return v


def _mock_db_kernel_tier(
    *,
    components: list,
    vulns: list,
) -> AsyncMock:
    """AsyncSession mock for direct ``_match_kernel_cpe`` invocations.

    First ``execute()`` returns the components query result (scalars.all
    → components); second returns the vulnerabilities (scalars.all →
    vulns).  Subsequent calls raise StopIteration — the tier never makes
    more than two queries.
    """
    comp_result = MagicMock()
    comp_result.scalars.return_value.all.return_value = components

    vuln_result = MagicMock()
    vuln_result.scalars.return_value.all.return_value = vulns

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[comp_result, vuln_result])
    return db


def _mock_db_full_matcher(
    *,
    blobs: list,
    existing: list[tuple[uuid.UUID, str]] | None = None,
    kernel_components: list | None = None,
    kernel_vulns: list | None = None,
) -> AsyncMock:
    """AsyncSession mock covering the matcher's execute() call sequence.

    Calls in order:
    1. blobs query
    2. existing (blob_id, cve_id) dedup keys
    3. kernel-component query (Tier 4 SELECT)
    4. kernel-vulnerability query (Tier 4 SELECT, skipped if step 3 empty)
    5. tier-4 bulk INSERT (Core ``insert()`` + executemany; skipped if no
       new tier-4 rows survive the dedup set)

    The bulk insert returns a no-op MagicMock — the matcher only needs
    the call to succeed; it doesn't read the result.
    """
    existing = existing or []
    kernel_components = kernel_components or []
    kernel_vulns = kernel_vulns or []

    blobs_result = MagicMock()
    blobs_result.scalars.return_value.all.return_value = blobs

    existing_result = MagicMock()
    existing_result.all.return_value = existing

    comp_result = MagicMock()
    comp_result.scalars.return_value.all.return_value = kernel_components

    vuln_result = MagicMock()
    vuln_result.scalars.return_value.all.return_value = kernel_vulns

    insert_result = MagicMock()  # tier-4 bulk insert — not inspected

    side_effects: list = [blobs_result, existing_result]
    # Tier 4 only hits the DB when there's at least one kmod blob.
    kmod_blobs = [b for b in blobs if (b.category or "").lower() == "kernel_module"]
    has_kmod = bool(kmod_blobs)
    if has_kmod:
        side_effects.append(comp_result)
        # Only the second Tier 4 query fires if the first returned rows.
        if kernel_components:
            side_effects.append(vuln_result)
            # Tier 4 bulk insert only fires if at least one new (blob, cve)
            # pair survives the dedup set.  The matrix is kmod_blobs ×
            # kernel_vulns; if every pair is in ``existing``, no insert.
            existing_set = set(existing)
            new_pairs = any(
                (b.id, v.cve_id) not in existing_set
                for b in kmod_blobs
                for v in kernel_vulns
            )
            if new_pairs:
                side_effects.append(insert_result)

    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.execute = AsyncMock(side_effect=side_effects)
    return db


@pytest.mark.asyncio
async def test_kernel_cpe_matcher_populates_kmod_blobs() -> None:
    """Two kmod blobs x three kernel CVEs = 6 ``CveMatch`` rows with
    ``kernel_cpe`` provenance."""
    firmware_id = uuid.uuid4()
    blob_a = _make_blob(vendor="qualcomm", category="kernel_module")
    blob_b = _make_blob(vendor="mediatek", category="kernel_module")

    comp = _make_kernel_component()
    vulns = [
        _make_kernel_vuln(cve_id="CVE-2024-1111", component_id=comp.id),
        _make_kernel_vuln(cve_id="CVE-2024-2222", component_id=comp.id, severity="critical"),
        _make_kernel_vuln(cve_id="CVE-2024-3333", component_id=comp.id, cvss_score=None),
    ]
    db = _mock_db_kernel_tier(components=[comp], vulns=vulns)

    matches = await _match_kernel_cpe([blob_a, blob_b], firmware_id, db)

    assert len(matches) == 6
    for m in matches:
        assert m.tier == "kernel_cpe"
        # Tier 4 projects every kernel CVE onto every kernel_module blob —
        # O(CVEs × modules) row inflation. confidence="low" so UIs can
        # down-rank vs. Tier 5 (subsystem-verified, "high").
        assert m.confidence == "low"
        assert m.blob_id in {blob_a.id, blob_b.id}
        assert m.cve_id in {"CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333"}

    # One CVE had cvss_score=None; ensure coercion preserved that.
    none_score = [m for m in matches if m.cve_id == "CVE-2024-3333"]
    assert all(m.cvss_score is None for m in none_score)


@pytest.mark.asyncio
async def test_kernel_cpe_matcher_no_kernel_component() -> None:
    """Kmod blobs but no linux-kernel SbomComponent → empty result, no vuln query."""
    firmware_id = uuid.uuid4()
    blob = _make_blob(vendor="qualcomm", category="kernel_module")

    # Only the component query should fire when components is empty.
    comp_result = MagicMock()
    comp_result.scalars.return_value.all.return_value = []
    db = AsyncMock()
    db.execute = AsyncMock(return_value=comp_result)

    matches = await _match_kernel_cpe([blob], firmware_id, db)

    assert matches == []
    # Component query fires; vuln query must not.
    assert db.execute.await_count == 1


@pytest.mark.asyncio
async def test_kernel_cpe_matcher_no_kmod_blobs() -> None:
    """Linux-kernel component with CVEs but no kmod blobs → no matches,
    no DB queries at all."""
    firmware_id = uuid.uuid4()
    # Only non-kmod blobs (wifi, modem, etc.)
    blobs = [
        _make_blob(vendor="broadcom", category="wifi"),
        _make_blob(vendor="qualcomm", category="modem"),
    ]

    db = AsyncMock()
    db.execute = AsyncMock()

    matches = await _match_kernel_cpe(blobs, firmware_id, db)

    assert matches == []
    # Short-circuit: no DB round-trips when there are no kmod blobs.
    db.execute.assert_not_called()


@pytest.mark.asyncio
async def test_kernel_cpe_matcher_aggregates_across_multiple_components() -> None:
    """Multiple linux-kernel SbomComponents (e.g., system + vendor partitions)
    contribute all their CVEs to each kmod blob."""
    firmware_id = uuid.uuid4()
    blob = _make_blob(vendor="qualcomm", category="kernel_module")
    comp_sys = _make_kernel_component(name="linux-kernel", version="6.6.102")
    comp_vendor = _make_kernel_component(
        name="linux_kernel", version="5.15.0", detection_source="kernel_build_id"
    )
    vulns = [
        _make_kernel_vuln(cve_id="CVE-2024-AAAA", component_id=comp_sys.id),
        _make_kernel_vuln(cve_id="CVE-2024-BBBB", component_id=comp_vendor.id),
    ]
    db = _mock_db_kernel_tier(components=[comp_sys, comp_vendor], vulns=vulns)

    matches = await _match_kernel_cpe([blob], firmware_id, db)

    cve_ids = {m.cve_id for m in matches}
    assert cve_ids == {"CVE-2024-AAAA", "CVE-2024-BBBB"}
    for m in matches:
        assert m.tier == "kernel_cpe"
        assert m.confidence == "low"


@pytest.mark.asyncio
async def test_kernel_cpe_persists_and_dedups_on_rerun() -> None:
    """Full matcher integration: first run streams 2 new kernel_cpe rows
    via the bulk INSERT path, second run (with those pairs already
    recorded) streams none.

    Tier 4 is persisted via SQLAlchemy Core ``insert(...)`` +
    executemany (not ``db.add``), to keep the cartesian
    ``kmod_blobs × kernel_cves`` matrix off the ORM identity map — the
    matrix can reach 2.65 M rows on Yocto firmware and previously OOM'd
    the backend at the bulk flush.  Test inspects the bulk-insert
    payload via ``db.execute.call_args_list`` and the new
    :attr:`MatchResult.tier4_rows` / ``tier4_distinct_cves`` summary
    attributes.
    """
    firmware_id = uuid.uuid4()
    blob_id = uuid.uuid4()
    kmod_blob = _make_blob(
        vendor="qualcomm", category="kernel_module", blob_id=blob_id
    )

    comp = _make_kernel_component()
    vulns = [
        _make_kernel_vuln(cve_id="CVE-2024-K1", component_id=comp.id),
        _make_kernel_vuln(cve_id="CVE-2024-K2", component_id=comp.id),
    ]

    # First run: no existing pairs → both CVEs inserted as one bulk
    # INSERT batch (well under the 5 000-row batch ceiling).
    db1 = _mock_db_full_matcher(
        blobs=[kmod_blob],
        existing=[],
        kernel_components=[comp],
        kernel_vulns=vulns,
    )
    run1 = await match_firmware_cves(firmware_id, db1)
    assert run1.tier4_rows == 2  # cartesian: 1 kmod × 2 cves
    assert run1.tier4_inserted == 2  # all 2 are new on first run
    assert run1.tier4_distinct_cves == frozenset({"CVE-2024-K1", "CVE-2024-K2"})
    # ORM-add is not used for tier-4; verify nothing else slipped in.
    assert all(
        getattr(call.args[0], "match_tier", None) != "kernel_cpe"
        for call in db1.add.call_args_list
    )
    # Inspect the bulk-insert payload — last execute() call is the
    # tier-4 executemany INSERT (see _mock_db_full_matcher side-effect
    # order).  Pattern: ``db.execute(insert(M), [dicts])`` so args[0]
    # is the Insert statement and args[1] is the list of param dicts.
    insert_calls = [
        c for c in db1.execute.call_args_list
        if len(c.args) == 2 and isinstance(c.args[1], list)
    ]
    assert len(insert_calls) == 1
    payload = insert_calls[0].args[1]
    assert len(payload) == 2
    for row in payload:
        assert row["blob_id"] == blob_id
        assert row["firmware_id"] == firmware_id
        assert row["component_id"] is None
        assert row["match_confidence"] == "low"
        assert row["match_tier"] == "kernel_cpe"
        assert row["resolution_status"] == "open"
        assert row["cve_id"] in {"CVE-2024-K1", "CVE-2024-K2"}

    # Second run: feed back the (blob, cve) pairs from run1's tier-4
    # output → dedup set covers everything → no bulk insert fires.
    existing_pairs = [(blob_id, cve) for cve in run1.tier4_distinct_cves]
    db2 = _mock_db_full_matcher(
        blobs=[kmod_blob],
        existing=existing_pairs,
        kernel_components=[comp],
        kernel_vulns=vulns,
    )
    run2 = await match_firmware_cves(firmware_id, db2)
    # Cartesian still 2 (matrix unchanged), but 0 new persisted (dedup'd).
    assert run2.tier4_rows == 2
    assert run2.tier4_inserted == 0
    assert run2.tier4_distinct_cves == frozenset({"CVE-2024-K1", "CVE-2024-K2"})
    db2.add.assert_not_called()
    # No bulk INSERT call should have fired on the second run
    # (executemany shape: 2-arg call where args[1] is the dict list).
    assert not [
        c for c in db2.execute.call_args_list
        if len(c.args) == 2 and isinstance(c.args[1], list)
    ]


@pytest.mark.asyncio
async def test_kernel_cpe_matcher_case_insensitive_component_name() -> None:
    """Component named ``Linux-Kernel`` still matches — the SQL predicate
    uses ``func.lower()``.  This test validates the Python side treats the
    matcher query params as case-insensitive too (smoke-level; the real
    case folding happens in Postgres)."""
    firmware_id = uuid.uuid4()
    blob = _make_blob(vendor="qualcomm", category="kernel_module")

    comp = _make_kernel_component(name="Linux-Kernel")
    vulns = [_make_kernel_vuln(cve_id="CVE-2024-CASE", component_id=comp.id)]
    # Simulate Postgres having already applied lower() → the mock just
    # returns the component; the tier must accept it unchanged.
    db = _mock_db_kernel_tier(components=[comp], vulns=vulns)

    matches = await _match_kernel_cpe([blob], firmware_id, db)
    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-2024-CASE"
    assert matches[0].tier == "kernel_cpe"
