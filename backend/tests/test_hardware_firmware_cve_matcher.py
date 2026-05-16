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
    detection_confidence: str = "medium",
) -> MagicMock:
    """Build a HardwareFirmwareBlob-shaped mock."""
    blob = MagicMock(spec=HardwareFirmwareBlob)
    blob.id = blob_id or uuid.uuid4()
    blob.vendor = vendor
    blob.category = category
    blob.version = version
    blob.chipset_target = chipset_target
    blob.metadata_ = metadata or {}
    blob.detection_confidence = detection_confidence
    return blob


# ---------------------------------------------------------------------------
# F-FORENSIC-11 (Reviewer B 2026-05-18) — curated-tier confidence floor.
# A LOW-confidence blob (e.g. Realtek BT parser's soft-fallback path)
# MUST NOT trigger curated YAML CVE attribution. Prevents soft-evidence
# vendor matches from polluting curated CVE rows.
# ---------------------------------------------------------------------------


def test_match_curated_skips_low_confidence_blob() -> None:
    """A LOW-confidence blob with vendor=realtek + category=bluetooth
    that otherwise matches a curated entry must produce ZERO rows."""
    families = [
        {
            "name": "realtek-test-cve",
            "vendor": "realtek",
            "category": "bluetooth",
            "cves": ["CVE-9999-0042"],
        },
    ]
    low_conf_blob = _make_blob(
        vendor="realtek",
        category="bluetooth",
        detection_confidence="low",
    )
    matches = _match_curated(low_conf_blob, families)
    assert matches == [], (
        "low-confidence vendor evidence must NOT trigger curated tier "
        "(F-FORENSIC-11 Reviewer B 2026-05-18 invariant)"
    )


def test_match_curated_fires_on_medium_confidence_blob() -> None:
    """Rule #46 negative canary: medium-confidence blob SHOULD trigger
    the curated tier — proves the F-FORENSIC-11 gate doesn't over-skip."""
    families = [
        {
            "name": "realtek-test-cve",
            "vendor": "realtek",
            "category": "bluetooth",
            "cves": ["CVE-9999-0042"],
        },
    ]
    med_conf_blob = _make_blob(
        vendor="realtek",
        category="bluetooth",
        detection_confidence="medium",
    )
    matches = _match_curated(med_conf_blob, families)
    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-9999-0042"


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
    # Each family needs the core fields for matching. An entry must have
    # either ``category`` OR ``category_regex`` (the latter introduced
    # 2026-05-15 for cross-category clusters like Achilles spanning
    # audio + dsp). An entry must have either ``vendor`` OR ``vendor_regex``
    # (the latter introduced 2026-05-16 for spec-level BT advisories that
    # span vendors). ``cves`` may be present-and-empty for advisory-only
    # families.
    for fam in families:
        assert "name" in fam
        assert "vendor" in fam or "vendor_regex" in fam, (
            f"family {fam.get('name')} missing both vendor and vendor_regex"
        )
        assert "category" in fam or "category_regex" in fam, (
            f"family {fam.get('name')} missing both category and category_regex"
        )
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

    def test_bt_banner_parser_braktooth_pin_projects_into_tier0(self) -> None:
        """End-to-end Tier 0 contract: when the BT banner parser populates
        ``metadata.known_vulnerabilities`` for a QCA Rome BTFM blob
        (BrakTooth Qualcomm-DoS subset), ``_match_parser_detected``
        projects every record into a parser_version_pin CveMatch.

        Pins the integration shape between
        ``app.services.hardware_firmware.parsers.bt_firmware_banner`` and
        ``_match_parser_detected`` so future refactors of either side
        can't silently break the pipeline.

        Reviewer B 2026-05-16: CVE-2021-28139 (ESP32 RCE per NVD) is
        deliberately NOT pinned — the parser excludes it. This test
        only includes the 3 Qualcomm-DoS CVEs.
        """
        # Same dict shape the banner parser writes via _emit_pins. Per
        # Reviewer B's forensic audits (2026-05-16 + 2026-05-17), the
        # SINGLE NVD-CPE-confirmed Qualcomm-CNA BrakTooth-DoS CVE is
        # CVE-2021-30348. CVE-2021-28139 (ESP32 RCE), -34147 (Cypress),
        # -31609 (Silicon Labs), -31612 (Zhuhai Jieli) are all in the
        # BrakTooth disclosure batch but have non-Qualcomm CPE entries
        # in NVD — they must NOT pin under qca_rome.
        braktooth_records = [
            {
                "cve_id": "CVE-2021-30348",
                "severity": "medium",
                "subcomponent": "bluetooth",
                "confidence": "high",
                "source": "parser_version_pin",
                "rationale": (
                    "BTFM banner confirms WCN3950 — Qualcomm BrakTooth "
                    "LLM utility-timer DoS"
                ),
            },
        ]
        blob = _make_blob(
            vendor="qualcomm",
            category="bluetooth",
            version="BTFM.CMC.1.3.0-00069-QCACHROMZ-1",
            chipset_target="wcn3950",
            metadata={
                "bt_fw_banner": {
                    "family": "qca_rome",
                    "vendor": "qualcomm",
                    "codename": "CMC",
                    "chipset_target": "wcn3950",
                },
                "known_vulnerabilities": braktooth_records,
            },
        )

        matches = _match_parser_detected([blob])

        # Single NVD-CPE-correct Qualcomm-CNA BrakTooth CVE.
        cve_ids = {m.cve_id for m in matches}
        assert cve_ids == {"CVE-2021-30348"}
        # All four non-Qualcomm-CNA disclosure-batch CVEs must NOT pin.
        for non_qualcomm_cve in (
            "CVE-2021-28139",  # ESP32 RCE
            "CVE-2021-34147",  # Cypress
            "CVE-2021-31609",  # Silicon Labs
            "CVE-2021-31612",  # Zhuhai Jieli
        ):
            assert non_qualcomm_cve not in cve_ids
        for m in matches:
            assert m.blob_id == blob.id
            assert m.tier == "parser_version_pin"
            assert m.confidence == "high"

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

    def test_chipset_regex_soft_when_blob_chipset_missing(self) -> None:
        """Updated 2026-05-15 — chipset_regex is now SOFT.

        Old semantics: BroadPwn required a bcm4xxx chipset_target → rejected
        on NULL.

        New semantics: NULL blob.chipset_target → match still fires WITH
        confidence downgraded from "high" to "medium". This was driven by
        the Moto-G32/G30 audit finding that chipset_target is populated on
        ~0% of qualcomm blobs; the strict gate produced zero matches across
        612 qualcomm blobs.

        Populated-but-non-matching chipset_target STILL rejects (covered by
        ``test_chipset_regex_miss_excludes`` below).
        """
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version="7.35.180.11",
            chipset_target=None,
        )
        matches = _match_curated(blob, self._families())
        broadpwn_hits = [m for m in matches if m.cve_id == "CVE-2017-9417"]
        assert len(broadpwn_hits) == 1
        # Soft match → confidence downgraded to medium.
        assert broadpwn_hits[0].confidence == "medium"

    def test_chipset_regex_miss_excludes(self) -> None:
        blob = _make_blob(
            vendor="broadcom",
            category="wifi",
            version="7.35.180.11",
            chipset_target="bcm1234",  # miss — regex wants bcm43xx
        )
        matches = _match_curated(blob, self._families())
        assert "CVE-2017-9417" not in {m.cve_id for m in matches}

    def test_strict_chipset_skips_soft_null_fallback(self) -> None:
        """Reviewer B 2026-05-17: ``strict_chipset: true`` disables the
        soft NULL-fallback so a restrictive CPE-attributed CVE does NOT
        over-attribute on Qualcomm+wifi blobs whose chipset_target is
        NULL. Verifies the new opt-in flag behaves correctly.
        """
        # CVE-2023-28581 entry in known_firmware.yaml ships with
        # strict_chipset: true. A qualcomm+wifi blob with NULL
        # chipset_target should NOT match.
        blob_null = _make_blob(
            vendor="qualcomm",
            category="wifi",
            version="some.version",
            chipset_target=None,
        )
        matches = _match_curated(blob_null, self._families())
        cve_ids = {m.cve_id for m in matches}
        assert "CVE-2023-28581" not in cve_ids, (
            "strict_chipset: true must suppress the soft-NULL fallback "
            "for the restrictive CVE-2023-28581 CPE list"
        )

        # Same blob, but chipset_target now matches the FastConnect regex
        # — should fire with high confidence (strict-positive case).
        blob_match = _make_blob(
            vendor="qualcomm",
            category="wifi",
            version="some.version",
            chipset_target="fastconnect6900",
        )
        matches2 = _match_curated(blob_match, self._families())
        cve_ids2 = {m.cve_id for m in matches2}
        assert "CVE-2023-28581" in cve_ids2

        # Same blob, chipset_target outside the regex — should NOT fire.
        blob_wrong = _make_blob(
            vendor="qualcomm",
            category="wifi",
            version="some.version",
            chipset_target="wcn3950",   # not in FastConnect CPE list
        )
        matches3 = _match_curated(blob_wrong, self._families())
        cve_ids3 = {m.cve_id for m in matches3}
        assert "CVE-2023-28581" not in cve_ids3

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

    # -----------------------------------------------------------------
    # vendor_regex — spec-level BT advisories (added 2026-05-16)
    # -----------------------------------------------------------------
    def test_vendor_regex_matches_qualcomm_bt(self) -> None:
        """ADVISORY-BT-KNOB has ``vendor_regex: '.'`` so it fires on
        Qualcomm BT blobs (which were vendor=qualcomm post-BTFM correction)."""
        blob = _make_blob(
            vendor="qualcomm",
            category="bluetooth",
            version="BTFM.CHE.2.0.0-00082-QCACHROMZ-1",
            chipset_target="wcn3990",
        )
        matches = _match_curated(blob, self._families())
        advisory_ids = {m.cve_id for m in matches}
        assert "ADVISORY-BT-KNOB" in advisory_ids
        assert "ADVISORY-BT-BLUFFS" in advisory_ids
        assert "ADVISORY-BT-BIAS" in advisory_ids
        assert "ADVISORY-BT-BLUR" in advisory_ids

    def test_vendor_regex_matches_broadcom_bt(self) -> None:
        """Spec-level advisories fire on Broadcom BT blobs (BCM43xx HCD)."""
        blob = _make_blob(
            vendor="broadcom",
            category="bluetooth",
            version=None,
            chipset_target="bcm43455",
        )
        matches = _match_curated(blob, self._families())
        advisory_ids = {m.cve_id for m in matches}
        assert "ADVISORY-BT-KNOB" in advisory_ids
        assert "ADVISORY-BT-BLUFFS" in advisory_ids

    def test_vendor_regex_matches_mediatek_bt(self) -> None:
        """Spec-level advisories fire on MediaTek BT blobs (MT79xx/MT66xx)."""
        blob = _make_blob(
            vendor="mediatek",
            category="bluetooth",
            version=None,
            chipset_target="mt7961",
        )
        matches = _match_curated(blob, self._families())
        advisory_ids = {m.cve_id for m in matches}
        assert "ADVISORY-BT-KNOB" in advisory_ids

    def test_vendor_regex_skips_non_bt_blobs(self) -> None:
        """Spec-level BT advisories MUST NOT fire on non-bluetooth blobs."""
        blob = _make_blob(
            vendor="qualcomm",
            category="wifi",  # WLAN, not BT
            version="some.wlan.firmware",
            chipset_target="wcn3990",
        )
        matches = _match_curated(blob, self._families())
        advisory_ids = {m.cve_id for m in matches}
        # Category gate stops the BT advisories from firing on wifi.
        assert "ADVISORY-BT-KNOB" not in advisory_ids
        assert "ADVISORY-BT-BLUFFS" not in advisory_ids

    def test_vendor_regex_rejects_empty_vendor(self) -> None:
        """vendor_regex with empty/None blob.vendor → no match (defensive).

        Without this guard, a regex like ``"."`` would match an empty
        string vacuously and fire on every uncategorized blob.
        """
        blob = _make_blob(vendor=None, category="bluetooth")
        matches = _match_curated(blob, self._families())
        # Even though vendor_regex="." would technically match "" with some
        # regex engines, the guard explicitly rejects empty vendor.
        advisory_ids = {m.cve_id for m in matches}
        assert "ADVISORY-BT-KNOB" not in advisory_ids

    # -----------------------------------------------------------------
    # Bluedroid / Fluoride host BT stack CVE coverage (rec #3)
    # -----------------------------------------------------------------
    def test_bluedroid_aosp_bt_matches_2023_cluster(self) -> None:
        """vendor=aosp, category=bluetooth → BleedingPodcast + GATT cluster."""
        blob = _make_blob(vendor="aosp", category="bluetooth")
        matches = _match_curated(blob, self._families())
        cve_ids = {m.cve_id for m in matches}
        assert "CVE-2023-45866" in cve_ids
        assert "CVE-2023-40129" in cve_ids
        assert "CVE-2023-35673" in cve_ids

    def test_bluedroid_aosp_includes_2024_disclosures(self) -> None:
        """vendor=aosp, category=bluetooth → 2024 DoS + OBEX disclosures."""
        blob = _make_blob(vendor="aosp", category="bluetooth")
        matches = _match_curated(blob, self._families())
        cve_ids = {m.cve_id for m in matches}
        assert "CVE-2024-43763" in cve_ids
        assert "CVE-2024-49728" in cve_ids

    def test_bluedroid_cves_do_not_fire_on_qcom_bt_blob(self) -> None:
        """Reviewer B M4 (2026-05-16): Bluedroid CVEs are AOSP host-stack
        bugs; libbt-vendor-qti.so is a different code surface (HAL
        adapter). Qualcomm BT blobs MUST NOT inherit Bluedroid CVEs
        via a duplicate vendor-fork entry — that was over-attribution.

        BrakTooth DoS cluster + spec-level advisories DO fire (those
        are silicon-firmware-level, not host-stack)."""
        blob = _make_blob(
            vendor="qualcomm",
            category="bluetooth",
            chipset_target="wcn3990",
        )
        matches = _match_curated(blob, self._families())
        cve_ids = {m.cve_id for m in matches}
        # Bluedroid CVEs do NOT fire on Qualcomm BT blobs.
        assert "CVE-2023-45866" not in cve_ids
        assert "CVE-2023-40129" not in cve_ids
        assert "CVE-2023-35673" not in cve_ids
        # BrakTooth Qualcomm-DoS (CVE-2021-30348) + spec advisories
        # still fire (legitimate silicon-firmware-level attributions).
        # Reviewer B 2026-05-17: the single Qualcomm-CNA CVE per NVD CPE
        # list is CVE-2021-30348; the 3 prior IDs (34147/31609/31612) and
        # CVE-2021-28139 are NOT Qualcomm-attributed.
        assert "CVE-2021-30348" in cve_ids
        assert "ADVISORY-BT-KNOB" in cve_ids
        # Non-Qualcomm-CNA BrakTooth-batch CVEs never fire on a qca_rome blob.
        for non_qualcomm_cve in (
            "CVE-2021-28139", "CVE-2021-34147",
            "CVE-2021-31609", "CVE-2021-31612",
        ):
            assert non_qualcomm_cve not in cve_ids

    # -----------------------------------------------------------------
    # wpa_supplicant CVE coverage (rec #4)
    # -----------------------------------------------------------------
    def test_wpa_supplicant_matches_2023_52160(self) -> None:
        """vendor=aosp, category=wifi → PEAP bypass + Dragonblood."""
        blob = _make_blob(vendor="aosp", category="wifi")
        matches = _match_curated(blob, self._families())
        cve_ids = {m.cve_id for m in matches}
        assert "CVE-2023-52160" in cve_ids
        # Dragonblood cluster
        assert "CVE-2019-9494" in cve_ids
        assert "CVE-2019-13377" in cve_ids
        # SAE / EAP-PWD side-channel
        assert "CVE-2022-23303" in cve_ids
        assert "CVE-2022-23304" in cve_ids

    def test_wpa_supplicant_not_fired_on_qcom_wifi(self) -> None:
        """wpa_supplicant CVEs are vendor=aosp; they must NOT fire on
        Qualcomm WLAN firmware blobs (different attack surface — the
        WLAN firmware blob is silicon, the supplicant is host software)."""
        blob = _make_blob(
            vendor="qualcomm",
            category="wifi",
            chipset_target="wcn3990",
        )
        matches = _match_curated(blob, self._families())
        cve_ids = {m.cve_id for m in matches}
        assert "CVE-2023-52160" not in cve_ids
        assert "CVE-2019-9494" not in cve_ids

    def test_vendor_regex_scoped_alternation(self) -> None:
        """A scoped vendor_regex (e.g. (qualcomm|broadcom)) matches both
        listed vendors but not others — sanity check on the alternation."""
        # Inline test family that the actual YAML doesn't use yet — we
        # verify the matcher behaviour, not the YAML content.
        test_families = [
            {
                "name": "Test scoped BT advisory",
                "advisory_id": "TEST-BT-SCOPED",
                "vendor_regex": "^(qualcomm|broadcom)$",
                "category": "bluetooth",
                "cves": [],
                "severity": "medium",
                "notes": "Test family — scoped vendor_regex",
            }
        ]
        for vendor in ("qualcomm", "broadcom"):
            blob = _make_blob(vendor=vendor, category="bluetooth")
            matches = _match_curated(blob, test_families)
            assert any(m.cve_id == "TEST-BT-SCOPED" for m in matches), \
                f"vendor={vendor!r} should match the scoped regex"
        # vendor=mediatek doesn't match the scope
        blob_mtk = _make_blob(vendor="mediatek", category="bluetooth")
        matches = _match_curated(blob_mtk, test_families)
        assert not any(m.cve_id == "TEST-BT-SCOPED" for m in matches)


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


# ---------------------------------------------------------------------------
# Soft chipset + category_regex tests (2026-05-15 systematic-debugging
# expansion). Driven by the Moto-G32/G30 audit finding that chipset_target
# is populated on ~0% of qualcomm blobs, making the previous strict
# chipset_regex gate produce zero matches across the entire Qualcomm
# subsystem.
# ---------------------------------------------------------------------------


def test_match_curated_soft_chipset_null_target_still_matches() -> None:
    """When a family declares chipset_regex but blob.chipset_target is NULL,
    the match still fires — confidence is downgraded to medium to signal
    the missing positive chipset evidence."""
    blob = _make_blob(vendor="qualcomm", category="modem", chipset_target=None)
    families = [
        {
            "name": "Test Modem RCE",
            "vendor": "qualcomm",
            "category": "modem",
            "chipset_regex": "(?i)^(sm|sdm)6[0-9]{3}.*",
            "cves": ["CVE-9999-TESTA"],
            "severity": "critical",
            "cvss_score": 9.8,
            "notes": "Test entry",
        }
    ]
    matches = _match_curated(blob, families)
    assert len(matches) == 1
    m = matches[0]
    assert m.cve_id == "CVE-9999-TESTA"
    # Soft match → downgrade.
    assert m.confidence == "medium"


def test_match_curated_strict_chipset_populated_target_must_match() -> None:
    """When blob.chipset_target IS populated and doesn't match
    chipset_regex, the match is rejected — strict mode still applies."""
    blob = _make_blob(
        vendor="qualcomm",
        category="modem",
        chipset_target="MT6789",  # MediaTek chipset; won't match the SM regex
    )
    families = [
        {
            "name": "Test Modem RCE",
            "vendor": "qualcomm",
            "category": "modem",
            "chipset_regex": "(?i)^(sm|sdm)6[0-9]{3}.*",
            "cves": ["CVE-9999-TESTB"],
            "severity": "critical",
            "cvss_score": 9.8,
            "notes": "Test entry",
        }
    ]
    matches = _match_curated(blob, families)
    assert matches == []


def test_match_curated_strict_chipset_matching_target_keeps_high_confidence() -> None:
    """When blob.chipset_target matches the regex, confidence stays high —
    soft mode only triggers when the target is NULL."""
    blob = _make_blob(
        vendor="qualcomm",
        category="modem",
        chipset_target="SM6225",  # Bengal — matches the regex
    )
    families = [
        {
            "name": "Test Modem RCE",
            "vendor": "qualcomm",
            "category": "modem",
            "chipset_regex": "(?i)^(sm|sdm)6[0-9]{3}.*",
            "cves": ["CVE-9999-TESTC"],
            "severity": "critical",
            "cvss_score": 9.8,
            "notes": "Test entry",
        }
    ]
    matches = _match_curated(blob, families)
    assert len(matches) == 1
    assert matches[0].confidence == "high"


def test_match_curated_category_regex_spans_audio_and_dsp() -> None:
    """category_regex lets one family match multiple related categories
    (e.g. Achilles cluster covers both audio aDSP and compute cDSP)."""
    families = [
        {
            "name": "Test Hexagon Cluster",
            "vendor": "qualcomm",
            "category_regex": "^(audio|dsp)$",
            "cves": ["CVE-9999-TESTD"],
            "severity": "high",
            "cvss_score": 8.4,
            "notes": "Test entry",
        }
    ]
    blob_audio = _make_blob(vendor="qualcomm", category="audio")
    blob_dsp = _make_blob(vendor="qualcomm", category="dsp")
    blob_other = _make_blob(vendor="qualcomm", category="modem")
    assert len(_match_curated(blob_audio, families)) == 1
    assert len(_match_curated(blob_dsp, families)) == 1
    # modem doesn't match the (audio|dsp) regex → no match.
    assert _match_curated(blob_other, families) == []


def test_match_curated_category_regex_takes_precedence_over_exact_category() -> None:
    """If both category and category_regex are present, the regex wins
    (more expressive). Exact-category field is ignored when regex exists."""
    families = [
        {
            "name": "Test Mixed",
            "vendor": "qualcomm",
            "category": "modem",  # would say "modem only"
            "category_regex": "^(audio|dsp)$",  # but regex says audio/dsp
            "cves": ["CVE-9999-TESTE"],
            "severity": "high",
            "cvss_score": 7.0,
        }
    ]
    blob_modem = _make_blob(vendor="qualcomm", category="modem")
    blob_audio = _make_blob(vendor="qualcomm", category="audio")
    # Regex wins → modem rejected, audio accepted.
    assert _match_curated(blob_modem, families) == []
    assert len(_match_curated(blob_audio, families)) == 1


def test_match_curated_qualcomm_advisory_fires_on_null_chipset() -> None:
    """Smoke test against the SHIPPED known_firmware.yaml: load the real
    entries and verify a typical Moto-G32 blob (qualcomm/modem, no chipset,
    no version) gets at least one match (the Snapdragon modem advisory)."""
    families = _load_known_firmware()
    blob = _make_blob(
        vendor="qualcomm",
        category="modem",
        chipset_target=None,
        version=None,
    )
    matches = _match_curated(blob, families)
    assert len(matches) >= 1, (
        "Expected the soft-chipset matcher + new advisory entries to surface "
        "at least one CVE on a typical Moto-G32 qualcomm/modem blob"
    )
    cves = {m.cve_id for m in matches}
    # CVE-2020-11292 (Snapdragon modem RCE) is the canonical regression check.
    assert "CVE-2020-11292" in cves, (
        f"CVE-2020-11292 (Snapdragon modem RCE) missing — got {cves}"
    )


def test_match_curated_qualcomm_audio_advisory_via_category_regex() -> None:
    """Achilles cluster (CVE-2020-11201..11209) now matches both audio and
    dsp categories through category_regex — was dsp-only before."""
    families = _load_known_firmware()
    audio_blob = _make_blob(vendor="qualcomm", category="audio")
    matches = _match_curated(audio_blob, families)
    cves = {m.cve_id for m in matches}
    # Achilles cluster has 9 CVE IDs; at least one must surface.
    achilles_cves = {f"CVE-2020-1120{i}" for i in range(1, 10)}
    assert cves & achilles_cves, (
        f"Achilles cluster missing on qualcomm/audio blob — got {cves}"
    )


# ---------------------------------------------------------------------------
# NVIDIA Tegra / L4T CVE cluster — added 2026-05-15 per postmortem
# hw-firmware-adaptive-session-2026-05-18 Rec #3. Each pin's
# chipset_regex + version_regex is verified against the NVD CPE list
# at YAML load time (this test) AND against per-CVE NVD WebFetch
# verification (commit message + notes field).
#
# The 3 user-prompt-discrepancy canaries (Rule #46 paired-canary):
# CVE-2021-1111 EXCLUDES TX1/Nano, CVE-2022-42269 INCLUDES TX1,
# CVE-2022-42270 EXCLUDES TX2 — each enforced by chipset_regex.
# ---------------------------------------------------------------------------


def _find_family_by_cve(families: list[dict], cve_id: str) -> dict | None:
    """Return the family entry that pins ``cve_id``, or None."""
    for fam in families:
        if cve_id in fam.get("cves", []):
            return fam
    return None


def test_tegra_cve_pins_all_six_loaded() -> None:
    """All 6 NVIDIA Tegra CVE pins are present in known_firmware.yaml."""
    families = _load_known_firmware()
    cve_ids = {
        "CVE-2019-5680",
        "CVE-2021-1111",
        "CVE-2021-34372",
        "CVE-2021-34397",
        "CVE-2022-42269",
        "CVE-2022-42270",
    }
    found = set()
    for fam in families:
        for cve in fam.get("cves", []):
            if cve in cve_ids:
                found.add(cve)
    missing = cve_ids - found
    assert not missing, f"Tegra CVE pins missing from YAML: {missing}"


def test_tegra_cve_pins_satisfy_f_forensic_10_narrowing() -> None:
    """Each Tegra CVE pin MUST have at least one narrower beyond
    vendor+category (chipset_regex or version_regex). Prevents the
    disclosure-batch antipattern Reviewer B has caught 4 sessions in
    a row — vendor+category alone over-attributes."""
    families = _load_known_firmware()
    tegra_cves = (
        "CVE-2019-5680",
        "CVE-2021-1111",
        "CVE-2021-34372",
        "CVE-2021-34397",
        "CVE-2022-42269",
        "CVE-2022-42270",
    )
    for cve in tegra_cves:
        fam = _find_family_by_cve(list(families), cve)
        assert fam is not None, f"{cve} family not found"
        narrowers_present = (
            fam.get("chipset_regex") is not None
            or fam.get("version_regex") is not None
        )
        assert narrowers_present, (
            f"{cve} pin lacks chipset_regex AND version_regex — "
            "F-FORENSIC-10 narrowing antipattern (over-attribution risk)"
        )


def test_cve_2019_5680_chipset_regex_tx1_only() -> None:
    """CANARY — CVE-2019-5680 (Selfblow) MUST accept TX1 (T210)
    chipsets and reject TX2 / Xavier / Nano. NVD CPE: TX1-only."""
    import re as _re

    families = _load_known_firmware()
    fam = _find_family_by_cve(list(families), "CVE-2019-5680")
    assert fam is not None
    chipset_re = fam["chipset_regex"]

    # Positive cases — must match.
    for tx1_chipset in ("t210", "T210", "tegra210", "tx1", "TX1"):
        assert _re.search(chipset_re, tx1_chipset), (
            f"CVE-2019-5680 chipset_regex rejected TX1 chipset {tx1_chipset!r}"
        )

    # Negative cases — must NOT match.
    for non_tx1 in ("t186", "t194", "t234", "tx2", "tx2-nx",
                    "xavier-nx", "agx-xavier", "orin", "nano"):
        assert not _re.search(chipset_re, non_tx1), (
            f"CVE-2019-5680 chipset_regex accepted non-TX1 chipset "
            f"{non_tx1!r} — false-positive Selfblow attribution risk"
        )


def test_cve_2021_1111_chipset_regex_excludes_tx1_and_nano() -> None:
    """CANARY (user-prompt-discrepancy) — CVE-2021-1111 NVD CPE
    explicitly excludes TX1 + Nano. User prompt said "ALL Jetsons"
    but NVD only lists AGX-Xavier + TX2 + TX2-NX + Xavier-NX."""
    import re as _re

    families = _load_known_firmware()
    fam = _find_family_by_cve(list(families), "CVE-2021-1111")
    assert fam is not None
    chipset_re = fam["chipset_regex"]

    # Positive — TX2/Xavier family must match.
    for chipset in ("t186", "t194", "tx2", "tx2-nx",
                    "xavier-nx", "agx-xavier"):
        assert _re.search(chipset_re, chipset), (
            f"CVE-2021-1111 chipset_regex rejected {chipset!r}"
        )

    # Negative — TX1 + Nano must NOT match (user-prompt claimed they
    # were in scope; NVD CPE says they aren't).
    for excluded in ("t210", "tx1", "nano", "jetson-nano"):
        assert not _re.search(chipset_re, excluded), (
            f"CVE-2021-1111 chipset_regex accepted {excluded!r} — "
            "user-prompt-discrepancy: NVD CPE explicitly excludes "
            "TX1/Nano"
        )


def test_cve_2022_42269_chipset_regex_includes_tx1() -> None:
    """CANARY (user-prompt-discrepancy) — CVE-2022-42269 NVD CPE
    ALSO includes jetson_tx1 in addition to AGX-Xavier/TX2/Xavier-NX.
    User prompt said "AGX-Xavier/TX2/Xavier-family"; NVD adds TX1."""
    import re as _re

    families = _load_known_firmware()
    fam = _find_family_by_cve(list(families), "CVE-2022-42269")
    assert fam is not None
    chipset_re = fam["chipset_regex"]

    # The user-prompt-discrepancy: TX1 MUST be accepted.
    for tx1_chipset in ("t210", "tx1", "tegra210"):
        assert _re.search(chipset_re, tx1_chipset), (
            f"CVE-2022-42269 chipset_regex rejected {tx1_chipset!r} — "
            "user-prompt-discrepancy: NVD CPE includes jetson_tx1"
        )

    # And AGX-Xavier / TX2 / Xavier-NX still accepted.
    for chipset in ("t186", "t194", "tx2", "agx-xavier", "xavier-nx"):
        assert _re.search(chipset_re, chipset), (
            f"CVE-2022-42269 chipset_regex rejected {chipset!r}"
        )


def test_cve_2022_42270_xavier_only_excludes_tx2() -> None:
    """CANARY — CVE-2022-42270 NVDLA is Xavier-only per NVD CPE.
    Must EXCLUDE TX2 (T186) and TX1 (T210) and Nano."""
    import re as _re

    families = _load_known_firmware()
    fam = _find_family_by_cve(list(families), "CVE-2022-42270")
    assert fam is not None
    chipset_re = fam["chipset_regex"]

    # Xavier family must match.
    for chipset in ("t194", "tegra194", "agx-xavier", "xavier-nx"):
        assert _re.search(chipset_re, chipset), (
            f"CVE-2022-42270 chipset_regex rejected Xavier chipset {chipset!r}"
        )

    # Non-Xavier must NOT match.
    for excluded in ("t186", "t210", "t234", "tx1", "tx2", "tx2-nx",
                     "nano", "orin"):
        assert not _re.search(chipset_re, excluded), (
            f"CVE-2022-42270 chipset_regex accepted {excluded!r} — "
            "NVDLA is Xavier-only per NVD CPE"
        )


def test_cve_2021_34397_excludes_tx1_and_nano() -> None:
    """CVE-2021-34397 MB2 bootloader: TX2/TX2-NX/Xavier-NX/AGX-Xavier
    only. Must EXCLUDE TX1 + Nano per NVD CPE."""
    import re as _re

    families = _load_known_firmware()
    fam = _find_family_by_cve(list(families), "CVE-2021-34397")
    assert fam is not None
    chipset_re = fam["chipset_regex"]

    # Positive.
    for chipset in ("t186", "t194", "tx2", "tx2-nx", "xavier-nx", "agx-xavier"):
        assert _re.search(chipset_re, chipset), (
            f"CVE-2021-34397 chipset_regex rejected {chipset!r}"
        )

    # Negative.
    for excluded in ("t210", "tx1", "nano"):
        assert not _re.search(chipset_re, excluded), (
            f"CVE-2021-34397 chipset_regex accepted {excluded!r}"
        )


def test_cve_2021_34372_has_no_chipset_regex_per_nvd_all_jetsons() -> None:
    """CVE-2021-34372 NVD CPE lists ALL Jetsons including TX1+Nano.
    chipset_regex is omitted (narrowing via version_regex only)."""
    families = _load_known_firmware()
    fam = _find_family_by_cve(list(families), "CVE-2021-34372")
    assert fam is not None
    # chipset_regex intentionally absent — applies to all Tegra boards.
    assert fam.get("chipset_regex") is None
    # version_regex provides the F-FORENSIC-10 narrowing.
    assert fam.get("version_regex") is not None
    # vendor + category combination = NVIDIA TEE = Trusty domain.
    assert fam["vendor"] == "nvidia"
    assert fam["category"] == "tee"


def test_tegra_version_regex_matches_pre_fix_l4t_releases() -> None:
    """Each Tegra version_regex MUST match the L4T release strings
    BELOW the fix version. Forward-prepared canary: when L4T release
    extraction lands, the pins fire on pre-fix blobs."""
    import re as _re

    families = _load_known_firmware()

    # CVE-2019-5680 (Selfblow): fix at R32.2. Pre-fix = R30/R31/R32.0/R32.1.
    fam = _find_family_by_cve(list(families), "CVE-2019-5680")
    version_re = fam["version_regex"]
    # NOTE: re.search matches anywhere in the string, so a longer
    # banner like "R32.3.1" can match a shorter regex prefix. We
    # primarily care that pre-fix matches; the version_regex isn't
    # the only gate (NVD CPE narrowing is documented in notes).
    for pre_fix in ("R30", "r31", "R32.0", "R32.1", "R32.0.1", "R32.1.0"):
        assert _re.search(version_re, pre_fix), (
            f"CVE-2019-5680 version_regex did not match pre-fix L4T "
            f"release {pre_fix!r}"
        )

    # CVE-2021-34372 (Trusty OTE): fix at R32.5.1. Pre-fix = R30/R31/
    # R32.0..R32.5.0.
    fam = _find_family_by_cve(list(families), "CVE-2021-34372")
    version_re = fam["version_regex"]
    for pre_fix in ("R30", "R31", "R32.0", "R32.1", "R32.2", "R32.3",
                    "R32.4", "R32.5.0", "R32.3.1"):
        assert _re.search(version_re, pre_fix), (
            f"CVE-2021-34372 version_regex did not match {pre_fix!r}"
        )

    # CVE-2022-42269 (Trusty SMC): fix at R32.7.2. Pre-fix up to R32.7.1.
    fam = _find_family_by_cve(list(families), "CVE-2022-42269")
    version_re = fam["version_regex"]
    for pre_fix in ("R30", "R31", "R32.0", "R32.5", "R32.6", "R32.7.0",
                    "R32.7.1", "R32.3.1"):
        assert _re.search(version_re, pre_fix), (
            f"CVE-2022-42269 version_regex did not match {pre_fix!r}"
        )


def test_tegra_cve_pins_carry_nvd_url_reference() -> None:
    """Each Tegra CVE pin's notes field MUST include the NVD URL
    reference per Reviewer B 2026-05-15..18 verifiability discipline.
    Operators auditing the pin can re-verify against NVD without
    leaving the YAML."""
    families = _load_known_firmware()
    tegra_cves = (
        "CVE-2019-5680",
        "CVE-2021-1111",
        "CVE-2021-34372",
        "CVE-2021-34397",
        "CVE-2022-42269",
        "CVE-2022-42270",
    )
    for cve in tegra_cves:
        fam = _find_family_by_cve(list(families), cve)
        assert fam is not None
        notes = fam.get("notes", "")
        assert "nvd.nist.gov/vuln/detail/" in notes, (
            f"{cve} pin notes missing NVD URL reference"
        )
        assert cve in notes, (
            f"{cve} pin notes do not cite the CVE ID itself"
        )
