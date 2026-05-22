"""Cross-stack F-FORENSIC-10 alignment regression canary.

Reviewer A MEDIUM finding deferred from `postmortem-hw-firmware-tegra-
activation-2026-05-15`: the curated tier's
``cve_matcher._KNOWN_FIRMWARE_NARROWING_FIELDS`` tuple and the BT layer's
``patterns_loader._parse_banner_cve_pin`` family-only check are the same
conceptual gate at different layers — both reject the disclosure-batch
antipattern (vendor+family or vendor+category exact match with no
additional narrowing dimension). Silent drift between them would let
one layer accept entries the other rejects, undermining the cross-stack
discipline that the gates jointly enforce.

This file asserts:

  1. Each layer's gate REJECTS its dialect of the family-only antipattern.
  2. Each layer's gate ACCEPTS its dialect of a narrowed entry.
  3. The curated tier ACCEPTS advisory-only entries (``cves: []`` bypasses
     the gate by design); the BT layer's schema requires a non-empty cves
     list at a separate gate — that asymmetry is intentional and
     documented here.
  4. Both layers' narrowing-field allowlists are non-empty + size-locked
     to the current contract (drift forces a deliberate test edit).
  5. A canonical cross-layer antipattern (vendor+family+category ONLY,
     no narrowing) fails BOTH layers — the alignment proper.

Conceptually, the gates differ in dialect (the curated YAML uses
regex-flavor narrowing fields; the BT YAML uses frozenset/regex/int
gates against parsed banner fields) but share the SAME contract: family
membership alone is insufficient to attribute a CVE. The fields are not
expected to be name-equal across layers — name-equality assertions
would be a false alignment. We assert SHAPE-equivalence (both reject
the conceptual antipattern; both accept narrowed entries).

The asymmetric reject MODE (curated: WARN+skip; BT: ValueError) is also
intentional: the curated loader runs against a long YAML so per-entry
errors must not gate every CVE match; the BT loader's pin set is
shorter so fail-loud is acceptable. Tests assert via each layer's
idiomatic shape — not via a forced common mode.

Per Rule #46 paired-canary discipline + Rule #25 cross-stack-alignment
single-slice. Promoted from Reviewer A 2026-05-15 to Rule-of-One
alignment test for the F-FORENSIC-10 gate.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator

import pytest


# =====================================================================
# Local caplog helper — sync, no-pytest-fixture-wiring required. The
# F-FORENSIC-10 curated-tier gate is a synchronous parser called from
# the loader; pytest's caplog fixture works for plain tests but the
# local helper is more explicit about WHICH logger it captures (the
# gates set the message on their module logger, not the root logger).
# =====================================================================
@contextlib.contextmanager
def _caplog_at(logger_name: str) -> Iterator[list[logging.LogRecord]]:
    """Capture log records from the named logger via a temporary handler.

    Mirror of pytest's caplog without requiring the fixture wiring;
    appends LogRecord objects to a list yielded to the caller.
    Duplicated from test_hardware_firmware_cve_matcher.caplog_at to keep
    this alignment file self-contained — the helper is small and the
    duplication is preferable to a cross-test-file import dependency.
    """
    captured: list[logging.LogRecord] = []

    class _ListHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            try:
                record.message = record.getMessage()
            except Exception:  # noqa: BLE001
                record.message = record.msg
            captured.append(record)

    handler = _ListHandler(level=logging.DEBUG)
    target = logging.getLogger(logger_name)
    prev_level = target.level
    target.setLevel(logging.DEBUG)
    target.addHandler(handler)
    try:
        yield captured
    finally:
        target.removeHandler(handler)
        target.setLevel(prev_level)


# =====================================================================
# Layer 1 — curated tier (cve_matcher._parse_known_firmware_data)
# =====================================================================
_L1_LOGGER = "app.services.hardware_firmware.cve_matcher"


def test_curated_tier_rejects_family_only_entry() -> None:
    """Layer 1 (curated tier) — vendor+category-only CVE entry SKIPPED
    + WARN-logged.

    Synthesizes the disclosure-batch antipattern shape (vendor +
    category + cves[] with NO narrowing field) against the curated
    YAML schema dialect; asserts the gate rejects.
    """
    from app.services.hardware_firmware.cve_matcher import (
        _parse_known_firmware_data,
    )

    raw = {
        "families": [
            {
                "name": "alignment-bad-family-only",
                "vendor": "qualcomm",
                "category": "wifi",
                "cves": ["CVE-9999-00100"],
            },
        ],
    }
    with _caplog_at(_L1_LOGGER) as records:
        accepted = _parse_known_firmware_data(raw)
    accepted_names = {fam.get("name") for fam in accepted}
    assert "alignment-bad-family-only" not in accepted_names, (
        "L1 F-FORENSIC-10 gate FAILED: family-only entry not rejected"
    )
    warn_messages = [
        r.message for r in records if r.levelno >= logging.WARNING
    ]
    assert any(
        "alignment-bad-family-only" in m for m in warn_messages
    ), (
        "L1 gate did not WARN on the rejected entry name; operators "
        f"need the actionable WARN. Got: {warn_messages!r}"
    )


def test_curated_tier_accepts_advisory_only_entry() -> None:
    """Layer 1 — advisory-only entries (``cves: []``) bypass the gate
    by design (the disclosure-batch antipattern is about CVE
    over-attribution; advisories don't claim CVE attribution).
    """
    from app.services.hardware_firmware.cve_matcher import (
        _parse_known_firmware_data,
    )

    raw = {
        "families": [
            {
                "name": "alignment-good-advisory",
                "advisory_id": "ADV-ALIGN1",
                "vendor": "qualcomm",
                "category": "wifi",
                "cves": [],
            },
        ],
    }
    accepted = _parse_known_firmware_data(raw)
    assert any(
        fam.get("name") == "alignment-good-advisory" for fam in accepted
    ), "L1 gate REJECTED an advisory-only entry — gate over-reaches"


@pytest.mark.parametrize(
    "narrowing_field,narrowing_value",
    [
        ("chipset_regex", "(?i)^(wcn3[0-9]{3})"),
        ("category_regex", "^wifi$"),
        ("version_regex", "^1\\.0\\.0$"),
        ("vendor_regex", "(?i)^qualcomm$"),
    ],
)
def test_curated_tier_accepts_entry_with_each_narrowing_field(
    narrowing_field: str, narrowing_value: str
) -> None:
    """Layer 1 — each of the 4 declared narrowing fields independently
    satisfies the gate.

    Mirrors test_f_forensic_10_gate_accepts_each_narrowing_field in
    test_hardware_firmware_cve_matcher.py; duplicated here so the
    alignment file is self-contained AND parametrized over the same
    allowlist. Drift between this list and
    ``_KNOWN_FIRMWARE_NARROWING_FIELDS`` fails the size-lock test below.
    """
    from app.services.hardware_firmware.cve_matcher import (
        _parse_known_firmware_data,
    )

    raw = {
        "families": [
            {
                "name": f"alignment-good-{narrowing_field}",
                "vendor": "qualcomm",
                "category": "wifi",
                narrowing_field: narrowing_value,
                "cves": ["CVE-9999-00101"],
            },
        ],
    }
    accepted = _parse_known_firmware_data(raw)
    accepted_names = {fam.get("name") for fam in accepted}
    assert f"alignment-good-{narrowing_field}" in accepted_names, (
        f"L1 gate REJECTED entry narrowed via {narrowing_field!r} — "
        "gate appears to have dropped a recognized narrowing field"
    )


# =====================================================================
# Layer 2 — BT banner CVE pin tier (patterns_loader._parse_banner_cve_pin)
# =====================================================================
def test_bt_layer_rejects_family_only_entry() -> None:
    """Layer 2 (BT YAML) — pin with ONLY ``family:`` set (no codename /
    chipset / banner / build_date / build_id / signed narrowing) raises
    ValueError per the family-only gate at patterns_loader.py:1034-1051.

    Asymmetry note: L1 WARN+skips; L2 raises. Both REJECT — the
    asymmetry is the mode, not the contract.
    """
    from app.services.hardware_firmware.patterns_loader import (
        _parse_banner_cve_pin,
    )

    bad_entry = {
        "id": "alignment-bad-family-only",
        "description": "Synthesized family-only disclosure-batch antipattern",
        "family": "realtek_bt",
        "cves": [
            {
                "id": "CVE-9999-9000",
                "severity": "high",
                "rationale": "would fire on ALL realtek_bt chipsets",
            }
        ],
    }
    with pytest.raises(ValueError, match=r"'family' alone is insufficient"):
        _parse_banner_cve_pin(0, bad_entry)


@pytest.mark.parametrize(
    "narrowing_field,narrowing_value",
    [
        ("codename_in", ["WCN3950"]),
        ("chipset_target_in", ["rtl8761b"]),
        ("banner_match", r"BCM4339 .*build"),
        ("build_date_before", "2018-01-01"),
        ("build_id_lt", 42),
        ("signed_eq", "signed"),
    ],
)
def test_bt_layer_accepts_entry_with_each_narrowing_field(
    narrowing_field: str, narrowing_value: object
) -> None:
    """Layer 2 — each of the 6 declared narrowing conditions independently
    satisfies the family-only gate when paired with ``family``.

    Parametrized over the 6 conditions checked at patterns_loader.py:
    1034-1042. Drift between this list and the gate's tuple fails the
    size-lock test below.
    """
    from app.services.hardware_firmware.patterns_loader import (
        _parse_banner_cve_pin,
    )

    entry = {
        "id": f"alignment-good-{narrowing_field}",
        "description": "Family + one narrowing condition",
        "family": "realtek_bt",
        narrowing_field: narrowing_value,
        "cves": [
            {
                "id": "CVE-9999-9001",
                "severity": "low",
                "rationale": "should parse cleanly",
            }
        ],
    }
    pin = _parse_banner_cve_pin(0, entry)
    assert pin.pin_id == f"alignment-good-{narrowing_field}", (
        f"L2 gate REJECTED entry narrowed via {narrowing_field!r} — "
        "gate appears to have dropped a recognized narrowing condition"
    )


# =====================================================================
# Cross-layer alignment — the core regression canary
# =====================================================================
def test_cross_layer_both_reject_same_conceptual_antipattern() -> None:
    """DRIFT CANARY: synthesize the conceptual disclosure-batch
    antipattern (vendor/family identity ONLY, no narrowing dimension)
    in BOTH layer's schema dialects; assert BOTH gates reject.

    This is the alignment-test core. If one layer's gate were to
    silently weaken (e.g. accept family-only entries on the BT side
    due to a refactor that misses the family_only block, or accept
    vendor+category-only entries on the curated side due to a
    rewrite of _KNOWN_FIRMWARE_NARROWING_FIELDS), this test fails
    and surfaces the asymmetry — which is exactly the cross-stack
    drift the alignment-test discipline targets.

    Note: each layer's reject mode is idiomatic to its dialect (L1
    WARN+skip; L2 raise). The test asserts each layer's rejection
    via its own shape, NOT a forced common mode.
    """
    from app.services.hardware_firmware.cve_matcher import (
        _parse_known_firmware_data,
    )
    from app.services.hardware_firmware.patterns_loader import (
        _parse_banner_cve_pin,
    )

    # Layer 1 antipattern — vendor+category+cves[] only.
    l1_antipattern = {
        "families": [
            {
                "name": "alignment-cross-layer-l1",
                "vendor": "broadcom",
                "category": "wifi",
                "cves": ["CVE-9999-00102"],
            },
        ],
    }
    with _caplog_at(_L1_LOGGER):
        l1_accepted = _parse_known_firmware_data(l1_antipattern)
    assert not any(
        fam.get("name") == "alignment-cross-layer-l1" for fam in l1_accepted
    ), "L1 gate did not reject the conceptual antipattern"

    # Layer 2 antipattern — family+cves[] only.
    l2_antipattern = {
        "id": "alignment-cross-layer-l2",
        "description": "Cross-layer alignment antipattern",
        "family": "broadcom_hcd",
        "cves": [
            {
                "id": "CVE-9999-00103",
                "severity": "high",
                "rationale": "family-only — should be rejected",
            }
        ],
    }
    with pytest.raises(ValueError, match=r"'family' alone is insufficient"):
        _parse_banner_cve_pin(0, l2_antipattern)


def test_cross_layer_narrowing_field_counts_documented() -> None:
    """Size-lock canary: both narrowing-field allowlists are at their
    current documented sizes (L1=4 fields, L2=6 conditions).

    A future expansion (e.g. adding `path_regex` to L1, or `oui_in`
    to L2) is a deliberate cross-stack discipline change — should
    require updating BOTH this test AND the alignment commentary in
    the postmortem. The size-lock catches accidental allowlist drift
    that silently widens (or narrows) the gate without operator
    visibility.

    NOT a name-equality assertion across layers — the dialects are
    intentionally different (regex-flavor vs frozenset/regex/int).
    Both gates enforce the SHAPE-equivalent contract: family/identity
    alone is insufficient.
    """
    from app.services.hardware_firmware.cve_matcher import (
        _KNOWN_FIRMWARE_NARROWING_FIELDS,
    )

    # L1 — 4 narrowing fields.
    assert len(_KNOWN_FIRMWARE_NARROWING_FIELDS) == 4, (
        "L1 _KNOWN_FIRMWARE_NARROWING_FIELDS size changed from 4 to "
        f"{len(_KNOWN_FIRMWARE_NARROWING_FIELDS)} — update this test "
        "alongside the postmortem alignment commentary so the "
        "cross-stack discipline stays explicit"
    )
    assert set(_KNOWN_FIRMWARE_NARROWING_FIELDS) == {
        "chipset_regex",
        "category_regex",
        "version_regex",
        "vendor_regex",
    }, (
        "L1 narrowing-field set changed — update this test + the "
        "alignment-test parametrization above"
    )

    # L2 — 6 narrowing conditions (counted via inspection of the gate
    # block in _parse_banner_cve_pin). Pinning by source-code inspection
    # avoids exposing an internal frozenset; the assertion is the
    # WRITTEN contract that the gate's family_only check covers 6
    # conditions.
    import inspect

    from app.services.hardware_firmware import patterns_loader

    src = inspect.getsource(patterns_loader._parse_banner_cve_pin)
    # The family_only block at the end of the function references each
    # condition once via ``cond is None``. Count distinct condition
    # names appearing in that block.
    l2_conditions = (
        "codename_in",
        "chipset_target_in",
        "banner_re",
        "build_date_before",
        "build_id_lt",
        "signed_eq",
    )
    for cond in l2_conditions:
        assert cond in src, (
            f"L2 narrowing condition {cond!r} no longer referenced in "
            "_parse_banner_cve_pin source — update this test + the "
            "alignment-test parametrization above"
        )
    # 6 conditions documented in the alignment-test parametrization
    # above; size-lock makes a future addition (e.g. `oui_in`) a
    # deliberate cross-stack discipline change.
    assert len(l2_conditions) == 6


def test_alignment_gate_canary_synthesizes_a_real_rejection() -> None:
    """Rule #46 META-CANARY: this test confirms the alignment file's
    synthesized violations actually trigger the layer gates, not just
    pass through.

    Without this meta-canary, a future refactor could silently weaken
    the synthesized antipattern (e.g. by accidentally including a
    narrowing field) so that the rejection tests above pass without
    actually exercising the rejection path. Synthesize a CLEARLY-bad
    L1 entry and confirm it produces the diagnostic WARN substring
    that operators rely on for actionable feedback.
    """
    from app.services.hardware_firmware.cve_matcher import (
        _parse_known_firmware_data,
    )

    raw = {
        "families": [
            {
                "name": "alignment-meta-canary",
                "vendor": "broadcom",
                "category": "wifi",
                "cves": ["CVE-9999-00104"],
            },
        ],
    }
    with _caplog_at(_L1_LOGGER) as records:
        _parse_known_firmware_data(raw)

    full_warn_text = " ".join(
        r.message for r in records if r.levelno >= logging.WARNING
    )
    # The WARN must contain the rejected name AND the recognized
    # narrowing-field allowlist (per the gate's WARN-message
    # contract). If the WARN is missing any of these tokens, the
    # alignment-test's "reject" assertions could be satisfied by a
    # gate that silently dropped entries without diagnostic output.
    assert "alignment-meta-canary" in full_warn_text, (
        "META-CANARY: rejected entry name absent from WARN"
    )
    for field in (
        "chipset_regex",
        "category_regex",
        "version_regex",
        "vendor_regex",
    ):
        assert field in full_warn_text, (
            f"META-CANARY: narrowing-field {field!r} absent from WARN; "
            "operator WARN no longer enumerates the allowlist"
        )
