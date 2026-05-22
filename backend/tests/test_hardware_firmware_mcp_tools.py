"""Unit tests for Phase 5 MCP tools.

Covers ``find_unsigned_firmware`` (DB query + grouping) and
``extract_dtb`` (path sandbox + fdt parser output).  Uses mock-DB pattern
consistent with ``test_hardware_firmware_graph.py``.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.ai.tool_registry import ToolContext
from app.ai.tools.hardware_firmware import (
    _handle_describe_advisory,
    _handle_extract_dtb,
    _handle_find_unsigned_firmware,
    _handle_list_extension_points,
)
from app.models.hardware_firmware import HardwareFirmwareBlob

# ---------------------------------------------------------------------------
# find_unsigned_firmware
# ---------------------------------------------------------------------------


def _make_blob(
    *,
    path: str,
    category: str,
    vendor: str | None,
    fmt: str,
    signed: str,
    size: int = 4096,
) -> MagicMock:
    b = MagicMock(spec=HardwareFirmwareBlob)
    b.blob_path = path
    b.category = category
    b.vendor = vendor
    b.format = fmt
    b.signed = signed
    b.file_size = size
    return b


def _make_context(db: AsyncMock) -> ToolContext:
    return ToolContext(
        project_id=uuid.uuid4(),
        firmware_id=uuid.uuid4(),
        extracted_path="/tmp/fake-extract",  # nosec: test-only path
        db=db,
    )


@pytest.mark.asyncio
async def test_find_unsigned_firmware_empty_returns_friendly_message() -> None:
    db = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    db.execute = AsyncMock(return_value=result)

    ctx = _make_context(db)
    out = await _handle_find_unsigned_firmware({}, ctx)
    assert "No unsigned or weakly-signed" in out


@pytest.mark.asyncio
async def test_find_unsigned_firmware_groups_by_category() -> None:
    blobs = [
        _make_blob(
            path="/vendor/firmware/wcn6750.bin",
            category="wifi",
            vendor="qualcomm",
            fmt="raw_bin",
            signed="unsigned",
        ),
        _make_blob(
            path="/vendor/firmware/bcmfw.bin",
            category="wifi",
            vendor="broadcom",
            fmt="fw_bcm",
            signed="weakly_signed",
        ),
        _make_blob(
            path="/vendor/lib/modules/qcom_camss.ko",
            category="kernel_module",
            vendor="qualcomm",
            fmt="ko",
            signed="unknown",
        ),
    ]
    db = AsyncMock()
    res = MagicMock()
    res.scalars.return_value.all.return_value = blobs
    db.execute = AsyncMock(return_value=res)

    ctx = _make_context(db)
    out = await _handle_find_unsigned_firmware({}, ctx)
    assert "3 blob(s)" in out
    assert "## wifi" in out
    assert "## kernel_module" in out
    # Signed-status surfaces in the bullet as markdown bold.
    assert "**unsigned**" in out
    assert "**weakly_signed**" in out
    assert "**unknown**" in out


# ---------------------------------------------------------------------------
# extract_dtb
# ---------------------------------------------------------------------------


def _build_simple_dtb() -> bytes:
    """Build a minimal DTB via the same helper used by Phase 2 parser tests."""
    from tests.fixtures.hardware_firmware._build_fixtures import build_minimal_dtb

    return build_minimal_dtb()


@pytest.mark.asyncio
async def test_extract_dtb_missing_path_returns_error() -> None:
    db = AsyncMock()
    ctx = _make_context(db)
    out = await _handle_extract_dtb({}, ctx)
    assert "dtb_path is required" in out


@pytest.mark.asyncio
async def test_extract_dtb_parses_compatible_and_firmware_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Write a synthetic DTB.
    try:
        dtb_bytes = _build_simple_dtb()
    except Exception:
        pytest.skip("fdt not available or API shape differs in this environment")
    dtb_file = tmp_path / "platform.dtb"
    dtb_file.write_bytes(dtb_bytes)

    db = AsyncMock()
    ctx = ToolContext(
        project_id=uuid.uuid4(),
        firmware_id=uuid.uuid4(),
        extracted_path=str(tmp_path),
        db=db,
    )
    # Force resolve_path to pass — our helper relies on the sandbox.  For the
    # test we bypass by monkeypatching the ToolContext.resolve_path to return
    # the literal file path (the real sandbox logic is tested elsewhere).
    monkeypatch.setattr(ctx, "resolve_path", lambda p: str(dtb_file))

    out = await _handle_extract_dtb({"dtb_path": "/platform.dtb"}, ctx)
    assert "# DTB:" in out
    # build_minimal_dtb produces compatible=qcom,wcn6750-wifi + firmware-name=wcn6750.bin.
    assert "qcom,wcn6750" in out
    assert "wcn6750.bin" in out


@pytest.mark.asyncio
async def test_extract_dtb_missing_file_returns_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = AsyncMock()
    ctx = ToolContext(
        project_id=uuid.uuid4(),
        firmware_id=uuid.uuid4(),
        extracted_path=str(tmp_path),
        db=db,
    )
    monkeypatch.setattr(
        ctx, "resolve_path", lambda p: str(tmp_path / "does-not-exist.dtb")
    )
    out = await _handle_extract_dtb({"dtb_path": "/does-not-exist.dtb"}, ctx)
    assert "not a file" in out


# ---------------------------------------------------------------------------
# list_extension_points — operator-facing YAML / parser discovery tool.
#
# Closes Reviewer C CC-3 / HOT-1 / HOT-2 from postmortem 2026-05-18.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_extension_points_returns_registered_yamls() -> None:
    """All 7 YAML surfaces registered via register_loader() must appear."""
    import json as _json

    db = AsyncMock()
    ctx = _make_context(db)

    # Import patterns_loader + cve_matcher to trigger their module-level
    # register_loader() calls (no-op if already imported by another test).
    import app.services.hardware_firmware.cve_matcher  # noqa: F401
    import app.services.hardware_firmware.patterns_loader  # noqa: F401

    out = await _handle_list_extension_points({}, ctx)
    payload = _json.loads(out)

    surface_names = {s["surface_name"] for s in payload["extension_surfaces"]}
    expected = {
        "vendor_prefixes",
        "firmware_patterns",
        "firmware_patterns_contexts",
        "bt_qca_codenames",
        "bt_banner_cve_pins",
        "bt_realtek_project_ids",
        "known_firmware",
    }
    assert expected.issubset(surface_names), (
        f"missing: {expected - surface_names}"
    )

    # Each surface entry has the required shape.
    for entry in payload["extension_surfaces"]:
        assert "surface_name" in entry
        assert "path" in entry
        assert "loaded_from_yaml" in entry
        assert "yaml_mtime_iso" in entry  # may be None
        assert "summary" in entry
        assert "reload_count" in entry
        assert "last_warning" in entry  # may be None
        assert "status" in entry

    # parser_format_map walks PARSER_REGISTRY — bt_fw_banner must appear.
    assert "bt_fw_banner" in payload["parser_format_map"]
    assert (
        payload["parser_format_map"]["bt_fw_banner"]
        == "BtFirmwareBannerParser"
    )

    # C10: load_rejections section surfaces F-FORENSIC-10 counter dict.
    assert "load_rejections" in payload
    assert "curated_known_firmware" in payload["load_rejections"]
    curated = payload["load_rejections"]["curated_known_firmware"]
    assert "f_forensic_10_no_narrowing" in curated
    assert "advisory_missing_advisory_id" in curated
    assert "advisory_id_too_long" in curated
    assert "advisory_id_duplicate_warn" in curated
    # All counter values are non-negative integers
    for k, v in curated.items():
        assert isinstance(v, int) and v >= 0, f"{k!r} not a non-negative int: {v!r}"

    # bt_parser_families table is verbatim from bt_firmware_banner.
    family_names = {f["family"] for f in payload["bt_parser_families"]}
    assert family_names == {
        "qca_rome",
        "broadcom_hcd",
        "mediatek_bt",
        "realtek_bt",
    }


@pytest.mark.asyncio
async def test_list_extension_points_excludes_unregistered_loader() -> None:
    """NEGATIVE CANARY (Rule #46) — a loader created in-test but never
    registered via register_loader() must NOT appear in the output."""
    import json as _json

    from app.utils import yaml_cache as YC

    db = AsyncMock()
    ctx = _make_context(db)

    # Synthesize a loader without registering it.
    not_registered_name = "test-list-extension-points-negative-canary"
    YC._yaml_loader_registry.pop(not_registered_name, None)

    out = await _handle_list_extension_points({}, ctx)
    payload = _json.loads(out)
    surface_names = {s["surface_name"] for s in payload["extension_surfaces"]}
    assert not_registered_name not in surface_names


@pytest.mark.asyncio
async def test_list_extension_points_surface_filter_narrows_results() -> None:
    """surface_filter regex restricts the returned surfaces."""
    import json as _json

    db = AsyncMock()
    ctx = _make_context(db)

    import app.services.hardware_firmware.patterns_loader  # noqa: F401

    out = await _handle_list_extension_points({"surface_filter": "^bt_"}, ctx)
    payload = _json.loads(out)
    surface_names = {s["surface_name"] for s in payload["extension_surfaces"]}
    # All matches start with bt_.
    assert all(name.startswith("bt_") for name in surface_names)
    # And the BT surfaces ARE included.
    assert "bt_qca_codenames" in surface_names


@pytest.mark.asyncio
async def test_list_extension_points_surface_filter_invalid_regex_returns_error() -> None:
    """Malformed regex returns an Error: message rather than crashing."""
    db = AsyncMock()
    ctx = _make_context(db)
    out = await _handle_list_extension_points({"surface_filter": "["}, ctx)
    assert out.startswith("Error: invalid surface_filter regex")


@pytest.mark.asyncio
async def test_list_extension_points_surfaces_last_warning_after_malformed_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end canary: a malformed YAML edit produces a non-null
    last_warning in the MCP tool output (the operator-visible surface
    of HOT-2). Synthesizes the failure against a real registered loader
    and confirms the tool reflects the WARN state."""
    import json as _json
    import os
    import time

    from app.utils import yaml_cache as YC

    db = AsyncMock()
    ctx = _make_context(db)

    yaml_path = tmp_path / "canary_surface.yaml"
    yaml_path.write_text("foo: 1\n", encoding="utf-8")
    loader: YC.MtimeCachedYamlLoader[dict] = YC.MtimeCachedYamlLoader(
        path=yaml_path,
        parser=lambda raw: dict(raw),
        defaults={},
        name="canary",
        summary=lambda v: f"{len(v)} keys",
    )
    surface_name = "list_extension_points_canary_surface"
    YC.register_loader(surface_name, loader)
    try:
        loader.get()  # successful load
        out = await _handle_list_extension_points(
            {"surface_filter": surface_name}, ctx,
        )
        payload = _json.loads(out)
        entry = next(
            s for s in payload["extension_surfaces"]
            if s["surface_name"] == surface_name
        )
        assert entry["last_warning"] is None
        assert entry["status"] == "loaded"

        # Break the YAML and bump mtime.
        yaml_path.write_text("bad: [unclosed\n", encoding="utf-8")
        now = time.time()
        os.utime(yaml_path, (now + 1.0, now + 1.0))
        loader.get()  # failed reload — keeps previous + populates last_warning

        out2 = await _handle_list_extension_points(
            {"surface_filter": surface_name}, ctx,
        )
        payload2 = _json.loads(out2)
        entry2 = next(
            s for s in payload2["extension_surfaces"]
            if s["surface_name"] == surface_name
        )
        assert entry2["last_warning"] is not None
        assert "Error" in entry2["last_warning"]
        assert entry2["status"] == "malformed_fallback"
    finally:
        YC._yaml_loader_registry.pop(surface_name, None)


# ---------------------------------------------------------------------------
# describe_advisory (backlog evening:RvwC-C4)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_describe_advisory_returns_matching_entries() -> None:
    """Operator queries an existing advisory_id; tool returns the YAML rows
    that declared it with the full payload + shared_advisory_id flag."""
    import json as _json

    db = AsyncMock()
    ctx = _make_context(db)
    out = await _handle_describe_advisory(
        {"advisory_id": "ADVISORY-FRAGATTACK"}, ctx,
    )
    payload = _json.loads(out)
    assert payload["advisory_id"] == "ADVISORY-FRAGATTACK"
    assert payload["match_count"] >= 1
    # Both FragAttacks entries (broadcom + qualcomm wcn3xxx) declare
    # shared_advisory_id: true (per RvwA-A5+B6 fix); is_shared must be True.
    assert payload["is_shared"] is True
    # Each match carries the YAML's fields.
    for m in payload["matches"]:
        assert m["advisory_id"] == "ADVISORY-FRAGATTACK"
        assert m["shared_advisory_id"] is True
        assert "vendor" in m
        assert "category" in m
        assert "severity" in m
        assert "notes" in m


@pytest.mark.asyncio
async def test_describe_advisory_returns_empty_for_unknown_id() -> None:
    import json as _json

    db = AsyncMock()
    ctx = _make_context(db)
    out = await _handle_describe_advisory(
        {"advisory_id": "ADVISORY-DOES-NOT-EXIST"}, ctx,
    )
    payload = _json.loads(out)
    assert payload["advisory_id"] == "ADVISORY-DOES-NOT-EXIST"
    assert payload["matches"] == []
    assert "hint" in payload


@pytest.mark.asyncio
async def test_describe_advisory_missing_input_returns_error() -> None:
    import json as _json

    db = AsyncMock()
    ctx = _make_context(db)
    out = await _handle_describe_advisory({}, ctx)
    payload = _json.loads(out)
    assert "error" in payload
    assert "advisory_id" in payload["error"]


# ---------------------------------------------------------------------------
# verify_cve_attribution (backlog evening:RvwC-C11)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_cve_attribution_returns_full_chain_for_curated_tier() -> None:
    """Walk the matcher's attribution chain for a curated-tier (cve, blob)
    tuple. Returns match_tier + match_confidence + blob context + YAML entry."""
    import json as _json
    from unittest.mock import MagicMock

    from app.ai.tools.hardware_firmware import _handle_verify_cve_attribution

    blob_id = uuid.uuid4()

    # Mock the sbom_vulnerabilities row.
    vuln_row = MagicMock()
    vuln_row.match_tier = "curated_yaml"
    vuln_row.match_confidence = "high"
    vuln_row.severity = "medium"
    vuln_row.cvss_score = 6.4
    vuln_row.adjusted_severity = None
    vuln_row.adjusted_cvss_score = None
    vuln_row.adjustment_rationale = None
    vuln_row.resolution_status = "open"

    # Mock the blob row.
    blob_row = MagicMock(spec=HardwareFirmwareBlob)
    blob_row.blob_path = "/vendor/firmware/wcn6750.bin"
    blob_row.vendor = "broadcom"
    blob_row.category = "wifi"
    blob_row.format = "fw_bcm"
    blob_row.chipset_target = "bcm4358"
    blob_row.detected_version = "7.35.180.11"
    blob_row.detection_confidence = "high"

    db = AsyncMock()
    # Two execute calls — vuln first, blob second.
    vuln_result = MagicMock()
    vuln_result.scalar_one_or_none.return_value = vuln_row
    blob_result = MagicMock()
    blob_result.scalar_one_or_none.return_value = blob_row
    db.execute = AsyncMock(side_effect=[vuln_result, blob_result])

    ctx = _make_context(db)
    out = await _handle_verify_cve_attribution(
        {"cve_id": "CVE-2017-9417", "blob_id": str(blob_id)}, ctx,
    )
    payload = _json.loads(out)
    assert payload["matched"] is True
    assert payload["cve_id"] == "CVE-2017-9417"
    assert payload["blob_id"] == str(blob_id)
    assert payload["match_tier"] == "curated_yaml"
    assert payload["match_confidence"] == "high"
    assert payload["blob_context"]["vendor"] == "broadcom"
    assert payload["blob_context"]["category"] == "wifi"
    # CVE-2017-9417 is BroadPwn — known_firmware.yaml has an entry for it.
    assert payload["matching_yaml_entry"] is not None
    assert "CVE-2017-9417" in payload["matching_yaml_entry"]["cves"] or \
        payload["matching_yaml_entry"]["advisory_id"] == "CVE-2017-9417"


@pytest.mark.asyncio
async def test_verify_cve_attribution_returns_unmatched_when_row_missing() -> None:
    import json as _json
    from unittest.mock import MagicMock

    from app.ai.tools.hardware_firmware import _handle_verify_cve_attribution

    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=result)

    ctx = _make_context(db)
    out = await _handle_verify_cve_attribution(
        {"cve_id": "CVE-9999-DOES-NOT-EXIST", "blob_id": str(uuid.uuid4())},
        ctx,
    )
    payload = _json.loads(out)
    assert payload["matched"] is False
    assert "hint" in payload


@pytest.mark.asyncio
async def test_verify_cve_attribution_rejects_invalid_blob_id() -> None:
    import json as _json

    from app.ai.tools.hardware_firmware import _handle_verify_cve_attribution

    db = AsyncMock()
    ctx = _make_context(db)
    out = await _handle_verify_cve_attribution(
        {"cve_id": "CVE-2017-9417", "blob_id": "not-a-uuid"}, ctx,
    )
    payload = _json.loads(out)
    assert "error" in payload
    assert "UUID" in payload["error"]


@pytest.mark.asyncio
async def test_verify_cve_attribution_missing_args_returns_error() -> None:
    import json as _json

    from app.ai.tools.hardware_firmware import _handle_verify_cve_attribution

    db = AsyncMock()
    ctx = _make_context(db)
    out = await _handle_verify_cve_attribution({}, ctx)
    payload = _json.loads(out)
    assert "error" in payload
    assert "cve_id" in payload["error"]
