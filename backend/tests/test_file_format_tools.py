"""P3.1.c MCP-tool handler tests for the file-format YAML registry.

Tests call the handlers DIRECTLY (no MCP dispatch layer) so we exercise the
pure logic surface. The three tools are STATELESS — no DB writes — so the
``ToolContext`` is a thin stub with a non-functional db / project / firmware
field (none of the handlers touch them).

Coverage shape:

* Happy paths — validate clean YAML; validate-with-blob magic match;
  validate-with-blob magic mismatch; list_file_formats; vendor / category
  filters; collision-audit clean catalog; collision-audit synthesized
  collision.
* Rejection paths — typo on confidence Literal; unknown ``extra=forbid``
  field; YAML syntax error.
* Rule #46 META-CANARIES — token-scan ``file_formats.py`` for ``.errors()``;
  token-scan for ``_render_validation_error_safe`` invocation; redaction
  shape for secret-shaped inputs; paired canary that the redactor fires;
  A4-collision (cross-vendor same-source) excluded; same-vendor collision
  surfaced.
* Live canary (Rule #35b) — realistic Medtronic MMTP YAML round-trips
  cleanly through ``validate_file_format``.
"""
from __future__ import annotations

import asyncio
import json
import re
import tokenize
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import yaml

from app.ai.tools.file_formats import (
    _handle_cross_firmware_format_collision_audit,
    _handle_list_file_formats,
    _handle_validate_file_format,
    _redact_input_value,
    _render_validation_error_operator,
    _render_validation_error_safe,
    register_file_format_tools,
)
from app.ai.tool_registry import ToolContext, ToolRegistry
from app.schemas.file_format import FileFormatManifest
from app.services.file_format_catalog import (
    FormatCatalog,
    PLUGIN_REGISTRY,
)
from app.services.file_format_catalog.resolver import (
    _unfreeze_plugin_registry_for_tests,
)


# ---------------------------------------------------------------------------
# Helpers + fixtures.
# ---------------------------------------------------------------------------


def _stub_context() -> ToolContext:
    """Minimal ToolContext — handlers in this module DO NOT touch db / paths."""
    return ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path="/tmp/__unused_in_p3_1_c__",
        db=None,  # type: ignore[arg-type]  # handlers don't touch db
    )


def _minimal_manifest_yaml(
    *,
    format_id: str = "test_fmt",
    manifest_source: str = "operator",
    precedence: int = 200,
    vendor: str = "test_vendor",
    category: str = "test_category",
    confidence: str = "high",
    bytes_hex: str = "4d4d5450",  # "MMTP" — 4 bytes, clears the 2-byte floor
    offset: int = 0,
    notes: str | None = None,
    extras: dict | None = None,
) -> str:
    """Render a YAML string for a minimal-valid manifest."""
    data: dict[str, Any] = {
        "schema_version": 1,
        "format_id": format_id,
        "manifest_source": manifest_source,
        "precedence": precedence,
        "category": category,
        "vendor": vendor,
        "confidence": confidence,
        "detection": {
            "combine": "all_required",
            "signals": [
                {
                    "kind": "magic_bytes",
                    "offset": offset,
                    "bytes_hex": bytes_hex,
                    "description": "test magic",
                },
            ],
        },
        "output": {
            "classifier_format": format_id,
            "classifier_category": category,
            "classifier_vendor": vendor,
            "confidence": confidence,
        },
    }
    if notes is not None:
        data["notes"] = notes
    if extras:
        data.update(extras)
    return yaml.safe_dump(data)


@pytest.fixture(autouse=True)
def _reset_default_catalog(tmp_path, monkeypatch):
    """Replace the module-level _DEFAULT_CATALOG with a clean tmp_path one.

    The MCP handlers reach into ``get_default_catalog()`` directly; tests
    require a stable, empty catalog so the audit + collision tests don't pick
    up production YAML drift. We monkeypatch in a fresh ``FormatCatalog``
    rooted at tmp_path/system + tmp_path/local for each test.
    """
    system_root = tmp_path / "system"
    local_root = tmp_path / "local"
    system_root.mkdir()
    local_root.mkdir()
    new_catalog = FormatCatalog(
        root_resolver=lambda: system_root,
        local_root_resolver=lambda: local_root,
    )
    import app.services.file_format_catalog.catalog as catalog_mod
    monkeypatch.setattr(catalog_mod, "_DEFAULT_CATALOG", new_catalog)
    # Plugin registry reset between tests.
    saved = dict(PLUGIN_REGISTRY)
    _unfreeze_plugin_registry_for_tests()
    PLUGIN_REGISTRY.clear()
    yield (system_root, local_root, new_catalog)
    PLUGIN_REGISTRY.clear()
    PLUGIN_REGISTRY.update(saved)
    _unfreeze_plugin_registry_for_tests()


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def _run(coro):
    """Synchronously run an async handler. asyncio.run for one-shot test calls."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Happy paths.
# ---------------------------------------------------------------------------


def test_validate_clean_yaml_returns_status_valid():
    ctx = _stub_context()
    yaml_text = _minimal_manifest_yaml()
    out = _run(_handle_validate_file_format({"yaml_text": yaml_text}, ctx))
    payload = json.loads(out)
    assert payload["status"] == "valid", payload
    assert payload["schema_errors"] == []
    assert payload["magic_overlap_warnings"] == []
    assert payload["manifest"]["format_id"] == "test_fmt"


def test_validate_clean_yaml_with_matching_blob_returns_blob_test_pass(tmp_path):
    ctx = _stub_context()
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"MMTP" + b"\x00" * 60)  # 4 magic + 60 padding
    yaml_text = _minimal_manifest_yaml()
    out = _run(_handle_validate_file_format(
        {"yaml_text": yaml_text, "blob_path": str(blob)}, ctx,
    ))
    payload = json.loads(out)
    assert payload["status"] == "valid", payload
    assert payload["blob_test"]["magic_match"] is True
    assert payload["blob_test"]["expected_hex"] == "4d4d5450"
    assert payload["blob_test"]["observed_hex"] == "4d4d5450"


def test_validate_clean_yaml_with_non_matching_blob_returns_invalid_against_blob(tmp_path):
    ctx = _stub_context()
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"NOPE" + b"\x00" * 60)
    yaml_text = _minimal_manifest_yaml()
    out = _run(_handle_validate_file_format(
        {"yaml_text": yaml_text, "blob_path": str(blob)}, ctx,
    ))
    payload = json.loads(out)
    assert payload["status"] == "invalid_against_blob", payload
    assert payload["blob_test"]["magic_match"] is False
    assert payload["blob_test"]["expected_hex"] == "4d4d5450"
    assert payload["blob_test"]["observed_hex"] == "4e4f5045"  # "NOPE"


def test_list_file_formats_returns_snapshot_id_and_count(_reset_default_catalog):
    system_root, _local, _cat = _reset_default_catalog
    _write_yaml(
        system_root / "_system" / "linux_blob.yaml",
        {
            "schema_version": 1,
            "format_id": "linux_blob",
            "manifest_source": "_system",
            "precedence": 0,
            "category": "linux_blob",
            "vendor": "unknown",
            "confidence": "low",
            "detection": {
                "combine": "any",
                "always_matches": True,
                "signals": [{"kind": "always_matches", "description": "fallback"}],
            },
            "output": {
                "classifier_format": "linux_blob",
                "classifier_category": "linux_blob",
                "classifier_vendor": "unknown",
                "confidence": "low",
            },
        },
    )
    ctx = _stub_context()
    out = _run(_handle_list_file_formats({}, ctx))
    payload = json.loads(out)
    assert "snapshot_id" in payload
    assert payload["count"] == 1
    assert payload["formats"][0]["format_id"] == "linux_blob"


def test_list_file_formats_filter_by_vendor_returns_subset(_reset_default_catalog):
    system_root, _local, _cat = _reset_default_catalog
    _write_yaml(
        system_root / "qualcomm" / "qcom_mbn.yaml",
        yaml.safe_load(_minimal_manifest_yaml(
            format_id="qcom_mbn", manifest_source="core",
            precedence=100, vendor="qualcomm", category="bootloader",
        )),
    )
    _write_yaml(
        system_root / "mediatek" / "mtk_lk.yaml",
        yaml.safe_load(_minimal_manifest_yaml(
            format_id="mtk_lk", manifest_source="core",
            precedence=100, vendor="mediatek", category="bootloader",
            bytes_hex="cafebabe",
        )),
    )
    ctx = _stub_context()
    out = _run(_handle_list_file_formats({"vendor": "qualcomm"}, ctx))
    payload = json.loads(out)
    assert payload["count"] == 1
    assert payload["formats"][0]["vendor"] == "qualcomm"


def test_list_file_formats_filter_by_category_returns_subset(_reset_default_catalog):
    system_root, _local, _cat = _reset_default_catalog
    _write_yaml(
        system_root / "qualcomm" / "qcom_mbn.yaml",
        yaml.safe_load(_minimal_manifest_yaml(
            format_id="qcom_mbn", manifest_source="core",
            precedence=100, vendor="qualcomm", category="bootloader",
        )),
    )
    _write_yaml(
        system_root / "qualcomm" / "qcom_modem.yaml",
        yaml.safe_load(_minimal_manifest_yaml(
            format_id="qcom_modem", manifest_source="core",
            precedence=100, vendor="qualcomm", category="modem",
            bytes_hex="d00dfeed",
        )),
    )
    ctx = _stub_context()
    out = _run(_handle_list_file_formats({"category": "modem"}, ctx))
    payload = json.loads(out)
    assert payload["count"] == 1
    assert payload["formats"][0]["format_id"] == "qcom_modem"


def test_cross_firmware_format_collision_audit_returns_empty_for_clean_catalog(_reset_default_catalog):
    ctx = _stub_context()
    out = _run(_handle_cross_firmware_format_collision_audit({}, ctx))
    payload = json.loads(out)
    assert payload["collision_count"] == 0
    assert payload["collisions"] == []


def test_cross_firmware_format_collision_audit_detects_synthesized_collision(_reset_default_catalog):
    """Two SAME-VENDOR manifests with same magic + same precedence — A4 leaves
    these in place (cross-vendor only); the P3.1.c audit surfaces them.
    """
    system_root, _local, _cat = _reset_default_catalog
    # Two manifests, SAME vendor, different format_ids, same magic_bytes —
    # A4 only fires on DIFFERENT vendors, so these persist in the catalog.
    _write_yaml(
        system_root / "qualcomm" / "qcom_mbn_v1.yaml",
        yaml.safe_load(_minimal_manifest_yaml(
            format_id="qcom_mbn_v1", manifest_source="core",
            precedence=100, vendor="qualcomm",
            bytes_hex="d00dfeed",
        )),
    )
    _write_yaml(
        system_root / "qualcomm" / "qcom_mbn_v2.yaml",
        yaml.safe_load(_minimal_manifest_yaml(
            format_id="qcom_mbn_v2", manifest_source="core",
            precedence=100, vendor="qualcomm",
            bytes_hex="d00dfeed",
        )),
    )
    ctx = _stub_context()
    out = _run(_handle_cross_firmware_format_collision_audit({}, ctx))
    payload = json.loads(out)
    assert payload["collision_count"] == 1, payload
    coll = payload["collisions"][0]
    assert coll["magic_bytes"] == "d00dfeed"
    assert coll["offset"] == 0
    assert coll["precedence"] == 100
    fids = {m["format_id"] for m in coll["manifests"]}
    assert fids == {"qcom_mbn_v1", "qcom_mbn_v2"}


# ---------------------------------------------------------------------------
# Rejection / error paths.
# ---------------------------------------------------------------------------


def test_validate_typo_surfaces_offending_value_first():
    """``confidence: 'hi'`` → status=invalid; first error has field=confidence
    + input_value contains 'hi' + allowed_values lists {low, medium, high} +
    a did_you_mean='high' hint.
    """
    yaml_text = _minimal_manifest_yaml(confidence="hi")
    ctx = _stub_context()
    out = _run(_handle_validate_file_format({"yaml_text": yaml_text}, ctx))
    payload = json.loads(out)
    assert payload["status"] == "invalid", payload
    errors = payload["schema_errors"]
    assert errors, payload
    confidence_errs = [e for e in errors if "confidence" in e["field"]]
    assert confidence_errs, errors
    e0 = confidence_errs[0]
    assert "hi" in e0["input_value"], e0
    assert e0["allowed_values"] is not None
    assert set(e0["allowed_values"]) >= {"low", "medium", "high"}, e0
    assert e0.get("did_you_mean") == "high", e0


def test_validate_unknown_field_surfaces_extra_forbid_error():
    """``extra=forbid`` rejects unknown top-level field."""
    yaml_text = _minimal_manifest_yaml(extras={"attacker_field": 1})
    ctx = _stub_context()
    out = _run(_handle_validate_file_format({"yaml_text": yaml_text}, ctx))
    payload = json.loads(out)
    assert payload["status"] == "invalid", payload
    extras_errs = [e for e in payload["schema_errors"]
                   if "attacker_field" in e["field"] or "extra" in e["message"].lower()]
    assert extras_errs, payload["schema_errors"]


def test_validate_yaml_syntax_error_returns_status_invalid():
    """Malformed YAML (unclosed quote) → status=invalid_yaml; yaml_error field."""
    yaml_text = 'format_id: "unclosed\nmanifest_source: operator\n'
    ctx = _stub_context()
    out = _run(_handle_validate_file_format({"yaml_text": yaml_text}, ctx))
    payload = json.loads(out)
    assert payload["status"] == "invalid_yaml"
    assert "yaml_error" in payload
    assert payload["schema_errors"] == []


def test_validate_missing_yaml_text_returns_clean_error():
    ctx = _stub_context()
    out = _run(_handle_validate_file_format({}, ctx))
    payload = json.loads(out)
    assert payload["status"] == "invalid"
    assert "yaml_text required" in payload["hint"]


# ---------------------------------------------------------------------------
# Rule #46 META-CANARIES.
# ---------------------------------------------------------------------------


def _read_source() -> str:
    src = (Path(__file__).parent.parent / "app" / "ai" / "tools"
           / "file_formats.py")
    return src.read_text(encoding="utf-8")


def test_meta_canary_validate_error_uses_pydantic_errors_not_string_truncation():
    """The Pydantic ``ValidationError`` rendering helpers MUST go through
    ``.errors()`` and MUST NOT render the exception via ``str(exc)[:NNN]``.

    Scope: the renderer functions only — defensive ``str(exc)[:200]`` for
    *other* exception types (resolver crash, OSError, yaml.YAMLError) is fine
    and not the failure shape this canary protects.
    """
    src = _read_source()
    # 1) Both renderers must invoke .errors() on the exception.
    assert "exc.errors()" in src, \
        "renderer must invoke .errors() on the ValidationError"

    # 2) Extract the body of each render_validation_error_* function via
    #    tokenize+indent; assert NO str(exc)[:NNN] truncation appears INSIDE.
    import ast
    tree = ast.parse(src)
    targets = {
        "_render_validation_error_safe",
        "_render_validation_error_operator",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in targets:
            body_src = ast.unparse(node)
            assert ".errors()" in body_src, \
                f"{node.name} must invoke .errors() on the ValidationError"
            assert not re.search(
                r"str\(\s*exc\s*\)\s*\[\s*:\s*\d{2,4}\s*\]", body_src,
            ), (
                f"{node.name} contains str(exc)[:NNN] truncation; render "
                "via .errors() instead"
            )


def test_meta_canary_validate_tool_uses_render_validation_error_safe():
    """Token-scan: the validate handler invokes the safe / operator renderer.

    Strip comments + docstring tokens via :mod:`tokenize` so the assertion
    fires on code, not on documentation that merely mentions the symbol.
    """
    from io import StringIO
    src = _read_source()
    code_tokens: list[str] = []
    for tok in tokenize.generate_tokens(StringIO(src).readline):
        if tok.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        code_tokens.append(tok.string)
    code_text = " ".join(code_tokens)
    # The handler must invoke at least one of the two renderers
    assert (
        "_render_validation_error_operator" in code_text
        or "_render_validation_error_safe" in code_text
    ), "validate handler does not invoke a render_validation_error_* helper"


def test_meta_canary_render_safe_redacts_input_value():
    """A secret-shaped input value in a validation error must NOT appear raw
    in the safe renderer's output — only the ``len=N sha8=XXX`` form."""
    secret = "API_KEY=abcdef1234567890zzz"
    yaml_text = _minimal_manifest_yaml(extras={"confidence": secret})
    try:
        FileFormatManifest.model_validate(yaml.safe_load(yaml_text))
    except Exception as exc:  # noqa: BLE001 — capture ValidationError
        from pydantic import ValidationError
        assert isinstance(exc, ValidationError)
        rendered = _render_validation_error_safe(exc)
        joined = json.dumps(rendered)
        # The raw secret must NOT appear
        assert secret not in joined, joined
        # The redacted form MUST appear
        assert "sha8=" in joined, joined
        assert "len=" in joined, joined
    else:
        pytest.fail("expected ValidationError but YAML validated")


def test_meta_canary_render_safe_canary_actually_fires():
    """Paired Rule #46 canary — synthesize a deliberate Pydantic error directly
    and confirm the safe renderer surfaces the schema_errors structure."""
    from pydantic import ValidationError
    # Smallest possible validation error: model with one required field.
    try:
        FileFormatManifest.model_validate({
            "schema_version": 1,
            "format_id": "FMT_id_with_caps",  # rejects pattern ^[a-z][a-z0-9_]*$
            "manifest_source": "operator",
            "precedence": 200,
            "category": "x", "vendor": "y", "confidence": "high",
            "detection": {
                "combine": "all_required",
                "signals": [{"kind": "magic_bytes", "offset": 0,
                             "bytes_hex": "4d4d5450"}],
            },
            "output": {
                "classifier_format": "FMT_caps",
                "classifier_category": "x",
                "classifier_vendor": "y",
                "confidence": "high",
            },
        })
    except ValidationError as exc:
        rendered = _render_validation_error_safe(exc)
        assert "schema_errors" in rendered
        assert isinstance(rendered["schema_errors"], list)
        assert len(rendered["schema_errors"]) >= 1
        # Every entry has the redaction markers
        for err in rendered["schema_errors"]:
            iv = err["input_value_redacted"]
            assert iv.startswith("len="), err
            assert "sha8=" in iv, err
        return
    pytest.fail("expected ValidationError but model validated")


def test_meta_canary_collision_audit_excludes_a4_validator_already_rejected(_reset_default_catalog):
    """A4 cross-vendor same-source same-magic same-precedence drops the
    entries at catalog load; the audit must NOT surface them. Synthesizing
    the SAME scenario as A4 — different vendor, SAME manifest_source —
    confirms the catalog already removed them before the audit reads it.

    Separately a same-vendor collision MUST be surfaced (A4 leaves it in).
    """
    system_root, _local, _cat = _reset_default_catalog
    # Cross-vendor same-source — A4 fires; both should be DROPPED before audit.
    _write_yaml(
        system_root / "qualcomm" / "qcom_x.yaml",
        yaml.safe_load(_minimal_manifest_yaml(
            format_id="qcom_x", manifest_source="core",
            precedence=100, vendor="qualcomm", bytes_hex="deadbeef",
        )),
    )
    _write_yaml(
        system_root / "mediatek" / "mtk_x.yaml",
        yaml.safe_load(_minimal_manifest_yaml(
            format_id="mtk_x", manifest_source="core",
            precedence=100, vendor="mediatek", bytes_hex="deadbeef",
        )),
    )
    ctx = _stub_context()
    out = _run(_handle_cross_firmware_format_collision_audit({}, ctx))
    payload = json.loads(out)
    # A4 has already dropped both — audit sees nothing.
    fids = {m["format_id"]
            for c in payload["collisions"]
            for m in c["manifests"]}
    assert "qcom_x" not in fids, payload
    assert "mtk_x" not in fids, payload

    # Now add a SAME-vendor collision — A4 doesn't fire, audit DOES surface.
    _write_yaml(
        system_root / "broadcom" / "bcm_a.yaml",
        yaml.safe_load(_minimal_manifest_yaml(
            format_id="bcm_a", manifest_source="core",
            precedence=100, vendor="broadcom", bytes_hex="feedface",
        )),
    )
    _write_yaml(
        system_root / "broadcom" / "bcm_b.yaml",
        yaml.safe_load(_minimal_manifest_yaml(
            format_id="bcm_b", manifest_source="core",
            precedence=100, vendor="broadcom", bytes_hex="feedface",
        )),
    )
    out2 = _run(_handle_cross_firmware_format_collision_audit({}, ctx))
    payload2 = json.loads(out2)
    bcm_collisions = [c for c in payload2["collisions"]
                      if c["magic_bytes"] == "feedface"]
    assert bcm_collisions, payload2
    bcm_fids = {m["format_id"] for m in bcm_collisions[0]["manifests"]}
    assert bcm_fids == {"bcm_a", "bcm_b"}, payload2


def test_meta_canary_redact_input_value_helper_shape():
    """The redaction helper produces ``len=N sha8=XXX`` for any input —
    including secret-shaped strings, nested dicts, and None."""
    secret = "AKIA-fake-secret-1234567890"
    rendered = _redact_input_value(secret)
    assert rendered.startswith("len=")
    assert "sha8=" in rendered
    assert secret not in rendered
    # Sha8 must be 8 hex chars
    sha = rendered.split("sha8=")[1]
    assert len(sha) == 8
    int(sha, 16)  # parses as hex; raises otherwise


def test_meta_canary_register_tools_registers_three_names():
    """Registration plumbs all three tools into a fresh ToolRegistry."""
    registry = ToolRegistry()
    register_file_format_tools(registry)
    names = {t["name"] for t in registry.get_anthropic_tools()}
    assert {
        "validate_file_format",
        "list_file_formats",
        "cross_firmware_format_collision_audit",
    } <= names


# ---------------------------------------------------------------------------
# Live canary (Rule #35b) — realistic Medtronic MMTP YAML round-trips.
# ---------------------------------------------------------------------------


def test_live_canary_validate_realistic_medtronic_mmtp_yaml(tmp_path):
    """Wave-1 S4 canonical example: paste a realistic Medtronic MMTP
    operator YAML, validate against an MMTP-prefixed blob, observe the
    valid + magic_match path end-to-end."""
    yaml_text = yaml.safe_dump({
        "schema_version": 1,
        "format_id": "medtronic_mmtp_implant_blob",
        "manifest_source": "operator",
        "precedence": 200,
        "category": "implant_firmware",
        "vendor": "medtronic",
        "product": "mmtp_pacer_v3",
        "confidence": "high",
        "notes": (
            "Medtronic MMTP implant firmware. Magic 'MMTP' at offset 0. "
            "Operator-supplied YAML under NDA reference NDA-2026-04."
        ),
        "detection": {
            "combine": "all_required",
            "signals": [
                {
                    "kind": "magic_bytes",
                    "offset": 0,
                    "bytes_hex": "4d4d5450",
                    "description": "Medtronic MMTP header",
                },
            ],
        },
        "output": {
            "classifier_format": "medtronic_mmtp_implant_blob",
            "classifier_category": "implant_firmware",
            "classifier_vendor": "medtronic",
            "classifier_product": "mmtp_pacer_v3",
            "confidence": "high",
        },
        "provenance": {
            "contributor_org": "Medtronic Plc",
            "attestation_url": "https://example.invalid/wairz/medtronic/mmtp",
        },
    })
    blob = tmp_path / "medtronic_blob.bin"
    blob.write_bytes(b"MMTP" + b"\x01\x02\x03\x04" * 100)

    ctx = _stub_context()
    out = _run(_handle_validate_file_format(
        {"yaml_text": yaml_text, "blob_path": str(blob)}, ctx,
    ))
    payload = json.loads(out)
    assert payload["status"] == "valid", payload
    assert payload["manifest"]["vendor"] == "medtronic"
    assert payload["manifest"]["category"] == "implant_firmware"
    assert payload["blob_test"]["magic_match"] is True
    assert payload["blob_test"]["expected_hex"] == "4d4d5450"
    # Resolver winner inside the merged snapshot — our candidate must win.
    assert payload["blob_test"].get("resolver_winner") == "medtronic_mmtp_implant_blob"
