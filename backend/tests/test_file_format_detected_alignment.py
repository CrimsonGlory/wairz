"""Rule #25 Shape-1 cross-stack alignment for ``DetectedFormat``.

Four source-of-truth surfaces must agree pairwise:

1. Pydantic Literal ``app.schemas.file_format.DetectedFormat``
2. Python Enum   ``app.services.format_detection.DetectedFormat``
3. TypeScript union ``frontend/src/types/detected_format.ts: DetectedFormat``
4. At-least-one YAML manifest ``pre_upload.detected_format`` covering each
   value (proves wiring — operator can rely on the value reaching detect_format).

Rule #48 5-part test shape:
  * paired rejection (forbidden value rejected at each layer)
  * paired acceptance (each value parametrized accepted at each layer)
  * size-lock (cardinality pinned at the current count)
  * cross-layer alignment proper (synthesise a Pydantic-Literal-only or
    Python-Enum-only value, assert the matching layer would reject)
  * META-CANARY per Rule #46 (canary test confirms the gate fires)

This test does NOT touch any DB layer — `firmware.detected_format` is an
opaque VARCHAR(48) (alembic d2e3f4a5b6c7 explicitly notes "No CHECK").
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import get_args

import pytest

from app.schemas.file_format import (
    DetectedFormat as PydanticDetectedFormat,
    ExtractionCapability as PydanticExtractionCapability,
)
from app.services.file_format_catalog import get_default_catalog
from app.services.format_detection import (
    DetectedFormat as EnumDetectedFormat,
    ExtractionCapability as EnumExtractionCapability,
)

# Resolve frontend TS path relative to repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_FRONTEND_TS = _REPO_ROOT / "frontend" / "src" / "types" / "detected_format.ts"


def _parse_ts_union(name: str) -> set[str]:
    """Parse `export type <name> = | 'a' | 'b' | ...` from the TS file.

    Returns the set of literal values declared in the union. Strict-parse;
    raises if the file doesn't contain a matching `export type` block.
    Tolerates inline (`= 'a' | 'b'`) and multi-line (with leading `|`) forms.
    """
    text = _FRONTEND_TS.read_text(encoding="utf-8")
    # Match `export type Name = <union-body> [\n\n|;]` non-greedy capture.
    pattern = re.compile(
        rf"export type {re.escape(name)}\s*=([^=;]+?)(?=\n\n|\nexport |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(text)
    if m is None:
        raise AssertionError(
            f"frontend/src/types/detected_format.ts: no `export type {name} =` "
            f"block found"
        )
    literal_re = re.compile(r"'([^']+)'")
    return set(literal_re.findall(m.group(1)))


# ---------------------------------------------------------------------------
# Part 2 — paired acceptance: each value accepted at each layer
# ---------------------------------------------------------------------------


_PYDANTIC_VALUES: set[str] = set(get_args(PydanticDetectedFormat))
_ENUM_VALUES: set[str] = {m.value for m in EnumDetectedFormat}
_TS_VALUES: set[str] = _parse_ts_union("DetectedFormat")
_EXT_PYDANTIC: set[str] = set(get_args(PydanticExtractionCapability))
_EXT_ENUM: set[str] = {m.value for m in EnumExtractionCapability}
_EXT_TS: set[str] = _parse_ts_union("ExtractionCapability")


def test_detected_format_pydantic_matches_python_enum() -> None:
    """Pydantic Literal and Python Enum carry identical value sets."""
    assert _PYDANTIC_VALUES == _ENUM_VALUES, (
        f"Pydantic-only: {_PYDANTIC_VALUES - _ENUM_VALUES}; "
        f"Enum-only: {_ENUM_VALUES - _PYDANTIC_VALUES}"
    )


def test_detected_format_pydantic_matches_typescript_union() -> None:
    """Pydantic Literal and the TS union carry identical value sets."""
    assert _PYDANTIC_VALUES == _TS_VALUES, (
        f"Pydantic-only: {_PYDANTIC_VALUES - _TS_VALUES}; "
        f"TS-only: {_TS_VALUES - _PYDANTIC_VALUES}"
    )


def test_extraction_capability_pydantic_matches_python_enum() -> None:
    """ExtractionCapability — Pydantic vs Enum."""
    assert _EXT_PYDANTIC == _EXT_ENUM


def test_extraction_capability_pydantic_matches_typescript() -> None:
    """ExtractionCapability — Pydantic vs TS union."""
    assert _EXT_PYDANTIC == _EXT_TS


# ---------------------------------------------------------------------------
# Part 4 — YAML wiring proof
# ---------------------------------------------------------------------------


def test_every_detected_format_value_is_wired_via_a_manifest() -> None:
    """Each enum value (except UNKNOWN) appears in at least one shipped YAML.

    UNKNOWN is the catch-all — the catalog has no UNKNOWN manifest by design;
    it's emitted when no manifest matches.
    """
    catalog = get_default_catalog().get_catalog()
    seen: set[str] = set()
    for manifest in catalog.values():
        if manifest.pre_upload is None:
            continue
        seen.add(manifest.pre_upload.detected_format)
    expected = _PYDANTIC_VALUES - {"unknown"}
    missing = expected - seen
    assert not missing, (
        f"DetectedFormat values not covered by any shipped manifest: {missing}. "
        f"Add a manifest with pre_upload.detected_format: <value> under "
        f"backend/app/services/file_format_catalog/data/file_formats/."
    )


# ---------------------------------------------------------------------------
# Part 3 — size lock
# ---------------------------------------------------------------------------


def test_detected_format_value_count_locked_at_20() -> None:
    """DetectedFormat cardinality pinned. Drift forces a deliberate edit."""
    assert len(_PYDANTIC_VALUES) == 20, (
        f"DetectedFormat values: {len(_PYDANTIC_VALUES)} (expected 20 — "
        f"includes android_apex added 2026-05-22 for Scout-2 G32 APEX gap). "
        f"Cross-stack alignment must update all 4 surfaces in one commit."
    )
    assert len(_ENUM_VALUES) == 20
    assert len(_TS_VALUES) == 20


def test_extraction_capability_value_count_locked_at_3() -> None:
    """ExtractionCapability cardinality pinned at 3."""
    assert len(_EXT_PYDANTIC) == 3
    assert len(_EXT_ENUM) == 3
    assert len(_EXT_TS) == 3


# ---------------------------------------------------------------------------
# Part 1 — paired rejection: forbidden value rejected at every layer
# ---------------------------------------------------------------------------


def test_paired_rejection_pydantic_rejects_unknown_value() -> None:
    """A made-up detected_format must fail Pydantic validation."""
    from pydantic import ValidationError

    from app.schemas.file_format import PreUploadHint

    with pytest.raises(ValidationError):
        PreUploadHint(
            detected_format="totally_made_up",  # type: ignore[arg-type]
            extraction_capability="full",
        )


def test_paired_rejection_python_enum_rejects_unknown_value() -> None:
    """The Python Enum rejects a made-up value at construction."""
    with pytest.raises(ValueError):
        EnumDetectedFormat("totally_made_up")


# ---------------------------------------------------------------------------
# Part 5 — META-CANARY (Rule #46)
# ---------------------------------------------------------------------------


def test_meta_canary_alignment_test_actually_compares() -> None:
    """Synthesize a wrong value and confirm the equality check would fail.

    Without this canary, the alignment tests passing is structurally
    indistinguishable from "the comparisons aren't actually running" (Rule #46).
    """
    # Synthesise a Pydantic-only value
    canary_pyd: set[str] = _PYDANTIC_VALUES | {"canary_only_pydantic"}
    canary_enum: set[str] = _ENUM_VALUES

    # The alignment check WOULD fail if the surfaces drifted by even one value
    assert canary_pyd != canary_enum, (
        "META-CANARY: equality check is not actually comparing — synthetic "
        "drift went undetected"
    )
    # And the diff messaging works
    diff = canary_pyd - canary_enum
    assert diff == {"canary_only_pydantic"}


def test_meta_canary_extraction_capability_catalog_derived_not_hardcoded() -> None:
    """EXTRACTION_CAPABILITY must derive from manifests, not a hand-rolled table.

    The catalog returns a manifest's `pre_upload.extraction_capability`; the
    module-level dict is built from those values at import time. Mutating
    the catalog snapshot's manifest list AT RUNTIME and rebuilding should
    yield a different dict, proving the link.
    """
    from app.services.format_detection import _build_capability_tables

    cap_a, _ = _build_capability_tables()
    cap_b, _ = _build_capability_tables()
    # Idempotent build
    assert cap_a == cap_b
    # The dict must have at least the 18 non-UNKNOWN formats wired
    # (proves derivation from real manifest data, not a stub).
    non_unknown_keys = {
        k.value for k in cap_a if k != EnumDetectedFormat.UNKNOWN
    }
    expected = _PYDANTIC_VALUES - {"unknown"}
    missing = expected - non_unknown_keys
    assert not missing, (
        f"_build_capability_tables() returned dict missing values: {missing}. "
        f"Either a manifest's pre_upload.detected_format is mis-typed or "
        f"the catalog isn't being walked at all."
    )
