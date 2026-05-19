"""MCP tools for the file-format YAML registry (P3.1.c — Rule #52 schema-driven).

Three operator-facing tools that unlock the iteration loop:

* ``validate_file_format`` — paste YAML text + optional blob path, get back a
  shape-true validation report (Pydantic ``errors()`` rendered offending-value-
  first per Phase 1+2 "What Broke #4" lesson). When ``blob_path`` is supplied,
  the validator builds a TEMPORARY in-memory catalog with the candidate
  manifest merged into the default snapshot (NEVER mutates the live catalog),
  then runs ``resolve()`` against the blob's head bytes.
* ``list_file_formats`` — enumerate every manifest in the live catalog,
  optionally filtered by ``vendor`` / ``category``. Includes ``last_warning``
  surfacing for catalog-load drift visibility.
* ``cross_firmware_format_collision_audit`` — scan the live catalog for
  same-magic same-offset same-precedence cross-format collisions. Different
  from cross-feature validator A4 (which drops cross-vendor same-source
  collisions at load time). This audit surfaces what remains AFTER A4 runs —
  same-vendor / cross-source legitimate-overlap entries an operator may want
  to review.

All three are STATELESS — no DB writes, no async session usage beyond what
the registry plumbs through ``ToolContext``. The validate tool's temporary
catalog is constructed on the stack and discarded after the call returns.

Validation-error rendering follows the dual-render contract:

* ``_render_validation_error_safe(exc)`` — REDACTED rendering for any caller
  that might surface the result through a multi-tenant or logged channel.
  Each error renders ``input_value_redacted="len=N sha8=XXX"`` only.
* ``_render_validation_error_operator(exc)`` — OPERATOR rendering: includes
  the redacted form PLUS an ``input_value_short`` ≤80-char ``repr(input)``
  string so operators see what was wrong locally. Only the operator-facing
  ``validate_file_format`` handler uses the dual form; the safe form is the
  default for any future cross-surface re-use.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

import yaml
from pydantic import ValidationError

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.schemas.file_format import FileFormatManifest
from app.services.file_format_catalog import (
    FormatCatalogSnapshot,
    get_default_catalog,
    resolve,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Validation-error rendering — Wave-1 S3 R + S5 M (input-value redaction).
# ---------------------------------------------------------------------------


def _redact_input_value(input_value: Any) -> str:
    """Return ``len=N sha8=XXX`` for the input value's repr — never the raw."""
    rendered = repr(input_value) if input_value is not None else "<missing>"
    sha = hashlib.sha256(rendered.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"len={len(rendered)} sha8={sha}"


def _allowed_values_for_error(err: dict) -> list[str] | None:
    """Best-effort extraction of enum-allowed values from a Pydantic error.

    Pydantic v2 surfaces the expected variants in ``ctx.expected`` for
    ``literal_error`` types; falls back to None when not available.
    """
    ctx = err.get("ctx") or {}
    expected = ctx.get("expected")
    if not expected:
        return None
    # Pydantic renders these as e.g. "'low', 'medium' or 'high'". Split on
    # commas and "or"; strip quotes.
    if isinstance(expected, str):
        tokens: list[str] = []
        for chunk in expected.replace(" or ", ",").split(","):
            tok = chunk.strip().strip("'\"")
            if tok:
                tokens.append(tok)
        return tokens or None
    if isinstance(expected, (list, tuple)):
        return [str(x) for x in expected]
    return None


def _did_you_mean(value: Any, allowed: list[str] | None) -> str | None:
    """Operator-facing nearest-match hint when the value is a short string.

    Uses simple substring proximity — Pydantic v2 doesn't ship a Levenshtein
    out of the box and importing one for this tool would be overkill. The
    common case is ``'hi'`` → ``'high'``; ``'med'`` → ``'medium'``.
    """
    if allowed is None or not isinstance(value, str):
        return None
    vl = value.lower()
    # Prefer prefix matches, then substring matches
    prefix = [a for a in allowed if a.lower().startswith(vl)]
    if prefix:
        return prefix[0]
    contains = [a for a in allowed if vl in a.lower()]
    if contains:
        return contains[0]
    return None


def _render_validation_error_safe(exc: ValidationError) -> dict:
    """Build a REDACTED rendering of a Pydantic ``ValidationError``.

    No raw ``input_value`` ever appears in the output — every input is
    rendered as ``len=N sha8=XXX`` (Wave-1 S3 R info-leak prevention).
    Returns a dict with key ``schema_errors`` shaped per Wave-1 S4.
    """
    rendered: list[dict] = []
    for err in exc.errors()[:32]:  # cap to bound output size
        loc = ".".join(str(p) for p in err.get("loc", ()))
        rendered.append({
            "field": loc or "<root>",
            "input_value_redacted": _redact_input_value(err.get("input")),
            "allowed_values": _allowed_values_for_error(err),
            "message": err.get("msg", "?"),
            "line": None,
            "column": None,
        })
    return {"schema_errors": rendered}


def _render_validation_error_operator(exc: ValidationError) -> dict:
    """Operator-facing rendering — includes REDACTED form AND a short ``repr``.

    Wave-1 S4: the validate tool is operator-facing (not tenant-facing), so
    operators need the value they typed. The ``input_value`` is capped to
    80 chars of ``repr`` to keep the output small AND defeat secret-shaped
    accidental leakage into long strings; the redacted ``input_value_redacted``
    accompanies it so audit logs / replays consistently include the safe form.
    """
    rendered: list[dict] = []
    for err in exc.errors()[:32]:
        loc = ".".join(str(p) for p in err.get("loc", ()))
        raw_input = err.get("input")
        short = repr(raw_input)[:80] if raw_input is not None else "<missing>"
        allowed = _allowed_values_for_error(err)
        hint = _did_you_mean(raw_input, allowed)
        entry = {
            "field": loc or "<root>",
            "input_value": short,
            "input_value_redacted": _redact_input_value(raw_input),
            "allowed_values": allowed,
            "message": err.get("msg", "?"),
            "line": None,
            "column": None,
        }
        if hint is not None:
            entry["did_you_mean"] = hint
        rendered.append(entry)
    return {"schema_errors": rendered}


# ---------------------------------------------------------------------------
# Helpers — temporary in-memory snapshot for validate-with-blob.
# ---------------------------------------------------------------------------


def _build_merged_snapshot(candidate: FileFormatManifest) -> FormatCatalogSnapshot:
    """Build a fresh snapshot with ``candidate`` merged into the live catalog.

    The live ``_DEFAULT_CATALOG`` is NEVER mutated — we copy the current
    ``by_id`` dict and overlay the candidate. The candidate wins on its
    format_id (override semantics) so a blob test reflects the supplied
    YAML's detection block, not whatever the on-disk one says.

    ``FormatCatalogSnapshot.from_dict`` rebuilds the canonical-JSON hash so
    ``snapshot_id`` distinguishes this from the live snapshot.
    """
    live = get_default_catalog().get_catalog()  # snapshot copy by API contract
    merged = dict(live)
    merged[candidate.format_id] = candidate
    import time as _time
    return FormatCatalogSnapshot.from_dict(merged, _time.time_ns())


def _read_blob_head(path: str, n: int = 4096) -> tuple[bytes, int] | None:
    """Read up to ``n`` bytes from ``path``; returns ``(head, size)`` or ``None``."""
    if not path or not os.path.isfile(path):
        return None
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(n)
    except OSError as exc:
        logger.warning("read_blob_head: %s: %s", path, exc)
        return None
    return head, size


# ---------------------------------------------------------------------------
# Handlers.
# ---------------------------------------------------------------------------


async def _handle_validate_file_format(
    input: dict, context: ToolContext,
) -> str:
    """Validate a YAML manifest against the schema. Optionally test against a blob.

    Wave-1 S4 status taxonomy:

    * ``valid`` — Pydantic accepts AND (if blob_path supplied) magic matches.
    * ``invalid`` — Pydantic rejects (schema_errors populated).
    * ``invalid_yaml`` — YAML doesn't parse at all.
    * ``invalid_against_blob`` — schema accepts but the blob's magic bytes
      don't match the supplied manifest's first magic_bytes signal.
    * ``invalid_collision`` — schema accepts but the candidate's
      detection block collides with an existing manifest at the SAME
      precedence + SAME offset + SAME bytes_hex.
    """
    yaml_text = input.get("yaml_text")
    if not yaml_text or not isinstance(yaml_text, str):
        return json.dumps({
            "status": "invalid",
            "schema_errors": [],
            "hint": "yaml_text required (string)",
        }, indent=2)

    # YAML syntax errors first — surface a clean top-level field rather than
    # cramming a yaml.YAMLError into the schema_errors list.
    try:
        raw = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return json.dumps({
            "status": "invalid_yaml",
            "yaml_error": str(exc).replace("\n", " | ")[:600],
            "schema_errors": [],
            "hint": "fix YAML syntax (unclosed quote / bad indent) then re-validate",
        }, indent=2)

    if raw is None:
        return json.dumps({
            "status": "invalid_yaml",
            "yaml_error": "empty YAML document",
            "schema_errors": [],
            "hint": "manifest cannot be empty",
        }, indent=2)

    # Pydantic validation — operator-facing rendering with short repr + safe hash.
    try:
        manifest = FileFormatManifest.model_validate(raw)
    except ValidationError as exc:
        rendered = _render_validation_error_operator(exc)
        return json.dumps({
            "status": "invalid",
            **rendered,
            "magic_overlap_warnings": [],
            "dispatch_consistency": None,
            "hint": "fix the schema errors above (offending value rendered first)",
        }, indent=2)

    # Schema passed — compute dispatch consistency + magic_overlap_warnings.
    warnings: list[dict] = []
    live_catalog = get_default_catalog().get_catalog()
    for sig in manifest.detection.signals:
        if sig.kind != "magic_bytes" or sig.offset is None or sig.bytes_hex is None:
            continue
        for other_id, other in live_catalog.items():
            if other_id == manifest.format_id:
                continue
            if other.precedence != manifest.precedence:
                continue
            for osig in other.detection.signals:
                if osig.kind != "magic_bytes":
                    continue
                if (osig.offset == sig.offset
                        and (osig.bytes_hex or "").lower() == sig.bytes_hex.lower()):
                    warnings.append({
                        "your_entry": manifest.format_id,
                        "collides_with": other_id,
                        "shared_signature": (
                            f"offset={sig.offset} bytes_hex={sig.bytes_hex.lower()}"
                        ),
                        "resolution_options": [
                            f"alias_of: {other_id}",
                            "change precedence to a different tier",
                            f"use mode: override + overrides: {other.source_path}",
                            "narrow detection (add path_context / filename signal)",
                        ],
                    })

    # Dispatch consistency — is the dispatch's matcher plugin registered?
    dispatch_consistency: dict = {"parser": None, "registered": True}
    if manifest.plugin.matcher is not None:
        from app.services.file_format_catalog.resolver import PLUGIN_REGISTRY
        ref = manifest.plugin.matcher.ref
        dispatch_consistency = {
            "parser": ref,
            "registered": ref in PLUGIN_REGISTRY,
        }

    response: dict[str, Any] = {
        "status": "valid",
        "schema_errors": [],
        "magic_overlap_warnings": warnings,
        "dispatch_consistency": dispatch_consistency,
        "manifest": {
            "format_id": manifest.format_id,
            "manifest_source": manifest.manifest_source,
            "precedence": manifest.precedence,
            "category": manifest.category,
            "vendor": manifest.vendor,
            "confidence": manifest.confidence,
        },
    }

    # Optional blob_path testing — build a TEMPORARY snapshot with the
    # candidate merged. NEVER mutate the live catalog.
    blob_path = input.get("blob_path")
    if blob_path:
        head_size = _read_blob_head(blob_path)
        if head_size is None:
            response["blob_test"] = {
                "path": blob_path,
                "magic_match": False,
                "error": f"blob not readable: {blob_path}",
            }
            response["status"] = "invalid_against_blob"
            response["hint"] = "blob_path not found / not readable"
        else:
            head, size = head_size
            # Test the candidate's first magic_bytes signal directly.
            first_magic = next(
                (s for s in manifest.detection.signals if s.kind == "magic_bytes"),
                None,
            )
            blob_test: dict[str, Any] = {
                "path": blob_path,
                "scan_first_64_bytes": head[:64].hex(),
            }
            if first_magic is not None:
                try:
                    expected = bytes.fromhex(first_magic.bytes_hex or "")
                except ValueError:
                    expected = b""
                off = first_magic.offset or 0
                observed = head[off:off + len(expected)] if expected else b""
                blob_test["expected_hex"] = (first_magic.bytes_hex or "").lower()
                blob_test["observed_hex"] = observed.hex()
                blob_test["magic_match"] = (observed == expected and bool(expected))
            else:
                blob_test["magic_match"] = False
                blob_test["expected_hex"] = ""
                blob_test["observed_hex"] = ""
                blob_test["note"] = "no magic_bytes signal in supplied manifest"
            # Also run the resolver against the merged snapshot — does the
            # candidate actually win?
            try:
                merged_snapshot = _build_merged_snapshot(manifest)
                fm = resolve(head, blob_path, size, snapshot=merged_snapshot)
                if fm is not None:
                    blob_test["resolver_winner"] = fm.format_id
                    blob_test["resolver_score"] = fm.confidence_score
                else:
                    blob_test["resolver_winner"] = None
                    blob_test["resolver_score"] = 0.0
            except Exception as exc:  # noqa: BLE001 — defensive
                logger.warning("validate_file_format: resolver: %s", exc)
                blob_test["resolver_winner"] = None
                blob_test["resolver_error"] = str(exc)[:200]
            response["blob_test"] = blob_test
            if not blob_test.get("magic_match"):
                response["status"] = "invalid_against_blob"
                response["hint"] = (
                    "magic bytes do not match the blob's head — recheck "
                    "offset / bytes_hex against an xxd of the first 64 bytes"
                )

    # If we found magic_overlap_warnings AND there's no blob_test downgrading
    # status, mark as invalid_collision so operators see the surface clearly.
    if warnings and response["status"] == "valid":
        response["status"] = "invalid_collision"
        response["hint"] = (
            "candidate's magic bytes collide with existing manifests at the "
            "same precedence — pick alias_of, change tier, or narrow detection"
        )

    if response["status"] == "valid":
        response["hint"] = "manifest accepted; drop into data/file_formats/<vendor>/"

    return json.dumps(response, indent=2)


async def _handle_list_file_formats(
    input: dict, context: ToolContext,
) -> str:
    """Enumerate the live catalog. Optional ``vendor`` / ``category`` filter."""
    vendor_filter = (input.get("vendor") or "").strip().lower()
    category_filter = (input.get("category") or "").strip().lower()
    cat_obj = get_default_catalog()
    snapshot = cat_obj.get_snapshot()
    rows: list[dict] = []
    for manifest in snapshot.manifests:
        if vendor_filter and manifest.vendor.lower() != vendor_filter:
            continue
        if category_filter and manifest.category.lower() != category_filter:
            continue
        rows.append({
            "format_id": manifest.format_id,
            "category": manifest.category,
            "vendor": manifest.vendor,
            "manifest_source": manifest.manifest_source,
            "precedence": manifest.precedence,
            "confidence": manifest.confidence,
            "source_path": manifest.source_path,
            "notes": manifest.notes,
        })
    return json.dumps({
        "snapshot_id": snapshot.snapshot_id,
        "count": len(rows),
        "formats": rows,
        "last_warning": cat_obj.last_warning,
        "filters": {
            "vendor": vendor_filter or None,
            "category": category_filter or None,
        },
    }, indent=2)


async def _handle_cross_firmware_format_collision_audit(
    input: dict, context: ToolContext,
) -> str:
    """Operator audit — scan catalog for same-magic same-offset cross-format collisions.

    Different from cross-feature validator A4 (catalog/catalog.py) which fires
    on CROSS-VENDOR same-precedence same-magic same-source collisions and
    DROPS the offending entries at load time. This audit surfaces what remains
    AFTER A4 runs — same-vendor and cross-source legitimate-overlap entries
    where two format_ids declare the same magic bytes. Use the output to
    decide between ``alias_of`` (true identity reuse), tier change, or
    detection narrowing.

    ``project_id`` is accepted but currently unused — the catalog is global
    by construction (operator YAML overlay is per-host, not per-project).
    Reserved for P4 when per-project manifest overlays land.
    """
    project_id = input.get("project_id")  # noqa: F841 — reserved for P4
    cat_obj = get_default_catalog()
    snapshot = cat_obj.get_snapshot()

    # Build index of (precedence, offset, bytes_hex_lower) -> [(format_id, manifest)]
    index: dict[tuple[int, int, str], list[FileFormatManifest]] = {}
    for manifest in snapshot.manifests:
        for sig in manifest.detection.signals:
            if sig.kind != "magic_bytes":
                continue
            if sig.offset is None or sig.bytes_hex is None:
                continue
            key = (manifest.precedence, sig.offset, sig.bytes_hex.lower())
            index.setdefault(key, []).append(manifest)

    collisions: list[dict] = []
    for (precedence, offset, bytes_hex_lower), manifests in index.items():
        # Deduplicate by format_id — a single manifest with multiple signals
        # at the same (offset, bytes) shouldn't self-collide.
        unique_by_fid: dict[str, FileFormatManifest] = {}
        for m in manifests:
            unique_by_fid.setdefault(m.format_id, m)
        if len(unique_by_fid) < 2:
            continue
        # Skip alias chains — if every manifest in the group declares
        # ``alias_of`` pointing to the same identity, this is intentional
        # overlap, not a collision.
        alias_targets = {
            (m.alias_of or m.format_id) for m in unique_by_fid.values()
        }
        if len(alias_targets) == 1:
            continue
        collisions.append({
            "magic_bytes": bytes_hex_lower,
            "offset": offset,
            "precedence": precedence,
            "manifests": [
                {
                    "format_id": m.format_id,
                    "manifest_source": m.manifest_source,
                    "source_path": m.source_path,
                    "precedence": m.precedence,
                    "vendor": m.vendor,
                    "category": m.category,
                }
                for m in unique_by_fid.values()
            ],
            "resolution_options": [
                "set alias_of on one manifest to declare identity",
                "differentiate precedence (raise one tier)",
                "narrow detection with a path_context / filename signal",
            ],
        })

    # Stable ordering for deterministic output.
    collisions.sort(key=lambda c: (c["offset"], c["magic_bytes"], -c["precedence"]))

    return json.dumps({
        "snapshot_id": snapshot.snapshot_id,
        "collisions": collisions,
        "collision_count": len(collisions),
        "last_warning": cat_obj.last_warning,
        "note": (
            "A4 catalog-load validator drops cross-vendor same-source "
            "collisions BEFORE this audit runs; remaining entries are "
            "same-vendor or cross-source legitimate-overlap candidates "
            "for operator review"
        ),
    }, indent=2)


# ---------------------------------------------------------------------------
# Registration.
# ---------------------------------------------------------------------------


def register_file_format_tools(registry: ToolRegistry) -> None:
    """Register the file-format YAML registry MCP tools (P3.1.c)."""
    registry.register(
        name="validate_file_format",
        description=(
            "Validate a file-format YAML manifest against the closed-grammar "
            "Pydantic schema (Rule #52). Returns offending-value-first error "
            "rendering, magic_overlap_warnings against the live catalog, and "
            "optionally tests the candidate against a blob path (does the "
            "first magic_bytes signal match the blob's head?). The live "
            "catalog is NEVER mutated — testing builds a temporary in-memory "
            "snapshot."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "yaml_text": {
                    "type": "string",
                    "description": "Full YAML manifest text to validate",
                },
                "blob_path": {
                    "type": "string",
                    "description": (
                        "Optional path to a blob — validator reads up to 4KB "
                        "of head bytes and tests the first magic_bytes signal"
                    ),
                },
            },
            "required": ["yaml_text"],
        },
        handler=_handle_validate_file_format,
    )
    registry.register(
        name="list_file_formats",
        description=(
            "Enumerate every manifest in the file-format catalog "
            "(snapshot-pinned). Optional vendor + category filters. Surfaces "
            "the catalog's last_warning so drift after a recent edit is "
            "visible."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "vendor": {
                    "type": "string",
                    "description": (
                        "Optional vendor filter (case-insensitive exact match "
                        "on output.vendor)"
                    ),
                },
                "category": {
                    "type": "string",
                    "description": "Optional category filter",
                },
            },
        },
        handler=_handle_list_file_formats,
    )
    registry.register(
        name="cross_firmware_format_collision_audit",
        description=(
            "Operator audit — scan the file-format catalog for same-magic "
            "same-offset same-precedence cross-format collisions. Different "
            "from cross-feature validator A4 (which drops cross-vendor "
            "same-source collisions at load); this audit surfaces same-vendor "
            "and cross-source overlap that A4 leaves in place for legitimate "
            "alias / tiered reasons."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "description": (
                        "Reserved for P4 per-project overlay; currently the "
                        "catalog is global"
                    ),
                },
            },
        },
        handler=_handle_cross_firmware_format_collision_audit,
    )


__all__ = [
    "_render_validation_error_operator",
    "_render_validation_error_safe",
    "register_file_format_tools",
]
