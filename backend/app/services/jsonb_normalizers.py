"""Boundary normalisers for every JSONB column on the wairz schema (CLAUDE.md Rule #35c).

Each helper here is the SOLE blessed read-boundary for one JSONB column. Every
consumer reading the column should route through the matching ``_normalize_*``
function rather than touching the raw value, because:

- Legacy rows pre-date current writer discipline and may have a different
  shape (e.g. ``device_metadata['vendor_decryption']`` exists as both
  ``list[dict]`` (canonical) and ``dict`` with ``blobs: list[str]``
  (legacy)). The unpack-audit incident (2026-05-04) is the inciting case;
  see ``unpack_audit_service._normalize_vendor_decryption``.
- ``None`` flows through every nullable JSONB column. Each consumer would
  otherwise have to repeat the ``or {}`` / ``or []`` defensive default.
- Future shape changes can be discriminated via the ``schema_version`` field
  stamped by the writer; the normaliser owns the dispatch.

Conventions:
- Naming: ``_normalize_<table>_<column>``. (Trailing underscore on a Python
  attribute name like ``metadata_`` is dropped — column name is what matters.)
- Signature: accept any of the historically-seen shapes plus ``None``;
  return the canonical empty default for unparseable inputs rather than
  raising. The boundary is defensive; inner logic can rely on the canonical
  shape.
- Idempotent: passing a canonical value back through returns the same
  canonical value. Tests must include this property.
- Schema version constants: ``<TABLE>_<COLUMN>_SCHEMA_VERSION = 1`` for
  columns whose writers stamp the version. Bump only on backwards-incompatible
  shape change AND extend the matching normaliser's dispatch.

The forward-looking discipline applies even to columns whose production
data is currently uniform — shape divergence accumulates over time, and the
helpers exist now so no future consumer has to remember to defend at the
boundary.
"""
from __future__ import annotations

from typing import Any

# ── firmware.device_metadata ──────────────────────────────────────────────────
#
# Canonical shape: ``dict`` containing arbitrary sub-keys written by
# different stages (firmware upload, unblob worker, vendor-AES decrypt,
# detection_audit, device acquisition, etc.). Sub-keys themselves may have
# their own normalisers (e.g. ``_normalize_vendor_decryption`` lives in
# ``unpack_audit_service``). This top-level normaliser only validates the
# column's outer container shape.
FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION = 1


def _normalize_firmware_device_metadata(value: Any) -> dict:
    """Return the canonical ``dict`` shape for ``Firmware.device_metadata``.

    ``None``, missing, or wrong-typed values yield an empty dict — this is
    a metadata-bag column, so absence is semantically equivalent to
    ``no extra metadata``. Callers that need to distinguish ``set-but-empty``
    from ``never-written`` should consult the row directly.
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_firmware_device_metadata(payload: dict | None) -> dict | None:
    """Stamp the schema_version onto a writer payload, preserving null contract.

    Returns ``None`` when ``payload`` is ``None`` or an empty dict so the
    column's nullable semantic survives (some writers clear the dict by
    assigning ``None``). For non-empty dicts, mutates-in-place and returns
    the same dict with the current ``FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION``
    stamped at ``payload["schema_version"]``. Idempotent — re-stamping a
    payload that already has the current version is a no-op.
    """
    if not payload:
        return None
    payload["schema_version"] = FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION
    return payload
