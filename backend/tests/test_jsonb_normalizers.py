"""Tests for ``app.services.jsonb_normalizers`` — boundary normalisers
for every JSONB column on the wairz schema (CLAUDE.md Rule #35c).

Each normaliser is verified with three properties:

1. **Canonical pass-through** — a value already in the canonical shape
   is returned unchanged (idempotency).
2. **Defensive coercion** — ``None`` and wrong-typed inputs return the
   canonical empty default rather than raising.
3. **Schema_version fidelity** — for columns that stamp a discriminator,
   the writer-side helper produces a payload whose ``schema_version``
   matches the module-level constant.
"""
from __future__ import annotations

import pytest

from app.services.jsonb_normalizers import (
    FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION,
    _normalize_firmware_device_metadata,
    _stamp_firmware_device_metadata,
)


# ── _normalize_firmware_device_metadata ──────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical shape — dict with arbitrary sub-keys.
        ({"detection_roots": ["/tmp/x"], "manufacturer": "ACME"},
         {"detection_roots": ["/tmp/x"], "manufacturer": "ACME"}),
        # Empty dict — preserved.
        ({}, {}),
        # Schema-versioned dict — preserved.
        ({"schema_version": 1, "vendor_decryption": []},
         {"schema_version": 1, "vendor_decryption": []}),
        # None — coerced to empty dict so callers can ``meta.get(...)`` safely.
        (None, {}),
        # Wrong type — list — coerced to empty dict.
        ([1, 2, 3], {}),
        # Wrong type — string — coerced to empty dict.
        ("not a dict", {}),
        # Wrong type — int — coerced to empty dict.
        (42, {}),
    ],
)
def test_normalize_firmware_device_metadata(value, expected):
    assert _normalize_firmware_device_metadata(value) == expected


def test_normalize_firmware_device_metadata_idempotent():
    canonical = {"schema_version": 1, "manufacturer": "ACME", "detection_roots": []}
    once = _normalize_firmware_device_metadata(canonical)
    twice = _normalize_firmware_device_metadata(once)
    assert once == twice == canonical


# ── _stamp_firmware_device_metadata ──────────────────────────────────────────


def test_stamp_firmware_device_metadata_adds_version():
    payload = {"manufacturer": "ACME"}
    out = _stamp_firmware_device_metadata(payload)
    assert out is not None
    assert out["schema_version"] == FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION
    assert out["manufacturer"] == "ACME"


def test_stamp_firmware_device_metadata_idempotent():
    payload = {"manufacturer": "ACME"}
    once = _stamp_firmware_device_metadata(payload)
    twice = _stamp_firmware_device_metadata(once)
    assert once == twice
    assert once["schema_version"] == FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION


def test_stamp_firmware_device_metadata_none_in_none_out():
    """None payload preserves the column's nullable contract."""
    assert _stamp_firmware_device_metadata(None) is None


def test_stamp_firmware_device_metadata_empty_in_none_out():
    """Empty dict collapses to None — writer semantic for `clear`."""
    assert _stamp_firmware_device_metadata({}) is None


def test_stamp_firmware_device_metadata_mutates_input():
    """Documents the mutation contract — writers may rely on it."""
    payload = {"manufacturer": "ACME"}
    out = _stamp_firmware_device_metadata(payload)
    assert out is payload  # same dict object
    assert "schema_version" in payload
