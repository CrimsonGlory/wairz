"""R2 blob-fingerprint tests (Stage-1 2026-06-08) — TLSH + imphash helpers.

TLSH is exercised for real (python-tlsh is a declared dep; importorskip keeps the suite green
on a host without the C extension). imphash's graceful non-PE degradation is exercised for real;
the normalizer covers Rule #35c canonical pass-through / defensive coercion / idempotency.
"""
from __future__ import annotations

import os

import pytest

from app.services.hardware_firmware.fingerprints import (
    FINGERPRINT_SCHEMA_VERSION,
    compute_imphash,
    finalize_tlsh,
    new_tlsh,
    normalize_blob_fingerprints,
    stamp_blob_fingerprints,
    tlsh_distance,
    update_tlsh,
)

tlsh = pytest.importorskip("tlsh")


def _stream(data: bytes, chunk: int = 4096) -> str | None:
    acc = new_tlsh()
    for i in range(0, len(data), chunk):
        update_tlsh(acc, data[i:i + chunk])
    return finalize_tlsh(acc)


def test_tlsh_stream_matches_oneshot_and_is_72_hex():
    data = os.urandom(8192)
    streamed = _stream(data)
    assert streamed is not None and len(streamed) == 72 and streamed.startswith("T1")
    assert streamed == tlsh.hash(data)  # streaming == one-shot over the same bytes


def test_tlsh_none_for_tiny_or_low_entropy():
    assert _stream(b"abc") is None              # <50 bytes -> ValueError -> None
    assert _stream(b"\x00" * 4096) is None      # no entropy -> None (not a crash)


def test_tlsh_distance_bands():
    a = tlsh.hash(os.urandom(8192))
    assert tlsh_distance(a, a) == 0             # identical
    assert tlsh_distance(a, tlsh.hash(os.urandom(8192))) > 0
    assert tlsh_distance(a, None) is None       # missing -> None
    assert tlsh_distance(None, None) is None


def test_tlsh_near_identical_blobs_have_small_distance():
    base = os.urandom(16384)
    mutated = bytearray(base); mutated[100] ^= 0xFF; mutated[5000] ^= 0x01  # 2-byte change
    d = tlsh_distance(tlsh.hash(base), tlsh.hash(bytes(mutated)))
    assert d is not None and d < 50            # a 2-byte delta stays near-identical


def test_imphash_none_on_non_pe(tmp_path):
    f = tmp_path / "not_a_pe.bin"
    f.write_bytes(os.urandom(2048))
    assert compute_imphash(str(f)) is None      # graceful: non-PE -> None, never raises
    assert compute_imphash(str(tmp_path / "missing.bin")) is None


def test_normalizer_canonical_passthrough_and_defensive():
    canon = {"schema_version": 1, "tlsh": "T1ABC", "imphash": "deadbeef"}
    assert normalize_blob_fingerprints(canon) == canon
    # idempotent
    assert normalize_blob_fingerprints(normalize_blob_fingerprints(canon)) == canon
    # defensive: None / wrong-type / partial
    for bad in (None, "string", 42, [], {"tlsh": 123, "imphash": None}):
        out = normalize_blob_fingerprints(bad)
        assert out["schema_version"] == FINGERPRINT_SCHEMA_VERSION
        assert out["tlsh"] is None and out["imphash"] is None


def test_stamp_produces_canonical():
    assert stamp_blob_fingerprints("T1XYZ", None) == {
        "schema_version": FINGERPRINT_SCHEMA_VERSION, "tlsh": "T1XYZ", "imphash": None}
    assert stamp_blob_fingerprints(None, None)["tlsh"] is None
