"""R2 Rule #44 matcher tests (Stage-1 2026-06-08) — the pure _rank_similar_blobs core.

DB-free: exercises imphash-exact + TLSH-distance matching, the max_distance cutoff, and the
imphash-first / distance-ascending sort. The full cross-firmware DB query +
supply_chain_signal needs a live canary against the running stack (noted in the commit).
"""
from __future__ import annotations

import os

import pytest

from app.ai.tools.hardware_firmware import _rank_similar_blobs

tlsh = pytest.importorskip("tlsh")


def _cand(fw, tlsh_h=None, imphash=None, sha="s"):
    return {"firmware_id": fw, "project_id": "p", "project_name": "P",
            "original_filename": "fw.bin", "blob_path": f"/{fw}", "blob_sha256": sha,
            "vendor": "qualcomm", "category": "modem", "tlsh": tlsh_h, "imphash": imphash}


def test_imphash_exact_matches_regardless_of_tlsh():
    ref = "deadbeefcafebabe"
    cands = [_cand("fw1", imphash=ref), _cand("fw2", imphash="other"), _cand("fw3", imphash=ref)]
    m = _rank_similar_blobs(None, ref, cands, 70)
    assert {x["firmware_id"] for x in m} == {"fw1", "fw3"}
    assert all(x["imphash_match"] for x in m)


def test_tlsh_distance_cutoff_and_bands():
    base = os.urandom(16384)
    near = bytearray(base); near[10] ^= 0xFF
    far = os.urandom(16384)
    ref_h = tlsh.hash(base)
    cands = [_cand("near", tlsh_h=tlsh.hash(bytes(near))), _cand("far", tlsh_h=tlsh.hash(far))]
    # tight cutoff: only the near blob matches
    m = _rank_similar_blobs(ref_h, None, cands, 40)
    assert [x["firmware_id"] for x in m] == ["near"]
    assert m[0]["tlsh_band"] in ("near_identical", "related")
    assert m[0]["tlsh_distance"] is not None and m[0]["imphash_match"] is False


def test_imphash_sorts_before_tlsh_then_by_distance():
    base = os.urandom(16384)
    ref_h = tlsh.hash(base)
    near = bytearray(base); near[1] ^= 0x01
    cands = [
        _cand("tlsh_far", tlsh_h=tlsh.hash(bytes(bytearray(base[i] ^ (i % 7) for i in range(len(base)))))),
        _cand("imphash_hit", imphash="abc"),
        _cand("tlsh_near", tlsh_h=tlsh.hash(bytes(near))),
    ]
    m = _rank_similar_blobs(ref_h, "abc", cands, 200)
    assert m[0]["firmware_id"] == "imphash_hit"          # imphash exact first
    tlsh_only = [x for x in m if not x["imphash_match"]]
    dists = [x["tlsh_distance"] for x in tlsh_only]
    assert dists == sorted(dists)                         # then ascending distance


def test_no_match_returns_empty():
    assert _rank_similar_blobs(None, None, [_cand("fw1", imphash="x")], 70) == []
    assert _rank_similar_blobs(None, "ref", [_cand("fw1", imphash="different")], 70) == []
