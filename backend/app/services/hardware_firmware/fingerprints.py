"""Blob fingerprints (R2, Stage-1 2026-06-08) — TLSH fuzzy hash + PE imphash for
cross-firmware supply-chain similarity (Rule #44).

PARSE-ONLY (Rule #45): these read bytes and hash/parse them; they never execute a blob.
EVERY function degrades to ``None`` on any failure — a fingerprint must NEVER break firmware
detection. Both are LOW standalone confidence (Rule #53 / Mandiant "Breaking Imphash":
packed or few-import bootloaders defeat imphash; tiny/low-entropy blobs have no TLSH) — they
RAISE-to-re-examine across firmwares, they never lower a disposition to cleared.

TLSH is computed in the detector's existing single-pass sha256 read (no extra file read).
imphash is PE-specific (computed post-classify only for ``pe_binary`` blobs).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

FINGERPRINT_SCHEMA_VERSION = 1


def new_tlsh():
    """Fresh streaming TLSH accumulator, or None if tlsh is unavailable (Rule #30 lazy import
    — tlsh is an optional C-extension dep; non-firmware paths must not pay its import)."""
    try:
        import tlsh  # noqa: PLC0415
    except ImportError:
        return None
    try:
        return tlsh.Tlsh()
    except Exception:  # noqa: BLE001 — never break detection on a fingerprint accumulator
        return None


def update_tlsh(acc, chunk: bytes) -> None:
    """Feed a chunk to the accumulator (no-op if acc is None)."""
    if acc is None or not chunk:
        return
    try:
        acc.update(chunk)
    except Exception:  # noqa: BLE001 — pure-data update; degrade silently
        pass


def finalize_tlsh(acc) -> str | None:
    """Finalize -> 72-char ``T1…`` hex, or None (tlsh raises ValueError on <50 bytes input
    or insufficient entropy — that is the correct 'no fuzzy hash' answer, not an error)."""
    if acc is None:
        return None
    try:
        acc.final()
        return acc.hexdigest() or None
    except ValueError:
        return None  # <50 bytes / too little variance — no TLSH (expected for tiny blobs)
    except Exception:  # noqa: BLE001 — never break detection
        return None


def compute_imphash(path: str) -> str | None:
    """PE import-table hash (Mandiant imphash). None for non-PE / packed / no-import / any
    failure. LOW standalone confidence — caller must treat a match as RAISE-to-re-examine."""
    try:
        import pefile  # noqa: PLC0415 — optional/heavy dep; lazy per Rule #30
    except ImportError:
        return None
    pe = None
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        ih = pe.get_imphash()
        return ih or None
    except Exception:  # noqa: BLE001 — non-PE / malformed PE / parse failure -> no imphash
        logger.debug("imphash unavailable for %s", path, exc_info=True)
        return None
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:  # noqa: BLE001
                pass


def tlsh_distance(a: str | None, b: str | None) -> int | None:
    """TLSH diff: 0 = identical; lower = more similar. Heuristic bands (malware-corpus
    convention; calibrate per corpus before hardcoding cutoffs): <=30 near-identical,
    <=70 related, >70 unrelated. None if either hash is missing/invalid."""
    if not a or not b:
        return None
    try:
        import tlsh  # noqa: PLC0415
        return tlsh.diff(a, b)
    except Exception:  # noqa: BLE001
        return None


def normalize_blob_fingerprints(value) -> dict:
    """Rule #35c boundary normaliser for ``metadata_['fingerprints']``.

    Canonical: ``{'schema_version': 1, 'tlsh': str|None, 'imphash': str|None}``. Defensive on
    None / wrong-type / legacy shapes; idempotent (normalising a canonical value is a no-op)."""
    out = {"schema_version": FINGERPRINT_SCHEMA_VERSION, "tlsh": None, "imphash": None}
    if isinstance(value, dict):
        t = value.get("tlsh")
        ih = value.get("imphash")
        if isinstance(t, str) and t:
            out["tlsh"] = t
        if isinstance(ih, str) and ih:
            out["imphash"] = ih
    return out


def stamp_blob_fingerprints(tlsh_digest: str | None, imphash: str | None) -> dict:
    """Writer helper — produce the canonical fingerprints dict for ``metadata_``."""
    return normalize_blob_fingerprints({"tlsh": tlsh_digest, "imphash": imphash})
