"""RICH header decoder service — Phase β.6.

Wraps :py:meth:`pefile.PE.parse_rich_header` (pefile 2024.8.26+) into a
canonical-dict verdict that maps onto
:attr:`app.models.WindowsPESignature.rich_header_json` JSONB.

Persona-E #1 (toolchain fingerprinting) — the Microsoft RICH header sits
between the DOS stub and the PE header on every PE compiled with the
Microsoft linker since Visual Studio .NET (2002). It records, in XOR-
obfuscated form, the version + count of every Microsoft toolchain
component that linked the binary: cl.exe versions, masm versions,
linker versions, library blocks, etc. For a security RE-er this is the
most reliable single signal of:

- Compiler version (= which mitigations are present: /GS /GUARD:CF /CETCOMPAT)
- Whether the build is dual-built (different toolchain versions in same
  artifact ⇒ partial rebuild ⇒ provenance question)
- Toolchain-version drift between PE pairs in the same firmware
  (heterogeneous build pipelines often signal supply-chain anomalies)

Persona-E section 2 #1: "RICH header divergence is the cheapest signal
that a binary's build pipeline isn't what the vendor claims" — we surface
the per-binary fingerprint (and a normalized hash for cross-binary clustering)
so the cross-firmware queries land directly on the JSONB column.

Output shape (Phase β.6):

  {
    "xor_key":      str,    # "0x12345678" — the 4-byte XOR key
    "entry_count":  int,    # number of (comp_id, count) pairs
    "entries": [            # one dict per RICH entry
        {
            "comp_id":      int,    # raw 32-bit ((build<<16) | prod_id)
            "build_number": int,    # high 16 bits — toolchain build
            "product_id":   int,    # low  16 bits — toolchain product ID
            "instances":    int,    # how many times the tool was used
        },
        ...
    ],
    "hash_md5":     str,    # pefile.get_rich_header_hash() — MD5 by
                            # default; fingerprint clusters builds
                            # produced by the same toolchain pipeline
  }

Returns ``None`` for PEs with no RICH header (non-Microsoft toolchain,
deliberately stripped, or pre-VS2002 era), for non-PE inputs, and for
anything pefile raises on. Never propagates exceptions — the caller
(``authenticode_service.verify_pe_file``) treats a missing RICH header
as "no toolchain fingerprint" and persists ``rich_header_json IS NULL``
on the row.

Performance: pefile.PE(fast_load=True) only reads headers (~1 KB),
so the call is sub-millisecond on a 10 MB DLL — safe to invoke
inline from the Phase β.7 background runner.
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# Sanity bound on the per-PE entry count. The largest Microsoft binaries
# (mso.dll, OneCore composites) carry ~80 RICH entries; 1000 is well
# above any plausible legitimate maximum and protects against malformed
# PEs whose XOR'd "values" stream walks off into garbage.
_MAX_ENTRIES = 1000


def _safe_md5_hex(data: bytes) -> str:
    """Stable MD5 hex of bytes — used when pefile's
    :py:meth:`PE.get_rich_header_hash` is unavailable or raises.
    """
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def _decode_entries(values: list[int]) -> list[dict[str, int]]:
    """Decode pefile's flat ``values`` list into entry dicts.

    pefile's contract per :py:meth:`PE.parse_rich_header` is:

      values[2i]   = (build_number << 16) | product_id   (compid)
      values[2i+1] = use count

    so each pair ``(values[2i], values[2i+1])`` makes one decoded entry.
    """
    entries: list[dict[str, int]] = []
    for i in range(min(len(values) // 2, _MAX_ENTRIES)):
        comp_id = int(values[2 * i]) & 0xFFFFFFFF
        instances = int(values[2 * i + 1]) & 0xFFFFFFFF
        entries.append({
            "comp_id": comp_id,
            "build_number": (comp_id >> 16) & 0xFFFF,
            "product_id": comp_id & 0xFFFF,
            "instances": instances,
        })
    return entries


def decode_rich_header(path: str | Path) -> dict | None:
    """Decode the RICH header of a PE binary into a canonical dict.

    Returns the canonical shape (see module docstring) on success;
    ``None`` for non-PE inputs, PEs without a RICH header, missing
    files, and any pefile parse failure. Never raises — the caller
    persists ``rich_header_json IS NULL`` on no-RICH-header PEs.

    pefile is imported lazily so the format-detection import path
    stays cheap (Rule #30 lazy-import discipline; pefile is a
    moderate-cost import compared to lief but still worth deferring
    when not all callers need it).
    """
    p = Path(path)
    if not p.is_file():
        return None

    try:
        import pefile  # noqa: PLC0415 — see docstring.
    except Exception:
        logger.debug("pefile unavailable; skipping RICH header decode")
        return None

    try:
        pe = pefile.PE(str(p), fast_load=True)
    except Exception:
        # pefile raises PEFormatError on non-PE / malformed PE inputs.
        # Treat any parse failure as "no RICH header" — never propagate.
        logger.debug("pefile parse failed for %s", p, exc_info=True)
        return None

    try:
        rich = pe.parse_rich_header()
    except Exception:
        logger.debug("parse_rich_header raised on %s", p, exc_info=True)
        rich = None
    if not rich:
        # Non-Microsoft toolchain, stripped header, or pre-VS2002 PE.
        return None

    raw_values = rich.get("values") or []
    entries = _decode_entries(list(raw_values))

    # XOR key — pefile stores it as ``key`` (4 bytes, little-endian) and
    # ``checksum`` (the same key as a 32-bit int). Surface as a hex
    # string so it round-trips through JSONB without bytes-vs-str drift.
    key_bytes = rich.get("key") or b""
    if isinstance(key_bytes, (bytes, bytearray)) and len(key_bytes) == 4:
        xor_key = "0x" + bytes(key_bytes).hex().upper()
    else:
        xor_key = ""

    # Hash for cross-binary clustering. pefile exposes
    # :py:meth:`PE.get_rich_header_hash` which defaults to MD5 over the
    # cleartext (algorithm-stable for clustering even though MD5 is
    # cryptographically broken — clustering is non-cryptographic).
    raw_data = rich.get("raw_data") or b""
    try:
        hash_md5 = pe.get_rich_header_hash() or _safe_md5_hex(raw_data)
    except Exception:
        hash_md5 = _safe_md5_hex(raw_data)

    return {
        "xor_key": xor_key,
        "entry_count": len(entries),
        "entries": entries,
        "hash_md5": hash_md5,
    }
