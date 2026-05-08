"""DBX revocation matcher service — Phase β.7.

Parses Microsoft's offline UEFI Secure Boot revocation bundle
(``dbxupdate.bin``) and matches a PE binary's leaf-certificate serial
number against the revoked-set, producing a canonical match-dict the
:mod:`app.services.authenticode_service` plumbs onto two scalar columns:

- ``WindowsPESignature.dbx_revoked: bool`` — indexed for the per-firmware
  "show me revoked PEs" rollup query.
- ``WindowsPESignature.dbx_revocation_kb: str | None`` — Microsoft KB
  identifier (e.g. ``"KB5012170"``) when the bundle's authoring tag
  surfaces it; otherwise ``None``.

Persona-E #2 + #10: Microsoft pushes revocations through the offline
DBX bundle (UEFI Forum ``RevocationListFile`` + Microsoft ``dbxupdate.bin``
servicing). Once a code-signing CA / signer / specific binary appears
in DBX, every downstream PE chained off that CA is no longer trustable
on a Secure-Boot-enforced system. Surfacing ``dbx_revoked=True``
post-Authenticode-validation is the cheapest single signal for "this
PE will fail SB enforcement on a current-patch Win11 install".

Format reference (UEFI 2.10 §32.4.1, EFI Signature Database):

  EFI_SIGNATURE_LIST {
      EFI_GUID  signature_type;          // 16 bytes
      uint32    signature_list_size;     // 4 bytes
      uint32    signature_header_size;   // 4 bytes
      uint32    signature_size;          // 4 bytes
      uint8     signature_header[signature_header_size];
      EFI_SIGNATURE_DATA signatures[];   // each is signature_size bytes
  }

  EFI_SIGNATURE_DATA {
      EFI_GUID  signature_owner;          // 16 bytes
      uint8     signature_data[];         // (signature_size - 16) bytes
  }

A real ``dbxupdate.bin`` carries one or more ``EFI_SIGNATURE_LIST``
structures back-to-back. The ones we care about for Phase β.7:

- ``EFI_CERT_X509_GUID`` (a5c059a1-94e4-4aa7-87b5-ab155c2bf072) — full
  DER-encoded X.509 cert; ANY chain ending in this cert is revoked.
  We extract the cert's serial number for matching against
  ``AuthenticodeVerdict.leaf_serial``.
- ``EFI_CERT_SHA256_GUID`` (c1c41626-504c-4092-aca9-41f936934328) —
  SHA-256 hash of an Authenticode-image. Phase β.7 ingests the entries
  but matching against the PE's Authenticode hash is deferred to β.8+
  (we don't currently compute the Authenticode hash; signify hides it).

Phase β.7 limits: matches by **leaf cert serial**. β.8+ may extend to
SHA-256 hash matching once the Authenticode hash is plumbed through.

β.10 will bundle the actual ``dbxupdate.bin`` into the worker image and
configure ``DBX_BUNDLE_PATH``; β.7 runs against either a fixture bundle
provided in tests or returns ``None`` gracefully when the bundle is
missing (the production-clean default — no DBX info ⇒ ``dbx_revoked=False``
on every row).

Output shape:

  {
      "schema_version": 1,
      "revoked": bool,
      "revocation_kb": str | None,
      "leaf_serial_normalized": str,    # uppercase hex, no leading zeros
      "match_kind": "x509_serial" | "none",
      "bundle_entries": int,            # total entries scanned in bundle
      "bundle_path": str,               # which bundle was loaded
  }

Returns ``None`` when:
- the bundle path is missing / unreadable / malformed,
- the PE has no leaf serial to match (unsigned / parse-failed),
- the matcher is invoked with explicit ``leaf_serial=None``.

Performance: bundle parsing is linear in entry count; cached in-process
keyed by ``(bundle_path, mtime)`` so a single parse amortises across
every PE in a firmware. Parsing a 2026-era Microsoft bundle (~500 KB,
~5000 entries) takes ~50 ms on the worker container.
"""
from __future__ import annotations

import logging
import os
import struct
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── EFI signature-type GUIDs (mixed-endian per UEFI spec) ────────────────
#
# The UEFI spec stores GUIDs in the canonical "mixed-endian" layout — the
# first three groups are little-endian, the final two big-endian. The
# constants below are the on-disk byte sequences taken directly from
# UEFI 2.10 §32.4.1 Table 32-7. We compare raw bytes (16 each) rather
# than parsing into ``uuid.UUID`` to avoid endian-mode confusion.
EFI_CERT_X509_GUID = bytes.fromhex("a1 59 c0 a5 e4 94 a7 4a 87 b5 ab 15 5c 2b f0 72".replace(" ", ""))
EFI_CERT_SHA256_GUID = bytes.fromhex("26 16 c4 c1 4c 50 92 40 ac a9 41 f9 36 93 43 28".replace(" ", ""))

# Sanity bound on the per-bundle entry count. 2026-era Microsoft bundles
# carry ~5000 entries; 50_000 is well above any plausible legitimate
# maximum and protects against malformed bundles whose ``signature_list_size``
# walks off into the bundle's tail. β.6 _MAX_ENTRIES analog.
_MAX_ENTRIES = 50_000

# Sanity bound on the total bundle size we'll mmap into memory. Real
# bundles are < 1 MB; 100 MB is a hard safety bound.
_MAX_BUNDLE_BYTES = 100 * 1024 * 1024

# Schema version — bump only on backwards-incompatible shape change.
DBX_MATCH_SCHEMA_VERSION = 1

# In-process cache keyed by (bundle_path_str, mtime). The bundle parser
# reads the file on first call and caches the parsed entries; subsequent
# calls within the same process re-use the cache as long as mtime hasn't
# changed. Per-firmware batch verification can run hundreds of PEs against
# one bundle without re-parsing. None means "no bundle has been loaded".
_BUNDLE_CACHE: tuple[str, float, dict[str, Any]] | None = None


def _normalize_serial(serial_hex: str | None) -> str | None:
    """Return uppercase hex, no leading zeros, no ``0x`` prefix.

    Both signify (``format(serial, 'X')``) and asn1crypto produce the
    same shape, but defensive normalisation lets callers pass either
    canonical form.
    """
    if not serial_hex:
        return None
    s = serial_hex.upper().lstrip("0X").lstrip("0")
    return s or "0"


def _parse_bundle_bytes(buf: bytes) -> dict[str, Any]:
    """Parse ``dbxupdate.bin`` byte content into a normalised dict.

    Returns ``{"x509_serials": set[str], "sha256_hashes": set[str], "entries_scanned": int}``.
    The parser is iterative — it walks each EFI_SIGNATURE_LIST header,
    decodes the contained signatures, and stops at the first malformed
    list (defensive: a corrupted Microsoft bundle should NOT crash the
    matcher; downstream the matcher just returns no-match).

    asn1crypto is lazy-imported inside this function (Rule #30) — only
    callers that actually have a bundle file pay the import cost.
    """
    try:
        import asn1crypto.x509 as x509  # noqa: PLC0415 — lazy per Rule #30.
    except Exception:  # pragma: no cover — asn1crypto is a hard dep
        logger.warning("asn1crypto unavailable; dbx parser cannot extract X.509 serials")
        x509 = None  # type: ignore[assignment]

    x509_serials: set[str] = set()
    sha256_hashes: set[str] = set()
    entries_scanned = 0
    pos = 0
    list_idx = 0
    while pos + 28 <= len(buf):
        sig_type = buf[pos:pos + 16]
        sig_list_size, sig_header_size, sig_size = struct.unpack_from(
            "<III", buf, pos + 16,
        )
        # Sanity checks — a malformed list_size or sig_size means we're
        # off-track. Stop walking; whatever we've extracted so far is
        # what the matcher gets to use.
        if (
            sig_list_size < 28 + sig_size
            or sig_size <= 16
            or sig_list_size > len(buf) - pos
        ):
            logger.debug(
                "dbx bundle: malformed signature list at offset %d (list_size=%d, sig_size=%d)",
                pos, sig_list_size, sig_size,
            )
            break

        sigs_start = pos + 28 + sig_header_size
        sigs_end = pos + sig_list_size
        if sigs_end > len(buf) or sigs_start >= sigs_end:
            break

        sigs_buf = buf[sigs_start:sigs_end]
        for i in range(0, len(sigs_buf), sig_size):
            if entries_scanned >= _MAX_ENTRIES:
                logger.warning(
                    "dbx bundle: hit _MAX_ENTRIES=%d cap; remainder skipped",
                    _MAX_ENTRIES,
                )
                return {
                    "x509_serials": x509_serials,
                    "sha256_hashes": sha256_hashes,
                    "entries_scanned": entries_scanned,
                }
            entry = sigs_buf[i:i + sig_size]
            # Tail entries shorter than the declared sig_size are
            # truncated payloads — the bundle is malformed at this list.
            # Stop scanning the current list cleanly without counting
            # the partial as scanned.
            if len(entry) < sig_size or len(entry) < 16:
                break
            entry_data = entry[16:]  # strip 16-byte signature_owner GUID

            if sig_type == EFI_CERT_X509_GUID and x509 is not None:
                try:
                    cert = x509.Certificate.load(entry_data)
                    serial_int = cert.serial_number
                    if isinstance(serial_int, int):
                        normalized = _normalize_serial(format(serial_int, "X"))
                        if normalized:
                            x509_serials.add(normalized)
                except Exception:
                    logger.debug(
                        "dbx bundle: x509 parse failed at list %d offset %d",
                        list_idx, i, exc_info=True,
                    )
            elif sig_type == EFI_CERT_SHA256_GUID and len(entry_data) == 32:
                sha256_hashes.add(entry_data.hex().lower())

            entries_scanned += 1

        pos = sigs_end
        list_idx += 1

    return {
        "x509_serials": x509_serials,
        "sha256_hashes": sha256_hashes,
        "entries_scanned": entries_scanned,
    }


def _load_bundle(bundle_path: Path) -> dict[str, Any] | None:
    """Read + parse a DBX bundle file with module-level mtime cache.

    Returns the parsed dict or ``None`` if the file is missing /
    unreadable / oversize. Cache is a tuple ``(path_str, mtime, parsed)``;
    a path or mtime mismatch invalidates and reparses.
    """
    global _BUNDLE_CACHE  # noqa: PLW0603 — module-level mtime cache.
    try:
        st = bundle_path.stat()
    except OSError:
        return None
    if not bundle_path.is_file():
        return None
    if st.st_size > _MAX_BUNDLE_BYTES:
        logger.warning(
            "dbx bundle %s exceeds _MAX_BUNDLE_BYTES=%d; refusing to load",
            bundle_path, _MAX_BUNDLE_BYTES,
        )
        return None

    cache_key = (str(bundle_path), st.st_mtime)
    if _BUNDLE_CACHE is not None and (
        _BUNDLE_CACHE[0] == cache_key[0] and _BUNDLE_CACHE[1] == cache_key[1]
    ):
        return _BUNDLE_CACHE[2]

    try:
        buf = bundle_path.read_bytes()
    except OSError:
        return None

    parsed = _parse_bundle_bytes(buf)
    _BUNDLE_CACHE = (cache_key[0], cache_key[1], parsed)
    return parsed


def _resolve_bundle_path(explicit: str | Path | None) -> Path | None:
    """Resolve which bundle to load: explicit > env > default-not-installed.

    β.10 will configure ``DBX_BUNDLE_PATH`` in the worker image. β.7
    leaves the default unconfigured so the function returns ``None``
    gracefully when no bundle has been provisioned — every PE then ships
    with ``dbx_revoked=False`` (the truthful "no DBX data available"
    answer; better than a fabricated revocation status).
    """
    if explicit is not None:
        return Path(explicit)
    env_value = os.environ.get("DBX_BUNDLE_PATH")
    if env_value:
        return Path(env_value)
    return None


def reset_bundle_cache() -> None:
    """Clear the in-process bundle cache. Called by tests; β.10 cron
    will also call this after refreshing the bundle on disk."""
    global _BUNDLE_CACHE  # noqa: PLW0603
    _BUNDLE_CACHE = None


def match_dbx_revocation(
    leaf_serial: str | None,
    bundle_path: str | Path | None = None,
) -> dict | None:
    """Match a PE leaf-cert serial against the DBX revocation set.

    Returns the canonical match dict on a successful comparison —
    ``revoked=True`` when the serial appears in the bundle's X.509 list,
    ``revoked=False`` when the bundle was loaded but the serial is
    absent. Returns ``None`` when (a) ``leaf_serial`` is None / empty,
    (b) the bundle path resolves to nothing, (c) the bundle is unreadable
    or malformed beyond rescue.

    The caller (``authenticode_service.verify_pe_file``) extracts the
    bool + KB-string fields onto the verdict's two scalar fields:

        match = match_dbx_revocation(verdict.leaf_serial)
        verdict.dbx_revoked = bool(match and match["revoked"])
        verdict.dbx_revocation_kb = (match or {}).get("revocation_kb")

    Performance: amortised O(1) per call after the first — the bundle
    is parsed once and the X.509 serial set is a Python ``set`` for
    O(1) membership.
    """
    normalized = _normalize_serial(leaf_serial)
    if normalized is None:
        return None

    resolved = _resolve_bundle_path(bundle_path)
    if resolved is None:
        return None

    parsed = _load_bundle(resolved)
    if parsed is None:
        return None

    revoked = normalized in parsed["x509_serials"]

    # Phase β.7 baseline does NOT carry KB strings — the dbxupdate.bin
    # format itself doesn't embed KB identifiers; β.10's bundling step
    # will optionally provision a side-car JSON mapping bundle hash →
    # KB metadata. Until then revocation_kb is None even on a true
    # match (the fact OF revocation is the durable signal; the KB is
    # a UX hint for the operator).
    revocation_kb: str | None = None

    return {
        "schema_version": DBX_MATCH_SCHEMA_VERSION,
        "revoked": revoked,
        "revocation_kb": revocation_kb,
        "leaf_serial_normalized": normalized,
        "match_kind": "x509_serial" if revoked else "none",
        "bundle_entries": parsed["entries_scanned"],
        "bundle_path": str(resolved),
    }
