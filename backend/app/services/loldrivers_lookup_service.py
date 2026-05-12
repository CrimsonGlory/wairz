"""LOLDrivers BYOVD fingerprinting lookup — Phase η.D.

Reads the build-time-bundled LOLDrivers JSON data set from
``$LOLDRIVERS_BUNDLE_PATH`` (default ``/opt/wairz/loldrivers.json``) and
maps Windows driver blob SHA256 hashes to known-vulnerable / known-
malicious drivers per the upstream ``magicsword-io/LOLDrivers`` data set
(Apache-2.0 licensed; bundled per CLAUDE.md Rule #37 — offline-trust-
anchor discipline; backend/ms-anchors/loldrivers.json).

Per Rule #36 no-execute discipline: the bundle is read AS DATA only;
driver content is never invoked. The walker passes the SHA256 of an
already-extracted driver blob; this module returns the BYOVD verdict
(record metadata + category + CVE list) without ever touching the blob
bytes itself.

Per Rule #37 graceful-degrade discipline: missing / empty / unreadable
bundle → :func:`lookup_driver_byovd` returns ``None`` and
:func:`is_loldrivers_available` returns ``False``. The caller sees the
truthful "no BYOVD data available" verdict, never a fabricated answer.

Per Rule #35c JSONB normalizer discipline: the upstream JSON has THREE
known shape anomalies (verified via Rule #19 evidence-first probe on the
2026-05-11 bundle):

1. ``CVE`` ∪ ``CVEs`` key-drift — 78/622 records have ``CVE`` (only
   22/622 with non-empty values); 1/622 has ``CVEs`` instead. The
   normalizer coalesces both into a single ``cve_ids`` list and drops
   empty strings.
2. 23/2132 ``KnownVulnerableSamples`` carry FLAT duplicate hash keys
   (``AuthentihashSHA256``, ``CompanyName``, ``SHA256``) ALONGSIDE the
   nested ``Authentihash.SHA256`` dict. The normalizer merges flat keys
   into the nested form so downstream consumers see one canonical shape.
3. Case drift — ``Verified`` is ``"TRUE"`` (544×) / ``"FALSE"`` (77×) /
   ``"True"`` (1×). The normalizer collapses to bool.

The bundle has NO ``schema_version`` field, so the normalizer is the
ONLY discriminator (Rule #35c worked example: legacy shape coexists with
canonical shape; consumer must normalize at the boundary).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ── Bundle path resolution ───────────────────────────────────────────────────


_DEFAULT_BUNDLE_PATH = "/opt/wairz/loldrivers.json"


def _resolve_bundle_path(explicit: str | Path | None = None) -> Path | None:
    """Return the resolved bundle path, or ``None`` if no bundle is
    configured. Mirrors ``dbx_service._resolve_bundle_path`` for parity.

    Resolution order:
    1. Explicit caller-supplied path (test fixture override).
    2. ``$LOLDRIVERS_BUNDLE_PATH`` env var.
    3. Default ``/opt/wairz/loldrivers.json`` (where the Dockerfile lands
       the bundle in η.D.A).

    Returns ``None`` only when the resolution produced an empty string —
    operators who explicitly want to disable BYOVD lookup can set
    ``LOLDRIVERS_BUNDLE_PATH=`` (empty) to get the truthful "no BYOVD
    data" verdict.
    """
    if explicit is not None:
        return Path(explicit)
    env_value = os.environ.get("LOLDRIVERS_BUNDLE_PATH")
    if env_value == "":
        return None
    if env_value:
        return Path(env_value)
    return Path(_DEFAULT_BUNDLE_PATH)


# ── BYOVD verdict shape ──────────────────────────────────────────────────────


class BYOVDVerdict(BaseModel):
    """Canonical BYOVD verdict returned by :func:`lookup_driver_byovd`.

    Field map per intake η.D contract:

    - ``sha256`` — the lookup key that matched (lowercase hex). Either
      the PE's file SHA256 OR the Authenticode hash, whichever surfaced
      the record. ``sha256_match_kind`` discriminates.
    - ``authentihash_sha256`` — the LOLDrivers record's
      ``Authentihash.SHA256`` field (NOT the lookup key necessarily).
      Useful for confirming re-signed-variant matches.
    - ``filename`` — first ``KnownVulnerableSamples[].Filename`` value
      (operator-visible label).
    - ``category`` — ``"vulnerable driver"`` or ``"malicious"``.
    - ``cve_ids`` — list of CVE identifiers coalesced from upstream
      ``CVE`` ∪ ``CVEs``. Empty list when no CVE association.
    - ``mitre_id`` — upstream ``MitreID`` field (typically ``T1068``
      Exploitation for Privilege Escalation).
    - ``loldrivers_id`` — upstream ``Id`` field (UUIDv4). Used to build
      the reference URL ``https://www.loldrivers.io/drivers/{id}/``.
    - ``loads_despite_hvci`` — heuristic flag derived from upstream
      ``Tags`` containing ``"HVCI"`` or ``"hvci-disabled"``. Optional;
      omitted when no signal in the record.
    - ``sha256_match_kind`` — ``"file"`` (matched on KVS SHA256) or
      ``"authentihash"`` (matched on Authentihash.SHA256). Auditable
      provenance for the lookup result.
    """

    sha256: str
    authentihash_sha256: str | None
    filename: str | None
    category: str
    cve_ids: list[str]
    mitre_id: str | None
    loldrivers_id: str
    loads_despite_hvci: bool = False
    sha256_match_kind: str  # "file" | "authentihash"


# ── Normalizers (Rule #35c — boundary shape discipline) ─────────────────────


def _normalize_cve_ids(record: dict) -> list[str]:
    """Coalesce upstream ``CVE`` ∪ ``CVEs`` keys into a single list.

    Rule #35c boundary normalizer. The upstream JSON has both keys in
    different records (78/622 with ``CVE``; 1/622 with ``CVEs`` instead).
    Empty strings are dropped (only 22/622 records with ``CVE`` had
    non-empty values per the 2026-05-11 probe).

    Idempotent. Returns ``[]`` for missing / malformed inputs.
    """
    out: list[str] = []
    seen: set[str] = set()
    for key in ("CVE", "CVEs"):
        value = record.get(key)
        if not isinstance(value, list):
            continue
        for entry in value:
            if not isinstance(entry, str):
                continue
            stripped = entry.strip()
            if not stripped:
                continue
            if stripped in seen:
                continue
            seen.add(stripped)
            out.append(stripped)
    return out


def _normalize_sample(sample: Any) -> dict:
    """Normalize one ``KnownVulnerableSamples`` entry to canonical shape.

    Rule #35c boundary normalizer. The upstream JSON has 23/2132 samples
    with FLAT duplicate hash keys (``AuthentihashSHA256``, ``CompanyName``,
    ``SHA256``) alongside the nested ``Authentihash.SHA256`` form. This
    normalizer merges flat keys into the nested shape so downstream
    consumers see ONE canonical access pattern.

    Returns ``{}`` for non-dict inputs (defensive boundary).
    """
    if not isinstance(sample, dict):
        return {}
    out = dict(sample)

    # Merge flat AuthentihashSHA256 into the nested Authentihash dict.
    flat_auth = out.pop("AuthentihashSHA256", None)
    if flat_auth and isinstance(flat_auth, str):
        nested = out.get("Authentihash")
        if not isinstance(nested, dict):
            nested = {}
        nested.setdefault("SHA256", flat_auth)
        out["Authentihash"] = nested

    return out


def _normalize_hash(value: Any) -> str | None:
    """Normalize a hash string to lowercase, stripped, non-empty.

    Returns ``None`` for missing / non-string / empty inputs. Used at the
    LOOKUP boundary so callers can pass hashes in any case + with any
    leading/trailing whitespace without having to pre-clean.
    """
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    return cleaned or None


# ── In-memory index ──────────────────────────────────────────────────────────


class _BundleIndex:
    """Pre-built in-memory lookup index.

    Built ONCE at lifespan startup (or on first lookup if the lifespan
    probe didn't run — e.g. in unit tests). Carries TWO dicts:

    - ``by_sha256`` — ``{sha256_lowercase: (record_dict, sample_dict)}``
      keyed on the KVS ``SHA256`` (the PE file hash). Primary lookup key.
    - ``by_authentihash`` — ``{authentihash_sha256_lowercase: same}``
      keyed on the KVS ``Authentihash.SHA256`` (the Authenticode hash —
      excludes the signature directory). Secondary key for re-signed
      variants.

    ``entries`` tracks the total number of KVS samples indexed; the
    lifespan probe surfaces this for operators.
    """

    def __init__(
        self,
        by_sha256: dict[str, tuple[dict, dict]],
        by_authentihash: dict[str, tuple[dict, dict]],
        entries: int,
        record_count: int,
    ) -> None:
        self.by_sha256 = by_sha256
        self.by_authentihash = by_authentihash
        self.entries = entries
        self.record_count = record_count


_INDEX_CACHE: _BundleIndex | None = None


def reset_index_cache() -> None:
    """Clear the in-process index cache. Called by tests; also useful
    after the host-side refresh script swaps the on-disk bundle (the
    cache survives the file swap until a process restart by default)."""
    global _INDEX_CACHE  # noqa: PLW0603
    _INDEX_CACHE = None


def _build_index(records: list[dict]) -> _BundleIndex:
    """Build the in-memory index from a parsed records list."""
    by_sha256: dict[str, tuple[dict, dict]] = {}
    by_authentihash: dict[str, tuple[dict, dict]] = {}
    entries = 0

    for record in records:
        if not isinstance(record, dict):
            continue
        samples = record.get("KnownVulnerableSamples") or []
        if not isinstance(samples, list):
            continue
        for raw_sample in samples:
            sample = _normalize_sample(raw_sample)
            if not sample:
                continue
            entries += 1

            # Primary key: the PE file hash.
            sha256 = _normalize_hash(sample.get("SHA256"))
            if sha256 and sha256 not in by_sha256:
                by_sha256[sha256] = (record, sample)

            # Secondary key: Authenticode hash (re-signed variants).
            nested = sample.get("Authentihash")
            if isinstance(nested, dict):
                authentihash = _normalize_hash(nested.get("SHA256"))
                if authentihash and authentihash not in by_authentihash:
                    by_authentihash[authentihash] = (record, sample)

    return _BundleIndex(
        by_sha256=by_sha256,
        by_authentihash=by_authentihash,
        entries=entries,
        record_count=len(records),
    )


def _load_index(
    bundle_path: str | Path | None = None,
) -> _BundleIndex | None:
    """Load and cache the in-memory lookup index.

    Returns ``None`` on missing / empty / malformed bundle (graceful
    degrade per Rule #37 — caller surfaces "no BYOVD data" rather than a
    fabricated verdict).
    """
    global _INDEX_CACHE  # noqa: PLW0603
    if _INDEX_CACHE is not None:
        return _INDEX_CACHE

    resolved = _resolve_bundle_path(bundle_path)
    if resolved is None:
        logger.warning(
            "loldrivers: $LOLDRIVERS_BUNDLE_PATH explicitly empty — BYOVD "
            "lookup disabled; all verdicts will be None.",
        )
        return None

    try:
        raw_bytes = resolved.read_bytes()  # noqa: ASYNC240 — one-shot lifespan / lazy load; not on a request hot path
    except FileNotFoundError:
        logger.warning(
            "loldrivers: bundle NOT FOUND at %s — BYOVD lookup disabled. "
            "Rebuild the worker image (Rule #8) or run "
            "scripts/refresh-loldrivers.sh.",
            resolved,
        )
        return None
    except OSError:
        logger.warning(
            "loldrivers: bundle at %s unreadable — BYOVD lookup disabled.",
            resolved,
            exc_info=True,
        )
        return None

    if not raw_bytes:
        logger.warning(
            "loldrivers: bundle at %s is empty (0 bytes) — BYOVD lookup "
            "disabled.",
            resolved,
        )
        return None

    try:
        records = json.loads(raw_bytes)
    except json.JSONDecodeError:
        logger.warning(
            "loldrivers: bundle at %s does not parse as JSON — BYOVD "
            "lookup disabled.",
            resolved,
            exc_info=True,
        )
        return None

    if not isinstance(records, list):
        logger.warning(
            "loldrivers: bundle at %s top-level is %s, expected list — "
            "BYOVD lookup disabled.",
            resolved,
            type(records).__name__,
        )
        return None

    index = _build_index(records)
    if index.entries == 0:
        logger.warning(
            "loldrivers: bundle at %s parsed but contains 0 KVS entries — "
            "BYOVD lookup disabled.",
            resolved,
        )
        return None

    _INDEX_CACHE = index
    return index


# ── Public API ───────────────────────────────────────────────────────────────


def is_loldrivers_available(
    bundle_path: str | Path | None = None,
) -> bool:
    """Return True if the LOLDrivers bundle is readable + parses + indexed
    at least one entry.

    Companion to :func:`lookup_driver_byovd`. Use this to gate operator-
    visible "BYOVD data not available" messages or to skip the lookup
    entirely in code paths where the bundle's absence is expected
    (development without a built worker image).
    """
    return _load_index(bundle_path) is not None


def lookup_driver_byovd(
    blob_sha256: str,
    bundle_path: str | Path | None = None,
) -> BYOVDVerdict | None:
    """Look up a Windows driver blob SHA256 against the LOLDrivers data set.

    Returns a :class:`BYOVDVerdict` populated with the canonical fields
    when the hash matches a known-vulnerable / known-malicious driver in
    the bundle. Returns ``None`` when:

    - the hash is None / empty / non-string
    - the bundle is not available (missing / unreadable / malformed)
    - the hash matches no record

    Matches against the PRIMARY key first (KVS ``SHA256`` — the PE file
    hash). On miss, falls back to the SECONDARY key (KVS
    ``Authentihash.SHA256`` — the Authenticode hash excluding the
    signature directory). The discriminator field
    ``BYOVDVerdict.sha256_match_kind`` records which lookup path won.

    The caller (driver-package unpacker hook + γ Services hive walker)
    supplies ``blob_sha256`` from the already-computed
    ``hardware_firmware_blobs.sha256`` column.

    Performance: amortised O(1) per call after the first — the bundle is
    parsed once and the lookup dicts give O(1) membership.
    """
    normalized = _normalize_hash(blob_sha256)
    if normalized is None:
        return None

    index = _load_index(bundle_path)
    if index is None:
        return None

    match_kind = "file"
    pair = index.by_sha256.get(normalized)
    if pair is None:
        match_kind = "authentihash"
        pair = index.by_authentihash.get(normalized)
    if pair is None:
        return None

    record, sample = pair

    # ── Project to canonical verdict shape ────────────────────────────
    nested_auth = sample.get("Authentihash") if isinstance(sample.get("Authentihash"), dict) else {}
    authentihash_sha256 = _normalize_hash(nested_auth.get("SHA256"))

    filename = sample.get("Filename")
    if not isinstance(filename, str):
        filename = None

    category_raw = record.get("Category")
    category = category_raw if isinstance(category_raw, str) else "unknown"

    cve_ids = _normalize_cve_ids(record)

    mitre_id_raw = record.get("MitreID")
    mitre_id = mitre_id_raw if isinstance(mitre_id_raw, str) and mitre_id_raw else None

    loldrivers_id_raw = record.get("Id")
    loldrivers_id = loldrivers_id_raw if isinstance(loldrivers_id_raw, str) else "unknown"

    # HVCI bypass tag detection — upstream Tags is list[str].
    loads_despite_hvci = False
    tags = record.get("Tags")
    if isinstance(tags, list):
        for tag in tags:
            if not isinstance(tag, str):
                continue
            tag_lower = tag.lower()
            if "hvci" in tag_lower and ("bypass" in tag_lower or "disabled" in tag_lower or "loads" in tag_lower):
                loads_despite_hvci = True
                break

    return BYOVDVerdict(
        sha256=normalized,
        authentihash_sha256=authentihash_sha256,
        filename=filename,
        category=category,
        cve_ids=cve_ids,
        mitre_id=mitre_id,
        loldrivers_id=loldrivers_id,
        loads_despite_hvci=loads_despite_hvci,
        sha256_match_kind=match_kind,
    )


def reference_url(loldrivers_id: str) -> str:
    """Build the operator-facing LOLDrivers reference URL.

    Used by the η.D.D ``classify_byovd_finding`` helper to put a clickable
    URL in the Finding's ``evidence`` field. The URL form is:

        https://www.loldrivers.io/drivers/{id}/

    Documented at https://www.loldrivers.io/api/ — every record's
    ``Id`` resolves to a public detail page under this prefix.
    """
    return f"https://www.loldrivers.io/drivers/{loldrivers_id}/"


__all__ = [
    "BYOVDVerdict",
    "is_loldrivers_available",
    "lookup_driver_byovd",
    "reference_url",
    "reset_index_cache",
]
