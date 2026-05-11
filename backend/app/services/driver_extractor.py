"""Phase γ.5 — Windows driver-package extractor + CAT signing-tier classifier.

Detects driver INF/CAT/SYS triplets in a firmware's extracted tree,
parses the INF (via :func:`app.services.driver_inf_parser.parse_inf_file`),
classifies the CAT signature into the Persona-E #13 capability badge
(``whql`` / ``attestation`` / ``cross_signed`` / ``unsigned`` /
``unknown``), and persists :class:`WindowsDriver` rows.

**Reuses the β.4-β.10 Authenticode stack** — the CAT signature
verification leverages :mod:`signify.pkcs7.SignedData` (the same library
+ certificate store + offline-trust-anchor discipline as
:mod:`app.services.authenticode_service`). γ.5 is integration only;
no new crypto code (per kickoff prompt design constraint).

**Rule #36 no-execute discipline**: nothing in this module passes an
extracted INF / CAT / SYS path to a process-spawn primitive
(``rundll32`` / ``.inf install`` / ``cscript`` / etc.). Files are
parsed AS DATA and surfaced as :class:`WindowsDriver` rows for the
operator's driver-matrix view.

**Rule #16 detection-roots**: the orchestrator walks every detection
root via :func:`get_detection_roots`, so scatter-zip + multi-partition
firmware (Android / multi-archive Windows installs) get driver
extraction uniformly without per-format hooks.

**Rule #5 sync-I/O discipline**: INF parsing + CAT signature parsing
are sync; the orchestrator wraps both in
:func:`asyncio.get_running_loop().run_in_executor` so heavy parses
don't block the event loop.

**Persona-E #13 signing-tier classification** — the heuristic:
- ``whql`` → leaf cert subject contains "Microsoft Windows Hardware
  Compatibility Publisher" (Microsoft's own code-signing CA for WHQL-
  certified drivers).
- ``attestation`` → issuer chain includes "Microsoft Windows
  Hardware Compatibility" but leaf is a vendor (Win10+ vendor
  attestation-signing root).
- ``cross_signed`` → leaf is a vendor cert AND chain anchors at a
  Microsoft cross-cert root (legacy pre-Windows-10 cross-cert path).
- ``unsigned`` → no CAT, OR CAT signature parse failed, OR the chain
  has no Microsoft anchor.
- ``unknown`` → CAT parses + has signers, but doesn't fit any of the
  above patterns.

This is a STRING-PATTERN heuristic. Full chain-walking validation
(EKU checks, CRL/OCSP, time-anchor) is out of scope for γ.5 — Phase
γ ships the matrix view; deeper classification refinement against
real CAT canaries lands in γ.9 or a follow-up.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.windows_driver import WindowsDriver
from app.services.driver_inf_parser import parse_inf_file
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_windows_drivers_inf_metadata,
)

logger = logging.getLogger(__name__)


# ── Triplet detection heuristic ──────────────────────────────────────────────

# INF files share their base name with the CAT and (typically) the
# primary SYS in a driver package. e.g. ``oem99.inf`` ↔ ``oem99.cat``
# ↔ ``oem99.sys``. We use the INF as the anchor and look for the
# matching CAT / SYS by stem in the same directory.
_INF_EXT: str = ".inf"
_CAT_EXT: str = ".cat"
_SYS_EXT: str = ".sys"


def _is_inf_file(path: str) -> bool:
    """Return True for files with a ``.inf`` extension. Sync I/O —
    caller wraps in run_in_executor (Rule #5)."""
    return os.path.isfile(path) and path.lower().endswith(_INF_EXT)


def scan_for_inf_triplets(roots: Iterable[str]) -> list[dict[str, str | None]]:
    """Walk every detection root and return a list of INF-anchored
    driver-package entries.

    Each entry is a dict with keys: ``inf_path``, ``cat_path``,
    ``sys_path`` (any may be ``None`` if the matching file isn't
    co-located). Sync I/O — wrap in run_in_executor for async callers.

    Skips symlinks pointing outside the root (Rule #1 sandbox spirit).
    """
    hits: list[dict[str, str | None]] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            # Index files by lowercase basename so .inf/.cat/.sys
            # matching is case-insensitive (Windows fs convention).
            by_stem: dict[str, dict[str, str]] = {}
            for name in filenames:
                stem, ext = os.path.splitext(name.lower())
                if ext not in (_INF_EXT, _CAT_EXT, _SYS_EXT):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                by_stem.setdefault(stem, {})[ext] = real_full
            # Emit one entry per stem that has an INF.
            for stem, files in by_stem.items():
                if _INF_EXT not in files:
                    continue
                hits.append({
                    "inf_path": files.get(_INF_EXT),
                    "cat_path": files.get(_CAT_EXT),
                    "sys_path": files.get(_SYS_EXT),
                })
    return hits


# ── CAT signing-tier classification ──────────────────────────────────────────


# Subject/issuer string patterns used to map a CAT signer cert to the
# Persona-E #13 capability badge. All comparisons are case-insensitive
# substring matches against the cert subject's CN field.
_WHQL_SUBJECT_PATTERN: str = "microsoft windows hardware compatibility publisher"
_MS_ANCHOR_SUBJECT_PATTERNS: tuple[str, ...] = (
    "microsoft root certificate authority",
    "microsoft code verification root",
    "microsoft windows hardware compatibility",
    "microsoft windows third party component ca",
)


def _stringify_certificate_subject(cert: Any) -> str:
    """Return a lower-cased string representation of a signify
    Certificate's subject. Defensive — signify exposes the subject
    via a ``subject`` attribute that may be either a string or an
    asn1crypto-style Name object depending on version."""
    try:
        subj = getattr(cert, "subject", None)
        if subj is None:
            return ""
        return str(subj).lower()
    except Exception:  # noqa: BLE001 — defensive boundary
        return ""


def _classify_chain(chain: list[Any]) -> str:
    """Apply the Persona-E #13 heuristic to a verified cert chain.

    ``chain`` is a list of signify Certificate objects, leaf first,
    root last (matches the SignedData.verify yield shape).

    Returns one of ``"whql"`` / ``"attestation"`` / ``"cross_signed"``
    / ``"unsigned"`` / ``"unknown"``. Per the module docstring:
    string-pattern heuristic only, no chain walking beyond the
    subject/issuer strings.
    """
    if not chain:
        return "unsigned"

    subjects = [_stringify_certificate_subject(c) for c in chain]
    leaf_subject = subjects[0]

    # whql — leaf cert subject IS the Microsoft Windows Hardware
    # Compatibility Publisher (Microsoft signs WHQL-certified drivers
    # with this CA's leaf).
    if _WHQL_SUBJECT_PATTERN in leaf_subject:
        return "whql"

    # Walk the rest of the chain looking for a Microsoft anchor.
    has_ms_anchor = any(
        any(p in s for p in _MS_ANCHOR_SUBJECT_PATTERNS) for s in subjects
    )

    if has_ms_anchor:
        # Vendor leaf chained through an MS root. Specific differentiator:
        # the Microsoft Windows Hardware Compatibility chain → attestation
        # (Win10+ vendor attestation); other MS roots → cross_signed
        # (legacy cross-cert chain).
        if any(_WHQL_SUBJECT_PATTERN in s for s in subjects[1:]):
            return "attestation"
        return "cross_signed"

    # Signed but no MS anchor — treat as unsigned per Persona-E #13's
    # safety stance (the operator wants visibility into untrusted
    # signers; lumping them into "unknown" hides them in mixed views).
    return "unsigned"


def classify_cat_signing_tier(
    cat_path: str | None,
) -> tuple[str, bool, str | None, str | None]:
    """Parse a CAT file's PKCS#7 signature and return
    ``(signing_tier, catalog_signed, signer_subject, signer_issuer)``.

    Sync I/O — caller wraps in run_in_executor (Rule #5).

    - ``signing_tier``: per the Persona-E #13 heuristic in
      :func:`_classify_chain`.
    - ``catalog_signed``: ``True`` if the PKCS#7 envelope parses AND
      contains at least one signer info, regardless of chain
      validation outcome (chain validation contributes to tier; the
      flag answers "did anyone sign this?").
    - ``signer_subject`` / ``signer_issuer``: leaf cert subject + issuer
      strings for the operator's matrix view.

    Defensive against every parse failure mode — a malformed CAT
    produces ``("unsigned", False, None, None)``.
    """
    if cat_path is None or not os.path.isfile(cat_path):
        return "unsigned", False, None, None

    # Lazy import — signify cold import is non-trivial; function-local
    # keeps the cost off the bootstrap path.
    from signify.authenticode import TRUSTED_CERTIFICATE_STORE
    from signify.exceptions import SignifyError
    from signify.pkcs7 import SignedData

    try:
        with open(cat_path, "rb") as fh:
            data = fh.read()
    except OSError:
        return "unsigned", False, None, None

    try:
        signed_data = SignedData.from_envelope(data)
    except SignifyError:
        return "unsigned", False, None, None
    except Exception:  # noqa: BLE001 — defensive boundary
        return "unsigned", False, None, None

    signers = list(getattr(signed_data, "signer_infos", None) or [])
    if not signers:
        return "unsigned", False, None, None

    # Try to verify; the verified chain feeds the tier classifier.
    # We accept verify failures gracefully — even a chain we can't
    # fully verify gives us a leaf cert subject we can pattern-match.
    chain: list[Any] = []
    try:
        chains_iter = signed_data.verify(
            trusted_certificate_store=TRUSTED_CERTIFICATE_STORE,
        )
        for c in chains_iter:
            chain = c
            break
    except SignifyError:
        chain = []
    except Exception:  # noqa: BLE001 — defensive boundary
        chain = []

    # Even when verify fails, dig the leaf cert out of the SignedData's
    # certificate set so we can still record subject/issuer for the
    # operator's matrix view.
    leaf_subject: str | None = None
    leaf_issuer: str | None = None
    if chain:
        leaf = chain[0]
        leaf_subject = str(getattr(leaf, "subject", "") or "") or None
        leaf_issuer = str(getattr(leaf, "issuer", "") or "") or None
    else:
        # Fallback: pull from the first signer's certificate match.
        first_signer = signers[0]
        signer_cert = getattr(first_signer, "signing_cert", None)
        if signer_cert is not None:
            leaf_subject = str(getattr(signer_cert, "subject", "") or "") or None
            leaf_issuer = str(getattr(signer_cert, "issuer", "") or "") or None

    tier = _classify_chain(chain)
    return tier, True, leaf_subject, leaf_issuer


# ── Async wrappers (Rule #5) ─────────────────────────────────────────────────


async def _scan_for_inf_triplets_async(
    roots: list[str],
) -> list[dict[str, str | None]]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, scan_for_inf_triplets, roots)


async def _parse_inf_file_async(path: str) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, parse_inf_file, path)


async def _classify_cat_signing_tier_async(
    cat_path: str | None,
) -> tuple[str, bool, str | None, str | None]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, classify_cat_signing_tier, cat_path)


# ── HardwareFirmwareBlob + WindowsDriver upserts ─────────────────────────────


def _sha256_hex(path: str) -> str:
    """Best-effort sha256 hex digest. Returns empty string on read
    failure (caller's UniqueConstraint via blob_path / driver_path
    handles dedup either way)."""
    import hashlib

    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _bytes_at(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


async def _ensure_hardware_firmware_blob(
    db: AsyncSession,
    *,
    firmware_id: uuid.UUID,
    file_path: str,
    relative_path: str,
) -> HardwareFirmwareBlob:
    """Get-or-create the HardwareFirmwareBlob row for a detected driver
    INF anchor. Sets ``category="driver_package"`` so the matrix view +
    driver-graph builders can filter on it."""
    loop = asyncio.get_running_loop()
    sha256 = await loop.run_in_executor(None, _sha256_hex, file_path)
    file_size = await loop.run_in_executor(None, _bytes_at, file_path)

    if sha256:
        existing = (
            await db.execute(
                select(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == firmware_id,
                    HardwareFirmwareBlob.blob_sha256 == sha256,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing.category != "driver_package":
                existing.category = "driver_package"
                existing.format = "windows_inf"
                existing.detection_source = "driver_extractor"
            return existing

    blob = HardwareFirmwareBlob(
        firmware_id=firmware_id,
        blob_path=relative_path,
        blob_sha256=sha256 or "",
        file_size=file_size,
        category="driver_package",
        format="windows_inf",
        detection_source="driver_extractor",
        detection_confidence="high",
    )
    db.add(blob)
    await db.flush()
    return blob


async def _ensure_windows_driver(
    db: AsyncSession,
    *,
    blob_id: uuid.UUID,
    driver_path: str,
    inf_path: str | None,
    cat_path: str | None,
    sys_path: str | None,
    inf_metadata: dict[str, Any],
    catalog_signed: bool,
    catalog_signer_subject: str | None,
    catalog_signer_issuer: str | None,
    signing_tier: str,
) -> WindowsDriver:
    """Get-or-create a WindowsDriver row for ``(blob_id, driver_path)``.

    Re-extracts UPDATE the existing row in place rather than INSERT
    a duplicate (matches the UniqueConstraint on the table).
    """
    existing = (
        await db.execute(
            select(WindowsDriver).where(
                WindowsDriver.blob_id == blob_id,
                WindowsDriver.driver_path == driver_path,
            )
        )
    ).scalar_one_or_none()

    version_block = inf_metadata.get("version_block") or {}
    manufacturer_block = inf_metadata.get("manufacturer_block") or []
    primary_manufacturer = (
        manufacturer_block[0]["name"] if manufacturer_block else None
    )
    pnp_ids: list[str] = []
    for model in inf_metadata.get("models") or []:
        hwid = model.get("hardware_id")
        if hwid and hwid not in pnp_ids:
            pnp_ids.append(hwid)
        for cid in model.get("compatible_ids") or []:
            if cid and cid not in pnp_ids:
                pnp_ids.append(cid)

    stamped_metadata = _stamp_windows_drivers_inf_metadata(dict(inf_metadata))
    driver_name = (
        manufacturer_block[0].get("name") if manufacturer_block else None
    )

    if existing is not None:
        existing.inf_path = inf_path
        existing.cat_path = cat_path
        existing.sys_path = sys_path
        existing.inf_class = version_block.get("Class")
        existing.class_guid = version_block.get("ClassGuid")
        existing.driver_provider = version_block.get("Provider")
        existing.driver_version = version_block.get("DriverVer")
        existing.driver_name = driver_name
        existing.manufacturer = primary_manufacturer
        existing.pnp_ids = pnp_ids or None
        existing.catalog_signed = catalog_signed
        existing.catalog_signer_subject = catalog_signer_subject
        existing.catalog_signer_issuer = catalog_signer_issuer
        existing.signing_tier = signing_tier
        existing.inf_metadata = stamped_metadata
        return existing

    driver = WindowsDriver(
        blob_id=blob_id,
        driver_path=driver_path,
        inf_path=inf_path,
        cat_path=cat_path,
        sys_path=sys_path,
        inf_class=version_block.get("Class"),
        class_guid=version_block.get("ClassGuid"),
        driver_provider=version_block.get("Provider"),
        driver_version=version_block.get("DriverVer"),
        driver_name=driver_name,
        manufacturer=primary_manufacturer,
        pnp_ids=pnp_ids or None,
        catalog_signed=catalog_signed,
        catalog_signer_subject=catalog_signer_subject,
        catalog_signer_issuer=catalog_signer_issuer,
        signing_tier=signing_tier,
        inf_metadata=stamped_metadata,
    )
    db.add(driver)
    await db.flush()
    return driver


# ── Orchestrator ─────────────────────────────────────────────────────────────


async def auto_extract_drivers(
    firmware_id: uuid.UUID, db: AsyncSession,
) -> dict[str, Any]:
    """Detect + extract every INF/CAT/SYS triplet in ``firmware_id``'s
    extracted tree.

    1. Resolve detection roots via :func:`get_detection_roots`
       (Rule #16).
    2. Scan filesystem for INF anchors + matching CAT / SYS in same
       directory (case-insensitive stem matching).
    3. For each triplet: parse INF (run_in_executor for Rule #5),
       classify CAT (run_in_executor for Rule #5), get/create
       HardwareFirmwareBlob (category="driver_package"), get/create
       WindowsDriver row.
    4. Return aggregate dict with run_seconds, driver_count,
       by_signing_tier histogram, by_class_guid histogram.
    """
    started = time.monotonic()

    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        return _empty_extract_result(0.0)

    roots = await get_detection_roots(firmware, db=db)
    if not roots:
        return _empty_extract_result(time.monotonic() - started)

    triplets = await _scan_for_inf_triplets_async(roots)
    if not triplets:
        return _empty_extract_result(time.monotonic() - started)

    by_signing_tier: dict[str, int] = {
        "whql": 0,
        "attestation": 0,
        "cross_signed": 0,
        "unsigned": 0,
        "unknown": 0,
    }
    by_class_guid: dict[str, int] = {}
    errors: list[str] = []

    for triplet in triplets:
        inf_path = triplet.get("inf_path")
        cat_path = triplet.get("cat_path")
        sys_path = triplet.get("sys_path")
        if inf_path is None:
            # Defensive — scan_for_inf_triplets only emits triplets
            # with an INF anchor, but be safe.
            continue

        try:
            inf_metadata = await _parse_inf_file_async(inf_path)
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            errors.append(
                f"inf parse failed for {inf_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            continue

        try:
            (
                signing_tier,
                catalog_signed,
                signer_subject,
                signer_issuer,
            ) = await _classify_cat_signing_tier_async(cat_path)
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            errors.append(
                f"cat classify failed for {cat_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            signing_tier = "unsigned"
            catalog_signed = False
            signer_subject = None
            signer_issuer = None

        # Compute relative paths under the detection root for the row.
        relative_inf = inf_path
        for r in roots:
            try:
                rp = os.path.realpath(r)  # noqa: ASYNC240 — realpath inside small bounded loop over detection roots (~1-3 entries) to compute relative path; per-root resolution acceptable
                if inf_path.startswith(rp + "/"):
                    relative_inf = inf_path[len(rp) + 1 :]
                    break
            except OSError:
                continue

        try:
            blob = await _ensure_hardware_firmware_blob(
                db,
                firmware_id=firmware_id,
                file_path=inf_path,
                relative_path=relative_inf,
            )
            await _ensure_windows_driver(
                db,
                blob_id=blob.id,
                driver_path=relative_inf,
                inf_path=relative_inf,
                cat_path=cat_path,
                sys_path=sys_path,
                inf_metadata=inf_metadata,
                catalog_signed=catalog_signed,
                catalog_signer_subject=signer_subject,
                catalog_signer_issuer=signer_issuer,
                signing_tier=signing_tier,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            errors.append(
                f"persist failed for {inf_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            continue

        by_signing_tier[signing_tier] = by_signing_tier.get(signing_tier, 0) + 1
        class_guid = (inf_metadata.get("version_block") or {}).get("ClassGuid")
        if class_guid:
            by_class_guid[class_guid] = by_class_guid.get(class_guid, 0) + 1

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "driver_count": len(triplets),
        "by_signing_tier": by_signing_tier,
        "by_class_guid": by_class_guid,
        "errors": errors,
    }


def _empty_extract_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "driver_count": 0,
        "by_signing_tier": {
            "whql": 0,
            "attestation": 0,
            "cross_signed": 0,
            "unsigned": 0,
            "unknown": 0,
        },
        "by_class_guid": {},
        "errors": [],
    }


async def auto_extract_drivers_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by
    :func:`unpack._run_hardware_firmware_detection_safe` after
    detection + graph + registry-walk complete. Same shape as the
    existing post-extraction safety helpers — owns its own session,
    swallows exceptions, logs.
    """
    try:
        async with async_session_factory() as db:
            result = await auto_extract_drivers(firmware_id, db)
            await db.commit()
            logger.info(
                "driver_extractor auto: firmware %s extracted %d drivers in "
                "%.2fs (whql=%d, attestation=%d, cross_signed=%d, "
                "unsigned=%d, unknown=%d)",
                firmware_id,
                result["driver_count"],
                result["run_seconds"],
                result["by_signing_tier"]["whql"],
                result["by_signing_tier"]["attestation"],
                result["by_signing_tier"]["cross_signed"],
                result["by_signing_tier"]["unsigned"],
                result["by_signing_tier"]["unknown"],
            )
    except Exception:
        logger.warning(
            "driver_extractor auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )
