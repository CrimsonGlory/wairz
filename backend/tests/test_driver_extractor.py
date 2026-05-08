"""Phase γ.5 — driver_extractor tests.

Coverage layers:

1. Pure helpers — ``scan_for_inf_triplets``, ``classify_cat_signing_tier``
   (with mocked signify SignedData), ``_classify_chain``.

2. Live canary (Rule #35b) — ``auto_extract_drivers`` end-to-end through
   ``tests._live_db.make_live_db`` against a synthetic INF / CAT triplet
   on disk. SELECTs the persisted ``WindowsDriver`` + ``HardwareFirmwareBlob``
   rows to verify every field the orchestrator explicitly sets (value-flow
   verification per the audit-2026-05-04 F-A-06 lesson baked into Rule #35b).
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from unittest.mock import patch

import pytest

from app.models import Firmware, HardwareFirmwareBlob, Project, WindowsDriver
from app.services.driver_extractor import (
    _classify_chain,
    _stringify_certificate_subject,
    auto_extract_drivers,
    classify_cat_signing_tier,
    scan_for_inf_triplets,
)
from tests._live_db import make_live_db


# ── Synthetic INF + CAT fixture builders ────────────────────────────────────


_TINY_INF = """
[Version]
Class       = Display
ClassGuid   = {4d36e968-e325-11ce-bfc1-08002be10318}
Provider    = "Test Vendor"
DriverVer   = 01/15/2024,31.0.101.5333
CatalogFile = test.cat

[Manufacturer]
%TestVendor% = TestSection

[TestSection]
"Test Display Device" = InstallSection, PCI\\VEN_AAAA&DEV_BBBB

[Strings]
TestVendor = "Test Vendor"
"""


def _write_inf_triplet(
    tmp_dir, *, stem: str = "test", with_cat: bool = True, with_sys: bool = True,
) -> dict[str, str | None]:
    """Lay an INF (and optional CAT + SYS) under ``tmp_dir``."""
    os.makedirs(tmp_dir, exist_ok=True)
    inf_path = os.path.join(tmp_dir, f"{stem}.inf")
    cat_path = os.path.join(tmp_dir, f"{stem}.cat") if with_cat else None
    sys_path = os.path.join(tmp_dir, f"{stem}.sys") if with_sys else None

    with open(inf_path, "w", encoding="utf-8") as fh:
        fh.write(_TINY_INF)
    if cat_path is not None:
        # CAT body is opaque PKCS#7-shaped placeholder — the
        # classifier will fail to parse it as a real PKCS#7 envelope
        # and return ("unsigned", False, None, None) by the defensive
        # contract.
        with open(cat_path, "wb") as fh:
            fh.write(b"\x30\x82" + b"\x00" * 32)
    if sys_path is not None:
        # SYS body is a PE-shaped placeholder.
        with open(sys_path, "wb") as fh:
            fh.write(b"MZ" + b"\x00" * 32)

    return {"inf_path": inf_path, "cat_path": cat_path, "sys_path": sys_path}


# ── scan_for_inf_triplets ───────────────────────────────────────────────────


def test_scan_for_inf_triplets_finds_complete_set(tmp_path) -> None:
    triplet_dir = str(tmp_path / "drivers" / "intel_gfx")
    written = _write_inf_triplet(triplet_dir, stem="igdkmd")

    found = scan_for_inf_triplets([str(tmp_path)])
    assert len(found) == 1
    assert found[0]["inf_path"] == written["inf_path"]
    assert found[0]["cat_path"] == written["cat_path"]
    assert found[0]["sys_path"] == written["sys_path"]


def test_scan_for_inf_triplets_emits_inf_only_when_no_cat(tmp_path) -> None:
    triplet_dir = str(tmp_path / "drivers" / "lone_inf")
    written = _write_inf_triplet(triplet_dir, with_cat=False, with_sys=False)

    found = scan_for_inf_triplets([str(tmp_path)])
    assert len(found) == 1
    assert found[0]["inf_path"] == written["inf_path"]
    assert found[0]["cat_path"] is None
    assert found[0]["sys_path"] is None


def test_scan_for_inf_triplets_skips_cat_without_inf(tmp_path) -> None:
    """A bare .cat with no matching .inf is not emitted as a triplet —
    the INF is the anchor."""
    bare_cat_dir = tmp_path / "drivers" / "orphan"
    bare_cat_dir.mkdir(parents=True)
    (bare_cat_dir / "orphan.cat").write_bytes(b"\x30\x82\x00\x00")

    found = scan_for_inf_triplets([str(tmp_path)])
    assert found == []


def test_scan_for_inf_triplets_handles_missing_root() -> None:
    assert scan_for_inf_triplets(["/nonexistent/path"]) == []


def test_scan_for_inf_triplets_skips_escape_symlinks(tmp_path) -> None:
    """Symlinks pointing outside the root are rejected (Rule #1
    sandbox spirit)."""
    outside = tmp_path / "outside"
    outside.mkdir()
    real_inf = outside / "evil.inf"
    real_inf.write_text(_TINY_INF)

    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "evil.inf").symlink_to(real_inf)

    found = scan_for_inf_triplets([str(rootfs)])
    assert found == []


# ── _classify_chain (Persona-E #13 heuristic) ───────────────────────────────


@dataclass
class _FakeCert:
    subject: str
    issuer: str = "CN=test"


def test_classify_chain_empty_is_unsigned() -> None:
    assert _classify_chain([]) == "unsigned"


def test_classify_chain_whql_leaf_is_whql() -> None:
    leaf = _FakeCert(subject="CN=Microsoft Windows Hardware Compatibility Publisher")
    assert _classify_chain([leaf]) == "whql"


def test_classify_chain_vendor_with_ms_anchor_is_cross_signed() -> None:
    leaf = _FakeCert(subject="CN=Test Vendor Inc.")
    root = _FakeCert(subject="CN=Microsoft Code Verification Root")
    assert _classify_chain([leaf, root]) == "cross_signed"


def test_classify_chain_vendor_with_attestation_anchor_is_attestation() -> None:
    leaf = _FakeCert(subject="CN=Test Vendor Inc.")
    intermediate = _FakeCert(
        subject="CN=Microsoft Windows Hardware Compatibility Publisher Attestation"
    )
    root = _FakeCert(subject="CN=Microsoft Root Certificate Authority")
    assert _classify_chain([leaf, intermediate, root]) == "attestation"


def test_classify_chain_vendor_without_ms_anchor_is_unsigned() -> None:
    """A signed-but-no-MS-anchor cert is treated as unsigned per the
    Persona-E #13 safety stance."""
    leaf = _FakeCert(subject="CN=Random CA")
    root = _FakeCert(subject="CN=Some Other Root")
    assert _classify_chain([leaf, root]) == "unsigned"


# ── classify_cat_signing_tier ───────────────────────────────────────────────


def test_classify_cat_signing_tier_no_cat_path() -> None:
    tier, signed, subject, issuer = classify_cat_signing_tier(None)
    assert tier == "unsigned"
    assert signed is False
    assert subject is None
    assert issuer is None


def test_classify_cat_signing_tier_missing_cat_file(tmp_path) -> None:
    tier, signed, _subject, _issuer = classify_cat_signing_tier(
        str(tmp_path / "nope.cat")
    )
    assert tier == "unsigned"
    assert signed is False


def test_classify_cat_signing_tier_malformed_cat(tmp_path) -> None:
    """A .cat file that doesn't parse as PKCS#7 returns the unsigned
    defensive default rather than raising."""
    bad_cat = tmp_path / "bad.cat"
    bad_cat.write_bytes(b"not a pkcs7 envelope")
    tier, signed, _subject, _issuer = classify_cat_signing_tier(str(bad_cat))
    assert tier == "unsigned"
    assert signed is False


def test_stringify_certificate_subject_handles_none() -> None:
    """Defensive — a Certificate-like object whose subject access
    raises is handled gracefully."""
    class _Bad:
        @property
        def subject(self):
            raise RuntimeError("boom")
    assert _stringify_certificate_subject(_Bad()) == ""


# ── auto_extract_drivers (live canary, Rule #35b) ───────────────────────────


async def _seed_firmware(db, *, extracted_path: str) -> tuple[uuid.UUID, uuid.UUID]:
    project = Project(name="γ.5-test")
    db.add(project)
    await db.flush()
    firmware = Firmware(
        project_id=project.id,
        sha256="0" * 64,
        extracted_path=extracted_path,
    )
    db.add(firmware)
    await db.flush()
    return project.id, firmware.id


async def test_auto_extract_drivers_persists_real_driver_row(tmp_path) -> None:
    """Live canary per Rule #35b. End-to-end: scan → INF parse → CAT
    classify (defensive 'unsigned' for synthetic CAT) → persist
    HardwareFirmwareBlob (category='driver_package') + WindowsDriver.

    Exercises the REAL ORM round-trip so the value-flow contract
    (orchestrator sets X → persisted row has X) is verified end-to-end.
    """
    triplet_dir = str(tmp_path / "rootfs" / "Windows" / "INF")
    _write_inf_triplet(triplet_dir, stem="igdkmd")

    async with make_live_db() as db:
        _project_id, firmware_id = await _seed_firmware(
            db, extracted_path=str(tmp_path / "rootfs")
        )
        await db.commit()

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(tmp_path / "rootfs")]

        with patch(
            "app.services.driver_extractor.get_detection_roots",
            new=_fake_roots,
        ):
            result = await auto_extract_drivers(firmware_id, db)
        await db.commit()

        # ── Aggregate result shape ──
        assert result["driver_count"] == 1
        # Synthetic CAT can't be PKCS#7 — defensive 'unsigned' tier.
        assert result["by_signing_tier"]["unsigned"] == 1
        assert result["errors"] == []

        # ── Live SELECTs — value-flow verification ──
        from sqlalchemy import select as _sel

        blobs = (
            await db.execute(
                _sel(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == firmware_id
                )
            )
        ).scalars().all()
        assert len(blobs) == 1
        blob = blobs[0]
        assert blob.category == "driver_package"
        assert blob.format == "windows_inf"
        assert blob.detection_source == "driver_extractor"

        drivers = (
            await db.execute(
                _sel(WindowsDriver).where(WindowsDriver.blob_id == blob.id)
            )
        ).scalars().all()
        assert len(drivers) == 1
        d = drivers[0]
        assert d.inf_class == "Display"
        assert d.class_guid == "{4d36e968-e325-11ce-bfc1-08002be10318}"
        assert d.driver_provider == "Test Vendor"
        assert d.driver_version == "01/15/2024,31.0.101.5333"
        assert d.manufacturer == "%TestVendor%"  # raw mfgname token; resolved=Test Vendor
        # PnP IDs aggregated from [Models] hardware_id + compatible_ids.
        assert d.pnp_ids == ["PCI\\VEN_AAAA&DEV_BBBB"]
        assert d.signing_tier == "unsigned"
        assert d.catalog_signed is False
        # inf_metadata is stamped + JSONB-roundtripped.
        assert d.inf_metadata is not None
        assert d.inf_metadata["schema_version"] == 1
        assert (
            d.inf_metadata["version_block"]["ClassGuid"]
            == "{4d36e968-e325-11ce-bfc1-08002be10318}"
        )


async def test_auto_extract_drivers_idempotent_on_rerun(tmp_path) -> None:
    """Two consecutive runs UPDATE the same WindowsDriver row rather
    than INSERTing duplicates (UniqueConstraint on (blob_id,
    driver_path))."""
    triplet_dir = str(tmp_path / "rootfs" / "Windows" / "INF")
    _write_inf_triplet(triplet_dir, stem="igdkmd")

    async with make_live_db() as db:
        _project_id, firmware_id = await _seed_firmware(
            db, extracted_path=str(tmp_path / "rootfs")
        )
        await db.commit()

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(tmp_path / "rootfs")]

        with patch(
            "app.services.driver_extractor.get_detection_roots",
            new=_fake_roots,
        ):
            await auto_extract_drivers(firmware_id, db)
            await db.commit()
            await auto_extract_drivers(firmware_id, db)
            await db.commit()

        from sqlalchemy import select as _sel

        blobs = (
            await db.execute(
                _sel(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == firmware_id
                )
            )
        ).scalars().all()
        drivers = (
            await db.execute(_sel(WindowsDriver))
        ).scalars().all()
        assert len(blobs) == 1
        assert len(drivers) == 1


async def test_auto_extract_drivers_no_drivers_returns_empty_aggregate(
    tmp_path,
) -> None:
    """Firmware with no INF files in its tree returns driver_count=0 +
    empty histograms; no ORM rows created."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()  # Linux-shaped tree; no Windows INFs.

    async with make_live_db() as db:
        _project_id, firmware_id = await _seed_firmware(
            db, extracted_path=str(rootfs)
        )
        await db.commit()

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(rootfs)]

        with patch(
            "app.services.driver_extractor.get_detection_roots",
            new=_fake_roots,
        ):
            result = await auto_extract_drivers(firmware_id, db)
        await db.commit()

        assert result["driver_count"] == 0
        assert result["by_class_guid"] == {}

        from sqlalchemy import select as _sel

        blobs = (
            await db.execute(
                _sel(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == firmware_id
                )
            )
        ).scalars().all()
        assert blobs == []
