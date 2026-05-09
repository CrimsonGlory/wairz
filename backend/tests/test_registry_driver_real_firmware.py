"""Phase γ.9 — Rule #35b real-firmware end-to-end canary set.

Activates the deferred real-firmware canary identified in the γ.9
cut-over kickoff: drives the FULL γ pipeline (γ.4 walker → γ.5
driver extractor → γ.8 finding emit) against on-disk fixtures and
asserts cumulative end-to-end behaviour.

Mirrors the β.14a precedent (pattern #1 — real-PE canary skip-tier
discipline). 3 tiers:

  - **Tier 1 (always runs)** — synthetic fixture: a regf-magic
    SOFTWARE hive + a tiny INF/CAT triplet laid on disk. Drives
    ``auto_walk_firmware`` (γ.4) → ``auto_extract_drivers`` (γ.5)
    → ``emit_registry_findings_from_walk`` (γ.8) →
    ``emit_driver_findings_from_extract`` (γ.8). Assertions:
      (a) ≥1 HardwareFirmwareBlob with category="registry_hive"
      (b) ≥1 HardwareFirmwareBlob with category="driver_package"
      (c) ≥1 WindowsRegistryExtract row
      (d) ≥1 WindowsDriver row
      (e) ≥1 Finding row from a γ source (any of the 3)
    Synthetic CAT fails to parse as PKCS#7 → tier='unsigned' → emits
    a windows_inf finding (medium severity); synthetic regfile passes
    the magic check but regipy may fail to parse the truncated
    structure → walker returns partial parsed_tree with errors.
    Both paths exercise the orchestrator + emit pipeline end-to-end
    even when the underlying parsers can't fully decode.

  - **Tier 2 (skip-unless ``WAIRZ_TEST_REAL_HIVE``)** — drives a real
    Win11 SOFTWARE / SYSTEM hive through ``walk_hive_path``. Asserts
    the walker produces a non-empty subkeys list with ``walk_complete=
    True``, the regipy parse succeeds without errors, and the
    classify_registry_persistence_findings classifier emits at least
    one persistence-relevant draft (real hives reliably contain Run
    and/or Services subkeys).

  - **Tier 3 (skip-unless ``WAIRZ_TEST_SIGNED_CAT``)** — drives a
    real Microsoft-signed driver .cat through
    ``classify_cat_signing_tier``. Asserts signing_tier IN
    ('whql', 'attestation', 'cross_signed') (any Microsoft-anchored
    chain) and catalog_signed=True. Provisioning path: any signed
    driver INF package from C:/Windows/INF on a real Windows install.

Fixture provisioning (operator graduation path):

    export WAIRZ_TEST_REAL_HIVE=/path/to/SOFTWARE
    export WAIRZ_TEST_SIGNED_CAT=/path/to/iigd_dch.cat
    pytest tests/test_registry_driver_real_firmware.py -v

The canary set graduates from "partial" (3 pass + 2 skip on a typical
Linux dev host) to "full" (5 pass) via fixture commits — no test
edits needed. Mirrors β.14a's graduation shape.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from app.models import (
    Finding,
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsDriver,
    WindowsRegistryExtract,
)
from app.services.driver_extractor import (
    auto_extract_drivers,
    classify_cat_signing_tier,
)
from app.services.finding_service import (
    FindingService,
    classify_registry_persistence_findings,
)
from app.services.registry_hive_walker import auto_walk_firmware, walk_hive_path
from tests._live_db import make_live_db

# ── Fixture env-var probes ──────────────────────────────────────────────────


_HOST_REAL_HIVE_FIXTURE = os.environ.get("WAIRZ_TEST_REAL_HIVE")
_HOST_SIGNED_CAT_FIXTURE = os.environ.get("WAIRZ_TEST_SIGNED_CAT")


# ── Synthetic fixture builders (Tier 1) ─────────────────────────────────────


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


def _write_synthetic_hive(path: str) -> None:
    """Lay a regf-magic-prefixed file at ``path`` (4 KiB total)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"regf" + b"\x00" * 4092)


def _write_synthetic_inf_cat_triplet(dirpath: str) -> None:
    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, "test.inf"), "w") as fh:
        fh.write(_TINY_INF)
    with open(os.path.join(dirpath, "test.cat"), "wb") as fh:
        fh.write(b"\x30\x82" + b"\x00" * 64)
    with open(os.path.join(dirpath, "test.sys"), "wb") as fh:
        fh.write(b"MZ" + b"\x00" * 64)


# ── Tier 1: synthetic fixture, always runs ──────────────────────────────────


async def test_tier1_synthetic_full_pipeline_persists_blobs_and_findings(
    tmp_path,
) -> None:
    """End-to-end γ pipeline against synthetic on-disk fixtures.

    Hits γ.4 walker + γ.5 extractor + γ.8 finding emit; asserts (a)
    HardwareFirmwareBlob rows for both registry_hive + driver_package
    categories, (b) WindowsRegistryExtract + WindowsDriver rows, (c)
    Finding rows from at least one γ source. Mocks regipy for the
    walker so the synthetic regf magic file produces a usable
    parsed_tree (real regipy fails on truncated structure; the mock
    keeps tier-1 deterministic without dragging a real hive in).
    """
    rootfs = tmp_path / "rootfs"
    hive_dir = rootfs / "Windows" / "System32" / "config"
    inf_dir = rootfs / "Windows" / "INF"
    _write_synthetic_hive(str(hive_dir / "SOFTWARE"))
    _write_synthetic_inf_cat_triplet(str(inf_dir))

    # Mock regipy to return a Run-key subkey so the walker produces a
    # non-empty parsed_tree (synthetic .hive isn't structurally valid;
    # tier-2 exercises real regipy against a real hive).
    from dataclasses import dataclass

    @dataclass
    class _FakeSubkey:
        subkey_name: str
        path: str
        timestamp: str
        values_count: int
        values: list
        actual_path: str | None = None

    class _FakeHive:
        def __init__(self, *_a, **_kw):
            pass
        def recurse_subkeys(self, **_kw):
            yield _FakeSubkey(
                subkey_name="Run",
                path="\\Microsoft\\Windows\\CurrentVersion\\Run",
                timestamp="2024-01-01T00:00:00",
                values_count=1,
                values=[{"name": "OneDrive", "type": "REG_SZ",
                         "value": "C:\\OneDrive.exe", "is_corrupted": False}],
            )

    async with make_live_db() as db:
        project = Project(name="γ.9-tier1")
        db.add(project)
        await db.flush()
        fw = Firmware(
            project_id=project.id,
            sha256="0" * 64,
            extracted_path=str(rootfs),
        )
        db.add(fw)
        await db.flush()
        await db.commit()

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(rootfs)]

        with (
            patch("regipy.registry.RegistryHive", new=_FakeHive),
            patch(
                "app.services.registry_hive_walker.get_detection_roots",
                new=_fake_roots,
            ),
            patch(
                "app.services.driver_extractor.get_detection_roots",
                new=_fake_roots,
            ),
        ):
            walk_result = await auto_walk_firmware(fw.id, db)
            await db.commit()
            extract_result = await auto_extract_drivers(fw.id, db)
            await db.commit()

        service = FindingService(db)
        registry_findings = await service.emit_registry_findings_from_walk(
            project.id, fw.id
        )
        driver_findings = await service.emit_driver_findings_from_extract(
            project.id, fw.id
        )
        await db.commit()

        # ── Acceptance assertions ──
        assert walk_result["hive_count"] >= 1
        assert extract_result["driver_count"] >= 1

        from sqlalchemy import select as _sel

        registry_blobs = (
            await db.execute(
                _sel(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == fw.id,
                    HardwareFirmwareBlob.category == "registry_hive",
                )
            )
        ).scalars().all()
        driver_blobs = (
            await db.execute(
                _sel(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == fw.id,
                    HardwareFirmwareBlob.category == "driver_package",
                )
            )
        ).scalars().all()
        assert len(registry_blobs) >= 1, "γ.4 should have created ≥1 registry_hive blob"
        assert len(driver_blobs) >= 1, "γ.5 should have created ≥1 driver_package blob"

        extracts = (
            await db.execute(_sel(WindowsRegistryExtract))
        ).scalars().all()
        drivers = (
            await db.execute(_sel(WindowsDriver))
        ).scalars().all()
        assert len(extracts) >= 1, "γ.4 should have created ≥1 WindowsRegistryExtract"
        assert len(drivers) >= 1, "γ.5 should have created ≥1 WindowsDriver"

        # γ.8 emit: combined ≥1 finding from any of the 3 new sources
        # (Run-key emit + unsigned-CAT emit; both should fire on this
        # synthetic fixture).
        γ_findings = (
            await db.execute(
                _sel(Finding).where(
                    Finding.firmware_id == fw.id,
                    Finding.source.in_([
                        "windows_registry_persistence",
                        "windows_inf",
                        "windows_driver_imports",
                    ]),
                )
            )
        ).scalars().all()
        assert len(γ_findings) >= 1, (
            "γ.8 emit should have produced ≥1 finding from a γ source "
            f"(registry={len(registry_findings)}, driver={len(driver_findings)})"
        )


def test_tier1_synthetic_walker_handles_empty_root(tmp_path) -> None:
    """A detection root with no hives + no INFs returns clean empty
    aggregates (no false-positive blobs / findings)."""
    from app.services.driver_extractor import scan_for_inf_triplets
    from app.services.registry_hive_walker import scan_for_hives

    empty_root = tmp_path / "empty"
    empty_root.mkdir()

    assert scan_for_hives([str(empty_root)]) == []
    assert scan_for_inf_triplets([str(empty_root)]) == []


# ── Tier 2: skip-unless WAIRZ_TEST_REAL_HIVE ────────────────────────────────


@pytest.mark.skipif(
    _HOST_REAL_HIVE_FIXTURE is None
    or not (_HOST_REAL_HIVE_FIXTURE and os.path.isfile(_HOST_REAL_HIVE_FIXTURE)),
    reason=(
        "WAIRZ_TEST_REAL_HIVE not set or path does not exist. "
        "Provisioning: extract a real Win11 SOFTWARE / SYSTEM hive "
        "(C:\\Windows\\System32\\config\\SOFTWARE on a real Win11 install), "
        "then `export WAIRZ_TEST_REAL_HIVE=/path/to/SOFTWARE` and rerun."
    ),
)
def test_tier2_real_hive_walks_via_real_regipy() -> None:
    """Tier 2 — real Win11 hive driven through walk_hive_path with NO
    regipy mock. Asserts the regipy parse succeeds (walk_complete=True),
    the parsed_tree subkey list is non-empty, and the
    classify_registry_persistence_findings classifier emits ≥1
    persistence draft (real hives reliably contain Run and/or
    Services subkeys)."""
    parsed = walk_hive_path(_HOST_REAL_HIVE_FIXTURE)
    assert parsed["walk_complete"] is True, (
        f"regipy parse failed for real hive {_HOST_REAL_HIVE_FIXTURE}: "
        f"errors={parsed.get('errors')}"
    )
    assert parsed["key_count"] > 0, "real hive should walk ≥1 key"
    assert len(parsed["subkeys"]) > 0

    drafts = classify_registry_persistence_findings(
        hive_path=_HOST_REAL_HIVE_FIXTURE,
        hive_type=parsed.get("hive_type", "unknown"),
        parsed_tree=parsed,
    )
    assert len(drafts) >= 1, (
        "real hive should contain ≥1 persistence-relevant subkey "
        "(Run / RunOnce / Services / IFEO / etc.)"
    )


# ── Tier 3: skip-unless WAIRZ_TEST_SIGNED_CAT ───────────────────────────────


@pytest.mark.skipif(
    _HOST_SIGNED_CAT_FIXTURE is None
    or not (_HOST_SIGNED_CAT_FIXTURE and os.path.isfile(_HOST_SIGNED_CAT_FIXTURE)),
    reason=(
        "WAIRZ_TEST_SIGNED_CAT not set or path does not exist. "
        "Provisioning: any signed driver .cat from C:\\Windows\\INF on a "
        "real Win10/Win11 install — `export WAIRZ_TEST_SIGNED_CAT=/path/to/iigd_dch.cat`."
    ),
)
def test_tier3_signed_cat_classifies_to_microsoft_anchor() -> None:
    """Tier 3 — real signed .cat driven through classify_cat_signing_tier
    with NO mock. Asserts catalog_signed=True and signing_tier IN
    ('whql', 'attestation', 'cross_signed') — any Microsoft-anchored
    chain. (Specific tier varies by which CA the fixture's signer
    chain anchors at; all three are valid 'signed by Microsoft anchor'
    outcomes per the Persona-E #13 heuristic.)"""
    tier, signed, subject, issuer = classify_cat_signing_tier(
        _HOST_SIGNED_CAT_FIXTURE
    )
    assert signed is True, (
        f"signify failed to parse PKCS#7 envelope for real CAT "
        f"{_HOST_SIGNED_CAT_FIXTURE}"
    )
    assert tier in ("whql", "attestation", "cross_signed"), (
        f"real signed CAT classified as {tier!r}; expected a Microsoft-"
        f"anchored tier. signer_subject={subject!r}, signer_issuer={issuer!r}"
    )
