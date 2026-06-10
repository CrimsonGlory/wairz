"""ReachabilityExportRecord (MOVE 2 Phase 1) — model + Rule #35c normalizers.

Per CLAUDE.md Rule #35c: each JSONB column (defined_symbols / imported_symbols) gets a normalizer
test trio (canonical pass-through, defensive coercion, idempotency). Per Rule #35b: a live-canary
round-trips a row through the real ORM (make_live_db) and SELECTs it back. The GIN-containment
query (defined_symbols @> '["X"]') is postgres-only and is exercised against the real container by
the Rule #44 lookup tool test in Phase 3 (SQLite has no JSONB @> operator).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.project import Project
from app.models.reachability_export import ReachabilityExportRecord
from app.services.jsonb_normalizers import (
    FIRMWARE_REACHABILITY_EXPORT_WALK_RESULT_SCHEMA_VERSION,
    _normalize_firmware_reachability_export_walk_result,
    _normalize_reachability_export_records_defined_symbols,
    _normalize_reachability_export_records_imported_symbols,
    _stamp_firmware_reachability_export_walk_result,
)
from tests._live_db import make_live_db


# ── Rule #35c normalizer trio ───────────────────────────────────────────────

def test_defined_symbols_canonical_passthrough():
    val = ["main", "init", "dhcp6_reply"]
    assert _normalize_reachability_export_records_defined_symbols(val) == val
    assert _normalize_reachability_export_records_imported_symbols(["malloc"]) == ["malloc"]


def test_symbol_list_defensive_coercion():
    # None / wrong-type / mixed-element inputs collapse to a clean list[str] — a hand-edited or
    # legacy row can never feed a GIN containment query a non-string element.
    norm = _normalize_reachability_export_records_defined_symbols
    assert norm(None) == []
    assert norm("not a list") == []
    assert norm({"defined": ["x"]}) == []
    assert norm(123) == []
    assert norm(["ok", 42, None, "fine", {"nested": 1}]) == ["ok", "fine"]
    assert norm([]) == []


def test_symbol_list_idempotent():
    norm = _normalize_reachability_export_records_defined_symbols
    once = norm(["a", 1, "b", None])
    assert norm(once) == once == ["a", "b"]


# ── Rule #35b live-canary: real ORM round-trip ──────────────────────────────

@pytest.mark.asyncio
async def test_reachability_export_record_round_trips_through_orm():
    async with make_live_db() as db:
        project = Project(name="MOVE2 P1 reachability-export canary")
        db.add(project)
        await db.flush()
        firmware = Firmware(
            project_id=project.id,
            original_filename="fw.bin",
            storage_path="/tmp/fw.bin",
            sha256=("a" * 64)[:64],
            file_size=1024,
        )
        db.add(firmware)
        await db.flush()

        rec = ReachabilityExportRecord(
            firmware_id=firmware.id,
            blob_id=None,
            blob_path="rootfs/usr/sbin/dnsmasq",
            blob_sha256=("0e491ae3" * 8)[:64],
            defined_symbols=["main", "init", "rfc1035_reply"],
            imported_symbols=["malloc", "free"],
            stripped=False,
            has_symtab=True,
            has_dynsym=True,
            arch="x64",
        )
        db.add(rec)
        await db.commit()

        # SELECT the persisted row back and inspect EVERY field the walker sets (Rule #35b).
        row = (
            await db.execute(
                select(ReachabilityExportRecord).where(
                    ReachabilityExportRecord.firmware_id == firmware.id
                )
            )
        ).scalar_one()
        assert row.blob_path == "rootfs/usr/sbin/dnsmasq"
        assert row.blob_sha256 == ("0e491ae3" * 8)[:64]
        assert row.defined_symbols == ["main", "init", "rfc1035_reply"]
        assert row.imported_symbols == ["malloc", "free"]
        assert row.stripped is False
        assert row.has_symtab is True and row.has_dynsym is True
        assert row.arch == "x64"
        assert isinstance(row.id, uuid.UUID)
        assert row.created_at is not None


# ── firmware aggregate normalizer/stamp (Phase 2, Rule #35c) ────────────────

def test_aggregate_normalizer_passthrough_and_coercion():
    agg = {"blob_count": 3, "elf_count": 2, "schema_version": 1}
    assert _normalize_firmware_reachability_export_walk_result(agg) == agg
    # None preserved ("no walk yet"); wrong-typed rows collapse to None.
    assert _normalize_firmware_reachability_export_walk_result(None) is None
    assert _normalize_firmware_reachability_export_walk_result(["x"]) is None
    assert _normalize_firmware_reachability_export_walk_result("nope") is None


def test_aggregate_stamp_idempotent():
    payload = {"blob_count": 1}
    once = _stamp_firmware_reachability_export_walk_result(payload)
    assert once["schema_version"] == FIRMWARE_REACHABILITY_EXPORT_WALK_RESULT_SCHEMA_VERSION
    assert once["provenance"] == "walker"
    twice = _stamp_firmware_reachability_export_walk_result(dict(once))
    assert twice == once  # idempotent


# ── Rule #39 tier-1: INNER walker runner (make_live_db; extract_elf_symbols patched) ──

@pytest.mark.asyncio
async def test_walker_inner_persists_per_blob_rows_and_aggregate(monkeypatch):
    # Patch the SOURCE binding the walker imported (Rule #30) so the test exercises the walker's
    # LOGIC (iterate blobs → persist rows → aggregate), not ELF parsing (tested separately).
    from app.services import reachability_export_walker as w

    fixtures = {
        "/extracted/usr/sbin/dnsmasq": {
            "defined_symbols": ["main", "rfc1035_reply"], "imported_symbols": ["malloc"],
            "stripped": False, "has_symtab": True, "has_dynsym": True, "arch": "x64",
        },
        "/extracted/lib/libfoo.so": {
            "defined_symbols": ["foo"], "imported_symbols": [],
            "stripped": True, "has_symtab": False, "has_dynsym": False, "arch": "arm",
        },
        "/extracted/data/firmware.bin": None,  # non-ELF -> skipped (never fabricated)
    }
    monkeypatch.setattr(w, "extract_elf_symbols", lambda path: fixtures.get(path))

    async with make_live_db() as db:
        project = Project(name="MOVE2 P2 walker canary")
        db.add(project)
        await db.flush()
        firmware = Firmware(
            project_id=project.id, original_filename="fw.bin",
            storage_path="/tmp/fw.bin", sha256=("d" * 64)[:64], file_size=1024,
        )
        db.add(firmware)
        await db.flush()
        for i, path in enumerate(fixtures):
            db.add(HardwareFirmwareBlob(
                firmware_id=firmware.id, blob_path=path,
                blob_sha256=(str(i) * 64)[:64], file_size=1000,
                category="binary", format="elf", detection_source="test",
            ))
        await db.commit()

        result = await w._do_reachability_export_run(db, firmware.id)
        await db.commit()

        # Aggregate: 3 blobs, 2 ELF (the .bin skipped), 1 stripped, 2+1 defined symbols.
        assert result["blob_count"] == 3
        assert result["elf_count"] == 2
        assert result["stripped_count"] == 1
        assert result["total_defined_symbols"] == 3

        rows = (
            await db.execute(
                select(ReachabilityExportRecord).where(
                    ReachabilityExportRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 2  # only the 2 ELF blobs persisted
        by_path = {r.blob_path: r for r in rows}
        # _rel_path strips the /extracted/ prefix (the wire-format key).
        assert by_path["usr/sbin/dnsmasq"].defined_symbols == ["main", "rfc1035_reply"]
        assert by_path["usr/sbin/dnsmasq"].stripped is False
        assert by_path["usr/sbin/dnsmasq"].has_symtab is True
        assert by_path["lib/libfoo.so"].stripped is True
        assert by_path["lib/libfoo.so"].defined_symbols == ["foo"]


@pytest.mark.asyncio
async def test_walker_inner_clears_stale_rows_on_rerun(monkeypatch):
    # Re-running the inner walker REPLACES the firmware's per-blob rows (clear-at-entry), so a blob
    # that no longer extracts symbols leaves no stale row.
    from app.services import reachability_export_walker as w

    state = {"path": "/extracted/a.so", "syms": {
        "defined_symbols": ["a"], "imported_symbols": [], "stripped": False,
        "has_symtab": True, "has_dynsym": False, "arch": "x64",
    }}
    monkeypatch.setattr(
        w, "extract_elf_symbols",
        lambda path: state["syms"] if path == state["path"] else None,
    )
    async with make_live_db() as db:
        project = Project(name="MOVE2 P2 rerun canary")
        db.add(project)
        await db.flush()
        firmware = Firmware(
            project_id=project.id, original_filename="fw.bin",
            storage_path="/tmp/fw.bin", sha256=("e" * 64)[:64], file_size=1024,
        )
        db.add(firmware)
        await db.flush()
        db.add(HardwareFirmwareBlob(
            firmware_id=firmware.id, blob_path="/extracted/a.so",
            blob_sha256=("f" * 64)[:64], file_size=1000,
            category="binary", format="elf", detection_source="test",
        ))
        await db.commit()

        await w._do_reachability_export_run(db, firmware.id)
        await db.commit()
        assert len((await db.execute(select(ReachabilityExportRecord))).scalars().all()) == 1

        # Second run: the blob no longer extracts (simulate it became non-ELF) -> stale row cleared.
        state["path"] = "/extracted/gone"
        await w._do_reachability_export_run(db, firmware.id)
        await db.commit()
        assert len((await db.execute(select(ReachabilityExportRecord))).scalars().all()) == 0


@pytest.mark.asyncio
async def test_reachability_export_unique_per_firmware_sha256():
    # uq_reachexport_firmware_sha256: a second record with the SAME (firmware, blob_sha256) is
    # rejected — the walker upserts on this key (one symbol record per blob content per firmware).
    from sqlalchemy.exc import IntegrityError

    async with make_live_db() as db:
        project = Project(name="MOVE2 P1 uq canary")
        db.add(project)
        await db.flush()
        firmware = Firmware(
            project_id=project.id, original_filename="fw.bin",
            storage_path="/tmp/fw.bin", sha256=("b" * 64)[:64], file_size=1024,
        )
        db.add(firmware)
        await db.flush()
        sha = ("c" * 64)[:64]
        db.add(ReachabilityExportRecord(
            firmware_id=firmware.id, blob_path="a", blob_sha256=sha, defined_symbols=["x"]))
        await db.commit()
        db.add(ReachabilityExportRecord(
            firmware_id=firmware.id, blob_path="b", blob_sha256=sha, defined_symbols=["y"]))
        with pytest.raises(IntegrityError):
            await db.commit()
