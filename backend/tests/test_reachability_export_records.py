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
from app.models.project import Project
from app.models.reachability_export import ReachabilityExportRecord
from app.services.jsonb_normalizers import (
    _normalize_reachability_export_records_defined_symbols,
    _normalize_reachability_export_records_imported_symbols,
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
