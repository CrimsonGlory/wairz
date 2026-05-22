"""Cross-project SBOM retro-fix automation (2026-05-22 over-constraint sweep follow-up).

For each firmware row with anomalous SBOM completeness (low component count
relative to file size + extracted_path "looks deep"), check whether the
recently-fixed find_filesystem_root_strict + BSP-aware _compute_roots_sync
+ LooseDebStrategy combination would have produced a different (better)
result. If yes, repair the row + re-trigger SBOM.

Run inside the backend container:
  docker compose exec -T -w /app -e PYTHONPATH=/app backend /app/.venv/bin/python /path/retro_fix_sbom.py [--apply]
"""
from __future__ import annotations

import asyncio
import os
import sys

from sqlalchemy import select, func, text
from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.sbom import SbomComponent
from app.services.firmware_paths import populate_detection_roots
from app.routers.sbom import _do_sbom_generate
from app.workers.unpack_common import find_filesystem_root_strict


CANDIDATES = [
    ("295eaf7a-515b-4206-8dde-a26393f2cbea", "DS1 live_base May 15"),
    ("e6e45f24-691f-4aea-8167-79772b9965a2", "DS1 live_base May 22"),
    ("eed5db82-49e9-4751-b2fc-733a0f7190bf", "DS1 Moto G32"),
    ("7433dfb1-5f82-4af6-8fff-98ad9611d7ac", "DS1 Elo Tablet"),
    ("4e6da402-0437-4d25-b97b-0478c26c9894", "test PowerPack.bin"),
    ("5b7735cd-592c-48be-a362-4f980470eb80", "ACM test target-ld"),
    ("1165fe74-5818-4c7d-9b8d-318509ab9c98", "Horizon Tablet App APK"),
]


def find_outer_extracted(extracted_path):
    if not extracted_path:
        return None
    cur = extracted_path
    while cur and cur != "/" and cur != os.path.dirname(cur):
        if os.path.basename(cur) == "extracted" and os.path.isdir(cur):
            return cur
        cur = os.path.dirname(cur)
    return None


async def assess(fw_id, project_hint):
    async with async_session_factory() as db:
        fw = (await db.execute(select(Firmware).where(Firmware.id == fw_id))).scalar_one_or_none()
        if fw is None:
            return {"id": fw_id, "found": False}
        sbom_count = await db.scalar(
            select(func.count(SbomComponent.id)).where(SbomComponent.firmware_id == fw_id)
        )
        outer = find_outer_extracted(fw.extracted_path)
        cur_path = fw.extracted_path or ""
        if outer:
            tail = cur_path[len(outer):].strip("/")
            depth = len([p for p in tail.split("/") if p])
        else:
            depth = 0
        outer_strict = find_filesystem_root_strict(outer) if outer is not None else None
        return {
            "id": fw_id, "found": True, "project": project_hint,
            "filename": fw.original_filename, "size_mb": (fw.file_size or 0) // (1024*1024),
            "current_extracted_path": cur_path, "outer_container": outer,
            "depth_past_extracted": depth, "strict_returns": outer_strict,
            "current_sbom_count": sbom_count or 0,
        }


async def apply_fix(fw_id, new_extracted_path):
    async with async_session_factory() as db:
        fw = (await db.execute(select(Firmware).where(Firmware.id == fw_id))).scalar_one()
        old_path = fw.extracted_path
        old_count = await db.scalar(
            select(func.count(SbomComponent.id)).where(SbomComponent.firmware_id == fw_id)
        )
        fw.extracted_path = new_extracted_path
        if isinstance(fw.device_metadata, dict) and "detection_roots" in fw.device_metadata:
            md = dict(fw.device_metadata)
            md.pop("detection_roots", None)
            fw.device_metadata = md
        await db.commit()
        roots = populate_detection_roots(fw)
        await db.commit()
        result = await _do_sbom_generate(db, fw, force_rescan=True)
        await db.commit()
        new_count = await db.scalar(
            select(func.count(SbomComponent.id)).where(SbomComponent.firmware_id == fw_id)
        )
        rows = (await db.execute(
            text("SELECT detection_source, COUNT(*) FROM sbom_components WHERE firmware_id = :fid GROUP BY detection_source ORDER BY 2 DESC"),
            {"fid": fw_id}
        )).all()
        return {
            "id": fw_id, "old_extracted_path": old_path, "new_extracted_path": new_extracted_path,
            "old_sbom_count": old_count, "new_sbom_count": new_count,
            "new_detection_roots_count": len(roots),
            "by_source": [(s, n) for s, n in rows], "sbom_result": result,
        }


async def main(apply):
    print("=" * 80)
    print(f"SBOM Retro-Fix Audit ({'APPLY' if apply else 'DRY-RUN'} mode)")
    print("=" * 80)
    plan = []
    for fw_id, project_hint in CANDIDATES:
        info = await assess(fw_id, project_hint)
        if not info["found"]:
            print(f"  ! {fw_id} not found in DB — skipping")
            continue
        print(f"\n{info['project']} ({fw_id[:8]})")
        print(f"  file: {info['filename']} ({info['size_mb']} MB)")
        print(f"  current path: {info['current_extracted_path']}")
        print(f"  outer container: {info['outer_container']}")
        print(f"  depth past extracted/: {info['depth_past_extracted']}")
        print(f"  strict-probe result: {info['strict_returns']}")
        print(f"  current SBOM count: {info['current_sbom_count']}")
        if info["outer_container"] is None:
            print("  → SKIP (no outer extracted/ container found)")
            continue
        if info["depth_past_extracted"] == 0:
            decision = "RERUN_SBOM_AT_CURRENT_PATH"
            new_path = info["current_extracted_path"]
        elif info["strict_returns"] is not None:
            decision = "RELOCATE_TO_STRICT"
            new_path = info["strict_returns"]
        else:
            decision = "RELOCATE_TO_OUTER"
            new_path = info["outer_container"]
        print(f"  → {decision}: new path = {new_path}")
        plan.append({"id": fw_id, "new_path": new_path, "info": info})

    if not apply:
        print(f"\nDRY-RUN complete. {len(plan)} firmware would be retro-fixed.")
        return

    print(f"\n{'='*80}\nAPPLYING fixes to {len(plan)} firmware...\n{'='*80}")
    for entry in plan:
        try:
            result = await apply_fix(entry["id"], entry["new_path"])
            delta = (result["new_sbom_count"] or 0) - (result["old_sbom_count"] or 0)
            print(f"\n{entry['info']['project']} ({entry['id'][:8]})")
            print(f"  SBOM: {result['old_sbom_count']} → {result['new_sbom_count']} ({'+' if delta >= 0 else ''}{delta})")
            print(f"  detection_roots: {result['new_detection_roots_count']}")
            print(f"  by source: {result['by_source']}")
        except Exception as e:
            print(f"  ! ERROR on {entry['id'][:8]}: {type(e).__name__}: {e}")
    print(f"\n{'='*80}\nDONE\n{'='*80}")


if __name__ == "__main__":
    asyncio.run(main("--apply" in sys.argv))
