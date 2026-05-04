---
title: "Infra: Volume Quotas, Cleanup, and PostgreSQL Backup"
status: completed
priority: high
target: docker-compose.yml, backend/app/services/
---

> **Status note 2026-04-21 (Rule-19 audit):** Shipped via session 198243b8 Stream Alpha
> across 4 commits (see `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` Wave 3
> history). Live audit verified:
> - **V1** `check_storage_quota` cron + 507 pre-upload check: commit `2440150`. Cron
>   registered at `backend/app/workers/arq_worker.py:690`
>   (`cron(check_storage_quota_job, minute=15)`), handler at line 578.
> - **V2** `cleanup_tmp_dumps` cron: commit `51770af`. Cron registered at
>   `arq_worker.py:691` (`cron(cleanup_tmp_dumps_job, hour=4, minute=0)`), handler at
>   line 527.
> - **V3** `pg-backup` service + backup-recovery docs: commit `5f08db1`. Service
>   defined at `docker-compose.yml:103`.
> - **V4** `reconcile_firmware_storage` cron (log-only drift detector): commit `50a9ca6`.
>   Cron at `arq_worker.py:692` (`cron(reconcile_firmware_storage_job, hour=5, minute=0)`),
>   handler at line 408.
> - **Config knobs:** commit `3f60398` added `firmware_retention_days` + `backup_dir`
>   to `backend/app/config.py:104,107`.
> This intake is retained for historical reference; further changes go in new intakes.

## Problem

### V1. `firmware_data` volume unbounded

`docker-compose.yml:73, 126` — shared RW between backend and worker. Mounted RO into emulation, fuzzing, system-emulation, vulhunt, clamav.

`MAX_UPLOAD_SIZE_MB=2048` caps per-upload, but **nothing caps total usage**. When the volume fills:
- `STORAGE_ROOT=/data/firmware` writes fail silently
- The unpack worker returns errors that look like extractor bugs
- No disk-usage metric, no alarm, no quota

### V2. `/tmp/wairz-dumps` host bind

`docker-compose.yml:77, 130` bind-mount `/tmp/wairz-dumps` from the host into backend and worker. No quota. Device-acquisition dumps stay until reboot OR manual cleanup. May contain sensitive firmware bytes.

### V3. No PostgreSQL backup strategy

`pgdata` is a Docker named volume (`docker-compose.yml:268`). Zero backup tooling. No WAL archiving. No documented recovery procedure. Volume corruption = **total data loss** (every project, finding, analysis cache).

### V4. No orphan detection across firmware DB rows vs disk

Firmware DB rows can become inconsistent with disk state:
- Row exists but extracted_path is gone (user deleted files manually)
- Directory exists but no DB row (crashed during upload)

No periodic check.

## Approach

### Fix V1 — Storage quota + monitoring

**Step 1. Add a disk-usage check in arq cron.**

```python
# backend/app/workers/arq_worker.py
import shutil
from app.config import get_settings

async def check_storage_quota(ctx: dict) -> dict:
    settings = get_settings()
    root = settings.storage_root
    total, used, free = shutil.disk_usage(root)
    used_pct = (used / total) * 100
    
    # Emit metric (if Prometheus instrumented)
    # storage_used_percent.set(used_pct)
    
    if used_pct > 90:
        logger.error(f"CRITICAL: {root} is {used_pct:.1f}% full ({free // (1024**3)} GB free)")
    elif used_pct > 80:
        logger.warning(f"WARNING: {root} is {used_pct:.1f}% full")
    
    return {"used_pct": used_pct, "free_gb": free // (1024**3)}

# In WorkerSettings.cron_jobs:
cron(check_storage_quota, minute=15),  # every hour at :15
```

**Step 2. Fail-fast on near-full storage.**

In `firmware_service.py` upload path, before accepting a new file, check free disk:

```python
def _check_storage_available(required_bytes: int) -> None:
    free = shutil.disk_usage(settings.storage_root).free
    if free < required_bytes * 1.5:  # 1.5x safety margin
        raise HTTPException(
            507,  # Insufficient Storage
            detail=f"Not enough disk space to accept upload. {free // (1024**2)} MB free."
        )
```

**Step 3. Old-firmware cleanup policy.**

Add config knob: `firmware_retention_days: int | None = None` (default: keep forever). When set, arq job deletes extraction directories for firmware older than N days AND flagged as "archived". Never auto-delete active data without opt-in.

### Fix V2 — /tmp cleanup

Add cron that removes `/tmp/wairz-dumps/*` older than 7 days:

```python
async def cleanup_tmp_dumps(ctx: dict) -> dict:
    import os
    from datetime import datetime, timedelta
    
    cutoff = (datetime.utcnow() - timedelta(days=7)).timestamp()
    tmpdir = "/tmp/wairz-dumps"
    if not os.path.isdir(tmpdir):
        return {"deleted": 0}
    
    deleted = 0
    for name in os.listdir(tmpdir):
        path = os.path.join(tmpdir, name)
        try:
            if os.path.getmtime(path) < cutoff:
                if os.path.isfile(path):
                    os.unlink(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)
                deleted += 1
        except OSError:
            pass
    return {"deleted": deleted}

# cron(cleanup_tmp_dumps, hour=4, minute=0),  # daily 04:00
```

### Fix V3 — PostgreSQL backup

**Option A — Simple scheduled pg_dump (recommended for v1).**

Add a `pg-backup` service to `docker-compose.yml`:

```yaml
services:
  pg-backup:
    image: postgres:16-alpine  # same as postgres service
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      PGHOST: postgres
      PGUSER: ${POSTGRES_USER:-wairz}
      PGPASSWORD: ${POSTGRES_PASSWORD}
      PGDATABASE: ${POSTGRES_DB:-wairz}
    volumes:
      - ${BACKUP_DIR:-./backups}:/backups
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        while true; do
          TIMESTAMP=$$(date +%Y%m%d_%H%M%S)
          echo "[backup] Starting dump at $$TIMESTAMP"
          pg_dump --clean --if-exists -Fc > /backups/wairz_$$TIMESTAMP.dump
          find /backups -name 'wairz_*.dump' -mtime +30 -delete
          echo "[backup] Done. Sleeping 24h..."
          sleep 86400
        done
    logging:
      driver: json-file
      options:
        max-size: 10m
```

`.env.example`:
```bash
BACKUP_DIR=./backups
```

Document the recovery procedure in `docs/operations/backup-recovery.md`:
```
## Recovery
docker compose exec -T postgres pg_restore --clean --if-exists -d wairz < backups/wairz_20260416_030000.dump
```

**Option B — WAL archiving (for production).**

If a real RTO/RPO is needed, configure continuous WAL archiving to S3 / filesystem with `wal-g` or `pgbackrest`. Out of scope for this intake; document as a follow-up.

### Fix V4 — Orphan reconciliation

Add an arq cron:

```python
async def reconcile_firmware_storage(ctx: dict) -> dict:
    """Find DB rows whose extracted_path is gone, and directories with no DB row."""
    async with async_session_factory() as db:
        stmt = select(Firmware).where(Firmware.extracted_path.isnot(None))
        firmware_rows = (await db.execute(stmt)).scalars().all()
        
        db_paths = {r.extracted_path for r in firmware_rows}
        
        # Find DB rows with missing dirs
        missing_dirs = [r.id for r in firmware_rows if not os.path.isdir(r.extracted_path)]
        
        # Find dirs with no DB row
        root = get_settings().storage_root
        disk_projects = os.listdir(os.path.join(root, "projects")) if os.path.isdir(os.path.join(root, "projects")) else []
        orphan_dirs = []
        for proj in disk_projects:
            proj_dir = os.path.join(root, "projects", proj, "firmware")
            if not os.path.isdir(proj_dir):
                continue
            for fw in os.listdir(proj_dir):
                fw_path = os.path.join(proj_dir, fw, "extracted")
                if os.path.isdir(fw_path) and fw_path not in db_paths:
                    orphan_dirs.append(fw_path)
    
    # For now: log, don't auto-delete. Safety first.
    if missing_dirs:
        logger.warning(f"Firmware rows with missing extraction: {missing_dirs}")
    if orphan_dirs:
        logger.warning(f"Extraction directories with no DB row: {orphan_dirs}")
    
    return {"missing_dirs": len(missing_dirs), "orphan_dirs": len(orphan_dirs)}

# cron(reconcile_firmware_storage, hour=5, minute=0),  # daily 05:00
```

V1: log-only. V2 (future): auto-cleanup of orphan dirs after operator opt-in.

## Files

- `docker-compose.yml` (add pg-backup service)
- `backend/app/workers/arq_worker.py` (4 new cron jobs)
- `backend/app/services/firmware_service.py` (pre-upload disk check)
- `backend/app/config.py` (firmware_retention_days, backup_dir)
- `.env.example` (BACKUP_DIR)
- `docs/operations/backup-recovery.md` (new)

## Acceptance Criteria

- [ ] `docker compose up -d` starts `pg-backup` service
- [ ] After 1 day (or manual trigger), `./backups/` contains a `.dump` file
- [ ] Backups older than 30 days are auto-deleted
- [ ] `pg_restore` from a backup recovers a clean DB (tested end-to-end)
- [ ] Upload to a near-full disk returns 507 before accepting the file
- [ ] `docker compose logs worker | grep storage_used_percent` shows periodic metrics
- [ ] `/tmp/wairz-dumps` cron removes files older than 7 days (verified with touch + mtime tweak)
- [ ] Orphan reconciliation cron logs any mismatches but does not delete in v1

## Risks

- `pg_dump` locks briefly on large tables — for Wairz scale (likely < 10 GB DB), this is sub-second; for larger deployments consider WAL archiving
- Backup volume can fill if not rotated — 30-day retention is explicit in the command
- Orphan directory deletion is disabled in v1 to avoid data loss; treat the warning logs as operator-actionable signals

## References

- Infrastructure review C8 (firmware_data unbounded), M9 (no backup), M15 (tmp bind)
