# Wave-1 Scout E — Rule #51 State-Machine Audit (S2)

> Investigation date: 2026-05-21 (Session 2 continuation)
> Scope: Post-Session-1 state-machine landscape on `firmware` table + Fix #1 + Fix #11 design
> Predecessor: `.planning/research/sbom-vuln-scan-regression-2026-05-21/wave1-scout-E-state-machine.md`

## Executive Summary

Session 1 closed two of the 30 state-machine columns on `firmware` — `upload_stage` (Fix #2, commit `8c51448`) and `bare_metal_audit_status` (Fix #5, commit `fc22c17`) — bringing total reaper coverage to 5 of 30 columns (3 device-dump/cve-match/vuln-scan from prior sessions + 2 from S1). **Fix #1** must ship the SBOM `/generate` Rule #33 sync→202+polling conversion + its FULL Rule #51 4-companion sweep — this is the structural giant per W2-γ's MULTI-SESSION verdict (~420 LOC across 4 commits). **Fix #11** must refactor `main.py` lifespan to derive reaper config from `walker_registry.WALKER_AUTO_TRIGGERS` so the 22 remaining walker columns inherit reaper coverage uniformly. The architectural recommendation is **Option B — centralised dict in walker_registry** (NOT YAML per Rule #52) because (a) reaper config is `(column_name, in_progress_states, error_message_template)` — pure data with no operator-extensibility motivation; (b) walker_registry.py is already the single source of truth for walker fan-out; (c) closed-grammar enforcement is mechanical (Pydantic Literal at module scope) and a YAML round-trip adds zero value. Confidence **HIGH** for Fix #1; **MEDIUM-HIGH** for Fix #11 architectural choice.

## State-Machine Column Matrix (Updated post-Session-1)

| Column | DB CHECK | Pydantic Literal | Reaper | POST tier | `_EXPECTED_TIERS` pinned | Rule #33 4-bullet |
|---|---|---|---|---|---|---|
| `upload_stage` | YES `ck_firmware_upload_stage` (`d2e3f4a5b6c7`:110-114) | YES `UploadStage` (schemas/firmware.py:10-18) | **YES (S1 Fix #2, `8c51448`)** — 15-min grace | n/a (set by upload) | n/a | partial — (a)-(d) partial |
| `sbom_status` | **NOT EXISTS — Fix #1 will add** | **NOT EXISTS — Fix #1 will add `SbomStatus`** | **NOT EXISTS — Fix #1 will add (no grace)** | `TIER_A_LIGHT_ACK` (sbom.py:143 — drift since SYNC) | YES (test_rate_limit_tiers.py:52) | **NO — Fix #1 designs full contract** |
| `vuln_scan_status` | YES `ck_firmware_vuln_scan_status` (`c1d2e3f4a5b6`) | YES `VulnScanStatus` (schemas/sbom.py:108) | YES (main.py:200-242) | `TIER_A_LIGHT_ACK` (sbom.py:554) | YES (test_rate_limit_tiers.py:53) | YES — reference impl |
| `cve_match_status` | YES `ck_firmware_cve_match_status` (`e6f7a8b9c0d1`:101-105) | YES `CveMatchStatus` (schemas/hardware_firmware.py:90) | YES (main.py:160-198) | `TIER_A_HEAVY` (hardware_firmware.py:612) | YES (test_rate_limit_tiers.py:49) | YES — canonical |
| `device_dump_session.status` | YES `ck_device_dump_session_status` | YES `DumpStatus` (schemas/device.py:61) | YES (main.py:123-158) | `TIER_A_HEAVY` (device.py:102) | YES (test_rate_limit_tiers.py:51) | YES |
| `bare_metal_audit_status` | YES (`fc5d6e7f8a9b`:92-94) | NO `BareMetalAuditStatus` Literal | **YES (S1 Fix #5, `fc22c17`)** — no grace | n/a (no operator POST; auto-fired via walker) | n/a | partial |
| `authenticode_chain_status` | YES (`b2a3c4d5e6f7`:77) | YES `AuthenticodeChainStatus` (schemas/hardware_firmware.py:144) | **NO** | `TIER_A_LIGHT_ACK` (hardware_firmware.py:707) | YES (test_rate_limit_tiers.py:54) | partial — has operator POST + 409 + 202; missing reaper |
| `dotnet_decompile_status` | YES (`d1e2f3a4b5c6`:100) | YES `DotnetDecompileStatus` (schemas/hardware_firmware.py:235) | **NO** | n/a | n/a | partial |
| `windows_update_diff_status` | YES (`d3a4b5c6d7e8`:100) | YES `WindowsUpdateDiffStatus` (schemas/hardware_firmware.py:247) | **NO** | n/a | n/a | partial |
| 22× walker `*_walk_status` (registry_hive, evtx, prefetch, srum, scheduled_task, lnk, mft, bcd, journald, systemd, etl, efs, container, appcompat, persistence, dpapi, usnjrnl, wmi, esp, mbr_vbr, sdb + windows_info/processes/injection) | YES each | YES ~13/22; remainder CHECK-only (Rule #33 .c housekeeping gap) | **NONE — Fix #11 closes via WALKER_AUTO_TRIGGERS derivation** | n/a (operator POST goes via MCP `trigger_<op>_walk` tools, not router endpoints) | n/a | partial each |
| `ics_protocol_walk_status` | NOT SHIPPED (ICS Session 2 deferred) | n/a | n/a | n/a | n/a | n/a |

**Total state-machine columns enumerated:** 30 (5 cve_match/vuln_scan/device_dump/upload_stage/bare_metal_audit covered + 3 dotnet_decompile/windows_update_diff/authenticode_chain partially aligned + 22 walker columns + 1 ICS deferred). Session 1 + Session 2 close 5 of those 5 partial-coverage columns and the 22 walker columns via Fix #11; remaining 3 (authenticode_chain, dotnet_decompile, windows_update_diff) are operator-fired but rare enough that they could ride Fix #11's reaper sweep ONLY IF the registry shape generalises beyond the WALKER_AUTO_TRIGGERS list — see Fix #11 Option B-extended below.

## Fix #1 Design — SBOM `/generate` Rule #33 conversion

### (a) New alembic migration

**Revision shape** (~115 LOC, mirrors `e6f7a8b9c0d1_add_cve_match_status_to_firmware.py:1-114`):

```python
# revision: <new>; down_revision: 'fd6e7f8a9b0c'  (current head)
SBOM_STATUS_VALUES = ("idle", "queued", "running", "completed", "failed")

def upgrade():
    op.add_column("firmware", sa.Column("sbom_status", sa.String(20),
        nullable=False, server_default="idle"))
    op.add_column("firmware", sa.Column("sbom_started_at",
        sa.DateTime(timezone=False), nullable=True))
    op.add_column("firmware", sa.Column("sbom_finished_at",
        sa.DateTime(timezone=False), nullable=True))
    op.add_column("firmware", sa.Column("sbom_error", sa.Text, nullable=True))
    # Rule #33 (b): result aggregate persisted on same row.
    # SBOM components themselves persist to `sbom_components` (the result),
    # so `sbom_result` JSONB mirrors cve_match_result shape:
    #   {"total": N, "cached": bool, "rtos_injected": bool, ...}
    op.add_column("firmware", sa.Column("sbom_result",
        postgresql.JSONB, nullable=True))
    quoted = ", ".join(f"'{v}'" for v in SBOM_STATUS_VALUES)
    op.create_check_constraint("ck_firmware_sbom_status",
        "firmware", f"sbom_status IN ({quoted})")
```

5 new columns mirroring the vuln_scan / cve_match precedent. The `sbom_result` JSONB is the Rule #33 (b) result aggregate — the actual SBOM components persist to `sbom_components` table, so `sbom_result` only stores the meta-result (component count, cached flag, RTOS injection summary) so the polling endpoint can return the same shape the synchronous endpoint used to.

### (b) Pydantic Literal at `backend/app/schemas/sbom.py`

```python
# Rule #33 (c): both Pydantic Literal AND DB CHECK constraint.
SbomStatus = Literal["idle", "queued", "running", "completed", "failed"]

class SbomGenerateStatusResponse(BaseModel):
    """202+polling response shape mirroring VulnerabilityScanStatusResponse."""
    firmware_id: uuid.UUID
    status: SbomStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    summary: SbomGenerateResponse | None = None  # populated when completed
    model_config = ConfigDict(from_attributes=True)
```

The existing `SbomGenerateResponse` (current sync return type) becomes the `summary` field of the polling response — same shape as `VulnerabilityScanStatusResponse.summary` carrying `VulnerabilityScanResponse`.

### (c) Router refactor at `backend/app/routers/sbom.py`

Mirror the `/vulnerabilities/scan` endpoint at sbom.py:549-620 verbatim:

```python
@router.post("/generate", response_model=SbomGenerateStatusResponse, status_code=202)
@limiter.limit(TIER_A_LIGHT_ACK)
async def generate_sbom(
    request: Request,
    project_id: uuid.UUID,
    force_rescan: bool = Query(False),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
) -> SbomGenerateStatusResponse:
    """Enqueue an SBOM generation for the resolved firmware (Rule #33 (a) idempotent POST).

    Returns 202 with sbom_status="queued". Frontend polls GET /sbom/generate/status
    every 2 s until "completed" or "failed", matching vuln-scan / cve-match cadence.
    """
    if firmware.sbom_status in ("queued", "running"):
        raise HTTPException(409,
            f"sbom-generate already {firmware.sbom_status} for this firmware")

    firmware.sbom_status = "queued"
    firmware.sbom_started_at = None
    firmware.sbom_finished_at = None
    firmware.sbom_error = None
    firmware.sbom_result = None
    await db.commit()

    # Rule #33 (d) rubric: in-process Syft subprocess + DB writes =
    # asyncio.create_task (cve-match / vuln-scan precedent). No worker
    # resource coordination needed; intermediate state persisted by
    # SbomService. _spawn_background_task wraps with strong-reference set
    # per S1 Fix #8 GC-hardening discipline.
    _spawn_background_task(
        _run_sbom_generate_background(firmware.id, project_id, force_rescan),
        name=f"sbom_generate_{firmware.id}",
    )
    return await _firmware_to_sbom_status(db, firmware)
```

Plus matching `_run_sbom_generate_background` (mirrors `_run_vuln_scan_background` at sbom.py:445-547) and `_firmware_to_sbom_status` (mirrors `_firmware_to_vuln_scan_status` at sbom.py:422-442).

### `_run_sbom_generate_background` shape — MUST use `_spawn_background_task` per Fix #8

The S1 Fix #8 GC-hardening helper at sbom.py:28-37 wraps `asyncio.create_task` with a strong-reference set, then `add_done_callback(_BACKGROUND_TASKS.discard)` trims on natural completion. This is mandatory for Fix #1 — the Syft subprocess is 30-120s, well within the GC vulnerability window Scout D originally identified.

The runner owns its own `AsyncSession` via `async_session_factory()` (Rule #39 .outer triplet — the outer state-machine wrapper). The inner pure-logic orchestrator is `SbomService.generate_sbom` (already exists; runs in executor per the current sync endpoint). Failure persistence on a fresh session if the inner session rolls back, per the canonical Rule #33 reference shape.

### Orphan reaper at `main.py` — NO grace window

Add a 5th reaper block mirroring vuln_scan + cve_match (NOT upload_stage which has the 15-min grace). The justification: SBOM generate work runs in-process via `asyncio.create_task` with `_spawn_background_task`'s strong-reference set; the 409 idempotency check at the operator POST blocks concurrent re-trigger; the work completes in 30-120s typical — there's no scenario where a freshly-spawned background task is mid-startup at exactly the same instant the lifespan reaper fires (which is what motivated upload_stage's 15-min grace per W2-β §SC5-NEW-SBOM-ε). The reaper shape:

```python
# Reap orphan sbom-generate firmware rows. Same shape as the cve-match /
# vuln-scan reapers above. Fix #1 of the 2026-05-21 SBOM/vuln-scan regression
# Session 2 — Rule #51 .i companion to the Rule #33 sync→202+polling
# conversion. No grace window: work is in-process, 30-120s typical, fully
# bounded by the 409 dedup check in the operator POST.
try:
    async with async_session_factory() as db:
        res = await db.execute(
            update(Firmware)
            .where(Firmware.sbom_status.in_(("queued", "running")))
            .values(
                sbom_status="failed",
                sbom_error="Backend restarted; runner state lost",
                sbom_finished_at=datetime.now(UTC),
            )
        )
        await db.commit()
        if res.rowcount:
            logger.info("Reaped %d orphan sbom-generate firmware row(s) on startup",
                res.rowcount)
except Exception:
    logger.warning("sbom-generate orphan reaper failed", exc_info=True)
```

### Tier re-evaluation per Rule #51 .ii — TIER_A_LIGHT_ACK already correct

The current decoration `@limiter.limit(TIER_A_LIGHT_ACK)` at sbom.py:143 was a Rule #51 .ii drift on a sync endpoint pre-conversion (Scout E S1 finding #2). Post-conversion, the same TIER_A_LIGHT_ACK becomes structurally CORRECT — the ack drops to sub-second, the detached work runs ≤2 min typical (Syft is 30-120s, the upper bound is well under TIER_A_LIGHT_ACK's "≤2 min detached work" derivation at rate_limit.py:37-51). No tier change required. The `_EXPECTED_TIERS` pin at test_rate_limit_tiers.py:52 already matches; no size-lock count drift.

### Frontend polling refactor at `frontend/src/pages/SbomPage.tsx`

Mirror the `handleScan` + polling-effect pattern at SbomPage.tsx:162-219 verbatim for `handleGenerate`:

1. `handleGenerate` POSTs `/sbom/generate` → 202 with status="queued"; catches 409 (fall through to polling).
2. New `useEffect` watches `generating` state; polls `/sbom/generate/status` every 2s until status flips to `completed` or `failed`.
3. On `completed`: read `status.summary` (the `SbomGenerateResponse` payload — components + total + cached), populate state.
4. On `failed`: toast.error with `status.error`.
5. New `frontend/src/types/index.ts` types: `SbomStatusValue` (Literal mirror) + `SbomGenerateStatus` (response shape).
6. New `frontend/src/api/sbom.ts` functions: `getSbomGenerateStatus(projectId, firmwareId)` paralleling `getVulnerabilityScanStatus`.

The existing `generateSbom` function's signature stays the same but the return type becomes `SbomGenerateStatus` (the 202 ack); callers reading `result.components` migrate to reading `status.summary.components` after polling completes.

## Fix #11 Architectural Design — Walker `*_walk_status` Reaper Sweep

The 22 walker columns share a uniform shape per the firmware model (model.py:113-966):

```
<prefix>_walk_status:       Mapped[str]    NOT NULL DEFAULT 'idle'
<prefix>_walk_started_at:   Mapped[datetime|None]
<prefix>_walk_finished_at:  Mapped[datetime|None]
<prefix>_walk_error:        Mapped[str|None]
<prefix>_walk_result:       Mapped[JSONB|None]   (some — varies by walker)
```

This uniformity is the architectural opportunity Fix #11 exploits. The operator-triggered re-walk path goes through `run_<op>_walk_background` (the Rule #39 .outer triplet), which DOES set `<prefix>_walk_status = "running"` and `<prefix>_walk_started_at`. Backend restart mid-walk leaves the row stuck in `("queued", "running")` exactly like the cve-match / vuln-scan / sbom-generate orphan pattern. The auto-fire path (`auto_<op>_walk_firmware_safe`) does NOT mutate the status field per Rule #39 .safe semantics (appcompat_walker.py:974-981 confirms) — so the reaper only matters for operator-fired re-walks via MCP `trigger_<op>_walk` tools.

### Option A: Per-walker `_REAPER_CONFIG` constant

Each `*_walker.py` declares a module-level constant:
```python
_REAPER_CONFIG = {
    "status_column": "appcompat_walk_status",
    "started_at_column": "appcompat_walk_started_at",
    "finished_at_column": "appcompat_walk_finished_at",
    "error_column": "appcompat_walk_error",
    "in_progress_states": ("queued", "running"),
    "error_message": "Backend restarted; walker state lost",
}
```

The lifespan reads each walker module + iterates the configs to issue UPDATEs. **Cost:** +5 LOC × 22 walkers = +110 LOC; touches 22 files. **Benefit:** locality (config lives next to the walker code that owns the column). **Drawback:** 22 files to keep in sync; new walker authors need to remember `_REAPER_CONFIG` AND `WALKER_AUTO_TRIGGERS` registration. Two-place coupling.

### Option B (RECOMMENDED): Centralised dict in `walker_registry.py`

Extend walker_registry.py with a parallel dict:

```python
@dataclass(frozen=True)
class WalkerReaperConfig:
    status_column: str
    started_at_column: str
    finished_at_column: str
    error_column: str
    in_progress_states: tuple[str, ...] = ("queued", "running")
    error_message: str = "Backend restarted; walker state lost"


# 22-entry dict keyed by the auto-trigger function NAME (NOT a reference,
# to keep the import graph cheap). Looked up at lifespan time.
WALKER_REAPER_CONFIGS: dict[str, WalkerReaperConfig] = {
    "auto_appcompat_walk_firmware_safe": WalkerReaperConfig(
        status_column="appcompat_walk_status",
        started_at_column="appcompat_walk_started_at",
        finished_at_column="appcompat_walk_finished_at",
        error_column="appcompat_walk_error",
    ),
    "auto_bcd_walk_firmware_safe": WalkerReaperConfig(
        status_column="bcd_walk_status",
        started_at_column="bcd_walk_started_at",
        finished_at_column="bcd_walk_finished_at",
        error_column="bcd_walk_error",
    ),
    # ... 20 more ...
}
```

Lifespan reaper at main.py reads `walker_registry.WALKER_REAPER_CONFIGS` and issues one UPDATE per walker:

```python
from sqlalchemy import inspect
from app.workers.walker_registry import WALKER_REAPER_CONFIGS

async with async_session_factory() as db:
    total_reaped = 0
    for trigger_name, cfg in WALKER_REAPER_CONFIGS.items():
        # Build the SET dict using getattr on Firmware columns (string-keyed
        # for the centralised dict shape — alternative is to use SQLAlchemy's
        # text() with parameter binding).
        col = getattr(Firmware, cfg.status_column)
        start_col = getattr(Firmware, cfg.started_at_column)
        end_col = getattr(Firmware, cfg.finished_at_column)
        err_col = getattr(Firmware, cfg.error_column)
        res = await db.execute(
            update(Firmware).where(col.in_(cfg.in_progress_states)).values({
                cfg.status_column: "failed",
                cfg.error_column: cfg.error_message,
                cfg.finished_at_column: datetime.now(UTC),
            })
        )
        total_reaped += res.rowcount or 0
    await db.commit()
    if total_reaped:
        logger.info("Reaped %d orphan walker row(s) across %d walkers on startup",
            total_reaped, len(WALKER_REAPER_CONFIGS))
```

**Cost:** +1 dataclass + 22 dict entries in walker_registry.py = ~80 LOC in ONE file; ~30 LOC in main.py for the reaper loop. **Benefit:** single source of truth — walker_registry.py is ALREADY where WALKER_AUTO_TRIGGERS lives; adding the parallel reaper dict is structurally cohesive. New walker authors update TWO entries in the SAME file: the auto-trigger list AND the reaper config dict. **Drawback:** the trigger-name keying means the registration discipline is "add to both lists" rather than "derive one from the other." Acceptable in exchange for explicit data shape.

**Extending Option B to authenticode_chain + windows_update_diff + dotnet_decompile.** Same column-shape exists on those rows (status / started_at / finished_at / error). A generalised `MISC_REAPER_CONFIGS` dict in main.py (or `app/services/reaper_configs.py`) covers them with the same dataclass shape — these aren't walkers, so they don't belong in `walker_registry.py`, but they share the architecture. Fix #11's scope is the 22 walkers; the other 3 columns are a Session 3 follow-up.

### Option C: YAML file (Rule #52 candidate?)

Defer to Scout B's Rule #52 assessment. **My recommendation: NO.** Rule #52 applies to "new analysis surfaces operators MUST extend without modifying Python (chip families, decoder families, vendor adapters)." Reaper config does NOT meet that bar:

- (a) Operators do NOT need to add new state-machine columns — adding a column requires alembic migration + Pydantic Literal + DB CHECK + model column + service code. The reaper config is downstream of that, not parallel to it. There's no operator-facing "extension surface" motivation.
- (b) Closed-grammar enforcement (Pydantic Literal at module scope) is mechanically equivalent — the only thing YAML buys is config-file-edit-without-Python — which is not a use case anyone has.
- (c) The reaper config IS pure data (column names + in-progress state list + error message) but it's WAIRZ-INTERNAL data; the entire backend is the only consumer.
- (d) Rule #52's worked examples (bare-metal chip families, file-format catalog) have hundreds of operator-extension points and a vendor partition discipline. The reaper config has 22 entries that grow by ~3/year — well below the threshold where Rule #52's YAML overhead pays for itself.

**Verdict:** Option B (centralised dict in walker_registry.py + dataclass). Code stays in Python; the Rule #46 META-CANARY proves every WALKER_AUTO_TRIGGERS entry has a matching WALKER_REAPER_CONFIGS entry (size-lock test asserts `len(WALKER_REAPER_CONFIGS) == len(WALKER_AUTO_TRIGGERS) == 26`).

### LOC estimate

- `walker_registry.py`: +1 dataclass + 22 dict entries = ~80 LOC
- `main.py`: +30 LOC for the reaper loop (replaces 4 separate try/except blocks for cve_match / vuln_scan / upload_stage / bare_metal_audit eventually — but Fix #11's scope is JUST the walker sweep, not a refactor of the existing 5 reapers)
- `tests/test_main_lifespan_reapers.py`: +6 META-CANARIES (one per walker column class — uniform discipline canary + size-lock + synthesize-and-assert per Rule #46)
- `tests/test_walker_registry.py`: +3 META-CANARIES (size-lock between `WALKER_AUTO_TRIGGERS` and `WALKER_REAPER_CONFIGS`; column-name validity against Firmware model; trigger_name-key consistency)

**Total: ~220 LOC across 4 files.** Matches W2-γ's Fix #11 estimate from the S1 postmortem.

## Cross-Stack Alignment Commit Shape (Rule #48 5-part for `sbom_status`)

Per Rule #25 single-slice exception #2 + Rule #48 5-part test shape, Fix #1's alembic + Pydantic Literal + DB CHECK + frontend mirror lands as ONE atomic commit:

1. **Paired rejection** — alembic DB CHECK rejects `sbom_status='bogus'` at DB level; Pydantic `SbomStatus` Literal rejects same at API level.
2. **Paired acceptance** — each of `("idle", "queued", "running", "completed", "failed")` round-trips through DB ↔ Pydantic ↔ frontend type union.
3. **Size-lock** — `assert len(get_args(SbomStatus)) == 5` AND `assert SBOM_STATUS_VALUES == ("idle", "queued", "running", "completed", "failed")` AND `len(_EXPECTED_TIERS) == 20` (unchanged — Fix #1 doesn't change tier coverage).
4. **Cross-layer alignment proper** — `test_sbom_status_alignment` synthesizes `bogus` and asserts BOTH the DB CHECK AND Pydantic Literal reject it; tests both rejection modes simultaneously (raise vs WARN).
5. **META-CANARY per Rule #46** — synthesize a malformed Pydantic Literal (e.g. missing one value) and confirm the alignment test FAILS; this proves the gate fires.

The commit message follows the Rule #25 Shape-1 form: `feat(sbom): Rule #33 sync→202+polling conversion + sbom_status state machine + frontend mirror`. Bisect-clean because the alembic migration + Pydantic Literal + DB CHECK MUST agree pairwise — splitting leaves the system in a state where one layer rejects what another accepts.

## Rule #51 4-companion Sweep Audit for Fix #1

### (i) Orphan reaper

Design above — 5th reaper block in main.py lifespan, NO grace window (mirrors cve_match / vuln_scan, not upload_stage). The bare_metal_audit Fix #5 from S1 is the closest precedent — both are in-process work where the 409 idempotency check + `_spawn_background_task` strong-ref set adequately bound concurrent state.

### (ii) Tier alignment

Already pinned correctly at `TIER_A_LIGHT_ACK` in `_EXPECTED_TIERS` (test_rate_limit_tiers.py:52). Pre-Session-1 the decoration at sbom.py:143 was a Rule #51 .ii DRIFT on a sync endpoint (Scout E S1 finding #2). Post-conversion the decoration becomes structurally CORRECT — sub-second ack + ≤2-min detached work per the rate_limit.py docstring at lines 37-51. The size-lock at test_rate_limit_tiers.py:135 (`len(_EXPECTED_TIERS) == 20`) remains correct — Fix #1 does NOT add a new endpoint (the `GET /sbom/generate/status` is GET, not POST, and only POSTs are tier-decorated). The frontend axios `SECURITY_SCAN_TIMEOUT` override at api/sbom.ts:38 becomes UNNECESSARY post-conversion — the 202 ack is sub-second so the default 30s axios floor is correct. The override CAN be removed in the same commit OR deferred — recommend removing in the same commit to clean up the Rule #29 derivation discipline.

### (iii) Frontend extractErrorMessage

The existing `extractErrorMessage` helper at frontend/src/utils/error.ts (used by SbomPage at line 140) handles the SlowAPI 429 structured body shape (Rule #51 .iii) — verified during the 2026-05-18 rate-limit campaign. The new `/sbom/generate/status` polling endpoint inherits the same handler behavior; no frontend changes needed beyond the new types + polling effect.

### (iv) DB pool headroom — dual generate+scan polling

Per W2-β §SC5-NEW-SBOM-γ, the dual-polling concern: after Fix #1 lands, the frontend can simultaneously poll BOTH `/sbom/generate/status` AND `/sbom/vulnerabilities/scan/status` every 2 s. Each poll = 1 DB connection from the pool for the SELECT round-trip. Combined burst rate when an operator triggers BOTH endpoints on a single firmware:

- generate polling: 2s × 1 connection = 30 reqs/min
- scan polling: 2s × 1 connection = 30 reqs/min
- existing component-page polling: 2s × ~3 connections per render = 90 reqs/min
- **Combined: ~150 reqs/min sustained = ~2.5 reqs/s steady state**

The current pool config (pool_size=15, max_overflow=25, total=40 per Rule #51's f6dbc7b sweep) handles this with ~30+ headroom. No pool bump required for Fix #1 specifically; existing post-2026-05-18 pool sizing is adequate. The W2-β §SC5-NEW-SBOM-γ concern was a sustained 4-firmware concurrent dual-poll workload (~600 reqs/min) — operators don't currently run that workload, and adding a 2-firmware concurrent dual-poll guard via SbomPage's `selectedFirmwareId` state (single firmware at a time per page) keeps the budget bounded.

The Rule #33 (b) `sbom_result` JSONB column is small (~200-500 bytes per row — just count + cached flag + RTOS metadata) so the row UPDATE cost on completion is negligible relative to the existing `sbom_components` INSERT cost (the actual SBOM payload).

## Cross-References

| File:line | Purpose |
|---|---|
| `backend/app/routers/sbom.py:142-252` | Current synchronous `/generate` endpoint to be refactored |
| `backend/app/routers/sbom.py:549-620` | `/vulnerabilities/scan` 202+polling reference pattern Fix #1 mirrors |
| `backend/app/routers/sbom.py:28-37` | `_spawn_background_task` GC-hardening helper (S1 Fix #8) |
| `backend/app/routers/sbom.py:445-547` | `_run_vuln_scan_background` reference shape for Fix #1's `_run_sbom_generate_background` |
| `backend/app/main.py:200-242` | vuln_scan reaper (Fix #1's reaper mirrors this — no grace) |
| `backend/app/main.py:244-303` | upload_stage reaper (S1 Fix #2 — 15-min grace; Fix #1 does NOT mirror this) |
| `backend/app/main.py:305-348` | bare_metal_audit reaper (S1 Fix #5 — no grace; Fix #1 mirrors this shape) |
| `backend/app/models/firmware.py:50-68` | cve_match + vuln_scan column shapes Fix #1's sbom_* mirrors |
| `backend/app/models/firmware.py:113-966` | All 22 walker columns Fix #11 reaps |
| `backend/app/schemas/sbom.py:108` | `VulnScanStatus` Literal Fix #1's `SbomStatus` mirrors |
| `backend/app/schemas/sbom.py:111-128` | `VulnerabilityScanStatusResponse` shape Fix #1's `SbomGenerateStatusResponse` mirrors |
| `backend/app/workers/walker_registry.py:100-158` | `WALKER_AUTO_TRIGGERS` list — Fix #11 adds parallel `WALKER_REAPER_CONFIGS` dict here |
| `backend/app/rate_limit.py:37-51` | `TIER_A_LIGHT_ACK` derivation docstring (Fix #1 inherits this tier) |
| `backend/tests/test_rate_limit_tiers.py:52` | `_EXPECTED_TIERS` already-pinned entry for `/sbom/generate` (no change needed) |
| `backend/tests/test_rate_limit_tiers.py:135` | `_EXPECTED_TIERS` size-lock (count=20 stays correct) |
| `backend/tests/test_main_lifespan_reapers.py:34-79` | upload_stage reaper META-CANARY (Fix #1 adds parallel `test_sbom_status_reaper_present_in_lifespan`) |
| `backend/tests/test_main_lifespan_reapers.py:127-167` | bare_metal_audit reaper META-CANARY (Fix #1's reaper test mirrors this — no-grace shape) |
| `backend/alembic/versions/e6f7a8b9c0d1_add_cve_match_status_to_firmware.py:1-114` | Alembic migration template Fix #1 mirrors |
| `backend/alembic/versions/fd6e7f8a9b0c_extend_findings_source_bare_metal.py` | Current alembic head — Fix #1's new revision has `down_revision='fd6e7f8a9b0c'` |
| `frontend/src/pages/SbomPage.tsx:162-219` | `handleScan` + polling effect Fix #1's `handleGenerate` mirrors |
| `frontend/src/api/sbom.ts:88-112` | `runVulnerabilityScan` + `getVulnerabilityScanStatus` Fix #1's `generateSbom` + `getSbomGenerateStatus` mirror |
| `frontend/src/types/index.ts:369-383` | `VulnScanStatusValue` + `VulnerabilityScanStatus` Fix #1's `SbomStatusValue` + `SbomGenerateStatus` mirror |
| `.planning/postmortems/postmortem-sbom-vuln-scan-regression-session1-2026-05-21.md` | Session 1 context — Fix #1 + Fix #11 listed under "Session 2 plan (queued)" lines 308-314 |
| `.planning/research/sbom-vuln-scan-regression-2026-05-21/wave1-scout-E-state-machine.md` | Predecessor enumeration of all 30 state-machine columns |
