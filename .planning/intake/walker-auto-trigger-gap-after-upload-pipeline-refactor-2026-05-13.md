---
title: Walker auto-trigger gap — post-`847eae9` upload-pipeline refactor breaks the walker chain for every firmware upload
opened: 2026-05-12 (filed late-night UTC; tagged 2026-05-13 for chronological clarity)
status: HIGH-PRIORITY — actively blocks the entire Windows test plan + every operator's first-impression test post-κ
priority: high (every firmware upload silently skips ALL 21 auto-trigger walkers)
discovered_during: Windows-firmware-test-plan execution on Medtronic ILLUMISITE 15.57 GB upload
parent: post-κ smoke-test (companion to ux-upload-progress-multistage-2026-05-12.md)
---

# Walker auto-trigger gap after upload-pipeline refactor

## Problem (verified empirically)

Operator uploaded a 15.57 GB Windows firmware ZIP. Upload pipeline completed:

```
firmware.id           = 640cda1f-fd00-422b-9bea-24fc7b5c7a37
firmware.upload_stage = 'ready'
firmware.file_size    = 16,716,949,288 bytes (15.57 GB)
firmware.unpack_stage = NULL
firmware.extracted_path = NULL
firmware.extraction_dir = NULL
firmware.device_metadata = NULL
```

ZIP was extracted to `/data/firmware/projects/<pid>/firmware/<fid>/zip_contents/`
(17 GB on disk) — extraction happened. The extracted tree contains walker-relevant
Windows artefacts:
- `Boot/BCD` (would trigger θ.A bcd_walk → `windows_bcd_*` findings)
- `bootmgr.efi` (would trigger θ.C esp_walk → `windows_esp_*` findings)
- `sources/boot.wim` (Windows imaging)
- `EFI/` directory (UEFI Secure Boot)

**But ALL 21 walker `*_walk_status` columns remained `idle`:**
- `registry_hive_walk_status`, `evtx_walk_status`, `prefetch_walk_status`,
  `srum_walk_status`, `scheduled_task_walk_status`, `lnk_walk_status`,
  `mft_walk_status`, `bcd_walk_status`, `wmi_walk_status`, `esp_walk_status`,
  `mbr_vbr_walk_status`, `sdb_walk_status`, `journald_walk_status`,
  `systemd_walk_status`, `etl_walk_status`, `efs_walk_status`,
  `container_walk_status`, `appcompat_walk_status`, `persistence_walk_status`,
  `dpapi_walk_status`, `usnjrnl_walk_status` — ALL `idle`.
- `0 findings` emitted.

## Root cause hypothesis

The `847eae9` refactor (intake `firmware-upload-progress-visibility-2026-05-07`)
introduced a new `_post_process_pipeline` (`backend/app/services/firmware_service.py:540-755`)
that transitions `upload_stage` through `detecting → extracting → analyzing → ready`.
This pipeline runs the unblob extraction and stages the firmware to `ready`.

**However, the walker auto-trigger registrations live in
`backend/app/workers/unpack.py:129-162`** (per κ Scout 3 audit) — each walker
registers an `auto_<op>_walk_firmware_safe(firmware_id)` callback. These callbacks
are wired to fire when the OLD `_run_unpack_background` completes — NOT when
`_post_process_pipeline` completes.

The new upload pipeline does extraction + sets `upload_stage='ready'` but
NEVER calls the unpack worker's post-unpack hook chain. So the walker
registrations are dead code for every firmware uploaded via the new pipeline.

`unpack_stage`, `extracted_path`, `extraction_dir`, `device_metadata` are all
written by the OLD unpack worker too — their NULL state in the example
firmware is consistent with "the new pipeline doesn't write these columns."

## Mechanical investigation (sub-agent dispatch hooks)

For the sub-agent that picks this up:

1. **Read `backend/app/services/firmware_service.py:540-755`** (`_post_process_pipeline`):
   identify what it does in the `analyzing` phase. Does it call walker hooks?
   Does it set `extracted_path` / `extraction_dir`?
2. **Read `backend/app/workers/unpack.py:129-162`** (auto-trigger block): list ALL
   the `auto_<op>_walk_firmware_safe` calls. Each one is a walker that's currently
   dead for new uploads.
3. **Identify the BRIDGE**: does `_post_process_pipeline` need to invoke the
   unpack worker hooks? OR is the OLD unpack worker still supposed to be
   invoked alongside the new pipeline? OR was the refactor incomplete?
4. **Check the intake `firmware-upload-progress-visibility-2026-05-07.md`**:
   did the original refactor scope include re-wiring walker triggers, or was
   that explicitly deferred?
5. **Test fixtures**: confirm `extracted_path` / `extraction_dir` are written by
   the OLD unpack worker but NOT by `_post_process_pipeline`.

## Three solution shapes

### Shape A — Minimum bridge (recommended for first ship)
In `_post_process_pipeline`'s `analyzing` phase, AFTER extraction completes,
explicitly invoke the same auto-trigger chain from `unpack.py:129-162`:

```python
# After unblob extraction → set extracted_path + extraction_dir + device_metadata
# Then fire each walker's safe auto-trigger:
for walker_hook in WALKER_AUTO_TRIGGER_HOOKS:
    asyncio.create_task(walker_hook(firmware.id))
```

LOC: ~20-30 (one new block in `_post_process_pipeline` + factor the existing
walker-hook list into a shared module so both the OLD unpack worker AND the
new pipeline can use it).
Alembic: none.
Rule #25: none (no Literal change).
Risk: medium — touches the new upload pipeline, requires Rule #8 rebuild.

### Shape B — Migrate fully to upload pipeline
Move ALL of `_run_unpack_background`'s responsibility into
`_post_process_pipeline`. Delete the OLD path. Larger refactor.

LOC: ~200-300 across multiple services.
Alembic: maybe — depends on whether `unpack_stage` should be deprecated.
Rule #25: yes if `unpack_stage` deprecation touches the Literal.
Risk: high — touches the canonical post-upload flow.

### Shape C — Reverse the refactor
Restore the OLD `_run_unpack_background` flow and treat `upload_stage` as a
secondary state machine. Worst option — reverts a deliberate Rule #33 .a
improvement.

## Recommendation

**Ship Shape A** as a single-stream fix. Then plan Shape B (full migration)
as a future refactor when there's appetite.

## Acceptance criteria

After the fix, an upload like the ILLUMISITE 15.57 GB ZIP should:

1. Reach `upload_stage='ready'` (current behavior — unchanged).
2. ALSO populate `extracted_path` + `extraction_dir` + `device_metadata`
   (likely via the same code path that's missing).
3. Trigger every relevant walker. Specifically for this firmware:
   - `bcd_walk_status` → `running` → `completed` (BCD walker should find
     `Boot/BCD` and emit `windows_bcd_*` findings if anomalies present)
   - `esp_walk_status` → `running` → `completed` (ESP walker should find
     `bootmgr.efi` and emit `windows_esp_*` findings if anomalies present)
   - Other walkers may register `idle` if the firmware lacks their target
     artefact — that's correct (e.g. journald shouldn't fire on a Windows
     boot CD).
4. Findings table contains rows for any anomalies detected.

## Manual workaround for current Medtronic ILLUMISITE test

Until the bridge ships, operator can manually trigger walks via MCP:

```
trigger_bcd_walk firmware_id=640cda1f-fd00-422b-9bea-24fc7b5c7a37
trigger_esp_walk firmware_id=640cda1f-fd00-422b-9bea-24fc7b5c7a37
trigger_appcompat_walk firmware_id=640cda1f-fd00-422b-9bea-24fc7b5c7a37
# (and any other applicable walker)
```

**Important caveat:** manual triggers may also fail if `extracted_path` is
NULL — most walkers fall back to `firmware.extracted_path` when
`get_detection_roots(firmware)` returns empty. The DB row may need to be
patched first to set `extracted_path` to the actual extraction directory
(`/data/firmware/projects/<pid>/firmware/<fid>/zip_contents/...`).

## Companion intakes

- `ux-upload-progress-multistage-2026-05-12.md` — UX side of the upload
  experience.
- `firmware-upload-progress-visibility-2026-05-07.md` (parent of the refactor
  that introduced this gap) — review for original scope statement re: walker
  triggers.

## Rule promotion candidate

Add to CLAUDE.md as Rule #47 candidate:

> **When refactoring an existing state machine to a new one, the refactor
> MUST enumerate every consumer hook of the OLD state machine and explicitly
> migrate or bridge them to the NEW state machine.** The `847eae9` refactor
> (upload_stage state machine) migrated the visible polling but left the
> walker auto-trigger registrations on the OLD unpack_stage path orphaned —
> every walker stream γ.4 → κ.E is dead-code for any firmware uploaded
> after the refactor. Rule-of-One; promote to Rule-of-Two if similar
> refactor-orphan surfaces in λ or later.
