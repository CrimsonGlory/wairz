---
title: "Next-session seed — execute firmware_service.py P3 carve-out from committed de-risk analysis"
status: pending
priority: medium
format: citadel-seed-v1
author: session-3d9d854e-autopilot
created: 2026-04-24T23:59:00Z
target_session: next
baseline_head: 8e99ec4  # intake: firmware_service de-risk analysis
previous_seed: seed-next-session-2026-04-24.md (closed +A/+A'/+A'-cont/+C-completed; 2026-04-24 shipped hash_lookups + wairz_runner in session 3d9d854e)
research_method: per-call Rule #30 audit committed in .planning/intake/backend-private-api-and-circular-imports.md
---

# Next-session seed — firmware_service.py P3 promotion

> Read order for the incoming session:
>   1. This file (execution plan)
>   2. `.planning/intake/backend-private-api-and-circular-imports.md` — the "De-risk analysis" section (top of file, added commit `8e99ec4`)
>   3. `backend/app/services/firmware_service.py` — the target file
>   4. `CLAUDE.md` Rules #11, #20, #25, #28, #30, #31

## Summary — execute pre-audited mechanical promotion

Session 3d9d854e committed a full per-call Rule #30 audit for firmware_service.py's 14 function-body `app.*` imports. All 5 source modules classified SAFE; Rule #30 legitimate-lazy criteria all NEGATIVE; zero test-patch activation risk verified; only HTTP routers import firmware_service at top level (terminal graph nodes); workers have zero top-level `app.services.*` imports (verified across all 5 worker modules).

The seed's original "cross-layer latent-cycle risk" warning was over-cautious — evidence contradicts it. The work is mechanically equivalent to hash_lookups + wairz_runner carve-outs already shipped this session.

## Execution plan (single commit, matches Rule #25 per-file precedent)

### Step 1 — Pre-measure (Rule #28)

```bash
python3 -c "
import ast, pathlib
tree = ast.parse(pathlib.Path('backend/app/services/firmware_service.py').read_text())
n = sum(1 for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
        for s in ast.walk(f) if s is not f and isinstance(s, ast.ImportFrom)
        and s.module and s.module.startswith('app.'))
print(f'Pre-count: {n} function-body app.* imports')
"
# Expect: 14
```

### Step 2 — Edit firmware_service.py

Add 5 top-level imports after `backend/app/services/firmware_service.py:L17` (alphabetized, matching codebase convention):

```python
from app.services.firmware_paths import populate_detection_roots
from app.workers.safe_extract import safe_extract_zip
from app.workers.unpack import (
    _run_hardware_firmware_detection_safe,
    detect_architecture,
    detect_kernel,
    detect_os_info,
    find_filesystem_root,
)
from app.workers.unpack_common import (
    _recursive_extract_nested,
    diagnose_failed_archives,
    widen_read_perms,
)
from app.workers.unpack_linux import _firmware_tar_filter
```

Remove 14 function-body imports at these lines (line numbers from baseline `8e99ec4`; verify before editing):
- L225 `_extract_archive`: `from app.workers.safe_extract import safe_extract_zip`
- L343 `upload`: `from app.workers.unpack import detect_architecture, detect_kernel, detect_os_info, find_filesystem_root`
- L355 `upload`: `from app.workers.unpack_linux import _firmware_tar_filter`
- L362 `upload`: `from app.workers.unpack_common import widen_read_perms`
- L412 `upload`: `from app.services.firmware_paths import populate_detection_roots`
- L434 `upload`: `from app.workers.unpack import _run_hardware_firmware_detection_safe`
- L473 `upload`: `from app.workers.unpack import detect_architecture, detect_kernel, detect_os_info, find_filesystem_root` (duplicate of L343)
- L490 `upload`: `from app.workers.unpack_common import widen_read_perms` (duplicate of L362)
- L527 `upload`: `from app.services.firmware_paths import populate_detection_roots` (duplicate of L412)
- L537 `upload`: `from app.workers.unpack import _run_hardware_firmware_detection_safe` (duplicate of L434)
- L581 `upload`: `from app.workers.unpack_common import _recursive_extract_nested`
- L614 `upload`: `from app.workers.unpack_common import widen_read_perms` (duplicate of L362)
- L627 `upload`: `from app.workers.unpack_common import diagnose_failed_archives`
- L675 `upload_rootfs`: `from app.workers.unpack import detect_architecture, detect_kernel, detect_os_info, find_filesystem_root` (duplicate of L343)

Expected delta: ~15 insertions (top-level block) / 14 deletions (function-body).

### Step 3 — Post-measure

Re-run the ast.walk count — should be **0**.

```bash
python3 -c "
import ast, pathlib
tree = ast.parse(pathlib.Path('backend/app/services/firmware_service.py').read_text())
n = sum(1 for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
        for s in ast.walk(f) if s is not f and isinstance(s, ast.ImportFrom)
        and s.module and s.module.startswith('app.'))
print(f'Post-count: {n}')
"
# Expect: 0
```

### Step 4 — Rule #11 import smoke

Per Rule #20 (docker cp + exec, no class-shape change so no restart needed):

```bash
docker cp backend/app/services/firmware_service.py wairz-backend-1:/app/app/services/firmware_service.py
docker cp backend/app/services/firmware_service.py wairz-worker-1:/app/app/services/firmware_service.py

docker compose exec -T -w /app -e PYTHONPATH=/app backend /app/.venv/bin/python -c "
from app.services.firmware_service import FirmwareService
print('backend ✓ FirmwareService:', FirmwareService.__name__)
"

docker compose exec -T -w /app -e PYTHONPATH=/app worker /app/.venv/bin/python -c "
from app.services.firmware_service import FirmwareService
print('worker ✓')
"
```

### Step 5 — Commit per Rule #25

```bash
git add backend/app/services/firmware_service.py
git commit -m "refactor(firmware_service): promote function-body imports to top-level

6th P3 carve-out (continuing from session 3d9d854e). Per-call Rule #30 audit
committed in intake (commit 8e99ec4) classified all 5 source modules as SAFE
and all legitimate-lazy criteria as NEGATIVE. Zero test-patch activation risk.

Promotions (14 → 0 function-body imports):
- app.services.firmware_paths.populate_detection_roots: 2 sites → 1 top-level
- app.workers.safe_extract.safe_extract_zip: 1 site → top-level
- app.workers.unpack.{_run_hardware_firmware_detection_safe, detect_architecture,
  detect_kernel, detect_os_info, find_filesystem_root}: 5 sites → 1 top-level
- app.workers.unpack_common.{_recursive_extract_nested, diagnose_failed_archives,
  widen_read_perms}: 5 sites → 1 top-level
- app.workers.unpack_linux._firmware_tar_filter: 1 site → top-level

Rule #11 import smoke green on backend + worker.
Post-session repo-wide residual: 33 → 19 function-body app.* imports across
15 files (down from 16).

Co-Authored-By: Claude <agent>
"
```

### Step 6 — Update intake + ROUTER.md + close if residual ≤ single-digit

Append a "Partial P3 progress — session {id}" paragraph to the intake log with:
- Commit SHA
- New residual count via ast.walk (expect 19/15)
- Confirmation Rule #30 audit held (no surprises)

Update `.mex/ROUTER.md` "Recently shipped" to reflect 6th P3 carve-out + new residual.

## Optional follow-on (only if time remains after firmware_service)

Next-densest remaining candidates (ast.walk counts, all single-digit):
- `hardware_firmware/cve_matcher.py` (2) — eligible, leaf-likely
- `clamav_service.py` (2) — eligible, pure-leaf (verified this session as import TARGET for hash_lookups)
- `attack_surface_service.py` (2) — eligible

Same Rule #30 audit procedure. But Rule #19 applies: no felt cycle pressure. Diminishing returns. Recommend STOP after firmware_service unless user directs further.

## First action for next session

```text
1. Read this file + the intake's "De-risk analysis" section (top of
   .planning/intake/backend-private-api-and-circular-imports.md)
2. Confirm baseline:
     git rev-parse HEAD  # expect 8e99ec4 or a descendant
3. Pre-measure (ast.walk) — expect 14 function-body app.* imports
4. Execute steps 2-5 above (edit, smoke, commit)
5. Log progress in intake + update ROUTER.md
6. If queue genuinely empty after: close seed, offer to user
```

## Baseline + rollback

Baseline `8e99ec4` (this seed's baseline) is the de-risk analysis commit. The execution creates a single refactor commit — `git revert <sha>` rolls it back cleanly.

## Risk

- **Line-number drift**: If firmware_service.py is edited between this seed and execution, L-numbers in step 2 may drift. Mitigation: use the symbol-based catalog (`from app.workers.safe_extract import safe_extract_zip` is unique; search-and-replace by content, not line number).
- **Unseen cycle**: The per-call audit was thorough (module-level + transitive + reverse-dep), but Python's import system can hide edge cases. Mitigation: Rule #11 smoke in step 4 catches any runtime import failure immediately. If smoke fails, `git reset --hard HEAD~1` and investigate.
- **Scope creep**: resist chaining a 7th P3 carve-out unless the user directs. Rule #19 + diminishing returns apply.

## Scout telemetry

None — this seed is pure execution-planning from session 3d9d854e's de-risk analysis. No parallel Explore scouts.
