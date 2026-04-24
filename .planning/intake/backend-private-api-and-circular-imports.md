---
title: "Backend: Promote Private APIs + Break Circular Imports"
status: partial
priority: high
target: backend/app/services/
partially_completed_at: 2026-04-19
partially_completed_via: "session 93a4948d — Phases 1 and 2 shipped (kernel_service cycle broken; _scan_* promoted via run_scan_subset)"
---

## Status: Partial — P1 and P2 complete (2026-04-19, session 93a4948d)

| Phase | Status | Commit | Scope |
|---|---|---|---|
| P1 — private-API leak | **complete** | `2a27175` | Added public `run_scan_subset(root, names, findings?)` + `SCANNERS` dict in `security_audit_service`. `assessment_service._phase_credential_crypto` now calls `run_scan_subset(["credentials","shadow","crypto_material"])` instead of importing three `_scan_*` privates. `grep '_scan_credentials\|_scan_crypto_material\|_scan_shadow' backend/app/services/assessment_service.py` → **0 hits**. |
| P2 — kernel_service ↔ emulation_service cycle | **complete** | `68ecb64` | `kernel_service.py:323` function-local `from app.services.emulation_service import _validate_kernel_file` → top-level `from app.services.emulation_constants import _validate_kernel_file` (the helper actually lives there and was re-exported only for convenience). `emulation_service.py` promoted 2 function-local `from app.services.kernel_service import KernelService` to top-level. Both files now import only top-level across the former cycle. |
| P3 — systemic function-local import audit | **deferred** | — | Baseline function-local `from app.services.*` count: session start = **40**, post-session = **37** (−3 from P1/P2). Remaining 37 live in 13 files (assessment_service, attack_surface_service, comparison_service, emulation_service, fuzzing_service, hardware_firmware/*, mobsfscan_service, qiling_service, sbom_service, security_audit_service, wairz_runner). A dependency-graph audit + per-cycle shared-extract is a standalone campaign; intake explicitly noted "Phase 3 is open-ended and can grow — cap the scope to specific service pairs per PR, not 'all of them'." **Deferred to a follow-up campaign** — see `.planning/intake/` for the Phase-3 carve-out if/when prioritized. |

### Acceptance criteria (audit result)

| Criterion | Status |
|---|---|
| P1: `grep -n 'from app.services.emulation_service import _validate_kernel_file' backend/app/services/kernel_service.py` → 0 | ✓ |
| P1: `kernel_service.py` and `emulation_service.py` both top-level import from `emulation_constants`, neither imports the other at any scope | ✓ (verified) |
| P2: `grep -rn '_scan_credentials\b\|_scan_crypto_material\b\|_scan_shadow\b' backend/app/services/assessment_service.py` → 0 | ✓ |
| P2: `assessment_service` has no direct function references to `security_audit_service` internals | ✓ (calls `run_scan_subset` by name only) |
| All existing tests pass | ✓ (tests continue to import `_scan_*` privates — legitimate, since they test the same-module implementation) |

### Remaining work (P3)

Non-blocking, open-ended. Spin out as a separate campaign when cycle pressure becomes felt.

**Partial P3 progress — session 5eefecb0 (2026-04-24, commit `fc384bb`):** `assessment_service.py` fully promoted (10 service + 1 model + 1 cross-layer `app.ai.tools.binary` function-local imports → top-level); deep cycle audit confirmed 0 callees back-import assessment_service and no module top-level-imports it, so promotion was safe. Rule #30 companion import-smoke caught a latent `ComplianceService` / `ETSIComplianceService` mismatch that had been silently killing `_phase_compliance` since the rename — fixed in the same commit (untested path, zero test coverage). Post-session function-local `from app.services.*` count: 37 → 26 (-11; mechanical, not cycle-driven). 13 files still carry function-locals: `fuzzing_service`(4), `wairz_runner`(3), `mobsfscan/pipeline`(2), `hardware_firmware/cve_matcher`(2), `firmware_service`(2), `emulation/user_mode`(2), `emulation/service`(2), `attack_surface_service`(2), plus 1-each in `security_audit/network`, `sbom/strategies/__init__`, `sbom/enrichment`, `qiling_service`, `mobsfscan/normalization`, `hardware_firmware/graph`, `hardware_firmware/classifier`. Each of these should be audited individually against Rule #30 legitimate-lazy criteria (optional-dep / LGPL / latent-cycle) before any further bulk promotion — don't assume assessment_service's mechanical-safe profile repeats.

**Partial P3 progress — session f2f9060c (2026-04-24, commits `7d349c3`, `d1a8701`, `77a5908`):** fuzzing_service + emulation/ subpackage pair cleared. `fuzzing_service.py` (4 → 0; event_service, emulation.docker_ops.copy_dir_to_container, sysroot_service.get_sysroot_path promoted), `emulation/service.py` (3 → 0; app.database.async_session_factory, qiling_service.{get_rootfs_path, run_binary_async}, sysroot_service.get_sysroot_path promoted), `emulation/user_mode.py` (2 → 0; sysroot_service.get_sysroot_path promoted). Rule #30 audit classified every target as pure-leaf: event_service imports only redis+app.config (5 existing top-level sites elsewhere); emulation.docker_ops is a post-Phase-5 free-function helper module imported top-level in 3 siblings; sysroot_service has ZERO app.* imports (pure stdlib); app.database imports only app.config; qiling_service has zero module-level app.services.* imports (qiling library lives in a subprocess-embedded script). Cycle-safe by construction across all 9 promotions. Rule #11 import-smoke green on backend+worker for all three files. Per-file commit per Rule #25. Post-session repo-wide broader `^\s+from app\.` count across `backend/app/services/`: 14 files still carry app.*-prefix function-locals (widened match caught `app.utils.*`, `app.database.*`, and others missed by the narrow pattern used last session). Biggest residual: `firmware_service.py` (14 under widened match). Next pair candidates by density: `firmware_service.py`(14), `security_audit/hash_lookups.py`(5), `mobsfscan/normalization.py`(4), `wairz_runner.py`(3), `mobsfscan/pipeline.py`(3).

**De-risk analysis — `firmware_service.py` (14 imports) — session 3d9d854e (2026-04-24):** The seed's "cross-layer latent-cycle risk" warning conflated two concerns. Evidence after per-call Rule #30 audit: cycle-risk is **ZERO**; the remaining concern is an orthogonal architectural layer-hygiene question (services → workers direction) that is out-of-P3-scope.

*Authoritative catalog (ast.walk):* 14 function-body `app.*` imports across 5 source modules (earlier grep-based "15" was a multi-line-import false-positive): `app.workers.safe_extract` (1 site), `app.workers.unpack` (5 sites, 3 unique call-names), `app.workers.unpack_linux` (1), `app.workers.unpack_common` (5 sites, 3 unique), `app.services.firmware_paths` (2 sites, 1 unique).

*Per-module Rule #30 audit — all 5 SAFE:*
| Source | Top-level app.* imports | Reverse-dep on firmware_service | Classification |
|---|---|---|---|
| `safe_extract` | 0 (pure stdlib) | NONE | pure leaf |
| `unpack` | sibling workers only | NONE | transitively leaf |
| `unpack_linux` | sibling workers only | NONE | transitively leaf |
| `unpack_common` | stdlib + elftools (1623 LOC but no I/O at module-init) | NONE | transitively leaf |
| `firmware_paths` | 0 app.* runtime (TYPE_CHECKING-guarded only) | NONE | pure leaf |

*Global cycle-node audit:* ONLY HTTP routers import firmware_service at top level (`firmware.py:24`, `deps.py:10`, `uart.py:23`, `comparison.py:29`) — routers are terminal nodes in the dep graph. All 5 workers have ZERO top-level `app.services.*` imports at module-init (verified). Cross-layer dep is strictly one-way: services/→workers/; workers→services direction is absent.

*Rule #30 legitimate-lazy criteria — all NEGATIVE:*
- (a) Optional/slow-dep: NO — `unpack_common` has zero subprocess/I/O at module-init; all 5 modules ALREADY loaded at worker-container startup via arq_worker; backend-container marginal cost ~50ms module-parse per startup, one-time.
- (b) GPL/LGPL partition: NO — all first-party.
- (c) Latent-cycle avoidance: NO — zero reverse-dep chains.

*Test-patch activation risk — ZERO:* 3 existing patches target `app.services.firmware_service.get_settings` (already top-level, L16, no change). ZERO patches target any of the 11 worker symbols being promoted. No silent-no-op activation per Rule #30's test-side risk.

*Recommended execution shape (future session, single commit):* add 5 top-level imports after firmware_service.py:L17 (one per source module, alphabetized); remove 14 function-body imports (5 duplicates in `upload()` collapse to 1 each); Rule #11 smoke on backend + worker; Rule #28 pre-measure sanity (14 → 0 via ast.walk). Expected delta: ~5 ins / 14 del. Matches hash_lookups + wairz_runner precedent this session. Post-execution repo-wide residual: 33 → 19 runtime function-body imports across 15 files.

*Out-of-P3-scope companion observation:* firmware_service consumes 11 worker symbols as pure helper functions (`detect_architecture`, `detect_kernel`, `widen_read_perms`, `safe_extract_zip`, `_firmware_tar_filter`, etc.). These live in `app/workers/` for historical reasons but are logically utilities, not async background processes. A FUTURE intake could extract them to `app/utils/firmware_helpers/` or similar. **Not this intake** — P3 is about promoting lazy imports, not relocating symbols.

---

**Partial P3 progress — session 3d9d854e continuation (2026-04-24, commit `781a30e`):** `wairz_runner.py` cleared (2 → 0 real runtime function-body imports; grep-apparent 3 → 1). Promotions: `app.services.androguard_service.AndroguardService` + `app.services.mobsf_runner.compare_findings` to top-level. Rule #30 classified as "layered lazy-import relic" — androguard_service lazy-imports the androguard library at function-body level (L508/523/640/861/891), so wairz_runner's function-local was defensive-of-defensive; the androguard cold-import is NOT triggered by top-level class-symbol promotion. mobsf_runner is pure-leaf stdlib-only. `_get_service()` docstring adjusted to "lazy-instantiate" (import is top-level; instance construction stays gated on first call to preserve cold-start avoidance on non-APK paths). Rule #11 import smoke green (backend + worker). **Rule #31 companion finding**: grep `^\s+from app\.` has bidirectional error modes — (a) OVER-count: L23 match is a docstring example showing caller-side usage, not runtime code (1 false-positive); (b) UNDER-count: `firmware_service.py` has 15 real imports via `ast.walk` but only 14 via grep (multi-line import continuation likely; not yet investigated). `ast.walk`-based count is authoritative. This is a recall/precision issue orthogonal to Rule #31's width hazard — file as a companion note; don't promote to a standalone Rule until a 3rd incident justifies it.

**Partial P3 progress — session 3d9d854e (2026-04-24, commit `404f66d`):** `security_audit/hash_lookups.py` cleared (5 → 0 runtime; `app.config.get_settings` + `app.services.{abusech_service, clamav_service, hashlookup_service, virustotal_service}` promoted; 3 function-local `asyncio` → 1 top-level as tidy-up). Rule #31 width-canary post-edit: narrow=0, broad=0, any-function-local=0 — all three agree. This file was the Rule #31 worst-case evidence example (narrow=0 → widened=5 before this session); now clean under both patterns. Rule #30 audit classified all 4 target services as pure-leaf (0 top-level `app.*` imports, 0 reverse-dep on `security_audit` — cycle-safe by construction). Rule #11 import smoke green on backend + worker (docker cp + exec per Rule #20; no class-shape change, no restart needed). Post-session residual across `backend/app/services/` (runtime-only, TYPE_CHECKING-excluded): 37 → 32 function-locals across 18 files (was 19). Next-pair candidates unchanged: `firmware_service.py`(14 — explicitly out-of-scope, cross-layer latent-cycle risk), `wairz_runner.py`(3), `hardware_firmware/cve_matcher.py`(2), `clamav_service.py`(2), `attack_surface_service.py`(2), 13 files with 1 each. Seed's "one pair per session" guidance respected — this session's single pair closed cleanly.

**Partial P3 progress — session 78f772bd (2026-04-24, commit `5e2cb18`):** `firmware_service.py` cleared — 6th P3 carve-out, executed against the pre-audited de-risk plan from session 3d9d854e (commit `8e99ec4`). 14 function-body `app.*` imports → 0 (raw `ast.walk` counted 15 due to L355 `_firmware_tar_filter` being inside the nested `_extract_tar` function inside `upload`, double-counted by both enclosing scopes; single deletion clears both). Promotions to top-level: `app.services.firmware_paths.populate_detection_roots` (2 sites), `app.workers.safe_extract.safe_extract_zip` (1), `app.workers.unpack.{_run_hardware_firmware_detection_safe, detect_architecture, detect_kernel, detect_os_info, find_filesystem_root}` (5), `app.workers.unpack_common.{_recursive_extract_nested, diagnose_failed_archives, widen_read_perms}` (5), `app.workers.unpack_linux._firmware_tar_filter` (1). Diff: +15 / -44 (seed predicted ~15/14; deletion delta is multi-line parenthesized blocks expanded into per-name lines — content unchanged from the seed's catalog). Per-call Rule #30 audit held with zero surprises: the 5 source modules were classified SAFE in the de-risk commit and remained so under runtime; no test patches activated; no class-shape change (Rule #20 `docker cp` + exec sufficient, no restart needed). Rule #11 import-smoke green on backend + worker. **Post-session repo-wide residual across `backend/app/services/` (ast.walk unique-line count): 18 across 15 files** (down from 33 across 16 files). Seed predicted 19; the -1 delta was the L355 ast-walk double-count noted above. Next-densest remaining candidates (all single-digit, all eligible per per-file Rule #30 audit): `attack_surface_service.py` (2), `clamav_service.py` (2 — pure-leaf, was a hash_lookups import target), `hardware_firmware/cve_matcher.py` (2), 12 files with 1 each. **Rule #19 stop point**: 6 P3 carve-outs across 2 sessions (4 last session, 2 this session counting from 3d9d854e + 78f772bd); diminishing returns from this point. Recommend pause unless user directs further. Rule #25 single-commit precedent held (one file → one commit; not the omnibus N-commit shape used for the larger refactors in sessions 0801ca27/b56eb487).

**Partial P3 progress — session f2f9060c continuation (2026-04-24, commits `b213795`, `ff111d2`):** mobsfscan/ subpackage pair cleared. Pre-edit broad `^\s+from app\.` measurement was 7 hits (matching intake estimate); Rule #31 width-canary discipline saved the scope — narrow pattern (`^\s+from app\.(services|ai|models|schemas)\.`) would have returned 4 and silently missed 3 `app.utils.*` hits. Of the 7 broad hits, 3 were `TYPE_CHECKING`-guarded (legitimate, preserved); 4 were genuine runtime function-body imports. `mobsfscan/normalization.py` (2 → 0 runtime; `app.models.finding.Finding` + `app.utils.firmware_context.{enrich_description, enrich_evidence}` promoted); `mobsfscan/pipeline.py` (2 → 0 runtime; duplicate `app.services.jadx_service.get_jadx_cache` in sibling `@staticmethod` helpers de-duped to a single top-level import). Rule #30 audit classified every target as pure-leaf: `models/finding` imports only `app.database` (no reverse mobsfscan dep); `utils/firmware_context` has ZERO `app.*` imports (pure stdlib+typing leaf); `jadx_service` has 3 top-level `app.*` imports (config, `_cache`, `utils.hashing`) — none transitively reach mobsfscan. Cycle-safe by construction; 0 test patches target the promoted first-party symbols. Rule #11 import-smoke green on backend+worker (after `docker cp` per Rule #20, no class-shape change so no restart needed). Per-file commit per Rule #25 (2 commits, each with its own diff — 3 inserts / 3 deletes in normalization; 1 insert / 4 deletes in pipeline). Post-session residual across `backend/app/services/` (runtime-only, TYPE_CHECKING-excluded): 19 files carry 40 total runtime function-local `app.*` imports. Next-pair candidates by density (unchanged from prior ranking, minus the two cleared this session): `firmware_service.py`(14 — intake flags as non-mechanical, DO NOT bulk-promote without per-call audit), `security_audit/hash_lookups.py`(5), `wairz_runner.py`(3), `hardware_firmware/cve_matcher.py`(2), `clamav_service.py`(2), `attack_surface_service.py`(2); the remaining 13 files carry 1 each. `firmware_service.py` is explicitly out-of-scope for mechanical promotion per seed-next-session-2026-04-24 guidance — its 14 lazy imports span cross-layer call patterns that need individual Rule #30 legitimate-lazy audits (latent-cycle risk much higher than leaf services).

---

## Original specification (preserved for reference)

---

## Problem

### P1. `assessment_service` calls private `_scan_*` helpers from `security_audit_service`

`backend/app/services/assessment_service.py:197-202, 290` imports:
- `_scan_credentials`
- `_scan_crypto_material`
- `_scan_shadow`

All prefixed with `_` signaling "private, do not use outside module." This is a leaky abstraction:
- If `security_audit_service` renames or changes these signatures, `assessment_service` silently breaks at runtime
- IDE / static analysis tools flag this pattern
- Future refactoring tools (e.g., rename-symbol) may miss the cross-module callers

### P2. Circular lazy import between `emulation_service` and `kernel_service`

Two modules lazy-import each other at function level to dodge module-level cycles:

**`backend/app/services/emulation_service.py:26-34`**:
```python
from app.services.emulation_constants import _validate_kernel_file  # top-level
# ...
# emulation_service.py:696
from app.services.kernel_service import KernelService  # function-local
# emulation_service.py:1187
from app.services.kernel_service import KernelService  # function-local again
```

**`backend/app/services/kernel_service.py:322-323`**:
```python
def some_method(self):
    # avoid circular dependency at module level
    from app.services.emulation_service import _validate_kernel_file
```

But `_validate_kernel_file` actually lives in `emulation_constants.py` (where `emulation_service` imports it from). `kernel_service` should bypass `emulation_service` and import from the constants module directly — breaking the cycle cleanly.

### P3. Systemic function-local imports hide cycles

10+ services use function-local imports to dodge cycles:
- `assessment_service.py`: 9 function-local imports (lines 60, 197, 239, 240, 290, 335, 530, 584, 645)
- `security_audit_service.py`: 5 (lines 901, 991, 1029, 1082, 1147)
- `emulation_service.py`: 6 (lines 250, 696, 956, 1187, 1251, 1367)
- `fuzzing_service.py`: 4 (lines 96, 404, 482, 778)

This pattern hides cycles from static analysis. The true problem: services at the top of the dependency graph (`assessment_service`, `security_audit_service`) depend on many peers. There's no orchestration layer distinct from domain services.

## Approach

### Phase 1 — Fix P2 (circular import — 10 minutes)

In `backend/app/services/kernel_service.py:322-323`:

```python
# Before
def some_method(self):
    from app.services.emulation_service import _validate_kernel_file  # avoid cycle
    _validate_kernel_file(...)

# After (top-level import)
from app.services.emulation_constants import _validate_kernel_file
# ...
class KernelService:
    def some_method(self):
        _validate_kernel_file(...)  # top-level now, no function-local import
```

This eliminates the lazy-import that existed only because `kernel_service` imported from `emulation_service` unnecessarily.

### Phase 2 — Fix P1 (promote private APIs)

Rename the three helpers in `security_audit_service.py` (dropping leading underscore):
- `_scan_credentials` → `scan_credentials`
- `_scan_crypto_material` → `scan_crypto_material`
- `_scan_shadow` → `scan_shadow`

Keep the old names as deprecated aliases temporarily:
```python
# Deprecated alias for backward compatibility. Remove after 2 releases.
_scan_credentials = scan_credentials
```

Update `assessment_service.py` to use the new names. Document in the docstring of each that these are public and consumable by other services.

**Better alternative (preferred):** Add a `run_scan_subset(scanners=["credentials", "crypto_material", "shadow"])` method to `security_audit_service` that internally dispatches. Then `assessment_service` calls the public method with a list.

```python
# backend/app/services/security_audit_service.py
SCANNERS = {
    "credentials": scan_credentials,
    "crypto_material": scan_crypto_material,
    "shadow": scan_shadow,
    "filesystem_permissions": scan_filesystem_permissions,
    # ...
}

async def run_scan_subset(scanner_names: list[str], firmware_id: UUID, ...) -> list[Finding]:
    findings = []
    for name in scanner_names:
        scanner = SCANNERS.get(name)
        if not scanner:
            raise ValueError(f"Unknown scanner: {name}")
        findings.extend(await run_in_executor(None, scanner, ...))
    return findings
```

### Phase 3 — Audit remaining function-local imports

Produce a dependency graph of inter-service imports:

```bash
# One-shot script to emit DOT graph
cd backend/app/services
grep -r "from app.services\." --include="*.py" -h | \
    sed -E 's/.*from app\.services\.([^ ]+) import.*/\1/' | \
    sort | uniq -c
```

Identify cycle pairs. For each cycle, choose one side to move to a shared `_base.py` or `constants.py` module. Track the list of function-local imports — every time one is removed, the static analysis improves.

**Long-term target:** No function-local imports in `backend/app/services/*.py`. All dependencies declared at module level; cycles broken via shared constants or extracted interfaces.

## Files

### Phase 1
- `backend/app/services/kernel_service.py:322-323` (move import to top)

### Phase 2
- `backend/app/services/security_audit_service.py` (rename 3 helpers + add alias)
- `backend/app/services/assessment_service.py` (update 3 import sites — lines 197-202, 290)
- **OR** add `run_scan_subset` to `security_audit_service` and update `assessment_service` to call it

### Phase 3 (follow-up PR)
- Dependency-graph script + list of function-local imports
- Per-cycle: identify shared extract point, do the extract
- Convert function-local imports to top-level one service at a time

## Acceptance Criteria

- [ ] Phase 1: `grep -n 'from app.services.emulation_service import _validate_kernel_file' backend/app/services/kernel_service.py` returns nothing
- [ ] Phase 1: `kernel_service.py` and `emulation_service.py` both top-level import from `emulation_constants`, neither imports the other
- [ ] Phase 2: `grep -rn '_scan_credentials\b\|_scan_crypto_material\b\|_scan_shadow\b' backend/app/services/assessment_service.py` returns zero hits — all callers use public names
- [ ] Phase 2 (if using run_scan_subset): `assessment_service` has no direct function references to `security_audit_service` internals
- [ ] All existing tests pass

## Risks

- MCP tools may call the `_scan_*` names directly — grep `backend/app/ai/tools` and update if so
- Frontend has no exposure to Python naming, no risk there
- Phase 3 is open-ended and can grow — cap the scope to specific service pairs per PR, not "all of them"

## References

- Backend review C3, H4, H5
