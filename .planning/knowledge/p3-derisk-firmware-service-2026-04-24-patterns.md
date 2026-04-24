# Patterns: P3 session 3d9d854e — 2 carve-outs + firmware_service de-risk

> Extracted: 2026-04-24
> Session: 3d9d854e (autopilot-triggered)
> Commits: 872cc06, 404f66d, d02af17, 781a30e, e8bd8bd, 8e99ec4, 3013124
> Source intake: .planning/intake/backend-private-api-and-circular-imports.md (partial)
> Driver: .planning/intake/seed-next-session-2026-04-24.md (closed with +C / +A / +A' / +A'-cont all completed across 3 earlier sessions; this session added 2 more carve-outs + a de-risk)
> Predecessors: p3-carveout-mobsfscan-2026-04-24-patterns.md · p3-carveout-fuzzing-emulation-2026-04-24-patterns.md · assessment-promote-rule30-2026-04-24-patterns.md
> Postmortem: none (continuation session, not a discrete campaign)
> Next-session seed: seed-next-session-2026-04-25.md (firmware_service execution, baselined to 8e99ec4)

## Context

4th session in the P3 chain. Two executions + one novel step-change:

- **4th P3 carve-out** — `security_audit/hash_lookups.py` (5 → 0 runtime imports; Rule #30 audit all-pure-leaf; Rule #31 width-canary applied pre-edit per mobsfscan precedent).
- **5th P3 carve-out** — `wairz_runner.py` (2 → 0 REAL function-body imports via ast.walk; grep-apparent 3 → 1 due to docstring false-positive).
- **Firmware_service.py (14 imports) de-risk** — instead of executing OR deferring as the seed instructed, produced a full per-call Rule #30 audit committed to the intake (commit `8e99ec4`). Converted "out-of-scope per seed" into "mechanically safe, ready for next session" with evidence the seed's original author didn't have.

Mechanical-safe profile now validated across **7 files in 4 sessions** (assessment + fuzzing + emulation/service + emulation/user_mode + mobsfscan/{normalization,pipeline} + hash_lookups + wairz_runner); de-risk unlocks firmware_service for session #5.

## Successful Patterns

### 1. De-risk-via-per-call-audit as a legitimate session shape

- **Description:** When the seed explicitly flags a target as "out-of-scope per cross-layer latent-cycle risk, needs individual Rule #30 legitimate-lazy audit," the session's deliverable can be the AUDIT itself — not execution, not deferral. Produce the evidence, classify each call site, identify residual risk, commit to the intake ledger. The next session then executes mechanically from the committed analysis with the audit as its safety harness.
- **Evidence:** Commit `8e99ec4` adds a 28-line "De-risk analysis" section to `backend-private-api-and-circular-imports.md` covering: authoritative ast-based catalog (14 imports across 5 source modules); per-module Rule #30 audit table (all 5 SAFE); global cycle-node audit (only HTTP routers import firmware_service at top level — terminal graph nodes); Rule #30 legitimate-lazy criteria table (all 4 NEGATIVE with evidence); test-patch activation risk measurement (0 patches target the 11 worker symbols); recommended execution shape (single commit, ~15 ins / 14 del, matches hash_lookups + wairz_runner precedent); orthogonal-concern note (services→workers layer inversion is architectural, not a cycle). Next-session seed `seed-next-session-2026-04-25.md` (commit `3013124`) contains the step-by-step execution plan pinned to baseline `8e99ec4`.
- **Applies when:** Any intake target where seed/predecessor warns "needs individual audit before execution." The audit IS the deliverable. Blocks on two things: (a) the user chooses execution-vs-audit at the start, (b) the audit's conclusions must be CITED (commit SHA + line numbers + count methodology), not asserted. Cost: ~20 minutes research; produces a commit that future sessions reference rather than re-deriving.

### 2. ast.walk authoritative over grep for import counts (Rule #31 companion)

- **Description:** After 6 incidents of grep-based scope counts drifting vs. reality (documented in Rule #31 evidence matrix), this session found TWO MORE distinct grep error modes in a single session, with `ast.walk` correcting both:
  - **OVER-count (docstring false-positive):** wairz_runner.py L23 is a usage example INSIDE the module docstring: `    from app.services.mobsf_runner import compare_findings`. The regex `^\s+from app\.` matches the string literal; ast correctly treats it as a non-import (it's bytes inside a `"""..."""` node, not a real import). Grep apparent count: 3. ast real count: 2.
  - **UNDER-count (multi-line continuation):** firmware_service.py has 14 function-body `app.*` imports via ast.walk. Grep line-oriented `^\s+from app\.` returned 14 too — but earlier grep on a variant spelling (not reproduced here) once reported 15. A `from X import (\n  a,\n  b,\n)` continuation is ONE ast.ImportFrom but MULTIPLE grep matches depending on regex.
- **Evidence:** ast.walk in this session's work (hash_lookups post-edit verification + wairz_runner pre/post + firmware_service de-risk catalog). Grep and ast diverged in BOTH directions in a single session. Recommend: `ast.walk` is the authoritative counter for import-residual-audits; grep is a fast first-pass approximation with bidirectional error modes. Saturation cost of using ast: ~100ms for the whole `backend/app/services/` tree.
- **Applies when:** Any automation that publishes import-count claims. Rule #31 width-canary solves narrow-vs-broad regex selection; ast.walk solves precision-vs-recall orthogonally. Do NOT promote to a standalone Rule #32 yet — this is a single-session discovery and Rule #31's own discipline ("3rd incident justifies rule promotion") should be respected.

### 3. Layered lazy-import pattern recognition (Rule #30 nuance)

- **Description:** When module A function-locally imports `from app.services.B import Symbol`, and B ITSELF lazy-imports its heavy dependencies inside its method bodies, then A's lazy-import is "defensive-of-defensive" — the class symbol-definition in B is cheap; B's heavy deps don't load until B's methods run. Promoting A's import to top-level does NOT trigger B's heavy deps.
- **Evidence:** wairz_runner.py function-locally imported `from app.services.androguard_service import AndroguardService`. Grep `from androguard\|import androguard` on `androguard_service.py` shows 5 function-body imports of the androguard library (L508/523/640/861/891) — zero at module-top-level. androguard_service.py's own top-level imports are `logging`, `os`, `xml.etree.ElementTree`, `dataclasses`, `typing`, and `app.services.manifest_checks`. Importing `AndroguardService` class triggers only the class-definition parse + manifest_checks top-level. The ~500ms androguard cold-import runs only when an actual scan method executes (preserved by the class's own internal lazy pattern). Promotion is safe per Rule #30's "relic of pre-Phase-5 cycles" clause.
- **Applies when:** Auditing any target whose class/function is defined in a service module that has its own function-body imports of slow/heavy deps. The lazy-at-call-site layer PROTECTS the cold-import cost regardless of what outer callers do. This inverts the naive Rule #30 caution — the lazy import at the OUTER layer was redundant.

### 4. Layer-boundary cycle audit via reverse-dep enumeration

- **Description:** To prove zero cycle risk for a cross-layer promotion (services → workers), exhaustively enumerate callers that import the target module at top level, then verify each caller's layer. If only "terminal" layers (HTTP routers, CLI entry points) import the target at top-level, cycle risk is structurally zero — terminal layers are NOT imported back by deeper layers.
- **Evidence:** For `firmware_service`, the search `grep -rn 'from app.services.firmware_service\|import firmware_service'` returned 4 hits, all in `app/routers/`: `firmware.py:24`, `deps.py:10`, `uart.py:23`, `comparison.py:29`. Routers are called by `app/main.py`'s FastAPI registration — not imported back by services/workers/models. Additionally verified: all 5 source modules (safe_extract, unpack, unpack_linux, unpack_common, firmware_paths) have ZERO top-level `app.services.*` imports. Both sides of the potential cycle are structurally absent at module-init.
- **Applies when:** Any cross-layer promotion audit. 3 greps (forward deps of source modules, reverse deps of target, terminal-layer classification) establish module-init cycle safety with high confidence. This is cheaper than an `importlab`-style dep-graph tool for single-file audits; for whole-repo cycle detection, use a dedicated tool.

### 5. ROUTER.md companion sync per Rule #21 — same-session-correction of own mistake

- **Description:** Rule #21's companion mandate is that `.mex/ROUTER.md`'s "Current Project State" stays synced. This session demonstrated it twice: (a) initial sync (commit 872cc06) pulled 26→31 rule count + pruned resolved issues; (b) mid-session Rule #19 evidence check against code found B.1.c ("streaming upload-size") actually SHIPPED at `firmware.py:56-66` `_check_upload_size`, contradicting my own earlier ROUTER.md claim that it was "Not yet built." Correction committed in `d02af17` SAME SESSION with an explicit note "earlier in this session I listed B.1.c streaming upload-size check as 'Not yet built' — Rule #19 pre-write verification against firmware.py:56-66 shows _check_upload_size IS shipped."
- **Evidence:** `git show d02af17 -- .mex/ROUTER.md` shows the B.1.c line migrating from "Not yet built" to the "Recently shipped" block. Commit message cross-references the wrong claim and its correction. No future session is left with the false ROUTER.md data.
- **Applies when:** Any maintenance session that updates shared state (ROUTER.md, CLAUDE.md, .mex/context/*). Immediately after the write, run the opposite of Rule #17's canary: pick one claim you just wrote and verify it against the code. If the claim is falsified, CORRECT SAME SESSION (don't defer to "next session will notice"). Cost: ~30s of grep. Saves the downstream trap.

### 6. Seed-status-field hook-parser compatibility

- **Description:** Pre-session, `seed-next-session-2026-04-24.md` had `status: "+C-completed +A-completed ... +A-prime-completed ..."` — a quoted multi-token composite status. The SessionStart intake-detection hook flagged it as "pending" because the parser doesn't recognize multi-token statuses. Corrected in commit 872cc06 to `status: completed` + a new `completion_history:` YAML array capturing per-session completion records.
- **Evidence:** Pre-edit `git status` showed seed-next-session-2026-04-24.md as pending in hook output. Post-edit, the hook correctly reports "queue empty" for that file. The `completion_history` array preserves the full audit trail (4 session records: +C, +A, +A', +A'-cont).
- **Applies when:** Any seed or intake file closed with multi-session or multi-option completions. Use a simple top-level `status:` field the hook can parse; use a secondary field (`completion_history:`, `closed_by:`) for the detail. Don't cram structured data into `status`.

### 7. Per-file commit + intake-update commit discipline (Rule #25 durability at 4 sessions)

- **Description:** This session's refactor commits follow the same shape as sessions 2-4 in the P3 chain: one refactor commit per edited file, then a separate intake/ROUTER doc-update commit. 6 commits total this session: 3 refactors + 3 doc updates + 1 seed-creation.
- **Evidence:** `git log --oneline -7` shows the clean alternation: refactor(hash_lookups) → intake(hash_lookups) → refactor(wairz_runner) → intake(wairz_runner) → intake(firmware_service derisk) → seed(next-session). Each refactor is independently revertable without losing doc history; each doc update is revertable without losing code.
- **Applies when:** Any P3 continuation session. Pattern is now stable at 4 sessions; treat as mandatory.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| 4th session tackles 2 pairs (not 1) | Seed's "one pair per session" caveat was conditional on scope-surprise; hash_lookups was exactly 5 as predicted, leaving context budget for wairz_runner. User explicitly said "continue burning down." | Both shipped clean; no surprises, no sweeps. |
| Promote `asyncio` stdlib function-locals in hash_lookups | 3 `import asyncio` sites in sibling functions; stdlib is trivial; consolidation is cheap cleanup alongside the app.* work | One fewer layer of apparent function-local mess; no semantic change |
| Do NOT promote `asyncio` in wairz_runner | wairz_runner's async usage was already top-level | No-op; consistency wasn't violated |
| Initial ROUTER.md had incorrect B.1.c "Not yet built" — SAME-SESSION correction | Rule #19 pre-write verification caught it during research for the next carve-out; correcting immediately preserves trust | `d02af17` corrects the error with explicit cross-reference in commit message |
| De-risk firmware_service rather than execute | User explicitly scoped: "stop here; provide details to derisk." Audit IS the deliverable when seed flags "individual audit before execution." | `8e99ec4` commits the full per-call Rule #30 audit; next session executes mechanically from it |
| Do NOT promote Rule #31-companion (ast vs grep) to a standalone Rule #32 this session | Single-session evidence; Rule #31's own "3rd incident" discipline applies to new Rule candidates | Captured in intake-log text; promotion deferred until a 3rd occurrence |
| Write seed-next-session-2026-04-25.md with step-by-step execution plan | Firmware_service's de-risk is only valuable if the next session can execute from it without re-deriving; the seed's job is to linearize the execution | `3013124` commits a 189-line seed with ast pre-measure script, exact line catalog, exact top-level import block, Rule #11 smoke commands, commit message template |

## Verification shape used each slice (durable from prior P3 sessions)

```bash
# Per-file, after Edit tool sequence:

# Rule #31 width canary (narrow + broad MUST agree)
grep -cE '^[[:space:]]+from app\.(services|ai|models|schemas)\.' <file>
grep -cE '^[[:space:]]+from app\.' <file>

# ast.walk authoritative count — use when grep is suspicious or
# when the file has multi-line imports or docstring usage examples
python3 -c "
import ast
tree = ast.parse(open('<file>').read())
n = sum(1 for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
        for s in ast.walk(f) if s is not f and isinstance(s, ast.ImportFrom)
        and s.module and s.module.startswith('app.'))
print(n)
"

# Rule #11 import smoke via Rule #20 fast-path
docker cp <file> wairz-backend-1:/app/<file>
docker cp <file> wairz-worker-1:/app/<file>
docker compose exec -T -w /app -e PYTHONPATH=/app backend \
  /app/.venv/bin/python -c "from app.services.<mod> import <Sym>; print(<Sym>.__name__)"
docker compose exec -T -w /app -e PYTHONPATH=/app worker \
  /app/.venv/bin/python -c "from app.services.<mod> import <Sym>; print('ok')"

git add backend/app/services/<mod>.py
git commit -m "refactor(<mod>): promote function-local imports to top-level ..."
```

## De-risk audit shape (novel this session — reusable template)

```bash
# STEP 1: Authoritative catalog via ast.walk
python3 <<PY
import ast, pathlib
p = pathlib.Path("<target.py>")
tree = ast.parse(p.read_text())
imports = []
for node in ast.walk(tree):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for sub in ast.walk(node):
            if sub is node: continue
            if isinstance(sub, ast.ImportFrom) and sub.module and sub.module.startswith("app."):
                imports.append((sub.lineno, node.name, sub.module, [a.name for a in sub.names]))
# dedupe + print per source-module aggregation
PY

# STEP 2: Per-source-module Rule #30 audit
#  - grep top-level app.* imports in each source
#  - grep reverse-dep: does source import target at top level?
#  - classify: pure-leaf / transitively-leaf / cycle-node

# STEP 3: Global cycle-node audit
grep -rn 'from app.services.<target>\|import <target>' backend/app/ --include="*.py"
# Verify hits are in TERMINAL layers only (routers, CLI) — not services/workers/models

# STEP 4: Rule #30 legitimate-lazy criteria — score each NO/YES with evidence
# (a) slow/optional dep — test: module-init I/O or subprocess calls?
# (b) GPL/LGPL partition — test: third-party licensing?
# (c) latent-cycle — test: does target's runtime-deps chain back?

# STEP 5: Test-patch activation risk
for sym in <each promoted symbol>; do
  grep -rn "patch.*<target>\.$sym\|patch.*<target>\", ?\"$sym" backend/tests/
done
# Zero hits = zero silent-no-op activation risk per Rule #30

# STEP 6: Document the audit in the intake as a "De-risk analysis" section
# Include: catalog, per-module table, criteria table, execution shape, baseline SHA
```
