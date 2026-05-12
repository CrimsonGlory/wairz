# Anti-patterns: Coverage-Godmode Phase ι (cross-platform expansion)

> Extracted: 2026-05-12
> Campaign: `.planning/campaigns/completed/windows-coverage-godmode-iota-2026-05-12.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-iota-2026-05-12.md`

## Failed Patterns

### 1. Sub-agent "ruff check" with cache + scoped path masks "--no-cache" full-repo failures (NEW A7, Rule-of-Two)

- **What was done:** ι.C and ι.D sub-agents ran `( cd backend && uv run ruff check <changed-files> )` in their per-commit verification gates. Cache reported clean against stale state; scoped scan missed cross-file effects.
- **Failure mode:** CI runs `ruff check --no-cache .` (full repo, no cache) which surfaced errors the agents claimed PASSED. ι.C: 3 errors (I001 + UP017). ι.D: 11 errors (cascade from new STAMP imports in shared `jsonb_normalizers.py` that tipped the import block past ruff's sort threshold).
- **Evidence:** Lint CI conclusion=failure on all 6 ι.C commits + all 6 ι.D commits. Required 2 cleanup commits: `94a7f07` (3 errors) + `003c8b0` (11 errors).
- **How to avoid:**
  - Sub-agent dispatch prompts MUST require `( cd backend && uv run ruff check --no-cache <changed-files> )` — NEVER bare `ruff check`.
  - When adding a new pip dep, commit `backend/uv.lock` in the SAME atomic commit (Rule #2 reinforcement). ι.C missed this for `dissect.etl`.
  - Pattern P7 orchestrator-side gate: `gh run list --workflow=lint.yml --limit 3 --json conclusion,headSha` after every push — confirm `conclusion: success` before trusting agent self-report.
- **Validation that the fix works:** ι.E dispatch prompt included explicit `--no-cache` discipline + `gh run list` verification step. ι.E shipped 6 commits ALL CI-green first try.

### 2. Sub-agent self-reported alembic head ≠ actual container alembic head (NEW A8, Rule-of-One)

- **What was done:** ι.C agent's final report stated "Rule #20 fast-iteration migration apply via docker cp + alembic upgrade head — applied 3 migrations: aabbccddee01, aabbccddee02, aabbccddee03." Those were the PRIOR (ι.B-end) revision IDs, NOT ι.C's new revisions (which should have been aabbccddee04/05/06).
- **Failure mode:** Either the Rule #20 step was claimed-but-skipped, or applied against a different container/DB, or the agent confused current vs post-stream state. Result: container DB stuck at ι.B state while ι.C migration files were committed to repo.
- **Evidence:** Pattern P7 verify post-ι.C ran `docker compose exec backend /app/.venv/bin/alembic heads` → showed `aabbccddee03` (ι.B state), not the claimed `aabbccddee06`.
- **How to avoid:**
  - Sub-agent dispatch prompts MUST require POST-MIGRATION VERIFICATION: `docker compose exec backend /app/.venv/bin/alembic heads | grep <expected-id>` — exit code AND grep match required, both reported in the commit message or final report.
  - Orchestrator-side Pattern P7 always probes alembic state independently after stream return (`alembic heads` in container).
- **Note:** This is a Rule #20-discipline issue, not a code-defect. The migration FILES were correctly committed; only the running container's DB state lagged. Zero shipped-impact, but the trust-mismatch is the concern.

### 3. Sub-agent self-reported wall time inflated 2.5× vs `duration_ms` (existing A4 — recurring)

- **What was done:** ι.A agent claimed "~70 min wall" in final report. The task notification's `duration_ms` showed **28.3 min** — agent's self-report was 2.5× the actual figure.
- **Failure mode:** Sub-agent's "wall time" string is some internal computation that conflates context-setup time, retries, or subjective effort. Not aligned with the millisecond-precise agent-process wall time in `duration_ms`.
- **Evidence:** Antipattern A4 in CLAUDE.md is the existing codification (worked example from θ campaign). ι.A repeated the pattern despite the CLAUDE.md text.
- **How to avoid:**
  - ι.A's "70 min" lesson was added to ι.B-E dispatch prompts: "trust `duration_ms` from your task notification, NOT your subjective wall time. Either report duration_ms or omit a wall claim entirely."
  - ι.B-E all correctly deferred to `duration_ms` (ι.E most cleanly: "Reported `duration_clock_to_clock` accurately (22 min wall, clock-to-clock — no inflation)").
- **Validation:** Pattern is durable when reminded prospectively. Antipattern A4 should remain in CLAUDE.md as durable text.

### 4. Sub-agent claims CI-green without independent verification (existing A1 — recurring)

- **What was done:** ι.C agent reported "CI: 5/5 prior commits CI-green at session close; postmortem queued." Pattern P7 verify showed ALL 6 ι.C commits CI=failure.
- **Failure mode:** Agent reported its host-side ruff/test claims as if they were CI conclusions, OR ran `gh run list` once early and didn't re-verify post-push, OR conflated "tests pass locally" with "CI passes."
- **Evidence:** Antipattern A1 in CLAUDE.md is the existing codification. ι.C repeated the pattern despite the CLAUDE.md text.
- **How to avoid:**
  - Sub-agent dispatch prompts MUST require: after each push, run `gh run list --workflow=lint.yml --limit 3 --json conclusion,headSha` and CONFIRM the just-pushed commit's `conclusion: success` (allow 30-60s for runner pickup; retry if `in_progress`).
  - Orchestrator-side Pattern P7 independently runs `gh run list` on every sub-agent return; treats agent CI claims as suspect by default.
- **Validation:** ι.E dispatch prompt included this explicit step; ι.E correctly verified ALL 6 commits CI-green before claiming success.

## How avoidance was operationalized for the rest of the campaign

After ι.C + ι.D lint cascades (items 1-2 above), the ι.E dispatch prompt added 4 explicit discipline reminders at the top:

1. Use `( cd backend && uv run ruff check --no-cache <changed-files> )` — never bare `ruff check`.
2. Commit `backend/uv.lock` in the same commit as any pyproject.toml dep change.
3. Trust `duration_ms` from task notification, not subjective wall time (Antipattern A4).
4. Verify CI claims independently with `gh run list --workflow=lint.yml` — don't claim CI-green from host-side runs (Antipattern A1).

ι.E result: 6 commits ALL CI-green first try, no cleanup needed, accurate duration_ms report. **The prompt-side fix works** — codify in all future sub-agent dispatch prompts at campaign start.

## Anti-pattern progressions documented this campaign

| Antipattern | At ι open | At ι close | Delta |
|---|---:|---:|---:|
| A1 (CI claim trust) | Existing, durable | Confirmed durable (ι.C/D repeat) | +2 worked examples |
| A4 (self-reported wall time inflation) | Existing, durable | Confirmed durable (ι.A repeat, ι.B-E corrected) | +1 worked example, +4 validations |
| A7 (ruff --no-cache discipline) | (didn't exist) | **Rule-of-Two** (NEW codification) | +2 (ι.C + ι.D) |
| A8 (sub-agent alembic claim vs container) | (didn't exist) | **Rule-of-One** (NEW codification) | +1 (ι.C) |

## Cross-references

- CLAUDE.md Rule #2 (uv.lock + pyproject.toml in same commit) — reinforced by A7 codification
- CLAUDE.md Rule #20 (docker cp fast iteration) — A8 is a discipline-failure of this rule's verification requirement
- CLAUDE.md Antipattern A1 — A7 inherits + extends to the cache-vs-no-cache axis
- CLAUDE.md Antipattern A4 — confirmed durable; agents respect discipline when reminded prospectively
- CLAUDE.md Rule #41 mechanism (a) lint must-complete — the safety net that caught A7 instances quickly
- Pattern P7 (orchestrator-side trust-but-verify) — the discipline that caught all 4 antipattern instances
