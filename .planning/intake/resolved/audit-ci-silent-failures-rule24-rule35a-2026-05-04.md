---
title: "CI silent failures — Rule #24 typecheck unenforced + Rule #35a parse-output silent-zero"
status: pending
priority: high
target: .github/workflows/lint.yml + .github/workflows/firmware-scan.yml (+ any composite actions)
---

## Description

Two independent CI defects that mask production-breaking output:

**(a) Rule #24 typecheck not enforced in CI** (Stream H F-H-18)
- Frontend CI build never explicitly invokes `npx tsc -b --force`.
- `lint.yml` has no typecheck step.
- Type errors propagate to runtime in production. The local Rule #24 mandatory-canary discipline is a per-developer guardrail; CI should be the deterministic gate.

**(b) Rule #35a-analog silent-zero on parse failures** (Stream H F-H-06)
- CI firmware-scan composite action parses scan output via `python3 -c "..." 2>/dev/null || echo 0`.
- A broken scan (Python parse error, missing file, malformed JSON) reports "0 critical findings" instead of failing the run.
- This is the same generalised lesson as Rule #35a (pipe-induced exit obfuscation) — verification artefacts can lie, and `2>/dev/null || echo 0` deliberately discards the lie.

**Evidence:** Stream H (F-H-06, F-H-18).

## Acceptance Criteria

**For (a):**
- [ ] Add typecheck step to `lint.yml` (or a dedicated `typecheck.yml` if separated): `cd frontend && npx tsc -b --force`. Job fails if exit ≠ 0.
- [ ] Add the Rule #24 canary as a CI gate: write `frontend/src/__canary.ts` with `const x: number = "nope";`, run `npx tsc -b --force`, assert it FAILS, then delete. This proves the typecheck command is actually checking.
- [ ] Update `.claude/harness.json` typecheck command if drift detected (Rule #24 already mandates `tsc -b --force`; verify the harness uses it).

**For (b):**
- [ ] Replace `python3 -c "..." 2>/dev/null || echo 0` patterns with: `python3 -c "..."`. If the script genuinely needs to default to 0 on failure, do so explicitly with `try/except` IN the python and exit non-zero on parse failure, then catch in shell.
- [ ] Add `set -euo pipefail` at the top of every CI shell script (audit composite actions).
- [ ] Audit all `.github/workflows/**/*.yml` for `2>/dev/null`, `||`, `| tail`, `| tee` patterns and document each as either justified (with inline comment) or rewritten to fail-loud.

## Out of Scope

- Migrating to CI rules engine (CodeQL, Renovate config) — separate scope.

## Cross-step

Per Rule #25, split into 2 commits: typecheck CI gate / parse-output fix.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-h-infra-2026-05-04.md` findings F-H-06, F-H-18.
