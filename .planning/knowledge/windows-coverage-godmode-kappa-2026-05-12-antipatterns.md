---
campaign_id: windows-coverage-godmode-kappa-2026-05-12
extraction_type: antipatterns (failure modes + recurrence audit)
opened: 2026-05-12
---

# Phase κ — antipatterns + failure mode audit

## Recurrence audit — existing antipatterns

| Antipattern | Source | κ recurrence count | Status post-κ |
|---|---|---|---|
| A1 (CI claim mismatch — trust gh, not brief) | ι.C/D incidents | **0** | Mitigation durable — Pattern P7 catches every claim before it propagates |
| A4 (sub-agent self-reported wall vs orchestrator wall) | various | 1 minor (κ.B postmortem) | Mitigation durable — orchestrator wall trusted; sub-agent wall caveated |
| A7 (ruff without --no-cache + scoped path) | ι.C/D recurrence | **0** | Mitigation durable — all 5 κ sub-agent prompts included A7 discipline |
| A8 (missing post-migration alembic verification) | ι.C-D | **0** | Mitigation durable — all 5 κ sub-agent prompts included A8 discipline |
| Rule #23 cross-stream sweeps (worktree-isolation) | wave-1/2 incidents | **0** | Mitigation durable — all 5 streams used worktree |
| Rule #25 bundled commits (anti-pattern) | various | **0** | Mitigation durable — all 21 stream commits per-piece per Rule #25 |

**Net: ZERO antipattern recurrences in κ.** Discipline matured to durable shape.

## NEW antipatterns surfaced in κ

### A9 (NEW — Rule-of-Two): Walker test-fixture string-pattern mismatches

**Family:** sub-agents writing walker test-fixture data + matcher patterns
trip on string-escape and regex-boundary semantics that look obvious but
trigger one-line dev fixes.

**Two instances within κ:**
1. **κ.B (Windows-path raw-string escapes).** `_PATH_SUSPICIOUS_FRAGMENTS = (r"\\Users\\Public\\", ...)`
   failed parse because Python raw-string literals CAN'T end in a trailing
   backslash (`r"...\"` is a syntax error: "EOL while scanning string
   literal"). Fixed by `("\\Users\\Public\\", ...)` with explicit escaped
   backslashes (single-backslash boundaries). **Also κ.B.D migration docstring**
   `\Users` triggered "invalid escape sequence" in non-raw string; fixed with
   `r"""..."""` prefix.
2. **κ.C (cron `\b` word-boundary at `/`).** Cron temp-path matcher regex
   used `\b/tmp/` — `\b` is anchored at `\w` ↔ `\W` transitions which has
   subtle semantics around `/` and shell-special chars. Fixed by replacing
   `\b` with explicit boundary character group `(^|\\s|;|\\||&)`.

**Mitigation (codified for sub-agent prompts from κ.D onwards):**
- For Windows-path constants: prefer EXPLICIT `"\\path\\"` (escaped) over `r"\path\"` (raw with trailing backslash — syntax error)
- For shell-command / filesystem-path matchers: prefer EXPLICIT shell-boundary groups (`(^|\s|;|\||&)`) over implicit word-boundary `\b`

**Status:** Rule-of-Two; watching λ + κ.X for Rule-of-Three. κ.D + κ.E did NOT
hit this family (DPAPI was UTF-16LE GUID patterns; UsnJrnl was bitmask
constants — different families). Rule-of-Three not yet earned.

### A10 (NEW — Rule-of-One — gate-canary partner): Tokenize-based forbidden-token scanner whitespace-join gap

**Surface:** Rule #36 EXTENSION test gates that tokenize the walker source and
search for forbidden tokens via regex MUST be whitespace-tolerant because
`tokenize` joins tokens with single spaces. A naive regex `\.decrypt\(` fails
against the synthetic `obj . decrypt (` produced by `tokenize` + space-join.

**Mitigation (codified as Rule #45 + Rule #46 partner):**
- All forbidden-token regexes use `\s*` between syntactic elements: `\.\s*decrypt\s*\(`, not `\.decrypt\(`
- Synthetic-violation canary test in the same file confirms gate would catch a real violation
- Synthetic must be CONSTRUCTED CODE (concatenated lines), NOT an f-string (f-strings become string literals that tokenize strips out)

**Status:** caught in κ.D. ι.D EFS gate had same weakness; backfilled this
campaign. CODIFIED as Rule #46 (canary discipline).

### A11 (NEW — Rule-of-One): Pipe-induced silent-exit in canary instrumentation

**Surface:** Rule #24 mandatory tsc canary invoked with pipe (`tsc 2>&1 | tail
-10`) — the pipe hid the real tsc exit code (Rule #35a). The canary's failure
mode caught itself.

**Mitigation (already established as Rule #35a — reinforced by κ.E):**
- For canary invocations, NEVER use pipes when exit code matters
- Pattern: `cmd; ec=$?` (capture exit BEFORE pipe), OR `set -o pipefail` explicitly, OR `${PIPESTATUS[0]}`

**Status:** Single instance in κ.E. Caught immediately by the canary discipline.
Rule #35a + Rule #46 are durable partners.

## Walker-test-gate weakness backfill action items

1. **ι.D EFS `test_walker_no_decrypt` regex** — apply κ.D's whitespace-tolerant
   pattern (`\.\s*decrypt\s*\(`). 1-line fix. Ship in κ.X or λ. STATUS: SHIPPED THIS CAMPAIGN.

## Antipatterns NOT observed in κ

- No Rule #20 class-shape rebuild issues (no class-shape changes that would
  require restart after `docker cp`)
- No Rule #26 frontend-rebuild-not-restart violations (frontend rebuild
  triggered mid-session by orchestrator)
- No Rule #2 missing-dependency commits (no new deps; all reuse)
- No Rule #6 CLI flag version regressions (no CLI tool version upgrades)
- No Rule #9 frontend `Record<Type, ...>` blank-page regressions (all
  cross-stack alignment shipped in Rule #25 single-slice commits)

## Health signal

ZERO sub-agent dispatches failed in κ. ZERO commits to main had broken state.
ZERO Pattern P7 verifications found discrepancies. ZERO cross-stream sweeps.
**Pattern P1 + P5 + P7 + Rule #23 discipline cluster is now structurally
mature for adjacency-batch campaigns.**
