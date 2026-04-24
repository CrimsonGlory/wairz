# Anti-patterns: P3 carve-out — fuzzing_service + emulation/ pair

> Extracted: 2026-04-24
> Session: f2f9060c
> Commits: 7d349c3, d1a8701, 77a5908, cac98ad

## Failed Patterns

### 1. Narrow regex pattern silently under-reported residual work

- **What was done:** The seed's candidate-ranking grep used `^[[:space:]]+from app\.(services|ai|models|schemas)\.` to count residual function-local imports per file. This narrow enumeration MISSED `app.database.*`, `app.utils.*`, and any other `app.*` subpackage not explicitly listed.
- **Failure mode:** `firmware_service.py` was reported at 2 residuals under the narrow pattern; the actual count under `^\s+from app\.` is 14 (7× under-count). If this session had picked `firmware_service` based on the narrow count's ranking, scope would have blown up mid-session (Rule #28 drift risk: the intake says "2", the file contains "14", the session runs out of budget half-done — Rule #11 penalty territory).
- **Evidence:** Post-session audit added `cac98ad` intake update with widened counts. Comparison:

| File | Narrow count | Widened count |
|---|---|---|
| fuzzing_service.py | 4 | 4 |
| emulation/service.py | 2 | 3 |
| emulation/user_mode.py | 2 | 2 |
| firmware_service.py | 2 | 14 |
| security_audit/hash_lookups.py | — | 5 |
| mobsfscan/normalization.py | — | 4 |

Files that appeared clean under the narrow pattern had substantial residuals under the widened one.
- **How to avoid:** For residual-import audits, always use `^[[:space:]]+from app\.` (broader) OR enumerate every known `app.*` subpackage. The narrow pattern is appropriate for targeted surveys (e.g., "which files still import from `app.services.*` specifically?") but NOT for exhaustive residual counts. When a scope-bearing claim ("N files left", "only M imports remain") is derived from a grep, publish the exact pattern used so future readers can re-run it.

### 2. Seed's best-candidates table persisted past its usefulness

- **What was done:** `seed-next-session-2026-04-24.md` included a "best candidates by cycle density × fix clarity" table that listed `assessment_service ↔ security_audit_service` as the top pair with 14 imports. But the seed was written 2026-04-23 evening; assessment_service was fully promoted 2026-04-24 morning (commit `fc384bb` in the same day); the seed was never refreshed.
- **Failure mode:** If the user had picked the seed's top-ranked pair without re-verification, half the scope would have been a no-op (assessment_service at 0 imports) and the other half (security_audit_service — now decomposed into a `security_audit/` subpackage) would have needed a different approach than the table described. Wasted ~2 min before I caught it.
- **Evidence:** Seed file, "Option A" section, best-candidates table. This session's re-measurement caught the drift before committing.
- **How to avoid:** When a multi-option recommendation doc lists specific facts (counts, file names, service pairs) and a follow-up session DOES execute one of those options, the executing session MUST re-verify the scope-bearing facts. Rule #28 extended to cross-session intake/seed claims. Don't trust a day-old "best candidates" table; re-run the grep.

### 3. (Near miss — not triggered this session but worth flagging)

- **What was done:** Did NOT do this — but the temptation was present.
- **Pattern:** Promoting a function-local import because "it looks like the last one worked mechanically" without doing the Rule #30 legitimate-lazy audit on the target.
- **Failure mode:** Rule #30's companion guidance: "DO NOT promote the lazy import 'to simplify testing' before reading WHY it's lazy." Legitimate lazy reasons include optional/slow dependency, GPL/LGPL partition, and genuine circular-import avoidance. If any of those apply, the promotion introduces a new bug (startup slowdown, license leak, import cycle at module import time).
- **Evidence:** Session 5eefecb0's `assessment_service` promotion was mechanically safe because the targets were all pure leaves. This session's targets were also pure leaves. But `firmware_service.py` (the next candidate) may NOT have the same profile — it sits close to workers (unpack, `wairz_runner`), which may carry optional-dep lazy imports for file formats (unblob, binwalk, etc.).
- **How to avoid:** Every target of a promotion needs a fresh per-target audit: `grep -nE '^(from|import).*app\.' <target>` + legitimacy-reason classification per Rule #30. No bulk promotions based on "the last session was clean." Each target is its own evidence case.

## Quality Rule Candidates

No high- or medium-confidence candidates emerge from this slice. The narrow-regex anti-pattern is real but not regex-catchable (a grep command is not code). The function-local-import anti-pattern (promote-without-audit) is already covered by Rule #30 in `CLAUDE.md` and the `auto-pytest-mock-patch-androguard-at-service` narrow rule in `harness.json`. Adding a broad "flag every `^\s+from app\.`" rule would fire on legitimate lazy imports and cause noise. Skip.
