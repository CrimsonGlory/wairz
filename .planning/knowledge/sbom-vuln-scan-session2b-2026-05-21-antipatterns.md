# Anti-patterns: SBOM/vuln-scan regression Session 2b (2026-05-21)

> Extracted: 2026-05-21 evening
> Postmortem: `.planning/postmortems/postmortem-sbom-vuln-scan-session2b-2026-05-21.md`

## Failed Patterns

### 1. Pre-existing tests asserted on inline-docstring shapes the refactor consolidated
- **What was done:** Session 1 + 2a shipped 5 reaper-presence tests asserting on `"Reap orphan X firmware rows"` docstring text in main.py. Fix #11's refactor replaced the inline blocks with a single data-driven sweep — the docstrings legitimately don't exist anymore.
- **Failure mode:** All 5 string-match tests failed at the Step 6 pytest sweep with `assert "Reap orphan X firmware rows" in src` AssertionError.
- **Evidence:** Postmortem "What Broke" #1. Commit `95e47a6` updated the 5 tests in the SAME commit as the refactor per Rule #25 single-slice exception #2.
- **How to avoid:** When refactoring inline blocks to a registry shape, the OLD presence-tests are PART of the refactor surface. Update them in the SAME atomic commit. Splitting leaves the old tests RED between commits — bisect-non-clean. **Mechanical detection:** before refactoring N inline blocks, `grep -rn "Reap orphan\|<other inline-docstring text>" backend/tests/` to find the dependents. Update them in the refactor's diff staging.

### 2. (Only 1 failed-pattern entry — Session 2b's design was locked by Session 2a's research; execution was straightforward.)
