# Anti-patterns: HW-Firmware Reviewer Follow-up — F-FORENSIC-10 Alignment + FragAttacks Realignment + CVE-2023-20819 Version Gate — 2026-05-15 Evening

> Extracted: 2026-05-15 (evening)
> Campaign: ad-hoc Citadel-driven session shipping 3 carried-forward Reviewer findings
> Postmortem: `.planning/postmortems/postmortem-hw-firmware-reviewer-followup-2026-05-15-evening.md`

## Failed Patterns

### 1. Re-using pre-realignment CVSS values without recursive NVD-CVSS re-verification

- **What was done:** TARGET 2 (commit `54a0a32`) preserved the pre-realignment `severity: medium / cvss_score: 6.5` on both FragAttacks advisory entries. The implementer's WebFetch + Scout 2's WebFetch verified NVD CPE for the realignment SCOPE (zero Broadcom/Qualcomm vendors), but didn't re-fetch CVSS field values — assumed the CVSS values were still authoritative.
- **Failure mode:** Operator-triage drift on advisory severity. The medium 6.5 was likely an earlier pre-advisory-conversion field-deployment-impact estimate; NVD primary CVSS 3.1 is LOW (3.5/2.6/3.5). For an advisory aggregating multiple SPEC-level CVEs, the worst-case individual NVD primary is the standard convention.
- **Evidence:** Reviewer B 2026-05-15-PM forensic-domain review independently re-fetched NVD primary CVSS for all 3 CVEs (CVE-2020-24586/87/88) and caught the drift. Triple-verification (scout → implementer → reviewer) caught what single-axis verification missed.
- **How to avoid:** Per Rule #19 recursive NVD-CPE verification (extended to CVSS field values per Pattern #2 of `postmortem-hw-firmware-mcp-tegra-2026-05-15`): when converting a curated CVE pin to advisory-only with aggregate severity, re-fetch NVD primary CVSS for EACH CVE in the advisory. The advisory's cvss_score is the worst-case individual; severity reflects the worst-case category. Cost: ~30 sec × N CVEs per advisory. Value: prevents operator-triage drift.

### 2. Force_rescan=True semantics conflated with DELETE behavior

- **What was done:** Initial verification plan called for `force_rescan=True` to re-emit rows. Investigating the matcher code revealed `force_rescan=True` removes the dedup check at `cve_matcher.py:989,1042` but doesn't DELETE existing rows — would hit UNIQUE constraint violations on re-insert.
- **Failure mode:** Confusion about the matcher's idempotency semantics. The postmortem's "force_rescan=True: 30 NEW CVE rows inserted" phrasing implies force_rescan = DELETE+re-insert, but the code shows force_rescan = skip-dedup-check-only. The new rows in the morning session were inserted because they didn't yet exist (post-clean-re-detect), not because force_rescan DELETEd anything.
- **Evidence:** Direct code-reading of `match_firmware_cves` at line 866-905 confirmed no DELETE in the matcher itself.
- **How to avoid:** For YAML-edit-driven row changes, use surgical DELETE before cve-match (Pattern #5 above). Document the recipe pattern for future YAML-edit verification workflows. Companion to Pattern #9 from morning's postmortem (detection re-runs) — Pattern #5 covers MATCHER re-runs.

### 3. Cwd drift after `cd <subdir> && <tool>` invocation

- **What was done:** Ran `cd backend && uv run pytest tests/test_hardware_firmware_cve_matcher.py -k "fragattacks"` to test the FragAttacks-related tests. The cd persisted into the next bash invocation; subsequent `git status` would have resolved against `backend/backend/...` per the Rule #38 antipattern.
- **Failure mode:** Subsequent git commands would emit `warning: could not open directory 'backend/backend/'` + `fatal: ambiguous argument` errors. Recovery cost: 30 seconds + confusing error trail.
- **Evidence:** Caught mid-session via `pwd` self-check before the next git command; reset to repo root via explicit `cd /home/dustin/code/wairz && pwd`. Net 0 git-resolution errors in the commit log (because the catch fired before the regression).
- **How to avoid:** Per Rule #38 — for git invocations use `git -C /home/dustin/code/wairz <subcommand>`; for `uv run pytest` + similar cwd-sensitive tools use subshell-scoped `( cd backend && uv run pytest ... )`. Subshell-scoping prevents cd leak into the next call. Rule-of-Three+ now (γ + δ + this catch); discipline is durable.

### 4. `docker compose exec backend python` runs system Python without sqlalchemy

- **What was done:** Initial Rule #11 import smoke used `docker compose exec -T backend python -c "from app.services...."`. Failed with `ModuleNotFoundError: No module named 'sqlalchemy'` because `python` is system Python (not the venv).
- **Failure mode:** Smoke-test confusion — the failure looked like a regression in the rebuild's installed packages, but the real cause was wrong Python interpreter.
- **Evidence:** Symptom-vs-cause: `import sqlalchemy` fails inside the backend container under system python; venv python at `/app/.venv/bin/python` has sqlalchemy installed correctly.
- **How to avoid:** Per CLAUDE.md Rule #20 — `docker compose exec -T -w /app -e PYTHONPATH=/app backend /app/.venv/bin/python -c "..."`. The venv invocation is the load-bearing form; the `python` shortcut is a footgun. Documenting as a recipe for Rule #11 smoke commands in `.mex/patterns/`.

## Cross-Cutting Anti-pattern Themes

1. **"NVD describes ATTRIBUTION; the advisory's CVSS describes the WORST-CASE AGGREGATE."** This session's FragAttacks CVSS drift was caused by assuming the pre-realignment CVSS values were authoritative without re-fetching. Triple-verification (scout → implementer → reviewer) is the discipline that catches drift; single-axis verification misses field-value drift.

2. **"force_rescan=True does NOT delete; it only skips the dedup check."** The matcher's semantics are nuanced. For YAML-edit verification, use surgical DELETE before cve-match (Pattern #5) rather than relying on force_rescan to DELETE+re-insert.

3. **"Subshell-scoped `cd` is the durable shape; bare `cd` leaks into the next bash invocation."** Per Rule #38, `( cd backend && uv run pytest ... )` is correct; `cd backend && uv run pytest` is the antipattern. Symptom-vs-cause: subsequent git commands fail with `ambiguous argument` errors; root cause is cwd drift.

4. **"docker compose exec backend python ≠ /app/.venv/bin/python."** System Python doesn't have project deps installed. Per Rule #20, use the venv path explicitly; the `python` shortcut is a footgun.

5. **"Pre-implementation corpus audit + post-rebuild delta validation is cheap and load-bearing."** The 1-second SQL audit calibrates expected deltas and surfaces surprise regressions immediately. Companion to Rule #19 evidence-first applied to YAML edits.

6. **"Advisory-only path bypasses the F-FORENSIC-10 gate by design — narrowing fields on advisory-only entries are load-bearing for `_match_curated` match scope, NOT for the gate."** Reviewer A A6 flagged that the FragAttacks advisory entries' narrowing fields (broadcom `category_regex`, qualcomm `chipset_regex`) appear redundant at the gate level but are load-bearing at the match level. Removing them in a future cleanup would re-introduce over-attribution under the advisory_id namespace. Add YAML comments marking these as load-bearing (deferred per Reviewer A A6).

7. **"Cross-stack alignment tests assert SHAPE-equivalence, not name-equality."** L1 (curated tier) has 4 regex-based narrowing fields; L2 (BT layer) has 6 frozenset/regex/int-based narrowing conditions. The dialects intentionally differ. The alignment test asserts both layers REJECT the conceptual antipattern via their idiomatic shapes; a name-equality test (e.g. asserting both allowlists contain `chipset_regex`) would be a false alignment.

8. **"`inspect.getsource` source-text-grep is fragile against source-code transforms."** Reviewer A A2 flagged the alignment test's `inspect.getsource(patterns_loader._parse_banner_cve_pin)` as fragile under Cython compilation / AST rewriting / frozen-wheel transforms. The durable shape is to export an explicit constant from patterns_loader and assert against `len(_BT_NARROWING_CONDITIONS) == 6` (mirror of the L1 `_KNOWN_FIRMWARE_NARROWING_FIELDS` shape). Deferred to next session.

9. **"Duplicate-advisory_id WARN was designed for ACCIDENTAL collisions; intentional convergence pollutes the diagnostic channel."** Reviewer A A5 flagged that the shared-advisory_id convergence trains operators to ignore the WARN, which will mask the next legitimate accidental collision. Anti-pattern shape: noisy intentional WARN drowns out the rare important signal. Fix: opt-in `shared_advisory_id: true` (or equivalent) YAML key that suppresses the WARN when both entries declare the convergence; the accidental case stays WARN. Deferred to next session.

10. **"7 sessions running with the multi-persona reviewer pattern catching CVE-attribution + CVSS drift."** The implementer-side verification catches some drift; the reviewer-side WebFetch catches OTHER drift. Different roles focus on different aspects. The discipline is durable beyond debate; this session's Reviewer B HIGH CVSS-drift catch is the 7th instance of the pattern.
