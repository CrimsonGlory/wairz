# Patterns: Rule #44 backfill + deep multi-persona review (Issue #15)

> Extracted: 2026-05-14
> Campaign: rule-44-cross-firmware-backfill (Issue #15) + Phase A/B/C/D follow-up
> Postmortem: .planning/postmortems/postmortem-rule-44-cross-firmware-backfill-plus-deep-review-2026-05-14.md

## Successful Patterns

### 1. Parallel multi-persona deep review via 3 background Agent calls

- **Description:** Dispatched 3 specialized reviewers in parallel — code/security (`citadel:arch-reviewer`), forensic domain expert (Explore subagent posing as senior DFIR analyst), SQL/performance auditor (Explore subagent). Single message with 3 `Agent` tool uses, all `run_in_background=true`. Total wall-clock ≤5 min for 3 deep reviews. Each agent's report was self-contained and DIRECTLY actionable; findings drove 6 follow-up Rule #25 commits.
- **Evidence:** Background agent IDs ac68a8979f997d98b, a94131d6c8b755e27, aee6b260e06b1fc06 (this session). Combined findings: 1 MED bug + 4 forensic calibrations + 1 missing index + 4 informational. Zero false-positives.
- **Applies when:** Any non-trivial feature shipping (≥10 commits in one session, ≥3 files of net-new code, security-sensitive surface). Single-persona review systematically misses domain-specific issues; 3 perspectives in parallel cover correctness + domain + performance for free.

### 2. Single-slice Rule #25 commit for identical-across-N-files fixes

- **Description:** C1 (project_id=None guard) was identical across 22 handlers. A per-piece commit chain would have produced 22 cosmetically-identical commits with no bisect value. The single-slice Rule #25 exception rationale applies: "if a multi-surface fix would leave the codebase in a half-fixed state with no benefit, bundle." Saved 21 CI runs.
- **Evidence:** Commit `6e85cb7` (22 files, 154 insertions, single message documenting the rationale). Per-piece would have cost ~20 CI runs (Rule #41 cancel-in-progress + concurrency cancel partial runs) + ~20 minutes of human review noise. The single-slice form ships in one atomic batch + one commit message documenting the cross-cutting rationale.
- **Applies when:** A defect's fix touches N files AND the per-file fix is identical (literally the same edit, not just shape-identical). Counter-example: per-walker calibration fixes (C2/C3/C4) are NOT single-slice because each walker has a different signal threshold + rationale. Mechanical detection: if `git diff --stat HEAD~1` shows N+ files with the SAME number of insertions/deletions, it's a single-slice candidate.

### 3. Parameterized canary registry for Rule #44 family coverage

- **Description:** `tests/test_rule_44_cross_firmware_canaries.py` declares a `_ToolSpec` dataclass (handler + record_factory + lookup_kwargs + expected_signal) and registers all 11 walkers in one `TOOLS = [...]` list. Two `pytest.mark.parametrize` tests (guard canary + value-flow canary) inherit coverage across the entire registry. A future Rule #44 walker auto-inherits canary coverage by adding ONE entry to TOOLS.
- **Evidence:** 22 parameterized tests + 4 calibration regression backstops = 26 tests in one file, 6-second runtime. Adding the 12th walker would require ~10 lines (factory + TOOLS entry) for full Rule #35b coverage.
- **Applies when:** A family of N functions with structurally-identical contracts (Rule #44 cross-firmware tools, JSONB normalizers, alembic-stamp helpers, etc.). The parametrize-over-registry pattern beats N copy-paste test functions on every axis: maintenance (single fixture change updates all), discoverability (one file lists every member), and onboarding (new walker author sees the pattern and registers their entry).

### 4. Live canary fixtures use Rule #35c normaliser shape, NOT writer pre-normalisation shape

- **Description:** When seeding JSONB columns in canary fixtures, use the canonical envelope the normaliser RETURNS (or the `{schema_version, items}` envelope the `_stamp_*` writer produces), NOT a guess at what the walker writes pre-normalisation. The handler reads via the normaliser; the fixture must round-trip through the same normaliser to produce the expected value.
- **Evidence:** Initial `_scheduled_task_with_encoded_ps` fixture wrote `{"schema_version": 1, "actions": [...]}` (incorrect — analogous to the walker's pre-normalisation shape). The normaliser expected `{"items": [...]}` and silently returned `[]` because there's no `items` key. Fixed to canonical `{"schema_version": 1, "items": [{"type": "Exec", "command": "powershell.exe", "arguments": "-EncodedCommand AAAA"}]}`. Caught on first test run; one-edit fix.
- **Applies when:** Authoring tier-1 live canaries against any service that reads JSONB through a Rule #35c normaliser. Mechanical: grep `_normalize_<table>_<column>` to find the canonical shape, then mirror it in the fixture.

### 5. Reviewer-finding → Rule #25 commit mapping is 1:1 per finding

- **Description:** Each Phase C commit (C1/C2/C3/C4/C5/C6) maps to exactly one reviewer finding. The commit message cites the finding's severity + reviewer + rationale + the specific source quote. This creates a durable audit trail: future review of the commits surfaces WHICH review pass + WHICH severity drove the fix.
- **Evidence:** Commits `6e85cb7` (C1: code-review F#2 MED), `693b172` (C2: forensic priority #3), `d9a5676` (C3: forensic priority #1), `dc78dbf` (C4: forensic finding #4), `556722c` (C5: forensic finding #5-light), `c181572` (C6: SQL-audit finding #1). Each commit message includes "forensic-domain review 2026-05-14:" or "SQL-audit 2026-05-14:" citations.
- **Applies when:** Any post-review fix phase. The discipline keeps Rule #25 per-piece commits semantically aligned with the review pipeline that surfaced them, so future audits can replay the chain. Cost: one extra line in each commit message; benefit: durable audit trail.

### 6. Pre-existing alembic test-coupling worked around by explicit model import

- **Description:** `test_alembic_autogenerate_empty.py` passes in CI (where the full test suite collection registers every model via transitive imports) but fails in isolation. New test files that import `app.ai.tools.windows_*` modules trigger volatility model registration but NOT their FK target (`MemoryDumpImage`), so `Base.metadata.create_all()` fails with `NoReferencedTableError`. Worked around by explicit `from app.models.memory_dump_image import MemoryDumpImage  # noqa: F401` in the canary test file.
- **Evidence:** Encountered twice this session — once during the Issue #15.1 walker commit (registration test passed, value-flow test failed in isolation), once during the canary file commit. Both surfaced the same diagnostic ("Foreign key associated with column 'volatility_injection_records.memory_image_id' could not find table 'memory_dump_image'") and the same fix.
- **Applies when:** Any new test file that exercises a service module which transitively loads a model whose FK target isn't in `app.models.__init__.py`. Mechanical: if the test imports `from app.ai.tools.X`, grep `X.py` for `from app.models.<unregistered>` and add the import to the test file. Best long-term fix: register every model in `app.models.__init__.py.__all__` (deferred to a future sweep).

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Ship Issue #15 backfill BEFORE running deep review | The 11 walker commits are mechanical applications of the Rule #44 precedent (per Issue #15 directive). Review should grade the WORK, not the intent. | Deep review found 6 follow-up defects that would have shipped silently otherwise. Validates the "ship-then-review" rhythm — review-then-ship would have stalled on speculative concerns. |
| Apply ALL 6 follow-up defects in this session, not file for follow-up | User directive "full plan, full execute, don't wait for me". Each fix is bounded (≤100 LOC) and clearly scoped. The compounding cost of deferring is non-trivial: every Rule #44 user query against bcd / evtx / scheduled_task would have produced noise. | 6 Rule #25 commits shipped. Calibration is correct from the start; no operator-visible noise. |
| Bundle 26 canaries in ONE commit (Rule #25 single-slice exception #2 cited) | The canaries are a unified test layer added as a single follow-up to a shipped feature. Splitting to 11+ commits would produce per-walker commits identical in shape with no bisect value. The parameterized registry pattern (Pattern #3) is intrinsically single-file. | Single 684-LOC test file. 26 tests pass in 6s. Adding walker #12's canary is a 10-line diff. |
| Defer the `models/__init__.py` registration sweep | Out of scope for this session. The workaround (explicit per-test imports) is durable; a sweep is a 1-commit follow-up that should be filed separately. | Documented as a follow-up in the postmortem. Operator's call to schedule. |
| Skip C7 (int conversion error guards on `limit`) | Cosmetic LOW from code review. Already-existing precedent has the same shape. Defer to a future "Rule #44 input-validation hardening" pass. | Acceptable defer per cost/benefit. |
| Retry Issue #20 close given user re-authorization | The user's "full plan, full execute, don't wait for me" expressly re-authorizes the pre-authorized close from the original session prompt. The Citadel external-action-gate hook still requires per-call confirmation. | Documented in summary; user closes manually if blocked. |

## Numbers worth tracking

| Metric | Value |
|--------|-------|
| Sessions on this campaign | 1 |
| Total commits | 20 |
| Phases | A (3 reviewers parallel) + B (canaries) + C (6 follow-up fixes) + D (postmortem) |
| Walker categories backfilled (Issue #15) | 11 |
| Cross-firmware MCP tools in registry post-campaign | 22 (11 pre-existing + 11 new) |
| Total MCP tools | 321 |
| Reviewer findings → follow-up commits | 6 (1:1 mapping) |
| Live canary tests | 26 |
| Test runtime delta | +6 seconds (negligible vs. 5524-test suite ~180s) |
| Lines added | ~2,800 |
| Reverts | 0 |
| Cross-stream sweeps | 0 (single-session, single-branch) |
| Rule #25 single-slice exceptions invoked | 2 (C1 cross-22-handler guard, canary test bundle) |
| Domain-expert reviewer wall-clock | ~5 min total (parallel via background agents) |

## Promotion candidates for CLAUDE.md

The following patterns are CANDIDATES for promotion if they fire on a second session (Rule-of-Two):

1. **"Parallel multi-persona Citadel-agent review for non-trivial campaigns"** — pattern #1 above. Rule-of-One status. Promote when a future ≥10-commit campaign uses the same parallel-reviewer dispatch shape.

2. **"Parameterized canary registry for feature families"** — pattern #3 above. Rule-of-One status. Promote when a second Rule #44 family or analogous feature family adopts the same `_ToolSpec` + parametrize-over-TOOLS shape.

3. **"Live canary fixtures use normaliser RETURN shape, not writer pre-normalisation shape"** — pattern #4 above. Rule-of-One status. Promote when a second JSONB-shape mismatch in a canary fixture is fixed by switching to the normaliser-canonical envelope.

Each is a clear-cut mechanical discipline; promotion requires Rule-of-Two evidence per the standing rule-promotion discipline.
