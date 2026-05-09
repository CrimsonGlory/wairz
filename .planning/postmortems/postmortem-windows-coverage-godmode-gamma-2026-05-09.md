# Postmortem: Windows-Coverage God-Mode — Phase γ (Registry + Driver Matrix)

> Date: 2026-05-08 (γ shipped 2026-05-08; campaign branch dated 2026-05-09)
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md` (Phase γ section)
> Branch: `feat/windows-phase-gamma-2026-05-09` (from β.14b tip `893dcac`)
> Duration: 2026-05-08 15:28 → 16:17 MDT (~49 minutes wall-clock)
> Commits: 9 (e3e94cc..8437ae3) on the γ branch
> Outcome: completed

## Summary

Phase γ shipped the registry-hive walker (regipy auto-walk on unpack), the
driver-package extractor (INF parser + signify-based CAT signing-tier
classifier per Persona-E #13), 13 new MCP tools across 2 categories, the
γ.7 cross-stack alignment commit (DB CHECK ↔ FE union ↔ FE config triple
agreement preserved), 4 frontend skeleton pages, and a 3-tier real-firmware
canary set. 9 commits, 0 reverts, 218 new tests, all green; container
rebuild + Rule #11 import smoke clean against alembic head `c9d0e1f2a3b4`.

## What Broke

### 1. Rule #38 ambiguity — "branch off main" mid-session correction

- **What happened:** Kickoff prompt said "fresh branch off main:
  feat/windows-phase-gamma-2026-05-09". Local `main` was 5 weeks stale
  (last commit `e2fd35e`); the actual mainline was `clean-history`
  (705 commits ahead of `main`, 33 commits behind the campaign branch).
  Branched correctly from the β tip (γ work depends on β infrastructure)
  and explained the reasoning; user confirmed mid-session ("I think our
  main we have been using is clean-history or something like that").
- **Caught by:** Pre-commit grep — verified `clean-history` HEAD ==
  merge-base of `main`-vs-β-branch == β branch's parent commit, so
  `feat/windows-phase-gamma-2026-05-09` (forked from β tip) ≡
  `clean-history + α + β` topologically.
- **Cost:** ~3 minutes of evidence-gathering before the first commit.
  Zero rework — the branch decision was correct on first attempt; the
  user clarification just confirmed.
- **Fix:** Documented the branch topology in the user-facing reply
  before proceeding; future kickoff prompts could say "off the active
  mainline" or "off clean-history" explicitly.
- **Infrastructure created:** None needed (branch decision was correct).
  Recommendation: kickoff-prompt template clarification — see
  Recommendations below.

### 2. Rule #35a pipe-trap recurrence

- **What happened:** Ran the Rule #24 mandatory tsc canary as
  `npx tsc -b --force 2>&1 | tail -10; echo "EXIT=$?"`. Output:
  ```
  src/__canary.ts(1,7): error TS2322: Type 'string' is not assignable to type 'number'.
  EXIT=0
  ```
  This is the Rule #35a pipe-trap from the audit-2026-05-04 lesson —
  `$?` after a pipeline reflects `tail`'s exit, not `tsc`'s. Bash tool
  doesn't enable `pipefail` by default.
- **Caught by:** **Self-canary** — the impossible combination ("error
  TS2322 AND exit=0 simultaneously") is a known pattern from the
  Rule #35a worked example, so the discrepancy was caught immediately.
- **Cost:** ~30 seconds (one re-run with file-redirect).
- **Fix:** Re-ran as `npx tsc -b --force > /tmp/tsc-canary.log 2>&1;
  ec=$?; tail -10 /tmp/tsc-canary.log; echo "REAL TSC EXIT=$ec"`.
  Real exit was 2 (canary correctly fails); typecheck of the actual
  γ surface returned exit 0 cleanly.
- **Infrastructure created:** None — Rule #35a already documents this
  exact failure mode. The recurrence is a Rule-of-Two for pipe-trap
  catches-via-canary (audit-2026-05-04 was the first; γ.7 is the second).

### 3. `make_live_db()` async-context-manager vs async-iterator confusion

- **What happened:** First draft of `tests/test_registry_hive_walker.py`
  used `async for db in make_live_db():` per a stale recollection of the
  pattern. Actual API is `async with make_live_db() as db:` (the helper
  is decorated with `@asynccontextmanager`, not an async generator
  producing the session via `yield`).
- **Caught by:** **pytest** — 3 tests errored at fixture setup with
  `TypeError: 'async for' requires an object with __aiter__ method,
  got _AsyncGeneratorContextManager`. The 28 pure-walker tests passed;
  only the live-canary tests failed.
- **Cost:** ~2 minutes (read existing usage in
  `test_windows_pe_signature_tools.py`, refactor 3 tests in-place).
- **Fix:** Removed the broken `live_db` fixture; rewrote each live-
  canary test to wrap its body in `async with make_live_db() as db:`
  per the precedent.
- **Infrastructure created:** Recommendation #1 below — a `.mex/patterns/
  use-live-db.md` recipe so future agents don't hit this.

### 4. Edit tool's "must Read first" requirement

- **What happened:** Twice during the session, ran `Edit` against a
  file (`backend/app/models/__init__.py` for γ.1; `backend/pyproject.toml`
  for γ.4) without first calling `Read` on it in this conversation
  turn. The file content was visible from earlier `Bash cat` output,
  but the Edit tool's safety contract requires a Read in the
  conversation history.
- **Caught by:** **Edit tool** — returned `File has not been read
  yet. Read it first before writing to it.`
- **Cost:** ~10 seconds each time (one extra Read call per occurrence).
- **Fix:** Read then Edit on retry.
- **Infrastructure created:** None — this is the Edit tool's intended
  guardrail working as designed.

### 5. Container pytest unavailable for in-container test sweep

- **What happened:** Attempted `docker compose exec -T backend
  /app/.venv/bin/pytest tests/...` for the γ.9 cut-over verification.
  The backend container is a production-only image with no pytest
  installed and no `tests/` directory mounted.
- **Caught by:** **Docker exec** — `OCI runtime exec failed: ... stat
  /app/.venv/bin/pytest: no such file or directory`.
- **Cost:** ~30 seconds (one failed exec attempt + pivot).
- **Fix:** Pivoted to host-side pytest sweep (323 tests pass) +
  in-container Rule #11 import smoke (model + service + tool-registry
  imports against the rebuilt container's runtime). This is the
  canonical β-precedent verification pattern; my expectation was
  wrong, not the infrastructure.
- **Infrastructure created:** None — the production-only container
  is a deliberate Dockerfile choice. Documented the canonical
  verification path inline in the γ.9 commit message for future
  reference.

### 6. `test_alembic_autogenerate_empty.py` host environment flake

- **What happened:** `pytest tests/ -x` halted at
  `test_alembic_autogenerate_empty.py::test_alembic_autogenerate_is_empty`
  with `asyncpg.exceptions.InvalidPasswordError: password authentication
  failed for user "wairz"` against `localhost:5432`.
- **Caught by:** **pytest** (failed, halted -x sweep).
- **Cost:** ~1 minute (diagnose, confirm pre-existing).
- **Fix:** N/A — pre-existing host-environment issue. Per the user-
  memory port-conflict note, host port 5432 is occupied by the
  Greenbone Postgres install (different creds); Wairz uses 5434. The
  test connects to `localhost:5432` directly (bypassing docker-compose
  port mapping); it fails on this dev host regardless of γ work.
- **Infrastructure created:** None for γ. Pre-existing flake — the
  test should either (a) read DATABASE_URL from env at runtime, OR
  (b) be marked skip-on-no-direct-postgres. Out of γ scope.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|------------------|
| Rule #24 tsc canary discipline | Pipe-trap exit-code obfuscation in the canary itself | 1 | Trusting a "0 errors" output that was actually masking a TS2322 error in the γ FE pages |
| `test_finding_source_alignment.py` | Cross-stack DB CHECK ↔ FE union ↔ FE config drift | 0 actual catches (γ.7 bundled all 3 surfaces in one commit per Rule #25 exception #2) | Single-slice exception #2 enforced — alignment test would have been RED between commits if γ.7 had been split. Saved a bisect-broken state. |
| `test_windows_check_literal_alignment.py` | New test added in γ.2 — Pydantic Literal ↔ DB CHECK alignment for `WindowsDriverSigningTier` + `WindowsRegistryExtractWalkStatus` | 0 actual drift catches (designed in alignment from the start) | Future drift between Pydantic Literal and CheckConstraint will fire here. |
| Rule #35b live canaries | Forced ORM round-trip + SELECT verification on every new service | 4 in registry walker + 3 in driver extractor + 4 in finding emitter + 2 in tier-1 canary = 13 live canaries shipped in γ | Constructor-args-vs-persisted-fields class of bugs (audit-2026-05-04 F-A-06 confidence-bypass shape). Mock-only tests structurally cannot catch these. |
| pytest fixture-shape error | `async for` vs `async with` on `make_live_db()` | 1 (3 tests, 1 root cause) | Silent passing tests that don't actually exercise the ORM round-trip. The TypeError was loud + immediate. |
| Edit tool Read-first guardrail | Edit attempts without prior Read | 2 | Silent edits against assumed file contents (the Bash `cat` output is stale relative to prior Edit calls). |
| Rule #19 evidence-first probes | regipy `recurse_subkeys` yield-shape probe before walker code; signify `pkcs7.SignedData` API probe before classifier; `WAIRZ_TEST_REAL_HIVE` env-var heuristic before tier-2 canary; β.14 patterns/antipatterns + PRD γ section read before γ.1 | 4 | Wrong-API guesses + 1-shot test design churn. β.14a pattern #5 (real-artefact verdict probe) generalised cleanly. |
| Rule #38 absolute-path discipline | `git -C /home/dustin/code/wairz` for every git invocation; subshell `(cd backend && ...)` for cwd-sensitive uv calls | ~50+ Bash invocations clean | CWD drift after `cd backend && ...` (the β.10 / β.12 incident pair). Rule-of-Three now (β.10 + β.12 + γ all clean under the codified rule). |

## Scope Analysis

- **Planned (γ kickoff prompt):** 9 sub-tasks γ.1..γ.9 — windows_registry_extracts table; windows_drivers table; firmware.registry_hive_walk_* status; regipy walker; INF/CAT extractor; 7+6 MCP tools; 4 FE pages + alignment commit; classifier + emit-from-walk; cut-over canary set.
- **Built:** All 9 sub-tasks shipped as 9 commits, ordering preserved, exact scope match. One mid-stream addition: `test_windows_check_literal_alignment.py` (new test file in γ.2) — co-located with the new tri-state Literal it verifies; matches the precedent `test_finding_source_alignment.py` shape.
- **Drift:** None on the build axis. One scope-clarification mid-session (branch base — see "What Broke #1") resolved without rework. The γ.7 frontend pages shipped as skeletons (per the prompt's explicit "skeleton FE pages + REST integration follow-up" framing); no scope creep.

## Patterns

- **Rule #25 per-sub-task commits held under γ** — 9 commits, each
  independently revertable, no `--no-verify`, no `--amend`. Rule-of-
  Eleven now across the campaign (α 12 + β 14 + γ 9 = 35 commits, 0
  reverts).
- **Rule #38 absolute-path discipline held under γ** — Rule-of-Three
  (β.10 first incident → β.12 second incident → β.14 first clean
  session → γ second clean session). Discipline is durable.
- **Rule #19 evidence-first generalises across libraries** — applied
  to regipy (`recurse_subkeys` yield shape), signify
  (`pkcs7.SignedData.from_envelope` API), and host-fixture probes
  (env-var path tests). Same shape every time: probe in 30 seconds,
  design test/code against the actual contract, save multi-iteration
  rework.
- **Rule #35a pipe-trap is a Rule-of-Two now** — audit-2026-05-04 was
  the first catch; γ.7 is the second. Codified rule + canary
  discipline both held; the second occurrence was caught in seconds.
- **Rule #25 single-slice exception #2 (cross-stack alignment)** —
  Rule-of-Three now: 7079b4d (2026-05-06) + ee2abd9 (β.12a) + f70c2e1
  (γ.7). Pattern is durable. The alignment test is RED between
  commits if split, GREEN under the bundled commit shape.
- **JSONB normalizer + schema_version + stamp helper discipline (Rule
  #35c)** — applied to 3 new JSONB columns in γ
  (windows_registry_extracts.parsed_tree, windows_drivers.inf_metadata,
  firmware.registry_hive_walk_result), each with normalizer + stamp +
  full test coverage matching the existing precedent. 4+ consumer
  files threshold rule applied uniformly.
- **Rule #33 .a/.c/.d 202+polling contract held under γ.3 + γ.6** —
  registry_hive_walk_* status set has Pydantic Literal + DB CHECK
  (.c), the trigger_registry_hive_walk MCP tool is idempotent with
  409-on-conflict (.a), and the dispatch is asyncio.create_task per
  the in-process rubric (.d).

## Recommendations

1. **Add `.mex/patterns/use-live-db.md`** — the `async with
   make_live_db() as db:` shape was non-obvious to a fresh agent
   (3 test errors caught it in seconds, but the pattern doc is
   cheap insurance). Cite the
   `test_windows_pe_signature_tools.py` precedent. Cost: ~10 LOC of
   docs. Benefit: zero re-discovery cost.

2. **Kickoff-prompt template clarification — "branch off main" vs
   "branch off active mainline"** — the kickoff prompt's "off main"
   triggered a 3-minute reasoning detour because local `main` is
   5 weeks stale relative to the active `clean-history` line.
   Future per-phase prompts should say "off the active mainline
   (clean-history)" OR "off the prior phase's branch tip" to avoid
   ambiguity. This is a documentation-only fix; no code change.

3. **REST endpoints for windows_registry + windows_driver** — γ.7
   shipped 4 frontend pages as skeletons because no REST surface
   exists yet. The pages are functional via MCP tools today (Claude
   Code / Desktop), but operators using the web UI see placeholder
   content. Add `GET /hardware-firmware/registry-hives`,
   `GET /hardware-firmware/registry-hives/{id}/walk`,
   `GET /hardware-firmware/drivers`, `GET /hardware-firmware/drivers/{id}`,
   `POST /registry-hive-walk` (Rule #33 trigger), `GET
   /registry-hive-walk/status` to `app/routers/hardware_firmware.py`.
   Cost: ~6 endpoints + matching API client functions in
   `frontend/src/api/hardwareFirmware.ts`. Benefit: γ FE feature
   parity with β.

4. **Tier-2/3 real-firmware canary fixture provisioning** — the
   γ.9 canary set ships 3 pass + 2 skip; tier-2 needs a real Win11
   SOFTWARE.hive at `WAIRZ_TEST_REAL_HIVE`, tier-3 needs a real
   signed driver `.cat` at `WAIRZ_TEST_SIGNED_CAT`. Fixture extraction
   from a real Win11 install is a one-time operator setup. Once
   provisioned, the canary set graduates from 3p+2s to 5 pass with no
   test edits. Mirrors the β.14a deferred-fixture-provisioning shape.

5. **Auto-walk-on-unpack hook coverage** — γ.4 wired
   `auto_walk_firmware_safe` into `unpack._run_hardware_firmware_
   detection_safe`, and γ.5 wired `auto_extract_drivers_safe`. Both
   are fire-and-forget calls inside an existing post-extraction
   helper. The standalone walker + extractor have full coverage; the
   integration via the unpack pipeline doesn't (no test that drives
   `_run_hardware_firmware_detection_safe` end-to-end and asserts
   the new γ blobs / extracts arrive). Suggest a single integration
   test in `test_unpack_post_detection_hooks.py` that mocks the
   unpacker output and asserts both auto-walk_safe + auto_extract_safe
   fire. Cost: ~80 LOC. Benefit: catches a regression where someone
   refactors `_run_hardware_firmware_detection_safe` and accidentally
   removes one of the γ hooks.

6. **CAT signing-tier classifier refinement** — the current heuristic
   is string-pattern only (subject CN substring matching for "Microsoft
   Windows Hardware Compatibility Publisher" + chain anchors for
   "Microsoft Code Verification Root" / "Microsoft Windows Hardware
   Compatibility"). Real production CAT files may have leaf cert
   subjects in non-CN form (alternate-name extensions, vendor strings,
   etc.). Tier-3 fixture provisioning will surface real verdicts;
   the classifier may need refinement after that data point. Document
   the heuristic limitations in the module docstring (already done in
   `driver_extractor.py`); refinement is a follow-up driven by tier-3
   probe data, not a γ scope item.

## Numbers

| Metric | Value |
|--------|-------|
| Phases planned | 9 (γ.1..γ.9) |
| Phases completed | 9 (100%) |
| Commits | 9 (e3e94cc..8437ae3) |
| Files changed | 36 (24 new, 12 modified) |
| Lines added | 8,388 |
| Lines deleted | 6 |
| Reverts | 0 |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 (Rule #24 canary fired correctly; not a "block") |
| Rule #24 mandatory canary | 1 fired (caught Rule #35a pipe-trap) |
| Edit-tool Read-first catches | 2 (no impact) |
| Pre-existing host flake hits | 1 (test_alembic_autogenerate_empty — unrelated) |
| Rework cycles | 0 (no commit needed re-shipping) |
| Tests added | +218 (323 total γ-related) |
| Tests passing | 323 |
| Tests skipped | 2 (tier-2/3 awaiting fixtures — expected) |
| New MCP tools | +13 (197 total registry size) |
| New JSONB normalizers | +3 (parsed_tree, inf_metadata, registry_hive_walk_result) |
| New Pydantic Literals | +3 (WindowsDriverSigningTier, WindowsRegistryExtractWalkStatus, RegistryHiveWalkStatus) |
| New finding sources | +3 (windows_registry_persistence, windows_inf, windows_driver_imports) |
| New ORM models | +2 (WindowsRegistryExtract, WindowsDriver) |
| New alembic migrations | +4 (γ.1, γ.2, γ.3, γ.7) |
| Wall-clock duration | ~49 minutes |

---HANDOFF---
- Postmortem: windows-coverage-godmode-gamma-2026-05-09
- Document: .planning/postmortems/postmortem-windows-coverage-godmode-gamma-2026-05-09.md
- Failures documented: 6 (1 ambiguity, 1 pipe-trap, 1 fixture-shape, 2 Edit-tool guards, 1 host flake)
- Safety catches: 7 (Rule #24 canary, alignment test, literal-CHECK alignment test, Rule #35b live canaries × 13, pytest fixture error, Edit guardrail, Rule #19 probes × 4, Rule #38 ~50+ clean invocations)
- Recommendations: 6 (use-live-db pattern doc, kickoff-prompt clarification, REST endpoints, tier-2/3 fixture provisioning, auto-walk hook integration test, CAT classifier refinement)
---
