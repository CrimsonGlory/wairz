# Patterns: Phase 2 — Test Coverage Backfill (21 routers + 26 services)

> Extracted: 2026-05-08
> Campaign: `.planning/campaigns/phase-2-test-coverage-routers-services-2026-05-06.md`
> Postmortem: `.planning/postmortems/postmortem-phase-2-test-coverage-routers-services-2026-05-08.md`

## Successful Patterns

### 1. ORM-persistence as the joint canary-value predictor (NOT LOC)

- **Description:** When triaging a service file for test-coverage backfill, the joint predictor of canary value is `(ORM persistence presence) OR (non-trivial parser/lookup-table shape)`. LOC is a soft tiebreaker only. Wave 9's pure-stdlib 207-LOC `sysroot_service` shipped with high canary value (non-trivial table-lookup shape); Wave 10's 88-LOC `emulation_preset_service` shipped (CRUD persistence); Wave 8's 326-LOC `abusech_service` skipped (pure HTTP pass-through); Wave 10's 142-LOC `hashlookup_service` skipped (pure HTTP client).
- **Evidence:** Wave 10 Decision Log (2026-05-08); cumulative SKIP rate distribution across the campaign (60% at 61-142 LOC band vs ~20% at 200-355 LOC bands).
- **Applies when:** Triaging any service file for test-coverage backfill under Rule #19 evidence-first.

### 2. `sys.modules`-injection + hasattr-sentinel as canonical Rule #30 SOURCE-patch

- **Description:** For lazy-imported third-party modules (`import weasyprint`, `import setools`, `import pypdf`, `import clamd`, etc. inside function bodies), patch via `with patch.dict(sys.modules, {"<libname>": fake_module})`. Pair every such test class with a `TestRule30...SourcePatch` containing `assert not hasattr(<consumer_module>, "<libname>")` — fails LOUDLY if a future refactor promotes the import to top-level (forcing migration to inverse-Rule-30 shape).
- **Evidence:** Established Wave 7 (`test_selinux_service.py:TestRule30SetoolsSourcePatch`); applied uniformly across Waves 7+8 (7 services). Cumulative across campaign: 7 SOURCE-patch services + sentinel pairs.
- **Applies when:** Service file lazy-imports a third-party module inside a function body (Rule #30 mechanical grep returns indented `from <lib>` or `import <lib>`).

### 3. `tests/_live_db.py` JSONB→TEXT shim hardening

- **Description:** Render JSONB / ARRAY as TEXT in DDL (NOT JSON) so SQLite's dialect-level JSON processor doesn't double-decode against custom bind/result shims. Pass a tolerant `json_deserializer` to the engine that strips outer single-quotes (the SQL-string-literal artefact from bare-string `server_default="'{}'"`) and falls back gracefully on parse failure.
- **Evidence:** Wave 2 commit `080c10d`; backstops every subsequent Rule #35b live-canary across 38+ test files.
- **Applies when:** Any new ORM model with JSONB or ARRAY columns + bare-string `server_default="'[]'"` / `server_default="'{}'"` shape needs SQLite-backed live-canary support.

### 4. Inverse-Rule-30 (top-level imports → CONSUMER-module patch)

- **Description:** When a service imports its third-party deps at MODULE scope (`from elftools.elf.elffile import ELFFile` at line 3, etc.), patches MUST hit the CONSUMER module (`app.services.X.Y`), NOT the source. Patching the source is a silent no-op because the consumer holds its own local reference.
- **Evidence:** Documented in Wave 1 `test_assessment_service.py:200`; generalized in Wave 6; reference exemplars across 11 services through the campaign.
- **Applies when:** Service file's `^(from|import) <third-party-lib>` grep returns top-level (un-indented) match.

### 5. Per-file commits per Rule #25 — independently revertable test additions

- **Description:** Every test file lands as its own commit with format `test(<module>): <summary> (N cases, +M LOC)`. Latent-bug fixes uncovered during test authoring (e.g. `apk_scan` `_cache` NameError) ship as SEPARATE commits per Rule #25, even when discovered in the same authoring session.
- **Evidence:** 40 substantive test commits + 3 fix commits across 10 waves; 0 reverts; `git bisect` and `git revert` work cleanly per-file.
- **Applies when:** Multi-file test backfill campaign with N>3 independently-verifiable sub-tasks.

### 6. Wave-end full-suite gate with exact-delta verification

- **Description:** After every wave, run the full-suite smoke and verify the passed-count delta exactly matches the sum of new cases added in that wave. Any silent regression in a prior wave's file surfaces as "expected +N got <N". Wave 9's gate caught 12 pre-existing failures from neighboring sbom/alembic work that would otherwise have shipped invisibly under Phase 2's signoff.
- **Evidence:** 10/10 waves passed exact-delta gate; Wave 9 gate caught the 12 pre-existing alignment failures.
- **Applies when:** Multi-wave test-addition campaigns where each wave's contribution must be cleanly attributed.

### 7. Two-pass pipeline canary via call-order tracking

- **Description:** For services with primary-then-fallback dispatch (e.g. `clamav_service.scan_directory` does multiscan → per-file fallback), capture call-order in a list inside the mock and assert on the sequence post-execution. A regression where someone swaps the method in the except branch (Python's catch-all `except Exception:` is wide enough to mask this) would silently return clean results without this canary.
- **Evidence:** `test_clamav_service.py::test_multiscan_raises_falls_back_to_per_file_scan` (Wave 9).
- **Applies when:** Any service with primary-then-fallback dispatch shape — HTTP retry logic with method swap, subprocess fallback (POSIX → Windows path), Redis-MISS → DB-read fallback in cache layers.

### 8. `git ls-files` candidate enumeration before each wave kickoff

- **Description:** Before each wave, re-enumerate the actual untested-service candidate set via `git ls-files backend/tests/ | grep test_<svc>.py`. Do NOT trust the previous wave's "remaining" claim or the campaign's session-end-memory log. The structured triage table (measurement-derived) is more reliable than session-end memory.
- **Evidence:** Wave 10 — closeout said "remaining 3", `git ls-files` confirmed 5 (3 SKIPs + 2 SHIPs).
- **Applies when:** Resuming any multi-wave campaign across session boundaries.

### 9. Multi-stage live-canary lifecycle in single test method

- **Description:** For services with full lifecycle CRUD shape (create → list → get → update → delete), author one comprehensive test method that walks all stages and SELECTs the persisted state at every transition. Stronger than 5 independent single-stage canaries because it verifies state continuity across operations.
- **Evidence:** `test_emulation_preset_service.py::TestFullLifecycleLiveCanary::test_create_list_get_update_delete` (Wave 10); `test_uart_service.py::TestFullLifecycleLiveCanary::test_connect_send_disconnect_status_transitions` (Wave 9).
- **Applies when:** Any CRUD-shaped service with ≥3 lifecycle methods that mutate the same row.

### 10. Rule #30 `inspect.getsource` lazy-import refactor canary

- **Description:** In a Rule #30 sentinel test, use `inspect.getsource(<function>)` and assert `"from <lib>" not in src` to catch a future regression that flips a top-level import to lazy. The sentinel makes the patch-shape contract LOUD — if someone moves the import inside a function body to "simplify testing", this assertion fails immediately, signalling the patches must migrate to SOURCE-shape.
- **Evidence:** `test_analysis_service.py::TestRule30InverseConsumerPatch::test_consumer_module_does_not_lazy_import_elffile` (Wave 10).
- **Applies when:** Any inverse-Rule-30 test class where the patch correctness depends on the import remaining top-level.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Wave shape = 5 files (Phase 1 cadence) | Per-file commits Rule #25, pause for review | Held through Waves 1-5; service waves dropped to 4-5 substantive + 1-2 SKIPs as triage matured |
| Serial in-place commits, NOT parallel worktrees | Each test file independent (writes only `backend/tests/test_<X>.py`); avoids Rule #23 worktree complexity; full container access for Rule #11 smoke runs | 0 cross-stream sweeps across 51 commits |
| SKIP `emulation_constants` from canary scope | Pure constants module — no service surface | Held; documented in Decision Log |
| `tests/_live_db.py` JSONB→TEXT shim hardening (Wave 2) | Wave 1 band-aid would have multiplied across the campaign | Eliminated double-decode for all subsequent waves; durable infrastructure |
| Inverse-Rule-30 case codified in Decision Log | One-off Wave 1 documentation generalized after Wave 6 saw it 3/5 times | Pre-authoring grep prevented every silent-no-op patch |
| F-A-06 confidence-bypass backstop generalized | Audit cited 5 sites needing explicit confidence canary | All 5 sites covered by campaign-end |
| `sys.modules`-injection + hasattr-sentinel as canonical SOURCE-patch | Wave 7's `setools` + `weasyprint` needed a stronger pattern than Wave 6's `patch.object` | Applied uniformly across Waves 7+8 (7 services); pattern durable |
| Rule #19 SKIP for 6 zero-canary services | Pure external clients / thin coordinators / pure constants — mock-only tests would verify tautologies | Audit signoff strengthened (honest SKIPs > dead mock files); 96% substantive coverage with 100% audit-cited routers |
| Wave 10 reconciliation via `git ls-files` (closeout said 3, table said 5, ls-files said 5) | Mechanical measurement > session-end memory | Caught a candidate-count drift pre-authoring |
| Pre-existing 11 alignment failures NOT closed in this campaign | Independent of Phase 2 contribution; tracked in separate intake | Honest closeout; campaign contribution cleanly attributed |
