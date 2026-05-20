# Postmortem: substring_in_head signal kind (P3.x — 2026-05-20)

> Date: 2026-05-20
> Campaign: P3.2 postmortem Rec #2 — `substring_in_head` signal kind
> closes the `windows_installer_iso` + `iso_9660` legacy bridge case.
> Direct-shipped per Rule #25 per-piece cadence; no campaign file
> (single Rule #25 Shape-1 single-slice commit + 1 chore SHA-pin).
> Duration: ~3 hours, commits `dcebd1c..52bce07` (2 commits)
> Outcome: **completed** (1 schema extension + 1 YAML adoption + 1
> bridge cleanup + 34 new tests + 4 new Rule #46 paired gate-canaries
> + `_SIGNAL_COST_CLASS` exhaustive canary that the project was
> missing entirely).

## Summary

P3.2 closed Phase 3.2 of the file-format YAML registry but deferred
five P3.x items for follow-on sessions; this session closes the first
of those (Rec #2 — `substring_in_head` signal kind) following the same
"deep research + Citadel + per-piece commit" cadence the user invoked
at session-open.

The decision NOT to dispatch Wave-1/Wave-2 scouts mirrors
`postmortem-backlog-sweep-2026-05-19.md` Pattern #1: HIGH backlog items
with a clear implementation contract from a prior session's review
close in priority order WITHOUT scout dispatch. The P3.2 postmortem
Rec #2 + Rec #3 already described the schema extension shape, the
bridge cleanup target, and the cross-stack alignment commit pattern.
Scout dispatch would have added 30-60 min for redundant convergence.

Two commits shipped:

| # | Commit | Title | Net delta |
|---|---|---|---|
| 1 | `dcebd1c` | feat(file-format): substring_in_head signal kind closes ISO bridge (P3.x) | +820/-31 / 9 files |
| 2 | `52bce07` | chore(backlog): pin commit SHA for p3x:substring_in_head row | +1/-1 / 1 file |

**Total:** 2 commits / +821 insertions / -32 deletions / **+789 net**
/ 34 new tests / 0 reverts / bisect-clean.

Schema extension files (commit 1):

* `backend/app/schemas/file_format.py` — `DetectionSignalKind` += value;
  new `SubstringInHeadCombine` Literal; new `SubstringInHeadConstraint`
  Pydantic sub-model (5 fields, `extra="forbid"`); `DetectionSignal`
  field + `_check_kind_fields` validator branch; exports updated.
* `backend/app/services/file_format_catalog/resolver.py` —
  `_eval_substring_in_head` evaluator; `_SIGNAL_COST_CLASS` entry;
  `SIGNAL_EVALUATORS` entry.
* `backend/app/services/file_format_catalog/data/file_formats/_system/windows_installer_iso.yaml`
  — adopts new signal (bootmgr / sources/boot.wim / sources\boot.wim
  needles); drops the filename signal that was previously load-bearing
  for extensionless-bootmgr-ISO disambiguation.
* `backend/app/services/format_detection.py` — drops `iso_9660` +
  `windows_installer_iso` from `_CATALOG_NEEDS_DISAMBIGUATION`; deletes
  the ~10-line bootmgr substring upgrade block in `_legacy_bridge_detect`.
* `backend/tests/fixtures/format_parity_corpus/_GENERATE.py` +
  `windows_installer_iso.head` — fixture regenerated with bootmgr at
  offset 0x100 + CD001 at 0x8001 (32774 bytes, same size).
* `backend/tests/test_file_format_parity.py` — drops
  `windows_installer_iso` from `_HEAD_BYTES_INSUFFICIENT`.
* `backend/tests/test_substring_in_head_evaluator.py` — new test file
  (34 tests across positive/negative eval + schema validation + catalog
  round-trip + Rule #46 paired META-CANARIES).

## What Broke

### 1. The Rule #8 rebuild's COPY layer snapshotted MID-EDIT — most source edits MISSED

* **What happened:** the opening Rule #8 rebuild (`docker compose up -d --build backend worker migrator`) ran for ~6 min compiling C extensions (pyesedb). During that window I edited `app/schemas/file_format.py`, `app/services/file_format_catalog/resolver.py`, `app/services/format_detection.py`, and the YAML. BuildKit's COPY layer snapshotted at one moment during the build; only the schema edit (made BEFORE the snapshot) landed in the image. Resolver + format_detection + YAML edits made AFTER the snapshot did NOT land. Subsequent live canary `docker compose exec backend python -c "...substring_in_head..."` failed with `0` matches in resolver.py (`docker compose exec -T backend grep -c "substring_in_head" /app/app/services/file_format_catalog/resolver.py` returned 0).
* **Caught by:** the post-rebuild grep verification step (NOT by the import smoke — the import smoke would have shown a partial failure but I structured the verification to catch it explicitly via grep).
* **Cost:** ~3 min — `docker cp` each missing file in, then `docker compose restart backend worker`, then re-run Rule #11 import smoke.
* **Fix:** `docker cp` per Rule #20 fast-iteration shape; restart backend + worker because the new Pydantic class (`SubstringInHeadConstraint`) is a class-shape change AND the new module-level constants (`_SIGNAL_COST_CLASS` entry, `SIGNAL_EVALUATORS` entry) are cached on first import (Rule #20 exception applies).
* **Infrastructure created:** none — the docker cp + restart is the documented Rule #20 fallback.
* **Generalisation:** when the Rule #8 rebuild runs in parallel with source edits, the COPY snapshot is non-deterministic. Either: (a) wait for the rebuild to complete BEFORE editing; (b) accept that some edits land + others don't, verify via `docker compose exec backend grep -c <token>` per file and `docker cp` the missing ones; (c) edit-first, rebuild-after — sequential ordering avoids the issue. P3.2 used path (c) because the schema changes were authored before the rebuild. This session used path (b) opportunistically (saving ~5 min of idle time). Documented for future sessions.

### 2. The corpus generator failed inside the production container — tests/ excluded by .dockerignore

* **What happened:** initial attempt to regenerate the corpus fixture via `docker compose exec -T -w /app backend uv run python tests/fixtures/format_parity_corpus/_GENERATE.py` failed with `can't open file '/app/tests/fixtures/format_parity_corpus/_GENERATE.py': [Errno 2] No such file or directory`.
* **Caught by:** the immediate `FileNotFoundError` traceback.
* **Cost:** ~2 min — investigated `.dockerignore` to confirm tests are excluded; switched to host `uv run` (which works since the host has the same venv).
* **Fix:** ran the generator on the host: `cd backend && uv run python tests/fixtures/format_parity_corpus/_GENERATE.py`. The fixture file is written to the HOST filesystem (where the test suite reads from); no in-container regeneration needed.
* **Infrastructure created:** none — host-side execution is the existing project pattern.
* **Generalisation:** `backend/.dockerignore` excludes tests/, alembic versions/, .ruff_cache, .planning, docs, *.md, .citadel, .claude per the production-only image policy (commit `b9f438f`, 2026-04-18). Test execution + fixture regeneration ALWAYS uses host-side `uv run` from `backend/`; never `docker compose exec`. The host's `backend/.venv` has the same `uv.lock`-resolved deps as the container.

### 3. Initial baseline pytest invocation against the OLD backend container returned phantom-green 223 passed

* **What happened:** at session-open I ran `docker compose exec -T -w /app backend uv run pytest tests/test_file_format_catalog.py ...` against the still-running "Up 15 hours" backend container — got `223 passed in 4.11s`. After the Rule #8 rebuild, the SAME invocation against the SAME path returned `ERROR: file or directory not found: tests/test_file_format_catalog.py`. Logically impossible if `.dockerignore` was respected in both builds.
* **Caught by:** the post-rebuild attempt failed loudly.
* **Cost:** ~2 min — investigated, never fully resolved, switched to host pytest.
* **Hypothesis:** the previous "Up 15 hours" backend container may have been built from a state where `.dockerignore` didn't exclude tests/, OR was built via a different path (developer override, partial rebuild). The post-Rule #8 rebuild produces a fresh image with the canonical `.dockerignore`. The earlier 223-pass output was real (pytest definitely ran and produced output) but its origin remains unclear.
* **Generalisation:** trust HOST pytest as the canonical test execution surface for wairz; treat container pytest as opportunistic / may-be-cached. The host's `uv run pytest` from `backend/` reads the LIVE source files directly, no caching ambiguity.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|---|---|---|---|
| `DetectionSignal._check_kind_fields` validator | substring_in_head signal without `substring_in_head_constraint` block | structural (1 test case) | Mis-authored operator YAML with empty constraint silently matches no needles |
| `DetectionSignal._check_kind_fields` symmetric-reject branch | `substring_in_head_constraint` set on `kind=filename` (typo / leftover) | structural (1 test case) | Schema-level constraint required for evaluator; symmetric reject prevents stale leftovers |
| `SubstringInHeadConstraint._check_needles` validator | min_count > len(needles_hex) — impossible to satisfy | structural (1 test case) | Operator authoring a constraint that can NEVER fire |
| `SubstringInHeadConstraint._check_needles` validator | Odd-length hex, sub-2-byte needles, over-64-byte needles, invalid hex chars | structural (4 test cases) | Operator-supplied invalid needles produce silent runtime ValueError in `bytes.fromhex()`; pre-validation rejects with actionable messages |
| `extra="forbid"` on `SubstringInHeadConstraint` | Unknown field on the constraint model | structural (1 test case) | Operator typos in YAML field names produce loud validation errors |
| Pre-existing `test_meta_canary_signal_evaluators_exhaustive` | The added `substring_in_head` value MUST have a `SIGNAL_EVALUATORS` entry | structural | "Added Literal value but forgot to wire the evaluator" failure mode — pytest fails immediately |
| NEW `test_meta_canary_signal_cost_class_exhaustive` (Rule #46 hygiene fixup) | The added Literal value MUST have a `_SIGNAL_COST_CLASS` entry | structural | "Added Literal value but forgot to assign a cost class" — resolver silently falls back to cost 99 (evaluated LAST), perf regression invisible without this canary |
| NEW paired gate-canaries for SIGNAL_EVALUATORS / _SIGNAL_COST_CLASS / DISPATCH_EVALUATORS exhaustives | Synthetic "missing entry" dict — exhaustive assertion would reject | structural (3 paired canaries) | Rule #46 §gate-canary-requirement closes — without paired canaries the exhaustives are silent-pass risks |
| Rule #46 anti-hardcode META-CANARY for `_eval_substring_in_head` | AST-walks evaluator body; rejects format-specific byte literals | structural | Future commit adding `if b"bootmgr" in head` shortcut would be caught at the schema-level discipline boundary |
| Rule #46 anti-hardcode paired gate-canary | Synthesizes hostile `_eval_substring_in_head` with `b"bootmgr"` hardcoded; asserts gate REJECTS | structural | Confirms the anti-hardcode AST walker actually fires on the violation it's designed to catch |
| Pre-shipping pytest sweep (433/434 across 12 test files) | Regressions from each new code surface | 433 distinct assertions | Schema + evaluator + YAML adoption + bridge cleanup all green |
| Rule #11 post-Rule #20-restart import smoke | All new symbols importable + exhaustive checks pass at runtime | 1 invocation | Class-shape change (new Pydantic model + cached singletons) would have failed silently on first request without the restart |
| Rule #35b live canary (in-container `detect_format` round-trip) | bootmgr-bearing ISO → `windows_installer_iso`; bare CD001 → `iso_9660`; bridge code mentions no ISO_9660 references | 4 distinct probes | Mock unit tests verify dispatch; the live canary verifies the actual value flow through the running backend's wired-in catalog snapshot |
| Catalog `last_warning` after load | `None` — no schema rejections on the new YAML adoption | 1 check | Mis-authored YAML at load time would have set `last_warning` to a non-None message; clean confirms the operator-facing experience |

## Scope Analysis

* **Planned (per session-open lane scope):** ~250 net LOC + tests; ~9 files; Rule #25 Shape-1 single-slice atomic commit.
* **Built:** 1 schema extension commit + 1 chore SHA pin = 2 commits; **+789 net** across 10 files (8 modified + 1 new test file + ADAPTIVE_BACKLOG.md). Higher than the 250-net estimate because: (a) the comprehensive META-CANARY discipline (4 paired gate-canaries + 2 anti-hardcode AST tests + 12 schema-validator tests) ran to ~570 LOC of new test code vs the ~150-LOC estimate; (b) the `SubstringInHeadConstraint` Pydantic sub-model with the 5-field schema + needle-validator + min_count cross-check ran to ~120 LOC vs the 60-LOC estimate.
* **Drift:** **None.** Single session, single atomic commit (per Rule #25 Shape-1 single-slice exception #2 — cross-stack alignment), 0 reverts, 0 mid-session scope expansion.

## Patterns

1. **HIGH P3.x deferrals close per the prior session's contract — no scout dispatch when shape + scope are already clear.** P3.2 postmortem Rec #2 + Rec #3 described the schema extension shape, the bridge cleanup target, AND the Rule #25 Shape-1 alignment pattern. No design ambiguity remained. Direct ship per `backlog-sweep-2026-05-19` Pattern #1 — Rule-of-Two now (backlog-sweep precedent + this session).

2. **Sub-model + symmetric-reject + extra='forbid' is the durable signal-kind extension shape.** Both the prior P3.2.b `TextFormatConstraint` and this session's `SubstringInHeadConstraint` follow the IDENTICAL 4-element pattern: (1) `extra="forbid"` Pydantic sub-model with closed-Literal sub-fields; (2) `DetectionSignal.<kind>_constraint: Constraint | None` field; (3) `DetectionSignal._check_kind_fields` validator branch (required-when-kind + symmetric-reject); (4) evaluator at `_eval_<kind>` consuming ONLY the constraint's declared fields (Rule #46 anti-hardcode AST canary enforces). Rule-of-Two now for the signal-kind extension recipe (text_format + substring_in_head). Promotable to a `.mex/patterns/add-signal-kind.md` recipe at Rule-of-Three.

3. **Rule #46 §gate-canary-requirement hygiene fixups land naturally as part of the next signal-kind extension.** This session added 4 paired gate-canaries (SIGNAL_EVALUATORS, _SIGNAL_COST_CLASS, DISPATCH_EVALUATORS — pre-existing exhaustives without paired canaries; plus the anti-hardcode AST canary for the new `_eval_substring_in_head`). The session ALSO added the EXHAUSTIVE canary for `_SIGNAL_COST_CLASS` that was missing entirely. When extending a dispatch table, sweep adjacent dispatch tables for missing exhaustives + missing paired canaries — they cluster.

4. **Rule #25 Shape-1 single-slice exception #2 stays the right shape for signal-kind extensions.** Splitting the schema + resolver + YAML + bridge cleanup into 4 commits would have left the exhaustive META-CANARIES RED between commits (schema adds Literal value before SIGNAL_EVALUATORS gets entry → exhaustive fails). Per Rule #25 single-slice exception #2 (cross-stack alignment commits), the multi-surface change ships atomically. Rule-of-Eleven now (Rule #25 Rule-of-Nine + P3.2 baseline + this session).

5. **Direct-push per-piece cadence + 0 reverts continues.** P3.1 + P3.2 + post-P3.2 backlog sweep + this session = 32+ commits across 4 sessions, 0 reverts, all bisect-clean. The cadence is durable.

6. **Test infrastructure executes on host, NOT in production container.** Wairz's `backend/.dockerignore` excludes `tests/` from the production image. Test fixtures regenerate via `cd backend && uv run python tests/fixtures/.../_GENERATE.py` (host); pytest runs via `cd backend && uv run pytest tests/...` (host). The `docker compose exec` path is OPPORTUNISTIC and may fail if `.dockerignore` cycles caught up. Documented for future sessions.

7. **`docker cp` + `restart` per Rule #20 exception is the right fallback when a parallel rebuild snapshots mid-edit.** Class-shape changes (new Pydantic model + new module-level constant entry) require a restart to bust cached singletons. Rule #20's exception clause covered this exactly. The rebuild that was running in parallel ended up cached deps PLUS old code; a follow-on small rebuild + restart is the corrective shape. For future sessions: prefer edit-first / rebuild-after sequential ordering OR be prepared to docker cp the deltas.

## Recommendations

1. **`Refinement.stem_category_map` schema extension** (P3.2 postmortem Rec #3, deferred). Today's `qcom_mbn.yaml` relies on the legacy `_category_from_qcom_name()` Python function to refine `other` category to `tee` / `modem` / etc. per stem. New schema field `refinement.stem_category_map: dict[str, str]` + `_apply_stem_category_refinement()` helper. Operator ships per-vendor stem maps without core changes. Next-session priority HIGH (single-session feasible per the same Rule #25 Shape-1 pattern).

2. **arq worker `on_startup` plugin registration** (P3.2 postmortem Rec #6, deferred). Today the worker process imports the catalog via `app.workers.unpack_common` but doesn't register plugins through the FastAPI lifespan; worker's RTOS classification falls back to legacy `detect_rtos`. Wire `WorkerSettings.on_startup` hook. Low-friction; ~30 LOC + restart-survival test.

3. **TI-TXT YAML + `block_header` Literal value** (P3.2 postmortem Rec #4, deferred — pairs with chip_family TI C28x walker integration). Defer until the chip_family walker lands.

4. **Per-family RTOS YAMLs in `_system/`** (P3.2 postmortem Rec #5, deferred). Today rtos_dispatch.yaml's `dispatch.cases` point at format_ids that DON'T exist as separate manifests; A3 silently skips them. Ship `_system/zephyr_elf.yaml` + 8 siblings. Net-additive YAMLs; no schema changes.

5. **`.mex/patterns/add-signal-kind.md` recipe** — at Rule-of-Three (next signal-kind extension), promote the sub-model + symmetric-reject + extra='forbid' + Rule #46 paired-canary pattern to a `.mex/patterns/` recipe. Current Rule-of-Two evidence: P3.2.b `TextFormatConstraint` + 2026-05-20 `SubstringInHeadConstraint`.

6. **Eliminate the 8 pre-existing UP037 violations in `app/schemas/file_format.py`** via `from __future__ import annotations` (single-line change at the top of the file; removes all 9 UP037 instances including the one this session added). Mechanically clean lint hygiene; deferred as out-of-scope for this session per Rule #25 minimum-scope discipline.

7. **`make_live_db()` FK breakage** (ADAPTIVE_BACKLOG.md `morning:RvwC-make_live_db-FK` MEDIUM, still pending). 3 tests in `test_hardware_firmware_router.py` blocked + 1 in `test_rate_limit_tiers.py`. Find via `pytest -k Canary --tb=line` sweep. Pre-existing failure surface; not introduced this session but worth flagging because it tripped the broader-sweep pytest run today.

## Numbers

| Metric | Value |
|---|---:|
| Commits | 2 (dcebd1c..52bce07) |
| Files changed (cumulative) | 10 (9 in commit 1 + 1 in commit 2) |
| Insertions | 821 |
| Deletions | 32 |
| Net | +789 |
| Reverts | 0 (bisect-clean) |
| Tests added | 34 (in 1 new test file) |
| Schema additions | 1 closed-Literal value (`substring_in_head`) + 1 closed-Literal (`SubstringInHeadCombine`) + 1 Pydantic sub-model (`SubstringInHeadConstraint`) + 1 DetectionSignal field + 1 validator branch |
| Resolver additions | 1 evaluator (`_eval_substring_in_head`) + 1 `_SIGNAL_COST_CLASS` entry + 1 `SIGNAL_EVALUATORS` entry |
| YAML adoptions | 1 (`_system/windows_installer_iso.yaml`) |
| Bridge cleanups | 2 (`_CATALOG_NEEDS_DISAMBIGUATION` -= 2; `_legacy_bridge_detect` bootmgr block deleted) |
| Corpus fixture changes | 1 (`windows_installer_iso.head` regenerated with bootmgr at 0x100) |
| Parity test sets shrunk | 1 (`_HEAD_BYTES_INSUFFICIENT` -= 1) |
| New Rule #46 paired META-CANARIES | 4 (SIGNAL_EVALUATORS + _SIGNAL_COST_CLASS + DISPATCH_EVALUATORS exhaustives + anti-hardcode AST) |
| NEW exhaustive canaries added (Rule #46 §exhaustive-coverage) | 1 (`_SIGNAL_COST_CLASS` vs `DetectionSignalKind`) |
| In-scope pytest sweep | 433/434 (1 skipped pre-existing) |
| Broader-sweep pre-existing failures (NOT introduced) | 3 (2 PE-signatures FK from make_live_db FK breakage; 1 rate-limit dynamic test) |
| Rule #11 import smoke | PASS |
| Rule #35b live canary against running backend | PASS (bootmgr-ISO → windows_installer_iso; bare ISO → iso_9660) |
| Catalog `last_warning` after YAML adoption | `None` (no schema rejections) |
| Rework cycles | 3 (rebuild snapshot-mid-edit; in-container corpus regen blocked; phantom-green prior pytest invocation — all caught in <5 min total) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Adversarial scouts dispatched | 0 (per backlog-sweep Pattern #1 — clear contract from prior session's review) |
| Wave-1 / Wave-2 methodology | NOT applied (Rule #52 closed-grammar discipline already validated; pattern reuse from P3.2.b) |
| Rule #21 cross-scaffold sync | 1 (ADAPTIVE_BACKLOG.md row + last-updated bump bundled in commit 1; SHA pinned in commit 2) |

---HANDOFF---
- Postmortem: substring-in-head-signal-2026-05-20
- Document: .planning/postmortems/postmortem-substring-in-head-signal-2026-05-20.md
- Failures documented: 3 (all caught + resolved in <5 min each)
- Safety catches: 13
- Recommendations: 7
- Commits: dcebd1c..52bce07 (2 commits)
- P3.x items remaining (still queued from P3.2 deferrals):
  * Refinement.stem_category_map (qcom_mbn closure) — HIGH next-session
  * arq worker on_startup plugin registration — MEDIUM
  * Per-family RTOS YAMLs in _system/ — MEDIUM
  * TI-TXT YAML + block_header Literal (paired with chip_family walker) — MEDIUM
- New Rule #46 hygiene debt CLEARED: 4 paired gate-canaries added; 1 new exhaustive canary added.
---

Run `/citadel:learn substring-in-head-signal-2026-05-20` to extract patterns into the knowledge base.
