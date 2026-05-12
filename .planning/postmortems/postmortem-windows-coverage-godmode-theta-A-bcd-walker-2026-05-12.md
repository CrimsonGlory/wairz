---
title: "Windows-Coverage God-Mode Phase θ.A — BCD store walker"
date: 2026-05-12
campaign: windows-coverage-godmode-theta-2026-05-12
campaign_file: .planning/campaigns/windows-coverage-godmode-theta-2026-05-12.md
parent_campaign: windows-coverage-godmode-eta-2026-05-11 (archived in completed/)
duration: ~2.5 hours single session (single-sub-agent-per-stream dispatch from Archon harness)
outcome: success (all 6 sub-tasks shipped to main; all 5 phase end conditions green)
---

# Postmortem: Windows-Coverage God-Mode Phase θ.A (BCD store walker)

> Date: 2026-05-12
> Campaign: `.planning/campaigns/windows-coverage-godmode-theta-2026-05-12.md` (θ.A is stream 1 of 3)
> Duration: ~2.5 hours single session
> Outcome: **success** — Phase θ.A ships 6 commits to main per Pattern P5 per-piece direct-push, all 5 phase end conditions green, full CI Lint + Backend Tests green on HEAD.

## Summary

Single-sub-agent-per-stream dispatch from the post-η campaign brief. Phase θ.A — Windows Boot Configuration Data (BCD) store walker — ships as the first of 3 core θ streams (θ.A BCD / θ.B WMI / θ.C ESP `.efi` correlation) selected by a 3-scout research-fleet pre-pass (commits `54eca0c` + `8236ff9`). The 3 scouts converged 3/3 HIGH on BCD as the lowest-risk-first stream — `regipy>=4.0,<5` already in pyproject (η.D BYOVD lookup brought it in), regipy's `BCD_HIVE_TYPE='bcd'` + `regipy.plugins.bcd.boot_entry_list.BootEntryListPlugin` provide the canonical traversal shape, zero new deps required.

6 commits shipped to main: θ.A.A ORM + alembic + JSONB normalisers, θ.A.B firmware bcd_walk_* status columns + Pydantic Literal + result normaliser, θ.A.C Rule #39 walker triplet (`_do_bcd_walk` inner + `run_bcd_walk_background` outer + `auto_bcd_walk_firmware_safe` safe), θ.A.D cross-stack alignment (Rule-of-Fourteen — DB CHECK extension + WindowsFindingSource Literal + frontend FindingSource union + FINDING_SOURCE_CONFIG + classifier + emit hook in ONE atomic commit), θ.A.E wiring of the finding emit into both wrappers, θ.A.F windows_bcd MCP tool category (3 tools: search / status / trigger; MCP count 236 → 239).

98 new tier-1 tests; 3 new MCP tools (236 → 239); WindowsFindingSource Literal 20 → 22; alembic chain `a8b9c0d1e2f3` → `3b6c4d5e6f7a` (+3 revisions); CI Lint green on all 6 phase commits; CI Backend Tests green on HEAD (2b462c0).

## What Broke

### 1. Ruff UP031 percent-formatting in BCD walker constants

- **What happened:** First draft of `bcd_walker.py` used `"%08X" % element_type` for the BCD element-type hex rendering (matching the regipy plugin's pattern). Ruff UP031 flagged it as "Use format specifiers instead of percent format" with 4 hits (2 in walker, 1 in test, 1 in mock fixture).
- **Caught by:** `uv run ruff check --no-cache` per Antipattern A6 — pre-commit lint pass on the walker + test files.
- **Cost:** ~1 minute — replaced `"%08X" % type_int` with `f"{type_int:08X}"` at 4 sites + ruff `--no-cache --fix` auto-handled an unrelated I001 import sort.
- **Fix:** Applied f-string conversion; tests re-ran clean. Same shape as the η.A precedent's lint cleanup.
- **Infrastructure created:** None — Rule-of-Many for ruff UP031 (the rule has fired on prior wairz refactors per the lint cleanup phase patterns). Mechanical fix.

### 2. Import-sort I001 on test_jsonb_normalizers.py after adding BCD normaliser imports

- **What happened:** Added `WINDOWS_BCD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION` / `WINDOWS_BCD_ENTRIES_CUSTOM_ELEMENTS_SCHEMA_VERSION` and the matching `_normalize_*` / `_stamp_*` imports to test_jsonb_normalizers.py via targeted Edit. Ruff I001 flagged the file as un-sorted because the additions were inserted in the middle of an alphabetical sort block.
- **Caught by:** `uv run ruff check --no-cache` post-edit on the test file.
- **Cost:** ~10 seconds — `ruff check --no-cache --fix` auto-handled the sort.
- **Fix:** Auto-fix; no human intervention needed.
- **Infrastructure created:** None — Rule-of-Many; ruff handles this mechanically.

### 3. None — the precedent η.A walker shape was reused with high fidelity.

The η.A NTFS-MFT walker precedent (commits `ad5f0fa..9baefd9`) provided a comprehensive template — same Rule #39 triplet shape, same JSONB-normaliser pattern, same MCP-tool category shape, same DB CHECK constraint extension shape, same single-sub-agent-per-stream dispatch cadence. Cross-referencing the precedent at design time before drafting code eliminated entire classes of design churn that would have surfaced otherwise.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|---|---:|---:|---|
| Rule #25 single-slice exception #2 cross-stack alignment test (`test_finding_source_alignment.py`) | DB CHECK ↔ FE union ↔ FE config pairwise agreement post-θ.A.D commit | 1 | Without this, θ.A.D could have shipped with FE-side missing config entry → React `Record<FindingSource, ...>` `undefined` crash on first BCD finding render (CLAUDE.md Rule #9 family) |
| Rule #41 must-complete CI (Lint per-commit sibling) | All 6 phase commits' Lint green | 6 | Backend Tests CI was cancelled-on-intermediate per Pattern P5 + concurrency.cancel-in-progress; without lint per-commit, a Rule #40 F823 family bug could have ridden through 6 commits before the next backend-tests run |
| Antipattern A6 ruff `--no-cache` per-piece | UP031 percent-formatting (4 hits) + I001 import sort (1 hit) | 2 | Without `--no-cache`, ruff's cache might have masked the nits; the fixes were trivial but the catch is mechanical |
| Rule #19 evidence-first probe of regipy API shape | Discovered `regipy.plugins.bcd.boot_entry_list` exists in tree before drafting walker — saved ~30 min of trial-and-error on the `\Objects\{guid}\Elements\{hex}\Element` traversal | 1 | Without the probe, would have re-discovered the BCD element-type subkey naming via test failures. Pattern: when integrating a library for the first time, `inspect.getsource()` on the canonical use-site (here `BootEntryListPlugin.run()`) shows the exact API shape needed |
| Rule #20 docker cp + alembic upgrade head (deferred — Rule #8 NOT needed) | All testing ran against the host venv via tier-1 `make_live_db()`; zero container interactions needed for θ.A. Alembic migrations live on disk in `backend/alembic/versions/`; the alembic chain was validated via `uv run alembic heads` on the host venv. | N/A | Saved ~10-15 min of Rule #8 rebuild cycles. End-of-stream Rule #8 rebuild deferred to whenever the next stream (θ.B) opens; current stream's verification ran entirely on the host venv. |
| Rule #11 host import smoke (`uv run python -c "from app.X import Y"`) | All new module imports resolved cleanly: `WindowsBcdEntry` ORM, `bcd_walker._do_bcd_walk` + sibling triplet, `finding_service._SOURCE_BCD_*` + `_BCDFindingDraft` + `emit_bcd_findings_from_walk`, `windows_bcd._handle_*` MCP tools | 4 | Without import smoke, a Rule #11 split-file constant or class-shape regression would only surface at runtime; the smoke caught zero issues this session (clean draft) but the discipline is mechanical |
| Rule #24 mandatory tsc canary | Frontend tsc -b --force confirmed checking files (canary intentionally failed with TS2322 type error) | 1 | Without the canary, "tsc exited 0" could have masked tsc-cache or files-empty short-circuit — Rule #17 silent-CLI-exit family |
| Rule #38 absolute paths + subshell-scoped `( cd backend && ... )` | Net 0 CWD-drift incidents in commit log; all git invocations used `git -C /home/dustin/code/wairz` form | 0 issues | Worked correctly throughout. The discipline is now durable beyond debate (Rule-of-Three+ in commit history); future occurrences should be flagged as regressions |
| Rule #35a exit-code-before-pipe (`cmd; ec=$?`) | Exit codes captured cleanly for ruff / pytest / tsc / alembic / bandit / async-subprocess-linter | 8 | Zero pipe-induced false-success exits observed. The discipline is mechanical |
| Rule #35b live canary (`make_live_db` round-trip + SELECT) | 98 tier-1 tests, ~30+ of which are make_live_db live canaries. The bootkit-shape entry round-trip in θ.A.D + θ.A.E confirmed Finding rows persist with HIGH confidence on both source tiers | 30+ | Without live canaries, the emit hook's value-flow contract (FindingCreate → Finding row's confidence/severity/source columns) would only be tested via mock unit tests — which can confirm call shape but not value flow (CLAUDE.md Rule #35b). Caught zero issues this session because the precedent's shape was reused cleanly |
| Bandit security scan (`uv run bandit -r app/ -c pyproject.toml`) | 0 issues (all severity / all confidence) | 1 | Validates that no new security-relevant patterns slipped in (e.g. shell=True on subprocess, hardcoded credentials, pickle untrusted inputs). The discipline is mechanical |
| `scripts/lint_async_subprocess.py` | 0 issues | 1 | Validates no new bare `wait_for(coro)` without timeout / no new `asyncio.create_subprocess_*` without explicit timeout / etc. The walker uses only `run_in_executor` for sync I/O wrap (Rule #5); no subprocess spawn. The discipline is mechanical |
| Pattern P5 per-piece direct-push to main + Rule #41 must-complete CI | All 6 phase commits + push immediately; CI Lint green per-commit; Backend Tests green on HEAD | 6 | The cadence is healthy and durable. No re-work cycles |
| Antipattern A10 alembic ID pre-validation (`git grep -l "<id>" backend/alembic/versions/`) | 3 fresh IDs pre-validated FREE before each migration's commit (1f4a2b3c4d5e for θ.A.A, 2a5b3c4d5e6f for θ.A.B, 3b6c4d5e6f7a for θ.A.D) | 3 | Zero alembic ID collisions; chain validated via `uv run alembic heads` after each migration |

## Scope Analysis

- **Planned (per single-sub-agent dispatch from campaign brief):** Phase θ.A BCD walker as 5-6 commits with `Phase θ.A` prefix. Sub-tasks θ.A.A (ORM+alembic+JSONB normaliser), θ.A.B (firmware status columns), θ.A.C (Rule #39 walker triplet), θ.A.D (cross-stack alignment + finding-emit), θ.A.E (wire emit into auto-walk), θ.A.F (MCP tool category).
- **Built:** Exactly the 6 planned sub-tasks shipped to main as 6 distinct commits per Pattern P5 per-piece direct-push. Test counts: 5 BCD model + 38 walker + 12 emit + 16 MCP tool + 22 JSONB normaliser additions = 93 new BCD-related + 5 alignment-related = 98 net new tests. MCP tool count 236 → 239 (target ≥ 239 — met exactly).
- **Drift:** **NONE.** Single sub-agent + reuse of η.A precedent + 3-scout pre-validation eliminated scope surprises. Per-piece direct-push cadence held cleanly.

## Patterns Extracted

1. **Single-sub-agent dispatch + comprehensive precedent reuse is the goldilocks shape for next-stream walker recipes when a Rule-of-N>=2 precedent exists.** η.A NTFS-MFT walker (5 commits, 32 walker tests) was the closest precedent for θ.A BCD walker. By reading the η.A walker source files end-to-end BEFORE drafting θ.A code, the dispatch eliminated all "what shape should I use" decisions during execution. Total session time: ~2.5h vs estimated 4-6h. Validates the recipe: "if a Rule #39 walker triplet has shipped in the last N=2+ campaigns, single-sub-agent dispatch with explicit precedent-file reading at design time is the right cadence — no Archon orchestration overhead needed."

2. **Rule #19 evidence-first applies to library-API probing, not just data-shape probing.** Before drafting `bcd_walker._extract_entry_fields`, ran `inspect.getsource(regipy.plugins.bcd.boot_entry_list)` to extract the canonical BCD-element traversal shape (`obj_key.get_subkey("Elements", raise_on_missing=False).get_subkey("%08X" % element_type, raise_on_missing=False).get_value("Element")`). Saved ~30 min of trial-and-error and ensured the walker's shape matches the upstream library's documented use-pattern. Generalises Rule #19 from "the DB describes truth" to "the library's source describes the API truth — read it before drafting consumer code."

3. **Single-slice exception #2 cross-stack alignment is now Rule-of-Fourteen.** θ.A.D extended `ck_findings_source` CHECK constraint + WindowsFindingSource Literal + frontend FindingSource union + frontend FINDING_SOURCE_CONFIG + classifier + emit hook in ONE atomic commit. `test_finding_source_alignment.py` enforced pairwise agreement immediately. The discipline is mechanical and durable beyond debate. Companion to Pattern 1: when reusing the η.A precedent, the alignment shape transfers cleanly without re-derivation.

4. **Rule #39 inner/outer/safe runner triplet is Rule-of-Nine** (γ.4 → δ.5 → ε.1.b.3 → ζ.2.B → ζ.3.B → η.B.C → η.C.C → η.A.C → θ.A.C). The pattern is the canonical wave-1 shape for any new walker in wairz. Recipe location: `.mex/patterns/inner-outer-safe-runner.md` (per CLAUDE.md Rule #39 promotion note).

5. **JSONB normaliser pairing with ORM column introduction is mechanical (Rule-of-Forty-ish on JSONB columns in wairz).** For each new JSONB column in θ.A.A's ORM: `_normalize_<table>_<column>` + `_stamp_<table>_<column>` helpers in `jsonb_normalizers.py` + `<TABLE>_<COLUMN>_SCHEMA_VERSION = 1` constant. Tier-1 tests in `test_jsonb_normalizers.py` cover canonical pass-through + defensive coercion (None / wrong-type) + idempotency. Discipline shipped 3 normaliser triplets in θ.A.A + θ.A.B (custom_elements + anomaly_flags + bcd_walk_result) with 22 new tests; mechanical execution from the precedent shape.

6. **Library-shipped plugin source is the highest-fidelity reference for unfamiliar binary-format parsers.** `regipy.plugins.bcd.boot_entry_list.py` (101 LOC) demonstrated exactly the BCD-walk shape wairz needed: GUID-keyed object enumeration + Description/Type discriminator + Elements/hex-type/Element traversal + ApplicationDevice byte-blob parsing for GPT GUIDs. Reading the plugin source provided BOTH the "what to walk" structure and the "how to coerce element values" patterns (UTF-16 LE strings, single-byte bool elements, DWORD-as-LE-bytes ints) that downstream code had to handle defensively. Should generalise into a pattern: "before integrating a new pure-Python parser, look for an upstream plugin or example exercising the same shape; spend 5 minutes reading it before drafting your own consumer."

## Decision Log

| # | Decision | Rationale | Outcome |
|---|---|---|---|
| 1 | Reuse η.A NTFS-MFT walker precedent file-by-file at design time | η.A is the closest-shaped Rule #39 triplet (same dep family — regipy + dissect.ntfs; same JSONB normaliser pattern; same MCP-tool category; same DB CHECK extension); reading the source at design time avoids re-derivation | All design decisions deferred to "what did η.A do?" — execution was straightforward |
| 2 | 6 commits (θ.A.A through θ.A.F) per Pattern P5 per-piece direct-push | Mirrors η.A's 5-commit pattern + adds θ.A.E as a dedicated commit for finding-emit wiring (η.A combined emit into C.E but the campaign brief specified 5-6 commits with separate θ.A.E for the emit wire); cleaner revert / bisect surface | 6 commits shipped cleanly; all 6 Lint-green per-piece |
| 3 | Anomaly classifier (5 substantive flags) + is_default_boot as context | The forensic-triage UX needs both "is this suspicious?" (5 flags) AND "is this the canonical OS entry?" (1 flag). Promoted both to the JSONB column; is_default_boot is excluded from the anomaly_only filter at the MCP layer | Classifier shipped in θ.A.C, emit hook shipped in θ.A.E; default-boot lookup via `_find_default_boot_guid` resolves the bootmgr's DefaultObject element |
| 4 | 2 finding sources (suspicious_path + testsigning_enabled), not 5 (one per anomaly flag) | Per intake style: the tier metadata goes into Finding.confidence/evidence, not into separate Literal values per anomaly. 2 sources covers the 2 mechanically-distinct detection patterns (path-heuristic vs policy-flag); HIGH/MEDIUM tier is heuristic-driven by combinations of the 5 flags | 2 source values shipped; classifier emits 0/1/2 drafts per row depending on flags raised |
| 5 | `BCD` filename case-insensitive match (vs file-magic check at enumeration time) | Walker enumeration is filesystem-level; the magic check belongs at the per-file parse boundary (`looks_like_regf`). Splitting cleanly between "candidate enumeration" and "magic-validated parse" matches the η.A walker's design | walk_bcd_stores hits any file named BCD (case-insensitive); not_regf status emitted if magic check fails |
| 6 | Tier-1 tests use mocked regipy.registry.RegistryHive, not real BCD store fixture | Synthesizing a REGF file in-process is heavy (4 KB header + hbins + cell pointer tracking). Mocking matches the η.A walker's dissect.ntfs.NTFS mock pattern; integration tests against a real BCD store are deferred to a follow-up | 38 walker tests + 12 emit tests + 16 MCP tool tests all pass cleanly via mocks + make_live_db; integration-test extension flagged as future work |
| 7 | MCP tool count target 239 — exactly met (236 + 3 new) | Target from campaign brief end conditions. Mirrors η.A.F's 3 tools (search / status / trigger) | 239 reached exactly; no over-shoot |

## HANDOFF

> **State at session-close (2026-05-12 ~late):**
> - HEAD: `2b462c0` on `origin/main`, working tree clean (only `.claude/harness.json` modified, untracked planning artefacts pending below)
> - Alembic head: `3b6c4d5e6f7a` (θ.A.D extend findings.source CHECK)
> - MCP tool count: 239 (target met)
> - Rule #39 walker triplet count: Rule-of-Nine (θ.A.C extends γ.4→δ.5→ε.1.b.3→ζ.2.B→ζ.3.B→η.B.C→η.C.C→η.A.C→θ.A.C)
> - Rule #25 cross-stack alignment count: Rule-of-Fourteen (θ.A.D extends the 13-deep chain)
> - WindowsFindingSource Literal: 22 values (was 20 at session start; +windows_bcd_suspicious_path + windows_bcd_testsigning_enabled)
> - CI: Lint green on all 6 phase commits; Backend Tests green on HEAD
> - Phase end conditions ALL met: ✓ pytest BCD walker + models green, ✓ tsc -b --force exits 0, ✓ bcd_walker.py exists, ✓ MCP tools ≥ 239 (=239), ✓ Phase θ.A commits ≥ 5 (=6)
>
> **Next-stream pickup:**
> - **θ.B WMI persistence walker** is the campaign brief's next stream. 6-8 hours wall estimated. Vendor-in scaffolding for ~200 LOC PyWMIPersistenceFinder per Rule #36 no-execute discipline. Walker shape: same Rule #39 triplet over OBJECTS.DATA + INDEX.BTR + MAPPING{1,2,3}.MAP. Detection focus: `__EventFilter` + `__EventConsumer` + `__FilterToConsumerBinding` triples. Pre-decomposition in campaign file already done.
> - **θ.C ESP `.efi` PE chain correlation** ships AFTER θ.B (2-4 hours wall, mostly wiring on existing signify + pefile primitives).
> - **Pending docs commit:** This postmortem + patterns + antipatterns docs need to be committed as the final θ.A artefact.
> - **Rule #8 backend+worker+migrator rebuild:** DEFERRED — no class-shape change requires it immediately (the firmware model's new bcd_walk_* columns will be picked up by next session's container rebuild via the migration chain). Run `docker compose up -d --build backend worker migrator` when starting θ.B work.

## Numbers

| Metric | Value |
|---|---:|
| Phases planned (θ.A sub-task count) | 6 |
| Phases completed | 6 (100%) |
| Total commits to main | 6 (θ.A.A through θ.A.F) |
| Files changed (cumulative session diff) | ~14 |
| Lines added / removed | ~5400 / ~10 |
| New tier-1 tests | 98 (5 model + 38 walker + 12 emit + 16 MCP tool + 22 JSONB normaliser + 5 alignment validations) |
| New MCP tools | 3 (windows_bcd: search / status / trigger) |
| MCP tool count delta | 236 → 239 (+3, target ≥ 239 met) |
| New WindowsFindingSource Literal values | 2 (windows_bcd_suspicious_path + windows_bcd_testsigning_enabled) |
| Literal values delta | 20 → 22 |
| New alembic revisions | 3 (chain `a8b9c0d1e2f3` → `1f4a2b3c4d5e` → `2a5b3c4d5e6f` → `3b6c4d5e6f7a`) |
| New JSONB normaliser pairs (Rule #35c) | 3 (windows_bcd_entries.custom_elements + windows_bcd_entries.anomaly_flags + firmware.bcd_walk_result) |
| Sub-agent delegations | 0 (single-agent dispatch from Archon harness) |
| Pattern doc / antipattern doc creation | 2 (this commit) |
| CLAUDE.md rules promoted | 0 (recommendations in this postmortem; promotion is a separate dispatch) |
| CI Lint runs | 6 (1 per phase commit) — ALL SUCCESS |
| CI Backend Tests runs | 6 (1 per phase commit; 5 cancelled-on-intermediate per Pattern P5 + concurrency.cancel-in-progress; HEAD green) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Anti-pattern warnings | 2 (ruff UP031 + I001 — auto-fixable) |
| Rework cycles (commit reverts) | 0 |
| Wall time | ~2.5 hours session start → final commit |
