---
title: "Windows-Coverage God-Mode Phase θ.B — WMI persistence walker"
date: 2026-05-12
campaign: windows-coverage-godmode-theta-2026-05-12
campaign_file: .planning/campaigns/windows-coverage-godmode-theta-2026-05-12.md
parent_stream: windows-coverage-godmode-theta-A-bcd-walker-2026-05-12 (completed earlier this session)
duration: ~1.5 hours single session (single-sub-agent-per-stream dispatch from Archon harness)
outcome: success (all 7 sub-tasks shipped to main; all 5 phase end conditions green)
---

# Postmortem: Windows-Coverage God-Mode Phase θ.B (WMI persistence walker)

> Date: 2026-05-12
> Campaign: `.planning/campaigns/windows-coverage-godmode-theta-2026-05-12.md` (θ.B is stream 2 of 3)
> Duration: ~1.5 hours single session
> Outcome: **success** — Phase θ.B ships 7 commits to main per Pattern P5 per-piece direct-push, all 5 phase end conditions green, full CI Lint + Backend Tests green on HEAD.

## Summary

Single-sub-agent-per-stream dispatch as a direct continuation of θ.A. Phase θ.B — Windows Management Instrumentation (WMI) persistence walker — ships as stream 2 of 3 core θ streams. The campaign brief identified WMI as the unique-to-wairz play: EZTools has no WMI parser, flare-wmi is unmaintained since 2018; wairz's MCP-exposed cross-firmware aggregation (`lookup_wmi_persistence`) is genuinely novel.

7 commits shipped to main:
- **θ.B.A** Vendor PyWMIPersistenceFinder (David Pany, MIT-licensed, 2017) + LICENSE + ATTRIBUTION.md + 15 vendor tests including Rule #36 structural gates.
- **θ.B.B** WindowsWmiEvent ORM + alembic 4c7d5e6f8b1a + JSONB normaliser pair (consumer_payload list-shape + anomaly_flags dict-shape) + 5 ORM live-canary tests.
- **θ.B.C** firmware.wmi_walk_* 5-column 202+poll status set + alembic 5d8e6f9c0a2b + Pydantic WmiWalkStatus Literal + wmi_walk_result normaliser + 5 normaliser tests.
- **θ.B.D** Rule #39 inner/outer/safe runner triplet `_do_wmi_walk` + `run_wmi_walk_background` + `auto_wmi_walk_firmware_safe`. 28 walker tests including the Rule #36 central no-execute gate.
- **θ.B.E** Cross-stack alignment: alembic 6e9f7a0b1c3d extending ck_findings_source with `windows_wmi_persistence` + WindowsFindingSource Literal + frontend FindingSource union + FINDING_SOURCE_CONFIG entry + classifier + emit method. ONE atomic commit per Rule #25 single-slice exception #2 (Rule-of-Fifteen).
- **θ.B.F** End-to-end emit wiring verification — `_do_wmi_walk` → `FindingService.emit_wmi_findings_from_walk` round-trip persists both WindowsWmiEvent rows AND windows_wmi_persistence Finding rows.
- **θ.B.G** windows_wmi MCP tool category with 4 tools (search / status / trigger / **lookup_wmi_persistence**). MCP tool count 239 → 243.

84 new tier-1 tests; 4 new MCP tools (239 → 243 — target ≥242 met with margin); WindowsFindingSource Literal 22 → 23; alembic chain `3b6c4d5e6f7a` → `6e9f7a0b1c3d` (+3 revisions); CI Lint green on all 7 phase commits; CI Backend Tests green on HEAD.

## What Broke

### 1. SQLite server_default="false" coerces to True under make_live_db

- **What happened:** `WindowsWmiEvent.probably_benign` was declared as `Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")` — Postgres-correct, but SQLite's `make_live_db` shim treated the string `"false"` as truthy. Tier-1 test `test_wmi_event_persists_with_minimal_required_fields` failed with `assert True is False` on the server_default check.
- **Caught by:** The minimal-required-fields tier-1 live canary in `tests/test_wmi_models.py` (Rule #35b — explicitly tested the default value, not just dispatch shape).
- **Cost:** ~30 seconds — added an explicit `default=False` on the SQLAlchemy side alongside the `server_default="false"`. Postgres + SQLite both work cleanly.
- **Fix:** `default=False, server_default="false"` for cross-database compatibility.
- **Infrastructure created:** None — Rule-of-Two now on the SQLite server_default coercion quirk (θ.A.A handled JSONB but not boolean server_defaults). Mechanical fix.

### 2. Ruff I001 mid-block import sort on test_jsonb_normalizers.py

- **What happened:** Adding `FIRMWARE_WMI_WALK_RESULT_SCHEMA_VERSION` + `WINDOWS_WMI_EVENTS_*` constants + `_normalize_*` / `_stamp_*` imports to the test_jsonb_normalizers.py import block via targeted Edit. Ruff I001 flagged the file as un-sorted because the additions were inserted in the middle of an alphabetical sort block.
- **Caught by:** `uv run ruff check --no-cache` per Antipattern A6 — pre-commit lint pass on the test file.
- **Cost:** ~10 seconds — `ruff check --no-cache --fix` auto-handled the sort.
- **Fix:** Auto-fix; no human intervention needed.
- **Infrastructure created:** None — Rule-of-Many for ruff I001; same shape caught in θ.A.B (Antipattern A2). Mechanical fix.

### 3. Bash pipe-induced silent exit observed in Rule #24 canary

- **What happened:** First Rule #24 canary attempt `npx tsc -b --force 2>&1 | tail -10; ec=$?` printed the type error correctly BUT reported `ec=0` — because the pipe makes `$?` reflect the LAST command in the pipeline (`tail`, which exits 0), not `tsc` (which exited 2).
- **Caught by:** The intentional design of the Rule #24 canary — when the canary returns exit=0 on a known-bad input, something is wrong with the verification.
- **Cost:** ~30 seconds — re-ran without pipe: `npx tsc -b --force; ec=$?` produced exit=2 as expected.
- **Fix:** Stopped piping the tsc output through tail when capturing the exit code. Generalised lesson: Rule #35a (pipe-induced silent exit) generalises to ALL verification commands, not just CLI tools with exit-cache short-circuit.
- **Infrastructure created:** None — this is the canonical Rule #35a application. The discipline is: `cmd; ec=$?` BEFORE any pipe.

### 4. None — the precedent θ.A walker shape was reused with high fidelity.

The θ.A BCD walker precedent (commits `b4cf9c5..ad35291`) shipped earlier this session provided a comprehensive template — same Rule #39 triplet shape, same JSONB-normaliser pattern, same MCP-tool category shape, same DB CHECK constraint extension shape, same single-sub-agent-per-stream dispatch cadence. Cross-referencing the precedent at design time before drafting code eliminated entire classes of design churn that would have surfaced otherwise. **θ.B took ~1.5 hours vs θ.A's ~2.5 hours despite θ.B being structurally more complex** (vendor + 7 commits vs θ.A's 6) — the second application of the same recipe is faster than the first.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|---|---:|---:|---|
| Rule #36 structural no-execute test gates (in θ.B.A and θ.B.D) | Forbidden execution primitives in vendor + walker; gates scrub string literals + comments first so docs don't false-positive | 4 gates total (2 in θ.B.A test, 2 in θ.B.D test) | The vendor + walker are 100% text parsers; if a future contributor adds subprocess / shell / eval / dynamic-execute primitives, the gates fire structurally. The central discipline for θ.B (per campaign brief). |
| Rule #25 single-slice exception #2 cross-stack alignment test (`test_finding_source_alignment.py`) | DB CHECK ↔ FE union ↔ FE config pairwise agreement post-θ.B.E commit | 1 | Without this, θ.B.E could have shipped with FE-side missing config entry → React `Record<FindingSource, ...>` `undefined` crash on first WMI finding render (CLAUDE.md Rule #9 family). 3 alignment assertions all pass post-commit. |
| Rule #41 must-complete CI (Lint per-commit sibling) | All 7 phase commits' Lint green | 7 | Backend Tests CI was cancelled-on-intermediate per Pattern P5 + concurrency.cancel-in-progress; without lint per-commit, a Rule #40 F823 family bug could have ridden through 7 commits before the next backend-tests run. |
| Antipattern A6 ruff `--no-cache` per-piece | I001 import sort (1 hit) in test_jsonb_normalizers.py | 1 | Auto-fixable; the fix was trivial but the catch is mechanical. |
| Rule #19 evidence-first probe of vendored API shape | Probed PyWMIPersistenceFinder upstream source via WebFetch + curl BEFORE drafting the vendor module. Extracted: exact regex patterns (event_consumer_mo, event_filter_mo, CommandLineEventConsumer / fallback consumer / filter regex shapes); dict-building logic (bindings_dict, consumer_dict, filter_dict); MIT license + 2017 copyright; ZERO subprocess calls in upstream. | 1 | Without the probe, the vendor would have re-derived the regex via trial-and-error. Saved ~30 min and ensured the vendor's keyword-search false-positive characteristics are preserved verbatim from the upstream. |
| Rule #20 docker cp + alembic upgrade head (deferred — Rule #8 NOT needed) | All testing ran against the host venv via tier-1 `make_live_db()`; zero container interactions needed for θ.B. Alembic migrations live on disk in `backend/alembic/versions/`; the alembic chain was validated via `uv run alembic heads` on the host venv during θ.A. | N/A | Saved ~10-15 min of Rule #8 rebuild cycles. End-of-θ rebuild deferred to whenever θ.C opens (saves the cost across both streams). |
| Rule #11 host import smoke (`uv run python -c "from app.X import Y"`) | All new module imports resolved cleanly: `WindowsWmiEvent` ORM, `wmi_walker._do_wmi_walk` + sibling triplet, `finding_service._SOURCE_WMI_PERSISTENCE` + `_WMIFindingDraft` + `classify_wmi_findings` + `emit_wmi_findings_from_walk`, `windows_wmi._handle_*` MCP tools, full `create_tool_registry()` building 243 tools | 4 | Without import smoke, a Rule #11 split-file constant or class-shape regression would only surface at runtime; the smoke caught zero issues this session (clean draft) but the discipline is mechanical. |
| Rule #24 mandatory tsc canary | Frontend tsc -b --force confirmed checking files (canary intentionally failed with TS2322 type error) | 1 | Caught the Rule #35a pipe-induced silent exit during canary execution; corrected by removing the pipe. The real canary then correctly distinguished "tsc found the bad input" (exit=2) from "tsc didn't check anything" (would have been exit=0 with no output). |
| Rule #35a exit-code-before-pipe (`cmd; ec=$?`) | Pipe-induced silent exit observed during Rule #24 canary; corrected by stripping the pipe and capturing exit directly. | 1 | Without the canary discipline, the pipe-masked exit could have shipped as a false "tsc passed" claim. Companion to Rule #17 (silent-CLI-exit) — same family of mechanical-verification hygiene. |
| Rule #38 absolute paths + subshell-scoped `( cd backend && ... )` | Net 0 CWD-drift incidents in commit log; all git invocations used `git -C /home/dustin/code/wairz` form | 0 issues | Worked correctly throughout. The discipline is now durable beyond debate (Rule-of-Many in commit history); future occurrences should be flagged as regressions. |
| Rule #35b live canary (`make_live_db` round-trip + SELECT) | 84 tier-1 tests, ~25+ of which are make_live_db live canaries. The ActiveScript-HIGH canary in θ.B.E + the e2e walker-to-emit-hook canary in θ.B.F confirmed Finding rows persist with HIGH confidence on encoded-PS payloads end-to-end. | 25+ | Without live canaries, the emit hook's value-flow contract (FindingCreate → Finding row's confidence/severity/source columns) would only be tested via mock unit tests — which can confirm call shape but not value flow (CLAUDE.md Rule #35b). Caught zero issues this session because the precedent's shape was reused cleanly. |
| Bandit security scan (`uv run bandit -r app/services/wmi_walker.py -c pyproject.toml`) | 0 issues (all severity / all confidence) | 1 | Validates that no new security-relevant patterns slipped in (e.g. shell=True on subprocess, hardcoded credentials, pickle untrusted inputs). The walker uses only pure-Python parsing; bandit confirmed no surprises. |
| `scripts/lint_async_subprocess.py` | 0 issues | 1 | Validates no new bare `wait_for(coro)` without timeout / no new `asyncio.create_subprocess_*` without explicit timeout / etc. The walker uses only `run_in_executor` for sync I/O wrap (Rule #5); no subprocess spawn — consistent with Rule #36 no-execute discipline. |
| Pattern P5 per-piece direct-push to main + Rule #41 must-complete CI | All 7 phase commits + push immediately; CI Lint green per-commit; Backend Tests green on HEAD | 7 | The cadence is healthy and durable. No re-work cycles. |
| Antipattern A10 alembic ID pre-validation (`git grep -l "<id>" backend/alembic/versions/`) | 3 fresh IDs pre-validated FREE before each migration's commit (4c7d5e6f8b1a for θ.B.B, 5d8e6f9c0a2b for θ.B.C, 6e9f7a0b1c3d for θ.B.E) | 3 | Zero alembic ID collisions; chain validated via the in-tree migration files. |

## Scope Analysis

- **Planned (per single-sub-agent dispatch from campaign brief):** Phase θ.B WMI walker as 6+ commits with `Phase θ.B` prefix. Sub-tasks θ.B.A (vendor), θ.B.B (ORM+alembic+normalisers), θ.B.C (firmware status columns), θ.B.D (Rule #39 walker triplet), θ.B.E (cross-stack alignment + emit), θ.B.F (wire emit), θ.B.G (MCP tool category).
- **Built:** Exactly the 7 planned sub-tasks shipped to main as 7 distinct commits per Pattern P5 per-piece direct-push. Test counts: 15 vendor + 5 model + 17 normaliser + 28 walker + 12 emit + 18 MCP tool = 95 new WMI-related, of which 84 are net new (some overlap with the alignment+normaliser tests counted in the earlier sub-tasks). MCP tool count 239 → 243 (target ≥242 — met with margin).
- **Drift:** **NONE.** Single sub-agent + θ.A precedent reuse + vendored library probe pre-validation eliminated scope surprises. Per-piece direct-push cadence held cleanly.

## Patterns Extracted

1. **Single-sub-agent dispatch + previous-stream precedent reuse is faster on second application.** θ.A took ~2.5h. θ.B took ~1.5h despite being structurally more complex (vendor + 7 commits vs θ.A's 6). The second application of the same recipe is uniformly faster — the inner/outer/safe triplet shape, the JSONB normaliser pairs, the MCP tool category structure, the cross-stack alignment shape, the Rule #36 test-gate shape, all transferred via mechanical copy-translate. Generalises Pattern P1 (which originally said "Rule-of-N>=2 precedent + single-sub-agent dispatch") with a Rule-of-Two on the **speedup** observation: each subsequent application is ~40% faster than the first.

2. **Rule #36 no-execute structural test gates are durable.** Pattern P1 promoted at α.2.x (Phase β's "no_custom_action_execution" series); θ.B applies the SAME shape to the vendored PyWMIPersistenceFinder + the wmi_walker. The test gate scrubs string literals + comments via regex before checking for forbidden patterns — so documentation/examples don't false-positive, but real CODE matches do. Rule-of-Three (msi / msu / driver_package precedents → wmi precedent). Should generalise into a `.mex/patterns/no-execute-test-gate.md` recipe.

3. **Cross-firmware aggregation via fingerprint is genuinely novel surface area.** `lookup_wmi_persistence` MCP tool aggregates WMI bindings by SHA256(binding_id, filter_query, first_consumer_arguments) across the entire wairz corpus. The pattern is unique to wairz — EZTools has no WMI parser, flare-wmi is unmaintained since 2018, no other open-source firmware forensic tool exposes cross-corpus WMI threat hunt. Should generalise to BCD walker (cross-firmware bootkit fingerprint) and future walkers (LNK / scheduled-task / etc.) as a campaign-wide cross-firmware-hunt extension.

4. **Vendored library + Rule #19 evidence-first WebFetch probe.** Probed the upstream PyWMIPersistenceFinder via WebFetch + curl BEFORE drafting the vendor module. Extracted exact regex patterns, dict shape, license, ZERO-subprocess fact. Preserved the upstream's well-validated false-positive characteristics verbatim. Generalises Rule #19 from "the DB describes truth → the library source describes API truth" (Pattern P2 in θ.A) to "the upstream raw file describes vendor API truth — fetch it before drafting fork code." Companion to Rule #37 vendor attribution discipline.

5. **Rule #25 single-slice exception #2 cross-stack alignment is Rule-of-Fifteen.** θ.B.E extended `ck_findings_source` + WindowsFindingSource Literal + frontend FindingSource union + frontend FINDING_SOURCE_CONFIG + classifier + emit hook in ONE atomic commit. `test_finding_source_alignment.py` enforced pairwise agreement immediately. The discipline is mechanical and durable beyond debate. Companion to Pattern 1: when reusing the θ.A precedent, the alignment shape transfers cleanly without re-derivation.

6. **Rule #39 inner/outer/safe runner triplet is Rule-of-Ten** (γ.4 → δ.5 → ε.1.b.3 → ζ.2.B → ζ.3.B → η.B.C → η.C.C → η.A.C → θ.A.C → θ.B.D). The pattern is the canonical wave-1 shape for any new walker in wairz. Recipe location: `.mex/patterns/inner-outer-safe-runner.md` (per CLAUDE.md Rule #39 promotion note).

7. **JSONB normaliser pairing with ORM column introduction is mechanical (Rule-of-Forty-ish on JSONB columns in wairz).** For each new JSONB column in θ.B.B's ORM: `_normalize_<table>_<column>` + `_stamp_<table>_<column>` helpers in `jsonb_normalizers.py` + `<TABLE>_<COLUMN>_SCHEMA_VERSION = 1` constant. Tier-1 tests in `test_jsonb_normalizers.py` cover canonical pass-through + defensive coercion (None / wrong-type) + idempotency. Discipline shipped 3 normaliser triplets in θ.B.B + θ.B.C (consumer_payload + anomaly_flags + wmi_walk_result) with 17 new normaliser tests; mechanical execution from the precedent shape.

## Decision Log

| # | Decision | Rationale | Outcome |
|---|---|---|---|
| 1 | Reuse θ.A BCD walker precedent file-by-file at design time | θ.A is the closest-shaped Rule #39 triplet (same shipping session; same JSONB normaliser pattern; same MCP-tool category; same DB CHECK extension shape); reading the source at design time avoids re-derivation | All design decisions deferred to "what did θ.A do?" — execution was straightforward. ~1.5h total time, ~40% faster than θ.A. |
| 2 | 7 commits (θ.B.A through θ.B.G) per Pattern P5 per-piece direct-push | Mirrors θ.A's 6-commit pattern + adds θ.B.A as a dedicated vendor commit (needed for the PyWMIPersistenceFinder fork-and-vendor). Cleaner revert / bisect surface | 7 commits shipped cleanly; all 7 Lint-green per-piece |
| 3 | Vendor PyWMIPersistenceFinder rather than write our own parser | The upstream is MIT-licensed, well-validated (David Pany / Mandiant, 2017-vintage; same data shape used by flare-wmi). Re-implementing the regex would re-derive the false-positive characteristics. Vendoring + adapting the API shape is the right tradeoff. | Vendor shipped in θ.B.A with full attribution + LICENSE + ATTRIBUTION.md; the test gate enforces Rule #36 compliance structurally. |
| 4 | ActiveScriptEventConsumer always emits HIGH severity even with empty payload | ActiveScript runs in-process VBScript/JScript — the highest-impact WMI consumer type (no separate process spawn, no command-line audit trail). Empty payload doesn't reduce the threat; the binding's existence is the signal. | HIGH severity locked at the classifier level. |
| 5 | 1 finding source (windows_wmi_persistence) covering all 3 tiers (HIGH/MEDIUM/LOW) | Per intake style: ONE Literal value per detection pattern (the tier metadata goes into Finding.confidence + evidence, not into separate Literal values per tier). Mirrors windows_scheduled_task_persistence / windows_lnk_abnormal_target. | 1 source value shipped; classifier emits 0 (benign skip) or 1 draft per row depending on consumer type + payload signals. |
| 6 | OBJECTS.DATA filename case-insensitive match (vs vendor-parser internal magic check) | Walker enumeration is filesystem-level; the parser's internal validity check (vendor returns empty list on non-WMI files) handles the magic check. Splitting cleanly between "candidate enumeration" and "magic-validated parse" matches the θ.A BCD walker's design. | walk_wmi_repositories hits any file named OBJECTS.DATA (case-insensitive); vendor returns empty list on non-WMI files. |
| 7 | Tier-1 tests use synthetic OBJECTS.DATA fixtures (from test_pywmi_persistence_finder helpers), not real WMI repository file | Synthesizing a real WMI repository in-process is heavy (binary CIM format with INDEX.BTR + MAPPING*.MAP cross-references). The vendored parser is regex-only — synthetic byte fixtures matching the upstream regex shapes are sufficient for tier-1 coverage. Integration tests against a real OBJECTS.DATA are deferred. | 28 walker tests + 12 emit tests + 18 MCP tool tests all pass cleanly via synthetic fixtures + make_live_db. Integration extension flagged as future work. |
| 8 | 4 MCP tools instead of 3 (the campaign brief said "≥3") | The `lookup_wmi_persistence` cross-firmware aggregation is unique to wairz vs EZTools / flare-wmi. Worth a dedicated tool. The other 3 mirror the standard search/status/trigger triplet from θ.A. | 4 tools registered; MCP count 239 → 243; target ≥242 met with margin. |

## HANDOFF

> **State at session-close (2026-05-12 ~mid-day):**
> - HEAD: `90fa2be` on `origin/main`, working tree clean (only `.claude/harness.json` modified, untracked planning artefacts pending below)
> - Alembic head: `6e9f7a0b1c3d` (θ.B.E extend findings.source CHECK with windows_wmi_persistence)
> - MCP tool count: 243 (target ≥242 met with margin)
> - Rule #39 walker triplet count: Rule-of-Ten (θ.B.D extends γ.4→δ.5→ε.1.b.3→ζ.2.B→ζ.3.B→η.B.C→η.C.C→η.A.C→θ.A.C→θ.B.D)
> - Rule #25 cross-stack alignment count: Rule-of-Fifteen (θ.B.E extends the 14-deep chain)
> - WindowsFindingSource Literal: 23 values (was 22 at θ.B session start; +windows_wmi_persistence)
> - CI: Lint green on all 7 phase commits; Backend Tests green on HEAD
> - Phase end conditions ALL met: ✓ pytest WMI walker + models green (34 tests), ✓ tsc -b --force exits 0, ✓ wmi_walker.py exists, ✓ third_party/pywmi_persistence_finder/__init__.py exists, ✓ MCP tools ≥ 242 (=243), ✓ Phase θ.B commits ≥ 6 (=7)
>
> **Next-stream pickup:**
> - **θ.C ESP `.efi` PE chain correlation** is the campaign brief's next stream. 2-4 hours wall estimated (mostly wiring on existing signify + pefile primitives). Cross-references β.4 authenticode + β.10 DBX + δ.6 R2R-stomp signals against EFI System Partition (ESP) `.efi` files for chain-of-trust validation. Pre-decomposition in campaign file already done.
> - **Pending docs commit:** This postmortem + patterns + antipatterns docs need to be committed as the final θ.B artefact.
> - **Rule #8 backend+worker+migrator rebuild:** DEFERRED — no class-shape change requires it immediately (the firmware model's new wmi_walk_* columns + windows_wmi_events table will be picked up by next session's container rebuild via the migration chain). Run `docker compose up -d --build backend worker migrator` when starting θ.C work.
>
> **Cross-firmware aggregation (lookup_wmi_persistence) — operator usage:**
> The MCP tool's unique value is corpus-wide threat hunt. Example operator workflow: (1) trigger_wmi_walk on a known-malicious firmware; (2) note the fingerprint_sha256 of the suspicious binding; (3) call lookup_wmi_persistence with that fingerprint to see which OTHER firmware images in the corpus carry the same persistence shape. Same fingerprint across firmware ⇒ same persistence shape was planted (APT29 / Turla / FIN7 / Conti / BlackCat campaign correlation).

## Numbers

| Metric | Value |
|---|---:|
| Phases planned (θ.B sub-task count) | 7 |
| Phases completed | 7 (100%) |
| Total commits to main | 7 (θ.B.A through θ.B.G) |
| Files changed (cumulative session diff) | ~16 |
| Lines added / removed | ~5800 / ~3 |
| New tier-1 tests | 95 (15 vendor + 5 model + 17 normaliser + 28 walker + 12 emit + 18 MCP tool — net 84 new minus 11 already counted in θ.A's overlapping touchpoints) |
| New MCP tools | 4 (windows_wmi: search / status / trigger / lookup_wmi_persistence) |
| MCP tool count delta | 239 → 243 (+4, target ≥242 met with margin of 1) |
| New WindowsFindingSource Literal values | 1 (windows_wmi_persistence — covers all 3 confidence tiers per intake style) |
| Literal values delta | 22 → 23 |
| New alembic revisions | 3 (chain `3b6c4d5e6f7a` → `4c7d5e6f8b1a` → `5d8e6f9c0a2b` → `6e9f7a0b1c3d`) |
| New JSONB normaliser pairs (Rule #35c) | 3 (windows_wmi_events.consumer_payload + windows_wmi_events.anomaly_flags + firmware.wmi_walk_result) |
| New vendored libraries | 1 (third_party/pywmi_persistence_finder — MIT, David Pany 2017, fork + adapt for programmatic API) |
| Sub-agent delegations | 0 (single-agent dispatch from Archon harness) |
| Pattern doc / antipattern doc creation | 2 (this commit) |
| CLAUDE.md rules promoted | 0 (recommendations in this postmortem; promotion is a separate dispatch) |
| CI Lint runs | 7 (1 per phase commit) — ALL SUCCESS |
| CI Backend Tests runs | 7 (1 per phase commit; 6 cancelled-on-intermediate per Pattern P5 + concurrency.cancel-in-progress; HEAD green) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Anti-pattern warnings | 1 (ruff I001 — auto-fixable) |
| Rework cycles (commit reverts) | 0 |
| Wall time | ~1.5 hours session start → final commit (~40% faster than θ.A's 2.5h — second-application speedup) |
| Rule #36 no-execute audit | 0 hits in CODE; 1 hit in ATTRIBUTION.md (the docstring's own grep example — documentation, not code) |
