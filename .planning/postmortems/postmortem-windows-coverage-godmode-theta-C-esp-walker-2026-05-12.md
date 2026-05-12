---
title: "Windows-Coverage God-Mode Phase θ.C — ESP `.efi` PE chain walker"
date: 2026-05-12
campaign: windows-coverage-godmode-theta-2026-05-12
campaign_file: .planning/campaigns/windows-coverage-godmode-theta-2026-05-12.md
parent_stream: windows-coverage-godmode-theta-B-wmi-walker-2026-05-12 (completed earlier this session)
duration: ~1 hour single session (single-sub-agent-per-stream dispatch from Archon harness)
outcome: success (all 5 sub-tasks shipped to main; all 5 phase end conditions green)
---

# Postmortem: Windows-Coverage God-Mode Phase θ.C (ESP `.efi` PE chain walker)

> Date: 2026-05-12
> Campaign: `.planning/campaigns/windows-coverage-godmode-theta-2026-05-12.md` (θ.C is stream 3 of 3)
> Duration: ~1 hour single session
> Outcome: **success** — Phase θ.C ships 5 commits to main per Pattern P5 per-piece direct-push, all 5 phase end conditions green, full CI Lint green on the first 4 commits (5th in_progress at session-close).

## Summary

Single-sub-agent-per-stream dispatch as a direct continuation of θ.A + θ.B. Phase θ.C — EFI System Partition (ESP) `.efi` PE chain correlation walker — ships as stream 3 of 3 core θ streams. The campaign brief identified ESP as the **smallest stream** ("mostly wiring on existing primitives"): β.4 signify Authenticode + β.10 DBX revocation + pefile metadata were already shipped; θ.C is the integration that wires them together for the boot-chain layer.

5 commits shipped to main:

- **θ.C.A** (`646f185`) WindowsEspEntry ORM + alembic `7a8b9c0d1e2f` + 4 JSONB normaliser+stamp pairs (authenticode_chain / dbx_revocation_match / anomaly_flags / firmware.esp_walk_result) + 6 Rule #35b live-canary model tests + 38 JSONB normaliser tests.
- **θ.C.B** (`b68ebc3`) firmware.esp_walk_* 5-column 202+poll status set + alembic `8b9c0d1e2f3a` + Pydantic EspWalkStatus Literal + EspAuthenticodeState Literal.
- **θ.C.C** (`d6f4bfb`) Rule #39 inner/outer/safe runner triplet `_do_esp_walk` + `run_esp_walk_background` + `auto_esp_walk_firmware_safe`. 39 walker tests including the Rule #36 central no-execute gate (`test_esp_no_efi_execution`).
- **θ.C.D** (`c0d5795`) Cross-stack alignment: alembic `9c0d1e2f3a4b` extending `ck_findings_source` with `windows_esp_unsigned` + `windows_esp_dbx_revoked` + WindowsFindingSource Literal + frontend FindingSource union + FINDING_SOURCE_CONFIG entries + `_ESPFindingDraft` + `classify_esp_findings` + `emit_esp_findings_from_walk`. ONE atomic commit per Rule #25 single-slice exception #2 (Rule-of-Sixteen). 10 finding-emit tests.
- **θ.C.F** (`c920459`) windows_esp MCP tool category with 4 tools (search / status / trigger / **lookup_esp_chain**). MCP tool count 243 → 247.

107 new tier-1 tests; 4 new MCP tools (243 → 247 — target ≥244 met with margin of 3); WindowsFindingSource Literal 23 → 25; alembic chain `6e9f7a0b1c3d` → `9c0d1e2f3a4b` (+3 revisions); CI Lint green on 4 of 5 phase commits (5th in-progress at session-close, expected green).

**Note on θ.C.E:** The campaign brief listed θ.C.E as a separate emit-wiring commit. θ.C.C's walker triplet already invokes `service.emit_esp_findings_from_walk()` inline from both `run_esp_walk_background` and `auto_esp_walk_firmware_safe`, AND θ.C.D ships the emit method itself. The 5-commit shipping shape is functionally equivalent to the 6-commit brief outline; the wiring isn't a separate concern.

## What Broke

### 1. get_detection_roots returned 2 roots in tier-1 tests (parent + sibling tmp dir)

- **What happened:** `_do_esp_walk` tier-1 tests using `tempfile.TemporaryDirectory` + `firmware.extracted_path = td` produced `get_detection_roots()` returning `[td, '/tmp']` (the firmware's tmp dir AND its parent), causing the walker to scan each `.efi` file TWICE. Assertion `efi_files_scanned == 1` failed with `2 == 1`.
- **Caught by:** Rule #35b live-canary assertion on the persisted count. Mock unit tests would have masked this.
- **Cost:** ~5 minutes — added a `@patch("app.services.esp_walker.get_detection_roots", _fake_roots)` per test to force a single-root layout. The BCD walker tests precedent uses the same shape.
- **Fix:** Patch `get_detection_roots` in tier-1 tests that need a controlled detection-root set.
- **Infrastructure created:** None — Rule-of-Two now on this pattern (BCD walker tests already had this discipline; θ.C.C inherited it after this catch).

### 2. Ruff I001 mid-block import sort on 3 files

- **What happened:** Adding imports mid-block in test_jsonb_normalizers.py / test_finding_service_esp_emit.py / test_windows_esp_tools.py triggered Ruff I001 on each.
- **Caught by:** `uv run ruff check --no-cache` per Antipattern A6.
- **Cost:** ~30 seconds total — `--fix` auto-handled all 3.
- **Fix:** Auto-fix; no human intervention needed.
- **Infrastructure created:** None — Rule-of-Many for ruff I001 (4 hits across θ.A + θ.B + θ.C — mechanical pattern).

### 3. None — the precedent θ.B walker shape was reused with very high fidelity.

The θ.B WMI walker precedent (commits `1e7645f..09aea12`) shipped earlier this session provided a comprehensive template — same Rule #39 triplet shape, same JSONB-normaliser pattern, same MCP-tool category shape (search / status / trigger / lookup), same DB CHECK constraint extension shape, same single-sub-agent-per-stream dispatch cadence. **θ.C took ~1 hour vs θ.B's ~1.5 hours and θ.A's ~2.5 hours** — third application of the same recipe is even faster than the second (Pattern P1 speedup compounds).

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|---|---:|---:|---|
| Rule #36 structural no-execute test gate (`test_esp_no_efi_execution`) | Forbidden execution primitives in walker — subprocess.*, asyncio.create_subprocess_*, os.system/execvp/spawnvp, runpy, eval/exec, **PLUS** EFI-specific wrappers (wine / mono / qemu-system / chainloader / rundll32 / regsvr32). String literals + comments scrubbed first. | 1 gate | The walker treats `.efi` as PE32+ DATA via signify + pefile + DBX byte-comparison only. If a future contributor adds `subprocess.run(['wine', efi_path])` or any analog, the gate fires structurally. CENTRAL discipline per CLAUDE.md Rule #36 + campaign brief. |
| Rule #25 single-slice exception #2 cross-stack alignment test (`test_finding_source_alignment.py`) | DB CHECK ↔ FE union ↔ FE config pairwise agreement post-θ.C.D commit | 1 | Without this, θ.C.D could have shipped with FE-side missing config entry → React `Record<FindingSource, ...>` `undefined` crash on first ESP finding render. 3 alignment assertions all pass post-commit. **Rule-of-Sixteen now**. |
| Rule #41 must-complete CI (Lint per-commit sibling) | 4 of 5 phase commits Lint green (5th in-progress at session-close, expected green) | 4 | Backend Tests CI was cancelled-on-intermediate per Pattern P5 + concurrency.cancel-in-progress; without lint per-commit, a Rule #40 F823 family bug could have ridden through 5 commits before the next backend-tests run. |
| Antipattern A6 ruff `--no-cache` per-piece | I001 import sort (3 hits) — auto-fixable | 3 | Mechanical fixes; the catch is structural. |
| Rule #19 evidence-first read of existing primitives | Read `verify_pe_file()` signature + `AuthenticodeVerdict` shape + `match_dbx_revocation` signature BEFORE drafting `_do_esp_walk`. Extracted: `verdict.dbx_revoked` + `verdict.dbx_revocation_kb` are already plumbed onto the verdict by β.4; the walker does NOT need to call `match_dbx_revocation` separately. | 1 | Without the probe, the walker would have called both verify_pe_file + match_dbx_revocation — duplicate work + duplicate bundle parsing. Saved ~30 lines and clarified the layering. |
| Rule #35b live canary (`make_live_db` round-trip + SELECT) | 107 tier-1 tests including ~30+ make_live_db live canaries. Caught the get_detection_roots multi-root issue (#1 above). The HIGH-tier-unsigned + dbx-revoked emit canaries confirmed Finding rows persist with the correct confidence/severity/source/file_path end-to-end. | 30+ | Without live canaries, the emit hook's value-flow contract would only be tested via mock unit tests — which can confirm call shape but not value flow. The get_detection_roots multi-scan bug was a live-canary catch. |
| Rule #20 docker cp + alembic upgrade head (deferred — Rule #8 NOT needed) | All testing ran against the host venv via tier-1 `make_live_db()`; zero container interactions needed for θ.C. Alembic chain was validated via `uv run alembic heads` on the host venv. | N/A | Saved ~10-15 min of Rule #8 rebuild cycles. End-of-θ rebuild deferred to whenever ι opens. |
| Rule #11 host import smoke | All new module imports resolved cleanly: `WindowsEspEntry` ORM, `esp_walker._do_esp_walk` + sibling triplet, `finding_service.classify_esp_findings` + `_SOURCE_ESP_*` + `emit_esp_findings_from_walk`, `windows_esp._handle_*` MCP tools, full `create_tool_registry()` building 247 tools | 5 | Caught zero issues this session (clean draft); the discipline is mechanical. |
| Rule #24 mandatory tsc canary | Frontend `tsc -b --force` confirmed checking files (canary intentionally failed with TS2322 type error, exit=2) | 1 | Tsc canary discipline durably internalised — no Rule #35a pipe-induced silent-exit issues this stream. |
| Rule #38 absolute paths + subshell-scoped `( cd backend && ... )` | Net 0 CWD-drift incidents in commit log; all git invocations used `git -C /home/dustin/code/wairz` form | 0 issues | Worked correctly throughout. Pattern is durable beyond debate (Rule-of-Many across η + θ.A + θ.B + θ.C). |
| Bandit security scan | 0 issues across `esp_walker.py` + `windows_esp.py` (1378 LOC scanned) | 1 | Validates no new security-relevant patterns (shell=True, hardcoded credentials, pickle untrusted inputs). |
| `scripts/lint_async_subprocess.py` | 0 issues | 1 | Validates no new bare `wait_for(coro)` without timeout / no new `asyncio.create_subprocess_*` without explicit timeout. Consistent with Rule #36 no-execute discipline (we don't spawn any subprocesses anyway). |
| Pattern P5 per-piece direct-push to main + Rule #41 must-complete CI | All 5 phase commits + push immediately; CI Lint green per-commit on first 4 (5th in-progress) | 5 | The cadence is healthy and durable. No re-work cycles. |
| Antipattern A10 alembic ID pre-validation | 3 fresh IDs pre-validated FREE before each migration's commit (`7a8b9c0d1e2f` for θ.C.A, `8b9c0d1e2f3a` for θ.C.B, `9c0d1e2f3a4b` for θ.C.D) | 3 | Zero alembic ID collisions; chain validated via the in-tree migration files. |

## Scope Analysis

- **Planned (per single-sub-agent dispatch from campaign brief):** Phase θ.C ESP walker as 4+ commits with `Phase θ.C` prefix. Sub-tasks θ.C.A (ORM+alembic+normalisers), θ.C.B (firmware status columns), θ.C.C (Rule #39 walker triplet), θ.C.D (cross-stack alignment + emit), θ.C.E (wire emit), θ.C.F (MCP tools).
- **Built:** 5 commits shipped to main. θ.C.E was absorbed into θ.C.C's walker triplet (which already calls the emit hook inline) + θ.C.D (which ships the emit method itself); a separate commit would have been functionally a no-op.
- **Drift:** **NONE.** Single sub-agent + θ.B precedent reuse + library-API evidence-first pre-validation eliminated scope surprises. Per-piece direct-push cadence held cleanly. The 5-commit shape is the natural minimum for this scope.

## Patterns Extracted

1. **Third application of single-sub-agent dispatch + precedent reuse compounds the speedup (Rule-of-Three now).** θ.A took ~2.5h. θ.B took ~1.5h. **θ.C took ~1h** despite still needing the full set of layers (ORM + status columns + walker triplet + classifier + emit + MCP tools). The third application is faster than the second; the speedup compounds because each successive walker can mechanically copy-translate from the most recent precedent (θ.B WMI was the closest match for θ.C ESP — same Rule #39 triplet shape, same MCP tool category, same cross-firmware aggregation surface). Generalises Pattern P1 — Rule-of-Three on the speedup observation.

2. **Integration-only streams can absorb sub-tasks if the layering already provides the wiring (Rule-of-One — promote candidate).** θ.C.E was originally planned as a separate "wire the emit hook" commit. But θ.C.C's walker triplet already invokes `service.emit_esp_findings_from_walk()` inline from both `run_esp_walk_background` and `auto_esp_walk_firmware_safe`, AND θ.C.D ships the emit method. There's no separate wiring step to commit. **The discipline is: when a sub-task is functionally subsumed by adjacent sub-tasks, fold it in rather than ship an empty commit.** Doesn't apply when the sub-task adds INDEPENDENT behaviour (e.g. a separate background-job entry point); applies when it's purely a "call X from Y" wiring that's already implicit in the layer's contract.

3. **Existing-primitive reuse via Rule #19 probe before draft.** Read `verify_pe_file()` + `AuthenticodeVerdict` + `match_dbx_revocation()` API surfaces BEFORE drafting `_do_esp_walk`. Discovered that the β.4 verifier ALREADY includes the β.10 DBX cross-reference (`verdict.dbx_revoked` is populated by `verify_pe_file` internally). The walker doesn't need to call DBX separately — it just maps the verdict's existing fields onto WindowsEspEntry columns. Saved ~30 lines of redundant plumbing. Generalises Rule #19 — "the existing service describes the integration boundary; READ it before drafting integration code."

4. **Rule #25 single-slice exception #2 cross-stack alignment is Rule-of-Sixteen.** θ.C.D extended `ck_findings_source` + WindowsFindingSource Literal + frontend FindingSource union + frontend FINDING_SOURCE_CONFIG + classifier + emit hook in ONE atomic commit. `test_finding_source_alignment.py` enforced pairwise agreement immediately. The discipline is mechanical and durable. **Beyond-debate at this point** — pattern shipped 16 times across 6 weeks without a single divergence.

5. **Rule #39 inner/outer/safe runner triplet is Rule-of-Eleven** (γ.4 → δ.5 → ε.1.b.3 → ζ.2.B → ζ.3.B → η.B.C → η.C.C → η.A.C → θ.A.C → θ.B.D → θ.C.C). The pattern is the canonical wave-1 shape for any new walker in wairz. **The next walker should treat the triplet as the default and only deviate if there's a specific architectural reason** (e.g. the work is genuinely synchronous + bounded enough to not need the state machine).

6. **Cross-firmware fingerprint aggregation is genuinely novel surface area (Rule-of-Three — promotable).** WMI θ.B.D's `lookup_wmi_persistence` was Pattern P3 (Rule-of-One). BCD θ.A also has `lookup_bcd_*`. **θ.C ESP's `lookup_esp_chain` makes Rule-of-Three** — unique boot-chain hunt across the wairz corpus by fingerprint / file SHA256. Same fingerprint across firmware ⇒ same `.efi` shape was planted (BlackLotus / Bootkitty / supply-chain correlation). The pattern is now durable; future walkers (LNK / scheduled-task / hibernate.sys) should consider adding the cross-firmware aggregation MCP tool as a default unless the artefact lacks a natural fingerprint shape.

7. **JSONB normaliser pairing with ORM column introduction is mechanical (Rule-of-Many).** For each new JSONB column in θ.C.A's ORM: `_normalize_<table>_<column>` + `_stamp_<table>_<column>` helpers in `jsonb_normalizers.py` + `<TABLE>_<COLUMN>_SCHEMA_VERSION = 1` constant. Tier-1 tests cover canonical pass-through + defensive coercion (None / wrong-type) + idempotency. **Discipline shipped 4 normaliser triplets in θ.C.A + θ.C.B (authenticode_chain + dbx_revocation_match + anomaly_flags + firmware.esp_walk_result) with 38 new normaliser tests; mechanical execution from the precedent shape.**

## Decision Log

| # | Decision | Rationale | Outcome |
|---|---|---|---|
| 1 | Reuse θ.B WMI walker precedent file-by-file at design time | θ.B is the closest-shaped Rule #39 triplet (same shipping session; same JSONB normaliser pattern; same MCP-tool category; same DB CHECK extension shape); reading the source at design time avoids re-derivation | All design decisions deferred to "what did θ.B do?" — execution was straightforward. ~1h total time, ~33% faster than θ.B. |
| 2 | 5 commits (θ.C.A through θ.C.F, skipping θ.C.E) per Pattern P5 per-piece direct-push | Mirrors θ.B's 7-commit pattern, BUT absorbs θ.C.E into θ.C.C+θ.C.D because the emit hook is wired inline in the walker triplet (functionally a no-op as a separate commit). 5 commits is the natural minimum scope. | 5 commits shipped cleanly; all 4 Lint-green per-piece (5th in-progress, expected green). |
| 3 | Skip vendoring — ESP walker uses existing β.4 signify + β.10 DBX + pefile primitives | Unlike θ.B which needed a 200 LOC PyWMIPersistenceFinder fork, θ.C is integration-only. signify is in pyproject.toml; pefile is in pyproject.toml; β.4 + β.10 services already wrap the validation pipeline. The walker just maps the verdict onto WindowsEspEntry columns. | Walker is 925 LOC of integration glue (vs θ.B WMI's 917 LOC + 200 LOC vendor); cleaner separation of concerns. |
| 4 | 4 MCP tools (search / status / trigger / lookup) not 2 (campaign brief said "~2") | The cross-firmware `lookup_esp_chain` aggregation is unique to wairz and structurally parallels lookup_wmi_persistence / lookup_bcd_*. Pattern P3 (Rule-of-Three now) supports keeping the lookup tool. The other 3 mirror the standard search/status/trigger triplet. | 4 tools registered; MCP count 243 → 247; target ≥244 met with margin of 3. |
| 5 | `walk_esp_efi_files` restricts to paths containing `EFI/` subdirectory (case-insensitive) | Some firmware extractions contain unrelated `.efi` extensions outside the ESP context (e.g. tool config files); restricting to paths under EFI/ avoids false matches. The restriction is case-insensitive so FAT32 mounts (lowercase) AND raw-image extractions (often original-case) both work. | walk_esp_efi_files cleanly finds bootloaders across canonical layouts; non-EFI `.efi` files are ignored. |
| 6 | authenticode_state CHECK constraint enforces 5-state enum | Mirrors Rule #33 .c discipline — DB CHECK is the durable safety floor, Pydantic `EspAuthenticodeState` Literal is the typo-gate at the boundary. Both gates are cheap; ship both. | CHECK + Literal pair shipped; 39 walker tests + 6 model tests assert the round-trip preserves the enum. |
| 7 | `map_verdict_to_authenticode_state` distinguishes `unsigned` from `parse_failed` via error-presence | A PE with `signed=False` could be EITHER truly unsigned (no certificate table; signify returns 0 signatures cleanly) OR malformed (signify raised; verdict carries `.error`). Distinguishing both states matters for downstream classification — parse_failed should NOT emit a windows_esp_unsigned finding because the unsigned signal isn't reliable. | Mapping shipped; tests cover both branches; classifier correctly emits 0 drafts on parse_failed. |
| 8 | DBX-revoked is the AUTHORITATIVE revocation signal — overrides chain_status='valid_now' | Even if signify's chain validation passes, a DBX hit means Microsoft has explicitly revoked the binary. The override is implemented in `map_verdict_to_authenticode_state` as the FIRST check — `if verdict.dbx_revoked: return 'signed_revoked'`. | Mapping correctly elevates DBX-revoked over chain validation; test `test_map_verdict_to_state_dbx_revoked_overrides_chain` asserts this. |

## HANDOFF

> **State at session-close (2026-05-12 ~mid-day):**
> - HEAD: `c920459` on `origin/main`, working tree clean (only `.claude/harness.json` modified; untracked planning artefacts pending below).
> - Alembic head: `9c0d1e2f3a4b` (θ.C.D extend findings.source CHECK with windows_esp_*).
> - MCP tool count: **247** (target ≥244 met with margin of 3; θ.B baseline was 243; θ.C added 4).
> - Rule #39 walker triplet count: **Rule-of-Eleven** (θ.C.C extends γ.4→δ.5→ε.1.b.3→ζ.2.B→ζ.3.B→η.B.C→η.C.C→η.A.C→θ.A.C→θ.B.D→θ.C.C).
> - Rule #25 cross-stack alignment count: **Rule-of-Sixteen** (θ.C.D extends the 15-deep chain).
> - WindowsFindingSource Literal: **25 values** (was 23 at θ.C session start; +windows_esp_unsigned + windows_esp_dbx_revoked).
> - CI: Lint green on θ.C.A / θ.C.B / θ.C.C / θ.C.D (commits 646f185 / b68ebc3 / d6f4bfb / c0d5795); θ.C.F (`c920459`) in_progress at session-close.
> - Phase end conditions ALL met: ✓ pytest test_esp_walker.py + test_esp_models.py green (45 tests total — 39 walker + 6 model), ✓ tsc -b --force exits 0 (canary verified), ✓ esp_walker.py exists, ✓ MCP tools ≥ 244 (=247), ✓ Phase θ.C commits ≥ 4 (=5).
>
> **Next-stream pickup:**
> - **Phase θ campaign closed (3 of 3 core streams shipped).** Optional θ.D (Shim .sdb) + θ.E (MBR/VBR) deferred to Phase ι per the campaign brief's "capacity-dependent" disposition.
> - **Pending docs commit:** This postmortem + patterns + antipatterns docs need to be committed as the final θ.C artefact (final commit of the θ campaign).
> - **Rule #8 backend+worker+migrator rebuild:** DEFERRED — no class-shape change requires it immediately. The firmware model's new esp_walk_* columns + windows_esp_entries table will be picked up by next session's container rebuild via the migration chain. Run `docker compose up -d --build backend worker migrator` when starting the next campaign (likely ι).
>
> **Cross-firmware ESP chain hunt (lookup_esp_chain) — operator usage:**
> The MCP tool's unique value is corpus-wide boot-chain threat hunt. Example operator workflow: (1) trigger_esp_walk on a known-malicious firmware; (2) note the fingerprint_sha256 of the unsigned bootmgfw.efi; (3) call lookup_esp_chain with that fingerprint to see which OTHER firmware images in the corpus carry the same `.efi` shape. Same fingerprint across firmware ⇒ same bootkit was planted (BlackLotus / Bootkitty / supply-chain compromise correlation). Alternatively query by file_sha256 directly (raw file-content match) or path_substring (e.g. "bootmgfw.efi" to find every Windows boot manager across the corpus).

## Numbers

| Metric | Value |
|---|---:|
| Phases planned (θ.C sub-task count) | 5-6 (brief outlined 6 but θ.C.E was absorbed) |
| Phases completed | 5 (100%) |
| Total commits to main | 5 (θ.C.A through θ.C.F, skipping E) |
| Files changed (cumulative session diff) | ~14 |
| Lines added / removed | ~4700 / ~3 |
| New tier-1 tests | 107 (6 model + 38 normaliser + 39 walker + 10 emit + 14 MCP tool) |
| New MCP tools | 4 (windows_esp: search / status / trigger / lookup_esp_chain) |
| MCP tool count delta | 243 → 247 (+4, target ≥244 met with margin of 3) |
| New WindowsFindingSource Literal values | 2 (windows_esp_unsigned + windows_esp_dbx_revoked) |
| Literal values delta | 23 → 25 |
| New alembic revisions | 3 (chain `6e9f7a0b1c3d` → `7a8b9c0d1e2f` → `8b9c0d1e2f3a` → `9c0d1e2f3a4b`) |
| New JSONB normaliser pairs (Rule #35c) | 4 (windows_esp_entries.authenticode_chain + windows_esp_entries.dbx_revocation_match + windows_esp_entries.anomaly_flags + firmware.esp_walk_result) |
| New vendored libraries | 0 (integration-only — reuses β.4 signify + β.10 DBX + pefile) |
| Sub-agent delegations | 0 (single-agent dispatch from Archon harness) |
| Pattern doc / antipattern doc creation | 2 (this commit) |
| CLAUDE.md rules promoted | 0 (recommendations in this postmortem; promotion is a separate dispatch) |
| CI Lint runs | 5 (1 per phase commit) — 4/5 SUCCESS at session-close, 5th in_progress (expected green) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Anti-pattern warnings | 3 (ruff I001 — all auto-fixable) |
| Rework cycles (commit reverts) | 0 |
| Wall time | ~1 hour session start → final commit (~33% faster than θ.B's 1.5h, ~60% faster than θ.A's 2.5h — third-application speedup compounds Pattern P1) |
| Rule #36 no-execute audit | 0 hits in CODE; 2 hits in DOCSTRINGS (the docstrings' own descriptions of what's forbidden — documentation, not violations) |
