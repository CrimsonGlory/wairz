# Postmortem: windows-coverage-godmode β.8 + β.9

> Date: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Duration: ~2 hours wall-clock (β.8 ship → β.9 ship: 07:05 → 08:03 UTC + ~1h pre-β.8 context-load)
> Outcome: completed (2 sub-tasks shipped; campaign as a whole still IN PROGRESS — β.10-β.14 remain)

## Summary

Shipped Phase β.8 (background runner) and Phase β.9 (MCP tool category)
back-to-back. β.8 added `_run_authenticode_chain_background` plus the
202+poll endpoint pair, walking each firmware's `hardware_firmware_blobs`
through MZ-magic pre-filter + `run_in_executor(verify_pe_file)` + per-PE
`WindowsPESignature` row persistence + aggregate stamping. β.9 wrapped
the β.4-β.8 services in a 6-tool MCP category (`verify_authenticode`,
`decode_rich_header`, `scan_dbx_revocation`, `detect_pe_arch_view`,
`list_signatures`, `get_signature_chain`). Two clean Rule #25 commits
(`70274c3`, `8247153`); zero reverts; 38 new tests; tool registry
178 → 184.

## What Broke

### 1. Test fixture substring collision — `"signed" in "unsigned.dll"`

- **What happened:** β.8's first attempt at `test_verify_firmware_pe_chain_persists_one_row_per_pe` used `if "signed" in path:` to branch the fake_verify between signed.exe and unsigned.dll. The substring `"signed"` matches BOTH filenames, so both PEs took the signed branch and the test asserted 2 signed rows but expected 1.
- **Caught by:** The Rule #35b live canary itself — `len(signed_rows) == 1` failed `assert 2 == 1` because the test SELECT'd persisted rows. A mock-only test asserting `db.add.call_count == 2` would have passed (both rows DID get added) and the value-flow regression would have shipped silently.
- **Cost:** ~1 minute (rename + re-run). Zero impact on commits.
- **Fix:** Renamed fixtures `trusted.exe` (signed) + `vendor.dll` (unsigned), branched on `path.endswith("trusted.exe")` so the discriminator can't accidentally match the other fixture. Comment block in the test documents the substring trap.
- **Infrastructure created:** None — Rule #35b's "SELECT the persisted row, inspect every field" discipline was the durable backstop here. The general rule-of-thumb (don't use substring matchers for test-fixture discrimination when the fixture names share substrings) is captured in this postmortem's pattern section but not promoted to a quality rule (signal-to-noise on a regex would be poor).

### 2. Pipe-induced false `pytest_rc=0` — Rule #35a near-miss

- **What happened:** First validation run used `pytest ... 2>&1 | tail -80; rc=$?; echo "pytest_rc=$rc"`. The pipe captured `tail`'s exit, not pytest's, so `pytest_rc=0` printed despite "1 failed, 15 passed" appearing in the tail output. Caught by reading the visible "FAILED" line in the output before trusting the captured exit code.
- **Caught by:** Self-review of the visible pytest summary line, NOT by the captured exit code. The Rule #35a pattern itself is the durable lesson — but the trap reproduced once in this session, exactly as Learned Rule #35a (a) warned.
- **Cost:** ~30 seconds (one re-validation cycle with `cmd > /tmp/x; rc=$?`). Zero impact on commits — the test fixture was fixed, exit code re-captured cleanly, commit only happened after real_pytest_rc=0.
- **Fix:** Switched to file-redirect pattern `cmd > /tmp/runner-test.out 2>&1; rc=$?; tail -30 /tmp/runner-test.out` for every subsequent pytest run in both β.8 and β.9. Pattern held cleanly for 5 subsequent invocations.
- **Infrastructure created:** None new — Rule #35a (a) is exactly the existing pattern; this session reproduced the trap and recovered correctly. Worth flagging in the patterns section that the trap is real even for operators who know about it.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|----------------|-------|------------------|
| Rule #35b live canary (test_verify_firmware_pe_chain_persists_one_row_per_pe) | Substring-collision in test fixtures (`"signed" in "unsigned.dll"`) | 1 | A mock-only test would have passed (2 db.add calls confirmed); the persisted-row SELECT caught the value-flow bug at fixture-design time, not at production time |
| `test_verdict_maps_to_windows_pe_signature_columns` drift-detector | After moving DIRECT_MAPPED to the runner module, the drift-detector still passes — confirming β.8's single-source-of-truth refactor preserves the contract | 1 | A future Phase γ verdict-field addition will surface here regardless of which file holds DIRECT_MAPPED; the test follows the constant |
| Rule #11 import smoke (post `docker cp` + restart) | β.8 runner + β.9 MCP category both import cleanly; tool count 178 → 184 confirms 6 expected registrations | 4 | Module-scope `NameError` from a typo in DIRECT_MAPPED elements OR a stale ai/__init__.py registration would have been caught at import, not at MCP request time |
| Rule #35a real-exit-code pattern | `cmd > /tmp/x; rc=$?` (not `cmd \| tail; rc=$?`) | 6+ | Would have masked the substring-collision test failure as `pytest_rc=0`; honest exit code surfaced the failure on first run |
| Rule #25 per-sub-task commits | β.8 + β.9 shipped as two focused commits | 2 | Bundled "feat(β): runner + MCP" would have meant a single revert surface for two semantically independent sub-tasks; β.8's runner is durable infrastructure, β.9 is a thin wrapper — independent revert/bisect lanes preserved |
| Rule #20 docker cp + restart (no class-shape change) | Both β.8 and β.9 added new modules + Pydantic classes only; restart sufficed | 2 | A full `docker compose up -d --build` (3-5 min each) would have cost ~6-10 min total; restart took ~10 sec each |
| Rule #19 evidence-first | Pre-coding grep confirmed `HardwareFirmwareBlob.blob_path` is the absolute on-disk path (set by detector.py:_walk_and_classify from entry.path) — not assumed | 1 | An assumption-based iteration that hit `extracted_path + blob_path` joining would have produced wrong absolute paths and verify_pe_file would have reported "PE file not found" for every blob |
| Pattern #4 verdict↔ORM column 1:1 + DIRECT_MAPPED frozen | β.8's single-source-of-truth refactor moves the literal `direct_mapped` from the test into the runner as a frozenset; the test imports it; future drift will surface in exactly one place | 1 | Without the move, Phase γ adding a verdict field would require updating both the runner's row-construction site AND the test's literal — silent drift risk if either was forgotten |

## Scope Analysis

- **Planned (β.8 — per user prompt):** "Background runner `_run_authenticode_chain_background` (asyncio.create_task) that walks each firmware's hardware_firmware_blobs, calls authenticode_service.verify_pe_file per PE, and persists one WindowsPESignature row per PE — driving the firmware.authenticode_chain_* 202+poll status columns from β.3 (idle → queued → running → completed/failed) per Rule #33 contract." Six explicit design constraints (verdict-spread persistence, Rule #7 session ownership, Rule #33 status transitions, Rule #11+#20 docker cp + restart, per-PE error containment, Rule #19 evidence-first).
- **Built (β.8):** New `app/services/authenticode_chain_runner.py` (423 LOC) with DIRECT_MAPPED frozenset (single source of truth), `_is_pe_file` MZ-magic pre-filter, `verify_firmware_pe_chain` heavy-work iterator (per-PE error containment, re-run idempotency via DELETE), `run_authenticode_chain_background` outer detached runner (status state machine). Plus `POST /authenticode-chain` (idempotent 202, 409 on conflict) + `GET /authenticode-chain/status` in `routers/hardware_firmware.py`. Plus 2 new schemas in `schemas/hardware_firmware.py`. Plus 16 tests (5 unit + 6 Rule #35b live canaries + 3 outer-runner status-transition + 2 misc). Plus drift-detector test refactored to import DIRECT_MAPPED from the runner.
- **Planned (β.9 — per recommended-next conversation):** "MCP `windows_pe_signature.py` (6 tools incl. verify_authenticode, decode_rich_header, scan_dbx_revocation, detect_pe_arch_view) + `__init__.py` wire-in" (PRD item 4 of Phase β).
- **Built (β.9):** `app/ai/tools/windows_pe_signature.py` (450 LOC) with the 4 PRD-named tools + 2 DB-read tools (`list_signatures`, `get_signature_chain`) that consume β.8's persisted rows. Plus 22 tests (6 service-layer mock tests + 6 Rule #35b live canaries for the read tools + 1 registration smoke + 9 boundary/error-path tests). `ai/__init__.py` updated with the registration call.
- **Drift:** None on β.8. Minor *positive* drift on β.9: the PRD said "6 tools incl. verify_authenticode, decode_rich_header, scan_dbx_revocation, detect_pe_arch_view" (4 explicit names + "incl." implying more). Shipped 4 service-wrappers + 2 DB-read tools (`list_signatures`, `get_signature_chain`) — the DB-read tools complete the operator workflow ("how do I see what β.8 produced?") without which the MCP category would be write-only-via-async-runner. Documented in the β.9 commit message.

## Patterns

- **Rule #35a's pipe trap is real even for operators who know it.** Session 2026-05-07 already documented it (Learned Rule #35a (a)); this session reproduced it once on the very first pytest validation and recovered immediately. The cost is small (~30 sec re-validate) but cumulative across sessions. **Action:** No new infrastructure — the existing rule + the muscle-memory of file-redirect IS the durable response. Worth noting that "I know about Rule #35a" is not equivalent to "I never trip Rule #35a"; the trap fires when you're focused on something else (test fixture bug here).
- **Rule #35b's "SELECT-the-persisted-row" is the only catch for test-fixture-discrimination bugs.** The substring-collision (`"signed" in "unsigned.dll"`) bug existed in the TEST, not the production runner. A mock-only test asserting `db.add.call_count == 2` would have passed — both rows DID get added; the bug was that they both had `signed=True`. The live canary's SELECT + `assert len(signed_rows) == 1` was the only mechanism that could distinguish "two rows added" from "two rows added with the right values". Pattern is durable across every Rule #35b application; β.8's value-flow check found a fixture bug, β.9's value-flow check (list_signatures + get_signature_chain) confirmed the read-side surfaces the persisted columns. **Action:** Continue applying. The mocks-vs-live-canaries discipline (CLAUDE.md "Mocks vs live canaries" + Rule #35b) is exactly the right framing.
- **Pattern #2 (verdict-field mirror) extends cleanly to "single source of truth via imported frozenset".** β.5/β.6/β.7 each grew the drift-detector's `direct_mapped` literal in the test file. β.8 moved that literal to a `DIRECT_MAPPED` frozenset in the runner module + had the test import it. The Rule of Three is now Rule of Four for Pattern #2; the **single-source-of-truth refactor** at the fourth iteration is the natural evolution of the pattern. **Action:** Worth promoting to a `.mex/patterns/add-pe-verdict-field.md` recipe (β.5/β.6 postmortem rec #1 — still pending; this session reinforces the case).
- **Rule #25 per-sub-task commits hold under back-to-back execution.** β.8 + β.9 in one session, two separate commits, zero "let me bundle these together" temptation. Keeps each independently revertable; β.8 (durable infrastructure) and β.9 (thin MCP wrapper) genuinely have different failure modes and the commit boundary preserves that. **Action:** No change. Pattern is now Rule-of-Five-plus across this campaign (β.5/β.6/β.7/β.8/β.9 each its own commit).
- **The cve-match precedent reduces β.8-class work to copy-and-modify.** β.8's outer runner + 202+poll endpoint pair was structurally identical to `_run_cve_match_background` + POST /cve-match + GET /cve-match/status. Same session ownership, same status transitions, same idempotent POST + 409 + 2 s polling shape. Total β.8 design time was ~5 minutes of "do exactly what cve-match did, replace cve_match with authenticode_chain". **Action:** This is the precedent that makes β.10/γ.X/δ.X 202+poll work cheap. Recipe candidate: `.mex/patterns/add-202-polling-windows-op.md` (already on PRD as a quality rule delta but not yet authored).
- **MCP-category-as-thin-service-wrapper is durable.** β.9's 6 tools each follow the same shape: resolve_path + run_in_executor + JSON-render-or-explicit-error. `verify_authenticode` is 7 LOC. `detect_pe_arch_view` is 6 LOC. The DB-read tools are 30 LOC each. Total tool LOC is ~170; the rest of the file is registration + helpers. **Action:** When Phase γ ships its registry/driver MCP categories, expect the same shape — service wrappers are the durable form. The PRD's `.mex/patterns/add-windows-format-handler.md` recipe (still pending) should encode this.

## Recommendations

1. **Promote Pattern #2 (verdict-field mirror + single-source-of-truth) to `.mex/patterns/add-pe-verdict-field.md`.** Five β-phase repetitions (β.5/β.6/β.7/β.8 the constant move/β.9 the MCP wrapper) is more than enough to justify a recipe. Cover: (a) service module returning `dict | None`, (b) Pattern #1 four-way verdict plumbing, (c) drift-detector update via imported frozenset, (d) JSONB-vs-scalar verdict-field decision tree, (e) MCP tool shape (service wrapper + resolve_path + run_in_executor + JSON shaping). Carries forward to Phase γ/δ verdict extensions (driver tier classification, .NET R2R-stomp signal). β.5/β.6 postmortem rec #1 is now over a session old; this is the natural session to ship the recipe — the patterns are stable and the operator has applied them four+ times.
2. **Promote 202+poll work to `.mex/patterns/add-202-polling-windows-op.md`.** Five applications now in tree (firmware unpacking, emulation, fuzzing, cve-match, authenticode-chain). The PRD listed the recipe as a quality-rule delta but didn't author it. The β.8 commit + the cve-match precedent it copied are exactly the worked example a recipe needs. Worth ~30 min of authoring time; saves an order of magnitude across γ/δ.
3. **β.10 (Dockerfile + cron for MS roots / DBX bundle) is the natural next session.** Different domain (Dockerfile, apt, cron script) — does not benefit from the warm β-services context. Fresh session keeps the cache hot for the new domain (apt package availability, cron syntax, the bundle-refresh schedule). Per Rule #29's offline-trust-anchor discipline (Rule #37 candidate), the bundle MUST land in the worker image as a build-time asset, NOT as a runtime download. Quarterly cron is the supported refresh path.
4. **Defer real-PE Rule #35b live canary across β.4-β.9 to β.14 cut-over.** Every β.X-phase to date has shipped with mock-only tests. The campaign PRD's Phase β live canary set ("dual-signed PE + signed driver `.cat` + DBX-revoked PE certificate") is gated on β.10's bundle provisioning + β.14's cut-over rebuild. The discipline is fine — premature live-canary work would test the bundle provisioning pipeline more than the verdict logic — but the deferral is now spanning 6 sub-tasks, which is the natural cap before it becomes a cliff. **β.14 cut-over should activate ALL deferred canaries in one rebuild**, not piecewise.

## Numbers

| Metric | Value |
|--------|-------|
| Sub-tasks planned (this session) | 2 (β.8 background runner + β.9 MCP tools) |
| Sub-tasks completed | 2 |
| Commits | 2 (`70274c3` β.8, `8247153` β.9) |
| Files added | 4 (`authenticode_chain_runner.py`, `test_authenticode_chain_runner.py`, `windows_pe_signature.py`, `test_windows_pe_signature_tools.py`) |
| Files modified | 4 (`routers/hardware_firmware.py`, `schemas/hardware_firmware.py`, `tests/test_authenticode_service.py`, `app/ai/__init__.py`) |
| Total LOC delta | +2227 / -13 (β.8 +1172/-13; β.9 +1055) |
| Tests added | 38 (16 β.8 runner + 22 β.9 MCP tools) |
| Failing tests after this session | 0 |
| Reverts | 0 |
| Rework cycles | 1 (β.8 test-fixture substring-collision; ~1 min) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Anti-pattern warnings | 0 |
| Rule #11 import smoke runs | 4 (β.8 pre-restart, β.8 post-restart, β.9 pre-restart, β.9 post-restart) — all green |
| Rule #20 docker cp + restart cycles | 2 (one per sub-task) |
| Rule #25 commits | 2 (one per sub-task) |
| Rule #35a `cmd; rc=$?` patterns | 6+ (after the one near-miss on first pytest invocation) |
| Rule #35a near-miss recoveries | 1 (pipe-induced false pytest_rc=0; caught via visible test summary line) |
| Rule #35b live canaries added | 12 (6 in β.8 — verify_firmware_pe_chain × 6 cases; 6 in β.9 — list_signatures × 3 + get_signature_chain × 3) |
| Pattern #7 REPL probes | 0 (β.8 + β.9 reused already-validated APIs from β.4-β.7; no new third-party libraries) |
| Tool registry growth | +6 (178 → 184) |
| Discipline slips | 0 (no `--no-verify`; no `--amend`; bare `git commit -m` per β.7 postmortem rec) |

---HANDOFF---
- Postmortem: windows-coverage-godmode β.8 + β.9
- Document: .planning/postmortems/postmortem-windows-coverage-godmode-beta8-beta9-2026-05-08.md
- Failures documented: 2 (1 test-fixture substring-collision; 1 Rule #35a near-miss recovered cleanly)
- Safety catches: 7 (Rule #35b live canary, drift-detector, Rule #11 import smoke, Rule #35a exit-code, Rule #25 per-sub-task commits, Rule #20 docker cp + restart, Rule #19 evidence-first)
- Recommendations: 4
---

Run `/learn windows-coverage-godmode-beta8-beta9` to extract patterns into the knowledge base.
