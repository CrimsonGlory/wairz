# Postmortem: windows-coverage-godmode β.14

> Date: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Duration: ~30 min wall-clock (kickoff prompt → β.14b commit + final cross-cut sweep)
> Outcome: completed (Phase β closed; γ + δ remain pending)

## Summary

Shipped Phase β.14 (final cut-over closing the Windows-Coverage God-Mode
β-phase) as 2 focused Rule #25 commits. β.14a (`77b257d`) activated
the deferred Rule #35b real-firmware canary set identified in the
β.10 / β.11 / β.12 postmortem rec #4 chain, adding
`backend/tests/test_authenticode_chain_real_firmware.py` (5 tests
across 3 tiers — 3 tier-1 always-runs canaries against host
mingw-w64 / systemd-bootx64 PEs through unmocked `verify_pe_file`,
2 tier-2/3 fixture-gated canaries). β.14b (`893dcac`) promoted the 3
candidate CLAUDE.md rule additions from β.12's postmortem rec #3:
Rule #25 single-slice exception #2 for cross-stack alignment tests
(worked examples `7079b4d` + `ee2abd9`), Rule #33 .c subtlety on
the typo-gate location (worked example `b67f062`), and a brand-new
Rule #38 Bash absolute-path discipline (worked examples β.10
antipattern #3 + β.12 postmortem "What Broke" #1). Per Rule #21,
the .mex/context/conventions.md Verify Checklist mirror landed in the
SAME commit as the CLAUDE.md edits. Plus a small companion fix:
β.13's Rule #36/#37 promotion missed updating CLAUDE.md's "rules
1–35 above" reference in the .mex companion-scaffold section; β.14b
caught the stale phrase and corrected it to "rules 1–38 above".
Total: +632 LOC across 3 files (1 added, 2 modified); 44-test
final cross-cut sweep stays clean; zero reverts; zero rework cycles
beyond two trivial test-side fixes (URL prefix + extracted_path).

## What Broke

### 1. HTTP-layer test URL mismatched the actual router prefix

- **What happened:** First run of `test_http_layer_post_authenticode_chain_round_trip` returned 404 on POST. The kickoff prompt's URL shape `POST /api/v1/projects/{id}/firmware/{fw}/authenticode-chain` was approximate — the actual router is mounted under `/hardware-firmware` (β.11a placed the authenticode-chain endpoint there), and `firmware_id` is a query parameter resolved by `app.routers.deps.resolve_firmware`, not a path segment. Correct URL: `/api/v1/projects/{project_id}/hardware-firmware/authenticode-chain?firmware_id={firmware_id}`.
- **Caught by:** The test's own assertion `assert resp.status_code == 202, resp.text` surfaced the 404 immediately + returned the response body for diagnosis.
- **Cost:** ~30 sec — single grep `grep -n 'APIRouter\|prefix=' hardware_firmware.py` gave the prefix, single Edit to update the URL.
- **Fix:** Updated `base` to use `/hardware-firmware/authenticode-chain` + appended `?firmware_id={fw.id}` query string for the POST + GET status calls.
- **Infrastructure created:** None. Kickoff-prompt URL approximations are normal; the test's clear assertion message made diagnosis instant.

### 2. Resolver 400 — firmware row missing extracted_path

- **What happened:** Second run got 400 `{"detail":"Firmware not yet unpacked"}`. `resolve_firmware` (`backend/app/routers/deps.py:33`) requires `firmware.extracted_path` to be non-null, gating any operation against a firmware that hasn't been unpacked yet. The test's `_seed_firmware` helper didn't set `extracted_path`.
- **Caught by:** The test's status-code assertion + the resolver's clear 400 message.
- **Cost:** ~30 sec — single Read of `deps.py` confirmed the requirement, single Edit added `extracted_path="/tmp/test-fw-extracted"` to `_seed_firmware` with an inline comment explaining why (the chain runner reads `HardwareFirmwareBlob.blob_path`, not this field; the placeholder satisfies the resolver without affecting the runner).
- **Fix:** Added the placeholder `extracted_path` in `_seed_firmware` so all 3 tier-1 tests + tier-2/3 (skip-unless) all share the same fixture shape.
- **Infrastructure created:** None. Inline comment in `_seed_firmware` documents the Decision; future tests using this helper inherit the working shape.

### 3. β.13 missed updating "rules 1–35 above" stale-phrase reference

- **What happened:** While drafting the Rule #38 promotion, surfaced that CLAUDE.md's `.mex/`-companion-scaffold section still says "rules 1–35 above" — β.13 added Rule #36 + Rule #37 but missed updating this companion phrase. The `.mex/context/conventions.md` Verify Checklist DID get the new bullets in β.13's `f80d606`; only the cross-reference text in CLAUDE.md was stale.
- **Caught by:** Self-recognition while reading the section to find the Rule #38 insertion point — the phrase visibly contradicted the count of rules in the file (37, not 35).
- **Cost:** ~10 sec — added one Edit to the same β.14b commit, bumping the phrase to "rules 1–38 above" alongside the new Rule #38 addition.
- **Fix:** Single Edit; bundled into β.14b as a companion fix per Rule #21 spirit (the phrase is a cross-reference between CLAUDE.md and the .mex Verify Checklist; both should agree on the count).
- **Infrastructure created:** None per se, but raises a recommendation (see Recommendations #1) — manual rule-count audits at promotion time aren't reliable; consider a CI grep that asserts the cross-reference matches the actual rule count.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|------------------|
| Rule #19 evidence-first | Read β.12 patterns / antipatterns / postmortem + CLAUDE.md Rules #25 / #33 / #36 / #37 + .mex Verify Checklist + worked-example commit hashes via `git show` BEFORE drafting any rule-promotion text; inventoried `backend/tests/fixtures/windows/` + `/data/firmware/projects/` + system-available real PEs BEFORE choosing the canary fixture shape; probed `verify_pe_file` against real PEs to confirm signify is in host venv + see what verdicts come back BEFORE writing assertions; read `_live_db.make_live_db()` shape + `WindowsPESignature` model fields + `HardwareFirmwareBlob` field shapes BEFORE drafting test seed helpers; read the actual `authenticode-chain` router prefix + the resolver's `extracted_path` gate BEFORE writing the HTTP-layer test | 6+ | Several would-be-wrong-shape decisions surfaced as evidence: the kickoff prompt's URL approximation `/firmware/{fw}/authenticode-chain` was wrong (actual: `/hardware-firmware/authenticode-chain?firmware_id=`); host venv DOES have signify (the prompt said it didn't — outdated); real host PEs return signed=False/unknown which informs what tier-1 can assert (vs requiring fixtures for criteria b/d/e); the `extracted_path` resolver gate would have produced a confusing 400 if not anticipated |
| Rule #21 mirror discipline | Caught the stale "rules 1–35 above" phrase in CLAUDE.md while drafting Rule #38 — β.13 missed it; β.14b corrected to "rules 1–38 above" in the same commit as the CLAUDE.md + .mex/context/conventions.md mirror | 1 | A 2-rule out-of-sync state would have rotted further with each rule promotion; manual count audits at next promotion would have hit the same kind of silent drift |
| Rule #25 per-sub-task commits | β.14a (test code, no production change) + β.14b (CLAUDE.md + .mex mirror, no test change) shipped as 2 separate focused commits; bisect-clean lanes preserved | 2 | A bundled "feat(β.14): full cut-over" commit would have mixed test code with rule text in one revert surface; bisect would have been less clean (the rule-promotion is doc-only and revertable independently of the canary set) |
| Rule #33 .c subtlety (just promoted in β.14b) | The promotion text itself encoded the subtlety so future agents reading the rule see "narrow Literal at the helper boundary, NOT the schema field" without needing to dig into the β.12 postmortem | 1 | Future-state: prevents the next "tighten FindingCreate.source" reflex on a similar enum extension. Rule-of-One worked example (`b67f062`); promotable to Rule-of-Two on the next similar enum addition |
| Rule #35a pipe-trap | Stayed clean throughout — every `cmd; rc=$?` invocation used the file-redirect pattern (`cmd > /tmp/foo.out 2>&1; rc=$?; tail`). No pipe-induced silent-success masks observed | 0 near-misses | Discipline maturing — Rule-of-Five across the campaign now (β.8 + β.9 + β.10 sibling + β.11 + β.14). Muscle memory holding |
| Rule #35b live canaries | 5 new live-canary tests in β.14a — 3 tier-1 always-runs (real PEs through unmocked verify_pe_file) + 2 tier-2/3 skip-unless-fixture canaries documenting fixture acquisition. The HTTP-layer test additionally exercises the full FastAPI dependency-injection chain + rate-limiter wrapper | 5 | Mock-only HTTP tests would have verified the 202 response shape but not value-flow through the real PE → signify → DBX → Finding emission path. The unmocked tier-1 tests catch any regression in the cumulative β.4-β.12 surface integration in one round-trip |
| Rule #38 (just promoted in β.14b) | Discipline held throughout the session — every git invocation was `git -C /home/dustin/code/wairz <subcmd>`, no `cd X && git` compounds anywhere. Bash CWD stayed at `/home/dustin/code/wairz/` (same as session start) for all 100+ tool calls | 0 near-misses | Rule promoted at end of β.12 postmortem; β.14 immediately practiced it. Discipline is durable now (Rule-of-Two — β.10 incident + β.12 incident, both as worked examples in the rule text; β.14 is the first session under the codified rule and held clean) |
| Cross-source-cleanup canary (β.12c precedent) | The `test_runner_does_not_delete_unrelated_findings_on_rerun` regression-guard from β.12c stayed green across the broader 299-test sweep — confirms β.12c's DELETE-scope discipline still holds across β.14a's new test additions | 1 | A regression in `verify_firmware_pe_chain`'s DELETE scope would have leaked into the new β.14a tests if it had been broken; the existing canary catches it before it could fail the new tests for the wrong reason |
| FastAPI TestClient + asyncio.create_task capture | The HTTP-layer test's novel pattern (capture `create_task`'d coroutines + await them deterministically) successfully bridged the asyncio-create_task fire-and-forget vs TestClient sync semantics gap | 1 | Without the capture pattern, the GET status would have raced the runner and intermittently returned `status="queued"` or `status="running"`; with it, the assertion `status == "completed"` is deterministic |

## Scope Analysis

- **Planned (per β.14 kickoff prompt):** Ship 2 focused commits — β.14a real-firmware end-to-end canary (1 commit; live canary in tests/, no production code change) + β.14b 3 candidate rule promotions (1 commit covering CLAUDE.md + .mex/context/conventions.md mirror per Rule #21). Design constraints: Rule #19 evidence-first reads of CLAUDE.md Rules #25/#33/#36/#37 + .mex Verify Checklist + worked-example commit hashes; Rule #19 inventory of available firmware fixtures; Rule #25 per-sub-task commit split (probably won't fold per single-slice exception); Rule #21 mirror in same commit; Rule #11 endpoint round-trip for Stream A; Rule #35a file-redirect; Rule #38 absolute paths over `cd` compounds.
- **Built:** 2 commits — β.14a (`77b257d`) added `backend/tests/test_authenticode_chain_real_firmware.py` (5 tests, 617 LOC) covering: tier-1 runner-direct smoke, tier-1 HTTP-layer round-trip via httpx ASGITransport, tier-1 outer-runner state machine, tier-2 MS-signed-PE skip-unless-fixture, tier-3 DBX-revoked-PE skip-unless-fixture. β.14b (`893dcac`) appended Rule #25 single-slice exception #2 + Rule #33 .c subtlety + new Rule #38 to CLAUDE.md, mirrored to .mex/context/conventions.md Verify Checklist, bumped `last_updated` 2026-05-04 → 2026-05-08, and corrected the stale "rules 1–35 above" → "rules 1–38 above" cross-reference.
- **Drift:** Zero scope drift. Kickoff prompt's 2-stream / 2-commit plan held exactly; the bundled-vs-split decision matched the kickoff's prediction ("probably not — Stream A is test code, Stream B is rule text; they're independently revertable"). Companion phrase fix (rules 1–35 → 1–38) was a surfaced-during-edit improvement, not scope creep — bundled into β.14b's single commit per Rule #21 spirit (cross-references between CLAUDE.md and .mex Verify Checklist should ship together).

## Patterns

- **Real-PE canary skip-tier discipline.** The β.14a test file ships 5 tests across 3 tiers: tier-1 always-runs (criteria a + c covered by host-available unsigned PEs through unmocked verify_pe_file); tier-2/3 skip-unless-fixture (criteria b / d / e covered when operator-provisioned MS-signed + DBX-revoked fixtures are committed). The skip-unless-fixture pattern documents the fixture-acquisition path in the test docstring so the canary graduates from skip → pass without code changes once provisioned. Rule-of-One (β.14a is the first instance in this codebase); pattern is novel and worth promoting to a recipe in `.mex/patterns/` on the second application.

- **TestClient + httpx ASGITransport + asyncio.create_task capture.** When a route fires `asyncio.create_task(background_runner(...))` per Rule #33 .d's create-task rubric, a TestClient round-trip can race the runner — the GET-status call returns `queued` / `running` instead of `completed`. The fix: monkeypatch `asyncio.create_task` to capture the spawned coroutine into a list, then `await captured[0]` directly inside the test before the GET-status call. Plus override `async_session_factory` (the runner's own factory) to redirect the runner's session to the live SQLite session. Rule-of-One (β.14a HTTP-layer test); pattern generalises to any 202+polling endpoint test that wants deterministic completion ordering.

- **Rule #21 mirror discipline + companion-phrase audit.** β.13 added Rule #36 + #37 but missed updating CLAUDE.md's "rules 1–35 above" cross-reference phrase. β.14b promoted Rule #38 AND caught the stale phrase, fixed both in the same commit. Mechanical heuristic: any rule promotion should grep `grep -n "rules 1[-–][0-9]" CLAUDE.md` and confirm the count matches the new total. The discipline is currently manual; a one-line CI check would automate it (Recommendation #1).

- **Stale-fixture-prompt URL approximations.** The β.14 kickoff prompt's URL `POST /api/v1/projects/{id}/firmware/{fw}/authenticode-chain` was approximate; the actual router prefix is `/hardware-firmware` and `firmware_id` is a query param. The kickoff prompt is a SPEC, not the source of truth — Rule #19 evidence-first applied: read `routers/hardware_firmware.py` to confirm the actual route shape BEFORE writing the test. The same discipline caught the `extracted_path` resolver gate. Same pattern across previous β-phase incidents (β.10's URL-shape mismatches in early canaries, β.11's frontend-route placeholders); discipline is durable.

- **Rule #25 per-sub-task commits is now Rule-of-Ten across this campaign.** β.5/β.6/β.7/β.8/β.9/β.10/β.11/β.12/β.13/β.14 each shipped per-sub-task commits with no `--no-verify` and no `--amend`. The discipline is durable; no new infrastructure needed.

- **Rule #35b live canary is now Rule-of-Ten across this campaign.** β.14a added 5 new live canaries (3 tier-1 always-runs through real ORM round-trips + 2 tier-2/3 skip-unless-fixture). Cumulative ~80 live canaries across β.4 through β.14. Discipline durable.

- **Rule #35a pipe-trap discipline holds Rule-of-Five.** β.8 + β.9 + β.10 + β.11 + β.14 all stayed clean; no `cmd | tail; rc=$?` pipe-induced silent-success masks. β.12 and β.13 had no near-misses either (clean discipline; both shipped with file-redirect throughout).

- **Rule #38 (just promoted) discipline applies cleanly its first session.** β.14 is the first session under the codified Rule #38; all 100+ Bash invocations used `git -C /home/dustin/code/wairz` for git + absolute paths or untouched-cwd for others; zero `cd X &&` compounds; zero CWD drift. Rule-of-Three when the next session also holds clean.

## Recommendations

1. **CI grep for stale rule-count cross-references.** β.13 missed updating CLAUDE.md's "rules 1–35 above" phrase when promoting Rules #36 + #37; β.14b caught it manually. The pattern indicates manual review at promotion time is unreliable. Add a one-line CI check or a harness rule:
   ```
   actual=$(grep -c '^[0-9]\+\. \*\*' CLAUDE.md)
   referenced=$(grep -oE 'rules 1[–-]([0-9]+)' CLAUDE.md | grep -oE '[0-9]+$' | tail -1)
   [ "$actual" = "$referenced" ] || { echo "stale rule-count cross-reference"; exit 1; }
   ```
   Cost: ~5 LOC. Benefit: catches the next promotion's missed phrase automatically.

2. **`scripts/build-windows-fixtures.sh` for tier-2/3 fixtures.** The β.14a tier-2 (MS-signed PE) + tier-3 (DBX-revoked PE) tests are skip-unless-fixture today; provisioning is manual per the test docstrings. A scripted analog to `scripts/refresh-ms-roots.sh` could:
   - For tier-2: download a redistributable Microsoft VC++ runtime, extract any signed DLL (e.g. `vcruntime140.dll`), copy to `backend/tests/fixtures/windows/ms_signed.dll`.
   - For tier-3: parse the bundled `dbxupdate.bin`, extract one revoked serial, find a known-compromised PE matching it (likely needs operator judgment for legal-source).
   Tier-3 is harder (legal-source PE matching) — start with tier-2 only. Cost: ~50 LOC bash + Dockerfile-build target. Benefit: tier-2 graduates from skip to pass automatically; one less manual step in CI.

3. **β.12 postmortem rec #5 (sidebar entry for /findings?source=windows_*) remains unimplemented.** Out of β.14 scope per the kickoff prompt; track in Phase γ or as a small follow-up doc-update commit alongside the next frontend rebuild.

4. **Phase γ + Phase δ next per the campaign PRD.** Phase β is now closed (α + β shipped, ε deferred to a separate campaign per D6). Phase γ = registry + drivers + persistence (regipy, INF/CAT, WHQL/attestation tier classification — Persona E #13). Phase δ = .NET + update-diff + storage (R2R-stomping detection, ilspycmd, KB-vs-KB diff). Both should run in fresh sessions per the β.12 postmortem rec #1 chain — domain shifts entirely, the β-phase Python+signify+DBX context doesn't help γ's regipy + INF/CAT focus.

5. **Knowledge-file commit cleanup.** The git status at session start showed 18+ untracked `.planning/knowledge/*-{patterns,antipatterns}.md` + `.planning/postmortems/postmortem-*.md` files accumulated across β.5–β.13 that were never committed. Some are session-only artefacts that may not belong in git; others are durable knowledge. Recommend a single doc-bundle commit OR a deliberate `.gitignore` rule for `.planning/knowledge/` if the convention is keep-local-only. Decision belongs to the operator; the artefacts themselves are valuable independently.

## Numbers

| Metric | Value |
|--------|-------|
| Sub-tasks planned (this session) | 2 (β.14a real-firmware canary + β.14b rule promotions) |
| Sub-tasks completed | 2 |
| Commits | 2 (`77b257d` β.14a, `893dcac` β.14b) |
| Files added | 1 (`backend/tests/test_authenticode_chain_real_firmware.py`, 617 LOC) |
| Files modified | 2 (`CLAUDE.md` +8/-3; `.mex/context/conventions.md` +7/-3) |
| Total LOC delta | +632 / -6 (β.14a +617 added; β.14b +15/-6 doc edits) |
| Tests added | 5 (3 tier-1 always-runs + 2 tier-2/3 skip-unless-fixture) |
| Tests passing (β.14a focused) | 3 passed, 2 skipped (rc=0) |
| Tests passing (broader sweep) | 299 passed, 3 skipped (rc=0) — `test_authenticode_chain_runner` + `test_authenticode_service` + `test_finding_service_pe_emit` + `test_finding_service` + `test_finding_source_alignment` + `test_dbx_service` + `test_jsonb_normalizers` + new file |
| Tests passing (final cross-cut) | 44 passed, 2 skipped (rc=0) |
| Reverts | 0 |
| Rework cycles | 0 (2 trivial test-side fixes within the same test-write loop — URL prefix + `extracted_path` — are not rework cycles by Rule #25's definition) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Anti-pattern warnings | 0 |
| Rule #11 import smoke runs | 0 (no class-shape change) |
| Rule #20 docker cp iterations | 0 (no migration) |
| Rule #20 / Rule #8 backend+worker rebuild cycles | 0 (no production code change) |
| Rule #25 commits | 2 (one per stream, both bisect-clean) |
| Rule #19 evidence-first applications | 6+ (β.12 knowledge files + CLAUDE.md rules + worked-example git show + fixture inventory + real-PE verdict probe + signify host-venv probe + _live_db shape + router/resolver shape) |
| Rule #21 mirror bundle commits | 1 (β.14b CLAUDE.md + .mex/context/conventions.md in same commit + companion-phrase fix) |
| Rule #33 .c subtlety promotion | 1 (β.14b appended to existing clause) |
| Rule #25 single-slice exception #2 promotion | 1 (β.14b appended to existing rule) |
| Rule #38 promotion (new) | 1 (β.14b new top-level rule) |
| Rule #35a `cmd; rc=$?` patterns | ~10 (signify probe, verdict probe, pytest sweeps × 4, git show, telemetry tail) |
| Rule #35a near-miss recoveries | 0 (file-redirect discipline held throughout) |
| Rule #35b live canaries added | 5 (3 tier-1 + 2 tier-2/3) |
| Rule #38 (just promoted) discipline holds | 100% (all git via `git -C /home/dustin/code/wairz`; no `cd X && git`; no CWD drift in 100+ Bash invocations) |
| CWD drift recoveries | 0 |
| Stale-phrase fixes | 1 ("rules 1–35 above" → "rules 1–38 above" in CLAUDE.md companion-scaffold section) |
| Tool registry growth | +0 (no new MCP tools) |
| Discipline slips | 0 (no `--no-verify`; no `--amend`; bare `git commit -m` per β-phase precedent now Rule-of-Ten) |

---HANDOFF---
- Postmortem: windows-coverage-godmode β.14
- Document: .planning/postmortems/postmortem-windows-coverage-godmode-beta14-2026-05-08.md
- Failures documented: 3 (HTTP-layer test URL mismatch + resolver-extracted_path 400 + β.13 stale rule-count phrase; all recovered instantly)
- Safety catches: 9 (Rule #19 × 6 evidence-first reads; Rule #21 mirror-discipline stale-phrase catch; Rule #25 commits × 2; Rule #33 .c subtlety promotion; Rule #35a discipline; Rule #35b live canary × 5; Rule #38 discipline 100% under codified rule; cross-source-cleanup canary; TestClient + create_task capture pattern)
- Recommendations: 5
---

Run `/learn windows-coverage-godmode-beta14` to extract patterns into the knowledge base.
