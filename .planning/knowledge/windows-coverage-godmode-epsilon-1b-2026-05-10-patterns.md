# Patterns: Windows-Coverage God-Mode ε.1.b (2026-05-10)

> Extracted: 2026-05-10
> Campaign: `.planning/campaigns/completed/windows-coverage-godmode-epsilon-1b-2026-05-10.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-epsilon-1b-2026-05-10.md`
> Branch: `feat/windows-phase-epsilon-2026-05-10`
> Commits in scope: `9e839a1..c86cf90` (ε.1.b.1 through ε.1.b.5 + housekeeping)
> Status: 5 sub-tasks completed; campaign Phase ε.1.b CLOSED

This is an incremental extraction layered on top of:
- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α + β.1–β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta7-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta8-beta9-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta10-beta13-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta11-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta12-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta14-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-gamma-2026-05-09-{patterns,antipatterns}.md`
- `windows-coverage-godmode-delta-2026-05-09-{patterns,antipatterns}.md`

Patterns already captured there are not re-stated; this file captures only the ε.1.b-delta learnings.

## Successful Patterns

### 1. Inner-vs-outer-vs-safe runner triplet (Rule-of-Three durable)

- **Description:** Background runners that own a Rule #33 .a state machine via `async_session_factory()` ship as a triplet of three functions:
  - `_do_<op>_run(db: AsyncSession, firmware_id: uuid.UUID) -> dict` — INNER pure-logic orchestrator. Accepts `db`. Resolves detection roots via `get_detection_roots` (Rule #16). Walks + parses + aggregates. Returns the result dict UNSTAMPED (caller stamps).
  - `run_<op>_background(firmware_id: uuid.UUID) -> None` — OUTER state-machine wrapper. Owns the 5-state transitions `idle → running → completed | failed` via `async_session_factory()`. Calls inner. Outer guard catches anything that escapes; failure persistence on a fresh session because the inner session rolled back.
  - `auto_walk_firmware_safe(firmware_id: uuid.UUID) -> None` — UNPACK-POST-DETECTION HOOK. Owns own session, swallows exceptions, logs only. Stamps result aggregate so operator can see the walk happened, but DOES NOT mutate the firmware status field — leaves it `idle` so a manual re-trigger via the trigger MCP tool works without 409 conflict.
- **Evidence:** ε.1.b.3 commit `c0e4979` — `evtx_service._do_evtx_walk_run` + `run_evtx_walk_background` + `auto_walk_firmware_safe`. γ.4 implicit precedent + δ.5 first explicit codification + ε.1.b.3 second explicit codification. **Rule-of-Three confirmed.**
- **Applies when:** Authoring any Rule #33 202+poll background work that needs (a) tier-1 testability via `make_live_db()`, AND (b) auto-fire-on-unpack semantics, AND (c) explicit operator-triggered re-runs. Recipe candidate for `.mex/patterns/inner-outer-safe-runner.md`. CLAUDE.md Rule #39 candidate.

### 2. Alembic revision-ID pre-validation script (eliminates the rotating-hex collision trap)

- **Description:** Before authoring any alembic migration, run a one-second Python regex script that enumerates all revision IDs in the versions tree and pre-validates a batch of candidates:
  ```python
  ( uv run python -c "
  import re, glob
  ids = set()
  for p in glob.glob('alembic/versions/*.py'):
      txt = open(p).read()
      m = re.search(r'(?m)^revision[: \\w]*=\\s*[\"\\']?([a-f0-9]+)', txt)
      if m: ids.add(m.group(1))
  for cand in ['e0a1b2c3d4e5', 'e1a2b3c4d5e6', 'e2a3b4c5d6e7', ...]:
      print(f'{\"TAKEN\" if cand in ids else \"FREE \"} {cand}')
  " )
  ```
  Pre-validate 4-8 candidates in one batch when authoring a multi-migration phase. Avoids the δ.3 antipattern (rotating-hex collisions with orphan migrations from unmerged branches; δ.3 hit two consecutive collisions).
- **Evidence:** ε.1.b session pre-validated `e0a1b2c3d4e5` (used in ε.1.b.2) and `e1a2b3c4d5e6` (used in ε.1.b.4) along with 6 more reserve candidates in one batch. Zero collisions across both ε.1.b migrations. The Python regex script runs in <1s.
- **Applies when:** Any session that will author one or more alembic migrations. Cost: 1 second + 8 candidate IDs in advance. Benefit: eliminates the multi-collision-retry trap. Promotable to `.mex/patterns/add-alembic-migration.md` recipe (already in PR #2). Mandatory pre-flight for migration-authoring sessions.

### 3. Authoritative head detection via Python regex over versions/*.py (when alembic CLI unavailable)

- **Description:** When the running container is offline / not built / image-changes-pending, find the current alembic head via a Python script over the versions directory. Walk the chain: every revision whose ID is NOT referenced by any other migration's `down_revision` is a head. A clean tree has exactly one head.
  ```python
  revs = {}
  for p in sorted(glob.glob('alembic/versions/*.py')):
      txt = open(p).read()
      rev_m = re.search(r'^revision(?:\s*:[^=]+)?\s*=\s*[\'"]([a-f0-9]+)[\'"]', txt, re.MULTILINE)
      down_m = re.search(r'^down_revision(?:\s*:[^=]+)?\s*=\s*[\'"]?([a-f0-9]+|None)[\'"]?', txt, re.MULTILINE)
      if rev_m:
          revs[rev_m.group(1)] = (down_m.group(1) if (down_m and down_m.group(1) != 'None') else None, p)
  referenced = {d for (d, _) in revs.values() if d}
  heads = [r for r in revs if r not in referenced]
  ```
  Crucially the regex must include `(?:\s*:[^=]+)?` to handle the `revision: str = "..."` annotated form (which is what δ-vintage migrations use).
- **Evidence:** First attempt at the regex used `^revision[: \\w]*=` which under-matched annotated forms — script returned 50 false-positive heads instead of 1. Fixed regex returned correctly: 1 head (`d5a6b7c8d9e0`), 60 total revisions, 59 referenced.
- **Applies when:** Need to confirm alembic head before authoring migrations OR before chaining a new migration off the existing tip. Companion to Pattern #2 (revision-ID pre-validation). Both can run in the same script.

### 4. Bash pipe-trap avoidance for exit-code capture (Rule #35a worked example)

- **Description:** When capturing an exit code after a command, NEVER use the pipe form. Three safe forms:
  - **File-redirect form (preferred when output is large):** `cmd > /tmp/log 2>&1; ec=$?; tail /tmp/log` — `$?` reflects `cmd` directly; pipe is gone.
  - **Direct form (preferred when output is small):** `cmd; ec=$?; echo "exit=$ec"` — no pipe at all.
  - **PIPESTATUS form (last resort if pipe unavoidable):** `cmd | tail -5; echo "exit=${PIPESTATUS[0]}"` — works in bash but not POSIX sh.
- **Evidence:** ε.1.b's first Rule #24 mandatory canary used `npx tsc -b --force 2>&1 | tail -15; echo "exit=$?"` and reported `exit=0` despite TS2322 visible — the pipe captured tail's exit. Re-ran with file-redirect form: `tsc > /tmp/log 2>&1; ec=$?; tail /tmp/log` correctly produced `exit=2`.
- **Applies when:** Any `Bash` invocation that needs to verify an exit code. The Bash tool runs in `set +o pipefail` mode by default; pipes mask exit codes silently. Companion to Rule #17 (silent CLI exit canary) and Rule #24 (mandatory tsc canary). Cost: zero — file-redirect is just as concise. Benefit: eliminates the silent-success class of bug at exit-code-checking sites.

### 5. Regex-based no-execute discipline test gate (extension of Rule #36 codification)

- **Description:** Where δ.4 codified Rule #36 via `assert_no_execute_argv(argv: list[str])` (subprocess argv-token check), ε.1.b extends the discipline to a SOURCE-FILE regex scan: `re.search(r"\bsubprocess\.run\s*\(", src)` for every forbidden token. Matches the CALL FORM (`X.Y(` with paren), not the bare token — so docstring mentions of forbidden tokens (which legitimately explain the rule) don't false-positive.
  ```python
  forbidden_call_patterns = (
      r"\bsubprocess\.run\s*\(",
      r"\bsubprocess\.Popen\s*\(",
      ...
      r"\basyncio\.create_subprocess_exec\s*\(",
      ...
  )
  for pat in forbidden_call_patterns:
      assert re.search(pat, src) is None, f"Rule #36 violation: {pat}"
  ```
- **Evidence:** ε.1.b.5 commit `8deadb1` — `test_evtx_real_firmware.py::test_tier1_no_execute_discipline_in_evtx_paths`. First draft used bare-token check `assert "subprocess.run" not in src` and false-positived on the docstring; refined to call-form regex. 10 forbidden patterns × 1 source file scan = 0 violations.
- **Applies when:** A service module needs Rule #36 enforcement but doesn't shell out at all (so the δ.4 argv-gate doesn't apply). Pure data-only services — EVTX parser, registry walker, etc. Two shapes of Rule #36 codification: (a) δ.4 argv-gate for services that DO spawn subprocesses (must verify argv[0] is trusted), (b) ε.1.b source-scan for services that DON'T spawn at all (must verify they never start).

### 6. Rule #25 single-slice exception #2 — Rule-of-Five durable (mature beyond doubt)

- **Description:** ε.1.b.4 bundled the alembic migration extending `ck_findings_source` + Pydantic `WindowsFindingSource` Literal extension + finding_service constants + `emit_evtx_findings_from_walk` + frontend `FindingSource` union extension + `FINDING_SOURCE_CONFIG` entries + `EvtxWalkPage.tsx` + App.tsx route registration + 6 MCP tools (registry 213→219) + `unpack.py` auto-walk hook in ONE atomic commit, per Rule #25 single-slice exception #2 (cross-stack alignment tests require pairwise agreement; splitting leaves the alignment test RED between commits and breaks bisect-clean lanes).
- **Evidence:** ε.1.b.4 commit `5466644`. The `test_finding_source_alignment.py` tests (3/3) pass on the bundled commit and would have been RED if any of the 4 surfaces had been split off. **Rule-of-Five now**: `7079b4d` (2026-05-06) + `ee2abd9` (β.12a) + `f70c2e1` (γ.7) + `20ea228` (δ.8) + `5466644` (ε.1.b.4). **Pattern is durable beyond reasonable doubt.**
- **Applies when:** Any cross-stack enum extension where `test_finding_source_alignment.py` (or analog) enforces pairwise agreement across DB CHECK ↔ FE union ↔ FE config. Bundle in one commit. Bisect-clean is preserved. Codified in CLAUDE.md Rule #25 — Rule-of-Five citation should be added.

### 7. JSONB normalizer + schema_version + stamp helper discipline (extends to Rule-of-Seven)

- **Description:** Rule #35c JSONB normalizer + stamp + schema_version discipline applied uniformly to one new tree-shaped JSONB column in ε.1.b:
  - `firmware.evtx_walk_result` (ε.1.b.3): per-firmware aggregate (run_seconds + evtx_count + by_provider histogram + by_status counts + total_records + sample_records_per_file cap + errors + per_file shape).
  Shipped with normalizer (None-preserving defensive coercion) + stamp helper (idempotent schema_version=1) + 11 tests covering canonical / None / wrong-type / idempotency.
- **Evidence:** ε.1.b.3 commit `c0e4979`. Plus γ added 3 + δ added 3 = **Rule-of-Seven application of Rule #35c**, cumulatively 7 windows-coverage normalizers (4 in γ+δ + 3 in pre-γ + 1 in ε). Pattern is mature beyond doubt.
- **Applies when:** Adding any tree-shaped JSONB column with ≥3 consumer files (ε.1.b's was 3+: writer + ≥1 MCP reader + ≥1 FE reader + finding_service emit hook). Reference recipe is `.mex/patterns/add-jsonb-column.md`.

### 8. Rule #19 evidence-first generalises to "verify at change-time, not consumer-session-time"

- **Description:** When a campaign explicitly defers a verification step (e.g. closeout PR #2 ε.2's "rebuild verification deferred to next session"), the deferral creates a latent failure mode that surfaces as a campaign-blocker for the NEXT consumer. ε.1.b's housekeeping commit `c86cf90` was forced because the closeout's deferred Rule #8 rebuild surfaced the `libpff-utils` Trixie packaging bug at ε.1.b cut-over time, not at closeout time. Rule #19 evidence-first should generalise: any change that touches infrastructure (Dockerfile, docker-compose.yml, alembic chain) MUST verify the rebuild succeeds in the same session — no exception, no "deferred to next session" allowed.
- **Evidence:** ε.1.b commit `c86cf90` is the housekeeping fix for the closeout deferral. The closeout campaign feature ledger explicitly noted "rebuild verification deferred to next session" — this is the Rule-of-One occurrence to flag.
- **Applies when:** Any commit touching `Dockerfile`, `docker-compose.yml`, alembic versions, or other infrastructure files. The session that authors the change MUST run the rebuild + smoke before declaring complete. Defer ANY verification to next session = create a campaign-blocker for next consumer. Promotable to a CLAUDE.md Rule #8 extension if it recurs.

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | DEFER `windows_event_records` per-event table to a future ζ.X phase | `firmware.evtx_walk_result` JSONB aggregate is sufficient for the walk-summary; per-event search indexing layers on top later without breaking the schema. Lean shape matches Rule #19 evidence-first. | Correct — ε.1.b shipped without the table; future ζ.X can add it as additive migration |
| 2 | `walk_evtx_files` takes `roots: Iterable[str]` not the original `extracted_path: Path` from ε.1.a's docstring | Match γ.4 `scan_for_hives` exactly. Caller (inner orchestrator) calls `get_detection_roots(firmware)` first per Rule #16. | Correct on first attempt; ε.1.a docstring updated in same commit (`9e839a1`) to match |
| 3 | Three new finding sources for Persona-E #4 forensic-timeline trio: `windows_sysmon_proc_create` + `windows_logon_success` + `windows_logon_failure` | Sysmon EID 1 + Security EID 4624 + Security EID 4625 are the three EIDs operators triage first in any Windows compromise investigation; LOW-confidence baseline ships now, heuristic-match → MEDIUM and threat-feed-correlation → HIGH deferred to ζ.X | Correct; cross-stack alignment passes with 28-source allowlist |
| 4 | ε.1.b.4 single-slice exception #2 — bundle 10 surfaces (alembic + Literal + 3 source constants + emit hook + 6 MCP tools + auto-walk hook + FE union + FE config + FE page + route) in ONE commit | Per-Rule #25 exception #2 — the alignment test would have been RED between commits if any surface had been split off; splitting also breaks bisect-clean lanes. The cross-stack pairwise agreement requirement is the load-bearing constraint. | Correct; **Rule-of-Five durable** for single-slice exception #2 |
| 5 | LOW-confidence baseline for ε.1.b.4 emit hook (every Sysmon-1 / 4624 / 4625 record gets a low-confidence review-candidate Finding) | Higher-tier classification (heuristic-match → MEDIUM, threat-feed → HIGH) is deferred to ζ.X once per-event row persistence lands and supports full-record inspection. The aggregate's per-file sample is sufficient evidence for the LOW baseline today. | Correct; emit hook ships pure-detection LOW review candidates; ζ.X layers heuristic tiers on top |
| 6 | Use `python3-pypff` to replace `libpff-utils` (which doesn't exist in Trixie) | The libyal toolchain ships utilities differently per format on Trixie — `libesedb-utils` and `libregf-utils` exist; `libpff-utils` doesn't (the libpff CLI usage shape is via the Python bindings). δ.7 windows_storage's PST handling can use python3-pypff for in-process parsing rather than a CLI tool. | Correct; `docker compose build --pull backend worker migrator` succeeded after the swap |
| 7 | Use `gh api -X PATCH /repos/.../pulls/3 --field body=@file` instead of `gh pr edit --body-file` | The `gh pr edit` GraphQL-backed CLI was failing silently due to a Projects-classic deprecation warning; the REST API direct path bypassed the warning entirely. | Correct; PR #3 body updated to ε.1.b summary; workaround documented in postmortem Recommendation #5 |

## Cross-references back into existing knowledge

- **Pattern #1 (inner/outer/safe runner triplet)** is the THIRD application of the inner-vs-outer split — γ.4 implicit precedent + δ.5 explicit + ε.1.b.3 explicit. **Rule-of-Three confirmed; PROMOTE** to CLAUDE.md Rule #39 + `.mex/patterns/inner-outer-safe-runner.md` recipe per postmortem Recommendations #3 + #4.
- **Pattern #2 (alembic revision-ID pre-validation)** confirms the durable shape of the `.mex/patterns/add-alembic-migration.md` recipe (PR #2). Zero collisions across two ε.1.b migrations.
- **Pattern #3 (Python regex over alembic versions/*.py for head detection)** is novel within this codebase as an explicit pattern. Useful when the running container is offline. Promotable to a CLAUDE.md note or a `.mex/patterns/` recipe on second occurrence.
- **Pattern #4 (Bash pipe-trap avoidance for exit-code capture)** is a worked example of Rule #35a applied to the Rule #24 mandatory canary. The file-redirect form is the canonical fix; Rule #35a already codifies the principle.
- **Pattern #5 (regex-based no-execute discipline test)** is a NEW shape of Rule #36 codification — distinct from δ.4's argv-gate. Both shapes coexist depending on whether the service spawns subprocesses or not. Companion test gate.
- **Pattern #6 (Rule #25 single-slice exception #2)** is now **Rule-of-Five** (`7079b4d` + `ee2abd9` β.12a + `f70c2e1` γ.7 + `20ea228` δ.8 + `5466644` ε.1.b.4). Pattern is durable beyond reasonable doubt. Codified in CLAUDE.md Rule #25 — citation should be added.
- **Pattern #7 (Rule #35c JSONB normalizer + stamp + schema_version)** is the SEVENTH application since codified at audit-2026-05-04. Pattern is mature beyond the rule-of-three bar.
- **Pattern #8 (Rule #19 generalisation to "verify at change-time")** is a NEW lesson surfaced by ε.1.b's housekeeping commit. Rule-of-One; if it recurs the rule should be updated.
- **Rule #25 per-sub-task commits** is now **Rule-of-Thirteen across the windows-coverage campaign** (α 12 + β 14 + γ 9 + δ 9 + ε.1.b 6 = 50 commits, 0 reverts). Pattern is durable beyond reasonable doubt.
- **Rule #35a pipe-trap reproducibility** — ε.1.b used the file-redirect + capture-before-tail discipline for the Rule #24 tsc canary. Codified rule + canary discipline both held.
- **Rule #35b live canary** is now applied across γ + δ + ε.1.b to ~41 new live canaries (γ added 13 + δ added 18 + ε.1.b added 4 + 6 in jsonb tests). Cumulative ~115 live canaries across α + β + γ + δ + ε.1.b.
- **Rule #36 no-execute discipline** — ε.1.b extends the rule from installer custom actions (α.2) + Authenticode (β.4) + registry (γ.4) + driver INF/CAT (γ.5) + .NET single-file bundles (δ.4) + capa-on-IL (δ.6) to EVTX (ε.1.b.3 — python-evtx parses EVTX as DATA via mmap; never invokes wevtutil / Get-WinEvent / scriptable replay). The regex-based source-scan test gate is the new instance-of-the-rule.
- **Rule #38 absolute-path bash discipline** — ε.1.b caught one mid-flow CWD drift instance (after `cd backend && uv run`) and corrected with explicit subshell `(uv run ...)` for the rest of the session. Validates the discipline rather than violating it. Net 0 incidents in the commit log. Rule-of-Four+ clean (β.14 + γ + δ + ε.1.b).
