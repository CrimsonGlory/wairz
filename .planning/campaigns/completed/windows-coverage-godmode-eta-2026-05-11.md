# Campaign: Windows-Coverage God-Mode — Phase η (forensic-artifact horizontal expansion)

Status: CLOSED (5 of 5 streams shipped across 2 sessions; final close 2026-05-12)
Started: 2026-05-11
Closed: 2026-05-12
Direction: "let's continue in this new session with as much in parallel as possible … spawn /citadel:archon for wave decomposition. THIS is the primary work for the session."
Branch: direct-push to main per-piece (Pattern P5; Trust = trusted ≥184 sessions)
Parent intake: `.planning/intake/windows-coverage-godmode-eta-2026-05-11.md`
Parent campaign closure: `.planning/campaigns/completed/windows-coverage-godmode-zeta-prefetch-srum-plus-lint-cleanup-2026-05-10.md` (commit `3fc48b3`)

## Production state at start

- main HEAD = `69283ff` (origin/main, this session's housekeeping carryover commit)
- Alembic head = `c5f6e7d8a9b0` (SRUM findings-source extension; ζ.3 closed)
- 226 MCP tools registered (source-of-truth: `find backend/app/ai/tools -name '*.py' | xargs grep -c 'registry\.register' | awk -F: '{s+=$2}END{print s}'`)
- WindowsFindingSource Literal = 13 values (windows_authenticode → windows_srum_application_runtime)
- Lint CI: SUCCESS on `69283ff` (verified 2026-05-11 20:55 UTC)
- Backend Tests CI: in progress on `69283ff` at session start (deferred per Rule #41 mechanism (b) nightly cron at 06:00 UTC; first scheduled run 2026-05-13)
- Working tree: CLEAN (housekeeping committed in `69283ff`)
- Citadel session-allow gate: granted for git push + gh (this session)

## Direction

Phase η extends the windows-coverage-godmode lineage horizontally across 5 forensic-artifact gaps surfaced by 3-scout research-fleet synthesis (2026-05-11). All 5 streams are static analysis on firmware extracts; file-disjoint enough for Rule #23 worktree-per-stream parallelism; follow established Rule #39 inner/outer/safe runner triplet recipe (Rule-of-Five durable post-ζ.3.B).

## Phase 0 — 3-scout research fleet (COMPLETE 2026-05-11 21:00 UTC)

| Scout | Lens | Top 3 recommendations | Output |
|---|---|---|---|
| Scout 1 | OSS lib survey | #7 Shim .sdb (lowest risk) / #5 BitLocker detect-only / #1 Volatility 3 | `.planning/research/eta-scope-2026-05-11/scout-1-oss-tooling.md` |
| Scout 2 | Persona-E adversary refresh | #2 WMI persistence / #3 Boot chain artefacts / #1 BYOVD LOLDrivers | `.planning/research/eta-scope-2026-05-11/scout-2-persona-refresh.md` |
| Scout 3 | Competitive RE platform parity (KAPE/Plaso/Velociraptor) | #2 NTFS MFT/USN/LogFile / #8 Scheduled Tasks XML / #4 LNK files | `.planning/research/eta-scope-2026-05-11/scout-3-competitive-platforms.md` |

## Synthesis → η scope (5 streams)

Convergent picks (≥2 scouts agreeing):
- **Scheduled Task XMLs** — Scout 2 (sub-priority) + Scout 3 (#2). Stdlib XML; no new dep. → **η.B THIS session**.

Cheap-mention with mechanical evidence:
- **PowerShell EID 4103/4104 annotation** — Scout 3 cheap mention; mechanical grep on `evtx_service.py` confirmed the EIDs are NOT currently tagged → pure annotation extension, smallest possible scope. → **η.E THIS session**.

Single-lens HIGH with low integration risk:
- **NTFS $MFT walker** — Scout 3 #1 HIGH (`dissect.ntfs` MIT, biggest competitive gap, pairs with β.7 VHDX). LARGEST stream → **η.A NEXT session** (defer for hot-start avoidance).
- **LNK file walker** — Scout 3 #3 HIGH (CLAUDE.md acknowledged gap; `LnkParse3` named in 2026-05-07 intake but never added to pyproject — confirmed via grep). → **η.C THIS session**.
- **BYOVD LOLDrivers fingerprinting** — Scout 2 #3 HIGH (Rule #37 anchor + α.2.6 driver triplets + γ Services walk reuse). Requires Dockerfile + cron-script + bundle workflow → **η.D NEXT session** (Rule #37 anchor work has higher cut-over cost).

Deferred to θ (next campaign letter):
- WMI persistence (scout disagreement: Scout 2 HIGH / Scout 3 DEFER → defer for focused decision)
- Boot chain artefacts (BCD + MBR/VBR + ESP — multi-walker scope warrants own phase)
- Volatility 3 integration (no memory-dump intake flow yet — architectural prerequisite)
- Shim .sdb / RecycleBin / JumpList / Browser / EFS / EVT / ETL / hibernate.sys — various reasons enumerated in intake's "Out of scope" section.

## Decision Log

| # | Decision | Rationale | Outcome |
|---|---|---|---|
| 1 | 3-scout research-fleet pre-pass (OSS / persona-E / competitive) | Scope was 13 candidates; convergent ranking across 3 lenses gives higher-confidence pick than single-lens analysis | All 3 scouts returned ≤210s; synthesis surfaced 5 candidates with strong signal across at-least-one lens |
| 2 | η ships 3 streams THIS session, defers 2 to next session | Hot-start avoidance per `feedback_do_them_all_pattern.md`; smaller streams (η.B + η.C + η.E) ship in parallel via Agent worktrees, larger (η.A NTFS + η.D BYOVD anchor work) get fresh-context next session | 3 parallel worktree streams dispatched; ~10-12 commits expected this session |
| 3 | NTFS $MFT only in η.A (defer $UsnJrnl + $LogFile to θ) | Single-walker scope per η stream keeps Pattern P4 1-day-per-walker cadence; the other two NTFS files have distinct ORM tables + finding shapes warranting own phase letters | η.A scope is bounded; θ inherits a clear prerequisite |
| 4 | PowerShell EID annotation extends Literal with single value `windows_powershell_script_block` (NOT 4 separate per-EID values) | Literal describes the FINDING (a PowerShell script-block was logged), not the event-id taxonomy; sub-EID metadata into details dict; reduces alignment-test churn | Cross-stack alignment commit ships 1 new Literal value, not 4 |
| 5 | BYOVD LOLDrivers anchor follows Rule #37 (offline bundled, NOT scan-time fetch) | Network-time fetch defeats the worker's security boundary; rate-limit / attacker-MITM risk; reproducibility | `backend/ms-anchors/loldrivers.json` + sha256 + url + scripts/refresh-loldrivers.sh quarterly cron |
| 6 | Per-piece direct-push to main (Pattern P5) | Trust = trusted; Rule #41 must-complete CI mitigations healthy (Lint per-commit + backend-tests nightly cron); per-piece preserves bisect-clean per Rule #25 | Direct-push authorized; no worktree-merge step; cron nightly catches regressions <24h |

## Phase End Conditions

| Phase | Condition Type | Condition |
|---|---|---|
| η.A | command_passes | `( cd backend && uv run pytest tests/test_mft_walker.py tests/test_mft_models.py -v )` exits 0 |
| η.A | metric_threshold | MCP tool count ≥ 229 (was 226 baseline) |
| η.A | command_passes | `( cd frontend && npx tsc -b --force )` exits 0 |
| η.A | file_exists | `backend/app/services/mft_walker.py` |
| η.A | command_passes | `git -C /home/dustin/code/wairz log --oneline --grep='Phase η.A' \| wc -l` ≥ 6 |
| η.B | command_passes | `( cd backend && uv run pytest tests/test_scheduled_task_walker.py tests/test_scheduled_task_models.py -v )` exits 0 |
| η.B | metric_threshold | MCP tool count ≥ 229 (after η.B alone; +3 for `windows_scheduled_task` category) |
| η.B | command_passes | `( cd frontend && npx tsc -b --force )` exits 0 |
| η.B | file_exists | `backend/app/services/scheduled_task_walker.py` |
| η.B | command_passes | `git -C /home/dustin/code/wairz log --oneline --grep='Phase η.B' \| wc -l` ≥ 4 |
| η.C | command_passes | `( cd backend && uv run pytest tests/test_lnk_walker.py tests/test_lnk_models.py -v )` exits 0 |
| η.C | metric_threshold | MCP tool count ≥ 232 (after η.B + η.C cumulative; +6 from baseline) |
| η.C | command_passes | `( cd frontend && npx tsc -b --force )` exits 0 |
| η.C | file_exists | `backend/app/services/lnk_walker.py` AND `LnkParse3` in `backend/pyproject.toml` |
| η.C | command_passes | `git -C /home/dustin/code/wairz log --oneline --grep='Phase η.C' \| wc -l` ≥ 4 |
| η.D | command_passes | `( cd backend && uv run pytest tests/test_loldrivers_lookup.py tests/test_byovd_finding_emit.py -v )` exits 0 |
| η.D | metric_threshold | MCP tool count ≥ 233 (cumulative) |
| η.D | file_exists | `backend/ms-anchors/loldrivers.json` AND `backend/ms-anchors/loldrivers.json.sha256` AND `scripts/refresh-loldrivers.sh` |
| η.D | command_passes | `docker compose exec -T backend test -r /opt/wairz/loldrivers.json` exits 0 (post-rebuild) |
| η.D | command_passes | `git -C /home/dustin/code/wairz log --oneline --grep='Phase η.D' \| wc -l` ≥ 5 |
| η.E | command_passes | `( cd backend && uv run pytest tests/test_finding_service_powershell_emit.py tests/test_evtx_service.py -k 'powershell or 4104 or 4103' -v )` exits 0 |
| η.E | command_passes | `( cd frontend && npx tsc -b --force )` exits 0 |
| η.E | metric_threshold | `grep -c '"windows_powershell_script_block"' backend/app/schemas/finding.py` ≥ 1 |
| η.E | command_passes | `git -C /home/dustin/code/wairz log --oneline --grep='Phase η.E' \| wc -l` ≥ 2 |

## Active Context

**Phase η CLOSED 2026-05-12 — all 5 streams shipped to origin/main.**

### Continuation session (2026-05-12) — END STATE:

- η.A (NTFS $MFT walker) COMPLETE — `b7264af` → `9baefd9` (7 per-piece commits; Rule-of-Twelve + Rule #39 Rule-of-Eight)
- η.D (BYOVD LOLDrivers fingerprinting) COMPLETE — `3b2c78b` → `1f51716` (7 per-piece commits; Rule-of-Thirteen; new Rule #37 worked example; LOLDrivers bundle 29.79 MB bundled in `backend/ms-anchors/loldrivers.json`)
- Cron empirical (Rule #41 mechanism (b)) DEFERRED again — current 2026-05-12 ~01:15 UTC; trigger 2026-05-13 06:00 UTC (~29h away)
- End-of-session validation: Rule #8 backend+worker+migrator rebuild GREEN; Rule #11 import smoke ALL OK; frontend tsc -b --force ec=0; targeted pytest 138/138 PASS; alembic head verified in container = `a8b9c0d1e2f3`; LOLDrivers bundle mounted at `/opt/wairz/loldrivers.json` size 29,791,569 bytes

### Initial session (2026-05-11) — recap:

- Phase 0 + Phase 1 (research + synthesis) COMPLETE
- Phase 2 (intake + tracking + 3 scout reports) COMPLETE — `f27f0ee`
- η.E (PowerShell EID 4103/4104 annotation) COMPLETE — `ac98e55` (1 atomic alignment commit; Rule-of-Nine)
- η.B (Scheduled Task XML walker) COMPLETE — `24d72ee` → `110584d` (5 per-piece commits; Rule-of-Ten + Rule #39 Rule-of-Six)
- η.C (LNK file walker) COMPLETE — `88c3be0` → `d321ef2` (6 per-piece commits; Rule-of-Eleven + Rule #39 Rule-of-Seven)
- η.A + η.D DEFERRED to 2026-05-12 continuation session (now CLOSED above)

**Direction check:** aligned. Original direction was "next-frontier η+ decomposition for windows-coverage-godmode"; output is η decomposition with execution shipping 3 of the 5 streams (η.B + η.C + η.E) plus full pre-decomposition of the deferred η.A + η.D streams with end conditions ready for next-session pickup.

**Session totals:**
- 14 commits to main this session: 1 housekeeping + 1 Phase 2 + 1 η.E + 5 η.B + 6 η.C
- 82 new tier-1 tests (12 PowerShell + 41 Scheduled Task + 41 LNK) — but more accurately 12 + 41 + 41 = 94 if we count η.B and η.C model + walker + emit + tools tests separately
- WindowsFindingSource Literal: 14 (post-η.E) → 16 (post-η.B.D) → 17 (post-η.C.D) values; FE union mirrors at 34 values; alignment test green pairwise post-each-commit
- DB ck_findings_source CHECK: 30 (pre-session baseline post ζ.3.C) → 31 (η.E) → 32 (η.B.D) → 33 (η.C.D) values
- MCP tool count: 226 → 232 (+6 tools across windows_scheduled_task ×3 + windows_lnk ×3)
- Alembic head: `c5f6e7d8a9b0` (start) → `a7b8c9d0e1f2` (end) — 6 new revisions chained
- Rule #39 walker triplet recipe: Rule-of-Five → Rule-of-Seven (Pattern P4 1-day-per-walker stays durable)
- Rule #25 single-slice exception #2 cross-stack alignment: Rule-of-Eight → Rule-of-Eleven (3 alignment commits this session)
- Rule #41 Lint must-complete CI: green on every per-piece push within ~1 minute

**Cut-over verification (post Rule #8 backend+worker+migrator rebuild — COMPLETE):**

- Rule #8 `docker compose up -d --build backend worker migrator`: completed; new images for backend + worker + migrator (migrator exit 0; backend + worker UP).
- Rule #11 import smoke against REBUILT backend container: ALL OK
  - `from app.services.scheduled_task_walker import _do_scheduled_task_run, run_scheduled_task_walk_background, auto_scheduled_task_walk_firmware_safe` → OK
  - `from app.services.lnk_walker import _do_lnk_run, run_lnk_walk_background, auto_lnk_walk_firmware_safe` → OK
  - `from app.services.finding_service import _classify_powershell_event, _SOURCE_POWERSHELL_SCRIPT_BLOCK, _SOURCE_SCHEDULED_TASK_PERSISTENCE, _SOURCE_LNK_ABNORMAL_TARGET` → OK
  - `from app.schemas.finding import WindowsFindingSource; len(get_args(WindowsFindingSource))` → 17
  - `import LnkParse3` → OK
- Single alembic head verified in rebuilt container: `a7b8c9d0e1f2` ← η.C.D extension
- 81/81 finding_service regression sweep PASS (3 alignment + 19 base + 14 PE + 18 reg/driver + 12 PowerShell + 7 sched-task + 8 LNK) — host-side .venv pre-rebuild
- Lint CI green on every per-piece push of the session's 14 commits (verified via `gh run list`)
- Backend Tests CI: cancelled on intermediate per Pattern P5 / Rule #41 expected behavior under `concurrency.cancel-in-progress`; latest commit `9f56876` Backend Tests in_progress at session-close

## Continuation State

**2026-05-12 continuation session — 15 commits to main (full Phase η now CLOSED):**

```
5bc9c7c chore(harness): session counter 184→185 (η continuation session start)
b7264af deps(backend): add dissect.ntfs>=3.10 for Phase η.A NTFS $MFT walker
ad5f0fa feat(mft): add windows_mft_records model + alembic + JSONB normalizers (Phase η.A.A)
83442c6 feat(firmware): mft_walk_* 5-column 202+poll status set (Phase η.A.B)
255adcc feat(mft): Rule #39 walker triplet for NTFS $MFT (Phase η.A.C)
66bd8d6 feat(findings): MFT $DATA ADS + timestomp cross-stack alignment + emit (Phase η.A.D)
838ab64 feat(mft): wire MFT finding emit into auto_mft_walk_firmware_safe (Phase η.A.E)
9baefd9 feat(mcp): windows_mft MCP tool category — 3 tools (Phase η.A.F)
3b2c78b feat(byovd): bundle LOLDrivers v1 JSON anchor per Rule #37 (Phase η.D.0)
6160fc0 feat(byovd): Dockerfile COPY + docker-compose env var for LOLDrivers (Phase η.D.A)
8a2edc7 feat(byovd): scripts/refresh-loldrivers.sh quarterly cron script (Phase η.D.B)
6fee15f feat(byovd): loldrivers_lookup_service with hash-keyed lookup dict (Phase η.D.C)
e0403f5 feat(findings): BYOVD driver cross-stack alignment + emit (Phase η.D.D)
739473b feat(byovd): wire LOLDrivers lookup into α.2.6 driver-extractor hook (Phase η.D.E)
1f51716 feat(mcp): lookup_byovd_driver MCP tool — 235→236 (Phase η.D.F)
```

**Phase η CLOSED.** Recommended NEXT session actions (in priority order):

1. **Cron empirical (Item #1; deferred again):** on/after 2026-05-13 06:00 UTC, run `gh run list --workflow=backend-tests.yml --limit 10 --json event,conclusion,createdAt,headSha | jq '.[] | select(.event=="schedule")'`. If green, declare Rule #41 mechanism (b) validated and update `.mex/patterns/rule-41-must-complete-ci.md`.
2. **Move this campaign file to `.planning/campaigns/completed/`** — Phase η is CLOSED; the file belongs in the completed directory.
3. **Pick up Phase θ work** — pre-scoped in `.planning/intake/windows-coverage-godmode-eta-2026-05-11.md` "Out of scope (deferred to θ)" section: WMI persistence + Boot chain (BCD + MBR/VBR + ESP) + Volatility 3 + Shim .sdb / EFS / EVT / ETL / hibernate.sys.
4. **Follow-up intake for backend `.env` `WAIRZ_ALLOW_NO_AUTH=true` documentation** — 118-restart-count anomaly surfaced this session (postmortem What Broke #8).
5. **/citadel:learn windows-coverage-godmode-eta-2026-05-11** — extract patterns + antipatterns to harness.json quality rules.

---

**Initial session (2026-05-11) — 14 commits to main:**

```
69283ff chore(planning): housekeeping carryover from postmortem-rec-closures-2026-05-11 + session counter
f27f0ee chore(planning): open windows-coverage-godmode Phase η — intake + campaign + 3 scout reports
ac98e55 feat(findings): PowerShell EID 4103/4104 cross-stack alignment + emit (Phase η.E)
24d72ee feat(scheduled-tasks): add windows_scheduled_tasks model + alembic + JSONB normalizers (Phase η.B.A)
829c991 feat(firmware): scheduled_task_walk_* 5-column 202+poll status set (Phase η.B.B)
ac31527 feat(scheduled-tasks): Rule #39 walker triplet for Windows Scheduled Task XML (Phase η.B.C)
e149dcf feat(findings): scheduled-task persistence cross-stack alignment + emit (Phase η.B.D)
110584d feat(mcp): windows_scheduled_task MCP tool category — 3 tools (Phase η.B.E)
88c3be0 deps(backend): add LnkParse3>=1.5 for Phase η.C LNK file walker
4dffb0e feat(lnk): add windows_lnk_records model + alembic + JSONB normalizers (Phase η.C.A)
59fa091 feat(firmware): lnk_walk_* 5-column 202+poll status set (Phase η.C.B)
7e56881 feat(lnk): Rule #39 walker triplet for Windows Shell Link (.lnk) (Phase η.C.C)
fd7cd23 feat(findings): LNK abnormal-target cross-stack alignment + emit (Phase η.C.D)
d321ef2 feat(mcp): windows_lnk MCP tool category — 3 tools (Phase η.C.E)
```

**What should happen NEXT session (per CLAUDE.md Rules #25/#38/#35a/#41/#43):**

1. **Verify state with `git -C /home/dustin/code/wairz log --oneline -16`** — HEAD should be `d321ef2` plus a 15th commit being this campaign-file Feature Ledger update commit (TBD when Archon commits + pushes).
2. **Cron empirical** (kickoff Item #1; deferred from this session): on/after 2026-05-13 06:00 UTC, run `gh run list --workflow=backend-tests.yml --limit 10 --json event,conclusion,createdAt,headSha | jq '.[] | select(.event=="schedule")'`. If green, declare Rule #41 mechanism (b) validated and update `.mex/patterns/rule-41-must-complete-ci.md`. If failed pre-pytest, tune `pytest-must-complete` setup steps.
3. **Pick up η.A (NTFS $MFT walker)** — read this file's η.A sub-task list + intake's η.A section. LARGEST stream (~600-900 LOC across walker + 3 ORM + finding emit). Recipe is now under-2-day per walker (η.B + η.C each took ~25-30 min via single sub-agent dispatch). Add `dissect.ntfs>=3.10` to pyproject; mirror `lnk_walker.py` (η.C.C) shape but for $MFT.
4. **Pick up η.D (BYOVD LOLDrivers fingerprinting)** — read this file's η.D sub-task list + intake's η.D section. Distinct shape from η.A/B/C (NO new walker — extends α.2.6 driver-package unpacker + γ Services walk with hash-match against bundled `loldrivers.json`); requires Rule #37 offline-trust-anchor discipline (Dockerfile delta + `scripts/refresh-loldrivers.sh` quarterly cron).
5. **η.A + η.D can run in parallel via Rule #23 worktrees** (file-disjoint subsystems: NTFS walker vs driver hash-match service). Pre-allocated alembic chain order if parallel: η.A migrations (3) chain first, η.D migration (1 alignment only — no table) chains after η.A's tail.

**Deferred items list (kickoff-style):**

| Item | Status | Trigger / next-session notes |
|---|---|---|
| Cron empirical (Item #1) | DEFERRED until 2026-05-13 06:00 UTC | Diagnostic command in this file's "What should happen NEXT session" #2 |
| η.A NTFS $MFT walker | DEFERRED to next session | Pre-decomposed in this file's η.A section (8 sub-tasks; 6+ commits expected; ~2-day single-stream OR 1-day with sub-agent dispatch) |
| η.D BYOVD LOLDrivers | DEFERRED to next session | Pre-decomposed in this file's η.D section (8 sub-tasks; 5+ commits expected; Rule #37 anchor refresh discipline) |
| θ phase scope | DEFERRED | WMI persistence + Boot chain artefacts + Volatility 3 + Shim .sdb / EFS / EVT / ETL / hibernate.sys — see this file's "Out of scope (deferred to θ)" section in the parent intake |

## Feature Ledger

(Will be populated as streams complete.)

| Phase | Sub-task | SHA | Description | Tests |
|---|---|---|---|---|
| Pre-η | housekeeping carryover | `69283ff` | postmortem-rec-closures-2026-05-11 closure artifacts + session counter bump 183→184 | n/a |
| Phase 0/1 | research scouts + synthesis | (no commit) | 3 parallel scouts dispatched + synthesized → η.A-E scope locked | n/a |
| Phase 2 | intake + tracking + scouts | `f27f0ee` | `.planning/intake` + `.planning/campaigns` + `.planning/research/eta-scope-2026-05-11/scout-{1,2,3}*.md` (5 files, +655 LOC) | n/a |
| η.E | PowerShell EID 4103/4104 cross-stack alignment + emit (atomic) | `ac98e55` | alembic `e7f8a9b0c1d2` + Literal + `_classify_powershell_event` helper + 16-entry obfuscation table + `emit_evtx_findings_from_walk` extension + FE union + FE config + 12 tier-1 tests; **Rule-of-Nine** | 12/12 PASS; 3 alignment PASS; 66/66 broader |
| η.B.A | scheduled tasks model + alembic + JSONB normalizers | `24d72ee` | alembic `f8a9b0c1d2e3` + `WindowsScheduledTask` + register + 5 normalizers/stamps + 5 SCHEMA_VERSION constants + 5 ORM tests | 5/5 PASS |
| η.B.B | scheduled_task_walk_* status set | `829c991` | alembic `f9a0b1c2d3e4` + 5-column 202+poll set + Pydantic Literal + DB CHECK `ck_firmware_scheduled_task_walk_status` | (covered by walker tests) |
| η.B.C | scheduled task walker triplet | `ac31527` | Rule #39 inner/outer/safe `scheduled_task_walker.py` (defusedxml swap; **Rule-of-Six** for walker triplet recipe) + 19 walker tests | 19/19 PASS |
| η.B.D | scheduled task cross-stack alignment | `e149dcf` | alembic `a0b1c2d3e4f5` + Literal + classifier + emit + FE union + FE config + 7 emit tests; **Rule-of-Ten** | 7/7 PASS; alignment green |
| η.B.E | windows_scheduled_task MCP tools | `110584d` | 3 tools (search + status + trigger) + 10 tool tests; tool count 226 → 229 | 10/10 PASS |
| η.C.0 | LnkParse3>=1.5 dep | `88c3be0` | pyproject + uv.lock; resolves LnkParse3==1.6.0 (closes 2026-05-07 intake TODO) | (host import smoke OK) |
| η.C.A | lnk records model + alembic + JSONB normalizers | `4dffb0e` | alembic `b1d2e3f4a5c6` + `WindowsLnkRecord` + register + normalizers + 6 ORM tests | 6/6 PASS |
| η.C.B | lnk_walk_* status set | `59fa091` | alembic `c2e3f4a5b6d7` + 5-column 202+poll + Pydantic Literal + DB CHECK | (covered by walker tests) |
| η.C.C | lnk walker triplet | `7e56881` | Rule #39 inner/outer/safe `lnk_walker.py` (LnkParse3 + `_jsonify` datetime coercer; **Rule-of-Seven** for walker triplet recipe) + 17 walker tests | 17/17 PASS |
| η.C.D | lnk cross-stack alignment | `fd7cd23` | alembic `a7b8c9d0e1f2` + Literal + `_LnkFindingDraft` dataclass + classifier + emit + FE union + FE config + 8 emit tests; **Rule-of-Eleven** | 8/8 PASS; alignment green |
| η.C.E | windows_lnk MCP tools | `d321ef2` | 3 tools (search + status + trigger) + 10 tool tests; tool count 229 → 232 | 10/10 PASS |
| η.A.0 | dissect.ntfs>=3.10 dep | `b7264af` | pyproject + uv.lock; resolves dissect.ntfs==3.16 (AGPL-3.0; corrects intake's MIT claim); transitives `dissect.cstruct>=4,<5` + `dissect.util>=3,<4` (pure Python AGPL) | (host import smoke OK) |
| η.A.A | mft records model + alembic + JSONB normalizers | `ad5f0fa` | alembic `1f3a2b4c5d6e` (pre-allocated `d2e3f4a5b6c7` collided; substituted) + `WindowsMftRecord` + register + normalizers + 27 tests (21 normalizer + 6 ORM round-trip) | 27/27 PASS |
| η.A.B | mft_walk_* status set | `83442c6` | alembic `2a4b3c5d6e7f` + 5-column 202+poll + Pydantic Literal + DB CHECK `ck_firmware_mft_walk_status` | (covered by walker tests) |
| η.A.C | mft walker triplet | `255adcc` | Rule #39 inner/outer/safe `mft_walker.py` (dissect.ntfs `NTFS(fh)` + `mft.segments()` + per-record $STD_INFO / $FILE_NAME / $DATA extraction; **Rule-of-Eight** for walker triplet recipe) + 31 walker tests; Rule #30 mock-at-source for fixture generation | 31/31 PASS |
| η.A.D | mft cross-stack alignment | `66bd8d6` | alembic `3b5c4d6e7f8a` + Literal + `_MFTFindingDraft` + classifier helpers (`_classify_mft_ads_hidden` + `_classify_mft_timestomp` + `classify_mft_findings`) + emit + FE union + FE config + 17 tests (14 emit + 3 alignment); **Rule-of-Twelve** for Rule #25 single-slice exception #2 cross-stack alignment | 17/17 PASS; alignment green |
| η.A.E | wire MFT emit into auto_mft_walk_firmware_safe | `838ab64` | emit hook + Rule #35b live-canary test verifying `confidence` field persistence | 1/1 PASS |
| η.A.F | windows_mft MCP tools | `9baefd9` | 3 tools (search_mft_records + mft_walk_status + trigger_mft_walk) + 12 tool tests; tool count 232 → 235 | 12/12 PASS |
| η.D.0 | LOLDrivers v1 JSON bundle per Rule #37 | `3b2c78b` | `backend/ms-anchors/loldrivers.json` 29.79 MB (intake's 5-10 MB estimate stale by 3-6x; scout-corrected) + .sha256 + .url + .LICENSE (Apache-2.0) + .NOTICE per redistribution terms; SHA256 pin `ddda516c90150069d1ca8b8a6151f53adadfd5608534a0e95265574792b81fec` | (post-push round-trip verified) |
| η.D.A | Dockerfile COPY + docker-compose env var | `6160fc0` | Dockerfile COPY + sha256sum -c verify at build + place at /opt/wairz/loldrivers.json + docker-compose `LOLDRIVERS_BUNDLE_PATH` on backend + worker | (covered by lifespan probe) |
| η.D.B | refresh-loldrivers.sh quarterly cron | `8a2edc7` | atomic download .tmp + rename + SHA256 compare + non-zero on drift + `--apply` + `--rebuild` flags; quarterly cadence (upstream releases ~5/week — borderline-stale; documented in script comments) | (script in scripts/) |
| η.D.C | loldrivers_lookup_service with hash-keyed dict | `6fee15f` | `lookup_driver_byovd(blob_sha256)` + `is_loldrivers_available()` + Rule #35c normalizer (coalesces CVE/CVEs key drift + merges 23-records flat/nested hash anomaly; lowercases hex hash boundary) + lifespan startup probe + 25 tests | 25/25 PASS |
| η.D.D | byovd cross-stack alignment | `e0403f5` | alembic `a8b9c0d1e2f3` (pre-allocated; verified free pre-dispatch) + Literal + `_BYOVDFindingDraft` + `classify_byovd_finding` + emit + FE union + FE config + 11 tests (8 classifier + 3 Rule #35b live-canary); **Rule-of-Thirteen** for Rule #25 single-slice exception #2 cross-stack alignment | 11/11 PASS; alignment green |
| η.D.E | wire BYOVD lookup into α.2.6 driver-extractor hook | `739473b` | emit at unpack-time for matched drivers; γ Services walker hook DEFERRED per Rule #19 evidence-first (Services-walk → ImagePath → driver-blob resolution not currently exposed in `registry_hive_walker.py`; out-of-scope) + 2 tests | 2/2 PASS |
| η.D.F | lookup_byovd_driver MCP tool | `1f51716` | extends `windows_driver` category with `lookup_byovd_driver` (blob_id resolution to SHA256 + verdict + LOLDrivers reference URL) + 4 tests; tool count 235 → 236 | 4/4 PASS |

## Reversibility

**Amber.** Multi-phase campaign; revert per-stream via individual `git revert <sha>` per per-piece commit per Rule #25. The Rule #37 anchor work in η.D (defer) is the highest-blast-radius change (Dockerfile + cron-script + bundled JSON); per Step Reversibility framework, η.D is the nearest-to-Red action and warrants extra confirmation at execution time.

## Trust Gating

Trust level read from `.claude/harness.json:399` `sessions_completed: 184` → trusted (≥20 sessions). No confirmation needed for amber actions. Red-class actions (force-push, repo-config edits) WOULD require confirmation but are not in scope for η.

## Daemon

Not activated this session. Step 2.5 trust-gated offer for trusted users is "Run continuously? (~${cost}) [y/n]" — but the user already authorized continuous parallel work via the kickoff prompt ("as much in parallel as possible" + Trust=trusted + Pattern P5 per-piece direct push). Explicit daemon activation skipped to keep session bounded; if remaining η.A + η.D + θ work warrants overnight execution, the next session can `/daemon start` against this campaign.
