# Campaign: Windows-Coverage God-Mode — Phase η (forensic-artifact horizontal expansion)

Status: in-progress
Started: 2026-05-11
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

**This session (2026-05-11):**

- Phase 0 + Phase 1 (research + synthesis) COMPLETE
- Phase 2 (intake + tracking file) JUST COMPLETED (this writeup)
- Wave 1 dispatch: η.B + η.C + η.E parallel via Agent worktrees — IMMINENT
- η.A (NTFS) + η.D (BYOVD) DEFERRED to next session

**Direction check:** aligned. Original direction was "next-frontier η+ decomposition for windows-coverage-godmode"; output is η decomposition with execution starting on the 3 cheapest streams. Larger streams properly scoped for next session.

## Continuation State

**Files modified so far this session (Archon control plane):**
- `.planning/intake/windows-coverage-godmode-eta-2026-05-11.md` (NEW — full η scope + sub-tasks + end conditions)
- `.planning/campaigns/windows-coverage-godmode-eta-2026-05-11.md` (NEW — this file)
- `.planning/research/eta-scope-2026-05-11/scout-{1,2,3}*.md` (NEW — 3 scout reports)

**Files modified this session (housekeeping carryover, pre-Archon):**
- `.claude/harness.json` (counter bump 183→184) — committed in `69283ff`
- `.planning/postmortems/postmortem-rec-closures-2026-05-11.md` (NEW closure artifact) — committed in `69283ff`
- `.planning/knowledge/postmortem-rec-closures-2026-05-11-{patterns,antipatterns}.md` (NEW closure artifacts) — committed in `69283ff`

**What should happen next** (in this session):
- Stage + commit + push the intake + campaign + 3 scout reports as ONE Phase 2 closure commit
- Dispatch 3 parallel Agent worktree streams for η.B + η.C + η.E
- Wait for stream completions
- Per-stream review + per-piece direct-push to main per Pattern P5
- End-of-session HANDOFF + next-session resume prompt

**What should happen next session:**
- Pick up η.A (NTFS $MFT walker) — read this file's η.A sub-task list + end conditions
- Pick up η.D (BYOVD LOLDrivers fingerprinting) — read η.D sub-task list + Rule #37 anchor discipline
- Both can run in parallel (file-disjoint subsystems)
- Cron empirical (parent kickoff Item #1) — verify nightly backend-tests run on/after 2026-05-13 06:00 UTC

## Feature Ledger

(Will be populated as streams complete.)

| Phase | Sub-task | SHA | Description | Tests |
|---|---|---|---|---|
| Phase 0 | Research scout pre-pass | (no commit) | 3 parallel scouts dispatched + synthesized | n/a |
| Phase 1 | Scope decision | (no commit) | 5 streams locked (η.A through η.E) | n/a |
| Phase 2 | Intake + tracking file | TBD | this writeup | n/a |
| η.B.A | scheduled tasks model | TBD | TBD | TBD |
| η.B.B | scheduled tasks status | TBD | TBD | TBD |
| η.B.C | scheduled tasks walker | TBD | TBD | TBD |
| η.B.D | scheduled tasks alignment | TBD | TBD | TBD |
| η.B.E | scheduled tasks MCP tools | TBD | TBD | TBD |
| η.C.0 | LnkParse3 dep | TBD | TBD | TBD |
| η.C.A | lnk records model | TBD | TBD | TBD |
| η.C.B | lnk walk status | TBD | TBD | TBD |
| η.C.C | lnk walker triplet | TBD | TBD | TBD |
| η.C.D | lnk alignment | TBD | TBD | TBD |
| η.C.E | lnk MCP tools | TBD | TBD | TBD |
| η.E.A | powershell alignment | TBD | TBD | TBD |
| η.E.B | powershell emit hook | TBD | TBD | TBD |

## Reversibility

**Amber.** Multi-phase campaign; revert per-stream via individual `git revert <sha>` per per-piece commit per Rule #25. The Rule #37 anchor work in η.D (defer) is the highest-blast-radius change (Dockerfile + cron-script + bundled JSON); per Step Reversibility framework, η.D is the nearest-to-Red action and warrants extra confirmation at execution time.

## Trust Gating

Trust level read from `.claude/harness.json:399` `sessions_completed: 184` → trusted (≥20 sessions). No confirmation needed for amber actions. Red-class actions (force-push, repo-config edits) WOULD require confirmation but are not in scope for η.

## Daemon

Not activated this session. Step 2.5 trust-gated offer for trusted users is "Run continuously? (~${cost}) [y/n]" — but the user already authorized continuous parallel work via the kickoff prompt ("as much in parallel as possible" + Trust=trusted + Pattern P5 per-piece direct push). Explicit daemon activation skipped to keep session bounded; if remaining η.A + η.D + θ work warrants overnight execution, the next session can `/daemon start` against this campaign.
