# Campaign: ASYNC family lint cleanup

Status: active
Started: 2026-05-11
Direction: Close ASYNC240/230/109/221 suppressions in `backend/pyproject.toml` by fixing source-level violations. Final state: 4 codes hit zero, `[tool.ruff.lint] ignore` shrinks 30 → 26, CI green at every commit.
Branch: `feat/post-merge-eps2c-zeta1-2026-05-09` (continuation; direct-push to main per-piece per Rule #25 + Pattern P5)
Parent campaign: `.planning/campaigns/completed/windows-coverage-godmode-zeta-prefetch-srum-plus-lint-cleanup-2026-05-10.md`
Parent triage: `.planning/lint-cleanup-triage-2026-05-10.md` (defer-with-issue entry: ASYNC family, est. 3-5 sessions)
Trust level: trusted (≥177 sessions; established direct-push-per-piece cadence)

## Production state at start (2026-05-11)

- main HEAD = `3fc48b3` (chore(planning): close ζ.2 Prefetch + ζ.3 SRUM + Lint Cleanup campaign)
- Branch `feat/post-merge-eps2c-zeta1-2026-05-09` synchronized with main
- Alembic head: `c5f6e7d8a9b0`
- MCP tool count: 226
- Open PRs: 0
- Both CI green at HEAD
- Working tree: only `M .claude/harness.json` (orthogonal — DO NOT commit as part of this campaign)
- pyproject.toml ruff `[tool.ruff.lint] ignore` size: 30 codes (target after campaign: 26)

## ASYNC inventory (verified 2026-05-11 via `uv run ruff check --no-cache --select <code> .` from backend/)

| Code | Hits | Notes |
|---|---:|---|
| ASYNC240 | 226 | sync I/O in async — 213 `os.path.*`, 13 `pathlib.Path.*`. Mix of pure-string (noqa) + real-I/O (executor wrap). |
| ASYNC230 | 50 | `open()` in async — always real I/O. `aiofiles.open()` or `run_in_executor`. |
| ASYNC109 | 36 | `timeout=` param in async function signature. Stylistic; replace with `async with asyncio.timeout():` where reasonable. |
| ASYNC221 | 7 | blocking subprocess in async — 100% in tests; either `asyncio.create_subprocess_exec` or per-line noqa with rationale. |
| **Total** | **319** | — |

### Top files by combined hit count

```
28  app/ai/tools/security.py          (21 ASYNC240 + 7 ASYNC230)
20  app/workers/unpack_android.py     (8 ASYNC240 + 12 ASYNC230)
18  app/ai/tools/binary.py            (11 ASYNC240 + 7 ASYNC230)
13  tests/test_analysis_router.py     (12 ASYNC240 + 1 ASYNC230)
10  tests/test_document_service.py    (4 ASYNC240 + 6 ASYNC230)
10  app/routers/apk_scan.py           (9 ASYNC240 + 1 ASYNC109)
 9  app/workers/arq_worker.py         (9 ASYNC240)
 8  app/ai/tools/windows_archive.py   (8 ASYNC240)
 7  app/workers/unpack_msu.py         (7 ASYNC240)
 7  app/services/kernel_service.py    (5 ASYNC240 + 2 ASYNC230)
 6  app/workers/unpack.py             (5 ASYNC240 + 1 ASYNC230)
 6  app/services/mobsfscan/pipeline.py (4 ASYNC109 + 2 other)
 6  app/services/assessment_service.py (6 ASYNC240)
```

### ASYNC221 inventory (full — small enough)

All 7 hits in tests (subprocess.run inside async pytest fixtures):
- `tests/test_unpack_cab.py:326`
- `tests/test_unpack_iso9660.py:363`
- `tests/test_unpack_msu.py:368, 383`
- `tests/test_unpack_wim.py:479`
- `tests/test_unpack_windows_installer_iso.py:609, 635`

### App/test split for ASYNC240

```
182  app/   (production code — real fixes)
 43  tests/ (mostly path-setup boilerplate — per-line noqa likely)
  1  scripts/
```

## Fix-shape strategy (per-call discrimination)

ASYNC240 fires on ALL `os.path.*` and `pathlib.Path.*` methods uniformly, but the right fix differs by call:

| Sub-pattern | Fix shape |
|---|---|
| `os.path.exists/getsize/isdir/isfile/getmtime` — real stat I/O | `await loop.run_in_executor(None, os.path.<x>, path)` |
| `os.path.join/basename/dirname/splitext/normpath/relpath/expanduser` — pure string | `# noqa: ASYNC240` with rationale |
| `os.path.realpath/abspath` — calls getcwd / stats symlinks | executor wrap |
| `Path(path).exists()/stat()/read_text()` — real I/O | executor wrap OR `aiofiles` |
| `Path(path).name/parent/suffix/parts` — pure attribute | noqa with rationale |

ASYNC230 (`open()`): always real I/O.
- Streaming reads → `async with aiofiles.open(...) as f: await f.read()`
- One-shot reads on small files → `await loop.run_in_executor(None, _read_sync, path)`
- Tests with fixture writes → per-test noqa is acceptable when the helper is wholly synchronous

ASYNC221 (`subprocess.run` in async):
- Production code → `asyncio.create_subprocess_exec` with explicit timeout per Rule #29
- Tests → per-test noqa with rationale (tests exercise sync unpacker CLIs; async conversion adds churn without value)

ASYNC109 (`timeout=` param on async def):
- Where caller passes a per-call override → keep param + per-line noqa with rationale
- Where the body uses `asyncio.wait_for(..., timeout=self.timeout)` → migrate to `async with asyncio.timeout(self.timeout):` block, parameter removed

## Decision Log

### D1 — Per-file commits, NOT per-code commits (2026-05-11)

The original briefing suggested per-code phases (Async.B = ASYNC240 batch, Async.C = ASYNC230 batch, ...). Inventory shows top files have hits across multiple codes — `security.py` has 21 ASYNC240 + 7 ASYNC230; `binary.py` has 11 + 7; `unpack_android.py` has 8 + 12. Per-code phases would touch each hot file 2-3 times, generating bisect-noise commits and risking partial-fix states.

**Decision:** commit per-FILE (closing all 4 codes within that file in one slice) rather than per-CODE (closing one code across all files). Rule #25 small-commit principle still holds — each per-file commit is independently revertable and describes its scope in one line ("fix(async): close ASYNC240+230 in security.py — N executor wraps + M per-line noqa"). Bisect-clean property maintained.

**Exception:** ASYNC109 stylistic conversions get their own phase since they're judgement-heavy per-call and benefit from concentrated review.

**Exception:** ASYNC221 gets its own phase since it's a small 7-hit tail and likely 100% per-line noqa.

### D2 — Daemon mode NOT activated (2026-05-11)

User's briefing explicitly wrote a "Bootstrap prompt for next session can be copy-paste" — signalling manual session-by-session cadence with per-piece direct-push (Pattern P5). Per Step 2.5 trust-gated daemon offer: trusted user already chose the cadence. Daemon offer skipped; user invokes a fresh session each time with the bootstrap prompt.

### D3 — `trio.Path` / `anyio.path` NOT adopted (2026-05-11)

Ruff's ASYNC240 message recommends `trio.Path` or `anyio.path`. Wairz uses native `asyncio` with executor-based I/O offload (Rule #5). Adopting trio/anyio is a structural pivot far outside this campaign's scope. The fix-shape stays inside the existing async idiom: `run_in_executor` for blocking I/O, `aiofiles` for streamed reads.

### D4 — Test files use per-line noqa, NOT async conversion (2026-05-11)

Test files (tests/test_unpack_*.py, etc.) often have async pytest fixtures that legitimately need synchronous helpers — fixture path setup, CLI tool invocation, file fixture creation. Converting these to fully-async equivalents adds churn without runtime value (tests aren't on the hot path). Default is per-line `# noqa: ASYNC<code> — <rationale>` for test sites; production code gets real fixes.

## Phase decomposition

### Phase Async.A — Inventory & campaign plan ✅ DONE (2026-05-11)

End conditions:
- [x] Per-code hit counts captured (226 / 50 / 36 / 7)
- [x] Hits-per-file aggregation captured (top-30 table above)
- [x] Fix-shape strategy decided (D1-D4 above)
- [x] Campaign file written at `.planning/campaigns/async-cleanup-2026-05-11.md`

### Phase Async.B — ASYNC221 cleanup (tests, 7 hits)

Smallest tail; serves as the strategy validation slice. Most likely outcome: 1-2 commits with per-line noqa + rationale per the D4 decision. If any test genuinely benefits from `asyncio.create_subprocess_exec`, that single test gets the conversion in the same commit.

End conditions:
- [ ] `( cd backend && uv run ruff check --no-cache --select ASYNC221 . )` returns 0 errors
- [ ] All noqa additions carry a one-line rationale comment (no bare `# noqa`)
- [ ] `( cd backend && uv run pytest tests/test_unpack_cab.py tests/test_unpack_iso9660.py tests/test_unpack_msu.py tests/test_unpack_wim.py tests/test_unpack_windows_installer_iso.py -v --no-header )` passes (no regressions from any test conversion)

### Phase Async.C — Hot-file refactors (production code, ~76 hits)

Per-file commits for the 4 top hot files. Each commit closes all in-file ASYNC violations across all 4 codes.

Sub-phases (one commit each):
- **Async.C.1** — `app/ai/tools/security.py` (28 hits — 21 ASYNC240 + 7 ASYNC230)
- **Async.C.2** — `app/workers/unpack_android.py` (20 hits — 8 + 12)
- **Async.C.3** — `app/ai/tools/binary.py` (18 hits — 11 + 7)
- **Async.C.4** — `app/routers/apk_scan.py` (10 hits — 9 ASYNC240 + 1 ASYNC109)

End conditions (per sub-phase):
- [ ] Targeted ruff confirms 0 hits in the file (`uv run ruff check --no-cache --select ASYNC <file>`)
- [ ] Rule #11 import smoke if any helper is extracted (`docker compose exec -T backend python -c "from app.X import Y"`)
- [ ] Targeted pytest passes for the file's tests (`uv run pytest tests/test_<module>.py -v`)
- [ ] CI Lint workflow green on the pushed commit

### Phase Async.D — App tail (production code, ~106 hits)

Per-file commits for remaining production code hits in app/. Suggested ordering by hit-count descending:

1. `app/workers/arq_worker.py` (9)
2. `app/ai/tools/windows_archive.py` (8)
3. `app/workers/unpack_msu.py` (7)
4. `app/services/kernel_service.py` (7)
5. `app/workers/unpack.py` (6)
6. `app/services/assessment_service.py` (6)
7. `app/services/hardware_firmware/graph.py` (4)
8. `app/cli/compare_apk.py` (4)
9. `app/ai/tools/windows_pe_signature.py` (4)
10. `app/ai/tools/windows_dotnet.py` (4)
11. `app/ai/tools/vulhunt.py` (4)
12. `app/services/mobsfscan/pipeline.py` (4)
13. (… ~30 more files with 1-3 hits each)

End conditions:
- [ ] Each in-scope file's ASYNC240/230/109 hits reach 0
- [ ] No new test failures in `uv run pytest backend/tests/ -x --tb=short` (run periodically, not per-commit)
- [ ] Each commit passes Lint CI

### Phase Async.E — Test cleanup (~43 ASYNC240 + scattered ASYNC230/109)

Per-file commits for top test files. Most resolve via per-line noqa per D4.

Top test files:
1. `tests/test_analysis_router.py` (13)
2. `tests/test_document_service.py` (10)
3. `tests/test_unpack_wim.py` (4 — plus 1 ASYNC221 already in B)
4. `tests/test_unpack_msix.py` (4)
5. `tests/test_dotnet_update_diff_real_firmware.py` (4)
6. `tests/test_assessment_service.py` (4)
7. (… more files with 1-3 hits)

End conditions:
- [ ] All ASYNC test hits resolved via either noqa-with-rationale OR genuine async conversion
- [ ] No noqa is bare (must carry a one-line rationale)
- [ ] Affected test files still pass

### Phase Async.F — ASYNC109 stylistic conversions (~36 hits)

Per-judgement fixes for `timeout=` params on async functions. Some sites keep the param + noqa (caller-supplied override); others migrate to `async with asyncio.timeout():`.

End conditions:
- [ ] ASYNC109 hits reach 0 (or justified noqa with rationale)
- [ ] No timeout-discipline regressions per Rule #29 (every `wait_for` / `subprocess` still has an explicit timeout)

### Phase Async.G — Suppression removal & final CI verification

Remove each ASYNC entry from `backend/pyproject.toml` `[tool.ruff.lint] ignore` once its hits are at zero. Sub-phases:

- **Async.G.1** — Remove ASYNC221 entry (after Phase B)
- **Async.G.2** — Remove ASYNC230 entry (after Phases C-E close it)
- **Async.G.3** — Remove ASYNC240 entry (after Phases C-E close it)
- **Async.G.4** — Remove ASYNC109 entry (after Phase F)

Note: removals can happen in different sessions if codes close in different sessions. Each removal is one commit.

End conditions:
- [ ] `( cd backend && uv run ruff check --no-cache --select ASYNC240,ASYNC230,ASYNC109,ASYNC221 . )` returns "All checks passed!" exit 0
- [ ] `grep -E "ASYNC(240|230|109|221)" backend/pyproject.toml` returns 0 hits in the `ignore` list (entries deleted, not commented out)
- [ ] `gh run list --branch main --limit 5 --json status,conclusion,workflowName --jq '.[]|select(.workflowName=="Backend Tests")|select(.conclusion!=null)|.conclusion' | head -1` is `success`

### Phase Async.H — Postmortem + knowledge extraction + campaign close

End conditions:
- [ ] `.planning/postmortems/postmortem-async-cleanup-2026-05-{date}.md` written
- [ ] `.planning/knowledge/async-cleanup-2026-05-{date}-patterns.md` written
- [ ] `.planning/knowledge/async-cleanup-2026-05-{date}-antipatterns.md` written
- [ ] `.planning/lint-cleanup-triage-2026-05-10.md` updated to mark 4 codes closed
- [ ] Campaign file moved to `.planning/campaigns/completed/`
- [ ] CLAUDE.md updated if any rule reaches Rule-of-N+ promotion (Pattern P1 candidate at Rule-of-Five from suppression-removal-as-bug-discovery accumulator)

## Phase End Conditions Summary (machine-verifiable)

| Phase | Type | Condition |
|---|---|---|
| Async.A | command_passes | `test -f .planning/campaigns/async-cleanup-2026-05-11.md` |
| Async.B | command_passes | `( cd backend && uv run ruff check --no-cache --select ASYNC221 . ) ; [ $? -eq 0 ]` |
| Async.C.* | command_passes | per-file `uv run ruff check --no-cache --select ASYNC240,ASYNC230,ASYNC109 <file>` exit 0 |
| Async.D | command_passes | `( cd backend && uv run ruff check --no-cache --select ASYNC240,ASYNC230 app/ ) ; [ $? -eq 0 ]` |
| Async.E | command_passes | `( cd backend && uv run ruff check --no-cache --select ASYNC240,ASYNC230 tests/ ) ; [ $? -eq 0 ]` |
| Async.F | command_passes | `( cd backend && uv run ruff check --no-cache --select ASYNC109 . ) ; [ $? -eq 0 ]` |
| Async.G | command_passes | `( cd backend && uv run ruff check --no-cache --select ASYNC240,ASYNC230,ASYNC109,ASYNC221 . ) ; [ $? -eq 0 ]` AND `grep -cE "ASYNC(240\|230\|109\|221)" backend/pyproject.toml | grep -q ^0$` |
| Async.H | file_exists | `.planning/postmortems/postmortem-async-cleanup-2026-05-*.md` AND `.planning/knowledge/async-cleanup-2026-05-*-{patterns,antipatterns}.md` |

## Feature Ledger

| Phase | Commit | Hits closed | Files | CI Lint | CI Backend Tests |
|---|---|---|---|---|---|
| Async.A | `d4001d3` | 0 (planning) | campaign file created | n/a | n/a |
| Async.B | `94912f2` | 7 ASYNC221 | 5 test_unpack_*.py | success | success |
| Async.C.1 | `ec97780` | 28 (21+7) | `app/ai/tools/security.py` | success | (superseded) |
| Async.C.2 | `b347ddc` | 20 (8+12) | `app/workers/unpack_android.py` | success | (superseded) |
| Async.C.3 | `20a4660` | 18 (11+7) | `app/ai/tools/binary.py` | success | (superseded) |
| Async.C.4 | `a61d171` | 10 (9+1) | `app/routers/apk_scan.py` | success | (superseded) |
| Async.D.1 | `b79dbd7` | 9 | `app/workers/arq_worker.py` | success | (superseded) |
| Async.D.2 | `a8535b1` | 8 | `app/ai/tools/windows_archive.py` | success | (superseded) |
| Async.D.3 | `9b73713` | 7 | `app/workers/unpack_msu.py` | success | (superseded) |
| Async.D.4 | `0f462f9` | 7 (5+2) | `app/services/kernel_service.py` | success | (superseded) |
| Async.D.5 | `a83fa14` | 6 (5+1) | `app/workers/unpack.py` | success | (superseded) |
| Async.D.6 | `93e9c28` | 6 | `app/services/assessment_service.py` | success | (superseded) |
| Async.D.7 | `a6c9b54` | 4 | `app/services/hardware_firmware/graph.py` | success | (superseded) |
| Async.D.8 | `f1eb9ae` | 4 | `app/cli/compare_apk.py` | success | (superseded) |
| Async.D.9 | `bf578fc` | 4 | `app/ai/tools/windows_pe_signature.py` | success | (superseded) |
| Async.D.10 | `2521ac4` | 4 (3+1) | `app/ai/tools/windows_dotnet.py` | success | (superseded) |
| Async.D.11 | `7d463a8` | 4 (2+2) | `app/cli/scan.py` | success | (superseded) |
| Async.D.12 | `4bda61a` | 3 (1+2) | `app/services/document_service.py` | success | (superseded) |
| Async.D.13 | `3649732` | 2 | `app/services/import_service.py` | success | success |
| Async.D.14 | `b07411a` | 1 | `app/workers/unpack_common.py` | success | (superseded) |
| Async.D.15 | `680be80` | 6 (2+4) | `app/services/mobsfscan/pipeline.py` | success | (superseded) |
| Async.D.16 | `dcb7ccb` | 4 (2+2) | `app/services/system_emulation_service.py` | success | (superseded) |
| Async.D.17 | `cf73bb6` | 4 (2+2) | `app/services/cwe_checker_service.py` | success | (superseded) |
| Async.D.18 | `57e838d` | 4 (1+3) | `app/ai/tools/vulhunt.py` | success | (superseded) |
| Async.D.19 | `5c326a2` | 3 | `app/services/fuzzing_service.py` | success | (superseded) |
| Async.D.20 | `a5c67cb` | 3 | `app/services/firmware_service.py` | success | (superseded) |
| Async.D.21 | `8a00449` | 3 | `app/services/export_service.py` | success | (superseded) |
| Async.D.22 | `2462eb2` | 3 | `app/routers/hardware_firmware.py` | success | (superseded) |
| Async.D.23 | `d1ff34d` | 3 | `app/ai/tools/uefi.py` | success | (superseded) |
| Async.D.24 | `e5c4c89` | ~3 | `app/ai/tools/emulation.py` | success | (superseded) |
| Async.D.25 | `ae5202f` | ~3 | `app/main.py` + `app/mcp_server.py` | success | (superseded) |
| Async.D.26 | `71ed542` | ~3 | `app/routers/health.py` + `app/routers/firmware.py` | success | (superseded) |
| Async.D.27 | `abc2b11` | 3 (2+1) | `app/ai/tools/strings.py` | success | (superseded) |
| Async.D.28 | `41e285c` | 4 (3+1) | `app/ai/tools/hardware_firmware.py` | success | (superseded) |
| Async.D.29 | `fea59df` | ~3 | `app/ai/tools/taint_llm.py` + `app/ai/tools/android_bytecode.py` | success | (superseded) |
| Async.D.30 | `17cd3d5` | ~3 | `app/services/ghidra_service.py` + `app/services/firmware_metadata_service.py` | success | (superseded) |
| Async.D.31 | `485cf70` | 4 (3+1) | `app/services/jadx_service.py` + `app/services/mobsfscan/parser.py` | success | (superseded) |
| Async.D.32 | `f1853db` | 5 (2+2+1) | `app/services/emulation/service.py` + `app/services/device_service.py` | success | (superseded) |
| Async.D.33 | `1c72759` | 2 | `app/workers/unpack_vhdx.py` + `app/workers/unpack_windows_installer_iso.py` | success | (superseded) |
| Async.D.34 | `821762a` | 2 (1+1) | `app/workers/unpack_cab.py` + helper extraction in `unpack_common.py` | pending | pending |

Running totals (mid-session 2 — 2026-05-12):
- ASYNC240: 226 → 66 (160 closed, 71% closed)
- ASYNC230: 50 → 12 (38 closed, 76% closed)
- ASYNC109: 36 → 16 (20 closed, 56% closed)
- ASYNC221: 7 → 0 (100% closed; suppression removed in `94912f2`)
- Combined: 319 → 92 (227 closed, 71% closed, 29% remains)

**Session 2 cadence:** 21 additional commits this session (D.14-D.34, 76 hits closed). Helper extraction in D.34 (`reset_extraction_dir_sync` in `unpack_common.py`) creates a reusable pattern for the remaining unpack_* workers. Per-file Decision D1 still in effect; some commits batched 2 files where the fix shape was identical (D.25, D.26, D.29, D.30, D.31, D.32, D.33, D.34) — Rule #25 small-commit principle preserved since each per-file slice is still independently revertable via patch-level surgery.

**Reusable pattern emerged in session 2:** the `reset_extraction_dir_sync` helper is one example of a common pre-fix sequence (exists-check + rmtree + makedirs). The same shape applies to: read-and-write-then-cleanup workflows in 7+ remaining unpack workers, kernel-image-prep flows, etc. Future Phase D sweeps should look for 3-call-into-1-hop opportunities, not just per-line wrap.

**Remaining app/scripts (Phase D residual — 7 hits, 7 files):**
- `app/workers/unpack_wim.py` (1)
- `app/workers/unpack_qnx_ifs.py` (1)
- `app/workers/unpack_psf.py` (1)
- `app/workers/unpack_msix.py` (1)
- `app/workers/unpack_msi.py` (1)
- `app/workers/unpack_iso9660.py` (1)
- `scripts/backfill_detection.py` (1)

**Remaining tests (Phase E — 67 hits across ~22 files):**
- `tests/test_analysis_router.py` (13) — top
- `tests/test_document_service.py` (10)
- `tests/test_import_service.py` (5)
- `tests/test_unpack_msix.py` (4)
- `tests/test_dotnet_update_diff_real_firmware.py` (4)
- `tests/test_assessment_service.py` (4)
- `tests/test_unpack_wim.py` (3)
- `tests/test_unpack_qnx_ifs.py` (3)
- `tests/test_unpack_msi.py` (2)
- `tests/test_unpack_iso9660.py` (2)
- `tests/test_unpack_cab.py` (2)
- `tests/test_jadx_service.py` (2)
- `tests/test_authenticode_chain_runner.py` (2)
- `tests/test_authenticode_chain_real_firmware.py` (2)
- 8 files with 1 hit each
- Per Decision D4: default = per-line noqa with rationale.

## Review Queue

(Populated when a sub-agent flags judgement points needing human review.)

## Continuation State

**Current phase:** Async.D — IN PROGRESS, partial (13 of ~20-25 production files closed; 100 hits remain in app/, 67 in tests/)
**Phase Async.A status:** complete (commit `d4001d3`)
**Phase Async.B status:** complete (commit `94912f2`; suppression removed from pyproject.toml)
**Phase Async.C status:** complete (4 commits: `ec97780`/`b347ddc`/`20a4660`/`a61d171`)
**Phase Async.D status:** PARTIAL — batch 1 (D.1-D.6, 6 commits, 43 hits) + batch 2 (D.7-D.13, 7 commits, 25 hits) shipped this session. ~10 production files still pending.
**Phase Async.E status:** blocked on D — but can be done in parallel with D tail (independent file set)
**Phase Async.F status:** blocked on E (or interleaved with D for ASYNC109-heavy files)
**Phase Async.G status:** blocked on F (all suppressions stay until all hits hit zero)
**Phase Async.H status:** blocked on G

**Last commit on main:** `3649732` (Phase Async.D.13, 2026-05-11 — import_service.py)
**Branch state:** `feat/post-merge-eps2c-zeta1-2026-05-09` at parity with origin/main. Working tree: `M .claude/harness.json` (orthogonal), `M .planning/campaigns/async-cleanup-2026-05-11.md` (this file — about to commit), `?? .claude/scheduled_tasks.lock` (Claude Code harness session lock — DO NOT commit, gitignore candidate).

<!-- session-end: 2026-05-11T16:53:27.006Z -->

## Remaining work inventory (verified end of session 2026-05-11)

Top 20 files with ASYNC240/230/109 hits, descending:

```
13  tests/test_analysis_router.py             (E.1)
10  tests/test_document_service.py            (E.2)
 6  app/services/mobsfscan/pipeline.py        (D.14 — mostly ASYNC109)
 5  tests/test_import_service.py              (E.3)
 4  tests/test_unpack_msix.py                 (E.4)
 4  tests/test_dotnet_update_diff_real_firmware.py (E.5)
 4  tests/test_assessment_service.py          (E.6)
 4  app/services/system_emulation_service.py  (D.15 — mostly ASYNC109)
 4  app/services/cwe_checker_service.py       (D.16 — 2 ASYNC109)
 4  app/ai/tools/vulhunt.py                   (D.17 — 3 ASYNC109)
 3  tests/test_unpack_wim.py                  (E.7)
 3  tests/test_unpack_qnx_ifs.py              (E.8)
 3  app/workers/unpack_common.py              (D.18)
 3  app/services/jadx_service.py              (D.19)
 3  app/services/fuzzing_service.py           (D.20)
 3  app/services/firmware_service.py          (D.21)
 3  app/services/export_service.py            (D.22)
 3  app/routers/hardware_firmware.py          (D.23)
 3  app/ai/tools/uefi.py                      (D.24)
 3  app/ai/tools/strings.py                   (D.25)
```

Plus ~30 more files with 1-2 hits each (the long tail).

**Split:** 100 hits in `app/`, 67 hits in `tests/`, 1 hit in `scripts/`.

## Continuation prompt for next session (Pattern P7 — copy-paste ready)

```
Resume wairz/async-cleanup-2026-05-11. main HEAD = 3649732 (Phase Async.D.13).
CI: Lint green on 3649732; Backend Tests in_progress at session end (check
`gh run list --limit 4 --workflow "Backend Tests" --json status,conclusion,headSha`
before starting — if it failed, investigate before continuing).

Read:
- .planning/campaigns/async-cleanup-2026-05-11.md (source-of-truth campaign file
  with full Feature Ledger and remaining-work inventory)
- CLAUDE.md (Rule #5 run_in_executor, Rule #25 per-commit slice, Rule #29
  timeout alignment, Rule #38 absolute paths, Rule #35a silent-exit before
  pipes)

Current state:
- 19 commits ahead of pre-campaign baseline 3fc48b3 (1 plan + 18 fix commits)
- ASYNC221: 0 hits (suppression already removed)
- ASYNC230: 14 hits remain (was 50)
- ASYNC240: 119 hits remain (was 226)
- ASYNC109: 35 hits remain (was 36)
- Total: 168 hits remain across ~25 files (was 319, 47% closed)
- pyproject.toml ignore: 30 → 29 (ASYNC221 removed); 3 suppressions still
  in place (ASYNC240/230/109) per Phase G plan

Next phase plan:
1. Phase Async.D tail (~10 more app/ files): pipeline.py, system_emulation_service.py,
   cwe_checker_service.py, vulhunt.py — these have ASYNC109 hits, so Phase F
   may interleave. Smaller files (unpack_common.py, fuzzing_service.py,
   firmware_service.py, export_service.py, hardware_firmware.py router,
   uefi.py tool, strings.py tool) close quickly.
2. Phase Async.E (tests, 67 hits): default per-line noqa with rationale per
   Decision D4. Top: test_analysis_router.py (13), test_document_service.py
   (10), test_import_service.py (5), test_unpack_msix.py (4),
   test_dotnet_update_diff_real_firmware.py (4), test_assessment_service.py (4).
3. Phase Async.F (35 ASYNC109): mostly stylistic; replace timeout= param
   with asyncio.timeout() context manager where reasonable. Per-line noqa
   for caller-supplied overrides. Already partially merged with D since some
   D files had ASYNC109 hits (apk_scan.py + windows_dotnet.py + cli/scan.py).
4. Phase Async.G: remove ASYNC240/230/109 entries from
   backend/pyproject.toml [tool.ruff.lint] ignore (after each code hits zero).
5. Phase Async.H: postmortem + patterns/antipatterns + close.

Trust: trusted. Direct-push to main per-piece. Final PR optional.
Use citadel:archon. Estimated 1-2 more sessions to close.

Operational rules durable for every session in this campaign:
- Rule #38 absolute paths: `git -C /home/dustin/code/wairz` + `( cd backend && ... )` subshells.
- Antipattern A6: every `uv run ruff check` carries `--no-cache`.
- Rule #35a / A1: capture exit codes BEFORE pipes — `cmd; ec=$?` not `cmd | tail; echo $?`.
- Rule #25 per-commit slice + Pattern P5 per-piece direct-push to main.
- DO NOT touch: .claude/harness.json, .claude/scheduled_tasks.lock,
  any unrelated file. Use `git add backend/<file>` discipline.
```

**Session ending decision (2026-05-11 archon):** stopping after 19 commits is the right place to break. The pattern is stable (D1 per-file commits, D4 noqa-with-rationale, helper-extraction-and-single-executor-hop for back-to-back I/O). Next session can pick up Phase D tail + Phase E in one focused push.

**Continuation prompt for next session (Pattern P7):**

```
Resume wairz/async-cleanup-2026-05-11. main HEAD = <UPDATE>, CI status <UPDATE>.

Read:
- .planning/campaigns/async-cleanup-2026-05-11.md (this campaign file, source-of-truth)
- CLAUDE.md (Rule #5 run_in_executor, Rule #25 per-commit slice, Rule #29 timeout alignment, Rule #38 absolute paths)

Current phase: <CURRENT>
Remaining: <REMAINING_PHASES>
Trust: trusted. Direct-push to main per-piece. Final PR optional.
Use citadel:archon.
```

## Operating reminders (durable for every session in this campaign)

1. **Rule #38** — always `git -C /home/dustin/code/wairz <subcommand>` for git; `( cd backend && uv run … )` subshell for backend tools. Never chain `cd backend && <tool>` with a subsequent git command.
2. **Antipattern A6** — every `uv run ruff check` carries `--no-cache` (the cache dir is root-owned from legacy container).
3. **Rule #35a / A1** — never trust an exit code captured after a pipe. `cmd; ec=$?` BEFORE the pipe.
4. **A2** — fix BEFORE remove suppression. Each ASYNC code stays in `ignore` until its hits hit zero, then comes out in the SAME commit OR a separate commit but only after zero is confirmed.
5. **Pattern P5** — per-piece direct-push to main; trusted cadence; concurrency-cancelled CI saves runner minutes.
6. **Rule #29** — every `subprocess` / `wait_for` declares an explicit timeout. ASYNC221 → `asyncio.create_subprocess_exec(..., timeout=...)` conversion preserves this.
7. **Rule #5** — async fns wrap blocking I/O in `loop.run_in_executor(None, sync_fn, *args)`. Default executor (ThreadPoolExecutor `os.cpu_count() × 5`) is fine.
8. **Rule #35b** — after a meaningful fix, run the fixed code ONCE against a real fixture row (live canary) before trusting mocks.
9. **Rule #25 single-slice exception #2** — does NOT apply to this campaign (no cross-stack alignment work).
10. **Rule #17 silent-CLI-exit canary** — once per session: `echo 'const x: number = "nope"; export default x;' > frontend/src/__canary.ts && (cd frontend && npx tsc -b --force); rm frontend/src/__canary.ts` — expect non-zero exit.

## References

- `.planning/lint-cleanup-triage-2026-05-10.md` — original triage with all 35 ruff codes
- `.planning/postmortems/postmortem-windows-coverage-godmode-zeta-prefetch-srum-plus-lint-cleanup-2026-05-09.md` — Phase Lint.A/B context (closed S314, F601, F811, E741, F402, B314)
- `.planning/knowledge/windows-coverage-godmode-zeta-prefetch-srum-plus-lint-cleanup-2026-05-09-patterns.md` — P1 (suppression-removal-as-bug-discovery), P5 (per-piece direct push)
- `.planning/knowledge/windows-coverage-godmode-zeta-prefetch-srum-plus-lint-cleanup-2026-05-09-antipatterns.md` — A1 (tail exit), A2 (fix-before-remove), A6 (ruff cache)
- CLAUDE.md — full Learned Rules catalog
