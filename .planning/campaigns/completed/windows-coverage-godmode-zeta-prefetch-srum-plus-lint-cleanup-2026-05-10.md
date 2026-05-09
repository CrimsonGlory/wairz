# Campaign: Windows-Coverage God-Mode — ζ.2 Prefetch + ζ.3 SRUM + Lint Tech-Debt Cleanup

Status: completed
Started: 2026-05-10 (continuation of 2026-05-09 final session)
Completed: 2026-05-10 (Phase Close shipped 0949851)
Direction: "do them all and you decide" — Phase ζ.2 Prefetch walker + ζ.3 SRUM walker + Lint tech-debt cleanup
Branch: `feat/post-merge-eps2c-zeta1-2026-05-09` (continuation; direct-push to main per-piece)
Parent intake: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
Companion postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-final-eps2c-zeta1-ci-recovery-2026-05-09.md`

## Production state at start

- main HEAD = `13ef37f` (origin/main); CI Lint + Backend Tests both SUCCESS.
- Alembic head = `f2b3c4d5e6f7`.
- 220 MCP tools registered.
- 0 open PRs; clean-history reconciled (78 commits behind, 0 ahead).
- WindowsFindingSource Literal = 11 values (10 + amcache_install from ζ.1).
- Containers up + healthy (backend, worker, postgres, redis, etc.).
- Working branch: `feat/post-merge-eps2c-zeta1-2026-05-09` continuation.

## Phase 0 — Research scout findings (2026-05-10)

### Scout A — Prefetch parser library

PyPI options enumerated:
- `prefetch-parser` (1.0.0) — single version, last shipped 2020. Stale.
- `windowsprefetch` (4.0.3) — actively maintained; pure Python; parses .pf files (Win10/11 supported with MAM compression)
- `libscca-python` (20250915) — libyal C extension; high quality but requires build-essential (already in image) + native build at install time.

**Decision: `windowsprefetch>=4.0.3`** — pure-Python, no Dockerfile delta, matches regipy/python-evtx ecosystem pattern (Rule #36 no-execute alignment: parses as data only). Falls back gracefully if a malformed .pf is encountered.

### Scout B — SRUM ESEDB parser library

- `pyesedb` does NOT exist on PyPI.
- `libesedb-python` (20240420) — the correct libyal Python binding. C extension, requires build-essential.
- `libesedb-utils` (CLI tools `esedbexport` + `esedbinfo`) **ALREADY INSTALLED** in `backend/Dockerfile:47`.

Path options:
- **(a) Python binding `libesedb-python`** — best ergonomics; C ext build cost; aligns with `python-evtx` shape (pure-Python parsing).
- **(b) Subprocess shell-out to `esedbexport`** — zero Dockerfile delta; produces flat dump files we then walk + parse line-by-line. Higher CLI-stability risk (Rule #6 flag verification) but no build-step risk.

**Decision: Path (a) with fallback documentation for path (b).** `libesedb-python` is the cleaner shape for a forensic walker; build cost is amortised against `regipy`/`signify` already-installed libs. If the C ext build fails during ζ.3 install, pivot to (b) without blocking — `libesedb-utils` is already in the image.

### Scout C — Lint suppression triage (35 ruff codes total — campaign brief said 26, +14% drift per Rule #28)

Full ruff `[tool.ruff.lint] ignore` list, by category:

| Category | Codes | Count | Severity |
|---|---|---|---|
| **Security (real concerns)** | S314 (xml without defusedxml × 2), S324 (md5 × 3) | 5 hits across 2 codes | Real — XML XXE risk, hash collision |
| **Async correctness (Rule #5 family)** | ASYNC240 (sync I/O × 226), ASYNC230 (open() in async × 50), ASYNC109 (timeout param × 36), ASYNC221 (subprocess × 8) | 320 hits across 4 codes | Real — performance + correctness |
| **Defensive boundary (intentional)** | S110 (try/except/pass × 121), S112 (try/except/continue × 33), B904 (raise without from × 126), B007 (unused loop var × 30) | 310 hits | Intentional — keep with refined justification |
| **FastAPI/firmware idiom** | B008 (Depends() × 206), S108 (/tmp × 15), S202 (tarfile × 5), S104 (bind all × 1), S105 (false-pos × 1) | 228 hits | Intentional — keep |
| **Pre-existing tech debt (low-cost fix)** | E402 (× 31), E741 (× 3), F401 (varies), F402, F601, F811, F821 (× 2 latent NetDepFinding), F841 (× 17), B017 (× 4), B023 (× 3), B905 (× 3) | ~75 hits | Real but cosmetic |
| **Modernization** | UP042 (str enum × 11 — Pydantic-compatible), UP040, UP046 | 14 hits | Cosmetic, intentional for some |

Bandit skips (16 codes): mostly mirror ruff S-codes; B404/B405/B408/B413/B501 are firmware-analysis-context patterns kept intentionally.

ESLint downgrades (5 codes — react-hooks/react-refresh family): cosmetic warnings about hook-deps + only-export-components. Real concerns mixed; defer to per-page review.

**Triage strategy:**
- Fix-now (highest leverage, lowest risk): F821 latent NetDepFinding (real broken symbol — 2 hits), F811 (redefined-while-unused — likely a real bug), F601 (repeated dict key — silent data-loss).
- Fix-now (security): S314 (× 2 — defusedxml swap is mechanical).
- Keep-with-justification: S110, S112, B904 (defensive boundary patterns), B008 (FastAPI idiom), S108 (firmware scratch), S202 (firmware extract), S104/S105 (intentional/false-pos), S324 (hash-compare-only), UP042 (Pydantic compat).
- Defer-with-issue: ASYNC family (320 hits — multi-session refactor; create `.planning/intake/lint-defer-async-correctness.md`), modernization UP-family (cosmetic; defer).

### Scout D — Fixture availability

- `backend/tests/fixtures/windows/`: only `tiny.dbxupdate.bin` (β.10 DBX). NO prefetch / SRUM / ESEDB fixtures.
- No existing prefetch/srum code in `backend/app/` (greenfield).
- Real fixtures via operator-provided real Win10/Win11 firmware: gated via tier-3 canary skip pattern (`.mex/patterns/real-firmware-skip-tier-canary.md`).

## Library probe (Rule #19 evidence-first — to run during ζ.3.A pre-commit)

To execute before drafting `srum_walker.py`:

```python
docker compose exec -T backend python -c "
import inspect
from libesedb import file as esedb_file  # or pyesedb after install
src = inspect.getsource(type(esedb_file()))
print(src[:3000])
"
```

Round-trip a synthetic 3-row ESEDB through python before drafting inner runner. If install fails, pivot to subprocess `esedbexport` shell-out.

## Phase decomposition

### Phase 1 — Housekeeping ✅ DONE

- Commit `c3a462a` — postmortem + knowledge + close-ui-residue-prs.sh + harness.json (3 new auto-rules from prior session) + sessions_completed bump.

### Phase ζ.2 — Prefetch walker (~600 LOC, 5-7 commits)

- ζ.2.A — Alembic migration `<freeID>_add_windows_prefetch_records_table` + ORM model + JSONB normalizer + `WINDOWS_PREFETCH_RECORDS_*_SCHEMA_VERSION = 1` + tests (1 commit).
- ζ.2.B — Add `windowsprefetch>=4.0.3` to `pyproject.toml` + Rule #39 triplet `prefetch_walker.py` + tier-1 tests via `make_live_db()` (1 commit).
- ζ.2.C — Cross-stack alignment commit (Rule #25 single-slice exception #2): alembic ck_findings_source extension to `windows_prefetch_execution` + `WindowsFindingSource` Literal extension + classifier helper + emit method + FE union + FE config (1 commit). Rule-of-Six → Rule-of-Seven.
- ζ.2.D — Finding-emit hook in `auto_prefetch_walk_firmware_safe` + integration with `FindingService` (1 commit).
- ζ.2.E — MCP tool registration `search_prefetch_records` (paginated) (1 commit).
- ζ.2.F — Validation: Rule #8 rebuild + Rule #11 import smoke + targeted pytest + ruff/bandit/eslint + tsc -b --force + lower-bound count sweep.
- ζ.2.G — Direct-push to main via `git push origin <branch-tip>:main`.
- ζ.2.H — CI watch + recovery if needed.

### Phase ζ.3 — SRUM walker (~900 LOC, 6-8 commits)

- ζ.3.A — pyesedb / libesedb-python probe report (no commit; campaign-file documentation).
- ζ.3.B — Add libesedb-python install (or pivot) + alembic migration with srum tables + ORM models + normalizers (1-2 commits depending on table count).
- ζ.3.C — Rule #39 triplet `srum_walker.py` + tier-1 tests (1 commit). Rule #39 Rule-of-Three → Rule-of-Four → Rule-of-Five.
- ζ.3.D — Cross-stack alignment commit (Rule #25 single-slice exception #2): 2 source values bundled — `windows_srum_network_activity` + `windows_srum_application_runtime`. Rule-of-Seven → Rule-of-Eight.
- ζ.3.E — Finding-emit hooks + FindingService integration.
- ζ.3.F — MCP tool registration `search_srum_records` with `record_type` filter.
- ζ.3.G — Validation suite + Rule #8 rebuild + Rule #11 smoke.
- ζ.3.H — Direct-push to main + CI watch.

### Phase Lint — Tech-debt cleanup

- Lint.A — `.planning/lint-cleanup-triage-2026-05-10.md` per Scout C synthesis above.
- Lint.B-N — Per-rule-code commits in priority order (security → real bugs → modernization).
- Lint.Z — Final cleanup commit removing now-unused suppressions; verify CI green.

### Phase Close

- Global postmortem + patterns + antipatterns.
- CLAUDE.md Rule #25 evidence count update (Rule-of-Six → Rule-of-Eight if both walkers ship cross-stack alignment).
- CLAUDE.md Rule #39 evidence count update (Rule-of-Three → Rule-of-Five if both walkers apply triplet).
- `.mex/context/conventions.md` Verify Checklist mirror update per Rule #21.

## Required disciplines (mandatory)

- **Rule #19 evidence-first:** library API probe before drafting inner runner.
- **Rule #25 single-slice exception #2:** cross-stack alignment commits bundle DB CHECK + Pydantic Literal + classifier + emit + FE union + FE config in one atomic commit. `test_finding_source_alignment.py` enforces.
- **Rule #33 .a state machine:** 5-state column (`idle → queued → running → completed | failed`); idempotent POST + 409-on-conflict.
- **Rule #35a/b/c:** pipe-induced exit canary; mock-vs-live canaries; JSONB normalizer + stamp + schema_version.
- **Rule #38 absolute-path bash:** `git -C /home/dustin/code/wairz <subcommand>`; subshell `( cd backend && uv run … )` form.
- **Rule #39 inner/outer/safe runner triplet:** new walkers ship 3 functions; tier-1 tests call INNER not OUTER.
- **Pattern #6 lower-bound count assertions:** `>= N` for growing collections; sweep `grep -rn "len(reg._tools) ==" backend/tests/` after every phase BEFORE pushing.
- **Local-vs-CI lint scope:** run `cat .github/workflows/lint.yml | grep -E 'run:'` to find the EXACT CI command before pushing.

## Decision log

| # | Decision | Rationale |
|---|---|---|
| 1 | Use `windowsprefetch>=4.0.3` for ζ.2 (not `prefetch-parser` which is stale) | Active maintenance; pure-Python; matches regipy/python-evtx pattern; no Dockerfile delta |
| 2 | Use `libesedb-python` for ζ.3 with subprocess `esedbexport` fallback | Cleaner Python shape; libesedb-utils already in image; pivot path documented if C ext build fails |
| 3 | Single-table (windows_srum_records with record_type discriminator) — pending probe confirmation | Lighter migration; pyesedb's table-list will inform whether discriminator works cleanly |
| 4 | Lint cleanup as Phase Lint AFTER ζ.2 + ζ.3 ship | ζ phases extend the codebase; cleaning lint before extends gives more accurate per-rule counts |
| 5 | Direct-push to main per-piece (no per-piece PRs) | User-stated preference per session brief; final consolidation PR optional |

## Active Context

Campaign complete (2026-05-10). All phases shipped, 14 commits ahead of
the baseline `13ef37f`. Backend Tests on the final HEAD `0949851` is
in-progress at session-end; Lint CI is green on `0949851`. The prior
SHA `63ec1c0` (Phase Lint.B.3) had Lint green + Backend Tests
in-progress at the time of the final push, with prior pushes (`fb4bcf9`,
`41c90fc`) confirming Backend Tests pass on the ζ-phase ground truth.

## Continuation State

Phase: closed
Sub-step: postmortem + knowledge + CLAUDE.md updates
Files modified across campaign: ~50 (4 new alembic revisions, 2 walker
modules, 2 ORM tables, 2 MCP tool categories, 6 lint cleanup files,
1 housekeeping commit, postmortem + knowledge files at close).
Blocking: none.
Last commit: `0949851` fix(ruff): rename ambiguous loop vars + close E741/F402.

## Telemetry

| Metric | Start | Final | Delta |
|---|---|---|---|
| main HEAD | `13ef37f` | `0949851` | +14 commits |
| Alembic head | `f2b3c4d5e6f7` | `c5f6e7d8a9b0` | +4 revisions |
| MCP tool count | 220 | 226 | +6 (windows_prefetch ×3 + windows_srum ×3) |
| WindowsFindingSource Literal values | 11 | 14 | +3 (prefetch_execution + srum_network_activity + srum_application_runtime) |
| Finding source allowlist (ck_findings_source) | 29 | 32 | +3 |
| Tests added | baseline | baseline + ~25 | +25 (prefetch ORM + walker + SRUM ORM + walker + lint regression coverage) |
| Rule #25 single-slice exception #2 | Rule-of-Six | Rule-of-Eight | +2 (ζ.2.C + ζ.3.C cross-stack alignment) |
| Rule #39 inner/outer/safe runner | Rule-of-Three | Rule-of-Five | +2 (prefetch_walker + srum_walker triplets) |
| Suppressions removed | 0 | 6 | -5 ruff (S314, F601, F811, E741, F402) -1 bandit (B314) |
| ruff `[tool.ruff.lint] ignore` size | 35 | 30 | -5 |
| bandit `[tool.bandit] skips` size | 16 | 15 | -1 |
