# Postmortem: Rule #44 cross-firmware backfill + deep multi-persona review

> **Date:** 2026-05-14
> **Session:** 9e4946ec — single-session campaign
> **Branch / range:** main · `bc91a4a..e2321ec` (20 commits)
> **Status:** SHIPPED — CI green on intermediate boundary `3ef7d06`; final push pending after Phase D

## TL;DR

Single-session campaign delivered (a) the Issue #15 Rule #44 cross-firmware aggregation backfill across 11 walker categories, then (b) a deep multi-persona review (code/security, forensic domain, SQL/performance) that surfaced 6 high-priority defects, then (c) shipped 6 follow-up Rule #25 commits fixing each defect, then (d) 26 Rule #35b live canary tests pinning both the value flow AND the calibration regressions.

**20 commits.** Zero reverts. Zero cross-stream sweeps (single-session, single-branch). CI status: 3 of 3 checks green on the intermediate boundary; final batch push pending.

## What we did (in order)

1. **CI recovery** (2 commits): the boundary commit `bc91a4a` had landed with 4 lint errors + 1 alembic-autogenerate-empty failure. Shipped a NOT-NULL forward-only alembic migration for `volatility_*_records.created_at` (the ORM declared `Mapped[datetime]` non-Optional but the λ.β.A / λ.γ.A migrations forgot `nullable=False`) AND a ruff import-sort + ASYNC240 fix across 4 test files.

2. **Issue #15 backfill** (11 commits): 11 Rule #25 per-piece commits each adding `_handle_lookup_<artefact>_across_firmwares` + registration + acceptance test to one walker MCP tool file. Identity-key picks per walker:
   - `windows_event_log`: `(provider, event_id)` natural tuple
   - `windows_mft`: `(filename, full_path)` natural tuple
   - `windows_lnk`: `(target_path, arguments)` natural tuple
   - `windows_scheduled_task`: `(task_name, run_as_user)` natural tuple
   - `windows_prefetch`: `(executable_name, prefetch_hash)`
   - `windows_srum`: `(app_identifier, record_type)`
   - `windows_registry`: `(hive_type, hive_path)` (joins through `HardwareFirmwareBlob`)
   - `windows_bcd`: `object_guid`
   - `windows_esp`: `fingerprint_sha256` (canonical-shape companion to pre-existing `lookup_esp_chain`)
   - `windows_mbr_vbr`: `fingerprint_sha256` (companion to `lookup_mbr_vbr_sector`)
   - `windows_sdb`: `fingerprint_sha256` (companion to `lookup_sdb_shim`)

3. **Deep multi-persona review** (3 parallel background agents, all under 5 min wall-clock):
   - **Code/security review** (`citadel:arch-reviewer`): 12 findings, 1 MED (project_id=None silent zero-result bug, inherited from precedent), rest LOW.
   - **Forensic domain expert** (Explore subagent posing as senior DFIR analyst): 11 per-walker evaluations + top-3 priorities — BCD GUID over-flagging (every Windows install has the same `{bootmgr}` GUID), EVTX threshold over-flagging (Security 4624 / Sysmon 1 are ubiquitous baselines), Registry hive_path normalization gaps.
   - **SQL/performance audit** (Explore subagent): 5 findings — `windows_scheduled_tasks` was the only walker where the cross-firmware filter column (`task_name`) lacked an index; limit semantics asymmetry; global-scope rate-limiting absence.

4. **Apply review findings** (6 commits, Phase C1–C6):
   - **C1**: `project_id=None` guard inserted into all 22 lookup handlers (single-slice Rule #25 commit — fix is identical across all consumers; splitting wastes CI runs).
   - **C2**: BCD `supply_chain_signal` now requires `match_count >= 2 AND (any_testsigning OR any_no_integrity_checks)` — the standard `{bootmgr}` GUID across 100 firmwares stays baseline; testsigning+match≥2 fires correctly.
   - **C3**: EVTX `supply_chain_signal` threshold raised from `>= 2` to `>= 5` firmwares — EVTX events are high-volume baseline.
   - **C4**: scheduled_task `supply_chain_signal` now requires `match_count >= 2 AND any_encoded_powershell` — vendor tasks (ProactiveScan / WinDefend) ship in every image; the encoded-PS shape is the T1053+T1059.001 attacker primitive.
   - **C5**: prefetch `executable_name` input normalized to `.upper()` so analyst mixed-case `cmd.exe` matches walker-persisted `CMD.EXE`.
   - **C6**: alembic migration adding `(firmware_id, task_name)` index to `windows_scheduled_tasks` + matching ORM `__table_args__` mirror — every other walker had its identity-column indexed.

5. **Rule #35b live canaries** (1 commit, 26 tests): `tests/test_rule_44_cross_firmware_canaries.py` with parameterized canaries for value flow + dedicated regression backstops for C2/C3/C4/C5 calibration. 6-second runtime.

## What broke

1. **First boundary commit failed CI** (root cause for the session intake). Two independent defects:
   - λ.β.A / λ.γ.A migrations omitted `nullable=False` on `created_at` while the ORM declared `Mapped[datetime]` non-Optional — `alembic check` detected the modify_nullable drift. Fixed in `b3e197d` via new ALTER migration (the precedent migrations were already on main; per Rule #25 we ship a new migration, not amend).
   - 4 ruff errors landed silently: 3 import-sort regressions (the recent walker test files weren't auto-sorted) + 1 ASYNC240 (`os.path.realpath` inside an async dict-comp at `test_firmware_paths.py:809`). Fixed by replacing the direct call with the existing `_real` helper.

2. **Pre-existing alembic test ordering coupling**: the `test_alembic_autogenerate_empty.py` test depends on which OTHER tests get collected first to register all models with `Base.metadata`. Running `test_search_events_mcp.py` in isolation triggers `NoReferencedTableError` on `volatility_injection_records.memory_image_id` → `memory_dump_image.id` because the `MemoryDumpImage` model isn't in `app.models.__init__.py`'s `__all__`. CI succeeds because the full 5524-test suite collects everything. Not in-scope for this session to fix; the new canary file at `test_rule_44_cross_firmware_canaries.py` works around it by explicit `from app.models.memory_dump_image import MemoryDumpImage` import.

3. **First canary attempt failed on JSONB shape**: my scheduled_task `_with_encoded_ps` factory wrote the actions JSONB as `{"schema_version": 1, "actions": [...]}` but the normalizer expects `{"items": [...]}` (or a bare list). The normalizer fell through to `return []` so `any_encoded_powershell` stayed False — supply_chain_signal didn't fire. Caught by the first test run; fixed by switching to the canonical `{"items": [...]}` envelope shape. Rule #35c JSONB normaliser discipline rewarded: writing canary against the normaliser shape (not the writer's pre-normalisation shape) is the durable pattern.

4. **First canary attempt failed on `HardwareFirmwareBlob.detection_source` NOT NULL**: the field isn't documented as required in the walker's docstring but is declared NOT NULL in the migration. Two test runs to surface; fixed by adding `detection_source="walker"`. **Pattern P5**: when seeding for tier-1 canaries, run the test ONCE and let SQLAlchemy's IntegrityError tell you which NOT NULL columns the factory missed — faster than reading the migration file.

## What worked

1. **Parallel multi-persona review via Citadel agents**: 3 agents dispatched in parallel (single message with 3 `Agent` tool uses, `run_in_background=true`), completed within 2-5 minutes wall-clock total. Findings ALL turned out to be actionable — code review caught the project_id=None guard bug AND inherited it to the 11 precedent tools that needed the same fix; forensic expert correctly identified BCD/EVTX/scheduled-task signal calibration gaps that a non-domain reviewer would have missed; SQL auditor pinpointed the single missing index (scheduled_task task_name).

2. **Single-slice Rule #25 commit for the C1 project_id guard**: the fix is identical across 22 handlers (11 backfill + 11 precedent). A per-piece commit chain would have produced 22 cosmetically-identical commits with no bisect value. The single-slice rationale is straight-from-Rule-#25: "if a multi-surface fix would leave the codebase in a half-fixed state with no benefit, bundle." Saved 21 CI runs.

3. **Parameterized canary registry pattern**: `_ToolSpec` dataclass + `pytest.parametrize` lets a future Rule #44 walker auto-inherit canary coverage by adding ONE TOOLS entry. Eliminates the "developer ships walker N+1 and forgets to add canary" failure mode. Pattern is reusable.

4. **Rule #35b live canaries caught at least 1 latent bug in fixtures**: the test_scheduled_task_no_signal_without_encoded_powershell test fired the assertion exactly as expected. The fixtures are durable.

5. **Rule #20 docker cp + alembic for fast iteration**: applied the new alembic migration via `docker cp + alembic upgrade head` in <30s without a Rule #8 full rebuild. The dev container had drifted 13 hours; rebuilt once mid-session and ran on durable state thereafter.

## What we should do differently next time

1. **Run ruff check + alembic check on the LAST commit before push, not just the first**. CI failed on bc91a4a because the 4 lint errors snuck in during a sweep — they would have been caught by a `( cd backend && uv run ruff check --no-cache . && /app/.venv/bin/alembic check )` smoke before push. Rule #43 covers ruff suppression discipline; Rule #41 covers boundary-commit detection-cost. Combined: pre-push gate should explicitly include `alembic check` because the autogenerate-drift gate WAS the failure.

2. **Sanity-check identity-key choices via a forensic-domain mental model BEFORE shipping the backfill commits**. The BCD `{bootmgr}` GUID over-flagging is forensically obvious in hindsight (every Windows install has it). A 30-second mental check ("would this identity key produce false positives on a normal corpus?") would have caught it BEFORE shipping. Cost: 5 follow-up commits (C2/C3/C4 alone are 3 commits). The forensic review at the END of the session is necessary but not sufficient — domain check should be PART of the backfill discipline.

3. **Live canaries should ship WITH the walker, not as a follow-up commit**. The Rule #25 single-slice exception we used (one consolidated canary file as a single follow-up) is correct in retrospect, but the better discipline going forward is "each Rule #44 backfill commit includes 2 canaries in its acceptance-test slot". The registration test alone is dispatch-shape; Rule #35b requires the value flow. Future Rule #44 walker streams should bundle.

4. **The `app/models/__init__.py` registration gap is a latent bug factory**. Models added to `app/models/` but NOT registered in `__init__.py.__all__` produce two failure modes: (a) `alembic autogenerate` proposes spurious "remove_table" diffs when not all tests are collected, (b) tests that need `make_live_db()` fail with `NoReferencedTableError` until they manually import the missing model. Memory_dump_image, volatility_*_record, and several others sit in this gap. Out of scope for this session — but a sweep "register every model in models/__init__.py" is a single Rule #25 commit that would harden every future test.

## Numbers worth tracking

| Metric | Value |
|--------|-------|
| Commits this session | 20 |
| Walker categories backfilled (Issue #15) | 11 |
| Cross-firmware MCP tools added | 11 (registry total now 22: 11 pre-existing + 11 new) |
| Total MCP tools in registry post-backfill | 321 |
| Follow-up defects surfaced by deep review | 6 (1 MED bug + 4 forensic calibrations + 1 missing index) |
| Follow-up Rule #25 commits | 6 (Phase C1–C6) |
| Rule #35b live canary tests added | 26 (22 parameterized + 4 calibration regression backstops) |
| Live canary runtime | 6 seconds |
| CI runs intermediate boundary `3ef7d06` | 3/3 green (Backend Tests + Lint + CodeQL) |
| Parallel reviewer agents dispatched | 3 (code/security + forensic + SQL/perf) |
| Reviewer wall-clock | ~5 min total (parallel) |
| Files modified | 30 |
| Lines added | ~2,800 |

## Forensic-review key findings (verbatim domain-expert insights)

1. **BCD `object_guid` alone is forensically dangerous**. The well-known GUIDs `{9dea862c-...}` (bootmgr), `{466f5a88-...}` (bootloader) are IDENTICAL across every Windows install. Using them as the sole identity key without a configuration-anomaly filter generates massive false-positive cross-firmware matches.

2. **EVTX events naturally repeat across normal firmware operation**. Security 4624 (logon success), System 7045 (service install), Sysmon 1 (process create) fire on EVERY captured system. A `match_count >= 2` threshold triggers `supply_chain_signal=True` constantly on baseline events.

3. **Vendor-shipped scheduled tasks ship in every Windows install** (ProactiveScan, WinDefend, Windows Update Medic, MapsToastTask, etc.). Naïve cross-firmware match doesn't distinguish baseline from attacker persistence.

4. **Windows prefetch `.pf` filenames are uppercase on disk**, so analyst mixed-case input silently misses matches.

5. **Registry `hive_path` varies per-user / per-install** (NTUSER_S-1-5-21-…). Future improvement: identity key on parsed subkey-name hashes, not physical paths. Deferred to a follow-up issue (see "Follow-ups" below).

## Follow-ups (deferred to future sessions, captured for backlog)

- **Issue (TBD)**: Registry hive_path normalization — pivot on parsed-subkey-name hashes rather than physical paths to catch user-id-varying persistence keys.
- **Issue (TBD)**: MFT case-normalization — case-insensitive NTFS lookups need normalized key.
- **Issue (TBD)**: SRUM threshold — byte-volume gates to suppress legitimate-app noise.
- **Issue (TBD)**: Global-scope rate-limiting OR explicit opt-in for `scope="global"` queries.
- **Issue (TBD)**: Limit semantics documentation — `limit` caps firmware-count returned, not SQL rows scanned.
- **Issue (TBD)**: `app/models/__init__.py` sweep — register MemoryDumpImage + VolatilityProcessRecord + VolatilityInjectionRecord + the other ~15 missing models to harden alembic-autogenerate-check and make_live_db().

These should be filed as GitHub issues by the operator after reviewing the commits.
