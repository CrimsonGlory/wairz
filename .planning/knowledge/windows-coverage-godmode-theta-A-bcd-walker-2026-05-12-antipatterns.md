---
campaign: windows-coverage-godmode-theta-2026-05-12
stream: θ.A — BCD store walker
date: 2026-05-12
kind: antipatterns (failure cases avoided OR caught)
related_postmortem: postmortem-windows-coverage-godmode-theta-A-bcd-walker-2026-05-12.md
---

# Antipatterns — Phase θ.A BCD store walker

Failure cases avoided or caught during the single-stream θ.A dispatch. Each antipattern carries Rule-of-N evidence and a mechanical detection recipe.

---

## A1 — ruff UP031 `%`-formatting in new Python code (Rule-of-Many, mechanical)

**Shape:** Drafting new Python code using `"%08X" % value` percent-formatting instead of f-string `f"{value:08X}"` form. Ruff UP031 flags it as "Use format specifiers instead of percent format."

**This session's hit:** 4 sites in `bcd_walker.py` + `test_bcd_walker.py` (matching the regipy plugin's `"%08X" % datatype` pattern; the upstream uses %-format but wairz's lint rules prefer f-strings).

**Detection:** `uv run ruff check --no-cache <files>` per Antipattern A6.

**Fix:** Replace `"%<spec>" % var` with `f"{var:<spec>}"`. Ruff `--fix` cannot auto-fix this (the unsafe-fixes flag is required); manual replace + re-run.

**Recipe to avoid:** When reading upstream library source as a precedent (per P2 / P6), translate any `%`-format strings to f-strings during the draft phase. Don't copy `%`-format verbatim from the upstream source.

---

## A2 — Mid-block import insertion forces ruff I001 import-sort error (Rule-of-Many, mechanical, auto-fixable)

**Shape:** Adding a new import inserted via targeted Edit in the middle of an alphabetical-sorted import block. Ruff I001 flags the file as un-sorted.

**This session's hit:** 1 hit in `test_jsonb_normalizers.py` — `WINDOWS_BCD_*` constants + `_normalize_/_stamp_windows_bcd_entries_*` helpers inserted mid-block.

**Detection:** `uv run ruff check --no-cache <files>`.

**Fix:** `uv run ruff check --no-cache --fix <files>` auto-handles.

**Recipe to avoid:** None — ruff auto-fix handles it mechanically. Trade-off is between Edit-precision and auto-fix-cost; both are fine.

---

## A3 — Pytest infra-failures are NOT campaign failures (Rule-of-Many — discipline)

**Shape:** When running the full backend pytest suite, infrastructure-dependent failures (real Postgres connection required, optional cpu_rec module, integration-test fixtures missing) can mask the real CI signal. Treat these as PRE-EXISTING and verify by checking against the baseline before declaring a campaign change broke them.

**This session's hit:** 8 pre-existing failures in `test_alembic_autogenerate_empty.py` (real Postgres needed), `test_tar_of_image_integration.py` × 3 (fixtures), `test_binary_analysis_service.py` × 2 (cpu_rec module not in dev venv), `test_terminal_router.py`, `test_hardware_firmware_kernel_vulns_index.py`. ALL confirmed identical to pre-θ.A baseline via `git stash + checkout 2500509^ -- <files>`.

**Detection:** When a backend pytest run reports failures, check whether the same tests fail against the pre-campaign HEAD (or whether they pass in CI's containerised environment).

**Recipe to avoid false-positive blocks:** Don't treat infra-dependent failures as campaign-blocking unless CI's containerised run also fails. CI Backend Tests (running in Docker) is the durable check.

---

## A4 — Mock unit tests assert dispatch shape but not value flow (CLAUDE.md Rule #35b — caught durably)

**Shape:** A mock test that asserts `mock.<method>.assert_called_once()` confirms the dispatch shape but NOT the values flowing through to the persisted row.

**This session's hit:** ZERO — every emit test (12 in test_finding_service_bcd_emit.py) followed Rule #35b by running through `make_live_db()` + emit hook + SELECT + inspect persisted Finding columns. The bootkit canary in θ.A.D + θ.A.E confirmed HIGH confidence persists end-to-end.

**Detection:** Mechanical — review test files for `mock.<method>.assert_called*()` without a corresponding `await db.execute(select(<Model>))` + `assert row.<column> == <expected>`.

**Recipe to avoid:** Every new finding-emit test that exercises the FindingService.create() boundary MUST round-trip through make_live_db and SELECT the persisted row. Rule #35b is mechanical; the live-canary recipe is fixed.

---

## A5 — Premature Rule #8 backend+worker+migrator rebuild (Rule-of-Two — discipline)

**Shape:** Running `docker compose up -d --build backend worker migrator` after EACH alembic migration is expensive (~3-5 min per cycle). For a 3-migration stream, that's ~10-15 min of waiting.

**This session's hit:** ZERO rebuilds during θ.A. All testing ran against the host venv via `make_live_db()` + tier-1 tests. Alembic chain was validated via `uv run alembic heads` on the host venv. End-of-stream rebuild DEFERRED to whenever θ.B opens (saves the cost across both streams).

**Detection:** Mechanical — does the change require a running container interaction? If only alembic chain validation + tier-1 ORM round-trips are needed, the host venv is sufficient.

**Recipe to avoid premature rebuild:** Apply Rule #20 (docker cp + alembic upgrade head) iteratively, OR defer entirely if tier-1 tests via make_live_db cover the verification surface. End-of-stream single rebuild closes the loop. Companion: when class-shape changes hit pydantic BaseSettings / @lru_cache singletons (per Rule #20 caveat), rebuild IS required.

---

## A6 — Drafting walker code from fresh-design when a Rule-of-N>=2 precedent exists (avoided this session)

**Shape:** Re-deriving "how should a walker triplet handle defensive boundaries / per-record extraction / aggregate counters / not-magic-format handling" when an N>=2 precedent has already shipped the answers.

**This session's hit:** ZERO — designed θ.A.C entirely against the η.A.C MFT walker precedent file-by-file. Variable names match, control flow matches, error-string formats match, mocking shapes match. Total design time: ~30 min of η.A reading + minimal new decisions.

**Detection:** Before drafting a new walker, check `grep -l "Rule #39" backend/app/services/*_walker.py | wc -l`. If ≥ 2, a precedent exists — read the closest match end-to-end.

**Recipe to avoid:** Pattern P1 (this session's patterns) is the durable shape — single-sub-agent dispatch + precedent file-by-file reuse. The η.A walker reading at design time cost ~30 min and saved entire classes of design churn.

---

## A7 — Forgetting Rule #16 detection-roots in a new walker (caught structurally this session)

**Shape:** Using `firmware.extracted_path` directly in a walker instead of `get_detection_roots(firmware, db=db)`. Scatter-zip / multi-archive Windows extracts surface sibling roots that `extracted_path` alone misses entirely.

**This session's hit:** ZERO — the walker template from η.A.C carried the `get_detection_roots(...)` discipline directly. The Rule #16 import was visible in the imports block of `mft_walker.py` at design-read time and was copy-translated to `bcd_walker.py` without modification.

**Detection:** Mechanical — `grep -n 'firmware\.extracted_path' backend/app/services/<new>_walker.py` should be 0; `grep -n 'get_detection_roots' <walker>` should be ≥ 1.

**Recipe to avoid:** When drafting a new walker against a precedent, retain the precedent's detection-root imports + invocation pattern verbatim. The Rule #16 violation surface is structural, not behavioural — it only surfaces when a real multi-archive firmware extract is walked, which won't happen in dev-venv tier-1 tests.

---

## A8 — Skipping the Rule #11 runtime import smoke after a class-shape change (avoided)

**Shape:** Running tier-1 pytest after extending an ORM with new columns (Firmware.bcd_walk_*) but NOT running a `uv run python -c "from app.models.firmware import Firmware; print(<cols>)"` smoke against the host venv. A subtle metadata-registration bug could pass tier-1 (because make_live_db creates the DDL fresh) but fail at runtime.

**This session's hit:** ZERO — ran Rule #11 import smokes after θ.A.B (firmware class-shape change), θ.A.C (new walker module), θ.A.D (new finding_service constants + classifier + emit method), and θ.A.F (new MCP tool module). All passed.

**Detection:** After every diff that adds/removes/renames a field on a SQLAlchemy ORM model, Pydantic BaseSettings, or @dataclass at module scope: `uv run python -c "from <module> import <Class>; print(<expected_attr>)"`.

**Recipe to avoid:** Pattern is documented in CLAUDE.md Rule #11; mechanical execution. ~5 seconds per smoke.

---

## A9 — Letting BCD store data flow into a process-spawn primitive (Rule #36 no-execute — structurally avoided)

**Shape:** Passing BCD-extracted `image_path` (a path to a bootloader binary) as `argv[0]` to a subprocess primitive, OR loading the binary via `ctypes.CDLL()`, OR mounting the partition described by ApplicationDevice. ALL forbidden per Rule #36.

**This session's hit:** ZERO — the walker emits image_path as a string column for operator review. No subprocess / no library-load / no mount.

**Detection:** Mechanical — `grep -rn 'subprocess\.\(run\|Popen\|call\|check_output\)\|asyncio\.create_subprocess_\(exec\|shell\)\|ctypes\.CDLL\|os\.system\|os\.execvp' backend/app/services/bcd_walker.py backend/app/ai/tools/windows_bcd.py` should be ZERO.

**Recipe to avoid:** Treat the BCD store as untrusted data input. Coerce element values to scalars / strings / lists in the JSONB layer; never expose them as subprocess args. Companion to CLAUDE.md Rule #36 — the worker is the security boundary; running attacker-controlled bootloader code inside the worker container would defeat the boundary even if a Docker escape didn't follow.

---

## A10 — Pre-allocating alembic IDs across multiple commits without per-commit `git grep` validation (caught durably)

**Shape:** Pre-allocating multiple alembic IDs at decomposition time and committing them across multiple commits without re-validating each ID's freshness immediately before its commit. A collision could be introduced by a parallel branch / sibling stream merge.

**This session's hit:** ZERO — each of the 3 alembic IDs (1f4a2b3c4d5e, 2a5b3c4d5e6f, 3b6c4d5e6f7a) was pre-validated FREE via `grep -rl "<id>" backend/alembic/versions/` immediately before its commit.

**Detection:** Antipattern A10 documented in CLAUDE.md and the η antipatterns. Mechanical: `git -C /home/dustin/code/wairz grep -l "<candidate_id>" backend/alembic/versions/` must return 0 lines.

**Recipe to avoid:** Mint each alembic ID one-at-a-time, in the commit where it's introduced. Chain each from the previous concrete commit's ID. Pattern A10 from η postmortem is the durable shape.

---

## Cross-references

- **CLAUDE.md antipatterns / discipline applied:** A6 (ruff --no-cache), A10 (alembic ID pre-validation), Rule #11 (runtime import smoke), Rule #16 (detection roots), Rule #35b (live canaries), Rule #36 (no-execute), Rule #38 (absolute paths).
- **Patterns shipped:** see `windows-coverage-godmode-theta-A-bcd-walker-2026-05-12-patterns.md`
- **Postmortem:** `postmortem-windows-coverage-godmode-theta-A-bcd-walker-2026-05-12.md`
