---
campaign: windows-coverage-godmode-theta-2026-05-12
stream: θ.C — ESP `.efi` PE chain walker
date: 2026-05-12
kind: antipatterns (failure cases avoided OR caught)
related_postmortem: postmortem-windows-coverage-godmode-theta-C-esp-walker-2026-05-12.md
---

# Antipatterns — Phase θ.C ESP `.efi` PE chain walker

Failure cases avoided or caught during the single-stream θ.C dispatch. Each antipattern carries Rule-of-N evidence and a mechanical detection recipe.

---

## A1 — `get_detection_roots` returns multiple roots in tier-1 tests (Rule-of-Two — durable)

**Shape:** A walker tier-1 test setup using `tempfile.TemporaryDirectory()` + `firmware.extracted_path = td` produces `get_detection_roots()` returning `[td, '/tmp']` (the firmware's tmp dir AND its parent). The walker scans every candidate file TWICE, breaking single-root assertion counts (`efi_files_scanned == 1` fails with `2 == 1`).

**This session's hit:** 3 sites in `tests/test_esp_walker.py` (the 3 `_do_esp_walk_*walks*` live canaries that used `firmware.extracted_path = td`).

**Detection:** A tier-1 walker test that asserts a count derived from filesystem walking BUT doesn't mock `get_detection_roots`. Symptom: `assert N == 1` fails with `N==2` even though the test fixture wrote exactly 1 candidate file.

**Fix:** `@patch("app.services.<walker>.get_detection_roots", _fake_roots)` where `_fake_roots` is an async helper that returns `[td]` for the test's tempdir.

**Recipe to avoid:** When writing tier-1 tests for a Rule #39 walker that performs filesystem scanning, ALWAYS patch `get_detection_roots` at the walker module path. The BCD walker tests (`test_bcd_walker.py`) already follow this discipline (~50 sites use `patch("app.services.bcd_walker.get_detection_roots", ...)`). Adopt the same shape for any new walker.

**Rule-of-Two now**: BCD walker tests already had this discipline (no recurrence there); θ.C walker tests inherited it after this catch. Should generalise to `.mex/patterns/walker-tier1-test-skeleton.md` recipe — mock detection_roots ALWAYS, even when the test seems to want the real roots.

---

## A2 — Mid-block import insertion forces ruff I001 import-sort error (Rule-of-Many, mechanical, auto-fixable)

**Shape:** Adding a new import inserted via targeted Edit in the middle of an alphabetical-sorted import block. Ruff I001 flags the file as un-sorted.

**This session's hit:** 3 hits across `test_jsonb_normalizers.py` / `test_finding_service_esp_emit.py` / `test_windows_esp_tools.py` (each added a new ESP import mid-block).

**Detection:** `uv run ruff check --no-cache <files>`.

**Fix:** `uv run ruff check --no-cache --fix <files>` auto-handles.

**Recipe to avoid:** None — ruff auto-fix handles it mechanically. Same shape caught in θ.A / θ.B (Antipattern A2 in both prior postmortems). Rule-of-Many.

---

## A3 — Mock unit tests assert dispatch shape but not value flow (CLAUDE.md Rule #35b — caught durably)

**Shape:** A mock test that asserts `mock.<method>.assert_called_once()` confirms the dispatch shape but NOT the values flowing through to the persisted row.

**This session's hit:** ZERO — every emit test (10 in test_finding_service_esp_emit.py) and every MCP tool test (14 in test_windows_esp_tools.py) followed Rule #35b by running through `make_live_db()` + walker / emit / handler + SELECT + inspect persisted columns. The HIGH-tier unsigned-bootloader canary AND the dbx_revoked canary confirmed `confidence` + `severity` + `source` + `file_path` persist end-to-end.

**Detection:** Mechanical — review test files for `mock.<method>.assert_called*()` without a corresponding `await db.execute(select(<Model>))` + `assert row.<column> == <expected>`.

**Recipe to avoid:** Every new finding-emit test that exercises the FindingService.create() boundary MUST round-trip through make_live_db and SELECT the persisted row. Rule #35b is mechanical; the live-canary recipe is fixed.

---

## A4 — Premature Rule #8 backend+worker+migrator rebuild (Rule-of-Many — discipline)

**Shape:** Running `docker compose up -d --build backend worker migrator` after EACH alembic migration is expensive (~3-5 min per cycle). For a 3-migration stream, that's ~10-15 min of waiting.

**This session's hit:** ZERO rebuilds during θ.C. All testing ran against the host venv via `make_live_db()` + tier-1 tests. Alembic chain was validated via `uv run alembic heads` on the host venv.

**Detection:** Mechanical — does the change require a running container interaction? If only alembic chain validation + tier-1 ORM round-trips are needed, the host venv is sufficient.

**Recipe to avoid premature rebuild:** Apply Rule #20 (docker cp + alembic upgrade head) iteratively, OR defer entirely if tier-1 tests via make_live_db cover the verification surface. End-of-θ rebuild deferred to whenever ι opens.

---

## A5 — Drafting walker code from fresh-design when a Rule-of-N>=2 precedent exists (avoided this session)

**Shape:** Re-deriving "how should a walker triplet handle defensive boundaries / per-record extraction / aggregate counters / not-magic-format handling" when an N>=2 precedent has already shipped the answers.

**This session's hit:** ZERO — designed θ.C.C entirely against the θ.B.D WMI walker precedent file-by-file. Variable names match, control flow matches, error-string formats match, mocking shapes match. Total design time: ~15 min of θ.B reading + minimal new decisions.

**Detection:** Before drafting a new walker, check `grep -l "Rule #39" backend/app/services/*_walker.py | wc -l`. If ≥ 2, a precedent exists — read the closest match end-to-end.

**Recipe to avoid:** Pattern P1 (this session's patterns) is the durable shape — single-sub-agent dispatch + precedent file-by-file reuse. The θ.B walker reading at design time cost ~15 min and saved entire classes of design churn.

---

## A6 — Forgetting Rule #16 detection-roots in a new walker (caught structurally this session)

**Shape:** Using `firmware.extracted_path` directly in a walker instead of `get_detection_roots(firmware, db=db)`. Scatter-zip / multi-archive Windows extracts surface sibling roots that `extracted_path` alone misses entirely.

**This session's hit:** ZERO — the walker template from θ.B.D carried the `get_detection_roots(...)` discipline directly. The Rule #16 import was visible in the imports block of `wmi_walker.py` at design-read time and was copy-translated to `esp_walker.py` without modification.

**Detection:** Mechanical — `grep -n 'firmware\.extracted_path' backend/app/services/<new>_walker.py` should be 0; `grep -n 'get_detection_roots' <walker>` should be ≥ 1.

**Recipe to avoid:** When drafting a new walker against a precedent, retain the precedent's detection-root imports + invocation pattern verbatim. The Rule #16 violation surface is structural, not behavioural — it only surfaces when a real multi-archive firmware extract is walked, which won't happen in dev-venv tier-1 tests.

---

## A7 — Skipping the Rule #11 runtime import smoke after a class-shape change (avoided)

**Shape:** Running tier-1 pytest after extending an ORM with new columns (Firmware.esp_walk_*) but NOT running a `uv run python -c "from app.models.firmware import Firmware; print(<cols>)"` smoke against the host venv.

**This session's hit:** ZERO — ran Rule #11 import smokes after θ.C.A (new ORM model), θ.C.B (firmware class-shape change), θ.C.C (new walker module), θ.C.D (new finding_service constants + classifier + emit method), and θ.C.F (new MCP tool module — built the full `create_tool_registry()` to verify 247 tools register cleanly).

**Detection:** After every diff that adds/removes/renames a field on a SQLAlchemy ORM model, Pydantic BaseSettings, or @dataclass at module scope: `uv run python -c "from <module> import <Class>; print(<expected_attr>)"`.

**Recipe to avoid:** Pattern is documented in CLAUDE.md Rule #11; mechanical execution. ~5 seconds per smoke.

---

## A8 — Letting `.efi` PE binaries flow into a process-spawn primitive (Rule #36 no-execute — structurally avoided)

**Shape (THE CENTRAL DISCIPLINE FOR θ.C):** Passing extracted `.efi` PE32+ binaries as `argv[0]` to a subprocess primitive (wine / mono / qemu-system / chainloader / rundll32 / regsvr32), OR loading them via `eval()` / `exec()` / `runpy`. ALL forbidden per Rule #36.

**This session's hit:** ZERO — the walker calls signify (which reads the certificate table as DATA), pefile (which reads the COFF header as DATA), and the β.10 DBX matcher (which compares hashes / serial numbers). NO codepath in this walker invokes wine / mono / qemu-system / chainloader / rundll32 / regsvr32 / any process-spawn primitive against the `.efi` files. Verified by structural test gate `test_esp_no_efi_execution` (39 walker tests pass; gate scrubs string literals + comments before matching forbidden patterns).

**Detection:** Mechanical — `grep -rn 'subprocess\.\(run\|Popen\|call\|check_output\)\|asyncio\.create_subprocess_\(exec\|shell\)\|os\.system\|os\.execvp\|wine\|mono\|qemu-system\|chainloader\|rundll32\|regsvr32' backend/app/services/esp_walker.py backend/app/ai/tools/windows_esp.py` should be ZERO matches in CODE (string-literal / comment hits ignored — the test gate scrubs those before matching).

**Recipe to avoid:** Treat `.efi` PEs as untrusted PE32+ data input. The walker maps the verdict (DATA) onto WindowsEspEntry columns; the classifier surfaces the metadata (DATA) in Finding evidence; the MCP tools return JSON (DATA). NO codepath INVOKES the binary at the persisted file_path. Companion to CLAUDE.md Rule #36 — the worker is the security boundary; running attacker-controlled `.efi` code inside the worker container would defeat the boundary even if a UEFI-emulator escape didn't follow.

The MCP tool output additionally surfaces a `data_only_disclaimer` field explicitly noting the `.efi` binaries are DATA and MUST NOT be invoked by the MCP client / operator.

---

## A9 — Pre-allocating alembic IDs across multiple commits without per-commit `git grep` validation (caught durably)

**Shape:** Pre-allocating multiple alembic IDs at decomposition time and committing them across multiple commits without re-validating each ID's freshness immediately before its commit. A collision could be introduced by a parallel branch / sibling stream merge.

**This session's hit:** ZERO — each of the 3 alembic IDs (`7a8b9c0d1e2f`, `8b9c0d1e2f3a`, `9c0d1e2f3a4b`) was pre-validated FREE via `git -C /home/dustin/code/wairz grep -l "<id>" backend/alembic/versions/` immediately before its commit.

**Detection:** Antipattern A10 documented in CLAUDE.md and the η antipatterns. Mechanical: `git grep -l "<candidate_id>" backend/alembic/versions/` must return 0 lines.

**Recipe to avoid:** Mint each alembic ID one-at-a-time, in the commit where it's introduced. Chain each from the previous concrete commit's ID. Pattern A10 from η postmortem is the durable shape.

---

## A10 — Calling `match_dbx_revocation` separately when β.4 verifier already includes it (caught at design-time by Rule #19 probe)

**Shape:** A walker that integrates Authenticode validation + DBX revocation invokes BOTH `verify_pe_file()` AND `match_dbx_revocation()` separately — duplicating work + duplicating bundle parsing. signify is called once for Authenticode; then `match_dbx_revocation` re-opens the DBX bundle even though `verify_pe_file` already plumbed it through.

**This session's hit:** ZERO — caught at DESIGN time by Rule #19 probe. Read `verify_pe_file()` body BEFORE drafting `_do_esp_walk`; discovered `verdict.dbx_revoked` + `verdict.dbx_revocation_kb` are already populated by the β.4 verifier (via internal `match_dbx_revocation()` call). The walker only needs to MAP the verdict — not call DBX separately.

**Detection:** During design-time review of integration boundaries, identify whether the upstream service ALREADY includes the secondary concern. For β.4 + β.10 specifically: `verify_pe_file` returns an `AuthenticodeVerdict` whose `.dbx_revoked` is set by the verifier internally. A grep for `match_dbx_revocation` in `authenticode_service.py` surfaces the layering.

**Recipe to avoid:** Apply Pattern P3 (this stream's patterns) — Rule #19 evidence-first probe of existing service boundaries. Read the upstream service's return shape; if the concern you were planning to add is already in the return, skip the duplicate call.

**Generalises Rule #19**: "the existing service describes the integration boundary; READ it before drafting integration code."

---

## A11 — Mid-flow assumption about scope (caught by `wc -l` re-measure)

**Shape:** Drafting the walker test set + the MCP tool set with an upfront LOC estimate, then discovering the actual scope is different at draft time.

**This session's hit:** ZERO — the campaign brief estimated θ.C as 4+ commits with "mostly wiring on existing primitives." Actual: 5 commits (absorbing θ.C.E into θ.C.C+θ.C.D), 925 LOC walker, 1091 LOC MCP tool category. The estimate was directionally correct. No mid-flow scope surprises required a re-measure.

**Detection:** Rule #28 — before starting any refactor whose scope is predicated on a specific LOC count in an intake / spec, re-measure with `wc -l` first. Applies here as a NULL — no re-measure was needed because the brief's "mostly wiring" disposition held.

**Recipe to avoid:** When a campaign brief flags a stream as "mostly wiring" or "small," check the brief's estimated wall time against the precedent campaign's actual wall time. θ.B took 1.5h actual; θ.C brief said "2-4h"; θ.C actual was 1h. The brief's lower bound is the realistic estimate when precedent-reuse compounds (Pattern P1 speedup).

---

## Cross-references

- **CLAUDE.md antipatterns / discipline applied:** A6 (ruff --no-cache), A10 (alembic ID pre-validation), Rule #11 (runtime import smoke), Rule #16 (detection roots), Rule #19 (evidence-first — extended to existing service boundaries), Rule #20 (docker cp + alembic upgrade head — deferred), Rule #35a (exit-code-before-pipe), Rule #35b (live canaries), Rule #36 (no-execute — CENTRAL DISCIPLINE FOR θ.C), Rule #38 (absolute paths).
- **Patterns shipped:** see `windows-coverage-godmode-theta-C-esp-walker-2026-05-12-patterns.md`
- **Postmortem:** `postmortem-windows-coverage-godmode-theta-C-esp-walker-2026-05-12.md`
