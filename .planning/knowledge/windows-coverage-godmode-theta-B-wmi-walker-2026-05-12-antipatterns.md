---
campaign: windows-coverage-godmode-theta-2026-05-12
stream: θ.B — WMI persistence walker
date: 2026-05-12
kind: antipatterns (failure cases avoided OR caught)
related_postmortem: postmortem-windows-coverage-godmode-theta-B-wmi-walker-2026-05-12.md
---

# Antipatterns — Phase θ.B WMI persistence walker

Failure cases avoided or caught during the single-stream θ.B dispatch. Each antipattern carries Rule-of-N evidence and a mechanical detection recipe.

---

## A1 — SQLite server_default="false" coerces to True under make_live_db (Rule-of-Two now)

**Shape:** Declaring a SQLAlchemy Boolean column with ONLY `server_default="false"` and no Python-side `default=False`. Under Postgres the server_default applies on INSERT and the column is correctly False. Under SQLite (which is what `make_live_db` uses for tier-1 testing), the string `"false"` is treated as a non-empty truthy value and the column comes out True.

**This session's hit:** 1 site in `app/models/windows_wmi_event.py`'s `probably_benign` column. Caught by `test_wmi_event_persists_with_minimal_required_fields` asserting `r.probably_benign is False`.

**Detection:** Tier-1 test assertions on the column's default value (not just dispatch shape) — Rule #35b live canary. The `assert r.probably_benign is False` fired because the live canary actually inspected the persisted value, not just `mock.add.assert_called_once()`.

**Fix:** Add explicit Python-side `default=False` alongside the `server_default="false"`. Both gates work; SQLite + Postgres both behave correctly.

**Recipe to avoid:** When declaring a Boolean column with a non-true default, ALWAYS pair `default=<python_value>` with `server_default="<sql_literal>"`. For `default=True`: `default=True, server_default="true"`. For `default=False`: `default=False, server_default="false"`. The Python-side default is the SQLAlchemy fallback when the server_default isn't applied.

**Rule-of-Two now**: θ.A.A handled JSONB column defaults correctly (no boolean columns with server_default in the BCD ORM); θ.B.B's WindowsWmiEvent caught the boolean-server-default-coercion case. Should generalise to a `.mex/patterns/sqlalchemy-boolean-default.md` recipe.

---

## A2 — Mid-block import insertion forces ruff I001 import-sort error (Rule-of-Many, mechanical, auto-fixable)

**Shape:** Adding a new import inserted via targeted Edit in the middle of an alphabetical-sorted import block. Ruff I001 flags the file as un-sorted.

**This session's hit:** 1 hit in `test_jsonb_normalizers.py` — `FIRMWARE_WMI_WALK_RESULT_SCHEMA_VERSION` + `WINDOWS_WMI_EVENTS_*` constants + `_normalize_*` / `_stamp_*` helpers inserted mid-block.

**Detection:** `uv run ruff check --no-cache <files>`.

**Fix:** `uv run ruff check --no-cache --fix <files>` auto-handles.

**Recipe to avoid:** None — ruff auto-fix handles it mechanically. Same shape caught in θ.A.A's normaliser-imports addition. Rule-of-Many.

---

## A3 — Rule #35a pipe-induced silent exit during Rule #24 canary (Rule-of-Two now)

**Shape:** Running `cmd 2>&1 | tail -N; ec=$?` reports `tail`'s exit (always 0 when input is well-formed), not `cmd`'s exit. The discipline is `cmd; ec=$?` BEFORE any pipe.

**This session's hit:** 1 site in the first Rule #24 canary attempt. `npx tsc -b --force 2>&1 | tail -10; ec=$?` printed the TS2322 type error correctly BUT reported `ec=0` — impossible if tsc actually exited non-zero with the bad input.

**Detection:** The canary's design — when a known-bad input produces a "successful" exit code, the verification is broken.

**Fix:** Re-ran without the pipe: `npx tsc -b --force; ec=$?` → `ec=2` as expected.

**Recipe to avoid:** When capturing an exit code for a CLI tool, run it WITHOUT a pipe. If output is wanted alongside, write to a temp file: `cmd > /tmp/out 2>&1; ec=$?; tail -10 /tmp/out`.

**Generalises Rule #35a**: cache-hit short-circuit (Rule #17 original) AND pipe-induced exit obfuscation (Rule #35a) are the two known silent-exit mechanisms. Both have Rule-of-Two now.

---

## A4 — Mock unit tests assert dispatch shape but not value flow (CLAUDE.md Rule #35b — caught durably)

**Shape:** A mock test that asserts `mock.<method>.assert_called_once()` confirms the dispatch shape but NOT the values flowing through to the persisted row.

**This session's hit:** ZERO — every emit test (12 in test_finding_service_wmi_emit.py + the e2e test in test_wmi_walker.py) followed Rule #35b by running through `make_live_db()` + emit hook + SELECT + inspect persisted Finding columns. The ActiveScript-HIGH canary confirmed Confidence.high persists end-to-end.

**Detection:** Mechanical — review test files for `mock.<method>.assert_called*()` without a corresponding `await db.execute(select(<Model>))` + `assert row.<column> == <expected>`.

**Recipe to avoid:** Every new finding-emit test that exercises the FindingService.create() boundary MUST round-trip through make_live_db and SELECT the persisted row. Rule #35b is mechanical; the live-canary recipe is fixed.

---

## A5 — Premature Rule #8 backend+worker+migrator rebuild (Rule-of-Many — discipline)

**Shape:** Running `docker compose up -d --build backend worker migrator` after EACH alembic migration is expensive (~3-5 min per cycle). For a 3-migration stream, that's ~10-15 min of waiting.

**This session's hit:** ZERO rebuilds during θ.B. All testing ran against the host venv via `make_live_db()` + tier-1 tests. Alembic chain was validated via `uv run alembic heads` on the host venv during θ.A. End-of-θ rebuild DEFERRED to whenever θ.C opens (saves the cost across both streams).

**Detection:** Mechanical — does the change require a running container interaction? If only alembic chain validation + tier-1 ORM round-trips are needed, the host venv is sufficient.

**Recipe to avoid premature rebuild:** Apply Rule #20 (docker cp + alembic upgrade head) iteratively, OR defer entirely if tier-1 tests via make_live_db cover the verification surface. End-of-stream single rebuild closes the loop. Companion: when class-shape changes hit pydantic BaseSettings / @lru_cache singletons (per Rule #20 caveat), rebuild IS required.

---

## A6 — Drafting walker code from fresh-design when a Rule-of-N>=2 precedent exists (avoided this session)

**Shape:** Re-deriving "how should a walker triplet handle defensive boundaries / per-record extraction / aggregate counters / not-magic-format handling" when an N>=2 precedent has already shipped the answers.

**This session's hit:** ZERO — designed θ.B.D entirely against the θ.A.C BCD walker precedent file-by-file. Variable names match, control flow matches, error-string formats match, mocking shapes match. Total design time: ~15 min of θ.A reading + minimal new decisions.

**Detection:** Before drafting a new walker, check `grep -l "Rule #39" backend/app/services/*_walker.py | wc -l`. If ≥ 2, a precedent exists — read the closest match end-to-end.

**Recipe to avoid:** Pattern P1 (this session's patterns) is the durable shape — single-sub-agent dispatch + precedent file-by-file reuse. The θ.A walker reading at design time cost ~15 min and saved entire classes of design churn.

---

## A7 — Forgetting Rule #16 detection-roots in a new walker (caught structurally this session)

**Shape:** Using `firmware.extracted_path` directly in a walker instead of `get_detection_roots(firmware, db=db)`. Scatter-zip / multi-archive Windows extracts surface sibling roots that `extracted_path` alone misses entirely.

**This session's hit:** ZERO — the walker template from θ.A.C carried the `get_detection_roots(...)` discipline directly. The Rule #16 import was visible in the imports block of `bcd_walker.py` at design-read time and was copy-translated to `wmi_walker.py` without modification.

**Detection:** Mechanical — `grep -n 'firmware\.extracted_path' backend/app/services/<new>_walker.py` should be 0; `grep -n 'get_detection_roots' <walker>` should be ≥ 1.

**Recipe to avoid:** When drafting a new walker against a precedent, retain the precedent's detection-root imports + invocation pattern verbatim. The Rule #16 violation surface is structural, not behavioural — it only surfaces when a real multi-archive firmware extract is walked, which won't happen in dev-venv tier-1 tests.

---

## A8 — Skipping the Rule #11 runtime import smoke after a class-shape change (avoided)

**Shape:** Running tier-1 pytest after extending an ORM with new columns (Firmware.wmi_walk_*) but NOT running a `uv run python -c "from app.models.firmware import Firmware; print(<cols>)"` smoke against the host venv. A subtle metadata-registration bug could pass tier-1 (because make_live_db creates the DDL fresh) but fail at runtime.

**This session's hit:** ZERO — ran Rule #11 import smokes after θ.B.B (new ORM model), θ.B.C (firmware class-shape change), θ.B.D (new walker module), θ.B.E (new finding_service constants + classifier + emit method), and θ.B.G (new MCP tool module). All passed. The final smoke even built the FULL `create_tool_registry()` to verify 243 tools register cleanly.

**Detection:** After every diff that adds/removes/renames a field on a SQLAlchemy ORM model, Pydantic BaseSettings, or @dataclass at module scope: `uv run python -c "from <module> import <Class>; print(<expected_attr>)"`.

**Recipe to avoid:** Pattern is documented in CLAUDE.md Rule #11; mechanical execution. ~5 seconds per smoke.

---

## A9 — Letting WMI consumer payloads flow into a process-spawn primitive (Rule #36 no-execute — structurally avoided)

**Shape (THE CENTRAL DISCIPLINE FOR θ.B):** Passing extracted WMI binding consumer payloads (CommandLineEventConsumer Arguments / ActiveScriptEventConsumer ScriptText / LogFileEventConsumer FileName + WriteString) as `argv[0]` to a subprocess primitive, OR loading them via `eval()` / `exec()` / `runpy`, OR invoking them via `wscript.exe` / `cscript.exe` / `powershell.exe` / `mshta.exe` / `rundll32.exe` / `regsvr32.exe` / `WmiPrvSE.exe` / `wmiexec.py` / `mofcomp.exe`. ALL forbidden per Rule #36.

**This session's hit:** ZERO — the walker emits consumer_payload as JSONB DATA for operator review. No subprocess / no eval / no exec / no library-load / no script-host invocation. Verified by 4 structural test gates (`test_vendor_no_execute_in_init_source`, `test_vendor_no_execute_across_entire_package`, `test_wmi_no_script_execution`, `test_wmi_vendor_no_script_execution`).

**Detection:** Mechanical — `grep -rn 'subprocess\.\(run\|Popen\|call\|check_output\)\|asyncio\.create_subprocess_\(exec\|shell\)\|os\.system\|os\.execvp\|wscript\.exe\|cscript\.exe\|powershell\.exe\|mshta\.exe\|WmiPrvSE\.exe\|wmiexec\|mofcomp' backend/app/services/wmi_walker.py backend/third_party/pywmi_persistence_finder/ backend/app/ai/tools/windows_wmi.py` should be ZERO matches in CODE (string-literal / comment hits ignored — the test gates scrub those before matching).

**Recipe to avoid:** Treat WMI OBJECTS.DATA as untrusted data input. Coerce element values to scalars / strings / lists in the JSONB layer; never expose them as subprocess args. The walker + vendor + MCP tool layer ALL carry the structural test gates. Companion to CLAUDE.md Rule #36 — the worker is the security boundary; running attacker-controlled WMI consumer code inside the worker container would defeat the boundary even if a Docker escape didn't follow.

The MCP tool output additionally surfaces a `data_only_disclaimer` field explicitly noting the payload is attacker-controlled DATA and MUST NOT be invoked by the MCP client / operator.

---

## A10 — Pre-allocating alembic IDs across multiple commits without per-commit `git grep` validation (caught durably)

**Shape:** Pre-allocating multiple alembic IDs at decomposition time and committing them across multiple commits without re-validating each ID's freshness immediately before its commit. A collision could be introduced by a parallel branch / sibling stream merge.

**This session's hit:** ZERO — each of the 3 alembic IDs (4c7d5e6f8b1a, 5d8e6f9c0a2b, 6e9f7a0b1c3d) was pre-validated FREE via `git -C /home/dustin/code/wairz grep -l "<id>" backend/alembic/versions/` immediately before its commit.

**Detection:** Antipattern A10 documented in CLAUDE.md and the η antipatterns. Mechanical: `git -C /home/dustin/code/wairz grep -l "<candidate_id>" backend/alembic/versions/` must return 0 lines.

**Recipe to avoid:** Mint each alembic ID one-at-a-time, in the commit where it's introduced. Chain each from the previous concrete commit's ID. Pattern A10 from η postmortem is the durable shape.

---

## A11 — Mid-commit vendor regex copying without preserving exact upstream patterns (caught structurally)

**Shape:** When vendoring an upstream library's regex patterns, transcribing them with subtle changes (escaping, character class equivalents, alternation order) that change the false-positive / false-negative characteristics from the upstream's well-validated shape.

**This session's hit:** ZERO — copied the upstream's regex patterns verbatim into Python bytestrings, only changing `r"..."` → `rb"..."` for the bytes-mode requirement (the vendor opens OBJECTS.DATA in "rb" mode). The Rule #19 evidence-first WebFetch probe captured the EXACT regex shapes:
- `r"([\w\_]*EventConsumer\.Name\=\")([\w\s]*)(\")"` → `rb"([\w\_]*EventConsumer\.Name\=\")([\w\s]*)(\")"` ✓
- `r"(_EventFilter\.Name\=\")([\w\s]*)(\")"` → `rb"(_EventFilter\.Name\=\")([\w\s]*)(\")"` ✓
- CommandLineEventConsumer regex preserved verbatim
- Fallback EventConsumer regex preserved verbatim

**Detection:** Compare the vendored regex literals against the upstream raw file character-by-character. The `r"..."` vs `rb"..."` is the only legitimate change; the regex itself must match.

**Recipe to avoid:** Use the Rule #19 evidence-first WebFetch / curl to extract the upstream's regex patterns as TEXT, then copy-paste them verbatim into the vendor file. Don't retype them from memory or "clean them up." The upstream's false-positive rate is a feature of the well-validated patterns; modifying them changes the detection characteristics.

---

## Cross-references

- **CLAUDE.md antipatterns / discipline applied:** A6 (ruff --no-cache), A10 (alembic ID pre-validation), Rule #11 (runtime import smoke), Rule #16 (detection roots), Rule #35a (exit-code-before-pipe — reinforced this stream), Rule #35b (live canaries), Rule #36 (no-execute — CENTRAL DISCIPLINE FOR θ.B), Rule #38 (absolute paths).
- **Patterns shipped:** see `windows-coverage-godmode-theta-B-wmi-walker-2026-05-12-patterns.md`
- **Postmortem:** `postmortem-windows-coverage-godmode-theta-B-wmi-walker-2026-05-12.md`
