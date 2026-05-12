---
campaign: windows-coverage-godmode-theta-2026-05-12
stream: θ.A — BCD store walker
date: 2026-05-12
kind: patterns (success cases)
related_postmortem: postmortem-windows-coverage-godmode-theta-A-bcd-walker-2026-05-12.md
---

# Patterns — Phase θ.A BCD store walker

Success cases extracted from the single-stream θ.A dispatch. Each pattern carries Rule-of-N evidence and a mechanical re-application recipe.

---

## P1 — Single-sub-agent dispatch + precedent file-by-file reuse for next-stream walker recipes (Rule-of-Three)

**Shape:** When a Rule-of-N>=2 precedent for a Rule #39 walker triplet exists, dispatch as a single sub-agent (no Archon orchestration), read the precedent files end-to-end at design time BEFORE drafting new code, then execute against the precedent's mechanical shape.

**Evidence:**
- η.B + η.C in session 2026-05-11 (Rule-of-Two — both validated single-sub-agent dispatch per stream).
- **θ.A this session** — third application; 2.5h session-end-to-session-end vs the estimated 4-6h budget. Zero scope churn during execution because all "what shape?" decisions were deferred to "what did η.A do?".

**Recipe:**
1. Identify the closest-shaped precedent. For walkers: walk + parse + persist via Rule #39 triplet — find the last 1-2 walker streams (`git log --oneline --grep='walker triplet'` or check `.mex/patterns/inner-outer-safe-runner.md`'s "Rule-of-N applications" list).
2. Read every precedent file at design time — service module + ORM model + migration + JSONB normaliser additions + MCP tool category + test files. Approximate 30 min of reading.
3. Draft new code against the precedent's shape — variable names match, control flow matches, defensive boundaries match, error-string formats match (Rule-of-Many "principle of least surprise" for future maintenance).
4. Execute per-sub-task with Pattern P5 per-piece direct-push.

**Anti-pattern to avoid:** Drafting walker code from a fresh-design perspective when a precedent exists — re-discovers entire classes of defensive-boundary edge cases that the precedent already handled.

---

## P2 — Rule #19 evidence-first extends to library-API probing (Rule-of-Three+)

**Shape:** Before drafting consumer code against a new pure-Python parser library, run `inspect.getsource()` on the canonical use-site (upstream plugin, example, or repo demo) to extract the exact API shape needed.

**Evidence:**
- η.A walker probed `dissect.ntfs.NTFS.mft.segments()` shape before drafting.
- η.C walker probed `LnkParse3.lnk_file().get_json()` output shape.
- **θ.A this session** — probed `regipy.plugins.bcd.boot_entry_list.BootEntryListPlugin.run()` source (101 LOC) BEFORE drafting `_extract_entry_fields`. Captured the canonical BCD-element traversal pattern (`obj_key.get_subkey("Elements", raise_on_missing=False).get_subkey("%08X" % type, raise_on_missing=False).get_value("Element")`) + the ApplicationDevice byte-blob GPT GUID parsing (bytes [32:48] + [56:72] of the blob). Saved ~30 min of trial-and-error.

**Recipe:**
1. When integrating a library for the first time in a new context, identify whether the library ships an upstream plugin / example / demo exercising the same shape.
2. `inspect.getsource(<canonical_use_site>)` OR direct file Read on the plugin file.
3. Note the API shape — argument forms, return types, error modes, defensive boundaries.
4. Draft consumer code that matches the upstream shape; deviations are documented as comments.

**Companion to Rule #19:** "the DB describes truth → the library's source describes the API truth — read it before drafting consumer code." Cost: ~5 minutes per integration; saves multiples of that in trial-and-error.

---

## P3 — JSONB normaliser pairing with ORM column introduction (Rule-of-Forty-ish; durable)

**Shape:** For each new JSONB column introduced in an ORM model:
1. Define `_normalize_<table>_<column>` (reader-boundary normaliser).
2. Define `_stamp_<table>_<column>` (writer-boundary stamper).
3. Define `<TABLE>_<COLUMN>_SCHEMA_VERSION = 1` constant.
4. Ship in same commit as the ORM model + alembic migration.
5. Tier-1 tests in `test_jsonb_normalizers.py` cover canonical pass-through + defensive coercion (None / wrong-type) + idempotency.

**Evidence:**
- Rule #35c documented the discipline in CLAUDE.md (the canonical reference).
- Every Rule #39 walker triplet since γ.4 has carried matching normaliser pairs.
- **θ.A this session** — 3 normaliser pairs shipped in θ.A.A + θ.A.B for `windows_bcd_entries.custom_elements`, `windows_bcd_entries.anomaly_flags`, and `firmware.bcd_walk_result`. 22 new normaliser tests. Mechanical execution from precedent.

**Recipe:** Follow the inline shape in `jsonb_normalizers.py`. The list-shaped column convention (each entry carries its own schema_version) vs dict-shaped column convention (single top-level schema_version) is documented at top of jsonb_normalizers.py.

---

## P4 — Rule #25 single-slice exception #2 cross-stack alignment is Rule-of-Fourteen (durable beyond debate)

**Shape:** When extending the FindingSource enum allowlist (DB CHECK + Pydantic Literal + frontend union + frontend FINDING_SOURCE_CONFIG), all four surfaces ship in ONE atomic commit per Rule #25 single-slice exception #2.

**Evidence (Rule-of-Fourteen post-θ.A.D):**
- `7079b4d` (2026-05-06 base)
- `ee2abd9` β.12a (windows_authenticode + windows_dbx_revoked)
- `f70c2e1` γ.7 (windows_registry_persistence + windows_inf + windows_driver_imports)
- `20ea228` δ.8 (windows_r2r_stomp + windows_il_capa)
- `5466644` ε.1.b.4 (windows_sysmon_proc_create + windows_logon_success + windows_logon_failure)
- `da71afa` ζ.1 (windows_amcache_install)
- `a6be708` ζ.2.C (windows_prefetch_execution)
- `04a3c55` ζ.3.C (windows_srum_network_activity + windows_srum_application_runtime)
- `ac98e55` η.E (windows_powershell_script_block) — Rule-of-Nine
- `e149dcf` η.B.D (windows_scheduled_task_persistence) — Rule-of-Ten
- `fd7cd23` η.C.D (windows_lnk_abnormal_target) — Rule-of-Eleven
- `66bd8d6` η.A.D (windows_mft_ads_hidden_content + windows_mft_timestomping) — Rule-of-Twelve
- η.D.D (windows_byovd_driver) — Rule-of-Thirteen
- **`a4d5f45` θ.A.D this session (windows_bcd_suspicious_path + windows_bcd_testsigning_enabled) — Rule-of-Fourteen**

The discipline is mechanical and durable beyond debate. `test_finding_source_alignment.py` enforces pairwise agreement immediately post-commit.

**Recipe:** see `.mex/patterns/cross-stack-finding-source-alignment.md` (recommended in η postmortem, may already exist).

---

## P5 — Rule #39 inner/outer/safe runner triplet is Rule-of-Nine (durable beyond debate)

**Shape:** Every new walker for a forensic artefact ships as 3 functions in `app/services/<artefact>_walker.py`:
1. `_do_<artefact>_run(db, firmware_id) -> dict` — INNER pure-logic orchestrator. Accepts caller-owned `db`. Returns aggregate dict UNSTAMPED.
2. `run_<artefact>_walk_background(firmware_id) -> None` — OUTER state-machine wrapper. Owns Rule #33 .a transitions via `async_session_factory()`.
3. `auto_<artefact>_walk_firmware_safe(firmware_id) -> None` — UNPACK-POST-DETECTION hook. Owns own session; swallows exceptions silently; does NOT mutate status column.

**Evidence (Rule-of-Nine post-θ.A.C):**
- γ.4 → δ.5 → ε.1.b.3 → ζ.2.B → ζ.3.B → η.B.C → η.C.C → η.A.C → **θ.A.C this session**

**Recipe:** `.mex/patterns/inner-outer-safe-runner.md` (per Rule #39 promotion note).

---

## P6 — Library-shipped plugin source is the highest-fidelity reference for unfamiliar binary-format parsers (Rule-of-Two, generalising)

**Shape:** When integrating a pure-Python parser library for a binary forensic format (registry hives, prefetch, EVTX, LNK, BCD, etc.), look for an upstream plugin / example that exercises the same shape; read it before drafting your own consumer.

**Evidence:**
- regipy's `regipy/plugins/bcd/boot_entry_list.py` (101 LOC) demonstrated exactly the BCD-walk shape wairz needed.
- dissect.ntfs's example scripts demonstrated the MFT segments shape for η.A.

**Recipe:**
1. After installing the parser dep, find the upstream's `plugins/` or `examples/` directory.
2. Identify the plugin / example closest to your use case.
3. Read it end-to-end (typically <200 LOC).
4. Note the API patterns + defensive boundaries + value-coercion shapes.
5. Draft your consumer to match.

**Cost:** ~5 minutes per integration. **Benefit:** eliminates entire classes of "what shape does this API expect?" trial-and-error.

---

## P7 — Pattern P5 per-piece direct-push + Rule #41 must-complete CI is healthy and durable (Rule-of-Many)

**Shape:** Each sub-task ships as its own commit; CI Lint runs per-commit; Backend Tests cancelled-on-intermediate per `concurrency.cancel-in-progress` (the lint sibling catches per-commit; the nightly cron at 06:00 UTC catches deeper regressions).

**Evidence:** All 6 phase commits this session shipped clean — Lint green per-piece, Backend Tests green on HEAD. Zero re-work cycles.

**Recipe:** See `.mex/patterns/rule-41-must-complete-ci.md` for the full mechanism description.

---

## Cross-references

- **CLAUDE.md rules applied:** #5 (executor wrap), #11 (runtime import smoke), #16 (detection roots), #19 (evidence-first), #20 (docker cp — deferred), #21 (CLAUDE.md ↔ mex sync), #24 (tsc -b --force), #25 (per-sub-task commits + single-slice exception #2), #29 (timeout discipline), #30 (lazy-import patch targets — none needed this stream), #33 (.a state machine + .c CHECK + .d task vs arq), #35a (exit-code-before-pipe), #35b (live canaries), #35c (JSONB normalisers), #36 (no-execute — BCD store is DATA only; image_path NEVER loaded), #37 (offline-trust-anchor — N/A this stream, regipy is in-tree), #38 (absolute paths + subshell-scoped cd), #39 (inner/outer/safe triplet), #41 (must-complete CI), #43 (per-line noqa rationale).
- **Antipatterns avoided:** A6 (ruff --no-cache), A10 (alembic ID pre-validation).
- **Postmortem:** `postmortem-windows-coverage-godmode-theta-A-bcd-walker-2026-05-12.md`
- **Companion antipatterns:** `windows-coverage-godmode-theta-A-bcd-walker-2026-05-12-antipatterns.md`
