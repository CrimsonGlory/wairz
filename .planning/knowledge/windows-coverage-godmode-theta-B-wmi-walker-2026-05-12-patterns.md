---
campaign: windows-coverage-godmode-theta-2026-05-12
stream: θ.B — WMI persistence walker
date: 2026-05-12
kind: patterns (success cases)
related_postmortem: postmortem-windows-coverage-godmode-theta-B-wmi-walker-2026-05-12.md
---

# Patterns — Phase θ.B WMI persistence walker

Success cases extracted from the single-stream θ.B dispatch. Each pattern carries Rule-of-N evidence and a mechanical re-application recipe.

---

## P1 — Single-sub-agent dispatch + previous-stream precedent reuse is faster on second application (Rule-of-Two on speedup)

**Shape:** When a Rule-of-N>=2 precedent for a Rule #39 walker triplet exists AND the SAME campaign has already shipped one stream, the second stream's dispatch is uniformly ~40% faster — the inner/outer/safe triplet shape, JSONB normaliser pairs, MCP tool category structure, cross-stack alignment shape, and Rule #36 test-gate shape all transfer via mechanical copy-translate.

**Evidence:**
- θ.A (BCD walker): ~2.5h, 6 commits, 98 tests.
- **θ.B (WMI walker) this stream**: ~1.5h, 7 commits, 95 tests. ~40% speedup despite structurally more complex scope (vendor + cross-firmware MCP tool).

**Recipe:**
1. Read the previous-stream precedent files end-to-end at design time. For θ.B: bcd_walker.py + windows_bcd_entry.py + windows_bcd.py + the 4 BCD test files.
2. Mechanically copy-translate: variable names match, control flow matches, error-string formats match, mocking shapes match.
3. Apply per-piece Pattern P5 direct-push cadence; rely on CI Lint per-commit for gate enforcement.

**Anti-pattern to avoid:** Trying to re-derive design decisions when the previous stream made them ~30 minutes ago. The second application is the easiest one to ship correctly.

---

## P2 — Rule #36 no-execute structural test gates are durable (Rule-of-Three+)

**Shape:** When integrating a parser for attacker-controlled data (MSI custom actions, MSU install scripts, WMI consumer payloads, etc.), add a test that scrubs string literals + comments from the parser/walker source code and asserts ZERO matches for forbidden execution primitives (subprocess.*, asyncio.create_subprocess_*, os.system/execvp/spawnvp, runpy, eval/exec function calls, script-host invocations).

**Evidence:**
- α.2 MSI: `test_unpack_msi_never_executes_custom_actions` — first canonical shape.
- α.2.4 MSU: similar gate.
- α.2.6 DriverPackage: similar gate.
- **θ.B.A vendored PyWMIPersistenceFinder**: `test_vendor_no_execute_in_init_source` + `test_vendor_no_execute_across_entire_package` — 2 gates.
- **θ.B.D wmi_walker.py**: `test_wmi_no_script_execution` + `test_wmi_vendor_no_script_execution` — 2 gates (one on walker, one on the vendor for redundancy).

**Recipe:**
1. Define `_FORBIDDEN_EXEC_PATTERNS: list[str]` with all known process-spawn primitive regexes + relevant script-host invocations.
2. Define `_strip_string_literals_and_comments(source: str) -> str` that scrubs triple-quoted blocks + single-quoted strings + line comments via regex.
3. Walk every .py file under the parser/walker directory; assert each scrubbed source contains ZERO matches for every pattern.
4. The gate is structural: if a future contributor adds an execution primitive, the test fails immediately.

**Companion to Rule #36 enforcement**: the test gate is the FIRST-line defense at code-review time; the runtime CI is the SECOND-line defense; the worker container security boundary is the THIRD-line defense.

---

## P3 — Cross-firmware aggregation via fingerprint is genuinely novel surface area (Rule-of-One — promote candidate)

**Shape:** A SHA256(canonical_binding_tuple) fingerprint persisted alongside the per-record landing zone enables a cross-firmware aggregation MCP tool that's UNIQUE to wairz vs every other open-source forensic tool.

**Evidence:**
- **θ.B.B + θ.B.D + θ.B.G `windows_wmi_events.fingerprint_sha256` + `lookup_wmi_persistence` MCP tool**: SHA256(binding_id, filter_query, first_consumer_arguments) tuple. EZTools has no WMI parser; flare-wmi is unmaintained since 2018; no other tool exposes corpus-wide WMI threat hunt.

**Recipe (for future walkers):**
1. Identify the canonical "shape signature" tuple for the walked artefact (e.g. BCD: object_guid + image_path + first_element_value; LNK: target_path + arguments; Scheduled Task: action_command + trigger_type).
2. Add a `fingerprint_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)` column to the per-record ORM table.
3. Compute fingerprint at walker time via `hashlib.sha256(tuple_str.encode("utf-8")).hexdigest()`.
4. Add an MCP tool `lookup_<artefact>_<shape>(fingerprint_sha256=...)` that aggregates by fingerprint across firmware corpus.
5. Same fingerprint across firmware ⇒ same persistence shape was planted (campaign-correlation surface).

**Generalisation candidate**: BCD bootkit fingerprint (cross-firmware bootkit hunt), LNK target fingerprint (Qakbot ↔ APT29 correlation), Scheduled Task action fingerprint (APT41 / Lazarus correlation). Should generalise to all wairz walkers as a campaign-wide hunt surface.

---

## P4 — Vendored library + Rule #19 evidence-first WebFetch probe (Rule-of-One — promote candidate)

**Shape:** When vendoring an upstream library that needs API-shape adaptation, fetch the canonical upstream source via WebFetch / curl BEFORE drafting the vendor module. Extract: regex patterns / function signatures / dict shapes / license / **whether the upstream has execution primitives** (Rule #36 due diligence).

**Evidence:**
- **θ.B.A vendoring PyWMIPersistenceFinder**: WebFetched the upstream raw file, extracted exact regex patterns (event_consumer_mo, event_filter_mo, CommandLineEventConsumer fallback consumer / filter regex shapes), dict-building logic (bindings_dict / consumer_dict / filter_dict), MIT license, ZERO subprocess calls. Then drafted the vendor as a refactor preserving the upstream's regex VERBATIM while adapting the API to programmatic `find_persistence(path)`.

**Recipe:**
1. `curl -sL <upstream-raw-url>` OR WebFetch with a prompt asking for regex patterns + dict shapes + license + any execution primitives.
2. Probe the upstream's API surface: function signatures, CLI vs library entry points, side effects (stdout output, file writes, etc.).
3. Draft the vendor by REFACTORING the upstream's entry point into a callable API; preserve regex patterns / dict shapes verbatim.
4. Add LICENSE + ATTRIBUTION.md per Rule #37 vendor-attribution discipline.
5. Add Rule #36 no-execute structural test gates per Pattern P2.

**Cost**: ~5 minutes per vendoring. **Benefit**: eliminates entire classes of "what does the API actually look like" trial-and-error AND ensures the upstream's well-validated false-positive characteristics are preserved verbatim.

**Companion to Rule #19**: "the DB describes truth → the library source describes API truth → the upstream raw file describes vendor source-of-truth — fetch it before drafting fork code."

---

## P5 — Rule #25 single-slice exception #2 cross-stack alignment is Rule-of-Fifteen (durable beyond debate)

**Shape:** When extending the FindingSource enum allowlist (DB CHECK + Pydantic Literal + frontend union + frontend FINDING_SOURCE_CONFIG), all four surfaces ship in ONE atomic commit per Rule #25 single-slice exception #2.

**Evidence (Rule-of-Fifteen post-θ.B.E):**
- `7079b4d` (2026-05-06 base)
- `ee2abd9` β.12a (windows_authenticode + windows_dbx_revoked)
- `f70c2e1` γ.7 (windows_registry_persistence + windows_inf + windows_driver_imports)
- `20ea228` δ.8 (windows_r2r_stomp + windows_il_capa)
- `5466644` ε.1.b.4 (3 EVTX-related)
- `da71afa` ζ.1 (windows_amcache_install)
- `a6be708` ζ.2.C (windows_prefetch_execution)
- `04a3c55` ζ.3.C (2 SRUM-related)
- `ac98e55` η.E (windows_powershell_script_block) — Rule-of-Nine
- `e149dcf` η.B.D (windows_scheduled_task_persistence) — Rule-of-Ten
- `fd7cd23` η.C.D (windows_lnk_abnormal_target) — Rule-of-Eleven
- `66bd8d6` η.A.D (2 MFT-related) — Rule-of-Twelve
- η.D.D (windows_byovd_driver) — Rule-of-Thirteen
- `a4d5f45` θ.A.D (2 BCD-related) — Rule-of-Fourteen
- **`383ffe9` θ.B.E this stream (windows_wmi_persistence) — Rule-of-Fifteen**

The discipline is mechanical and durable beyond debate. `test_finding_source_alignment.py` enforces pairwise agreement immediately post-commit.

**Recipe:** see `.mex/patterns/cross-stack-finding-source-alignment.md` (recommended in η postmortem; may already exist).

---

## P6 — Rule #39 inner/outer/safe runner triplet is Rule-of-Ten (durable beyond debate)

**Shape:** Every new walker for a forensic artefact ships as 3 functions in `app/services/<artefact>_walker.py`:
1. `_do_<artefact>_run(db, firmware_id) -> dict` — INNER pure-logic orchestrator. Accepts caller-owned `db`. Returns aggregate dict UNSTAMPED.
2. `run_<artefact>_walk_background(firmware_id) -> None` — OUTER state-machine wrapper. Owns Rule #33 .a transitions via `async_session_factory()`.
3. `auto_<artefact>_walk_firmware_safe(firmware_id) -> None` — UNPACK-POST-DETECTION hook. Owns own session; swallows exceptions silently; does NOT mutate status column.

**Evidence (Rule-of-Ten post-θ.B.D):**
- γ.4 → δ.5 → ε.1.b.3 → ζ.2.B → ζ.3.B → η.B.C → η.C.C → η.A.C → θ.A.C → **θ.B.D this stream**

**Recipe:** `.mex/patterns/inner-outer-safe-runner.md` (per Rule #39 promotion note).

---

## P7 — Pattern P5 per-piece direct-push + Rule #41 must-complete CI is healthy and durable (Rule-of-Many)

**Shape:** Each sub-task ships as its own commit; CI Lint runs per-commit; Backend Tests cancelled-on-intermediate per `concurrency.cancel-in-progress` (the lint sibling catches per-commit; the nightly cron at 06:00 UTC catches deeper regressions).

**Evidence:** All 7 phase commits this session shipped clean — Lint green per-piece, Backend Tests green on HEAD. Zero re-work cycles.

**Recipe:** See `.mex/patterns/rule-41-must-complete-ci.md` for the full mechanism description.

---

## P8 — Rule #35a pipe-induced silent exit observed + corrected via canary (Rule-of-Two now)

**Shape:** When verifying CLI tool exit codes, `cmd 2>&1 | tail -N; ec=$?` reports `tail`'s exit (always 0), not `cmd`'s. The discipline is `cmd; ec=$?` BEFORE any pipe.

**Evidence:**
- Original Rule #35a promotion (2026-05-04 session).
- **θ.B this stream's Rule #24 canary**: first attempt `npx tsc -b --force 2>&1 | tail -10; ec=$?` printed the type error AND `ec=0` — impossible if tsc actually exited non-zero. Re-ran without pipe: `npx tsc -b --force; ec=$?` → `ec=2` as expected.

**Recipe:**
1. When capturing an exit code for a CLI tool, run it WITHOUT a pipe; if output is wanted alongside, use `cmd > /tmp/out 2>&1; ec=$?; tail -10 /tmp/out`.
2. If a pipe is unavoidable, use `set -o pipefail` explicitly OR `${PIPESTATUS[0]}` after the pipeline.

**Generalises Rule #17** (silent-CLI-exit canary) to a SECOND silent-exit mechanism: cache-hit short-circuit (Rule #17 original) AND pipe-induced exit obfuscation (Rule #35a, reinforced here).

---

## Cross-references

- **CLAUDE.md rules applied:** #5 (executor wrap), #11 (runtime import smoke), #16 (detection roots), #19 (evidence-first), #20 (docker cp — deferred), #21 (CLAUDE.md ↔ mex sync), #24 (tsc -b --force), #25 (per-sub-task commits + single-slice exception #2), #29 (timeout discipline), #30 (lazy-import patch targets — used in walker → finding_service emit hook), #33 (.a state machine + .c CHECK + .d task vs arq), #35a (exit-code-before-pipe), #35b (live canaries), #35c (JSONB normalisers), #36 (no-execute — CENTRAL DISCIPLINE FOR θ.B; structural test gates enforce it), #37 (offline-trust-anchor — N/A this stream, vendor is in-tree under third_party/), #38 (absolute paths + subshell-scoped cd), #39 (inner/outer/safe triplet — Rule-of-Ten now), #41 (must-complete CI), #43 (per-line noqa rationale).
- **Antipatterns avoided:** A6 (ruff --no-cache), A10 (alembic ID pre-validation).
- **Postmortem:** `postmortem-windows-coverage-godmode-theta-B-wmi-walker-2026-05-12.md`
- **Companion antipatterns:** `windows-coverage-godmode-theta-B-wmi-walker-2026-05-12-antipatterns.md`
