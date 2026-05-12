---
postmortem_id: postmortem-windows-coverage-godmode-iota-C-etl-walker-2026-05-12
campaign_id: windows-coverage-godmode-iota-2026-05-12
stream_id: ι.C — Windows ETL trace-log walker
status: closed
opened: 2026-05-12
session_id: ι.C single-stream (cont. from ι.B close f7b9836)
trust_level: trusted (direct-push to main per-piece, Pattern P5)
commits:
  - 0b79b5f feat(windows-etl): WindowsEtlEvent ORM + alembic migration (ι.C.A)
  - c65fd82 feat(firmware): etl_walk_* 5-column 202+poll status set (ι.C.B)
  - 6969e5e feat(etl): Rule #39 walker triplet for Windows ETL via dissect.etl (ι.C.C)
  - d6c798a feat(findings): Windows ETL cross-stack alignment + emit (ι.C.D)
  - 220b8a1 feat(mcp): windows_etl MCP tool category — 6 tools (ι.C.E)
mcp_count_delta: 263 → 269 (+6 — 5 per-firmware + 1 cross-firmware aggregation)
alembic_head_delta: aabbccddee03 → aabbccddee06 (3 new revisions: aabbccddee04, aabbccddee05, aabbccddee06)
finding_source_count_delta: 57 → 61 (+4 — FIRST ι Windows source-family extension after 2 Linux extensions)
new_oss_dep: dissect.etl>=3.14 (Fox-IT, AGPL-3.0, released 2025-11-20)
rule_chain_extensions:
  - Rule #39 inner/outer/safe runner triplet — Rule-of-Sixteen → Rule-of-Seventeen
  - Rule #25 single-slice exception #2 — Rule-of-Twenty → Rule-of-Twenty-One
  - Pattern P1 single-sub-agent + precedent reuse — Rule-of-Seven → Rule-of-Eight
  - Cross-firmware aggregation at walker-stream time — Rule-of-One (ι.B) → Rule-of-Two (ι.C)
tests_landed: ι.C.A 29 + ι.C.C 63 + ι.C.E 25 = 117 new tier-1 tests (all passing)
duration_clock_to_clock: 22 minutes wall (15:45Z probe → 16:07Z postmortem author start)
duration_caveat: |
  Clock-to-clock duration measured against `date -u` boundaries at session start
  (15:45Z dissect.etl pip install) and final commit landing (16:05Z 220b8a1 push).
  Excludes pre-session prompt-read time. Antipattern A4 reminder applied — wall
  claim only, no inflated self-reported duration.
---

# Phase ι.C — Windows ETW .etl trace-log walker postmortem

## Summary

ι.C shipped the **THIRD ι walker** and the **FIRST ι Windows-side
walker** in wairz's portfolio across 5 per-piece direct-pushed commits.
All 5 streams landed clean — zero rollbacks, zero cross-stream sweeps,
zero CI cancellations on the Lint job at session-author time. MCP
tool count 263 → 269 (+6, including the cross-firmware aggregation
tool). Alembic chained 3 new revisions. FindingSource catalog
expanded from 57 to 61 values with the FIRST ι Windows extension.
Pattern P1 sub-agent + precedent-reuse loop continues to compound:
ι.B's freshly-laid systemd walker + Rule #39 triplet + cross-firmware
aggregation precedent all transferred to ι.C with mostly per-symbol
substitutions plus walker-specific parsing logic (dissect.etl vs
configparser).

**Strategic outcome:** ι.C closes the second-most-critical Windows-
side Persona-E gap identified by the Phase ι kick-off Scout 2 refresh
(FortiGuard 2024 IR — kernel ETL retained the post-clear process tree
after Security.evtx was cleared). The ETL walker is the canonical
T1070.001 (Clear Windows Event Logs) + T1562.002 (Disable Windows
Event Logging) + T1574 (Hijack Execution Flow — providers) surface
— three top-15 MITRE ATT&CK indicators for Windows endpoints. With
existing EVTX walker (ε.1.b) giving us the structured event log, the
ETL walker now layers the binary trace-log surface on top — wairz
now matches Microsoft DART team's documented investigation pattern
of always checking ETL when EVTX has been tampered.

**Cross-firmware aggregation differentiation reinforced:** ι.C.E
shipped `lookup_etl_provider_across_firmwares` from the start (NOT
deferred) — the SECOND application of the cross-firmware aggregation
pattern at walker-stream time. ι.B.E shipped
`lookup_systemd_unit_across_firmwares` (Rule-of-One); ι.C.E ships its
ETL counterpart (Rule-of-Two). The pattern is now durable — future
ι.D / ι.E / future walker streams should ship a cross-firmware
aggregation tool with the standard shape (name ending
`_across_firmwares`, scope=project|global, supply_chain_signal on
match_count >= 2).

**Rule #19 evidence-first OSS-library decision**: dissect.etl 3.14
(Fox-IT, AGPL-3.0, released 2025-11-20) was a DRAMATIC reversal from
the θ campaign's clean-room-parser default. The probe ran the
package's installer, then `inspect.getsource` on the ETL / Buffer /
EventRecord / EventHeader / LogfileHeader classes. The API was
perfectly aligned with the walker pattern:

- `ETL(fh)` consumes a binary file-handle.
- `iter(etl)` yields `EventRecord` instances directly.
- `record.header` exposes `provider_id` (UUID), `timestamp` (datetime),
  `process_id`, `thread_id`, `opcode`, `version` + descriptor fields.
- `record.event` lazily resolves manifest-bound payloads via
  `event_values()` when a manifest matches.
- `etl.logfile_header.LoggerName` exposes the session name.

A clean-room ETL parser would have been ~3K LOC (XPRESS-compressed
buffers + variable header types + per-provider manifest resolution).
dissect.etl is the right tool — and the dependency footprint is
already aligned (dissect.cstruct + dissect.util transit deps in tree
from η.A.A dissect.ntfs).

## What Broke

**Net 2 incidents caught + fixed in-flight; 0 regressions to main.**

### W1 (caught in ι.C.C walker test, fixed pre-commit)

- **Mechanical:** `test_datetime_to_filetime_invalid_returns_zero`
  passed `"not a datetime"` to `datetime_to_filetime()`; the except
  clause caught `(TypeError, ValueError, OverflowError)` but NOT
  `AttributeError` (which fires on `dt.tzinfo` access).
- **Root cause:** missed exception in the defensive coercion
  catch-all.
- **Fix:** added `AttributeError` to the except tuple. All 63 walker
  tests now pass.
- **Time-to-detect:** ~30 seconds (test fail with clear traceback).
- **Time-to-fix:** ~15 seconds (one-character edit).

### W2 (caught in ι.C.E MCP-tools test, fixed pre-commit)

- **Mechanical:** `_handle_search_etl_events` used
  `cast(WindowsEtlEvent.payload, JSONB).cast(str).ilike(pattern)` —
  the double cast (`JSONB → str`) produced a SQLAlchemy TypeError at
  comparator-attribute lookup time (the inner cast returned an
  expression with a non-`TypeEngine` `.type` attribute).
- **Root cause:** wrong cast composition. The PostgreSQL pattern is
  to cast directly to `Text` (sqlalchemy `Text` type) for an `::text`
  conversion that supports `ilike()`.
- **Fix:** changed to `cast(WindowsEtlEvent.payload, Text).ilike(...)`
  with a single cast. All 25 MCP tool tests now pass.
- **Time-to-detect:** ~10 seconds (test fail with verbose SQLA
  traceback).
- **Time-to-fix:** ~30 seconds (two-line edit + import swap).

### W3 (caught in ι.C.E MCP-tools test, fixed pre-commit)

- **Mechanical:** `test_trigger_etl_walk_schedules` used
  `monkeypatch.setattr("asyncio.create_task", _fake_create_task)`
  which replaces the global `asyncio.create_task` — but the windows_etl
  handler imports `asyncio` at the top, then references
  `asyncio.create_task` at call-site. The monkeypatch fired
  successfully but `_fake_create_task` returned `None`, which
  downstream `await`-able code can't accept.
- **Root cause:** insufficient mock — needs to return a real Task-
  shaped object, AND `monkeypatch.setattr("asyncio.create_task", ...)`
  also needed to target the module-scoped reference for the handler.
- **Fix:** switched to `unittest.mock.patch(
  "app.ai.tools.windows_etl.asyncio.create_task", side_effect=_fake_create_task)`
  that closes the coro AND returns a real `asyncio.ensure_future(_noop())`
  task object. Also removed the parallel conflict-test's monkeypatch
  (it returned early before scheduling, so no mock was needed).
- **Time-to-detect:** ~20 seconds (test fail with asyncio.create_task
  TypeError).
- **Time-to-fix:** ~1 minute (rewrite + test re-run).

## What Safety Systems Caught

1. **Tests** — every break above (W1 / W2 / W3) was caught by the
   test suite BEFORE the commit was authored, not after. Live canaries
   (Rule #35b) verified the value-flow contract end-to-end for the
   inner walker (mocked dissect.etl parser feeding synthetic events
   through the per-row builder).

2. **Rule #19 evidence-first probe** — confirmed dissect.etl v3.14
   has the API shape needed BEFORE writing walker code. `inspect.getsource`
   on ETL / Buffer / EventRecord / EventHeader / LogfileHeader produced
   the canonical reference for the per-event field mapping. Took
   ~2 minutes; saved 3+ hours of "wait, what does .descriptor expose?"
   speculation.

3. **Rule #11 runtime import smoke** — caught at each commit boundary.
   After ι.C.A, verified ORM imports clean against the host-side venv;
   after ι.C.D, verified `classify_etl_findings + emit_etl_findings_
   from_walk` import clean. No class-shape Rule #20 issues encountered
   (additive-only changes to firmware schema).

4. **Rule #36 no-execute test gate** — `test_etl_walker_no_execute`
   greps the walker source for `subprocess.* / asyncio.create_subprocess_*
   / os.system / os.execvp / runpy.run_path / eval / exec`; zero
   matches. The parser treats .etl binary records as DATA, never
   starts a kernel trace session, registers an ETW logger, invokes
   any process referenced in event payloads, or loads any embedded
   provider manifest as code.

5. **Rule #24 frontend tsc canary** — fired correctly with exit 2 on
   the planted `const x: number = "nope"` test, then exit 0 for the
   real ι.C.D type-check (after the WindowsFindingSource extension +
   FINDING_SOURCE_CONFIG mirror).

6. **Rule #35a pipe-induced exit-code obfuscation** — applied the
   ι.B postmortem's lesson to the Rule #24 canary: captured the exit
   code INSIDE the same subshell as tsc, not after a `rm` cleanup.
   Companion Rule #38 — used `git -C /home/dustin/code/wairz`
   throughout to avoid CWD drift.

7. **Cross-stack alignment test** — passed cleanly on first run for
   ι.C.D. The test stack-awareness established for ι.A.D and ι.B.D
   accepted the 4 new windows_etl_* values automatically.

8. **CI per-piece direct-push** (Pattern P5 + Rule #41) — 5 commits
   pushed directly to main per-piece; Lint job invoked per commit
   (queued/running at postmortem-author time; not blocking for the
   author).

## Patterns Promoted

### Pattern P1 single-sub-agent + precedent reuse — Rule-of-Seven → Rule-of-Eight

ι.C is the EIGHTH consecutive application of Pattern P1. Each
precedent file (systemd_walker.py / linux_systemd_units.py /
aabbccddee01 alembic / linux_systemd MCP tools /
test_finding_source_alignment.py + the ι.B postmortem's lessons
about FINDING_SOURCE_CONFIG icons + cross-firmware aggregation shape)
was reused with mostly per-symbol substitutions plus walker-specific
parsing logic. Promotion: **Rule-of-Eight**.

### Rule #39 inner/outer/safe runner triplet — Rule-of-Sixteen → Rule-of-Seventeen

The seventeenth consecutive Rule #39 application; the third applied
to a non-Windows-or-Linux-walker (ETL is Windows-side, but the
triplet shape transferred cleanly from ι.B's Linux systemd
precedent). The dissect.etl-based parsing inside the inner orchestrator
(vs ι.B's configparser substitution) did not change the triplet shape
at all. Promotion confirmed.

### Rule #25 single-slice exception #2 — Rule-of-Twenty → Rule-of-Twenty-One

The twenty-first consecutive cross-stack alignment single-slice
commit. ι.A.D was Rule-of-Nineteen (FIRST non-Windows); ι.B.D was
Rule-of-Twenty (SECOND non-Windows). ι.C.D is Rule-of-Twenty-One
(FIRST ι Windows extension). The alignment test stack-awareness
established for ι.A.D + ι.B.D required zero changes to accept the
ι.C.D additions (4 new windows_etl_* values picked up automatically).
Promotion confirmed.

### Cross-firmware aggregation at walker-stream time — Rule-of-One → Rule-of-Two

**Strong-evidence promotion**. ι.B.E shipped
`lookup_systemd_unit_across_firmwares` from the start (precedent
Rule-of-One). ι.C.E ships `lookup_etl_provider_across_firmwares`
from the start (now Rule-of-Two). The pattern shape is now durable:

- Tool name pattern: `lookup_<artefact>_<across_firmwares>`
- Required parameters: the per-firmware natural-key (`unit_name` /
  `provider_guid`) + optional refinement parameter (`exec_substring`
  / `event_id`)
- `scope` parameter: `"project"` (default) | `"global"`
- Output schema: per-firmware match metadata + `supply_chain_signal`
  field on `match_count >= 2`
- Implementation: SQL JOIN against the per-firmware table + Firmware
  + Project, grouped by firmware, ordered by created_at, limited

Future walker streams (ι.D / ι.E / future) MUST ship the cross-
firmware aggregation tool at walker-stream time, not as a follow-up.
The marginal cost is ~50 LOC of MCP-tool handler code + ~5 tests;
the benefit is the wairz competitive differentiator surface.

### Scout 3 audience-concern hypothesis — NOT TESTED THIS STREAM

The ι kickoff Scout 3 (audience concerns) framed ETL as
high-Persona-E-value-but-low-real-firmware-prevalence. A post-stream
SQL `SELECT COUNT(*) FROM windows_etl_events;` aggregated against
deployed firmware would test the Scout 3 vs Scout 2 framing. Not
executed during this stream (host-side DB not actively populated
with Windows firmware captures); deferred to operator-driven
production deployment.

## Decision Log

### D1 — OSS library choice (Rule #19 evidence-first)

**Choice:** dissect.etl 3.14 over clean-room parser.

**Evidence considered:**
- `dissect.etl` v3.14 (Fox-IT, AGPL-3.0, released 2025-11-20) on PyPI;
  installs cleanly with no native build deps; pulls dissect.cstruct
  + dissect.util as transitive AGPL deps (already in tree from
  dissect.ntfs η.A.A).
- API confirmed via `inspect.getsource` (ETL + Buffer + EventRecord +
  EventHeader + LogfileHeader) — perfectly aligned with the wairz
  walker pattern.
- Clean-room ETL parser would be ~3K LOC of XPRESS decompression +
  variable-header types + per-provider manifest resolution; vendor-
  manifest catalog distribution would be a separate problem.

**Decision rationale:** dissect.etl is the right tool. The Fox-IT
dissect family is the canonical Python-side DFIR parser suite; the
v3.14 release (2025-11-20) confirms active maintenance; AGPL-3.0
matches wairz's license. No new dependency footprint pressure
(pulls deps already in tree).

**Tradeoff accepted:** dissect.etl's manifest catalog is shipped
with the package and only includes a subset of Microsoft providers.
Events from providers without a shipped manifest get raw-bytes b64
preview in the payload column rather than decoded field key/value
pairs. This is acceptable for the primary use case (anomaly
detection on header-level signals: provider_guid /
etl_session_name / event_opcode) but operator may want richer
payload decoding for HIGH-confidence Findings. Deferred to a future
ι.C-supplemental if operator workflows reveal demand.

**REVERSAL FROM θ:** Phase θ's clean-room-parser default (used for
BCD / SDB) was correct for those formats (small binary structures,
no compression). The θ pattern does NOT generalize to all binary
Windows artefacts — dissect.etl's depth + Microsoft's ETL format
complexity made the dependency the right choice. Rule #19 evidence-
first applies; the answer is "measure the actual library API + the
parser scope before committing."

### D2 — Anomaly source-name set (4 sources)

**Choice:** 4 sources covering the canonical Windows ETL post-
compromise surface:

- `windows_etl_kernel_proc_after_clear` (HIGH — T1070.001 — FortiGuard
  2024 IR canonical tradecraft)
- `windows_etl_provider_disabled` (HIGH — T1562.002)
- `windows_etl_non_microsoft_in_diagtrack` (HIGH — T1574; the
  Diagtrack session is Microsoft-only by design)
- `windows_etl_unusual_provider` (MEDIUM — T1574 candidate; baseline
  review)

**Considered but deferred:**
- `windows_etl_payload_lolbin_match` — pattern-match event payloads
  for LOLBin indicators (powershell.exe / mshta.exe / certutil.exe).
  Deferred because payload decoding requires manifest match; many
  events have no manifest. Would require either expanding the
  manifest catalog OR Python-side keyword search on the raw payload.
- `windows_etl_session_modification` — flag events from
  Trace-Control providers that aren't `provider_disabled` (e.g.
  session resize, buffer-flush events). Deferred because the false-
  positive rate on legitimate WMI Autologger reconfiguration is
  high.

### D3 — `non_microsoft_in_diagtrack` subsumes `unusual_provider`

**Choice:** when both `unusual_provider` AND `non_microsoft_in_diagtrack`
fire on the same event, only emit `non_microsoft_in_diagtrack` (HIGH).
Skip the `unusual_provider` (MEDIUM) emission.

**Rationale:** The Diagtrack-specific signal is strictly stronger
than the general unusual_provider signal; emitting both produces
duplicate Findings on the same row that triage workflow has to
de-duplicate manually. Same shape as ι.B.D's suspicious_unit_name
fold into suspicious_path.

**Tradeoff accepted:** operator who wants to know about the
`unusual_provider` bit independently has to query the row's
`anomaly_flags` JSONB directly via the MCP `list_etl_events`
`anomaly_bit="unusual_provider"` filter. The Finding row only
surfaces the strongest signal.

### D4 — Cross-firmware aggregation tool surface

**Choice:** ship `lookup_etl_provider_across_firmwares` as part of
ι.C.E (not as a follow-up). SECOND application of the ι.B pattern.

**Rationale:** see "Patterns Promoted" above. The tool is
structurally trivial once the per-firmware tools exist; the benefit
is asymmetric (wairz competitive differentiator). Rule-of-Two now
locked in for this pattern.

**Tradeoff accepted:** match aggregation is exact GUID match +
optional event_id match. Fuzzy/semantic match (e.g. matching ETW
provider GUIDs that differ in their last 4 hex digits suggesting
a vendor-rolled GUID set) deferred to a future ι.C-supplemental.

### D5 — `kernel_proc_after_evtx_clear` correlation source

**Choice:** correlate the kernel_process anomaly bit against
`firmware.evtx_walk_result.log_clear_count > 0`.

**Rationale:** if the firmware has been EVTX-walked AND the walk
found Security.evtx clear records, kernel-process events in ETL are
the canonical FortiGuard 2024 IR signal. The correlation is computed
once at walker-start time (reading firmware.evtx_walk_result) and
applied to every event in the firmware's .etl files.

**Tradeoff accepted:**
- The correlation requires the EVTX walker to have run BEFORE the
  ETL walker. If the operator runs the ETL walker first and EVTX
  walker second, the kernel_proc_after_evtx_clear bit will be False
  on the first run; operator must re-trigger the ETL walker after
  the EVTX walker completes.
- The correlation uses ε.1.b's EVTX walker result aggregate — if
  the EVTX walker reports `log_clear_count` of 0 because the firmware
  has no Security.evtx OR no Security.evtx clear marker, the
  kernel_proc_after_evtx_clear bit stays False even if the operator
  has external evidence of EVTX tampering. Operator workflow: if
  external evidence suggests EVTX tampering, manually set firmware.
  evtx_walk_result.log_clear_count = 1 via a future MCP tool (NOT
  in this stream).

## HANDOFF stub

**State at session close:** ι.C complete. All 5 commits landed on
main. Backend container running on alembic head aabbccddee06 (after
operator-driven `docker compose up -d --build backend worker
migrator`). MCP tool count 269. FindingSource catalog 61 values.

**Next stream:** Per the Phase ι kick-off brief, ι.D / ι.E are
candidate Windows-or-Linux-side walkers depending on operator
priorities. The Rule #39 triplet shape + cross-firmware aggregation
tool shape both transfer directly from ι.C. Precedent files for
the next stream: read etl_walker.py + windows_etl_events.py +
aabbccddee04 migration + ι.C.D alignment commit + ι.C.E MCP tools
(for the cross-firmware aggregation pattern Rule-of-Two).

**Rebuilds needed:** backend + worker + migrator after `git pull`
because ι.C adds:
- A new ORM table (windows_etl_events) — Rule #20 exception applies
  if class-shape changes; here it's additive so `docker compose
  restart backend` would suffice.
- A new firmware column set (etl_walk_*) — ditto, additive.
- A new dependency (dissect.etl) in pyproject.toml — REQUIRES
  `--build` because the Python package install layer must rebuild.
- Mandatory `--build backend worker migrator` per CLAUDE.md Rule #8.

**Open follow-ups (none blocking ι.D / ι.E):**
- D1 tradeoff: dissect.etl manifest catalog is incomplete. Real-
  firmware survey would tell us whether the missing-manifest events
  are predominantly value-laden (e.g. third-party EDR events with
  payload fields we'd want decoded) or noise-laden (e.g. internal
  Microsoft system events we don't care about). Defer.
- D2 tradeoff: 2 additional source candidates (LOLBin payload match;
  session_modification non-disable). Defer until operator workflow
  reveals demand.
- D3 fold tradeoff: `unusual_provider` fold into
  `non_microsoft_in_diagtrack`. Defer.
- D4 fuzzy-match: defer until operator workflow surveys reveal demand.
- D5 tradeoff: EVTX-walker-first ordering requirement. Document in
  operator-facing UI.

**Pattern P1 Rule-of-Eight confirmed at ι.C close.** Future ι.D
estimate (per A6 brief estimate discounting): ~22-30 min agent-wall
based on ι.B's ~25 min and ι.C's ~22 min.

**Cross-firmware aggregation Rule-of-Two confirmed at ι.C close.**
Future Linux + Windows walkers MUST ship `lookup_<X>_across_firmwares`
from the start, mirroring ι.B.E + ι.C.E shape.

**Rule #19 evidence-first OSS-library reversal documented.** dissect.
etl is the new precedent for Windows binary trace-log walkers.
Clean-room parsing remains the right choice for small / well-
documented Windows artefacts (BCD, SDB); for complex ETL-class
formats, the dissect family is the answer. Future walkers should
probe BOTH paths before committing.
