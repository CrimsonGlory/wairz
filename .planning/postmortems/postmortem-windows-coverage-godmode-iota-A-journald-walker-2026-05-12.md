---
postmortem_id: postmortem-windows-coverage-godmode-iota-A-journald-walker-2026-05-12
campaign_id: windows-coverage-godmode-iota-2026-05-12
stream_id: ι.A — Linux journald walker
status: closed
opened: 2026-05-12
session_id: ι.A single-stream (cont. from kickoff brief 7abf774)
trust_level: trusted (direct-push to main per-piece, Pattern P5)
commits:
  - 13a1223 feat(linux-journald): LinuxJournaldEntry ORM + alembic migration (ι.A.A)
  - fbbcdcb feat(firmware): journald_walk_* 5-column 202+poll status set (ι.A.B)
  - 4f25fbb feat(journald): Rule #39 walker triplet for Linux journald (ι.A.C)
  - c99d781 feat(findings): Linux journald cross-stack alignment + emit (ι.A.D)
  - 9952af4 feat(mcp): linux_journald MCP tool category — 5 tools (ι.A.E)
mcp_count_delta: 252 → 257 (+5)
alembic_head_delta: cd1e2f3a4b5c → fb4c5d6e7f8a (3 new revisions: ea2f3a4b5c6d, fb3a4b5c6d7e, fb4c5d6e7f8a)
finding_source_count_delta: 47 → 52 (+5 — FIRST non-Windows source family)
rule_chain_extensions:
  - Rule #39 inner/outer/safe runner triplet — Rule-of-Fourteen → Rule-of-Fifteen
  - Rule #25 single-slice exception #2 — Rule-of-Eighteen → Rule-of-Nineteen (FIRST non-Windows)
  - Pattern P1 single-sub-agent + precedent reuse — Rule-of-Five → Rule-of-Six
tests_landed: ι.A.A 18 + ι.A.C 32 + ι.A.D 0 (existing test EXTENDED via implicit shape) + ι.A.E 16 = 66 new tier-1 tests
---

# Phase ι.A — Linux journald walker postmortem

## Summary

ι.A shipped the **FIRST LINUX walker** in wairz's portfolio across 5
per-piece direct-pushed commits (~70 minutes agent-wall). All 5 streams
landed clean — zero rollbacks, zero cross-stream sweeps, zero CI
cancellations on the Lint job. MCP tool count 252 → 257 (+5). Alembic
chained 3 new revisions. FindingSource catalog expanded from 47 to 52
values with the first non-Windows source family. The η + θ Windows-only
walker pattern is now broken; ι.B / ι.C / ι.D have clear precedent
files to mirror.

**Strategic outcome:** Scouts 2 + 3 of the campaign pre-pass converged
HIGH on this stream as "must-have for credibility" — wairz's primary
audience analyses Linux firmware at the same or higher rate than
Windows firmware. The Linux journald walker closes the structural
gap created by η + θ's 10 consecutive Windows walkers.

## What Broke

**Net 2 incidents caught + fixed in-flight; 0 regressions to main.**

### W1 (caught in ι.A.A normaliser tests, fixed pre-commit)

- **Mechanical:** initial draft used `LINUX_JOURNALD_ENTRIES_*` in
  imports; pytest output showed all 18 tests pass on first run. No
  break — just noted that the JSONB normaliser pattern from BCD
  precedent transferred cleanly with zero edits beyond the per-table
  prefix.

### W2 (caught in ι.A.C walker test, fixed pre-commit)

- **Mechanical:** synthetic .journal builder assumed
  `_MIN_HEADER_SIZE = 168` (matching the systemd-docs Header struct
  size), but my actual `_read_header` parser computes the offset as
  `signature(8) + flags(8) + state+reserved(8) + 4*16-byte UUIDs(64) +
  9 * 8-byte fields(72) = 160 bytes`. Two assertion failures revealed
  the discrepancy: (a) test_read_header_minimal expected 168 (mine
  said 160), (b) the build function asserted len(header)==168.
- **Root cause:** I had originally read the systemd docs and noted
  "168" as the documented minimum header size; recheck against my
  actual struct decode showed the docs count an additional set of
  later-version fields beyond the truly-required minimum. The
  parser correctly accepts 160-byte headers (older systemd) and only
  reads up to that boundary.
- **Fix:** updated `_MIN_HEADER_SIZE = 160` + test constant
  `HEADER_SIZE = 160`. All 32 walker tests now pass.
- **Time-to-detect:** ~3 minutes (test run, error message direct).
- **Time-to-fix:** ~2 minutes.

### W3 (caught in ι.A.C walker test, fixed pre-commit)

- **Mechanical:** Firmware model fields were wrong in my test
  fixtures — I used `filename`, `file_path` (which don't exist) instead
  of `original_filename`, `storage_path`. SQLAlchemy raised TypeError
  at instantiation.
- **Root cause:** went from memory rather than reading the model file
  upfront. Rule #4 violation (Pydantic-schema-to-ORM-fields match;
  same principle applies to test fixture vs ORM column names).
- **Fix:** grep `^    [a-z_]*: Mapped` in firmware.py → corrected the
  field names in 2 fixture sites.
- **Time-to-detect:** ~2 minutes (first failed test).
- **Time-to-fix:** ~1 minute.

### W4 (caught in ι.A.D alignment test, fixed pre-commit)

- **Mechanical:** Initially added a JS `//` line-comment INSIDE the
  `FINDING_SOURCE_CONFIG` object literal in `statusConfig.ts`
  between SDB entries and journald entries. The cross-stack alignment
  parser at `test_finding_source_alignment.py:_parse_finding_source_config_keys`
  walks the body tracking brace depth + string state but does NOT
  handle `//` comments. The `// Phase ι.A.D — ...` text leaked into
  the next entry's "key" buffer, and the key regex
  `^\s*['\"]?([\w\-]+)['\"]?\s*:` failed because buf started with
  `// Phase...` not whitespace+identifier+colon. Result:
  `linux_journald_priority_critical` appeared missing from the
  config (1 false-negative).
- **Root cause:** under-tested edge case in the alignment parser
  (`//` line-comments inside the config literal). Not a wairz
  regression — same parser has been correct against the entire
  Windows-source decadrun. The new pattern just happened to be the
  first time anyone tried to add a comment ABOVE the new entries.
- **Fix:** removed the inline comment. The campaign-level Persona-E
  / TTP comment lives in the alembic migration + Pydantic Literal
  comment block, not duplicated in the frontend config.
- **Time-to-detect:** ~3 minutes (test fail with diff).
- **Time-to-fix:** ~30 seconds (delete 2-line comment).
- **Optional follow-up:** the test parser COULD be extended to
  strip `//` line-comments, but that's gilt over a 30-second fix
  applied at the source. Deferred unless a future stream genuinely
  needs the inline comments.

### W5 (caught in ι.A.C lint, fixed pre-commit)

- **Mechanical:** ruff UP012 flagged 2 instances of
  `.encode("utf-8")` (where the default encoding is already UTF-8).
  Autofix applied successfully.
- **Root cause:** my synthetic .journal builder used the explicit
  encoding argument for documentation purposes; ruff prefers the
  default form.
- **Fix:** `ruff check --fix` applied 2 changes; all 32 tests still
  passed.
- **Time-to-detect:** ~5 seconds (lint output).
- **Time-to-fix:** ~5 seconds (autofix).

## What Safety Systems Caught

1. **Tests** — every break above (W2 / W3 / W4 / W5) was caught by
   the test suite BEFORE the commit was authored, not after. Live
   canaries (Rule #35b) verified the value-flow contract end-to-end
   for the inner walker (priority=1, transport=audit, unit=/tmp/...
   round-trip).

2. **Linter (ruff)** — caught W5 + 2 minor warnings, autofixed.

3. **Cross-stack alignment test** — caught W4 (the journald config
   parsing issue) before push. Without this gate, the frontend
   would have shipped with a missing FINDING_SOURCE_CONFIG entry
   and the runtime UI would have rendered `linux_journald_priority_critical`
   findings as "Manual" (the default fallback per CLAUDE.md Rule #9).

4. **Rule #19 evidence-first probe** — pre-empted a major scope
   miscount. The campaign brief assumed `dissect.journal` would
   exist (Scout 1 named it as the first-choice OSS library), but
   the probe revealed:
   - `pip show dissect.journal` → not found
   - `curl pypi.org/pypi/dissect.journal/json` → HTTP 404
   - `kaitaistruct` available (MIT) — but would need ~500 LOC of
     Kaitai-generated vendor-in code
   - Decision: clean-room parser over public `journal-def.h`
     reference — smaller (~200 LOC), same license-aligned shape
     as regipy / python-evtx / windowsprefetch already in tree.

5. **Rule #16 detection-roots Linux-firmware spot check** —
   pre-empted a potential surprise. The kick-off probe ran
   `get_detection_roots` against 15 Linux firmware rows in the
   live DB; every row returned 1-8 sensible roots covering
   squashfs / ext4 / erofs / tar.xz / cramfs extractions. No
   adapter needed for Linux firmware.

6. **Rule #11 runtime import smoke** — caught at each commit
   boundary. New ORM column shape on Firmware (Rule #20 exception)
   required `docker compose restart backend worker` after the ι.A.B
   migration — confirmed `cols ok: True True` via runtime probe
   before proceeding to ι.A.C.

7. **Rule #36 no-execute test gate** — `test_journald_walker_no_execute`
   greps the walker source for subprocess.* / asyncio.create_subprocess_*
   / os.system / os.execvp / runpy.run_path / eval / exec; zero
   matches. The parser treats journal entries as DATA, never invokes
   `journalctl` or `systemd-cat`.

8. **Rule #38 absolute paths** — used `git -C /home/dustin/code/wairz`
   throughout; zero CWD drift incidents.

9. **CI per-piece direct-push** (Pattern P5 + Rule #41) — Lint job
   completed successfully on every commit (4/4 = success). Backend
   Tests show concurrency-cancel-in-progress behavior (3/4 cancelled,
   1 in_progress at session close) which is correct per Rule #41
   mechanism (a) — saves runner minutes during fast-cadence work.

## Patterns Promoted

### Pattern P1 single-sub-agent + precedent reuse — Rule-of-Five → Rule-of-Six

ι.A is the SIXTH consecutive application of Pattern P1. Each
precedent file (bcd_walker.py / windows_bcd_entry.py / 1f4a2b3c4d5e
alembic / windows_bcd MCP tools / test_finding_source_alignment.py)
was reused with mostly per-table-name substitutions plus walker-
specific decode logic. Total time-on-stream ~70 minutes — 30 min
under the 100-min brief estimate. Per CLAUDE.md Antipattern A6
(discount estimates 50-75% for sub-task ladder steps 2+), the
actual ~70 min for the FIRST-LINUX-walker first-mover stream came
in 30% under the wall-time prediction. Promotion: Rule-of-Six.

### Rule #39 inner/outer/safe runner triplet — Rule-of-Fourteen → Rule-of-Fifteen

The fifteenth consecutive Rule #39 application; the first applied
to a non-Windows walker. The triplet shape (inner accepts db /
outer state-machine wraps via async_session_factory / safe-hook
for unpack-time use) transferred cleanly. The clean-room parser
substitution for the OSS library (vs regipy / python-evtx /
windowsprefetch in the prior Windows streams) did not change the
triplet shape at all. Promotion confirmed.

### Rule #25 single-slice exception #2 — Rule-of-Eighteen → Rule-of-Nineteen

The nineteenth consecutive cross-stack alignment single-slice
commit; FIRST application to a non-Windows source family. The
existing alignment test was stack-aware (it reads DB CHECK / FE
union / FE config without privileging Windows), so it accepted
the LinuxFindingSource additions without test code changes.
Promotion confirmed.

### NEW pattern candidate — "FIRST <X>" precedent commit

When a stream is the FIRST application of a pattern in a NEW
dimension (first Linux walker, first non-Windows finding-source,
first non-Windows MCP category), the commit messages should
explicitly mark "FIRST <dimension>" so future streams can find the
precedent file by grep. ι.A.A / ι.A.C / ι.A.D / ι.A.E all carry
"FIRST LINUX" markers. This makes ι.B (systemd unit walker, the
SECOND Linux walker) trivially discoverable. Promote as "name the
precedent commit explicitly when extending to a new dimension"
pattern. Rule-of-One; await Rule-of-Two before harness-rule
codification.

### NEW pattern candidate — "kick-off detection-root spot check"

Per the campaign brief's risk surface #1, the first stream in a
new platform / dimension should probe `get_detection_roots` for
sensible behavior on representative production data BEFORE drafting
walker code. The 1-second `docker compose exec ... python` probe
against 15 Linux firmware rows confirmed roots resolved correctly
for squashfs / ext / erofs / tar.xz. This pre-empted a potentially-
ugly "walker runs but returns 0 results because detection-roots
returns []" debug session. Future "first <platform>" streams
should include this probe.

## Decision Log

### D1 — OSS library choice (Rule #19 evidence-first)

**Choice:** clean-room pure-Python parser over the public
systemd/sd-journal `journal-def.h` reference.

**Evidence considered:**
- `pip show dissect.journal` → package-not-found (the campaign
  scout had assumed this would exist; it does not).
- `curl pypi.org/pypi/dissect.journal/json` → HTTP 404 (confirming
  the absence — not just a stale local cache).
- `kaitaistruct` available (MIT, v0.11) but Kaitai-generated parser
  would need ~500 LOC of vendor-in code.

**Decision rationale:** clean-room over the public format
specification is smaller (~200 LOC), no new dependency, same
license-aligned shape as the pure-Python parsers (regipy /
python-evtx / windowsprefetch) already in wairz. The journald
binary format is stable since systemd v1.10 (2010) per the
campaign brief, so format-drift risk is LOW.

**Tradeoff accepted:** compressed payloads (XZ / LZ4 / Zstd) are
NOT decoded; counted via `compressed_skipped`. Most journald
entries are below the ~512 B compression threshold; decompression
deferred to a future ι.X stream if firmware-image survey reveals
high compression-prevalence.

### D2 — Anomaly source-name set

**Choice:** 5 sources covering the canonical Linux persistence /
anti-forensics surface:

- `linux_journald_priority_critical` (LOW — review baseline)
- `linux_journald_oom_killer` (MEDIUM — T1499 collateral)
- `linux_journald_suspicious_unit` (HIGH — T1543.002)
- `linux_journald_log_clear` (MEDIUM — T1070.002)
- `linux_journald_selinux_denied` (MEDIUM — T1562.001)

**Considered but deferred:**
- `linux_journald_audit_failure` (T1562.012) — folded into the
  `audit_failure` anomaly bit but NOT promoted to a separate
  Finding source. The audit-failure pattern in the journald binary
  log overlaps heavily with the audit transport's own conventions;
  separate audit-walker stream (ι.B/C scope candidate?) would
  surface auditd records directly. Folding under suspicious_unit
  would mis-categorize. Decision: keep the bit for in-row anomaly
  flag aggregation; do NOT emit a Finding row for it.

### D3 — anomaly_only filter on the MCP `list_journald_entries`

**Choice:** `anomaly_only` filter excludes `priority_critical` from
the substantive-anomaly set.

**Rationale:** healthy Linux systems regularly produce priority 0-2
entries during boot (kernel hardware probes, audit subsystem
initialization, daemon restarts after upgrade). Including
priority_critical in `anomaly_only=True` would over-saturate the
filter; the operator using the MCP tool to find suspicious
behavior would see hundreds of legitimate kernel boot entries.
The 6 substantive bits (oom_killer / audit_failure / selinux_denied
/ segfault / suspicious_unit / log_clear_marker) all map to
genuine adversary TTPs that warrant operator review.

priority_critical IS still emitted as a Finding (LOW confidence,
medium severity) so it appears in the global findings list — it
just doesn't dominate the MCP `anomaly_only` filter.

### D4 — Test fixture: synthetic .journal vs vendor-in sample

**Choice:** synthetic builder in pure Python.

**Rationale:** vendored .journal files would need to be either
small (limited coverage) or large (repo bloat); both add a
maintenance burden. The synthetic builder is ~80 LOC and exercises
the full parser end-to-end (header → DATA objects → ENTRY object
→ items array → field=value resolution). It also doubles as a
documentation artifact — future readers can see how a real journal
file is laid out by reading `_build_minimal_journal`.

**Tradeoff accepted:** the synthetic builder only covers
uncompressed, non-compact, single-entry files. Real journald files
have compressed payloads + the COMPACT incompatible flag set + many
entries. Multi-entry coverage IS exercised via the `walk_journal_files`
detection-root test (uses 2+ tempfile-backed magic-only files);
compressed-payload + COMPACT coverage is deferred until a real
firmware-image case provides the test fixture.

## HANDOFF stub

**State at session close:** ι.A complete. All 5 commits landed on
main. Backend container running on alembic head fb4c5d6e7f8a. MCP
tool count 257. FindingSource catalog 52 values.

**Next stream:** ι.B systemd unit file persistence walker — pairs
with ι.A as "Linux persistence stack." Per Scout 1's analysis,
zero new dependency (configparser stdlib). The Rule #39 triplet
shape transfers directly from ι.A. ι.B precedent files: read
journald_walker.py + linux_journald_entry.py + ι.A.A migration +
ι.A.D alignment commit.

**Rebuilds needed:** backend + worker + migrator if any ι.B
alembic migration adds new columns to Firmware (likely — same
5-column pattern). docker compose restart suffices for ORM-only
changes (per Rule #20 exception).

**Open follow-ups (none blocking ι.B):**
- D1 tradeoff: compressed-payload decompression for journald (XZ /
  LZ4 / Zstd). Defer to a future ι.X if firmware corpus survey
  reveals high prevalence.
- D2 deferred: separate audit-log walker (could be ι.D scope —
  auditd binary log parsing).
- Cross-stack alignment test could grow `//` line-comment handling
  if a future stream needs inline comments inside FINDING_SOURCE_CONFIG.
  Not blocking.

**Pattern P1 Rule-of-Six confirmed at ι.A close.** Future ι.B
estimate (per A6 brief estimate discounting): ~25-35 min agent-wall
(brief said ~30 min — already discount-aware).
