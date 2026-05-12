---
postmortem_id: postmortem-windows-coverage-godmode-iota-B-systemd-walker-2026-05-12
campaign_id: windows-coverage-godmode-iota-2026-05-12
stream_id: ι.B — Linux systemd unit-file walker
status: closed
opened: 2026-05-12
session_id: ι.B single-stream (cont. from ι.A close 992c496)
trust_level: trusted (direct-push to main per-piece, Pattern P5)
commits:
  - 8d89a3c feat(linux-systemd): LinuxSystemdUnit ORM + alembic migration (ι.B.A)
  - 32d917e feat(firmware): systemd_walk_* 5-column 202+poll status set (ι.B.B)
  - 21509bc feat(systemd): Rule #39 walker triplet for Linux systemd units (ι.B.C)
  - 62d0efa feat(findings): Linux systemd cross-stack alignment + emit (ι.B.D)
  - dbcc3b9 feat(mcp): linux_systemd MCP tool category — 6 tools (ι.B.E)
mcp_count_delta: 257 → 263 (+6 — 5 per-firmware + 1 cross-firmware aggregation)
alembic_head_delta: fb4c5d6e7f8a → aabbccddee03 (3 new revisions: aabbccddee01, aabbccddee02, aabbccddee03)
finding_source_count_delta: 52 → 57 (+5 — SECOND non-Windows source family)
rule_chain_extensions:
  - Rule #39 inner/outer/safe runner triplet — Rule-of-Fifteen → Rule-of-Sixteen
  - Rule #25 single-slice exception #2 — Rule-of-Nineteen → Rule-of-Twenty
  - Pattern P1 single-sub-agent + precedent reuse — Rule-of-Six → Rule-of-Seven
new_pattern_candidate: cross-firmware aggregation MCP tool — FIRST application for any Linux walker; ι.B shipped it from the start while ι.A deferred
tests_landed: ι.B.A 68 + ι.B.C 65 + ι.B.E 26 = 159 new tier-1 tests
duration_ms_actual: REPORTED VIA TASK NOTIFICATION (see HANDOFF)
---

# Phase ι.B — Linux systemd unit-file walker postmortem

## Summary

ι.B shipped the **SECOND LINUX walker** in wairz's portfolio across 5
per-piece direct-pushed commits. All 5 streams landed clean — zero
rollbacks, zero cross-stream sweeps, zero CI cancellations on the
Lint job. MCP tool count 257 → 263 (+6, including the FIRST-of-kind
cross-firmware aggregation tool). Alembic chained 3 new revisions.
FindingSource catalog expanded from 52 to 57 values with the second
non-Windows source family. Pattern P1 sub-agent + precedent-reuse
loop continues to compound: ι.A's freshly-laid LinuxFindingSource
framework + Rule #39 triplet + ι.A.D alignment-test stack-awareness
all transferred to ι.B with mostly per-symbol substitutions plus
walker-specific parsing logic.

**Strategic outcome:** ι.B closes the second-most-critical Persona-E
Linux gap identified by the Phase ι kick-off Scout 2 refresh (APT36 /
FIRESTARTER / Quasar QLNX). The systemd unit-file walker is the
canonical T1543.002 (systemd-service persistence) + T1547.001
(autostart) + T1053.006 (systemd-timer) surface — three top-15
MITRE ATT&CK indicators for Linux endpoints. With ι.A (journald)
giving us the post-execution audit trail and ι.B (systemd) giving
us the pre-execution persistence catalog, wairz now has matching
coverage to its Windows offering for the two most common Linux
forensic surfaces.

**Cross-firmware aggregation differentiation:** ι.B.E shipped
``lookup_systemd_unit_across_firmwares`` — the first such tool for
any Linux walker. ι.A deferred it. The tool surfaces a
supply_chain_signal field when a unit appears across ≥2 firmware
captures within a project (or globally), which is the operator's
canonical "vendor-pushed legitimate" vs "shared infection" triage
question. Future ι.C / ι.D / ι.E streams should ship cross-firmware
aggregation in the MCP layer at the same time as the per-firmware
tools, not as a follow-up.

## What Broke

**Net 3 incidents caught + fixed in-flight; 0 regressions to main.**

### W1 (caught in ι.B.C walker test, fixed pre-commit)

- **Mechanical:** initial draft of ``walk_systemd_unit_paths`` used
  ``os.path.stat.S_ISLNK(st.st_mode)`` to skip symlinks. Python's
  ``os.path`` module has no ``.stat`` attribute; the correct symbol
  is ``stat.S_ISLNK`` from the top-level ``stat`` module.
- **Root cause:** mistake from memory — wrong module path. Caught
  immediately by ``ruff check`` flagging the unused ``stat`` import
  AND a manual code review of the lstat path.
- **Fix:** added ``import stat`` and changed the call to
  ``stat.S_ISLNK(st_info.st_mode)`` (also renamed ``st`` → ``st_info``
  to avoid shadowing the new ``stat`` module name).
- **Time-to-detect:** ~30 seconds (ruff + visual review).
- **Time-to-fix:** ~30 seconds.

### W2 (caught in ι.B.C test, fixed pre-commit)

- **Mechanical:** ``test_is_obfuscated_exec_long_shell_c`` constructed
  a string that, when its body-after-``-c `` was measured, came in at
  99 characters — under the 120-char regex threshold for the
  ``_RE_LONG_SHELL_C`` pattern. The test expected the obfuscation
  detector to fire but it didn't.
- **Root cause:** my test fixture was too short. The regex
  ``(?:/bin/sh|/bin/bash|sh|bash)\s+-c\s+["']?.{120,}`` requires 120+
  chars AFTER the ``-c `` prefix; my string only had 99.
- **Fix:** expanded the test command string to 130+ characters of
  body. All 65 walker tests now pass.
- **Time-to-detect:** ~2 minutes (test fail with assertion error).
- **Time-to-fix:** ~1 minute.

### W3 (caught in ι.B.E test, fixed pre-commit)

- **Mechanical:** ``test_search_systemd_units_finds_by_unit_name``
  expected the substring-search query ``"ssh"`` to match only ONE row
  (unit_name="sshd"), but it matched TWO. The OR'd search hits
  unit_name OR description OR exec_start — and my fixture's default
  description "OpenSSH server" and exec_start "/usr/sbin/sshd -D"
  both contained "ssh".
- **Root cause:** under-isolated fixture. The default
  ``_make_systemd_unit`` carries forensic-realistic defaults that
  themselves contain the search target.
- **Fix:** updated the test to override description and exec_start
  on the "sshd" row so only its unit_name matches the search query.
- **Time-to-detect:** ~3 minutes (test fail, debug, re-run).
- **Time-to-fix:** ~1 minute.

## What Safety Systems Caught

1. **Tests** — every break above (W1 / W2 / W3) was caught by
   the test suite BEFORE the commit was authored, not after. Live
   canaries (Rule #35b) verified the value-flow contract end-to-end
   for the inner walker (suspicious_path + root_minimal_deps +
   suspicious_unit_name combo against a synthetic adversary-shaped
   .service file).

2. **Linter (ruff)** — caught W1's broken import in <1 second.
   Caught 1 import-ordering nit on the normalizer-test file (autofix
   applied).

3. **Cross-stack alignment test** — passed cleanly on first run.
   ι.A.W4's lesson about not putting inline `//` comments inside
   FINDING_SOURCE_CONFIG was respected — the rationale prose lives
   in the alembic migration and Pydantic Literal docstring only.

4. **Rule #19 evidence-first probe** — confirmed configparser is
   insufficient for systemd's deviations (duplicate keys collapse
   to LAST-write-wins instead of accumulating), but a manual
   ~80-LOC parser is the smaller-surface fix vs vendor-in. Same
   shape as ι.A's clean-room journald parser decision.

5. **Rule #11 runtime import smoke** — caught at each commit
   boundary. New ORM column shape on Firmware (Rule #20 exception)
   required ``docker compose restart backend worker`` after the
   ι.B.B migration — confirmed cols ok: True True via runtime probe
   before proceeding to ι.B.C. Same shape for ι.B.D + ι.B.E (no
   class shape change for those, but Rule #11 smoke verified
   classify_systemd_findings and create_tool_registry both import
   clean against the running container).

6. **Rule #36 no-execute test gate** — ``test_systemd_walker_no_execute``
   greps the walker source for ``subprocess.*`` /
   ``asyncio.create_subprocess_*`` / ``os.system`` /
   ``os.execvp`` / ``runpy.run_path`` / ``eval`` / ``exec``; zero
   matches. The parser treats unit-file INI text as DATA, never
   invokes systemctl / systemd-run / runuser / ExecStart= commands /
   WorkingDirectory= mounts.

7. **Rule #24 frontend tsc canary** — fired correctly with exit 2
   on the planted ``const x: number = "nope"`` test, then exit 0
   for the real ι.B.D type-check (after the LinuxFindingSource
   extension + FINDING_SOURCE_CONFIG mirror). No silent-pass risk.

8. **Rule #35a pipe-induced exit-code obfuscation** — the first
   Rule #24 canary attempt used ``rm`` AFTER the tsc invocation;
   the ``echo "canary exit=$?"`` reflected ``rm``'s exit (0), not
   tsc's. Re-ran with the exit-code capture INSIDE the same
   subshell as tsc (and ``rm`` outside) — got the correct exit=2
   for the planted bad input. Companion Rule #38 — also used
   ``git -C /home/dustin/code/wairz`` throughout to avoid CWD
   drift.

9. **CI per-piece direct-push** (Pattern P5 + Rule #41) — Lint job
   completed successfully on 4/4 prior commits (ι.B.A through
   ι.B.D) at session close; ι.B.E was queued at the moment of
   postmortem authoring.

## Patterns Promoted

### Pattern P1 single-sub-agent + precedent reuse — Rule-of-Six → Rule-of-Seven

ι.B is the SEVENTH consecutive application of Pattern P1. Each
precedent file (journald_walker.py / linux_journald_entry.py /
ea2f3a4b5c6d alembic / linux_journald MCP tools /
test_finding_source_alignment.py + the ι.A postmortem's W4 lesson
about FINDING_SOURCE_CONFIG inline comments) was reused with
mostly per-symbol substitutions plus walker-specific parsing
logic. Promotion: Rule-of-Seven.

### Rule #39 inner/outer/safe runner triplet — Rule-of-Fifteen → Rule-of-Sixteen

The sixteenth consecutive Rule #39 application; the second applied
to a non-Windows walker. The triplet shape transferred cleanly.
The configparser substitution for the parser (vs ι.A's clean-room
journald struct decode) did not change the triplet shape at all.
Promotion confirmed.

### Rule #25 single-slice exception #2 — Rule-of-Nineteen → Rule-of-Twenty

The twentieth consecutive cross-stack alignment single-slice
commit. ι.A.D was the FIRST non-Windows source family application
(Rule-of-Nineteen); ι.B.D is the SECOND. The alignment test stack-
awareness established for ι.A.D required zero changes to accept
the ι.B.D additions (5 new linux_systemd_* values picked up
automatically). Promotion confirmed.

### NEW pattern candidate — "cross-firmware aggregation is part of MCP tools at walker-stream time"

ι.A.E shipped 5 MCP tools (per-firmware only) and deferred cross-
firmware aggregation as a future enhancement. ι.B.E shipped 6 MCP
tools INCLUDING ``lookup_systemd_unit_across_firmwares`` from the
start.

The cross-firmware-aggregation shape is structurally trivial once
the per-firmware tools exist (one extra JOIN on Firmware + Project,
one extra route through the tool registry, one extra test class
in the contract suite). The benefit is asymmetric: cross-firmware
aggregation is the wairz competitive differentiator — surfacing
supply_chain_signal when the same unit appears across ≥2 firmware
captures within a project (or globally).

Future Linux walker streams (ι.C cron / ι.D auditd / future) SHOULD
ship cross-firmware aggregation in the MCP layer at the same time
as the per-firmware tools, not as a follow-up. Marker: tool name
ending in ``_across_firmwares``, scope parameter taking "project"
(default) vs "global", supply_chain_signal output field on
match_count >= 2.

Rule-of-One; await Rule-of-Two before harness-rule codification.

### NEW pattern reinforcement — "FIRST <X>" precedent commit marker

ι.A introduced explicit "FIRST LINUX" markers in commit messages
so future streams could discover the precedent file by grep. ι.B
extends with "SECOND LINUX" markers in commit messages + module
docstrings. The pattern is self-reinforcing: future ι.C will mark
"THIRD LINUX" and so on, building a grep-discoverable lineage. The
pattern was already promoted to Rule-of-One in ι.A; ι.B's
adherence reinforces but doesn't formally extend (pattern is now
self-sustaining).

## Decision Log

### D1 — OSS library choice (Rule #19 evidence-first)

**Choice:** manual ~80-LOC parser over Python's stdlib
``configparser``.

**Evidence considered:**
- ``configparser.ConfigParser(strict=False)`` handles INI syntax but
  collapses duplicate keys to LAST-write-wins, whereas systemd
  semantics ACCUMULATE duplicate keys for list-shape keys
  (After / WantedBy / etc).
- ``configparser`` doesn't handle systemd's deliberate-multivalue-
  space-separated RHS form (``WantedBy=a b``) — would treat ``a b``
  as a single string.

**Decision rationale:** a ~80-LOC manual parser is smaller-surface
than a configparser wrapper that re-implements duplicate-key
accumulation + space-separated expansion. The systemd unit-file
format is documented and stable. No new dependency.

**Tradeoff accepted:** systemd's full INI extensions (e.g.
``Environment="A=B" "C=D"`` quoted multi-value, conditional
``ConditionPathExists=`` directives that systemd evaluates at
load-time) are NOT parsed. Conditions surface as raw strings in
``unit_raw``; quoted multi-value Environment= fields aren't
expanded. Deferred to a future ι.B-supplemental if real firmware
surveys reveal high prevalence.

### D2 — Anomaly source-name set (5 sources)

**Choice:** 5 sources covering the canonical Linux systemd
persistence + execution + autostart surface:

- ``linux_systemd_suspicious_path`` (HIGH — T1543.002)
- ``linux_systemd_obfuscated_exec`` (HIGH — T1027)
- ``linux_systemd_socket_unusual_port`` (MEDIUM — T1571)
- ``linux_systemd_root_minimal_deps`` (MEDIUM — rootkit pattern)
- ``linux_systemd_enabled_outside_standard`` (MEDIUM — T1543.002
  supporting indicator)

**Considered but deferred:**
- ``linux_systemd_disabled_but_present`` — folded into the
  ``disabled_but_present`` anomaly bit but NOT promoted to a
  separate Finding source. The disabled-but-present pattern in a
  production-target Linux system overlaps heavily with legitimate
  staged-for-rollout services that admins disabled deliberately.
  Folding under suspicious_path would mis-categorize. Decision:
  keep the bit for in-row anomaly flag aggregation; do NOT emit a
  Finding row for it.
- ``linux_systemd_suspicious_unit_name`` — emit-side decision was
  to fold this into the ``suspicious_path`` Finding when both fire
  on the same row (avoids duplicate Finding rows for the same
  attacker-dropper unit). The bit is still surfaced as data in the
  row's anomaly_flags JSONB and via the MCP
  ``anomaly_bit="suspicious_unit_name"`` filter.

### D3 — Cross-firmware aggregation tool surface

**Choice:** ship ``lookup_systemd_unit_across_firmwares`` as part
of ι.B.E (not as a follow-up).

**Rationale:** see "NEW pattern candidate" above. The tool is
structurally trivial once the per-firmware tools exist; the benefit
is asymmetric (wairz competitive differentiator).

**Tradeoff accepted:** the tool does pure-string-match aggregation
(unit_name exact match + exec_substring case-insensitive partial
match). It does NOT do fuzzy/semantic match (an attacker who
renames ``sshd.service`` to ``sshd-server.service`` would evade
the aggregation). Deferred to a future ι.B-supplemental — fuzzy
matching can be layered onto the same query via PostgreSQL's
``similarity()`` operator or via Python-side Levenshtein scoring.

### D4 — anomaly_only filter on the MCP ``list_systemd_units``

**Choice:** ``anomaly_only`` filter excludes ``disabled_but_present``
from the substantive-anomaly set.

**Rationale:** same shape as ι.A.D's exclusion of ``priority_critical``
from the journald anomaly_only filter. Healthy Linux production
systems carry dozens of staged-but-disabled units (e.g.
sysstat-collect.service shipped disabled-by-default in many
distros). Including it would saturate the filter.

The 6 substantive bits (suspicious_path / suspicious_unit_name /
socket_unusual_port / root_minimal_deps /
enabled_outside_standard / obfuscated_exec) all map to genuine
adversary TTPs that warrant operator review.

``disabled_but_present`` IS still emitted as data on the row's
anomaly_flags JSONB and via the ``anomaly_bit`` filter.

### D5 — Drop-in override merge semantics

**Choice:** concatenate drop-in texts AFTER the main unit text in
lexical order, then re-parse the merged string with the manual
parser.

**Rationale:** matches systemd's documented merge order (drop-ins
override the main unit in lexical order). Last-write-wins for
scalar keys is preserved naturally; list-shape keys accumulate
naturally. The single-pass re-parse keeps the implementation
trivial vs maintaining a section-merge data structure.

**Tradeoff accepted:** drop-in files in this implementation may
not interleave correctly when they declare overlapping NEW
sections (e.g. a drop-in adding a fresh [Service] block when the
main file already had one — the parser merges them but cross-
boundary section interaction isn't tested). Real-world drop-ins
overwhelmingly add or override INDIVIDUAL keys within an existing
section, so this is a low-priority concern.

## HANDOFF stub

**State at session close:** ι.B complete. All 5 commits landed on
main. Backend container running on alembic head aabbccddee03. MCP
tool count 263. FindingSource catalog 57 values.

**Next stream:** Per the Phase ι kick-off brief, ι.C is "Linux
cron/at scheduler walker" — pairs with ι.B as "Linux scheduled-
task stack." Per Scout 1's analysis, zero new dependency (cron
files are plain text). The Rule #39 triplet shape + cross-firmware
aggregation tool shape both transfer directly from ι.B. ι.C
precedent files: read systemd_walker.py + linux_systemd_units.py
+ ι.B.A migration + ι.B.D alignment commit + ι.B.E MCP tools (for
the cross-firmware aggregation pattern).

**Rebuilds needed:** backend + worker + migrator if any ι.C
alembic migration adds new columns to Firmware (likely — same
5-column pattern). docker compose restart suffices for ORM-only
changes (per Rule #20 exception).

**Open follow-ups (none blocking ι.C):**
- D1 tradeoff: systemd Environment= quoted multi-value expansion;
  ConditionPathExists= load-time directive parsing. Defer to a
  future ι.B-supplemental if firmware corpus survey reveals high
  prevalence.
- D3 tradeoff: fuzzy/semantic match for cross-firmware aggregation
  (PostgreSQL ``similarity()`` or Levenshtein scoring). Defer
  until operator workflow surveys reveal demand.
- Drop-in merge edge case (D5 tradeoff) — section interleaving
  across drop-in files. Defer until a real firmware case exhibits
  the failure mode.

**Pattern P1 Rule-of-Seven confirmed at ι.B close.** Future ι.C
estimate (per A6 brief estimate discounting): ~20-30 min agent-
wall.

**Cross-firmware aggregation precedent established at ι.B.** Future
Linux walkers (ι.C cron, ι.D auditd, ι.E future) should ship
``lookup_<X>_across_firmwares`` from the start, mirroring ι.B.E's
shape. The Rule-of-One promotion will solidify to Rule-of-Two when
ι.C ships its own cross-firmware aggregation tool.
