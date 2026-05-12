---
postmortem_id: postmortem-windows-coverage-godmode-kappa-C-linux-persistence-2026-05-12
campaign_id: windows-coverage-godmode-kappa-2026-05-12
stream_id: κ.C — Linux persistence triplet walker (bash_history + crontab + ld.so.preload bundled)
status: closed
opened: 2026-05-12
session_id: κ.C single-stream (cont. from κ.B close ad344b0)
trust_level: trusted (direct-push to main per-piece, Pattern P5)
commits:
  - d1ba504 feat(linux-persistence): 3 ORMs (bash_history + crontab + ld_preload) + alembic migration (κ.C.A)
  - a7581db feat(firmware): persistence_walk_* 5-column 202+poll status set (κ.C.B)
  - 4de6714 feat(persistence): Rule #39 walker triplet for Linux bash_history + crontab + ld.so.preload (κ.C.C)
  - 301dcee feat(findings): Linux persistence cross-stack alignment + emit (κ.C.D)
  - 3db20f9 feat(mcp): linux_persistence MCP tool category — 5 tools (κ.C.E)
mcp_count_delta: 287 → 292 (+5 — 4 per-firmware + 1 cross-firmware aggregation)
alembic_head_delta: aabbccddee0f → aabbccddee12 (3 new revisions: aabbccddee10, aabbccddee11, aabbccddee12)
finding_source_count_delta: LinuxFindingSource 15 → 18 (+3 — second κ extension to Linux family; first was none — Linux family is brand-new from ι)
new_oss_dep: zero — stdlib-only (text-line parsing, regex for crontab schedule_spec; no library required)
rule_chain_extensions:
  - Rule #39 inner/outer/safe runner triplet — Rule-of-Twenty → Rule-of-Twenty-One
  - Rule #25 single-slice exception #2 — Rule-of-Twenty-Four → Rule-of-Twenty-Five
  - Rule #44 cross-firmware aggregation at walker-stream time — Rule-of-Six → Rule-of-Seven (DURABLE BEYOND DEBATE)
  - Multi-artefact single-walker pattern (γ.4 registry-hive precedent) — Rule-of-Three → Rule-of-Four (γ.4 + ι.B + κ.C; the κ.C case extends to 3 sibling ORM tables rather than 1 ORM with a discriminator column — first "fan-out single walker" application)
  - Pattern P1 single-sub-agent + precedent reuse — Rule-of-Twelve → Rule-of-Thirteen
  - Pattern P7 trust-but-verify orchestrator gate — Rule-of-Eight → Rule-of-Nine
tests_landed: 46 walker tests + 39 jsonb normalizer tests + 3 alignment tests = 88 new tier-1 tests (all passing)
duration_clock_to_clock: ~38 minutes wall (sub-agent self-reported; within 45-min cap)
duration_caveat: |
  Within the cap. The 3-ORM-1-walker shape adds modest per-ORM overhead but the
  walker logic and tests are stdlib-only (no library API probing needed). Net
  duration similar to κ.B (~36 min) despite the broader scope.
---

# Phase κ.C — Linux persistence triplet walker postmortem

## Summary

κ.C shipped the **fan-out multi-artefact single-walker** shape — ONE walker
(`linux_persistence_walker.py`) emitting to THREE sibling ORM tables across 5
per-piece direct-pushed commits. All 5 commits landed clean. MCP total 287 → 292
(+5). Alembic chained 3 new revisions (`aabbccddee10/11/12`). LinuxFindingSource
catalogue expanded from 15 → 18 values (third extension to the Linux family which
launched in ι). 1097 LOC walker (3 sub-parsers + heuristics) + 597 LOC tests. 88
new tier-1 tests pass.

**Strategic outcome — fan-out walker shape codified.** γ.4 registry_hive_walker
established the "one walker, N artefact types" pattern with a single ORM discriminator
column (`hive_type ∈ {SYSTEM, SOFTWARE, NTUSER, SAM, SECURITY}`). κ.C extends it to
**3 distinct sibling ORM tables** (`linux_bash_history_entries`, `linux_cron_jobs`,
`linux_ld_preload_entries`) — different per-artefact column shapes but shared status
state-machine and walker invocation. This is the right shape when artefacts are
**conceptually grouped** (Linux persistence) but **structurally distinct** (commands
vs schedule-specs vs library-paths). Rule-of-Four for the multi-artefact pattern;
first application of the fan-out variant.

**Adversary lens:** T1059.004 (Unix Shell — bash_history clear), T1053.003 (Cron),
T1574.006 (LD_PRELOAD). Real-world cohort: APT36 Transparent Tribe (Aug 2025),
FIRESTARTER CISA/NCSC 2026, Quasar Linux QLNX (May 2026). The 3 artefacts are
adversary-grouped (a real intrusion typically touches all 3) and wairz's
cross-firmware aggregation (`lookup_linux_persistence_across_firmwares`) surfaces
the cohort signal across the firmware corpus.

## What worked

- **Pattern P1 single-sub-agent + precedent reuse — Rule-of-Thirteen.** Sub-agent
  read γ.4 + ι.B + κ.B precedents and emitted the 3-ORM-1-walker shape with mostly
  per-symbol substitutions. The novelty was the 3 sub-parsers + 9 suspicious-flag
  classifiers (`clear_marker`, `download_pattern`, `priv_esc_pattern` for
  bash_history; `temp_path_command`, `reboot_persistence`, `network_egress_pattern`
  for cron; `temp_path_library`, `unusual_extension`, `world_writable_dir` for
  ld.so.preload).
- **Pure-stdlib parsing eliminated library-version risk.** No `dissect.*` or
  `regipy` dependency for text-line parsing. The crontab parser handles both
  `/etc/crontab` (with user field) and `/var/spool/cron/<user>` (user from filename)
  per the prompt; bash_history handles non-UTF8 with `errors='replace'`. No format
  surprises.
- **Rule #36 no-execute test gate carried forward cleanly from κ.B.** Tokenize-based
  forbidden-token scan applied to the new walker; trivially passes (pure-Python
  text parsing).
- **Rule #25 single-slice exception #2 cross-stack alignment — Rule-of-Twenty-Five
  milestone.** κ.C.D bundled migration + Literal extension + service emit + frontend
  union + frontend config in ONE commit; 3/3 alignment tests pass.
- **Worktree isolation continues to hold zero-sweep.** No commits from other branches
  / orchestrator activity swept into κ.C's worktree during the ~38 min run.

## What broke

**1 gotcha caught + fixed inside the same commit (no separate fix-up commit):**

- **κ.C.C: cron temp-path regex used `\b` (word boundary) which doesn't fire at `/`
  boundary; 4 walker tests went 3 passes → 46/46 after a one-line fix replacing `\b`
  with an explicit boundary group `(^|\\s|;|\\||&)`.** Word-boundary `\b` is anchored
  at `\w` ↔ `\W` transitions in Python regex; `/` is `\W` and `t` (start of `temp`)
  is `\w`, so `\b` SHOULD fire between `/tmp` and `temp_payload`. BUT the pattern was
  matching at the START of `/tmp/`, where the preceding char in `crontab` line context
  is variable (`5 * * * * /tmp/...` — preceded by space) and `\b` semantics around
  punctuation/whitespace transitions are subtle. The explicit boundary group is
  mechanically reliable for shell-command contexts.

  This is **family-related to κ.B's Windows-path raw-string escapes** — both are
  string-pattern semantic mismatches that the sub-agent didn't catch in advance and
  required a one-line fix during dev. Rule-of-Two for the broader pattern:

  > **NEW Rule-of-Two candidate (was Rule-of-One at κ.B):** When authoring walker
  > test-fixture data + matcher patterns: string-escape AND regex-boundary semantics
  > need EXTRA scrutiny — both `r"\path\"` (Python raw-string syntax error from
  > trailing backslash) AND `\b` (word-boundary that has subtle behaviour around
  > `/` and shell-special chars) catch sub-agents off-guard despite identifying as
  > "obvious" patterns. Mitigation: when a walker matches against shell-command
  > content or filesystem paths, prefer EXPLICIT boundary character groups
  > (`(^|\\s|;|\\||&)`) over implicit word-boundary `\b`; and prefer escaped
  > double-backslash literals (`"\\Path\\"`) over raw strings ending in backslash
  > (`r"\Path\"`). Watching κ.D + κ.E for Rule-of-Three promotion to formal rule
  > codification.

## Sub-agent observations

- **Sub-parser decomposition was the right call.** 3 private functions
  (`_parse_bash_history_file`, `_parse_crontab_file`, `_parse_ld_so_preload_file`)
  inside the walker module each carry their own helpers + heuristics. Easy to test
  independently (each got its own test class in the 46-test suite). If a future
  walker needs a 4th sub-parser, it's a one-function addition without refactoring
  the orchestrator.
- **3-ORM Migration adds modest overhead.** One migration file
  (`aabbccddee10_add_linux_persistence_tables.py`) creates 3 tables, 3 indexes per
  FK, and 3 dual-default UUID columns. ~221 LOC migration. Versus 3 separate
  migrations: cleaner deploy boundary (atomic up/down for the bundle) but harder to
  bisect on individual table issues. The bundled form is right for κ.C's shape
  (atomic conceptual group) but might be wrong for unrelated tables.
- **Auto-trigger registration in `unpack.py`** — single 4-line block per the κ.B
  pattern. The bundled walker fires once per firmware regardless of which artefacts
  are present (sub-parsers gracefully no-emit when their target file doesn't exist).

## Rule promotion confirmed

- **Rule #39 inner/outer/safe triplet — Rule-of-Twenty-One.** Pattern mechanical.
- **Rule #25 single-slice exception #2 — Rule-of-Twenty-Five.** Beyond debate.
- **Rule #44 cross-firmware aggregation — Rule-of-Seven DURABLE BEYOND DEBATE.** All
  3 κ streams shipped with cross-firmware aggregation by default.
- **Multi-artefact single-walker — Rule-of-Four.** γ.4 + ι.B + κ.C span 3 distinct
  applications. The fan-out variant (3 sibling ORM tables) is now an established
  shape.
- **Pattern P1 — Rule-of-Thirteen.** Each new walker takes less context to design.
- **Pattern P7 — Rule-of-Nine.** Independent verification catches nothing untruthful
  in κ.C (sub-agent's self-report matched orchestrator's evidence exactly).

## Forward signal

- κ.D (DPAPI parse-only metadata walker) dispatches next. Worktree per Rule #23.
  Matures Rule #45 parse-only-metadata to Rule-of-Two (durable). The Rule #36
  no-execute test gate from κ.B + κ.C carries forward as Rule #36 EXTENSION
  (no-decrypt test gate per ι.D EFS precedent).
- κ.E (UsnJrnl $J walker) dispatches after κ.D. dissect.ntfs reuse (η.A precedent).
- The walker-test-fixture string-pattern Rule-of-Two candidate watches κ.D + κ.E for
  Rule-of-Three promotion.
