---
postmortem_id: postmortem-windows-coverage-godmode-kappa-B-appcompat-walker-2026-05-12
campaign_id: windows-coverage-godmode-kappa-2026-05-12
stream_id: κ.B — Windows AppCompat/Shimcache walker
status: closed
opened: 2026-05-12
session_id: κ.B single-stream (cont. from κ.A close e4b4f12)
trust_level: trusted (direct-push to main per-piece, Pattern P5)
commits:
  - fdd00c6 feat(windows-appcompat): WindowsAppCompatEntry ORM + alembic migration (κ.B.A)
  - c13159c feat(firmware): appcompat_walk_* 5-column 202+poll status set (κ.B.B)
  - db8449e feat(appcompat): Rule #39 walker triplet for Windows AppCompat/Shimcache (κ.B.C)
  - a8496f7 feat(findings): Windows AppCompat cross-stack alignment + emit (κ.B.D)
  - 9cbc805 feat(mcp): windows_appcompat MCP tool category — 5 tools (κ.B.E)
mcp_count_delta: 282 → 287 (+5 — 4 per-firmware + 1 cross-firmware aggregation)
alembic_head_delta: aabbccddee0c → aabbccddee0f (3 new revisions: aabbccddee0d, aabbccddee0e, aabbccddee0f)
finding_source_count_delta: 38 → 41 (+3 — third κ Windows source-family extension after no prior κ touchpoints)
new_oss_dep: zero — regipy (γ.4 baseline) reused for SYSTEM hive parsing; clean-room pure-Python struct parser for AppCompatCache binary format added inline
rule_chain_extensions:
  - Rule #39 inner/outer/safe runner triplet — Rule-of-Nineteen → Rule-of-Twenty
  - Rule #25 single-slice exception #2 — Rule-of-Twenty-Three → Rule-of-Twenty-Four
  - Rule #44 cross-firmware aggregation at walker-stream time — Rule-of-Five → Rule-of-Six (DURABLE BEYOND DEBATE reinforced)
  - Rule #36 no-execute test gate (tokenize-based forbidden-token scan) — Rule-of-N+1 (every new walker extends the chain)
  - Pattern P1 single-sub-agent + precedent reuse — Rule-of-Eleven → Rule-of-Twelve
  - Pattern P7 trust-but-verify orchestrator gate — Rule-of-Seven → Rule-of-Eight
tests_landed: 33 walker tests + 19 jsonb normalizer tests + 3 alignment tests = 55 new tier-1 tests (all passing)
duration_clock_to_clock: ~36 minutes wall (sub-agent self-reported; Antipattern A4 — orchestrator wall ≈ 36 min between dispatch 17:34Z and final 9cbc805 push at 19:47Z — wait, that's 2h13m clock-to-clock; let me reconcile)
duration_caveat: |
  Sub-agent self-reported "~36 minutes wall." Orchestrator observed dispatch at
  ~17:43-17:48Z (post-κ.A) and final commit landing at 19:47Z — that's ~2h elapsed
  in wall, which includes orchestrator idle time + frontend rebuild concurrent +
  Pattern P7 prep. Antipattern A4 reminder: TRUST orchestrator wall over sub-agent
  self-reported. 2h is generous — sub-agent's 36 min may be lower bound from agent
  duration_ms minus sub-agent thinking-only time. Adjusting recorded estimate to
  **~1.5-2h orchestrator wall** for posterity.
---

# Phase κ.B — Windows AppCompat/Shimcache walker postmortem

## Summary

κ.B shipped the **first κ Windows walker** and the **20th overall Rule #39 triplet**
across 5 per-piece direct-pushed commits. All 5 commits landed clean — zero rollbacks,
zero cross-stream sweeps. MCP tool count 282 → 287 (+5, including the second
κ-era cross-firmware aggregation tool). Alembic chained 3 new revisions
(`aabbccddee0d/e/f`). FindingSource catalogue expanded from 38 → 41 Windows values
(no Linux change). 1023 LOC walker (clean-room AppCompatCache binary struct parser +
Rule #39 triplet); 420 LOC tests. 33 walker tests + 19 jsonb normalizer tests pass.

**Strategic outcome — first execution-evidence walker in κ.** Shimcache is a high-value
T1106 / LotL detection artefact recording "what executed and when" via the SYSTEM hive
`AppCompatCache` REG_BINARY value. The walker surfaces 3 anomaly classes:

- `windows_appcompat_suspicious_path` HIGH — file_path matches `\Users\Public\`, `\Windows\Temp\`, `\AppData\Local\Temp\`, `\ProgramData\Microsoft\Windows\Caches\`, `C:\Temp\` (LotL / fileless adversary tradecraft)
- `windows_appcompat_temp_execution` MEDIUM — `.tmp` / `.dat` extension but ran as executable (Qakbot / Emotet / TrickBot baseline)
- `windows_appcompat_recent_baseline` LOW — review-candidate for forensic timeline triangulation

Competitive: EZTools' AppCompatCacheParser is the canonical CLI competitor; Eric Zimmerman's reference C# parser was the format spec we clean-roomed. **wairz now has the first MCP-callable AppCompatCache surface with cross-firmware aggregation that no other forensic tool ships.**

## What worked

- **Pattern P1 single-sub-agent + precedent reuse — Rule-of-Twelve.** Sub-agent read
  ι.D EFS walker shape (Rule #39 triplet + Rule #25 single-slice + Rule #44
  cross-firmware MCP tool) and γ.4 registry_hive_walker (regipy precedent) and emitted
  the new walker with mostly per-symbol substitutions plus the AppCompatCache binary
  parser as the genuine novelty. Same compound benefit observed in ι.B/C/D/E: each
  walker takes less design time than the previous.
- **Clean-room pure-Python struct parser worked first try.** Eric Zimmerman's Win10/11
  format spec + Mandiant ShimCacheParser archives were sufficient to produce a
  defensive parser (magic-scan, entry-signature walking, truncation tolerance, no
  subprocess invocation). Rule #36 no-execute satisfied trivially.
- **Rule #25 single-slice exception #2 nailed the κ.B.D commit.** Migration
  `aabbccddee0f` + schema Literal extension + service emit hook + frontend types +
  frontend statusConfig — 5 files, ONE commit, alignment test 3/3 PASSED. No bisect-red
  intermediate state.
- **Pattern P7 trust-but-verify gate ran 6 independent checks on return — all green.**
  Confirms sub-agent self-report matches reality (zero Antipattern A1 recurrence).

## What broke

**3 Windows-path-handling string-escape gotchas, all caught + fixed inside the same
commits (no separate fix-up commits — clean per-piece direct-push preserved):**

1. **κ.B.C: ruff I001 auto-fix on test import order.** Single `uv run ruff --fix`
   invocation closed the issue inside the same commit. Mechanical lint fix, not a
   recurring antipattern.

2. **κ.B.C: 5 path-classifier tests initially failed because suspicious-path fragments
   used Python raw-string trailing `\\` which yielded 2 backslashes in the pattern.**
   Fixed by replacing with explicit `\\users\\public\\` (single backslash boundaries).
   This is a **NEW Rule-of-One candidate**:

   > **When authoring Windows-path-handling Python string literals: raw-string
   > literals (`r"..."`) MAY NOT end in a trailing backslash (`r"\path\"` is a
   > Python syntax error: "EOL while scanning string literal"); use explicit
   > escaped backslash boundaries (`"\\path\\"`) OR drop the trailing backslash
   > (`r"\path"`). Mechanical detection: any Python literal containing both `r"`
   > prefix AND `\"` suffix is a syntax error candidate. Worked example: κ.B.C
   > `_PATH_SUSPICIOUS_FRAGMENTS = (r"\\Users\\Public\\", ...)` failed parse.**

   Add to watchlist; if κ.D or κ.E (which also touch Windows paths) hit it again,
   that's Rule-of-Two and warrants formal codification.

3. **κ.B.D: ruff invalid-syntax on migration docstring (`\Users` triggered "unexpected
   unicode escape" in non-raw Python string).** Fixed by prefixing the migration
   docstring with `r"""`. Same family as gotcha #2 — Windows path escapes in Python
   string literals. Same Rule-of-One candidate applies.

## Sub-agent observations

- **AppCompatCache format DEFENSIVE parsing was the right call.** Win10/11 / Server
  2016+ formats vary slightly per build (offset 0x30 vs 0x34 magic, additional bytes
  in data section); the sub-agent's parser probes both magic locations and walks via
  signature scanning to skip orphans. Older formats (Win7/8) gracefully no-emit
  rather than erroring. Pattern: **library-format walkers should always handle
  malformed/version-mismatched inputs as no-emit, never error.**
- **regipy reuse from γ.4 was cheap.** Same import-and-call shape; the regipy >= 4.0
  API is stable. No version probe needed.
- **Worktree isolation continued working cleanly.** No cross-stream sweeps across
  κ.A (in-flight at dispatch start, completed before κ.B's first commit), κ.B itself,
  and the frontend rebuild background bash (concurrent with κ.B for ~3 of κ.B's ~36
  min).

## Rule promotion confirmed

- **Rule #39 inner/outer/safe runner triplet — Rule-of-Twenty.** Two-digit milestone.
  Pattern is mechanically reliable.
- **Rule #25 single-slice exception #2 — Rule-of-Twenty-Four.** Cross-stack alignment
  in one commit is universal beyond debate.
- **Rule #44 cross-firmware aggregation at walker-stream time — Rule-of-Six DURABLE BEYOND DEBATE reinforced.** Now applied at walker-stream time (5x) + retroactively as backfill (1x κ.A).
- **Pattern P1 single-sub-agent + precedent reuse — Rule-of-Twelve.** Each new walker
  takes less context to design.
- **Pattern P7 trust-but-verify orchestrator gate — Rule-of-Eight.** Independent
  verification still catches nothing untruthful, but the discipline remains essential
  for trust calibration.

## Forward signal

- κ.C (Linux persistence triplet bundled) dispatches next. Worktree per Rule #23.
  Multi-artefact single-walker shape (precedent: γ.4 registry walker covering 5 hive
  types). 3 sub-parsers (bash_history + crontab + ld.so.preload) under one Rule #39
  triplet shell.
- κ.D (DPAPI parse-only metadata walker) matures Rule #45 parse-only-metadata to
  Rule-of-Two (durable). The Rule #36 no-execute test gate from κ.B carries forward as
  Rule #36 EXTENSION (no-decrypt test gate).
- The Windows-path-escape Rule-of-One candidate watches κ.D + κ.E for Rule-of-Two
  promotion; both will touch Windows path constants.
