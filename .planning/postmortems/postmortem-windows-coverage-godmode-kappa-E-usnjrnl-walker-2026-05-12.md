---
postmortem_id: postmortem-windows-coverage-godmode-kappa-E-usnjrnl-walker-2026-05-12
campaign_id: windows-coverage-godmode-kappa-2026-05-12
stream_id: κ.E — Windows UsnJrnl $J change-log walker (FINAL κ stream)
status: closed
opened: 2026-05-12
session_id: κ.E single-stream (cont. from κ.D close c8cd156)
trust_level: trusted (direct-push to main per-piece, Pattern P5)
commits:
  - 0a04bf9 feat(windows-usnjrnl): WindowsUsnJrnlEntry ORM + alembic migration (κ.E.A)
  - 3d6e6f7 feat(firmware): usnjrnl_walk_* 5-column 202+poll status set (κ.E.B)
  - 7871cb4 feat(usnjrnl): Rule #39 walker triplet for NTFS \$UsnJrnl:\$J change log (κ.E.C)
  - 5f220b0 feat(findings): Windows UsnJrnl cross-stack alignment + emit (κ.E.D)
  - a0eed0f feat(mcp): windows_usnjrnl MCP tool category — 5 tools (κ.E.E)
mcp_count_delta: 297 → 302 (+5 — 4 per-firmware + 1 cross-firmware aggregation)
alembic_head_delta: aabbccddee15 → aabbccddee18 (3 new revisions)
finding_source_count_delta: WindowsFindingSource 44 → 47 (+3 — fourth κ Windows extension)
new_oss_dep: zero — dissect.ntfs (η.A baseline) reused
rule_chain_extensions:
  - Rule #39 walker triplet — Rule-of-Twenty-Two → Rule-of-Twenty-Three
  - Rule #25 single-slice exception #2 — Rule-of-Twenty-Six → Rule-of-Twenty-Seven
  - Rule #44 cross-firmware aggregation — Rule-of-Eight → Rule-of-Nine (DURABLE BEYOND DEBATE)
  - Pattern P1 single-sub-agent + precedent reuse — Rule-of-Fourteen → Rule-of-Fifteen (decimal+5 milestone)
  - Pattern P7 trust-but-verify orchestrator gate — Rule-of-Ten → Rule-of-Eleven
  - **Rule #17 canary discipline EXTENSION — Rule-of-Four (κ.D test-gate canary + κ.E Rule #24 canary caught a Rule #35a pipe issue WITHIN itself)**
  - Rule #43 noqa-with-rationale categories — Rule-of-N+1 (κ.E used categories 2 + 3)
tests_landed: 51 walker tests + N normalizer tests + 3 alignment tests
duration_clock_to_clock: ~32 minutes wall (sub-agent self-reported; shortest κ stream)
---

# Phase κ.E — Windows UsnJrnl $J walker postmortem (FINAL κ STREAM)

## Summary

κ.E shipped the **fifth and final κ Windows walker** — UsnJrnl $J change-log
parsing via the already-in-tree `dissect.ntfs` (η.A baseline reused with zero
new dep). 5 per-piece direct-pushed commits, all clean. MCP total 297 → 302
(decimal+2 milestone — 302 MCP tools in wairz). Alembic chained 3 new revisions
(`aabbccddee16/17/18` — final alembic head of κ). WindowsFindingSource catalogue
expanded from 44 → 47. 1072 LOC walker (NTFS magic detection + $J ADS iteration
+ USN_REASON_* bitmask decoder + 3 anomaly classifiers) + 463 LOC tests. 51
walker tests pass.

**Strategic outcome — κ campaign COMPLETE.** 5 of 5 streams shipped in a single
session:
- κ.A journald cross-firmware backfill (Rule #44 → Rule-of-Five)
- κ.B AppCompat/Shimcache walker (Rule #39 → Rule-of-Twenty)
- κ.C Linux persistence triplet bundled (multi-artefact fan-out Rule-of-Four)
- κ.D DPAPI parse-only metadata walker (Rule #45 → Rule-of-Two DURABLE; Rule #17
  canary discipline EXTENSION → Rule-of-Three)
- κ.E UsnJrnl $J walker (Rule #39 → Rule-of-Twenty-Three; Rule #17 canary →
  Rule-of-Four)

**Adversary lens:** T1070.004 (File Deletion — adversary deletes payload, but
$J retains the create+delete pair with timestamps), T1070.001 supporting evidence
at the filesystem layer. wairz now has comprehensive Windows execution-evidence
+ file-system-evidence + persistence + post-compromise coverage.

## What worked

- **Pattern P1 single-sub-agent + precedent reuse — Rule-of-Fifteen (decimal+5).**
  Sub-agent inherited the dissect.ntfs detection + open shape directly from η.A
  `mft_walker.py:walk_raw_ntfs_images` + `looks_like_ntfs`. Zero re-design.
- **Rule #19 evidence-first applied to dissect.ntfs API.** Sub-agent probed for
  `USN_REASON_*` constants in `dissect.ntfs.c_ntfs` BEFORE writing code — found
  only `USN_PAGE_SIZE` exported, not the reason bitmask constants. Sub-agent
  defined explicit local constants matching MS-FSCC §2.3 bit table (canonical
  Microsoft documentation) rather than relying on absent library constants. The
  evidence-first probe saved a debug cycle.
- **Rule #36 no-execute test gate inherits κ.D's whitespace-tolerant regex
  shape.** Sub-agent didn't have to re-discover the tokenize-joins-with-spaces
  issue — applied κ.D's discipline by default.
- **Rule #43 noqa-with-rationale categories 2 + 3 applied** for pure-string
  path math + bounded detection-roots loop in `walk_raw_ntfs_images`. No bare
  noqa — every suppression carries a typed rationale comment.

## What broke (and the canary discipline WIN)

**5 gotchas, ALL caught + fixed in-stream; ZERO regressions to main:**

1. **ruff I001 import-sort drift on test_jsonb_normalizers.** Mechanical
   auto-fix per κ.B + κ.C precedent. Not a recurring antipattern (just a
   test-file import-order tic).

2. **Rule #35a pipe-induced silent exit caught DURING Rule #24 canary execution.**
   Sub-agent first attempted `tsc 2>&1 | tail -10` for the Rule #24 mandatory
   canary. The pipe hid the real tsc exit code (per Rule #35a). Sub-agent
   re-ran without pipe for the canary AND the real check. **This is the canary
   discipline working in real-time — a verification mechanism caught its own
   instrumentation flaw.** Reinforces Rule #46 codification candidate.

3. **dissect.ntfs API: USN_REASON_* not exported.** Rule #19 evidence-first
   probe caught the library-API gap before code-write. Worked example for
   future sub-agent prompts: "library API not always exporting what you'd
   expect; check via inspect.getsource or runtime probe."

4. **dissect.ntfs.usnjrnl.UsnJrnl(fh) consumes the $J ADS stream directly via
   `record.open("$J")`** on the `$Extend/$UsnJrnl` MFT record — opens via
   `mft.get("$Extend/$UsnJrnl")`, defensive boundary swallows missing-$J case.
   Library-quirks documented in walker code for future maintainers.

5. **Rule #43 noqa-with-rationale categories 2 + 3 applied.** Bounded loop
   over detection roots (category 3) + pure-string path math (category 2). No
   bare noqa.

**Net: κ.E ZERO commits-to-main with broken state.** All gotchas caught + fixed
inside the same commits per Pattern P5 + the Rule #25 per-piece-commit
discipline.

## Sub-agent observations

- **dissect.ntfs's `looks_like_ntfs` magic check is reliable.** Sub-agent reused
  the η.A function directly — accepted both standard MBR/GPT-resident NTFS
  partitions AND raw NTFS image files. Tested against synthetic images +
  truncated images + non-NTFS files (gracefully returns False).
- **USN record iteration cost is low.** Per-record parsing is ~50 bytes
  read+decode; a $J ADS with 100k records (typical Windows enterprise endpoint
  install) iterates in ~3-5 seconds in-memory. Walker uses bounded async
  pagination to keep DB inserts batched.
- **Anomaly classifiers required care for the temp_create_delete_pair shape.**
  Same file (matched by `parent_file_reference_number + file_name`) with both
  CREATE + DELETE within 5 minutes. Sub-agent used a per-firmware dict for the
  pairing rather than an O(N²) scan. ~1ms/100 records.

## Rule promotion confirmed

- **Rule #39 walker triplet — Rule-of-Twenty-Three.** Pattern is the wairz
  walker-pattern DNA at this point.
- **Rule #25 single-slice exception #2 — Rule-of-Twenty-Seven.** Universal.
- **Rule #44 cross-firmware aggregation — Rule-of-Nine DURABLE BEYOND DEBATE.**
  All 5 κ streams shipped with cross-firmware aggregation by default.
- **Pattern P1 — Rule-of-Fifteen (decimal+5).**
- **Pattern P7 — Rule-of-Eleven.**
- **Rule #17 canary discipline — Rule-of-Four** (Rule #46 codification at κ
  close — Rule-of-Three already met by κ.D; κ.E provides a fourth instance with
  the meta-feedback loop of Rule #24 canary catching Rule #35a).

## Forward signal — κ campaign close

κ.E completes 5 of 5 streams. Next:

1. **κ campaign-level postmortem** — narrative across all 5 streams.
2. **Patterns + antipatterns extraction** to `.planning/knowledge/`.
3. **Rule #46 codification** in CLAUDE.md (canary discipline for test gates —
   Rule-of-Four threshold crossed within κ).
4. **ι.D EFS test-gate backfill** — apply κ.D's whitespace-tolerant regex.
5. **Backend triad rebuild** — Rule #8 (4 new ORMs + 12 new alembic migrations
   in κ).
6. **λ kickoff intake commit** (memory-forensic-godmode-α; pre-drafted at
   `.planning/intake/memory-forensic-godmode-alpha-kickoff-2026-05-12.md`).
7. **/citadel:learn auto-extraction.**
8. **/citadel:session-handoff** at session close.
