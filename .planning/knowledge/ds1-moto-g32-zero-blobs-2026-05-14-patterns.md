# Patterns: DS1 Moto-G32 zero-blobs systematic-debugging session

> Extracted: 2026-05-14
> Campaign: ad-hoc systematic-debugging session (user prompt `/citadel:systematic-debugging projects/8413d661-...`)
> Postmortem: .planning/postmortems/postmortem-ds1-moto-g32-zero-blobs-2026-05-14.md

## Successful Patterns

### 1. systematic-debugging Phase 1-3 prevented shotgun fixing on a 3-bug cascade

- **Description:** The skill prescribed observe → hypothesize → verify → fix BEFORE writing code. For this session, that meant: query DB for project state → inspect detection_audit JSONB → trace `_find_unblob_extraction_top` step-by-step on the real path → confirm `_find_extraction_container` returns `rfnv` unchanged → confirm the climb stops on first non-_extract pair → prototype-verify the proposed fix returns the right top → THEN write code. Avoided the easy guess "maybe re-rebuild fixes it" (the running container WAS already on the post-c68b3b6 code; the bug was in the fix itself, not in container staleness).
- **Evidence:** Phase 1 DB queries, Phase 2 helper-by-helper trace via `_find_unblob_extraction_top` + `_walk_for_additional_roots` direct invocation, Phase 3 prototype-verify of the proposed fix BEFORE editing the source file. Each phase narrowed the hypothesis space measurably.
- **Applies when:** Any user-reported bug that the obvious-fix (rerun extraction, rebuild containers) doesn't resolve. Skip the protocol when the bug is a single one-line typo with an obvious patch.

### 2. Path-string fallback as a TEXT layer on top of filesystem traversal

- **Description:** When walking a directory tree by parent climbing gets blocked by non-matching dir names, switch to STRING-level analysis: split the path by os.sep, scan components for the desired marker, validate the found prefix with `os.path.isdir()` + realpath-guard, return. This is fundamentally different from filesystem walking — it operates on the string shape only — and reaches segments the climb cannot.
- **Evidence:** `_find_unblob_extraction_top` fallback (commit c0c107e). Climb works for normal unblob output; path-string fallback handles the Moto radio.img/efs deep-nest case where 4 non-_extract dirs block the climb.
- **Applies when:** A tree-walk traversal has STRUCTURAL knowledge about the path string (in this case: "outermost _extract segment after the per-firmware `extracted/` marker") that the localized parent-climb logic can't express. The fallback should ALWAYS be guarded by realpath checks to avoid sandbox escapes.

### 3. Bulk INSERT failure exposed a downstream-only bug

- **Description:** The NUL-byte issue in PE/ELF metadata had EXISTED in the codebase for months but never surfaced because the detection-roots resolver never previously fed PE/ELF blobs through the detector. The first fix (path-string fallback) was the precondition that exposed the second bug. Both fixes were necessary; either alone wouldn't have shipped a working DS1 firmware.
- **Evidence:** Detection roots fix surfaced 313 candidates; bulk INSERT then failed with `0x00 invalid byte sequence`. Repro chain: fix #1 → 56 detection roots → 313 candidates → INSERT → asyncpg rejection → "still 0 blobs in DB".
- **Applies when:** Debugging "feature X produces nothing" bugs. After each fix, RE-VERIFY end-to-end (not just the proximate symptom). If the count is still wrong, surface the new error and root-cause-investigate again. The systematic-debugging skill's "fix the first bug, then re-verify" discipline captured this.

### 4. Parallel Citadel multi-persona review found 3 distinct follow-up bugs

- **Description:** After shipping the 2 critical-path fixes, dispatched 3 parallel reviewers (arch-reviewer + forensic-domain expert + corpus-auditor). Each surfaced a distinct issue the others would have missed:
  - arch-reviewer: realpath-guard gap + LAST-marker doc gap
  - forensic-domain: BTFM.bin Broadcom miscategorization (18 blobs)
  - corpus-auditor: 4 OTHER firmwares stuck in same shape + missing operator workflow
- **Evidence:** Phase A1/A2/A3 agent outputs (2026-05-14, ~5 min total wall-clock for all 3 parallel). Each finding mapped 1:1 to a Phase C commit.
- **Applies when:** Any non-trivial bug fix touching security-sensitive surface (sandbox, classifier, persistence). Single-persona review systematically misses the others' axis.

### 5. Detection_audit JSONB enabled SQL-queryable corpus sweep

- **Description:** A previously-instrumented `firmware.device_metadata.detection_audit` JSONB column (orphan_ratio + blobs_detected + files_on_disk + walk_source + last_detection_at) made the corpus sweep a single SQL query: `WHERE (detection_audit->>'orphan_ratio')::float >= 0.95 AND (detection_audit->>'blobs_detected')::int = 0`. Without this instrumentation, operators would discover broken firmwares one-at-a-time via UI complaints.
- **Evidence:** Phase A3 audit-query returned 5 firmwares (DS1 + 4 others) in under 100ms. Phase B re-detection on those 5 recovered 2 (DS1 to 331 blobs, GS724Tv6 to 2 blobs) and confirmed 3 are legitimate "no firmware blobs in scope" outcomes.
- **Applies when:** Designing any detection / classification / walker pipeline. Always include a diagnostic JSONB shape that future corpus-sweeps can query directly.

### 6. Existing `backfill_detection.py` script supported targeted CLI extension

- **Description:** The script already had `--firmware-id` / `--limit` / `--dry-run` flags. Adding `--only-broken` was 30 lines of JSONB-filter expression. Avoided writing a separate one-off script; built on top of the pre-shipping operator-tooling instead.
- **Evidence:** Commit bcdfb8c — added one flag + one query branch. Operator can now run `backfill_detection.py --only-broken --dry-run` to see stuck firmwares, then `--only-broken` (no dry-run) to recover them.
- **Applies when:** Adding operator-tooling for a new diagnostic class. Check existing scripts in `backend/scripts/` first — often a 30-line extension beats a 200-line new script.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Apply realpath-guard ONLY to fallback, not to climb | Climb traverses through legitimate-`_extract` dirs by design; realpath-guard there would over-fire on unblob's normal output. Fallback is a heuristic so additional safety is warranted there. Companion: `_walk_for_additional_roots` uses `followlinks=False` so descendant-symlink data exposure is bounded. | Realpath gap closed for the fallback; climb path unaffected; existing 4 firmware_paths tests pass. |
| `cleaned or None` collapse in `_sanitize_text` | Drop empty-after-strip values to NULL — semantically "after sanitization, this column has no signal". Operator querying `WHERE cert_subject IS NULL` correctly captures both "parser found no subject" and "parser returned all-NUL noise". | Verified all 11 sanitization edge cases via the 28-test parametrized suite. |
| Add 3 Broadcom YAML patterns covering BTFM.bin AND its 18 sub-components | The raw BTFM.bin only exists for non-unblob extraction paths; unblob fully decomposes the archive. Both pattern shapes ship together so the classifier hits regardless of unblob's behavior. | DS1 firmware: 18 Broadcom Bluetooth blobs correctly categorized; total blob count 313 → 331. |
| Postmortem corpus sweep PRE-postmortem, not after | The forensic + corpus review findings drove additional Phase C commits, so the postmortem should reflect the final state (5 commits + 39 tests + 4 firmwares recovered), not the initial 2-commit state. Avoids amending the postmortem after each follow-up. | Single comprehensive postmortem; no document churn. |

## Numbers worth tracking

| Metric | Value |
|--------|-------|
| Sessions on this campaign | 1 |
| Total commits | 5 |
| Files modified | 7 |
| Lines added | ~750 |
| New tests | 39 |
| DS1 firmware blob count delta | 0 → 313 → 331 (the 313→331 jump is +18 Broadcom Bluetooth after the forensic fix) |
| Corpus firmwares discovered in broken state | 5 |
| Corpus firmwares automatically recovered | 2 |
| Reviewer findings → Rule #25 follow-up commits | 3 (1:1 mapping per reviewer's MED/HIGH finding) |
| Reviewer wall-clock | ~5 min total (parallel) |

## Promotion candidates for CLAUDE.md

The following patterns are CANDIDATES for promotion if they recur (Rule-of-Two):

1. **"Path-string structural fallback for tree-walk traversal blocked by name pattern"** — pattern #2 above. Generalizable beyond firmware_paths: any climb-based directory resolver could adopt the same fallback shape when path-shape knowledge exceeds local-name-pattern knowledge. Rule-of-One status. Promote when a second non-firmware_paths consumer adopts the shape.

2. **"NUL-byte sanitization at the bulk-INSERT boundary for PE/ELF metadata"** — pattern #3 above. PostgreSQL TEXT/VARCHAR/JSONB reject `0x00` literals; ELF parsers commonly return them. Other consumers of LIEF / pyelftools / pefile metadata (windows_pe_signature, windows_authenticode walkers, etc.) likely have the same latent bug. Rule-of-One status; promote on Rule-of-Two if a second walker surfaces the same crash shape.

3. **"detection_audit JSONB as a corpus-sweep primitive"** — pattern #5 above. Single SQL query against an instrumented JSONB column enabled finding 4 OTHER stuck firmwares. Every future detection/walker pipeline should ship with an analogous diagnostic JSONB. Rule-of-One within wairz (it already exists for the hardware-firmware detector; future walkers should mirror). Promote when a second pipeline adopts the same audit shape.
