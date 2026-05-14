---
title: Extended session postmortem — λ.α streams A-C + tibx exhaustive investigation
campaign: memory-forensic-godmode α + tibx-investigation
date: 2026-05-12 → 2026-05-13
status: session-closed
commits_shipped: 22 (44124db..49f4e35 on origin/main)
---

# Extended session postmortem — λ.α A-C + tibx investigation

Cross-spans two effective sub-sessions (initial wakeup + post-pivot
re-engagement). Captures the union because the work threads share
state.

## What shipped to origin/main

**22 commits, 44124db → 49f4e35.** Grouped by theme:

### Initial Item #1 (walker-results backfill) — 2 commits
- `7438520` fix(tests): use unpack_log marker as rootfs-shortcut discriminator (Rule #47 consumer-hook miss on `5f3d195` walker-bridge)
- `2321ebe` chore(scripts): walker-results backfill — close Rule #47 gap for pre-bridge rows (15 rows × 21 walkers = 315 stamps)

### λ.α memory-forensic-godmode α streams — 3 commits
- `8ed2d48` feat(models): add memory_dump_image table — λ.α.A (11 cols + 2 composite indexes + FK CASCADE; alembic `bce1f2a3b4c5`)
- `d357938` feat(memory-forensic): λ.α.B memory-image enumerator (Rule #39 6th-application triplet; 5 firmware-side state cols + DB CHECK; walker_registry 22→23)
- `ef14bb5` feat(dockerfile): λ.α.C Vol3 + ISF symbol bundle gate (ARG INCLUDE_VOL3=0; pinned `volatility3==2.28.0[full]`; `VOL3_SYMBOLS_PATH` env)

### Session-1 close-out — 3 commits
- `0fbea01` docs(postmortem): λ session 1 close — streams A-C shipped + decisions locked
- `f22c511` docs(learn): λ session-1 patterns + antipatterns extraction
- `5c19490` feat(tibx): magic-byte detection + master/continuation slice diagnostics (incl. `.raw` in `_RAW_IMAGE_EXTENSIONS`)
- `78f7c6b` docs(postmortem): tibx investigation + ILLUMISITE end-to-end ADDENDUM (boot.wim extracted; 322 driver packages + 9 BCD + 1 WMI + 3 signed EFI + 2 findings stamped on `640cda1f`)

### tibx BYOB-SC architecture (built, reverted) — 5 commits
- `767d0d6` feat(tibx): λ.μ BYOB-SC side-container — Acronis tibxread integration
- `69b381a` fix(tibx): compose pids conflict + entrypoint heredoc backtick escape
- `23cb720` test(tibx): unit suite (15 tests) + CLAUDE.md Rule #36 Exception 3
- `86a4dd8` docs(postmortem): tibx BYOB extraction attempt — Docker Hub path is dead end
- `9428b5f` Revert "feat(tibx): λ.μ BYOB-SC + fix + tests" (operator-direct)

### tibx alternative-paths deep research — 4 commits
- `210b78b` docs(research): tibx alternatives 3-scout findings + synthesis (Wine NO-GO, format-RE 80h+, QEMU-PE-boot HOLD-pending-probe)
- `3fd7bad` docs(research): tibx probe #1 result — UEFI bootx64.efi LOADS; BCD fixable
- `08ec2b7` docs(research): tibx probe #2 — Fix B (BCD hivex/byte patch) is NO-GO
- (Decision shipped in commit body: Branch 3 — accept opacity)

### GitHub infrastructure — 1 commit
- `49f4e35` ci(github): add Dependabot config + CodeQL scanning workflow + 8 issues filed + 16 topics + 19 labels + Issues/security features enabled

## What broke

### #1 — `test_zip_of_fat_image_does_not_shortcut` regressed at CI boundary (44124db)
**What happened:** the walker-bridge wire-in (`5f3d195`) made
`firmware.extracted_path` get set unconditionally for generic-ZIP
extractions. The test asserted `extracted_path is None` as a proxy for
"rootfs shortcut didn't fire". The proxy broke; CI failed on the FIRST
boundary commit after a long run of Rule #41-cancelled intermediates.

**Why it surfaced now:** Rule #41 concurrency-cancel masks failures in
intermediate commits; only the last commit before a quiet period
surfaces accumulated defects. `44124db` was that commit.

**Fix shipped:** `7438520` — discriminate on `unpack_log` marker (the
TRUE-intent signal — "rootfs shortcut fired" vs "didn't") rather than
the broken `extracted_path` proxy. **Rule #47 mechanical application —
Rule-of-Two confirmed.**

### #2 — Worker image stale relative to backend image
**What happened:** `docker compose images backend worker migrator`
returned three different image IDs despite the prior session's
"rebuild all three" claim. Worker container's `walker_registry` import
failed (`ModuleNotFoundError: No module named 'app.workers.walker_registry'`).

**Mitigation in tree:** Item #1 backfill executed via the backend
container (which had the fix), not the worker. Documented as Rule #8
violation; future operators should `docker compose images <a> <b> <c>
| awk '{print $4}' | sort -u | wc -l` and expect `1`.

### #3 — SQLAlchemy identity map silenced walker effect
**What happened:** First version of `backfill_walker_results_2026_05_13.py`
reported `results 0 → 0` for the smoke-test row even though walkers
had stamped 21 result columns. Walkers ran in their own
`async_session_factory` sessions; the outer session's identity map
cached the pre-walk row.

**Fix shipped:** `db.expire(firmware)` BEFORE the re-SELECT — Rule #32
EXCEPTION case where `db.refresh()` IS load-bearing across sessions.

### #4 — Git revert missed deleting `test_unpack_tibx.py`
**What happened:** `9428b5f` (revert of `767d0d6 + 69b381a + 23cb720`)
left `backend/tests/test_unpack_tibx.py` on disk because git revert
didn't enumerate the file's add from `23cb720`. Orphaned test references
a deleted worker; would have broken `pytest --collect-only`.

**Fix shipped:** Deleted in `08ec2b7` ("D backend/tests/test_unpack_tibx.py").

### #5 — Acronis tibxread Docker Hub extraction crashes pre-help
**What happened:** Extracted `tibxread` + full Acronis tree from
`mercurylabssagl/acronis_backup_agent:15.0.31637` (897 MiB). SIGABRT at
init: `BUG at d:/995/archive/ver3/adapter/environment.cpp:171/Archive3_GetDefaultPcsProcess()`.
Even with full `/opt/start.sh` + 5 Acronis services running
`--privileged`, the registered runtime state Acronis expects is set up
during install + REGISTRATION (likely cloud-dependent).

**Decision:** Postmortem at `postmortem-tibx-byob-extraction-attempt-2026-05-13.md`;
operator-side Acronis install required (BYOB pattern Scout C
designed). BYOB-SC architecture reverted in `9428b5f` per operator
"scratch the tibx support work" directive.

### #6 — Probe #1 BCD `0xc000000e` (Microsoft Windows Boot Manager)
**What happened:** QEMU + OVMF UEFI booted `bootx64.efi` successfully
from a partition-less FAT32 disk containing the customer's recovery PE
files + a chain `startup.nsh`. Windows Boot Manager then failed on
`\EFI\Microsoft\Boot\BCD` with `0xc000000e` (BCD missing or contains
errors).

**Diagnosis:** BCD's internal device-GUID references point at a volume
that doesn't exist (Microsoft's `MakeWinPEMedia` writes BCD with a
volume-GUID that matches the prepared media; naïve `mcopy` skipped
that).

### #7 — Probe #2 byte-level BCD patch insufficient
**What happened:** Replaced all 4 PARTITION (type 5) device descriptors
in the BCD with BOOT (type 6) via hivex + byte-level pass. Still
`0xc000000e`.

**Diagnosis:** Microsoft BCDs likely have cross-referenced GUID + suspected
integrity hashes that span the hive. Byte-level patches break consistency
checks; we trade "unknown device" for "BCD corrupt".

**Decision:** Branch 3 (accept .tibx opacity). Filed issue #14 for re-open
on N=2 operator encounter.

### #8 — GitHub token (fine-grained PAT) had read-only `Contents` permission
**What happened:** `git push origin main` returned 403 even though
`gh auth status` showed authenticated. `gh api -X GET` worked for read
endpoints; `git-receive-pack` returned 403.

**Diagnosis:** Fine-grained PAT had `Metadata: Read` only. Operator
needed to grant `Contents: Read and write`.

**Resolved out-of-band** — operator edited the PAT scope; push went
through.

## What didn't break (worth noting)

- **Pattern P5 per-piece direct-push to main** — 22 commits, Trust=trusted, 0 reverts of unintentional bisect-poisoning.
- **Rule #25 per-sub-task commits** — every commit independently revertable; commits #767d0d6+#69b381a+#23cb720 reverted cleanly as a single revert commit when scope changed.
- **Rule #38 absolute paths (git -C, subshell-scoped cd backend)** — zero CWD drift incidents this session.
- **3-scout parallel research-fleet pattern** — fired twice (initial λ.α pre-pass + tibx alternatives), both produced actionable synthesis.
- **CLAUDE.md Rule discipline** — Rule #19 evidence-first caught spec-vs-DB drift; Rule #32 explicit-re-SELECT corrected identity-map masking; Rule #41 boundary-commit reflex held; Rule #47 fired twice with correct mitigation.

## Decisions locked

- **`.tibx`: Branch 3** (accept opacity until N=2). Re-open trigger: 2nd Acronis-bundled firmware in a different device family.
- **Vol3 invocation shape: subprocess** (Rule #29 timeout discipline + process isolation + heap reclaim).
- **ISF bundle source: GitHub release** (NOT Apache mirror — stale).
- **ISF refresh cadence: quarterly** (matches DBX + LOLDrivers).
- **Default `ARG INCLUDE_VOL3=0`** (opt-in like `INCLUDE_DOTNET`).
- **Defer credentials family** (`hashdump` / `lsadump` / `cachedump` / `truecrypt`) beyond λ.δ per Rule #45.
- **Branch protection: NOT added** to wairz repo — preserves Pattern P5.
- **Issues: ENABLED** as durable work-tracking surface (was previously off; deferred items only visible in `.planning/`).

## Known follow-ups (now tracked as issues)

- #11 λ.α.D vol3_runner.py — **priority/high**
- #12 refresh-vol3-symbols.sh
- #13 Tests for memory_image_paths + enumerator
- #14 .tibx deferred — re-open trigger
- #15 Rule #44 cross-firmware backfill × 11 walkers
- #16 Recovery-PE walker codification (auto-recurse `sources/boot.wim`)
- #17 λ.β windows_processes_walker
- #18 λ.γ windows_injection_walker — **priority/high** (2026-06-07 deprecation deadline)

## Validation summary

- All 22 commits pushed to `origin/main`
- CI: Lint passes on most commits; Backend Tests in flight (Rule #41 boundary-commit awaits)
- Migrations applied: alembic head advanced from `aabbccddee18` → `bdf2a3b4c5d6` (λ.α.A + λ.α.B)
- Walker registry: 22 → 23 auto-triggers
- Findings DB: ILLUMISITE `640cda1f` carries 21 walker result columns + 2 findings + 323 hardware-firmware blobs
- 8 issues filed; 16 topics + 19 labels created; Dependabot + CodeQL configured

## Time spent

Approximately 6 hours wall-clock across two effective sub-sessions
(2026-05-12 evening + 2026-05-13 morning).
