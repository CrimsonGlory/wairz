---
intake_id: windows-coverage-godmode-eta-2026-05-11
title: Windows ecosystem god-mode coverage — Phase η (forensic-artifact horizontal expansion)
status: approved-for-execution
opened: 2026-05-11
parent_intake: .planning/intake/windows-coverage-godmode-2026-05-07.md
parent_status: closed (3fc48b3 — ζ.2/ζ.3/Lint cleanup); α-ζ all shipped; latest feature commit fb4bcf9
campaign_branch: direct-push to main per-piece (Pattern P5; Trust = trusted ≥184 sessions)
research_artifacts:
  scout_dir: .planning/research/eta-scope-2026-05-11/
  scout_1: scout-1-oss-tooling.md         # OSS lib survey for 7 candidates
  scout_2: scout-2-persona-refresh.md     # Persona-E adversary completionist refresh
  scout_3: scout-3-competitive-platforms.md  # KAPE / Plaso / Velociraptor / FACT / EMBA gap analysis
---

# Wairz Windows-Coverage God-Mode — Phase η (forensic-artifact horizontal expansion)

## Goal

Extend wairz's Windows-RE coverage horizontally across 5 forensic-artifact gaps surfaced by 3-scout research-fleet synthesis (2026-05-11). All 5 streams are static analysis on firmware extracts (no live-system hooks), file-disjoint enough for Rule #23 worktree-per-stream parallelism, and follow the established Rule #39 inner/outer/safe runner triplet recipe (Rule-of-Five durable post-ζ.3.B).

Phase η does NOT introduce a new persistence-store category (no new MCP tool category beyond what each stream needs); it composes the Rule #25 single-slice cross-stack alignment + Rule #39 walker triplet + Rule #29/#33 202+polling status + Rule #35c JSONB normalizer recipes that the 4 prior windows-coverage-godmode campaigns proved.

## Pre-existing baseline (do not re-build)

α-δ all shipped (CAB/MSI/MSIX/MSU/PSF/VHDX/DriverPackage extraction; Authenticode/DBX/RICH/ARM64EC; registry hive walk + driver matrix + WHQL classification; .NET update-diff + R2R-stomping). ε.1 EVTX walker + ε.2 windows_event_records persistence + search_events MCP tool. ζ.1 Amcache install-history finding emit. ζ.2 Prefetch walker + 3 MCP tools. ζ.3 SRUM walker + 3 MCP tools. 226 MCP tools across 21 categories. WindowsFindingSource Literal at 13 values (windows_authenticode through windows_srum_application_runtime).

Established CLAUDE.md rules from the windows-coverage-godmode lineage: Rule #23 (worktree-per-stream), Rule #25 (per-sub-task commits + single-slice exception #2 cross-stack alignment), Rule #29/#33 (202+polling timeout discipline), Rule #35c (JSONB schema_version + normalizer + stamp triplet), Rule #36 (no-execute installer/package code), Rule #37 (offline-trust-anchor — bake into worker image, NOT scan-time fetch), Rule #38 (absolute paths + git -C), Rule #39 (inner/outer/safe runner triplet), Rule #40 (function-local imports MUST sit at top of function body), Rule #41 (Rule #41 must-complete CI mitigation across the 4 mechanisms), Rule #43 (per-line noqa rationale with 4 categories).

## Out of scope (explicit non-goals for Phase η — most defer to θ)

- **WMI persistence walker** (OBJECTS.DATA + INDEX.BTR + MAPPINGn.MAP). Scout 2 ranks HIGH (persona-E priority), Scout 3 ranks DEFER (firmware-RE niche). Scope-disagreement → defer to θ where the integration shape (python-cim ecosystem alignment vs new bespoke parser) gets a focused decision.
- **Boot chain artefacts** (BCD store + MBR/VBR detection + ESP `.efi` PE chain). Scout 2 HIGH; multi-artifact (3 sub-walkers) makes it bigger than a single η stream — defer to θ as its own phase.
- **Memory dump triage / Volatility 3 integration**. Pre-existing OOS (D5 NO in 2026-05-07 intake). Scout 1 confirms `volatility3` is mature (v2.28.0 active, all Windows plugins shipped) but Scout 2 implicitly DEFERS because wairz has no memory-dump intake flow yet. Architectural prerequisite (memory-dump upload UI + processing pipeline) is θ-scope at minimum.
- **hibernate.sys decompression**. Scout 1 recommendation: fold into Volatility 3 integration (not a standalone η item). Defer with #1.
- **EFS DDF/DRF cert-key matching**. Scout 1 flags HIGHEST-EFFORT (200-400 LOC bespoke parser; no turnkey lib). Defer indefinitely.
- **EVT (legacy pre-Vista)**. Scout 1 LOW-RISK (libevt-python pip wheels), but pre-Vista applies to limited firmware corpus. Defer to a "completeness sweep" sub-phase later.
- **ETL parsing**. Scout 1 best lib is `dissect.etl` (AGPL-3.0 — wairz is open-source so OK but flag for downstream). Smaller persona-E priority than the 5 chosen for η. Defer to θ.
- **Shim engine `.sdb`**. Scout 1 LOWEST-RISK (`python-sdb` Apache 2.0 drop-in), but Scout 2 + 3 don't rank it top-3 — application-compat shimming is genuine T1546.011 but lower frequency than the chosen η candidates. Defer to θ as a low-risk addition.
- **NTFS $UsnJrnl + $LogFile** (the OTHER two NTFS sub-artifacts beyond $MFT). Scout 3 recommendation is `dissect.ntfs` collapses much of $MFT walking; $UsnJrnl + $LogFile are SEPARATE walkers. Defer the latter two to η+1 / θ; ship $MFT alone in η.A.
- **Recycle Bin / Jump Lists / Browser artifacts**. Scout 3 LOW persona-D priority (wrong fit for firmware-RE platform). Defer indefinitely.
- **NTFS write-mount / read-write FUSE / dnSpy GUI / Fully-AOT'd .NET**. Inherited from 2026-05-07 OOS. Stay OOS — security-risk / GUI-incompatible / scope-mismatched.

## Decision log (D1–D9, all defaulted to recommended unless redirected by user)

- **D1 NTFS-only $MFT in η.A (defer $UsnJrnl + $LogFile to θ):** YES (single-walker scope per η stream; `dissect.ntfs` covers $MFT cleanly; the other two NTFS files have distinct ORM tables + finding shapes that warrant their own phase letters).
- **D2 Scheduled Task XML walker in η.B uses stdlib `xml.etree` (NOT defusedxml):** YES with rationale. The Tasks XML files are extracted from a firmware tree we control via the unpack pipeline; the parsed content is treated as untrusted DATA per Rule #36 no-execute, so the parsing happens but no XML-driven action runs. Use `defusedxml.ElementTree.fromstring` where available (per Pattern P3 from ζ campaign — defusedxml swap pattern). Reserve stdlib `xml.etree` only for type annotations.
- **D3 LNK walker in η.C adds `LnkParse3>=1.5` to pyproject.toml:** YES. The 2026-05-07 intake listed LnkParse3 in tooling-stack but the dep was never added. CONFIRMED via `grep LnkParse3 backend/pyproject.toml` → 0 hits. η.C adds the dep + first walker.
- **D4 BYOVD η.D bundles `loldrivers.json` per Rule #37 offline-trust-anchor discipline:** YES. `backend/ms-anchors/loldrivers.json` + `backend/ms-anchors/loldrivers.json.sha256` + `backend/ms-anchors/loldrivers.json.url` triplet matching the dbxupdate.bin pattern. Refresh script at `scripts/refresh-loldrivers.sh` quarterly (LOLDrivers releases ~monthly but quarterly refresh is acceptable lag for adversary-techniques tooling).
- **D5 PowerShell EID annotation η.E extends `WindowsFindingSource` Literal with `windows_powershell_script_block` only (NOT 4 separate literal values for 4103/4104/4105/4106):** YES. The literal values describe the FINDING (a PowerShell script-block was logged), not the event-id taxonomy; sub-event-id metadata goes into the finding's `details` dict. Reduces alignment-test churn.
- **D6 Three smaller streams (η.B + η.C + η.E) ship in THIS session via parallel Agent worktrees; two larger streams (η.A NTFS + η.D BYOVD) defer to next session:** YES. Recipe hot-start avoidance per `feedback_do_them_all_pattern.md`; cross-stream worktree discipline per Rule #23.
- **D7 Per-piece direct-push to main (Pattern P5):** YES. Trust = trusted; Rule #41 must-complete CI mitigations are healthy (Lint per-commit + backend-tests nightly cron at 06:00 UTC); per-piece commits remain bisect-clean per Rule #25.
- **D8 No new MCP tool category for η.E:** YES. PowerShell EID annotation extends ε's existing `evtx_service.py` walker emit + the existing `search_events` MCP tool already paginates `windows_event_records` rows (no new endpoint needed).
- **D9 Defer Volatility 3 / WMI / Boot chain to a θ campaign letter (not bundled into η):** YES. Each is its own multi-stream effort warranting its own phase. η stays a horizontal-expansion phase across smaller-scoped artefact walkers.

## 5-stream rollout (THIS session ships 3; next session ships 2)

### Phase η.A — NTFS $MFT walker (defer to next session — LARGEST stream)

**Acceptance:** Every NTFS volume extracted from a firmware (typically the VHDX → raw NTFS path established in α.2.7 + β.7) gets walked at unpack time; per-file MFT records persisted to `windows_mft_records` table; deleted-file recovery candidates surfaced; finding emit for $DATA-stream-hidden-content (T1564.004) and timestomping evidence ($MFT vs $StandardInformation timestamps divergence).

Sub-tasks (~6-8 commits per Pattern P4 1-day-per-walker):

1. η.A.0 — `pyproject.toml` add `dissect.ntfs>=3.10` (MIT, Fox-IT/NCC Group; pure Python; no native build).
2. η.A.A — Alembic migration `<freeID>_add_windows_mft_records.py` + ORM model `WindowsMftRecord` + JSONB normalizers per Rule #35c (`device_metadata['mft_walk_*']` if needed) + `WINDOWS_MFT_RECORDS_*_SCHEMA_VERSION = 1` + tier-1 ORM tests via `make_live_db()`.
3. η.A.B — `firmware.mft_walk_*` 5-column 202+poll status set per Rule #33 contract (idle/queued/running/completed/failed + Pydantic Literal + DB CHECK constraint `ck_firmware_mft_walk_status`).
4. η.A.C — Rule #39 inner/outer/safe runner triplet `mft_walker.py` (`_do_mft_run` + `run_mft_walk_background` + `auto_mft_walk_firmware_safe`) + tier-1 inner-runner tests against a real `tiny.ntfs.dd` fixture.
5. η.A.D — Cross-stack alignment commit (Rule #25 single-slice exception #2 — Rule-of-Eight → Rule-of-Nine): alembic `ck_findings_source` extension + `WindowsFindingSource` Literal extension (`windows_mft_ads_hidden_content`, `windows_mft_timestomping`) + classifier helper + emit method + frontend `FindingSource` union + `FINDING_SOURCE_CONFIG` mirror. ATOMIC.
6. η.A.E — Finding-emit hook in `auto_mft_walk_firmware_safe` + integration with `FindingService`.
7. η.A.F — MCP tool category `windows_mft.py` (3 tools: `search_mft_records` + `mft_walk_status` + `trigger_mft_walk`) per the established `windows_srum.py` pattern. Tool count: 226 → 229.
8. η.A.G — Validation: Rule #8 backend+worker+migrator rebuild + Rule #11 import smoke + targeted pytest + Rule #35b live canary against a real Win11 ISO's NTFS volume + ruff/bandit/eslint + tsc -b --force lower-bound tool count check.
9. η.A.H — Direct-push to main per-piece (8 commits) + CI watch.

**End conditions:**
- `command_passes`: `( cd backend && uv run pytest tests/test_mft_walker.py tests/test_mft_models.py -v )` exits 0.
- `metric_threshold`: `find backend/app/ai/tools -name '*.py' | xargs grep -c 'registry\.register' | awk -F: '{s+=$2}END{print s}'` ≥ 229 (was 226 baseline).
- `command_passes`: `( cd frontend && npx tsc -b --force )` exits 0.
- `file_exists`: `backend/app/services/mft_walker.py` exists with the inner/outer/safe runner triplet.
- `command_passes`: `git -C /home/dustin/code/wairz log --oneline --grep='Phase η.A' | wc -l` ≥ 6.

### Phase η.B — Scheduled Task XML walker (THIS SESSION — Wave 1 stream)

**Acceptance:** Every Windows firmware extract walked for `\Windows\System32\Tasks\` XML task definitions; persistence findings emitted per task with `RunLevel=HighestAvailable` AND triggers AND actions surfaced; encoded-PowerShell-action shape (Qakbot pattern) flagged at HIGH confidence.

Sub-tasks (~4-5 commits per Pattern P4 — XML is well-structured, no new dep):

1. η.B.A — Alembic migration `<freeID>_add_windows_scheduled_tasks.py` + ORM model `WindowsScheduledTask` + JSONB normalizer for `triggers`/`actions`/`principal` + `WINDOWS_SCHEDULED_TASKS_*_SCHEMA_VERSION = 1` + tier-1 ORM tests.
2. η.B.B — `firmware.scheduled_task_walk_*` 5-column 202+poll status set per Rule #33.
3. η.B.C — Rule #39 inner/outer/safe runner triplet `scheduled_task_walker.py` + tier-1 inner-runner tests against a synthesized `tiny.task.xml` fixture (3-task synthetic XML — RunOnce / On Logon / On Schedule).
4. η.B.D — Cross-stack alignment commit (Rule #25 single-slice exception #2 — Rule-of-Nine → Rule-of-Ten): `ck_findings_source` + `WindowsFindingSource` Literal extension (`windows_scheduled_task_persistence`) + classifier helper (encoded-PowerShell detection + non-system author) + emit method + FE union + FE config. ATOMIC.
5. η.B.E — MCP tool category `windows_scheduled_task.py` (3 tools: `search_scheduled_tasks` + `scheduled_task_walk_status` + `trigger_scheduled_task_walk`). Tool count: 229 → 232 (after η.A) or 226 → 229 (if η.B ships first).
6. η.B.F — Validation suite + Rule #8 rebuild + Rule #11 smoke + lower-bound count check.
7. η.B.G — Direct-push to main + CI watch.

**End conditions:**
- `command_passes`: `( cd backend && uv run pytest tests/test_scheduled_task_walker.py tests/test_scheduled_task_models.py -v )` exits 0.
- `metric_threshold`: tool count ≥ 229 (assuming η.B ships before η.A; +3 for `windows_scheduled_task` category).
- `command_passes`: `( cd frontend && npx tsc -b --force )` exits 0.
- `file_exists`: `backend/app/services/scheduled_task_walker.py` exists.
- `command_passes`: `git -C /home/dustin/code/wairz log --oneline --grep='Phase η.B' | wc -l` ≥ 4.

### Phase η.C — LNK file walker (THIS SESSION — Wave 1 stream)

**Acceptance:** Every Windows firmware extract walked for `.lnk` files (typically in user profiles, Recent docs, Start Menu Programs); MAC times + target path + working-dir + arguments + icon ref persisted; finding emit for "abnormal LNK target" (T1547.009) — non-Microsoft target binary, `cmd.exe /c` patterns, encoded args.

Sub-tasks (~4-5 commits per Pattern P4):

1. η.C.0 — `pyproject.toml` add `LnkParse3>=1.5` (the 2026-05-07 intake's TODO never landed; this commit closes it).
2. η.C.A — Alembic migration `<freeID>_add_windows_lnk_records.py` + ORM model `WindowsLnkRecord` + JSONB normalizer for `target_metadata` (target path / working dir / args / hotkey / show-window) + `WINDOWS_LNK_RECORDS_*_SCHEMA_VERSION = 1` + tier-1 ORM tests.
3. η.C.B — `firmware.lnk_walk_*` 5-column 202+poll status set per Rule #33.
4. η.C.C — Rule #39 inner/outer/safe runner triplet `lnk_walker.py` + tier-1 inner-runner tests against a synthesized `tiny.lnk` fixture (3 LNKs — explorer-target / cmd-target / encoded-PowerShell-target).
5. η.C.D — Cross-stack alignment commit (Rule #25 single-slice exception #2 — Rule-of-Ten → Rule-of-Eleven): `ck_findings_source` + `WindowsFindingSource` Literal extension (`windows_lnk_abnormal_target`) + classifier helper + emit method + FE union + FE config. ATOMIC.
6. η.C.E — MCP tool category `windows_lnk.py` (3 tools: `search_lnk_records` + `lnk_walk_status` + `trigger_lnk_walk`). Tool count: +3.
7. η.C.F — Validation suite + Rule #8 rebuild + Rule #11 smoke + lower-bound count check.
8. η.C.G — Direct-push to main + CI watch.

**End conditions:**
- `command_passes`: `( cd backend && uv run pytest tests/test_lnk_walker.py tests/test_lnk_models.py -v )` exits 0.
- `metric_threshold`: tool count ≥ 232 (after η.B + η.C, both +3).
- `command_passes`: `( cd frontend && npx tsc -b --force )` exits 0.
- `file_exists`: `backend/app/services/lnk_walker.py` exists with the Rule #39 triplet.
- `file_exists`: `LnkParse3` appears in `backend/pyproject.toml`.
- `command_passes`: `git -C /home/dustin/code/wairz log --oneline --grep='Phase η.C' | wc -l` ≥ 4.

### Phase η.D — BYOVD LOLDrivers fingerprinting (defer to next session — Rule #37 anchor work)

**Acceptance:** Every signed driver extracted via α.2.6 driver-package unpacker AND every driver path cross-referenced against γ Services hive walk gets fingerprinted against an offline LOLDrivers JSON anchor; matches emit `windows_byovd_driver` finding at HIGH confidence with the LOLDrivers reference URL + CVE list + threat-actor attribution.

Sub-tasks (~5-6 commits):

1. η.D.0 — Bundle `backend/ms-anchors/loldrivers.json` + `backend/ms-anchors/loldrivers.json.sha256` + `backend/ms-anchors/loldrivers.json.url` per Rule #37 offline-trust-anchor discipline. Initial bundle from `https://www.loldrivers.io/api/drivers.json` (~5-10 MB JSON; pin SHA256).
2. η.D.A — Dockerfile delta: `COPY` ms-anchors + `RUN sha256sum -c loldrivers.json.sha256` + place at `/opt/wairz/loldrivers.json` + chmod 0444 + chown wairz. docker-compose.yml: set `LOLDRIVERS_BUNDLE_PATH=/opt/wairz/loldrivers.json` env var on backend AND worker.
3. η.D.B — `scripts/refresh-loldrivers.sh` quarterly cron script (atomic-write per Rule #19; SHA256 compare; non-zero on drift; `--apply` for auto-pin-update; `--rebuild` for `docker compose build --no-cache --pull worker backend migrator`).
4. η.D.C — `loldrivers_lookup_service.py` — single function `lookup_driver_byovd(blob_id: uuid.UUID) -> BYOVDVerdict | None` with hash-to-LOLDrivers-record dict pre-built from the bundle. Lifespan startup probe logs presence + size + entry count.
5. η.D.D — Cross-stack alignment commit (Rule #25 single-slice exception #2 — Rule-of-Eleven → Rule-of-Twelve): `ck_findings_source` + `WindowsFindingSource` Literal extension (`windows_byovd_driver`) + classifier helper + emit method + FE union + FE config. ATOMIC.
6. η.D.E — Finding-emit hook in `auto_driver_package_firmware_safe` (extends α.2.6) + integration with γ Services hive walk for already-installed drivers.
7. η.D.F — MCP tool extension: extend the existing `windows_driver` tool category with `lookup_byovd_driver` (1 new tool — fingerprint a single driver hash). Tool count: +1.
8. η.D.G — Validation + Rule #8 rebuild + lifespan startup probe verifies `/opt/wairz/loldrivers.json` mounts + size > 0.
9. η.D.H — Direct-push to main + CI watch.

**End conditions:**
- `command_passes`: `( cd backend && uv run pytest tests/test_loldrivers_lookup.py tests/test_byovd_finding_emit.py -v )` exits 0.
- `metric_threshold`: tool count ≥ 233.
- `file_exists`: `backend/ms-anchors/loldrivers.json` AND `backend/ms-anchors/loldrivers.json.sha256` AND `scripts/refresh-loldrivers.sh`.
- `command_passes`: `docker compose exec -T backend test -r /opt/wairz/loldrivers.json` exits 0 (post-rebuild).
- `command_passes`: `git -C /home/dustin/code/wairz log --oneline --grep='Phase η.D' | wc -l` ≥ 5.

### Phase η.E — PowerShell EID 4103/4104 annotation (THIS SESSION — Wave 1 stream)

**Acceptance:** ε's existing `evtx_service.py` walker tags PowerShell event IDs (4103 ModuleLogging + 4104 ScriptBlock + 4105/4106 Pipeline events) into a new finding source `windows_powershell_script_block`. Encoded-PowerShell heuristics (base64 + obfuscation patterns) at HIGH confidence; module-load-only at LOW.

Sub-tasks (~2-3 commits per Pattern P4 — pure annotation extension; no new walker; no new MCP tool):

1. η.E.A — Cross-stack alignment commit (Rule #25 single-slice exception #2 — Rule-of-Twelve → Rule-of-Thirteen): `ck_findings_source` extension + `WindowsFindingSource` Literal extension (`windows_powershell_script_block`) + classifier helper `classify_powershell_event(record_data: dict) -> ClassificationResult | None` (handles 4103/4104/4105/4106 + base64 / obfuscation) + emit method `emit_powershell_findings_from_event_walk` + FE union + FE config. ATOMIC.
2. η.E.B — Wire the classifier into ε's existing finding-emit hook (`auto_evtx_walk_firmware_safe` already runs after walker; extend the per-record loop to include PowerShell EID branch). Tier-1 tests against synthetic 4104 event payload (encoded base64 + decoded plain).
3. η.E.C — Validation suite + Rule #8 rebuild + Rule #11 smoke (no new tool surface so MCP count unchanged).
4. η.E.D — Direct-push to main + CI watch.

**End conditions:**
- `command_passes`: `( cd backend && uv run pytest tests/test_finding_service_powershell_emit.py tests/test_evtx_service.py -k 'powershell or 4104 or 4103' -v )` exits 0.
- `command_passes`: `( cd frontend && npx tsc -b --force )` exits 0.
- `metric_threshold`: `grep -c '"windows_powershell_script_block"' backend/app/schemas/finding.py` ≥ 1.
- `command_passes`: `git -C /home/dustin/code/wairz log --oneline --grep='Phase η.E' | wc -l` ≥ 2.

## Quality rule deltas (durable, append-only per `protect-files.js` allowed-change shape)

- `auto-windows-byovd-loldrivers-bundle-required` (η.D) — fires when a `Dockerfile` change references `loldrivers.json` without the SHA256 sidecar.
- `auto-windows-mft-walker-must-use-detection-roots` (η.A) — fires when `mft_walker.py` references `firmware.extracted_path` without `get_detection_roots(firmware)` (Rule #16 partner).
- Existing `auto-review-no-raw-join-in-sandbox` filePattern stays unchanged (already covers `app/workers/unpack_*.py`).

## Tooling stack — pyproject deltas

```
pyproject.toml additions for η:
  dissect.ntfs>=3.10        # η.A — Fox-IT/NCC Group, MIT, pure Python, no native build
  LnkParse3>=1.5            # η.C — closes 2026-05-07 TODO; pure Python; format-stable
```

No apt-get additions for η.B (stdlib XML), η.C (LnkParse3 pure-Python), η.D (no library; bundled JSON anchor), or η.E (existing python-evtx).

For η.A: `dissect.ntfs` requires no system deps; verify via Rule #19 library probe in container before drafting `_do_mft_run`.

## Test fixture sourcing

`backend/tests/fixtures/windows/` additions:

- `tiny.ntfs.dd` — synthesized via `qemu-img create -f raw test.dd 1M; mkfs.ntfs -F test.dd` (η.A).
- `tiny.task.xml` — handwritten 3-task XML (η.B).
- `tiny.lnk` — synthesized via `LnkParse3` reference; 3 LNKs (explorer-target / cmd-target / encoded-PowerShell-target) (η.C).
- `tiny.loldrivers.json` — 3-driver subset of the real bundle for tier-1 tests (η.D).
- `tiny.evtx.powershell` — 4-record EVTX with EIDs 4103/4104/4105/4106 (η.E).

All fixtures ≤200 KB to stay within the existing `backend/tests/fixtures/windows/` size budget.

## Live canaries (Rule #35b, per stream)

- η.A: real Win11 23H2 ISO mounted via VHDX → raw NTFS partition; `_do_mft_run` against the actual `\Windows\System32\` MFT records.
- η.B: real Win11 firmware extract walked for `\Windows\System32\Tasks\Microsoft\Windows\` system tasks (~150-200 task XMLs). Spot-check 3 known tasks (e.g. `\Maintenance\WinSAT`, `\WindowsUpdate\Scheduled Start`).
- η.C: real Win11 firmware's `\Users\<profile>\Recent\` LNK files (typically 30-100 LNKs in a healthy profile).
- η.D: real signed driver from γ canary corpus (e.g. PROCEXP100.SYS — known LOLDriver) cross-referenced against the bundled `loldrivers.json` → `windows_byovd_driver` finding emitted at HIGH confidence.
- η.E: real Win11 firmware's `Windows PowerShell.evtx` with 4104 ScriptBlock events → emit verifies encoded-PowerShell detection.

## References

- Scout 1: `.planning/research/eta-scope-2026-05-11/scout-1-oss-tooling.md` (OSS lib survey)
- Scout 2: `.planning/research/eta-scope-2026-05-11/scout-2-persona-refresh.md` (persona-E adversary refresh)
- Scout 3: `.planning/research/eta-scope-2026-05-11/scout-3-competitive-platforms.md` (KAPE/Plaso/Velociraptor gap analysis)
- Parent intake: `.planning/intake/windows-coverage-godmode-2026-05-07.md` (CLOSED)
- Parent campaign closure: commit `3fc48b3` ("close ζ.2 + ζ.3 + Lint Cleanup campaign")
- CLAUDE.md Rules #1, #6, #8, #11, #16, #19, #20, #21, #22, #23, #25, #27, #29, #33, #34, #35, #36, #37, #38, #39, #40, #41, #43
- `.mex/patterns/INDEX.md` precedent recipes (notably: `inner-outer-safe-runner.md`, `add-202-polling-windows-op.md`, `add-windows-format-handler.md`, `add-alembic-migration.md`, `real-firmware-skip-tier-canary.md`, `rule-41-must-complete-ci.md`)
- `.claude/harness.json` quality rules

## Status

- ✅ Phase 0 (3-scout research-fleet pre-pass) complete (2026-05-11 ~21:00 UTC)
- ✅ Phase 1 (synthesis + scope decision) complete (η.A-E locked)
- 🟡 Phase 2 (campaign intake + tracking file authored) IN PROGRESS
- ⬜ η.A (NTFS $MFT walker) — DEFERRED to next session
- ⬜ η.B (Scheduled Task XML walker) — THIS SESSION Wave 1
- ⬜ η.C (LNK file walker) — THIS SESSION Wave 1
- ⬜ η.D (BYOVD LOLDrivers fingerprinting) — DEFERRED to next session
- ⬜ η.E (PowerShell EID 4103/4104 annotation) — THIS SESSION Wave 1

## Wave 1 dispatch shape

THIS session ships η.B + η.C + η.E in parallel via Agent worktrees per Rule #23 dispatch:

```
git worktree add .worktrees/eta-b-scheduled-tasks -b feat/stream-eta-b-scheduled-tasks-2026-05-11
git worktree add .worktrees/eta-c-lnk-walker -b feat/stream-eta-c-lnk-walker-2026-05-11
git worktree add .worktrees/eta-e-powershell-eid -b feat/stream-eta-e-powershell-eid-2026-05-11
```

Each stream operates IN its worktree (cd .worktrees/stream-<name>) for all writes/commits. Symlink `frontend/node_modules` from main checkout into each worktree to avoid 2 GB npm-install per stream.

`.worktrees/` is already in `.gitignore` per the prior windows-coverage-godmode lineage.

After all 3 streams complete, Archon reviews each worktree's commits, runs Rule #8 single rebuild + Rule #11 single import smoke + tsc -b --force on the merged main, then direct-pushes the merged commits to origin/main per-piece (Pattern P5 cadence) and removes the worktrees.

## Next session pickup

Next session inherits η.A + η.D as DEFERRED items with full sub-task decomposition above. End conditions are codified per phase. The campaign-tracking file at `.planning/campaigns/windows-coverage-godmode-eta-2026-05-11.md` (separate from this intake) carries Active Context + Continuation State.

---

**This intake is the AUTHORITATIVE scope+plan for Phase η. The campaign-tracking file (`.planning/campaigns/windows-coverage-godmode-eta-2026-05-11.md`) carries Archon execution state. Both stay in sync.**
