# Wave-1 Scout B — Adjacency + Rule #52 Closed-Grammar Precedent (S2)

> Investigation date: 2026-05-21 (Session 2)
> Persona: ADJACENCY + Rule #52 PRECEDENT
> Scope: Identify which Session 2 fixes are candidates for Rule #52 closed-grammar refactor;
> assess Rule-of-Three promotion race against ICS Session 2 (postmortem 2026-05-20).

## Executive Summary

The single strongest Rule #52 closed-grammar refactor candidate among Session 2 fixes is **Fix #9 (`_post_process_pipeline` unpack gate)** — the upload-pipeline's hardcoded tarball / rootfs-ZIP / Android-OTA / generic-ZIP IF-ELIF chain at `backend/app/services/firmware_service.py:589-759` is an exact structural sibling of the bare-metal walker's per-rule POLICY_EVALUATORS dispatch table (`backend/app/services/bare_metal_walker.py:255-267`) and the file-format catalog's per-format DispatchKind table (`backend/app/services/file_format_catalog/resolver.py:679-686`). Fix #11 (walker reaper sweep) is a weaker candidate — the reaper config IS data-shaped but already derives from `walker_registry.WALKER_AUTO_TRIGGERS` (`backend/app/workers/walker_registry.py:101-158`), so closed-grammar refactor adds packaging not capability. Fix #1 (SBOM `/generate` Rule #33 conversion) is code-only; Fix #6 (grype `force_rescan`) is code-only; the broader create_task GC sweep is code-only. **Rule #52 Rule-of-Three promotion this session is NO** — ICS Session 2 (postmortem 2026-05-20 line 148) explicitly claims the Rule-of-Three slot and is closer to shipping (Session 1 already shipped 4500 LOC scaffold; Session 2 ships walker + MCP + plugins). The extraction-strategy refactor (this session's strongest Fix #9 candidate) is a Rule-of-Three "could happen if ICS slips" backup but legitimately deserves the **Rule-of-Four DURABLE BEYOND DEBATE** slot AFTER ICS ships. Estimated extraction-strategy refactor scope ~2500-3000 net LOC + 4-5 weeks of Wave-1+Wave-2 deep research (Rule #52 Wave-1+Wave-2 methodology per `feedback_wave2_cross_feature_methodology.md`); confidence MEDIUM on the design, HIGH on the structural fit.

## Rule #52 Precedent Re-cap (Instance #1 + Instance #2)

### Instance #1 — Bare-Metal MCU/DSP (`bare_metal_walker.py` + `chip_catalog.py`)

The first worked example (`backend/app/services/bare_metal_walker.py:1-40` docstring) ships a closed-grammar dispatch surface for chip-family security audits. The shape: closed Pydantic Literals (`Arch` / `Endianness` / `Packing` / `RegionSemantic` / `PolicyOperator` / `RegionAccess` / `GhidraProcessor` / `DetectionSignalKind` / `RegionDiscovery` / `DescriptorSource`) declared in `backend/app/schemas/chip_family.py`, an mtime-cached YAML catalog at `backend/app/services/hardware_firmware/chip_catalog.py:1-100` walking `data/chip_families/<vendor>/<family>.yaml` (e.g. `ti/tms320f28066.yaml`), an architecture-agnostic walker dispatching over `POLICY_EVALUATORS: dict[PolicyOperator, ...]` at `bare_metal_walker.py:255-267` (8 closed evaluators: `unsecure_when_all_words_equal` / `unsecure_when_any_word_equal` / `perma_lock_when_all_words_equal` / `required_value_at_offset` / `forbidden_value_at_offset` / `entropy_floor` / `entropy_ceiling` / `informational`), a Rule #39 inner/outer/safe runner triplet, operator-precedence descriptor arbitration (`bare_metal_walker.py:275-280`), and Rule #45 parse-only no-decrypt token-scan gate. Adding a new chip family is YAML-only; adding a new policy operator is a Rule #25 Shape-1 cross-stack alignment commit (closed Literal + POLICY_EVALUATORS handler + alignment test).

### Instance #2 — File-Format YAML Registry (`file_format_catalog/` + `data/file_formats/`)

The second worked example (`backend/app/services/file_format_catalog/__init__.py:1-13` docstring) ships a closed-grammar resolver for unpacker-format dispatch. The shape: 20+ closed Pydantic Literals in `backend/app/schemas/file_format.py` (`DetectionSignalKind` 13 entries / `DispatchKind` 6 entries / `SortTier` 3 entries / `TextFormatCharset` 6 entries / `TextFormatLineTerminator` 4 entries / `ManifestSource` 5 entries / `TextFormatFirstLine` / `SubstringInHeadConstraint.combine` 2 entries / etc.), mtime-cached catalog at `backend/app/services/file_format_catalog/catalog.py:1-604`, cost-sorted resolver at `backend/app/services/file_format_catalog/resolver.py:896-976` with closed `SIGNAL_EVALUATORS: dict[DetectionSignalKind, _SignalEvaluator]` (`resolver.py:542-556`) and closed `DISPATCH_EVALUATORS: dict[DispatchKind, _DispatchEvaluator]` (`resolver.py:679-686`), HYBRID `PLUGIN_REGISTRY` escape hatch with `freeze_plugin_registry()` at `resolver.py:761-764` (W2-β attack I — frozen post-startup so a stale signal can't TOCTOU), 49 operator-extensible YAMLs across `_system/` + 8 vendor partitions (e.g. `linux_squashfs.yaml` 35 lines), cross-feature validators A1-A9 (path cross-check / cross-vendor collision / dispatch-rank monotonicity / plugin-namespace disjointness / high-collision floor / rtos_family sanitization), 60+ Rule #46 META-CANARIES. The HYBRID plugin escape hatch handles cases where the closed grammar is insufficient (legacy `detect_rtos` taxonomy that partners legitimately extend) — codified via the `MatcherProto` protocol at `resolver.py:694-713`.

Both worked examples share the same architectural template: closed-grammar Pydantic Literals + free-string taxonomy + plugin escape hatch + cross-feature gates + mtime-cached catalog + per-evaluator dispatch table + Rule #39 walker triplet + Rule #46 META-CANARY paired with every closed table.

## Refactor Candidate Assessment

### Fix #1 — SBOM /generate Rule #33 conversion

- **Rule #52 angle:** **None substantive.** The SBOM strategy registry at `backend/app/services/sbom/service.py:68-85` already follows a Strategy pattern with 12 strategy classes (`DpkgStrategy`, `OpkgStrategy`, `PythonPackagesStrategy`, `KernelStrategy`, `FirmwareMarkersStrategy`, `BusyBoxStrategy`, `CLibraryStrategy`, `GccStrategy`, `SoFilesStrategy`, `BinaryStringsStrategy`, `AndroidStrategy`, `SyftStrategy`). Each strategy is a Python class implementing `SbomStrategy.run(StrategyContext)` (`backend/app/services/sbom/strategies/base.py:44-73`). The strategies are NOT data-driven — they're code-driven by design because each strategy carries non-trivial parsing logic (Syft subprocess invocation, dpkg/status parsing, busybox symbol extraction, etc.). **The strategy registry IS adaptable today** — operator drops a new `SbomStrategy` subclass into `backend/app/services/sbom/strategies/` and adds the import to `service.py:_STRATEGY_CLASSES`. No YAML refactor would simplify this.
- **Recommended shape:** **Code-only.** The Rule #33 conversion (sync → 202+polling with `sbom_status` column) is mechanical and follows the Rule #33 .a/.b/.c/.d contract verbatim (state machine + result aggregate JSONB + DB CHECK + Pydantic Literal + create_task vs arq decision + Rule #51 reaper). No closed-grammar opportunity.
- **LOC + complexity delta vs straight Rule #33:** Straight Rule #33 conversion is ~80 LOC across migration / model / schemas / router / frontend + 1 Rule #48 Shape-1 commit. Adding closed-grammar refactor would add ~500 LOC for no operator-facing benefit — strategies are already pluggable at the Python level. **Verdict: ship straight Rule #33 conversion; defer closed-grammar consideration until/unless a clear adaptability demand emerges (e.g. operator-supplied custom strategy definitions).**

### Fix #6 — grype force_rescan

- **Rule #52 angle:** None. The grype service at `backend/app/services/grype_service.py:60-265` is a thin wrapper around `grype sbom:<path>` subprocess invocation. There's no dispatch surface, no per-format branching, no extensible vocabulary. The fix is a single signature parameter addition (`scan_with_grype(firmware_id, project_id, db, *, force_rescan: bool = False)`) plus a `delete(SbomVulnerability).where(firmware_id == ...)` block when `force_rescan=True` — mirroring the NVD-path's existing semantics at `vulnerability_service.py:82-92`.
- **Recommended shape:** **Code-only.** ~15 LOC including test.
- **LOC + complexity delta:** Minimal. No refactor candidate.

### Fix #9 — _post_process_pipeline unpack gate

- **Rule #52 angle:** **STRONGEST CANDIDATE THIS SESSION.** The `_post_process_pipeline` at `backend/app/services/firmware_service.py:544-822` contains a 270-line IF-ELIF chain hard-coding extraction-strategy selection:
  - Line 589 (`is_tar`) → tarball-shortcut path (line 590-657)
  - Line 663 (`is_zip` + branches) → rootfs-ZIP path (line 685-706) | Android-OTA path (line 707 fallthrough) | generic-ZIP path (line 707-759)
  
  Even worse, the deeper unpack worker at `backend/app/workers/unpack.py:413-720+` has a SECOND hard-coded chain dispatching on `classify_firmware()` output (`fw_type == "android_apk"` / `"uefi_firmware"` / `"intel_hex"` / `"rtos_blob"` / `"android_boot"` / `"partition_dump_tar"` / `"linux_rootfs_tar"` / etc.). This is the same structural anti-pattern that file-format catalog replaced — operator-extensible adaptability is the entire premise. Adding a new firmware format today is a multi-file code change touching at least `unpack_common.py:classify_firmware`, `unpack.py:_unpack_firmware_inner`, and `firmware_service.py:_post_process_pipeline`. With the proposed refactor, adding a new format would be ONE YAML file (already partly true for detection via file-format catalog, but extraction strategy still requires code).
  
- **Closed-grammar shape candidate:**
  
  **Pydantic model** (`backend/app/schemas/extraction_strategy.py` — new file):
  ```
  schema_version: 1
  strategy_id: str  # snake_case unique key (e.g. "tarball_shortcut")
  manifest_source: ManifestSource  # _system | core | operator | attested_external | unauthenticated_external
  precedence: int  # tie-break within tier
  applies_to:
    detected_formats: list[str]  # cross-ref file_format_catalog format_id
    classify_firmware_types: list[str]  # legacy fw_type strings for transition period
  extraction:
    handler: ExtractionHandler  # closed Literal — see below
    handler_config:
      # Sub-model per ExtractionHandler with discriminated-union validation
      # (Rule #52 Wave-2 W2-β §SC5-NEW pattern — sub-model + symmetric-reject)
      tarball_shortcut?: TarballConfig
      zip_rootfs?: ZipRootfsConfig
      zip_generic?: ZipGenericConfig
      binwalk_fallback?: BinwalkConfig
      unblob_fallback?: UnblobConfig
      qemu_img_convert?: QemuImgConvertConfig  # vhdx etc.
      cabextract?: CabextractConfig
      androguard_apk?: AndroguardApkConfig
      msi_table_extract?: MsiTableConfig
      tibx_sidecar?: TibxConfig  # Exception-3 BYO container
      ...
  post_extraction:
    next_actions: list[PostExtractionAction]  # closed Literal — see below
    # e.g. [walk_filesystem_root, detect_architecture, populate_detection_roots,
    #       fire_walker_auto_triggers]
  resource_limits:
    max_extraction_size_mb: int  # default 10240 (10 GB)
    max_extraction_files: int  # default 100_000
    timeout_seconds: int  # default 600
    max_compression_ratio: float  # default 100.0
  ```
  
  **Closed Literals** (extension via Rule #25 Shape-1 alignment commits):
  - `ExtractionTier`: `["shortcut_clean", "shortcut_recursed", "fast_path", "generic_fallback", "byo_sidecar"]` — note: this is the ADAPTIVE_BACKLOG `prior-2026-05-18:RvwC-CC-2` entry's enum, repurposed at higher granularity.
  - `ExtractionHandler`: `["tarball_extractall", "zip_rootfs_extract", "zip_generic_with_recursion", "binwalk_subprocess", "unblob_subprocess", "androguard_apk_copy", "uefi_extract", "qemu_img_convert", "cabextract_subprocess", "msi_table_extract", "msu_chain_extract", "vhdx_qemu_convert", "tibx_sidecar_container", "intel_hex_convert", "rtos_blob_inline", "android_ota_extract", "android_sparse_extract", "android_boot_extract", "android_scatter_extract"]`. ~20 entries seeded from the existing fw_type branches.
  - `PostExtractionAction`: `["walk_filesystem_root", "detect_architecture", "detect_os_info", "detect_kernel", "populate_detection_roots", "fire_walker_auto_triggers", "recursive_nested_archive_expand", "widen_read_perms", "diagnose_failed_archives", "stamp_extraction_diagnostics"]` ~10 entries.
  - `DispatchKind` (extension carry-over to extraction): `by_classify_firmware_type` / `by_file_format_id` / `by_first_signal_match`.
  
  **YAML directory:** `backend/app/services/extraction_strategy_catalog/data/extraction_strategies/{vendor}/{strategy_id}.yaml`. Vendor partitions mirror file-format catalog. `_system/tarball_shortcut.yaml`, `_system/zip_rootfs.yaml`, `_system/binwalk_fallback.yaml`, etc. for the in-tree precedent.
  
  **Resolver:** `extraction_strategy_catalog/resolver.py` with closed dispatch over `STRATEGY_HANDLERS: dict[ExtractionHandler, _StrategyHandler]` — mirroring `SIGNAL_EVALUATORS` / `DISPATCH_EVALUATORS` shape. Each handler is a closed `Callable[[ExtractionContext], ExtractionResult]`.
  
  **Cross-feature gates (Rule #52 W2-β analogs):**
  - **A1 (pairwise consistency)** — every `applies_to.detected_formats` entry must exist as a `format_id` in the file_format_catalog snapshot (cross-feature validation at catalog load time).
  - **A2 (handler-config-discriminated-union)** — exactly ONE `handler_config.<X>` sub-block declared, matching `extraction.handler`; symmetric-reject pattern from P3.2.b TextFormatConstraint precedent.
  - **A3 (post-extraction-action-monotonicity)** — `next_actions` must be a topologically-valid order (walk_filesystem_root BEFORE detect_architecture BEFORE fire_walker_auto_triggers).
  - **A4 (resource-limit-floor)** — operator-tier strategy cannot set `max_extraction_size_mb > 50_000` or `timeout_seconds > 1200` (defense against operator-overlay DoS at the unpack worker tier).
  - **A5 (Exception-3 BYO opt-in)** — strategies using `tibx_sidecar_container` or analogous sidecar handlers must declare `requires_byo: true` and surface a clear `byo_env_var` for operator setup (mirrors `WAIRZ_TIBX_AGENT_PATH` pattern at Rule #36 Exception 3).
  
- **LOC estimate:**
  - Schema (`schemas/extraction_strategy.py`): ~400 LOC (20 closed Literals + 15 handler-config sub-models with `extra="forbid"` + validators).
  - Catalog loader (`extraction_strategy_catalog/catalog.py`): ~600 LOC mirroring file-format-catalog at ~604 LOC.
  - Resolver (`extraction_strategy_catalog/resolver.py`): ~800 LOC mirroring file-format resolver at 1008 LOC, simpler because no dispatch chains.
  - Closed handlers: ~1200 LOC factoring the existing 20+ extraction code-paths into independent handler functions.
  - YAML seed manifests: 20 YAMLs × ~40 lines = ~800 LOC.
  - Tests + Rule #46 META-CANARIES: ~800 LOC mirroring file-format-catalog test density.
  - **Total: ~4600 LOC net add** (with some offsetting deletions in unpack.py / firmware_service.py — net delta likely +3000 LOC).
  
- **Promotion to Rule #52 Rule-of-Three?** See below — there's a race with ICS Session 2 for this slot.

### Fix #11 — Walker reaper sweep

- **Rule #52 angle:** **Weak candidate.** The reaper config IS data-shaped (per-status-column grace-window + error-message template + transition state), but the existing infrastructure at `backend/app/main.py:120-310` already derives the column list from architectural knowledge of `Firmware`'s state-machine columns. Closed-grammar refactor would add packaging — a `reaper_config.yaml` declaring `{column_name: grace_minutes, error_template, eligible_states}` — but doesn't unlock new adaptability (operators don't write custom firmware-row state machines).
- **Better partner:** The proposed Fix #11 shape from W2-α Fix #5 (`backend/app/main.py:200-242` reaper derives from `walker_registry.WALKER_AUTO_TRIGGERS`) is more natural. Each walker registers a tuple `(column_name, grace_minutes, error_template)` alongside its safe-runner registration in `walker_registry._load_walker_safe_runners` (`backend/app/workers/walker_registry.py:45-158`). The reaper iterates the same registry to derive its work. This is Rule #47 consumer-hook enumeration partner — when adding a walker, you ALWAYS register the reaper config in the same commit.
- **Recommended shape:** **Hybrid.** Extend `WALKER_AUTO_TRIGGERS` to carry per-walker reaper config; do NOT lift to YAML. The dispatch surface here is Python-level (the reaper is a Python lifespan startup hook) and adding YAML adds round-trip cost without operator extensibility benefit.

### Broader create_task GC sweep

- **Rule #52 angle:** None. The fix is mechanical — replace bare `asyncio.create_task(coro)` calls with the existing `_spawn_background_task(coro, name=...)` helper at `backend/app/routers/sbom.py:31-34` (which captures a strong reference per Rule #51 §SC5-NEW-SBOM). Found via grep: `backend/app/services/firmware_service.py:818`, `backend/app/routers/firmware.py:175`, `:297`, `:436`, `:441` — 5 sites total in the regression window. Pure code substitution.
- **Recommended shape:** **Code-only.** ~10-15 LOC total.

## YAML-ify Decision Matrix

| Fix | Pure code | Hybrid | Closed-grammar YAML | Recommended |
|---|---|---|---|---|
| Fix #1 (SBOM /generate Rule #33) | ✓ | — | — | **Code-only** — Strategy pattern already adaptable at Python level; Rule #33 mechanical |
| Fix #6 (grype force_rescan) | ✓ | — | — | **Code-only** — single signature param + delete block |
| Fix #9 (_post_process_pipeline unpack gate) | — | — | ✓ | **Closed-grammar — DEFER to multi-session campaign** — 4600 LOC, Rule-of-Four slot |
| Fix #11 (walker reaper sweep) | — | ✓ | — | **Hybrid** — extend `WALKER_AUTO_TRIGGERS` registry entries with reaper config; do NOT lift to YAML |
| create_task GC sweep | ✓ | — | — | **Code-only** — `_spawn_background_task` substitution |

## Rule #52 Promotion Math

- **Current state (2026-05-21):** Rule-of-Two DURABLE BEYOND DEBATE.
  - Instance #1: Bare-metal MCU/DSP (`bare_metal_walker.py` + `chip_catalog.py` + `data/chip_families/`)
  - Instance #2: File-format YAML registry (`file_format_catalog/` + `data/file_formats/`)

- **ICS Session 2 candidate:** Rule-of-Three claim.
  - Source: `.planning/postmortems/postmortem-ics-protocol-session1-2026-05-20.md` lines 14-16 ("Session 2 ships the walker + MCP tools + ORM + alembic + finding-source alignment + Rule #52 Rule-of-Three promotion").
  - Status: Session 1 (scaffold) shipped — schema + catalog + resolver + 1 production Modbus/TCP YAML + 114 tests, commits `0dabbd6..1d0d0a9` (2026-05-20).
  - Remaining work: walker (Rule #39 triplet) + ORM columns + alembic migration + JSONB normaliser + orphan reaper + Rule #25 Shape-1 finding-source alignment + MCP tool category (Rule #44 mandatory `lookup_ics_protocol_across_firmwares`) + 2 plugins (string-scanner + library-symbol scanner) + remaining 2 protocols (DNP3 + S7Comm).
  - Estimated remaining LOC: ~3000 per W2-γ yardstick.
  - **ICS Session 2 holds the Rule-of-Three slot legitimately.** Postmortem line 148 ("Rule #52 Rule-of-Three promotion") is explicit; Session 1 substrate is already 4500 LOC live.

- **This session candidate (Fix #9 extraction-strategy refactor):** Rule-of-Three OR Rule-of-Four slot.
  - **DOES THIS SESSION SHIP IT?** **NO.** Fix #9 at the closed-grammar scale is a 4600-LOC multi-session campaign requiring Wave-1 + Wave-2 deep research (Rule #52 methodology per `feedback_wave2_cross_feature_methodology.md`). Session 2's actual scope per the task is: SBOM `/generate` Rule #33 + grype `force_rescan` + `_post_process_pipeline` unpack gate (per W2-α Fix #3 — un-gating the walker fan-out, NOT refactoring the extraction strategy) + walker reaper sweep + create_task GC sweep. The original Fix #9 W2-α scope is the SMALLER fix (`unpack.py:106` early-exit gate removal at ~10-25 LOC), not the full Rule #52 closed-grammar refactor.
  - **CAN IT SLOT FOR A FUTURE SESSION?** YES — and it's a strong candidate. The proposed `extraction_strategy_catalog/` would be Rule #52's most architecturally interesting application yet because it bridges file_format_catalog (detection layer) and walker_registry (post-extraction analysis layer). Rule #52 Rule-of-Four would be DURABLE BEYOND DEBATE after this ships.

- **Race condition: do they collide?**
  - **NO.** ICS Session 2 has runway to ship by end of May (Session 1 shipped 2026-05-20; Session 2 sized at ~3000 LOC fits a 4-6 hour session). The Fix #9 extraction-strategy refactor would target June/July at earliest — needs its own Wave-1+Wave-2 research phase (a la P3.1 + P3.2 + ICS Session 1).
  - **Order:** ICS Session 2 ships → Rule #52 graduates to Rule-of-Three DURABLE BEYOND DEBATE → backlog the extraction-strategy campaign → Rule-of-Four DURABLE BEYOND DEBATE after that ships.
  - **Stack effect:** Each successive Rule #52 application reinforces the pattern; Rule-of-Four would lock in "closed-grammar dispatch + plugin escape hatch + cross-feature gates" as the wairz house style for adaptable surfaces.

- **Verdict:** **DO NOT attempt to promote Rule #52 to Rule-of-Three in this session.** Fix #9 in this session is the SMALLER scope (W2-α Fix #3 walker fan-out un-gating ~10-25 LOC). The closed-grammar refactor is a multi-session campaign that should be QUEUED in `.planning/ADAPTIVE_BACKLOG.md` as `prior-2026-05-21:RuleOf4-extraction-strategy-catalog` with explicit dependency on ICS Session 2 closing the Rule-of-Three slot first.

## Cross-References

1. `backend/app/services/bare_metal_walker.py:1-40` — Rule #52 Instance #1 walker docstring + architecture
2. `backend/app/services/bare_metal_walker.py:255-267` — POLICY_EVALUATORS closed dispatch
3. `backend/app/services/hardware_firmware/chip_catalog.py:1-100` — Instance #1 mtime-cached YAML catalog
4. `backend/app/services/hardware_firmware/data/chip_families/ti/tms320f28066.yaml:1-100` — Instance #1 production YAML
5. `backend/app/services/file_format_catalog/__init__.py:1-53` — Instance #2 package re-exports
6. `backend/app/services/file_format_catalog/resolver.py:542-556` — Instance #2 SIGNAL_EVALUATORS closed dispatch
7. `backend/app/services/file_format_catalog/resolver.py:679-686` — Instance #2 DISPATCH_EVALUATORS closed dispatch
8. `backend/app/services/file_format_catalog/resolver.py:694-713` — Instance #2 MatcherProto plugin escape
9. `backend/app/services/file_format_catalog/resolver.py:761-764` — Instance #2 `freeze_plugin_registry` (W2-β attack I closure)
10. `backend/app/services/file_format_catalog/data/file_formats/_system/linux_squashfs.yaml:1-36` — Instance #2 production YAML
11. `backend/app/services/firmware_service.py:544-822` — Fix #9 closed-grammar candidate (`_post_process_pipeline` IF-ELIF chain)
12. `backend/app/services/firmware_service.py:589-657` — tarball-shortcut handler (would become `tarball_shortcut.yaml`)
13. `backend/app/services/firmware_service.py:663-759` — ZIP-shortcut handlers (rootfs vs generic, would become 2 YAMLs)
14. `backend/app/workers/unpack.py:413-720+` — second hard-coded fw_type IF-ELIF chain (would also fold into extraction_strategy_catalog)
15. `backend/app/workers/walker_registry.py:101-158` — Fix #11 partner (reaper config in same registry)
16. `backend/app/services/sbom/service.py:68-85` — SBOM strategy registry (already adaptable at Python level; Fix #1 not a closed-grammar candidate)
17. `backend/app/services/sbom/strategies/base.py:44-73` — `SbomStrategy` ABC (existing Strategy pattern)
18. `backend/app/main.py:120-310` — lifespan reapers (Fix #11 target)
19. `.planning/postmortems/postmortem-ics-protocol-session1-2026-05-20.md:1-150` — ICS Session 1 postmortem (Rule-of-Three claim line 148)
20. `.planning/research/sbom-vuln-scan-regression-2026-05-21/wave2-alpha-convergence.md:127-188` — Session 2 fix enumeration (Fix #1-#6)
21. `.planning/ADAPTIVE_BACKLOG.md:119` — `prior-2026-05-18:RvwC-CC-2` extraction_strategy enum entry (related; this rule scales it up)
22. `backend/app/services/ics_protocol_catalog/data/ics_protocols/_system/modbus_tcp.yaml:1-80` — ICS Session 1 production YAML (Rule #52 instance #3 in flight)

## Closing Note on "Don't Over-Apply Rule #52"

Rule #52 is correctly applied when:
- The surface is **operator-extensible without Python access** (third parties / partners / advanced ops authors YAML).
- The closed grammar is **finite and small** (≤20-30 closed Literal values per dimension; sub-models per dispatch shape).
- **Adaptability is the load-bearing virtue** (the operator's mandate this session: "we won't be the only ones ingesting files into the tool").
- **Plugin escape hatch is genuinely needed** for the open-vocabulary subset (RTOS families, custom string scanners, BYO sidecar binaries).

Rule #52 is OVER-APPLIED when:
- The surface is already adaptable at the Python level via existing protocols / ABCs (SBOM strategy pattern).
- The grammar would have unbounded vocabulary (regex / script / expression — Rule #52's hard ceiling).
- The closed-Literal extension cost (Rule #25 Shape-1 cross-stack alignment) exceeds the operator-extensibility benefit.

Fix #9 (extraction-strategy refactor) PASSES all four "correctly applied" tests but at a scope that exceeds this session — defer to a dedicated multi-session campaign with proper Wave-1+Wave-2 research methodology. Fix #1 / Fix #6 / Fix #11 / create_task sweep FAIL the four tests in various ways — ship as code-only or hybrid changes. The discipline this session: ship Session 2's straight Rule #33 + grype + walker un-gating + reaper + GC sweep fixes; queue the extraction-strategy refactor as a Rule-of-Four candidate after ICS Session 2 closes Rule-of-Three.
