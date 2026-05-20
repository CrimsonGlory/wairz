# Anti-patterns: file-format YAML registry P3.2 (2026-05-19)

> Extracted: 2026-05-19
> Campaign: .planning/research/file-format-yaml-registry-p32-final-convergence-2026-05-19.md (direct-shipped)
> Postmortem: .planning/postmortems/postmortem-file-format-yaml-registry-p32-2026-05-19.md

## Failed Patterns

### 1. Naive `is_always_match` boolean flag for resolver sort key (REJECTED at design time)
- **What was done:** Postmortem proposed `(0 if not is_always_match else 1, -source_rank, ...)` to put sentinels last.
- **Failure mode:** Hardcodes sentinel-detection policy into resolver Python while pretending the schema is closed. Two `always_matches: true` manifests would ship with subtly different sort intent and the resolver couldn't tell them apart.
- **Evidence:** S1-P3.2 verdict explicitly rejected (b)-vs-(a) decision matrix in `file-format-yaml-registry-p32-wave1-S1-sort-tier-2026-05-19.md`.
- **How to avoid:** Use schema-driven `sort_tier: Literal[...]` declared in YAML; the resolver becomes a pure mechanical sort over the closed Literal. Operator intent on the manifest, not derived from a runtime side-condition.

### 2. Closed `RTOS_FORMAT_MAP: dict[Literal[rtos_name], str]` (REJECTED at design time)
- **What was done:** S1-Phase-3.1 recommendation to close the dynamic `f"{rtos_name}_elf"` format string via a closed Python Literal mapping the 9 bundled RTOS families to format_ids.
- **Failure mode:** **Anti-Rule-#52** — partner contribution gated on a wairz core merge per new RTOS family; the `rtos_family` value is not "executable Python" (it's a LOOKUP KEY in a dispatch table), so closing it violates the "closed grammar where YAML maps to executable Python" cap of Rule #52.
- **Evidence:** S3-P3.2 verdict cites user direction "don't hardcode strict formats" + audit showing the `f"{rtos_name}_elf"` string has zero typed consumers (just one `.endswith("_elf")` check) — closing it adds a new HARD-TYPED surface that doesn't exist today.
- **How to avoid:** HYBRID — plugin returns free-string `rtos_family: str` via typed `RtosDetection` dataclass; resolver stashes on ContextVar; new `DispatchKind="by_rtos_family"` evaluator maps family → format_id via YAML `dispatch.cases` (operator-extensible). Soft `RTOS_FAMILY_ADVISORY: frozenset[str]` WARNs at catalog load on unregistered families; never rejects.

### 3. `more_specific_than: list[FormatId]` partial-order DAG (REJECTED at design time)
- **What was done:** S2 explored partial-order DAG as alternative grammar to numeric `precedence` — each manifest declares `more_specific_than: [<other_format_ids>]`.
- **Failure mode:** **§SC5 re-occurrence** per S5 + W2-β — operator-supplied manifest could declare `more_specific_than: ["_system/linux_blob_fallback"]` to leapfrog the sentinel floor; cycles risk; cross-vendor specificity claims unclear.
- **Evidence:** S2 + S5 + W2-β cross-validated rejection; LOC cost 254 (partial-order DAG) vs 111 (keep-precedence-flip-sort-direction) for the same user-visible correctness win.
- **How to avoid:** Keep numeric `precedence: int` + add optional documentary `precedence_tier` Literal field (deferred to P3.3) + flip resolver sort direction (1-LOC). Partial-order grammars open §SC5-class attack surfaces without commensurate gain.

### 4. `WAIRZ_FORMAT_PLUGIN_PATH` env-var without side-container isolation (DEFERRED to P4)
- **What was done:** dissect.target precedent recommended an out-of-tree Python plugin loader via env-var path; would let operators ship plugins outside the wairz core.
- **Failure mode:** Operator-controlled Python loaded at lifespan = **Rule #36 + Rule #45 + §SC5 triple-breach**. binwalk CVE-2022-4510 (plugin-drop in operator config dir) is the direct precedent.
- **Evidence:** S3 + S5 unanimous deferral; W2-α confirmed. Plugin loading from an env-var path can't be made safe under operator-hostile threat model without a Rule #36 Exception 3 side-container (separate container, network_mode: none, cap_drop: ALL, etc.).
- **How to avoid:** DEFER to P4. When shipped: side-container with explicit operator opt-in via bind-mount; named volume for parse output handoff; never load operator-supplied Python in the worker process directly.

### 5. terminator_record_hex byte-count error in intel_hex.yaml (caught in-session)
- **What was done:** Original `terminator_record_hex: "3a30303030303030303146460a"` for Intel HEX EOF record — 13 hex pairs / 26 chars / 13 bytes.
- **Failure mode:** **One extra `30` byte** — Intel HEX EOF is `:00000001FF\n` = 12 bytes (`:` + 7×`0` + `1FF` + `\n`); hex encoding should be 24 chars. The 13th byte (extra `0`) made the tail-scan `term_record not in tail` check fail against every valid Intel HEX blob.
- **Evidence:** Resolver smoke test against a hand-crafted Intel HEX blob returned `linux_blob` (floor sentinel) instead of `intel_hex`; investigation revealed the YAML's hex string was 1 byte too long.
- **How to avoid:** When authoring `terminator_record_hex` (or any byte-counted hex field), VERIFY the byte count matches the intended ASCII representation by counting each character. For Intel HEX EOF: `:` + `00` (length) + `0000` (address) + `01` (type) + `FF` (checksum) = 11 ASCII chars + `\n` = 12 bytes = 24 hex chars. A Rule #46 paired META-CANARY synthesizing valid + invalid EOF records could catch this at test-authoring time.

### 6. TI-TXT block-header format incompatibility with strict per-record evaluator (deferred)
- **What was done:** Wrote `_system/ti_txt.yaml` with `record_start_byte_hex: "40"` (`@`) + `min_first_block_records: 2`; expected the evaluator to count `@F000\n` + 1 data line as 2 records.
- **Failure mode:** `_eval_text_format`'s collection loop has `if stripped[0:1] != start_byte: break` after the first record-start line — strict per-record assumption. TI-TXT data lines DON'T start with `@` (only block headers do), so collection stops at 1 record and `min_first_block_records=2` fails.
- **Evidence:** Smoke test against `@F000\nAB CD EF\n12 34 56\nq\n` returned False from evaluator + linux_blob from resolve().
- **How to avoid:** Extend `first_line_must_match` Literal with a new value `block_header` that relaxes the strict-per-record-start requirement; ship TI-TXT YAML alongside the Literal extension + chip_family TI C28x walker wiring in a single Rule #25 Shape-1 commit. Until then, don't ship half-features (Rule #19 + Rule #28 deferral).

### 7. `dispatch.default: rtos_blob` in rtos_dispatch.yaml (caught by A6 at load time)
- **What was done:** Original `_system/rtos_dispatch.yaml` declared `dispatch.default: rtos_blob` so unknown families fall through to the generic core-tier rtos_blob manifest.
- **Failure mode:** **A6 dispatch-rank-monotonicity violation** — `_system` (rank 100) routing to `core` (rank 80) splits attestation across two tiers (`FormatMatch.manifest_source` would reflect chain ENTRY, `format_id` would reflect chain TERMINUS).
- **Evidence:** A6 catalog-load WARN fired at first load: `"rtos_dispatch" (source=_system, rank=100) routes to "rtos_blob" (source=core, rank=80) — attestation split`.
- **How to avoid:** Drop the `default` field from `_system` manifests dispatching to non-`_system` targets. The manifest's own `output.classifier_format` provides the fallback (rtos_dispatch.yaml's output.classifier_format=rtos_blob). Comment in YAML documents the design choice for future maintainers.

### 8. Schema fixture migration silently broken across 12 existing tests after sort_tier validator
- **What was done:** Added Detection model_validator `always_matches=True ⇒ sort_tier="floor"` to the schema. Existing test fixtures that declared `always_matches: true` without the matching `sort_tier: floor` started failing ValidationError at fixture construction.
- **Failure mode:** The validator worked exactly as designed; the FIXTURES were wrong. 12 tests in 3 test files (test_file_format_schema.py + test_file_format_catalog.py + test_file_format_tools.py) needed `sort_tier: floor` added.
- **Evidence:** Targeted pytest run after P3.2.a schema edits showed 12 failures with the same ValidationError message.
- **How to avoid:** When adding a new cross-field validator that requires a previously-implicit field, search ALL test fixtures for the field's parent shape + propose the migration. For wairz's catalog test corpus, `_minimal_manifest_dict` helper centralized the common case so a single helper update covered 8 of 12 fixtures; 4 inline fixtures needed targeted edits. Defense: a Rule #46 paired META-CANARY that synthesizes the always_matches + general-tier combination + asserts schema rejection (already shipped as `test_meta_canary_always_matches_implies_floor_gate_actually_fires_m4`).

### 9. Test fixtures pinning to pre-flip broken behavior (caught by broader sweep)
- **What was done:** 4 existing tests authored under the pre-flip resolver assumed specific format_ids that win under `-precedence` ordering: `test_detects_iso_9660` (expected `iso_9660`); `test_detects_tar_archive_by_extension_when_gzipped` (expected `TAR_ARCHIVE`); `test_unknown_when_no_signature_matches` (expected `UNKNOWN`); `test_classify_preserves_qcom_pil_stem` (expected `tee` category).
- **Failure mode:** Post-flip, the resolver correctly chose the MORE-SPECIFIC manifest per "lower precedence wins" — but the tests had been written when "higher precedence wins" was the behavior. Tests failed because the catalog now returned `windows_installer_iso` / `linux_firmware_blob` / `linux_firmware_blob` / `other` instead of the test's assumed legacy outputs.
- **Evidence:** Broader pytest sweep after P3.2.a resolver edits surfaced 4 unexpected failures.
- **How to avoid:** When a resolver-semantic change (sort flip, tier-rank addition, dispatch-evaluator extension) lands, expect ALL tests that pinned to specific catalog-resolution outputs to need re-validation. The fix shape: either (a) update the test expectation to match the new correct behavior, (b) add the test's expected format_id to the bridge disambiguation set so legacy fallback handles it, or (c) extend the catalog's discriminating signal so the manifest's specificity is properly expressed. P3.2.a used a mix of (a)+(b) per case.

### 10. Removing `linux_blob` from `_CATALOG_NEEDS_DISAMBIGUATION` too aggressively (caught + reverted in-session)
- **What was done:** Initial P3.2.a edit removed `linux_blob` from `_CATALOG_NEEDS_DISAMBIGUATION` thinking the catalog would now return specific formats (post-flip + sort_tier floor).
- **Failure mode:** For pre-upload `detect_format()`, the always_matches sentinel STILL matches every blob (its intended floor semantic), so post-removal `detect_format()` returned `linux_firmware_blob` for unrecognized bytes — but the pre-upload UX wants `UNKNOWN` for "I don't know what this is". The classifier path was fine (linux_blob IS a valid catalog answer there); the pre-upload path needed the bridge to convert sentinel-only-match into UNKNOWN.
- **Evidence:** test_format_detection.py::test_unknown_when_no_signature_matches failed after the removal.
- **How to avoid:** When dropping a format_id from `_CATALOG_NEEDS_DISAMBIGUATION`, distinguish the CLASSIFIER path (post-upload analysis; specific format_id is correct) from the PRE-UPLOAD detect_format() path (does this look like a known firmware; UNKNOWN for unrecognized). They have different semantics. P3.2.a kept `linux_blob` in the disambiguation set with an explicit comment explaining why.
