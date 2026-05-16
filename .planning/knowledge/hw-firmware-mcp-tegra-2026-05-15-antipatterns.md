# Anti-patterns: HW-Firmware list_extension_points + Tegra Parser + CVE Pins — 2026-05-15

> Extracted: 2026-05-15
> Campaign: ad-hoc Citadel-driven session
> Postmortem: `.planning/postmortems/postmortem-hw-firmware-mcp-tegra-2026-05-15.md`

## Failed Patterns

### 1. Accepting user-prompt CVE-attribution claims without per-NVD verification
- **What was done:** The session's TARGET 3 spec arrived with 6 named CVEs + per-CVE attribution claims (chipset family, fix version, product). Implementing the pins verbatim per the user's text would have shipped 3 wrong attributions:
  - CVE-2021-1111 user said "ALL Jetsons"; NVD CPE explicitly EXCLUDES TX1/Nano/Nano-2GB (only AGX-Xavier + TX2 + TX2-NX + Xavier-NX in hardware anchors).
  - CVE-2021-34372 user said `product=tegra_tos_trusty`; NVD CPE uses `product=jetson_linux` (and the curated `families:` schema has no `product:` field).
  - CVE-2022-42269 user said "AGX-Xavier/TX2/Xavier-family"; NVD CPE ALSO includes `jetson_tx1`.
- **Failure mode:** Without per-CVE NVD-CPE verification, CVE-2021-1111 would over-attribute to every TX1 + Nano firmware blob (especially harmful for Nano, the highest-volume Jetson SKU); CVE-2022-42269 would under-attribute on TX1 firmware (missing a legitimately-affected silicon); CVE-2021-34372 would ship with a non-existent schema field.
- **Evidence:** Scout 3's research notes cited the NVD URLs + verbatim CPE entries; the implementing developer independently re-fetched via WebFetch before committing. Reviewer B re-verified post-implementation as a recursive-discipline canary.
- **How to avoid:** Per Rule #19 evidence-first, EVERY CVE-attribution claim — whether from user prompt, scout report, reviewer finding, vendor advisory, or LLM summary — gets the direct NVD URL fetch BEFORE pinning. The 2026-05-18 session established the discipline for scout reports + reviewer findings; this session extended it to **user-prompt-claim verification**. The discipline is recursive across all claim sources. Cost: ~30 sec per CVE via WebFetch; carries zero risk; eliminates the over-attribution / under-attribution failure mode at every layer.

### 2. Shipping CVSS field values from scout summaries without per-NVD primary verification
- **What was done:** Initial Tegra CVE pins shipped with CVSS scores from Scout 3's research summary, not from independent NVD primary CVSS fetch. Two pins drifted:
  - CVE-2021-1111 shipped `cvss_score: 6.0`; NVD primary (NVIDIA CNA CVSS 3.1) is **6.7 MEDIUM**. Off by 0.7.
  - CVE-2021-34397 shipped `severity: medium / cvss_score: 5.5`; NVD primary (NIST CVSS 3.1) is **LOW / 2.3**. Off by 3.2 points + 1 severity tier (overrated).
- **Failure mode:** Severity-tier overrating distorts operator triage — CVE-2021-34397 would have surfaced as MEDIUM in the UI rather than LOW, drawing attention away from genuinely higher-impact findings. Numeric-field drift on attribution-critical CVEs erodes the per-NVD verifiability discipline (operators auditing the pin would notice the mismatch with NVD and lose trust in the curated tier).
- **Evidence:** Reviewer B forensic-domain review independently fetched NVD primary CVSS for each pin and surfaced both drifts.
- **How to avoid:** The per-NVD recursive-verification discipline extends to ALL numeric fields, not just attribution scope. Scout summaries CAN drift on CVSS / severity / score / vector. The NVD page's "CVSS V3 Metrics" section is the primary source. Ship a regression-canary test (`test_tegra_cve_pins_cvss_scores_match_nvd_primary`) that asserts each pin's CVSS field matches NVD primary — fails fast on any future drift introduced by casual edits.

### 3. Missing the 5th failure path in `last_warning` (file vanish after successful load)
- **What was done:** Initial `MtimeCachedYamlLoader.last_warning` populated on 4 failure paths (stat OSError, YAMLError, top-level type-check, parser-validation). The 5th failure path — file vanished after a successful load (`_handle_missing` when `_loaded_from_yaml=True`) — was missed.
- **Failure mode:** The `list_extension_points` MCP tool reads `loader.last_warning` to report load state. Without this fix, an operator who deletes their YAML mid-edit (or whose ConfigMap remount drops the file briefly) would see `status="loaded"` / `last_warning=null` in the MCP output, directly contradicting HOT-2's "operators see WHY their state silently fell back" goal. The WARN log fires (operator-invisible without shell access); the operator-facing MCP says "everything looks fine."
- **Evidence:** Reviewer A architecture review explicitly enumerated the 4 paths + flagged the missing 5th. Existing test `test_file_vanish_after_successful_load_keeps_previous_state` only asserted state preservation, not `last_warning` population.
- **How to avoid:** When implementing an operator-visibility primitive over a multi-path failure surface, enumerate ALL paths exhaustively — not just the "obvious" ones. The Reviewer A discipline applies: walk the called function's exception/conditional branches + assert every branch that triggers a WARN log ALSO populates the operator-visibility field. Paired-canary test for every branch (this session added 2 new canaries for the vanish path: populate-on-vanish + clear-on-restore).

### 4. Hard-coding the same logical concept at two sites without an alignment test
- **What was done:** `_BT_PARSER_FAMILIES` (frozenset) in `patterns_loader.py` and `BT_PARSER_FAMILIES` (tuple of dicts) in `parsers/bt_firmware_banner.py` carry the same logical concept — the list of valid BT parser families — in two places. A future contributor adding a 5th family who updates only one site causes either silent rejection of valid YAML pins (patterns_loader side missed) OR a phantom family in MCP output (bt_firmware_banner side missed).
- **Failure mode:** No runtime error; just silent drift between the validation gate and the operator-facing discovery surface. The bug surfaces on operator complaint ("I added a pin under family: amlogic_bt and it doesn't load") OR via an MCP user noticing the tool reports families that the YAML schema rejects.
- **Evidence:** Reviewer C adaptability review surfaced both sites + flagged the drift risk.
- **How to avoid:** When the same logical concept lives in two in-tree sites, EITHER (a) refactor to a single source via runtime-derivation (lazy-import) OR (b) ship an alignment test that asserts the two sites stay in sync. This session chose (b) because (a) is complicated by circular imports between the two modules. The Rule #25 cross-stack-alignment-commit shape applied as a per-edit gate.

### 5. Standalone-script detection invocation missing explicit commit
- **What was done:** During end-of-session verification, the standalone Python script invoked `detect_hardware_firmware()` from inside an `async_session_factory()` context manager WITHOUT a trailing `await db.commit()`. The function uses `db.flush()` per Rule #3 (the caller owns the transaction); without commit, exit of the `async with` block rolled back the flush.
- **Failure mode:** `detect_hardware_firmware()` returned 99 (the number of blobs flushed); subsequent SQL query showed 0 blobs (rolled back). Mid-session debugging would chase phantom regression-bug ghosts ("the new Tegra parser broke detection!") before realizing the verification script itself dropped the writes.
- **Evidence:** SQL audit revealed 0 rows for a function call that returned 99. Adding `await db.commit()` + re-running confirmed 99 rows persisted.
- **How to avoid:** When invoking flush-using service functions from a standalone async script (NOT a router handler), the standalone caller MUST `await db.commit()` before exiting the context manager. Per Rule #3, the inner function flushes; the outer caller commits. The discipline is "outside-a-router = you commit". Pair every standalone script's service-function invocation with an explicit commit, OR wrap in a helper that handles the commit centrally.

### 6. Trusting filename-only Tegra patterns without a content-evidence overlay
- **What was done:** Pre-2026-05-18, 24 filename-only Tegra patterns shipped in `firmware_patterns.yaml` (commit 3000a9e). Operators renaming Tegra blobs (intentionally or via vendor packaging) would silently miss classification.
- **Failure mode:** Hidden under-attribution. An operator uploading a Tegra firmware with `foo.bin` (operator-renamed bpmp.bin) would see vendor=unknown, missing CVE attribution against the entire NVIDIA Tegra subsystem.
- **Evidence:** Reviewer A C1 + Reviewer C TEG-1 (postmortem 2026-05-18) called for the content-evidence parser; the session shipped it as TARGET 2. End-to-end DS1 detection confirmed the parser correctly classified operator-renamed DTBs via FDT compatible-string scan (44/99 blobs).
- **How to avoid:** When shipping classifier patterns for a new vendor family, queue a follow-up content-evidence parser commit. Pattern #3 of postmortem-2026-05-18 already documented this; the 2026-05-15 session shipped the deferred follow-through. Filename-only patterns are FAST PATH (cheap to add); content-evidence parsers are CORRECTNESS PATH (catches operator-modified inputs). Both are needed.

### 7. Letting forward-prepared CVE pins relax their version_regex to "fire-on-vendor-alone"
- **What was done:** The 6 Tegra CVE pins were initially considered with version_regex that would match a broad range of L4T release strings. After Reviewer B discipline review, the chosen shape ships STRICT version_regex (e.g. `(?i)(r3[01]\b|r32\.[0-4]\b|r32\.5\.0\b|...)` for the CVE-2021-34372 < R32.5.1 case) that doesn't fire on the current corpus because the Tegra parser doesn't extract L4T release.
- **Failure mode that was AVOIDED:** Relaxing the version_regex to fire on ALL Tegra blobs of the matching chipset family — would have over-attributed CVE-2021-1111 to TX2 firmware running R32.6.1+ (the FIXED versions), CVE-2019-5680 to TX1 firmware running R32.2+ (the FIXED versions), etc. Each false-positive row dilutes operator trust in the curated tier.
- **Evidence:** The shipped pins (commit `6bc1c1d`) carry strict version_regex + explicit "Forward-Prepared Note" in the YAML header explaining activation conditions. 0 rows fired post-rebuild; the pins activate when L4T-release-extraction lands.
- **How to avoid:** When the version-discriminator data isn't yet extracted from blob content, the right call is STRICT version_regex + forward-prepared documentation. Over-attribution is materially worse than under-attribution for operator trust (Reviewer B 2026-05-17 discipline). Activation deferred to a follow-up commit when the prerequisite extraction lands; the YAML header documents the activation path.

### 8. Reading private attributes of another module's class from inside an MCP tool handler
- **What was done:** `_surface_state_payload` in `tools/hardware_firmware.py` reads 4 private attrs of `MtimeCachedYamlLoader`: `_cached_mtime_ns`, `_loaded_from_yaml`, `_cached`, `_summary`. This is exactly the abstraction-boundary violation Reviewer A's 2026-05-18 finding warned about — the tool layer reaches INTO the cache implementation rather than calling a public API.
- **Failure mode:** Any rename or refactor in `yaml_cache.py` (e.g. promoting `_cached_mtime_ns` to `_atomic_mtime` for an mmap-based variant) silently breaks the MCP tool — `getattr(..., None)` returns None on every entry, surfacing as "all surfaces report yaml_mtime_iso=null / status=defaults" with no exception. The defensive `getattr(..., None)` shape MASKS the failure mode.
- **Evidence:** Reviewer A A6 + A7 findings; deferred to a follow-up `state_snapshot()` method refactor (~40 LOC).
- **How to avoid:** Future-author: when a tool needs N fields from another module's class, ADD a public method on that class returning a dict — don't reach into private attrs via `getattr(loader, "_field", None)`. The defensive `getattr` shape silently masks future renames; a public method tracks rename signals via test failures.

### 9. Forgetting that detected blobs need `db.commit()` AFTER `db.flush()` in standalone scripts
- See Anti-pattern #5. Symptom is the same shape; lesson is the same.

### 10. `_stringify_metadata` only walks one level deep, so nested-dict metadata is invisible to version_regex
- **What was done:** The 6 Tegra CVE pins use `version_regex` that matches against `blob.version` OR any value in `_stringify_metadata(blob.metadata_)`. But the current implementation walks only ONE LEVEL deep — nested dicts (e.g. `metadata["tegra_blob"]["l4t_release"]`) are invisible. Even when a future L4T-release-extraction commit lands, if it stores the value inside the nested `tegra_blob` dict, version_regex still won't fire.
- **Failure mode:** Activation of the forward-prepared Tegra pins would silently fail. Operators would extend `tegra_blob.py` to extract L4T release, run cve-match, and see 0 Tegra-CVE rows — without understanding why.
- **Evidence:** Reviewer B B4 finding; the recommended fix path is to enforce that L4T release lands as `blob.metadata["l4t_release"]` (TOP-LEVEL string) so `_stringify_metadata` reaches it. The YAML Forward-Prepared Note now documents this contract.
- **How to avoid:** When designing a forward-prepared pin that depends on a future-extracted field, EXPLICITLY DOCUMENT where the field must land (top-level vs nested) so the future commit's author lands it at the right level. Alternative: extend `_stringify_metadata` to walk one level deeper — bigger change but solves the class of failure modes for all future nested-metadata pins.

## Cross-Cutting Anti-pattern Themes

1. **"Specs are candidates, not truth — even when shipped by experts."** This session's user-prompt CVE claims were partially wrong on 3 of 6 CVEs. Prior sessions caught scout-report errors + reviewer-finding errors. The discipline countermeasure is mechanical: every CVE-attribution claim → fetch the NVD CPE list. Cost trivial; protection unbounded.

2. **"Numeric fields drift as easily as scope claims."** CVSS field values shipped from Scout 3's summary drifted from NVD primary by 0.7 points (CVE-2021-1111) and 3.2 points + 1 severity tier (CVE-2021-34397). Per-NVD discipline applies to ALL numeric fields, not just attribution scope. Regression-canary tests fail fast on any future drift.

3. **"Operator-visibility primitives need exhaustive failure-path enumeration."** The `last_warning` field initially missed the 5th failure path (file vanish). A field that's "operator-visible by design" silently absent on a real failure path defeats its own purpose. Walk every conditional/exception branch + assert population.

4. **"Two sites for the same logical concept need an alignment test."** Hard-coded constants drift silently. Cross-stack alignment tests catch drift at CI; runtime-derivation eliminates drift but requires careful circular-import handling. Both are valid — choose based on import structure.

5. **"Standalone async scripts own the commit."** Flush-using service functions delegate commit-ownership to the caller. Outside-a-router callers must explicitly commit before context exit. Easy to miss; pairs with Rule #3 semantics.

6. **"Filename-only attribution is the FAST PATH; content-evidence is the CORRECTNESS PATH."** Both are needed. Filename patterns cover the common case cheaply; content parsers catch operator-modified inputs. Queue a content-parser follow-up whenever filename patterns ship for a new vendor family.

7. **"Forward-prepared pins ship documented activation conditions, not relaxed regex."** Over-attribution is worse than under-attribution. Strict version_regex + Forward-Prepared Note is the right shape when the version-discriminator data isn't yet extracted; activation is a follow-up.

8. **"Private-attribute access from another module is silent-future-breakage."** Add a public state-snapshot method instead. The defensive `getattr(..., None)` shape masks rename signals.

9. **"Multi-persona reviewer dispatch is durable beyond debate — 5 sessions running."** 2026-05-15 (BTFM correction), 2026-05-16 (BT banner parser), 2026-05-17 (BT YAML externalization + recursive Reviewer B CVE catch), 2026-05-18 (recursive Reviewer B Selfblow catch), 2026-05-15-PM (3 user-prompt-discrepancy catches + 2 CVSS-field drift catches). Cost ~5-10 min per session; value: multiple structural drift surfaces caught that single-axis review misses.

10. **"`_stringify_metadata` one-level-deep is a class-of-failure trap for nested-dict metadata."** Forward-prepared pins depending on future-extracted nested fields silently fail. Document the contract (top-level vs nested) OR extend the walker. Either solves the class.
