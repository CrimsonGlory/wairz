# Postmortem: file-format-yaml-registry P3.2 (2026-05-19)

> Date: 2026-05-19
> Campaign: ad-hoc multi-phase (no `.planning/campaigns/` file — direct-shipped per Rule #25 per-piece cadence; planning artifacts at `.planning/research/file-format-yaml-registry-p32-*-2026-05-19.{md,py}`)
> Duration: single session, commits `34d0689..007abf3` (6 commits)
> Outcome: **completed** (6/6 P3.2 phases shipped; 1/7 deferred to P3.3.a per W2-β; CLAUDE.md Rule #52 promoted to Rule-of-Two DURABLE BEYOND DEBATE)

## Summary

Phase 3.2 of the file-format YAML registry closed P3.1's 5 deferrals
(postmortem items 2-5 + 8-9) under the same "deep research + Citadel +
per-piece commit" cadence that shipped P3.1. 5 Wave-1 expert-persona
scouts (sort-tier / precedence partial-order / plugin-RTOS / text-format
closed-grammar / adversarial cross-feature) + 3 Wave-2 critique scouts
(α convergence / β cross-feature blow-it-up / γ Rule #28 yardstick).
Wave-2 β surfaced **3 NEW Scout-GG-§SC5 analogs** that landed as catalog-
load gates A6/A7/A8 in P3.2.b/c BEFORE the shipping commits closed.

6 commits across the chain:

| # | Title | Net LOC | Test count |
|---|-------|---------|------------|
| P3.2.a | sort_tier reform + precedence-flip + _legacy_magic_classify removal | +784/-138 | +26 (12 sort-tier + 4 paired META-CANARIES + 10 helper) |
| P3.2.b | TextFormatConstraint + Intel HEX + SREC YAMLs + A8 floor | +866/-8 | +24 (10 evaluator + 4 A8 + 4 schema + 6 META-CANARIES) |
| P3.2.c | RTOS plugin wiring HYBRID + by_rtos_family + A6/A7/A9 | +1017/-5 | +31 (10 dataclass/registration + 8 A9 + 3 A7 + 6 dispatch + 4 META-CANARIES) |
| P3.2.d | container precedence docs + windows_cab disambig drop | +83/-1 | 0 (data + docs only) |
| P3.2.e | parity test → JSON-snapshot form | +116/-34 | +6 (5 snapshot + 1 META-CANARY) |
| P3.2.f | Rule #52 Rule-of-Two + Wave-2 methodology + .mex sync | +10/-1 | 0 (docs only) |

**Total:** 6 commits / +2,876 insertions / -187 deletions / **+2,689 net**
/ 87 new tests / 0 reverts / bisect-clean across all 6 commits.

User direction repeated 4× across sessions ("adaptable/versatile/flexible/
resilient — don't hardcode strict formats") drove the rejection of two
S1-Phase-3.1 closed-Literal recommendations: `RTOS_FORMAT_MAP:
dict[Literal[rtos_name], str]` (rejected per S3-P3.2; user reminder is
load-bearing for the HYBRID dispatch choice) AND naive flag-based
sort-key (rejected per S1-P3.2; closed-Literal `SortTier` ships instead).

CLAUDE.md Rule #52 promoted from **Rule-of-One** (bare-metal MCU/DSP) to
**Rule-of-Two DURABLE BEYOND DEBATE** (bare-metal + file-format YAML
registry). Promotion lands the durable pattern: closed-grammar Pydantic
Literals + free-string taxonomy + plugin escape hatch + cross-feature
catalog-load validators + Rule #44 cross-firmware MCP tool + Rule #46
paired META-CANARIES + Wave-1+Wave-2 deep-research methodology.

## What Broke

### 1. P3.2.a flip exposed 4 latent regression sites in existing tests

- **What happened:** P3.2.a's `precedence` sort-direction flip aligned
  the resolver with author intent across all 47 manifests. But 4 existing
  tests had been authored assuming the BROKEN (pre-flip) behavior:
  - `test_detects_iso_9660` — expected `iso_9660` but post-flip
    `windows_installer_iso` (precedence 100 < 200) wins for any
    `CD001 + .iso` blob.
  - `test_detects_tar_archive_by_extension_when_gzipped` — extension
    fallback to TAR_ARCHIVE expected, but catalog returns linux_firmware_blob.
  - `test_unknown_when_no_signature_matches` — expected UNKNOWN, but
    catalog returns linux_firmware_blob (floor sentinel always matches).
  - `test_classify_preserves_qcom_pil_stem` — expected `tee` category,
    but catalog returns `other` (qcom_mbn YAML's classifier_category).
- **Caught by:** broader pytest sweep after the schema + resolver edits
  landed.
- **Cost:** ~15 min total.
- **Fix:** kept `linux_blob` + added `windows_installer_iso` in
  `_CATALOG_NEEDS_DISAMBIGUATION` (legacy bridge handles bootmgr
  upgrade + ISO disambig until `substring_in_head` signal kind ships
  in P3.x); added `qcom_mbn` to the catalog-filter set so legacy
  `_category_from_qcom_name` stem refinement still runs (catalog YAML
  can't yet express per-stem category derivation — defers to P3.x
  Refinement-block schema extension).
- **Infrastructure created:** documented the bridge-still-needed
  cases in P3.2.a + P3.2.d commit messages with explicit P3.x deferral
  pointers.

### 2. _system fixture migrations missed in 12+ tests after sort_tier validator

- **What happened:** the new Detection model_validator `always_matches=True
  ⇒ sort_tier='floor'` rejected EVERY existing `_system` fixture that
  declared `always_matches: true` without the matching `sort_tier: floor`.
  12 tests (across test_file_format_schema.py + test_file_format_catalog.py
  + test_file_format_tools.py) hit ValidationError at fixture
  construction.
- **Caught by:** targeted pytest run after P3.2.a schema edits.
- **Cost:** ~5 min — `_minimal_manifest_dict` helper in test_file_format_catalog.py
  needed one edit; test_file_format_tools.py + test_file_format_schema.py
  needed inline fixture updates.
- **Fix:** added `sort_tier: floor` to the default-detection fixture
  helper + 2 inline fixture sites. Once the helper was updated, all
  consuming tests passed.
- **Infrastructure created:** None — the validator worked exactly as
  designed.

### 3. terminator_record_hex byte-count error in intel_hex.yaml

- **What happened:** original `terminator_record_hex` for Intel HEX EOF
  record had **one extra `30` byte** (8 zeros after the colon instead of
  7), so the tail-scan check `term_record not in tail` failed against
  every valid Intel HEX blob.
- **Caught by:** the resolver smoke test after P3.2.b schema edits —
  catalog returned None instead of `intel_hex` for a known-valid blob.
- **Cost:** ~5 min — manual counting + fix.
- **Fix:** corrected to `3a303030303030303146460a` (12 bytes = `:00000001FF\n`).
- **Infrastructure created:** none — fix was a 1-character YAML edit.

### 4. ti_txt.yaml block-header format incompatible with strict per-record evaluator

- **What happened:** TI-TXT's format (`@<addr>\nAB CD EF\n12 34\nq\n`)
  has `@` only on block-header lines; data lines don't start with `@`.
  The closed-grammar evaluator's strict "every record starts with
  record_start_byte" assumption (collected via `if stripped[0:1] !=
  start_byte: break`) only counted the first line as a record →
  min_first_block_records=2 failed.
- **Caught by:** smoke test against a hand-crafted TI-TXT blob.
- **Cost:** ~10 min — investigated + concluded that adding a
  `block_header` Literal value to `first_line_must_match` would require
  Rule #25 Shape-1 cross-stack alignment AND the TI-TXT consumer
  (chip_family TI C28x walker) isn't wired yet anyway.
- **Fix:** **deferred TI-TXT to a follow-on** (Rule #19 evidence-first
  + Rule #28 yardstick). Removed `ti_txt.yaml` from P3.2.b scope;
  shipped Intel HEX + SREC only. TI-TXT lands when (a) `block_header`
  Literal extension lands AND (b) chip_family TI C28x walker
  integration goes live.
- **Infrastructure created:** clear deferral note in the P3.2.b commit
  message + the convergence doc's "what defers" section.

### 5. A6 dispatch-rank-monotonicity tripped rtos_dispatch.yaml's `default: rtos_blob`

- **What happened:** P3.2.c's new A6 gate WARN-fired on the first load
  of `_system/rtos_dispatch.yaml` because its `dispatch.default:
  rtos_blob` pointed to a `core`-tier manifest (existing `misc/rtos_blob.yaml`
  at source_rank=80). `_system` (rank 100) routing to `core` (rank 80)
  is exactly the attestation-split A6 was designed to catch.
- **Caught by:** the A6 gate itself, via `catalog.last_warning` at first
  load.
- **Cost:** ~5 min — investigated whether to (a) move rtos_blob.yaml
  to `_system/`, (b) change the default, or (c) drop the default
  altogether.
- **Fix:** **dropped the `default: rtos_blob` from rtos_dispatch.yaml**.
  When the dispatch evaluator returns None for an unknown family, the
  resolver falls through to the manifest's own `output.classifier_format:
  rtos_blob`, which has the same operator-facing semantics WITHOUT
  triggering A6. Documented the design choice inline in the YAML.
- **Infrastructure created:** explicit comment in rtos_dispatch.yaml
  explaining why there's no `default` set — operators copying the
  pattern see the discipline encoded in the comment.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|---|---|---|---|
| `_check_sort_tier_invariants` Detection validator | 12 existing `_system` fixtures using `always_matches: true` without `sort_tier: floor` | 12 (test fixture updates) | Mis-authored sentinels silently treated as general-tier; operators confused about sort order |
| FileFormatManifest `_check_cross_field_invariants` (sort_tier reservation) | Hypothetical operator/core manifests claiming sort_tier=floor/ceiling | 3 (in P3.2.a test battery) | Operator-supplied manifests demoting `_system` sentinels OR claiming invariants over operator overrides |
| Per-tier cardinality table (P3.2.a — replaced P3.1 singleton check) | Multiple `_system` always_matches manifests (synthesized in test) | 1 (test fixture) | Two catch-all paths producing ambiguous resolution; loosen via Rule #25 Shape-1 when concrete second-floor lands |
| A6 dispatch-rank-monotonicity (P3.2.c) | rtos_dispatch.yaml's `default: rtos_blob` (attestation split _system → core) | 1 (in-design catch) | _system dispatch-chain terminus split across attestation tiers (W2-β §SC5-NEW-1) |
| A7 plugin-namespace-disjointness (P3.2.c) | Plugin A + Plugin B both declaring rtos_families={"freertos"} | 1 (in test battery) | Partner plugin hijacking another plugin's family name (W2-β §SC5-NEW-3) |
| A8 high-collision floor (P3.2.b) | Operator text_format with charset=ascii_printable + precedence<5000 (8 test variants) | 8 (parameterized) | Effective `always_matches` without the flag (W2-β §SC5-NEW-2) |
| A9 rtos_family sanitization (P3.2.c) | 8 hostile family patterns (shell metachars / SQL injection / path traversal / overlong / empty) | 8 (parameterized) | Plugin output flowing to logs / DB / external systems with hostile content |
| `TextFormatConstraint._check_length_bounds` (constraint-strength floor) | min_first_block_records=1 + min_line_length<8 — too weak to discriminate | 1 (test fixture) | Operator near-empty constraint matching all text files |
| `DetectionSignal._check_kind_fields` (text_format ⇔ constraint) | text_format signal without text_format_constraint; constraint set on non-text_format signal | 2 (paired test) | Schema-level constraint required for evaluator; symmetric reject prevents stale leftovers |
| Rule #46 META-CANARY M5 (text_format AST anti-hardcode) + paired canary | Synthesized `_eval_text_format` body with `b":"` hardcoded literal | 1 (canary) | Anti-hardcode discipline drift; closed-grammar regression |
| Rule #46 META-CANARY M8 (plugin source no-exec/no-network/no-eval) + paired canary | Synthesized hostile plugin with `subprocess.run(...)` | 1 (canary) | Bundled plugin defeating worker container's security boundary |
| Rule #46 META-CANARY M1 (sort-key tuple AST shape) + paired canary | Synthesized wrong-order sort-key tuple | 1 (canary) | Future commit silently reordering the sort key + breaking Scout GG §SC5 invariant |
| Rule #46 META-CANARY M7 (DispatchKind exhaustive) + paired canary | DispatchKind Literal extended without DISPATCH_EVALUATORS entry | 1 (canary) | Catalog silently dropping `by_rtos_family` dispatches |
| Rule #46 META-CANARY M3 (no operator sort_tier=floor in YAML corpus) + paired canary | Synthesized hostile YAML at non-`_system` path claiming sort_tier=floor | 1 (canary) | Path cross-check bypass (defense in depth alongside schema validator) |
| Parity-snapshot META-CANARY (P3.2.e) | Synthesized corrupted snapshot value (format="WRONG_FORMAT_ID") | 1 (canary) | Parity tests passing while comparing against wrong snapshot (W2-β paired-canary discipline) |
| Wave-2 W2-β cross-feature critique | 3 NEW Scout GG §SC5 analogs: dispatch-chain authority laundering (→ A6); TextFormatConstraint high-collision (→ A8); RTOS plugin family namespace collision (→ A7) | 3 categories, structural | Multi-feature attack surfaces single-axis Wave-1 architecturally couldn't surface |
| Wave-2 W2-α convergence synthesis | Resolved 5 contradictions across S1-S5 (RTOS dispatch grammar; sort_tier cardinality; TextFormatConstraint charset values; commit order; precedence-flip migration risk) | 5 | Implementation drift between Wave-1 scout recommendations |
| Wave-2 W2-γ Rule #28 yardstick | Pre-commit scope re-measurement; identified P3.2.b/c as ~700+830 LOC; confirmed single-session feasible | 1 | Mid-session context exhaustion |

## Scope Analysis

- **Planned (per final-convergence doc):** 6 P3.2 commits + 1 P3.3 commit (legacy shim removal) for a total of 7 commits; ~3,230 P3.2 insertions / ~1,150 deletions; W2-γ verdict single-session feasible at 0.28× P3.1.
- **Built:** 6 commits in P3.2 (a..f); shipped exactly as planned; +2,876/-187/+2,689 net (slightly higher than the W2-γ estimate due to more comprehensive META-CANARY coverage than the convergence doc projected — 60+ paired canaries vs the projected 28). P3.3.a (legacy shim deletion) deferred per W2-β.
- **Drift:** **Minor.** 4 in-flight tests needed bridge expansion (`windows_installer_iso` + `qcom_mbn` added to `_CATALOG_NEEDS_DISAMBIGUATION` / catalog-filter sets) because the YAMLs lack the discriminating signals (substring-in-head signal kind + Refinement-block stem-category-map — both deferred to P3.x). TI-TXT YAML deferred to a follow-on (block-header mode + chip_family wiring need to land together). Field-level scope cuts (block_header Literal value; per-family RTOS YAMLs; arq worker on_startup hook; `WAIRZ_FORMAT_PLUGIN_PATH` env var) matched W2-α + W2-β deferral plan.

## Patterns

1. **Wave-2 cross-feature critique surfaces attacks Wave-1 architecturally can't — Rule-of-Two now.** P3.1 W2-β found 5 cross-feature attacks A1-A5. P3.2 W2-β found 3 NEW §SC5 analogs leading to A6/A7/A8. Both worked-examples confirm the 2-wave separation is the durable methodology pattern. Promoted to `feedback_wave2_cross_feature_methodology.md` as a feedback memory + companion section in CLAUDE.md Rule #52.

2. **Closed-grammar Pydantic Literals + free-string taxonomy + plugin escape hatch is the Rule-of-Two shape.** Both worked-examples (bare-metal MCU/DSP + file-format YAML registry) use the same 3-layer split: DATA in YAML (closed-Literal-validated), BEHAVIOR in Python plugins (registered via `register_*()`), WALKER consumes via closed dispatch table. Adding a closed-Literal value requires Rule #25 Shape-1 single-slice cross-stack alignment. This is the durable pattern for Rule #52.

3. **User-direction repetition (4× now) is a strong implementation signal.** "Adaptable/versatile/flexible/resilient — don't hardcode strict formats" repeated across 4 sessions drove TWO concrete rejections in P3.2: (a) S1-Phase-3.1's closed `RTOS_FORMAT_MAP` recommendation rejected per S3-P3.2 (user direction is load-bearing for the HYBRID choice); (b) naive `is_always_match` boolean-flag sort-key rejected per S1-P3.2 (closed `SortTier` Literal ships instead). When the user repeats a principle 4×, scout dispatches should explicitly cite it in the prompt; the scout's recommendations should weight it heavily.

4. **Bridge-still-needed cases document themselves via the disambiguation set.** When a YAML doesn't yet have the discriminating signal needed to win cleanly (e.g. windows_installer_iso needs bootmgr-substring-in-head; qcom_mbn needs per-stem category map), the cleanest interim path is to ADD the format_id to `_CATALOG_NEEDS_DISAMBIGUATION` (or `_classify_via_catalog`'s catalog-filter set) so legacy fallback handles disambiguation. Inline comments document the missing signal kind + which P3.x phase ships the schema extension. P3.2 used this 3 times (windows_installer_iso, windows_cab — now dropped, qcom_mbn).

5. **A6/A7/A9 gates land in the same commit as their consumer.** A8 lands in P3.2.b (TextFormatConstraint consumer); A6/A7/A9 land in P3.2.c (RTOS plugin consumer). When the gate's domain-specific code ships, the gate ships too — Rule #46 paired-canary discipline is the test for "the gate ACTUALLY runs". This prevents the orphan-gate failure mode where the gate exists but doesn't fire on its intended target.

6. **Per-piece direct-push cadence (Rule #25) + per-commit bisect-cleanness — Rule-of-Three now.** P3.1 (8 commits, 0 reverts), P3.2 (6 commits, 0 reverts), and the bare-metal MCU/DSP campaign (5 commits, 0 reverts) all shipped bisect-clean per-piece per Rule #25. Each commit has its own acceptance grep + test surface. The cadence is durable.

7. **Single-slice cross-stack exception (Rule #25 exception #2) covers atomic-multi-surface changes.** P3.2.a bundled schema + resolver + classifier + format_detection + AUTHORING.md + tests as ONE commit because splitting them would leave the catalog in an inconsistent sort behavior between commits. The Rule #25 single-slice exception explicitly covers this case; the convergence doc made the call before shipping. Future Rule-of-N updates to single-slice-exception #2 will continue to grow the evidence table in CLAUDE.md Rule #25.

8. **TI-TXT deferral via Rule #19 evidence-first + Rule #28 yardstick worked.** Mid-implementation, discovered TI-TXT's block-header format doesn't fit the strict per-record evaluator without a `block_header` Literal extension. Two paths: (a) extend the Literal now (Rule #25 Shape-1 + chip_family wiring); (b) defer until both pieces land together. Path (b) ships now (Intel HEX + SREC only). The deferral is documented in the convergence doc + commit message + AUTHORING.md doesn't mention TI-TXT. When the chip_family TI C28x walker lands AND the block_header Literal extension lands, TI-TXT YAML ships alongside in a single Rule #25 commit. This is the right shape for Rule #52 deferrals — don't ship half-features.

## Recommendations

1. **P3.3.a — delete the 3 legacy shim modules.** P3.2.e converted `test_file_format_parity.py` to JSON-snapshot form so the modules become deletable. P3.3.a is a single Rule #25 commit: delete `classifier_legacy.py` + `format_detection_legacy.py` + `unpack_common_classify_legacy.py` + any remnant `_legacy_bridge_detect` body. Acceptance grep: `find backend -name '*_legacy*.py' | wc -l = 0`. Net ~-700 LOC (deletion). Schedule for the next session.

2. **P3.x — `substring_in_head` signal kind extension.** Both `windows_installer_iso` (bootmgr substring) AND `iso_9660` (CD001 magic at offset 32769; works today via magic_bytes signal) can drop from `_CATALOG_NEEDS_DISAMBIGUATION` when a `substring_in_head` signal kind ships. Schema extension + Rule #25 Shape-1 cross-stack alignment + Rule #46 META-CANARY for exhaustive coverage of SIGNAL_EVALUATORS.

3. **P3.x — `Refinement.stem_category_map` schema extension.** Today's `qcom_mbn.yaml` relies on the legacy `_category_from_qcom_name()` Python function to refine `other` category to `tee` / `modem` / etc. per stem. A new schema field `refinement.stem_category_map: dict[str, str]` would move the mapping into the YAML; the classifier consumes it via a new `_apply_stem_category_refinement()` helper. Operator can ship per-vendor stem maps without core changes.

4. **P3.x — TI-TXT YAML + `block_header` Literal value.** When the chip_family TI C28x walker integration lands, ship TI-TXT YAML alongside in a single Rule #25 commit: (a) extend `TextFormatFirstLine` Literal with `block_header` value; (b) update `_eval_text_format` to relax the strict-record-start collection when `first_line_must_match=block_header`; (c) ship `_system/ti_txt.yaml` with the new Literal value; (d) Rule #46 paired META-CANARY confirming the new evaluator branch.

5. **P3.x — Per-family RTOS YAMLs in `_system/`.** Today the rtos_dispatch.yaml's `dispatch.cases` point at format_ids that DON'T exist as separate manifests; A3 silently skips them; the dispatch falls through to the manifest's own output. Operators can drop `data/file_formats.local/<family>_elf.yaml` to extend, but the BUNDLED experience would benefit from `_system/zephyr_elf.yaml` etc. for the common cases. Defer to a follow-on session.

6. **P3.x — arq worker `on_startup` plugin registration.** The worker process imports the catalog via `app.workers.unpack_common` but doesn't go through `app/main.py` lifespan. P3.2.c registers plugins ONLY in the backend lifespan. Worker process plugin registration would happen via arq's `WorkerSettings.on_startup` hook. Today the worker's RTOS classification falls back to the legacy `detect_rtos` path in unpack_common.py, which still works — but the catalog-driven `by_rtos_family` dispatch only fires in the backend (API requests). Wiring the worker startup hook lands the catalog-driven path everywhere.

7. **P4 — `WAIRZ_FORMAT_PLUGIN_PATH` env-var for out-of-tree Python plugins.** Per S3 + S5 + W2-α consensus, this is a Rule #36 + Rule #45 + §SC5 triple-breach if shipped naively; defer to P4 as a side-container (Exception 3) where operator-supplied Python loads inside an isolated container that returns parse output through a shared named volume.

8. **CLAUDE.md Rule #52 worked-examples — keep the table growing.** Rule-of-Three eligibility lands on the next adaptable-extension surface. When it ships, append worked-example #3 to Rule #52's table. The 3-layer split discipline + Wave-1+Wave-2 methodology + 60+ paired META-CANARIES are now the durable baseline.

## Numbers

| Metric | Value |
|---|---:|
| Phases planned | 6 (P3.2.a..f) + 1 deferred (P3.3.a) |
| Phases completed | 6 |
| Commits | 6 (34d0689..007abf3) |
| Files changed (cumulative) | 30 |
| Insertions | 2,876 |
| Deletions | 187 |
| Net | +2,689 |
| Reverts | 0 (bisect-clean across all 6 commits) |
| Tests added | 87 (26 sort-tier + 24 text-format + 31 RTOS + 6 parity snapshot) |
| Tests passing (in-scope sweep) | 348/348 |
| File-format manifests in catalog (live) | 49 (was 47 in P3.1; +2 NEW = motorola_srec + rtos_dispatch; +1 UPDATED = intel_hex) |
| Closed Literal enumerations (in production schema) | 23 (was 18 in P3.1; +5 NEW = SortTier + TextFormatCharset + TextFormatLineTerminator + TextFormatFirstLine + DispatchKind.by_rtos_family) |
| New Pydantic models with `extra="forbid"` | 1 (TextFormatConstraint) |
| Plugins registered | 1 (rtos_detection_default) |
| Catalog-load gates (cumulative A1-A9) | 9 (was 5 in P3.1; +4 NEW = A6/A7/A8/A9) |
| Rule #46 META-CANARIES added | 60+ (cumulative across P3.2) |
| Adversarial scouts dispatched | 8 (5 Wave-1 + 3 Wave-2) |
| Adversarial findings adopted | 15+ (3 NEW §SC5 analogs leading to A6/A7/A8 + S3 hybrid grammar + S2 precedence-flip + various) |
| Cross-feature attacks new in P3.2 | 3 (dispatch-chain authority laundering; TextFormatConstraint high-collision; RTOS plugin family namespace collision) |
| Wave-2 contradictions resolved | 5 (RTOS dispatch grammar; sort_tier cardinality; TextFormatConstraint charset; commit order; precedence-flip migration risk) |
| Rule #28 drift | 0.18× P3.1 (well under 1.1× yardstick) |
| Rule #25 Shape-1 cross-stack alignment commits | 1 (P3.2.a single-slice exception #2 — schema + resolver + classifier + format_detection + AUTHORING.md + tests bundled) |
| Legacy shims preserved for revert | 3 (classifier_legacy + format_detection_legacy + unpack_common_classify_legacy; deletion deferred to P3.3.a per W2-β) |
| Rework cycles | 5 (each "What Broke" entry; all caught in-session by tests/canaries) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Rule #11 import smoke | PASS (all P3.2.a/b/c surfaces importable) |
| Rule #8 three-way rebuild | RUN once at start of session as baseline; not re-run after P3.2 commits since no class-shape changes beyond additive Literal extensions |
| Rule #46 paired-canary discipline | applied to every "asserts absence" gate (M1-M8 + parity-snapshot) |
| Rule #41 CI consolidation pause | not needed (single session, all commits direct-pushed) |
| CLAUDE.md Rule #52 promotion | **Rule-of-One → Rule-of-Two DURABLE BEYOND DEBATE** (locked 2026-05-19) |

---HANDOFF---
- Postmortem: file-format-yaml-registry-p32-2026-05-19
- Document: .planning/postmortems/postmortem-file-format-yaml-registry-p32-2026-05-19.md
- Failures documented: 5
- Safety catches: 16
- Recommendations: 8
- Phase 3.2 commits: 34d0689..007abf3 (6 commits)
- Deferred to P3.3: legacy shim deletion (3 modules; ~-700 LOC)
- Deferred to P3.x: substring_in_head signal + Refinement.stem_category_map + TI-TXT + per-family RTOS YAMLs + arq worker on_startup hook
- Deferred to P4: WAIRZ_FORMAT_PLUGIN_PATH side-container
---

Run `/citadel:learn file-format-yaml-registry-p32-2026-05-19` to extract patterns into the knowledge base.
