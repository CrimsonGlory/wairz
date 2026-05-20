# Patterns: file-format YAML registry P3.2 (2026-05-19)

> Extracted: 2026-05-19
> Campaign: .planning/research/file-format-yaml-registry-p32-final-convergence-2026-05-19.md (direct-shipped per Rule #25; no campaign file in .planning/campaigns/)
> Postmortem: .planning/postmortems/postmortem-file-format-yaml-registry-p32-2026-05-19.md

## Successful Patterns

### 1. Wave-1 + Wave-2 cross-feature critique separation (Rule-of-Two)
- **Description:** Dispatch 5 single-axis Wave-1 expert-persona scouts (architecture / adjacency / red-team / operator-UX / precedence), wait for convergence, then dispatch 3 Wave-2 critique scouts (α convergence / β cross-feature blow-it-up / γ Rule #28 yardstick). W2-β combines pairs of features Wave-1 individually validated as safe.
- **Evidence:** P3.2 W2-β surfaced 3 NEW Scout-GG-§SC5 analogs (dispatch-chain authority laundering → A6; TextFormatConstraint high-collision → A8; RTOS plugin family namespace collision → A7). P3.1 W2-β found 5 cross-feature attacks A1-A5. Both campaigns confirm Wave-1 single-axis scouts architecturally can't surface combinatorial attacks.
- **Applies when:** Rule #52 adaptable-extension surfaces with closed-grammar YAML + free-string taxonomy + plugin escape hatch. The 2-wave separation is the durable methodology pattern; promoted to feedback memory `feedback_wave2_cross_feature_methodology.md`.

### 2. Closed-grammar Pydantic Literals + free-string taxonomy + plugin escape hatch (Rule-of-Two on Rule #52)
- **Description:** 3-layer split: (1) DATA in YAML validated against Pydantic v2 model with closed `Literal` fields; (2) BEHAVIOR in Python plugins registered via `register_*()` (`MatcherProto` + `freeze_plugin_registry`); (3) WALKER consumes data through closed dispatch tables (`SIGNAL_EVALUATORS` + `DISPATCH_EVALUATORS`).
- **Evidence:** 20+ closed Literals in `app/schemas/file_format.py` (SortTier / DispatchKind / ManifestSource / DetectionSignalKind / TextFormatCharset / etc.); 49 operator-extensible YAMLs; 9 cross-feature catalog-load validators (A1-A9); HYBRID plugin escape hatch via `register_matcher` + `RtosDetection` typed dataclass + `_RTOS_DETECTION_CONTEXT` ContextVar + `by_rtos_family` dispatch.
- **Applies when:** any new analysis surface operators must extend without modifying Python (chip families, decoder families, vendor adapters, file-format manifests, ICS protocol decoders, JTAG TAP families).

### 3. User-direction repetition (4×) as load-bearing implementation signal
- **Description:** When the user repeats a principle 4×+ across sessions ("adaptable/versatile/flexible/resilient — don't hardcode strict formats"), the principle becomes load-bearing for implementation choices. Scout prompts cite it; scout recommendations weight it heavily.
- **Evidence:** P3.2 used this to REJECT two S1-Phase-3.1 closed-Literal recommendations: (a) `RTOS_FORMAT_MAP: dict[Literal[rtos_name], str]` (S3-P3.2 rejected per user direction); (b) naive `is_always_match` boolean-flag sort-key (S1-P3.2 rejected for closed `SortTier` Literal instead).
- **Applies when:** scout dispatches for Rule #52 surfaces; convergence-doc decision tables; per-piece implementation when scout recommendations diverge.

### 4. Bridge-still-needed cases via `_CATALOG_NEEDS_DISAMBIGUATION` set
- **Description:** When a YAML doesn't yet have the discriminating signal needed to win cleanly (substring-in-head for windows_installer_iso; per-stem category map for qcom_mbn), add the format_id to the disambiguation set so legacy fallback handles disambiguation. Inline comments document the missing signal kind + P3.x phase that ships the schema extension.
- **Evidence:** P3.2.a kept `linux_blob` + `windows_installer_iso` in `_CATALOG_NEEDS_DISAMBIGUATION` (substring-in-head signal deferred to P3.x); added `qcom_mbn` to `_classify_via_catalog` catalog-filter set (per-stem refinement deferred to P3.x). P3.2.d dropped `windows_cab` after parity verification.
- **Applies when:** schema extension for a discriminating signal is needed but isn't load-bearing for the current campaign's scope.

### 5. A-gates land in the same commit as their consumer
- **Description:** Catalog-load validators (A6/A7/A8/A9) ship in the same commit as the YAML/code that introduces the attack surface they gate. Rule #46 paired-canary discipline is the test for "the gate ACTUALLY runs".
- **Evidence:** A8 high-collision floor ships in P3.2.b (TextFormatConstraint introducer); A6 dispatch-rank-monotonicity + A7 plugin-namespace-disjointness + A9 rtos_family sanitization ship in P3.2.c (RTOS plugin introducer).
- **Applies when:** any commit that introduces a new attack surface requiring catalog-load enforcement.

### 6. Per-piece direct-push + bisect-clean (Rule-of-Three across campaigns)
- **Description:** Each commit has its own acceptance grep + test surface. No reverts; bisect-clean; per-piece revertable.
- **Evidence:** P3.1 (8 commits, 0 reverts), P3.2 (6 commits, 0 reverts), bare-metal MCU/DSP (5 commits, 0 reverts) — Rule-of-Three durable now.
- **Applies when:** any multi-commit campaign where commits are independently verifiable.

### 7. Single-slice cross-stack exception (Rule #25 exception #2)
- **Description:** When schema + resolver + classifier + format_detection + docs + tests must land atomically (splitting would leave the catalog in an inconsistent sort behavior between commits), bundle as ONE commit per Rule #25 single-slice exception.
- **Evidence:** P3.2.a bundled `SortTier` Literal + `Detection` validator + `FileFormatManifest` cross-field validator + catalog cardinality refactor + resolver `_compute_sort_key()` extraction + sort-direction flip + `linux_blob_fallback.yaml` sort_tier: floor + `_legacy_magic_classify` deletion + AUTHORING.md + 26 new tests in ONE commit.
- **Applies when:** atomic-multi-surface changes where intermediate commits would leave the system in an inconsistent state.

### 8. Rule #19 + Rule #28 deferral over half-feature ship
- **Description:** When mid-implementation discovers a missing prerequisite (e.g. block-header Literal value for TI-TXT) AND the downstream consumer (chip_family TI C28x walker) isn't wired yet, DEFER the half-feature to a follow-on where both prerequisites land together. Don't ship half-features.
- **Evidence:** P3.2.b deferred TI-TXT YAML; shipped Intel HEX + SREC only. AUTHORING.md doesn't mention TI-TXT; the convergence doc + commit message + postmortem document the deferral with clear next-steps.
- **Applies when:** mid-implementation a feature reveals a schema gap that requires Rule #25 Shape-1 cross-stack alignment + the consumer isn't ready.

### 9. AST-walk META-CANARY for anti-hardcode discipline
- **Description:** Token-scan / AST-walk the implementation body of a closed-grammar evaluator for hardcoded values (byte literals, family strings, format IDs). Every comparison MUST go through the schema's typed fields, not hardcoded constants.
- **Evidence:** M5 META-CANARY in `test_text_format_evaluator.py` AST-walks `_eval_text_format` body for forbidden byte literals (`b":"`, `b"S"`, `b"@"`); allowlist `b""` + `b"\n"` + `b"\r"` + `b"\r\n"` (mechanical terminator-stripping constants). Paired canary synthesizes hostile body with `b":"` literal + confirms gate fires.
- **Applies when:** any closed-grammar evaluator that takes typed input from a schema field — gate against future drift back to hardcoded constants.

### 10. Tokenize-based plugin source scan (no-subprocess / no-network / no-eval)
- **Description:** Tokenize plugin source files; strip comment + string tokens (per κ.D pattern); scan the remaining tokens for forbidden symbols (`subprocess`, `eval(`, `exec(`, `requests`, `socket`, etc.). Bundled in-tree plugins MUST NOT defeat the worker container's security boundary.
- **Evidence:** M8 META-CANARY in `test_rtos_plugin_dispatch.py` tokenize-scans the `plugins/` directory; paired canary synthesizes hostile plugin source with `subprocess.run(...)` + confirms gate fires.
- **Applies when:** any module that loads as a plugin under `PLUGIN_REGISTRY` or analog — defense alongside Rule #36 no-execute base.

### 11. ContextVar for per-call evidence passing across evaluator → dispatch
- **Description:** When a signal evaluator's evidence needs to flow to the dispatch evaluator within the same `resolve()` call (typed detection output → dispatch routing key), use a per-call `ContextVar` reset at the start of every `resolve()`. Avoids global state + async-context bleed.
- **Evidence:** `_RTOS_DETECTION_CONTEXT: ContextVar[RtosDetection | None]` reset at `resolve()` entry; `_eval_rtos_check` sets on hit; `_dispatch_by_rtos_family` reads + falls to `manifest.dispatch.default` on miss.
- **Applies when:** any signal-evaluator-to-dispatch-evaluator data flow within a synchronous resolve() call.

### 12. Soft advisory frozenset for free-string taxonomy
- **Description:** When a closed `Literal` would be anti-Rule-#52 (operator extensibility required), declare a soft `frozenset[str]` advisory of the bundled-plugin's known values. Catalog-load gate WARNs (not REJECTs) when YAML references families not in `RTOS_FAMILY_ADVISORY ∪ Σ matcher.rtos_families`. Operator extends by registering a plugin with additional family values.
- **Evidence:** `RTOS_FAMILY_ADVISORY: frozenset[str]` declares the 10 bundled families (zephyr / freertos / vxworks / threadx / qnx / etc.); catalog-load WARN scan combines the advisory with each plugin's `rtos_families`.
- **Applies when:** a closed Literal would force partners to upstream a PR to extend the taxonomy.

### 13. Per-tier cardinality table replaces singleton catalog-load check
- **Description:** When the schema permits N≥1 instances per closed-Literal value but the catalog enforces a CARDINALITY constraint (singleton-floor + zero-ceiling today), encode the constraint in a `dict[<Literal_value>, int]` cardinality table at catalog-load. Loosen via Rule #25 Shape-1 commit when concrete second-instance use case appears.
- **Evidence:** `_SORT_TIER_MAX_CARDINALITY: dict[str, int] = {"floor": 1, "ceiling": 0}` in `catalog.py`; loader walks `by_tier` index + drops excess manifests with WARN.
- **Applies when:** any closed-Literal value where the schema permits N≥1 but invariants today require a specific count.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| `sort_tier: Literal["floor","general","ceiling"]` schema field, NOT runtime `is_always_match` flag | Schema-driven discipline (Rule #52); operator declares intent in YAML; closed Literal extensible | shipped P3.2.a; 4 paired META-CANARIES enforcing the closed-grammar |
| Flip resolver `precedence` sort direction (lower wins) | S2 audit found 14 inversions all caused by `-precedence` shape; all 47 manifests authored "lower wins" intent; 1-LOC fix matched author intent | shipped P3.2.a; zero YAML edits needed |
| RTOS dispatch HYBRID (free-string `rtos_family` + new `DispatchKind="by_rtos_family"`), NOT closed `RTOS_FORMAT_MAP` Literal | Closed Literal would be anti-Rule-#52 + partner-hostile + couldn't accommodate operator-supplied RTOS families | shipped P3.2.c; user direction "don't hardcode formats" cited |
| Defer `WAIRZ_FORMAT_PLUGIN_PATH` env-var to P4 (side-container) | Operator-controlled Python loader = Rule #36 + Rule #45 + §SC5 triple-breach | deferred per S3 + S5 + W2-α + W2-β consensus |
| TextFormatConstraint 6-value charset Literal (added `hex_space_separated` for future TI-TXT data lines) | W2-α convergence pre-empts S4 Q1 — `hex_space_separated` slot ships now to avoid future single-slice extension | shipped P3.2.b |
| A8 high-collision floor: operator text_format + ascii_printable charset + precedence<5000 REJECTED | W2-β §SC5-NEW-2: prevents "operator declares effective always_matches without the flag" via permissive charset + low min_records | shipped P3.2.b; 8 hostile-pattern test parameterizations |
| Defer TI-TXT YAML to P3.x (block_header Literal + chip_family TI C28x walker land together) | TI-TXT block-header format doesn't fit strict per-record evaluator; chip_family consumer not yet wired | deferred per Rule #19 + Rule #28 |
| Drop `default: rtos_blob` from rtos_dispatch.yaml | A6 dispatch-rank-monotonicity caught the _system → core attestation split; unknown families fall through to manifest's own output.classifier_format=rtos_blob | shipped P3.2.c |
| Convert parity test to JSON-snapshot form so P3.3.a can delete legacy shims | W2-β identified 3 import sites of classifier_legacy; snapshot-form preserves parity verification without the legacy module dependency | shipped P3.2.e; 5 snapshot tests + paired META-CANARY |
| CLAUDE.md Rule #52 promoted Rule-of-One → Rule-of-Two DURABLE BEYOND DEBATE | file-format YAML registry is the SECOND adaptable-extension surface after bare-metal MCU/DSP; both used the same 3-layer split + Wave-1+Wave-2 methodology | shipped P3.2.f; Rule-of-Three eligibility on next surface |
