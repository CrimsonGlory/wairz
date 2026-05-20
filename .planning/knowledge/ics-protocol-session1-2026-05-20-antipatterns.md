# Anti-patterns: ICS Protocol Catalog — Session 1 (2026-05-20)

> Extracted: 2026-05-20
> Campaign: (no campaign file — direct-shipped per Rule #25 per-piece cadence)
> Postmortem: .planning/postmortems/postmortem-ics-protocol-session1-2026-05-20.md
> Commits: 0dabbd6..91bf4e5

## Failed Patterns

### 1. Wave-1 single-axis scout LOC estimates without `wc -l` ground truth
- **What was done:** Wave-1 Scout A (architecture) provided LOC estimates per phase based on intuition + Scout A's understanding of the existing file_format_catalog scope. Estimate was "v1 = ~4000 LOC" (1.5× P3.2).
- **Failure mode:** The intuition-based estimate was 2-3× too low. Wave-2 γ (yardstick) ran `wc -l` against actual reference files (file_format.py = 1,262 LOC; file_format_catalog/* = 1,749 LOC; efs_walker.py = 1,232 LOC; linux_systemd.py = 843 LOC) and projected ~10,300 LOC actual. Without W2-γ, the session would have hit context exhaustion mid-Phase D or shipped a half-finished state.
- **Evidence:** W2-γ measurements in `.planning/research/ics-protocol-2026-05-20/wave2-gamma-yardstick.md`. Scout A estimate cited verbatim in `wave1-scout-A-architecture.md` §"Single-Session Feasibility".
- **How to avoid:** Wave-1 scout LOC estimates are INFORMATIVE but NOT AUTHORITATIVE. The authoritative measurement is W2-γ's `wc -l` against reference files. **Always run W2-γ before committing to a single-session scope** when the campaign touches >2× P3.2 baseline; HONOR the verdict (single-session vs multi-session). Per Rule #28 yardstick discipline.

### 2. Accessing Pydantic flat-result type as nested
- **What was done:** Live canary print statement used `m.output.protocol_family` on an IcsProtocolMatch object.
- **Failure mode:** `AttributeError: 'IcsProtocolMatch' object has no attribute 'output'`. The IcsProtocolMatch result type is FLAT (top-level `protocol_family`, `layer`, `transport`, `vendor` fields) — it does NOT mirror IcsProtocolManifest's nested `output` sub-block. The design choice is to give MCP tool output a clean flat shape; the schema docstring explains this.
- **Evidence:** Live canary script in Session 1 Commit 3 verification.
- **How to avoid:** When designing a result type for an MCP tool surface, prefer FLAT shape over nested. Document the flatness in the schema docstring. Reviewers (and your own canaries) reading the result type should NOT assume mirror of input schema.

### 3. Initial design instinct toward operator-supplied Python plugins (over-permissive)
- **What was done:** Wave-1 Scout A initially proposed v0 = HYBRID plugin escape hatch supporting OPERATOR-supplied Python plugin files at `data/ics_protocols.local/_plugins/*.py`.
- **Failure mode:** Wave-1 Scout C (red-team) surfaced the attack vector — operator-supplied plugins can `subprocess.run()` / `socket.connect()` / `cryptography.decrypt()` to violate Rule #36 (no-execute) + Rule #45 (no-decrypt). Operator-tier YAML rights would expand to RCE inside the worker container.
- **Evidence:** W2-α convergence resolved this contradiction by:
    1. RESTRICTING plugins to IN-TREE ONLY (`backend/app/services/ics_protocol_catalog/plugins/<plugin>.py`)
    2. Token-scanning plugin source AT IMPORT TIME for forbidden imports (Rule #45 + Rule #46 paired META-CANARY discipline)
    3. `freeze_plugin_registry()` at startup before first request
    4. Wave-2 W2-β surfaced §SC5-NEW-ICS-7 — even in-tree plugins are subject to hot-reload × YAML-applicability cross-check attack (mitigation I16 — applicability re-validation at YAML-load, not at plugin-register)
- **How to avoid:** When designing a plugin escape hatch in a Rule #52 catalog, DEFAULT to in-tree-only with operator-supplied YAML controlling applicability. Operator-supplied Python plugins are a Rule #36 + Rule #45 breach surface — defer to a side-container (Rule #36 Exception 3) where the security boundary is the container, not the plugin.

### 4. Plugins shipped in Session 1 without I16 hot-reload mitigation (avoided pre-emptively)
- **What was done (pre-emptive avoidance):** Wave-1 Scout A initially proposed shipping `ics_string_scanner_default` plugin in v0.
- **Failure mode (avoided):** W2-β §SC5-NEW-ICS-7 surfaced: hot-reload × `freeze_plugin_registry()` attack. Operator with `.local` YAML rights can RE-PURPOSE a bundled trusted plugin to act on arbitrary manifest IDs by editing YAML and triggering mtime hot-reload — NO plugin Python code rights required. The freeze pins the registry (name→class) but NOT the YAML-side `applicable_manifest_ids` cross-check.
- **Evidence:** W2-β report `wave2-beta-blowup.md` §SC5-NEW-ICS-7.
- **How to avoid:** When shipping plugins to a Rule #52 catalog, ship the W2-β-style applicability cross-check (re-validation at every hot-reload) in the SAME COMMIT as the first plugin. Session 1 deferred plugins entirely; Session 2 ships plugin + I16 mitigation atomically.

### 5. Anti-hardcode META-CANARY scope confusion (potential)
- **What was done (pre-emptive clarification):** The Rule #46 anti-hardcode AST canary walks the resolver source for hardcoded byte literals. Tests synthesize hostile evaluator bodies via heredoc strings; the canary correctly catches them.
- **Failure mode (potential):** A naïve canary author might scope the AST walk to the WHOLE codebase (including tests) and false-positive on `b"\x00" * 16` test fixtures. The actual canary correctly scopes to `_resolver_source()` only — the helper reads ONE specific file path.
- **Evidence:** Each Rule #46 anti-hardcode AST canary in this session uses `_resolver_source()` returning a single file path; never walks `tests/` or other module trees.
- **How to avoid:** Anti-hardcode AST canaries MUST scope to PRODUCTION CODE only. Use a per-canary `_<module>_source()` helper that reads the specific file under audit. Test files legitimately use literal byte sequences for fixture synthesis; the canary should never see them.
