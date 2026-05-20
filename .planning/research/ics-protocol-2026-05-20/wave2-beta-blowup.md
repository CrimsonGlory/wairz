# Wave-2 Beta — Cross-Feature Blow-It-Up — ICS Protocol Catalog (2026-05-20)

> Mandate: combine pairs/triples of features Wave-1 individually validated as SAFE, look for verbatim Scout-GG-§SC5 analogs at NEW boundaries that Wave-1 single-axis scouts architecturally couldn't see. Wave-1 C already enumerated §SC5-NEW-ICS-1..4 — this report MUST find §SC5-NEW-ICS-5+.
>
> Methodology: P3.2 W2-β found 3 new SC5 analogs at NEW pairings (dispatch-chain authority laundering / TextFormatConstraint high-collision / RTOS plugin namespace collision); the durable shape is "find the NEW cross-feature boundary where two safe features compose unsafely."

## Executive Summary

Wave-1 C enumerated 4 §SC5-NEW-ICS-N attacks. W2-β finds **6 NEW** §SC5-NEW-ICS-5..10 attacks at cross-feature boundaries Wave-1 single-axis scouts validated as individually safe. Two of them (#5 metadata seeding via `ics_protocol_family_regex` × Rule #35c normaliser; #7 hot-reload × `freeze_plugin_registry()`) are HIGH severity — they let an operator with .local YAML rights affect CVE attribution OR worker container security without any plugin code rights.

The remaining four (#6 cross-firmware MCP × project isolation; #8 catch-all plugin × cost-class monotonicity; #9 walker filter × detection-root contract; #10 boot-order race between catalog hot-reload and CVE matcher start) are MEDIUM severity but Rule #46 paired-canary gateable today.

The closing recommendation extends cross-feature gates to **I14-I19** (6 new), all REJECT-class except I17 (WARN), with paired META-CANARY shapes specified per Rule #46.

---

## §SC5-NEW-ICS-5: Pre-seeded `metadata_["ics_protocol_families"]` from a hostile JSONB pre-write × Rule #35c normaliser idempotence

**Severity:** HIGH. **CVE attribution attack via blob metadata fabrication.**

**Mechanism (Wave-1 components composing):**

- Scout E §"CVE Matcher Integration" (lines 116-123) specifies the matcher reads `blob.metadata_["ics_protocol_families"]` (JSONB list) and requires `ics_protocol_family_regex` to match against it. Wave-1 E validated the regex-narrowing contract is safe IN ISOLATION.
- Scout C attack #19 ("Refinement-override category laundering") closes the YAML-side write path via `applies_when: any` reject for operator tier. Wave-1 C validated the WRITE-FROM-CATALOG path is safe with I12 in place.
- BUT: nothing prevents a different writer (operator-supplied descriptor, manual SQL fix, a future MCP endpoint that does `submit_ics_protocol_descriptor` per Scout D Tier-3 tool list) from pre-populating `metadata_["ics_protocol_families"] = ["s7comm"]` on a non-Siemens blob.
- The CVE matcher reads this metadata in the SAME shape regardless of WHO wrote it — there is no provenance discriminator on the JSONB list itself; only the descriptor row has `(descriptor_source, ingestor_id)` per Rule #52 (Scout E line 145 analog). The matcher doesn't consult the descriptor row before reading metadata.
- Result: operator submits `submit_ics_protocol_descriptor(firmware_id, families=["s7comm"])` for an Allen-Bradley blob → CVE matcher applies all Siemens S7 CVEs to that blob with curated authority.

**Why Wave-1 missed it:** Scout C focused on YAML attack vectors; Scout E focused on the matcher field contract. Neither composed "matcher trust of metadata_ key" × "any caller can write that key." The descriptor row's provenance fields are load-bearing but the matcher doesn't read them.

**Scout citations:**
- Scout E line 119: "Walker populates `blob.metadata_['ics_protocol_families']`" — but Scout E DOESN'T say "ONLY the walker can write this key."
- Scout D Tier-3 line 41: `submit_ics_protocol_descriptor` — operator-facing tool. Validated as a legitimate operator hint surface.
- Scout C: I2 (vendor_authority from manifest_source) — does NOT apply to JSONB pre-seeding because the metadata_ write path isn't gated by the catalog at all.

**Schema-level mitigation — I14 NEW (REJECT):**

The CVE matcher MUST read `blob.metadata_["ics_protocol_families"]` ONLY when paired with a SISTER provenance key `blob.metadata_["ics_protocol_families__provenance"]` set to the typed Literal `"walker"` (NOT `"operator"`, NOT `"descriptor"`). Rule #35c normaliser MUST stamp BOTH keys atomically. Operator-supplied descriptor rows can SUGGEST families (in the descriptor row's own field) but the matcher consults the descriptor row through an explicit `resolve_walker_aggregated_families(blob_id)` helper that prefers walker output over descriptor unless `descriptor_source == "attested_external"` (per Scout E lines 23-30 provenance arbitration).

**Paired META-CANARY (Rule #46):**

```python
# backend/tests/test_ics_protocol_metadata_provenance.py
def test_matcher_rejects_metadata_without_walker_provenance():
    """SYNTHESIZE a blob row with metadata_['ics_protocol_families']=['s7comm'] and
    NO sister provenance key. Match against a curated CVE pinned to s7comm. Assert
    the curated CVE is NOT applied (no row in sbom_vulnerabilities)."""

def test_matcher_canary_actually_fires():
    """Synthesize a blob with BOTH keys stamped 'walker'. Assert curated CVE IS applied.
    Without this canary, the gate could degenerate to 'never apply curated' and pass.
    Per Rule #46 — gate without canary is silent pass."""
```

---

## §SC5-NEW-ICS-6: `lookup_ics_protocol_across_firmwares(scope="global")` × project_id absent from filter clause × multi-tenant DB

**Severity:** HIGH. **Cross-tenant data exfiltration.**

**Mechanism (Wave-1 components composing):**

- Scout A line 70-72 specifies the cross-firmware MCP tool: `GROUP BY firmware.id with match_count, supply_chain_signal = (match_count >= 2)`. Validated SAFE by Scout A — Rule #44 mandatory.
- Scout E line 84 (the SQL shape) shows `where IcsProtocolDetection.protocol_family == protocol_family, *where_clauses` — note `where_clauses` is constructed from `binary_substring` + `scope`. Validated SAFE by Scout E in isolation.
- Scout D §"Cross-Firmware Aggregation — ICS-Specific Queries" line 68 ("Which firmwares share an outdated DNP3 stack version?") — operator query for global aggregation.
- BUT wairz is a multi-tenant project model: `project.id` is the tenant boundary. Existing scope='global' tools (linux_persistence.py:345, windows_event_log.py:434, linux_journald.py:452, windows_bcd.py:354, windows_injection.py:354, windows_processes.py:384, windows_registry.py:491) ALL accept scope='global' and DO NOT filter by `current_user.permitted_project_ids`. Verified via grep: zero permission-filter codepaths in those handlers.
- The existing pattern works in wairz today because wairz has no multi-tenant auth model — single API key, single operator. BUT the design rationale for SC5 detection requires us to ask: when wairz grows to multi-operator OR is fielded inside an MSP with multiple customers' firmware, the `scope='global'` cross-firmware tool becomes a data-exfil surface for ANY operator who can authenticate.
- Concrete attack: operator A uploads a firmware, asks `lookup_ics_protocol_across_firmwares(protocol_family="s7comm", scope="global")` — gets a row-per-firmware list including operator B's PRIVATE Siemens PLC firmware with `firmware_id` + `project_id` (which leak the tenant) + `binary_path_substring` evidence (which leak NDA'd file paths).

**Why Wave-1 missed it:** Wave-1 A + E both validated the SQL shape as safe AND the existing precedent (8 prior `lookup_*_across_firmwares` tools) is unambiguous. Scout D validated the operator-UX query as legitimate. Neither asked "what happens when wairz acquires multi-tenancy?"

**Scout citations:**
- Scout A line 71: SQL JOIN+GROUP shape (safe in single-tenant).
- Scout D line 68 + Tier-1 line 25: cross-firmware query is a Rule #44 MANDATORY tool.
- Scout C — NONE of the 20 attacks address cross-tenant; Scout C is YAML-attacker focused.

**Schema-level mitigation — I15 NEW (REJECT today, WARN until multi-tenant lands):**

The MCP tool MUST consult a `Settings.multi_tenant_mode: bool` config. When False (today's state), scope='global' is permitted and the tool behaves as today. When True, scope='global' MUST be replaced by `scope='permitted'` and the filter clause MUST include `Firmware.project_id.in_(permitted_project_ids)`. The contract is documented in the tool's docstring AND in the Rule #44 recipe at `.mex/patterns/cross-firmware-lookup.md`. **Defer the auth layer to v1**, but ship the gate TODAY so when multi-tenancy lands, the consumer-hook enumeration is already complete.

**Paired META-CANARY:**

```python
def test_lookup_global_scope_rejected_in_multi_tenant_mode(monkeypatch):
    monkeypatch.setattr(settings, "multi_tenant_mode", True)
    result = await _handle_lookup_ics_protocol_across_firmwares(
        {"protocol_family": "s7comm", "scope": "global"}, ctx
    )
    assert "permitted" in result.lower() or "global scope not allowed" in result

def test_canary_global_works_in_single_tenant_mode():
    """Synthetic — multi_tenant_mode=False (default). Confirm scope='global' still returns
    cross-firmware rows. Without this, the gate could degenerate to 'always reject global'."""
```

This applies the same shape as the existing `scope='global'` tools and bookmarks the multi-tenant carve-out so it's not forgotten in v1. Recommend filing a Rule #47 consumer-hook enumeration for "every `lookup_*_across_firmwares` MCP tool" → wires the same gate uniformly.

---

## §SC5-NEW-ICS-7: YAML hot-reload at mtime change × `freeze_plugin_registry()` enforced ONLY at startup

**Severity:** HIGH. **Worker container security boundary bypass.**

**Mechanism (Wave-1 components composing):**

- Scout A line 48: `freeze_plugin_registry()` post-startup (W2-β attack I closure mirror) — validated SAFE by Scout A.
- Scout B line 50 (file_format_catalog precedent): "mtime-cached YAML loader with hot-reload" — validated SAFE by Scout B as the right adjacent pattern.
- Verified: `file_format_catalog/catalog.py:122` does mtime-based hot-reload on every catalog read; YAML changes are picked up WITHOUT a backend restart.
- BUT: `freeze_plugin_registry()` is enforced ONCE at startup. The YAML loader continues to consume hot-reloaded YAML at every read.
- Hostile composition: operator modifies a `.local/<protocol>.yaml` to add a `plugin` field referencing a bundled plugin name (already-registered) but with `dispatch.cases` pointing to a NEW format_id the operator just authored. The YAML hot-reload activates the new dispatch path INSTANTLY. The plugin's `applicable_manifest_ids` allowlist (Scout C §"Plugin-isolation requirements" #6) is checked against the YAML's `manifest_id` at YAML-LOAD TIME, not at plugin-registration time.
- If `applicable_manifest_ids` is checked only at PLUGIN registration (frozen) but `manifest_id` is hot-reloaded, the operator can swing the plugin to apply to ARBITRARY manifest IDs by mutating YAML. Worse: the operator can poison the `_RTOS_DETECTION_CONTEXT`-analog ContextVar (Scout A — `IcsDetectionContext` line 43) to cross-write across catalog-isolation boundaries because the ContextVar is per-call and the catalog feeds it from hot-reloaded YAML.

**Why Wave-1 missed it:** Wave-1 A validated `freeze_plugin_registry()`. Wave-1 B validated mtime hot-reload. Neither asked: what state is frozen at startup, and what state is hot-reloaded? `freeze_plugin_registry()` freezes the PYTHON REGISTRY (names → classes); it does NOT freeze the YAML-side `applicable_manifest_ids` cross-check that gates dispatch.

**Scout citations:**
- Scout A line 48: `freeze_plugin_registry()` (frozen at startup).
- Scout B line 50: mtime hot-reload (recommended adjacent pattern).
- Scout C §"Plugin-isolation" #4 ("`freeze_plugin_registry()` at startup before first request") + #6 ("Plugin applicability allowlist") — Scout C validated both but didn't compose them.

**Schema-level mitigation — I16 NEW (REJECT):**

The `applicable_manifest_ids` cross-check MUST run at YAML-LOAD TIME (every hot-reload), comparing the loaded manifest_id against each registered plugin's frozen allowlist. If a hot-reloaded YAML references a plugin via `plugin.name` AND `manifest.id NOT IN plugin.applicable_manifest_ids`, REJECT the YAML at load time with a WARN; the YAML is dropped from the cache. The loader maintains a `_plugin_applicability_cache: dict[(plugin_name, manifest_id), bool]` keyed on the frozen plugin registry + the current manifest_id; flush ONLY when a new plugin registration happens (which, under `freeze_plugin_registry()`, never happens post-startup → cache stays warm for the process lifetime).

A complementary defense: introduce a `catalog.snapshot_token` (Scout A line 47 frozen-registry analog) that the resolver checks for every `resolve()` call against the manifest's mtime — any drift must invalidate the per-call ContextVar.

**Paired META-CANARY:**

```python
def test_hot_reload_rejects_plugin_applicability_drift(tmp_path):
    """1. Write valid .local/dnp3.yaml with plugin.name=ics_string_scanner_default
    AND applicable_manifest_ids allowing it.
    2. Load catalog — passes.
    3. Edit YAML to set manifest.id='modbus' (which is NOT in plugin's applicability).
    4. Trigger hot-reload via mtime touch.
    5. Assert the modified YAML is REJECTED at hot-reload (cache shows old version OR
       failed_mtime entry recorded)."""

def test_canary_drift_detection_actually_fires():
    """Synthesize a manifest where applicability allows the new manifest_id; confirm
    hot-reload accepts. Without this, the gate could degenerate to 'always reject hot-reload'."""
```

---

## §SC5-NEW-ICS-8: Catch-all plugin `ics_unknown_scanner` × `cost_class=1` declared but invokes full-file regex/memory scan

**Severity:** MEDIUM. **DoS via cost-class monotonicity violation.**

**Mechanism (Wave-1 components composing):**

- Scout A line 5: "v1 scope: 5 canonical protocols (Modbus/TCP, DNP3, OPC-UA Binary, S7Comm, BACnet/IP) plus **1 plugin-driven catch-all for the long-tail**." Validated SAFE by Scout A.
- Scout A line 46: "Bundled plugins (v1): `ics_string_scanner_default`, `ics_elf_symtab_default`, `ics_pe_imports_default` — each ~CHEAP CACHE invoked ONCE per binary; results stashed on `IcsDetectionContext`."
- Scout C §"Plugin-isolation requirements" #4 (`freeze_plugin_registry()`) — bundled plugins are TRUSTED via in-tree-only enforcement (#1).
- BUT: the catch-all plugin is the high-risk surface. It will WANT to do whole-file regex or full memory scan to identify long-tail protocols (Mitsubishi MELSEC, OMRON FINS, Beckhoff ADS) — that's its whole purpose. The bundled `ics_string_scanner_default` cache is "once per binary" (Scout A line 46), but the catch-all is fundamentally a "per-call regex scan" pattern.
- If the catch-all declares `cost_class=1` (cheap) but actually performs a 10 MB+ memory scan, the resolver's cost-sorted ordering (Scout B line 47 — "cost-sorted resolver") will invoke it EARLY for every binary. On a corpus of 10,000 binaries the cumulative cost is 100 GB+ of memory reads — DoS.
- Variant: the catch-all plugin's regex is operator-extensible per Scout D §3 ("operators need `vendor_extended_allowlist`"). Operator declares 50 vendor-extended FC ranges → regex grows non-monotonically → catch-all blows past its cost class.

**Why Wave-1 missed it:** Scout A validated bundled plugins individually as "cache once per binary." Scout B validated cost-sorted resolver as right pattern. Neither asked "what happens when a catch-all plugin LIES about its cost_class?"

**Scout citations:**
- Scout A line 5 + 46 (catch-all + cache once).
- Scout B line 47 (cost-sorted resolver — assumes cost_class is truthful).
- Scout C §"Plugin-isolation" #5 (`side_effects: Literal["none"]` ONLY) — captures intent but not cost monotonicity.

**Schema-level mitigation — I17 NEW (WARN at catalog load; REJECT at runtime via observability):**

(a) Catalog-load gate: each bundled plugin declares `max_evidence_bytes_processed: int` (Pydantic typed positive int). If `cost_class == 1`, require `max_evidence_bytes_processed <= 4096` (i.e. only cache-window head). If the plugin processes more, declare `cost_class >= 5`. Catalog-load validates this is monotonic.

(b) Runtime gate: the resolver wraps each plugin's `detect()` invocation in `time.monotonic_ns()` + `tracemalloc` peak measurement; logs WARN if the OBSERVED cost class exceeds the DECLARED cost class by > 2x. Three consecutive WARNs → REJECT (mark plugin disabled).

The observability path is the right shape because cost-class is fundamentally a runtime property, not a load-time one. WARN-at-load + REJECT-at-runtime via consecutive-violation budget mirrors Citadel hook pattern.

**Paired META-CANARY:**

```python
def test_catalog_rejects_cheap_plugin_with_large_evidence_budget():
    """Synthesize a plugin spec with cost_class=1 AND max_evidence_bytes_processed=1_048_576.
    Assert catalog-load fails."""

def test_canary_legitimate_cheap_plugin_loads():
    """Synthesize cost_class=1 AND max_evidence_bytes_processed=2048. Confirm load passes.
    Per Rule #46."""
```

---

## §SC5-NEW-ICS-9: Walker filter set (Scout A's "filtered walk set") × Rule #16 detection roots × symlinked-out-of-root hostile blob

**Severity:** MEDIUM. **Walker scope escape via symlink.**

**Mechanism (Wave-1 components composing):**

- Scout A line 51-56: "Filtered walk set: every `HardwareFirmwareBlob` row, every ELF/PE binary, every config file matching path heuristics `/etc/*.conf|.xml|.json|.cfg`." Validated SAFE by Scout A.
- Scout E line 8 + Rule #16 mandates `get_detection_roots(firmware)` to seed the walk. Validated SAFE.
- CLAUDE.md Security #1 / `app/utils/sandbox.py` mandates `os.path.realpath()` + prefix check on every file access.
- BUT: the walker's filter set is THREE-PRONG:
  1. `HardwareFirmwareBlob` rows (DB-derived; trusted by inference, but Scout A doesn't say the walker validates the blob's `path` against detection roots);
  2. ELF/PE binaries (filesystem scan — needs Rule #16);
  3. Config files matching `/etc/*.conf|.xml|.json|.cfg` (filesystem scan — needs Rule #16 OR a separate sandbox check).
- If the walker iterates `HardwareFirmwareBlob` rows BUT the blob's `path` column points to a symlink-resolved path outside the detection roots (e.g. an Android `/system/etc/init.d/foo.conf` that's a symlink to `/var/log/wairz-audit/operator-secrets.json`), the walker reads operator audit data and embeds it in `ics_protocol_audit_result` JSONB. Then the cross-firmware MCP tool exposes that data to any operator querying.
- Even with `os.path.realpath()` enforced at the file-read site, the JSONB output includes paths the walker scanned — leaking file existence and path structure.
- Variant: the walker's "config file" prong scans `/etc/*.json` — but a malicious firmware unpacker could symlink `/etc/wairz_config.json` to `/proc/self/environ` (worker container env). On NEXT walker invocation, the symlink resolves to the worker container's env including any DB connection strings.

**Why Wave-1 missed it:** Scout A specified the walker's filter set as a logical type; Scout E specified detection roots. Neither composed the three-prong filter (DB-derived + filesystem-scan-by-extension + filesystem-scan-by-path-pattern) with the symlink attack surface.

**Scout citations:**
- Scout A line 51-56 (filtered walk set).
- Scout E line 8 (Rule #39 inner triplet uses detection roots).
- CLAUDE.md Rule #16 (detection roots helper) + Security #1 (sandbox).

**Schema-level mitigation — I18 NEW (REJECT):**

The walker triplet inner function MUST validate every candidate path through a SINGLE choke point:

```python
def _is_valid_ics_walk_target(path: str, detection_roots: list[str]) -> bool:
    real = os.path.realpath(path)
    return any(real.startswith(os.path.realpath(root) + os.sep) for root in detection_roots)
```

ALL three prongs (DB-derived blob paths, ELF/PE filesystem scan, config-file filesystem scan) MUST flow through this choke point BEFORE the file is opened. If invalid, the path is DROPPED (not WARN — silent drop with a debug-level log; WARN exposes the symlink target to operators which is itself a leak).

Companion: the walker's JSONB output MUST normalise paths to RELATIVE-to-detection-root form (Rule #16 partner) so JSONB never leaks absolute paths outside the firmware tree.

**Paired META-CANARY:**

```python
def test_walker_rejects_symlinked_out_of_root_blob(tmp_path):
    """Create a HardwareFirmwareBlob row pointing to a symlink that resolves outside
    detection roots. Run walker inner. Assert blob is dropped (not in result.per_binary)."""

def test_canary_legitimate_blob_walked(tmp_path):
    """Confirm a blob inside detection roots IS walked."""
```

This generalises Rule #34a (unblob sandbox EXDEV) which fixed a related symptom (zero-byte files from sandboxed link); the rule extends to read-side, not just write-side.

---

## §SC5-NEW-ICS-10: Catalog hot-reload mtime watcher × CVE matcher boot-time `_KNOWN_FIRMWARE_NARROWING_FIELDS` × no race fence

**Severity:** MEDIUM. **Boot-order race window allows CVE matcher to mis-validate operator YAML.**

**Mechanism (Wave-1 components composing):**

- Scout E line 116-123: `_KNOWN_FIRMWARE_NARROWING_FIELDS` is extended to include `ics_protocol_family_regex` at CVE matcher boot. Validated SAFE in isolation.
- Scout A line 47 + Scout B line 50: catalog has mtime hot-reload that fires on every catalog read.
- Existing pattern at `cve_matcher.py:124`: `_KNOWN_FIRMWARE_NARROWING_FIELDS` is a module-level constant — evaluated ONCE at import. Verified via grep.
- The race window: catalog state at the moment `_KNOWN_FIRMWARE_NARROWING_FIELDS` is evaluated determines what curated YAML the matcher validates. If the catalog hot-reload fires CONCURRENTLY with the first matcher invocation, the matcher sees a partially-loaded catalog (some YAMLs accepted, some not yet processed) — and a curated YAML pinning `ics_protocol_family_regex: "siemens"` may evaluate against an EMPTY families list because the walker hasn't run yet on this firmware.
- More dangerous variant: at uvicorn worker spin-up, the catalog snapshot is loaded BEFORE the matcher's narrowing-field tuple is evaluated. If the matcher's tuple is computed FROM the catalog's known fields (e.g. via a `dataclasses.fields(IcsProtocolManifest)` introspection), an mtime-hot-reload removing or renaming a YAML field changes the matcher's narrowing tuple — silently widening attribution scope.
- Variant: the catalog hot-reload runs on the BACKEND but the WORKER container reads catalog snapshot independently. Two containers can have divergent catalog snapshots → divergent CVE narrowing → operator-visible inconsistency between the API response (backend) and the persisted `sbom_vulnerabilities` row (worker).

**Why Wave-1 missed it:** Scout E validated the matcher field shape; Scout A/B validated hot-reload independently. The boot-order race is invisible without composing "module-level constant" × "hot-reload" × "two-container topology."

**Scout citations:**
- Scout E line 118-119 (matcher narrowing).
- Scout A line 47 (catalog).
- Scout B line 50 (hot-reload).
- `cve_matcher.py:124` _KNOWN_FIRMWARE_NARROWING_FIELDS (module-level — boot-frozen).

**Schema-level mitigation — I19 NEW (REJECT):**

(a) `_KNOWN_FIRMWARE_NARROWING_FIELDS` MUST be a Pydantic `Literal` allowlist tuple, NOT introspected from manifest fields. The Rule #25 single-slice cross-stack alignment commit that adds `ics_protocol_family_regex` ships the change to the tuple, the schema field, AND the alignment test together (Rule #48 5-part shape). This eliminates the introspection variant entirely.

(b) Catalog hot-reload MUST acquire an `asyncio.Lock` (or `threading.Lock` if the matcher runs in a different process pool) before mutating the catalog state. The matcher acquires READ on the same lock. This serialises hot-reload + matcher invocation.

(c) Backend + worker MUST share catalog state via a single source of truth — recommend storing catalog snapshot mtime in the `firmware.metadata_["catalog_snapshot_mtime"]` column at scan time, so the worker's snapshot is anchored to the backend's. Divergence becomes detectable.

Note: (a) is the high-leverage fix; (b) + (c) are defense-in-depth.

**Paired META-CANARY:**

```python
def test_narrowing_fields_are_literal_not_introspected():
    """AST-scan cve_matcher.py to confirm _KNOWN_FIRMWARE_NARROWING_FIELDS is a literal tuple,
    NOT computed via dataclasses.fields or pydantic introspection."""

def test_canary_introspection_form_would_fail():
    """Synthesize a hypothetical introspection-form and assert AST-scan catches it.
    Without canary, the gate could pass against any random tuple."""
```

---

## I14-I19 — Updated Cross-Feature Gate Inventory

| Gate | Description | Severity | Composes |
|---|---|---|---|
| I1 | mode=override × manifest_source rank parity (A1 mirror) | REJECT | A1 |
| I2 | vendor_authority from manifest_source, terminus-aware (A2 mirror) | REJECT | A2 |
| I3 | dispatch.cases × deprecation.status: removed (A3 mirror, WARN for ICS — §SC5-NEW-ICS-3) | WARN | A3 |
| I4 | Cross-vendor same-precedence same-magic collision (A4 mirror) | REJECT | A4 |
| I5 | dispatch.depth_max >= 2 × eager expensive plugin (A5 mirror) | REJECT | A5 |
| I6 | dispatch-rank-monotonicity (A6 mirror, REJECT for CVE-feeding) | REJECT | A6 |
| I7 | Plugin-namespace-disjointness (A7 mirror) | REJECT | A7 |
| I8 | High-collision floor: operator weak signal × precedence < 5000 (A8 mirror) | REJECT | A8 |
| I9 | protocol_id sanitization (A9 mirror) | WARN | A9 |
| I10 | Transport-port × protocol-family agreement | REJECT | Scout C #10 |
| I11 | F-FORENSIC-10 analog — CVE-bearing curated entry requires narrowing beyond (vendor, category) | REJECT | Scout C #11 |
| I12 | Refinement `applies_when: any` REJECTED for operator | REJECT | Scout C #12 |
| I13 | Dispatch-cycle detection BFS | REJECT | Scout C #13 |
| **I14 NEW** | `metadata_["ics_protocol_families"]` reads require sister `__provenance` key set to `walker` | REJECT | §SC5-NEW-ICS-5 |
| **I15 NEW** | `scope='global'` in cross-firmware MCP tool requires `multi_tenant_mode=False` OR `permitted_project_ids` filter | REJECT (when multi-tenant) | §SC5-NEW-ICS-6 |
| **I16 NEW** | Hot-reloaded manifest's `plugin.name` requires `manifest.id IN plugin.applicable_manifest_ids` (cross-check at YAML-load, not plugin-register) | REJECT | §SC5-NEW-ICS-7 |
| **I17 NEW** | `cost_class == 1` requires `max_evidence_bytes_processed <= 4096`; observability gate REJECTs at 3 consecutive overruns | WARN/REJECT | §SC5-NEW-ICS-8 |
| **I18 NEW** | Walker triplet inner — all three prongs (DB-derived blob, ELF/PE filesystem-scan, config-file filesystem-scan) flow through `_is_valid_ics_walk_target()` choke point | REJECT (silent drop) | §SC5-NEW-ICS-9 |
| **I19 NEW** | `_KNOWN_FIRMWARE_NARROWING_FIELDS` is a literal tuple (Rule #25 cross-stack alignment), NOT introspected; hot-reload acquires lock | REJECT | §SC5-NEW-ICS-10 |

**6 NEW gates beyond Wave-1 C's I10-I13.** All gateable today via Rule #46 paired-canary test shapes. I14 + I17 + I18 + I19 ship as P3-equivalent catalog-load validators. I15 ships as carve-out for v1 multi-tenant work. I16 ships at the plugin-applicability cross-check (which Scout C already specified at #6 but didn't extend to hot-reload).

---

## Recommended Action Items for Implementation Campaign

1. **Phase A schema commit** — add `metadata_["ics_protocol_families__provenance"]` to Rule #35c normaliser shape; Pydantic Literal for the provenance enum (`"walker" | "operator" | "attested_external"`).

2. **Phase B catalog-load commit** — implement I14 + I16 + I17 + I19 as catalog-load validators; all 4 ship with Rule #46 paired META-CANARY tests in the same file.

3. **Phase D walker commit** — implement I18 walker choke point function `_is_valid_ics_walk_target()` in the walker module; route all three prongs through it; relative-path normalisation in JSONB stamp output.

4. **Phase F MCP tool commit** — implement I15 multi-tenant gate as Settings flag + tool-side fence; documented in Rule #44 recipe.

5. **Postmortem note** — Rule #46 reviewer-level check: every new gate ships with a paired META-CANARY that synthesizes a violation. Without that, the gate is a Rule #17 silent-pass instance.

6. **Defer to v1** — I15 multi-tenant enforcement path; I17 observability runtime-budget enforcement (catalog-load gate ships in v0, runtime gate ships in v1 alongside Prometheus metrics).

---

## Scariest New Attack (TL;DR for parent agent)

**§SC5-NEW-ICS-7 (Hot-reload × `freeze_plugin_registry()`).** Operator with `.local` YAML rights (the explicit operator tier) can RE-PURPOSE a bundled plugin to act on arbitrary manifest IDs by editing YAML and triggering mtime hot-reload — no plugin Python code rights required. The `freeze_plugin_registry()` defence Scout A validated freezes only the Python registry (names → classes), NOT the YAML-side `applicable_manifest_ids` cross-check that gates dispatch. Bundled plugins are TRUSTED (in-tree only, token-scanned at import per Scout C #9-11), so operator-driven hijack of a trusted plugin breaches the worker container's security boundary even though no untrusted code was loaded. Mitigation = I16 (cross-check at YAML-load every hot-reload, not at plugin-register). Ships as Rule #46 paired META-CANARY in Phase B catalog-load commit.

---

## Methodology Note

W2-β operates by combining Wave-1-validated features pairwise + triplewise. The 6 new attacks composed: (1) JSONB normaliser × MCP descriptor tool × CVE matcher; (2) cross-firmware tool × project isolation × scope='global'; (3) hot-reload × `freeze_plugin_registry()` × plugin applicability; (4) catch-all plugin × cost-class × Scout D vendor extensions; (5) walker filter set × Rule #16 × symlink; (6) module-level constant × hot-reload × two-container topology. Each pairing was validated SAFE by single-axis scouts; only the cross-feature lens surfaces the §SC5 analog.

Three of the six (I14, I17, I19) are ALREADY-shipped patterns elsewhere in wairz (Rule #35c provenance; Rule #25 cross-stack alignment) — applying them to ICS is mechanical. Three (I15, I16, I18) require NEW gates with paired META-CANARIES specific to the ICS catalog.
