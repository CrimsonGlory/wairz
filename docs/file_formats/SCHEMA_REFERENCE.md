# Schema Reference

The canonical source of truth for the file-format manifest schema is the
Pydantic model at `backend/app/schemas/file_format.py` and its JSON-Schema
export at
`backend/app/services/file_format_catalog/data/file_formats/.schema.json`.

This document enumerates every closed `Literal` and constraint so
operators can reference shapes WITHOUT crawling Python source. The
auto-generation pipeline that keeps this document in lockstep with the
Python schema is queued for P3.2 (Wave-2 deferred). Until then, this
file is hand-maintained — when a Literal changes upstream, this file
gets the matching edit in the same Rule #25 commit.

## Closed Literals

### `ManifestSource`

```
"_system"
"core"
"operator"
"attested_external"
"unauthenticated_external"
```

Each maps to an on-disk path tier; the loader rejects mismatches.

### `VendorAuthority`

```
"curated"
"operator_supplied"
"external_attested"
```

Derived view, never authored directly in YAML. Computed from
`manifest_source` per the table in `README.md`.

### `OverlayMode`

```
"new"        (default — rejects duplicate format_id)
"override"   (requires overrides: <path>)
"extend"     (P3.2 — equivalent to override today)
```

### `EvaluationMode`

```
"best_match"
```

Single value today. First-match was the bug shape (Wave-1 S5 B). The
resolver always collects-then-sorts.

### `Combine`

```
"all_required"  (AND across signals)
"any"           (OR across signals)
"weighted"      (sum of (weight*match) must clear min_confidence_score)
```

### `DetectionSignalKind`

```
"filename"
"path_context"
"size_range"
"elf_check"
"intel_hex_check"
"pe_check"
"text_format"
"magic_bytes"
"zip_markers"
"tar_markers"
"rtos_check"
"always_matches"
```

Cost-class groupings (resolver `_SIGNAL_COST_CLASS`):

| Class | Kinds |
|-------|-------|
| zero | filename, path_context, size_range |
| cheap | elf_check, intel_hex_check, pe_check, text_format |
| mid | magic_bytes (≤512 bytes head read) |
| expensive | zip_markers, tar_markers, rtos_check |

`always_matches` is reserved for the single `_system/linux_blob_fallback.yaml`
sentinel and rejected at load on any other manifest.

### `DispatchKind`

```
"by_partition_name"
"by_zip_inner_file"
"by_inner_magic"
"alias"
"none"  (default)
```

### `PluginBind`

```
"eager"  (default — load-time resolution, ImportError fatal)
"lazy"   (match-time resolution per fallback policy)
```

### `PluginFallback`

```
"skip"
"reject"
"raw_bin"
```

### `PluginRole`

```
"primary"
"refine"  (default)
"none"
```

### `PluginDisagreement`

```
"log_warn"  (default)
"reject"
"plugin_wins"
"static_wins"
```

### `PluginSideEffects`

```
"none"   (only permitted value)
```

Plugins MUST be pure (Wave-1 S5 attack P — side-channel ordering).

### `ExternalManifestsPolicy`

```
"deny"   (default for core/system)
"allow"
"require_attestation"
```

### `Confidence`

```
"high"
"medium"
"low"
```

### `VendorPrecedence`

```
"filename_wins"  (default)
"path_wins"
```

Closes the implicit filename-vs-path ambiguity in path-context
refinement.

### `TieBreaker`

```
"rule_specificity"
"vendor_lex_asc"
"filename_lex_asc"
```

Final-tier disambiguators when source-rank + precedence + specificity
all tied.

### `DetectedFormat` — pre-upload surface

```
"linux_firmware_blob"
"android_apk"
"android_ota"
"windows_installer_iso"
"acronis_backup"
"qnx_ifs"
"pe_executable"
"wim_archive"
"iso_9660"
"tar_archive"
"zip_archive"
"windows_cab"
"windows_msi"
"windows_msix"
"windows_msu"
"windows_psf"
"windows_vhdx"
"windows_driver_package"
"unknown"
```

Adding a value REQUIRES Rule #25 cross-stack alignment (DB CHECK ↔
Pydantic Literal ↔ frontend Record mirror).

### `ExtractionCapability`

```
"full"     (extraction works end-to-end)
"partial"  (surface extraction OK; reassembly TBD)
"none"     (informational only; user extracts externally)
```

### `DeprecationStatus`

```
"active"      (default)
"deprecated"  (requires replaced_by + removal_phase)
"removed"     (requires replaced_by; rejected from dispatch chains via A3)
```

## Field constraints

### `format_id`

- `min_length=1`, `max_length=64`
- `pattern=^[a-z][a-z0-9_]*$`
- Globally unique across the catalog (per `OverlayMode` semantics).

### `alias_of`

- `max_length=64`, same pattern as `format_id`.
- No alias chains > 1.
- Mutually exclusive with `dispatch.kind != "none"`.

### `category` / `vendor` / `product`

- FREE STRING; `min_length=1`, `max_length=64`.
- Cross-stack alignment via Rule #25 Shape-1 when adding values that
  need DB / frontend mirror coverage.

### `precedence`

- `ge=0`, `le=10_000`.
- `[0,9]` reserved for `_system` manifests.
- `[>=5000]` required for `magic_bytes <= 2 bytes`.

### `DetectionSignal.stems_lower`

- `max_length=64` entries.
- Each entry: `min_length=4` chars (Wave-1 S3 §2 floor).

### `DetectionSignal.extensions_lower`

- `max_length=32` entries.
- Each entry: `min_length=2` chars (e.g. `".sh"`); MUST include the dot.

### `DetectionSignal.path_substrings_any_of`

- `max_length=32` entries.
- Each entry: MUST start with `/`; `min_length=6` chars.

### `DetectionSignal.bytes_hex`

- `max_length=1024` chars (i.e. ≤ 512 bytes).
- Even-length lowercase hex.
- `min_length=4` chars (2 bytes); 2-byte magic requires
  `precedence >= 5000` on the manifest.

### `DetectionSignal.mask_hex`

- Same length as `bytes_hex`.
- Cannot be all-zero (use `detection.always_matches=true` for catch-all).

### `Detection.signals`

- `min_length=1`, `max_length=32` entries.
- Cost-sorted at evaluation; declaration order is documentation only.

### `Refinement.path_substrings_any_of`

- `max_length=32` entries.
- Each entry: MUST start with `/`; `min_length=6` chars.

## Auto-generation status

This file is hand-maintained until P3.2 wires up Pydantic TypeAdapter
inspection into a markdown-generator. Drift between this file and the
Python schema is a Rule #21 violation; alignment lives in the same
commit that changes the schema.

## See also

- `backend/app/schemas/file_format.py` — Pydantic source (canonical).
- `backend/app/services/file_format_catalog/data/file_formats/.schema.json`
  — JSON-Schema export for editor LSP.
- `ERROR_GLOSSARY.md` — error-code → remediation mapping.
- `AUTHORING.md` — walkthrough.
- CLAUDE.md Rule #52 — schema-driven extensibility hard rule.
